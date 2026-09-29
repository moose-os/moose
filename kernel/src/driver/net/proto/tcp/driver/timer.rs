//! Background timer thread: RTO retransmission, keepalive, delayed ACK,
//! zero-window persist probing, pacing release, TIME-WAIT expiry, and
//! Tail Loss Probes.

use alloc::{sync::Arc, vec::Vec};

use super::{
    super::{
        cc::CongestionControl,
        ecn,
        eifel::{self, RetransmitCause},
        frto::{self, FrtoPhase},
        sack,
        types::{TcpControlBlock, TcpDatagramHeader, TcpError, TcpState},
    },
    TcpDriver,
};
use crate::subsystem::{
    clock::time::{Duration, Instant},
    scheduler::{current_thread, yield_to_scheduler},
    sync::IrqGuardedRwLock,
};

impl TcpDriver {
    /// Checks whether the head of the retransmission queue has been
    /// outstanding longer than the current RTO, and if so, runs the
    /// full RTO response.
    pub(crate) fn tick_retransmission_timer(&self, tcb: &mut TcpControlBlock) -> bool {
        // If the connection is closed, we can't send any data.
        if tcb.state == TcpState::Closed {
            return false;
        }

        let now = Instant::now();
        let flight = tcb.flight_size_bytes();

        let (seq, rto_retrans_end, send_time, retries) = {
            let Some(seg) = tcb.retransmission_queue.front() else {
                return false;
            };

            (seg.seq, seg.end_seq(), seg.send_time, seg.retries)
        };

        // If segment at front of the queue didn't exceed RTO, other segments neither, so
        // just return.
        if now - send_time < tcb.rto {
            return false;
        }

        // We can retransmit for 5 times - if we don't get a response, just close the connection.
        if retries >= 5 {
            tcb.state = TcpState::Closed;
            tcb.last_error = Some(TcpError::Timeout);

            tcb.event.notify();

            return false;
        }

        // Nested RTO during F-RTO (RFC 5682): abort F-RTO as "not spurious"
        // and fall through into conventional retransmit.
        let frto_nested_abort = !tcb.ts.enabled && tcb.frto.phase != FrtoPhase::Idle;
        if frto_nested_abort {
            tcb.frto.declared_loss_count = tcb.frto.declared_loss_count.saturating_add(1);
            tcb.frto.clear();

            log::trace!("nested RTO -> abort, conventional recovery {:?}", tcb.tuple);
        }

        if let Some(seg) = tcb.retransmission_queue.front_mut() {
            // Update send time and increment retries count.
            seg.send_time = now;
            seg.retries += 1;
        }

        // If we got RTO, we have to abort "soft" recovery methods, like Fast Recovery,
        // and get back to the Slow Start.
        tcb.in_fast_recovery = false;
        tcb.duplicate_ack_count = 0;

        // Arm spurious RTO detectors: Eifel when Timestamps are enabled, and F-RTO otherwise.
        if tcb.ts.enabled {
            eifel::eifel_on_rto_before_md(tcb);
        } else if !frto_nested_abort {
            frto::frto_on_rto(tcb, rto_retrans_end);
        } else {
            eifel::eifel_clear_pending(tcb);
        }

        let smss = tcb.effective_mss.max(1);
        match tcb.congestion_control {
            CongestionControl::Cubic(ref mut cubic) => {
                let beta = cubic.beta as u64;
                let ss = ((flight as u64 * beta) >> 10) as u32;

                tcb.ssthresh = ss.max(2 * smss);
                tcb.cwnd = smss;
                tcb.cwv.cwnd_raw = smss;

                cubic.epoch_start = Instant::now();
                cubic.k_ns = 0;
                cubic.w_max = tcb.ssthresh;
                cubic.last_max_cwnd = tcb.ssthresh;
                cubic.recover = 0;
            }
            CongestionControl::Reno(ref mut reno) => {
                tcb.ssthresh = (flight / 2).max(2 * smss);
                tcb.cwnd = smss;
                tcb.cwv.cwnd_raw = smss;
                reno.recover = 0;
            }
        }
        tcb.abc.clear_accumulators();

        // RFC 6298 §5.5: exponential backoff, capped at 60s.
        let doubled = Duration::from_nanos(tcb.rto.as_nanos().saturating_mul(2));
        tcb.rto = doubled.min(Duration::from_secs(60));

        // Reset the RTT probe for lost packet.
        if let Some(p) = tcb.rtt_m.probe
            && p.seq == seq
        {
            tcb.rtt_m.probe = None;
        }

        true
    }

    /// The timer thread's main loop. Every ~20ms, walks every connection
    /// and checks, per TCB: RTO retransmission, Tail Loss Probe deadline,
    /// zero-window, persist probing, keepalive, delayed-ACK deadline, and
    /// whether a paced send is due to resume.
    pub fn tcp_timer_thread(&self) -> ! {
        log::info!("TCP: Timer thread started");

        loop {
            let now = Instant::now();

            let tcb_list: Vec<_> = self.connections.read().values().cloned().collect();
            let mut remove_tuples = Vec::new();

            for tcb_arc in &tcb_list {
                let retransmit;
                let mut window_probe = false;
                let keepalive;
                let mut delayed_ack = false;
                let mut pacing_release = false;
                let mut tlp_fire = false;

                {
                    // skip entries being currently processed in some other thread.
                    let Some(mut tcb) = tcb_arc.try_write() else {
                        continue;
                    };

                    // Remove connection with closed state from the table.
                    if tcb.state == TcpState::Closed {
                        remove_tuples.push(tcb.tuple);
                        continue;
                    }

                    // Tick retransmission timer.
                    retransmit = self.tick_retransmission_timer(&mut tcb);

                    // Dont fire a TLP probe when retransmission timer did its job.
                    if !retransmit
                        && let Some(deadline) = tcb.sack.tlp_deadline
                        && now >= deadline
                    {
                        tlp_fire = true;
                        tcb.sack.tlp_deadline = None;
                    }

                    // Handle persist timer.
                    if let Some(deadline) = tcb.persist_timer
                        && now >= deadline
                    {
                        // Send windor probe if we have something to send.
                        window_probe = !tcb.send_buffer.is_empty();

                        // Backoff behaviour
                        let duration =
                            Duration::from_nanos(tcb.persist_backoff.as_nanos().saturating_mul(2));
                        tcb.persist_backoff = duration.min(Duration::from_secs(60));
                        tcb.persist_timer = Some(now + tcb.persist_backoff);
                    }

                    keepalive = self.tick_keepalive_timer(&mut tcb, now);

                    if let Some(deadline) = tcb.ack_deadline
                        && now >= deadline
                    {
                        delayed_ack = true;
                        tcb.ack_deadline = None;
                        tcb.ack_needed = false;
                        tcb.unacked_segments = 0;
                    }

                    // Resume paced new-data when the inter-packet gap elapses.
                    if tcb.pacing.enabled
                        && !tcb.send_buffer.is_empty()
                        && tcb.pacing.next_tx.map(|d| now >= d).unwrap_or(true)
                    {
                        pacing_release = true;
                    }

                    if tcb.state == TcpState::TimeWait
                        && let Some(dl) = tcb.timewait_deadline
                        && now >= dl
                    {
                        tcb.state = TcpState::Closed;
                        tcb.event.notify();
                    }

                    if tcb.state == TcpState::Closed {
                        remove_tuples.push(tcb.tuple);
                    }
                }

                if delayed_ack {
                    self.send_immediate_ack_unlocked(tcb_arc);
                }
                if retransmit {
                    self.retransmit_front_unlocked(tcb_arc, RetransmitCause::Rto);
                }
                if tlp_fire {
                    sack::tlp_send_probe_unlocked(self, tcb_arc);
                }
                if window_probe {
                    self.send_window_probe_unlocked(tcb_arc);
                }
                if keepalive {
                    self.send_keepalive_probe_unlocked(tcb_arc);
                }
                if pacing_release {
                    self.process_send_queue(tcb_arc.clone());
                }
            }

            if !remove_tuples.is_empty()
                && let Some(mut conns) = self.connections.try_write()
            {
                for tuple in remove_tuples {
                    conns.remove(&tuple);
                }
            }

            // @TODO: sleep until min(next_tx)?
            //current_thread().sleep(Duration::from_millis(20));
            yield_to_scheduler();
        }
    }

    /// Checks whether a keepalive probe is due: arms after
    /// `KEEPALIVE_IDLE` of no received traffic, then fires every
    /// `KEEPALIVE_INTERVAL` up to `KEEPALIVE_MAX_PROBES` times before
    /// giving up on the connection as timed out.
    fn tick_keepalive_timer(&self, tcb: &mut TcpControlBlock, now: Instant) -> bool {
        const KEEPALIVE_IDLE: Duration = Duration::from_secs(30);
        const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(5);
        const KEEPALIVE_MAX_PROBES: u32 = 3;

        if tcb.state != TcpState::Established {
            tcb.keepalive_deadline = None;
            return false;
        }

        if tcb.keepalive_deadline.is_none() {
            if now - tcb.last_rx_time >= KEEPALIVE_IDLE {
                tcb.keepalive_deadline = Some(now);
            } else {
                return false;
            }
        }

        let deadline = match tcb.keepalive_deadline {
            Some(d) => d,
            None => return false,
        };
        if now < deadline {
            return false;
        }

        if tcb.keepalive_count >= KEEPALIVE_MAX_PROBES {
            tcb.state = TcpState::Closed;
            tcb.last_error = Some(TcpError::Timeout);
            tcb.event.notify();
            tcb.keepalive_deadline = None;

            return false;
        }

        tcb.keepalive_count += 1;
        tcb.keepalive_deadline = Some(now + KEEPALIVE_INTERVAL);
        true
    }

    /// Sends a keepalive probe: an ACK for one sequence number before
    /// `snd_nxt`, which is outside the window the peer has already
    /// acked, and so reliably provokes a response even though it
    /// carries no real data.
    pub(crate) fn send_keepalive_probe_unlocked(
        &self,
        tcb_arc: &Arc<IrqGuardedRwLock<TcpControlBlock>>,
    ) {
        let (socket, mut hdr, opts, tos) = {
            let mut tcb = tcb_arc.write();

            let mut hdr = TcpDatagramHeader::new(&tcb);
            hdr.set_flag(TcpDatagramHeader::ACK, true);
            hdr.set_sequence_number(tcb.snd_una.wrapping_sub(1));

            let (opts, _) = super::send::established_outgoing_options(&mut tcb);
            let tos = ecn::apply_outgoing_ecn(&mut tcb, &mut hdr, &[]);

            (tcb.socket, hdr, opts, tos)
        };

        self.net_send_tcp_datagram_with_options(socket, &mut hdr, &opts, &[], tos);
    }

    /// Sends a zero-window probe: one byte of real
    /// send-buffer data, sent even though the peer's advertised window
    /// is zero, purely to provoke a fresh window update in
    /// case the one that would have opened it got lost.
    pub(crate) fn send_window_probe_unlocked(
        &self,
        tcb_arc: &Arc<IrqGuardedRwLock<TcpControlBlock>>,
    ) {
        let packet = {
            let mut tcb = tcb_arc.write();

            if tcb.send_buffer.is_empty() {
                None
            } else {
                let probe = [tcb.send_buffer[0]];

                let mut hdr = TcpDatagramHeader::new(&tcb);
                hdr.set_flag(TcpDatagramHeader::ACK, true);
                hdr.set_acknowledgement_number(tcb.rcv_nxt);
                hdr.set_sequence_number(tcb.snd_nxt);

                let (opts, _) = super::send::established_outgoing_options(&mut tcb);
                let tos = ecn::apply_outgoing_ecn(&mut tcb, &mut hdr, &probe);

                Some((tcb.socket, hdr, probe, opts, tos))
            }
        };

        if let Some((socket, mut hdr, probe, opts, tos)) = packet {
            self.net_send_tcp_datagram_with_options(socket, &mut hdr, &opts, &probe, tos);
        }
    }
}
