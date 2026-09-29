//! Incoming-segment processing: handshake completion, established-state
//! ACK/data handling, and the top-level dispatch by connection state.

use alloc::{sync::Arc, vec::Vec};

use x86_64::instructions::random::RdRand;
use zerocopy::FromBytes;

use super::{
    super::{
        cc::{self, CongestionControl},
        checksum,
        ecn::IP_ECN_CE,
        eifel::{self},
        frto::{self},
        options::{TcpOption, TcpOptionsParser, TcpOptionsWriter},
        sack::{self},
        timestamp::{self},
        types::{
            ConnectionTuple, DEFAULT_MSS, TcpControlBlock, TcpDatagramHeader, TcpError, TcpState,
            UnackedSegment,
        },
    },
    TcpDriver,
};
use crate::{
    driver::net::{
        Ipv4Addr, NetworkInterfaceId, Socket,
        proto::{PacketBuffer, tcp_socket},
    },
    kernel::kernel_ref,
    subsystem::{
        clock::time::{Duration, Instant},
        sync::IrqGuardedRwLock,
    },
};

/// Reads MSS, Window Scale, Timestamps, and SACK-Permitted out of a
/// peer's options and applies them to the TCB.
pub(super) fn apply_peer_tcp_options(tcb: &mut TcpControlBlock, options: &[u8], seg_seq: u32) {
    for opt in TcpOptionsParser::new(options) {
        match opt {
            TcpOption::Mss(mss) => {
                tcb.peer_mss = mss;

                log::trace!("Peer MSS = {}", mss);
            }
            TcpOption::WindowScale(shift) => {
                tcb.snd_wscale = shift.min(14); // 14 is max
                tcb.wnd_scale_enabled = true;

                log::trace!("Peer Window Scale = {}", shift);
            }
            TcpOption::Timestamp { tsval, .. } => {
                tcb.ts.enabled = true;
                tcb.ts.ts_recent = tsval;
                tcb.ts.last_ack_ts_seq = seg_seq;
                tcb.ts.recent_age = Instant::now();

                log::trace!("Peer Timestamps enabled, TS.Recent={}", tsval);
            }
            TcpOption::SackPermitted => {
                tcb.sack.enabled = true;

                log::trace!("Peer SACK-Permitted, SACK enabled {:?}", tcb.tuple);
            }
            _ => {}
        }
    }

    // Recompute effective MSS, because Timestamp/MSS may have changed it.
    tcb.recompute_effective_mss();
}

impl TcpDriver {
    /// Handles an incoming SYN-ACK.
    ///
    /// Three outcomes depending on what arrives:
    /// - RST: the peer refused the connection - tear down and report
    ///   `ConnectionReset`.
    /// - We're already `Established`: this is a retransmitted SYN-ACK
    ///   (our final ACK must have been lost) - just re-send the ACK, no
    ///   state change.
    /// - We're in `SynSent` with an acceptable ACK: complete the
    ///   handshake - negotiate options and move to `Established`.
    ///
    /// Anything else (wrong state, unacceptable ACK) is either ignored
    /// or answered with a challenge RST, per RFC 9293 §3.10.7.3.
    fn process_syn_ack(
        &self,
        tcb: &Arc<IrqGuardedRwLock<TcpControlBlock>>,
        header: &TcpDatagramHeader,
        options: &[u8],
    ) {
        let mut t = tcb.write();

        if header.is_rst() {
            // 1) RFC 9293 §3.5.2: a RST in response to our SYN means the peer
            // actively refused the connection (e.g. nothing listening there).
            t.state = TcpState::Closed;
            t.last_error = Some(TcpError::ConnectionReset);

            t.retransmission_queue.clear();
            t.rtt_m.probe = None;
            t.event.notify();
            t.handshake_gate.open();

            return;
        }

        if t.state == TcpState::Established {
            // 2) We already finished the handshake; the peer is most likely
            // retransmitting its SYN-ACK because our final ACK never
            // reached them - so retransmit our ACK (because sending
            // ACK is always safe)
            let mut hdr = TcpDatagramHeader::new(&t);
            hdr.set_flag(TcpDatagramHeader::ACK, true);

            let _ = self.net_send_from_tcb(&mut t, &mut hdr, &[]);

            return;
        }

        if t.state != TcpState::SynSent {
            return; // stray SYN-ACK for a connection that has moved past this stage
        }

        // RFC 9293 §3.10.7.3: the ACK field of a SYN-ACK must acknowledge our
        // SYN, i.e. SND.UNA < SEG.ACK <= SND.NXT. Anything else doesn't
        // belong to this handshake attempt and gets challenged with a RST.
        if !t.is_acceptable_ack(header.ack_number.get()) {
            let tuple = t.tuple;
            let nic = t.socket.nic();

            drop(t);

            self.send_standalone_rst(tuple, header, nic);

            return;
        }

        // The segment is now validated and ready to process.
        let seq = header.sequence_number.get();
        let ack = header.ack_number.get();
        let wire_wnd = header.window_size.get();

        // Parse Timestamps/MSS/etc from the SYN-ACK header.
        apply_peer_tcp_options(&mut t, options, seq);

        // If peer offered Timestamps, then enable the feature on this connection
        // and initialize PAWS / RTT estimators.
        if let Some((tsval, tsecr)) = timestamp::find_timestamp(options) {
            t.ts.enabled = true;

            let _ = timestamp::on_rx_timestamp(&mut t, seq, tsval, true, false);

            // It should be always true, but just for safety reasons.
            if tsecr != 0 {
                let rtt_ms = timestamp::tcp_ts_now(t.ts.offset).wrapping_sub(tsecr);

                // Safety check: RTT should be bigger than 0 always, and less than 60s.
                if rtt_ms > 0 && rtt_ms < 60_000 {
                    let r = Duration::from_millis(rtt_ms as u64);
                    t.rtt_m.last_ts_sample = Some(r);

                    // Update RTT estimators based on the received timestamp.
                    timestamp::update_rtt_estimators(&mut t, r);
                }
            }

            // Recompute MSS as Timestamp might have changed the max option size.
            // @TODO: Is it necessary here?
            t.recompute_effective_mss();
        }

        // Complete the RTT probe armed in `connect()`.
        //
        // If timestamps are enabled, we have done it 5 lines before, but if they are not,
        // we need to complete first RTT measurement by hand.
        if let Some(probe) = t.rtt_m.probe.take()
            && (ack.wrapping_sub(probe.end) as i32) >= 0
        {
            let diff = Instant::now() - probe.sent_at;

            t.rtt_m.last_probe_sample = Some(diff);

            // If timestamps are enabled, ignore old RTT probe.
            if !t.ts.enabled {
                timestamp::update_rtt_estimators(&mut t, diff);

                log::trace!("RTT probe(SYN)={:?} {:?}", diff, t.tuple);
            }
        }

        // RFC 3168 §6.1.1: complete ECN negotiation on SYN-ACK with ECE=1, CWR=0.
        t.ecn.enabled =
            header.get_flag(TcpDatagramHeader::ECE) && !header.get_flag(TcpDatagramHeader::CWR);

        if t.ecn.enabled {
            log::trace!("ECN negotiated (active open) {:?}", t.tuple);
        }

        // Update internal counters.
        t.snd_wnd = t.scale_peer_window(wire_wnd);
        t.snd_wl1 = seq;
        t.snd_wl2 = ack;
        t.irs = seq;
        t.rcv_nxt = seq.wrapping_add(1);
        t.snd_una = ack;

        // Drain retransmission queue to avoid retransmitting SYN.
        self.drain_retransmission_queue(&mut t, ack);

        // Mark the connection as established, and wake up user mode threads.
        t.state = TcpState::Established;
        t.event.notify();

        // Send final ACK completing 3-way handshake.
        let mut hdr = TcpDatagramHeader::new(&t);
        hdr.set_flag(TcpDatagramHeader::ACK, true);

        log::trace!("Completed 3-way handshake for {:?}", t.tuple);

        let _ = self.net_send_from_tcb(&mut t, &mut hdr, &[]);

        // Wake up user thread calling connect(). The connection is now established and
        // ready to receive/send data.
        tcb.read().handshake_gate.open();
    }

    /// Handles an incoming SYN for a port we're listening on - creates a
    /// new TCB in `SynReceived` and replies with SYN-ACK.
    ///
    /// If nothing is listening on the port, replies with a
    /// standalone RST instead of creating any state.
    fn process_passive_syn(
        &self,
        tuple: ConnectionTuple,
        header: &TcpDatagramHeader,
        options: &[u8],
        nic: NetworkInterfaceId,
    ) {
        let Some(settings) = tcp_socket::listener_opts_for_port(self, tuple.local_port) else {
            self.send_standalone_rst(tuple, header, nic);
            return;
        };

        let iss = RdRand::new().unwrap().get_u32().unwrap();
        let socket = Socket::new(
            tuple.local_ip,
            tuple.local_port,
            tuple.remote_ip,
            tuple.remote_port,
            nic,
        );

        let mut tcb = TcpControlBlock::new(iss, tuple, socket, &settings);
        settings.apply_receive_path(&mut tcb);

        tcb.state = TcpState::SynReceived;
        tcb.irs = header.sequence_number.get();
        tcb.rcv_nxt = tcb.irs.wrapping_add(1);

        apply_peer_tcp_options(&mut tcb, options, header.sequence_number.get());

        // RFC 3168 §6.1.1: peer offered ECN iff SYN carried both ECE and CWR,
        // and we are willing to use ECN on this session.
        tcb.ecn.enabled = settings.ecn_enabled
            && header.get_flag(TcpDatagramHeader::ECE)
            && header.get_flag(TcpDatagramHeader::CWR);

        // Update SND.WND / WL* from the passive SYN (ACK may be 0 on SYN).
        let syn_seq = header.sequence_number.get();
        let syn_ack = header.ack_number.get();
        tcb.snd_wnd = tcb.scale_peer_window(header.window_size.get());
        tcb.snd_wl1 = syn_seq;
        tcb.snd_wl2 = syn_ack;
        tcb.snd_nxt = iss.wrapping_add(1);

        let tcb_arc = Arc::new(IrqGuardedRwLock::new(tcb.clone()));
        self.connections.write().insert(tuple, tcb_arc.clone());

        // Send SYN-ACK to complete the 3-way handshake.
        let mut hdr = TcpDatagramHeader::new(&tcb);
        hdr.set_sequence_number(iss);
        hdr.set_acknowledgement_number(tcb.rcv_nxt);
        hdr.set_flag(TcpDatagramHeader::SYN, true);
        hdr.set_flag(TcpDatagramHeader::ACK, true);

        // SYN-ACK: ECE=1, CWR=0 when accepting ECN (RFC 3168).
        if tcb.ecn.enabled {
            hdr.set_flag(TcpDatagramHeader::ECE, true);

            log::trace!("ECN negotiated (passive open) {:?}", tuple);
        }

        // Push negotiated options.
        let mut synack_ts = None;
        let mut opt_writer = TcpOptionsWriter::new();

        opt_writer.push_mss(DEFAULT_MSS);

        if settings.wnd_scale_enabled {
            opt_writer.push_window_scale(settings.rcv_wscale);
        }
        if settings.sack_enabled {
            opt_writer.push_sack_permitted();
        }
        if settings.timestamps_enabled && tcb.ts.enabled {
            let timestamp = timestamp::tcp_ts_now(tcb.ts.offset);
            opt_writer.push_timestamp(timestamp, tcb.ts.ts_recent);
            synack_ts = Some(timestamp);
        }

        let synack_opts = opt_writer.finish();

        {
            let mut t = tcb_arc.write();

            // Save timestamp value
            if let Some(timestamp) = synack_ts {
                t.ts.last_tx_tsval = timestamp;
            }

            // Push the SYN-ACK to the retransmission queue.
            t.retransmission_queue.push_back(UnackedSegment {
                seq: iss,
                data: Vec::new(),
                flags: hdr.flags,
                send_time: Instant::now(),
                retries: 0,
                retransmit_tsval: None,
                sacked: false,
                lost: false,
                xmit_mstamp: Instant::now(),
                retrans: false,
            });
        }

        log::trace!("Passive SYN for {:?}, sending SYN-ACK", tuple);

        // Send the segment to the remote host.
        self.net_send_tcp_datagram_with_options(socket, &mut hdr, synack_opts, &[], 0);
    }

    /// Handles the final ACK of a passive-open handshake (peer's response
    /// to our SYN-ACK).
    fn process_syn_received_ack(
        &self,
        tcb_arc: &Arc<IrqGuardedRwLock<TcpControlBlock>>,
        header: &TcpDatagramHeader,
        payload: &[u8],
        options: &[u8],
        ip_ecn: u8,
    ) {
        // RST always terminates the connection.
        if header.is_rst() {
            let mut tcb = tcb_arc.write();

            tcb.state = TcpState::Closed;
            tcb.last_error = Some(TcpError::ConnectionReset);

            tcb.event.notify();

            return;
        }

        let local_port = {
            let mut tcb = tcb_arc.write();

            if tcb.state != TcpState::SynReceived || !header.is_ack() {
                None
            } else {
                let ack = header.ack_number.get();

                if !tcb.is_acceptable_ack(ack) {
                    log::trace!("Invalid ACK in SynReceived for {:?}", tcb.tuple);

                    None
                } else {
                    tcb.snd_una = ack;

                    self.drain_retransmission_queue(&mut tcb, ack);

                    tcb.state = TcpState::Established;
                    tcb.event.notify();

                    Some(tcb.tuple.local_port)
                }
            }
        };

        if let Some(port) = local_port {
            crate::driver::net::proto::tcp_socket::enqueue_accepted_connection(
                self,
                port,
                tcb_arc.clone(),
            );

            // If ACK carries piggybacked data, just process it:
            if !payload.is_empty() || !options.is_empty() {
                self.process_data_datagram(payload, header, options, tcb_arc, ip_ecn);
            }
        }
    }

    /// The main established-connection segment handler. One incoming
    /// segment can carry any combination of: a cumulative ACK advancing
    /// the send window, a duplicate ACK signaling possible loss, SACK
    /// blocks, an ECN mark or echo, new data, a FIN, or nothing new at
    /// all, etc.
    ///
    /// This function, roughly, in order performs these checks:
    /// 1. Fast path: if the segment is a pure retransmit carrying
    ///    nothing past `RCV.NXT`, just re-ACK and bail out.
    /// 2. ECN receive-side: note CE marks (schedule an ECE echo),
    ///    clear the echo once CWR arrives.
    /// 3. Timestamps: PAWS check, RTT sample from TSecr if present.
    /// 4. ECN send-side: an ECE on this ACK is treated like a loss
    ///    for congestion control (MD), but with no retransmit.
    /// 5. ACK processing - three cases based on where `ack` falls
    ///    relative to `SND.UNA`:
    ///    - advances it (new data acked): grow cwnd (ABC/CWV), run
    ///      Eifel or F-RTO spurious-RTO checks, sample RTT, apply SACK
    ///      info and loss detection, drain the retransmission queue,
    ///      handle FIN-related state transitions, possibly end fast
    ///      recovery (RFC 6582) or note a partial ACK.
    ///    - equals it with no payload (duplicate ACK): bump the
    ///      dup-ACK counter, run SACK/RACK loss detection, and either
    ///      enter fast recovery (3 dupACKs or SACK/RACK evidence) or
    ///      inflate cwnd by one more SMSS.
    ///    - is behind it (stale ACK): just re-ACK to resync the peer.
    /// 6. Receive-side processing: if the ACK was acceptable and
    ///    there's payload/FIN to handle, checks the segment fits the
    ///    receive window, writes in-order data (or hands out-of-order
    ///    data to SACK), advances `RCV.NXT`, and decides whether to ACK
    ///    immediately or coalesce (RFC 1122 delayed ACK).
    fn process_data_datagram(
        &self,
        payload: &[u8],
        header: &TcpDatagramHeader,
        options: &[u8],
        tcb_arc: &Arc<IrqGuardedRwLock<TcpControlBlock>>,
        ip_ecn: u8,
    ) {
        let seq = header.sequence_number.get();
        let ce = (ip_ecn & 0b11) == IP_ECN_CE;
        let ece = header.get_flag(TcpDatagramHeader::ECE);
        let cwr = header.get_flag(TcpDatagramHeader::CWR);

        // Fast path: if the segment's last byte is already below RCV.NXT, it
        // carries nothing new - ACK again to resync the peer and drop it.
        if !payload.is_empty() && !header.is_rst() {
            let seg_end = seq.wrapping_add(payload.len() as u32);
            let rcv_nxt = tcb_arc.read().rcv_nxt;

            if (seg_end.wrapping_sub(rcv_nxt) as i32) <= 0 {
                // Still honour ECN, so congestion feedback is not lost on duplicates.
                if ce {
                    let mut tcb = tcb_arc.write();

                    if tcb.ecn.enabled {
                        tcb.ecn.ce_seen = tcb.ecn.ce_seen.saturating_add(1);
                        tcb.ecn.echo_pending = true;
                    }
                }

                self.send_immediate_ack_unlocked(tcb_arc);

                return;
            }
        }

        let mut tcb = tcb_arc.write();

        // RST always terminates the connection.
        if header.is_rst() {
            tcb.state = TcpState::Closed;
            tcb.last_error = Some(TcpError::ConnectionReset);

            tcb.event.notify();

            return;
        }

        // RFC 9293 §3.10.7.4: once past the handshake, every segment MUST
        // carry ACK.
        if !header.is_ack() {
            log::trace!(
                "drop segment without ACK in state {:?} seq={}",
                tcb.state,
                seq
            );

            return;
        }

        // ECN receive side: we have CE in IP header.
        //
        // CE means a router marked this packet instead of dropping it, and we need
        // to echo it back to the remote host.
        if tcb.ecn.enabled && ce {
            tcb.ecn.ce_seen = tcb.ecn.ce_seen.saturating_add(1);

            // RFC 3168 §6.1.3: set ECE on subsequent ACKs until CWR arrives.
            tcb.ecn.echo_pending = true;
        }

        // ECN receive side: if peer reduced their CWND, stop echoing ECN information.
        if tcb.ecn.enabled && cwr {
            tcb.ecn.echo_pending = false;
        }

        // RFC 7323 §3.2: after Timestamps are negotiated, require the option.
        let ts_opt = timestamp::find_timestamp(options);
        if tcb.ts.enabled && ts_opt.is_none() {
            log::trace!("drop segment without Timestamp option seq={}", seq);

            return;
        }

        if let Some((tsval, tsecr)) = ts_opt {
            // Pass the timestamp value to the dedicated function for state update. It also
            // checks PAWS, and returns false if we should drop the segment.
            if !timestamp::on_rx_timestamp(&mut tcb, seq, tsval, header.is_syn(), false) {
                return;
            }

            if tsecr != 0 {
                let rtt_ms = timestamp::tcp_ts_now(tcb.ts.offset).wrapping_sub(tsecr);

                // Sanity check: RTT should be always bigger than 0ms, and less than 60s (such
                // a slow link doesn't even exist, right...?)
                if (0..60_000).contains(&rtt_ms) {
                    let diff = Duration::from_millis(rtt_ms as u64);
                    tcb.rtt_m.last_ts_sample = Some(diff);

                    // Update RTT estimators from newly derived data.
                    timestamp::update_rtt_estimators(&mut tcb, diff);
                }
            }
        }

        // Parse SACK blocks.
        let (sack_blocks_buf, sack_nblocks) = sack::parse_sack_blocks(options);
        let sack_blocks = &sack_blocks_buf[..sack_nblocks];

        let ack = header.ack_number.get();
        let ack_acceptable = tcb.is_acceptable_ack(ack);

        // Mutable variables describing what to do once the TCB lock is dropped:
        // it's just easier to avoid nested locking and multiple deadlocks encountered
        // during the testing sessions with this.
        let mut send_ack = tcb.ecn.enabled && tcb.ecn.echo_pending && ce;
        let mut fast_retransmit = false;
        let mut dup_recovery_inflate = false;
        let mut partial_retransmit_ack: Option<u32> = None;
        let mut run_send_queue = false;

        // ECN send side:
        // ECE on an ACK -> reduce cwnd/ssthresh like a congestion event, but
        // do not retransmit (cause data was delivered; only a mark was set).
        if ack_acceptable && tcb.ecn.enabled && ece && !tcb.ecn.cwr_pending && !tcb.in_fast_recovery
        {
            // Tracing counters:
            tcb.ecn.ece_rx = tcb.ecn.ece_rx.saturating_add(1);
            tcb.ecn.ecn_md = tcb.ecn.ecn_md.saturating_add(1);

            // Reduce cwnd/ssthresh:
            cc::on_congestion_event(self, &mut tcb);

            // Echo CWR back to the sender.
            tcb.ecn.cwr_pending = true;

            run_send_queue = true;

            log::trace!(
                "ECN: ECE received - MD cwnd={} ssthresh={} {:?}",
                tcb.cwnd,
                tcb.ssthresh,
                tcb.tuple
            );
        }

        if !ack_acceptable {
            // RFC 9293 §3.10.7.4: ACK outside (SND.UNA, SND.NXT] doesn't
            // belong to this connection - send a challenge ACK to synchronize
            // remote.
            send_ack = true;
        } else if ack > tcb.snd_una {
            // ACK > SND.UNA --> new data acked
            let prev_snd_una = tcb.snd_una;

            if tcb.in_fast_recovery {
                let recover = match &tcb.congestion_control {
                    CongestionControl::Reno(r) => r.recover,
                    CongestionControl::Cubic(c) => c.recover,
                };

                // RFC 6582 (NewReno): an ACK covering the whole recovery
                // point ends Fast Recovery.
                if (ack.wrapping_sub(recover) as i32) >= 0 {
                    tcb.in_fast_recovery = false;

                    tcb.cwnd = tcb.ssthresh;
                    tcb.cwv.cwnd_raw = tcb.ssthresh;

                    tcb.abc.clear_accumulators();

                    log::trace!("Fast Recovery finished");
                } else {
                    let smss = tcb.effective_mss.max(1);

                    tcb.cwnd = tcb.ssthresh + 3 * smss;
                    tcb.cwv.cwnd_raw = tcb.cwnd;

                    partial_retransmit_ack = Some(ack);

                    log::trace!("TCP: Fast Recovery partial ACK (stay in recovery)");
                }
            }

            let had_unacked_fin = tcb.retransmission_queue.iter().any(|s| s.is_fin());
            let prior_state = tcb.state;

            // Update internal counters:
            tcb.snd_una = ack;
            tcb.duplicate_ack_count = 0;
            tcb.last_ack_received = ack;

            // Spurious RTO detection: Eifel or F-RTO (based on Timestamps).
            tcb.eifel.bytes_acked = ack.wrapping_sub(prev_snd_una);
            let bytes_acked = tcb.eifel.bytes_acked;
            if tcb.ts.enabled {
                eifel::eifel_on_acceptable_ack(&mut tcb, ts_opt.map(|(_, t)| t), ece);
            } else {
                frto::frto_on_ack(&mut tcb, ack, false);
            }

            // Advancing ACK always drains send queue below.

            // Complete Karn probe.
            if let Some(p) = tcb.rtt_m.probe
                && (ack.wrapping_sub(p.end) as i32) >= 0
            {
                let diff = Instant::now() - p.sent_at;

                tcb.rtt_m.probe = None;
                tcb.rtt_m.last_probe_sample = Some(diff);

                // Update RTT only if Timestamps are disabled: if enabled, we fed RTT previous with
                // more accurate data.
                if !tcb.ts.enabled {
                    timestamp::update_rtt_estimators(&mut tcb, diff);
                }
            }

            // RFC 3465 ABC: pass newly ACKed byte count into SS/CA growth.
            cc::update_congestion_window(&mut tcb, bytes_acked);

            // Parse SACK blocks.
            if tcb.sack.enabled {
                sack::sack_tx_apply(&mut tcb, ack, sack_blocks);
                sack::sack_mark_lost(&mut tcb);
                sack::rack_detect(&mut tcb);

                // If SACK detected any loss and we're not in Fast Recovery yet,
                // trigger the congestion event.
                if !tcb.in_fast_recovery && sack::sack_has_lost(&tcb) {
                    sack::sack_enter_recovery(&mut tcb);

                    tcb.in_fast_recovery = true;

                    cc::on_congestion_event(self, &mut tcb);

                    fast_retransmit = true;

                    log::trace!(
                        "SACK: loss detected on advancing ACK, entering recovery {:?}",
                        tcb.tuple
                    );
                }
            }

            // Remove ACKed segments from retransmission queue.
            self.drain_retransmission_queue(&mut tcb, ack);

            // After every ACK advancing the SND.NXT, we need to process
            // send queue without waiting for any timer to expire.
            run_send_queue = true;

            // RFC 8985 §7.1: any forward progress on SND.UNA re-arms the
            // Tail Loss Probe.
            sack::tlp_arm(&mut tcb);

            // Once our own FIN is ACKed, make the state transition based on prior state.
            if had_unacked_fin && !tcb.retransmission_queue.iter().any(|s| s.is_fin()) {
                match prior_state {
                    TcpState::FinWait1 => {
                        tcb.state = TcpState::FinWait2;

                        log::trace!("FinWait1 -> FinWait2 (FIN ACKed)");
                    }
                    TcpState::Closing => {
                        tcb.state = TcpState::TimeWait;

                        tcb.timewait_deadline = Some(Instant::now() + Duration::from_secs(120));

                        log::trace!("Closing -> TimeWait (FIN ACKed)");
                    }
                    TcpState::LastAck => {
                        tcb.state = TcpState::Closed;

                        tcb.event.notify();

                        log::trace!("LastAck -> Closed (FIN ACKed)");
                    }
                    _ => {}
                }
            }
        } else if ack == tcb.snd_una && payload.is_empty() && !tcb.retransmission_queue.is_empty() {
            // Duplicate ACK
            //
            // RFC 5681 §3.2: three duplicate ACKs for the same sequence
            // number are taken as a probable loss signal, and we
            // retransmit without waiting for the RTO timer to expire.

            tcb.duplicate_ack_count += 1;

            log::trace!(
                "dup ACK {:?} ack={} count={}",
                tcb.tuple,
                ack,
                tcb.duplicate_ack_count
            );

            // Feed F-RTO state machine with duplicated ACK.
            if !tcb.ts.enabled {
                frto::frto_on_ack(&mut tcb, ack, true);
            }

            // RFC 6675: a duplicate ACK is exactly where fresh SACK
            // information about the peer's receive-side scoreboard shows up,
            // so update our sender-side scoreboard and re-run loss detection
            // on every one.
            let sack_lost_now = if tcb.sack.enabled {
                sack::sack_tx_apply(&mut tcb, ack, sack_blocks);
                sack::sack_mark_lost(&mut tcb);
                sack::rack_detect(&mut tcb);

                sack::sack_has_lost(&tcb)
            } else {
                false
            };

            // If we're not in Fast Recovery and DupACK count == 3, then enter Fast Recovery and
            // indicate congestion event:
            if !tcb.in_fast_recovery && (tcb.duplicate_ack_count == 3 || sack_lost_now) {
                log::trace!("3x Dup ACK for SEQ {}", ack);

                if tcb.sack.enabled {
                    sack::sack_enter_recovery(&mut tcb);
                }
                tcb.in_fast_recovery = true;
                cc::on_congestion_event(self, &mut tcb);
                fast_retransmit = true;
                run_send_queue = true;
            } else if tcb.in_fast_recovery {
                // Each further duplicate ACK means one more packet has left
                // the network, so there's room to put one more in flight
                // (the "artificial window inflation" step of Fast Recovery).
                let smss = tcb.effective_mss.max(1);

                tcb.cwnd = tcb.cwnd.saturating_add(smss);
                tcb.cwv.cwnd_raw = tcb.cwv.cwnd_raw.saturating_add(smss);

                dup_recovery_inflate = true;
                run_send_queue = true;
            }
        } else if ack < tcb.snd_una {
            // ACK for the data we already marked as ACKed - send challenge ACK to resync
            // the peer.

            log::trace!(
                "stale ACK {:?} ack={} snd_una={}",
                tcb.tuple,
                ack,
                tcb.snd_una
            );

            send_ack = true;
        }

        // If ACK is acceptable, payload is not empty, it's not FIN and the packet is not
        // sent just to indicate the error in send state (fast retransmit), process the
        // data in the segment.
        let process_receive = ack_acceptable
            && (!payload.is_empty()
                || header.is_fin()
                || (!send_ack && !fast_retransmit && !dup_recovery_inflate));

        if process_receive {
            if !tcb.is_segment_acceptable(seq, payload.len() as u32) {
                // If segment is not acceptable, just send the challenge ACK and don't
                // proceed with parsing.
                send_ack = true;
            } else {
                // Update sender window
                tcb.maybe_update_send_window(seq, ack, header.window_size.get());

                // Update the counters, as we have just received valid packet from
                // the remote.
                tcb.last_rx_time = Instant::now();
                tcb.keepalive_count = 0;
                tcb.keepalive_deadline = None;

                if !payload.is_empty() {
                    if seq != tcb.rcv_nxt {
                        // If SEQ != RCV.NXT, it's an out-of-order packet.
                        //
                        // If SACK is enabled, then copy the data into the receive buffer
                        // and record it in the scoreboard, but don't make it accessible for
                        // the user yet.
                        if tcb.sack.enabled {
                            sack::sack_receive_out_of_order(&mut tcb, seq, payload);

                            // Update receive window, as we copied some data into the buffer.
                            tcb.update_rcv_wnd_from_buffer();
                        }

                        // RFC 2018: An out-of-order segment must trigger an immediate dupACK.
                        send_ack = true;
                    } else {
                        let n = if tcb.sack.enabled {
                            let rcv_nxt = tcb.rcv_nxt;
                            tcb.receive_buffer.write_at(rcv_nxt, seq, payload)
                        } else {
                            tcb.receive_buffer.write(payload)
                        };

                        if n == 0 {
                            // Receive buffer is full - nothing to do,
                            // but send ACK to tell the remote we have zero-window.
                            send_ack = true;
                        } else {
                            let old_rcv_nxt = tcb.rcv_nxt;
                            tcb.rcv_nxt = tcb.rcv_nxt.wrapping_add(n as u32);

                            if tcb.sack.enabled {
                                // A previously out-of-order range may now be
                                // exactly adjacent to the new RCV.NXT - run SACK
                                // merging routine.
                                sack::sack_rx_advance_from_scoreboard(&mut tcb);
                            }

                            log::trace!(
                                "RX data {:?} seq={} len={} stored={} rcv_nxt {} -> {}",
                                tcb.tuple,
                                seq,
                                payload.len(),
                                n,
                                old_rcv_nxt,
                                tcb.rcv_nxt
                            );

                            // Update receive window based on newly arrived data.
                            tcb.update_rcv_wnd_from_buffer();

                            // We need to ACK the data, so set `ack_needed`.
                            tcb.ack_needed = true;
                            tcb.unacked_segments += 1;
                        }
                    }
                } else if tcb.rcv_wnd == 0 {
                    tcb.ack_needed = true;
                    tcb.unacked_segments += 1;
                }

                if header.is_fin() {
                    tcb.handle_fin_flag();
                    tcb.ack_needed = true;
                }

                if tcb.ack_needed {
                    // RFC 1122 §4.2.3.2: ACK immediately for PSH, FIN, a
                    // zero window, or once two segments are outstanding;
                    // otherwise coalesce ACKs for up to 40ms (delayed ACK).
                    if header.get_flag(TcpDatagramHeader::PSH)
                        || header.is_fin()
                        || tcb.rcv_wnd == 0
                        || tcb.unacked_segments >= 2
                    {
                        send_ack = true;
                        tcb.ack_needed = false;
                        tcb.unacked_segments = 0;
                        tcb.ack_deadline = None;
                    } else {
                        tcb.ack_deadline = Some(Instant::now() + Duration::from_millis(40));
                    }
                }

                if !payload.is_empty() || header.is_fin() {
                    tcb.event.notify();
                }

                run_send_queue = true;
            }
        }

        drop(tcb);

        // Fixed order: ACK first, then retransmits, then
        //  anything of ours still waiting to go out.
        if send_ack {
            self.send_immediate_ack_unlocked(tcb_arc);
        }
        if fast_retransmit {
            self.fast_retransmit_front(tcb_arc);
        }
        if let Some(ack) = partial_retransmit_ack {
            self.retransmit_first_partial_ack(tcb_arc, ack);
        }
        if run_send_queue {
            self.process_send_queue(tcb_arc.clone());
        }
    }

    /// Entry point for every incoming TCP segment: verifies the checksum,
    /// looks up (or creates) the connection's TCB by 4-tuple, and
    /// dispatches to the right handler for the connection's current
    /// state.
    pub fn process_data(
        &self,
        sender_ip: Ipv4Addr,
        target_ip: Ipv4Addr,
        buffer: &mut PacketBuffer,
        nic: NetworkInterfaceId,
        ip_ecn: u8,
    ) -> Result<(), ()> {
        let frame_len = buffer.frame().len();

        let local_ip = kernel_ref()
            .network_subsystem()
            .interfaces()
            .get(nic)
            .ok_or(())?
            .local_internet_address
            .unwrap_or(Ipv4Addr::unspecified());

        {
            let frame = buffer.payload_mut();
            if frame.len() < 20 {
                return Err(());
            }

            let (hdr, _) = TcpDatagramHeader::read_from_prefix(frame).map_err(|_| ())?;
            let hdr_len = hdr.header_len_bytes();
            if frame.len() < hdr_len {
                return Err(());
            }

            let wire_csum = hdr.checksum.get();
            frame[16] = 0;
            frame[17] = 0;
            let computed = checksum::calculate_tcp_checksum(
                sender_ip.octets(),
                target_ip.octets(),
                &frame[..hdr_len],
                &frame[hdr_len..],
            );
            frame[16] = (wire_csum >> 8) as u8;
            frame[17] = wire_csum as u8;
            if computed != wire_csum {
                log::warn!(
                    "bad checksum {}:{} -> {}:{} flags=0x{:02x} seq={} ack={} wire=0x{:04x} calc=0x{:04x} iface_ip={}",
                    sender_ip,
                    hdr.source_port.get(),
                    target_ip,
                    hdr.dest_port.get(),
                    hdr.flags,
                    hdr.sequence_number.get(),
                    hdr.ack_number.get(),
                    wire_csum,
                    computed,
                    local_ip
                );

                return Ok(());
            }

            let options = &frame[20..hdr_len];
            let payload = &frame[hdr_len..];

            let tuple = ConnectionTuple {
                local_ip: target_ip,
                local_port: hdr.dest_port.get(),
                remote_ip: sender_ip,
                remote_port: hdr.source_port.get(),
            };

            let tcb_arc = self.connections.read().get(&tuple).cloned();

            if let Some(tcb_arc) = tcb_arc {
                let state = tcb_arc.read().state;

                if hdr.is_syn() || hdr.is_ack() || hdr.is_rst() || hdr.is_fin() {
                    log::trace!(
                        "RX {:?} state={:?} flags=0x{:02x} seq={} ack={} len={}",
                        tuple,
                        state,
                        hdr.flags,
                        hdr.sequence_number.get(),
                        hdr.ack_number.get(),
                        payload.len()
                    );
                }

                match state {
                    TcpState::SynSent => {
                        if hdr.is_rst() {
                            log::trace!("RST during connect {:?} flags=0x{:02x}", tuple, hdr.flags);

                            self.abort_connection(tuple, TcpError::ConnectionReset);
                        } else if hdr.is_syn() && hdr.is_ack() {
                            self.process_syn_ack(&tcb_arc, &hdr, options);
                        }
                    }
                    TcpState::SynReceived => {
                        self.process_syn_received_ack(&tcb_arc, &hdr, payload, options, ip_ecn);
                    }
                    TcpState::Established => {
                        // If our handshake ACK was lost, the peer may re-send its
                        // SYN-ACK; process_syn_ack's Established branch answers
                        // it with another ACK regardless of whether this is the
                        // first or a later retransmit.
                        if hdr.is_syn() && hdr.is_ack() {
                            self.process_syn_ack(&tcb_arc, &hdr, options);
                        } else {
                            self.process_data_datagram(payload, &hdr, options, &tcb_arc, ip_ecn);
                        }
                    }
                    TcpState::FinWait1
                    | TcpState::FinWait2
                    | TcpState::CloseWait
                    | TcpState::Closing
                    | TcpState::LastAck => {
                        self.process_data_datagram(payload, &hdr, options, &tcb_arc, ip_ecn)
                    }

                    TcpState::TimeWait if hdr.is_fin() => {
                        tcb_arc.write().timewait_deadline =
                            Some(Instant::now() + Duration::from_secs(120));

                        self.send_immediate_ack_unlocked(&tcb_arc);
                    }
                    _ => {}
                }
            } else {
                if hdr.is_rst() {
                    return Ok(());
                }

                log::trace!(
                    "no TCB for {}:{} -> {}:{} flags=0x{:02x} seq={} ack={} len={}",
                    sender_ip,
                    hdr.source_port.get(),
                    local_ip,
                    hdr.dest_port.get(),
                    hdr.flags,
                    hdr.sequence_number.get(),
                    hdr.ack_number.get(),
                    payload.len()
                );

                if hdr.is_syn() && !hdr.is_ack() {
                    self.process_passive_syn(tuple, &hdr, options, nic);
                } else {
                    self.send_standalone_rst(tuple, &hdr, nic);
                }
            }
        }

        buffer.consume_bytes(frame_len);

        Ok(())
    }
}
