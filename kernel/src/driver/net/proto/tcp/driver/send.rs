//! Outgoing-segment construction and the send path: building headers
//! and options, the main [`process_send_queue`](TcpDriver::process_send_queue)
//! loop that turns buffered app data into segments (respecting Nagle,
//! the congestion/receive window, and pacing), plus connection close,
//! RST, and window-update helpers.

use alloc::{sync::Arc, vec::Vec};

use zerocopy::{
    IntoBytes,
    network_endian::{U16, U32},
};

use super::{
    super::{
        checksum, cwv, ecn,
        frto::FrtoPhase,
        options::{TCP_OPTS_MAX, TcpOptionsWriter},
        pacing,
        sack::{self, SACK_RX_RANGES_MAX, SackBlock},
        timestamp::{self, RttProbe},
        types::{
            ConnectionTuple, TcpControlBlock, TcpDatagramHeader, TcpError, TcpState, UnackedSegment,
        },
    },
    TcpDriver,
};
use crate::{
    driver::net::{
        NetworkInterfaceId, Socket,
        proto::{DEFAULT_HEADER_RESERVE, PacketBuffer, SLOT_SIZE, ip::IpProtocol},
    },
    kernel::kernel_ref,
    subsystem::{
        clock::time::{Duration, Instant},
        sync::IrqGuardedRwLock,
    },
};

/// Builds the options block for a normal established-state segment:
/// Timestamps and up to as many SACK blocks as fit in the remaining budget.
pub(crate) fn established_outgoing_options(tcb: &mut TcpControlBlock) -> (Vec<u8>, Option<u32>) {
    let mut writer = TcpOptionsWriter::new();
    let mut tsval_out = None;

    // If timestamps are negotiated, put current timestamp value and echo
    // recent timestamp value back.
    if tcb.ts.enabled {
        let tsval = timestamp::tcp_ts_now(tcb.ts.offset);
        tcb.ts.last_tx_tsval = tsval;
        writer.push_timestamp(tsval, tcb.ts.ts_recent);
        tsval_out = Some(tsval);
    }

    // Report up to 4 SACK blocks, if SACK negotiated and we have
    // anything to SACK.
    if tcb.sack.enabled && tcb.sack.rx_range_len > 0 {
        let mut ordered = [SackBlock::default(); SACK_RX_RANGES_MAX];
        let mut n = 0usize;

        // First SACK always have to be recent.
        if let Some(recent) = tcb.sack.rx_recent {
            ordered[0] = recent;
            n = 1;
        }

        for i in 0..tcb.sack.rx_range_len as usize {
            let b = tcb.sack.rx_ranges[i];
            if Some(b) != tcb.sack.rx_recent {
                ordered[n] = b;
                n += 1;
            }
        }

        let budget = TCP_OPTS_MAX.saturating_sub(writer.written());
        let written_before = writer.written();

        writer.push_sack_limited(&ordered[..n], budget);

        if writer.written() != written_before {
            tcb.sack.blocks_tx = tcb.sack.blocks_tx.saturating_add(1);
        }
    }

    (writer.finish().to_vec(), tsval_out)
}

impl TcpDriver {
    /// Sends `header`/`data` with the standard established-state options
    /// (Timestamps + SACK) and ECN marking already applied.
    pub(crate) fn net_send_from_tcb(
        &self,
        tcb: &mut TcpControlBlock,
        header: &mut TcpDatagramHeader,
        data: &[u8],
    ) -> Option<u32> {
        let (opts, tsval) = established_outgoing_options(tcb);
        let tos = ecn::apply_outgoing_ecn(tcb, header, data);
        let _ =
            self.net_send_tcp_datagram_with_options(tcb.socket, header, opts.as_slice(), data, tos);

        tsval
    }

    /// Sends a header with no options - used for the handful of cases
    /// (standalone RST, unconditional RST on teardown) that don't need
    /// Timestamps/SACK negotiated for this segment.
    pub(crate) fn net_send_tcp_datagram(
        &self,
        socket: Socket,
        header: &mut TcpDatagramHeader,
        data: &[u8],
    ) {
        self.net_send_tcp_datagram_with_options(socket, header, &[], data, 0);
    }

    /// Sends a bare ACK right now, bypassing the send queue - used
    /// wherever a segment needs to be acknowledged immediately rather
    /// than waiting for the delayed-ACK timer or the next data send.
    pub(crate) fn send_immediate_ack_unlocked(
        &self,
        tcb_arc: &Arc<IrqGuardedRwLock<TcpControlBlock>>,
    ) {
        let (socket, mut hdr, opts, tos) = {
            let mut tcb = tcb_arc.write();
            let mut hdr = TcpDatagramHeader::new(&tcb);
            hdr.set_flag(TcpDatagramHeader::ACK, true);

            let (opts, _) = established_outgoing_options(&mut tcb);

            let tos = ecn::apply_outgoing_ecn(&mut tcb, &mut hdr, &[]);
            (tcb.socket, hdr, opts, tos)
        };

        self.net_send_tcp_datagram_with_options(socket, &mut hdr, &opts, &[], tos);
    }

    /// Lowest-level send: fills in the Data Offset from `options.len()`,
    /// assembles header + options + payload into one contiguous buffer,
    /// computes the checksum over the assembled bytes, and hands it off
    /// to IPv4 for transmission.
    pub(crate) fn net_send_tcp_datagram_with_options(
        &self,
        socket: Socket,
        header: &mut TcpDatagramHeader,
        options: &[u8],
        data: &[u8],
        tos: u8,
    ) -> bool {
        let header_len = 20 + options.len();
        header.set_offset((header_len / 4) as u8);

        let mut header_buf = [0u8; 60];
        header_buf[..20].copy_from_slice(header.as_bytes());
        if !options.is_empty() {
            header_buf[20..header_len].copy_from_slice(options);
        }

        header.checksum = U16::from(checksum::calculate_tcp_checksum(
            socket.local_address().octets(),
            socket.remote_address().octets(),
            &header_buf[..header_len],
            data,
        ));

        header_buf[..20].copy_from_slice(header.as_bytes());

        let mut storage = [0u8; DEFAULT_HEADER_RESERVE + SLOT_SIZE];
        let mut packet_buffer = PacketBuffer::for_transmit(&mut storage, DEFAULT_HEADER_RESERVE);

        packet_buffer.append_data(data);
        if !options.is_empty() {
            packet_buffer.prepend_bytes(&header_buf[20..header_len]);
        }
        packet_buffer.prepend_header(header);

        let nic = socket.nic();
        let dst_ip = socket.remote_address();

        let network_subsystem = kernel_ref().network_subsystem();
        if let Err(()) = network_subsystem.ipv4().send_packet(
            IpProtocol::Tcp,
            &mut packet_buffer,
            dst_ip,
            nic,
            tos,
        ) {
            log::warn!("TCP: send_packet failed (dst={}, nic={:?})", dst_ip, nic);

            return false;
        }

        true
    }

    /// Starts an active close: queues a FIN and moves to
    /// `FinWait1`.
    pub fn close_connection(&self, tcb_arc: Arc<IrqGuardedRwLock<TcpControlBlock>>) {
        let fin_to_send = {
            let mut tcb = tcb_arc.write();
            let now = Instant::now();

            let (new_state, fin_seq) = match tcb.state {
                TcpState::Established | TcpState::SynReceived => {
                    log::trace!("Active Close for {:?}", tcb.tuple);

                    (TcpState::FinWait1, tcb.snd_nxt)
                }
                TcpState::CloseWait => {
                    log::trace!("Passive Close for {:?}", tcb.tuple);

                    (TcpState::LastAck, tcb.snd_nxt)
                }
                state => {
                    log::trace!("close() in state {:?} — ignored", state);
                    return;
                }
            };

            let mut fin_hdr = TcpDatagramHeader::new(&tcb);
            fin_hdr.set_flag(TcpDatagramHeader::FIN, true);
            fin_hdr.set_flag(TcpDatagramHeader::ACK, true);

            let (opts, _) = established_outgoing_options(&mut tcb);
            let tos = ecn::apply_outgoing_ecn(&mut tcb, &mut fin_hdr, &[]);

            tcb.retransmission_queue.push_back(UnackedSegment {
                seq: fin_seq,
                data: Vec::new(),
                // Don't persist CWR in the queue.
                flags: fin_hdr.flags & !TcpDatagramHeader::CWR,
                send_time: now,
                retries: 0,
                retransmit_tsval: None,
                sacked: false,
                lost: false,
                xmit_mstamp: now,
                retrans: false,
            });

            tcb.snd_nxt = tcb.snd_nxt.wrapping_add(1);
            tcb.state = new_state;

            (tcb.socket, fin_hdr, opts, tos)
        };

        let (socket, mut fin_hdr, opts, tos) = fin_to_send;
        self.net_send_tcp_datagram_with_options(socket, &mut fin_hdr, &opts, &[], tos);
    }

    /// Queues app data for sending and kicks off the send path.
    pub fn send_data(
        &self,
        tcb_arc: Arc<IrqGuardedRwLock<TcpControlBlock>>,
        data: &[u8],
    ) -> Result<(), TcpError> {
        {
            let mut tcb = tcb_arc.write();

            if tcb.state != TcpState::Established && tcb.state != TcpState::CloseWait {
                return Err(TcpError::NotConnected);
            }

            tcb.send_buffer.extend(data);
        }

        self.process_send_queue(tcb_arc);

        Ok(())
    }

    /// The core send loop: pulls as much as it can out of `send_buffer`
    /// and turns it into segments, sending to the remote host.
    ///
    /// Each iteration re-checks, in order:
    /// 1. Buffer empty - nothing to do; note we're application-limited
    ///    (RFC 7661 §4.1/§4.3) and clear any pacing deadline.
    /// 2. Pacing - if a gap from the last send hasn't elapsed yet,
    ///    hold (the timer thread will retry later).
    /// 3. Nagle - with unacked data outstanding and less than one
    ///    MSS buffered, hold the small write rather than sending a tiny
    ///    segment - except for the F-RTO Step2 probe, which must go out
    ///    regardless.
    /// 4. Window - if `min(cwnd, snd_wnd)` is already full or the
    ///    peer's window is zero, nothing can be sent; distinguishes
    ///    which window is the blocker for New CWV's bookkeeping, and
    ///    arms the zero-window persist timer if that's the cause.
    /// 5. Otherwise, carves off `min(buffered, window remaining, MSS)`
    ///    bytes, builds and queues the segment, updates New CWV's
    ///    validation state, re-arms the Tail Loss Probe, schedules the
    ///    pacing gap before the next segment, and sends it.
    pub(crate) fn process_send_queue(&self, tcb_arc: Arc<IrqGuardedRwLock<TcpControlBlock>>) {
        loop {
            let mut tcb = tcb_arc.write();

            if tcb.send_buffer.is_empty() {
                // Nothing queued: application-limited (RFC 7661 §§4.3).
                cwv::cwv_note_app_limited(&mut tcb);

                tcb.pacing.clear_deadline();

                return;
            }

            // Check whether we're allowed to send now or have to wait.
            if pacing::pacing_should_hold(&mut tcb, Instant::now()) {
                return;
            }

            let in_flight = tcb.snd_nxt.wrapping_sub(tcb.snd_una);
            tcb.cwv.pipe_max = tcb.cwv.pipe_max.max(in_flight);
            let mss = tcb.effective_mss as usize;

            // RFC 9293 §3.7.4 (Nagle's algorithm): while data from us is
            // still unacknowledged, hold small writes rather than sending
            // them as their own tiny segment.
            let frto_probe = tcb.frto.phase == FrtoPhase::Step2;
            if tcb.nagle_enabled && !frto_probe && in_flight > 0 && tcb.send_buffer.len() < mss {
                // We're sending less than CWND, so technically it's app-limited in terms of CWV.
                cwv::cwv_note_app_limited(&mut tcb);

                return;
            }

            let effective_wnd = tcb.snd_wnd.min(tcb.cwnd);

            // If amount of data sent but not yet ACKed is bigger than effective window, we can't
            // send any data.
            if effective_wnd <= in_flight || tcb.snd_wnd == 0 {
                // Distinguish, whether we're app limited or blocked by the CWND now.
                if tcb.snd_wnd > in_flight && tcb.cwnd <= in_flight {
                    cwv::cwv_note_validated(&mut tcb);
                } else {
                    cwv::cwv_note_app_limited(&mut tcb);
                }

                // Blocked by the receive window, the congestion window, or
                // both. If it's a genuine zero window, arm the persist timer
                // so we probe periodically rather than waiting forever for a
                // window update that might get lost.
                if tcb.persist_timer.is_none() {
                    tcb.persist_timer = Some(Instant::now() + Duration::from_millis(50));
                    tcb.persist_backoff = Duration::from_millis(50);
                }

                return;
            }

            // We can send the data, so no need to arm the persist timer.
            tcb.persist_timer = None;

            let window_remaining = effective_wnd.saturating_sub(in_flight);
            let send_len = tcb
                .send_buffer
                .len()
                .min(window_remaining as usize)
                .min(mss);

            if send_len == 0 {
                return;
            }

            let data: Vec<u8> = tcb.send_buffer.drain(..send_len).collect();

            // Send the data to the remote.
            let mut hdr = TcpDatagramHeader::new(&tcb);
            hdr.set_flag(TcpDatagramHeader::ACK, true);
            hdr.set_flag(TcpDatagramHeader::PSH, true);
            hdr.set_sequence_number(tcb.snd_nxt);

            let (opts, _) = established_outgoing_options(&mut tcb);
            let tos = ecn::apply_outgoing_ecn(&mut tcb, &mut hdr, &data);

            // If possible, arm the RTT Karn's probe.
            if tcb.rtt_m.probe.is_none() {
                let end = tcb.snd_nxt.wrapping_add(data.len() as u32);

                tcb.rtt_m.probe = Some(RttProbe {
                    seq: tcb.snd_nxt,
                    end,
                    sent_at: Instant::now(),
                });
            }
            let nxt = tcb.snd_nxt;

            let flight_after = in_flight.saturating_add(send_len as u32);
            tcb.cwv.pipe_max = tcb.cwv.pipe_max.max(flight_after);
            tcb.cwv.last_data_tx = Instant::now();
            tcb.cwv.app_limited_since = None;

            // If, after we send the data, the CWND will be full, mark it as a validated
            // state.
            if flight_after >= tcb.cwnd && tcb.cwnd <= tcb.snd_wnd {
                cwv::cwv_note_validated(&mut tcb);
            }

            // Add the segment to the retransmission queue.
            let xmit_now = Instant::now();
            tcb.retransmission_queue.push_back(UnackedSegment {
                seq: nxt,
                data: data.clone(),
                flags: hdr.flags & !TcpDatagramHeader::CWR,
                send_time: xmit_now,
                retries: 0,
                retransmit_tsval: None,
                sacked: false,
                lost: false,
                xmit_mstamp: xmit_now,
                retrans: false,
            });

            tcb.snd_nxt = tcb.snd_nxt.wrapping_add(send_len as u32);

            // RFC 8985 §7.1: (re)arm the Tail Loss Probe on every new-data
            // transmission.
            sack::tlp_arm(&mut tcb);

            // Schedule the next new-data segment (spread cwnd over SRTT).
            if let Some(gap) = pacing::pacing_gap_for(&mut tcb, send_len as u32) {
                tcb.pacing.next_tx = Some(Instant::now() + gap);
                tcb.pacing.paced_count = tcb.pacing.paced_count.saturating_add(1);
            } else {
                tcb.pacing.clear_deadline();
            }

            let socket = tcb.socket;
            drop(tcb);

            // Finally, send the segment.
            self.net_send_tcp_datagram_with_options(socket, &mut hdr, &opts, &data, tos);
        }
    }

    /// Answers a segment for an unrecognized/refused connection with a
    /// standalone RST - no TCB involved, since one either doesn't exist
    /// or shouldn't be created (RFC 9293 §3.5.2).
    pub(crate) fn send_standalone_rst(
        &self,
        tuple: ConnectionTuple,
        received_hdr: &TcpDatagramHeader,
        nic: NetworkInterfaceId,
    ) {
        // Whether the reply-segment has any SEQ number or ACK flag, depends on what
        // segment we are replying to.
        let (seq, ack, flags) = if received_hdr.is_ack() {
            (received_hdr.ack_number.get(), 0, TcpDatagramHeader::RST)
        } else {
            let a = received_hdr.sequence_number.get().wrapping_add(1);
            (0, a, TcpDatagramHeader::RST | TcpDatagramHeader::ACK)
        };

        let socket = Socket {
            remote_port: tuple.remote_port,
            local_port: tuple.local_port,
            remote_address: tuple.remote_ip,
            local_address: tuple.local_ip,
            nic,
        };

        let mut rst_hdr = TcpDatagramHeader {
            source_port: U16::new(tuple.local_port),
            dest_port: U16::new(tuple.remote_port),
            sequence_number: U32::new(seq),
            ack_number: U32::new(ack),
            offset_res: 5 << 4,
            flags,
            window_size: U16::new(0),
            checksum: U16::new(0),
            urgent_pointer: U16::new(0),
        };

        self.net_send_tcp_datagram(socket, &mut rst_hdr, &[]);
    }

    /// Sends RST to all active connections and transitions them to Closed.
    ///
    /// Called on system shutdown.
    pub fn terminate_all_connections(&self) {
        let connections: Vec<_> = self.connections.read().values().cloned().collect();

        for tcb_arc in connections {
            let packet = {
                let mut tcb = tcb_arc.write();
                if tcb.state == TcpState::Closed {
                    None
                } else {
                    let mut hdr = TcpDatagramHeader::new(&tcb);
                    hdr.set_flag(TcpDatagramHeader::RST, true);
                    hdr.set_flag(TcpDatagramHeader::ACK, true);
                    let socket = tcb.socket;
                    tcb.state = TcpState::Closed;
                    tcb.event.notify();
                    Some((socket, hdr))
                }
            };

            if let Some((socket, mut hdr)) = packet {
                self.net_send_tcp_datagram(socket, &mut hdr, &[]);
            }
        }
    }
}
