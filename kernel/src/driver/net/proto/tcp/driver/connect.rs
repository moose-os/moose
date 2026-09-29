//! Active-open connection setup and synchronous reads.
//!
//! Everything the driver needs for `connect()` and blocking `receive()` -
//! the two API calls that have to block the caller's thread until
//! something happens on the network, unlike the rest of the driver which
//! is event/interrupt-driven.

use alloc::{sync::Arc, vec::Vec};

use x86_64::instructions::random::RdRand;

use super::{
    super::{
        options::TcpOptionsWriter,
        timestamp::{self, RttProbe},
        types::*,
    },
    TcpDriver,
};
use crate::{
    driver::net::{Ipv4Addr, NetworkInterfaceId, Socket},
    subsystem::{
        clock::time::{Duration, Instant},
        scheduler::{block_on_event, yield_to_scheduler},
        sync::IrqGuardedRwLock,
    },
};

impl TcpDriver {
    /// Opens a connection to remote host.
    pub fn connect(
        &self,
        nic: NetworkInterfaceId,
        local_ip: Ipv4Addr,
        local_port: u16,
        remote_ip: Ipv4Addr,
        remote_port: u16,
        settings: &mut TcpSessionSettings,
    ) -> Result<Arc<IrqGuardedRwLock<TcpControlBlock>>, TcpError> {
        let local_port = if local_port == 0 {
            Self::alloc_ephemeral_port()
        } else {
            local_port
        };

        let socket = Socket::new(local_ip, local_port, remote_ip, remote_port, nic);
        let tuple = ConnectionTuple::from_socket(&socket);
        let iss = RdRand::new().unwrap().get_u32().unwrap();

        log::trace!(
            "connect {}:{} -> {}:{}",
            local_ip,
            local_port,
            remote_ip,
            remote_port
        );

        settings.receive_buffer_size = clamp_tcp_receive_buffer_bytes(settings.receive_buffer_size);
        let mut tcb = TcpControlBlock::new(iss, tuple, socket, settings);
        settings.apply_receive_path(&mut tcb);

        tcb.state = TcpState::SynSent;
        tcb.snd_nxt = iss.wrapping_add(1); // SYN consumes one sequence number

        let tcb_arc = Arc::new(IrqGuardedRwLock::new(tcb));
        self.connections.write().insert(tuple, tcb_arc.clone());

        // Build and queue SYN segment.
        // RFC 3168 §6.1.1: offer ECN by setting both ECE and CWR on SYN.
        let mut hdr = TcpDatagramHeader::new(&tcb_arc.read());
        hdr.set_sequence_number(iss);
        hdr.set_acknowledgement_number(0);
        hdr.set_flag(TcpDatagramHeader::SYN, true);
        if settings.ecn_enabled {
            hdr.set_flag(TcpDatagramHeader::ECE, true);
            hdr.set_flag(TcpDatagramHeader::CWR, true);
        }

        let syn_ts = timestamp::tcp_ts_now(tcb_arc.read().ts.offset);

        let mut opt_writer = TcpOptionsWriter::new();
        opt_writer.push_mss(DEFAULT_MSS);

        if settings.wnd_scale_enabled {
            opt_writer.push_window_scale(settings.rcv_wscale);
        }
        if settings.sack_enabled {
            opt_writer.push_sack_permitted();
        }
        if settings.timestamps_enabled {
            opt_writer.push_timestamp(syn_ts, 0);
        }

        let syn_options = opt_writer.finish();

        {
            let mut t = tcb_arc.write();

            // The SYN itself is also tracked in the retransmission queue
            // (it needs RTO/retransmit handling like any other segment)
            // and doubles as the RTT probe for the handshake's first sample.
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

            t.rtt_m.probe = Some(RttProbe {
                seq: iss,
                end: iss.wrapping_add(1),
                sent_at: Instant::now(),
            });

            t.ts.last_tx_tsval = syn_ts;
        }

        // Send the SYN packet
        if !self.net_send_tcp_datagram_with_options(socket, &mut hdr, syn_options, &[], 0) {
            self.connections.write().remove(&tuple);

            return Err(TcpError::NoRoute);
        }

        log::trace!("SYN sent {:?}", tuple);

        // timeout: 5s
        let deadline = Instant::now() + Duration::from_secs(5);
        tcb_arc.read().event.clear_pending();

        loop {
            let (state, last_error) = {
                let t = tcb_arc.read();
                (t.state, t.last_error)
            };

            if state == TcpState::Established {
                log::trace!("connect complete {:?}", tuple);

                return Ok(tcb_arc);
            }

            if state == TcpState::Closed {
                self.connections.write().remove(&tuple);

                return Err(last_error.unwrap_or(TcpError::ConnectionRefused));
            }

            if Instant::now() >= deadline {
                self.connections.write().remove(&tuple);

                return Err(TcpError::Timeout);
            }

            // Wait for RxProcessThread to deliver the SYN-ACK and run
            // process_syn_ack, which sends the final ACK itself and flips
            // the state to Established.
            yield_to_scheduler();
        }
    }

    /// Picks a random ephemeral port (RFC 6335 dynamic range, 49152-65535)
    /// for an active open that didn't request a specific local port.
    fn alloc_ephemeral_port() -> u16 {
        let random_val: u16 = RdRand::new().and_then(|r| r.get_u16()).unwrap_or(0);
        let base: u16 = 49152;
        let range: u16 = 65535 - 49152 + 1;

        base + (random_val % range)
    }

    /// Blocking read: copies as much as `target` can hold out of the
    /// receive buffer, sleeping on the connection's event if nothing is
    /// available yet. Returns `Ok(0)` on EOF (peer closed and buffer is
    /// drained), `Err` on a connection error, or the number of bytes read
    /// otherwise.
    pub fn receive_sync(
        &self,
        tcb: Arc<IrqGuardedRwLock<TcpControlBlock>>,
        target: &mut [u8],
    ) -> Result<usize, TcpError> {
        loop {
            let (read_bytes, terminal, err) = {
                let mut lock = tcb.write();

                if let Some(error) = lock.last_error {
                    (0, true, Some(error))
                } else {
                    let n = lock.receive_buffer.read(target);

                    if n > 0 {
                        // Update receive window, as application read some data from the buffer,
                        // but dont send immediate ACK - avoid SWS.
                        lock.update_rcv_wnd_from_buffer();

                        (n, false, None)
                    } else {
                        // No data.
                        let closed = matches!(
                            lock.state,
                            TcpState::CloseWait
                                | TcpState::Closed
                                | TcpState::LastAck
                                | TcpState::TimeWait
                        );

                        (0, closed, None)
                    }
                }
            };

            if let Some(e) = err {
                return Err(e);
            }

            if terminal && read_bytes == 0 {
                return Ok(0); // EOF
            }

            if read_bytes > 0 {
                return Ok(read_bytes);
            }

            // Buffer empty, connection still open - sleep until data arrives.
            let event = tcb.read().event.clone();

            block_on_event(&event);
        }
    }
}
