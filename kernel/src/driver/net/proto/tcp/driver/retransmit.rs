//! Retransmission - picking and resending the right segment on loss.
//!
//! One shared implementation ([`retransmit_matching_unlocked`]) backs
//! three different callers, each wanting a different segment:
//! - fast retransmit (3 dupACKs / SACK evidence) wants the head of the
//!   queue, or - with SACK - the lowest confirmed hole;
//! - a partial ACK during fast recovery wants the next unacked segment
//!   past what that partial ACK just covered (RFC 6582);
//! - an RTO wants the head, plus Eifel bookkeeping so a spurious timeout
//!   can later be undone.

use alloc::sync::Arc;

use super::{
    super::{
        ecn::{self},
        eifel::RetransmitCause,
        types::{TcpControlBlock, TcpDatagramHeader},
    },
    TcpDriver,
};
use crate::subsystem::{clock::time::Instant, sync::IrqGuardedRwLock};

impl TcpDriver {
    /// Retransmits the segment just past what a partial ACK during fast
    /// recovery covered - RFC 6582's response to a second loss showing
    /// up within the same recovery window.
    pub(crate) fn retransmit_first_partial_ack(
        &self,
        tcb_arc: &Arc<IrqGuardedRwLock<TcpControlBlock>>,
        ack: u32,
    ) {
        self.retransmit_matching_unlocked(tcb_arc, RetransmitCause::PartialAck, Some(ack));
    }

    /// Retransmits the head of the queue (or, with SACK, the lowest
    /// confirmed hole) - RFC 5681 §3.2 fast retransmit, triggered by 3
    /// dupACKs or SACK/RACK loss evidence.
    pub(crate) fn fast_retransmit_front(&self, tcb_arc: &Arc<IrqGuardedRwLock<TcpControlBlock>>) {
        self.retransmit_front_unlocked(tcb_arc, RetransmitCause::FastRetransmit);
    }

    /// Retransmits the head of the queue for any `cause` other than a
    /// partial ACK - used directly for RTO retransmits.
    pub(crate) fn retransmit_front_unlocked(
        &self,
        tcb_arc: &Arc<IrqGuardedRwLock<TcpControlBlock>>,
        cause: RetransmitCause,
    ) {
        self.retransmit_matching_unlocked(tcb_arc, cause, None);
    }

    /// Picks the right segment to resend for `cause`, rebuilds its
    /// header/options, and sends it. Which segment gets picked:
    ///
    /// - SACK enabled: the lowest-sequence segment explicitly marked
    ///   `lost` (by RFC 6675 IsLost or RACK) that hasn't since been
    ///   SACKed out from under us; if nothing's marked lost yet (e.g.
    ///   the very first retransmit of a fresh recovery episode), falls
    ///   back to the lowest segment that isn't already SACKed.
    /// - Partial ACK (no SACK): the first segment whose end is still
    ///   past what `partial_ack` covered.
    /// - Otherwise: the head of the queue.
    fn retransmit_matching_unlocked(
        &self,
        tcb_arc: &Arc<IrqGuardedRwLock<TcpControlBlock>>,
        cause: RetransmitCause,
        partial_ack: Option<u32>,
    ) {
        let (socket, mut hdr, data, opts, tos) = {
            let mut tcb = tcb_arc.write();

            let seg_idx = if tcb.sack.enabled {
                // RFC 6675 §5: retransmit the lowest-sequence hole the
                // scoreboard has explicitly marked IsLost (or RACK-lost)
                // that the peer hasn't already SACKed out from under us.
                tcb.retransmission_queue
                    .iter()
                    .position(|s| s.lost && !s.sacked)
                    .or_else(|| tcb.retransmission_queue.iter().position(|s| !s.sacked))
            } else if let Some(ack) = partial_ack {
                tcb.retransmission_queue
                    .iter()
                    .position(|s| (ack.wrapping_sub(s.end_seq()) as i32) < 0)
            } else {
                if tcb.retransmission_queue.is_empty() {
                    None
                } else {
                    // Head of the queue
                    Some(0)
                }
            };

            let Some(seg_idx) = seg_idx else {
                return;
            };

            let (opts, tsval) =
                crate::driver::net::proto::tcp::driver::send::established_outgoing_options(
                    &mut tcb,
                );

            if cause == RetransmitCause::Rto {
                // RetransmitTS only for Eifel (Timestamps path).
                if tcb.ts.enabled
                    && let Some(timestamp) = tsval
                {
                    tcb.eifel.retransmit_ts = Some(timestamp);

                    if let Some(seg) = tcb.retransmission_queue.get_mut(seg_idx) {
                        seg.retransmit_tsval = Some(timestamp);
                    }
                }
            }

            let now = Instant::now();
            if let Some(seg) = tcb.retransmission_queue.get_mut(seg_idx) {
                // RFC 8985 §5: every (re)transmission refreshes xmit_mstamp
                // so RACK can time-order this copy against future ACKs.
                seg.xmit_mstamp = now;

                // Mark retransmitted as true, so RTT Karn probe won't take the
                // sample into account.
                seg.retrans = true;

                // Mark it as not lost: we are retransmitting it right now.
                seg.lost = false;
            }

            if tcb.sack.enabled {
                tcb.sack.rexmit_holes = tcb.sack.rexmit_holes.saturating_add(1);
            }

            let seg = &tcb.retransmission_queue[seg_idx];
            let mut hdr = TcpDatagramHeader::new(&tcb);

            hdr.set_flags(seg.flags & !TcpDatagramHeader::CWR);
            hdr.set_sequence_number(seg.seq);

            let data = seg.data.clone();

            let tos = ecn::apply_outgoing_ecn(&mut tcb, &mut hdr, &data);

            (tcb.socket, hdr, data, opts, tos)
        };

        self.net_send_tcp_datagram_with_options(socket, &mut hdr, &opts, &data, tos);
    }

    /// Drops every segment the cumulative ACK now fully covers.
    pub(crate) fn drain_retransmission_queue(&self, tcb: &mut TcpControlBlock, ack: u32) {
        tcb.retransmission_queue
            .retain(|seg| (ack.wrapping_sub(seg.end_seq()) as i32) < 0);
    }
}
