//! Selective Acknowledgments (SACK), DSACK, RACK, and Tail Loss Probe (RACK-TLP).
//!
//! RFCs: [RFC 2018](https://www.rfc-editor.org/rfc/rfc2018.html) (SACK),
//! [RFC 6675](https://www.rfc-editor.org/rfc/rfc6675.html) (scoreboard),
//! [RFC 2883](https://www.rfc-editor.org/rfc/rfc2883.html) (DSACK undo),
//! [RFC 8985](https://www.rfc-editor.org/rfc/rfc8985.html) (RACK + TLP).
//!
//! Plain cumulative ACK only tells us "everything up to here arrived" -
//! if a packet in the middle gets lost but later ones make it, the
//! receiver can't say so, and the sender ends up retransmitting data
//! that already got there just fine.
//!
//! SACK fixes that: the receiver lists the out-of-order ranges it actually
//! has, so the sender only retransmits the real hole. On the receive side,
//! those ranges are tracked as a small fixed scoreboard (`rx_ranges`) - the
//! actual bytes already live in [`super::TcpReceiveBuffer`] via `write_at`,
//! so this module never keeps a second copy per gap.
//!
//! On the send side, SACK info marks segments `sacked` in the
//! retransmission queue. RFC 6675's `IsLost` rule then says: if enough
//! bytes past a segment have been SACKed (3 segments' worth), that
//! segment is presumed lost even without a timeout. RACK (RFC 8985) adds
//! a second, time-based way to reach the same conclusion - if a segment
//! sent clearly before another one that just got (S)ACKed still hasn't
//! shown up after a reordering window, it's lost too, which catches
//! cases dupACK-counting alone would miss (e.g. only one segment
//! trailing behind).
//!
//! DSACK (RFC 2883) is the receiver reporting a duplicate delivery -
//! evidence that a "lost" segment actually wasn't, so a retransmit (or a
//! whole recovery episode) fired for nothing. On the sender, that's a
//! trigger to undo the cwnd/ssthresh cut from that recovery.
//!
//! TLP (RFC 8985 §7) is a separate, small addition for tail loss:
//! probing once after a quiet period so a lost last segment doesn't
//! have to wait for a full RTO to be discovered.

use crate::{
    driver::net::proto::tcp::{TcpDriver, ecn::apply_outgoing_ecn},
    subsystem::clock::time::{Duration, Instant},
};

/// One SACK block as `[left, right)` sequence edges (RFC 2018).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct SackBlock {
    pub(super) left: u32,
    pub(super) right: u32,
}

impl SackBlock {
    pub(super) fn len(self) -> u32 {
        self.right.wrapping_sub(self.left)
    }

    /// Whether this block fully covers `[seq, end)`.
    pub(super) fn covers(self, seq: u32, end: u32) -> bool {
        (seq.wrapping_sub(self.left) as i32) >= 0 && (self.right.wrapping_sub(end) as i32) >= 0
    }
}

/// Max out-of-order ranges tracked on the receiver.
pub(super) const SACK_RX_RANGES_MAX: usize = 8;

/// RFC 6675 DupThresh - 3 segments' worth of bytes SACKed past a hole
/// is enough to call that hole lost without waiting for a timeout.
pub(super) const DUP_THRESH: u32 = 3;

/// SACK + RACK + TLP state for one connection.
#[derive(Clone, Debug)]
pub(super) struct SackRackState {
    /// Both ends advertised SACK-Permitted during the handshake.
    pub(super) enabled: bool,

    /// Receiver scoreboard.
    pub(super) rx_ranges: [SackBlock; SACK_RX_RANGES_MAX],

    /// Length of valid entries in receiver scoreboard.
    pub(super) rx_range_len: u8,

    /// Most recently filled out-of-order block.
    pub(super) rx_recent: Option<SackBlock>,

    // DSACK undo
    /// Highest sequence edge SACKed so far this recovery episode.
    pub(super) high_sacked: u32,

    /// cwnd snapshotted on entering recovery, to restore if a
    /// DSACK later shows the recovery was unnecessary.
    pub(super) undo_cwnd: u32,

    /// Snapshotted `ssthresh` for DSACK recovery.
    pub(super) undo_ssthresh: u32,

    /// Whether the DSACK recovery is pending.
    pub(super) undo_pending: bool,

    // RACK
    //pub(super) rack_rtt: Duration,
    /// Smallest RTT observed used to calculate reordering window.
    pub(super) rack_min_rtt: Duration,

    /// Send time of the most recently (S)ACKed segment.
    pub(super) rack_xmit_ts: Instant,

    /// How much older than the newest delivery a segment can be before
    /// it's presumed lost rather than just reordered.
    pub(super) rack_reorder_window: Duration,

    /// Extra rounds to keep an inflated reordering window after a DSACK
    /// shows we were too aggressive.
    pub(super) rack_reorder_window_persist: u8,

    // TLP
    /// When the tail-loss probe should fire, if one is armed.
    pub(super) tlp_deadline: Option<Instant>,

    /// SND.NXT when the last TLP went out (0 = none sent yet).
    pub(super) tlp_high_rxt: u32,

    /// Whether the last TLP was a retransmit of the last segment (true)
    /// or new data (false).
    pub(super) tlp_is_retrans: bool,

    //  diagnostics
    pub(super) blocks_rx: u32,
    pub(super) blocks_tx: u32,
    pub(super) islost_marks: u32,
    pub(super) rack_marks: u32,
    pub(super) tlp_probes: u32,
    pub(super) dsack_undo: u32,
    pub(super) dsack_seen: u32,
    pub(super) rexmit_holes: u32,
}

impl SackRackState {
    pub(super) fn new() -> Self {
        Self {
            enabled: false,
            rx_ranges: [SackBlock::default(); SACK_RX_RANGES_MAX],
            rx_range_len: 0,
            rx_recent: None,
            high_sacked: 0,
            undo_cwnd: 0,
            undo_ssthresh: 0,
            undo_pending: false,
            //rack_rtt: Duration::from_nanos(0),
            rack_min_rtt: Duration::from_secs(60),
            rack_xmit_ts: Instant::now(),
            rack_reorder_window: Duration::from_nanos(0),
            rack_reorder_window_persist: 0,
            tlp_deadline: None,
            tlp_high_rxt: 0,
            tlp_is_retrans: false,
            blocks_rx: 0,
            blocks_tx: 0,
            islost_marks: 0,
            rack_marks: 0,
            tlp_probes: 0,
            dsack_undo: 0,
            dsack_seen: 0,
            rexmit_holes: 0,
        }
    }
}

use alloc::{sync::Arc, vec::Vec};

use super::{
    driver::send::established_outgoing_options,
    options::{TcpOption, TcpOptionsParser},
    types::{TcpControlBlock, TcpDatagramHeader},
};
use crate::subsystem::sync::IrqGuardedRwLock;

/// Pulls the SACK blocks out of a segment's options. RFC 2018 allows
/// only one SACK option per segment (up to 4 blocks), so this stops at
/// the first one found.
pub(super) fn parse_sack_blocks(options: &[u8]) -> ([SackBlock; 4], usize) {
    // We can fit max 4 SACK blocks in the TCP header options.
    let mut blocks = [SackBlock::default(); 4];

    let mut n = 0usize;
    for opt in TcpOptionsParser::new(options) {
        if let TcpOption::Sack(data) = opt {
            for chunk in data.as_chunks::<8>().0 {
                if n >= blocks.len() {
                    break;
                }

                let left = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
                let right = u32::from_be_bytes([chunk[4], chunk[5], chunk[6], chunk[7]]);

                if (right.wrapping_sub(left) as i32) > 0 {
                    blocks[n] = SackBlock { left, right };

                    n += 1;
                }
            }

            // RFC 2018: at most one SACK option per segment.
            break;
        }
    }

    (blocks, n)
}

/// Stores a received out-of-order segment directly at its final
/// position in the receive buffer, then records the range on the
/// scoreboard.
pub(super) fn sack_receive_out_of_order(tcb: &mut TcpControlBlock, seq: u32, payload: &[u8]) {
    let rcv_nxt = tcb.rcv_nxt;
    let n = tcb.receive_buffer.write_at(rcv_nxt, seq, payload);

    if n == 0 {
        // Buffer full, or the segment fell entirely outside the window
        // we can currently hold - nothing to record.
        return;
    }

    let end = seq.wrapping_add(n as u32);

    sack_rx_insert_range(tcb, seq, end);
}

/// Adds `[left, right)` to the receiver scoreboard, merging it with any
/// existing range it overlaps or touches - so a segment that fills the
/// gap between two known ranges coalesces both into one instead of
/// leaving a zero-length seam between them.
pub(super) fn sack_rx_insert_range(tcb: &mut TcpControlBlock, left: u32, right: u32) {
    let mut merged = SackBlock { left, right };

    let mut i = 0usize;

    // Try to merge adjacent ranges.
    while i < tcb.sack.rx_range_len as usize {
        let b = tcb.sack.rx_ranges[i];

        // Overlaps or is exactly adjacent (touching edges merge too)
        let touches = (merged.left.wrapping_sub(b.right) as i32) <= 0
            && (b.left.wrapping_sub(merged.right) as i32) <= 0;

        if touches {
            if (b.left.wrapping_sub(merged.left) as i32) < 0 {
                merged.left = b.left;
            }
            if (b.right.wrapping_sub(merged.right) as i32) > 0 {
                merged.right = b.right;
            }

            let last = tcb.sack.rx_range_len as usize - 1;
            tcb.sack.rx_ranges[i] = tcb.sack.rx_ranges[last];
            tcb.sack.rx_ranges[last] = SackBlock::default();
            tcb.sack.rx_range_len -= 1;

            // Re-scan from the same index: the block that just moved
            // into slot `i` might also touch `merged`.
            continue;
        }

        i += 1;
    }

    // We either merged at least one range, and made one slot free for new range,
    // or we didn't merge anything at can safely drop it.
    if (tcb.sack.rx_range_len as usize) >= SACK_RX_RANGES_MAX {
        log::trace!(
            "SACK: rx scoreboard full ({} ranges), dropping [{}, {})",
            SACK_RX_RANGES_MAX,
            merged.left,
            merged.right
        );

        return;
    }

    // Insert new range into the scoreboard.
    tcb.sack.rx_ranges[tcb.sack.rx_range_len as usize] = merged;
    tcb.sack.rx_range_len += 1;
    tcb.sack.rx_recent = Some(merged);
}

/// After RCV.NXT moves, checks whether any scoreboard range now starts
/// exactly at the new RCV.NXT - if so, folds it into the contiguous
/// stream and repeats, since closing one gap can expose the next one immediately.
pub(super) fn sack_rx_advance_from_scoreboard(tcb: &mut TcpControlBlock) {
    loop {
        let mut folded = false;

        for i in 0..tcb.sack.rx_range_len as usize {
            let b = tcb.sack.rx_ranges[i];

            // Only care about ranges that start exactly with new RCV.NXT
            if b.left != tcb.rcv_nxt {
                continue;
            }

            // After we advanced RCV.NXT, it turned out that we have more data as well,
            // from previously received segments, and filled the gap, so make it accessible for
            // the user space.
            let n = b.len();
            tcb.receive_buffer.advance_contig(n as usize);
            tcb.rcv_nxt = tcb.rcv_nxt.wrapping_add(n);

            // Remove current SACK entry, move last one into the
            // current slot, and decrease the blocks counter.
            let last = tcb.sack.rx_range_len as usize - 1;
            tcb.sack.rx_ranges[i] = tcb.sack.rx_ranges[last];
            tcb.sack.rx_ranges[last] = SackBlock::default();
            tcb.sack.rx_range_len -= 1;

            if tcb.sack.rx_recent == Some(b) {
                tcb.sack.rx_recent = None;
            }

            folded = true;

            // Restart the scan if the array mutated.
            break;
        }

        if !folded {
            break;
        }
    }
}

/// Applies incoming SACK blocks to the retransmission queue. Two things
/// can happen there:
///
/// - a block, whose right edge is at/behind the cumulative ACK is a duplicate
///   SACK (DSACK), and it's an evidence of a duplicate delivery. It gets routed
///   to the [`super::sack::sack_dsack_undo`] for further processing.
/// - anything else marks the covered segments `sacked` so we can delete it from
///   retransmission queue.
pub(super) fn sack_tx_apply(tcb: &mut TcpControlBlock, ack: u32, blocks: &[SackBlock]) {
    if blocks.is_empty() {
        return;
    }

    // stats
    tcb.sack.blocks_rx = tcb.sack.blocks_rx.saturating_add(blocks.len() as u32);

    for &b in blocks {
        // If receiver successfully handled first transmission, and we've sent
        // retransmission, it can send us SACK entry, whose edges are behind cumulatively
        // ACKed bytes in the header - it's a sign of duplicate delivery.
        let is_dsack = (b.right.wrapping_sub(ack) as i32) <= 0;
        if is_dsack {
            // stats
            tcb.sack.dsack_seen = tcb.sack.dsack_seen.saturating_add(1);

            // Handle this scenario in separate function.
            sack_dsack_undo(tcb, b);

            continue;
        }

        for seg in tcb.retransmission_queue.iter_mut() {
            if seg.sacked {
                continue;
            }

            // Try to search retransmission queue and mark SACKed packets as `SACKed`.
            if b.covers(seg.seq, seg.end_seq()) {
                seg.sacked = true;

                // Newly-confirmed-delivered data can't simultaneously be
                // "lost".
                seg.lost = false;

                if (b.right.wrapping_sub(tcb.sack.high_sacked) as i32) > 0 {
                    tcb.sack.high_sacked = b.right;
                }
            }
        }
    }
}

/// A duplicated SACK just tuld us a segment we have retransmitted, wasn't
/// actually lost. If we're still in recovery, restore the pre-recovery
/// cwnd/ssthresh and widen the RACK reordering window - spurious retransmission
/// means it is too tight for the current network.
pub(super) fn sack_dsack_undo(tcb: &mut TcpControlBlock, block: SackBlock) {
    if tcb.sack.undo_pending {
        let smss = tcb.effective_mss.max(1);

        tcb.cwnd = tcb.sack.undo_cwnd.max(smss);
        tcb.ssthresh = tcb.sack.undo_ssthresh;
        tcb.cwv.cwnd_raw = tcb.cwnd;
        tcb.in_fast_recovery = false;
        tcb.sack.undo_pending = false;
        tcb.sack.dsack_undo = tcb.sack.dsack_undo.saturating_add(1);

        log::trace!(
            "SACK: DSACK undo for [{}, {}) - restoring cwnd={} ssthresh={} {:?}",
            block.left,
            block.right,
            tcb.cwnd,
            tcb.ssthresh,
            tcb.tuple
        );
    }

    let widened = Duration::from_nanos(
        tcb.sack
            .rack_reorder_window
            .as_nanos()
            .saturating_mul(2)
            .max(Duration::from_millis(1).as_nanos()),
    );

    tcb.sack.rack_reorder_window = widened;
    tcb.sack.rack_reorder_window_persist = tcb.sack.rack_reorder_window_persist.saturating_add(16);
}

/// Snapshots cwnd/ssthresh right before a SACK-triggered recovery, so
/// `sack_dsack_undo` has something to restore if the recovery turns out
/// to have been unnecessary.
pub(super) fn sack_enter_recovery(tcb: &mut TcpControlBlock) {
    tcb.sack.undo_cwnd = tcb.cwnd;
    tcb.sack.undo_ssthresh = tcb.ssthresh;
    tcb.sack.undo_pending = true;
}

/// RFC 6675 IsLost: walks the unacked, unsacked segments and marks any
/// with at least `DUP_THRESH` worth of SACKed bytes above it as lost -
/// enough evidence to retransmit without waiting for a timeout.
pub(super) fn sack_mark_lost(tcb: &mut TcpControlBlock) {
    let smss = tcb.effective_mss.max(1);
    let threshold = DUP_THRESH.saturating_mul(smss);

    let candidates: Vec<u32> = tcb
        .retransmission_queue
        .iter()
        .filter(|s| !s.sacked)
        .map(|s| s.seq)
        .collect();

    for seq in candidates {
        if sack_bytes_above(tcb, seq) < threshold {
            continue;
        }

        if let Some(seg) = tcb.retransmission_queue.iter_mut().find(|s| s.seq == seq)
            && !seg.sacked
            && !seg.lost
        {
            seg.lost = true;

            tcb.sack.islost_marks = tcb.sack.islost_marks.saturating_add(1);
        }
    }
}

/// Total SACKed bytes at or above `seq` - the evidence `sack_mark_lost`
/// weighs against `DUP_THRESH` to decide whether a segment counts as lost.
pub(super) fn sack_bytes_above(tcb: &TcpControlBlock, seq: u32) -> u32 {
    tcb.retransmission_queue
        .iter()
        .filter(|s| s.sacked && (s.seq.wrapping_sub(seq) as i32) >= 0)
        .map(|s| s.end_seq().wrapping_sub(s.seq))
        .fold(0u32, |acc, len| acc.saturating_add(len))
}

/// Bytes genuinely still in flight - neither SACKed (delivered) nor
/// marked lost.
pub(super) fn sack_pipe_bytes(tcb: &TcpControlBlock) -> u32 {
    tcb.retransmission_queue
        .iter()
        .filter(|s| !s.sacked && !s.lost)
        .map(|s| s.end_seq().wrapping_sub(s.seq))
        .fold(0u32, |acc, len| acc.saturating_add(len))
}

/// Whether anything in the retransmission queue is currently marked lost
/// (and not yet SACKed).
pub(super) fn sack_has_lost(tcb: &TcpControlBlock) -> bool {
    tcb.retransmission_queue.iter().any(|s| s.lost && !s.sacked)
}

/// RFC 8985 RACK: updates the reordering-window estimate and marks any
/// segment as lost if it was sent clearly before a segment we now have
/// delivery evidence for, and it's been longer than the reordering
/// window without being (S)ACKed itself.
pub(super) fn rack_detect(tcb: &mut TcpControlBlock) {
    // Newest transmission time among segments we now have direct
    // delivery evidence for. `xmit_mstamp` is the time of the last
    // copy sent (RFC 8985 §5), so this is safe to use even for
    // retransmitted segments.
    let newest_xmit = tcb
        .retransmission_queue
        .iter()
        .filter(|s| s.sacked)
        .map(|s| s.xmit_mstamp)
        .max();

    // Set `tcb.sack.rack_xmit_ts` and `tcb.sack.rack_min_rtt` based on
    // newest packet we sent and got ACKed.
    if let Some(xmit_ts) = newest_xmit
        && xmit_ts > tcb.sack.rack_xmit_ts
    {
        tcb.sack.rack_xmit_ts = xmit_ts;

        let now = Instant::now();
        if now > xmit_ts {
            let rtt = now - xmit_ts;
            //tcb.sack.rack_rtt = rtt;
            tcb.sack.rack_min_rtt = tcb.sack.rack_min_rtt.min(rtt);
        }
    }

    rack_update_reordering_winow(tcb);

    let rack_xmit_ts = tcb.sack.rack_xmit_ts;
    let reo_wnd = tcb.sack.rack_reorder_window;

    // Walk through the retransmission queue, and for every not SACK-ed nor Lost packet,
    // check whether the transmit timestamp > rack_xmit_ts + reordering_window. If yes, then mark
    // it as lost and begin retransmission.
    for seg in tcb.retransmission_queue.iter_mut() {
        if seg.sacked || seg.lost {
            continue;
        }

        if rack_xmit_ts > seg.xmit_mstamp && (rack_xmit_ts - seg.xmit_mstamp) > reo_wnd {
            seg.lost = true;

            tcb.sack.rack_marks = tcb.sack.rack_marks.saturating_add(1);
        }
    }
}

/// Recomputes the reordering window from the smallest observed RTT, unless
/// a recent DSACK is still asking us to keep it inflated (`rack_reo_wnd_persist`).
pub(super) fn rack_update_reordering_winow(tcb: &mut TcpControlBlock) {
    if tcb.sack.rack_reorder_window_persist > 0 {
        tcb.sack.rack_reorder_window_persist -= 1;
        return;
    }

    // a quarter of the smallest RTT observed - tight enough to catch real
    // loss promptly, loose enough to absorb ordinary reordering on this path.
    tcb.sack.rack_reorder_window = Duration::from_nanos(tcb.sack.rack_min_rtt.as_nanos() / 4);
}

/// Feeds a fresh RTT sample into RACK's running minimum.
pub(super) fn rack_feed_rtt(tcb: &mut TcpControlBlock, r: Duration) {
    tcb.sack.rack_min_rtt = tcb.sack.rack_min_rtt.min(r);
}

/// Arms (or disarms) the tail-loss probe timer. No probe is armed with
/// nothing outstanding or already in fast recovery - TLP is specifically
/// for "one segment might be lost and nothing else will tell us," which
/// doesn't apply once real loss recovery is already enabled.
pub(super) fn tlp_arm(tcb: &mut TcpControlBlock) {
    if tcb.retransmission_queue.is_empty() || tcb.in_fast_recovery {
        tcb.sack.tlp_deadline = None;
        return;
    }

    let srtt = tcb.srtt.unwrap_or(Duration::from_millis(200));
    let rttvar = tcb.rttvar.unwrap_or(Duration::from_millis(50));

    const MIN_PTO: Duration = Duration::from_millis(10);
    const WORST_CASE_DELAYED_ACK: Duration = Duration::from_millis(200);

    let pto = if tcb.retransmission_queue.len() > 1 {
        Duration::from_nanos(srtt.as_nanos().saturating_mul(2)).max(MIN_PTO)
    } else {
        let jitter = Duration::from_nanos(rttvar.as_nanos().saturating_mul(4));
        Duration::from_nanos(srtt.as_nanos().saturating_add(jitter.as_nanos()))
            .max(WORST_CASE_DELAYED_ACK)
    };

    tcb.sack.tlp_deadline = Some(Instant::now() + pto);
}

/// Fires the tail-loss probe once the deadline from `tlp_arm` passes.
/// Prefers sending genuinely new data if there's room (that alone can
/// generate the ACK/SACK feedback needed to tell whether the tail was
/// lost); only falls back to retransmitting the last outstanding segment
/// if there's nothing new to send.
pub(super) fn tlp_send_probe_unlocked(
    driver: &TcpDriver,
    tcb_arc: &Arc<IrqGuardedRwLock<TcpControlBlock>>,
) {
    let send_new = {
        let tcb = tcb_arc.read();
        !tcb.send_buffer.is_empty() && tcb.can_send(1)
    };

    // If we still have more data in the send buffer, then just
    // process send_queue.
    if send_new {
        {
            let mut tcb = tcb_arc.write();
            tcb.sack.tlp_is_retrans = false;
            tcb.sack.tlp_high_rxt = tcb.snd_nxt;
            tcb.sack.tlp_probes = tcb.sack.tlp_probes.saturating_add(1);
        }

        driver.process_send_queue(tcb_arc.clone());
        return;
    }

    // If there's no more data available, then we trigger a full retransmit.
    let (socket, mut hdr, data, opts, tos) = {
        let mut tcb = tcb_arc.write();

        let Some(seg_idx) =
            (!tcb.retransmission_queue.is_empty()).then(|| tcb.retransmission_queue.len() - 1)
        else {
            return;
        };

        let (opts, _tsval) = established_outgoing_options(&mut tcb);
        let now = Instant::now();

        // Retransmit last packet.
        if let Some(seg) = tcb.retransmission_queue.get_mut(seg_idx) {
            seg.xmit_mstamp = now;
            seg.retrans = true;
        }
        tcb.sack.tlp_is_retrans = true;
        tcb.sack.tlp_high_rxt = tcb.snd_nxt;
        tcb.sack.tlp_probes = tcb.sack.tlp_probes.saturating_add(1);

        let seg = &tcb.retransmission_queue[seg_idx];
        let mut hdr = TcpDatagramHeader::new(&tcb);
        hdr.set_flags(seg.flags & !TcpDatagramHeader::CWR);
        hdr.set_sequence_number(seg.seq);
        let data = seg.data.clone();
        let tos = apply_outgoing_ecn(&mut tcb, &mut hdr, &data);

        (tcb.socket, hdr, data, opts, tos)
    };

    driver.net_send_tcp_datagram_with_options(socket, &mut hdr, &opts, &data, tos);
}
