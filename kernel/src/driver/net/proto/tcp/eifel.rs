//! Eifel spurious RTO detection and response.
//!
//! RFCs: [RFC 3522](https://www.rfc-editor.org/rfc/rfc3522.html) (Eifel Detection),
//! [RFC 4015](https://www.rfc-editor.org/rfc/rfc4015.html) (Eifel Response).
//!
//! A RTO doesn't always mean a packet was lost - a delay spike or a
//! stall on the ACK path can make the timer fire even though the data
//! got there fine. If we just trust the timeout, we decrease the window and
//! retransmit for nothing, and the connection slow downs for a while over a
//! problem that already fixed itself.
//!
//! Eifel catches this after the fact, using timestamps: when we
//! retransmit on RTO, we remember the TSval we sent (`retransmit_ts`).
//! If the ACK that eventually comes back echoes a TSecr *older* than
//! that - it's acking the original segment, not the retransmit -
//! then the RTO was spurious, and we undo the damage: restore `ssthresh` and
//! `SND.NXT` to what they were before the timeout, and rebuild cwnd from
//! what's actually in flight instead of leaving it artificially small.
//!
//! Needs Timestamps negotiated to work (no TSecr -> no comparison),
//! and is mutually exclusive with F-RTO ([`super::frto`]) - both solve
//! the same problem, so only one runs. If the ACK that would've proven
//! it spurious carries ECN's ECE instead, we treat that as a real
//! congestion signal and don't undo anything - see
//! `eifel_on_acceptable_ack`.
//!
//! [`RetransmitCause`] records why a segment was retransmitted; only an
//! actual RTO arms Eifel - fast retransmit and partial-ACK retransmits
//! don't.

/// RFC 4015: cap on the post-undo cwnd burst, ~3x MSS.
pub(super) const EIFEL_IW_BYTES: u32 = 4380;

/// Eifel Detection (RFC 3522) + Response (RFC 4015) state.
#[derive(Clone, Debug, Default)]
pub(super) struct EifelState {
    /// `max(FlightSize, ssthresh)` right before the RTO's MD - what
    /// `ssthresh` gets restored to if this RTO turns out spurious.
    pub(super) pipe_prev: Option<u32>,

    /// TSval we sent on the RTO retransmission.
    pub(super) retransmit_ts: Option<u32>,

    /// SND.NXT at the moment of the RTO - restored on undo.
    pub(super) snd_max: Option<u32>,

    /// Bytes newly acked by the ACK that resolves this RTO.
    pub(super) bytes_acked: u32,

    // stats
    /// How many times we've caught a spurious RTO.
    pub(super) spurious_count: u32,
}

impl EifelState {
    pub(super) fn new() -> Self {
        Self::default()
    }
}

/// Why a segment is being retransmitted. Only `Rto` arms Eifel Detection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RetransmitCause {
    Rto,
    FastRetransmit,
    PartialAck,
}

use super::types::TcpControlBlock;

/// Called right before we apply MD for an RTO. Snapshots what we need
/// to undo later, if the timeout was spurious.
pub(super) fn eifel_on_rto_before_md(tcb: &mut TcpControlBlock) {
    // Eifel can't run without timestamps.
    if !tcb.ts.enabled {
        return;
    }

    // Clear F-RTO as it is mutually-exclusive with Eifel.
    // Not really needed, clear it because some defensive programming.
    tcb.frto.clear();

    // Save values we need to restore later.
    let flight = tcb.flight_size_bytes();
    tcb.eifel.pipe_prev = Some(core::cmp::max(flight, tcb.ssthresh));
    tcb.eifel.snd_max = Some(tcb.snd_nxt);
    tcb.eifel.bytes_acked = 0;
}

/// Drops any pending Eifel state.
pub(super) fn eifel_clear_pending(tcb: &mut TcpControlBlock) {
    tcb.eifel.pipe_prev = None;
    tcb.eifel.retransmit_ts = None;
    tcb.eifel.snd_max = None;
    tcb.eifel.bytes_acked = 0;
}

/// Checks whether the ACK that just came in proves the pending RTO was
/// spurious, and if so, undoes it.
pub(super) fn eifel_on_acceptable_ack(tcb: &mut TcpControlBlock, tsecr: Option<u32>, ece: bool) {
    let Some(retransmit_ts) = tcb.eifel.retransmit_ts else {
        return;
    };
    let Some(tsecr) = tsecr else {
        eifel_clear_pending(tcb);
        return;
    };

    // RFC 3522 §3.1: TSecr < RetransmitTS means this ACK is for the
    // original segment, not our retransmit - so the RTO fired for
    // nothing.
    let spurious = (tsecr.wrapping_sub(retransmit_ts) as i32) < 0;
    if !spurious || ece {
        // Not spurious, or ECN says there really was congestion - leave
        // the MD in place.
        eifel_clear_pending(tcb);

        return;
    }

    // It actually was spurious, so restore previously saved values and leave FR.
    let pipe_prev = tcb.eifel.pipe_prev.unwrap_or(tcb.flight_size_bytes());
    let snd_max = tcb.eifel.snd_max.unwrap_or(tcb.snd_nxt);
    let bump = core::cmp::min(tcb.eifel.bytes_acked, EIFEL_IW_BYTES);
    let flight = tcb.flight_size_bytes();

    // RFC 4015 §3.4 step (9): rebuild cwnd from what's actually in
    // flight.
    tcb.cwnd = flight.saturating_add(bump);
    tcb.cwv.cwnd_raw = tcb.cwnd;
    tcb.ssthresh = pipe_prev;
    tcb.abc.clear_accumulators();

    // RFC 4015 step (8): restore SND.NXT so we skip retransmissions.
    if (snd_max.wrapping_sub(tcb.snd_una) as i32) >= 0 {
        tcb.snd_nxt = snd_max;
    }

    // Disable Fast Recovery and provide some tracing info.
    tcb.in_fast_recovery = false;
    tcb.eifel.spurious_count = tcb.eifel.spurious_count.saturating_add(1);

    log::trace!(
        "Eifel Response: spurious RTO TSecr={} < RetransmitTS={} cwnd={} ssthresh={}",
        tsecr,
        retransmit_ts,
        tcb.cwnd,
        tcb.ssthresh
    );

    // Reset Eifel counters.
    eifel_clear_pending(tcb);
}
