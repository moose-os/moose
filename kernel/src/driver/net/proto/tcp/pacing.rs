//! Packet pacing for TCP transmission.
//!
//! **RFC:** no dedicated RFC - this follows the Linux-style approach of
//! spreading a cwnd's worth of segments over roughly one RTT, in the
//! spirit of [RFC 5681](https://www.rfc-editor.org/rfc/rfc5681.html) and
//! [RFC 8312](https://www.rfc-editor.org/rfc/rfc8312.html) (CUBIC assumes
//! the sender paces).
//!
//! Without pacing, `process_send_queue` just blasts out as many segments
//! as `cwnd` allows the moment an ACK opens up room - on a fat pipe that's
//! a burst of packets all at once, which can overflow a router's buffer
//! and cause drops even though the average send rate was perfectly
//! fine. Pacing spreads that same amount of data out over the RTT instead
//! of sending it all in one tight loop, using a simple model:
//!
//! ```text
//!   rate ≈ (cwnd / SRTT) * gain
//! ```
//!
//! `gain` is higher in slow start (200%, since we want to keep catching
//! up fast) and lower in congestion avoidance (120%, just enough headroom
//! over the natural ACK clock). Until we have an SRTT sample, there's
//! nothing to pace against, so sends go out unpaced.
//!
//! Retransmits and probes skip pacing entirely - fast retransmit, RTO
//! retransmits, the F-RTO Step2 probe, zero-window probes. Those are
//! recovery/control traffic and shouldn't sit around waiting for a pacing
//! slot.
//!
//! [`super::TcpDriver::process_send_queue`] actually checks it before sending.

use crate::subsystem::clock::time::{Duration, Instant};

/// Pacing state for one connection.
#[derive(Clone, Debug)]
pub(super) struct PacingState {
    /// Master switch for this TCB.
    pub(super) enabled: bool,

    /// Earliest time we're allowed to send the next new-data segment.
    /// `None` means nothing's being held back right now.
    pub(super) next_tx: Option<Instant>,

    // stats
    /// Most recently computed rate, bytes/s.
    pub(super) rate_bps: u64,

    /// Most recently computed inter-packet gap.
    pub(super) last_gap: Duration,

    /// Segments that got held back waiting for `next_tx`.
    pub(super) held_count: u32,

    /// Segments actually sent with a pacing gap applied.
    pub(super) paced_count: u32,
}

impl PacingState {
    pub(super) fn new(enabled: bool) -> Self {
        Self {
            enabled,
            next_tx: None,
            rate_bps: 0,
            last_gap: Duration::from_nanos(0),
            held_count: 0,
            paced_count: 0,
        }
    }

    pub(super) fn clear_deadline(&mut self) {
        self.next_tx = None;
    }
}

use super::{frto::FrtoPhase, types::TcpControlBlock};

/// Computes how long to wait before sending the next segment after one
/// of `send_len` bytes, based on the current rate estimate. Returns `None`
/// if pacing isn't active (disabled, nothing to send, or no SRTT sample
/// yet - can't pace against a rate we don't know).
///
/// The gap has a floor of 1µs (so we never busy-spin on a near-zero gap)
/// and a ceiling of the current RTO (so a stalled pacing computation can
/// never freeze sending entirely).
pub(super) fn pacing_gap_for(tcb: &mut TcpControlBlock, send_len: u32) -> Option<Duration> {
    if !tcb.pacing.enabled || send_len == 0 {
        return None;
    }

    let Some(srtt) = tcb.srtt else {
        tcb.pacing.rate_bps = 0;
        return None;
    };

    let srtt_ns = (srtt.as_nanos() as u128).max(1);
    let cwnd = tcb.cwnd.max(1) as u128;

    // Gain: 200% in Slow Start, 120% in CA (percent).
    let gain: u128 = if tcb.cwnd < tcb.ssthresh { 200 } else { 120 };

    // rate_Bps = cwnd * 1e9 * gain / (srtt_ns * 100)
    let rate = (cwnd * 1_000_000_000u128 * gain) / (srtt_ns * 100);
    let rate = rate.max(1) as u64;

    tcb.pacing.rate_bps = rate;

    // gap_ns = send_len * 1e9 / rate
    let gap_ns = (send_len as u128 * 1_000_000_000u128) / rate as u128;

    // Floor at 1 µs so we never spin; cap at RTO so a stall cannot freeze TX.
    let gap = Duration::from_nanos(gap_ns.max(1_000) as u64).min(tcb.rto);
    tcb.pacing.last_gap = gap;

    Some(gap)
}

/// Whether the send path should hold off right now instead of sending.
/// Always says no if pacing is off, or if we're mid F-RTO Step2 probe
/// (that one has to go out immediately, pacing or not).
pub(super) fn pacing_should_hold(tcb: &mut TcpControlBlock, now: Instant) -> bool {
    // F-RTO Step2 probe must go out immediately.
    if !tcb.pacing.enabled || tcb.frto.phase == FrtoPhase::Step2 {
        return false;
    }

    // If the next allowed transmit time is in the future, hold the data in the buffers.
    if let Some(next) = tcb.pacing.next_tx
        && now < next
    {
        tcb.pacing.held_count = tcb.pacing.held_count.saturating_add(1);

        return true;
    }

    false
}
