//! Appropriate Byte Counting (ABC) for congestion-window growth.
//!
//! RFC: [RFC 3465](https://www.rfc-editor.org/rfc/rfc3465.html).
//!
//! Growing cwnd by counting ACKs has two problems. Delayed ACKs most
//! of the time cumulatively ACKs a couple of segments, so counting ACKs
//! makes slow start double every two RTTs instead of one - we lose half
//! of our slow start speed to a receiver-side optimization that has nothing to
//! do with congestion. From the other side, attacker can send us packets ACKing
//! one byte at the time and blow cwnd in one stop - large abuse vector.
//!
//! ABC's fix: grow from bytes actually acked, but cap Slow Start phase at `L *
//! SMSS` per ACK (`L = 2`) so one fat ACK can't jump the window further
//! than roughly one RTT's worth of doubling would.
//!
//! Congestion avoidance accumulates acked bytes and only adds +1 SMSS once
//! the accumulator catches up to the current window.
//!
//! ABC only decides how many bytes to credit - it doesn't decide
//! whether cwnd is allowed to grow at all. That's CWV's job
//! ([`super::cwv`], RFC 7661): when CWV blocks growth, the real
//! accumulator is left untouched (no bytes "spent" on a window that
//! never opened), while the no-CWV shadow (`cwnd_raw`) keeps accumulating
//! regardless, purely so the two can be compared on the diagnostics
//! snapshot.
//!
//! On any congestion event, the accumulators get wiped, so the stale credits
//! from before the lose can't falsely open the window right after it has been shrinked.

/// RFC 3465 Appropriate Byte Counting State
#[derive(Clone, Debug)]
pub(super) struct AbcState {
    /// RFC 3465 `L`: max SMSS one slow-start ACK can credit. Fixed at 2.
    pub(super) l_smss: u8,

    /// Congestion Avoidance byte accumulator for the real cwnd.
    pub(super) ca_accum: u32,

    /// Accumulator for the no-CWV shadow window (`cwnd_raw`). Only for tracing purposes.
    pub(super) ca_accum_raw: u32,

    // diagnostic data
    /// Total bytes credited into cwnd / cwnd_raw by ABC.
    pub(super) bytes_credited: u64,

    /// Times a slow-start credit got capped by `L * SMSS`.
    pub(super) ss_capped: u32,

    /// Times congestion avoidance produced a +1 SMSS increment.
    pub(super) ca_increments: u32,
}

impl AbcState {
    pub(super) fn new() -> Self {
        Self {
            l_smss: 2, // RFC 3465 §2.3 recommended L
            ca_accum: 0,
            ca_accum_raw: 0,
            bytes_credited: 0,
            ss_capped: 0,
            ca_increments: 0,
        }
    }

    /// Drop CA credits after a loss/recovery reset - avoids post-MD jumps.
    pub(super) fn clear_accumulators(&mut self) {
        self.ca_accum = 0;
        self.ca_accum_raw = 0;
    }
}
