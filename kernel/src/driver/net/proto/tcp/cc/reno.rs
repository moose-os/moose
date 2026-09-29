//! TCP Reno congestion control algorithm.
//!
//! RFC: [RFC 5681](https://www.rfc-editor.org/rfc/rfc5681.html) (congestion
//! control); Fast Recovery follows [RFC 6582](https://www.rfc-editor.org/rfc/rfc6582.html)
//! (NewReno).
//!
//! Reno is the classic AIMD algorithm: additive increase, multiplicative
//! decrease. `cwnd` doubles per RTT in slow start, then grows linearly
//! (~1 MSS/RTT) in congestion avoidance, and gets halved on loss.
//!
//! `recover` marks the sequence number that has to be ACKed before recovery
//! is considered done.

/// Reno congestion control state (RFC 5681 / RFC 6582).
#[derive(Clone, Debug)]
pub struct RenoState {
    /// Fast Recovery ends once an ACK covers this sequence (RFC 6582).
    pub recover: u32,
}
