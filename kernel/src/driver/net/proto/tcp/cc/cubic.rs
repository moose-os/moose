//! CUBIC congestion control algorithm (RFC 8312).
//!
//! Instead of growing linearly like Reno, CUBIC grows cwnd as a cubic
//! function of time since the last loss:
//!
//!     W_cubic(t) = C * (t - K)^3 + W_max
//!
//! `W_max` is the window where the last loss happened - the curve's
//! inflection point. Right after a loss we're well below it, so the cube
//! term is large and growth is fast; as we approach `t = K` the curve
//! flattens out around `W_max`, probing gently near where it hurt last
//! time; past `K` it steepens again, on the bet that if nothing broke
//! yet, there's more room. `C` sets how sharp that curve is; `beta` sets
//! how hard we cut on loss.
//!
//! This is why CUBIC tends to beat Reno on high-BDP (long fat) links:
//! Reno's linear +1 MSS/RTT takes forever to refill a big pipe after a
//! single loss, while CUBIC's cube term gets there much faster and only
//! slows down once it's actually near the danger zone.

use crate::subsystem::clock::time::Instant;

/// CUBIC state (RFC 8312).
///
/// Tracks the cubic growth curve `W_cubic(t) = C * (t-K)^3 + W_max`, where
/// `t` is time since the last loss and `K` is picked so the curve hits
/// `W_max` - the inflection point, i.e. the window size that triggered
/// the last loss - exactly at `t = K`:
///
///     K = cbrt(W_max * (1 - beta) / C)
#[derive(Clone, Debug)]
pub struct CubicState {
    /// Window at the last loss - the curve's target/inflection point.
    pub w_max: u32,

    /// When the current growth epoch started (time of last loss).
    pub epoch_start: Instant,

    /// `K`, in nanoseconds, precomputed once per epoch so we don't redo
    /// the cube root on every packet.
    pub k_ns: u64,

    /// Backoff factor on loss, scaled by 1024 (RFC 8312 default: 0.7).
    pub beta: u32,

    /// Curve steepness constant, scaled by 1024 (RFC 8312 default: 0.4).
    pub c: u32,

    /// cwnd from the previous epoch - used by Fast Convergence to decide
    /// whether to re-target `w_max` lower.
    pub last_max_cwnd: u32,

    /// Fast Recovery ends once an ACK covers this sequence number
    /// (RFC 6582 Reno's `recover`).
    pub recover: u32,
}
