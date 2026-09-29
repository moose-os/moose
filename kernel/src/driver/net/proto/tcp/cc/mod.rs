//! TCP congestion-control algorithms.
//!
//! Congestion control decides how much data we can have in
//! flight (sent, not yet ACKed). If we send too much, routers along
//! the path will start dropping packets; if we send too little, we waste the
//! link. The number of bytes we're allowed to have in flight is `cwnd` (congestion window)
//! and `ssthresh` is the point where we switch behavior:
//!
//! - `cwnd < ssthresh` -> Slow Start: `cwnd` doubles every ACK.
//!   We don't know the network's limit yet, so we ramp up fast.
//! - `cwnd >= ssthresh` -> Congestion Avoidance: `cwnd` grows by 1 MSS
//!   per received ACK. We're close to the maximum throughput, so
//!   we probe slowly.
//!
//! When a loss is detected, the `cwnd` is cut by
//! a factor (multiplicative decrease):
//! `ssthresh` drops to half of cwnd (Reno) or `beta * cwnd` (CUBIC), and
//! cwnd lands near the new ssthresh instead of restarting from scratch.
//!
//! If the loss was caught via dup ACKs rather than a timeout, we don't
//! stop sending entirely - we enter Fast Recovery: keep `cwnd` cut down,
//! patch the hole, and only resume normal growth once it's fixed.
//!
//! **RFCs:** Reno — [RFC 5681](https://www.rfc-editor.org/rfc/rfc5681.html),
//! [RFC 6582](https://www.rfc-editor.org/rfc/rfc6582.html); CUBIC —
//! [RFC 8312](https://www.rfc-editor.org/rfc/rfc8312.html). Window growth
//! uses Appropriate Byte Counting ([`super::abc`], RFC 3465); whether growth
//! is allowed uses New CWV ([`super::cwv`], RFC 7661).

mod cubic;
mod reno;

pub use cubic::CubicState;
pub use reno::RenoState;

/// Which congestion-control algorithm a TCB is running.
#[derive(Clone, Debug)]
pub enum CongestionControl {
    /// Reno / NewReno - linear growth, halves cwnd on loss.
    Reno(RenoState),

    /// CUBIC - cubic growth curve.
    Cubic(CubicState),
}

/// Point-in-time CC / RTT sample for debugging purposes.
#[derive(Clone, Copy, Debug)]
pub struct TcpCcSnapshot {
    /// Sample timestamp in ns.
    pub t_ns: u64,

    /// Smoothed RTT, µs.
    pub srtt_us: u64,

    /// RTT variance, µs.
    pub rttvar_us: u64,

    /// Current retransmission timeout, µs.
    pub rto_us: u64,

    /// Congestion window, bytes.
    pub cwnd: u32,

    /// Slow-start / congestion-avoidance threshold.
    pub ssthresh: u32,

    /// Receiver's advertised window.
    pub snd_wnd: u32,

    /// Bytes currently in flight.
    pub flight: u32,

    /// 0 = Reno, 1 = CUBIC
    pub algo: u8,

    /// CUBIC: window size at the last loss - the point the curve aims back at.
    pub w_max: u32,

    /// CUBIC: time (ns) for the curve to climb back to `w_max`.
    pub k_ns: u64,

    /// In fast recovery right now (loss detected via dup ACKs, not yet repaired).
    pub in_fast_recovery: bool,

    /// Consecutive duplicate ACKs seen (fast retransmit usually fires at 3).
    pub dupacks: u32,

    /// TCP Timestamps (RFC 7323) negotiated.
    pub ts_enabled: u8,

    /// Latest RTT probe sample, µs.
    pub rtt_probe_us: u64,

    /// Timestamp tied to that probe, µs.
    pub rtt_ts_us: u64,

    /// Spurious retransmissions caught by the Eifel algorithm.
    pub eifel_spurious: u32,

    /// Pending `pipe_prev` from Eifel detection, or 0 if none.
    pub eifel_pipe_prev: u32,

    /// 1 if Classic ECN was negotiated (RFC 3168).
    pub ecn_enabled: u8,

    /// CE marks seen on incoming IP packets.
    pub ecn_ce_seen: u32,

    /// ECE marks we've sent.
    pub ecn_ece_tx: u32,

    /// ECE marks we've received.
    pub ecn_ece_rx: u32,

    /// Window reductions triggered by ECN (no actual packet loss).
    pub ecn_md: u32,

    /// CWR marks we've sent.
    pub ecn_cwr_tx: u32,

    /// 1 if RFC 7661 New CWV is enabled on this TCB.
    pub cwv_enabled: u8,

    /// 1 if New CWV currently considers cwnd validated (RFC 7661 §4.1) —
    /// while unvalidated, growth is blocked.
    pub cwv_validated: u8,

    /// Largest `pipe` seen in the current New CWV validation window.
    pub cwv_pipe_max: u32,

    /// Shadow congestion window without RFC 7661 gating.
    pub cwnd_no_cwv: u32,

    /// Times New CWV blocked growth (§4.1, cwnd unvalidated).
    pub cwv_no_increase: u32,

    /// Reductions from idle periods (§4.2).
    pub cwv_idle_reduce: u32,

    /// Reductions from prolonged app-limited periods (§4.3).
    pub cwv_applim_reduce: u32,

    /// RFC 3465 ABC CA accumulator (real cwnd).
    pub abc_ca_accum: u32,

    pub abc_bytes_credited: u64,

    /// Times slow-start growth got capped by the `L*SMSS` limit (RFC 3465 §2.1).
    pub abc_ss_capped: u32,

    /// Full +1 SMSS increments applied in congestion avoidance.
    pub abc_ca_increments: u32,

    /// 0=Idle, 1=Step1, 2=Step2 (RFC 5682); always 0 when Timestamps on.
    pub frto_phase: u8,

    /// Retransmissions F-RTO flagged as spurious (unneeded).
    pub frto_spurious: u32,

    /// Retransmissions F-RTO confirmed as real loss.
    pub frto_declared_loss: u32,

    /// 1 if pacing is enabled on this TCB.
    pub pacing_enabled: u8,

    /// Current pacing rate (bytes/s); 0 if inactive / no SRTT yet.
    pub pacing_rate_bps: u64,

    /// Last inter-segment gap (µs).
    pub pacing_gap_us: u64,

    /// Segments held back waiting their turn under pacing.
    pub pacing_held: u32,

    /// Segments sent on schedule under pacing.
    pub pacing_paced: u32,

    /// 1 if SACK-Permitted was negotiated.
    pub sack_enabled: u8,

    pub sack_blocks_rx: u32,

    pub sack_blocks_tx: u32,

    /// Segments the RFC 6675 `IsLost` check flagged as lost.
    pub sack_islost: u32,

    /// Retransmits triggered by RACK's time-based heuristic instead of dupACK count.
    pub sack_rack: u32,

    /// Tail Loss Probes sent.
    pub sack_tlp: u32,

    /// Retransmits undone after a D-SACK showed they weren't needed.
    pub sack_dsack_undo: u32,

    /// Retransmits sent to patch holes flagged by the SACK map.
    pub sack_rexmit_holes: u32,

    /// Distinct out-of-order ranges currently tracked in the SACK map.
    pub sack_ooo_ranges: u8,
}

use super::{TcpDriver, cwv::CwvReduceReason, types::TcpControlBlock};
use crate::subsystem::clock::time::{Duration, Instant};

/// Called on every incoming ACK: grows `cwnd` per the current phase
/// (slow start / congestion avoidance) using ABC byte counting (RFC 3465),
/// gated by New CWV (RFC 7661).
///
/// No-ops during fast recovery; the window doesn't grow again until the
/// hole in the stream is patched.
pub(super) fn update_congestion_window(tcb: &mut TcpControlBlock, bytes_acked: u32) {
    // We don't grow CWND if Fast Recovery is active.
    if tcb.in_fast_recovery {
        return;
    }

    // Apply cwnd growth for the debugging purposes.
    grow_cwnd_value(tcb, true, bytes_acked);

    // If the CWV (Congestion Window Validation) feature is disabled, we just trust the caller
    // and set tcb.cwnd into calculated value, and return.
    if !tcb.cwv.enabled {
        tcb.cwnd = tcb.cwv.cwnd_raw;

        log::trace!("CWV off: cwnd=cwnd_no_cwv={} {:?}", tcb.cwnd, tcb.tuple);

        return;
    }

    let now = Instant::now();

    // If there's no data for the time bigger than RTO, CWV reduces CWND because of
    // non-validated phase.
    if now - tcb.cwv.last_data_tx > tcb.rto {
        super::cwv::cwv_reduce_cwnd(tcb, CwvReduceReason::Idle);
    }

    // If we're app-limited for more than RTO, CWV reduces CWND.
    if let Some(since) = tcb.cwv.app_limited_since
        && now - since >= tcb.rto
    {
        super::cwv::cwv_reduce_cwnd(tcb, CwvReduceReason::AppLimited);

        tcb.cwv.app_limited_since = Some(now);
    }

    // We can't increase CWND while in non-validated phase.
    if !tcb.cwv.validated {
        // Save debug info
        tcb.cwv.no_increase = tcb.cwv.no_increase.saturating_add(1);

        log::trace!(
            "CWV no-increase not-validated phase: cwnd={} cwnd_no_cwv={} pipe_max={} {:?}",
            tcb.cwnd,
            tcb.cwv.cwnd_raw,
            tcb.cwv.pipe_max,
            tcb.tuple
        );

        return;
    }

    // Consume this validation credit for one growth sample.
    tcb.cwv.validated = false;
    tcb.cwv.pipe_max = 0;

    // Actually grow the CWND now.
    grow_cwnd_value(tcb, false, bytes_acked);

    log::trace!(
        "CWV+ABC grow: cwnd={} cwnd_no_cwv={} bytes_acked={} {:?}",
        tcb.cwnd,
        tcb.cwv.cwnd_raw,
        bytes_acked,
        tcb.tuple
    );
}

/// Actual per-ACK cwnd increment, depending on the phase:
///
/// - Slow Start (`cwnd < ssthresh`): grow by the acked bytes (ABC), capped
///   at `L * SMSS` (RFC 3465 §2.3) so one big cumulative ACK can't blow the
///   window up in a single step.
/// - Congestion Avoidance (`cwnd >= ssthresh`): bytes pile up in an
///   accumulator (RFC 3465 §2.1), and cwnd only grows by one SMSS once
///   the accumulator catches up to the current window.
///
/// `raw` picks whether we're updating the real, CWV-gated cwnd or the real window.
///
/// For CUBIC, congestion avoidance instead targets the cubic curve (RFC
/// 8312), but never below what plain Reno would give (TCP-friendliness).
pub(super) fn grow_cwnd_value(tcb: &mut TcpControlBlock, raw: bool, bytes_acked: u32) {
    // No need to grow CWND if received segment didn't ACK any byte.
    if bytes_acked == 0 {
        return;
    }

    let ssthresh = tcb.ssthresh;
    let smss = tcb.effective_mss.max(1);
    let l_bytes = smss.saturating_mul(tcb.abc.l_smss as u32);

    let cwnd_now = if raw { tcb.cwv.cwnd_raw } else { tcb.cwnd };

    if cwnd_now < ssthresh {
        // RFC 3465 §2.2 - Slow Start byte counting with L cap.
        let credit = bytes_acked.min(l_bytes);

        if credit < bytes_acked {
            // If we capped ACKed bytes with a `L * MSS` formula, just increase the counter for the tracking purposes.
            tcb.abc.ss_capped = tcb.abc.ss_capped.saturating_add(1);
        }

        if raw {
            tcb.cwv.cwnd_raw = tcb.cwv.cwnd_raw.saturating_add(credit);
        } else {
            tcb.cwnd = tcb.cwnd.saturating_add(credit);
        }

        // tracing
        tcb.abc.bytes_credited = tcb.abc.bytes_credited.saturating_add(credit as u64);

        log::trace!(
            "ABC SS: +{} (acked={}, L·SMSS={}) cwnd={} cwnd_no_cwv={} {:?}",
            credit,
            bytes_acked,
            l_bytes,
            tcb.cwnd,
            tcb.cwv.cwnd_raw,
            tcb.tuple
        );

        return;
    }

    // RFC 3465 §2.1 - Congestion Avoidance byte accumulator.
    if raw {
        tcb.abc.ca_accum_raw = tcb.abc.ca_accum_raw.saturating_add(bytes_acked);
    } else {
        tcb.abc.ca_accum = tcb.abc.ca_accum.saturating_add(bytes_acked);
        tcb.abc.bytes_credited = tcb.abc.bytes_credited.saturating_add(bytes_acked as u64);
    }

    // Calculate Reno window growth.
    let mut reno_wnd = if raw { tcb.cwv.cwnd_raw } else { tcb.cwnd };
    loop {
        let accum = if raw {
            tcb.abc.ca_accum_raw
        } else {
            tcb.abc.ca_accum
        };

        // If we have not enough bytes for +1 MSS, just break the loop.
        if reno_wnd == 0 || accum < reno_wnd {
            break;
        }

        if raw {
            tcb.abc.ca_accum_raw -= reno_wnd;
        } else {
            tcb.abc.ca_accum -= reno_wnd;
        }

        // Add +1 MSS to CWND
        reno_wnd = reno_wnd.saturating_add(smss);

        // Debug counter
        tcb.abc.ca_increments = tcb.abc.ca_increments.saturating_add(1);
    }

    match &tcb.congestion_control {
        CongestionControl::Cubic(cubic) => {
            // CUBIC target, but never below Reno's - keeps CUBIC from
            // being slower than Reno in the same conditions (TCP friendliness).
            let elapsed = Instant::now() - cubic.epoch_start;
            let cubic_target = calculate_cubic_window(cubic, elapsed);
            let target = cubic_target.max(reno_wnd);

            let cwnd = if raw {
                &mut tcb.cwv.cwnd_raw
            } else {
                &mut tcb.cwnd
            };

            if target > *cwnd {
                // Don't jump straight to target - at most +1 SMSS per call.
                let inc = (target - *cwnd).min(smss);
                *cwnd = cwnd.saturating_add(inc);
            } else {
                *cwnd = reno_wnd;
            }
        }
        CongestionControl::Reno(_) => {
            if raw {
                tcb.cwv.cwnd_raw = reno_wnd;
            } else {
                tcb.cwnd = reno_wnd;
            }
        }
    }
}

/// Reaction to a detected loss - multiplicative decrease. cwnd is cut
/// by a factor, and `ssthresh` remembers the new, lower ceiling.
///
/// - Reno: `ssthresh = flight / 2`.
/// - CUBIC: `ssthresh = cwnd * beta` (gentler than Reno's halving,
///   `beta` ~0.7). Also tracks `W_max`, the window the curve re-targets.
///
/// Also computes `K` (time for the curve to climb back to `w_max`) once
/// here, so [`calculate_cubic_window`] doesn't redo that math per packet.
pub(super) fn on_congestion_event(_driver: &TcpDriver, tcb: &mut TcpControlBlock) {
    // If SACK is enabled, let's use SACK provided in-flight bytes count, because it is
    // more reliable than default SND.NXT - SND.UNA
    let flight = if tcb.sack.enabled {
        super::sack::sack_pipe_bytes(tcb)
    } else {
        tcb.flight_size_bytes()
    };

    let smss = tcb.effective_mss.max(1);

    match tcb.congestion_control {
        CongestionControl::Cubic(ref mut cubic) => {
            let prev = cubic.last_max_cwnd;

            cubic.epoch_start = Instant::now();

            // Save current CWND as max CWND
            cubic.last_max_cwnd = tcb.cwnd;

            // Fast Convergence. If `cwnd > prev`, its normal situation, because we grew
            // our CWND bigger than it was before last drop occurred. If `cwnd < prev`, it
            // means that network topology has changed or someone is sending more data, thus blocking
            // us - don't target full CWND, but instead try to catch up to 90% of CWND as our target.
            cubic.w_max = if tcb.cwnd < prev {
                (tcb.cwnd * 9) / 10
            } else {
                tcb.cwnd
            };

            // ssthresh = cwnd * beta, but we don't want to use FP instructions in kernel, so perform
            // little trick with using 1024-scaled values.
            tcb.ssthresh = ((tcb.cwnd as u64 * cubic.beta as u64) >> 10) as u32;

            // cwnd = ssthresh + 3 * MSS (Fast Recovery inflation - +3 segments from DupACKs)
            tcb.cwnd = tcb.ssthresh + 3 * smss;

            // Perform same calculations on shadow values.
            let raw_ss = ((tcb.cwv.cwnd_raw as u64 * cubic.beta as u64) >> 10) as u32;
            tcb.cwv.cwnd_raw = raw_ss + 3 * smss;

            // Save the number of the bytes we've sent before the drop - so we won't enter
            // on_congestion_event multiple times in single drop.
            cubic.recover = tcb.snd_nxt;

            // K = cbrt(W_max*(1-beta)/C), computed here so future calls
            // to calculate_cubic_window don't need to redo it per-packet.
            let diff = cubic.w_max.saturating_sub(tcb.cwnd) as f64;
            let c = (cubic.c as f64) / 1024.0;
            let k_s = if diff > 0.0 && c > 0.0 {
                libm::cbrt(diff / c)
            } else {
                0.0
            };
            cubic.k_ns = (k_s * 1_000_000_000.0) as u64;
        }
        CongestionControl::Reno(ref mut reno) => {
            // Halve the ssthresh
            tcb.ssthresh = (flight / 2).max(2 * smss);

            // +3 MSS is typical Fast Recovery inflation
            tcb.cwnd = tcb.ssthresh + 3 * smss;

            // Same with shadow values
            tcb.cwv.cwnd_raw = (tcb.cwv.cwnd_raw / 2)
                .max(2 * smss)
                .saturating_add(3 * smss);

            // Save the number of the bytes we've sent before the drop - so we won't enter
            // on_congestion_event multiple times in single drop.
            reno.recover = tcb.snd_nxt;
        }
    }

    log::trace!(
        "MD: cwnd={} cwnd_no_cwv={} ssthresh={} {:?}",
        tcb.cwnd,
        tcb.cwv.cwnd_raw,
        tcb.ssthresh,
        tcb.tuple
    );

    tcb.abc.clear_accumulators();
}

/// CUBIC's target window (RFC 8312) at `elapsed` time since the last
/// loss: `W(t) = C * (t - K)^3 + W_max`. Right after a loss growth is fast,
/// then flattens out near `w_max` (where it hurt last time), then speeds
/// up again if no new loss shows up - CUBIC probes the ceiling instead of
/// climbing linearly like Reno.
pub(super) fn calculate_cubic_window(cubic: &CubicState, elapsed: Duration) -> u32 {
    let t = (elapsed.as_nanos() as f64) / 1e9;
    let k = (cubic.k_ns as f64) / 1e9;
    let c = (cubic.c as f64) / 1024.0;

    let diff = t - k;
    let w = c * (diff * diff * diff) + cubic.w_max as f64;

    if w.is_nan() || w < 0.0 {
        cubic.w_max
    } else {
        w as u32
    }
}
