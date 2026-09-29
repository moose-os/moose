//! New Congestion Window Validation (New CWV).
//!
//! RFC: [RFC 7661](https://www.rfc-editor.org/rfc/rfc7661.html).
//!
//! Problem: `cwnd` grows on every ACK that advances SND.UNA - it's fine
//! when the sender is network-limited (we have data to send, but the cwnd and
//! network is slowing us down), but wrong when it's application-limited (app
//! just isn't writing much, or Nagle is holding us back). ACKs still inflate cwnd
//! even though the path never proved it can handle that much.
//!
//! If we leave a connection idle or lightly loaded for a
//! while, and cwnd quietly balloons to something the network was never
//! actually tested against (especially fast with CUBIC growth) - then
//! the next burst, dumps that oversized window in one go and causes loss
//! that didn't need to happen.
//!
//! The fix: only let cwnd grow when it's actually been "validated" -
//! i.e. flight has recently pressed against it. If the connection goes
//! idle for longer than an RTO, or stays application-limited for
//! that long, pull `cwnd` back down toward what was actually observed
//! in flight, instead of leaving it inflated.
//!
//! Logic lives in [`super::TcpDriver::update_congestion_window`] and the
//! send-path hooks; this file is just the state and the two building
//! blocks (`cwv_note_validated` / `cwv_note_app_limited` /
//! `cwv_reduce_cwnd`) they call into.

use super::types::TcpControlBlock;
use crate::subsystem::clock::time::Instant;

/// RFC 7661 New CWV state.
#[derive(Clone, Debug)]
pub(super) struct NewCwvState {
    /// Master switch — false means this has no effect on `cwnd` at all.
    pub(super) enabled: bool,

    /// Flight has recently pressed against cwnd. Cleared after one
    /// growth sample is consumed.
    pub(super) validated: bool,

    /// Peak flight size seen since the last growth/validation sample.
    pub(super) pipe_max: u32,

    /// Last time we sent new data (not just ACKs). Used for idle clock.
    pub(super) last_data_tx: Instant,

    /// When the current app-limited streak started, if any.
    pub(super) app_limited_since: Option<Instant>,

    /// Shadow cwnd that grows with plain SS/CA, without gating - for
    /// comparison against the real cwnd.
    pub(super) cwnd_raw: u32,

    // diagnostics
    /// Times idle blocked a would-be increase.
    pub(super) no_increase: u32,
    /// Times idle validation pulled cwnd down.
    pub(super) idle_reduce: u32,
    /// Times app-limited validation pulled cwnd down.
    pub(super) applim_reduce: u32,
}

impl NewCwvState {
    pub(super) fn new(enabled: bool, initial_cwnd: u32) -> Self {
        Self {
            enabled,
            // Treat a fresh connection as already validated so early
            // slow start isn't blocked before we've seen any traffic.
            validated: true,
            pipe_max: 0,
            last_data_tx: Instant::now(),
            app_limited_since: None,
            cwnd_raw: initial_cwnd,
            no_increase: 0,
            idle_reduce: 0,
            applim_reduce: 0,
        }
    }
}

/// Why `cwv_reduce_cwnd` is being called. Doesn't affect the math at all -
/// both reasons reduce cwnd the same way - this only exists so the right
/// counter gets picked for debugging.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum CwvReduceReason {
    /// Idle longer than an RTO.
    Idle,

    /// Application-limited longer than an RTO.
    AppLimited,
}

pub(super) fn cwv_note_validated(tcb: &mut TcpControlBlock) {
    if !tcb.cwv.enabled {
        return;
    }

    tcb.cwv.validated = true;
    tcb.cwv.app_limited_since = None;
}

pub(super) fn cwv_note_app_limited(tcb: &mut TcpControlBlock) {
    if !tcb.cwv.enabled {
        return;
    }

    tcb.cwv.validated = false;

    if tcb.cwv.app_limited_since.is_none() {
        tcb.cwv.app_limited_since = Some(Instant::now());
    }
}

pub(super) fn cwv_reduce_cwnd(tcb: &mut TcpControlBlock, reason: CwvReduceReason) {
    // Get either max cwnd or count of in flight bytes (max)
    let pipe = tcb.cwv.pipe_max.max(tcb.flight_size_bytes());

    // We can't cut CWND below 2 * MSS
    let floor = (2 * tcb.effective_mss).max(1);
    let target = pipe.max(floor);

    // If current CWND > target CWND and we're in not validated state, then
    // lower the CWND.
    if tcb.cwnd > target {
        tcb.cwnd = target;

        // If old ssthresh is lower than currnet CWND, then ssthresh = cwnd, to let the
        // TCP stack know that the link previously handled bigger payloads.
        if tcb.ssthresh < tcb.cwnd {
            tcb.ssthresh = tcb.cwnd;
        }

        // Only for tracing purposes:
        match reason {
            CwvReduceReason::Idle => {
                tcb.cwv.idle_reduce = tcb.cwv.idle_reduce.saturating_add(1);

                log::trace!(
                    "CWV idle reduce: cwnd={} cwnd_no_cwv={} pipe={} {:?}",
                    tcb.cwnd,
                    tcb.cwv.cwnd_raw,
                    pipe,
                    tcb.tuple
                );
            }
            CwvReduceReason::AppLimited => {
                tcb.cwv.applim_reduce = tcb.cwv.applim_reduce.saturating_add(1);

                log::trace!(
                    "CWV app-limited reduce: cwnd={} cwnd_no_cwv={} pipe={} {:?}",
                    tcb.cwnd,
                    tcb.cwv.cwnd_raw,
                    pipe,
                    tcb.tuple
                );
            }
        }
    }

    tcb.cwv.pipe_max = pipe;
}
