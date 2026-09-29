//! Forward RTO-Recovery (F-RTO) for spurious timeout undo.
//!
//! RFC: [RFC 5682](https://www.rfc-editor.org/rfc/rfc5682.html).
//!
//! Same problem as Eifel solves - an RTO firing even though the data
//! actually got through - but for connections that didn't negotiate
//! Timestamps, so there's no TSecr to compare against.
//!
//! F-RTO instead watches how the next couple of ACKs behave after the RTO
//! retransmit: if they keep advancing SND.UNA, the original data (and
//! the retransmit) both made it and the timeout was spurious; if a
//! dupACK shows up instead, it really was a loss.
//!
//! Mutually exclusive with Eifel - `tcb.ts.enabled` means Timestamps are
//! on, so Eifel handles this instead and F-RTO just stays `Idle`
//! forever.
//!
//! It works with two-step probe:
//! - RTO happens -> retransmit just the head segment, remember where
//!   SND.NXT was, go to `Step1`.
//! - First ACK back: a dupACK means real loss, stop here. A cumulative
//!   ACK means the retransmit (or the original) got through - move to
//!   `Step2` and send one segment of genuinely new data as a further
//!   check.
//! - Next ACK: another dupACK still means real loss. Another cumulative
//!   advance confirms it was spurious - undo the MD.
//! - If a second RTO fires while we're mid-probe, that's real loss too -
//!   bail out, no re-arming.

/// F-RTO state (RFC 5682). Not armed at all when Timestamps/Eifel are enabled.
#[derive(Clone, Debug)]
pub(super) struct FrtoState {
    /// Where we are in the two-step probe.
    pub(super) phase: FrtoPhase,

    /// SND.NXT at RTO time - the Step2 probe must be new data at or past this.
    pub(super) recover_nxt: u32,

    /// Exclusive end of the segment we retransmitted on RTO.
    pub(super) rto_retrans_end: u32,

    /// cwnd from right before the RTO's MD, in case we need to undo it.
    pub(super) prev_cwnd: u32,

    /// ssthresh from right before the RTO's MD, in case we need to undo it.
    pub(super) prev_ssthresh: u32,

    // stats
    /// Times F-RTO confirmed the RTO was spurious.
    pub(super) spurious_count: u32,

    /// Times F-RTO confirmed it was a real loss (dupACK, or a nested RTO
    /// mid-probe).
    pub(super) declared_loss_count: u32,
}

/// Where F-RTO is in its two-step probe after an RTO retransmit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(super) enum FrtoPhase {
    /// Not running — either nothing's happened, or Timestamps are
    /// enabled and Eifel is handling this instead.
    Idle = 0,

    /// Just retransmitted on RTO, waiting on the first ACK to decide
    /// dupACK (real loss) vs. cumulative advance (send Step2 probe).
    Step1 = 1,

    /// Sent the new-data probe, waiting on the next ACK to decide
    /// dupACK (real loss) vs. cumulative advance (confirmed spurious).
    Step2 = 2,
}

impl FrtoState {
    pub(super) fn new() -> Self {
        Self {
            phase: FrtoPhase::Idle,
            recover_nxt: 0,
            rto_retrans_end: 0,
            prev_cwnd: 0,
            prev_ssthresh: 0,
            spurious_count: 0,
            declared_loss_count: 0,
        }
    }

    pub(super) fn clear(&mut self) {
        self.phase = FrtoPhase::Idle;
    }
}

use super::{eifel::eifel_clear_pending, types::TcpControlBlock};

/// Arms the F-RTO probe right after we've retransmitted on an RTO.
/// Snapshots what we'd need to restore if this turns out spurious.
pub(super) fn frto_on_rto(tcb: &mut TcpControlBlock, rto_retrans_end: u32) {
    // When Timestamps are available, Eifel handles this situation.
    if !tcb.ts.enabled {
        return;
    }

    // Save data we might need to recover soon.
    tcb.frto.prev_cwnd = tcb.cwnd;
    tcb.frto.prev_ssthresh = tcb.ssthresh;
    tcb.frto.recover_nxt = tcb.snd_nxt;
    tcb.frto.rto_retrans_end = rto_retrans_end;
    tcb.frto.phase = FrtoPhase::Step1;

    // Clear Eifel state - just defensive programming.
    eifel_clear_pending(tcb);

    log::trace!(
        "TCP F-RTO Step1 armed recover_nxt={} rto_end={} cwnd={} ssthresh={} {:?}",
        tcb.frto.recover_nxt,
        rto_retrans_end,
        tcb.cwnd,
        tcb.ssthresh,
        tcb.tuple
    );
}

/// Feeds one incoming ACK into the F-RTO state machine and advances
/// (or resolves) the probe.
pub(super) fn frto_on_ack(tcb: &mut TcpControlBlock, ack: u32, is_dup: bool) {
    if tcb.ts.enabled {
        tcb.frto.clear();

        return;
    }

    match tcb.frto.phase {
        FrtoPhase::Idle => {}
        FrtoPhase::Step1 => {
            if is_dup {
                // First feedback after the RTO retransmit is a dupACK - real loss.
                tcb.frto.declared_loss_count = tcb.frto.declared_loss_count.saturating_add(1);

                tcb.frto.clear();

                log::trace!(
                    "F-RTO Step1: dupACK ack={} -> not spurious {:?}",
                    ack,
                    tcb.tuple
                );

                return;
            }

            // Cumulative ACK advanced SND.UNA - send the new-data probe.
            tcb.frto.phase = FrtoPhase::Step2;

            // Make sure there's room to actually send that probe segment.
            let smss = tcb.effective_mss.max(1);
            tcb.cwnd = tcb.cwnd.max(smss);
            tcb.cwv.cwnd_raw = tcb.cwv.cwnd_raw.max(smss);

            log::trace!(
                "F-RTO Step1: ACK advanced ack={} -> send new-data probe {:?}",
                ack,
                tcb.tuple
            );
        }
        FrtoPhase::Step2 => {
            // Got another DupACK - it was a real loss.
            if is_dup {
                tcb.frto.declared_loss_count = tcb.frto.declared_loss_count.saturating_add(1);

                tcb.frto.clear();

                log::trace!(
                    "F-RTO Step2: dupACK ack={} -> not spurious {:?}",
                    ack,
                    tcb.tuple
                );

                return;
            }

            // Another cumulative advance confirms it - spurious RTO.
            frto_declare_spurious(tcb);
        }
    }
}

/// Undoes the RTO's congestion response once F-RTO has confirmed it was
/// spurious: rebuilds cwnd, restores ssthresh, and clears recovery state.
pub(super) fn frto_declare_spurious(tcb: &mut TcpControlBlock) {
    let smss = tcb.effective_mss.max(1);

    // Restore ssthresh: go back to what it was before the MD, but
    // never lower than the minimum (2x SMSS), and never lower than
    // whatever ssthresh happens to be right now.
    tcb.ssthresh = tcb.frto.prev_ssthresh.max((2 * smss).max(tcb.ssthresh));

    // cwnd is NOT restored to prev_cwnd, because at least 2-3 RTT passed,
    // the network could have changed and we didn't notice it - instead
    // use the currently in-flight byte count + one SMSS
    let flight = tcb.flight_size_bytes();
    tcb.cwnd = flight.saturating_add(smss).max(2 * smss);

    // Shadow window follows the real one here, because spurious retransmission
    // should not have any effect on CC algorithms.
    tcb.cwv.cwnd_raw = tcb.cwnd;

    // Current ABC state responds to the ACKed bytes before the loss occured.
    // Reset it, so it won't falsely expand window on the next ACK.
    tcb.abc.clear_accumulators();

    // Clear the Eifel state - it should be clear anyways, but for safety reasons.
    eifel_clear_pending(tcb);

    // We were treating this as a loss episode - since it's spurious, there's
    // no loss to recover from anymore.
    tcb.in_fast_recovery = false;

    // Diagnostics only.
    tcb.frto.spurious_count = tcb.frto.spurious_count.saturating_add(1);

    log::trace!(
        "F-RTO: spurious RTO undone cwnd={} ssthresh={} (was cwnd={} ssthresh={}) {:?}",
        tcb.cwnd,
        tcb.ssthresh,
        tcb.frto.prev_cwnd,
        tcb.frto.prev_ssthresh,
        tcb.tuple
    );

    // Reset the F-RTO state machine so it will be ready for
    // future RTOs.
    tcb.frto.clear();
}
