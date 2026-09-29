//! TCP Timestamps and PAWS (Protection Against Wrapped Sequence numbers).
//!
//! RFC: [RFC 7323](https://www.rfc-editor.org/rfc/rfc7323.html) (TCP
//! Extensions for High Performance).
//!
//! Two mostly-unrelated things are based on the same option, which is why
//! they're bundled here.
//!
//! RTT sampling: Without Timestamps, RTT can only be measured by
//! timing one "probe" segment at a time and matching it to its ACK -
//! and if that segment ever gets retransmitted, you can't tell which
//! copy the ACK is actually for (Karn's ambiguity), so retransmitted
//! segments can't be used as samples. Timestamps sidestep that: every
//! segment carries a TSval, every ACK echoes it back as TSecr, so
//! `now - TSecr` gives a clean RTT sample on essentially every ACK, no
//! matching required. That's also what makes Eifel's spurious-RTO
//! detection possible at all.
//!
//! PAWS. On a fast, high-bandwidth connection, 32-bit sequence
//! numbers can wrap around within the time a segment could still be
//! floating around the network and get mistaken for new data. PAWS adds
//! a second check on top of the sequence number: if an incoming
//! segment's TSval is older than the most recent one we've accepted
//! (`ts_recent`), it's treated as a stray from before the wrap and
//! dropped - unless the connection's been idle long enough
//! ([`PAWS_IDLE`]) that the check doesn't mean anything anymore.
//!
//! One extra wrinkle: `offset` adds a random per-connection bias to the
//! outgoing TSval instead of sending raw uptime. Otherwise TSval leaks
//! how long the host has been up, which is a fingerprinting / idle-scan
//! vector. It doesn't break the RTT math - `now - TSecr` cancels the
//! offset out the same way on both sides.

use x86_64::instructions::random::RdRand;

use crate::subsystem::clock::time::{Duration, Instant};

/// PAWS idle threshold (24 days @ 1 ms timestamp tick) -
/// past this, a gap in TSval no longer implies a stray old segment.
pub(super) const PAWS_IDLE: Duration = Duration::from_secs(24 * 24 * 3600);

/// One in-flight Karn-style RTT probe: we timed sending this segment and
/// are waiting for the ACK that confirms it (not a retransmit) to time
/// the round trip.
#[derive(Clone, Copy, Debug)]
pub(super) struct RttProbe {
    /// Sequence number of the packet with RTT probe.
    pub(super) seq: u32,

    /// Exclusive end of the probed segment (seq + SEG.LEN, SYN/FIN count as 1).
    pub(super) end: u32,

    /// Time, the segment was sent at.
    pub(super) sent_at: Instant,
}

/// Tracks both RTT sources side by side.
#[derive(Clone, Debug)]
pub(super) struct RttMeasurementState {
    pub(super) probe: Option<RttProbe>,
    pub(super) last_probe_sample: Option<Duration>,
    pub(super) last_ts_sample: Option<Duration>,
}

impl RttMeasurementState {
    pub(super) fn new() -> Self {
        Self {
            probe: None,
            last_probe_sample: None,
            last_ts_sample: None,
        }
    }
}

/// Per-connection Timestamps/PAWS state.
#[derive(Clone, Debug)]
pub(super) struct TcpTimestampState {
    /// Both ends offered Timestamps during the handshake.
    pub(super) enabled: bool,

    /// The most recent peer TSval we've accepted - PAWS compares new
    /// segments against this, and it's echoed back as our outgoing TSecr.
    pub(super) ts_recent: u32,

    /// Sequence number that last advanced `ts_recent`.
    pub(super) last_ack_ts_seq: u32,

    /// When `ts_recent` was last refreshed - feeds the PAWS idle check.
    pub(super) recent_age: Instant,

    /// Last TSval we put on the wire.
    pub(super) last_tx_tsval: u32,

    /// Random per-connection bias folded into outgoing TSval so it
    /// doesn't just reveal host uptime.
    pub(super) offset: u32,
}

impl TcpTimestampState {
    pub(super) fn new() -> Self {
        let offset = RdRand::new()
            .and_then(|r| r.get_u32())
            .unwrap_or(0xA5A5_5A5A);

        Self {
            enabled: false,
            ts_recent: 0,
            last_ack_ts_seq: 0,
            recent_age: Instant::now(),
            last_tx_tsval: 0,
            offset,
        }
    }
}

use super::{
    options::{TcpOption, TcpOptionsParser},
    sack::rack_feed_rtt,
    types::TcpControlBlock,
};
use crate::kernel::kernel_ref;

/// Current TSval to stamp on an outgoing segment - the monotonic clock in
/// milliseconds, offset by this connection's random bias.
pub(super) fn tcp_ts_now(offset: u32) -> u32 {
    let ms = (kernel_ref().clock().monotonic_ns() / 1_000_000) as u32;
    ms.wrapping_add(offset)
}

/// Pulls the Timestamps option (TSval, TSecr) out of a segment's options, if present.
pub(super) fn find_timestamp(options: &[u8]) -> Option<(u32, u32)> {
    for opt in TcpOptionsParser::new(options) {
        if let TcpOption::Timestamp { tsval, tsecr } = opt {
            return Some((tsval, tsecr));
        }
    }

    None
}

/// Runs an incoming segment's TSval through PAWS and updates `ts_recent`.
/// Returns `false` if the segment should be dropped as a stray from
/// before a sequence-number wrap.
pub(super) fn on_rx_timestamp(
    tcb: &mut TcpControlBlock,
    seg_seq: u32,
    tsval: u32,
    is_syn: bool,
    is_rst: bool,
) -> bool {
    // This function assumes that Timestamps are enabled, but just
    // for safety reasons:
    if !tcb.ts.enabled {
        return true;
    }

    // Check, whether the link was idle long enough to not trust the packet.
    let idle = (Instant::now() - tcb.ts.recent_age) > PAWS_IDLE;

    // RFC 7323: RST and SYN are exempt from PAWS drop.
    // THen make sure we have any timestamp to compare against and check the PAWS.
    if !is_rst
        && !is_syn
        && !idle
        && tcb.ts.ts_recent != 0
        && (tsval.wrapping_sub(tcb.ts.ts_recent) as i32) < 0
    {
        log::trace!(
            "PAWS drop: TSval={} < TS.Recent={} seq={}",
            tsval,
            tcb.ts.ts_recent,
            seg_seq
        );

        // Drop the packet.
        return false;
    }

    // Need to refresh TS.Recent when SEG.SEQ advances.
    let advances = (seg_seq.wrapping_sub(tcb.ts.last_ack_ts_seq) as i32) >= 0;

    if advances || is_syn {
        tcb.ts.ts_recent = tsval;
        tcb.ts.last_ack_ts_seq = seg_seq;
        tcb.ts.recent_age = Instant::now();
    }

    // Accept the packet.
    true
}

/// Feeds one fresh RTT sample `r` into the SRTT/RTTVAR/RTO estimators
/// (RFC 6298), regardless of whether it came from a Karn probe or a
/// Timestamp echo - the caller already decided which source to trust.
pub(super) fn update_rtt_estimators(tcb: &mut TcpControlBlock, r: Duration) {
    // RFC 8985: RACK's reordering-window heuristic is keyed off the
    // smallest RTT seen recently.
    rack_feed_rtt(tcb, r);

    let r_ns = r.as_nanos();

    match (tcb.srtt, tcb.rttvar) {
        (Some(srtt), Some(rttvar)) => {
            // RTTVAR = (3/4) * RTTVAR + (1/4) * |SRTT - R|
            // SRTT   = (7/8) * SRTT   + (1/8) * R

            let smoothed = srtt.as_nanos();
            let variance = rttvar.as_nanos();

            let diff = smoothed.abs_diff(r_ns);
            tcb.rttvar = Some(Duration::from_nanos((3 * variance) / 4 + diff / 4));
            tcb.srtt = Some(Duration::from_nanos((7 * smoothed) / 8 + r_ns / 8));
        }
        _ => {
            // First sample: seed SRTT with R itself and
            // RTTVAR with R/2.
            tcb.srtt = Some(r);
            tcb.rttvar = Some(Duration::from_nanos(r_ns / 2));
        }
    }

    // RTO = SRTT + 4*RTTVAR, clamped to [1s, 60s].
    let srtt = tcb.srtt.unwrap();
    let rttvar = tcb.rttvar.unwrap();
    let four_rttvar = Duration::from_nanos(rttvar.as_nanos().saturating_mul(4));

    let rto = Duration::from_nanos(srtt.as_nanos().saturating_add(four_rttvar.as_nanos()));
    tcb.rto = rto.max(Duration::from_secs(1)).min(Duration::from_secs(60));
}
