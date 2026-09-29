//! Explicit Congestion Notification (ECN) for TCP.
//!
//! RFC: [RFC 3168](https://www.rfc-editor.org/rfc/rfc3168.html) (Classic ECN);
//! negotiation uses the ECE/CWR flags from [RFC 9293](https://www.rfc-editor.org/rfc/rfc9293.html).
//!
//! Normally the only way TCP learns about congestion is a dropped
//! packet. ECN lets a router mark the packet instead of dropping it:
//! it flips a CE (Congestion Experienced) bit in the IP header rather
//! than discarding the packet in case of congestion on the link. The
//! receiver sees that mark and starts echoing ECE on its ACKs; the
//! sender treats ECE just like a loss for congestion-control purposes
//! (multiplicative decrease, no retransmit needed since nothing was
//! actually dropped) and sets CWR on its next data segment to indicate
//! it reduced the window.
//!
//! Effect: congestion feedback without the packet loss that would
//! normally carry it - better throughput and latency on paths where
//! routers support it.
//!
//! Negotiated during the handshake (SYN sets ECE+CWR, SYN-ACK echoes
//! ECE).
//!
//! The handshake and the actual MD-on-ECE reaction live in
//! [`super::TcpDriver`].

/// RFC 3168: ECT(0) - ECN-capable transport, codepoint 10.
pub(super) const IP_ECN_ECT0: u8 = 0b10;
/// RFC 3168: CE - Congestion Experienced, codepoint 11.
pub(super) const IP_ECN_CE: u8 = 0b11;

/// Classic ECN state.
#[derive(Clone, Debug, Default)]
pub(super) struct TcpEcnState {
    /// Set once both SYNs completed the ECE/CWR handshake.
    pub(super) enabled: bool,

    /// We saw CE on an incoming packet - keep sending ECE on ACKs until
    /// the sender acks it back with CWR (RFC 3168 §6.1.3).
    pub(super) echo_pending: bool,

    /// We handled this ECE - send CWR once on the next data
    /// segment to close the loop.
    pub(super) cwr_pending: bool,

    // stats
    /// Times we saw CE in the IP header.
    pub(super) ce_seen: u32,

    /// Times we set ECE on an outgoing ACK.
    pub(super) ece_tx: u32,

    /// Times we processed an incoming ECE (sender side).
    pub(super) ece_rx: u32,

    /// Times we backed off cwnd because of ECE rather than an actual loss.
    pub(super) ecn_md: u32,

    /// Times we set CWR on an outgoing data segment.
    pub(super) cwr_tx: u32,
}

impl TcpEcnState {
    pub(super) fn new() -> Self {
        Self::default()
    }
}

use super::types::{TcpControlBlock, TcpDatagramHeader};

/// Stamps outgoing ECN state onto a header: ECE if we owe the sender an
/// echo of a CE mark we saw, CWR if we owe an ack that we already backed
/// off.
pub(super) fn apply_outgoing_ecn(
    tcb: &mut TcpControlBlock,
    header: &mut TcpDatagramHeader,
    data: &[u8],
) -> u8 {
    // Don't send any codepoint if ECN is disabled.
    if !tcb.ecn.enabled {
        return 0;
    }

    // Set the ECE if we need to echo congestion back to the remote.
    if tcb.ecn.echo_pending && header.is_ack() {
        header.set_flag(TcpDatagramHeader::ECE, true);
        tcb.ecn.ece_tx = tcb.ecn.ece_tx.saturating_add(1);
    }

    // Set CWR if we have successfully handled congestion event.
    if tcb.ecn.cwr_pending && !data.is_empty() {
        header.set_flag(TcpDatagramHeader::CWR, true);
        tcb.ecn.cwr_tx = tcb.ecn.cwr_tx.saturating_add(1);
        tcb.ecn.cwr_pending = false;
    }

    // Congestion codepoint indicating we support the feature
    IP_ECN_ECT0
}
