#![allow(unused)]
//! TCP core types.
//!
//! [`TcpControlBlock`] (TCB) is the per-connection state blob everything
//! else in this driver reads and mutates - send/receive sequence
//! variables, buffers, timers, and the congestion-control sub-state.
//! [`TcpDatagramHeader`] is the wire format; [`TcpState`] is the RFC 9293
//! state machine.

use alloc::{collections::VecDeque, sync::Arc, vec::Vec};

use zerocopy::{
    FromBytes, Immutable, IntoBytes, KnownLayout,
    network_endian::{U16, U32},
};

use super::{
    abc::AbcState,
    cc::{CongestionControl, CubicState, TcpCcSnapshot},
    cwv::NewCwvState,
    ecn::TcpEcnState,
    eifel::EifelState,
    frto::FrtoState,
    options::TCP_TS_OPTION_OVERHEAD,
    pacing::PacingState,
    receive_buffer::TcpReceiveBuffer,
    sack::SackRackState,
    timestamp::{RttMeasurementState, TcpTimestampState},
};
use crate::{
    driver::net::{Ipv4Addr, Socket},
    kernel::kernel_ref,
    subsystem::{
        clock::time::{Duration, Instant},
        scheduler::{Event, OneshotGate},
    },
};

/// Our own MSS ceiling - the largest segment we're willing to build,
/// before whatever the peer advertises is factored in.
pub const MSS: usize = 1460;

/// MSS we advertise to the peer on SYN/SYN-ACK. Same as [`MSS`] here
/// (1460 = standard 1500-byte Ethernet MTU minus 20B IP + 20B TCP).
pub const DEFAULT_MSS: u16 = 1460;

/// Receive-side window scale shift we offer by default (RFC 7323) -
/// scales our advertised window up by `2^7 = 128`.
pub const DEFAULT_RCV_WSCALE: u8 = 7;

/// RFC 5681 / RFC 6928: IW ≈ 1–10 SMSS; 1512 B ≈ one Ethernet SMSS.
const INITIAL_CWND: u32 = 1512;

/// RFC 5681: initial ssthresh SHOULD be set arbitrarily high
/// (e.g. largest possible advertised window) so the connection starts
/// in Slow Start. A value below INITIAL_CWND forces Congestion
/// Avoidance from the first ACK (`grow_cwnd_value`: cwnd < ssthresh).
/// 0x7fff_ffff matches the common "infinite ssthresh" sentinel (Linux).
const INITIAL_SSTHRESH: u32 = 0x7fff_ffff;

/// Default per-connection receive ring size.
pub const DEFAULT_TCP_RECV_BUFFER_BYTES: usize = 4096;

/// Hard cap on receive ring size.
pub const MAX_TCP_RECV_BUFFER_BYTES: usize = 256 * 1024;

/// Normalizes `SO_RCVBUF` / `max_rcv_wnd` into a safe ring capacity.
pub fn clamp_tcp_receive_buffer_bytes(requested: usize) -> usize {
    let cap = if requested > 0 {
        requested
    } else {
        DEFAULT_TCP_RECV_BUFFER_BYTES
    };

    if cap > MAX_TCP_RECV_BUFFER_BYTES {
        log::trace!(
            "recv buffer capped: requested={} max={}",
            cap,
            MAX_TCP_RECV_BUFFER_BYTES
        );

        MAX_TCP_RECV_BUFFER_BYTES
    } else {
        cap.max(DEFAULT_TCP_RECV_BUFFER_BYTES)
    }
}

/// TCP connection states as defined in [RFC 9293](https://www.rfc-editor.org/rfc/rfc9293.html).
///
/// ```text
///                               +---------+ ---------\      active OPEN
///                               |  CLOSED |            \    -----------
///                               +---------+<---------\  \   create TCB
///                                 |     ^              \  \
///                    passive OPEN |     |   CLOSE       \  \
///                    ------------ |     | ----------     \  \
///                     create TCB  |     | delete TCB      \  \
///                                 V     |                  \  V
///                               +---------+            +----------+
///                               |  LISTEN |            |  SYN-SENT|
///                               +---------+            +----------+
///                   rcv SYN      |     |                 |     ^
///                  -----------   |     |     SEND        |     |
///                   snd SYN,ACK  |     |    -------      |     |
///                                V     |    snd SYN      |     |
///                               +---------+              |     |
///                               |   SYN   | <------------      |
///                               |   RCVD  |          rcv SYN   |
///                               +---------+      -----------   |
///                   rcv ACK of SYN  |            snd SYN,ACK   |
///                   --------------  |    rcv SYN               |
///                           V       |   -----------            |
///                       +---------+ |   snd ACK                |
///                       |  ESTAB  |<-                          |
///                       +---------+                            |
///                        |     |                               |
///            CLOSE       |     |    rcv FIN                    |
///           -------      |     |    -------                    |
///           snd FIN      |     |    snd ACK                    |
///                        V     V                               |
///          +---------+      +---------+                        |
///          |  FIN    |      |  CLOSE  |                        |
///          | WAIT-1  |      |   WAIT  |                        |
///          +---------+      +---------+                        |
///            |    |          |     |                           |
///   rcv FIN  |    | rcv ACK  |     |  CLOSE                    |
///   -------  |    | -------  |     | -------                   |
///   snd ACK  |    |    V     |     | snd FIN                   |
///            V    | +---------+    V                           |
///       +---------+ |  FIN    |  +---------+                   |
///       | CLOSING | | WAIT-2  |  | LAST-ACK|                   |
///       +---------+ +---------+  +---------+                   |
///            |          | rcv FIN  |     |                     |
///   rcv ACK  |          | -------  |     | rcv ACK             |
///   -------  |          | snd ACK  |     | -------             |
///            V          V          |     V                     |
///          +----------+            |    +---------+            |
///          | TIME-WAIT| <----------     |  CLOSED |            |
///          +----------+                 +---------+            |
/// ```
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum TcpState {
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
}

/// A segment that has been sent but not yet acknowledged.
///
/// Kept in the retransmission queue until cumulatively ACKed by the peer.
/// Doubles as the bookkeeping struct for SACK, RACK, TLP, and Eifel -
/// `sacked`/`lost` are set by SACK processing, `xmit_mstamp`/`retrans` by
/// RACK, and `first_tsval`/`retransmit_tsval` by Eifel Detection.
#[derive(Debug, Clone)]
pub struct UnackedSegment {
    /// Sequence number of the first data byte.
    pub seq: u32,

    /// Buffered payload (empty for SYN/FIN-only segments).
    pub data: Vec<u8>,

    /// TCP control flags included in the original segment.
    pub flags: u8,

    /// When the segment was last transmitted (used for RTO checking).
    pub send_time: Instant,

    /// Number of retransmissions so far.
    pub retries: u32,

    /// RFC 7323: TSval on first transmission (Eifel Detection baseline).
    //pub first_tsval: Option<u32>,

    /// RFC 3522: TSval on most recent timeout retransmission (`RetransmitTS`).
    pub retransmit_tsval: Option<u32>,

    /// RFC 2018: peer reported this segment in a SACK block (not yet cum-ACK).
    pub sacked: bool,

    /// RFC 6675 IsLost and/or RFC 8985 RACK declared this segment lost.
    /// Eligible for selective retransmission; not counted in SACK pipe.
    pub lost: bool,

    /// Transmit timestamp for RACK (updated on every (re)transmit).
    pub xmit_mstamp: Instant,

    /// Last wire copy was a retransmission (Karn / RACK bookkeeping).
    pub retrans: bool,
}

impl UnackedSegment {
    /// Whether this segment carries the SYN flag.
    pub fn is_syn(&self) -> bool {
        (self.flags & TcpDatagramHeader::SYN) != 0
    }

    /// Whether this segment carries the FIN flag.
    pub fn is_fin(&self) -> bool {
        (self.flags & TcpDatagramHeader::FIN) != 0
    }

    /// Sequence number one past the last byte this segment occupies.
    ///
    /// SYN and FIN each consume one sequence number even though they carry
    /// no payload, so a control-only segment's end is simply `seq + 1`.
    pub fn end_seq(&self) -> u32 {
        self.seq.wrapping_add(if self.is_syn() || self.is_fin() {
            1
        } else {
            self.data.len() as u32
        })
    }
}

/// Errors that can occur during TCP connection lifetime.
#[derive(Debug, Copy, Clone)]
pub enum TcpError {
    ConnectionRefused,
    Timeout,
    NoRoute,
    ConnectionReset,
    NotConnected,
}

/// All per-connection TCP state - one instance per connection. Grouped below
/// by concern; the congestion-control and reliability sub-states
/// (`cc`, `sack`, `eifel`, `frto`, `cwv`, `abc`, `ecn`, `pacing`,
/// `ts`) each have their own module with their own docs.
#[derive(Clone)]
pub struct TcpControlBlock {
    // RFC 9293 Send Sequence variables
    /// Oldest sequence number sent but not yet acknowledged.
    pub snd_una: u32,
    /// Next sequence number to use for new data.
    pub snd_nxt: u32,
    /// Peer's advertised send window, already scaled to bytes.
    pub snd_wnd: u32,
    /// Sequence number of the segment that last updated `snd_wnd`
    pub snd_wl1: u32,
    /// Ack number of the segment that last updated `snd_wnd`.
    pub snd_wl2: u32,
    /// Initial send sequence number chosen for this connection.
    pub iss: u32,

    // RFC 9293 Receive Sequence variables
    /// Next sequence number expected from the peer.
    pub rcv_nxt: u32,
    /// Our advertised receive window.
    pub rcv_wnd: u16,
    /// Initial receive sequence number, from the peer's SYN.
    pub irs: u32,

    /// Connection state
    pub state: TcpState,

    /// The connection's 4-tuple (local/remote IP and port).
    pub tuple: ConnectionTuple,

    /// The connection's socket.
    pub socket: Socket,

    /// Reassembled, in-order data waiting for the application to read.
    pub receive_buffer: TcpReceiveBuffer,

    /// App-written data waiting to be segmented and sent.
    pub send_buffer: VecDeque<u8>,

    /// Wakes threads waiting for data or state changes.
    pub event: Arc<Event>,

    /// Signals active-open completion (final ACK sent or connection refused).
    pub handshake_gate: Arc<OneshotGate>,

    /// A delayed ACK is owed to the peer.
    pub ack_needed: bool,

    /// When the pending delayed ACK must be sent by, if any.
    pub ack_deadline: Option<Instant>,

    /// Segments received since the last ACK we sent (delayed-ACK counter).
    pub unacked_segments: u8,

    /// Sent, not-yet-cumulatively-acked segments, oldest first.
    pub retransmission_queue: VecDeque<UnackedSegment>,

    /// Current retransmission timeout.
    pub rto: Duration,

    /// RFC 6298 Smoothened RTT estimator.
    pub(super) srtt: Option<Duration>,

    /// RFC 6298 RTT variance.
    pub(super) rttvar: Option<Duration>,

    /// RTT Karn's probe.
    pub(super) rtt_m: RttMeasurementState,

    /// Deadline for the next zero-window probe, if the peer's window is closed.
    pub persist_timer: Option<Instant>,

    /// Current backoff interval between zero-window probes.
    pub persist_backoff: Duration,

    /// Last time any segment was received on this connection.
    pub last_rx_time: Instant,

    /// When the next keepalive probe is due, if enabled.
    pub keepalive_deadline: Option<Instant>,

    /// TIME-WAIT expiry (2MSL timer).
    pub timewait_deadline: Option<Instant>,

    /// Consecutive unanswered keepalive probes.
    pub keepalive_count: u32,

    /// Most recent error, surfaced to the application.
    pub last_error: Option<TcpError>,

    /// Whether Nagle's algorithm is active on this connection.
    pub nagle_enabled: bool,

    /// Last ACK number seen (for duplicate-ACK detection).
    pub last_ack_received: u32,

    /// Consecutive duplicate ACKs seen since `last_ack_received` last advanced.
    pub duplicate_ack_count: u32,

    /// Which CC algorithm this connection is running.
    pub congestion_control: CongestionControl,

    /// Congestion window.
    pub cwnd: u32,

    /// Slow-start / congestion-avoidance threshold.
    pub ssthresh: u32,

    /// Currently recovering from a loss detected via duplicate ACKs.
    pub in_fast_recovery: bool,

    /// Cap on our advertised receive window (independent of buffer size).
    pub max_rcv_wnd: u32,

    /// Peer's advertised MSS from the handshake.
    pub peer_mss: u16,

    /// Our negotiated receive-side window scale shift.
    pub rcv_wscale: u8,

    /// Peer's negotiated send-side window scale shift.
    pub snd_wscale: u8,

    /// Window scaling (RFC 7323) was negotiated on this connection.
    pub wnd_scale_enabled: bool,

    /// RFC7323 Timestamps Extension State (see [`TcpTimestampState`]).
    pub(super) ts: TcpTimestampState,

    /// RFC 3522 Eifel Detection and RFC 4015 Eifel Response - spurious-RTO
    /// undo (see [`EifelState`]).
    pub(super) eifel: EifelState,

    /// RFC 5682 F-RTO - active only when `!ts.enabled` (see [`FrtoState`]).
    pub(super) frto: FrtoState,

    /// RFC 3168 Explicit Congestion Notification (see [`TcpEcnState`]).
    pub(super) ecn: TcpEcnState,

    /// RFC 7661 New Congestion Window Validation (see [`NewCwvState`]).
    pub(super) cwv: NewCwvState,

    /// RFC 3465 Appropriate Byte Counting (see [`AbcState`]).
    pub(super) abc: AbcState,

    /// Packet pacing (see [`PacingState`]).
    pub(super) pacing: PacingState,

    /// RFC 2018/6675/8985 SACK + RACK + TLP (see [`SackRackState`]).
    pub(super) sack: SackRackState,

    /// Precomputed SMSS (peer MSS - Timestamp overhead when enabled).
    /// Refresh via [`TcpControlBlock::recompute_effective_mss`] after MSS/TS negotiation.
    pub effective_mss: u32,
}

impl TcpControlBlock {
    pub fn new(
        iss: u32,
        connection: ConnectionTuple,
        socket: Socket,
        settings: &TcpSessionSettings,
    ) -> Self {
        Self {
            snd_una: iss,
            snd_nxt: iss,
            snd_wnd: 0,
            snd_wl1: 0,
            snd_wl2: 0,
            iss,
            rcv_nxt: 0,
            rcv_wnd: 0,
            irs: 0,
            state: TcpState::Closed,
            tuple: connection,
            socket,
            event: Arc::new(Event::new()),
            handshake_gate: Arc::new(OneshotGate::new()),
            ack_needed: false,
            ack_deadline: None,
            unacked_segments: 0,
            retransmission_queue: VecDeque::new(),
            rto: Duration::from_secs(1), // RFC 6298: conservative initial RTO
            srtt: None,
            rttvar: None,
            rtt_m: RttMeasurementState::new(),
            send_buffer: VecDeque::new(),
            persist_timer: None,
            persist_backoff: Duration::from_millis(500),
            last_rx_time: Instant::now(),
            keepalive_deadline: None,
            timewait_deadline: None,
            keepalive_count: 0,
            last_error: None,
            receive_buffer: TcpReceiveBuffer::new(clamp_tcp_receive_buffer_bytes(
                settings.receive_buffer_size,
            )),
            nagle_enabled: settings.nagle_enabled,
            last_ack_received: 0,
            duplicate_ack_count: 0,
            congestion_control: CongestionControl::Cubic(CubicState {
                w_max: 0,
                epoch_start: Instant::now(),
                k_ns: 0,
                last_max_cwnd: 0,
                beta: 717, // 0.7 x 1024, per RFC 8312's recommended default
                c: 410,    // 0.4 x 1024, per RFC 8312's recommended default
                recover: 0,
            }),
            cwnd: INITIAL_CWND,
            ssthresh: INITIAL_SSTHRESH,
            in_fast_recovery: false,
            max_rcv_wnd: 0,
            peer_mss: DEFAULT_MSS,
            rcv_wscale: 0,
            snd_wscale: 0,
            wnd_scale_enabled: false,
            ts: TcpTimestampState::new(),
            eifel: EifelState::new(),
            frto: FrtoState::new(),
            ecn: TcpEcnState::new(),
            cwv: NewCwvState::new(settings.cwv_enabled, INITIAL_CWND),
            abc: AbcState::new(),
            pacing: PacingState::new(settings.pacing_enabled),
            sack: SackRackState::new(),
            effective_mss: MSS as u32,
        }
    }

    /// RFC 6691 / RFC 7323: SMSS = min(MSS, peer_mss) - 12 if Timestamps on.
    pub fn recompute_effective_mss(&mut self) {
        let mut mss = core::cmp::min(MSS, self.peer_mss as usize);

        if self.ts.enabled {
            mss = mss.saturating_sub(TCP_TS_OPTION_OVERHEAD);
        }

        self.effective_mss = mss.max(1) as u32;
    }

    /// Free receive-buffer space capped by `max_rcv_wnd`.
    pub fn effective_rcv_wnd(&self) -> u32 {
        self.receive_buffer
            .free_space()
            .min(self.max_rcv_wnd as usize) as u32
    }

    /// Refreshes `rcv_wnd` from the buffer and the `max_rcv_wnd` cap.
    pub fn update_rcv_wnd_from_buffer(&mut self) {
        self.rcv_wnd = self.effective_rcv_wnd().min(u16::MAX as u32) as u16;
    }

    /// Scaled window value to place in the TCP header - `rcv_wnd`
    /// right-shifted by our negotiated scale factor, if any.
    pub fn advertised_rcv_wnd_u16(&self) -> u16 {
        let wnd = self.rcv_wnd as u32;

        if self.wnd_scale_enabled && self.rcv_wscale > 0 {
            (wnd >> self.rcv_wscale).min(65535) as u16
        } else {
            wnd.min(65535) as u16
        }
    }

    /// Converts a wire-format window advertisement from the peer into an
    /// actual byte count.
    ///
    /// RFC 7323: once window scaling has been negotiated, the 16-bit
    /// window field in every segment from this peer is a right-shifted
    /// value; the real window is `advertised << shift`.
    pub fn scale_peer_window(&self, wire_wnd: u16) -> u32 {
        if self.wnd_scale_enabled && self.snd_wscale > 0 {
            (wire_wnd as u32) << self.snd_wscale
        } else {
            wire_wnd as u32
        }
    }

    /// RFC 9293 3.10.7.4: update SND.WND only from a newer advertisement.
    ///
    /// ```text
    ///   if SND.WL1 < SEG.SEQ
    ///      or (SND.WL1 == SEG.SEQ and SND.WL2 <= SEG.ACK):
    ///        SND.WND = SEG.WND
    ///        SND.WL1 = SEG.SEQ
    ///        SND.WL2 = SEG.ACK
    /// ```
    ///
    /// Without this gate, a reordered older segment can shrink (or inflate)
    /// the send window after a newer update already applied.
    pub fn maybe_update_send_window(&mut self, seg_seq: u32, seg_ack: u32, wire_wnd: u16) {
        let seq_newer = (seg_seq.wrapping_sub(self.snd_wl1) as i32) > 0;
        let ack_newer_same_seq =
            self.snd_wl1 == seg_seq && (seg_ack.wrapping_sub(self.snd_wl2) as i32) >= 0;

        if seq_newer || ack_newer_same_seq {
            self.snd_wnd = self.scale_peer_window(wire_wnd);
            self.snd_wl1 = seg_seq;
            self.snd_wl2 = seg_ack;
        }
    }

    /// RFC 9293: ACK is acceptable when SND.UNA < ACK <= SND.NXT.
    pub fn is_acceptable_ack(&self, ack: u32) -> bool {
        let distance = ack.wrapping_sub(self.snd_una);
        let window = self.snd_nxt.wrapping_sub(self.snd_una);

        distance <= window
    }

    /// Checks whether a single sequence number falls inside the receive window.
    ///
    /// Handles the wrap-around case per RFC 9293 §3.10.7.4.
    pub fn is_in_receive_window(&self, seq: u32) -> bool {
        let end = self.rcv_nxt.wrapping_add(self.rcv_wnd as u32);

        if self.rcv_nxt <= end {
            seq >= self.rcv_nxt && seq < end
        } else {
            seq >= self.rcv_nxt || seq < end
        }
    }

    /// Checks whether the first or last byte of a segment is inside the
    /// receive window - accepting a segment doesn't require the whole
    /// packet to be in-window, just that it overlaps it somewhere. A
    /// zero-length segment is only accepted at exactly `rcv_nxt` when our
    /// window is closed (RFC 9293's zero-window probe case).
    pub fn is_segment_acceptable(&self, seq: u32, len: u32) -> bool {
        if len == 0 {
            return if self.rcv_wnd == 0 {
                seq == self.rcv_nxt
            } else {
                self.is_in_receive_window(seq)
            };
        }

        let seq_end = seq.wrapping_add(len - 1);
        self.is_in_receive_window(seq) || self.is_in_receive_window(seq_end)
    }

    /// Returns `true` when `n` additional bytes fit inside the remote receive window.
    pub fn can_send(&self, n: u32) -> bool {
        let in_flight = self.snd_nxt.wrapping_sub(self.snd_una);

        in_flight.checked_add(n).is_some_and(|t| t <= self.snd_wnd)
    }

    /// Advances `rcv_nxt` past the FIN and transitions the state machine.
    ///
    /// State transitions:
    ///   Established -> CloseWait  (remote-initiated close)
    ///   FinWait1    -> Closing    (simultaneous close)
    ///   FinWait2    -> TimeWait   (active close completion)
    pub fn handle_fin_flag(&mut self) {
        // FIN occupies one byte in window
        self.rcv_nxt = self.rcv_nxt.wrapping_add(1);

        // FIN disables delayed ACK
        self.ack_needed = true;

        match self.state {
            TcpState::Established => {
                self.state = TcpState::CloseWait;
                self.event.notify();

                log::trace!("State: Established -> CloseWait");
            }
            TcpState::FinWait1 => {
                self.state = TcpState::Closing;

                log::trace!("State: FinWait1 -> Closing");
            }
            TcpState::FinWait2 => {
                self.state = TcpState::TimeWait;
                self.timewait_deadline = Some(Instant::now() + Duration::from_secs(120));

                log::trace!("State: FinWait2 -> TimeWait; 2MSL timer armed");
            }
            _ => log::trace!("FIN in state {:?}, ignoring", self.state),
        }
    }

    /// Bytes currently in flight: `SND.NXT - SND.UNA`.
    pub(super) fn flight_size_bytes(&self) -> u32 {
        self.snd_nxt.wrapping_sub(self.snd_una)
    }

    /// Snapshots the current CC/RTT/reliability state into a
    /// [`TcpCcSnapshot`] for the tracing purposes.
    pub fn cc_snapshot(&self) -> TcpCcSnapshot {
        let (algo, w_max, k_ns) = match &self.congestion_control {
            CongestionControl::Reno(_) => (0, 0, 0),
            CongestionControl::Cubic(c) => (1, c.w_max, c.k_ns),
        };

        TcpCcSnapshot {
            t_ns: kernel_ref().clock().monotonic_ns(),
            srtt_us: self.srtt.map(|d| d.as_nanos() / 1000).unwrap_or(0),
            rttvar_us: self.rttvar.map(|d| d.as_nanos() / 1000).unwrap_or(0),
            rto_us: self.rto.as_nanos() / 1000,
            cwnd: self.cwnd,
            ssthresh: self.ssthresh,
            snd_wnd: self.snd_wnd,
            flight: self.flight_size_bytes(),
            algo,
            w_max,
            k_ns,
            in_fast_recovery: self.in_fast_recovery,
            dupacks: self.duplicate_ack_count,
            ts_enabled: self.ts.enabled as u8,
            rtt_probe_us: self
                .rtt_m
                .last_probe_sample
                .map(|d| d.as_nanos() / 1000)
                .unwrap_or(0),
            rtt_ts_us: self
                .rtt_m
                .last_ts_sample
                .map(|d| d.as_nanos() / 1000)
                .unwrap_or(0),
            eifel_spurious: self.eifel.spurious_count,
            eifel_pipe_prev: self.eifel.pipe_prev.unwrap_or(0),
            ecn_enabled: self.ecn.enabled as u8,
            ecn_ce_seen: self.ecn.ce_seen,
            ecn_ece_tx: self.ecn.ece_tx,
            ecn_ece_rx: self.ecn.ece_rx,
            ecn_md: self.ecn.ecn_md,
            ecn_cwr_tx: self.ecn.cwr_tx,
            cwv_enabled: self.cwv.enabled as u8,
            cwv_validated: self.cwv.validated as u8,
            cwv_pipe_max: self.cwv.pipe_max,
            cwnd_no_cwv: self.cwv.cwnd_raw,
            cwv_no_increase: self.cwv.no_increase,
            cwv_idle_reduce: self.cwv.idle_reduce,
            cwv_applim_reduce: self.cwv.applim_reduce,
            abc_ca_accum: self.abc.ca_accum,
            abc_bytes_credited: self.abc.bytes_credited,
            abc_ss_capped: self.abc.ss_capped,
            abc_ca_increments: self.abc.ca_increments,
            frto_phase: self.frto.phase as u8,
            frto_spurious: self.frto.spurious_count,
            frto_declared_loss: self.frto.declared_loss_count,
            pacing_enabled: self.pacing.enabled as u8,
            pacing_rate_bps: self.pacing.rate_bps,
            pacing_gap_us: self.pacing.last_gap.as_nanos() / 1000,
            pacing_held: self.pacing.held_count,
            pacing_paced: self.pacing.paced_count,
            sack_enabled: self.sack.enabled as u8,
            sack_blocks_rx: self.sack.blocks_rx,
            sack_blocks_tx: self.sack.blocks_tx,
            sack_islost: self.sack.islost_marks,
            sack_rack: self.sack.rack_marks,
            sack_tlp: self.sack.tlp_probes,
            sack_dsack_undo: self.sack.dsack_undo,
            sack_rexmit_holes: self.sack.rexmit_holes,
            sack_ooo_ranges: self.sack.rx_range_len,
        }
    }
}

/// TCP segment header as defined in RFC 9293 §3.1.
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |          Source Port          |       Destination Port        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                        Sequence Number                        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                    Acknowledgment Number                      |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |  Data |       |U|A|P|R|S|F|                                   |
/// | Offset|  Res  |R|C|S|S|Y|I|            Window                 |
/// |       |       |G|K|H|T|N|N|                                   |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |           Checksum            |         Urgent Pointer        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[repr(C, packed)]
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Debug, Copy, Clone)]
pub struct TcpDatagramHeader {
    /// Sender port number.
    pub source_port: U16,

    /// Destination port number.
    pub dest_port: U16,

    /// Sequence number of the first data byte in this segment.
    pub sequence_number: U32,

    /// Value of the next sequence number the sender is expecting to receive.
    pub ack_number: U32,

    /// Header length in 32-bit words in the high nibble, while low nibble is reserved
    /// and must be zero.
    pub offset_res: u8,

    /// Control bits.
    pub flags: u8,

    /// Number of bytes the sender can receive.
    pub window_size: U16,

    /// Header and data checksum.
    pub checksum: U16,

    /// Byte offset from the current sequence number where urgent data begins.
    pub urgent_pointer: U16,
}

impl TcpDatagramHeader {
    /// RFC 9293 §3.1: no more data from the sender.
    pub const FIN: u8 = 0b0000_0001;

    /// RFC 9293 §3.1: Synchronize - synchronize sequence numbers to initiate a connection.
    pub const SYN: u8 = 0b0000_0010;

    /// RFC 9293 §3.1: Reset - abort the connection.
    pub const RST: u8 = 0b0000_0100;

    /// RFC 9293 §3.1: Push - receiver should pass buffered data to the application immediately.
    pub const PSH: u8 = 0b0000_1000;

    /// RFC 9293 §3.1: Acknowledgment - indicates that the acknowledgment number field is valid.
    pub const ACK: u8 = 0b0001_0000;

    /// RFC 9293 §3.1: Urgent - indicates that the urgent pointer field is valid.
    pub const URG: u8 = 0b0010_0000;

    /// RFC 3168 §6.1: ECN-Echo - receiver saw CE (or SYN-ACK ECN OK).
    pub const ECE: u8 = 0b0100_0000;

    /// RFC 3168 §6.1: Congestion Window Reduced - sender reacted to ECE.
    pub const CWR: u8 = 0b1000_0000;

    /// Builds a header from the current TCB state (SEQ=SND.NXT, ACK=RCV.NXT).
    pub fn new(tcb: &TcpControlBlock) -> Self {
        let mut h = Self {
            source_port: U16::from(tcb.tuple.local_port),
            dest_port: U16::from(tcb.tuple.remote_port),
            sequence_number: tcb.snd_nxt.into(),
            ack_number: tcb.rcv_nxt.into(),
            offset_res: 0,
            flags: 0,
            window_size: U16::from(tcb.advertised_rcv_wnd_u16()),
            checksum: 0.into(),
            urgent_pointer: 0.into(),
        };

        h.set_offset(5);

        h
    }

    pub fn set_sequence_number(&mut self, v: u32) {
        self.sequence_number = U32::from(v);
    }

    pub fn set_acknowledgement_number(&mut self, v: u32) {
        self.ack_number = U32::from(v);
    }

    /// Sets the Data Offset field (header length in 32-bit words, must be 5..=15).
    pub fn set_offset(&mut self, offset: u8) {
        assert!((5..=15).contains(&offset));

        self.offset_res = (self.offset_res & 0x0F) | (offset << 4);
    }

    pub fn get_offset(&self) -> u8 {
        (self.offset_res >> 4) & 0x0F
    }

    /// Header length in bytes (Data Offset * 4).
    pub fn header_len_bytes(&self) -> usize {
        self.get_offset() as usize * 4
    }

    /// Sets or clears one or more flag bits given by `mask`.
    pub fn set_flag(&mut self, mask: u8, value: bool) {
        if value {
            self.flags |= mask;
        } else {
            self.flags &= !mask;
        }
    }

    /// Whether all bits in `mask` are set.
    pub fn get_flag(&self, mask: u8) -> bool {
        (self.flags & mask) != 0
    }

    pub fn set_flags(&mut self, flags: u8) {
        self.flags = flags;
    }

    pub fn is_syn(&self) -> bool {
        self.get_flag(Self::SYN)
    }

    pub fn is_ack(&self) -> bool {
        self.get_flag(Self::ACK)
    }

    pub fn is_fin(&self) -> bool {
        self.get_flag(Self::FIN)
    }

    pub fn is_rst(&self) -> bool {
        self.get_flag(Self::RST)
    }
}

/// Unique identifier for a TCP connection (RFC 9293).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConnectionTuple {
    pub local_ip: Ipv4Addr,
    pub local_port: u16,
    pub remote_ip: Ipv4Addr,
    pub remote_port: u16,
}

impl ConnectionTuple {
    /// Builds the tuple identifying `socket`'s connection.
    pub fn from_socket(socket: &Socket) -> Self {
        Self {
            local_ip: socket.local_address(),
            local_port: socket.local_port(),
            remote_ip: socket.remote_address(),
            remote_port: socket.remote_port(),
        }
    }
}

/// Per-listener socket configuration.
#[derive(Clone, Copy, Debug)]
pub struct TcpSessionSettings {
    pub nagle_enabled: bool,
    pub recv_buf_size: usize,
    pub rcv_wscale: u8,
    pub cwv_enabled: bool,
    pub pacing_enabled: bool,
    pub wnd_scale_enabled: bool,
    pub sack_enabled: bool,
    pub timestamps_enabled: bool,
    pub ecn_enabled: bool,
    pub receive_buffer_size: usize,
}

impl Default for TcpSessionSettings {
    fn default() -> Self {
        Self {
            nagle_enabled: true,
            recv_buf_size: 4096,
            rcv_wscale: DEFAULT_RCV_WSCALE,
            cwv_enabled: true,
            pacing_enabled: true,
            wnd_scale_enabled: true,
            sack_enabled: true,
            timestamps_enabled: true,
            ecn_enabled: true,
            receive_buffer_size: 4096,
        }
    }
}

impl TcpSessionSettings {
    /// Applies buffer/window scale and CC-related flags after `TcpControlBlock::new`.
    pub(super) fn apply_receive_path(&self, tcb: &mut TcpControlBlock) {
        let buf_cap = self.recv_buf_size.max(1);
        tcb.receive_buffer = TcpReceiveBuffer::new(buf_cap);
        tcb.max_rcv_wnd = buf_cap as u32;
        tcb.rcv_wscale = self.rcv_wscale;
        tcb.wnd_scale_enabled = self.wnd_scale_enabled;
        tcb.update_rcv_wnd_from_buffer();
    }
}
