//! TCP header options — parse and build.
//!
//! RFC: [RFC 9293](https://www.rfc-editor.org/rfc/rfc9293.html) §3.1 (options
//! format); individual options from [RFC 7323](https://www.rfc-editor.org/rfc/rfc7323.html)
//! (Timestamps), [RFC 2018](https://www.rfc-editor.org/rfc/rfc2018.html) (SACK),
//! and classic MSS / Window Scale options.
//!
//! Options are TLV-encoded and packed into a shared 40-byte budget
//! ([`TCP_OPTS_MAX`]) that everything else in this stack (SACK, timestamps,
//! MSS, window scale) has to fit into and share. `TcpOptionsParser` walks
//! that area on an incoming header; `TcpOptionsWriter` builds it for an
//! outgoing one, handling the 4-byte alignment padding so nothing else in
//! the driver has to think about it.

use super::sack::SackBlock;

/// RFC 9293: TCP options area is at most 40 bytes.
pub(super) const TCP_OPTS_MAX: usize = 40;

/// RFC 9293 §3.1: End of Option List - Kind 0, terminates parsing immediately.
const TCP_OPT_EOL: u8 = 0;

/// RFC 9293 §3.1: No-Operation - Kind 1, used only for alignment padding.
const TCP_OPT_NOP: u8 = 1;

/// RFC 9293 §3.1: Maximum Segment Size - Kind 2, Length 4.
const TCP_OPT_MSS: u8 = 2;

/// RFC 7323 §2.2: Window Scale - Kind 3, Length 3, SYN-only.
const TCP_OPT_WINDOW_SCALE: u8 = 3;

/// RFC 7323 §3.2: Timestamps option Kind.
const TCP_OPT_TIMESTAMP: u8 = 8;

/// RFC 2018: SACK-Permitted (SYN / SYN-ACK only).
const TCP_OPT_SACK_PERMITTED: u8 = 4;

/// RFC 2018: SACK blocks option Kind.
const TCP_OPT_SACK: u8 = 5;

/// NOP + NOP + Kind + Len + TSval + TSecr.
pub(super) const TCP_TS_OPTION_OVERHEAD: usize = 12;

/// One decoded TCP option. `Unknown` covers anything we don't parse but
/// still need to skip over correctly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpOption<'a> {
    /// Terminates parsing immidiately.
    EndOfList,

    /// Padding byte.
    NoOp,

    /// Maximum Segment Size
    Mss(u16),

    /// Window Scale
    WindowScale(u8),

    /// Timestamp: TSval, TSecr.
    Timestamp { tsval: u32, tsecr: u32 },

    /// Peer supports selective ACK (SYN only).
    SackPermitted,

    /// SACK (Raw blocks only)
    Sack(&'a [u8]),

    /// Unknown data
    Unknown { kind: u8, data: &'a [u8] },
}

/// Parses the TCP options area (RFC 9293 §3.1), i.e. `header[20..header_len]`.
///
/// Every option is either a single, bare `Kind` byte, or a Kind-Length-Value
/// triplet where `Length` counts the whole option including the Kind and
/// Length bytes themselves:
///
/// ```text
/// single-byte option (End of Option List / No-Operation):
///   +--------+
///   |  Kind  |
///   +--------+
///
/// TLV option:
///   +--------+--------+---------- ... ----------+
///   |  Kind  | Length |           Data           |
///   +--------+--------+---------- ... ----------+
/// ```
pub struct TcpOptionsParser<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> TcpOptionsParser<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }
}

impl<'a> Iterator for TcpOptionsParser<'a> {
    type Item = TcpOption<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos >= self.data.len() {
            return None;
        }

        let kind = self.data[self.pos];

        if kind == TCP_OPT_EOL {
            self.pos = self.data.len();

            return Some(TcpOption::EndOfList);
        }

        if kind == TCP_OPT_NOP {
            self.pos += 1;

            return Some(TcpOption::NoOp);
        }

        // TLV option: need at least the Length byte, and Length itself must
        // be self-consistent with what's left in the buffer.
        if self.pos + 1 >= self.data.len() {
            self.pos = self.data.len();

            return None;
        }

        let len = self.data[self.pos + 1] as usize;
        if len < 2 || self.pos + len > self.data.len() {
            self.pos = self.data.len();

            return None;
        }

        let opt_data = &self.data[self.pos + 2..self.pos + len];
        self.pos += len;

        Some(match kind {
            TCP_OPT_MSS if len == 4 => {
                TcpOption::Mss(u16::from_be_bytes([opt_data[0], opt_data[1]]))
            }
            TCP_OPT_WINDOW_SCALE if len == 3 => TcpOption::WindowScale(opt_data[0]),
            TCP_OPT_TIMESTAMP if len == 10 && opt_data.len() == 8 => {
                let tsval =
                    u32::from_be_bytes([opt_data[0], opt_data[1], opt_data[2], opt_data[3]]);
                let tsecr =
                    u32::from_be_bytes([opt_data[4], opt_data[5], opt_data[6], opt_data[7]]);

                TcpOption::Timestamp { tsval, tsecr }
            }
            TCP_OPT_SACK_PERMITTED if len == 2 => TcpOption::SackPermitted,
            TCP_OPT_SACK if len >= 2 && (len - 2).is_multiple_of(8) => TcpOption::Sack(opt_data),
            _ => TcpOption::Unknown {
                kind,
                data: opt_data,
            },
        })
    }
}

/// Builds the options block for an outgoing SYN / SYN-ACK.
///
/// Options are written back to back and padded with No-Operation (`0x01`)
/// bytes up to a 4-byte boundary, since the header's Data Offset field is
/// expressed in 32-bit words. For example, `push_mss(1460)` followed by
/// `push_window_scale(7)` produces:
///
/// ```text
/// 02 04 05 B4  03 03 07 01
/// \___MSS___/  \_WScale_/ ^
///                        NOP pad to 8 bytes
/// ```
pub struct TcpOptionsWriter {
    buf: [u8; 40],
    len: usize,
}

impl TcpOptionsWriter {
    pub fn new() -> Self {
        Self {
            buf: [0; 40],
            len: 0,
        }
    }

    /// `02 04 <mss>` (Kind=2, Length=4).
    pub fn push_mss(&mut self, mss: u16) {
        self.buf[self.len] = TCP_OPT_MSS;
        self.buf[self.len + 1] = 4;
        self.buf[self.len + 2] = (mss >> 8) as u8;
        self.buf[self.len + 3] = mss as u8;

        self.len += 4;
    }

    /// `03 03 <shift>` (Kind=3, Length=3).
    pub fn push_window_scale(&mut self, shift: u8) {
        self.buf[self.len] = TCP_OPT_WINDOW_SCALE;
        self.buf[self.len + 1] = 3;
        self.buf[self.len + 2] = shift;

        self.len += 3;
    }

    /// RFC 7323 §3.2: `01 01 08 0A <TSval> <TSecr>` (12 bytes). Leads with
    /// two NOPs so the 4-byte Timestamp value that follows lands on a
    /// 4-byte boundary.
    pub fn push_timestamp(&mut self, tsval: u32, tsecr: u32) {
        self.buf[self.len] = TCP_OPT_NOP;
        self.buf[self.len + 1] = TCP_OPT_NOP;
        self.buf[self.len + 2] = TCP_OPT_TIMESTAMP;
        self.buf[self.len + 3] = 10;
        self.buf[self.len + 4..self.len + 8].copy_from_slice(&tsval.to_be_bytes());
        self.buf[self.len + 8..self.len + 12].copy_from_slice(&tsecr.to_be_bytes());

        self.len += 12;
    }

    /// Bytes already written (before [`finish`] padding).
    pub fn written(&self) -> usize {
        self.len
    }

    /// RFC 2018 SACK-Permitted: `01 01 04 02` (Kind=4 Length=2).
    pub fn push_sack_permitted(&mut self) {
        if self.len + 4 > self.buf.len() {
            return;
        }

        self.buf[self.len] = TCP_OPT_NOP;
        self.buf[self.len + 1] = TCP_OPT_NOP;
        self.buf[self.len + 2] = TCP_OPT_SACK_PERMITTED;
        self.buf[self.len + 3] = 2;

        self.len += 4;
    }

    /// Emit as many SACK blocks as fit in `budget` remaining option bytes.
    ///
    /// With Timestamps already taking 12 bytes, `budget` is typically 28 -
    /// room for at most 3 blocks (2 + 3 * 8 = 26). Without TS, up to 4 blocks
    /// (the RFC 2018 max regardless of space). Silently sends fewer blocks
    /// than requested rather than overflowing the options area.
    pub(super) fn push_sack_limited(&mut self, blocks: &[SackBlock], budget: usize) {
        let align = (4 - (self.len % 4)) % 4;
        let avail = budget.saturating_sub(align);
        if avail < 10 {
            return;
        }

        let max_n = ((avail - 2) / 8).min(4).min(blocks.len());
        if max_n == 0 {
            return;
        }

        let need = align + 2 + 8 * max_n;
        if self.len + need > self.buf.len() {
            return;
        }

        for _ in 0..align {
            self.buf[self.len] = TCP_OPT_NOP;
            self.len += 1;
        }

        self.buf[self.len] = TCP_OPT_SACK;
        self.buf[self.len + 1] = (2 + 8 * max_n) as u8;
        self.len += 2;

        for b in blocks.iter().take(max_n) {
            self.buf[self.len..self.len + 4].copy_from_slice(&b.left.to_be_bytes());
            self.buf[self.len + 4..self.len + 8].copy_from_slice(&b.right.to_be_bytes());
            self.len += 8;
        }
    }

    /// Pads to a 4-byte boundary with NOP and returns the slice.
    pub fn finish(&mut self) -> &[u8] {
        while !self.len.is_multiple_of(4) {
            self.buf[self.len] = TCP_OPT_NOP;
            self.len += 1;
        }

        &self.buf[..self.len]
    }
}
