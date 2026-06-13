//! # Hyper-V Integration Component - Utility Message Protocol
//!
//! ## Overview
//!
//! All Hyper-V Integration Component (IC) services share a common packet format. It provides:
//!
//! - A unified pipe-level framing header ([`UtilPipeHeader`])
//! - A common IC message header ([`UtilMessageHeader`]) carrying the message type,
//!   protocol versions, transaction ID, and status
//! - A version negotiation handshake that every IC channel performs before
//!   any service-specific traffic
//!
//! Individual services get their own dedicated VMBus channel but all speak
//! this protocol for negotiation and acknowledgement.
//!
//! ## Wire Layout
//!
//! ```text
//! ┌───────────────────────────────────────────────────┐
//! │  UtilPipeHeader      (8 bytes)                    │
//! │    flags, msgs                                    │
//! ├───────────────────────────────────────────────────┤
//! │  UtilMessageHeader   (variable, packed)           │
//! │    framework_version, message_type,               │
//! │    message_version, message_size,                 │
//! │    status, transaction_id, flags                  │
//! ├───────────────────────────────────────────────────┤
//! │  Service payload     (message_type–dependent)     │
//! │    NegotiateProtocol → [UtilVersion…]             │
//! │    Shutdown          → UtilShutdownMessage        │
//! │    Heartbeat         → UtilHeartbeatMessage       │
//! └───────────────────────────────────────────────────┘
//! ```
//!
//! ## Version Negotiation
//!
//! Every IC channel performs a single round-trip negotiation before service
//! traffic begins:
//!
//! ```text
//! Host                                  Guest
//!   │                                     │
//!   │  NegotiateProtocol                  │
//!   │  (N framework + M message versions) │
//!   │ ──────────────────────────────────► │
//!   │                                     │
//!   │  NegotiateProtocol (response)       │
//!   │  (1 framework + 1 message version)  │
//!   │ ◄────────────────────────────────── │
//!   │                                     │
//! ```
//!
//! The guest selects the highest mutually-supported version from its own
//! [`IcVersionSet`] and echoes the packet back in-place with counts set to 1.
//! [`negotiate_versions`] implements this logic and can be reused by any service.

use core::{char::decode_utf16, ptr, slice};

use alloc::string::String;

pub mod file_copy;
pub mod heartbeat;
pub mod kvp;
pub mod shutdown;
pub mod socket;
pub mod time_sync;

/// [`UtilPipeHeader::flags`] value indicating that the payload carries IC data.
pub(crate) const IC_PIPE_FLAG_DATA: u32 = 1;

/// [`UtilMessageHeader::flags`] bitmask: this packet is a response.
pub(crate) const IC_MSG_FLAG_RESPONSE: u8 = 1 << 0;

/// [`UtilMessageHeader::flags`] bitmask: response with a write intent.
///
/// All acknowledgements sent from guest to host set this value.
pub(crate) const IC_MSG_FLAG_RESPONSE_WRITE: u8 = (1 << 0) | (1 << 2);

/// Message types used by the Hyper-V IC Utility Protocol.
#[repr(u16)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum UtilMessageType {
    /// Protocol version negotiation — always the first exchange on every IC channel.
    NegotiateProtocol = 0,

    /// Periodic liveness probe — host expects a timely echo from the guest.
    Heartbeat = 1,

    /// Key-Value Pair exchange — bidirectional metadata sharing between host and guest.
    KvpExchange = 2,

    /// Graceful shutdown request from the host.
    Shutdown = 3,

    /// Time synchronisation — host pushes its UTC clock to the guest.
    TimeSync = 4,

    /// Volume Shadow Service coordination (backup/snapshot).
    Vss = 5,

    /// File copy service — host-initiated file transfer into the guest.
    Fcopy = 7,
}

/// Protocol version descriptor used in IC version negotiation.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct UtilVersion {
    /// Major version component.
    pub major: u16,

    /// Minor version component.
    pub minor: u16,
}

impl UtilVersion {
    pub const fn new(major: u16, minor: u16) -> Self {
        Self { major, minor }
    }
}

/// Low-level pipe metadata that precedes every IC message on the VMBus channel.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct UtilPipeHeader {
    /// Pipe-level flags — set to [`IC_PIPE_FLAG_DATA`] for normal IC traffic.
    pub flags: u32,

    /// Number of IC messages bundled in this pipe payload (typically 1).
    pub message_count: u32,
}

/// Common header present at the start of every IC message.
///
/// Immediately after this header in memory comes the service-specific payload.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct UtilMessageHeader {
    /// Pipe-level framing metadata.
    pub pipe: UtilPipeHeader,

    /// Framework protocol version negotiated for this channel.
    pub framework_version: UtilVersion,

    /// IC message type — identifies the payload that follows.
    pub message_type: UtilMessageType,

    /// Service-level protocol version negotiated for this channel.
    pub message_version: UtilVersion,

    /// Total size of the IC payload in bytes (excluding this header).
    pub message_size: u16,

    /// Operation status code.
    pub status: u32,

    /// Per-transaction identifier used to correlate requests with responses.
    pub transaction_id: u8,

    /// Message-level flags.
    pub flags: u8,

    /// Reserved.
    pub reserved: [u8; 2],
}

/// Wire payload for [`UtilMessageType::NegotiateProtocol`].
///
/// Immediately after this struct in memory there is a flat array of
/// `framework_version_count + message_version_count` values:
///
/// ```text
/// [ fw_ver_0, fw_ver_1, … | msg_ver_0, msg_ver_1, … ]
///  └── framework_version_count ──┘  └── message_version_count ──┘
/// ```
#[repr(C, packed)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct UtilNegotiateMessage {
    /// Common IC message header.
    pub header: UtilMessageHeader,

    /// Number of framework entries in the trailing array.
    pub framework_version_count: u16,

    /// Number of message-layer entries in the trailing array.
    pub message_version_count: u16,

    /// Reserved — must be zero.
    pub reserved: u32,
}

/// A static, ordered list of IC protocol versions supported by a service.
///
/// Versions must be listed from newest to oldest so that [`negotiate_versions`]
/// naturally selects the highest mutually-supported version.
pub type IcVersionSet = &'static [UtilVersion];

/// Handles a [`UtilMessageType::NegotiateProtocol`] packet in-place.
///
/// Reads the host-offered version lists from `data_ptr`, selects the best
/// mutually-supported pair from `supported_versions`, and rewrites the packet.
pub(crate) fn negotiate_versions(
    data_ptr: *const u8,
    supported_versions: IcVersionSet,
) -> (bool, UtilVersion, UtilVersion) {
    let neg_ptr = data_ptr as *mut UtilNegotiateMessage;
    let neg_msg = unsafe { ptr::read_unaligned(neg_ptr) };

    if neg_msg.framework_version_count == 0 || neg_msg.message_version_count == 0 {
        panic!("IC version negotation: host sent empty version list.");
    }

    let total = (neg_msg.framework_version_count + neg_msg.message_version_count) as usize;
    let versions_ptr = unsafe { neg_ptr.add(1) as *mut UtilVersion };
    let host_versions = unsafe { slice::from_raw_parts(versions_ptr, total) };

    let host_fw = &host_versions[..neg_msg.framework_version_count as usize];
    let host_msg = &host_versions[neg_msg.framework_version_count as usize..];

    // Pick the highest driver-preferred version that the host also offers
    let sel_fw = supported_versions.iter().find(|v| host_fw.contains(v));
    let sel_msg = supported_versions.iter().find(|v| host_msg.contains(v));

    match (sel_fw, sel_msg) {
        (Some(&fw), Some(&msg)) => {
            unsafe {
                (*neg_ptr).header.pipe.flags = IC_PIPE_FLAG_DATA;
                (*neg_ptr).header.flags = IC_MSG_FLAG_RESPONSE_WRITE;
                (*neg_ptr).framework_version_count = 1;
                (*neg_ptr).message_version_count = 1;

                versions_ptr.write_unaligned(fw);
                versions_ptr.add(1).write_unaligned(msg);
            }

            (true, fw, msg)
        }
        _ => {
            error!("integration components: no compatible version found");
            (false, UtilVersion::new(0, 0), UtilVersion::new(0, 0))
        }
    }
}

/// Marks a packet buffer as a generic IC acknowledgement response.
pub(crate) fn mark_as_response(data_ptr: *const u8) {
    let hdr_ptr = data_ptr as *mut UtilMessageHeader;
    unsafe { (*hdr_ptr).flags = IC_MSG_FLAG_RESPONSE_WRITE };
}

/// Decodes a UTF-16 Little Endian (UTF-16LE) byte buffer into a standard Rust [`String`].
pub(crate) fn decode_utf16_buf(buf: &[u8]) -> String {
    decode_utf16(
        buf.chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .take_while(|&u| u != 0),
    )
    .map(|r| r.unwrap_or('\u{FFFD}'))
    .collect()
}

/// Encode `src` as UTF-16LE into `dst`, zero-padding the remainder.
/// Returns the number of bytes written.
pub(crate) fn encode_utf16le(src: &str, dst: &mut [u8]) -> usize {
    dst.fill(0);
    let mut written = 0;
    for unit in src.encode_utf16() {
        if written + 2 > dst.len() {
            break;
        }
        dst[written..written + 2].copy_from_slice(&unit.to_le_bytes());
        written += 2;
    }
    written
}
