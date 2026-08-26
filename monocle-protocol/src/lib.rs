#![no_std]

//! Monocle Remote Logging Protocol.
//!
//! Monocle is a lightweight, transport-agnostic wire format designed for
//! multiplexing log messages and diagnostic data streams over a single byte-oriented
//! connection. It allows multiple endpoints - such as the core hypervisor, various
//! guest virtual machines, and host-to-guest interactive consoles - to seamlessly
//! share the same underlying communication channel.
//!
//! # Frame Format
//! To preserve message boundaries over continuous streams, the protocol encapsulates
//! messages into simple frames. Each frame consists of a 5-byte header followed by
//! a variable-length payload:
//!
//! `[channel_id: u8] [length: u32 LE] [payload: length bytes]`
//!
//! - `channel_id`: A 1-byte identifier encoding both the entity type (Hypervisor, Guest, or Stdin) and its specific ID.
//! - `length`: A 32-bit unsigned integer in Little-Endian format, specifying the payload size.
//! - `payload`: The raw byte content of the message (maximum 64 KiB).

/// Size of the header: 1 byte of channel ID and 4 bytes of LE encoded payload length.
pub const MONOCLE_FRAME_HEADER_SIZE: usize = 5;

/// Maximum allowed length of the payload in a single Monocle message.
pub const MONOCLE_MAX_PAYLOAD_LEN: usize = 64 * 1024;

/// Well-known port number used for the remote logging socket service.
pub const REMOTE_LOG_HVSOCK_PORT: u32 = 4242;

/// Well-known GUID identifying the host-side service for Monocle logging.
pub const MONOCLE_HOST_SERVICE_GUID: &str = "00001092-facb-11e6-bd58-64006a7986d3";

/// Well-known GUID identifying the guest-side endpoint for Monocle logging.
pub const MONOCLE_GUEST_ENDPOINT_GUID: &str = "4d4f4f53-0001-4000-a000-000000000001";

/// Describes entity that produced the message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MonocleLogSource {
    /// The core Reindeer hypervisor.
    Hypervisor,

    /// A specific Guest VM, identified by its ID (0-63).
    Guest(u8),

    /// Host-to-guest byte stream, typically for an emulated COM console (Stdin).
    Stdin(u8),
}

impl MonocleLogSource {
    /// Decodes the source entity from the 1-byte wire format channel ID.
    pub fn from_u8(value: u8) -> Option<Self> {
        let kind = value & 3;
        let id = value >> 2;

        match kind {
            0 => Some(Self::Hypervisor),
            1 => Some(Self::Guest(id)),
            2 => Some(Self::Stdin(id)),
            _ => None,
        }
    }

    /// Encodes the source entity into a 1-byte wire format channel ID.
    pub fn to_u8(self) -> u8 {
        match self {
            Self::Hypervisor => 0,
            Self::Guest(id) => 1 | (id << 2),
            Self::Stdin(id) => 2 | (id << 2),
        }
    }

    /// Returns a human-readable string label representing the source category.
    pub fn label(self) -> &'static str {
        match self {
            Self::Hypervisor => "Hypervisor",
            Self::Guest(_) => "Guest",
            Self::Stdin(_) => "Stdin",
        }
    }
}

/// A decoded Monocle packet containing the source routing information and the raw text payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MonocleFrame<'a> {
    /// The entity that originated this frame.
    pub kind: MonocleLogSource,

    /// The raw byte payload of the message.
    pub payload: &'a [u8],
}

/// Errors that can occur when encoding a Monocle frame.
#[derive(Debug)]
pub enum MonocleEncodeError {
    /// The provided payload exceeds the maximum allowed length (`MONOCLE_MAX_PAYLOAD_LEN`).
    PayloadTooLarge,

    /// The provided output buffer is too small to contain the full frame.
    BufferTooSmall,
}

/// Errors that can occur when decoding a Monocle byte stream.
#[derive(Debug)]
pub enum DecodeError {
    /// The buffer does not contain enough bytes to form a complete header or payload.
    Incomplete,

    /// The channel ID byte contains an unknown or invalid source kind.
    InvalidKind,

    /// The header indicates a payload length larger than the protocol allows.
    PayloadTooLarge,
}

/// Converts a payload and its source into a complete wire-format frame, writing it to the output slice.
/// Returns the total number of bytes written to the buffer.
pub fn encode_frame(
    kind: MonocleLogSource,
    payload: &[u8],
    out: &mut [u8],
) -> Result<usize, MonocleEncodeError> {
    if payload.len() > MONOCLE_MAX_PAYLOAD_LEN {
        return Err(MonocleEncodeError::PayloadTooLarge);
    }

    let total = MONOCLE_FRAME_HEADER_SIZE + payload.len();
    if out.len() < total {
        return Err(MonocleEncodeError::BufferTooSmall);
    }

    out[0] = kind.to_u8();

    let len = payload.len() as u32;
    out[1..5].copy_from_slice(&len.to_le_bytes());
    out[MONOCLE_FRAME_HEADER_SIZE..total].copy_from_slice(payload);

    Ok(total)
}

/// Attempts to parse a single valid Monocle frame from the beginning of the provided buffer.
/// Returns the decoded frame and the total number of bytes consumed.
pub fn decode_frame(buffer: &[u8]) -> Result<(MonocleFrame<'_>, usize), DecodeError> {
    if buffer.len() < MONOCLE_FRAME_HEADER_SIZE {
        return Err(DecodeError::Incomplete);
    }

    let kind = MonocleLogSource::from_u8(buffer[0]).ok_or(DecodeError::InvalidKind)?;
    let len = u32::from_le_bytes([buffer[1], buffer[2], buffer[3], buffer[4]]) as usize;

    if len > MONOCLE_MAX_PAYLOAD_LEN {
        return Err(DecodeError::PayloadTooLarge);
    }

    let total = MONOCLE_FRAME_HEADER_SIZE + len;
    if buffer.len() < total {
        return Err(DecodeError::Incomplete);
    }

    Ok((
        MonocleFrame {
            kind,
            payload: &buffer[MONOCLE_FRAME_HEADER_SIZE..total],
        },
        total,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_guest() {
        let mut buf = [0u8; 32];

        let n = encode_frame(MonocleLogSource::Guest(5), b"hello", &mut buf).unwrap();
        let (frame, consumed) = decode_frame(&buf[..n]).unwrap();

        assert_eq!(consumed, n);
        assert_eq!(frame.kind, MonocleLogSource::Guest(5));
        assert_eq!(frame.payload, b"hello");
    }

    #[test]
    fn round_trip_hypervisor() {
        let mut buf = [0u8; 32];

        let n = encode_frame(MonocleLogSource::Hypervisor, b"hello", &mut buf).unwrap();
        let (frame, consumed) = decode_frame(&buf[..n]).unwrap();

        assert_eq!(consumed, n);
        assert_eq!(frame.kind, MonocleLogSource::Hypervisor);
        assert_eq!(frame.payload, b"hello");
    }
}
