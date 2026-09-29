//! # ICMP (Internet Control Message Protocol) Subsystem
//!
//! This module implements the ICMP protocol (RFC 792).
//!
//! ## ICMP Packet Header (RFC 792)
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! ┌───────────────┬───────────────┬───────────────────────────────┐
//! │  Type (8 bits)│  Code (8 bits)│      Checksum (16 bits)       │
//! ├───────────────┴───────────────┼───────────────────────────────┤
//! │      Identifier (16 bits)     │    Sequence Number (16 bits)  │
//! └───────────────────────────────┴───────────────────────────────┘
//! ```
//!
//! Beyond ping, this driver also reacts to type-3 (Destination
//! Unreachable) messages that quote a TCP segment we sent: if the code
//! indicates a hard failure (port/host/net/protocol unreachable), the
//! matching TCP connection is aborted immediately rather than left to
//! time out on its own.
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, network_endian::U16};

use crate::{
    driver::net::{
        Ipv4Addr, NetworkInterfaceId,
        proto::{
            DEFAULT_HEADER_RESERVE, PacketBuffer, SLOT_SIZE,
            ip::{IpProtocol, Ipv4PacketHeader},
            tcp::{ConnectionTuple, TcpError},
        },
    },
    kernel::kernel_ref,
};

/// # ICMP Message Types
/// ### Message Classification
///
/// | Category       | Types                                                     |
/// | :---           | :---                                                      |
/// | Informational  | Echo Request/Reply, Timestamp, Info                       |
/// | Error Reporting| Destination Unreachable, Time Exceeded, Parameter Problem |
/// | Flow/Routing   | Source Quench, Redirect                                   |
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IcmpMessageType {
    /// Used to respond to an Echo Request (Ping).
    EchoReply = 0,

    /// Generated when a packet cannot be delivered to its destination.
    DestinationUnreachable = 3,

    /// A primitive congestion control message.
    SourceQuench = 4,

    /// Informs a host to update its routing table for a more optimal path.
    Redirect = 5,

    /// A standard "Ping" request used to test reachability.
    EchoRequest = 8,

    /// Sent when a packet's TTL reaches zero or fragment reassembly times out.
    TimeExceeded = 11,

    /// Indicates a header error that prevents further processing.
    ParameterProblem = 12,

    /// Request for a synchronized timestamp from a remote host.
    TimestampRequest = 13,

    /// Response containing the remote host's current timestamp.
    TimestampReply = 14,

    /// Obsolete: Formerly used to obtain a network mask.
    InfoRequest = 15,

    /// Obsolete: Response to an Info Request.
    InfoReply = 16,
}

/// ICMP type-3 codes treated as fatal for an in-flight TCP connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IcmpDestinationUnreachableCode {
    Network = 0,
    Host = 1,
    Protocol = 2,
    Port = 3,
}

impl IcmpDestinationUnreachableCode {
    fn from_u8(code: u8) -> Option<Self> {
        match code {
            0 => Some(Self::Network),
            1 => Some(Self::Host),
            2 => Some(Self::Protocol),
            3 => Some(Self::Port),
            _ => None,
        }
    }

    /// Maps this ICMP code to the error a matching TCP connection
    /// should be aborted with.
    fn to_tcp_error(self) -> TcpError {
        match self {
            Self::Port => TcpError::ConnectionRefused,
            Self::Network | Self::Host | Self::Protocol => TcpError::NoRoute,
        }
    }
}

/// # ICMP Packet Header
///
/// This structure represents the fixed 8-byte header found at the beginning of
/// every ICMP message (RFC 792).
///
/// ### Memory Layout
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// ┌───────────────┬───────────────┬───────────────────────────────┐
/// │  Type (8 bits)│  Code (8 bits)│      Checksum (16 bits)       │
/// ├───────────────┴───────────────┼───────────────────────────────┤
/// │      Identifier (16 bits)     │    Sequence Number (16 bits)  │
/// └───────────────────────────────┴───────────────────────────────┘
/// ```
#[repr(C, packed)]
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Copy, Clone)]
pub struct IcmpPacketHeader {
    /// The ICMP message type.
    pub message_type: u8,

    /// The ICMP message code.
    pub code: u8,

    /// The 16-bit network-endian checksum.
    pub checksum: U16,

    /// An identifier to help match requests/replies.
    pub identifier: U16,

    /// A sequence number to help match requests/replies.
    pub sequence_number: U16,
}

impl IcmpPacketHeader {
    pub fn message_type(&self) -> Option<IcmpMessageType> {
        match self.message_type {
            0 => Some(IcmpMessageType::EchoReply),
            3 => Some(IcmpMessageType::DestinationUnreachable),
            4 => Some(IcmpMessageType::SourceQuench),
            5 => Some(IcmpMessageType::Redirect),
            8 => Some(IcmpMessageType::EchoRequest),
            11 => Some(IcmpMessageType::TimeExceeded),
            12 => Some(IcmpMessageType::ParameterProblem),
            13 => Some(IcmpMessageType::TimestampRequest),
            14 => Some(IcmpMessageType::TimestampReply),
            15 => Some(IcmpMessageType::InfoRequest),
            16 => Some(IcmpMessageType::InfoReply),
            _ => None,
        }
    }
}

/// Driver managing ICMP packet queuing and worker synchronization.
pub struct IcmpDriver {}

impl IcmpDriver {
    /// Initializes ICMP driver.
    pub fn new() -> Self {
        Self {}
    }

    /// Constructs and sends an ICMP Echo Reply in response to an Echo Request.
    fn send_echo_reply(
        &self,
        request_header: &IcmpPacketHeader,
        request_buffer: &PacketBuffer,
        sender_ip: &Ipv4Addr,
        nic: NetworkInterfaceId,
    ) {
        let network_subsystem = kernel_ref().network_subsystem();

        let mut storage = [0u8; DEFAULT_HEADER_RESERVE + SLOT_SIZE];
        let mut reply_buffer = PacketBuffer::for_transmit(&mut storage, DEFAULT_HEADER_RESERVE);

        // Prepare the reply header based on the request
        let mut reply_header = *request_header;
        reply_header.message_type = IcmpMessageType::EchoReply as u8;
        reply_header.checksum = U16::ZERO;

        reply_buffer.append_data(reply_header.as_bytes());
        reply_buffer.append_data(request_buffer.payload());

        // Calculate the checksum
        let checksum = self.calculate_icmp_checksum(reply_buffer.payload());
        reply_header.checksum = U16::new(checksum);

        // Write the checksum back
        reply_buffer.payload_mut()[2..4].copy_from_slice(reply_header.checksum.as_bytes());

        if network_subsystem
            .ipv4()
            .send_packet(IpProtocol::Icmp, &mut reply_buffer, *sender_ip, nic, 0)
            .is_err()
        {
            log::trace!("echo reply dropped");
        }
    }

    /// Computes the ICMP checksum. An odd-length payload has
    /// its trailing byte padded with a zero low byte before being
    /// summed (RFC 1071).
    fn calculate_icmp_checksum(&self, data: &[u8]) -> u16 {
        let mut sum: u32 = 0;
        let (chunks, remainder) = data.as_chunks::<2>();

        for chunk in chunks {
            let word = ((chunk[0] as u16) << 8) | (chunk[1] as u16);
            sum = sum.wrapping_add(word as u32);
        }

        // Trailing odd byte, if any: pad with a zero low byte.
        if let [last] = remainder {
            sum = sum.wrapping_add((*last as u32) << 8);
        }

        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        !(sum as u16)
    }

    /// Extracts the connection this ICMP error is about, from the
    /// original IP + TCP header the error message quotes back (RFC 792:
    /// every error message includes the IP header plus at least the
    /// first 8 bytes of the datagram, which for TCP means the
    /// source/destination ports).
    fn parse_quoted_tcp_tuple(payload: &[u8]) -> Option<ConnectionTuple> {
        let (ip_hdr, _) = Ipv4PacketHeader::read_from_prefix(payload).ok()?;
        let ihl = ip_hdr.header_length();
        if payload.len() < ihl + 4 || ip_hdr.protocol != IpProtocol::Tcp as u8 {
            return None;
        }

        let tcp = &payload[ihl..];
        let local_port = u16::from_be_bytes([tcp[0], tcp[1]]);
        let remote_port = u16::from_be_bytes([tcp[2], tcp[3]]);

        Some(ConnectionTuple {
            local_ip: ip_hdr.sender_ip(),
            local_port,
            remote_ip: ip_hdr.target_ip(),
            remote_port,
        })
    }

    /// Handles a type-3 Destination Unreachable: if the code is one we
    /// treat as fatal and the message quotes a TCP header we can match
    /// to a live connection, aborts that connection immediately with the
    /// corresponding error instead of waiting for it to time out on its
    /// own.
    fn handle_destination_unreachable(&self, header: &IcmpPacketHeader, buffer: &PacketBuffer) {
        let Some(code) = IcmpDestinationUnreachableCode::from_u8(header.code) else {
            log::trace!("ICMP dest unreachable: ignored code={}", header.code);
            return;
        };

        let Some(tuple) = Self::parse_quoted_tcp_tuple(buffer.payload()) else {
            log::trace!(
                "ICMP dest unreachable code={}: no quoted TCP header",
                header.code
            );
            return;
        };

        log::trace!(
            "ICMP dest unreachable code={} for TCP {}:{} -> {}:{}",
            header.code,
            tuple.local_ip,
            tuple.local_port,
            tuple.remote_ip,
            tuple.remote_port
        );

        kernel_ref()
            .network_subsystem()
            .tcp()
            .abort_connection(tuple, code.to_tcp_error());
    }

    /// Processes incoming ICMP packet.
    pub fn process_data(
        &self,
        buffer: &mut PacketBuffer,
        sender_ip: &Ipv4Addr,
        nic: NetworkInterfaceId,
    ) -> Result<(), ()> {
        let header = buffer.consume_header::<IcmpPacketHeader>().unwrap();

        let Some(msg_type) = header.message_type() else {
            log::trace!("Unknown ICMP message type {}", header.message_type);
            return Ok(());
        };

        match msg_type {
            IcmpMessageType::EchoRequest => {
                self.send_echo_reply(&header, buffer, sender_ip, nic);
            }
            IcmpMessageType::DestinationUnreachable => {
                self.handle_destination_unreachable(&header, buffer);
            }
            other => log::trace!("Unhandled ICMP message type {:?}", other),
        }

        Ok(())
    }
}
