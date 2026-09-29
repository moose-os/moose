//! # IPv4 (Internet Protocol version 4) Subsystem
//!
//! This module implements the Network Layer (Layer 3) of the kernel network stack,
//! providing packet routing, addressing, and protocol dispatching (UDP, TCP, ICMP).

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, network_endian::U16};

use crate::{
    driver::net::{
        Ipv4Addr, MacAddress, NetworkInterfaceId,
        proto::{PacketBuffer, ethernet::EtherType},
    },
    kernel::kernel_ref,
};

/// IPv4 Protocol Numbers
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpProtocol {
    /// Internet Control Message Protocol
    Icmp = 1,

    /// Internet Group Management Protocol
    Igmp = 2,

    /// Transmission Control Protocol
    Tcp = 6,

    /// Core-based trees
    Cbt = 7,

    /// Exterior Gateway Protocol
    Egp = 8,

    /// Any private interior gateway
    Igp = 9,

    /// User Datagram Protocol
    Udp = 17,

    /// Enhanced Interior Gateway Routing Protocol
    Eigrp = 88,

    /// Open Shortest Path First
    Ospf = 89,
}

/// # IPv4 Packet Header
///
/// This structure represents the standard 20-byte IPv4 header (RFC 791).
/// This driver doesn't support IP options (`header_length()` can exceed 20,
/// but anything past the fixed fields is just skipped, not parsed) or
/// fragmentation
///
/// ### Memory Layout
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |Version|  IHL  |Type of Service|          Total Length         |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |         Identification        |Flags|      Fragment Offset    |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |  Time to Live |    Protocol   |         Header Checksum       |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                       Source IP Address                       |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                    Destination IP Address                     |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
#[repr(C, packed)]
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Debug, Copy, Clone)]
pub struct Ipv4PacketHeader {
    /// Version (4 bits) and Internet Header Length (4 bits).
    pub version_ihl: u8,

    /// Type of Service / Differentiated Services Code Point. TCP reads
    /// the low 2 bits of this back out as Classic ECN (RFC 3168 §5).
    pub tos: u8,

    /// Total Length of the packet (Header + Data).
    pub total_length: U16,

    /// Identification for fragmentation.
    pub identification: U16,

    /// Flags (3 bits) and Fragment Offset (13 bits).
    pub flags_fragment_offset: U16,

    /// Time to Live (hop count).
    pub ttl: u8,

    /// Protocol.
    pub protocol: u8,

    /// 16-bit header checksum for error detection.
    pub checksum: U16,

    /// Source IP Address.
    pub source_ip: [u8; 4],

    /// Destination IP Address.
    pub target_ip: [u8; 4],
}

impl Ipv4PacketHeader {
    /// Returns the source IPv4 address from the header.
    pub fn sender_ip(&self) -> Ipv4Addr {
        Ipv4Addr::new(self.source_ip)
    }

    /// Returns the destination IPv4 address from the header.
    pub fn target_ip(&self) -> Ipv4Addr {
        Ipv4Addr::new(self.target_ip)
    }

    /// Calculates the header length in bytes using the IHL field.
    /// The IHL (Internet Header Length) specifies the number of 32-bit words in the header.
    pub fn header_length(&self) -> usize {
        ((self.version_ihl & 0x0F) * 4) as usize
    }

    /// Returns the total length of the IP packet (header + payload) in bytes.
    pub fn total_length(&self) -> usize {
        self.total_length.get() as usize
    }

    /// Maps the protocol field to an `IpProtocol` variant.
    /// Returns `None` and logs a warning if the protocol number is unrecognized.
    pub fn protocol(&self) -> Option<IpProtocol> {
        match self.protocol {
            1 => Some(IpProtocol::Icmp),
            2 => Some(IpProtocol::Igmp),
            6 => Some(IpProtocol::Tcp),
            7 => Some(IpProtocol::Cbt),
            8 => Some(IpProtocol::Egp),
            9 => Some(IpProtocol::Igp),
            17 => Some(IpProtocol::Udp),
            88 => Some(IpProtocol::Eigrp),
            89 => Some(IpProtocol::Ospf),
            _ => {
                log::warn!("Unknown IP protocol: {}", self.protocol);
                None
            }
        }
    }
}

/// Layer 3 driver: builds and sends outgoing IPv4 packets, and dispatches
/// incoming ones to the right transport-layer driver by protocol number.
pub struct Ipv4Driver {}

impl Ipv4Driver {
    pub fn new() -> Self {
        Self {}
    }

    /// Encapsulates and sends an IPv4 packet.
    pub fn send_packet(
        &self,
        protocol: IpProtocol,
        buffer: &mut PacketBuffer,
        destination_ip_address: Ipv4Addr,
        nic: NetworkInterfaceId,
        tos: u8,
    ) -> Result<(), ()> {
        let header_length = size_of::<Ipv4PacketHeader>();
        let total_data_length: usize = buffer.payload().len();
        let total_length = header_length + total_data_length;

        let network_subsytem = kernel_ref().network_subsystem();
        let nic = network_subsytem.interfaces().get(nic).ok_or(())?;
        let source_ip = nic
            .local_internet_address
            .unwrap_or(Ipv4Addr::unspecified());

        // Initialize the header.
        let mut header = Ipv4PacketHeader {
            version_ihl: (4 << 4) | (header_length / 4) as u8,
            tos,
            total_length: U16::new(total_length as u16),
            identification: U16::new(0),
            flags_fragment_offset: U16::new(0),
            ttl: 64,
            protocol: protocol as u8,
            checksum: U16::ZERO,
            source_ip: source_ip.octets(),
            target_ip: destination_ip_address.octets(),
        };

        // Calculate the checksum
        header.checksum = U16::new(self.calculate_header_checksum(&header));

        buffer.prepend_header(&header);

        // Resolve destination MAC using ARP
        let dest_mac = if destination_ip_address == Ipv4Addr::broadcast() {
            MacAddress::broadcast()
        } else {
            let next_hop = network_subsytem
                .routing_table()
                .read()
                .resolve_next_hop(destination_ip_address)
                .ok_or(())?;

            network_subsytem
                .arp()
                .get_mac_address(&next_hop, &nic.interface_id)
                .ok_or(())?
        };

        // Send frame
        network_subsytem.ethernet().send_frame(
            nic.local_mac_address,
            dest_mac,
            EtherType::Ipv4,
            buffer,
            nic.interface_id,
        );

        Ok(())
    }

    /// Calculates the 16-bit one's complement checksum for the IPv4
    /// header (RFC 791 §3.1).
    fn calculate_header_checksum(&self, header: &Ipv4PacketHeader) -> u16 {
        let bytes = header.as_bytes();
        let mut sum: u32 = 0;

        for i in (0..bytes.len()).step_by(2) {
            let word = u16::from_be_bytes([bytes[i], bytes[i + 1]]);
            sum = sum.wrapping_add(word as u32);
        }

        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        !(sum as u16)
    }

    /// Processes an inbound IPv4 packet and dispatches it to the appropriate transport protocol.
    pub fn process_data(
        &self,
        buffer: &mut PacketBuffer,
        nic: NetworkInterfaceId,
    ) -> Result<(), ()> {
        let header = buffer.consume_header::<Ipv4PacketHeader>().unwrap();
        let network_subsystem = kernel_ref().network_subsystem();

        if header.version_ihl >> 4 != 4 {
            log::trace!(
                "dropping non-IPv4 packet (version={})",
                header.version_ihl >> 4
            );

            return Err(());
        }

        if header.flags_fragment_offset.get() & 0x1FFF != 0 {
            log::trace!(
                "dropping fragmented packet from {} (fragmentation unsupported)",
                header.sender_ip()
            );
            return Err(());
        }

        let ip_payload_len = header.total_length().saturating_sub(header.header_length());
        buffer.trim_payload(ip_payload_len);

        match header.protocol() {
            Some(IpProtocol::Udp) => {
                if let Err(()) = network_subsystem
                    .udp()
                    .process_data(header.sender_ip(), buffer)
                {
                    log::trace!("UDP layer rejected packet from {}", header.sender_ip())
                }
            }
            Some(IpProtocol::Icmp) => {
                if let Err(()) =
                    network_subsystem
                        .icmp()
                        .process_data(buffer, &header.sender_ip(), nic)
                {
                    log::trace!("ICMP layer rejected packet from {}", header.sender_ip());
                }
            }
            Some(IpProtocol::Tcp) => {
                log::trace!(
                    "RX TCP {} -> {} len={}",
                    header.sender_ip(),
                    header.target_ip(),
                    buffer.frame().len()
                );

                let ip_ecn = header.tos & 0b11;
                if let Err(()) = network_subsystem.tcp().process_data(
                    header.sender_ip(),
                    header.target_ip(),
                    buffer,
                    nic,
                    ip_ecn,
                ) {
                    log::trace!("TCP layer rejected packet from {}", header.sender_ip())
                }
            }

            _ => warn!("Unhandled or unknown IP protocol: {:?}", header.protocol),
        }

        Ok(())
    }
}
