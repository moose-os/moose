use alloc::fmt;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, network_endian::U16};

pub mod nic;

#[derive(Clone, Copy, PartialEq, Eq, Hash, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct MacAddress(pub [u8; 6]);

impl MacAddress {
    pub fn broadcast() -> Self {
        Self([0xFF; 6])
    }
}

impl fmt::Debug for MacAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bytes = &self.0;
        write!(
            f,
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
        )
    }
}

#[repr(u16)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum EtherType {
    Cdp = 0x2000,
    Stp = 0x42,
    Ipv4 = 0x0800,                // IPv4
    Arp = 0x0806,                 // ARP
    WakeOnLan = 0x0842,           // Wake-on‑LAN
    ReverseArp = 0x8035,          // RARP
    AppleTalk = 0x809B,           // EtherTalk
    Aarp = 0x80F3,                // AppleTalk ARP
    Vlan = 0x8100,                // IEEE 802.1Q VLAN tag
    Slpp = 0x8102,                // Simple Loop Prevention Protocol
    Vlacp = 0x8103,               // Virtual Link Aggregation Control Protocol
    Ipx = 0x8137,                 // IPX
    Qnx = 0x8204,                 // QNX Qnet
    Ipv6 = 0x86DD,                // IPv6
    EthernetFlowControl = 0x8808, // Ethernet flow control
    SlowProtocols = 0x8809,       // LACP etc.
    CobraNet = 0x8819,
    MplsUnicast = 0x8847,   // MPLS unicast
    MplsMulticast = 0x8848, // MPLS multicast
    PPPoEDiscovery = 0x8863,
    PPPoESession = 0x8864,
    HomePlugMME = 0x887B,
    EapOverLan = 0x888E, // 802.1X
    Profinet = 0x8892,
    HyperScsi = 0x889A,
    ATAoE = 0x88A2,
    EtherCAT = 0x88A4,
    QinQ = 0x88A8, // provider bridging
    Powerlink = 0x88AB,
    Lldp = 0x88CC, // Link Layer Discovery Protocol
    SercosIII = 0x88CD,
    HomePlugGreenPhy = 0x88E1,
    MediaRedundancy = 0x88E3,
    MacSec = 0x88E5,
    ProviderBackbone = 0x88E7, // PBB IEEE 802.1ah
    Ptp = 0x88F7,              // Precision Time Protocol
    NcSi = 0x88F8,
    Prp = 0x88FB,      // Parallel Redundancy Protocol
    Cfm = 0x8902,      // Connectivity Fault Management / Y.1731
    FCoE = 0x8906,     // Fibre Channel over Ethernet
    FCoEInit = 0x8914, // Initialization Protocol
    RoCE = 0x8915,     // RDMA over Converged Ethernet
    TTEthernet = 0x891D,
    IEEE1905_1 = 0x893A,
    Hsr = 0x892F,
    ConfigTest = 0x9000,    // configuration testing
    Qinq9100 = 0x9100,      // Q‑in‑Q / loopback
    RedundancyTag = 0xF1C1, // IEEE 802.1CB
}

impl TryFrom<u16> for EtherType {
    type Error = u16;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0x0800 => Ok(EtherType::Ipv4),
            0x0806 => Ok(EtherType::Arp),
            0x0842 => Ok(EtherType::WakeOnLan),
            0x2000 => Ok(EtherType::Cdp),
            0x8035 => Ok(EtherType::ReverseArp),
            0x809B => Ok(EtherType::AppleTalk),
            0x80F3 => Ok(EtherType::Aarp),
            0x8100 => Ok(EtherType::Vlan),
            0x8102 => Ok(EtherType::Slpp),
            0x8103 => Ok(EtherType::Vlacp),
            0x8137 => Ok(EtherType::Ipx),
            0x8204 => Ok(EtherType::Qnx),
            0x86DD => Ok(EtherType::Ipv6),
            0x8808 => Ok(EtherType::EthernetFlowControl),
            0x8809 => Ok(EtherType::SlowProtocols),
            0x8819 => Ok(EtherType::CobraNet),
            0x8847 => Ok(EtherType::MplsUnicast),
            0x8848 => Ok(EtherType::MplsMulticast),
            0x8863 => Ok(EtherType::PPPoEDiscovery),
            0x8864 => Ok(EtherType::PPPoESession),
            0x887B => Ok(EtherType::HomePlugMME),
            0x888E => Ok(EtherType::EapOverLan),
            0x8892 => Ok(EtherType::Profinet),
            0x889A => Ok(EtherType::HyperScsi),
            0x88A2 => Ok(EtherType::ATAoE),
            0x88A4 => Ok(EtherType::EtherCAT),
            0x88A8 => Ok(EtherType::QinQ),
            0x88AB => Ok(EtherType::Powerlink),
            0x88CC => Ok(EtherType::Lldp),
            0x88CD => Ok(EtherType::SercosIII),
            0x88E1 => Ok(EtherType::HomePlugGreenPhy),
            0x88E3 => Ok(EtherType::MediaRedundancy),
            0x88E5 => Ok(EtherType::MacSec),
            0x88E7 => Ok(EtherType::ProviderBackbone),
            0x88F7 => Ok(EtherType::Ptp),
            0x88F8 => Ok(EtherType::NcSi),
            0x88FB => Ok(EtherType::Prp),
            0x8902 => Ok(EtherType::Cfm),
            0x8906 => Ok(EtherType::FCoE),
            0x8914 => Ok(EtherType::FCoEInit),
            0x8915 => Ok(EtherType::RoCE),
            0x891D => Ok(EtherType::TTEthernet),
            0x893A => Ok(EtherType::IEEE1905_1),
            0x892F => Ok(EtherType::Hsr),
            0x9000 => Ok(EtherType::ConfigTest),
            0x9100 => Ok(EtherType::Qinq9100),
            0xF1C1 => Ok(EtherType::RedundancyTag),
            _ => Err(value),
        }
    }
}

#[repr(C, packed)]
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Debug, Copy, Clone)]
pub struct EthernetFrameHeader {
    pub destination_mac: [u8; 6],
    pub source_mac: [u8; 6],
    pub ether_type: U16,
}

impl EthernetFrameHeader {
    pub fn destination_mac(&self) -> MacAddress {
        MacAddress(self.destination_mac)
    }

    pub fn source_mac(&self) -> MacAddress {
        MacAddress(self.source_mac)
    }

    pub fn ether_type(&self) -> Result<EtherType, u16> {
        EtherType::try_from(self.ether_type.get())
    }
}

#[repr(C, packed)]
#[derive(
    Clone, Copy, PartialEq, Eq, Hash, FromBytes, IntoBytes, Immutable, KnownLayout, Ord, PartialOrd,
)]
pub struct Ipv4Addr {
    octets: [u8; 4],
}

impl From<[u8; 4]> for Ipv4Addr {
    #[inline]
    fn from(octets: [u8; 4]) -> Self {
        Ipv4Addr::new(octets)
    }
}

impl Ipv4Addr {
    /// Create a new IPv4 address from raw bytes.
    pub fn new(octets: [u8; 4]) -> Self {
        Self { octets }
    }

    /// Access raw octets.
    pub fn octets(&self) -> [u8; 4] {
        self.octets
    }
}

impl From<Ipv4Addr> for u32 {
    fn from(ip: Ipv4Addr) -> Self {
        let [a, b, c, d] = ip.octets;

        ((a as u32) << 24) | ((b as u32) << 16) | ((c as u32) << 8) | (d as u32)
    }
}

impl From<u32> for Ipv4Addr {
    fn from(ip_u32: u32) -> Self {
        let a = (ip_u32 >> 24) as u8;
        let b = (ip_u32 >> 16) as u8;
        let c = (ip_u32 >> 8) as u8;
        let d = ip_u32 as u8;

        Self::new([a, b, c, d])
    }
}

impl fmt::Display for Ipv4Addr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}.{}.{}.{}",
            self.octets[0], self.octets[1], self.octets[2], self.octets[3]
        )
    }
}

impl fmt::Debug for Ipv4Addr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}.{}.{}.{}",
            self.octets[0], self.octets[1], self.octets[2], self.octets[3]
        )
    }
}

/// IPv4 Header Structure (RFC 791)
///
/// ### Header Diagram (32-bit words)
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
/// |                       Source Address                          |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                    Destination Address                        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct Ipv4Header {
    /// Version (4 bits) + Internet Header Length (4 bits)
    pub version_ihl: u8,
    /// Differentiated Services Code Point (6 bits) + Explicit Congestion Notification (2 bits)
    pub dscp_ecn: u8,
    /// Total length of the datagram (header + data) in bytes
    pub total_length: u16,
    /// Unique identifier for fragments of a single datagram
    pub identification: u16,
    /// Control flags (3 bits) + Fragment offset (13 bits)
    pub flags_fragment: u16,
    /// Datagram lifetime to prevent routing loops
    pub ttl: u8,
    /// Next level protocol (e.g., TCP = 6, UDP = 17)
    pub protocol: u8,
    /// Error-checking for the header
    pub header_checksum: u16,
    /// IPv4 address of the sender
    pub source_address: Ipv4Addr,
    /// IPv4 address of the receiver
    pub dest_address: Ipv4Addr,
}
