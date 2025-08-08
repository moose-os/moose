use core::fmt;

pub mod nic;

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MacAddress(pub [u8; 6]);

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

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct EthernetFrameHeader {
    pub destination_mac: MacAddress,
    pub source_mac: MacAddress,
    pub ether_type: EtherType,
}
#[repr(C, packed)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ipv4Addr {
    octets: [u8; 4],
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

impl fmt::Display for Ipv4Addr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}.{}.{}.{}",
            self.octets[0], self.octets[1], self.octets[2], self.octets[3]
        )
    }
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct Ipv4Header {
    pub version_ihl: u8,      // Version (4 bits) + Internet Header Length (4 bits)
    pub dscp_ecn: u8,         // DSCP (6 bits) + ECN (2 bits)
    pub total_length: u16,    // Total length (header + data)
    pub identification: u16,  // Identification
    pub flags_fragment: u16,  // Flags (3 bits) + Fragment offset (13 bits)
    pub ttl: u8,              // Time to live
    pub protocol: u8,         // Protocol
    pub header_checksum: u16, // Header checksum
    pub source_address: Ipv4Addr, // Source IP address
    pub dest_address: Ipv4Addr, // Destination IP address
}
