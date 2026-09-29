//! # Ethernet Network Subsystem
//!
//! This module implements the Data Link Layer (Layer 2) of the kernel network stack.
//!
//! ### Ethernet II Frame Layout (RFC 894)
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |       Destination MAC Address (Bytes 0-3)                     |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! | Dest MAC (4-5)                |    Source MAC Address (0-1)   |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |           Source MAC Address (Bytes 2-5)                      |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! | EtherType (IPv4/ARP/etc)      |                               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+        Payload Data           |
//! |                                                               |
//! ~                  (Variable Length: 46 - 1500 bytes)           ~
//! |                                                               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//!
//! ## Inbound Packet Flow
//!
//! ```text
//!  ┌──────────────┐      ┌──────────────────────────┐      ┌─────────────────┐
//!  │ Hardware NIC │─────>│ NIC Interrupt Handler    │─────>│ Ethernet Driver │
//!  └──────────────┘      └──────────────────────────┘      └────────┬────────┘
//!                                                                   │
//!                                                                   │ (enqueue)
//!                                                                   ▼
//!                                                  ┌──────────────────────────┐
//!                                                  │ processing_queue (Ring)  │
//!                                                  └──────────┬───────────────┘
//!                                                             │
//!                                                             │ (notify / wake)
//!                                                             ▼
//!  ┌────────────────┐      ┌─────────────────┐      ┌──────────────────────────┐
//!  │  IPV4_DRIVER   │<─────┤ process_data()  │<─────┤ ethernet_worker (Thread) │
//!  └────────────────┘      └────────┬────────┘      └──────────────────────────┘
//!                                   │
//!  ┌────────────────┐               │
//!  │   ARP_DRIVER   │<──────────────┘
//!  └────────────────┘
//! ```
use core::mem;

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, network_endian::U16};

use super::ip::Ipv4PacketHeader;
use crate::{
    driver::net::{MacAddress, NetworkInterfaceId, proto::PacketBuffer},
    kernel::kernel_ref,
};

/// EtherType values this stack can recognize on the wire.
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

/// The 14-byte Ethernet II header - destination and source MAC plus the
/// EtherType tag identifying the payload's protocol.
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

    /// Decodes the EtherType field, or returns the raw value if it's
    /// not one this stack recognizes.
    pub fn ether_type(&self) -> Result<EtherType, u16> {
        EtherType::try_from(self.ether_type.get())
    }
}

/// Layer 2 driver: builds and sends outgoing Ethernet frames, and
/// dispatches incoming ones to the right Layer 3 protocol driver by
/// EtherType.
pub struct EthernetDriver {}

impl EthernetDriver {
    /// Initializes the Ethernet driver.
    pub fn new() -> Self {
        Self {}
    }

    /// Encapsulates and transmits data as an Ethernet II frame.
    pub fn send_frame(
        &self,
        source_mac: MacAddress,
        destination_mac: MacAddress,
        protocol: EtherType,
        buffer: &mut PacketBuffer,
        nic: NetworkInterfaceId,
    ) {
        // Construct Ethernet header
        let header = EthernetFrameHeader {
            destination_mac: destination_mac.0,
            source_mac: source_mac.0,
            ether_type: (protocol as u16).into(),
        };

        // Prepend Ethernet header at the start of the frame.
        buffer.prepend_header(&header);

        let frame = buffer.frame();
        let network_subsystem = kernel_ref().network_subsystem();

        // Send the frame to the NIC.
        match network_subsystem.interfaces().get(nic) {
            Some(interface) => match &interface.nic {
                Some(card) => card.send_packet(frame),
                None => log::trace!("nic={:?} has no attached card, dropping frame", nic),
            },
            None => log::trace!("unknown nic={:?}, dropping frame", nic),
        }
    }

    /// Dispatches queued Ethernet frames to their respective Layer 3 protocol drivers.
    pub fn process_data(
        &self,
        buffer: &mut PacketBuffer,
        nic: NetworkInterfaceId,
    ) -> Result<(), ()> {
        // Get the Ethernet header and ether_type
        let header = buffer.consume_header::<EthernetFrameHeader>().unwrap();
        let Some(ether_type) = self.identify_protocol(buffer, &header) else {
            return Ok(());
        };

        log::trace!(
            "RX nic={:?} src={:?} dst={:?} ethertype={:?} payload_len={}",
            nic,
            header.source_mac(),
            header.destination_mac(),
            ether_type,
            buffer.payload().len()
        );

        // Pass the frame for further processing in dedicated protocol driver.
        match ether_type {
            EtherType::Ipv4 => {
                let payload = buffer.payload();

                // Try to learn ARP MAC->IP mapping from incoming data as well.
                if payload.len() >= mem::size_of::<Ipv4PacketHeader>()
                    && let Ok((ip_hdr, _)) = Ipv4PacketHeader::read_from_prefix(payload)
                {
                    kernel_ref().network_subsystem().arp().learn_from_ip_rx(
                        &nic,
                        ip_hdr.sender_ip(),
                        header.source_mac(),
                    );
                }

                // Send the packet to the IP stack for further processing.
                if let Err(()) = kernel_ref()
                    .network_subsystem()
                    .ipv4()
                    .process_data(buffer, nic)
                {
                    log::trace!("nic={:?}: IPv4 layer rejected frame", nic)
                }
            }
            EtherType::Arp => {
                if let Err(()) = kernel_ref()
                    .network_subsystem()
                    .arp()
                    .process_data(buffer, nic)
                {
                    log::trace!("RX nic={:?}: ARP layer rejected frame", nic)
                }
            }

            unknown => trace!("dropping unhandled ethertype: {:?}", unknown),
        }

        Ok(())
    }

    /// Determines the EtherType of an incoming frame, falling back to
    /// IEEE 802.2 LLC/SNAP decoding when the header's own EtherType
    /// field isn'tplain Ethernet II type.
    fn identify_protocol(
        &self,
        buffer: &PacketBuffer,
        hdr: &EthernetFrameHeader,
    ) -> Option<EtherType> {
        // Try to match ether type based on the header field.
        if let Ok(et) = hdr.ether_type() {
            return Some(et);
        }

        // If typical EtherType values are not recognized, it's probably LLC/SNAP frame with
        // added 3 fields before the data payload: DSAP/SSAP/CTL, which identifies the underlying
        // protocol.
        let payload = buffer.payload();
        if payload.len() < 3 {
            return None;
        }

        let dsap = payload[0];
        let ssap = payload[1];
        let control = payload[2];

        match (dsap, ssap, control) {
            // SNAP Encapsulation
            (0xAA, 0xAA, 0x03) if payload.len() >= 8 => {
                let type_bytes = [payload[6], payload[7]];
                EtherType::try_from(u16::from_be_bytes(type_bytes)).ok()
            }

            // Spanning Tree Protocol
            (0x42, 0x42, 0x03) => Some(EtherType::Stp),

            // Default/Unknown
            _ => {
                log::trace!(
                    "dropping unknown LLC frame (dsap=0x{:x}, ssap=0x{:x}, ctl=0x{:x})",
                    dsap,
                    ssap,
                    control
                );

                None
            }
        }
    }
}
