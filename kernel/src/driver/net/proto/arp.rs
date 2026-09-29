//! # ARP Driver Module
//!
//! Implements the Address Resolution Protocol (RFC 826) - the thing that
//! answers "who has this IP, tell me your MAC" on a local network. IP
//! routing only gets you to the right subnet; actually putting a frame
//! on the wire needs the destination's hardware (MAC) address, and ARP
//! is how that gets learned.
//!
//! ### ARP Packet Structure
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |       Hardware Type (1)       |      Protocol Type (0x0800)   |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |  HW Len (6)   | Proto Len (4) |       Operation (1/2)         |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                     Sender MAC Address (0-3)                  |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |  Sender MAC (4-5)             |      Sender IP (0-1)          |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |        Sender IP (2-3)        |      Target MAC (0-1          |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                     Target MAC Address (2-5)                  |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                           Target IP                           |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```

use alloc::sync::Arc;

use hashbrown::HashMap;
use x86_64::instructions::interrupts;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, network_endian::U16};

use crate::{
    driver::net::{
        Ipv4Addr, MacAddress, NetworkInterfaceId, TtlCache,
        proto::{DEFAULT_HEADER_RESERVE, PacketBuffer, ethernet::EtherType},
    },
    kernel::kernel_ref,
    subsystem::{
        clock::time::{Duration, Instant},
        scheduler::OneshotGate,
        sync::IrqGuardedRwLock,
    },
};

/// How long to wait for a reply before giving up on one ARP request.
const ARP_RESOLVE_TIMEOUT: Duration = Duration::from_secs(3);

/// Types of hardware as defined by IANA.
/// Ref: <https://www.iana.org/assignments/arp-parameters/arp-parameters.xhtml>
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(u16)]
enum HardwareType {
    /// Ethernet (10Mb)
    Ethernet = 1,

    /// IEEE 802 Networks
    Ieee802 = 6,

    /// ARCNET
    Arcnet = 7,

    /// Frame Relay
    FrameRelay = 15,

    /// Asynchronous Transfer Mode (ATM)
    Atm = 19,

    /// HDLC
    Hdlc = 28,

    /// Fibre Channel
    FibreChannel = 30,
}

/// Supported protocol types (EtherTypes) used in ARP - which L3
/// protocol's addresses are being resolved.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(u16)]
enum ProtocolType {
    /// Internet Protocol version 4 (IPv4)
    Ipv4 = 0x0800,

    /// Internet Protocol version 6 (IPv6)
    Ipv6 = 0x86DD,
}

/// ARP Operation codes.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(u16)]
pub enum ArpOperation {
    /// ARP Request - "who has this IP?"
    Request = 1,

    /// ARP Reply - "I do, here's my MAC."
    Reply = 2,

    /// RARP Request.
    RarpRequest = 3,

    /// RARP Reply.
    RarpReply = 4,
}

impl From<u16> for ArpOperation {
    fn from(value: u16) -> Self {
        match value {
            1 => ArpOperation::Request,
            2 => ArpOperation::Reply,
            3 => ArpOperation::RarpRequest,
            4 => ArpOperation::RarpReply,
            value => panic!("Unknown value for ArpOperation: {}", value),
        }
    }
}

/// Wire-level representation of an ARP frame header.
#[repr(C, packed)]
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Debug, Copy, Clone)]
pub struct ArpFrameHeader {
    pub hardware_type: U16,
    pub protocol_type: U16,
    pub hardware_length: u8,
    pub protocol_length: u8,
    pub operation: U16,
    pub sender_mac: [u8; 6],
    pub sender_ip: [u8; 4],
    pub target_mac: [u8; 6],
    pub target_ip: [u8; 4],
}

impl ArpFrameHeader {
    /// Returns the sender's IPv4 address from the ARP header.
    pub fn sender_ip(&self) -> Ipv4Addr {
        Ipv4Addr::new(self.sender_ip)
    }

    /// Returns the sender's hardware (MAC) address from the ARP header.
    pub fn sender_mac(&self) -> MacAddress {
        MacAddress(self.sender_mac)
    }

    /// Returns the target's IPv4 address from the ARP header.
    pub fn target_ip(&self) -> Ipv4Addr {
        Ipv4Addr::new(self.target_ip)
    }

    /// Returns the target's hardware (MAC) address from the ARP header.
    pub fn target_mac(&self) -> MacAddress {
        MacAddress(self.target_mac)
    }

    /// Returns Operation type.
    pub fn operation(&self) -> ArpOperation {
        ArpOperation::from(self.operation.get())
    }
}

/// A cache entry key: which interface, and which IP on it.
/// Interface-scoped because the same IP can mean different things
/// (different next-hop MAC) on different links.
type ArpKey = (NetworkInterfaceId, Ipv4Addr);

/// Resolved IP->MAC entries, capped at 128 and expiring on a TTL.
type ArpCache = TtlCache<ArpKey, MacAddress, 128>;

/// Main ARP protocol driver managing the IP-to-MAC resolution process.
pub struct ArpDriver {
    /// Actual ARP cache.
    cache: ArpCache,

    /// One gate per in-flight resolution.
    wait_queue: IrqGuardedRwLock<HashMap<ArpKey, Arc<OneshotGate>>>,
}

impl ArpDriver {
    /// Creates ARP driver instance
    pub fn new() -> Self {
        Self {
            cache: ArpCache::new(
                (NetworkInterfaceId(0), Ipv4Addr::new([0, 0, 0, 0])),
                MacAddress([0u8; 6]),
                Duration::from_secs(30),
            ),
            wait_queue: IrqGuardedRwLock::new(HashMap::new()),
        }
    }

    /// Records L2 adjacency learned from an inbound IPv4 frame.
    ///
    /// Every IP packet that arrives already tells us who's on the other end
    /// of the wire, so there's no reason to wait for that peer to show up
    /// in an actual ARP exchange before caching it. Also refreshes the entry
    /// for the resolved next-hop (not just the packet's source IP), since that's
    /// the key `get_mac_address` actually looks up for routed traffic.
    pub fn learn_from_ip_rx(&self, nic: &NetworkInterfaceId, ip: Ipv4Addr, mac: MacAddress) {
        // Dont cache broadcast/invalid addresses.
        if ip == Ipv4Addr::unspecified() || ip == Ipv4Addr::broadcast() {
            return;
        }

        // Insert the entry into the cache (or replace it).
        self.cache.insert((*nic, ip), mac);

        // If eth_src is the gateway, it's routed packet - so refresh that ARP entry too.
        if let Some(next_hop) = kernel_ref()
            .network_subsystem()
            .routing_table()
            .read()
            .resolve_next_hop(ip)
            && next_hop != ip
            && next_hop != Ipv4Addr::unspecified()
            && next_hop != Ipv4Addr::broadcast()
        {
            self.cache.insert((*nic, next_hop), mac);
        }
    }

    /// Attempts to resolve an IPv4 address to a hardware MAC address.
    ///
    /// Checks the cache first; on a miss, sends an ARP Request and
    /// blocks the calling thread until either a reply arrives or
    /// [`ARP_RESOLVE_TIMEOUT`] passes.
    pub fn get_mac_address(&self, ip: &Ipv4Addr, nic: &NetworkInterfaceId) -> Option<MacAddress> {
        // First check ARP Table to avoid unnecessary network lookups.
        if let Some(mac) = self.cache.lookup((*nic, *ip)) {
            // If we got cache hit, it's the best case scenario, just return MAC address and return.
            log::trace!("ARP cache hit for IP {}: {:?}", ip, mac);

            return Some(mac);
        }

        // Blocking ARP resolution requires thread context with interrupts enabled
        if !interrupts::are_enabled() {
            log::trace!("ARP cache miss for IP {} with IRQs disabled", ip);

            return None;
        }

        log::trace!("ARP cache miss for IP {}", ip);

        // If address is not in cache, try to look it up in the network by sending ARP Request.
        self.send_arp_request(ip, nic);

        // send_arp_request blocks the thread until we get the response, so perform one more lookup,
        // and check if it didn't timeout.
        if let Some(mac) = self.cache.lookup((*nic, *ip)) {
            log::trace!("Received ARP reply for IP {}: {:?}", ip, mac);

            return Some(mac);
        }

        log::trace!("ARP request timeout for IP {}", ip);

        None
    }

    /// Constructs and broadcasts an ARP Request frame to the local network.
    fn send_arp_request(&self, target_ip: &Ipv4Addr, nic_id: &NetworkInterfaceId) {
        let key = (*nic_id, *target_ip);

        // Get the gate we're gonna wait for. We either create new for new
        // request, or piggyback to already existing.
        let gate = {
            let mut wait_queue = self.wait_queue.write();

            wait_queue
                .entry(key)
                .or_insert_with(|| Arc::new(OneshotGate::new()))
                .clone()
        };

        let network_subsystem = kernel_ref().network_subsystem();
        let nic = network_subsystem.interfaces().get(*nic_id).unwrap();
        let sender_ip = nic
            .local_internet_address
            .unwrap_or(Ipv4Addr::unspecified());

        // Prepare ARP request. Target MAC is left blank, as we don't know it.
        let request_hdr = ArpFrameHeader {
            hardware_type: U16::new(HardwareType::Ethernet as u16),
            protocol_type: U16::new(ProtocolType::Ipv4 as u16),
            hardware_length: 6,
            protocol_length: 4,
            operation: U16::new(ArpOperation::Request as u16),
            sender_mac: nic.local_mac_address.0,
            sender_ip: sender_ip.octets,
            target_mac: [0u8; 6],
            target_ip: target_ip.octets(),
        };

        let mut storage = [0u8; DEFAULT_HEADER_RESERVE + 64];
        let mut buffer = PacketBuffer::for_transmit(&mut storage, DEFAULT_HEADER_RESERVE);
        buffer.prepend_header(&request_hdr);

        log::trace!(
            "TX request nic={:?} sender_ip={} sender_mac={:?} target_ip={}",
            nic.interface_id,
            sender_ip,
            nic.local_mac_address,
            target_ip
        );

        // Send ARP frame.
        network_subsystem.ethernet().send_frame(
            nic.local_mac_address,
            MacAddress::broadcast(),
            EtherType::Arp,
            &mut buffer,
            nic.interface_id,
        );

        // Wait on gate and check the deadline, as gate opening is not synchronized
        // with wait.
        let deadline = Instant::now() + ARP_RESOLVE_TIMEOUT;
        while Instant::now() < deadline {
            if self.cache.lookup(key).is_some() || gate.is_open() {
                break;
            }

            gate.wait();
        }

        // Remove it from wait_queue, as it got already resolved.
        self.wait_queue.write().remove(&key);
    }

    /// Constructs and sends an ARP Reply frame in response to an ARP Request.
    fn send_arp_reply(&self, header: &ArpFrameHeader, nic: NetworkInterfaceId) {
        let network_subsystem = kernel_ref().network_subsystem();
        let nic = network_subsystem.interfaces().get(nic).unwrap();

        let reply_hdr = ArpFrameHeader {
            hardware_type: U16::new(HardwareType::Ethernet as u16),
            protocol_type: U16::new(ProtocolType::Ipv4 as u16),
            hardware_length: 6,
            protocol_length: 4,
            operation: U16::new(ArpOperation::Reply as u16),
            sender_mac: nic.local_mac_address.0,
            sender_ip: nic
                .local_internet_address
                .unwrap_or(Ipv4Addr::unspecified())
                .octets,
            target_mac: header.sender_mac,
            target_ip: header.sender_ip,
        };

        let mut storage = [0u8; DEFAULT_HEADER_RESERVE + 64];
        let mut buffer = PacketBuffer::for_transmit(&mut storage, DEFAULT_HEADER_RESERVE);
        buffer.prepend_header(&reply_hdr);

        log::trace!(
            "TX reply nic={:?} sender_ip={} sender_mac={:?} target_ip={} target_mac={:?}",
            nic.interface_id,
            Ipv4Addr::new(reply_hdr.sender_ip),
            nic.local_mac_address,
            header.sender_ip(),
            header.sender_mac(),
        );

        network_subsystem.ethernet().send_frame(
            nic.local_mac_address,
            header.sender_mac(),
            EtherType::Arp,
            &mut buffer,
            nic.interface_id,
        );
    }

    /// Dispatches and processes an incoming ARP frame.
    pub fn process_data(
        &self,
        buffer: &mut PacketBuffer,
        nic: NetworkInterfaceId,
    ) -> Result<(), ()> {
        let header = buffer.consume_header::<ArpFrameHeader>().unwrap();

        log::trace!(
            "RX nic={:?} op={:?} sender_ip={} sender_mac={:?} target_ip={} target_mac={:?}",
            nic,
            header.operation(),
            header.sender_ip(),
            header.sender_mac(),
            header.target_ip(),
            header.target_mac(),
        );

        match header.operation() {
            ArpOperation::Request => {
                // This frame tells us exactly what IP and MAC does sender have, so
                // we can freely cache it for future use.
                self.cache
                    .insert((nic, header.sender_ip()), header.sender_mac());

                let nic_ip = kernel_ref()
                    .network_subsystem()
                    .interfaces()
                    .get(nic)
                    .ok_or(())?
                    .local_internet_address;

                log::trace!(
                    "RX request nic={:?} nic_ip={:?} target_ip={} match={}",
                    nic,
                    nic_ip,
                    header.target_ip(),
                    nic_ip == Some(header.target_ip())
                );

                // If it's our interface, just send a reply.
                if nic_ip == Some(header.target_ip()) {
                    self.send_arp_reply(&header, nic);
                }
            }

            ArpOperation::Reply => {
                log::trace!("Received ARP reply from IP={}", header.sender_ip());

                // If we've got the reply, just cache it and open the gate other
                // threads are waiting on.
                let key = (nic, header.sender_ip());
                self.cache.insert(key, header.sender_mac());

                if let Some(gate) = self.wait_queue.write().remove(&key) {
                    gate.open();
                }
            }

            // Very unlikely, as RARP is an old artifact.
            unknown => warn!("Got ARP packet with invalid operation={:?}", unknown),
        };

        Ok(())
    }
}
