//! # DHCP Client
//!
//! One session per interface (keyed by MAC), tracked in `sessions`. The
//! worker thread blocks on `socket_recv_from` and drives the state
//! machine forward on each Offer/Ack; a separate per-lease timer thread
//! wakes at T1 to renew (unicast to the server) and, if that doesn't
//! refresh the lease in time, at T2 to rebind (broadcast) before the
//! lease finally expires.

use alloc::{sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use hashbrown::HashMap;
use zerocopy::{
    FromBytes, Immutable, IntoBytes, KnownLayout,
    network_endian::{U16, U32},
};

use crate::{
    driver::net::{
        Ipv4Addr, Ipv4Prefix, MacAddress, NetworkInterfaceId, NextHop,
        proto::{
            dns::{DnsResolver, DnsResolverConfig},
            udp::UdpSocketHandle,
        },
    },
    kernel::kernel_ref,
    subsystem::{
        clock::time::Duration,
        process::DEFAULT_THREAD_PRIORITY,
        scheduler::{OneshotGate, current_thread, yield_to_scheduler},
        sync::IrqGuardedMutex,
    },
};

/// Well-known DHCP server port.
const DHCP_SERVER_PORT: u16 = 67;

/// Well-known DHCP client port.
const DHCP_CLIENT_PORT: u16 = 68;

/// DHCP receive buffer size.
const DHCP_RECV_BUFFER_SIZE: usize = 1536;

/// MAGIC Cookie used for BOOTP.
const MAGIC_COOKIE: [u8; 4] = [0x63, 0x82, 0x53, 0x63];

/// BOOTP `op` field: this message is a request (client -> server).
const OP_BOOTREQUEST: u8 = 1;

/// `htype`: Ethernet.
const HTYPE_ETHERNET: u8 = 1;

/// `hlen`: length of an Ethernet MAC address.
const HLEN_MAC: u8 = 6;

/// Standard DHCP frame header as defined in RFC 2131, options area included.
#[repr(C, packed)]
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Debug, Copy, Clone)]
pub struct DhcpFrameHeader {
    /// BOOTREQUEST (client->server) or BOOTREPLY (server->client).
    pub operation: u8,

    /// Hardware type.
    pub hardware_type: u8,

    /// Hardware address length.
    pub hardware_address_length: u8,

    /// Number of relay agent hops (always 0 here, as we don't support Relay servers).
    pub hops: u8,

    /// Transaction ID, chosen by the client and echoed by the server,
    /// used to match replies to the request that triggered them.
    pub xid: U32,

    /// Seconds elapsed since the client started this acquisition/renewal.
    pub seconds: U16,

    /// Flags - bit 0 (0x8000) is the "broadcast" flag, requesting the
    /// server reply via broadcast rather than unicast to `your_ip_addr`
    /// (needed since the client has no usable IP yet).
    pub flags: U16,

    /// Client's own IP, if it already has one and is confirming it (0
    /// during initial Discover/Request).
    pub client_ip_addr: [u8; 4],

    /// "Your" IP - the address the server is offering/assigning.
    pub your_ip_addr: [u8; 4],

    /// IP of the next server in the bootstrap process.
    pub next_server_ip: [u8; 4],

    /// IP of the relaying agent, if any.
    pub relay_agent_ip: [u8; 4],

    /// Client's hardware (MAC) address.
    pub hardware_address: [u8; 6],

    /// Padding out to 16 bytes total for the hardware-address field.
    pub hardware_address_padding: [u8; 10],

    /// Optional client host name.
    pub host_name: [u8; 64],

    /// Optional boot file name.
    pub file_name: [u8; 128],

    /// Magic cookie + TLV-encoded options.
    pub options: [u8; 312],
}

/// DHCP/BOOTP fixed header without the variable-length options - used
/// when reading an incoming frame, where the options are then parsed
/// separately from the remaining bytes via [`DhcpOptionsParser`].
#[repr(C, packed)]
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Debug, Copy, Clone)]
pub struct DhcpFixedHeader {
    pub operation: u8,
    pub hardware_type: u8,
    pub hardware_address_length: u8,
    pub hops: u8,
    pub xid: U32,
    pub seconds: U16,
    pub flags: U16,
    pub client_ip_addr: [u8; 4],
    pub your_ip_addr: [u8; 4],
    pub next_server_ip: [u8; 4],
    pub relay_agent_ip: [u8; 4],
    pub hardware_address: [u8; 6],
    pub hardware_address_padding: [u8; 10],
    pub host_name: [u8; 64],
    pub file_name: [u8; 128],
}

impl DhcpFixedHeader {
    /// The client MAC this reply is addressed to.
    pub fn client_mac_address(&self) -> MacAddress {
        MacAddress(self.hardware_address)
    }

    /// The IP address being offered/assigned (`your_ip_addr`).
    pub fn offered_internet_address(&self) -> Ipv4Addr {
        Ipv4Addr::new(self.your_ip_addr)
    }

    /// This message's transaction ID, for matching against the request
    /// that triggered it.
    pub fn transaction_id(&self) -> u32 {
        self.xid.get()
    }
}

/// Builds a DHCP options area: writes the magic cookie up front, then
/// appends TLV-encoded options one at a time, and terminates with `End`
/// on [`finish`](Self::finish).
pub struct DhcpOptionsWriter<'a> {
    buffer: &'a mut [u8],
    position: usize,
}

impl<'a> DhcpOptionsWriter<'a> {
    /// Starts writing into `buffer`, stamping the magic cookie at the front.
    pub fn new(buffer: &'a mut [u8]) -> Self {
        buffer[0..4].copy_from_slice(&MAGIC_COOKIE);

        Self {
            buffer,
            position: 4,
        }
    }

    /// Appends one `code`/`data` option (Kind-Length-Value).
    pub fn add_option(&mut self, code: DhcpOptionCode, data: &[u8]) {
        self.buffer[self.position] = code as u8;
        self.buffer[self.position + 1] = data.len() as u8;
        self.buffer[self.position + 2..self.position + 2 + data.len()].copy_from_slice(data);
        self.position += 2 + data.len();
    }

    /// Writes the terminating `End` option.
    pub fn finish(self) {
        self.buffer[self.position] = DhcpOptionCode::End as u8;
    }
}

/// DHCP message type (option 53).
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DhcpMessageType {
    Discover = 1,
    Offer = 2,
    Request = 3,
    Decline = 4,
    Ack = 5,
    Nak = 6,
    Release = 7,
    Inform = 8,
}

impl TryFrom<u8> for DhcpMessageType {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Discover),
            2 => Ok(Self::Offer),
            3 => Ok(Self::Request),
            4 => Ok(Self::Decline),
            5 => Ok(Self::Ack),
            6 => Ok(Self::Nak),
            7 => Ok(Self::Release),
            8 => Ok(Self::Inform),
            _ => Err(()),
        }
    }
}

/// DHCP option codes this client reads or writes.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DhcpOptionCode {
    Pad = 0,
    SubnetMask = 1,
    Router = 3,
    DnsServer = 6,
    HostName = 12,
    DomainName = 15,
    NetBiosOverTcpIpNodeType = 46,
    RequestedIpAddress = 50,
    IpAddressLeaseTime = 51,
    OptionOverload = 52,
    MessageType = 53,
    ServerIdentifier = 54,
    ParameterRequestList = 55,
    Message = 56,
    MaximumDhcpMessageSize = 57,
    RenewalTimeValue = 58,
    RebindingTimeValue = 59,
    VendorClassIdentifier = 60,
    ClientIdentifier = 61,
    End = 255,
}

impl From<u8> for DhcpOptionCode {
    fn from(code: u8) -> Self {
        match code {
            0 => Self::Pad,
            1 => Self::SubnetMask,
            3 => Self::Router,
            6 => Self::DnsServer,
            12 => Self::HostName,
            15 => Self::DomainName,
            46 => Self::NetBiosOverTcpIpNodeType,
            50 => Self::RequestedIpAddress,
            51 => Self::IpAddressLeaseTime,
            52 => Self::OptionOverload,
            53 => Self::MessageType,
            54 => Self::ServerIdentifier,
            55 => Self::ParameterRequestList,
            56 => Self::Message,
            57 => Self::MaximumDhcpMessageSize,
            58 => Self::RenewalTimeValue,
            59 => Self::RebindingTimeValue,
            60 => Self::VendorClassIdentifier,
            61 => Self::ClientIdentifier,
            255 => Self::End,
            unknown => panic!("unknown DHCP option code: {unknown}"),
        }
    }
}

/// One parsed option: its code and raw value bytes.
pub struct DhcpOption<'a> {
    pub code: DhcpOptionCode,
    pub data: &'a [u8],
}

/// Parses a DHCP options area (after the fixed header).
pub struct DhcpOptionsParser;

impl DhcpOptionsParser {
    /// Walks `buffer` (the options area of a received frame) into a list
    /// of options.
    pub fn parse(buffer: &[u8]) -> Vec<DhcpOption<'_>> {
        let mut options = Vec::new();

        // It has to start from MAGIC_COOKIE.
        if buffer.len() < 4 || buffer[0..4] != MAGIC_COOKIE {
            return options;
        }

        let mut position = 4;
        while position < buffer.len() {
            let code = DhcpOptionCode::from(buffer[position]);

            match code {
                DhcpOptionCode::End => break,
                DhcpOptionCode::Pad => position += 1,
                _ => {
                    if position + 1 >= buffer.len() {
                        break;
                    }

                    let length = buffer[position + 1] as usize;
                    let data_start = position + 2;
                    let data_end = data_start + length;

                    if data_end > buffer.len() {
                        break;
                    }

                    options.push(DhcpOption {
                        code,
                        data: &buffer[data_start..data_end],
                    });

                    position = data_end;
                }
            }
        }

        options
    }

    /// Pulls the `MessageType` (option 53) out of an
    /// already-parsed option list, if present and valid.
    pub fn message_type(options: &[DhcpOption<'_>]) -> Option<DhcpMessageType> {
        options
            .iter()
            .find(|option| option.code == DhcpOptionCode::MessageType)
            .and_then(|option| option.data.first())
            .and_then(|value| DhcpMessageType::try_from(*value).ok())
    }
}

/// Finalized IPv4 configuration obtained from a DHCP server.
#[derive(Debug, Clone)]
pub struct DhcpLease {
    pub internet_address: Ipv4Addr,
    pub subnet_mask: Ipv4Addr,
    pub default_gateway: Ipv4Addr,
    pub dns_servers: Vec<Ipv4Addr>,
    pub lease_time_seconds: u32,
    pub renewal_time_seconds: Option<u32>,   // option 58 (T1)
    pub rebinding_time_seconds: Option<u32>, // option 59 (T2)
    pub server_identifier: Option<Ipv4Addr>, // option 54
}

/// Per-interface DHCP negotiation state.
#[derive(Clone)]
struct DhcpSession {
    /// Interface ID used for communication.
    interface_id: NetworkInterfaceId,

    /// MAC address of this interface.
    mac_address: MacAddress,

    /// The last DHCP message type we sent.
    last_message: DhcpMessageType,

    /// Transaction ID of the request `last_message` refers to.
    transaction_id: u32,

    /// The lease once an Offer has provided one.
    lease: Option<DhcpLease>,

    /// Opened once the initial DORA sequence completes with an ACK.
    completion: Arc<OneshotGate>,

    /// Latches once `completion` has been opened, so a later renewal
    /// doesn't try to re-open a gate that's already served its purpose.
    acquisition_complete: Arc<AtomicBool>,

    /// Whether the per-lease T1/T2 timer thread has already been
    /// spawned for this interface, so it's only started once.
    timer_spawned: Arc<AtomicBool>,
}

/// Owns the shared UDP socket (port 68) and every interface's DHCP
/// session state.
pub struct DhcpDriver {
    udp_socket: IrqGuardedMutex<Option<UdpSocketHandle>>,
    sessions: IrqGuardedMutex<HashMap<MacAddress, Arc<DhcpSession>>>,
    xid_counter: AtomicU32,
}

impl DhcpDriver {
    pub fn new() -> Self {
        Self {
            udp_socket: IrqGuardedMutex::new(None),
            sessions: IrqGuardedMutex::new(HashMap::new()),
            xid_counter: AtomicU32::new(0x1234_5678),
        }
    }

    /// One-time setup: bind UDP port 68 and spawn the kernel worker thread.
    pub fn initialize(&self) {
        let udp = kernel_ref().network_subsystem().udp();
        let socket = udp.socket_create();

        udp.socket_bind(socket, DHCP_CLIENT_PORT)
            .expect("DHCP: failed to bind UDP port 68");

        *self.udp_socket.lock() = Some(socket);

        kernel_ref()
            .spawn_kernel_thread(dhcp_worker, 0, DEFAULT_THREAD_PRIORITY)
            .unwrap();
    }

    /// Sends Discover for every registered NIC that still has no IPv4 address.
    pub fn begin_discovery_for_all_nics(&self) {
        let ns = kernel_ref().network_subsystem();

        ns.interfaces().for_each_occupied(|id, iface| {
            if iface.nic.is_some() && iface.local_internet_address.is_none() {
                self.begin_lease_acquisition(id, iface.local_mac_address);
            }
        });
    }

    /// Starts a new DORA sequence for one interface: creates its
    /// session and sends the initial Discover.
    fn begin_lease_acquisition(&self, interface_id: NetworkInterfaceId, mac_address: MacAddress) {
        // Dont start new session if an old one is in progress.
        if self.sessions.lock().contains_key(&mac_address) {
            return;
        }

        let transaction_id = self.xid_counter.fetch_add(1, Ordering::Relaxed);
        let completion = Arc::new(OneshotGate::new());
        let acquisition_complete = Arc::new(AtomicBool::new(false));
        let timer_spawned = Arc::new(AtomicBool::new(false));

        {
            let mut sessions = self.sessions.lock();
            sessions.insert(
                mac_address,
                Arc::new(DhcpSession {
                    interface_id,
                    mac_address,
                    last_message: DhcpMessageType::Discover,
                    transaction_id,
                    lease: None,
                    completion,
                    acquisition_complete,
                    timer_spawned,
                }),
            );
        }

        // Send discover.
        if self.send_discover(mac_address, transaction_id).is_err() {
            log::trace!("Failed to send Discover for {:?}", mac_address);

            self.sessions.lock().remove(&mac_address);

            return;
        }

        log::trace!("Discover sent (xid=0x{:x})", transaction_id);
    }

    /// Worker entry point.
    pub fn worker_loop(&self) -> ! {
        let mut receive_buffer = [0u8; DHCP_RECV_BUFFER_SIZE];

        loop {
            let _ = self.receive_and_process_one(&mut receive_buffer);
        }
    }

    /// Blocks for one incoming UDP datagram on port 68, parses it as a
    /// DHCP frame, and routes it to the matching session's Offer/Ack
    /// handler by the frame's client MAC.
    fn receive_and_process_one(&self, receive_buffer: &mut [u8]) -> Result<(), ()> {
        let socket = {
            let guard = self.udp_socket.lock();
            guard.ok_or(())?
        };

        let udp = kernel_ref().network_subsystem().udp();

        let (received_length, _sender_address, _sender_port) =
            udp.socket_recv_from(socket, receive_buffer)?;
        let fixed_len = size_of::<DhcpFixedHeader>();

        if received_length < fixed_len {
            return Ok(());
        }

        let (header, rest) = DhcpFixedHeader::read_from_prefix(&receive_buffer[..received_length])
            .map_err(|_| ())?;

        let options = DhcpOptionsParser::parse(rest);
        let message_type = DhcpOptionsParser::message_type(&options);
        let mac_address = header.client_mac_address();

        let session = {
            let sessions = self.sessions.lock();
            sessions.get(&mac_address).cloned()
        };

        let Some(session) = session else {
            log::trace!("Ignoring packet for unknown MAC {mac_address:?}");

            return Ok(());
        };

        // Process DHCP message based on the message type.
        match message_type {
            Some(DhcpMessageType::Offer) => self.handle_offer(&header, &options, &session)?,
            Some(DhcpMessageType::Ack) => self.handle_ack(&header, &options, &session)?,
            Some(other) => log::warn!("unhandled message type: {other:?}"),

            None => log::warn!("packet without MessageType option"),
        }

        Ok(())
    }

    /// Handles an incoming Offer: verifies it's actually a reply to our
    /// pending Discover, parses the proposed lease out of the options,
    /// advances the session to `Request`, and sends the Request accepting it.
    fn handle_offer(
        &self,
        header: &DhcpFixedHeader,
        options: &[DhcpOption<'_>],
        session: &DhcpSession,
    ) -> Result<(), ()> {
        // Offer is acceptable only after Discover (DORA flow).
        if session.last_message != DhcpMessageType::Discover {
            return Ok(());
        }

        // Transaction ids MUST match.
        if header.transaction_id() != session.transaction_id {
            return Ok(());
        }

        let lease = parse_lease_from_options(header, options);

        log::trace!(
            "DHCP Offer received: ip={} mask={} gateway={} xid={}",
            lease.internet_address,
            lease.subnet_mask,
            lease.default_gateway,
            header.transaction_id()
        );

        {
            let mut sessions = self.sessions.lock();

            // Put new lease offer into the DhcpSession.
            sessions.insert(
                session.mac_address,
                Arc::new(DhcpSession {
                    interface_id: session.interface_id,
                    mac_address: session.mac_address,
                    last_message: DhcpMessageType::Request,
                    transaction_id: session.transaction_id,
                    lease: Some(lease.clone()),
                    completion: session.completion.clone(),
                    acquisition_complete: session.acquisition_complete.clone(),
                    timer_spawned: session.timer_spawned.clone(),
                }),
            );
        }

        // Send request accepting the lease.
        self.send_request(
            session.mac_address,
            session.transaction_id,
            &lease,
            header.your_ip_addr,
            options,
        )
    }

    /// Handles an incoming Ack.
    fn handle_ack(
        &self,
        header: &DhcpFixedHeader,
        options: &[DhcpOption<'_>],
        session: &DhcpSession,
    ) -> Result<(), ()> {
        // ACK is acceptable only after Request (DORA flow).
        if session.last_message != DhcpMessageType::Request {
            log::trace!(
                "ignoring ACK for {:?} (expected Request, got {:?})",
                session.mac_address,
                session.last_message
            );

            return Ok(());
        }

        // Transaction ids MUST match.
        if header.transaction_id() != session.transaction_id {
            log::trace!(
                "ignoring ACK xid mismatch expected={} got={}",
                session.transaction_id,
                header.transaction_id()
            );

            return Ok(());
        }

        // Refresh lease fields with whatever the server repeated in ACK.
        // (Some servers send only a subset, so keep the session copy as baseline.)
        let mut lease = session.lease.clone().ok_or(())?;
        let ack_lease = parse_lease_from_options(header, options);
        lease.subnet_mask = ack_lease.subnet_mask;
        lease.default_gateway = ack_lease.default_gateway;
        lease.dns_servers = ack_lease.dns_servers;
        lease.lease_time_seconds = ack_lease.lease_time_seconds;
        lease.renewal_time_seconds = ack_lease.renewal_time_seconds;
        lease.rebinding_time_seconds = ack_lease.rebinding_time_seconds;
        lease.server_identifier = ack_lease.server_identifier.or(lease.server_identifier);

        {
            let mut sessions = self.sessions.lock();

            // Update lease in DhcpSession.
            sessions.insert(
                session.mac_address,
                Arc::new(DhcpSession {
                    interface_id: session.interface_id,
                    mac_address: session.mac_address,
                    last_message: DhcpMessageType::Ack,
                    transaction_id: session.transaction_id,
                    lease: Some(lease.clone()),
                    completion: session.completion.clone(),
                    acquisition_complete: session.acquisition_complete.clone(),
                    timer_spawned: session.timer_spawned.clone(),
                }),
            );
        }

        // Install routes based on the lease, and set IP address of the interface.
        self.install_routes(session.interface_id, &lease);
        self.update_interface_address(session.interface_id, lease.internet_address);

        // If we've got DNS server, try to configure the DNS resolver.
        if !lease.dns_servers.is_empty() {
            DnsResolver::configure(DnsResolverConfig {
                interface_id: session.interface_id,
                servers: lease.dns_servers.clone(),
            });
        }

        log::info!(
            "DHCP ACK received: ip={} mask={} gateway={} xid={}",
            lease.internet_address,
            lease.subnet_mask,
            lease.default_gateway,
            header.transaction_id()
        );

        if !session.acquisition_complete.swap(true, Ordering::AcqRel) {
            session.completion.open();
        }

        self.ensure_lease_timer(
            session.interface_id,
            session.mac_address,
            &lease,
            &session.timer_spawned,
        );

        Ok(())
    }

    /// Installs the routes an acquired lease implies: the local subnet
    /// as a direct route, a /32 host route for our own address, and the
    /// default route via the offered gateway.
    fn install_routes(&self, interface_id: NetworkInterfaceId, lease: &DhcpLease) {
        let network_subsystem = kernel_ref().network_subsystem();
        let mut routing_table = network_subsystem.routing_table().write();

        let prefix_length = u32::from(lease.subnet_mask).count_ones() as u8;
        let network = {
            let ip_u32: u32 = lease.internet_address.into();
            let mask_u32: u32 = lease.subnet_mask.into();

            Ipv4Addr::from(ip_u32 & mask_u32)
        };

        // local network
        routing_table.insert_for_interface(
            Ipv4Prefix::new(network, prefix_length),
            interface_id,
            NextHop::Direct,
        );

        // host route for the assigned address
        routing_table.insert_for_interface(
            Ipv4Prefix::new(lease.internet_address, 32),
            interface_id,
            NextHop::Direct,
        );

        // default gateway
        routing_table.insert_for_interface(
            Ipv4Prefix::new(Ipv4Addr::unspecified(), 0),
            interface_id,
            NextHop::Gateway(lease.default_gateway),
        );

        routing_table.print();
    }

    /// Refreshes T1/T2 in the session and spawns the lease timer thread
    /// for this interface.
    fn ensure_lease_timer(
        &self,
        interface_id: NetworkInterfaceId,
        mac_address: MacAddress,
        lease: &DhcpLease,
        timer_spawned: &Arc<AtomicBool>,
    ) {
        let lease_time = Duration::from_secs(lease.lease_time_seconds as u64);
        if lease_time.as_nanos() == 0 {
            return;
        }

        self.update_lease_timers(mac_address, lease);

        if timer_spawned.swap(true, Ordering::AcqRel) {
            return;
        }

        let arg = interface_id.0 as u64;
        kernel_ref()
            .spawn_kernel_thread(dhcp_lease_timer_worker, arg, 9)
            .unwrap();
    }

    /// Computes T1 (renewal) and T2 (rebinding) - from the server's
    /// values if it gave them (options 58/59), otherwise the RFC 2131
    /// §4.4.5 defaults of 50% and 87.5% of the lease time.
    fn update_lease_timers(&self, mac_address: MacAddress, lease: &DhcpLease) {
        let lease_secs = lease.lease_time_seconds as u64;

        let t1 = lease
            .renewal_time_seconds
            .map(|s| Duration::from_secs(s as u64))
            .unwrap_or(Duration::from_secs(core::cmp::max(1, lease_secs / 2)));

        let t2 = lease
            .rebinding_time_seconds
            .map(|s| Duration::from_secs(s as u64))
            .unwrap_or(Duration::from_secs(core::cmp::max(1, (lease_secs * 7) / 8)));

        let server_id = lease.server_identifier.unwrap_or(lease.default_gateway);

        let mut sessions = self.sessions.lock();
        if let Some(existing) = sessions.get(&mac_address).cloned() {
            let mut lease2 = existing.lease.clone().unwrap_or_else(|| lease.clone());
            lease2.renewal_time_seconds = Some((t1.as_nanos() / 1_000_000_000) as u32);
            lease2.rebinding_time_seconds = Some((t2.as_nanos() / 1_000_000_000) as u32);
            lease2.server_identifier = Some(server_id);

            sessions.insert(
                mac_address,
                Arc::new(DhcpSession {
                    interface_id: existing.interface_id,
                    mac_address: existing.mac_address,
                    last_message: existing.last_message,
                    transaction_id: existing.transaction_id,
                    lease: Some(lease2),
                    completion: existing.completion.clone(),
                    acquisition_complete: existing.acquisition_complete.clone(),
                    timer_spawned: existing.timer_spawned.clone(),
                }),
            );
        }
    }

    /// Applies the acquired address to the interface and wakes anything
    /// waiting on an interface address becoming available.
    fn update_interface_address(
        &self,
        interface_id: NetworkInterfaceId,
        internet_address: Ipv4Addr,
    ) {
        kernel_ref()
            .network_subsystem()
            .interfaces()
            .update(interface_id, |interface| {
                interface.local_internet_address = Some(internet_address);
            });

        kernel_ref()
            .network_subsystem()
            .notify_interface_address_ready();
    }

    /// Builds and broadcasts the initial Discover.
    fn send_discover(&self, mac_address: MacAddress, transaction_id: u32) -> Result<(), ()> {
        let ip_addr = Ipv4Addr::unspecified().octets();

        let mut header = DhcpFrameHeader {
            operation: OP_BOOTREQUEST,
            hardware_type: HTYPE_ETHERNET,
            hardware_address_length: HLEN_MAC,
            hops: 0,
            xid: U32::new(transaction_id),
            seconds: U16::new(0),
            flags: U16::new(0x8000),
            client_ip_addr: ip_addr,
            your_ip_addr: ip_addr,
            next_server_ip: ip_addr,
            relay_agent_ip: ip_addr,
            hardware_address: mac_address.0,
            hardware_address_padding: [0; 10],
            host_name: [0; 64],
            file_name: [0; 128],
            options: [0; 312],
        };

        let mut writer = DhcpOptionsWriter::new(&mut header.options);

        writer.add_option(
            DhcpOptionCode::MessageType,
            &[DhcpMessageType::Discover as u8],
        );

        let mut client_identifier = [0u8; 7];
        client_identifier[0] = HTYPE_ETHERNET;
        client_identifier[1..7].copy_from_slice(&mac_address.0);
        writer.add_option(DhcpOptionCode::ClientIdentifier, &client_identifier);

        // Ask for subnet mask, default gateway, dns and domain name.
        writer.add_option(
            DhcpOptionCode::ParameterRequestList,
            &[
                DhcpOptionCode::SubnetMask as u8,
                DhcpOptionCode::Router as u8,
                DhcpOptionCode::DnsServer as u8,
                DhcpOptionCode::DomainName as u8,
            ],
        );

        writer.finish();

        self.send_udp_broadcast(header.as_bytes())
    }

    /// Builds and broadcasts a Request accepting an Offer.
    fn send_request(
        &self,
        mac_address: MacAddress,
        transaction_id: u32,
        lease: &DhcpLease,
        offered_ip_addr: [u8; 4],
        offer_options: &[DhcpOption<'_>],
    ) -> Result<(), ()> {
        log::trace!(
            "Request prepare xid={} offered_ip={} server/options_cnt={}",
            transaction_id,
            Ipv4Addr::new(offered_ip_addr),
            offer_options.len()
        );

        let server_identifier = offer_options
            .iter()
            .find(|option| option.code == DhcpOptionCode::ServerIdentifier)
            .and_then(|option| option.data.get(0..4))
            .map(|octets| Ipv4Addr::new(octets.try_into().unwrap()))
            .unwrap_or(lease.default_gateway);

        let ip_addr = Ipv4Addr::unspecified().octets();

        let mut header = DhcpFrameHeader {
            operation: OP_BOOTREQUEST,
            hardware_type: HTYPE_ETHERNET,
            hardware_address_length: HLEN_MAC,
            hops: 0,
            xid: U32::new(transaction_id),
            seconds: U16::new(0),
            flags: U16::new(0x8000),
            client_ip_addr: ip_addr,
            your_ip_addr: offered_ip_addr,
            next_server_ip: ip_addr,
            relay_agent_ip: ip_addr,
            hardware_address: mac_address.0,
            hardware_address_padding: [0; 10],
            host_name: [0; 64],
            file_name: [0; 128],
            options: [0; 312],
        };

        let mut writer = DhcpOptionsWriter::new(&mut header.options);

        writer.add_option(
            DhcpOptionCode::MessageType,
            &[DhcpMessageType::Request as u8],
        );

        let mut client_identifier = [0u8; 7];
        client_identifier[0] = HTYPE_ETHERNET;
        client_identifier[1..7].copy_from_slice(&mac_address.0);
        writer.add_option(DhcpOptionCode::ClientIdentifier, &client_identifier);

        writer.add_option(
            DhcpOptionCode::RequestedIpAddress,
            &lease.internet_address.octets(),
        );

        writer.add_option(
            DhcpOptionCode::ServerIdentifier,
            &server_identifier.octets(),
        );

        writer.add_option(
            DhcpOptionCode::ParameterRequestList,
            &[
                DhcpOptionCode::SubnetMask as u8,
                DhcpOptionCode::Router as u8,
                DhcpOptionCode::DnsServer as u8,
                DhcpOptionCode::DomainName as u8,
            ],
        );

        writer.finish();

        self.send_udp_broadcast(header.as_bytes())
    }

    /// Builds and unicasts a renewal Request at T1: addressed directly
    /// to the known server, with `client_ip_addr` filled in since we
    /// already have a valid lease.
    fn send_renew_request(
        &self,
        mac_address: MacAddress,
        transaction_id: u32,
        lease: &DhcpLease,
        server_identifier: Ipv4Addr,
    ) -> Result<(), ()> {
        let ip_addr = Ipv4Addr::unspecified().octets();

        let mut header = DhcpFrameHeader {
            operation: OP_BOOTREQUEST,
            hardware_type: HTYPE_ETHERNET,
            hardware_address_length: HLEN_MAC,
            hops: 0,
            xid: U32::new(transaction_id),
            seconds: U16::new(0),
            flags: U16::new(0),
            client_ip_addr: lease.internet_address.octets(),
            your_ip_addr: ip_addr,
            next_server_ip: ip_addr,
            relay_agent_ip: ip_addr,
            hardware_address: mac_address.0,
            hardware_address_padding: [0; 10],
            host_name: [0; 64],
            file_name: [0; 128],
            options: [0; 312],
        };

        let mut writer = DhcpOptionsWriter::new(&mut header.options);
        writer.add_option(
            DhcpOptionCode::MessageType,
            &[DhcpMessageType::Request as u8],
        );

        writer.add_option(
            DhcpOptionCode::ServerIdentifier,
            &server_identifier.octets(),
        );

        let mut client_identifier = [0u8; 7];
        client_identifier[0] = HTYPE_ETHERNET;
        client_identifier[1..7].copy_from_slice(&mac_address.0);
        writer.add_option(DhcpOptionCode::ClientIdentifier, &client_identifier);

        writer.finish();

        let socket = self.udp_socket.lock().ok_or(())?;
        let udp = kernel_ref().network_subsystem().udp();

        // Renew is normally unicast to the server.
        udp.socket_send_to(
            socket,
            header.as_bytes(),
            server_identifier,
            DHCP_SERVER_PORT,
        )?;

        Ok(())
    }

    /// Builds and broadcasts a rebind Request at T2 - used when T1's
    /// unicast renewal didn't get a response, so we fall back to asking
    /// any server on the network.
    fn send_rebind_request(
        &self,
        mac_address: MacAddress,
        transaction_id: u32,
        lease: &DhcpLease,
    ) -> Result<(), ()> {
        let ip_addr = Ipv4Addr::unspecified().octets();
        let mut header = DhcpFrameHeader {
            operation: OP_BOOTREQUEST,
            hardware_type: HTYPE_ETHERNET,
            hardware_address_length: HLEN_MAC,
            hops: 0,
            xid: U32::new(transaction_id),
            seconds: U16::new(0),
            flags: U16::new(0x8000),
            client_ip_addr: lease.internet_address.octets(),
            your_ip_addr: ip_addr,
            next_server_ip: ip_addr,
            relay_agent_ip: ip_addr,
            hardware_address: mac_address.0,
            hardware_address_padding: [0; 10],
            host_name: [0; 64],
            file_name: [0; 128],
            options: [0; 312],
        };

        let mut writer = DhcpOptionsWriter::new(&mut header.options);
        writer.add_option(
            DhcpOptionCode::MessageType,
            &[DhcpMessageType::Request as u8],
        );

        let mut client_identifier = [0u8; 7];
        client_identifier[0] = HTYPE_ETHERNET;
        client_identifier[1..7].copy_from_slice(&mac_address.0);
        writer.add_option(DhcpOptionCode::ClientIdentifier, &client_identifier);

        writer.finish();

        self.send_udp_broadcast(header.as_bytes())
    }

    /// Sends a DHCP frame as a broadcast to the standard server port (67).
    fn send_udp_broadcast(&self, payload: &[u8]) -> Result<(), ()> {
        let socket = self.udp_socket.lock().ok_or(())?;
        let udp = kernel_ref().network_subsystem().udp();

        udp.socket_send_to(socket, payload, Ipv4Addr::broadcast(), DHCP_SERVER_PORT)?;

        Ok(())
    }
}

/// Extracts a [`DhcpLease`] from a parsed option list.
fn parse_lease_from_options(header: &DhcpFixedHeader, options: &[DhcpOption<'_>]) -> DhcpLease {
    let mut subnet_mask = Ipv4Addr::new([255, 255, 255, 0]);
    let mut default_gateway = Ipv4Addr::new([0, 0, 0, 0]);
    let mut dns_servers = Vec::new();
    let mut lease_time_seconds = 3600u32;
    let mut renewal_time_seconds: Option<u32> = None;
    let mut rebinding_time_seconds: Option<u32> = None;
    let mut server_identifier: Option<Ipv4Addr> = None;

    for option in options {
        match option.code {
            DhcpOptionCode::SubnetMask if option.data.len() >= 4 => {
                subnet_mask = Ipv4Addr::from(<[u8; 4]>::try_from(&option.data[0..4]).unwrap());
            }
            DhcpOptionCode::Router if option.data.len() >= 4 => {
                default_gateway = Ipv4Addr::from(<[u8; 4]>::try_from(&option.data[0..4]).unwrap());
            }
            DhcpOptionCode::DnsServer => {
                dns_servers = option
                    .data
                    .as_chunks::<4>()
                    .0
                    .iter()
                    .map(|chunk| Ipv4Addr::from(*chunk))
                    .collect();
            }
            DhcpOptionCode::IpAddressLeaseTime if option.data.len() >= 4 => {
                lease_time_seconds = u32::from_be_bytes(option.data[0..4].try_into().unwrap());
            }
            DhcpOptionCode::RenewalTimeValue if option.data.len() >= 4 => {
                renewal_time_seconds =
                    Some(u32::from_be_bytes(option.data[0..4].try_into().unwrap()));
            }
            DhcpOptionCode::RebindingTimeValue if option.data.len() >= 4 => {
                rebinding_time_seconds =
                    Some(u32::from_be_bytes(option.data[0..4].try_into().unwrap()));
            }
            DhcpOptionCode::ServerIdentifier if option.data.len() >= 4 => {
                server_identifier = Some(Ipv4Addr::from(
                    <[u8; 4]>::try_from(&option.data[0..4]).unwrap(),
                ));
            }
            _ => {}
        }
    }

    DhcpLease {
        internet_address: header.offered_internet_address(),
        subnet_mask,
        default_gateway,
        dns_servers,
        lease_time_seconds,
        renewal_time_seconds,
        rebinding_time_seconds,
        server_identifier,
    }
}

/// Per-lease background timer: sleeps until T1 and sends a unicast
/// renewal, then (relative) until T2 and sends a broadcast rebind, then
/// sleeps out the rest of the lease before looping to do it all again.
extern "C" fn dhcp_lease_timer_worker(arg: u64) -> ! {
    let interface_id = NetworkInterfaceId(arg as u16);

    loop {
        let dhcp = kernel_ref().network_subsystem().dhcp();
        let sessions = dhcp.sessions.lock();

        let session = sessions
            .values()
            .find(|s| s.interface_id == interface_id)
            .cloned();
        drop(sessions);

        let Some(session) = session else {
            yield_to_scheduler();
            continue;
        };

        let Some(lease) = session.lease.clone() else {
            yield_to_scheduler();
            continue;
        };

        let lease_time = Duration::from_secs(lease.lease_time_seconds as u64);
        let lease_secs = lease.lease_time_seconds as u64;
        let t1 = lease
            .renewal_time_seconds
            .map(|s| Duration::from_secs(s as u64))
            .unwrap_or(Duration::from_secs(core::cmp::max(1, lease_secs / 2)));
        let t2 = lease
            .rebinding_time_seconds
            .map(|s| Duration::from_secs(s as u64))
            .unwrap_or(Duration::from_secs(core::cmp::max(1, (lease_secs * 7) / 8)));

        current_thread().sleep(t1);
        yield_to_scheduler();

        // Issue a renew request (unicast to server id if known).
        let server_id = lease.server_identifier.unwrap_or(lease.default_gateway);
        let xid = dhcp.xid_counter.fetch_add(1, Ordering::Relaxed);

        // Put session into "Request" state for the new xid so ACK will be accepted.
        {
            let mut sessions = dhcp.sessions.lock();
            sessions.insert(
                session.mac_address,
                Arc::new(DhcpSession {
                    interface_id,
                    mac_address: session.mac_address,
                    last_message: DhcpMessageType::Request,
                    transaction_id: xid,
                    lease: Some(lease.clone()),
                    completion: session.completion.clone(),
                    acquisition_complete: session.acquisition_complete.clone(),
                    timer_spawned: session.timer_spawned.clone(),
                }),
            );
        }

        let _ = dhcp.send_renew_request(session.mac_address, xid, &lease, server_id);

        // Sleep to T2 (relative).
        if t2.as_nanos() > t1.as_nanos() {
            current_thread().sleep(Duration::from_nanos(t2.as_nanos() - t1.as_nanos()));
            yield_to_scheduler();
        }

        // Rebind (broadcast) if still no ACK refreshed.
        let xid2 = dhcp.xid_counter.fetch_add(1, Ordering::Relaxed);
        {
            let mut sessions = dhcp.sessions.lock();
            sessions.insert(
                session.mac_address,
                Arc::new(DhcpSession {
                    interface_id,
                    mac_address: session.mac_address,
                    last_message: DhcpMessageType::Request,
                    transaction_id: xid2,
                    lease: Some(lease.clone()),
                    completion: session.completion.clone(),
                    acquisition_complete: session.acquisition_complete.clone(),
                    timer_spawned: session.timer_spawned.clone(),
                }),
            );
        }
        let _ = dhcp.send_rebind_request(session.mac_address, xid2, &lease);

        // Wait until expiration before looping.
        if lease_time.as_nanos() > t2.as_nanos() {
            current_thread().sleep(Duration::from_nanos(lease_time.as_nanos() - t2.as_nanos()));
        }

        yield_to_scheduler();
    }
}

/// Kernel thread entry point.
extern "C" fn dhcp_worker(_arg: u64) -> ! {
    let dhcp = kernel_ref().network_subsystem().dhcp();
    dhcp.begin_discovery_for_all_nics();
    dhcp.worker_loop();
}
