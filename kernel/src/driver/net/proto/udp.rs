//! # UDP (User Datagram Protocol) Subsystem
//!
//! This module implements the User Datagram Protocol (UDP) as defined in RFC 768.
//! UDP provides a connectionless, unreliable datagram service used for applications
//! where low latency is preferred over error recovery (e.g., DNS, DHCP, VoIP).
//!
//! The socket part will be deleted once VFS Socket object will be merged into the
//! baseline.
//!

use alloc::{
    collections::{BTreeMap, VecDeque},
    sync::Arc,
    vec::Vec,
};
use core::sync::atomic::{AtomicBool, Ordering};

use x86_64::instructions::interrupts::without_interrupts;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, network_endian::U16};

use crate::{
    driver::net::{
        Ipv4Addr, Socket,
        proto::{DEFAULT_HEADER_RESERVE, PacketBuffer, SLOT_SIZE, ip::IpProtocol},
    },
    kernel::kernel_ref,
    subsystem::{
        scheduler::{Event, current_thread, yield_to_scheduler},
        sync::{IrqGuardedMutex, IrqGuardedRwLock},
    },
};

/// # UDP Datagram Header
///
/// This structure represents the standard 8-byte UDP header as defined in RFC 768.
///
/// ### Memory Layout
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |          Source Port          |       Destination Port        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |             Length            |           Checksum            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
#[repr(C, packed)]
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Debug, Copy, Clone)]
pub struct UdpDatagramHeader {
    /// Port number of the sender.
    pub source_port: U16,

    /// Port number of the receiver.
    pub destination_port: U16,

    /// The length in octets of this user datagram, including this header and the data.
    pub length: U16,

    /// The 16-bit one's complement of the one's complement sum of a pseudo header
    /// of information from the IP header, the UDP header, and the data.
    pub checksum: U16,
}

impl UdpDatagramHeader {
    /// Returns the source port number.
    pub fn source_port(&self) -> u16 {
        self.source_port.get()
    }

    /// Returns the destination port number.
    pub fn destination_port(&self) -> u16 {
        self.destination_port.get()
    }
}

/// Responsible for coordinating the reception and dispatch of UDP datagrams.
pub struct UdpDriver {
    socket_table: IrqGuardedRwLock<SocketTable>,
}

impl UdpDriver {
    /// Computes the UDP checksum (RFC 768) over the IPv4 pseudo-header
    /// plus the UDP header and payload, with the checksum field itself
    /// treated as zero while summing.
    fn calculate_udp_checksum(
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        protocol: IpProtocol,
        udp_len: u16,
        header_and_data: &[u8],
    ) -> u16 {
        // IPv4 pseudo-header for UDP checksum:
        //   - src addr (32)
        //   - dst addr (32)
        //   - zero (8)
        //   - protocol (8)
        //   - UDP length (16)
        //
        // Then checksum over UDP header+data with checksum field set to 0.
        let mut sum: u32 = 0;

        let src = src_ip.octets();
        let dst = dst_ip.octets();

        let mut add_u16_be = |hi: u8, lo: u8| {
            let word = u16::from_be_bytes([hi, lo]) as u32;
            sum = sum.wrapping_add(word);
        };

        // src addr: 2x u16
        add_u16_be(src[0], src[1]);
        add_u16_be(src[2], src[3]);
        // dst addr: 2x u16
        add_u16_be(dst[0], dst[1]);
        add_u16_be(dst[2], dst[3]);

        // zero + protocol
        let proto = protocol as u8 as u16; // IpProtocol::Udp = 17
        add_u16_be(0x00, proto as u8);

        // UDP length
        sum = sum.wrapping_add(udp_len as u32);

        // UDP header + data (treat as big-endian 16-bit words)
        let mut i = 0usize;
        while i + 1 < header_and_data.len() {
            let word = u16::from_be_bytes([header_and_data[i], header_and_data[i + 1]]) as u32;
            sum = sum.wrapping_add(word);
            i += 2;
        }

        if i < header_and_data.len() {
            // Odd trailing byte: pad with 0 as the low byte.
            let word = u16::from_be_bytes([header_and_data[i], 0]) as u32;
            sum = sum.wrapping_add(word);
        }

        // Fold carries
        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        let mut result = !(sum as u16);

        // Per RFC768: if computed checksum is 0x0000, transmit as 0xFFFF.
        if result == 0 {
            result = 0xFFFF;
        }

        result
    }

    /// Initializes UDP driver
    pub fn new() -> Self {
        Self {
            socket_table: IrqGuardedRwLock::new(SocketTable::new()),
        }
    }

    /// Constructs and sends a UDP datagram using a fully-specified
    /// [`Socket`].
    pub fn send_datagram(&self, socket: Socket, data: &[u8]) {
        let network_subsystem = kernel_ref().network_subsystem();

        let mut storage = [0u8; DEFAULT_HEADER_RESERVE + SLOT_SIZE];
        let mut packet_buffer = PacketBuffer::for_transmit(&mut storage, DEFAULT_HEADER_RESERVE);

        let header = UdpDatagramHeader {
            source_port: U16::new(socket.local_port),
            destination_port: U16::new(socket.remote_port),
            length: U16::new(data.len() as u16 + 8),
            checksum: U16::ZERO,
        };

        packet_buffer.append_data(data);
        packet_buffer.prepend_header(&header);

        let src_ip = network_subsystem
            .interfaces()
            .get(socket.nic)
            .and_then(|iface| iface.local_internet_address)
            .unwrap_or(Ipv4Addr::unspecified());

        let udp_len = header.length.get();
        let checksum = Self::calculate_udp_checksum(
            src_ip,
            socket.remote_address,
            IpProtocol::Udp,
            udp_len,
            packet_buffer.payload(),
        );

        // Write checksum into the UDP header (offset 6..8).
        // After `prepend_header`, `payload()` contains the whole UDP datagram.
        packet_buffer.payload_mut()[6..8].copy_from_slice(&checksum.to_be_bytes());

        let _ = network_subsystem.ipv4().send_packet(
            IpProtocol::Udp,
            &mut packet_buffer,
            socket.remote_address,
            socket.nic,
            0,
        );
    }

    /// Processes an inbound UDP datagram and dispatches it to the appropriate application driver.
    pub fn process_data(&self, sender_ip: Ipv4Addr, buffer: &mut PacketBuffer) -> Result<(), ()> {
        let header = buffer
            .consume_header::<UdpDatagramHeader>()
            .map_err(|_| ())?;

        let (src_port, dst_port) = (header.source_port(), header.destination_port());

        self.dispatch_to_socket(dst_port, sender_ip, src_port, buffer.payload());

        Ok(())
    }
}

/// Opaque handle identifying a kernel-mode UDP socket.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct UdpSocketHandle(u32);

/// One received datagram, queued in a socket's [`UdpRecvBuffer`] until
/// the application calls `recv`/`recv_from`.
pub struct ReceivedDatagram {
    pub src_addr: Ipv4Addr,
    pub src_port: u16,
    pub data: Vec<u8>,
}

/// A bounded queue of received datagrams plus the wakeup a blocking
/// `recv_from` waits on.
pub struct UdpRecvBuffer {
    queue: IrqGuardedMutex<VecDeque<ReceivedDatagram>>,
    wake: Event,
    capacity: usize,
    closed: AtomicBool,
}

impl UdpRecvBuffer {
    pub fn new(capacity: usize) -> Self {
        Self {
            queue: IrqGuardedMutex::new(VecDeque::with_capacity(capacity)),
            wake: Event::new(),
            capacity,
            closed: AtomicBool::new(false),
        }
    }

    pub fn wake(&self) -> &Event {
        &self.wake
    }

    /// Enqueues one datagram and wakes recv waiters.
    pub fn push(&self, dgram: ReceivedDatagram) -> Result<(), ()> {
        without_interrupts(|| {
            let mut queue = self.queue.lock();

            if queue.len() >= self.capacity {
                return Err(());
            }

            queue.push_back(dgram);

            Ok(())
        })?;

        self.wake.notify();

        Ok(())
    }

    pub fn try_pop(&self) -> Option<ReceivedDatagram> {
        without_interrupts(|| self.queue.lock().pop_front())
    }

    /// Marks the buffer closed and wakes anything blocked on it.
    pub fn close(&self) {
        self.closed.store(true, Ordering::Release);

        self.wake.notify();
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }
}

/// Every UDP socket on this kernel instance.
pub struct SocketTable {
    sockets: BTreeMap<u16, Arc<IrqGuardedMutex<UdpSocketState>>>,
    bound_ports: BTreeMap<u16, UdpSocketHandle>,
    next_ephemeral: u16,
}

impl SocketTable {
    pub fn new() -> Self {
        Self {
            sockets: BTreeMap::new(),
            bound_ports: BTreeMap::new(),
            next_ephemeral: 49152, // IANA dynamic/private range start
        }
    }

    /// Registers a freshly created, not-yet-bound socket and hands back
    /// a handle for it.
    pub fn insert_unbound(
        &mut self,
        sock: Arc<IrqGuardedMutex<UdpSocketState>>,
    ) -> UdpSocketHandle {
        let mut handle = 1u16;

        while self.sockets.contains_key(&handle) {
            handle = handle.wrapping_add(1);

            if handle == 0 {
                handle = 1;
            }
        }

        self.sockets.insert(handle, sock);

        UdpSocketHandle(handle as u32)
    }

    pub fn get(&self, handle: UdpSocketHandle) -> Result<Arc<IrqGuardedMutex<UdpSocketState>>, ()> {
        let key = handle.0 as u16;

        self.sockets.get(&key).cloned().ok_or(())
    }

    pub fn get_mut(
        &mut self,
        handle: UdpSocketHandle,
    ) -> Result<Arc<IrqGuardedMutex<UdpSocketState>>, ()> {
        self.get(handle)
    }

    /// Removes a socket and releases whatever port it held, if any.
    pub fn remove(
        &mut self,
        handle: UdpSocketHandle,
    ) -> Result<Arc<IrqGuardedMutex<UdpSocketState>>, ()> {
        let key = handle.0 as u16;
        let sock = self.sockets.remove(&key).ok_or(())?;
        let port = sock.lock().local_port;
        if port != 0 {
            self.bound_ports.remove(&port);
        }

        Ok(sock)
    }

    pub fn port_in_use(&self, port: u16) -> bool {
        self.bound_ports.contains_key(&port)
    }

    pub fn register_port(&mut self, port: u16, handle: UdpSocketHandle) {
        self.bound_ports.insert(port, handle);
    }

    pub fn unregister_port(&mut self, port: u16) {
        self.bound_ports.remove(&port);
    }

    pub fn get_port(&self, handle: UdpSocketHandle) -> Result<u16, ()> {
        let sock = self.get(handle)?;
        Ok(sock.lock().local_port)
    }

    /// Picks the next free port in the dynamic/private range
    /// (49152–65535, RFC 6335).
    pub fn alloc_ephemeral(&mut self) -> Result<u16, ()> {
        for _ in 0..(u16::MAX - 49152) {
            let port = self.next_ephemeral;
            self.next_ephemeral = self.next_ephemeral.wrapping_add(1);
            if self.next_ephemeral < 49152 {
                self.next_ephemeral = 49152;
            }

            if !self.port_in_use(port) {
                return Ok(port);
            }
        }

        Err(())
    }

    pub fn find_by_port(&self, port: u16) -> Option<Arc<IrqGuardedMutex<UdpSocketState>>> {
        let handle = self.bound_ports.get(&port)?;
        self.sockets.get(&(handle.0 as u16)).cloned()
    }
}

/// One UDP socket's state.
pub struct UdpSocketState {
    pub local_port: u16,
    pub remote_addr: Option<(Ipv4Addr, u16)>,
    pub recv_buf: UdpRecvBuffer,
}

/// Per-socket options.
#[derive(Clone)]
pub struct SocketOpts {
    pub recv_buf_size: usize, // SO_RCVBUF
}

impl UdpDriver {
    /// Creates a new, unbound UDP socket with a 4096-datagram receive
    /// buffer, and returns its handle.
    pub fn socket_create(&self) -> UdpSocketHandle {
        let state = UdpSocketState {
            local_port: 0,
            remote_addr: None,
            recv_buf: UdpRecvBuffer::new(4096),
        };

        self.socket_table
            .write()
            .insert_unbound(Arc::new(IrqGuardedMutex::new(state)))
    }

    /// Binds a socket to a local port. `port == 0` picks an ephemeral one.
    pub fn socket_bind(&self, handle: UdpSocketHandle, port: u16) -> Result<(), ()> {
        let mut table = self.socket_table.write();

        let port = if port == 0 {
            table.alloc_ephemeral()?
        } else if table.port_in_use(port) {
            return Err(());
        } else {
            port
        };

        let sock = table.get_mut(handle)?;
        sock.lock().local_port = port;
        table.register_port(port, handle);

        Ok(())
    }

    /// Blocking receive: returns the next queued datagram's data or blocks
    /// until one arrives.
    pub fn socket_recv_from(
        &self,
        handle: UdpSocketHandle,
        buf: &mut [u8],
    ) -> Result<(usize, Ipv4Addr, u16), ()> {
        let sock = self.socket_table.read().get(handle)?.clone();

        loop {
            if let Some(dgram) = sock.lock().recv_buf.try_pop() {
                let n = dgram.data.len().min(buf.len());
                buf[..n].copy_from_slice(&dgram.data[..n]);

                return Ok((n, dgram.src_addr, dgram.src_port));
            }

            if sock.lock().recv_buf.is_closed() {
                return Err(());
            }

            let wake = sock.lock().recv_buf.wake().clone();
            wake.wait_on(&current_thread());
            yield_to_scheduler();
        }
    }

    pub fn socket_connect(
        &self,
        handle: UdpSocketHandle,
        remote_addr: Ipv4Addr,
        remote_port: u16,
    ) -> Result<(), ()> {
        let mut table = self.socket_table.write();
        let sock = table.get_mut(handle)?;
        let mut s = sock.lock();

        if s.local_port == 0 {
            s.local_port = table.alloc_ephemeral()?;
            table.register_port(s.local_port, handle);
        }

        s.remote_addr = Some((remote_addr, remote_port));
        Ok(())
    }

    /// Sends to the socket's "connected" remote address.
    pub fn socket_send(&self, handle: UdpSocketHandle, data: &[u8]) -> Result<usize, ()> {
        let (local_port, remote_addr, remote_port) = {
            let table = self.socket_table.read();
            let sock = table.get(handle)?;
            let guard = sock.lock();
            let (remote_addr, remote_port) = guard.remote_addr.ok_or(())?;
            (guard.local_port, remote_addr, remote_port)
        };

        self.do_send(local_port, remote_addr, remote_port, data)
    }

    /// Sends one datagram to an explicit destination.
    pub fn socket_send_to(
        &self,
        handle: UdpSocketHandle,
        data: &[u8],
        remote_addr: Ipv4Addr,
        remote_port: u16,
    ) -> Result<usize, ()> {
        let local_port = {
            let table = self.socket_table.read();
            let sock = table.get(handle)?;
            sock.lock().local_port
        };

        if local_port == 0 {
            return Err(());
        }

        self.do_send(local_port, remote_addr, remote_port, data)
    }

    /// Builds and sends one UDP datagram from `local_port` to
    /// `remote_addr:remote_port`.
    fn do_send(
        &self,
        local_port: u16,
        remote_addr: Ipv4Addr,
        remote_port: u16,
        data: &[u8],
    ) -> Result<usize, ()> {
        let network_subsystem = kernel_ref().network_subsystem();

        let mut storage = [0u8; DEFAULT_HEADER_RESERVE + SLOT_SIZE];
        let mut packet_buffer = PacketBuffer::for_transmit(&mut storage, DEFAULT_HEADER_RESERVE);

        let header = UdpDatagramHeader {
            source_port: U16::new(local_port),
            destination_port: U16::new(remote_port),
            length: U16::new(data.len() as u16 + 8),
            checksum: U16::ZERO,
        };

        packet_buffer.append_data(data);
        packet_buffer.prepend_header(&header);

        let src_ip = network_subsystem
            .interfaces()
            .get(crate::driver::net::NetworkInterfaceId(0))
            .and_then(|iface| iface.local_internet_address)
            .unwrap_or(Ipv4Addr::unspecified());

        let udp_len = header.length.get();
        let checksum = Self::calculate_udp_checksum(
            src_ip,
            remote_addr,
            IpProtocol::Udp,
            udp_len,
            packet_buffer.payload(),
        );

        packet_buffer.payload_mut()[6..8].copy_from_slice(&checksum.to_be_bytes());

        // TODO: choose NIC based on routing table
        let _ = network_subsystem.ipv4().send_packet(
            IpProtocol::Udp,
            &mut packet_buffer,
            remote_addr,
            crate::driver::net::NetworkInterfaceId(0),
            0,
        );

        Ok(data.len())
    }

    pub fn socket_close(&self, handle: UdpSocketHandle) {
        let mut table = self.socket_table.write();
        if let Ok(port) = table.get_port(handle) {
            table.unregister_port(port);
        }

        if let Ok(sock) = table.remove(handle) {
            sock.lock().recv_buf.close();
        }
    }

    /// Routes an inbound datagram to whichever socket is bound to
    /// `dst_port`, if any.
    fn dispatch_to_socket(&self, dst_port: u16, src_addr: Ipv4Addr, src_port: u16, payload: &[u8]) {
        let sock = {
            let table = self.socket_table.read();
            table.find_by_port(dst_port)
        };

        let Some(sock) = sock else {
            trace!("UDP: no listener on port {}", dst_port);
            return;
        };

        let dgram = ReceivedDatagram {
            src_addr,
            src_port,
            data: payload.to_vec(),
        };

        if sock.lock().recv_buf.push(dgram).is_err() {
            log::warn!("UDP: recv queue full on port {}", dst_port);
        }
    }
}
