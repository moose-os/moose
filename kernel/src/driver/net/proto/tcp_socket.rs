//! Kernel-mode TCP socket layer.
//!
//! # Deprecated
//!
//! It is left as-is only for the testing purposes; when the VFS will be
//! ready for creating Socket objects and performing operations on them,
//! this file will be deleted.

use alloc::{
    collections::{BTreeMap, VecDeque},
    sync::Arc,
};
use core::fmt;

use super::tcp::{TcpControlBlock, TcpDriver, TcpError, TcpSessionSettings};
use crate::{
    driver::net::{Ipv4Addr, NetworkInterfaceId},
    kernel::kernel_ref,
    subsystem::{
        scheduler::OneshotGate,
        sync::{IrqGuardedMutex, IrqGuardedRwLock},
    },
};

/// Opaque handle identifying a kernel-mode TCP socket - index
/// into [`TcpSocketTable`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TcpSocketHandle(u32);

/// Socket API errors.
#[derive(Debug, Clone, Copy)]
pub enum TcpSocketError {
    /// The handle doesn't refer to any socket.
    InvalidHandle,

    /// Operation needs a bound (or listening/connected) socket, but this one is `Unbound`.
    NotBound,

    /// The requested local port is already bound or listened on.
    AddrInUse,

    /// Operation needs a listening socket, but this one isn't listening.
    NotListening,

    /// Operation needs a connected socket, but this one isn't connected.
    NotConnected,

    /// A listener's pending-connection queue is full.
    BacklogFull,

    /// The socket has already been closed.
    Closed,

    /// The socket is already connected (or listening) and can't be
    /// connected/bound again.
    AlreadyConnected,

    /// A lower-level TCP error.
    Io(TcpError),
}

impl From<TcpError> for TcpSocketError {
    fn from(err: TcpError) -> Self {
        Self::Io(err)
    }
}

impl fmt::Display for TcpSocketError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidHandle => write!(f, "invalid TCP socket handle"),
            Self::NotBound => write!(f, "socket is not bound"),
            Self::AddrInUse => write!(f, "address already in use"),
            Self::NotListening => write!(f, "socket is not listening"),
            Self::NotConnected => write!(f, "socket is not connected"),
            Self::BacklogFull => write!(f, "listen backlog is full"),
            Self::Closed => write!(f, "socket is closed"),
            Self::AlreadyConnected => write!(f, "socket is already connected"),
            Self::Io(err) => write!(f, "tcp io error: {:?}", err),
        }
    }
}

/// Which half of a connection [`TcpDriver::socket_shutdown`] should
/// close.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Shutdown {
    Read,
    Write,
    Both,
}

/// What a socket currently is.
pub(crate) enum TcpSocketRole {
    Unbound,
    Bound {
        local_ip: Ipv4Addr,
        local_port: u16,
        nic: NetworkInterfaceId,
    },
    Listener {
        local_ip: Ipv4Addr,
        local_port: u16,
        nic: NetworkInterfaceId,
        backlog: usize,
        pending: VecDeque<Arc<IrqGuardedRwLock<TcpControlBlock>>>,
        gate: Arc<OneshotGate>,
    },
    Connected {
        tcb: Arc<IrqGuardedRwLock<TcpControlBlock>>,
    },
    Closed,
}

/// A socket's role plus the options.
pub(crate) struct TcpSocketState {
    role: TcpSocketRole,
    pub(crate) opts: TcpSessionSettings,
}

/// All sockets for this kernel instance, keyed by handle.
pub(crate) struct TcpSocketTable {
    /// Socket table.
    sockets: BTreeMap<u32, Arc<IrqGuardedMutex<TcpSocketState>>>,

    /// port -> listener handle map
    listeners: BTreeMap<u16, TcpSocketHandle>,
    /// port -> handle for bound-but-not-yet-listening sockets
    bound_ports: BTreeMap<u16, TcpSocketHandle>,

    /// Next handle number
    next_handle: u32,
}

impl TcpSocketTable {
    pub fn new() -> Self {
        Self {
            sockets: BTreeMap::new(),
            listeners: BTreeMap::new(),
            bound_ports: BTreeMap::new(),
            next_handle: 1,
        }
    }

    /// Hands out the next handle.
    fn alloc_handle(&mut self) -> TcpSocketHandle {
        let h = TcpSocketHandle(self.next_handle);

        self.next_handle = self.next_handle.wrapping_add(1).max(1);

        h
    }

    pub(crate) fn insert(&mut self, state: TcpSocketState) -> TcpSocketHandle {
        let h = self.alloc_handle();

        self.sockets
            .insert(h.0, Arc::new(IrqGuardedMutex::new(state)));

        h
    }

    pub(crate) fn get(
        &self,
        handle: TcpSocketHandle,
    ) -> Result<Arc<IrqGuardedMutex<TcpSocketState>>, TcpSocketError> {
        self.sockets
            .get(&handle.0)
            .cloned()
            .ok_or(TcpSocketError::InvalidHandle)
    }

    fn remove(
        &mut self,
        handle: TcpSocketHandle,
    ) -> Result<Arc<IrqGuardedMutex<TcpSocketState>>, TcpSocketError> {
        self.sockets
            .remove(&handle.0)
            .ok_or(TcpSocketError::InvalidHandle)
    }

    pub(crate) fn listener_for_port(&self, port: u16) -> Option<TcpSocketHandle> {
        self.listeners.get(&port).copied()
    }

    fn port_in_use(&self, port: u16) -> bool {
        self.listeners.contains_key(&port) || self.bound_ports.contains_key(&port)
    }

    /// Picks the first free port in the dynamic/private range
    /// (49152–65535, RFC 6335).
    fn alloc_ephemeral_port(&self) -> Result<u16, TcpSocketError> {
        (49152..=65535u16)
            .find(|&p| !self.port_in_use(p))
            .ok_or(TcpSocketError::AddrInUse)
    }
}

/// Looks up the socket options a new passive-open connection on `port`
/// should inherit from its listener, if one exists.
pub(crate) fn listener_opts_for_port(driver: &TcpDriver, port: u16) -> Option<TcpSessionSettings> {
    let sock = {
        let table = driver.socket_table.read();
        let handle = table.listener_for_port(port)?;
        table.get(handle).ok()?
    };

    Some(sock.lock().opts)
}

/// Called once a passive-open handshake completes: pushes the new TCB
/// onto its listener's `pending` queue and wakes anything blocked in
/// `accept()`.
pub(crate) fn enqueue_accepted_connection(
    driver: &TcpDriver,
    local_port: u16,
    tcb: Arc<IrqGuardedRwLock<TcpControlBlock>>,
) {
    let (listener_arc, backlog) = {
        let table = driver.socket_table.read();

        let handle = match table.listener_for_port(local_port) {
            Some(h) => h,
            None => return,
        };

        let arc = match table.sockets.get(&handle.0) {
            Some(a) => Arc::clone(a),
            None => return,
        };

        let backlog = {
            let guard = arc.lock();
            match &guard.role {
                TcpSocketRole::Listener { backlog, .. } => *backlog,
                _ => return,
            }
        };

        (arc, backlog)
    };

    let mut guard = listener_arc.lock();
    let TcpSocketRole::Listener { pending, gate, .. } = &mut guard.role else {
        return;
    };

    if pending.len() >= backlog {
        log::trace!("listen backlog full on port {}", local_port);
        return;
    }

    pending.push_back(tcb);
    gate.open();

    log::trace!(
        "connection queued for accept on port {} (pending={})",
        local_port,
        pending.len()
    );
}

impl TcpDriver {
    /// Creates a new unbound TCP socket and returns its handle.
    pub fn socket_create(&self) -> TcpSocketHandle {
        self.socket_table.write().insert(TcpSocketState {
            role: TcpSocketRole::Unbound,
            opts: TcpSessionSettings::default(),
        })
    }

    /// Replaces socket-level options.
    pub fn socket_set_opts(
        &self,
        handle: TcpSocketHandle,
        opts: TcpSessionSettings,
    ) -> Result<(), TcpSocketError> {
        let sock = self.socket_table.read().get(handle)?;

        sock.lock().opts = opts;

        Ok(())
    }

    /// Binds a socket to a local port. `port == 0` picks an ephemeral
    /// one.
    pub fn socket_bind(
        &self,
        handle: TcpSocketHandle,
        port: u16,
        nic: NetworkInterfaceId,
    ) -> Result<(), TcpSocketError> {
        let sock = self.socket_table.read().get(handle)?;

        let old_port: Option<u16> = {
            let guard = sock.lock();
            match guard.role {
                TcpSocketRole::Unbound => None,
                TcpSocketRole::Bound { local_port, .. } => Some(local_port),
                TcpSocketRole::Connected { .. } => return Err(TcpSocketError::AlreadyConnected),
                TcpSocketRole::Listener { .. } => return Err(TcpSocketError::AlreadyConnected),
                TcpSocketRole::Closed => return Err(TcpSocketError::Closed),
            }
        };

        let local_ip = kernel_ref()
            .network_subsystem()
            .interfaces()
            .get(nic)
            .and_then(|iface| iface.local_internet_address)
            .ok_or(TcpSocketError::NotBound)?;

        let assigned_port = {
            let mut table = self.socket_table.write();

            // Drop any previously bound port so it does not cause a false conflict.
            if let Some(p) = old_port {
                table.bound_ports.remove(&p);
            }

            if port == 0 {
                let p = table.alloc_ephemeral_port()?;
                table.bound_ports.insert(p, handle);
                p
            } else if table.port_in_use(port) {
                if let Some(p) = old_port {
                    table.bound_ports.insert(p, handle);
                }

                return Err(TcpSocketError::AddrInUse);
            } else {
                table.bound_ports.insert(port, handle);

                port
            }
        };

        sock.lock().role = TcpSocketRole::Bound {
            local_ip,
            local_port: assigned_port,
            nic,
        };

        Ok(())
    }

    /// Transitions a bound socket into the LISTEN state. Idempotent if
    /// already listening; fails on any other role.
    pub fn socket_listen(
        &self,
        handle: TcpSocketHandle,
        backlog: usize,
    ) -> Result<(), TcpSocketError> {
        let sock = self.socket_table.read().get(handle)?;

        let (local_ip, local_port, nic) = {
            let guard = sock.lock();

            match guard.role {
                TcpSocketRole::Bound {
                    local_ip,
                    local_port,
                    nic,
                } => (local_ip, local_port, nic),
                TcpSocketRole::Listener { .. } => return Ok(()), // idempotent
                _ => return Err(TcpSocketError::NotBound),
            }
        };

        // Move the port from "bound" to "listening" in the table before
        // the socket itself says so, so a SYN arriving in between still
        // finds a consistent state on one side or the other.
        {
            let mut table = self.socket_table.write();

            if table.listeners.contains_key(&local_port) {
                return Err(TcpSocketError::AddrInUse);
            }

            table.bound_ports.remove(&local_port);
            table.listeners.insert(local_port, handle);
        }

        sock.lock().role = TcpSocketRole::Listener {
            local_ip,
            local_port,
            nic,
            backlog: backlog.max(1),
            pending: VecDeque::new(),
            gate: Arc::new(OneshotGate::new()),
        };

        Ok(())
    }

    /// Blocking accept: dequeues the next completed connection from
    /// `listener`'s backlog, or sleeps until one arrives.
    pub fn socket_accept(
        &self,
        listener: TcpSocketHandle,
    ) -> Result<TcpSocketHandle, TcpSocketError> {
        loop {
            let sock = self.socket_table.read().get(listener)?;

            let gate_or_tcb: Result<
                Arc<IrqGuardedRwLock<TcpControlBlock>>,
                Option<Arc<OneshotGate>>,
            > = {
                let mut guard = sock.lock();

                match &mut guard.role {
                    TcpSocketRole::Listener { pending, gate, .. } => {
                        if let Some(tcb) = pending.pop_front() {
                            if pending.is_empty() {
                                unsafe { gate.reset() };
                            }

                            Ok(tcb)
                        } else {
                            Err(Some(Arc::clone(gate)))
                        }
                    }
                    TcpSocketRole::Closed => Err(None),
                    _ => Err(None),
                }
            };

            match gate_or_tcb {
                Ok(tcb) => {
                    let opts = sock.lock().opts;

                    let new_handle = self.socket_table.write().insert(TcpSocketState {
                        role: TcpSocketRole::Connected { tcb },
                        opts,
                    });

                    log::trace!("accept dequeued connection for listener {:?}", listener);

                    return Ok(new_handle);
                }
                Err(Some(gate)) => {
                    // Nothing pending yet - sleep until enqueue_accepted_connection
                    // opens the gate, then loop and check again.
                    gate.wait();
                }
                Err(None) => {
                    let guard = sock.lock();

                    return Err(match guard.role {
                        TcpSocketRole::Closed => TcpSocketError::Closed,
                        _ => TcpSocketError::NotListening,
                    });
                }
            }
        }
    }

    /// Attaches an already-established TCB to a socket handle.
    pub fn socket_adopt_connected(
        &self,
        handle: TcpSocketHandle,
        tcb: Arc<IrqGuardedRwLock<TcpControlBlock>>,
    ) -> Result<(), TcpSocketError> {
        let sock = self.socket_table.read().get(handle)?;
        let mut guard = sock.lock();

        match guard.role {
            TcpSocketRole::Connected { .. } => return Err(TcpSocketError::AlreadyConnected),
            TcpSocketRole::Listener { .. } => return Err(TcpSocketError::NotBound),
            TcpSocketRole::Closed => return Err(TcpSocketError::Closed),
            TcpSocketRole::Unbound | TcpSocketRole::Bound { .. } => {}
        }

        guard.role = TcpSocketRole::Connected { tcb };

        Ok(())
    }

    /// Socket wrapper around [`TcpDriver::connect`].
    pub fn socket_connect(
        &self,
        handle: TcpSocketHandle,
        remote_addr: Ipv4Addr,
        remote_port: u16,
    ) -> Result<(), TcpSocketError> {
        let sock = self.socket_table.read().get(handle)?;

        let (local_ip, local_port, nic, mut opts) = {
            let guard = sock.lock();

            match &guard.role {
                TcpSocketRole::Connected { .. } => return Err(TcpSocketError::AlreadyConnected),
                TcpSocketRole::Listener { .. } => return Err(TcpSocketError::NotBound),
                TcpSocketRole::Closed => return Err(TcpSocketError::Closed),

                TcpSocketRole::Bound {
                    local_ip,
                    local_port,
                    nic,
                } => (*local_ip, *local_port, *nic, guard.opts.clone()),

                TcpSocketRole::Unbound => {
                    let nic = NetworkInterfaceId(0);
                    let local_ip = kernel_ref()
                        .network_subsystem()
                        .interfaces()
                        .get(nic)
                        .and_then(|iface| iface.local_internet_address)
                        .ok_or(TcpSocketError::NotBound)?;
                    (local_ip, 0, nic, guard.opts.clone())
                }
            }
        };

        let tcb = self.connect(
            nic,
            local_ip,
            local_port,
            remote_addr,
            remote_port,
            &mut opts,
        )?;

        sock.lock().role = TcpSocketRole::Connected { tcb };

        Ok(())
    }

    /// Queues `data` for sending.
    pub fn socket_send(
        &self,
        handle: TcpSocketHandle,
        data: &[u8],
    ) -> Result<usize, TcpSocketError> {
        let tcb = self.connected_tcb(handle)?;

        self.send_data(tcb, data)?;

        Ok(data.len())
    }

    /// Blocking receive. `Ok(0)` means EOF.
    pub fn socket_recv(
        &self,
        handle: TcpSocketHandle,
        buf: &mut [u8],
    ) -> Result<usize, TcpSocketError> {
        let tcb = self.connected_tcb(handle)?;

        self.receive_sync(tcb, buf).map_err(TcpSocketError::from)
    }

    /// Snapshot of RTT / congestion-control state for an established socket.
    pub fn socket_cc_stats(
        &self,
        handle: TcpSocketHandle,
    ) -> Result<super::tcp::TcpCcSnapshot, TcpSocketError> {
        let tcb = self.connected_tcb(handle)?;

        Ok(tcb.read().cc_snapshot())
    }

    /// Half- or fully-closes the write side.
    pub fn socket_shutdown(
        &self,
        handle: TcpSocketHandle,
        how: Shutdown,
    ) -> Result<(), TcpSocketError> {
        if matches!(how, Shutdown::Write | Shutdown::Both) {
            let tcb = self.connected_tcb(handle)?;

            self.close_connection(tcb);
        }

        Ok(())
    }

    /// Closes and removes the socket, releasing its handle and any port
    /// it held.
    pub fn socket_close(&self, handle: TcpSocketHandle) -> Result<(), TcpSocketError> {
        let sock = self.socket_table.write().remove(handle)?;

        let role = {
            let mut guard = sock.lock();
            core::mem::replace(&mut guard.role, TcpSocketRole::Closed)
        };

        match role {
            TcpSocketRole::Listener {
                local_port,
                gate,
                mut pending,
                ..
            } => {
                self.socket_table.write().listeners.remove(&local_port);
                gate.open();

                for tcb in pending.drain(..) {
                    self.close_connection(tcb);
                }
            }
            TcpSocketRole::Bound { local_port, .. } => {
                self.socket_table.write().bound_ports.remove(&local_port);
            }
            TcpSocketRole::Connected { tcb } => {
                self.close_connection(tcb);
            }
            _ => {}
        }

        Ok(())
    }

    /// Extracts the TCB Arc for a connected socket.
    pub(crate) fn connected_tcb(
        &self,
        handle: TcpSocketHandle,
    ) -> Result<Arc<IrqGuardedRwLock<TcpControlBlock>>, TcpSocketError> {
        let sock = self.socket_table.read().get(handle)?;
        let guard = sock.lock();
        match &guard.role {
            TcpSocketRole::Connected { tcb } => Ok(Arc::clone(tcb)),
            TcpSocketRole::Closed => Err(TcpSocketError::Closed),
            _ => Err(TcpSocketError::NotConnected),
        }
    }
}
