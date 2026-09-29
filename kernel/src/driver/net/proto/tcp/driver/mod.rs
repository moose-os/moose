//! TCP connection driver.
//!
//! [`TcpDriver`] owns the connection table (keyed by [`ConnectionTuple`])
//! and the listening-socket table, and is the entry point for everything
//! else - the network stack delivering incoming packets, sockets
//! sending data, timers firing.

use alloc::sync::Arc;

use hashbrown::HashMap;

use super::types::*;
use crate::{
    driver::net::proto::tcp_socket::TcpSocketTable, kernel::kernel_ref,
    subsystem::sync::IrqGuardedRwLock,
};

mod connect;
mod recv;
mod retransmit;
pub(super) mod send;
mod timer;

/// Shared state for all TCP connections and listeners on this stack.
pub struct TcpDriver {
    /// Live connections.
    pub(super) connections:
        IrqGuardedRwLock<HashMap<ConnectionTuple, Arc<IrqGuardedRwLock<TcpControlBlock>>>>,

    /// Listening sockets and the options new passive-open connections
    /// should inherit from them.
    pub(crate) socket_table: IrqGuardedRwLock<TcpSocketTable>,
}

impl TcpDriver {
    pub fn new() -> Self {
        Self {
            connections: IrqGuardedRwLock::new(HashMap::new()),
            socket_table: IrqGuardedRwLock::new(TcpSocketTable::new()),
        }
    }

    /// Starts the background worker thread that drives timers and
    /// retransmissions for every connection.
    pub fn initialize(&self) {
        kernel_ref()
            .spawn_kernel_thread(super::tcp_worker, 0, 7)
            .unwrap();
    }

    /// Aborts a connection after an ICMP hard error (RFC 1122 §3.2.2.4).
    ///
    /// Unlike a normal close, there's no FIN handshake here - an ICMP
    /// hard error (e.g. destination unreachable) means the path is
    /// broken.
    pub fn abort_connection(&self, tuple: ConnectionTuple, error: TcpError) {
        let Some(tcb_arc) = self.connections.read().get(&tuple).cloned() else {
            return;
        };

        let mut tcb = tcb_arc.write();
        if tcb.state == TcpState::Closed {
            return;
        }

        let state = tcb.state;
        tcb.state = TcpState::Closed;
        tcb.last_error = Some(error);
        tcb.retransmission_queue.clear();
        tcb.rtt_m.probe = None;
        tcb.persist_timer = None;

        super::eifel::eifel_clear_pending(&mut tcb);

        tcb.frto.clear();
        tcb.event.notify();

        drop(tcb);

        log::warn!("TCP: abort {:?} state={:?} err={:?}", tuple, state, error);
    }
}
