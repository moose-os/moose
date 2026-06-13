//! Hyper-V Guest Sockets Integration Service.
//!
//! Implements a VMBus-based byte stream socket, allowing high-performance,
//! low-latency communication between the Hyper-V host and the guest OS
//! without relying on the network stack.
//!
//! Packets exchanged over this channel are encapsulated using the standard
//! [`VmBusPipeHeader`] with [`VmBusPipeMessageType::Data`].
//!
use alloc::{sync::Arc, vec::Vec};
use core::{
    ptr, slice,
    sync::atomic::{AtomicU32, AtomicU64, Ordering},
};
use spin::RwLock;
use x86_64::instructions::interrupts::without_interrupts;

use crate::{
    driver::hv::{
        guid::Guid,
        hyperv::{
            VmBusOfferChannel, VmBusPacketType, VmBusPipeHeader, VmBusPipeMessageType,
            channel::VmBusChannel, synthetic_device::VmBusSyntheticDevice,
        },
    },
    kernel::kernel_ref,
    subsystem::scheduler::OneshotGate,
};

/// Lifecycle state of a [`VmBusSocket`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketState {
    /// Freshly created; no operation has been performed yet.
    Idle,

    /// [`VmBusSocket::connect`] has been called; waiting for `ConnectResponse`.
    Connecting,

    /// Full-duplex data path is open.
    Connected,

    /// [`VmBusSocket::listen`] has been called; waiting for an inbound `Connect`.
    Listening,

    /// Connection has been torn down (gracefully or due to a channel error).
    Closed,
}

/// Socket state.
pub struct VmBusSocketState {
    /// Current lifecycle phase.
    ///
    /// Guards all I/O operations: `read` and `write` check this field and
    /// return an error immediately when the socket is not [`SocketState::Connected`].
    pub state: SocketState,

    /// Bytes received from the peer that have not yet been consumed by `read()`.
    /// @TODO: Ringbuffer?
    pub rx_buf: Vec<u8>,

    /// Set by the ISR when a `Disconnect` frame arrives; causes `read()` to
    /// return an EOF error on the next call.
    pub peer_disconnected: bool,

    /// Monotonically increasing transaction id for outgoing VMBus packets.
    pub next_xid: AtomicU64,
}

/// Hyper-V socket – bidirectional byte-stream socket over VMBus.
///
/// One instance represents one virtual connection.
///
/// Blocking operations suspend the caller via [`OneshotGate::wait`] and are
/// resumed by the interrupt-driven [`process_incoming_data`] path calling
/// [`OneshotGate::open`].
pub struct VmBusSocket {
    /// Channel used by the socket.
    pub channel: VmBusChannel,

    /// Channel offer sent by the host.
    pub offer: VmBusOfferChannel,

    /// Internal socket state.
    pub state: RwLock<VmBusSocketState>,

    /// Gate signalled by the ISR to wake any blocking API caller.
    pub event: Arc<OneshotGate>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketError {
    VmBusUnavailable,
    ConnectRejected,
    ChannelNotDelivered,
    ConnectNotFound,
}

pub(crate) struct PendingSocketConnect {
    pub(crate) guest_endpoint: Guid,
    pub(crate) host_service: Guid,
    pub(crate) gate: Arc<OneshotGate>,
    pub(crate) tl_status: AtomicU32,
    pub(crate) socket: spin::Mutex<Option<Arc<VmBusSocket>>>,
}

impl PendingSocketConnect {
    pub(crate) fn new(guest_endpoint: Guid, host_service: Guid) -> Self {
        Self {
            guest_endpoint,
            host_service,
            gate: Arc::new(OneshotGate::new()),
            tl_status: AtomicU32::new(u32::MAX),
            socket: spin::Mutex::new(None),
        }
    }

    pub(crate) fn matches_offer(&self, offer: &VmBusOfferChannel) -> bool {
        self.guest_endpoint == offer.channel_instance
    }
}

impl VmBusSocket {
    pub fn request_connection(
        remote_host: Guid,
        local_port: Guid,
    ) -> Result<Arc<Self>, SocketError> {
        let hyperv = unsafe {
            kernel_ref()
                .virtualized_devices_manager
                .get()
                .ok_or(SocketError::VmBusUnavailable)?
                .unwrap_vmbus()
        };

        hyperv.connect_socket_blocking(remote_host, local_port)
    }

    /// Creates a new [`VmBusSocket`] in [`SocketState::Connected`].
    ///
    /// The socket is immediately ready for `read` / `write`; the VMBus-level
    /// channel negotiation has already been completed by the caller.
    pub fn new(channel: VmBusChannel, offer: VmBusOfferChannel) -> Self {
        Self {
            channel,
            offer,
            state: RwLock::new(VmBusSocketState {
                state: SocketState::Connected,
                rx_buf: Vec::new(),
                next_xid: AtomicU64::new(1),
                peer_disconnected: false,
            }),
            event: Arc::new(OneshotGate::new()),
        }
    }
}

impl VmBusSocket {
    /// Blocks until the ISR calls `event.open()`, then resets the gate for
    /// reuse.
    fn wait_for_event(&self) {
        self.event.wait();

        // SAFETY: only one thread waits on this gate at a time per protocol
        // step; reset is safe once wait() has returned.
        unsafe { self.event.reset() };
    }
}

impl VmBusSocket {
    /// Blocking read – copies up to `buf.len()` bytes into `buf`.
    ///
    /// Returns the number of bytes actually written. Suspends the caller via
    /// [`OneshotGate::wait`] when the receive buffer is empty.
    pub fn read(&self, buf: &mut [u8]) -> Result<usize, &'static str> {
        if self.state.read().state == SocketState::Closed {
            return Err("read() on closed socket");
        }

        loop {
            let res = without_interrupts(|| {
                let mut st = self.state.write();

                if !st.rx_buf.is_empty() {
                    let n = buf.len().min(st.rx_buf.len());

                    buf[..n].copy_from_slice(&st.rx_buf[..n]);
                    st.rx_buf.drain(..n);

                    return Some(Ok(n));
                }

                if st.peer_disconnected {
                    st.state = SocketState::Closed;

                    return Some(Err("connection closed by remote"));
                }

                None
            });

            if let Some(actual_result) = res {
                return actual_result;
            }

            self.wait_for_event();
        }
    }

    /// Blocking read that fills `buf` completely before returning.
    ///
    /// Useful when an exact-size message is expected.
    pub fn read_exact(&self, buf: &mut [u8]) -> Result<(), &'static str> {
        let mut filled = 0;

        while filled < buf.len() {
            let n = self.read(&mut buf[filled..])?;

            filled += n;
        }

        Ok(())
    }

    /// Sends all bytes in `buf` to the peer.
    ///
    /// Always returns `buf.len()` on success. VMBus in-band packets are
    /// posted synchronously so this call does not block.
    pub fn write(&self, payload: &[u8]) -> Result<usize, &'static str> {
        if self.state.read().state == SocketState::Closed {
            return Err("write() on closed socket");
        }

        let pipe = VmBusPipeHeader {
            message_type: VmBusPipeMessageType::Data,
            size: payload.len() as u32,
        };
        let pipe_len = size_of::<VmBusPipeHeader>();
        let total_len = payload.len() + pipe_len;

        let mut buf = alloc::vec![0u8; total_len];
        let ptr = buf.as_mut_ptr();

        unsafe {
            ptr::copy_nonoverlapping(&pipe as *const _ as *const u8, ptr, pipe_len);

            if !buf.is_empty() {
                ptr::copy_nonoverlapping(payload.as_ptr(), ptr.add(pipe_len), buf.len());
            }
        }

        let xid = self.state.read().next_xid.fetch_add(1, Ordering::Relaxed);

        self.channel.send_packet(
            buf.as_ptr(),
            total_len,
            xid,
            false,
            VmBusPacketType::DataInband,
        );

        Ok(buf.len())
    }

    /// Convenience wrapper – sends a UTF-8 string slice.
    pub fn write_str(&self, s: &str) -> Result<usize, &'static str> {
        self.write(s.as_bytes())
    }

    /// Gracefully closes the connection.
    ///
    /// Sends an empty `Data` frame (size = 0) as a disconnect signal, and
    /// transitions the socket to [`SocketState::Closed`]. Subsequent calls to
    /// `read` or `write` will return an error immediately.
    pub fn close(&self) {
        {
            let mut st = self.state.write();
            if st.state == SocketState::Closed {
                return;
            }
            st.state = SocketState::Closed;
        }

        // Empty payload – interpreted by the peer's ISR as a disconnect signal
        let _ = self.write(&[]);
    }
}

impl VmBusSyntheticDevice for VmBusSocket {
    fn initialize(&self) -> bool {
        true
    }

    fn has_data_to_process(&self) -> bool {
        self.channel.has_data_to_process()
    }

    fn process_incoming_data(&self) {
        self.channel.disable_interrupts();

        while let Some(packet) = self.channel.read() {
            let data_ptr = packet.data.as_ptr() as *mut u8;
            let header = unsafe { (data_ptr as *const VmBusPipeHeader).as_ref().unwrap() };
            let slice = unsafe {
                slice::from_raw_parts(
                    data_ptr.add(size_of::<VmBusPipeHeader>()),
                    header.size as usize,
                )
            };

            if header.size == 0 {
                self.state.write().peer_disconnected = true;
            } else {
                assert_eq!({ header.message_type }, VmBusPipeMessageType::Data);
                self.state.write().rx_buf.extend_from_slice(slice);
            }

            self.event.open();
        }

        self.channel.enable_interrupts();
    }

    fn on_rescind(&self) {
        self.close();

        self.channel.close();
    }
}

unsafe impl Sync for VmBusSocket {}
unsafe impl Send for VmBusSocket {}
