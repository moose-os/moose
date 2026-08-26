//! Monocle logging subsystem.
//!
//! Provides a mechanism to transmit system logs over a selected socket implementation
//! to a remote host computer for external diagnostics and debugging.
use alloc::{sync::Arc, vec::Vec};

use monocle_protocol::{
    MONOCLE_FRAME_HEADER_SIZE, MONOCLE_GUEST_ENDPOINT_GUID, MONOCLE_HOST_SERVICE_GUID,
    MONOCLE_MAX_PAYLOAD_LEN, MonocleEncodeError, MonocleLogSource,
};
use spin::{Mutex, Once};
use x86_64::instructions::interrupts::without_interrupts;

use crate::driver::hv::{
    guid::Guid,
    hyperv::synthetic_device::integration::socket::{SocketError, VmBusSocket},
};

/// Maximum capacity required for a single encoded Monocle frame.
const MONOCLE_FRAME_CAPACITY: usize = MONOCLE_FRAME_HEADER_SIZE + MONOCLE_MAX_PAYLOAD_LEN;

/// Global singleton instance of the Monocle logger.
static MONOCLE_LOGGER: Once<Arc<MonocleLogger>> = Once::new();

/// Returns a reference to the globally registered Monocle logger, if one exists.
pub fn monocle_logger() -> Option<&'static Arc<MonocleLogger>> {
    MONOCLE_LOGGER.get()
}

/// Attempts to register the provided Monocle logger as the global instance.
pub fn try_register(logger: Arc<MonocleLogger>) {
    MONOCLE_LOGGER.call_once(|| logger);
}

/// Logger that formats and transmits diagnostic messages.
pub struct MonocleLogger {
    /// The VMBus socket connection to the remote host.
    socket: Arc<VmBusSocket>,

    /// Thread-safe buffer used for encoding frames prior to transmission.
    encode_buf: Mutex<Vec<u8>>,
}

impl MonocleLogger {
    /// Establishes a new VMBus socket connection to the remote Monocle host using predefined GUIDs.
    pub fn connect() -> Result<Arc<Self>, SocketError> {
        let host_service = Guid::from_str(MONOCLE_HOST_SERVICE_GUID);
        let guest_endpoint = Guid::from_str(MONOCLE_GUEST_ENDPOINT_GUID);
        let socket = VmBusSocket::request_connection(host_service, guest_endpoint)?;

        Ok(Arc::new(Self {
            socket,
            encode_buf: Mutex::new(Vec::with_capacity(MONOCLE_FRAME_CAPACITY)),
        }))
    }

    /// Returns a reference to the underlying VMBus socket.
    pub fn socket(&self) -> &Arc<VmBusSocket> {
        &self.socket
    }

    /// Sends raw byte data to the remote host, automatically splitting it into smaller frames if it exceeds the maximum payload size.
    pub fn log(&self, kind: MonocleLogSource, data: &[u8]) {
        if data.is_empty() {
            return;
        }

        for chunk in data.chunks(MONOCLE_MAX_PAYLOAD_LEN) {
            if self.send_frame(kind, chunk).is_err() {
                break;
            }
        }
    }

    /// Sends a string message to the remote host.
    pub fn log_str(&self, kind: MonocleLogSource, message: &str) {
        self.log(kind, message.as_bytes());
    }

    /// Encodes a single chunk of data into a frame and transmits it over the socket.
    fn send_frame(&self, kind: MonocleLogSource, payload: &[u8]) -> Result<(), MonocleEncodeError> {
        let mut buf = self.encode_buf.lock();
        buf.resize(MONOCLE_FRAME_HEADER_SIZE + payload.len(), 0);

        let frame_len = monocle_protocol::encode_frame(kind, payload, &mut buf)?;

        without_interrupts(|| {
            let _ = self.socket.write(&buf[..frame_len]);
        });

        Ok(())
    }
}
