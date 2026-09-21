//! # Hyper-V Heartbeat Integration Component
//!
//! ## Overview
//!
//! The Heartbeat IC service allows the Hyper-V host to periodically verify that
//! the guest operating system and its IC driver stack are still alive and
//! responsive.  If the guest fails to respond within the host's timeout window
//! the host marks the VM as unresponsive.
//!
//! ## Protocol
//!
//! After the standard IC version negotiation (see [`util_protocol`]), the host
//! sends [`UtilMessageType::Heartbeat`] probes at a fixed interval (~2 seconds).
//! The guest must echo each probe back unchanged — except for incrementing the
//! [`HeartbeatMessage::seq`] counter and setting the response flag.
//!
//! ```text
//! Host                              Guest
//!   │                                 │
//!   │  Heartbeat (seq = N)            │
//!   │ ──────────────────────────────► │
//!   │                                 │
//!   │  Heartbeat (seq = N+1, ack)     │
//!   │ ◄────────────────────────────── │
//!   │                                 │
//!   │  Heartbeat (seq = N+1)          │
//!   │ ──────────────────────────────► │
//!   │  …                              │
//! ```

use crate::driver::hv::hyperv::{
    VmBusOfferChannel, VmBusPacketType,
    channel::VmBusChannel,
    synthetic_device::{
        VmBusSyntheticDevice,
        integration::{
            IcVersionSet, UtilMessageHeader, UtilMessageType, UtilVersion, mark_as_response,
            negotiate_versions,
        },
    },
};

/// Heartbeat IC protocol version 1.0.
const HEARTBEAT_VERSION1_0: UtilVersion = UtilVersion::new(1, 0);

/// Heartbeat IC protocol version 3.0.
const HEARTBEAT_VERSION3_0: UtilVersion = UtilVersion::new(3, 0);

/// All Heartbeat protocol versions supported by this driver.
const HEARTBEAT_VERSIONS: IcVersionSet = &[HEARTBEAT_VERSION3_0, HEARTBEAT_VERSION1_0];

/// Payload for [`UtilMessageType::Heartbeat`].
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
struct HeartbeatMessage {
    /// Incremented by the guest on every response.  The host uses this to
    /// detect stale or replayed acknowledgements.
    seq: u32,

    /// Reserved — must be zero.
    reserved: [u8; 4],
}

/// Hyper-V Heartbeat Integration Component device.
///
/// Responds to periodic liveness probes sent by the Hyper-V host.  Each probe
/// is acknowledged by echoing the packet back with an incremented sequence
/// number.  Missing too many probes causes the host to report the VM as
/// unresponsive.
pub struct VmBusHeartbeatService {
    /// VMBus channel used for all the communication.
    pub(crate) channel: VmBusChannel,

    /// Offer sent by VMBus.
    offer: VmBusOfferChannel,
}

impl VmBusHeartbeatService {
    pub fn new(channel: VmBusChannel, offer: VmBusOfferChannel) -> Self {
        Self { channel, offer }
    }
}

impl VmBusSyntheticDevice for VmBusHeartbeatService {
    fn initialize(&self) -> bool {
        true
    }

    fn has_data_to_process(&self) -> bool {
        self.channel.has_data_to_process()
    }

    fn process_incoming_data(&self) {
        self.channel.disable_interrupts();

        while let Some(packet) = self.channel.read() {
            let data_ptr = packet.data.as_ptr();
            let util_hdr = unsafe { *(data_ptr as *const UtilMessageHeader) };

            match util_hdr.message_type {
                UtilMessageType::NegotiateProtocol => {
                    negotiate_versions(data_ptr, HEARTBEAT_VERSIONS);
                }
                UtilMessageType::Heartbeat => {
                    let hb_ptr = unsafe {
                        data_ptr.add(size_of::<UtilMessageHeader>()) as *mut HeartbeatMessage
                    };

                    // Update sequence number
                    unsafe { (*hb_ptr).seq = hb_ptr.read().seq + 1 };

                    mark_as_response(data_ptr);
                }

                unknown => panic!("Got unknown message type: {:?}", unknown),
            }

            // Echo the (modified) packet back as acknowledgement.
            self.channel.send_packet(
                packet.data.as_ptr(),
                packet.data.len(),
                0,
                false,
                VmBusPacketType::DataInband,
            );
        }

        self.channel.enable_interrupts();
    }
}
