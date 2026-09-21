//! Hyper-V Guest Shutdown Integration Service.
//!
//! Implements the VMBus Shutdown Integration Component, which allows the Hyper-V
//! host to request a clean, controlled power-off of the guest operating system.
//!
//! The service negotiates a protocol version with the host and, upon receiving a
//! [`UtilMessageType::Shutdown`] message and triggers an ACPI-level system shutdown
//! via the Fixed ACPI Description Table (FADT).

use acpica_rs::sys::AcpiGbl_FADT;

use crate::{
    arch::x86::asm::{inw, outw},
    driver::hv::hyperv::{
        VmBusOfferChannel, VmBusPacketType,
        channel::VmBusChannel,
        synthetic_device::{
            VmBusSyntheticDevice,
            integration::{
                IcVersionSet, UtilMessageHeader, UtilMessageType, UtilVersion, mark_as_response,
                negotiate_versions,
            },
        },
    },
};

/// Shutdown protocol version 1.0.
const SHUTDOWN_VERSION1_0: UtilVersion = UtilVersion::new(1, 0);

/// Shutdown protocol version 3.0.
const SHUTDOWN_VERSION3_0: UtilVersion = UtilVersion::new(3, 0);

/// Shutdown protocol version 3.1.
const SHUTDOWN_VERSION3_1: UtilVersion = UtilVersion::new(3, 1);

/// Shutdown protocol version 3.2.
const SHUTDOWN_VERSION3_2: UtilVersion = UtilVersion::new(3, 2);

/// Ordered set of Shutdown protocol versions supported by this guest.
///
/// Listed from most-preferred (newest) to least-preferred. Version negotiation
/// selects the first entry that the host also accepts.
const SHUTDOWN_VERSIONS: IcVersionSet = &[
    SHUTDOWN_VERSION3_2,
    SHUTDOWN_VERSION3_1,
    SHUTDOWN_VERSION3_0,
    SHUTDOWN_VERSION1_0,
];

/// Hyper-V Integration Service: System Shutdown.
///
/// Listens on a dedicated VMBus channel for shutdown signals issued by the hypervisor
/// administrator or host automation scripts.
pub struct VmBusShutdownService {
    /// The VMBus channel used to exchange packets with the host.
    channel: VmBusChannel,

    /// The original offer descriptor received from the host during channel enumeration.
    offer: VmBusOfferChannel,
}

impl VmBusShutdownService {
    /// Creates a new `VmBusShutdownService` from a connected VMBus channel.
    pub fn new(channel: VmBusChannel, offer: VmBusOfferChannel) -> Self {
        Self { channel, offer }
    }
}

impl VmBusSyntheticDevice for VmBusShutdownService {
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
            let util_hdr = unsafe { *(data_ptr as *const UtilMessageHeader) };

            match util_hdr.message_type {
                UtilMessageType::NegotiateProtocol => {
                    negotiate_versions(data_ptr, SHUTDOWN_VERSIONS);

                    mark_as_response(data_ptr);

                    // Echo the (modified) packet back as acknowledgement.
                    self.channel.send_packet(
                        packet.data.as_ptr(),
                        packet.data.len(),
                        0,
                        false,
                        VmBusPacketType::DataInband,
                    );
                }
                UtilMessageType::Shutdown => {
                    info!("VMBus Shutdown Request received");
                    info!("Shutting down...");

                    mark_as_response(data_ptr);

                    // we have to send an ACK to be able to shut down
                    self.channel.send_packet(
                        packet.data.as_ptr(),
                        packet.data.len(),
                        0,
                        false,
                        VmBusPacketType::DataInband,
                    );

                    // perform a shutdown using ACPI FADT tables
                    unsafe { shutdown_via_fadt() };
                }
                _ => {}
            }
        }

        self.channel.enable_interrupts();
    }
}

/// Triggers an immediate ACPI hardware power-off sequence using the FADT definitions.
///
/// This method interacts directly with the motherboard's Power Management 1 Control
/// Blocks (`PM1a_CNT` and `PM1b_CNT`), setting the `SLP_TYP` bits to transition the
/// machine into the S5 (Soft Off) power state.
unsafe fn shutdown_via_fadt() {
    // Get ports from ACPI FADT tables
    let port_a = unsafe { AcpiGbl_FADT.XPm1aControlBlock.Address as u16 };
    let port_b = unsafe { AcpiGbl_FADT.XPm1bControlBlock.Address as u16 };

    if port_a == 0 {
        error!("FADT PM1a port is zero");
        return;
    }

    // Typical ACPI S5 Sleep Type value for standard QEMU/Hyper-V environments
    let slp_typ_s5 = 7u16;
    // Bit 13: Sleep Enable bit in the PM1x_CNT register.
    let slp_en = 1 << 13; // SLEEP_ENABLE

    let current_a = inw(port_a);
    let val_a = (current_a & !(0x1C00 | 0x2000)) | (slp_typ_s5 << 10) | slp_en;

    outw(port_a, val_a);

    if port_b != 0 {
        let current_b = inw(port_b);
        let val_b = (current_b & !(0x1C00 | 0x2000)) | (slp_typ_s5 << 10) | slp_en;
        outw(port_b, val_b);
    }

    // Fallback sequence if standard sequence did not work
    outw(port_a, (current_a & !(0x1C00 | 0x2000)) | slp_en);

    unreachable!()
}
