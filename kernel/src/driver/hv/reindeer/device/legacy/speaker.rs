//! Virtual PC Speaker & System Control Port B (`0x61`) Device Model.
//!
//! Emulates the legacy PC/AT System Control Port B (`0x61`), which connects the Programmable
//! Interval Timer (PIT 8254 Channel 2) output and direct software bits to the internal PC Speaker.
//!
//! The PC speaker is not emulated; this is a stub device for port 0x61.

use alloc::{sync::Arc, vec::Vec};

use spin::rwlock::RwLock;

use crate::driver::hv::reindeer::device::{DeviceResource, VirtualDevice, legacy::pit::VirtualPit};

/// System Control Port B I/O Address.
pub const SYSTEM_CONTROL_PORT_B: u16 = 0x61;

/// DRAM Refresh Cycle Toggle Bit Mask (Bit 4).
const REFRESH_TOGGLE_BIT: u64 = 1 << 4;

/// Virtual PC Speaker and Port 0x61 state container.
pub struct VirtualSpeaker {
    /// Internal register byte caching port 0x61 state.
    data: u64,

    /// Reference to Virtual PIT to query Channel 2 OUT pin and control Gate 2.
    pit: Arc<RwLock<VirtualPit>>,
}

impl VirtualSpeaker {
    /// Creates a new `VirtualSpeaker` instance initialized to standard post-RESET defaults.
    pub fn new(pit: Arc<RwLock<VirtualPit>>) -> Arc<RwLock<Self>> {
        Arc::new(RwLock::new(VirtualSpeaker { data: 0x00, pit }))
    }
}

impl VirtualDevice for VirtualSpeaker {
    /// Returns human-readable device name.
    fn name(&self) -> &str {
        "Virtual Speaker"
    }

    /// Reserves I/O port `0x61` for System Control Port B.
    fn get_resources(&self) -> Vec<DeviceResource> {
        alloc::vec![DeviceResource::IoPort {
            port: SYSTEM_CONTROL_PORT_B,
        }]
    }

    /// Handles guest reads from port `0x61`.
    ///
    /// Dynamically toggles Bit 4 (DRAM Refresh Toggle Bit) on every read cycle to simulate
    /// classic hardware timing loops used by legacy BIOS/DOS code.
    fn handle_io_read(&mut self, _cpu_id: usize, addr: u64, _width: u8) -> u64 {
        assert_eq!(addr, SYSTEM_CONTROL_PORT_B as u64);

        self.data ^= REFRESH_TOGGLE_BIT;

        let mut val = self.data & 0x1F;
        if self.pit.read().get_channel2_out() {
            val |= 1 << 5;
        }

        val
    }

    /// Handles guest writes to port `0x61`.
    ///
    /// Updates the speaker state, PIT gate status, and NMI check flags.
    fn handle_io_write(&mut self, _cpu_id: usize, addr: u64, value: u64, _width: u8) {
        assert_eq!(addr, SYSTEM_CONTROL_PORT_B as u64);

        let gate_enabled = (value & 0x01) != 0;
        self.pit.write().set_channel2_gate(gate_enabled);

        self.data = value;
    }

    /// Generates AML byte stream for the PC Speaker device node.
    ///
    /// Declares `PNP0800` (AT Standard Speaker) with 1 byte of Fixed I/O reserved at `0x61`.
    fn generate_aml(&self) -> Option<Vec<u8>> {
        Some(crate::aml!(@ROOT
            Device ("SPKR") {
                Name ("_HID", "PNP0800")
                Name ("_DDN", "PC Speaker")

                Name ("_CRS", ResourceTemplate() {
                    FixedIO (0x61, 1)
                })

                Method ("_STA", 0) {
                    Return (0x0Fu8)
                }
            }
        ))
    }
}
