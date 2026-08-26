//! Virtual ACPI Power Management Block (`VirtualAcpiPm`) Device Model.
//!
//! This module emulates the ACPI PM1a Event and Control Registers for a guest virtual machine.
//! The ACPI specification requires the PM1a block to manage system power states (such as poweroff
//! or sleep), enable/disable ACPI mode, and register System Control Interrupt (SCI) events.
//!
//! ### Registers Emulated (Port range `0x600` – `0x605`)
//! - `0x600` (`PM1a_STS`, 16-bit): Power Management 1 Status Register.
//! - `0x602` (`PM1a_EN`, 16-bit): Power Management 1 Enable Register. Controls which events trigger SCIs.
//! - `0x604` (`PM1a_CNT`, 16-bit): Power Management 1 Control Register. Controls sleep states (`SLP_TYP`),
//!   sleep enable (`SLP_EN`, bit 13), and system control interrupt enable (`SCI_EN`, bit 0).
//!
//! - The registers mapped here correspond directly to the I/O base address declared in the FADT table
//!   (`PM1a_EVT_BLK = 0x600`, `PM1a_CNT_BLK = 0x604`).

use alloc::{sync::Arc, vec::Vec};

use spin::rwlock::RwLock;

use crate::driver::hv::reindeer::device::{DeviceResource, VirtualDevice};

/// Base I/O port for the ACPI PM1a block (Status: `0x600`, Enable: `0x602`, Control: `0x604`).
const PM1_BASE: u16 = 0x600;

/// Total size in bytes of the I/O port region allocated for the PM1a block.
const PM1_SIZE: u16 = 6;

/// Virtual ACPI Power Management 1 (`PM1a`) Device.
///
/// Holds the internal state for ACPI status, enable, and control registers.
pub struct VirtualAcpiPm {
    /// PM1 Status Register (`PM1a_STS`). Tracks active ACPI hardware events.
    pm1_sts: u16,

    /// PM1 Enable Register (`PM1a_EN`). Masks or unmasks interrupts for ACPI events.
    pm1_en: u16,

    /// PM1 Control Register (`PM1a_CNT`). Manages power transition requests (e.g., system sleep/shutdown).
    pm1_cnt: u16,
}

impl VirtualAcpiPm {
    /// Creates and initializes a new `VirtualAcpiPm` instance.
    ///
    /// The `pm1_cnt` register is pre-initialized to `0x0001` (`SCI_EN = 1`).
    /// This signals to the guest operating system that ACPI mode is already active
    /// and that standard System Control Interrupts are enabled without requiring SMI handshakes.
    pub fn new() -> Arc<RwLock<Self>> {
        Arc::new(RwLock::new(Self {
            pm1_sts: 0,
            pm1_en: 0,
            // SCI_EN=1: ACPI mode already enabled (SMI_CMD=0 in FADT)
            pm1_cnt: 0x0001,
        }))
    }
}

impl VirtualDevice for VirtualAcpiPm {
    /// Returns the human-readable identifier for this virtual device.
    fn name(&self) -> &str {
        "ACPI PM1"
    }

    /// Declares the I/O port resources consumed by this device (`0x600`–`0x605`).
    fn get_resources(&self) -> Vec<DeviceResource> {
        alloc::vec![DeviceResource::IoPortRange {
            base: PM1_BASE,
            size: PM1_SIZE,
        }]
    }

    /// Handles I/O read operations directed to the PM1a register space.
    ///
    /// A 4-byte read at port `0x600` combines `PM1_STS` (lower 16 bits) and `PM1_EN` (upper 16 bits).
    fn handle_io_read(&mut self, _cpu_id: usize, addr: u64, width: u8) -> u64 {
        let port = addr as u16;

        match (port, width) {
            (0x600, 4) => (self.pm1_sts as u64) | ((self.pm1_en as u64) << 16),
            (0x600, 2) => self.pm1_sts as u64,
            (0x602, 2) => self.pm1_en as u64,
            (0x604, 2) => self.pm1_cnt as u64,
            (0x600, 1) => (self.pm1_sts & 0xFF) as u64,
            (0x601, 1) => (self.pm1_sts >> 8) as u64,
            (0x602, 1) => (self.pm1_en & 0xFF) as u64,
            (0x603, 1) => (self.pm1_en >> 8) as u64,
            (0x604, 1) => (self.pm1_cnt & 0xFF) as u64,
            (0x605, 1) => (self.pm1_cnt >> 8) as u64,

            _ => panic!("ACPI PM1: bad read port={:#x} width={}", port, width),
        }
    }

    /// Handles I/O write operations directed to the PM1a register space.
    fn handle_io_write(&mut self, _cpu_id: usize, addr: u64, value: u64, width: u8) {
        let port = addr as u16;

        match (port, width) {
            (0x600, 2) | (0x600, 4) => {
                // PM1_STS is write-1-to-clear
                self.pm1_sts &= !(value as u16);

                if width == 4 {
                    self.pm1_en = (value >> 16) as u16;
                }
            }
            (0x602, 2) => self.pm1_en = value as u16,
            (0x604, 2) => {
                self.pm1_cnt = value as u16;

                if self.pm1_cnt & (1 << 13) != 0 {
                    panic!(
                        "ACPI PM1: SLP_EN set cnt={:#x} (sleep not implemented)",
                        self.pm1_cnt
                    );
                }
            }
            (0x600, 1) => self.pm1_sts &= !(value as u16),
            (0x601, 1) => self.pm1_sts &= !((value as u16) << 8),
            (0x602, 1) => self.pm1_en = (self.pm1_en & 0xFF00) | (value as u16 & 0xFF),
            (0x603, 1) => self.pm1_en = (self.pm1_en & 0x00FF) | ((value as u16 & 0xFF) << 8),
            (0x604, 1) => {
                self.pm1_cnt = (self.pm1_cnt & 0xFF00) | (value as u16 & 0xFF);

                if self.pm1_cnt & (1 << 13) != 0 {
                    panic!("ACPI PM1: SLP_EN set cnt={:#x}", self.pm1_cnt);
                }
            }
            (0x605, 1) => {
                self.pm1_cnt = (self.pm1_cnt & 0x00FF) | ((value as u16 & 0xFF) << 8);

                if self.pm1_cnt & (1 << 13) != 0 {
                    panic!("ACPI PM1: SLP_EN set cnt={:#x}", self.pm1_cnt);
                }
            }

            _ => panic!(
                "ACPI PM1: bad write port={:#x} width={} value={:#x}",
                port, width, value
            ),
        }
    }

    fn generate_aml(&self) -> Option<Vec<u8>> {
        None
    }
}
