//! # Virtual PCI Host Bridge Implementation
//!
//! This module implements a virtual PCI Host Bridge conforming to the PCI Local Bus Specification (Type 1 Configuration Mechanism).
//! It acts as the primary interface between guest system I/O instructions (`IN`/`OUT` to ports `0xCF8`–`0xCFF`)
//! and virtual PCI devices.
//!
//! ## Architecture Overview
//!
//! In standard x86 systems, the PCI Type 1 access mechanism uses two 32-bit I/O ports:
//! - `CONFIG_ADDRESS` (`0xCF8`): A 32-bit register specifying the target PCI Bus, Device, Function, and Register Offset, alongside an Enable bit (bit 31).
//! - `CONFIG_DATA` (`0xCFC`): A 32-bit window used to read or write data from/to the register specified in `CONFIG_ADDRESS`.
//!
//! ```text
//!  Guest OS I/O Access
//!   (in/out 0xCF8/0xCFC)
//!            │
//!            ▼
//!  ┌───────────────────────────────┐
//!  │    VirtualPciHostBridge       │
//!  │ ┌───────────────────────────┐ │
//!  │ │ config_address: u32       │ │
//!  │ └───────────────────────────┘ │
//!  └──────────────┬────────────────┘
//!                 │ Lookup PciAddress (Bus, Device, Function)
//!                 ▼
//!  ┌───────────────────────────────┐
//!  │  HashMap<PciAddress, Arc<..>> │
//!  └──────────────┬────────────────┘
//!                 │ Dispatch config_read / config_write
//!                 ▼
//!  ┌───────────────────────────────┐
//!  │    VirtualPciDevice Trait     │
//!  └───────────────────────────────┘
//! ```

use alloc::{sync::Arc, vec::Vec};

use hashbrown::HashMap;
use spin::rwlock::RwLock;

use crate::driver::hv::reindeer::device::{DeviceResource, VirtualDevice};

/// Represents a canonical 3-tuple PCI Bus-Device-Function (BDF) physical topology address.
///
/// # Field Constraints (PCI Local Bus Specification)
/// - `bus`: 8 bits (0–255, supporting up to 256 buses).
/// - `device`: 5 bits used (0–31, up to 32 devices per bus).
/// - `function`: 3 bits used (0–7, up to 8 functions per device).
#[derive(Debug, Hash, Eq, PartialEq, Clone, Copy)]
pub struct PciAddress {
    /// Bus index (0..255).
    pub bus: u8,

    /// Device slot index on the bus (0..31).
    pub device: u8,

    /// Function index inside the device (0..7).
    pub function: u8,
}

/// Virtual PCI Host Bridge emulation structure.
///
/// Handles trapping of x86 I/O port reads/writes directed at the PCI configuration mechanism,
/// maintains the internal latch state for `CONFIG_ADDRESS`, and routes configuration reads/writes
/// to registered [`VirtualPciDevice`] instances.
pub struct VirtualPciHostBridge {
    /// Map of physical BDF addresses to thread-safe virtual PCI device instances.
    devices: HashMap<PciAddress, Arc<RwLock<dyn VirtualPciDevice>>>,

    /// Latched 32-bit raw value of the `CONFIG_ADDRESS` port (`0xCF8`).
    config_address: u32,
}

impl VirtualPciHostBridge {
    /// Base I/O port address for the PCI Type 1 `CONFIG_ADDRESS` register (`0xCF8`).
    const CONFIG_ADDR_BASE: u64 = 0xCF8;

    /// Base I/O port address for the PCI Type 1 `CONFIG_DATA` register window (`0xCFC`).
    const CONFIG_DATA_BASE: u64 = 0xCFC;

    /// Register window size in bytes for configuration address and data ports (4 bytes / 32 bits).
    const CONFIG_REG_SIZE: u64 = 4;

    /// Creates a new, uninitialized `VirtualPciHostBridge` with an empty device topology.
    ///
    /// The initial `config_address` is set to `0` (Disabled, Bus 0, Device 0, Function 0, Register 0).
    pub fn new() -> Arc<RwLock<Self>> {
        Arc::new(RwLock::new(VirtualPciHostBridge {
            devices: HashMap::new(),
            config_address: 0,
        }))
    }

    /// Decodes the currently latched `config_address` into a structured [`PciAddress`].
    ///
    /// # Bit Layout of `CONFIG_ADDRESS` (0xCF8)
    /// - Bit 31: Enable Bit (Ignored in BDF extraction, checked during data routing)
    /// - Bits 24–30: Reserved
    /// - Bits 16–23: Bus Number (8 bits)
    /// - Bits 11–15: Device Number (5 bits)
    /// - Bits 8–10: Function Number (3 bits)
    /// - Bits 0–7: Register Offset (Bits 0–1 reserved / alignment)
    fn get_address(&self) -> PciAddress {
        let addr = self.config_address;

        PciAddress {
            bus: ((addr >> 16) & 0xFF) as u8,
            device: ((addr >> 11) & 0x1F) as u8,
            function: ((addr >> 8) & 0x07) as u8,
        }
    }

    /// Extracts the 8-bit aligned PCI configuration register dword offset from `config_address`.
    fn get_offset(&self) -> u16 {
        (self.config_address & 0xFC) as u16
    }

    /// Looks up and clones the reference-counted device handle corresponding to the latched `CONFIG_ADDRESS`.
    ///
    /// Returns `None` if no virtual device is registered at the requested [`PciAddress`].
    fn get_device(&self) -> Option<Arc<RwLock<dyn VirtualPciDevice>>> {
        self.devices.get(&self.get_address()).cloned()
    }

    /// Validates I/O access bounds and access width for configuration ports.
    ///
    /// # Parameters
    /// - `base`: Base port address (`CONFIG_ADDR_BASE` or `CONFIG_DATA_BASE`).
    /// - `addr`: Actual accessed port address.
    /// - `width`: Access width in bytes (must be 1, 2, or 4).
    fn check_access(base: u64, addr: u64, width: u8) {
        let width = width as u64;
        if width != 1 && width != 2 && width != 4 {
            panic!(
                "PCI config: invalid access width {} at port {:#x}",
                width, addr
            );
        }

        if addr < base || addr + width > base + Self::CONFIG_REG_SIZE {
            panic!(
                "PCI config: out-of-bounds access port={:#x} width={} (window {:#x}..{:#x})",
                addr,
                width,
                base,
                base + Self::CONFIG_REG_SIZE
            );
        }
    }

    /// Updates the internal `config_address` register, allowing byte-, word-, or dword-wide partial writes.
    ///
    /// Some legacy software or real-mode BIOS code performs 8-bit or 16-bit writes to port `0xCF8`..`0xCFB`.
    /// This method computes a bit shift and bitmask based on `addr - CONFIG_ADDR_BASE` to merge sub-dword writes
    /// into the current `config_address` state without corrupting unwritten bytes.
    fn merge_config_address(&mut self, addr: u64, value: u64, width: u8) {
        Self::check_access(Self::CONFIG_ADDR_BASE, addr, width);

        if width == 4 {
            self.config_address = value as u32;
            return;
        }

        let shift = ((addr - Self::CONFIG_ADDR_BASE) * 8) as u32;
        let mask = if width == 1 { 0xFFu32 } else { 0xFFFFu32 };
        let shifted_mask = mask << shift;
        let shifted_value = (value as u32 & mask) << shift;

        self.config_address = (self.config_address & !shifted_mask) | shifted_value;
    }

    /// Reads the `config_address` register (or a slice of it) based on address and access width.
    ///
    /// Supports sub-dword reads by shifting and masking `self.config_address`.
    fn read_config_address(&self, addr: u64, width: u8) -> u64 {
        Self::check_access(Self::CONFIG_ADDR_BASE, addr, width);

        let shift = ((addr - Self::CONFIG_ADDR_BASE) * 8) as u32;
        let mask = if width == 1 {
            0xFFu32
        } else if width == 2 {
            0xFFFFu32
        } else {
            0xFFFF_FFFFu32
        };

        ((self.config_address >> shift) & mask) as u64
    }

    /// Computes the absolute target register offset inside a device's PCI configuration space.
    ///
    /// Combines dword-aligned base offset (`get_offset()`) with byte alignment offset derived from `addr - CONFIG_DATA_BASE`.
    fn config_data_offset(&self, addr: u64) -> u16 {
        self.get_offset() + (addr - Self::CONFIG_DATA_BASE) as u16
    }
}

impl VirtualDevice for VirtualPciHostBridge {
    /// Returns the human-readable string name of this virtual device.
    fn name(&self) -> &str {
        "PciHostBridge"
    }

    /// Returns the system resource footprint (I/O Port ranges) required by this PCI host bridge.
    ///
    /// Configures trapping for:
    /// 1. `0xCF8..0xCFF`: PCI Type 1 `CONFIG_ADDRESS` + `CONFIG_DATA`.
    /// 2. `0xC000..0xCFFF`: PCI Mechanism #2 window for compatibility probing.
    fn get_resources(&self) -> Vec<DeviceResource> {
        alloc::vec![
            // CONFIG_ADDRESS 0xCF8..0xCFB + CONFIG_DATA 0xCFC..0xCFF (type-1)
            DeviceResource::IoPortRange {
                base: 0xCF8,
                size: 8,
            },
            // PCI Configuration Mechanism #2 data window
            DeviceResource::IoPortRange {
                base: 0xC000,
                size: 0x1000,
            },
        ]
    }

    /// Handles trapped guest x86 I/O port read instructions (`IN` / `INS`).
    ///
    /// # Routing Rules
    /// - `0xCF8..=0xCFB`: Returns content from latched `CONFIG_ADDRESS`.
    /// - `0xCFC..=0xCFF`: Queries target PCI device's [`VirtualPciDevice::config_read`].
    ///   - If no device exists at target BDF: Returns `0xFFFF_FFFF_FFFF_FFFF` (master abort floating line).
    /// - `0xC000..=0xCFFF`: Mechanism #2 probe region. Returns all-ones floating line.
    ///   to signal that Mechanism #2 is not present.
    fn handle_io_read(&mut self, _cpu_id: usize, addr: u64, width: u8) -> u64 {
        match addr {
            0xCF8..=0xCFB => self.read_config_address(addr, width),
            0xCFC..=0xCFF => {
                Self::check_access(Self::CONFIG_DATA_BASE, addr, width);
                let offset = self.config_data_offset(addr);

                match self.get_device() {
                    Some(dev) => dev.read().config_read(offset, width),
                    None => 0xFFFF_FFFF_FFFF_FFFF,
                }
            }
            0xC000..=0xCFFF => 0xFFFF_FFFF,
            _ => panic!("PCI: unexpected I/O read from port {:#x}", addr),
        }
    }

    /// Handles trapped guest x86 I/O port write instructions (`OUT` / `OUTS`).
    ///
    /// # Routing Rules
    /// - `0xCF8..=0xCFB`: Updates latched `CONFIG_ADDRESS`.
    /// - `0xCFC..=0xCFF`: Routes write payload to target device's [`VirtualPciDevice::config_write`].
    ///   - Writes to non-existent BDFs are silently ignored (standard bus behavior).
    /// - `0xC000..=0xCFFF`: Unsupported Mechanism #2 write attempt; triggers panic.
    fn handle_io_write(&mut self, _cpu_id: usize, addr: u64, value: u64, width: u8) {
        match addr {
            0xCF8..=0xCFB => self.merge_config_address(addr, value, width),
            0xCFC..=0xCFF => {
                Self::check_access(Self::CONFIG_DATA_BASE, addr, width);

                let offset = self.config_data_offset(addr);

                if let Some(dev) = self.get_device() {
                    dev.read().config_write(offset, value, width)
                }
            }
            0xC000..=0xCFFF => panic!(
                "PCI type2: write not supported port={:#x} width={} value={:#x}",
                addr, width, value
            ),
            _ => panic!("PCI: unexpected I/O write to port {:#x}", addr),
        }
    }

    fn generate_aml(&self) -> Option<Vec<u8>> {
        None
    }
}

/// Trait required for all virtual hardware components attached to the virtual PCI bus.
///
/// Implementors must provide handlers for configuration space reads and writes according
/// to standard PCI register space layouts (Standard Type 0 Configuration Headers).
pub trait VirtualPciDevice: Send + Sync {
    /// Reads a value from the device's PCI configuration space.
    ///
    /// # Parameters
    /// - `offset`: The register offset within PCI configuration space (e.g., `0x00` for Vendor ID/Device ID, `0x10` for BAR0).
    /// - `width`: Access width in bytes (1, 2, or 4).
    ///
    /// # Returns
    /// The zero-extended register value read from configuration space.
    fn config_read(&self, offset: u16, width: u8) -> u64;

    /// Writes a value to the device's PCI configuration space.
    ///
    /// # Parameters
    /// - `offset`: The register offset within PCI configuration space.
    /// - `value`: The payload value to write.
    /// - `width`: Access width in bytes (1, 2, or 4).
    fn config_write(&self, offset: u16, value: u64, width: u8);
}
