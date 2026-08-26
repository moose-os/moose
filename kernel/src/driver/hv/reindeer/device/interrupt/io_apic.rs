//! Virtual I/O Advanced Programmable Interrupt Controller (I/O APIC).
//!
//! The I/O APIC is a critical component in the x86 architecture responsible for
//! receiving hardware interrupts from devices and routing them to the appropriate
//! Local APIC(s) via the system bus.
//!
//! # Architecture and Interrupt Routing Diagram
//!
//! ```text
//! +------------------+       +------------------+
//! |                  |       |                  |
//! | External Device  |------>| External Device  | ... (Interrupt sources)
//! | (e.g. Timer/PIC) | IRQ0  | (e.g. VirtIO)    | IRQx
//! +------------------+       +------------------+
//!          |                          |
//!          +------------+-------------+
//!                       | (Hardware Pins / IRQ Lines)
//!                       v
//! +---------------------------------------------------+
//! |                   I/O APIC                        |
//! |                                                   |
//! | +-----------------------------------------------+ |
//! | | Redirection Table (typically 24 Entries)      | |
//! | | RTE[0]: Masked=0, Vector=0x20, Dest=0x00      | |
//! | | RTE[1]: Masked=1, Vector=0x00, Dest=0x00      | |
//! | | ...                                           | |
//! | | RTE[x]: Masked=0, Vector=0x35, Dest=0x01      | |
//! | +-----------------------------------------------+ |
//! +---------------------------------------------------+
//!                       |
//!                       | APIC Bus / System Bus (Message Signaled)
//!                       v
//! +---------------------------------------------------+
//! |                    System Bus                     |
//! +---------------------------------------------------+
//!             |                           |
//!             v                           v
//! +-----------------------+   +-----------------------+
//! |      Local APIC 0     |   |      Local APIC 1     |
//! | (APIC ID: 0x00)       |   | (APIC ID: 0x01)       |
//! +-----------------------+   +-----------------------+
//!             |                           |
//!             v                           v
//! +-----------------------+   +-----------------------+
//! |        CPU Core 0     |   |        CPU Core 1     |
//! +-----------------------+   +-----------------------+
//! ```
//!
//! # How the I/O APIC Works
//!
//! Historically, x86 systems used the 8259 PIC (Programmable Interrupt Controller),
//! which was tightly coupled to a single CPU. In modern multiprocessor architectures,
//! the APIC subsystem is split into two parts:
//! 1. I/O APIC (System-wide): Collects interrupt signals (IRQs) from hardware devices.
//! 2. Local APIC (Per-CPU): Sits on each CPU core, receives routed interrupts, and delivers them to the execution pipeline.
//!
//! The I/O APIC contains a Redirection Table with a fixed number of entries (usually 24).
//! Each physical pin on the I/O APIC corresponds to one Redirection Table Entry (RTE).
//! The Guest OS programs these entries via Memory-Mapped I/O (MMIO) to configure:
//! - Vector: Which interrupt number (0-255) the CPU should see.
//! - Destination: Which CPU (or group of CPUs) should receive the interrupt.
//! - Mask: Whether the interrupt is currently enabled or disabled.
//! - Delivery Mode & Trigger Mode: How the interrupt signal is interpreted (e.g., edge-triggered vs. level-triggered).

use alloc::{sync::Arc, vec::Vec};

use iced_x86::Register;
use spin::rwlock::RwLock;

use crate::driver::hv::reindeer::{
    device::{DeviceResource, VirtualDevice, interrupt::lapic::LocalApicDevice},
    guest::registers::CpuState,
};

/// Represents a 64-bit Redirection Table Entry (RTE) in the I/O APIC.
///
/// The 64-bit entry is split into two 32-bit registers (`lower` and `upper`).
///
/// ```text
///        63       56 55                                       32
///       +---------+-------------------------------------------+
/// UPPER | Dest    |                 Reserved                  |
///       | APIC ID |                 (must be 0)               |
///       +---------+-------------------------------------------+
///        31       17 16 15 14 13 12 11   10    8 7           0
///       +-----------+--+--+--+--+--+------+-----+-----------+
/// LOWER | Reserved  |M |T |R |P |D | Dest | Del | Interrupt |
///       | (must 0)  |  |  |  |  |  | Mode | Mode|  Vector   |
///       +-----------+--+--+--+--+--+------+-----+-----------+
/// ```
///
/// * **M** (Bit 16): Mask
/// * **T** (Bit 15): Trigger Mode
/// * **R** (Bit 14): Remote IRR
/// * **P** (Bit 13): Interrupt Pin Polarity
/// * **D** (Bit 12): Delivery Status
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
struct ApicRedirectionEntry {
    /// Lower 32 bits of the RTE.
    /// Contains the interrupt vector, delivery mode, destination mode,
    /// polarity, trigger mode, and the interrupt mask bit.
    lower: u32,

    /// Upper 32 bits of the RTE.
    /// Contains the destination APIC ID.
    upper: u32,
}

impl ApicRedirectionEntry {
    /// Checks if the interrupt is masked.
    ///
    /// Bit 16 in the lower 32 bits indicates whether the interrupt
    /// is masked (1) or unmasked/active (0). A masked interrupt
    /// will not be forwarded to the Local APIC.
    pub fn is_masked(&self) -> bool {
        (self.lower & (1 << 16)) != 0
    }

    /// Retrieves the interrupt vector.
    ///
    /// Bits 0-7 of the lower 32 bits determine the interrupt vector
    /// (e.g., `0x30`) that will be delivered to the Local APIC.
    pub fn vector(&self) -> u8 {
        (self.lower & 0xFF) as u8
    }

    /// Retrieves the Delivery Mode.
    ///
    /// Bits 8-10 of the lower 32 bits define how the interrupt is delivered.
    /// - `000`: Fixed
    /// - `001`: Lowest Priority
    /// - `010`: SMI
    /// - `100`: NMI
    /// - `101`: INIT
    /// - `111`: ExtINT
    pub fn delivery_mode(&self) -> u8 {
        ((self.lower >> 8) & 0x7) as u8
    }

    /// Retrieves the destination APIC ID.
    ///
    /// Bits 56-63 of the 64-bit RTE (which maps to bits 24-31 of the upper 32 bits)
    /// specify the physical or logical destination ID of the target Local APIC.
    pub fn destination_id(&self) -> u8 {
        (self.upper >> 24) as u8
    }

    /// Checks the Destination Mode.
    ///
    /// Bit 11 of the lower 32 bits defines the interpretation of the Destination ID:
    /// - `false`: Physical Mode (ID matches the exact Local APIC ID).
    /// - `true`: Logical Mode (ID is treated as a bitmask/logical target).
    pub fn destination_mode(&self) -> bool {
        (self.lower & (1 << 11)) != 0
    }
}

/// The main structure representing the state of the Virtual I/O APIC.
///
/// It maintains the Redirection Table, current register selections (via IOREGSEL),
/// and manages connections to the system's Local APICs and the legacy PIC.
pub struct VirtualIoApic {
    /// The currently selected I/O APIC register offset.
    /// Set by writing to the `IOREGSEL` (0x00) memory-mapped register.
    selected_register: u32,

    /// The APIC ID for this I/O APIC instance.
    id: u32,

    /// The Redirection Table containing 24 entries.
    /// Each entry corresponds to an interrupt pin (0-23).
    redirection_table: [ApicRedirectionEntry; 24],

    /// The I/O APIC Arbitration Register.
    arb_reg: u32,

    /// Reference to the system's Local APIC.
    /// Used to deliver interrupts to guest vCPUs via the Local APIC.
    lapics: Arc<RwLock<LocalApicDevice>>,
}

impl VirtualIoApic {
    /// Creates a new instance of the Virtual I/O APIC.
    ///
    /// The I/O APIC starts in a hardware reset state where all Redirection Table Entries
    /// are masked, and vectors are initialized to 0.
    pub fn new(lapics: Arc<RwLock<LocalApicDevice>>, id: u32) -> Arc<RwLock<Self>> {
        // Hardware reset: all RTEs masked, vector 0.
        let redirection_table = [ApicRedirectionEntry {
            lower: 1 << 16,
            upper: 0,
        }; 24];

        Arc::new(RwLock::new(VirtualIoApic {
            selected_register: 0,
            id,
            redirection_table,
            arb_reg: 0,
            lapics,
        }))
    }

    /// Returns `true` when the pin is masked or has no valid vector programmed.
    pub fn is_pin_masked(&self, pin: usize) -> bool {
        if pin >= self.redirection_table.len() {
            return true;
        }

        let entry = self.redirection_table[pin];
        entry.is_masked() || entry.vector() < 16
    }

    /// Handles a write to the internal register currently selected by `IOREGSEL`.
    ///
    /// This method is triggered when the guest OS writes to the `IOWIN` (0x10) MMIO offset.
    fn write_selected_register(&mut self, value: u32) {
        match self.selected_register {
            // Register 0x00: I/O APIC ID
            0x00 => self.id = (value >> 24) & 0x0F,

            // Register 0x01: I/O APIC Version (Read Only, ignore write)
            0x01 => {}

            // Register 0x02: I/O APIC Arbitration ID
            0x02 => self.arb_reg = value,

            // Registers 0x10 to 0x3F: Redirection Table Entries (RTE)
            // Each entry takes two 32-bit registers (lower and upper).
            reg @ 0x10..=0x3F => {
                let index = ((reg - 0x10) / 2) as usize;
                let is_high = (reg - 0x10) % 2 != 0;

                if index < self.redirection_table.len() {
                    if is_high {
                        self.redirection_table[index].upper = value;
                    } else {
                        self.redirection_table[index].lower = value;
                    }
                }
            }
            _ => panic!(
                "IOAPIC: Write to unknown register 0x{:x}",
                self.selected_register
            ),
        }
    }

    /// Handles a read from the internal register currently selected by `IOREGSEL`.
    ///
    /// This method is triggered when the guest OS reads from the `IOWIN` (0x10) MMIO offset.
    fn read_selected_register(&self) -> u32 {
        match self.selected_register {
            // Register 0x00: I/O APIC ID (shifted to upper bits)
            0x00 => (self.id & 0x0F) << 24,

            // Register 0x01: I/O APIC Version
            // Bits 0-7: Version (0x11), Bits 16-23: Max Redirection Entries (23, meaning 24 entries)
            0x01 => (23 << 16) | 0x11,

            // Register 0x02: I/O APIC Arbitration ID
            0x02 => self.arb_reg,

            // Registers 0x10 to 0x3F: Redirection Table Entries (RTE)
            reg @ 0x10..=0x3F => {
                let index = ((reg - 0x10) / 2) as usize;
                let is_high = (reg - 0x10) % 2 != 0;

                if index < self.redirection_table.len() {
                    if is_high {
                        self.redirection_table[index].upper
                    } else {
                        self.redirection_table[index].lower
                    }
                } else {
                    0
                }
            }
            _ => panic!("Read unknown register: 0x{:x}", self.selected_register),
        }
    }

    /// Triggers an interrupt on a specific I/O APIC pin.
    ///
    /// This is the primary interface used by other virtual devices
    /// to signal interrupts to the guest OS.
    pub fn set_irq(&mut self, pin: usize, level: bool) {
        // Drop out-of-bounds pins
        if pin >= self.redirection_table.len() {
            return;
        }

        let entry = self.redirection_table[pin];

        // Currently, only assertion/edge-trigger is simulated.
        if !level {
            return;
        }

        // If the guest has masked this interrupt, silently drop it.
        if entry.is_masked() {
            return;
        }

        let vector = entry.vector();
        if vector < 16 {
            // Vectors below 16 are reserved for CPU exceptions.
            log::debug!(
                "IOAPIC pin {}: vector {:#x} not programmed, dropping",
                pin,
                vector
            );

            return;
        }

        // Validate delivery mode.
        // Fixed (0) and Lowest Priority (1) are supported on Uniprocessor (UP) systems.
        let mode = entry.delivery_mode();
        if mode != 0 && mode != 1 {
            log::debug!(
                "IOAPIC pin {}: unsupported delivery mode {}, dropping",
                pin,
                mode
            );

            return;
        }

        let dest_id = entry.destination_id();

        // Forward the validated interrupt to the Local APIC
        self.lapics
            .read()
            .set_irq(dest_id as usize, vector as usize);
    }
}

impl VirtualDevice for VirtualIoApic {
    /// Returns the human-readable name of the device.
    fn name(&self) -> &str {
        "Virtual I/O APIC"
    }

    /// Intercepts and handles MMIO write requests to the I/O APIC address space.
    fn handle_mmio_write(&mut self, _cpu_id: usize, addr: u64, value: u64, _width: u8) {
        // Mask out the base address to get the local register offset.
        let offset = addr & 0xFF;

        match offset {
            // 0x00: IOREGSEL (I/O Register Select)
            // Guest selects which internal register it wants to access.
            0x00 => self.selected_register = value as u32,

            // 0x10: IOWIN (I/O Window)
            // Guest reads/writes data to the register previously selected by IOREGSEL.
            0x10 => self.write_selected_register(value as u32),

            _ => panic!("Unhandled write to I/O APIC: offset 0x{:x}", offset),
        }
    }

    /// Intercepts and handles MMIO read requests from the I/O APIC address space.
    fn handle_mmio_read(
        &mut self,
        _cpu_id: usize,
        addr: u64,
        _width: u8,
        _register: Register,
        _guest_registers: &mut CpuState,
    ) -> u64 {
        // Mask out the base address to get the local register offset.
        let offset = addr & 0xFF;

        match offset {
            // 0x00: IOREGSEL
            0x00 => self.selected_register as u64,

            // 0x10: IOWIN
            0x10 => self.read_selected_register() as u64,

            _ => panic!("Unhandled read from I/O APIC: offset 0x{:x}", offset),
        }
    }

    /// Declares the physical memory resources consumed by this device.
    ///
    /// The standard memory location for the PC I/O APIC is `0xFEC0_0000`.
    fn get_resources(&self) -> Vec<DeviceResource> {
        alloc::vec![DeviceResource::Mmio {
            base: 0xFEC0_0000,
            size: 0x1000
        }]
    }

    /// Generates the ACPI Machine Language (AML) definition for the device.
    fn generate_aml(&self) -> Option<Vec<u8>> {
        Some(crate::aml!(@ROOT
            Device ("IOAP") {
                Name ("_HID", "PNP0003")
                Name("_ADR", 0xFEC0_0000u32 as i32)

                Name ("_CRS", ResourceTemplate() {
                    Memory64(true, 0xFEC00000, 0xFEC01000, 0x1000)
                })

                Method ("_STA", 0) {
                    Return (0x0Fu8)
                }
            }
        ))
    }
}
