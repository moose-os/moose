//! Emulation of the legacy Intel 8259A Programmable Interrupt Controller (PIC).
//!
//! This module provides a dual 8259A PIC cascade setup (Master at I/O ports `0x20`-`0x21`,
//! Slave at I/O ports `0xA0`-`0xA1`).

use alloc::{sync::Arc, vec::Vec};

use spin::rwlock::RwLock;

use crate::driver::hv::reindeer::device::{DeviceResource, VirtualDevice};

/// Represents a pending PIC interrupt ready for delivery to a guest vCPU.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PicPending {
    /// The ISA IRQ line number (0..15).
    pub irq_line: u8,

    /// The remapped architectural interrupt vector (derived from `master_base` or `slave_base`).
    pub vector: u8,
}

/// Dual 8259A Programmable Interrupt Controller device.
///
/// Encapsulates the combined state of both Master (IRQs 0-7) and Slave (IRQs 8-15) controllers.
/// The slave PIC is cascaded to IRQ line 2 on the master PIC.
#[derive(Debug, Clone)]
pub struct ProgrammableInterruptControllerDevice {
    /// Interrupt Request Register (IRR): Bitmask of IRQs requested but not yet serviced.
    irr: u16,

    /// In-Service Register (ISR): Bitmask of IRQs currently being serviced by a CPU.
    isr: u16,

    /// Interrupt Mask Register (IMR): Bitmask of disabled IRQs (Master: bits 0-7, Slave: bits 8-15).
    imr: u16,

    /// Remapped vector base for Master PIC (configured via ICW2).
    master_base: u8,

    /// Remapped vector base for Slave PIC (configured via ICW2).
    slave_base: u8,

    /// Initialization state sequence step for Master PIC (0 = operational, 1 = ICW2, 2/3 = ICW3/4).
    init_step_master: u8,

    /// Initialization state sequence step for Slave PIC (0 = operational, 1 = ICW2, 2/3 = ICW3/4).
    init_step_slave: u8,

    /// Register selection for Master status reads via port `0x20` (0 = IRR, 1 = ISR).
    read_register_select_master: u8,

    /// Register selection for Slave status reads via port `0xA0` (0 = IRR, 1 = ISR).
    read_register_select_slave: u8,
}

impl ProgrammableInterruptControllerDevice {
    /// Constructs a new [`ProgrammableInterruptControllerDevice`] in default reset state.
    ///
    /// Initially, all IRQ lines are masked (`imr = 0xFFFF`), vector bases are unset (0),
    /// and both master/slave controllers are in operational mode (`init_step = 0`).
    pub fn new() -> Arc<RwLock<Self>> {
        Arc::new(RwLock::new(Self {
            irr: 0,
            isr: 0,
            imr: 0xFFFF,
            init_step_master: 0,
            init_step_slave: 0,
            master_base: 0,
            slave_base: 0,
            read_register_select_master: 0,
            read_register_select_slave: 0,
        }))
    }

    /// Handles an I/O port read targeting the PIC registers.
    pub fn handle_read(&self, io_port: u16) -> u64 {
        match io_port {
            0x21 => (self.imr & 0xFF) as u64,
            0xA1 => ((self.imr >> 8) & 0xFF) as u64,

            0x20 => self.read_status_register(self.read_register_select_master, true),
            0xA0 => self.read_status_register(self.read_register_select_slave, false),

            _ => 0,
        }
    }

    /// Handles an I/O port write targeting the PIC registers.
    pub fn handle_write(&mut self, io_port: u16, data: u64) {
        let val = data as u8;

        match io_port {
            0x20 | 0xA0 => {
                if val & 0x10 != 0 {
                    // ICW1 - Begin Initialization Sequence
                    if io_port == 0x20 {
                        self.init_step_master = 1;
                    } else {
                        self.init_step_slave = 1;
                    }
                } else if val & 0x08 == 0 {
                    // OCW2 - EOI (End of Interrupt) processing
                    if val & 0x20 != 0 {
                        self.handle_eoi(io_port == 0x20);
                    }
                } else {
                    // OCW3 - Register Read Selection (IRR vs ISR)
                    if val & 0x02 != 0 {
                        let sel = val & 0x01;
                        if io_port == 0x20 {
                            self.read_register_select_master = sel;
                        } else {
                            self.read_register_select_slave = sel;
                        }
                    }
                }
            }
            0x21 | 0xA1 => {
                let is_master = io_port == 0x21;

                let step = if is_master {
                    self.init_step_master
                } else {
                    self.init_step_slave
                };

                match step {
                    1 => {
                        // ICW2: Interrupt Vector Remapping
                        if is_master {
                            self.master_base = val & 0xF8;
                            self.init_step_master = 2;
                        } else {
                            self.slave_base = val & 0xF8;
                            self.init_step_slave = 2;
                        }
                    }
                    2 | 3 => {
                        // ICW3 / ICW4: Cascade configuration & Mode selection
                        if is_master {
                            self.init_step_master = 0;
                        } else {
                            self.init_step_slave = 0;
                        }
                    }
                    0 => {
                        // IMR: Update Interrupt Mask Register
                        if is_master {
                            self.imr = (self.imr & 0xFF00) | (val as u16);
                        } else {
                            self.imr = (self.imr & 0x00FF) | ((val as u16) << 8);
                        }
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }

    /// Converts an IRQ line index (0..15) into a 16-bit bitmask.
    fn irq_bit(irq: u8) -> u16 {
        assert!(irq < 16, "PIC irq_line must be 0..15, got {}", irq,);

        1u16 << irq
    }

    /// Asserts an IRQ line, setting the corresponding bit in the Interrupt Request Register (IRR).
    pub fn raise_irq(&mut self, irq: u8) {
        let mask = Self::irq_bit(irq);

        self.irr |= mask;
    }

    /// Evaluates whether an unmasked interrupt is pending and eligible for injection.
    pub fn check_pending(&self) -> Option<u8> {
        let unmasked_irr = self.irr & !self.imr;

        if unmasked_irr == 0 {
            return None;
        }

        let pending_irq = unmasked_irr.trailing_zeros() as u8;

        if self.isr != 0 {
            let current_irq = self.isr.trailing_zeros() as u8;

            if current_irq <= pending_irq {
                return None;
            }
        }

        Some(pending_irq)
    }

    /// Accepts the highest priority pending interrupt, moving it from IRR to ISR.
    ///
    /// # Returns
    /// * `Some((irq, vector))` - Tuple of the active IRQ line and remapped vector byte.
    /// * `None` - If no eligible interrupt is available.
    pub fn accept_interrupt(&mut self) -> Option<(u8, u8)> {
        if let Some(irq) = self.check_pending() {
            let mask = Self::irq_bit(irq);

            self.irr &= !mask;
            self.isr |= mask;

            if irq >= 8 {
                self.isr |= Self::irq_bit(2);
            }

            let vector = if irq < 8 {
                self.master_base.wrapping_add(irq)
            } else {
                self.slave_base.wrapping_add(irq - 8)
            };

            return Some((irq, vector));
        }

        None
    }

    /// Processes Non-Specific End-Of-Interrupt (EOI) commands issued by guest CPU drivers.
    ///
    /// Clears the active bit in the In-Service Register (ISR) for the highest priority IRQ.
    pub fn handle_eoi(&mut self, is_master_port: bool) {
        if is_master_port {
            let master_isr = (self.isr & 0xFF) as u8;

            if master_isr != 0 {
                let irq = master_isr.trailing_zeros() as u8;
                self.isr &= !Self::irq_bit(irq);
            }
        } else {
            let slave_isr = (self.isr >> 8) as u8;
            if slave_isr != 0 {
                let irq = slave_isr.trailing_zeros() as u8;
                self.isr &= !Self::irq_bit(irq + 8);
            }

            // Slave EOI automatically cascades an EOI to Master IRQ 2
            self.isr &= !Self::irq_bit(2);
        }
    }

    /// Inspects the next pending interrupt without modifying PIC internal state.
    pub fn peek_pending(&self) -> Option<PicPending> {
        let irq_line = self.check_pending()?;

        assert!(
            irq_line < 16,
            "check_pending returned {} (irr={:#x} imr={:#x} isr={:#x})",
            irq_line,
            self.irr,
            self.imr,
            self.isr
        );

        let vector = if irq_line < 8 {
            self.master_base.wrapping_add(irq_line)
        } else {
            self.slave_base.wrapping_add(irq_line - 8)
        };

        Some(PicPending { irq_line, vector })
    }

    /// Helper for status register read dispatching (IRR vs ISR).
    fn read_status_register(&self, select: u8, is_master: bool) -> u64 {
        let reg = if select == 0 { self.irr } else { self.isr };

        if is_master {
            (reg & 0xFF) as u64
        } else {
            ((reg >> 8) & 0xFF) as u64
        }
    }
}

impl VirtualDevice for ProgrammableInterruptControllerDevice {
    fn name(&self) -> &str {
        "8259 PIC"
    }

    fn get_resources(&self) -> Vec<DeviceResource> {
        alloc::vec![
            DeviceResource::IoPortRange {
                base: 0x20,
                size: 2,
            },
            DeviceResource::IoPortRange {
                base: 0xA0,
                size: 2,
            },
        ]
    }

    fn handle_io_read(&mut self, _cpu_id: usize, addr: u64, _width: u8) -> u64 {
        self.handle_read(addr as u16)
    }

    fn handle_io_write(&mut self, _cpu_id: usize, addr: u64, value: u64, _width: u8) {
        self.handle_write(addr as u16, value);
    }

    /// Generates the AML (ACPI Machine Language) byte stream representing the `PIC` device node in DSDT.
    fn generate_aml(&self) -> Option<Vec<u8>> {
        Some(crate::aml!(@ROOT
            Device ("PIC") {
                Name ("_HID", "PNP0000") // 8259-compatible PIC.
                Name ("_UID", 1)

                Name ("_CRS", ResourceTemplate() {
                    FixedIO (0x20, 1)
                    FixedIO (0xA0, 1)
                })

                Method ("_STA", 0) {
                    Return (0x0Fu8)
                }
            }
        ))
    }
}
