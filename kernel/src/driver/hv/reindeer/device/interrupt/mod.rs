//! Emulation subsystem for x86/x86_64 interrupt controllers.
//!
//! This subsystem handles, prioritizes, routes, and delivers hardware and software
//! interrupts to virtual CPU cores (vCPUs).
//!
//! # Interrupt Subsystem Architecture
//!
//! In x86 architecture, two main generations of interrupt controllers exist, which
//! a virtual machine monitor must emulate to ensure full compatibility—ranging
//! from early boot stages (Real Mode / BIOS) to modern symmetric multiprocessing (SMP) operating systems:
//!
//! 1. Legacy PIC (8259A): A cascaded dual-chip controller providing access to 16 IRQ lines (0–15).
//!    Primarily used during initial system boot. Its output line (`INT`) is connected to the
//!    LINT0 pin of the primary CPU's Local APIC (configured in `ExtINT` mode).
//! 2. Local APIC (LAPIC): An integrated controller embedded into each vCPU core. It handles
//!    interrupt vector delivery, system timers (Local Timer), Inter-Processor Interrupts (IPIs),
//!    and EOI/TPR registers.
//! 3. I/O APIC (IOAPIC): A global system controller that receives signals from I/O buses
//!    (e.g., PCI, ISA) and routes them to specific Local APICs based on its Redirection Table.
//!
//! # Interrupt Signal Flow Overview
//!
//! ```text
//!  +--------------------------------------------------------------------------+
//!  |                       x86 INTERRUPT SUBSYSTEM                            |
//!  |                                                                          |
//!  |  +---------------------+                 +----------------------------+  |
//!  |  |   PCI / MSI Calls   |                 |    Legacy Devices (ISA)    |  |
//!  |  +----------+----------+                 +--------------+-------------+  |
//!  |            |                                            |                |
//!  |            | (Direct MSI / GSI)                         | (IRQs 0-15)    |
//!  |            v                                            v                |
//!  |  +---------------------+                 +----------------------------+  |
//!  |  |       io_apic       |                 |            pic             |  |
//!  |  |    (System IO-APIC) |                 |     (Dual 8259A PIC)       |  |
//!  |  +----------+----------+                 +--------------+-------------+  |
//!  |            |                                            |                |
//!  |            | (MSI / Bus Vector)                         | (ExtINT/LINT0) |
//!  |            +--------------------+-----------------------+                |
//!  |                                 |                                        |
//!  |                                 v                                        |
//!  |                      +--------------------+                              |
//!  |                      |       lapic        | <--- IPI (Inter-Processor)   |
//!  |                      | (vCPU Local APIC)  |                              |
//!  |                      +----------+---------+                              |
//!  |                                 |                                        |
//!  |                                 | (Direct CPU Vector Delivery)           |
//!  |                                 v                                        |
//!  |                      +--------------------+                              |
//!  |                      |     vCPU Core      |                              |
//!  |                      +--------------------+                              |
//!  +--------------------------------------------------------------------------+
//! ```

pub mod io_apic;
pub mod lapic;
pub mod pic;
