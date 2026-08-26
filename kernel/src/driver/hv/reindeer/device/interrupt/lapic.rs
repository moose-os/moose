//! # Local Advanced Programmable Interrupt Controller (LAPIC)
//!
//! ## Architectural Overview
//! The Local APIC (LAPIC) is a core component of the x86/x86_64 system architecture, integrated into each
//! CPU core (Intel SDM Vol 3A, Chapter 10). It handles local interrupt routing, inter-processor interrupts (IPIs),
//! local timer events, performance monitoring counters, and internal error conditions.
//!
//! ## Interrupt Flow
//! Interrupts from all sources (I/O APIC, IPIs, LVT entries, timer) pass through an internal prioritization algorithm:
//!
//! 1. Interrupt Request Register (IRR): A 256-bit bitmap (8 x 32-bit registers) tracking pending, unacknowledged interrupts.
//! 2. In-Service Register (ISR): A 256-bit bitmap tracking interrupts currently being serviced by the guest CPU handler.
//! 3. Task Priority Register (TPR): Defines the current priority threshold set by the OS kernel.
//!
//! An interrupt vector V is divided into a Priority Class (P = V >> 4) and a Sub-priority (S = V % 16).
//! Vector injection into the vCPU occurs only when class of pending IRR is greater than TPR and ISR currently serviced by the vCPU.
//!
//! ## Hardware Pins: LINT0 and LINT1
//! Local APICs feature two local interrupt input pins:
//! - LINT0: Configured during early boot (Virtual Wire Mode) as `ExtINT`. Incoming lines from the legacy 8259 PIC bypass
//!   LAPIC prioritization and directly trigger an interrupt acknowledge (INTA) cycle. Alternatively, configured as `Fixed` or `NMI`.
//! - LINT1: Typically wired to Non-Maskable Interrupt (NMI) delivery lines or performance counters.
//!
//! ## LAPIC Timer Mechanics
//! Rather than spawning real-time OS timer threads (which incur high synchronization overhead), this emulator calculates
//! elapsed time deterministically by comparing the guest's Time Stamp Counter (`TSC`) cycles against configured APIC Divide values.

use alloc::{sync::Arc, vec::Vec};

use hashbrown::HashMap;
use spin::rwlock::RwLock;

use crate::driver::hv::reindeer::{
    device::{
        DeviceResource, VirtualDevice, interrupt::pic::ProgrammableInterruptControllerDevice,
    },
    guest::{clock::GuestClock, registers::CpuState},
};

/// Physical hardware state and register space for a single vCPU Local APIC instance.
///
/// Implements MMIO registers mapped relative to `base_address` (default: `0xFEE0_0000`).
pub struct LocalApicState {
    /// Local APIC Identifier Register (Offset `0x20`, bits 31..24). Contains unique APIC ID.
    pub id: u32,

    /// Local APIC Version Register (Offset `0x30`). Fixed hardware identification value (0x14 = Integrated APIC).
    pub version: u32,

    /// Base physical MMIO address assigned to this LAPIC (Default: `0xFEE0_0000`).
    pub base_address: u64,

    /// Reference to the legacy 8259 PIC required for Virtual Wire Mode EOI forwarding and ExtINT queries.
    pub pic: Arc<RwLock<ProgrammableInterruptControllerDevice>>,

    /// Spurious Interrupt Vector Register (SVR, Offset `0xF0`). Controls APIC enabling and spurious vector assignment.
    pub spurious_vector: u64,

    /// Task Priority Register (TPR, Offset `0x80`). Bits 7..4 define the minimum priority threshold for interrupt delivery.
    pub tpr: u64,

    /// LVT Error Register (Offset `0x370`). Configuration entry for internal APIC error interrupts.
    pub lvt_error: u64,

    /// Divide Configuration Register (DCR, Offset `0x3E0`). Dictates frequency scaling for the internal timer.
    pub divide_config_register: u64,

    /// Runtime status of the internal timer. `true` if active and ticking.
    pub timer_on: bool,

    /// Initial Count Register (Offset `0x380`). Seed value programmed by guest to start the timer.
    pub initial_count: u32,

    /// Monotonic guest TSC cycle count recorded when the current timer interval was initiated.
    pub start_guest_tsc: u64,

    /// Interrupt Request Register (IRR, Offsets `0x200..0x270`). 256-bit mask of vectors pending delivery.
    pub irr: [u32; 8],

    /// In-Service Register (ISR, Offsets `0x100..0x170`). 256-bit mask of vectors currently executing on the CPU core.
    pub isr: [u32; 8],

    /// Global software activation status computed from SVR bit 8.
    pub is_enabled: bool,

    /// Destination Format Register (DFR, Offset `0xE0`). Determines model for logical destination matching (Flat vs Cluster).
    pub dfr: u64,

    /// Logical Destination Register (LDR, Offset `0xD0`). Programmable logical target ID for logical IPI/IOAPIC routing.
    pub ldr: u64,

    /// Local Vector Table entry for LINT0 pin (Offset `0x350`).
    pub lvt_lint0: u32,

    /// Local Vector Table entry for LINT1 pin (Offset `0x360`).
    pub lvt_lint1: u32,

    /// Local Vector Table entry for LAPIC Timer (Offset `0x320`).
    pub lvt_timer: u32,

    /// Interrupt Command Register Low.
    pub icr_low: u32,

    /// Interrupt Command Register High.
    pub icr_high: u32,
}

/// Dispatched interrupt descriptor ready for injection into the guest VMCS before VM-entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveredInterrupt {
    /// Legacy 8259 PIC vector routed via LINT0 in Virtual Wire Mode (ExtINT).
    ExtInt {
        /// Physical IRQ input line (0..15) on the 8259 PIC hierarchy.
        irq_line: u8,

        /// Vector number queried from the PIC master/slave during INTA acknowledge.
        vector: u8,
    },

    /// Standard APIC vector queued in IRR (from I/O APIC, IPI, or timer).
    Lapic(u8),

    /// Fixed vector routed directly through LINT0 when LINT0 is configured in Fixed Delivery Mode.
    LapicLvtLint0 {
        /// Interrupt vector assigned within the LVT LINT0 register.
        lint0_vector: u8,

        /// Associated hardware IRQ line on the legacy controller.
        irq_line: u8,
    },
}

/// Central management controller handling MMIO access, timers, and arbitration across all vCPU Local APICs.
pub struct LocalApicDevice {
    /// Mapping of system CPU indexes to their respective thread-safe Local APIC state structures.
    state: HashMap<usize, Arc<RwLock<LocalApicState>>>,

    /// Shared guest clock abstraction used to map TSC cycles to high-resolution physical time.
    guest_clock: Arc<GuestClock>,

    /// Direct lookup table mapping raw APIC ID to internal vCPU index.
    apic_map: HashMap<usize, usize>,
}

impl LocalApicDevice {
    // Architectural MMIO Register Offsets (Intel SDM Vol 3A Table 10-1)

    /// Local APIC ID Register offset.
    const REG_ID: u64 = 0x20;

    /// Local APIC Version Register offset.
    const REG_VERSION: u64 = 0x30;

    /// Task Priority Register (TPR) offset.
    const REG_TPR: u64 = 0x80;

    /// End of Interrupt (EOI) Register offset.
    const REG_EOI: u64 = 0xB0;

    /// Logical Destination Register (LDR) offset.
    const REG_LDR: u64 = 0xD0;

    /// Destination Format Register (DFR) offset.
    const REG_DFR: u64 = 0xE0;

    /// Spurious Interrupt Vector Register (SVR) offset.
    const REG_SVR: u64 = 0xF0;

    /// Error Status Register (ESR) offset.
    const REG_ESR: u64 = 0x280;

    /// Interrupt Command Register Low (ICR0) offset.
    const REG_ICR_LOW: u64 = 0x300;

    /// Interrupt Command Register High (ICR1) offset.
    const REG_ICR_HIGH: u64 = 0x310;

    /// LVT Timer Register offset.
    const REG_LVT_TIMER: u64 = 0x320;

    /// LVT LINT0 Register offset.
    const REG_LVT_LINT0: u64 = 0x350;

    /// LVT LINT1 Register offset.
    const REG_LVT_LINT1: u64 = 0x360;

    /// LVT Error Register offset.
    const REG_LVT_ERROR: u64 = 0x370;

    /// Timer Initial Count Register offset.
    const REG_INITIAL_COUNT: u64 = 0x380;

    /// Timer Current Count Register offset.
    const REG_CURRENT_COUNT: u64 = 0x390;

    /// Timer Divide Configuration Register offset.
    const REG_DCR: u64 = 0x3E0;

    // Architectural Bitmasks

    /// LVT Mask Bit (Bit 16). When set, delivery of the corresponding local interrupt is suppressed.
    const LVT_MASKED: u32 = 1 << 16;

    /// LVT Timer Mode Bit (Bit 17). 0 = One-Shot mode, 1 = Periodic mode.
    const LVT_TIMER_PERIODIC: u32 = 1 << 17;

    /// Software APIC Enable Bit (Bit 8 in SVR). Toggles operational status of the LAPIC.
    const SVR_APIC_ENABLE: u64 = 1 << 8;

    /// ICR_LOW: Delivery Status (0 = Idle, 1 = Send Pending)
    const ICR_DELIVERY_STATUS_MASK: u32 = 1 << 12;

    /// Constructs a new `LocalApicDevice` coupled with the guest clock.
    pub fn new(guest_clock: Arc<GuestClock>) -> Arc<RwLock<Self>> {
        Arc::new(RwLock::new(Self {
            state: HashMap::new(),
            guest_clock,
            apic_map: HashMap::new(),
        }))
    }

    /// Allocates and resets the Local APIC register file for a specific CPU core.
    ///
    /// Sets initial register defaults matching post-RESET hardware state (SDM Vol 3A, Section 10.4.7.1).
    pub fn initialize(
        &mut self,
        cpu_id: usize,
        pic: Arc<RwLock<ProgrammableInterruptControllerDevice>>,
    ) {
        let state = LocalApicState {
            id: cpu_id as u32,
            version: 0x00050014, // Integrated 82489DX APIC with 6 LVTs
            base_address: 0xFEE0_0000,
            pic,
            spurious_vector: 0x10,
            tpr: 0,
            lvt_error: 1 << 16, // Masked upon power-on
            divide_config_register: 0,
            timer_on: false,
            initial_count: 0,
            start_guest_tsc: 0,
            irr: [0u32; 8],
            isr: [0u32; 8],
            is_enabled: false,
            dfr: 0xFFFF_FFFF, // Flat destination model by default
            ldr: 0xFFFF_FFFF,
            // LINT0 powers up unmasked and set to Delivery Mode 111b (ExtINT / Virtual Wire Mode)
            lvt_lint0: 0x0000_0700,
            lvt_lint1: 0x0001_0000, // LINT1 masked
            lvt_timer: 0x0001_0000, // Timer masked
            icr_high: 0,
            icr_low: 0,
        };

        let apic_id = state.id as usize;
        self.apic_map.insert(apic_id, cpu_id);

        self.state.insert(cpu_id, Arc::new(RwLock::new(state)));
    }

    /// Performs arbitration to find the highest-priority interrupt currently pending for injection.
    ///
    /// Priority check hierarchy:
    /// 1. Evaluates LINT0 pin (8259 ExtINT pass-through or LVT LINT0 Fixed mode).
    /// 2. Scans IRR for vectors higher than current TPR priority class and active ISR class.
    pub fn get_pending_interrupt(
        &self,
        cpu_id: usize,
        pic: &mut ProgrammableInterruptControllerDevice,
        guest_tpr: u64,
    ) -> Option<DeliveredInterrupt> {
        let state = self.state.get(&cpu_id).unwrap().read();

        // Effective processor priority threshold is the maximum of LAPIC TPR and guest architectural TPR
        let effective_tpr = state.tpr.max(guest_tpr);
        let processor_prio = (effective_tpr >> 4) as u8;
        let mut isr_prio = 0u8;

        // Find highest bit set in ISR to evaluate the currently executing interrupt class
        for i in (0..8).rev() {
            if state.isr[i] != 0 {
                // Compute absolute vector number from dword index and most significant bit position
                let bit = 31 - state.isr[i].leading_zeros();
                let isr_vec = (i * 32) as u8 + bit as u8;
                isr_prio = isr_vec >> 4;
                break;
            }
        }

        // If LINT0 is unmasked, hardware lines connected to the 8259 PIC bypass normal IRR queuing.
        if (state.lvt_lint0 & Self::LVT_MASKED) == 0 {
            let delivery_mode = (state.lvt_lint0 >> 8) & 0x7;

            if let Some(pending) = pic.peek_pending() {
                if delivery_mode == 0b111 {
                    // ExtINT Delivery Mode: Vector is fetched dynamically from PIC during INTA cycle
                    return Some(DeliveredInterrupt::ExtInt {
                        irq_line: pending.irq_line,
                        vector: pending.vector,
                    });
                } else if delivery_mode == 0b000 {
                    // Fixed Delivery Mode: Vector is explicitly defined in LVT LINT0 register
                    let lint0_vector = (state.lvt_lint0 & 0xFF) as u8;
                    let lint0_prio = lint0_vector >> 4;

                    // Vector must exceed both active task priority and in-service priority
                    if lint0_vector >= 16 && lint0_prio > processor_prio && lint0_prio > isr_prio {
                        return Some(DeliveredInterrupt::LapicLvtLint0 {
                            lint0_vector,
                            irq_line: pending.irq_line,
                        });
                    }
                }
            }
        }

        // Local APIC IRR query.
        if let Some(vector) = self.find_highest_pending_lapic_irq(&state, processor_prio, isr_prio)
        {
            return Some(DeliveredInterrupt::Lapic(vector));
        }

        None
    }

    /// Commits an interrupt for injection, transitioning vector state from requested (IRR) to active (ISR).
    ///
    /// Must be invoked immediately prior to VM-entry.
    pub fn commit_delivered_interrupt(
        &self,
        interrupt: DeliveredInterrupt,
        pic: &mut ProgrammableInterruptControllerDevice,
        cpu_id: usize,
    ) -> Option<u8> {
        match interrupt {
            DeliveredInterrupt::ExtInt { irq_line, vector } => {
                assert!(irq_line < 16, "ExtInt irq_line out of range: {}", irq_line);

                // Acknowledge IRQ line on legacy PIC master/slave controller
                if pic.accept_interrupt().is_none() {
                    log::warn!("ExtInt injection failed: PIC rejected interrupt acceptance");

                    None
                } else {
                    Some(vector)
                }
            }
            DeliveredInterrupt::LapicLvtLint0 {
                lint0_vector,
                irq_line,
            } => {
                assert!(irq_line < 16, "LINT0 irq_line out of range: {}", irq_line);

                // Acknowledge IRQ line on legacy PIC master/slave controller
                if pic.accept_interrupt().is_none() {
                    log::warn!("LINT0 injection failed: PIC rejected interrupt acceptance");

                    None
                } else {
                    Some(lint0_vector)
                }
            }
            DeliveredInterrupt::Lapic(vector) => {
                self.commit_interrupt(cpu_id, vector);

                Some(vector)
            }
        }
    }

    /// Moves a vector from the Interrupt Request Register (IRR) into the In-Service Register (ISR).
    pub fn commit_interrupt(&self, cpu_id: usize, vector: u8) {
        let mut state = self.state.get(&cpu_id).unwrap().write();

        // Calculate array dword index (0..7) and bit offset (0..31)
        let reg_idx = (vector / 32) as usize;
        let bit_idx = vector % 32;
        let mask = 1 << bit_idx;

        // Clear vector from IRR bitmap and set bit in active ISR bitmap
        state.irr[reg_idx] &= !mask;
        state.isr[reg_idx] |= mask;
    }

    /// Compares guest TSC progression against programmed LAPIC Timer parameters.
    ///
    /// Enqueues the timer vector into IRR upon expiration and handles auto-reload if in Periodic Mode.
    pub fn check_lapic_timer(&self, cpu_id: usize) {
        let mut state = self.state.get(&cpu_id).unwrap().write();

        // Bail out immediately if timer is uninitialized or disabled
        if !state.timer_on || state.initial_count == 0 || state.start_guest_tsc == 0 {
            return;
        }

        let vector = (state.lvt_timer & 0xFF) as u8;
        if vector < 16 || (state.lvt_timer & Self::LVT_MASKED) != 0 {
            state.timer_on = false;

            return;
        }

        // Calculate elapsed timer ticks based on guest TSC cycles and Divide Configuration Register
        let elapsed_lapic_ticks = self
            .guest_clock
            .lapic_ticks_elapsed(state.start_guest_tsc, state.divide_config_register);

        if elapsed_lapic_ticks >= state.initial_count as u64 {
            let is_periodic = (state.lvt_timer & Self::LVT_TIMER_PERIODIC) != 0;

            if is_periodic {
                // Re-arm baseline TSC stamp for next period
                state.start_guest_tsc = self.guest_clock.now_tsc();
            } else {
                // One-shot mode: clear initial count and stop timer
                state.initial_count = 0;
                state.timer_on = false;
            }

            drop(state);

            self.set_irq(cpu_id, vector as usize);
        }
    }

    /// Scans the IRR bit matrix to locate the highest pending vector exceeding processor priority thresholds.
    fn find_highest_pending_lapic_irq(
        &self,
        state: &LocalApicState,
        processor_prio: u8,
        isr_prio: u8,
    ) -> Option<u8> {
        let mut highest_irr_vector = None;

        // Iterate backwards from highest dword (vectors 224..255) down to lowest (vectors 0..31)
        for i in (0..8).rev() {
            if state.irr[i] != 0 {
                let bit = 31 - state.irr[i].leading_zeros();
                highest_irr_vector = Some((i * 32) as u8 + bit as u8);
                break;
            }
        }

        let pending_vec = highest_irr_vector?;
        let pending_prio = pending_vec >> 4;

        // Delivery constraint: Vector Priority Class must strictly exceed both Processor Priority and ISR Priority
        if pending_prio > processor_prio && pending_prio > isr_prio {
            Some(pending_vec)
        } else {
            None
        }
    }

    /// Maps a hardware/bus APIC target ID to the internal zero-based vCPU index.
    fn resolve_destination(&self, apic_id: usize) -> Option<usize> {
        self.apic_map
            .get(&apic_id)
            .copied()
            .or_else(|| self.state.contains_key(&apic_id).then_some(apic_id))
            .or_else(|| self.state.keys().next().copied())
    }

    /// Latches an interrupt vector into the IRR pending bitmap.
    pub fn set_irq(&self, apic_id: usize, vector: usize) {
        if let Some(cpu_id) = self.resolve_destination(apic_id) {
            let Some(state) = self.state.get(&cpu_id) else {
                return;
            };

            // Vectors 0..15 are reserved for system exceptions and are invalid for APIC routing
            if vector < 16 {
                return;
            }

            let mut state = state.write();
            let reg_idx = vector / 32;
            let bit_idx = vector % 32;
            let mask = 1 << bit_idx;

            // Recover from lost EOI scenarios: if vector is still set in ISR but IRR was cleared, clear ISR
            if (state.isr[reg_idx] & mask) != 0 && (state.irr[reg_idx] & mask) == 0 {
                state.isr[reg_idx] &= !mask;
            }

            // Latch vector into IRR
            state.irr[reg_idx] |= mask;
        }
    }

    pub fn dispatch_ipi(&self, apic_id: usize, dest_shorthand: u8, delivery_mode: u8, vector: u8) {
        match dest_shorthand {
            // Destination: other vCPU.
            0 => unimplemented!(),

            // Destination: self.
            1 => self.inject_ipi(apic_id, delivery_mode, vector),

            // Destination: all including self.
            2 => self.inject_ipi(apic_id, delivery_mode, vector),

            // Destination: all excluding self.
            3 => unimplemented!(),

            _ => unimplemented!(),
        }
    }

    fn inject_ipi(&self, apic_id: usize, delivery_mode: u8, vector: u8) {
        match delivery_mode {
            0 => {
                // Fixed Mode
                if vector >= 16 {
                    self.set_irq(apic_id, vector as usize);
                }
            }
            _ => panic!("Unsupported IPI delivery mode: {}", delivery_mode),
        }
    }
}

impl VirtualDevice for LocalApicDevice {
    fn name(&self) -> &str {
        "LocalAPIC"
    }

    fn get_resources(&self) -> Vec<DeviceResource> {
        alloc::vec![DeviceResource::Mmio {
            base: 0xFEE0_0000,
            size: 0x1000 // One 4 KiB page.
        }]
    }

    /// Handles MMIO read requests directed to LAPIC register space (`base_address + offset`).
    fn handle_mmio_read(
        &mut self,
        cpu_id: usize,
        addr: u64,
        _width: u8,
        _register: iced_x86::Register,
        _guest_registers: &mut CpuState,
    ) -> u64 {
        let state = self.state.get(&cpu_id).unwrap().read();
        let offset = addr - state.base_address;

        match offset {
            Self::REG_ID => (cpu_id as u64) << 24,
            Self::REG_VERSION => state.version as u64,
            Self::REG_SVR => state.spurious_vector,
            Self::REG_TPR => state.tpr,
            Self::REG_DFR => state.dfr,
            Self::REG_LDR => state.ldr,
            Self::REG_LVT_LINT0 => state.lvt_lint0 as u64,
            Self::REG_LVT_LINT1 => state.lvt_lint1 as u64,
            Self::REG_LVT_TIMER => state.lvt_timer as u64,
            Self::REG_ESR => 0, // Error status returns 0 when no internal errors present
            Self::REG_DCR => state.divide_config_register,

            // In-Service Register Window (0x100..0x170, 8 dwords spaced 16 bytes apart)
            0x100..=0x170 => {
                let index = ((offset - 0x100) / 0x10) as usize;
                state.isr.get(index).map_or(0, |&v| v as u64)
            }

            // Interrupt Request Register Window (0x200..0x270, 8 dwords spaced 16 bytes apart)
            0x200..=0x270 => {
                let index = ((offset - 0x200) / 0x10) as usize;
                state.irr.get(index).map_or(0, |&v| v as u64)
            }

            Self::REG_ICR_LOW => (state.icr_low & !Self::ICR_DELIVERY_STATUS_MASK) as u64,
            Self::REG_ICR_HIGH => state.icr_high as u64,

            // Real-time calculation of decremented Current Count Register
            Self::REG_CURRENT_COUNT => {
                if state.initial_count == 0 || state.start_guest_tsc == 0 {
                    0
                } else {
                    let elapsed = self
                        .guest_clock
                        .lapic_ticks_elapsed(state.start_guest_tsc, state.divide_config_register);
                    let count = state.initial_count as u64;

                    let remaining = if elapsed >= count {
                        if (state.lvt_timer & Self::LVT_TIMER_PERIODIC) != 0 {
                            count - (elapsed % count)
                        } else {
                            0
                        }
                    } else {
                        count - elapsed
                    };

                    remaining & 0xFFFF_FFFF
                }
            }

            _ => panic!(
                "Unhandled LAPIC MMIO Read from physical address 0x{:x}",
                addr
            ),
        }
    }

    /// Handles MMIO write requests directed to LAPIC register space (`base_address + offset`).
    fn handle_mmio_write(&mut self, cpu_id: usize, addr: u64, value: u64, _width: u8) {
        let mut state = self.state.get(&cpu_id).unwrap().write();
        let offset = addr - state.base_address;

        match offset {
            Self::REG_SVR => {
                state.spurious_vector = value;
                state.is_enabled = (value & Self::SVR_APIC_ENABLE) != 0;
                log::debug!(
                    "LAPIC CPU {}: SVR updated to {:#x} (Software Enabled={})",
                    cpu_id,
                    state.spurious_vector,
                    state.is_enabled
                );
            }

            Self::REG_EOI => {
                // End Of Interrupt (EOI) write: Clear highest priority bit currently active in ISR
                for i in (0..8).rev() {
                    if state.isr[i] != 0 {
                        let highest_bit = 31 - state.isr[i].leading_zeros();
                        state.isr[i] &= !(1 << highest_bit);
                        break;
                    }
                }

                // Forward EOI to legacy 8259 PIC if LINT0 is configured in Virtual Wire Mode (ExtINT)
                let lint0 = state.lvt_lint0;
                if (lint0 & Self::LVT_MASKED) == 0 && ((lint0 >> 8) & 0x7) == 0b111 {
                    state.pic.write().handle_eoi(true);
                }
            }

            Self::REG_ICR_HIGH => {
                state.icr_high = value as u32;
            }
            Self::REG_ICR_LOW => {
                state.icr_low = value as u32 & !Self::ICR_DELIVERY_STATUS_MASK;

                let vector = (value & 0xFF) as u8;
                let delivery_mode = (value >> 8) & 0x07;
                let dest_shorthand = (value >> 18) & 0x03;

                let apic_id = state.id;

                drop(state);

                self.dispatch_ipi(
                    apic_id as usize,
                    dest_shorthand as u8,
                    delivery_mode as u8,
                    vector,
                );
            }

            Self::REG_LVT_ERROR => {
                state.lvt_error = (value as u32 & 0x100FF) as u64;
            }

            Self::REG_DCR => {
                // Mask non-architectural bits (only bits 0, 1, and 3 control division ratio)
                state.divide_config_register = (value as u32 & 0b1011) as u64;
            }

            Self::REG_INITIAL_COUNT => {
                state.initial_count = value as u32;
                state.start_guest_tsc = self.guest_clock.now_tsc();
                state.timer_on =
                    state.initial_count != 0 && (state.lvt_timer & Self::LVT_MASKED) == 0;
            }

            Self::REG_LVT_TIMER => {
                state.lvt_timer = value as u32;
                let is_masked = (value & Self::LVT_MASKED as u64) != 0;
                let vector = (value & 0xFF) as u8;

                if is_masked || vector < 16 {
                    state.timer_on = false;
                } else if state.initial_count != 0 {
                    state.timer_on = true;
                    state.start_guest_tsc = self.guest_clock.now_tsc();
                }
            }

            Self::REG_LDR => state.ldr = value,
            Self::REG_DFR => state.dfr = value,
            Self::REG_TPR => state.tpr = value,

            Self::REG_LVT_LINT0 | Self::REG_LVT_LINT1 => {
                // Apply LVT Mask: Vector (0..7), Delivery Mode (8..10), Polarity (13), Remote IRR (14), Trigger (15), Mask (16)
                let mask = 0x117FF;
                let val = (value as u32) & mask;
                if offset == Self::REG_LVT_LINT0 {
                    state.lvt_lint0 = val;
                } else {
                    state.lvt_lint1 = val;
                }
            }

            Self::REG_ESR => {} // Writing any value to ESR resets internal error latches

            _ => panic!(
                "Unhandled LAPIC MMIO Write to address 0x{:x} (value=0x{:x})",
                addr, value
            ),
        }
    }

    fn generate_aml(&self) -> Option<Vec<u8>> {
        None
    }
}
