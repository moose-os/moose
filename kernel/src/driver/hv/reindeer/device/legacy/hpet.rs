//! Virtual High Precision Event Timer (HPET) Device Model.
//!
//! The HPET exposes a 64-bit free-running main counter and three comparators
//! through an MMIO register block. Counter values are calculated on-demand from
//! the guest TSC provided by [`GuestClock`].
use alloc::{sync::Arc, vec::Vec};

use iced_x86::Register;
use spin::rwlock::RwLock;

use crate::driver::hv::reindeer::{
    device::{DeviceResource, VirtualDevice, interrupt::io_apic::VirtualIoApic},
    guest::{clock::GuestClock, registers::CpuState},
};

/// Standard physical base address of the HPET MMIO register block.
pub const HPET_MMIO_BASE: u64 = 0xFED0_0000;

/// Size of the HPET MMIO register block.
const HPET_MMIO_SIZE: u64 = 0x400;

/// Virtual HPET main counter frequency in Hertz.
const HPET_HZ: u64 = 10_000_000;

/// Main counter clock period in femtoseconds.
const HPET_PERIOD_FS: u64 = 100_000_000;

/// Number of comparators exposed by this HPET block.
///
/// The IA-PC HPET specification requires at least 3 timers; guests (notably
/// Windows) may refuse to enumerate a block that advertises fewer.
const NUM_TIMERS: usize = 3;

/// `NUM_TIM_CAP` field value: the index of the last timer, i.e. `NUM_TIMERS - 1`.
const NUM_TIM_CAP: u64 = (NUM_TIMERS as u64 - 1) << 8;

/// General Capabilities and ID register value.
///
/// Advertises three 64-bit timers and Intel vendor ID `0x8086`.
const GENERAL_CAPABILITIES: u64 = (HPET_PERIOD_FS << 32) | 0x8086_2000 | NUM_TIM_CAP | 0x10;

const GENERAL_ENABLE: u64 = 1;
const TIMER_INTERRUPT_TYPE: u64 = 1 << 1;
const TIMER_INTERRUPT_ENABLE: u64 = 1 << 2;
const TIMER_PERIODIC: u64 = 1 << 3;
const TIMER_PERIODIC_CAPABLE: u64 = 1 << 4;
const TIMER_SIZE_CAPABLE: u64 = 1 << 5;
const TIMER_32_BIT_MODE: u64 = 1 << 8;
const TIMER_ROUTE_SHIFT: u64 = 9;
const TIMER_ROUTE_MASK: u64 = 0x1F << TIMER_ROUTE_SHIFT;
const TIMER_ROUTE_CAPABILITIES: u64 = 0x00FF_FFFF << 32;
const TIMER_WRITABLE_MASK: u64 = TIMER_INTERRUPT_TYPE
    | TIMER_INTERRUPT_ENABLE
    | TIMER_PERIODIC
    | TIMER_32_BIT_MODE
    | TIMER_ROUTE_MASK;

/// Byte offset of the first per-timer register block (Timer 0 Config).
const TIMER_BLOCK_BASE: u64 = 0x100;

/// Size in bytes of each per-timer register block (config, comparator, FSB route).
const TIMER_BLOCK_STRIDE: u64 = 0x20;

/// Per-timer mutable state for a single comparator.
#[derive(Clone, Copy)]
struct TimerState {
    /// Configuration and capability register for this specific timer.
    config: u64,

    /// The match value that triggers an interrupt when reached by the main counter.
    comparator: u64,

    /// The interval value added to the comparator in periodic mode.
    period: u64,

    /// Internal flag indicating whether a timer is armed.
    armed: bool,
}

impl TimerState {
    const fn new() -> Self {
        Self {
            config: 0,
            comparator: 0,
            period: 0,
            armed: false,
        }
    }
}

/// Mutable state of the virtual HPET register block.
struct HpetState {
    /// General Configuration Register (controls overall HPET operation).
    general_config: u64,

    /// The base value of the 64-bit main up-counter.
    main_counter: u64,

    /// The guest clock time (e.g., TSC) when the counter was last enabled.
    counter_started_at: u64,

    /// General Interrupt Status Register (indicates which timers triggered an interrupt).
    interrupt_status: u64,

    /// State of all individual comparators/timers.
    timers: [TimerState; NUM_TIMERS],
}

impl HpetState {
    fn new(now: u64) -> Self {
        Self {
            general_config: 0,
            main_counter: 0,
            counter_started_at: now,
            interrupt_status: 0,
            timers: [TimerState::new(); NUM_TIMERS],
        }
    }
}

/// Virtual HPET with three periodic-capable comparators.
pub struct VirtualHpet {
    /// Internal mutable state of the HPET registers and timers.
    state: RwLock<HpetState>,

    /// Connection to the I/O APIC for delivering interrupts to the guest.
    io_apic: Arc<RwLock<VirtualIoApic>>,

    /// Source of guest time used to calculate on-demand counter values.
    guest_clock: Arc<GuestClock>,
}

impl VirtualHpet {
    /// Creates a new HPET instance connected to the guest I/O APIC.
    pub fn new(
        io_apic: Arc<RwLock<VirtualIoApic>>,
        guest_clock: Arc<GuestClock>,
    ) -> Arc<RwLock<Self>> {
        Arc::new(RwLock::new(Self {
            state: RwLock::new(HpetState::new(guest_clock.now_tsc())),
            io_apic,
            guest_clock,
        }))
    }

    /// Calculates the current main counter value from elapsed guest TSC ticks.
    fn current_counter(&self, state: &HpetState) -> u64 {
        if state.general_config & GENERAL_ENABLE == 0 {
            return state.main_counter;
        }

        let elapsed_tsc = self
            .guest_clock
            .now_tsc()
            .wrapping_sub(state.counter_started_at);
        let elapsed_ticks =
            (elapsed_tsc as u128 * HPET_HZ as u128) / self.guest_clock.tsc_hz() as u128;

        state.main_counter.wrapping_add(elapsed_ticks as u64)
    }

    fn timer_config(&self, timer: &TimerState) -> u64 {
        timer.config | TIMER_PERIODIC_CAPABLE | TIMER_SIZE_CAPABLE | TIMER_ROUTE_CAPABILITIES
    }

    /// Maps an offset in `[TIMER_BLOCK_BASE, TIMER_BLOCK_BASE + NUM_TIMERS * STRIDE)`
    /// to a `(timer index, register-within-block)` pair, if it falls in that range.
    fn decode_timer_offset(offset: u64) -> Option<(usize, u64)> {
        if offset < TIMER_BLOCK_BASE {
            return None;
        }

        let rel = offset - TIMER_BLOCK_BASE;
        let index = (rel / TIMER_BLOCK_STRIDE) as usize;

        if index >= NUM_TIMERS {
            return None;
        }

        Some((index, rel % TIMER_BLOCK_STRIDE))
    }

    fn read_register(&self, offset: u64) -> u64 {
        let state = self.state.read();

        match offset {
            0x000 => GENERAL_CAPABILITIES,
            0x010 => state.general_config,
            0x020 => state.interrupt_status,
            0x0F0 => self.current_counter(&state),
            _ => match Self::decode_timer_offset(offset) {
                Some((index, 0x00)) => self.timer_config(&state.timers[index]),
                Some((index, 0x08)) => state.timers[index].comparator,
                Some((_, 0x10)) => 0,
                _ => 0,
            },
        }
    }

    fn access_mask(width: u8) -> u64 {
        match width {
            1 => u8::MAX as u64,
            2 => u16::MAX as u64,
            4 => u32::MAX as u64,
            8 => u64::MAX,
            _ => 0,
        }
    }

    fn write_register(&self, offset: u64, value: u64, width: u8) {
        let register = offset & !7;
        let shift = (offset & 7) * 8;
        let access_mask = Self::access_mask(width) << shift;
        let value = value << shift;
        let now = self.guest_clock.now_tsc();
        let mut state = self.state.write();

        match register {
            0x010 => {
                let current_counter = self.current_counter(&state);

                let was_enabled = state.general_config & GENERAL_ENABLE != 0;
                let new_config = (state.general_config & !access_mask) | (value & access_mask);
                let enabled = new_config & GENERAL_ENABLE != 0;

                if was_enabled != enabled {
                    state.main_counter = current_counter;
                    state.counter_started_at = now;
                }

                state.general_config = new_config & GENERAL_ENABLE;
            }
            0x020 => {
                // Interrupt Status is write-one-to-clear, one bit per timer.
                state.interrupt_status &= !(value & access_mask);
            }
            0x0F0 => {
                let current = self.current_counter(&state);

                state.main_counter = (current & !access_mask) | (value & access_mask);
                state.counter_started_at = now;
            }
            _ => {
                if let Some((index, reg)) = Self::decode_timer_offset(register) {
                    let timer = &mut state.timers[index];

                    match reg {
                        0x00 => {
                            let writable_mask = access_mask & TIMER_WRITABLE_MASK;
                            timer.config =
                                (timer.config & !writable_mask) | (value & writable_mask);
                        }
                        0x08 => {
                            let comparator =
                                (timer.comparator & !access_mask) | (value & access_mask);

                            timer.comparator = if timer.config & TIMER_32_BIT_MODE != 0 {
                                comparator & u32::MAX as u64
                            } else {
                                comparator
                            };

                            timer.period = if timer.config & TIMER_PERIODIC != 0 {
                                timer.comparator.max(1)
                            } else {
                                0
                            };

                            timer.armed = true;
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    /// Checks every comparator and delivers an interrupt for each one that expires.
    ///
    /// Returns `true` if at least one timer fired.
    pub fn check_timer(&self) -> bool {
        let mut fired_routes: Vec<usize> = Vec::new();

        {
            let mut state = self.state.write();
            if state.general_config & GENERAL_ENABLE == 0 {
                return false;
            }

            let counter = self.current_counter(&state);

            for index in 0..NUM_TIMERS {
                let timer = &mut state.timers[index];
                if timer.config & TIMER_INTERRUPT_ENABLE == 0 || !timer.armed {
                    continue;
                }

                if counter < timer.comparator {
                    continue;
                }

                state.interrupt_status |= 1 << index;
                let timer = &mut state.timers[index];

                if timer.config & TIMER_PERIODIC != 0 && timer.period != 0 {
                    let elapsed = counter.saturating_sub(timer.comparator);
                    let periods = elapsed / timer.period + 1;

                    timer.comparator = timer
                        .comparator
                        .wrapping_add(periods.saturating_mul(timer.period));
                } else {
                    timer.armed = false;
                }

                let route = ((timer.config & TIMER_ROUTE_MASK) >> TIMER_ROUTE_SHIFT) as usize;

                fired_routes.push(route);
            }
        }

        if fired_routes.is_empty() {
            return false;
        }

        for route in fired_routes {
            self.io_apic.write().set_irq(route, true);
        }

        true
    }
}

impl VirtualDevice for VirtualHpet {
    /// Returns the human-readable device name.
    fn name(&self) -> &str {
        "High Precision Event Timer"
    }

    /// Claims the standard HPET MMIO register range.
    fn get_resources(&self) -> Vec<DeviceResource> {
        alloc::vec![DeviceResource::Mmio {
            base: HPET_MMIO_BASE,
            size: HPET_MMIO_SIZE,
        }]
    }

    /// Handles guest reads from the HPET MMIO register block.
    fn handle_mmio_read(
        &mut self,
        _cpu_id: usize,
        addr: u64,
        width: u8,
        _register: Register,
        _guest_registers: &mut CpuState,
    ) -> u64 {
        let offset = addr.saturating_sub(HPET_MMIO_BASE);
        let shift = (offset & 7) * 8;

        (self.read_register(offset & !7) >> shift) & Self::access_mask(width)
    }

    /// Handles guest writes to the HPET MMIO register block.
    fn handle_mmio_write(&mut self, _cpu_id: usize, addr: u64, value: u64, width: u8) {
        let offset = addr.saturating_sub(HPET_MMIO_BASE);

        self.write_register(offset, value, width);

        let _ = self.check_timer();
    }

    fn generate_aml(&self) -> Option<Vec<u8>> {
        None
    }
}
