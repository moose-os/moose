use crate::arch::x86::asm::outb;
use crate::arch::x86::idt::{register_interrupt_handler, ExceptionFrame};
use crate::driver::pic::{PIC, PIC_1_OFFSET};
use alloc::boxed::Box;
use core::arch::asm;
use spin::RwLock;
use x86_64::instructions::interrupts::without_interrupts;

// CPU Timer
const CHANNEL0_DATA_PORT: u16 = 0x40;
// DRAM Refresh (xd)
#[allow(unused)]
const CHANNEL1_DATA_PORT: u16 = 0x41;
// Speaker
#[allow(unused)]
const CHANNEL2_DATA_PORT: u16 = 0x42;
const COMMAND_REGISTER: u16 = 0x43;
const PIT_TIMER: u8 = PIC_1_OFFSET;

pub static mut PIT: ProgrammableIntervalTimer = ProgrammableIntervalTimer::new();

pub struct ProgrammableIntervalTimer {
    ticks: RwLock<u32>,
    initialized: bool,
}

impl ProgrammableIntervalTimer {
    pub const fn new() -> Self {
        ProgrammableIntervalTimer {
            ticks: RwLock::new(0),
            initialized: false,
        }
    }

    pub fn initialize(&mut self) {
        x86_64::instructions::interrupts::disable();

        // +------+-----+-----+-----+---+-----+---+
        // |  7      6  |  5     4  | 3  2  1 | 0 |
        // +------+-----+-----+-----+---+-----+---+
        // | CHNL       | AM        | Mode    |BCD|
        // +------+-----+-----+-----+---+-----+---+
        //
        // CHNL - Channel (0/1/2)
        // AM - Access Mode
        //   0 - Latch count value command
        //   1 - Low-byte only
        //   2 - High-byte only
        //   3 - Low- and high-byte
        // Mode:
        //   0 - Interrupt on terminal count
        //   1 - Hardware Retriggerable one shot
        //   2 - Rate Generator
        //   3 - Square Wave Mode
        //   4 - Software Strobe
        //   5 - Hardware Strobe
        //
        // Configure CHANNEL0 to LH with Rate Generator mode (frequency divider)
        outb(COMMAND_REGISTER, 0b00110110);

        // We set divisor to 0xFFFF and count to 18 ticks - approx 1 ms
        let divisor = 0xFFFFu16;

        // PIT accepts only two one-byte transfers
        outb(CHANNEL0_DATA_PORT, (divisor & 0xFF) as u8);
        outb(CHANNEL0_DATA_PORT, (divisor >> 8) as u8);

        // Set timer interrupt handler
        register_interrupt_handler(
            PIT_TIMER,
            Box::new(|isf, _registers| pit_interrupt_handler(isf)),
        );

        x86_64::instructions::interrupts::enable();

        self.initialized = true;
    }

    pub fn wait_seconds(&mut self, seconds: u16) {
        if !self.initialized {
            panic!("PIT not initialized!");
        }

        *self.ticks.write() = 0;

        unsafe { PIC.unmask_interrupt(0) };

        // Spinlock :(
        loop {
            if without_interrupts(|| *self.ticks.read() >= (seconds * 18) as u32) {
                break;
            }

            unsafe { asm!("hlt") };
        }

        unsafe { PIC.mask_interrupt(0) };
    }

    // @TODO: Refactor
    pub fn wait_sixteen_millis(&mut self) {
        if !self.initialized {
            panic!("PIT not initialized!");
        }

        *self.ticks.write() = 0;

        unsafe { PIC.unmask_interrupt(0) };

        // Spinlock :(
        loop {
            if without_interrupts(|| *self.ticks.read() >= 3) {
                break;
            }

            unsafe { asm!("hlt") };
        }

        unsafe { PIC.mask_interrupt(0) };
    }

    fn interrupt_handler(&mut self) {
        *self.ticks.write() += 1;
    }
}

fn pit_interrupt_handler(_frame: &ExceptionFrame) {
    unsafe { PIT.interrupt_handler() }
    outb(0x20, 0x20);
}
