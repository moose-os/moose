//! PIT-based TSC calibration for the kernel clock subsystem.
//!
//! Uses the legacy 8254 Programmable Interval Timer (channel 2) as a fixed
//! ~1.193182 MHz reference to measure how many TSC ticks elapse over a 10 ms
//! window. The result is scaled to an estimated TSC frequency in Hz and fed
//! into [`ClockSource`] selection during system clock initialization.
//!
//! Assumed present on IBM-PC compatible hardware and used as the lowest-priority
//! fallback when HPET or hypervisor clocks are unavailable. The PIT is used only
//! for one-shot calibration at boot, not for runtime timekeeping.
//!
use core::arch::x86_64::_rdtsc;

use crate::{
    arch::x86::asm::{inb, outb},
    driver::clock::ClockSource,
};

/// PIT Channel 2 frequency is 1.193182 MHz.
/// A count of 11932 ticks yields a window of exactly ~10ms (11932 / 1193182 = 0.01s).
const TARGET_COUNT: u16 = 11932;

/// PIT Channel 0 Data Port.
pub const PIT_CHANNEL_0_DATA: u16 = 0x40;
/// PIT Channel 1 Data Port.
pub const PIT_CHANNEL_1_DATA: u16 = 0x41;
/// PIT Channel 2 Data Port.
pub const PIT_CHANNEL_2_DATA: u16 = 0x42;
/// PIT Mode Command Register.
pub const PIT_COMMAND_REGISTER: u16 = 0x43;

/// System Control Port B.
pub const SYSTEM_CONTROL_PORT_B: u16 = 0x61;

pub struct PitTimer {}

impl ClockSource for PitTimer {
    /// Checks if the PIT is present. For x86_64 IBM-PC compatible systems,
    /// the PIT is legacy hardware and always assumed to be present.
    fn present(&self) -> bool {
        true
    }

    /// Measures the number of TSC ticks that elapse during a 10ms window using PIT Channel 2.
    fn measure_tsc_ticks(&self) -> u64 {
        unsafe {
            // Enable Speaker Gate (bit 0) to allow Channel 2 to count. Also ensure bit 1 is set, to prevent
            // speaker from generating noise.
            let port_61 = inb(SYSTEM_CONTROL_PORT_B);
            outb(SYSTEM_CONTROL_PORT_B, (port_61 & 0xFD) | 1);

            // Configure PIT: Channel 2, access mode LSB/MSB, operating mode 0 (Interrupt on Terminal Count).
            outb(PIT_COMMAND_REGISTER, 0xB0);

            // Load the 16-bit countdown value into Channel 2 data port.
            outb(PIT_CHANNEL_2_DATA, (TARGET_COUNT & 0xFF) as u8); // Low byte
            outb(PIT_CHANNEL_2_DATA, (TARGET_COUNT >> 8) as u8); // High byte

            // Capture the starting point of the TSC.
            let tsc_start = _rdtsc();

            // Busy-loop until the PIT finishes countdown.
            loop {
                if (inb(SYSTEM_CONTROL_PORT_B) & 0x20) != 0 {
                    break;
                }

                core::hint::spin_loop();
            }

            // Capture the ending TSC value immediately after the 10ms window closes.
            let tsc_end = _rdtsc();

            // Disable PIT Channel 2.
            outb(SYSTEM_CONTROL_PORT_B, port_61 & 0xFC);

            // Calculate total elapsed TSC cycles
            let delta_tsc = tsc_end - tsc_start;

            delta_tsc * 100
        }
    }
}
