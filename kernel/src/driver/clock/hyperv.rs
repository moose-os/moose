//! Hyper-V reference-counter TSC calibration for the kernel clock subsystem.
//!
//! When running under Hyper-V, reads the guest TSC reference MSR
//! (`HV_X64_MSR_TIME_REF_COUNT`, fixed 10 MHz) and uses it as a stable timebase
//! to measure how many TSC ticks elapse over a 10 ms window. The result is scaled
//! to an estimated TSC frequency in Hz and fed into [`ClockSource`] selection
//! during system clock initialization.
//!
//! Used only for one-shot calibration at boot; the MSR is not polled at runtime.

use core::{arch::x86_64::_rdtsc, hint};

use raw_cpuid::{CpuId, Hypervisor};
use x86_64::registers::model_specific::Msr;

use crate::driver::clock::ClockSource;

/// Hyper-V Guest TSC Reference MSR. Ticks at a constant frequency of 10 MHz.
const HV_X64_MSR_TIME_REF_COUNT: u32 = 0x40000020;

/// The constant frequency of the Hyper-V reference counter (10 MHz).
const HV_REF_CLOCK_FREQUENCY_HZ: u64 = 10_000_000;

/// To measure a 10ms (0.01s) window, we need to wait for exactly 100,000 ticks.
const TARGET_TICKS: u64 = 100_000;

pub struct HyperVReferenceCounter {}

impl ClockSource for HyperVReferenceCounter {
    /// Checks if running under a Hyper-V hypervisor.
    fn is_present(&self) -> bool {
        CpuId::new().get_hypervisor_info().unwrap().identify() == Hypervisor::HyperV
    }

    /// Measures the number of TSC ticks that elapse during a 10ms window using Hyper-V Reference Counter MSR.
    fn measure_tsc_ticks(&self) -> u64 {
        unsafe {
            let msr = Msr::new(HV_X64_MSR_TIME_REF_COUNT);

            // Read the current reference counter and spin until it increments.
            // This guarantees we capture tsc_start precisely at the start of a fresh tick window.
            let sync_ref = msr.read();
            let mut start_ref;

            loop {
                start_ref = msr.read();

                if start_ref != sync_ref {
                    break;
                }

                hint::spin_loop();
            }

            // Immediately capture the starting point of the CPU Time Stamp Counter (TSC).
            let tsc_start = _rdtsc();

            // Busy-loop until the difference between the current MSR value and start_ref reaches 100,000 ticks.
            loop {
                let current_ref = msr.read();

                if current_ref - start_ref >= TARGET_TICKS {
                    break;
                }
            }

            // Capture the ending TSC value immediately after the 10ms window closes.
            let tsc_end = _rdtsc();

            // Calculate total elapsed TSC cycles during the 10ms calibration window.
            let delta_tsc = tsc_end - tsc_start;

            delta_tsc * 100
        }
    }
}
