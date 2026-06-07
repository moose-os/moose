//! KVM paravirtual clock TSC calibration for the kernel clock subsystem.
//!
//! When running under KVM, registers a shared [`KvmPvClockSystemTime`] page via
//! `MSR_KVM_SYSTEM_TIME_NEW`, reads the hypervisor-provided TSC-to-nanosecond
//! conversion factors, and extrapolates how many TSC ticks correspond to a 10 ms
//! window. The result is scaled to an estimated TSC frequency in Hz and fed into
//! [`ClockSource`] selection during system clock initialization.
//!
//! Used only for one-shot calibration at boot; the PV clock page is unregistered
//! afterward and not polled at runtime.

use core::{hint, ptr};

use raw_cpuid::{CpuId, Hypervisor};
use x86_64::registers::model_specific::Msr;

use crate::{
    driver::clock::ClockSource,
    subsystem::memory::{Any, CurrentAddressSpace, Frame, PageFlags, memory_manager},
};

/// KVM system time structure shared between hypervisor and guest.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
struct KvmPvClockSystemTime {
    pub version: u32,
    pub pad0: u32,
    pub tsc_timestamp: u64,
    pub system_time: u64,
    pub tsc_to_system_mul: u32,
    pub tsc_shift: i8,
    pub flags: u8,
    pub pad: [u8; 2],
}

/// MSR used to register the physical address of the KVM system time structure.
const MSR_KVM_SYSTEM_TIME_NEW: u32 = 0x4b564d01;

/// 10ms in nanoseconds.
const TARGET_NS: u64 = 10_000_000;

pub struct KvmClockTimer {}

impl ClockSource for KvmClockTimer {
    /// Detects KVM presence by checking hypervisor CPUID leaves.
    fn is_present(&self) -> bool {
        CpuId::new().get_hypervisor_info().unwrap().identify() == Hypervisor::KVM
    }

    /// Calculates the theoretical number of TSC ticks in a 10ms window
    /// using mathematically extrapolated data from the KVM PV Clock page.
    fn measure_tsc_ticks(&self) -> u64 {
        unsafe {
            let mut mm = memory_manager().write();
            let clock_frame = mm.allocate_frame().unwrap();

            let mut return_value = 0;
            let _ = mm.map_temporary(
                CurrentAddressSpace,
                Any(&Frame::new(clock_frame.address())),
                PageFlags::empty(),
                |addr| {
                    // Register physical page with KVM via MSR.
                    // Bit 0 enables the page.
                    let mut msr = Msr::new(MSR_KVM_SYSTEM_TIME_NEW);
                    msr.write(clock_frame.address().as_u64() | 1);

                    let pv_clock_ptr: *mut KvmPvClockSystemTime = addr.page.address().as_mut_ptr();

                    // Read the calibration data using KVM's versioning protocol.
                    // If version is odd, KVM is currently writing to the page.
                    let mut version;
                    let mut mul;
                    let mut shift;

                    loop {
                        version = ptr::read_volatile(ptr::addr_of!((*pv_clock_ptr).version));
                        if version == 0 || version % 2 != 0 {
                            // KVM is currently writing to this page.
                            hint::spin_loop();

                            continue;
                        }

                        mul = ptr::read_volatile(ptr::addr_of!((*pv_clock_ptr).tsc_to_system_mul));
                        shift = ptr::read_volatile(ptr::addr_of!((*pv_clock_ptr).tsc_shift));

                        let version_after =
                            ptr::read_volatile(ptr::addr_of!((*pv_clock_ptr).version));

                        // Check if KVM didn't start an update while we were reading the data.
                        if version == version_after {
                            break;
                        }

                        hint::spin_loop();
                    }

                    // Unregister the page to clean up the hypervisor state.
                    msr.write(0);

                    // KVM converts TSC to nanoseconds using the formula: ns = (tsc * mul) >> 32
                    // Since we want to find the number of TSC ticks in 10ms (10,000,000 ns):
                    // tsc = (ns << 32) / mul
                    let mut tsc_ticks = (TARGET_NS << 32) / (mul as u64);

                    // Apply KVM's shift factor
                    if shift >= 0 {
                        tsc_ticks >>= shift as u64;
                    } else {
                        tsc_ticks <<= (-shift) as u64;
                    }

                    return_value = tsc_ticks;
                },
            );

            // @TODO: Free allocated page frame

            return_value * 100
        }
    }
}
