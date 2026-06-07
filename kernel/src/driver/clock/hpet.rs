//! HPET-based TSC calibration for the kernel clock subsystem.
//!
//! Locates the ACPI HPET table via ACPICA, maps the MMIO register block, and
//! uses the main counter as a reference to measure how many TSC ticks elapse
//! over a 10 ms window. The result is scaled to an estimated TSC frequency in Hz
//! and fed into [`ClockSource`] selection during system clock initialization.
//!
//! HPET is used only for one-shot calibration at boot; the running kernel does not
//! keep the counter enabled afterward.
//!
use core::{arch::x86_64::_rdtsc, ptr};

use acpica_rs::{
    AE_OK,
    sys::{ACPI_STATUS, ACPI_TABLE_HEADER, ACPI_TABLE_HPET, AcpiGetTable},
};

use crate::{
    driver::clock::ClockSource,
    subsystem::memory::{
        AnyIn, CurrentAddressSpace, Frame, PageFlags, PhysicalAddress, memory_manager,
    },
};

/// High Precision Event Timer (HPET)
const HPET_SIGNATURE: [u8; 4] = *b"HPET";

// HPET Register Offsets

/// General Capabilities and ID Register
const HPET_CAPABILITIES: isize = 0x00;

/// General Configuration Register
const HPET_CONFIGURATION: isize = 0x10;

/// Main Counter Value Register
const HPET_MAIN_COUNTER: isize = 0xF0;

/// Target 10ms in femtoseconds (10^13).
const TARGET_FS: u64 = 10_000_000_000_000;

pub struct HpetTimer {}

impl HpetTimer {
    /// Retrieves the HPET ACPI table using ACPICA.
    pub(crate) fn get_table(&self) -> (ACPI_STATUS, *mut ACPI_TABLE_HEADER) {
        let mut table_ptr: *mut ACPI_TABLE_HEADER = ptr::null_mut();

        let status = unsafe { AcpiGetTable(HPET_SIGNATURE.as_ptr() as *mut i8, 1, &mut table_ptr) };

        (status, table_ptr)
    }
}

impl ClockSource for HpetTimer {
    /// Checks, if HPET is present in the system ACPI table.
    fn present(&self) -> bool {
        let (status, table_ptr) = self.get_table();

        status == AE_OK && !table_ptr.is_null()
    }

    /// Measures the number of TSC ticks that elapse during a 10ms window using HPET timer.
    fn measure_tsc_ticks(&self) -> u64 {
        // Fetch the ACPI table to find the address of HPET MMIO registers
        let (_, table_ptr) = self.get_table();
        let table = unsafe { &*(table_ptr as *const ACPI_TABLE_HPET) };

        // Map the HPET registers as writable and uncached. We discard the return value, because this space might be AlreadyMapped
        // by Limine.
        let hpet_base: *const u8 = unsafe {
            memory_manager().write().map(
                CurrentAddressSpace,
                AnyIn(
                    &Frame::new(PhysicalAddress::new(table.Address.Address)),
                    256..511,
                ),
                PageFlags::WRITABLE | PageFlags::DISABLE_CACHING | PageFlags::WRITE_THROUGH,
            )
        }
        .unwrap()
        .page
        .address()
        .as_ptr();

        // Read capabilities register to get the counter period (higher 32 bits) in femtoseconds (10^-12)
        let cap_reg =
            unsafe { core::ptr::read_volatile(hpet_base.offset(HPET_CAPABILITIES) as *const u64) };
        let period_fs = cap_reg >> 32;

        if period_fs == 0 {
            log::error!("HPET counter period is 0. Broken hardware/emulation.");

            return 0;
        }

        // Enable the main counter by setting ENABLE_CNF bit in the Configuration Register
        let mut config =
            unsafe { core::ptr::read_volatile(hpet_base.offset(HPET_CONFIGURATION) as *const u64) };
        config |= 1; // ENABLE_CNF
        unsafe {
            core::ptr::write_volatile(hpet_base.offset(HPET_CONFIGURATION) as *mut u64, config)
        };

        // 10ms = 10^13 femtoseconds
        let ticks_to_wait = TARGET_FS / period_fs;

        // Capture starting points for HPET and TSC
        let start_hpet =
            unsafe { core::ptr::read_volatile(hpet_base.offset(HPET_MAIN_COUNTER) as *const u64) };
        let tsc_start = unsafe { _rdtsc() };

        // Busy loop until the HPET main counter advances by the required number of ticks
        loop {
            let current_hpet = unsafe {
                core::ptr::read_volatile(hpet_base.offset(HPET_MAIN_COUNTER) as *const u64)
            };

            if current_hpet - start_hpet >= ticks_to_wait {
                break;
            }
        }

        // Capture the ending TSC value just after the 10ms elapsed
        let tsc_end = unsafe { _rdtsc() };

        // Disable the HPET main counter, as we won't use it later.
        config &= !1;
        unsafe {
            core::ptr::write_volatile(hpet_base.offset(HPET_CONFIGURATION) as *mut u64, config)
        };

        // Return total elapsed TSC cycles
        let delta_tsc = tsc_end - tsc_start;
        delta_tsc * 100
    }
}
