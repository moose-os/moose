//! Boot-time TSC calibration sources for the kernel clock subsystem.
//!
//! Provides the [`ClockSource`] trait and platform-specific implementations used
//! to estimate CPU TSC frequency before the monotonic clock is initialized.
//! Each source measures how many TSC ticks elapse over a fixed 10 ms reference
//! window, using a different hardware or hypervisor timebase:
//!
//! - [`hpet::HpetTimer`] — ACPI HPET main counter
//! - [`hyperv::HyperVReferenceCounter`] — Hyper-V guest reference MSR (10 MHz)
//! - [`kvmclock::KvmClockTimer`] — KVM paravirtual system-time page
//! - [`pit::PitTimer`] — legacy PIT channel 2 (fallback on PC hardware)
//!
//! SystemClock probes these sources at boot, picks the best available one,
//! and uses it only for calibration — none of them drive runtime timekeeping.
//!
pub mod hpet;
pub mod hyperv;
pub mod kvmclock;
pub mod pit;

/// A trait defining a hardware clock source for time measurement.
///
/// Implementations of this trait provide an interface to query the availability
/// of a clock source and to measure its current performance using TSC (Time Stamp Counter)
/// ticks. This is essential for accurate profiling, scheduling, and system-time
/// synchronization.
pub trait ClockSource {
    /// Checks whether the clock source is present in the system.
    fn present(&self) -> bool;

    /// Returns count of TSC ticks elapsed in 10ms.
    fn measure_tsc_ticks(&self) -> u64;
}
