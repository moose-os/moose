//! Kernel timekeeping: clocks, durations, and high-resolution timers.
//!
//! This module is the runtime clock layer built on top of boot-time TSC
//! calibration in [`crate::driver::clock`]:
//!
//! - [`system_clock::SystemClock`] — monotonic and wall-clock time from the TSC,
//!   with RTC-based calibration at boot and LAPIC tick conversion for deadlines
//! - [`time`] — [`time::Duration`], [`time::DateTime`], and related helpers
//! - [`timer`] — per-CPU [`timer::HrTimerSubsystem`] for expiry-ordered timers
//!   (scheduler preemption, thread wakeups, callbacks)
//!
//! Hardware calibration sources live in `driver::clock`; this module owns the
//! abstractions used by the scheduler, syscalls, and other kernel subsystems.
//!
pub mod system_clock;
pub mod time;
pub mod timer;
