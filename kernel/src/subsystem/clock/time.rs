//! Time types and formatting helpers for the kernel clock subsystem.
//!
//! Provides lightweight, `no_std` time abstractions built on nanosecond precision:
//!
//! - [`Duration`] — elapsed time spans (ns, ms, s)
//! - [`Instant`] — monotonic points since boot, backed by system clock
//! - [`DateTime`] — UTC calendar time decoded from Unix timestamps
//! - [`LoggerTime`] — `dmesg`-style `[SS.UUUUUU]` formatting for kernel logs
//!
//! These types are used by timers, the scheduler, syscalls, and logging; they do
//! not perform hardware access themselves.
//!
use core::{
    fmt,
    ops::{Add, AddAssign, Sub},
};

use crate::{kernel::kernel_ref, subsystem::clock::system_clock::is_leap_year};

/// The year the Unix epoch begins: 1970-01-01 00:00:00 UTC.
pub(crate) const UNIX_EPOCH_YEAR: i64 = 1970;

/// A `Duration` type represents a span of time, stored internally as nanoseconds.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct Duration(u64);

impl Duration {
    /// Creates a new `Duration` from the specified number of nanoseconds.
    pub const fn from_nanos(nanos: u64) -> Self {
        Self(nanos)
    }

    /// Creates a new `Duration` from the specified number of milliseconds.
    pub const fn from_millis(millis: u64) -> Self {
        Self(millis * 1_000_000)
    }

    /// Creates a new `Duration` from the specified number of seconds.
    pub const fn from_secs(secs: u64) -> Self {
        Self(secs * 1_000_000_000)
    }

    /// Returns the total number of nanoseconds contained by this `Duration`.
    pub const fn as_nanos(&self) -> u64 {
        self.0
    }
}

impl fmt::Display for Duration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ns = self.0;
        match ns {
            0..1_000 => write!(f, "{} ns", ns),
            1_000..1_000_000 => write!(f, "{}.{:03} us", ns / 1_000, ns % 1_000),
            1_000_000..1_000_000_000 => {
                write!(f, "{}.{:03} ms", ns / 1_000_000, (ns % 1_000_000) / 1_000)
            }
            _ => write!(
                f,
                "{}.{:03} s",
                ns / 1_000_000_000,
                (ns % 1_000_000_000) / 1_000_000
            ),
        }
    }
}

/// An `Instant` represents a specific point in time, measured in nanoseconds
/// since the system started. It is guaranteed to be monotonic, meaning
/// time always moves forward and never goes backward.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct Instant {
    /// Nanoseconds since system start.
    ns: u64,
}

impl Instant {
    /// Returns an `Instant` corresponding to "now".
    ///
    /// This queries the underlying system/kernel clock to get the current
    /// monotonic timestamp in nanoseconds.
    pub fn now() -> Self {
        Self {
            ns: kernel_ref().clock().monotonic_ns(),
        }
    }
}

impl Add<Duration> for Instant {
    type Output = Self;

    fn add(self, rhs: Duration) -> Self {
        Self {
            ns: self.ns.saturating_add(rhs.as_nanos()),
        }
    }
}

impl AddAssign<Duration> for Instant {
    fn add_assign(&mut self, rhs: Duration) {
        *self = *self + rhs;
    }
}

impl Sub<Duration> for Instant {
    type Output = Self;

    fn sub(self, rhs: Duration) -> Self {
        Self {
            ns: self.ns.saturating_sub(rhs.as_nanos()),
        }
    }
}

impl Sub<Instant> for Instant {
    type Output = Duration;

    fn sub(self, rhs: Instant) -> Duration {
        Duration::from_nanos(self.ns.saturating_sub(rhs.ns))
    }
}

/// A wrapper around a monotonic nanosecond timestamp designed for `dmesg`-style log formatting.
///
/// `LoggerTime` formats the internal nanosecond counter into a human-readable
/// string representation showing seconds and microseconds, padded with leading zeros.
pub struct LoggerTime(u64);

impl LoggerTime {
    /// Creates a new `LoggerTime` from a monotonic timestamp in nanoseconds.
    pub fn from_mono_ns(ns: u64) -> Self {
        Self(ns)
    }
}

impl fmt::Display for LoggerTime {
    /// Formats the timestamp into a `dmesg`-style format: `[SS.UUUUUU]`.
    ///
    /// * `SS` - Total seconds, padded to at least 2 digits.
    /// * `UUUUUU` - Remaining microseconds, padded to exactly 6 digits.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let seconds = self.0 / 1_000_000_000;
        let microseconds = (self.0 % 1_000_000_000) / 1_000;

        write!(f, "[{:02}.{:06}]", seconds, microseconds)
    }
}

/// This structure represents time in UTC (Coordinated Universal Time) and provides
/// a way to format timestamps for display, logs, or user interfaces.
#[derive(Debug, Copy, Clone)]
pub struct DateTime {
    /// Year component (e.g., 2026).
    pub year: i32,

    /// Month component, 1-indexed (1 = January, 12 = December).
    pub month: u8,

    /// Day of the month, 1-indexed (1 to 31).
    pub day: u8,

    /// Hour component, 24-hour format (0 to 23).
    pub hour: u8,

    /// Minute component (0 to 59).
    pub minute: u8,

    /// Second component (0 to 59).
    pub second: u8,
}

impl DateTime {
    /// Converts a Unix timestamp (seconds elapsed since January 1, 1970) into a `DateTime`.
    pub fn from_unix_secs(unix_secs: u64) -> Self {
        let second = (unix_secs % 60) as u8;
        let minute = (unix_secs % 3_600 / 60) as u8;
        let hour = (unix_secs % 86_400 / 3_600) as u8;
        let mut days = (unix_secs / 86_400) as i32;

        // Walk forward year by year from the epoch.
        let mut year = UNIX_EPOCH_YEAR;
        loop {
            let days_in_year = if is_leap_year(year) { 366 } else { 365 };
            if days >= days_in_year {
                days -= days_in_year;
                year += 1;
            } else {
                break;
            }
        }

        // Walk forward month by month within the year.
        let month_lengths = if is_leap_year(year) {
            [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
        } else {
            [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
        };

        let mut month = 1u8;
        for &len in &month_lengths {
            if days >= len {
                days -= len;
                month += 1;
            } else {
                break;
            }
        }

        Self {
            year: year as i32,
            month,
            day: (days + 1) as u8,
            hour,
            minute,
            second,
        }
    }
}

impl fmt::Display for DateTime {
    /// Formats the `DateTime` using the ISO 8601 extended format with a `UTC` suffix.
    ///
    /// Output format: `YYYY-MM-DD HH:MM:SS UTC`
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
            self.year, self.month, self.day, self.hour, self.minute, self.second
        )
    }
}
