//! Kernel system clock: TSC-based monotonic time and RTC-backed wall clock.
//!
//! [`SystemClock`] is the primary runtime time source. At boot it selects the best
//! available [`ClockSource`] (Hyper-V, KVM, HPET, or PIT), calibrates TSC frequency
//! and LAPIC tick rate, and aligns monotonic time with the hardware RTC via
//! [`RealTimeClock`].
//!
//! # Time model
//!
//! ```text
//! monotonic_ns  = rdtsc() converted via fixed-point (mult >> shift)
//! wall_clock_ns = monotonic_ns + wall_clock_base_ns   // base from RTC at boot
//! ```
//!
use core::{
    arch::x86_64::_rdtsc,
    sync::atomic::{AtomicU64, Ordering},
};

use common::{average, std_dev};

use crate::{
    arch::x86::{
        asm::{inb, outb},
        cpu::ProcessorControlBlock,
    },
    driver::clock::{
        ClockSource, hpet::HpetTimer, hyperv::HyperVReferenceCounter, kvmclock::KvmClockTimer,
        pit::PitTimer,
    },
    subsystem::clock::time::{DateTime, UNIX_EPOCH_YEAR},
};

/// I/O port used to select which CMOS/RTC register to read or write.
const CMOS_ADDR_PORT: u16 = 0x70;

/// I/O port used to read from or write to the CMOS/RTC register
/// previously selected via [`CMOS_ADDR_PORT`].
const CMOS_DATA_PORT: u16 = 0x71;

/// RTC register index for the current **seconds** value (0–59).
const RTC_REG_SECONDS: u8 = 0x00;

/// RTC register index for the current **minutes** value (0–59).
const RTC_REG_MINUTES: u8 = 0x02;

/// RTC register index for the current **hours** value (0–23, 24-hour mode assumed).
const RTC_REG_HOURS: u8 = 0x04;

/// RTC register index for the current **day of month** value (1–31).
const RTC_REG_DAY: u8 = 0x07;

/// RTC register index for the current **month** value (1–12).
const RTC_REG_MONTH: u8 = 0x08;

/// RTC register index for the current **year** value within the century (0–99).
const RTC_REG_YEAR: u8 = 0x09;

/// RTC register index for the current **century** value.
const RTC_REG_CENTURY: u8 = 0x32;

/// RTC Status Register A index.
/// See [`RTC_UIP_FLAG`] for the update-in-progress bit.
const RTC_REG_STATUS_A: u8 = 0x0A;

/// RTC Status Register B index.
/// See [`RTC_BINARY_MODE_FLAG`] for the BCD/binary selection bit.
const RTC_REG_STATUS_B: u8 = 0x0B;

/// Bit 7 of [`RTC_REG_STATUS_A`].
/// Set by the hardware while a time update is in progress.
const RTC_UIP_FLAG: u8 = 0x80;

/// Bit 2 of [`RTC_REG_STATUS_B`].
/// When **set**, all time and date registers contain plain binary values.
/// When **clear**, they are encoded in BCD and must be converted with [`bcd_to_bin`].
const RTC_BINARY_MODE_FLAG: u8 = 0x04;

/// Provides direct access to the hardware Real-Time Clock (RTC)
/// via the CMOS I/O ports.
pub struct RealTimeClock;

impl RealTimeClock {
    /// Returns the current seconds value directly from the RTC register.
    pub fn seconds(&self) -> u8 {
        self.read_register(RTC_REG_SECONDS)
    }

    /// Returns the current minutes value directly from the RTC register.
    pub fn minutes(&self) -> u8 {
        self.read_register(RTC_REG_MINUTES)
    }

    /// Returns the current hour value directly from the RTC register (24-hour mode assumed).
    pub fn hour(&self) -> u8 {
        self.read_register(RTC_REG_HOURS)
    }

    /// Returns the current day of month value directly from the RTC register (1–31).
    pub fn day(&self) -> u8 {
        self.read_register(RTC_REG_DAY)
    }

    /// Returns the current month value directly from the RTC register (1–12).
    pub fn month(&self) -> u8 {
        self.read_register(RTC_REG_MONTH)
    }

    /// Returns the current year-within-century value directly from the RTC register (0–99).
    pub fn year(&self) -> u8 {
        self.read_register(RTC_REG_YEAR)
    }

    /// Returns the current century value directly from the RTC register.
    pub fn century(&self) -> u8 {
        self.read_register(RTC_REG_CENTURY)
    }

    /// Returns `tsc, unix_timestamp_secs` sampled atomically around
    /// a clean RTC read (no update in progress).
    pub fn get_unix_timestamp(&self) -> (u64, u64) {
        // Spin until the RTC is not mid-update, then snapshot TSC + registers
        // together so they correspond to the same instant.
        while self.read_register(RTC_REG_STATUS_A) & RTC_UIP_FLAG != 0 {}

        let tsc = unsafe { _rdtsc() };

        let seconds = self.seconds();
        let minutes = self.minutes();
        let hour = self.hour();
        let day = self.day();
        let month = self.month();
        let year = self.year();

        let is_bcd = self.read_register(RTC_REG_STATUS_B) & RTC_BINARY_MODE_FLAG == 0;

        let decode = |v: u8| if is_bcd { bcd_to_bin(v) } else { v };

        let rtc = RtcTime {
            second: decode(seconds),
            minute: decode(minutes),
            hour: decode(hour),
            day: decode(day),
            month: decode(month),
            year: 2000 + decode(year) as u16,
        };

        (tsc, rtc.to_unix_timestamp())
    }

    /// Selects `reg` via [`CMOS_ADDR_PORT`] and returns the byte read from [`CMOS_DATA_PORT`].
    fn read_register(&self, reg: u8) -> u8 {
        outb(CMOS_ADDR_PORT, reg);

        inb(CMOS_DATA_PORT)
    }
}

/// Converts a BCD-encoded byte to its plain binary equivalent.
const fn bcd_to_bin(bcd: u8) -> u8 {
    ((bcd >> 4) * 10) + (bcd & 0x0F)
}

/// A decoded RTC time snapshot with all fields in plain binary (not BCD).
struct RtcTime {
    /// Seconds within the current minute (0–59).
    second: u8,

    /// Minutes within the current hour (0–59).
    minute: u8,

    /// Hour within the current day (0–23). 24-hour mode is assumed.
    hour: u8,

    /// Day of the month (1–31).
    day: u8,

    /// Month of the year (1–12).
    month: u8,

    /// Full four-digit year.
    year: u16,
}

/// Cumulative number of days elapsed before the start of each month
/// in a non-leap year, using a 1-based month index.
///
/// `DAYS_BEFORE_MONTH[m]` gives the number of days from January 1st
/// up to (but not including) month `m`. Slot `0` is unused and set to `0`
/// so that month numbers map directly to indices without subtraction.
///
/// # Example
/// `DAYS_BEFORE_MONTH[3]` = `59` — January (31) + February (28) precede March.
const DAYS_BEFORE_MONTH: [i64; 13] = [0, 0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];

/// Number of seconds in a single day (24 * 60 * 60).
const SECONDS_PER_DAY: i64 = 86_400;

/// Number of seconds in a single hour (60 * 60).
const SECONDS_PER_HOUR: i64 = 3_600;

impl RtcTime {
    /// Converts this RTC snapshot to a Unix timestamp.
    ///
    /// Computes the number of seconds elapsed since 1970-01-01 00:00:00 UTC
    /// by summing days from complete years, completed months, and the current
    /// day, then converting the total to seconds and adding the time of day.
    fn to_unix_timestamp(&self) -> u64 {
        let year = self.year as i64;
        let month = self.month as i64;
        let day = self.day as i64;

        // Days from complete years since the Unix epoch.
        let mut total_days = (year - UNIX_EPOCH_YEAR) * 365;

        // Leap-day correction relative to the epoch.
        total_days += leap_days_since_epoch(year);

        // Days from completed months in the current year.
        total_days += DAYS_BEFORE_MONTH[month as usize];
        if month > 2 && is_leap_year(year) {
            total_days += 1;
        }

        // Days elapsed within the current month (0-based).
        total_days += day - 1;

        let total_seconds = total_days * SECONDS_PER_DAY
            + self.hour as i64 * SECONDS_PER_HOUR
            + self.minute as i64 * 60
            + self.second as i64;

        total_seconds as u64
    }
}

/// Returns `true` if `year` is a leap year under the Gregorian calendar.
///
/// A year is a leap year when it is:
/// - divisible by 4,and not divisible by 100, or
/// - divisible by 400.
pub(crate) const fn is_leap_year(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

/// Returns the number of leap days that occurred between the Unix epoch
/// (1970-01-01) and the start of `year`, relative to the epoch.
///
/// Uses the standard Gregorian formula: every 4 years gains a leap day,
/// every 100 years loses one, and every 400 years gains one back.
fn leap_days_since_epoch(year: i64) -> i64 {
    (year / 4 - UNIX_EPOCH_YEAR / 4) - (year / 100 - UNIX_EPOCH_YEAR / 100)
        + (year / 400 - UNIX_EPOCH_YEAR / 400)
}

/// The main timekeeping primitive for the kernel.
///
/// Combines a TSC-based monotonic clock with a wall-clock baseline derived
/// from the RTC at boot. All time values are in nanoseconds.
///
/// # Clock model
/// ```text
/// wall_clock_ns = monotonic_ns + wall_clock_base_ns
///                      │                  │
///               TSC * (mult >> shift)   set once at boot
///                                       from RTC unix timestamp
/// ```
pub struct SystemClock {
    /// Frequency of the CPU timestamp counter in Hz.
    tsc_frequency: u64,

    /// Frequency of the Local APIC timer in Hz.
    lapic_frequency: u64,

    /// Nanosecond offset added to the monotonic clock to obtain wall-clock time.
    pub wall_clock_base_ns: AtomicU64,

    /// Bit-shift applied after the TSC multiply to yield nanoseconds.
    pub ns_per_tsc_shift: u32,

    /// Fixed-point multiplier for converting TSC ticks to nanoseconds.
    pub ns_per_tsc_mult: u64,
}

impl SystemClock {
    /// Creates a new `SystemClock`, selects the best available clock source, and
    /// calibrates its wall-clock baseline against the RTC.
    ///
    /// # Clock source selection
    ///
    /// Probes four clock sources in priority order — HyperV reference counter and
    /// KVM clock (priority 0), HPET (priority 1), and PIT (priority 2) — performing
    /// a warm-up read followed by three TSC tick measurements for each present source.
    /// The source with the lowest priority value is then selected as the TSC frequency
    /// reference.
    ///
    /// # Fixed-point multiplier
    ///
    /// Converting TSC ticks to nanoseconds requires dividing by `tsc_freq`, but
    /// integer division at runtime is expensive on x86. Linux solves this with a
    /// multiply-then-shift trick: precompute a scaled reciprocal once at boot and
    /// replace every future division with a multiply and a bitshift:
    ///
    /// ```text
    /// ns = (tsc * mult) >> SHIFT
    ///    = (tsc * (1_000_000_000 << SHIFT) / tsc_freq) >> SHIFT
    ///    = tsc * 1_000_000_000 / tsc_freq
    /// ```
    pub fn new() -> Self {
        const SHIFT: u32 = 32;

        let hpet = HpetTimer {};
        let hyperv_ref = HyperVReferenceCounter {};
        let kvmclock = KvmClockTimer {};
        let pit = PitTimer {};

        let clocksources: [(&str, u8, &dyn ClockSource); 4] = [
            ("HyperV RefCounter", 0, &hyperv_ref),
            ("kvmclock", 0, &kvmclock),
            ("HPET", 1, &hpet),
            ("PIT", 2, &pit),
        ];

        let mut results: [(&&str, bool, u8, u64, u64); 4] = [(&"", false, 0, 0, 0); 4];
        for (index, (name, priority, clock)) in clocksources.iter().enumerate() {
            let is_present = clock.is_present();

            if !is_present {
                results[index] = (name, false, *priority, 0, 0);

                continue;
            }

            // warm up
            let _ = clock.measure_tsc_ticks();

            // perform 3 measurements, then calculate mean and standard deviation and put it in results array
            let samples = [
                clock.measure_tsc_ticks(),
                clock.measure_tsc_ticks(),
                clock.measure_tsc_ticks(),
            ];

            let mean = average(&samples);
            let std_dev = std_dev(&samples).unwrap();

            results[index] = (name, is_present, *priority, mean, std_dev);
        }

        results
            .iter()
            .for_each(|entry| Self::print_timer_stats(entry.0, entry.1, entry.2, entry.3, entry.4));

        let best = results
            .iter()
            .filter(|(_, present, _, _, _)| *present)
            .min_by_key(|(_, _, priority, _, _)| priority)
            .unwrap();

        debug!("Using {} as a reliable clock source...", best.0);
        let tsc_frequency = best.3; // mean

        let lapic_frequency = ProcessorControlBlock::current()
            .local_apic()
            .calculate_lapic_frequency(tsc_frequency);

        let mult = ((1_000_000_000u64 << SHIFT) + tsc_frequency / 2) / tsc_frequency;

        let mut clock = Self {
            tsc_frequency,
            lapic_frequency,
            wall_clock_base_ns: AtomicU64::new(0),
            ns_per_tsc_mult: mult,
            ns_per_tsc_shift: SHIFT,
        };

        clock.calibrate_wall_clock();

        debug!(
            "Current datetime: {}",
            DateTime::from_unix_secs(current_unix_secs(&clock))
        );

        clock
    }

    /// Aligns the monotonic TSC clock with the current RTC wall-clock time.
    fn calibrate_wall_clock(&mut self) {
        let (tsc, unix_secs) = RealTimeClock.get_unix_timestamp();
        let timestamp_ns = unix_secs * 1_000_000_000;
        let current_ns = self.tsc_to_ns(tsc);
        let base = timestamp_ns.saturating_sub(current_ns);

        self.wall_clock_base_ns.store(base, Ordering::Relaxed);
    }

    /// Converts a raw TSC value to nanoseconds using the precomputed fixed-point multiplier.
    ///
    /// Performs the multiply in `u128` to prevent overflow - at 4 GHz and
    /// `mult = 2^32`, the intermediate product reaches ~2^94, which exceeds `u64::MAX`.
    #[inline]
    fn tsc_to_ns(&self, tsc: u64) -> u64 {
        ((tsc as u128 * self.ns_per_tsc_mult as u128) >> self.ns_per_tsc_shift) as u64
    }

    /// Returns the number of nanoseconds elapsed since the kernel started,
    /// based on the current TSC value.
    #[inline]
    pub fn monotonic_ns(&self) -> u64 {
        self.tsc_to_ns(unsafe { _rdtsc() })
    }

    /// Returns the current wall-clock time as nanoseconds since the Unix epoch
    /// (1970-01-01 00:00:00 UTC).
    #[inline]
    pub fn wall_clock_ns(&self) -> u64 {
        self.monotonic_ns() + self.wall_clock_base_ns.load(Ordering::Relaxed)
    }

    /// Converts a nanosecond duration to Local APIC timer ticks.
    ///
    /// Used by the scheduler to program the APIC one-shot timer for a deadline
    /// `ns` nanoseconds in the future:
    #[inline]
    pub fn ns_to_apic_ticks(&self, ns: u64) -> u32 {
        (ns as u128 * self.lapic_frequency as u128 / 1_000_000_000) as u32
    }

    /// Prints timer statistics to the console.
    fn print_timer_stats(name: &str, present: bool, _priority: u8, mean: u64, std_dev: u64) {
        let mean_ghz = mean / 1_000_000_000;
        let mean_mhz = (mean % 1_000_000_000) / 1_000_000;

        if !present {
            debug!("{}: not present", name);

            return;
        }

        if std_dev >= 1_000_000 {
            let sd_mhz = std_dev / 1_000_000;
            let sd_khz = (std_dev % 1_000_000) / 1_000;

            debug!(
                "{}: mean = {}.{:03} GHz, std dev = {}.{:03} MHz",
                name, mean_ghz, mean_mhz, sd_mhz, sd_khz
            );
        } else {
            let sd_khz = std_dev / 1_000;
            let sd_hz = std_dev % 1_000;

            debug!(
                "{}: mean = {}.{:03} GHz, std dev = {}.{:03} kHz",
                name, mean_ghz, mean_mhz, sd_khz, sd_hz
            );
        }
    }
}

/// Returns the current wall-clock time as whole seconds since the Unix epoch.
pub fn current_unix_secs(clock: &SystemClock) -> u64 {
    clock.wall_clock_ns() / 1_000_000_000
}
