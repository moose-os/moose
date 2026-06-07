use core::fmt::Write;

use log::{Level, LevelFilter, Log, SetLoggerError};
use x86_64::instructions::interrupts;

use crate::{kernel::kernel_ref, subsystem::clock::time::LoggerTime};

static BOOT_LOGGER: BootLogger = BootLogger;

struct BootLogger;

impl Log for BootLogger {
    fn enabled(&self, _metadata: &log::Metadata) -> bool {
        true
    }

    fn log(&self, record: &log::Record) {
        if self.enabled(record.metadata()) {
            let kernel = kernel_ref();

            let level = record.level();

            let target = record
                .target()
                .rsplit_once("::")
                .map_or(record.target(), |(_, suffix)| suffix);
            let shortened_target = match target {
                "io_apic" => "ioapic",
                "local_apic" => "lapic",
                unknown => {
                    let byte_length = unknown
                        .char_indices()
                        .nth(6)
                        .map(|(idx, _)| idx)
                        .unwrap_or(unknown.len());

                    &unknown[0..byte_length]
                }
            };

            let (serial_color, terminal_color) = match level {
                Level::Error => ("38;5;1m", "38;2;224;108;117m"),
                Level::Warn => ("38;5;3m", "38;2;229;192;123m"),
                Level::Info => ("38;5;4m", "38;2;97;175;239m"),
                Level::Debug => ("38;5;13m", "38;2;198;120;221m"),
                Level::Trace => ("38;5;14m", "38;2;86;182;194m"),
            };

            let time = kernel_ref()
                .clock
                .get()
                .map(|c| LoggerTime::from_mono_ns(c.monotonic_ns()));

            interrupts::without_interrupts(|| {
                {
                    let mut serial = kernel.serial().lock();

                    if let Some(t) = time {
                        _ = write!(&mut serial, "\x1b[36m{}\x1b[0m ", t);
                    }

                    if !shortened_target.is_empty() {
                        _ = writeln!(
                            &mut serial,
                            "[\x1b[{}{:<5}\x1b[0m] [\x1b[38;2;90;90;90m{:^6}\x1b[0m] {}",
                            serial_color,
                            level.as_str(),
                            shortened_target,
                            record.args()
                        );
                    } else {
                        _ = writeln!(
                            &mut serial,
                            "[\x1b[{}{:<5}\x1b[0m] {}",
                            serial_color,
                            level.as_str(),
                            record.args()
                        );
                    }
                }

                if let Some(terminal) = kernel.terminal.get() {
                    let mut terminal = terminal.lock();

                    if let Some(t) = time {
                        _ = write!(&mut terminal, "\x1b[36m{}\x1b[0m ", t);
                    }

                    if !shortened_target.is_empty() {
                        _ = writeln!(
                            &mut terminal,
                            "[\x1b[{}{:<5}\x1b[0m] [\x1b[38;2;90;90;90m{:^6}\x1b[0m] {}",
                            terminal_color,
                            level.as_str(),
                            shortened_target,
                            record.args()
                        );
                    } else {
                        _ = writeln!(
                            &mut terminal,
                            "[\x1b[{}{:<5}\x1b[0m] {}",
                            terminal_color,
                            level.as_str(),
                            record.args()
                        );
                    }
                }
            });
        }
    }

    fn flush(&self) {}
}

pub fn init_logger() -> Result<(), SetLoggerError> {
    log::set_logger(&BOOT_LOGGER).map(|()| log::set_max_level(LevelFilter::Trace))
}
