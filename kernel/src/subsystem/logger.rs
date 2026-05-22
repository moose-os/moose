use core::fmt::Write;

use log::{LevelFilter, Log, SetLoggerError};
use x86_64::instructions::interrupts;

use crate::kernel::kernel_ref;

static BOOT_LOGGER: BootLogger = BootLogger;

struct BootLogger;

impl Log for BootLogger {
    fn enabled(&self, _metadata: &log::Metadata) -> bool {
        true
    }

    fn log(&self, record: &log::Record) {
        if self.enabled(record.metadata()) {
            let kernel = kernel_ref();

            interrupts::without_interrupts(|| {
                {
                    let mut serial = kernel.serial().lock();

                    _ = writeln!(&mut serial, "[{}] {}", record.level(), record.args());
                }

                if let Some(terminal) = kernel.terminal.get() {
                    let mut terminal = terminal.lock();

                    _ = writeln!(&mut terminal, "[{}] {}", record.level(), record.args());
                }
            });
        }
    }

    fn flush(&self) {}
}

pub fn init_logger() -> Result<(), SetLoggerError> {
    log::set_logger(&BOOT_LOGGER).map(|()| log::set_max_level(LevelFilter::Trace))
}
