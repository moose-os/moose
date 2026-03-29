use alloc::sync::Arc;
use core::fmt::Write;

use log::{LevelFilter, Log, SetLoggerError};
use spin::{Mutex, Once, RwLock};
use x86_64::instructions::interrupts;

use crate::{
    arch::x86::cpu::ProcessorControlBlock, driver::serial::Serial, subsystem::terminal::Terminal,
};

static BOOT_LOGGER: Once<BootLogger> = Once::new();
static POST_BOOT_LOGGER: Once<PostBootLogger> = Once::new();

static LOGGER: SwitchableLogger = SwitchableLogger::new();

struct SwitchableLogger {
    inner: RwLock<Option<&'static dyn Log>>,
}

impl SwitchableLogger {
    const fn new() -> Self {
        Self {
            inner: RwLock::new(None),
        }
    }

    fn set_logger(&self, logger: &'static dyn Log) {
        interrupts::without_interrupts(|| {
            *self.inner.write() = Some(logger);
        });
    }
}

impl Log for SwitchableLogger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        let logger = self.inner.read();

        if let Some(logger) = *logger {
            logger.enabled(metadata)
        } else {
            false
        }
    }

    fn log(&self, record: &log::Record) {
        let logger = self.inner.read();

        if let Some(logger) = *logger {
            logger.log(record);
        }
    }

    fn flush(&self) {
        let logger = self.inner.read();

        if let Some(logger) = *logger {
            logger.flush();
        }
    }
}

struct BootLogger {
    serial: Arc<Mutex<Serial>>,
    terminal: Arc<Mutex<Terminal>>,
}

impl BootLogger {
    const fn new(serial: Arc<Mutex<Serial>>, terminal: Arc<Mutex<Terminal>>) -> Self {
        Self { serial, terminal }
    }
}

impl Log for BootLogger {
    fn enabled(&self, _metadata: &log::Metadata) -> bool {
        true
    }

    fn log(&self, record: &log::Record) {
        if self.enabled(record.metadata()) {
            interrupts::without_interrupts(|| {
                {
                    let mut serial = self.serial.lock();

                    _ = writeln!(&mut serial, "[{}] {}", record.level(), record.args());
                }
                {
                    let mut terminal = self.terminal.lock();

                    _ = writeln!(&mut terminal, "[{}] {}", record.level(), record.args());
                }
            });
        }
    }

    fn flush(&self) {}
}

struct PostBootLogger {
    serial: Arc<Mutex<Serial>>,
    terminal: Arc<Mutex<Terminal>>,
}

impl PostBootLogger {
    const fn new(serial: Arc<Mutex<Serial>>, terminal: Arc<Mutex<Terminal>>) -> Self {
        Self { serial, terminal }
    }
}

impl Log for PostBootLogger {
    fn enabled(&self, _metadata: &log::Metadata) -> bool {
        true
    }

    fn log(&self, record: &log::Record) {
        if self.enabled(record.metadata()) {
            let cpu_id = unsafe { &*ProcessorControlBlock::get_pcb_for_current_processor() }
                .apic_processor_id;

            interrupts::without_interrupts(|| {
                {
                    let mut serial = self.serial.lock();

                    _ = writeln!(
                        &mut serial,
                        "[CPU{}] [{}] {}",
                        cpu_id,
                        record.level(),
                        record.args()
                    );
                }
                {
                    let mut terminal = self.terminal.lock();

                    _ = writeln!(
                        &mut terminal,
                        "[CPU{}] [{}] {}",
                        cpu_id,
                        record.level(),
                        record.args()
                    );
                }
            });
        }
    }

    fn flush(&self) {}
}

pub fn init_logger(
    serial: Arc<Mutex<Serial>>,
    terminal: Arc<Mutex<Terminal>>,
) -> Result<(), SetLoggerError> {
    LOGGER.set_logger(BOOT_LOGGER.call_once(|| BootLogger::new(serial, terminal)));

    log::set_logger(&LOGGER).map(|()| log::set_max_level(LevelFilter::Trace))
}

pub fn switch_to_post_boot_logger(serial: Arc<Mutex<Serial>>, terminal: Arc<Mutex<Terminal>>) {
    LOGGER.set_logger(POST_BOOT_LOGGER.call_once(|| PostBootLogger::new(serial, terminal)));
}
