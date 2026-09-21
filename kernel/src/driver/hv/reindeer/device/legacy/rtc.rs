//! Virtual Real-Time Clock (RTC) and CMOS NVRAM Device Model.
//!
//! Emulates the classic Motorola MC146818 Real-Time Clock chip and associated CMOS RAM.
//!
//! The RTC provides time-of-day information, system configuration NVRAM storage, and alarm/timer functions.
//! Access is mediated via two primary I/O ports:
//! - Address/Index Port (`0x70`): Used by the guest to select a CMOS register index (0x00-0x7F).
//!   The most significant bit (Bit 7) serves as the NMI Disable flag.
//! - Data Port (`0x71`): Used to read or write the value of the currently selected CMOS index.
//!
//! Reads to time registers are passed directly to the host's physical RTC hardware
//! via raw assembly instructions (`outw`/`inb`) to provide accurate host-synced time to the guest.

use alloc::{sync::Arc, vec::Vec};

use spin::rwlock::RwLock;

use crate::{
    arch::x86::asm::{inb, outb},
    driver::hv::reindeer::device::{DeviceResource, VirtualDevice},
};

/// CMOS Index/Address I/O Port (`0x70`).
pub const CMOS_ADDR: u16 = 0x70;

/// CMOS Data I/O Port (`0x71`).
pub const CMOS_DATA: u16 = 0x71;

/// RTC Register 0x00: Seconds (0-59 in BCD or Binary format).
const SECONDS: u8 = 0x00;

/// RTC Register 0x01: Seconds Alarm.
const SECONDS_ALARM: u8 = 0x01;

/// RTC Register 0x02: Minutes (0-59 in BCD or Binary format).
const MINUTES: u8 = 0x02;

/// RTC Register 0x03: Minutes Alarm.
const MINUTES_ALARM: u8 = 0x03;

/// RTC Register 0x04: Hours (1-12 or 0-23 depending on format settings).
const HOURS: u8 = 0x04;

/// RTC Register 0x05: Hours Alarm.
const HOURS_ALARM: u8 = 0x05;

/// RTC Register 0x06: Day of the Week (1 = Sunday).
const DAY_OF_WEEK: u8 = 0x06;

/// RTC Register 0x07: Day of the Month (1-31).
const DAY_OF_MONTH: u8 = 0x07;

/// RTC Register 0x08: Month (1-12).
const MONTH: u8 = 0x08;

/// RTC Register 0x09: Year (00-99).
const YEAR: u8 = 0x09;

/// Status Register A: Controls divider chains, oscillator, and update-in-progress (UIP) flag.
const STATUS_A: u8 = 0xA;

/// Status Register B: Controls 24h/12h mode, BCD/Binary data format, and interrupt enables.
const STATUS_B: u8 = 0xB;

/// Status Register C: Interrupt status flags (read-cleared).
const STATUS_C: u8 = 0xC;

/// Status Register D: Valid RAM and Time (VRT) power-state flag.
const STATUS_D: u8 = 0xD;

/// Standard IBM PC/AT CMOS NVRAM offset for Century (19 or 20).
const CENTURY: u8 = 0x32;

/// Virtual Real-Time Clock device container.
#[derive(Debug)]
pub struct VirtualRealTimeClockDevice {
    /// Currently selected CMOS register index (0x00-0x7F).
    port: u16,
}

impl VirtualRealTimeClockDevice {
    /// Creates a new `VirtualRealTimeClockDevice` instance initialized to index 0.
    pub fn new() -> Arc<RwLock<Self>> {
        Arc::new(RwLock::new(VirtualRealTimeClockDevice { port: 0 }))
    }
}

impl VirtualDevice for VirtualRealTimeClockDevice {
    /// Returns the human-readable device name.
    fn name(&self) -> &str {
        "RTC Clock"
    }

    /// Claims I/O ports `0x70` (Index/NMI) and `0x71` (Data).
    fn get_resources(&self) -> Vec<DeviceResource> {
        alloc::vec![
            DeviceResource::IoPort { port: 0x70 },
            DeviceResource::IoPort { port: 0x71 },
        ]
    }

    /// Handles guest reads from I/O ports `0x70` or `0x71`.
    ///
    /// Reads to port `0x71` trigger a hardware read request from the host's physical RTC for time-related fields.
    fn handle_io_read(&mut self, _cpu_id: usize, addr: u64, _width: u8) -> u64 {
        match addr {
            // Port 0x70 returns the active index
            0x70 => self.port as u64,

            // Port 0x71 reads data from the currently selected CMOS register index
            0x71 => match self.port as u8 {
                SECONDS => {
                    outb(CMOS_ADDR, SECONDS);
                    inb(CMOS_DATA) as u64
                }
                MINUTES => {
                    outb(CMOS_ADDR, MINUTES);
                    inb(CMOS_DATA) as u64
                }
                HOURS => {
                    outb(CMOS_ADDR, HOURS);
                    inb(CMOS_DATA) as u64
                }
                DAY_OF_MONTH => {
                    outb(CMOS_ADDR, DAY_OF_MONTH);
                    inb(CMOS_DATA) as u64
                }
                DAY_OF_WEEK => {
                    outb(CMOS_ADDR, DAY_OF_WEEK);
                    inb(CMOS_DATA) as u64
                }
                MONTH => {
                    outb(CMOS_ADDR, MONTH);
                    inb(CMOS_DATA) as u64
                }
                YEAR => {
                    outb(CMOS_ADDR, YEAR);
                    inb(CMOS_DATA) as u64
                }
                CENTURY => {
                    outb(CMOS_ADDR, CENTURY);
                    inb(CMOS_DATA) as u64
                }

                // Alarm registers — returns 0x00 (alarms disabled)
                SECONDS_ALARM | MINUTES_ALARM | HOURS_ALARM => 0x00,

                // Status A: 0x26 indicates standard 32.768 kHz oscillator and 26 ms rate
                STATUS_A => 0x26,

                // Status B: Passthrough to host to preserve BCD/24h format settings
                STATUS_B => {
                    outb(CMOS_ADDR, STATUS_B);
                    inb(CMOS_DATA) as u64
                }

                // Status C: Interrupt flags. Reading automatically clears pending IRQs (always 0x00 here)
                STATUS_C => 0x00,

                // Status D: Bit 7 = 1 (VRT - Valid RAM and Time), indicating battery power is healthy
                STATUS_D => 0x80,

                // Unhandled or general CMOS NVRAM registers
                _ => 0x00,
            },
            _ => unreachable!(),
        }
    }

    /// Handles guest writes to I/O ports `0x70` or `0x71`.
    fn handle_io_write(&mut self, _cpu_id: usize, addr: u64, value: u64, _width: u8) {
        match addr {
            0x70 => {
                let cmos_index = value & 0x7F;

                self.port = cmos_index as u16;
            }
            0x71 => {
                // Ignore writes to RTC registers or status configuration during boot probes
                log::debug!(
                    "RTC: ignore write index={:#x} value={:#x}",
                    self.port,
                    value
                );
            }
            _ => unreachable!(),
        }
    }

    /// Generates AML byte stream for the Real-Time Clock device node.
    fn generate_aml(&self) -> Option<Vec<u8>> {
        Some(crate::aml!(@ROOT
            Device ("RTC") {
                Name ("_HID", "PNP0B00")
                Name ("_DDN", "RTC")

                Name ("_CRS", ResourceTemplate() {
                    FixedIO (0x70, 2)
                })

                Method ("_STA", 0) {
                    Return (0x0Fu8)
                }
            }
        ))
    }
}
