//! Virtual ACPI Power Management Timer (PM Timer) Device Model.
//!
//! The ACPI PM Timer is a free-running, non-interrupting 24-bit (or 32-bit) counter
//! running at a fixed hardware frequency of 3.579545 MHz (`PM_TIMER_HZ`).
//!
//! The counter value is not updated via continuous thread ticks.
//! Instead, `read_ticks()` computes the elapsed 3.579545 MHz cycles on-demand based on the
//! guest CPU's Time Stamp Counter (TSC) obtained from [`GuestClock`].

use alloc::{sync::Arc, vec::Vec};

use spin::rwlock::RwLock;

use crate::driver::hv::reindeer::{
    device::{DeviceResource, VirtualDevice},
    guest::clock::GuestClock,
};

/// Default I/O port address for the Power Management Timer.
///
/// Corresponds to the base address declared in the ACPI `FADT` table (`PM_TMR_BLK`).
pub const PM_TIMER_PORT: u16 = 0x608;

/// Fixed ACPI hardware clock frequency in Hertz (3.579545 MHz).
///
/// Derived historically from 14.31818 MHz / 4 (NTSC colorburst crystal reference).
const PM_TIMER_HZ: u64 = 3_579_545;

/// Virtual ACPI Power Management Timer state container.
pub struct VirtualPmTimer {
    /// Monotonic timekeeper source driving the TSC calculations.
    guest_clock: Arc<GuestClock>,
}

impl VirtualPmTimer {
    /// Creates a new `VirtualPmTimer` instance bound to the provided [`GuestClock`].
    pub fn new(guest_clock: Arc<GuestClock>) -> Arc<RwLock<Self>> {
        Arc::new(RwLock::new(Self { guest_clock }))
    }

    /// Calculates the current 32-bit ACPI PM Timer counter value.
    fn read_ticks(&self) -> u32 {
        // Convert guest TSC cycles to PM Timer ticks using 128-bit arithmetic to prevent overflow.
        let ticks = (self.guest_clock.now_tsc() as u128 * PM_TIMER_HZ as u128)
            / self.guest_clock.tsc_hz() as u128;

        ticks as u32
    }
}

impl VirtualDevice for VirtualPmTimer {
    /// Returns the human-readable device name.
    fn name(&self) -> &str {
        "ACPI PM Timer"
    }

    /// Claims the I/O port space allocated for the PM Timer (`0x608`).
    fn get_resources(&self) -> Vec<DeviceResource> {
        alloc::vec![DeviceResource::IoPortRange {
            base: PM_TIMER_PORT,
            size: 4
        }]
    }

    /// Handles guest I/O port reads targeting the PM Timer port.
    fn handle_io_read(&mut self, _cpu_id: usize, addr: u64, width: u8) -> u64 {
        let offset = (addr.saturating_sub(PM_TIMER_PORT as u64)) as u32;
        let ticks = self.read_ticks();

        let shifted = ticks.checked_shr(offset * 8).unwrap_or(0);

        match width {
            1 => (shifted & 0xFF) as u64,
            2 => (shifted & 0xFFFF) as u64,
            4 => shifted as u64,
            _ => shifted as u64,
        }
    }

    /// Generates the AML bytecode node for the PM Timer device.
    fn generate_aml(&self) -> Option<Vec<u8>> {
        Some(crate::aml!(@ROOT
            Device ("PMTM") {
                Name ("_HID", "PNP0C02")
                Name ("_CRS", ResourceTemplate() {
                    FixedIO (0x608, 4)
                })
                Method ("_STA", 0) {
                    Return (0x0Fu8)
                }
            }
        ))
    }
}
