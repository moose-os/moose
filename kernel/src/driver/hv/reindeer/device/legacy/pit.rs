//! Virtual Intel 8254 Programmable Interval Timer (PIT) Device Model.
//!
//! The 8254 PIT provides legacy system timer services for the guest OS. It consists of
//! 3 independent counter channels driven by an internal base oscillator running at
//! 1.193182 MHz (`PIT_HZ`).
//!
//! ### Channel Assignments
//! - Channel 0 (`0x40`): System Timer Interrupt (IRQ0 / IO-APIC IRQ2 pin override).
//! - Channel 1 (`0x41`): Legacy DRAM refresh timer (typically unused by modern OSes).
//! - Channel 2 (`0x42`): PC Speaker tone generator and system status control.
//! - Command Register (`0x43`): Write-only control register for operating modes and latching.
//!
//! ### Time Virtualization Architecture
//! Counter values are not updated via continuous real-time ticking loops. Instead, counter values
//! are dynamically calculated on-demand based on the CPU Time Stamp Counter (TSC) delta retrieved
//! from [`GuestClock`].

use alloc::{sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicBool, Ordering};

use spin::rwlock::RwLock;

use crate::driver::hv::reindeer::{
    device::{
        DeviceResource, VirtualDevice,
        interrupt::{io_apic::VirtualIoApic, pic::ProgrammableInterruptControllerDevice},
    },
    guest::clock::GuestClock,
};

/// Standard 8254 master clock frequency (Hz).
const PIT_HZ: u64 = 1_193_182;

/// Internal state tracking for an individual 8254 PIT counter channel.
struct PitChannel {
    /// Cached current counter value (16-bit).
    count: u16,

    /// Reload value loaded by the guest to determine the counting period.
    reload_value: u16,

    /// PIT Operating Mode (Mode 0: Interrupt on Terminal Count, Mode 2: Rate Generator, Mode 3: Square Wave).
    mode: u8,

    /// Tracks byte sequencing for multi-byte I/O writes.
    access_state: AccessState,

    /// Tracks byte sequencing for multi-byte I/O reads.
    read_state: AccessState,

    /// Holds a latched counter snapshot captured when a Counter Latch command (`0x43`) is issued.
    latched_value: Option<u16>,

    /// Guest TSC value corresponding to the last time this channel's counter was reloaded.
    last_tsc: u64,

    /// Guest TSC value when the last IRQ interrupt was delivered for channel.
    last_irq_tsc: u64,

    /// Gate input bit status.
    gate_enabled: bool,

    /// PIT access command (1 = LSB only, 2 = MSB only, 3 = LSB then MSB).
    access_mode: u8,

    /// Channel 0 is waiting to generate an IRQ (oneshot) or is in periodic mode.
    irq_armed: bool,
}

/// Represents the current byte access phase for 16-bit counter register I/O operations.
#[derive(Clone, Copy)]
enum AccessState {
    /// Next access targets the Least Significant Byte (LSB).
    Lsb,

    /// Next access targets the Most Significant Byte (MSB).
    Msb,
}

impl PitChannel {
    /// Creates a default, uninitialized PIT channel.
    fn new() -> Self {
        Self {
            count: 0,
            reload_value: 0,
            mode: 0,
            access_state: AccessState::Lsb,
            read_state: AccessState::Lsb,
            latched_value: None,
            last_tsc: 0,
            last_irq_tsc: 0,
            gate_enabled: true,
            access_mode: 3,
            irq_armed: false,
        }
    }
}

/// Virtual 8254 Programmable Interval Timer (PIT) device structure.
///
/// Manages 3 counter channels and routes interrupt signals
/// to both the legacy PIC and the I/O APIC.
pub struct VirtualPit {
    /// Array of 3 independent PIT channels.
    channels: RwLock<[PitChannel; 3]>,

    /// Shared reference to the virtual 8259 Programmable Interrupt Controller.
    pic: Arc<RwLock<ProgrammableInterruptControllerDevice>>,

    /// Shared reference to the I/O APIC.
    io_apic: Arc<RwLock<VirtualIoApic>>,

    /// Monotonic guest clock provider derived from physical/virtual CPU TSC.
    guest_clock: Arc<GuestClock>,

    /// Set once OS programs IOAPIC pin 2 with a valid timer vector.
    /// After that, a masked pin means "stop PIT IRQ0".
    ioapic_timer_enabled: AtomicBool,
}

impl VirtualPit {
    /// Creates a new `VirtualPit` instance.
    pub fn new(
        pic: Arc<RwLock<ProgrammableInterruptControllerDevice>>,
        io_apic: Arc<RwLock<VirtualIoApic>>,
        guest_clock: Arc<GuestClock>,
    ) -> Arc<RwLock<Self>> {
        Arc::new(RwLock::new(Self {
            channels: RwLock::new([PitChannel::new(), PitChannel::new(), PitChannel::new()]),
            pic,
            io_apic,
            guest_clock,
            ioapic_timer_enabled: AtomicBool::new(false),
        }))
    }

    /// Dynamically computes the current countdown value for a channel based on elapsed TSC ticks.
    ///
    /// Converts elapsed CPU TSC cycles to equivalent 1.193182 MHz PIT oscillator ticks.
    fn get_current_count(channel: &PitChannel, guest_clock: &GuestClock) -> u16 {
        let current_tsc = guest_clock.now_tsc();
        let tsc_elapsed = current_tsc - channel.last_tsc;
        let cpu_hz = guest_clock.tsc_hz();

        // Convert CPU TSC ticks to PIT ticks.
        // Use u128 to avoid overflow.
        let ticks_elapsed = ((tsc_elapsed as u128 * PIT_HZ as u128) / cpu_hz as u128) as u64;

        // A reload_value of 0 in hardware acts as 65536 ticks
        let reload = if channel.reload_value == 0 {
            65536
        } else {
            channel.reload_value as u64
        };

        let current_offset = ticks_elapsed % reload;

        (reload - current_offset) as u16
    }

    fn is_periodic(mode: u8) -> bool {
        matches!(mode, 2 | 3)
    }

    fn commit_reload(channel: &mut PitChannel, now: u64) {
        channel.last_tsc = now;
        channel.last_irq_tsc = now;
        channel.count = channel.reload_value;

        let shutdown = !Self::is_periodic(channel.mode) && channel.reload_value == 0;
        channel.irq_armed = !shutdown;
    }

    fn deliver_irq0(&self) {
        let io_apic = self.io_apic.read();
        let ioapic_live = !io_apic.is_pin_masked(2);
        if ioapic_live {
            self.ioapic_timer_enabled.store(true, Ordering::Relaxed);
            drop(io_apic);

            self.io_apic.write().set_irq(2, true);
            self.io_apic.write().set_irq(2, false);

            return;
        }
        drop(io_apic);

        if self.ioapic_timer_enabled.load(Ordering::Relaxed) {
            return;
        }

        self.pic.write().raise_irq(0);
    }

    /// Checks elapsed time and fires timer interrupts for Channel 0 if due.
    ///
    /// Modes 2/3 are periodic. Modes 0/1/4/5 are one-shot.
    /// Returns `true` if an interrupt was generated.
    pub fn check_timer(&self) -> bool {
        let mut channels = self.channels.write();
        let channel = &mut channels[0];

        if !channel.irq_armed {
            return false;
        }

        let effective_reload = if channel.reload_value == 0 {
            65536u64
        } else {
            channel.reload_value as u64
        };

        let current_tsc = self.guest_clock.now_tsc();
        let cpu_hz = self.guest_clock.tsc_hz();
        let fire_interval =
            ((cpu_hz as u128 * effective_reload as u128) / PIT_HZ as u128).max(1) as u64;

        if channel.last_irq_tsc == 0 {
            channel.last_irq_tsc = current_tsc;
            return false;
        }

        let elapsed = current_tsc.wrapping_sub(channel.last_irq_tsc);
        if elapsed < fire_interval {
            return false;
        }

        let periodic = Self::is_periodic(channel.mode);
        if periodic {
            let periods = elapsed / fire_interval;
            channel.last_irq_tsc = channel.last_irq_tsc.wrapping_add(periods * fire_interval);
        } else {
            channel.irq_armed = false;
            channel.last_irq_tsc = current_tsc;
        }

        drop(channels);

        self.deliver_irq0();

        true
    }

    /// Sets the hardware Gate status for PIT Channel 2 (controlled by Port 0x61 Bit 0).
    pub fn set_channel2_gate(&self, enabled: bool) {
        let mut channels = self.channels.write();
        let ch2 = &mut channels[2];

        ch2.gate_enabled = enabled;

        if enabled {
            ch2.last_tsc = self.guest_clock.now_tsc();
        }
    }

    /// Computes the live state of the Channel 2 Output pin (OUT2) for Port 0x61 Bit 5 read-back.
    pub fn get_channel2_out(&self) -> bool {
        let channels = self.channels.read();
        let ch = &channels[2];
        if !ch.gate_enabled {
            return false;
        }

        let current_tsc = self.guest_clock.now_tsc();
        let tsc_elapsed = current_tsc.saturating_sub(ch.last_tsc);
        let cpu_hz = self.guest_clock.tsc_hz();
        if cpu_hz == 0 {
            return false;
        }

        let ticks_elapsed = ((tsc_elapsed as u128 * PIT_HZ as u128) / cpu_hz as u128) as u64;
        let reload = if ch.reload_value == 0 {
            65536u64
        } else {
            ch.reload_value as u64
        };

        match ch.mode {
            // Mode 0: Interrupt on Terminal Count (OUT stays HIGH once counter reaches 0)
            0 => ticks_elapsed >= reload,

            // Mode 2 & 3: Rate Generator / Square Wave
            2 | 3 => {
                let current_offset = ticks_elapsed % reload;

                (reload - current_offset) > (reload / 2)
            }
            _ => ticks_elapsed >= reload,
        }
    }

    /// Internal handler for I/O write operations directed to ports `0x40`–`0x43` and `0x61`.
    fn handle_io_write_inner(&mut self, port: u16, value: u8) {
        match port {
            0x40..=0x42 => {
                let idx = (port - 0x40) as usize;
                let now = self.guest_clock.now_tsc();
                let mut channels = self.channels.write();
                let channel = &mut channels[idx];

                match channel.access_mode {
                    1 => {
                        channel.reload_value = value as u16;

                        Self::commit_reload(channel, now);
                    }
                    2 => {
                        channel.reload_value = (value as u16) << 8;

                        Self::commit_reload(channel, now);
                    }
                    _ => match channel.access_state {
                        AccessState::Lsb => {
                            channel.reload_value = (channel.reload_value & 0xFF00) | (value as u16);
                            channel.access_state = AccessState::Msb;
                        }
                        AccessState::Msb => {
                            channel.reload_value =
                                (channel.reload_value & 0x00FF) | ((value as u16) << 8);
                            channel.access_state = AccessState::Lsb;

                            Self::commit_reload(channel, now);
                        }
                    },
                }
            }
            0x43 => {
                let channel_idx = (value >> 6) & 0x03;
                if channel_idx < 3 {
                    let mut channels = self.channels.write();
                    let channel = &mut channels[channel_idx as usize];
                    let access_mode = (value >> 4) & 0x03;

                    if access_mode == 0 {
                        channel.count = Self::get_current_count(channel, &self.guest_clock);
                        channel.latched_value = Some(channel.count);
                        channel.read_state = AccessState::Lsb;
                    } else {
                        channel.mode = (value >> 1) & 0x07;
                        channel.access_mode = access_mode;
                        channel.access_state = AccessState::Lsb;
                        channel.read_state = AccessState::Lsb;
                        channel.irq_armed = false;

                        if channel_idx == 0 {
                            channel.last_irq_tsc = 0;
                        }
                    }
                }
            }
            _ => {}
        }
    }

    /// Internal handler for I/O read operations from ports `0x40`–`0x42` and `0x61`.
    fn handle_io_read_inner(&mut self, port: u16) -> u8 {
        match port {
            // Channel 0, 1, or 2 Data Registers
            0x40..=0x42 => {
                let idx = (port - 0x40) as usize;
                let mut channels = self.channels.write();
                let channel = &mut channels[idx];

                // Use latched value if present; otherwise, compute live count dynamically
                let val_to_read = channel
                    .latched_value
                    .unwrap_or_else(|| Self::get_current_count(channel, &self.guest_clock));

                match channel.read_state {
                    AccessState::Lsb => {
                        channel.read_state = AccessState::Msb;

                        (val_to_read & 0xFF) as u8
                    }
                    AccessState::Msb => {
                        channel.read_state = AccessState::Lsb;
                        channel.latched_value = None; // Clear latch after reading MSB

                        ((val_to_read >> 8) & 0xFF) as u8
                    }
                }
            }
            _ => 0xFF,
        }
    }
}

impl VirtualDevice for VirtualPit {
    /// Returns the human-readable device name.
    fn name(&self) -> &str {
        "8254 PIT"
    }

    /// Claims I/O ports `0x40`–`0x43` (PIT channels/control) and `0x61` (System Control Port B).
    fn get_resources(&self) -> Vec<DeviceResource> {
        alloc::vec![
            DeviceResource::IoPort { port: 0x40 },
            DeviceResource::IoPort { port: 0x41 },
            DeviceResource::IoPort { port: 0x42 },
            DeviceResource::IoPort { port: 0x43 },
        ]
    }

    /// Handles guest I/O port read requests and services pending Channel 0 timer IRQs.
    fn handle_io_read(&mut self, _cpu_id: usize, addr: u64, _width: u8) -> u64 {
        let value = self.handle_io_read_inner(addr as u16);

        let _ = self.check_timer();

        value as u64
    }

    /// Handles guest I/O port write requests and services pending Channel 0 timer IRQs.
    fn handle_io_write(&mut self, _cpu_id: usize, addr: u64, value: u64, width: u8) {
        let port = addr as u16;

        if (0x40..=0x42).contains(&port) && width >= 2 {
            let now = self.guest_clock.now_tsc();
            let mut channels = self.channels.write();
            let channel = &mut channels[(port - 0x40) as usize];

            channel.reload_value = value as u16;
            channel.access_state = AccessState::Lsb;

            Self::commit_reload(channel, now);
        } else {
            self.handle_io_write_inner(port, value as u8);
        }

        let _ = self.check_timer();
    }

    /// Generates AML byte stream for the `PIT0` device node in the ACPI DSDT namespace.
    ///
    /// Declares `PNP0100` (Standard 8254 PIT) with a Fixed I/O range at `0x40` (length 4).
    fn generate_aml(&self) -> Option<Vec<u8>> {
        Some(crate::aml!(@ROOT
            Device ("PIT0") {
                Name ("_HID", "PNP0100")
                Name ("_CRS", ResourceTemplate() {
                    FixedIO (0x40, 4)
                })
                Method ("_STA", 0) {
                    Return (0x0Fu8)
                }
            }
        ))
    }
}
