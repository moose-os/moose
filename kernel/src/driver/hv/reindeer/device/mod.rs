//! # System Bus and Virtual Device Subsystem
//!
//! This module provides the central I/O and MMIO routing architecture for the VMM.
//! It is responsible for mapping physical guest resources (x86 I/O ports and Memory-Mapped I/O regions)
//! to virtual hardware devices, and dispatching guest VM-exits to the appropriate `VirtualDevice` handlers.
//!
//! ## Key Components
//!
//! * [`VirtualDevice`]: Trait implemented by all emulated hardware devices (e.g., UART, PCI host bridge, I/O APIC).
//! * [`SystemBus`]: Thread-safe central bus manager holding lookup tables for I/O ports and MMIO ranges.
//! * [`DeviceResource`]: Enumeration of physical/virtual resources requested by emulated devices.
//!
//! ## Unclaimed Legacy Hardware & Probing
//!
//! Modern guest operating systems (such as Linux or Windows during boot) aggressively probe
//! standard legacy x86 hardware ranges (e.g., ISA DMA, Floppy Controllers, Parallel Ports, Gameports,
//! and Motherboard Super-I/O chips) via x86 `IN`/`OUT` instructions.
//!
//! To prevent host panics when guests probe these unmapped addresses, [`SystemBus::is_legacy_device_port`]
//! identifies known legacy ranges:
//! * Reads (`IN`): Emulate open-bus/floating bus pull-up behavior (returning `0xFF`, `0xFFFF`, or `0xFFFFFFFF`),
//!   or `0x00` for devices like ATA and i8042 where `0xFF` would signal active busy flags (`BSY=1`) and cause guest kernel boot loops.
//! * Writes (`OUT`): Silently dropped.

use alloc::{collections::btree_map::BTreeMap, sync::Arc, vec::Vec};
use core::range::RangeInclusive;

use iced_x86::Register;
use spin::rwlock::RwLock;

use self::interrupt::io_apic::VirtualIoApic;
use crate::driver::hv::reindeer::guest::registers::CpuState;

pub mod interrupt;
pub mod legacy;
pub mod pci;

/// Shared services provided to virtual devices after the VM platform is initialized.
#[derive(Clone)]
pub struct DeviceContext {
    /// Guest interrupt controller used by devices to assert IRQ lines.
    pub io_apic: Arc<RwLock<VirtualIoApic>>,
}

/// Represents a system hardware resource requested or occupied by a virtual device.
#[derive(Debug, Clone, Copy)]
pub enum DeviceResource {
    /// A single 16-bit x86 I/O port address.
    IoPort { port: u16 },

    /// A half-open range of contiguous I/O ports `[base, base + size)`.
    IoPortRange { base: u16, size: u16 },

    /// A Memory-Mapped I/O (MMIO) physical guest address range `[base, base + size)`.
    Mmio { base: u64, size: u64 },
}

/// Core interface implemented by all virtual devices managed by the hypervisor.
pub trait VirtualDevice: Send {
    /// Connects the device to services created as part of the guest platform.
    fn attach(&mut self, _context: &DeviceContext) {
        // Most devices do not require platform services.
    }

    /// Returns the human-readable identifier of the virtual device.
    fn name(&self) -> &str;

    /// Enumerates all system resources (I/O ports, MMIO ranges, IRQs) required by this device.
    fn get_resources(&self) -> Vec<DeviceResource>;

    /// Handles an x86 Port I/O read cycle (`IN` instruction) targeting a port owned by this device.
    ///
    /// # Parameters
    /// * `_cpu_id`: ID of the CPU the instruction was executed on.
    /// * `_addr`: Port address being read.
    /// * `_width`: Read access width in bytes (1, 2, or 4).
    ///
    /// # Returns
    /// The register value read by the guest CPU zero-extended to `u64`.
    fn handle_io_read(&mut self, _cpu_id: usize, addr: u64, _width: u8) -> u64 {
        unimplemented!(
            "Unimplemented IO read from addr=0x{:x}, device={}",
            addr,
            self.name()
        )
    }

    /// Handles an x86 Port I/O write cycle (`OUT` instruction) targeting a port owned by this device.
    ///
    /// # Parameters
    /// * `_cpu_id`: ID of the CPU the instruction was executed on.
    /// * `_addr`: Port address being written to.
    /// * `_value`: Data value written by the guest CPU.
    /// * `_width`: Write access width in bytes (1, 2, or 4).
    fn handle_io_write(&mut self, _cpu_id: usize, addr: u64, _value: u64, _width: u8) {
        unimplemented!(
            "Unimplemented IO write to addr=0x{:x}, device={}",
            addr,
            self.name()
        )
    }

    /// Handles a Memory-Mapped I/O (MMIO) read exit originating from guest instruction access.
    ///
    /// # Parameters
    /// * `_cpu_id`: ID of the CPU the instruction was executed on.
    /// * `_addr`: Guest physical address of the MMIO access.
    /// * `_width`: Access width in bytes (1, 2, 4, or 8).
    /// * `_register`: Destination architectural CPU register parsed by the instruction decoder.
    /// * `_guest_registers`: Mutable handle to the guest CPU architectural state for register update.
    ///
    /// # Returns
    /// The decoded value read from the MMIO register.
    fn handle_mmio_read(
        &mut self,
        _cpu_id: usize,
        addr: u64,
        _width: u8,
        _register: Register,
        _guest_registers: &mut CpuState,
    ) -> u64 {
        unimplemented!(
            "Unimplemented MMIO read from addr=0x{:x}, device={}",
            addr,
            self.name()
        )
    }

    /// Handles a Memory-Mapped I/O (MMIO) write exit.
    ///
    /// # Parameters
    /// * `_cpu_id`: ID of the CPU the instruction was executed on.
    /// * `_addr`: Guest physical address being written to.
    /// * `_value`: Data value being written.
    /// * `_width`: Access width in bytes (1, 2, 4, or 8).
    fn handle_mmio_write(&mut self, _cpu_id: usize, addr: u64, _value: u64, _width: u8) {
        unimplemented!(
            "Unimplemented MMIO write to addr=0x{:x}, device={}",
            addr,
            self.name()
        )
    }

    /// Generates ACPI Machine Language (AML) byte sequence describing this device for DSDT/SSDT tables.
    ///
    /// Returns `None` if the device does not require ACPI enumeration.
    fn generate_aml(&self) -> Option<Vec<u8>>;
}

/// Internal mapping entry binding an inclusive physical MMIO memory range to a virtual device instance.
struct MmioEntry {
    /// Inclusive physical memory address interval `[start, end]`.
    pub range: RangeInclusive<u64>,

    /// Thread-safe reference to the target virtual device handling this range.
    pub device: Arc<RwLock<dyn VirtualDevice>>,
}

/// The central system bus holding address mappings for guest Port I/O and MMIO spaces.
///
/// `SystemBus` routes VM-exit events caused by guest hardware accesses to the registered [`VirtualDevice`].
pub struct SystemBus {
    /// Lookup table mapping individual 16-bit x86 I/O ports to virtual devices.
    io_map: RwLock<BTreeMap<u16, Arc<RwLock<dyn VirtualDevice>>>>,

    /// Sorted list of MMIO memory ranges for memory-mapped device dispatch.
    mmio_map: RwLock<Vec<MmioEntry>>,

    /// Complete collection of all virtual devices registered on this system bus.
    devices: RwLock<Vec<Arc<RwLock<dyn VirtualDevice>>>>,
}

impl SystemBus {
    /// Constructs a new, unpopulated `SystemBus`.
    pub fn new() -> Self {
        Self {
            io_map: RwLock::new(BTreeMap::new()),
            mmio_map: RwLock::new(Vec::new()),
            devices: RwLock::new(Vec::new()),
        }
    }

    /// Registers a virtual device on the system bus and maps all of its declared resources.
    ///
    /// This method queries `device.get_resources()` and automatically populates internal I/O and MMIO
    /// dispatch maps.
    pub fn register_device(&mut self, device: Arc<RwLock<dyn VirtualDevice>>) {
        let resources = device.read().get_resources();

        for res in resources {
            match res {
                DeviceResource::IoPort { port } => {
                    self.io_map.write().insert(port, device.clone());
                }
                DeviceResource::IoPortRange { base, size } => {
                    self.map_io_range(base, size, device.clone());
                }
                DeviceResource::Mmio { base, size } => {
                    self.map_mmio(base, size, device.clone());
                }
            }
        }

        self.devices.write().push(device);
    }

    /// Maps a physical Memory-Mapped I/O address range `[base, base + size)` to a virtual device.
    pub fn map_mmio(&self, base: u64, size: u64, device: Arc<RwLock<dyn VirtualDevice>>) {
        assert!(size > 0, "map_mmio size must be non-zero");

        let mut map = self.mmio_map.write();

        map.push(MmioEntry {
            range: RangeInclusive::from(base..=base + size - 1),
            device,
        });

        map.sort_by_key(|entry| entry.range.start);
    }

    /// Unmaps a previously registered MMIO region starting at `base` with `size` bytes.
    pub fn unmap_mmio(&self, base: u64, size: u64) {
        if size == 0 {
            return;
        }

        let end = base + size - 1;

        self.mmio_map
            .write()
            .retain(|entry| !(entry.range.start == base && entry.range.last == end));
    }

    /// Maps a contiguous range of x86 I/O ports `[base, base + size)` to a virtual device.
    pub fn map_io_range(&self, base: u16, size: u16, device: Arc<RwLock<dyn VirtualDevice>>) {
        assert!(size > 0, "IoPortRange size must be non-zero");

        let end = base
            .checked_add(size)
            .expect("IoPortRange overflows u16 port space");

        let mut map = self.io_map.write();
        for port in base..end {
            map.insert(port, device.clone());
        }
    }

    /// Unmaps a contiguous range of x86 I/O ports starting at `base`.
    pub fn unmap_io_range(&self, base: u16, size: u16) {
        if size == 0 {
            return;
        }

        let Some(end) = base.checked_add(size) else {
            return;
        };

        let mut map = self.io_map.write();
        for port in base..end {
            map.remove(&port);
        }
    }

    /// Returns a vector snapshot of all virtual devices currently registered on this bus.
    pub fn devices(&self) -> Vec<Arc<RwLock<dyn VirtualDevice>>> {
        self.devices.read().clone()
    }

    /// Discovers standard IBM PC COM UART serial port base addresses present on this bus.
    ///
    /// Used during system initialization to populate legacy BIOS Data Area (BDA at physical address `0x400`).
    /// Returns up to 4 sorted, deduplicated base addresses matching standard COM ranges (`0x3F8`, `0x2F8`, `0x3E8`, `0x2E8`).
    pub fn uart_io_bases(&self) -> Vec<u16> {
        const COM_BASES: [u16; 4] = [0x3F8, 0x2F8, 0x3E8, 0x2E8];

        let mut bases: Vec<u16> = self
            .devices
            .read()
            .iter()
            .flat_map(|device| device.read().get_resources())
            .filter_map(|res| match res {
                DeviceResource::IoPort { port } => Some(port),
                DeviceResource::IoPortRange { base, size } if size >= 8 => Some(base),
                _ => None,
            })
            .filter(|port| COM_BASES.contains(port))
            .collect();

        bases.sort_unstable();
        bases.dedup();
        bases.truncate(4);
        bases
    }

    /// Dispatches an x86 Port I/O read access (`IN` instruction) from the guest.
    ///
    /// # Resolution Logic
    /// 1. Checks if a device is registered at `port` in `io_map`.
    /// 2. If unclaimed, checks [`Self::is_legacy_device_port`]:
    ///    * ATA/IDE (`0x1F0..0x1F7`) & i8042 (`0x60`, `0x64`) return `0` (clearing busy status flags).
    ///    * Other legacy probe ports return floating-bus open values (`0xFF`, `0xFFFF`, `0xFFFFFFFF`).
    /// 3. If the port is completely unknown, panics to highlight unhandled guest I/O access.
    pub fn dispatch_io_read(&self, cpu_id: usize, port: u16, width: u8) -> u64 {
        if let Some(dev) = self.io_map.read().get(&port) {
            dev.write().handle_io_read(cpu_id, port as u64, width)
        } else if Self::is_legacy_device_port(port) {
            // Special cases for specific legacy devices where floating open-bus 0xFF causes boot hangs:
            //
            // 1. Unclaimed ATA/IDE (0x1F0–0x1F7, 0x3F6, 0x170–0x177, 0x376):
            //    Reading 0xFF interprets bit 7 (BSY) as set. Returning 0xFF causes guest drivers
            //    (e.g. Linux `pata_legacy`) to spin forever in an infinite wait loop. Returning 0x00
            //    signals an empty bus with no device attached.
            //
            // 2. i8042 Keyboard Controller (0x60, 0x64):
            //    Returning 0x00 keeps Output Buffer Full (OBF) and Input Buffer Full (IBF) cleared,
            //    allowing guest drivers to gracefully report "No PS/2 controller found".
            if matches!(
                port,
                0x1f0..=0x1f7 | 0x3f6 | 0x170..=0x177 | 0x376 | 0x60 | 0x64
            ) {
                return 0;
            }

            // Standard open-bus (floating bus) hardware behavior:
            // Unconnected physical data lines with pull-up resistors read as all 1s.
            match width {
                1 => 0xFF,
                2 => 0xFFFF,
                4 => 0xFFFF_FFFF,
                _ => panic!("Bad read width {} at port {:#x}", width, port),
            }
        } else {
            panic!("Unknown read from port {:#x} width={}", port, width)
        }
    }

    /// Dispatches an x86 Port I/O write access (`OUT` instruction) from the guest.
    ///
    /// If the port belongs to a registered device, the write is passed to its handler.
    /// Writes to unclaimed legacy hardware ports identified by [`Self::is_legacy_device_port`]
    /// are silently discarded. Unexpected writes to unmapped ports trigger a panic.
    pub fn dispatch_io_write(&self, cpu_id: usize, port: u16, width: u8, value: u64) {
        if let Some(dev) = self.io_map.read().get(&port) {
            dev.write()
                .handle_io_write(cpu_id, port as u64, value, width)
        } else if Self::is_legacy_device_port(port) {
            // Known absent hardware / legacy probe range — silently drop write.
        } else {
            panic!(
                "Unknown write to port {:#x} width={} value={:#x}",
                port, width, value
            )
        }
    }

    /// Checks whether an I/O port address belongs to a known legacy hardware device,
    /// motherboard Super-I/O controller, or ISA probe window.
    ///
    /// Operating systems aggressively probe these ranges during kernel bring-up to discover legacy PC hardware.
    pub fn is_legacy_device_port(port: u16) -> bool {
        matches!(
            port,
            // 8237 ISA DMA channels & page registers
            0x00..=0x0f | 0x80..=0x8f | 0xc0..=0xdf
            // Legacy COM serial ports (COM1–COM4)
            | 0x3f8..=0x3ff | 0x2f8..=0x2ff | 0x3e8..=0x3ef | 0x2e8..=0x2ef
            // Legacy ATA/IDE (Primary & Secondary command/control)
            | 0x1f0..=0x1f7 | 0x3f6 | 0x170..=0x177 | 0x376
            // Parallel LPT ports (LPT1–LPT3 + ECP/EPP extensions)
            | 0x3bc..=0x3be | 0x378..=0x37a | 0x278..=0x27a | 0x7bc..=0x7be | 0x778..=0x77a | 0x678..=0x67a
            // Legacy Floppy Disk Controller
            | 0x3f0..=0x3f5 | 0x3f7 | 0x377
            // Gameport / Joystick probe window
            | 0x200..=0x20f
            // Miscellaneous ISA probe window
            | 0x100..=0x11f
            // Legacy platform / watchdog / RTC probe ports (including 0x6D / 109)
            | 0x6a | 0x6b | 0x6d | 0x91
            // Super-I/O & motherboard watchdog probe ports
            | 0x162e | 0x162f | 0x164e | 0x164f
            // ISA bring-up probe window
            | 0x2100..=0x210f
            // i8042 PS/2 Keyboard/Mouse controller
            | 0x60 | 0x64
            // Super-I/O index/data config space (SMSC/ITE/Nuvoton)
            | 0x2e | 0x2f | 0x4e | 0x4f
            // Old flash devices
            | 0x258 | 0x259
            // Old ISA
            | 0x300..=0x370 | 0x220..=0x2ff
            // Various old devices
            | 0x3e0 | 0x3e1 | 0x3e2 | 0x3e3 | 0x3e4 | 0x211 | 0x218 | 0x219 | 0x21a
        )
    }

    /// Dispatches a Memory-Mapped I/O read access targeting physical address `addr`.
    ///
    /// Searches `mmio_map` for a registered device containing `addr` within its range.
    /// Returns `Some(value)` if intercepted and handled, or `None` if no device claims the address.
    pub fn dispatch_mmio_read(
        &self,
        cpu_id: usize,
        addr: u64,
        width: u8,
        register: Register,
        guest_registers: &mut CpuState,
    ) -> Option<u64> {
        let mmio = self
            .mmio_map
            .read()
            .iter()
            .find(|e| e.range.contains(&addr))
            .map(|e| Arc::clone(&e.device));

        mmio.map(|dev| {
            dev.write()
                .handle_mmio_read(cpu_id, addr, width, register, guest_registers)
        })
    }

    /// Dispatches a Memory-Mapped I/O write access targeting physical address `addr`.
    ///
    /// Returns `true` if a registered device intercepted the write, or `false` if unmapped.
    pub fn dispatch_mmio_write(&self, cpu_id: usize, addr: u64, width: u8, value: u64) -> bool {
        let mmio = self
            .mmio_map
            .read()
            .iter()
            .find(|e| e.range.contains(&addr))
            .map(|e| Arc::clone(&e.device));

        if let Some(dev) = mmio {
            dev.write().handle_mmio_write(cpu_id, addr, value, width);

            true
        } else {
            false
        }
    }
}
