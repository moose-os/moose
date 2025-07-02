use crate::arch::x86::asm::{inb, inw, outb, outl, outw};
use crate::driver::apic::{
    DeliveryMode, DestinationMode, PinPolarity, RedirectionEntry, TriggerMode,
};
use crate::driver::io::device_manager::register_device_interrupt;
use crate::driver::io::DriverId;
use crate::kernel::kernel_ref;
use crate::memory::{memory_manager, Page, PageFlags, VirtualAddress, PAGE_SIZE};
use crate::{block_driver, bus_driver};
use alloc::borrow::ToOwned;
use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use alloc::{format, vec};
use core::cmp::min;
use core::mem::transmute;
use core::sync::atomic::Ordering;
use deku::bitvec::{BitSlice, Msb0};
use deku::{DekuError, DekuRead};
use goblin::elf;
use hashbrown::HashMap;
use io::device_manager::DeviceRef;
use io::{
    BlockDriver, BusDriver, Device, DeviceId, DeviceProperties, DriverBase, DriverError,
    DriverPredicate, NetworkDriver, DEVICE_ID_COUNTER,
};
use log::{debug, info};
use raw_cpuid::{CpuId, Hypervisor};
use spin::{Mutex, RwLock};

use super::io::{self, InterruptBasedDriver};
use super::pci::{PciDeviceClass, PciDeviceClassMassStorageControllerSubclass};

const ATA_PRIMARY_IO_PORT: u16 = 0x1F0;
const ATA_SECONDARY_IO_PORT: u16 = 0x170;
const ATA_PRIMARY_IRQ: u32 = 14;
const ATA_SECONDARY_IRQ: u32 = 15;

const ATA_SECTOR_SIZE: u32 = 512;
const ATA_CAPABILITY_DMA_LBA: u16 = 1 << 9;
const ATA_PRD_MARK_END: u16 = 0x8000;

// Disks
const ATA_MASTER: u8 = 0;
const ATA_SLAVE: u8 = 1;

// Channels
const ATA_PRIMARY: u8 = 0;
const ATA_SECONDARY: u8 = 1;

// Registers
const ATA_REG_DATA: u16 = 0x0;
const ATA_REG_ERROR: u16 = 0x1;
const ATA_REG_SECCOUNT0: u16 = 0x2;
const ATA_REG_LBA0: u16 = 0x3;
const ATA_REG_LBA1: u16 = 0x4;
const ATA_REG_LBA2: u16 = 0x5;
const ATA_REG_HDDEVSEL: u16 = 0x6;
const ATA_REG_COMMAND: u16 = 0x7;
const ATA_REG_STATUS: u16 = 0x7;
const ATA_REG_SECCOUNT1: u16 = 0x8;
const ATA_REG_LBA3: u16 = 0x9;
const ATA_REG_LBA4: u16 = 0xA;
const ATA_REG_LBA5: u16 = 0xB;
const ATA_REG_CONTROL: u16 = 0xC;
const ATA_REG_ALTSTATUS: u16 = 0xC;
const ATA_REG_DEVADDRESS: u16 = 0xD;

// Command/Status Port bits
// Error
const ATA_SR_ERR: u8 = 0x01;
// Index
const ATA_SR_IDX: u8 = 0x02;
// Corrected data
const ATA_SR_CORR: u8 = 0x04;
// Data request ready
const ATA_SR_DRQ: u8 = 0x08;
// Drive seek complete
const ATA_SR_DSC: u8 = 0x10;
// Drive write fault
const ATA_SR_DF: u8 = 0x20;
// Drive ready
const ATA_SR_DRDY: u8 = 0x40;
// Busy
const ATA_SR_BSY: u8 = 0x80;

// Commands
const ATA_CMD_READ_PIO: u8 = 0x20;
const ATA_CMD_READ_PIO_EXT: u8 = 0x24;
const ATA_CMD_READ_DMA: u8 = 0xC8;
const ATA_CMD_READ_DMA_EXT: u8 = 0x25;
const ATA_CMD_WRITE_PIO: u8 = 0x30;
const ATA_CMD_WRITE_PIO_EXT: u8 = 0x34;
const ATA_CMD_WRITE_DMA: u8 = 0xCA;
const ATA_CMD_WRITE_DMA_EXT: u8 = 0x35;
const ATA_CMD_CACHE_FLUSH: u8 = 0xE7;
const ATA_CMD_CACHE_FLUSH_EXT: u8 = 0xEA;
const ATA_CMD_PACKET: u8 = 0xA0;
const ATA_CMD_IDENTIFY_PACKET: u8 = 0xA1;
const ATA_CMD_IDENTIFY: u8 = 0xEC;

static mut ATA_GLOBAL_LOCK: Mutex<bool> = Mutex::new(true);

pub type Sector = [u8; ATA_SECTOR_SIZE as usize];

#[derive(Clone, Copy, Debug, Default)]
#[repr(C, packed)]
struct PhysicalRegionDescriptor {
    buffer_physical_address: u32,
    transfer_size: u16,
    mark_end: u16,
}

#[derive(Debug)]
pub struct AtaBusDriver {}

impl AtaBusDriver {
    fn check_disk(bus: u8, drive: u8, controller: &Device) -> Option<Device> {
        let io_base = match bus {
            ATA_PRIMARY => ATA_PRIMARY_IO_PORT,
            ATA_SECONDARY => ATA_SECONDARY_IO_PORT,
            _ => unreachable!(),
        };

        // Select disk
        outb(
            io_base + ATA_REG_HDDEVSEL,
            match drive {
                ATA_MASTER => 0xA0,
                ATA_SLAVE => 0xB0,
                _ => unreachable!(),
            },
        );

        // Zero some registers
        outb(io_base + ATA_REG_SECCOUNT0, 0);
        outb(io_base + ATA_REG_LBA0, 0);
        outb(io_base + ATA_REG_LBA1, 0);
        outb(io_base + ATA_REG_LBA2, 0);

        // Send IDENTIFY command
        outb(io_base + ATA_REG_COMMAND, ATA_CMD_IDENTIFY);

        // Check if drive exists
        if inb(io_base + ATA_REG_STATUS) == 0 {
            return None;
        }

        // Poll until BSY bit clears
        let mut error = false;
        loop {
            let status = inb(io_base + ATA_REG_STATUS);
            if (status & ATA_SR_ERR) != 0 {
                // Disk is not valid ATA drive (can be valid ATAPI tho)
                error = true;
                break;
            }
            if (status & ATA_SR_BSY) == 0 && (status & ATA_SR_DRQ) != 0 {
                // Valid ATA disk
                break;
            }
        }

        if error {
            // Check if it's ATAPI drive
            let lba1 = inb(io_base + ATA_REG_LBA1);
            let lba2 = inb(io_base + ATA_REG_LBA2);

            if (lba1 == 0x14 && lba2 == 0xEB) || (lba1 == 0x69 && lba2 == 0x96) {
                // Valid ATAPI disk
                debug!("Found valid ATAPI disk, skipping...");
            } else {
                // Invalid disk (not existent device?)
            }

            return None;
        }

        // Read IDENTITY command response (it's not possible using DMA so need to use PIO mode)
        let mut identify_response = [0u16; (ATA_SECTOR_SIZE / 2) as usize];
        for i in 0..(ATA_SECTOR_SIZE / 2) as usize {
            identify_response[i] = inw(io_base + ATA_REG_DATA);
        }

        let identify_response_as_bytes: [u8; 512] = unsafe { transmute(identify_response) };
        let parsed_identify_response =
            AtaIdentityResponse::try_from(identify_response_as_bytes.as_slice()).unwrap();

        // We don't support disks without DMA or LBA addressing (LBA can be easily converted to CHS,
        // but reading using PIO mode is so slow)
        if parsed_identify_response.capabilities & ATA_CAPABILITY_DMA_LBA == 0 {
            return None;
        }

        Some(Device {
            id: unsafe { DEVICE_ID_COUNTER.fetch_add(1, Ordering::Relaxed) },
            vendor_id: controller.vendor_id,
            device_id: controller.device_id,
            driver: None,
            children: vec![],
            properties: DeviceProperties::PCI {
                address: {
                    let DeviceProperties::PCI {
                        address,
                        inner_identificator: _,
                    } = controller.properties;
                    address
                },
                inner_identificator: ((bus as u64) << 8) | (drive as u64),
            },
            can_be_bus_controller: false,
        })
    }
}

impl DriverBase for AtaBusDriver {
    fn attach(&self, _device: DeviceRef) -> Result<(), DriverError> {
        todo!()
    }

    fn detach(&self, _device: DeviceRef) -> Result<(), DriverError> {
        todo!()
    }

    fn supported_devices(&self) -> Result<DriverPredicate, DriverError> {
        Ok(DriverPredicate::PciClass(
            PciDeviceClass::MassStorageController(
                PciDeviceClassMassStorageControllerSubclass::IdeController,
            ),
        ))
    }

    fn initialize(&mut self, driver_id: io::DriverId) -> Result<(), DriverError> {
        todo!()
    }

    fn deinitialize(&self) -> Result<(), DriverError> {
        todo!()
    }
}

impl BusDriver for AtaBusDriver {
    fn supports_bus_capability(&self) -> bool {
        true
    }

    fn enumerate_devices(&self, device: &Device) -> Result<Vec<Device>, DriverError> {
        let mut disks = vec![];

        for bus in [ATA_PRIMARY, ATA_SECONDARY] {
            for drive in [ATA_MASTER, ATA_SLAVE] {
                if let Some(disk) = Self::check_disk(bus, drive, device) {
                    disks.push(disk);
                }
            }
        }

        debug!("Found {} ATA disks", disks.len());

        Ok(disks)
    }
}

impl InterruptBasedDriver for AtaBusDriver {}

bus_driver!(AtaBusDriver);

#[derive(Debug)]
pub struct AtaDiskDriver {
    pub disks: RwLock<HashMap<DeviceId, AtaDiskState>>,
    pub driver_id: DriverId,
}

#[derive(Debug)]
pub struct AtaDiskState {
    bus: u8,
    drive: u8,
    size_in_sectors: u32,
    prdt_page: u64,
    bar1: u32,
    bar3: u32,
    bar4: u32,
    dma_allowed: bool,
}

impl AtaDiskDriver {
    fn prepare_prdt(&self, prdt_page: u64, sector_count: usize, buffer: &[u8]) {
        const PRD_SIZE: usize = size_of::<PhysicalRegionDescriptor>();

        // Make sure PRDT will fit in one page frame. This effectively limits ATA reads to 512
        // sectors, or 256 KiB
        assert_eq!(PRD_SIZE, 8);
        assert!((sector_count * PRD_SIZE) < PAGE_SIZE);

        let prdt = prdt_page as *mut [PhysicalRegionDescriptor; PAGE_SIZE / PRD_SIZE];

        let mut address = buffer.as_ptr().addr();
        let mut offset_within_page = address & 0xFFF;
        let mut remaining_length = buffer.len();
        let mut index = 0;

        loop {
            // Convert virtual address of buffer to physical address (they don't have to be
            // contiguous)
            let physical_address = memory_manager()
                .read()
                .translate_virtual_address_to_physical_for_current_address_space(
                    VirtualAddress::new(address as u64),
                )
                .unwrap()
                .as_u64();

            // PRD allows DMA only to 32-bit physical addresses
            assert!(physical_address <= u32::MAX as u64);

            // Calculate bytes to transfer as minimum of (remaining bytes in this page) and
            // (remaining bytes of transfer)
            let to_transfer = min(remaining_length, PAGE_SIZE - offset_within_page);

            // Fill in PRD
            let prd = unsafe { &mut (*prdt)[index] as &mut PhysicalRegionDescriptor };
            *prd = PhysicalRegionDescriptor {
                buffer_physical_address: physical_address as u32,
                transfer_size: to_transfer as u16,
                mark_end: 0,
            };

            address += to_transfer;
            offset_within_page = address & 0xFFF;
            remaining_length -= to_transfer;

            // If there's no more data to transfer, then quit
            if remaining_length == 0 {
                break;
            } else {
                index += 1;
            }
        }

        // Mark last PRD as last entry in PRDT.
        unsafe { (*prdt)[index].mark_end = ATA_PRD_MARK_END };

        assert_eq!(
            buffer.as_ptr().addr() + sector_count * ATA_SECTOR_SIZE as usize,
            address
        );
    }

    fn io_wait(&self, disk: &AtaDiskState) {
        // Every I/O read from this port takes ~100ns and specification say we should wait
        // ~400ns between resets
        let port = match (disk.bus) {
            ATA_PRIMARY => self.get_io_base(disk) + disk.bar1 as u16 + 2, // For the primary channel, ALTSTATUS/CONTROL port is BAR1 + 2.
            ATA_SECONDARY => self.get_io_base(disk) + disk.bar3 as u16 + 2, // For the secondary channel, ALTSTATUS/CONTROL port is BAR3 + 2.
            _ => unreachable!(),
        };

        for _ in 0..4 {
            _ = inb(port);
        }
    }
    fn select_drive(&self, state: &AtaDiskState) {
        // 0x40 because we need LBA bit set
        outb(
            self.get_io_base(state) + ATA_REG_HDDEVSEL,
            0x40 | (state.drive << 4),
        );
    }
    fn get_io_base(&self, state: &AtaDiskState) -> u16 {
        match state.bus {
            ATA_PRIMARY => ATA_PRIMARY_IO_PORT,
            ATA_SECONDARY => ATA_SECONDARY_IO_PORT,
            _ => unreachable!(),
        }
    }
}

impl DriverBase for AtaDiskDriver {
    fn attach(&self, device: DeviceRef) -> Result<(), DriverError> {
        let DeviceProperties::PCI {
            address: _,
            inner_identificator,
        } = device.properties;
        let bus = (inner_identificator >> 8) as u8;
        let drive = inner_identificator as u8;
        let dma_allowed =
            CpuId::new().get_hypervisor_info().unwrap().identify() == Hypervisor::QEMU;

        if !dma_allowed {
            debug!("Moose is not running under QEMU, so DMA has been disabled and I/O ports will be used instead, which may impact performance.");
        }

        let io_base = match bus {
            ATA_PRIMARY => ATA_PRIMARY_IO_PORT,
            ATA_SECONDARY => ATA_SECONDARY_IO_PORT,
            _ => unreachable!(),
        };

        let pci_device = device.to_pci_device().unwrap();
        pci_device.enable_dma();

        let mut bar1 = pci_device.get_bar(1);
        let mut bar3 = pci_device.get_bar(3);
        let mut bar4 = pci_device.get_bar(4);

        if (bar4 & 0x1) != 1 {
            // We dont support memory based accesses
            return Err(DriverError::AttachFailed);
        }

        // Cut information bit from register address
        bar4 &= 0xfffc;

        // Select disk
        outb(
            io_base + ATA_REG_HDDEVSEL,
            match drive {
                ATA_MASTER => 0xA0,
                ATA_SLAVE => 0xB0,
                _ => unreachable!(),
            },
        );

        // Zero some registers
        outb(io_base + ATA_REG_SECCOUNT0, 0);
        outb(io_base + ATA_REG_LBA0, 0);
        outb(io_base + ATA_REG_LBA1, 0);
        outb(io_base + ATA_REG_LBA2, 0);

        // Send IDENTIFY command
        outb(io_base + ATA_REG_COMMAND, ATA_CMD_IDENTIFY);

        // Poll until BSY bit clears
        while (inb(io_base + ATA_REG_STATUS) & ATA_SR_BSY) != 0 {}

        // Read IDENTITY command response (it's not possible using DMA so need to use PIO mode)
        let mut identify_response = [0u16; (ATA_SECTOR_SIZE / 2) as usize];
        for i in 0..(ATA_SECTOR_SIZE / 2) as usize {
            identify_response[i] = inw(io_base + ATA_REG_DATA);
        }

        let identify_response_as_bytes: [u8; 512] = unsafe { transmute(identify_response) };
        let parsed_identify_response =
            AtaIdentityResponse::try_from(identify_response_as_bytes.as_slice()).unwrap();

        // Allocate page for DMA transfers
        let prdt_page = {
            let mut memory_manager = memory_manager().write();

            let frame = memory_manager.allocate_frame().unwrap().address().as_u64();

            unsafe {
                memory_manager
                    .map_identity_for_current_address_space(
                        &Page::new(VirtualAddress::new(frame)),
                        PageFlags::WRITABLE | PageFlags::DISABLE_CACHING,
                    )
                    .unwrap();
            };

            // Physical address needs to fit in 32 bits
            assert!(frame <= u32::MAX as u64);

            frame
        };

        let disk_state = AtaDiskState {
            bus,
            drive,
            size_in_sectors: parsed_identify_response.capacity,
            prdt_page,
            bar1,
            bar3,
            bar4,
            dma_allowed,
        };

        self.disks.write().insert(device.id, disk_state);

        Ok(())
    }

    fn detach(&self, device: DeviceRef) -> Result<(), DriverError> {
        self.disks.write().remove(&device.id);

        Ok(())
    }

    fn supported_devices(&self) -> Result<DriverPredicate, DriverError> {
        // controller and children devices both have the same pci class id and pci address
        // so there's no reliable way to dont pass newly-created-device again to the bus driver
        // and avoid infinite loop.

        Ok(DriverPredicate::PciClass(
            PciDeviceClass::MassStorageController(
                PciDeviceClassMassStorageControllerSubclass::IdeController,
            ),
        ))
    }

    fn initialize(&mut self, driver_id: DriverId) -> Result<(), DriverError> {
        self.driver_id = driver_id;

        Ok(())
    }

    fn deinitialize(&self) -> Result<(), DriverError> {
        todo!()
    }
}

impl BlockDriver for AtaDiskDriver {
    fn supports_block_capabilities(&self) -> bool {
        true
    }

    fn block_size(&self) -> u64 {
        ATA_SECTOR_SIZE as u64
    }

    fn read_block(&self, device_id: DeviceId, block_id: u64) -> Result<Vec<u8>, io::DriverError> {
        let disks = self.disks.read();
        let state = disks.get(&device_id).unwrap();

        assert!(block_id < state.size_in_sectors as u64);

        // Allocate data buffer
        let mut buffer = [0u8; ATA_SECTOR_SIZE as usize];
        let slice = buffer.as_mut_slice();

        // Need to hold this lock until DMA transfer completes because ATA is not thread safe
        let _ = unsafe { ATA_GLOBAL_LOCK.lock() };
        let io_base = self.get_io_base(state);

        // If we can't use DMA, then use shorter (but slower) PIO path
        if !state.dma_allowed {
            self.select_drive(state);
            outb(io_base + ATA_REG_SECCOUNT0, 0);
            outb(io_base + ATA_REG_LBA0, (block_id >> 24) as u8);
            outb(io_base + ATA_REG_LBA1, (block_id >> 32) as u8);
            outb(io_base + ATA_REG_LBA2, (block_id >> 40) as u8);
            outb(io_base + ATA_REG_SECCOUNT0, 1);
            outb(io_base + ATA_REG_LBA0, (block_id >> 0) as u8);
            outb(io_base + ATA_REG_LBA0, (block_id >> 8) as u8);
            outb(io_base + ATA_REG_LBA0, (block_id >> 16) as u8);
            outb(io_base + ATA_REG_COMMAND, ATA_CMD_READ_PIO_EXT);

            self.io_wait(state);

            // Poll until BSY bit clears
            while (inb(io_base + ATA_REG_STATUS) & ATA_SR_BSY) != 0 {}

            for i in 0..(ATA_SECTOR_SIZE / 2) as usize {
                let data = inw(io_base + ATA_REG_DATA);
                slice[i * 2] = data as u8;
                slice[i * 2 + 1] = (data >> 8) as u8;
            }

            return Ok(buffer.to_vec());
        }

        // DMA allowed

        // Get BMR command register from PCI configuration space BAR4
        let bmr_command_register = state.bar4 as u16;

        let bmr_status_register = bmr_command_register + 2;
        let bmr_prdt_register = bmr_command_register + 4;

        // Prepare PhysicalRegionDescriptor Table
        self.prepare_prdt(state.prdt_page, 1, slice);

        // Select drive
        //
        // We can do that because we don't support LBA48 (yet)
        // @TODO: Add support for LBA48
        self.select_drive(state);

        // Reset BMR command register
        outb(bmr_command_register, 0);

        // Clear interrupt and error bits in status register
        // This is weird register, because we clear bits by issuing write with these bits set.
        outb(bmr_status_register, inb(bmr_status_register) | 0x2 | 0x4);

        // Set PRDT entry (it's identity mapped)
        outl(bmr_prdt_register, state.prdt_page as u32);

        // Set DMA in read mode
        outb(bmr_command_register, 0x8);

        self.io_wait(state);

        // Allow ATA interrupts
        outb(io_base + ATA_REG_ALTSTATUS, 0);

        // Set feature/error register to 0
        outb(io_base + ATA_REG_ERROR, 0);

        // Set sector count and LBA
        outb(io_base + ATA_REG_SECCOUNT0, 1 as u8);
        outb(io_base + ATA_REG_LBA0, block_id as u8);
        outb(io_base + ATA_REG_LBA1, (block_id >> 8) as u8);
        outb(io_base + ATA_REG_LBA2, (block_id >> 16) as u8);

        // Write the READ DMA to the command register
        outb(io_base + ATA_REG_COMMAND, ATA_CMD_READ_DMA);

        // Start DMA reading
        outb(bmr_command_register, 0x8 | 0x1);

        // @TODO: Interrupts instead of polling
        loop {
            let status = inb(io_base + ATA_REG_STATUS);

            if status & ATA_SR_BSY == 0 && status & ATA_SR_DRQ != 0 {
                debug!("BMR status register: {}", inb(bmr_status_register));
                break;
            }
        }

        Ok(slice.to_vec())
    }

    fn write_block(
        &self,
        device_id: DeviceId,
        block_id: u64,
        data: &[u8],
    ) -> Result<(), DriverError> {
        let disks = self.disks.read();
        let state = disks.get(&device_id).unwrap();
        assert!(block_id < state.size_in_sectors as u64);

        // Need to hold this lock until DMA transfer completes because ATA is not thread safe
        let _ = unsafe { ATA_GLOBAL_LOCK.lock() };

        // Get BMR command register from PCI configuration space BAR4
        let bmr_command_register = state.bar4 as u16;
        let bmr_prdt_register = bmr_command_register + 4;

        // Prepare PRDT
        self.prepare_prdt(state.prdt_page, 1, data);

        // Select drive
        //
        // We can do that because we don't support LBA48 (yet)
        // @TODO: Add support for LBA48
        self.select_drive(state);

        // Reset BMR command register
        outb(bmr_command_register, 0);

        // Set PRDT entry (it's identity mapped)
        outl(bmr_prdt_register, state.prdt_page as u32);

        // Set sector count and LBA
        outb(self.get_io_base(state) + ATA_REG_SECCOUNT0, 1);
        outb(self.get_io_base(state) + ATA_REG_LBA0, block_id as u8);
        outb(
            self.get_io_base(state) + ATA_REG_LBA1,
            (block_id >> 8) as u8,
        );
        outb(
            self.get_io_base(state) + ATA_REG_LBA2,
            (block_id >> 16) as u8,
        );

        // Write the READ DMA to the command register
        outb(self.get_io_base(state) + ATA_REG_COMMAND, ATA_CMD_WRITE_DMA);

        // Start DMA reading
        outb(bmr_command_register, 0x1);

        // @TODO: Interrupts instead of polling
        loop {
            let status = inb(self.get_io_base(state) + ATA_REG_STATUS);

            if status & ATA_SR_BSY == 0 && status & ATA_SR_DRQ != 0 {
                break;
            }
        }

        Ok(())
    }
}

impl NetworkDriver for AtaDiskDriver {} // default impl
impl BusDriver for AtaDiskDriver {} // default impl
impl InterruptBasedDriver for AtaDiskDriver {} // default impl
impl io::Driver for AtaDiskDriver {} // default impl

// We don't really care about all reported fields and options
#[derive(DekuRead, Debug)]
struct AtaIdentityResponse {
    #[deku(
        pad_bytes_before = "52",
        reader = "AtaIdentityResponse::read_model_number(deku::rest)"
    )]
    _model_number: String,
    #[deku(pad_bytes_before = "6")]
    capabilities: u16,
    #[deku(pad_bytes_before = "14", pad_bytes_after = "394")]
    capacity: u32,
}

impl AtaIdentityResponse {
    fn read_model_number(
        rest: &BitSlice<u8, Msb0>,
    ) -> Result<(&BitSlice<u8, Msb0>, String), DekuError> {
        let mut buffer = [0u8; 40];
        let mut remaining_slice = rest;

        // ATA reports model number in some cringe format with swapped bytes, so we need to
        // "unswap" it to make it a "real" string
        for i in 0..20 {
            let higher_byte;
            let lower_byte;

            (remaining_slice, higher_byte) = u8::read(remaining_slice, ())?;
            (remaining_slice, lower_byte) = u8::read(remaining_slice, ())?;

            buffer[i * 2] = lower_byte;
            buffer[i * 2 + 1] = higher_byte;
        }

        let string = String::from_utf8_lossy(&buffer)
            .trim_start()
            .trim_end()
            .to_owned();

        Ok((remaining_slice, string))
    }
}
