use alloc::{borrow::ToOwned, string::String, sync::Arc, vec, vec::Vec};
use core::{cmp::min, mem::transmute};

use deku::{
    no_std_io::{Read, Seek},
    reader::Reader,
    DekuError, DekuRead, DekuReader,
};
use spin::Mutex;

use crate::{
    arch::x86::asm::{inb, inw, outb, outl},
    driver::pci::PciDevice,
    subsystem::memory::{memory_manager, Page, PageFlags, VirtualAddress, PAGE_SIZE},
};

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

pub type Sector = [u8; ATA_SECTOR_SIZE as usize];

#[derive(Clone, Copy, Debug, Default)]
#[repr(C, packed)]
struct PhysicalRegionDescriptor {
    buffer_physical_address: u32,
    transfer_size: u16,
    mark_end: u16,
}

pub struct AtaDrive {
    bus: u8,
    drive: u8,
    pci_device: Arc<Mutex<PciDevice>>,
    size_in_sectors: u32,
    prdt_page: u64,
}

impl AtaDrive {
    pub fn read_sectors(&self, starting_sector_lba: u32, n: u32) -> Vec<Sector> {
        assert!(starting_sector_lba < self.size_in_sectors);
        assert!(starting_sector_lba + n < self.size_in_sectors);

        // Need to hold this lock until DMA transfer completes because ATA is not thread safe
        let device_lock = self.pci_device.lock();

        // Get BMR command register from PCI configuration space BAR4
        let mut bmr_command_register = device_lock.get_bar(4) as u16;

        // Lowest bit tells us whether it's MemorySpace BAR or I/O Space Bar
        assert_eq!(
            bmr_command_register & 0x1,
            1,
            "We don't support memory-mapped I/O registers"
        );

        // Cut information bit from register address
        bmr_command_register &= 0xfffc;

        let bmr_status_register = bmr_command_register + 2;
        let bmr_prdt_register = bmr_command_register + 4;

        // Allocate data buffer
        let buffer: Vec<Sector> = vec![[0u8; ATA_SECTOR_SIZE as usize]; n as usize];
        let slice = buffer.as_flattened();

        // Prepare PhysicalRegionDescriptor Table
        self.prepare_prdt(n as usize, slice);

        // Select drive
        //
        // We can do that because we don't support LBA48 (yet)
        // @TODO: Add support for LBA48
        self.select_drive();

        // Reset BMR command register
        outb(bmr_command_register, 0);

        // Clear interrupt and error bits in status register
        // This is weird register, because we clear bits by issuing write with these bits set.
        outb(bmr_status_register, inb(bmr_status_register) | 0x2 | 0x4);

        // Set PRDT entry (it's identity mapped)
        outl(bmr_prdt_register, self.prdt_page as u32);

        // Set DMA in read mode
        outb(bmr_command_register, 0x8);

        self.io_wait();

        // Allow ATA interrupts
        outb(self.get_io_base() + ATA_REG_ALTSTATUS, 0);

        // Set feature/error register to 0
        outb(self.get_io_base() + ATA_REG_ERROR, 0);

        // Set sector count and LBA
        outb(self.get_io_base() + ATA_REG_SECCOUNT0, n as u8);
        outb(self.get_io_base() + ATA_REG_LBA0, starting_sector_lba as u8);
        outb(
            self.get_io_base() + ATA_REG_LBA1,
            (starting_sector_lba >> 8) as u8,
        );
        outb(
            self.get_io_base() + ATA_REG_LBA2,
            (starting_sector_lba >> 16) as u8,
        );

        // Write the READ DMA to the command register
        outb(self.get_io_base() + ATA_REG_COMMAND, ATA_CMD_READ_DMA);

        // Start DMA reading
        outb(bmr_command_register, 0x8 | 0x1);

        // @TODO: Interrupts instead of polling
        loop {
            let status = inb(self.get_io_base() + ATA_REG_STATUS);

            if status & ATA_SR_BSY == 0 && status & ATA_SR_DRQ != 0 {
                break;
            }
        }

        buffer
    }

    pub fn write_sector(&self, starting_sector_lba: u32, data: &Sector) {
        assert!(starting_sector_lba < self.size_in_sectors);
        assert!((starting_sector_lba + ATA_SECTOR_SIZE) < self.size_in_sectors);

        // Need to hold this lock until DMA transfer completes because ATA is not thread safe
        let device_lock = self.pci_device.lock();

        // Get BMR command register from PCI configuration space BAR4
        let mut bmr_command_register = device_lock.get_bar(4) as u16;

        // Lowest bit tells us whether it's MemorySpace BAR or I/O Space Bar
        assert_eq!(
            bmr_command_register & 0x1,
            1,
            "We don't support memory-mapped I/O registers"
        );

        // Cut information bit from register address
        bmr_command_register &= 0xfffc;

        let bmr_prdt_register = bmr_command_register + 4;

        // Prepare PRDT
        self.prepare_prdt(data.len(), data);

        // Select drive
        //
        // We can do that because we don't support LBA48 (yet)
        // @TODO: Add support for LBA48
        self.select_drive();

        // Reset BMR command register
        outb(bmr_command_register, 0);

        // Set PRDT entry (it's identity mapped)
        outl(bmr_prdt_register, self.prdt_page as u32);

        // Set sector count and LBA
        outb(self.get_io_base() + ATA_REG_SECCOUNT0, 1);
        outb(self.get_io_base() + ATA_REG_LBA0, starting_sector_lba as u8);
        outb(
            self.get_io_base() + ATA_REG_LBA1,
            (starting_sector_lba >> 8) as u8,
        );
        outb(
            self.get_io_base() + ATA_REG_LBA2,
            (starting_sector_lba >> 16) as u8,
        );

        // Write the READ DMA to the command register
        outb(self.get_io_base() + ATA_REG_COMMAND, ATA_CMD_WRITE_DMA);

        // Start DMA reading
        outb(bmr_command_register, 0x1);

        // @TODO: Interrupts instead of polling
        loop {
            let status = inb(self.get_io_base() + ATA_REG_STATUS);

            if status & ATA_SR_BSY == 0 && status & ATA_SR_DRQ != 0 {
                break;
            }
        }
    }

    fn prepare_prdt(&self, sector_count: usize, buffer: &[u8]) {
        const PRD_SIZE: usize = size_of::<PhysicalRegionDescriptor>();

        // Make sure PRDT will fit in one page frame. This effectively limits ATA reads to 512
        // sectors, or 256 KiB
        assert_eq!(PRD_SIZE, 8);
        assert!((sector_count * PRD_SIZE) < PAGE_SIZE);

        let prdt = self.prdt_page as *mut [PhysicalRegionDescriptor; PAGE_SIZE / PRD_SIZE];

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

    fn io_wait(&self) {
        // Every I/O read from this port takes ~100ns and specification say we should wait
        // ~400ns between resets
        for _ in 0..4 {
            _ = inb(0x3F6);
        }
    }
    fn select_drive(&self) {
        // 0x40 because we need LBA bit set
        outb(
            self.get_io_base() + ATA_REG_HDDEVSEL,
            0x40 | (self.drive << 4),
        );
    }

    fn get_io_base(&self) -> u16 {
        match self.bus {
            ATA_PRIMARY => ATA_PRIMARY_IO_PORT,
            ATA_SECONDARY => ATA_SECONDARY_IO_PORT,
            _ => unreachable!(),
        }
    }
}

pub struct Ata;

impl Ata {
    pub fn perform_disk_discovery(pci_device: Arc<Mutex<PciDevice>>) -> Vec<AtaDrive> {
        let mut disks = vec![];

        for bus in [ATA_PRIMARY, ATA_SECONDARY] {
            for drive in [ATA_MASTER, ATA_SLAVE] {
                if let Some(disk) = Self::check_disk(bus, drive, pci_device.clone()) {
                    disks.push(disk);
                }
            }
        }

        disks
    }

    fn check_disk(bus: u8, drive: u8, pci_device: Arc<Mutex<PciDevice>>) -> Option<AtaDrive> {
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
            debug!("Disk offline");
            return None;
        }

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

        // We don't support disks without DMA or LBA addressing (LBA can be easily converted to CHS,
        // but reading using PIO mode is so slow)
        if parsed_identify_response.capabilities & ATA_CAPABILITY_DMA_LBA == 0 {
            return None;
        }

        // Enable Bus Mastering for IDE Controller (Bus Mastering is DMA for PCI)
        pci_device.lock().enable_dma();

        // Allocate page frame for DMA transfers
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

        debug!("Disk online, info: {:#?}", parsed_identify_response);

        Some(AtaDrive {
            bus,
            drive,
            pci_device,
            size_in_sectors: parsed_identify_response.capacity,
            prdt_page,
        })
    }
}

// We don't really care about all reported fields and options
#[derive(DekuRead, Debug)]
struct AtaIdentityResponse {
    #[deku(
        pad_bytes_before = "52",
        reader = "AtaIdentityResponse::read_model_number(deku::reader)"
    )]
    _model_number: String,
    #[deku(pad_bytes_before = "6")]
    capabilities: u16,
    #[deku(pad_bytes_before = "14", pad_bytes_after = "394")]
    capacity: u32,
}

impl AtaIdentityResponse {
    fn read_model_number<R: Read + Seek>(reader: &mut Reader<R>) -> Result<String, DekuError> {
        let mut buffer = [0u8; 40];

        // ATA reports model number in some cringe format with swapped bytes, so we need to
        // "unswap" it to make it a "real" string
        for i in 0..20 {
            let higher_byte = u8::from_reader_with_ctx(reader, ())?;
            let lower_byte = u8::from_reader_with_ctx(reader, ())?;

            buffer[i * 2] = lower_byte;
            buffer[i * 2 + 1] = higher_byte;
        }

        let string = String::from_utf8_lossy(&buffer)
            .trim_start()
            .trim_end()
            .to_owned();

        Ok(string)
    }
}
