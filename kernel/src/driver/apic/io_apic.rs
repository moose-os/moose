use crate::driver::acpi::MadtIoApic;
use crate::memory::{memory_manager, MemoryError, Page, PageFlags, VirtualAddress};
use bitfield_struct::bitfield;
use core::ptr;
use log::debug;

const IO_APIC_ID_REGISTER: u32 = 0x00;
const IO_APIC_VERSION_REGISTER: u32 = 0x01;
const IO_APIC_REDIRECTION_TABLE_START: u32 = 0x10;

#[derive(Debug, Clone)]
pub struct IoApic {
    pub madt_io_apic: MadtIoApic,
    register_select_ptr: *mut u32,
    register_data_ptr: *mut u32,
}

impl IoApic {
    pub fn new(madt_io_apic: MadtIoApic) -> Self {
        let register_select_ptr = madt_io_apic.io_apic_address as *mut u32;
        let register_data_ptr = (madt_io_apic.io_apic_address + 0x10) as *mut u32;

        unsafe {
            if let Err(e) = memory_manager()
                .write()
                .map_identity_for_current_address_space(
                    &Page::new(VirtualAddress::new(madt_io_apic.io_apic_address as u64)),
                    PageFlags::WRITABLE | PageFlags::WRITE_THROUGH,
                )
            {
                match e {
                    MemoryError::AlreadyMapped => {}
                    invalid => panic!("{}", invalid),
                }
            }
        }

        let io_apic = Self {
            madt_io_apic,
            register_select_ptr,
            register_data_ptr,
        };

        io_apic.print_debug_info();

        io_apic
    }

    pub fn redirect_interrupt(&self, redirection_entry: RedirectionEntry, irq: u8) {
        self.write_register(
            (IO_APIC_REDIRECTION_TABLE_START as u8 + irq * 2) as u32,
            redirection_entry.0 as u32,
        );
        self.write_register(
            (IO_APIC_REDIRECTION_TABLE_START as u8 + irq * 2 + 1) as u32,
            (redirection_entry.0 >> 32) as u32,
        );
    }

    pub fn get_redirection_entry_count(&self) -> u32 {
        ((self.read_register(IO_APIC_VERSION_REGISTER) >> 16) & 0xFF) + 1
    }

    pub fn print_debug_info(&self) {
        let id = (self.read_register(IO_APIC_ID_REGISTER) >> 24) & 0xF0;
        let ver = self.read_register(IO_APIC_VERSION_REGISTER) & 0xFF;
        let redir_entry_count = ((self.read_register(IO_APIC_VERSION_REGISTER) >> 16) & 0xFF) + 1;

        debug!(
            "IO APIC: ID={}, VER={}, REDIRECTION_ENTRY_COUNT={}, GSIB={}",
            id, ver, redir_entry_count, self.madt_io_apic.global_system_interrupt_base
        );
    }

    fn write_register(&self, register: u32, value: u32) {
        unsafe {
            // Select register
            ptr::write_volatile(self.register_select_ptr, register);

            // Write data
            ptr::write_volatile(self.register_data_ptr, value);
        }
    }

    fn read_register(&self, register: u32) -> u32 {
        unsafe {
            // Select register
            ptr::write_volatile(self.register_select_ptr, register);

            // Read data
            ptr::read_volatile(self.register_data_ptr)
        }
    }
}

unsafe impl Send for IoApic {}

#[bitfield(u64)]
pub struct RedirectionEntry {
    pub interrupt_vector: u8,
    #[bits(3)]
    pub delivery_mode: DeliveryMode,
    #[bits(1)]
    pub destination_mode: DestinationMode,
    #[bits(1)]
    pub delivery_status: u8,
    #[bits(1)]
    pub pin_polarity: PinPolarity,
    #[bits(1)]
    pub remote_irr: u8,
    #[bits(1)]
    pub trigger_mode: TriggerMode,
    pub mask: bool,
    #[bits(39)]
    pub reserved: u64,
    pub destination: u8,
}

#[derive(Debug)]
#[repr(u8)]
pub enum DeliveryMode {
    Fixed,
    LowestPriority,
    SystemManagementInterrupt,
    NonMaskableInterrupt,
    Initialization,
    ExternalInitialization,
}

impl DeliveryMode {
    const fn into_bits(self) -> u8 {
        match self {
            DeliveryMode::Fixed => 0b000,
            DeliveryMode::LowestPriority => 0b001,
            DeliveryMode::SystemManagementInterrupt => 0b010,
            DeliveryMode::NonMaskableInterrupt => 0b100,
            DeliveryMode::Initialization => 0b101,
            DeliveryMode::ExternalInitialization => 0b111,
        }
    }

    const fn from_bits(bits: u8) -> Self {
        match bits {
            0b000 => DeliveryMode::Fixed,
            0b001 => DeliveryMode::LowestPriority,
            0b010 => DeliveryMode::SystemManagementInterrupt,
            0b100 => DeliveryMode::NonMaskableInterrupt,
            0b101 => DeliveryMode::Initialization,
            0b111 => DeliveryMode::ExternalInitialization,
            _ => unreachable!(),
        }
    }
}

#[derive(Debug)]
#[repr(u8)]
pub enum DestinationMode {
    Physical,
    Logical,
}

impl DestinationMode {
    const fn into_bits(self) -> u8 {
        match self {
            DestinationMode::Physical => 0,
            DestinationMode::Logical => 1,
        }
    }

    const fn from_bits(bits: u8) -> Self {
        match bits {
            0 => DestinationMode::Physical,
            1 => DestinationMode::Logical,
            _ => unreachable!(),
        }
    }
}

#[derive(Debug)]
#[repr(u8)]
pub enum PinPolarity {
    ActiveHigh,
    ActiveLow,
}

impl PinPolarity {
    const fn into_bits(self) -> u8 {
        match self {
            PinPolarity::ActiveHigh => 0,
            PinPolarity::ActiveLow => 1,
        }
    }

    const fn from_bits(bits: u8) -> Self {
        match bits {
            0 => PinPolarity::ActiveHigh,
            1 => PinPolarity::ActiveLow,
            _ => unreachable!(),
        }
    }
}

#[derive(Debug)]
#[repr(u8)]
pub enum TriggerMode {
    Edge,
    Level,
}

impl TriggerMode {
    const fn into_bits(self) -> u8 {
        match self {
            TriggerMode::Edge => 0,
            TriggerMode::Level => 1,
        }
    }

    const fn from_bits(bits: u8) -> Self {
        match bits {
            0 => Self::Edge,
            1 => Self::Level,
            _ => unreachable!(),
        }
    }
}
