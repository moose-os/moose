use alloc::{format, vec, vec::Vec};

use deku::{
    bitvec::{BitSlice, Msb0},
    DekuEnumExt, DekuError, DekuRead,
};

#[derive(DekuRead, Debug, Default)]
#[repr(C)]
#[deku(magic = b"APIC")]
pub struct Madt {
    pub length: u32,
    pub revision: u8,
    pub checksum: u8,
    #[deku(bytes = "6")]
    pub oem_id: u64,
    pub oem_table_id: u64,
    pub oem_revision: u32,
    pub creator_id: u32,
    pub creator_revision: u32,
    pub local_apic_address: u32,
    pub flags: u32,
    #[deku(reader = "madt_reader((*length as usize), deku::rest)")]
    pub entries: Vec<MadtEntry>,
}

#[derive(DekuRead, Debug, Clone)]
#[repr(C)]
pub struct MadtEntry {
    pub entry_type: u8,
    pub record_length: u8,
    #[deku(ctx = "*entry_type")]
    pub inner: MadtEntryInner,
}

#[derive(DekuRead, Debug, Clone)]
#[deku(ctx = "entry_type: u8", id = "entry_type")]
#[repr(C)]
pub enum MadtEntryInner {
    #[deku(id = "0")]
    ProcessorLocalApic(MadtProcessorLocalApic),
    #[deku(id = "1")]
    IoApic(MadtIoApic),
    #[deku(id = "2")]
    IoApicInterruptSourceOverride(MadtIoApicInterruptSourceOverride),
    #[deku(id = "3")]
    IoApicNonMaskableInterruptSource(MadtIoApicNonMaskableInterruptSource),
    #[deku(id = "4")]
    LocalApicNonMaskableInterrupts(MadtLocalApicNonMaskableInterrupts),
    #[deku(id = "5")]
    LocalApicAddressOverride(MadtLocalApicAddressOverride),
    // 6 - I/O SAPIC
    // 7 - Local SAPIC
    // 8 - Platofrm Interrupt Sources
    #[deku(id = "9")]
    ProcessorLocalx2Apic(MadtProcessorLocalx2Apic),
    // 10 - Local x2APIC NMI
    #[deku(id = "10")]
    Localx2ApicNonMaskableInterrupts(MadtLocalx2ApicNonMaskableInterrupts),
    // 11 - GIC CPU Interface
    // 12 - GIC Distributor
    // 13 - GIC MSI Frame
    // 14 - GIC Reditributor
    // 15 - GIC Interrupt Translation Sergice
    // 16 - Multiprocessor Wakeup
    // 17 - Core Programmable Interrupt Controller
    // 18 - Legacy I/O Programmable Interrupt Controller
    // 19 - HyperTransport Programmable Interrupt Controller
    // 20 - Extend I/O Programmable Interrupt Controller (EIO PIC)
    // 21 MSI Programmable Interrupt Controller (MSI PIC)
    // 22 Bridge I/O Programmable Interrupt Controller (BIO PIC)
    // 23 Low Pin Count Programmable Interrupt Controller (LPC PIC)
}

#[derive(DekuRead, Debug, Clone)]
#[repr(C)]
pub struct MadtProcessorLocalApic {
    pub acpi_processor_id: u8,
    pub apic_id: u8,
    pub flags: u32,
}

#[derive(DekuRead, Debug, Clone)]
#[repr(C)]
pub struct MadtIoApic {
    pub io_apic_id: u8,
    pub _reserved: u8,
    pub io_apic_address: u32,
    pub global_system_interrupt_base: u32,
}

#[derive(DekuRead, Debug, Clone)]
#[repr(C)]
pub struct MadtIoApicInterruptSourceOverride {
    pub nmi_source: u8,
    pub _reserved: u8,
    pub global_system_interrupt: u32,
    pub flags: u16,
}

#[derive(DekuRead, Debug, Clone)]
#[repr(C)]
pub struct MadtIoApicNonMaskableInterruptSource {
    pub flags: u16,
    pub global_system_interrupt: u32,
}

#[derive(DekuRead, Debug, Clone)]
#[repr(C)]
pub struct MadtLocalApicNonMaskableInterrupts {
    pub acpi_processor_id: u8,
    pub flags: u16,
    pub lint: u8,
}

#[derive(DekuRead, Debug, Clone)]
#[repr(C)]
pub struct MadtLocalApicAddressOverride {
    pub _reserved: u16,
    pub address: u64,
}

#[derive(DekuRead, Debug, Clone)]
#[repr(C)]
pub struct MadtProcessorLocalx2Apic {
    pub _reserved: u16,
    pub processors_local_x2apic_id: u32,
    pub flags: u32,
    pub acpi_id: u32,
}

#[derive(DekuRead, Debug, Clone)]
#[repr(C)]
pub struct MadtLocalx2ApicNonMaskableInterrupts {
    pub flags: u16,
    pub acpi_processor_uid: u32,
    pub local_x2apic_lint: u8,
    #[deku(bytes = "3")]
    pub reserved: u32,
}

fn madt_reader(
    length: usize,
    rest: &BitSlice<u8, Msb0>,
) -> Result<(&BitSlice<u8, Msb0>, Vec<MadtEntry>), DekuError> {
    let mut remaining_bytes = length - 0x2C;

    let mut entries = vec![];

    let mut rest = rest;

    while remaining_bytes > 0 {
        let (remaining_slice, entry) = MadtEntry::read(rest, ())?;

        rest = remaining_slice;
        remaining_bytes -= entry.record_length as usize;

        entries.push(entry);
    }

    Ok((rest, entries))
}
