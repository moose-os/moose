mod acpica;
mod devices;
mod hid;
mod madt;
mod rsdp;
mod sdt;

pub use acpica::*;
pub use devices::*;
pub use madt::*;
pub use rsdp::*;
pub use sdt::*;

use alloc::{boxed::Box, sync::Arc};
use core::{mem, ptr, slice};

use acpica_rs::{
    AE_OK, set_os_services_implementation,
    sys::{
        ACPI_FULL_INITIALIZATION, AcpiEnableSubsystem, AcpiInitializeObjects,
        AcpiInitializeSubsystem, AcpiInitializeTables, AcpiLoadTables,
    },
};

use crate::subsystem::memory::{
    Frame, MemoryError, Page, PageFlags, PhysicalAddress, VirtualAddress, memory_manager,
};

/// Root System Description Pointer Signature
const RSDP_SIGNATURE: [u8; 8] = *b"RSD PTR ";
///  Multiple APIC Description Table (MADT)
const MADT_SIGNATURE: [u8; 4] = *b"APIC";
/// Boot Error Record Table (BERT)
const BERT_SIGNATURE: [u8; 4] = *b"BERT";
/// Corrected Platform Error Polling Table (CPEP)
const CPEP_SIGNATURE: [u8; 4] = *b"CPEP";
/// Differentiated System Description Table (DSDT)
const DSDT_SIGNATURE: [u8; 4] = *b"DSDT";
/// Embedded Controller Boot Resources Table (ECDT)
const ECDT_SIGNATURE: [u8; 4] = *b"ECDT";
/// Error Injection Table (EINJ)
const EINJ_SIGNATURE: [u8; 4] = *b"EINJ";
/// Error Record Serialization Table (ERST)
const ERST_SIGNATURE: [u8; 4] = *b"ERST";
/// Fixed ACPI Description Table (FADT)
const FADT_SIGNATURE: [u8; 4] = *b"FACP";
/// Firmware ACPI Control Structure (FACS)
const FACS_SIGNATURE: [u8; 4] = *b"FACS";
/// Hardware Error Source Table (HEST)
const HEST_SIGNATURE: [u8; 4] = *b"HEST";
/// Maximum System Characteristics Table (MSCT)
const MSCT_SIGNATURE: [u8; 4] = *b"MSCT";
/// Memory Power State Table (MPST)
const MPST_SIGNATURE: [u8; 4] = *b"MPST";
/// Platform Memory Topology Table (PMTT)
const PMTT_SIGNATURE: [u8; 4] = *b"PMTT";
/// Persistent System Description Table (PSDT)
const PSDT_SIGNATURE: [u8; 4] = *b"PSDT";
/// ACPI RAS Feature Table (RASF)
const RASF_SIGNATURE: [u8; 4] = *b"RASF";
/// Root System Description Table
const RSDT_SIGNATURE: [u8; 4] = *b"RSDT";
/// Smart Battery Specification Table (SBST)
const SBST_SIGNATURE: [u8; 4] = *b"SBST";
/// System Locality System Information Table (SLIT)
const SLIT_SIGNATURE: [u8; 4] = *b"SLIT";
/// System Resource Affinity Table (SRAT)
const SRAT_SIGNATURE: [u8; 4] = *b"SRAT";
/// Secondary System Description Table (SSDT)
const SSDT_SIGNATURE: [u8; 4] = *b"SSDT";
/// Extended System Description Table (XSDT; 64-bit version of the RSDT)
const XSDT_SIGNATURE: [u8; 4] = *b"XSDT";

const BIOS_EXTENDED_AREA_MEMORY_START: u64 = 0x000E0000;
const BIOS_EXTENDED_AREA_MEMORY_END: u64 = 0x000FFFFF;
const PAGE_NUMBER_MASK: u64 = 0xFFFF_FFFF_F000;

pub struct Acpi {
    pub rsdp: Rsdp,
    pub madt: Arc<Madt>,
}

impl Acpi {
    pub fn from_rsdp(rsdp: *const Rsdp) -> Acpi {
        assert!(!rsdp.is_null());

        assert!(unsafe { &*rsdp }.verify_checksum(), "Invalid RSDP");

        let rsdt_address = unsafe { &*rsdp }.rsdt_address as u64;

        assert!(rsdt_address != 0, "RSDP must contain valid address to RSDT");

        {
            let mut memory_manager = memory_manager().write();

            match unsafe {
                memory_manager.map_for_current_address_space(
                    &Page::new(VirtualAddress::new(rsdt_address & 0xFFFF_FFFF_F000)),
                    &Frame::new(PhysicalAddress::new(rsdt_address & 0xFFFF_FFFF_F000)),
                    PageFlags::empty(),
                )
            } {
                // If page was unmapped, and we've just mapped it, it's ok
                Ok(()) => {}
                // If page was already mapped, it means that we have mapped it in previous loop
                // iteration, and it's ok
                Err(MemoryError::AlreadyMapped) => {}
                // In case of any other error bail out
                Err(err) => {
                    panic!("Memory error: {}", err);
                }
            };
        }

        let mut madt = None;

        let rsdt_header_slice = unsafe {
            slice::from_raw_parts(rsdt_address as *const u8, mem::size_of::<SdtHeader>())
        };
        let rsdt_header = unsafe { &*rsdt_header_slice.as_ptr().cast::<SdtHeader>() };

        // Iterate over pointers to another tables
        for entry in 0..((rsdt_header.length - (mem::size_of::<SdtHeader>() as u32)) / 4) as u64 {
            // Get address to the pointer to another table
            let address_to_pointer_to_another_table =
                (rsdt_address + (mem::size_of::<SdtHeader>() as u64) + (entry * 4)) as *const u32;
            let pointer_to_entry_header =
                unsafe { ptr::read_unaligned(address_to_pointer_to_another_table) };

            // Map table into memory
            unsafe {
                let page_number = pointer_to_entry_header as u64 & PAGE_NUMBER_MASK;
                match memory_manager().write().map_for_current_address_space(
                    &Page::new(VirtualAddress::new(page_number)),
                    &Frame::new(PhysicalAddress::new(page_number)),
                    PageFlags::empty(),
                ) {
                    // If page was unmapped, and we've just mapped it, it's ok
                    Ok(()) => {}
                    // If page was already mapped, it means that we have mapped it in previous loop
                    // iteration, and it's ok
                    Err(MemoryError::AlreadyMapped) => {}
                    // In case of any other error bail out
                    Err(err) => {
                        panic!("Memory error: {}", err);
                    }
                }
            };

            // We need to first parse every entry header, create slice and then parse it, because
            // we need to create safe slice around this table and the only way we can get the slice
            // length is by reading the entry header.
            let entry_header = unsafe { &*(pointer_to_entry_header as *const SdtHeader) };
            let slice = unsafe {
                slice::from_raw_parts(
                    pointer_to_entry_header as *const u8,
                    entry_header.length as usize,
                )
            };

            if entry_header.signature == MADT_SIGNATURE {
                madt = Some(Arc::new(Madt::try_from(slice).unwrap()));
            }
        }

        // Map memory mapped I/O frames of the first and the second HPET (high precision event timer)
        {
            let mut memory_manager = memory_manager().write();

            unsafe {
                memory_manager
                    .map_identity_for_current_address_space(
                        &Page::new(VirtualAddress::new(0xFED00000)),
                        PageFlags::WRITABLE | PageFlags::WRITE_THROUGH | PageFlags::DISABLE_CACHING,
                    )
                    .unwrap();

                memory_manager
                    .map_identity_for_current_address_space(
                        &Page::new(VirtualAddress::new(0xFED80000)),
                        PageFlags::WRITABLE | PageFlags::WRITE_THROUGH | PageFlags::DISABLE_CACHING,
                    )
                    .unwrap()
            }
        }

        Self {
            rsdp: unsafe { *rsdp },
            madt: madt.expect("MADT must be present."),
        }
    }

    fn validate_checksum(_header: &SdtHeader) -> bool {
        todo!()
    }
}

#[derive(Debug)]
pub enum AcpicaError {
    InitializeSubsystem,
    InitializeTables,
    LoadTables,
    EnableSubsystem,
    InitializeObjects,
}

pub unsafe fn initialize_acpica() -> Result<(), AcpicaError> {
    set_os_services_implementation(Box::new(MooseAcpicaOsImplementation {}));

    if unsafe { AcpiInitializeSubsystem() } != AE_OK {
        return Err(AcpicaError::InitializeSubsystem);
    }

    if unsafe { AcpiInitializeTables(ptr::null_mut(), 16, true as u8) } != AE_OK {
        return Err(AcpicaError::InitializeTables);
    }

    if unsafe { AcpiLoadTables() } != AE_OK {
        return Err(AcpicaError::LoadTables);
    }

    if unsafe { AcpiEnableSubsystem(ACPI_FULL_INITIALIZATION) } != AE_OK {
        return Err(AcpicaError::EnableSubsystem);
    }

    if unsafe { AcpiInitializeObjects(ACPI_FULL_INITIALIZATION) } != AE_OK {
        return Err(AcpicaError::InitializeObjects);
    }

    Ok(())
}
