//! ACPI table construction library.
//!
//! Provides packed C-compatible structure definitions and builder methods to assemble standard
//! ACPI static description tables (RSDP, RSDT, XSDT, FADT, HPET, and MADT) compliant with the
//! ACPI Specification (Revision 6.3+).

use alloc::vec::Vec;
use core::{
    mem::{self, offset_of},
    ptr, slice,
};

pub mod aml;

/// Root System Description Pointer (RSDP) signature string (`"RSD PTR "`).
pub const RSDP_SIGNATURE: &[u8; 8] = b"RSD PTR ";

/// Root System Description Table (RSDT) signature string (`"RSDT"`).
pub const RSDT_SIGNATURE: &[u8; 4] = b"RSDT";

/// Extended System Description Table (XSDT) signature string (`"XSDT"`).
pub const XSDT_SIGNATURE: &[u8; 4] = b"XSDT";

/// Fixed ACPI Description Table (FADT / FACP) signature string (`"FACP"`).
pub const FADT_SIGNATURE: &[u8; 4] = b"FACP";

/// Multiple APIC Description Table (MADT) signature string (`"APIC"`).
pub const MADT_SIGNATURE: &[u8; 4] = b"APIC";

/// High Precision Event Timer Table (HPET) signature string (`"HPET"`).
pub const HPET_SIGNATURE: &[u8; 4] = b"HPET";

/// OEM Identification string (6 bytes) used in table headers.
pub const OEM_ID: &[u8; 6] = b" DEER ";

/// OEM Table Identification string (8 bytes) used in table headers.
pub const OEM_TABLE_ID: &[u8; 8] = b"REINDEER";

/// Vendor ID string (4 bytes) of the ASL compiler or generator.
pub const COMPILER_ID: &[u8; 4] = b"CONE";

/// Vendor Revision ID of the ASL compiler or generator.
pub const CREATOR_ID: u32 = 0x454E4F43; // "CONE"

/// Root System Description Pointer (RSDP) structure for ACPI v2.0+.
///
/// Ref: ACPI 6.3 Spec, Section 5.2.5.3 (Table 5-27).
#[derive(Debug, Copy, Clone)]
#[repr(C, packed)]
pub struct RsdpAcpiHeader {
    /// `"RSD PTR "` signature string.
    pub signature: [u8; 8],

    /// Checksum of the first 20 bytes (ACPI 1.0 portion).
    pub checksum: u8,

    /// OEM-supplied ID string.
    pub oem_id: [u8; 6],

    /// Revision of the RSDP structure. `2` for ACPI 2.0+.
    pub revision: u8,

    /// Physical 32-bit address of the RSDT table.
    pub rsdt_address: u32,

    /// Length of the entire RSDP structure in bytes (36 bytes for ACPI 2.0+).
    pub length: u32,

    /// Physical 64-bit address of the XSDT table.
    pub xsdt_address: u64,

    /// Checksum of the entire 36-byte RSDP structure.
    pub extended_checksum: u8,

    /// Reserved bytes for alignment (must be 0).
    pub reserved: [u8; 3],
}

/// Standard System Description Table Header common to all ACPI tables except RSDP and FACS.
///
/// Ref: ACPI 6.3 Spec, Section 5.2.6 (Table 5-28).
#[derive(Debug, Copy, Clone)]
#[repr(C, packed)]
pub struct DescriptionHeader {
    /// 4-byte ASCII signature string identifying table type (e.g., `"FACP"`, `"APIC"`).
    pub signature: [u8; 4],

    /// Total size of the table in bytes, including this header.
    pub length: u32,

    /// Revision of the structure corresponding to the table signature.
    pub revision: u8,

    /// Entire table checksum (sum of all bytes in the table modulo 256 must equal 0).
    pub checksum: u8,

    /// OEM ID string identifying the system vendor.
    pub oem_id: [u8; 6],

    /// OEM Table ID string identifying the specific board or implementation.
    pub oem_table_id: [u8; 8],

    /// OEM-supplied revision number.
    pub oem_revision: u32,

    /// Vendor ID of the utility that created the table.
    pub creator_id: u32,

    /// Revision of the utility that created the table.
    pub creator_revision: u32,
}

/// Generic Address Structure (GAS) used for register location encoding.
///
/// Ref: ACPI 6.3 Spec, Section 5.2.3.2 (Table 5-25).
#[repr(C, packed)]
#[derive(Debug, Copy, Clone, Default)]
pub struct GenericAddressStructure {
    /// Address space ID: `0` = System Memory, `1` = System I/O, `2` = PCI Config.
    pub address_space_id: u8,

    /// Size of the register in bits.
    pub register_bit_width: u8,

    /// Offset of the register bit field from the given address.
    pub register_bit_offset: u8,

    /// Access size: `0` = Undefined, `1` = Byte, `2` = Word, `3` = DWord, `4` = QWord.
    pub access_size: u8,

    /// Physical base address of the register.
    pub address: u64,
}

impl GenericAddressStructure {
    /// Helper constructor to initialize an I/O Port GAS descriptor.
    ///
    /// # Arguments
    /// * `address` - Port I/O address.
    /// * `bit_width` - Width of the register in bits (8, 16, or 32).
    pub fn io(address: u64, bit_width: u8) -> Self {
        Self {
            address_space_id: 1, // Port I/O
            register_bit_width: bit_width,
            register_bit_offset: 0,
            access_size: match bit_width {
                8 => 1,
                16 => 2,
                32 => 3,
                _ => 0,
            },
            address,
        }
    }
}

/// Fixed ACPI Description Table (FADT) layout.
///
/// Ref: ACPI 6.3 Spec, Section 5.2.9 (Table 5-34).
#[derive(Debug, Copy, Clone)]
#[repr(C, packed)]
pub struct FadtAcpiHeader {
    /// Common ACPI header with signature `"FACP"`.
    pub header: DescriptionHeader,

    /// 32-bit physical address of the Firmware ACPI Control Structure (FACS).
    pub firmware_ctrl: u32,

    /// 32-bit physical address of the Differentiated System Description Table (DSDT).
    pub dsdt: u32,

    /// Reserved byte (must be zero).
    pub reserved: u8,

    /// Preferred Power Management Profile hint (e.g., `1` = Desktop).
    pub preferred_pm_profile: u8,

    /// System Vector for System Control Interrupt (SCI).
    pub sci_int: u16,

    /// System I/O port address of the System Management Interrupt (SMI) command port.
    pub smi_cmd: u32,

    /// Value written to `smi_cmd` port to disable SMI ownership and enable ACPI mode.
    pub acpi_enable: u8,

    /// Value written to `smi_cmd` port to re-enable SMI ownership and disable ACPI mode.
    pub acpi_disable: u8,

    /// Value written to `smi_cmd` port to request execution of S4BIOS state.
    pub s4bios_req: u8,

    /// System I/O port written to control processor performance states.
    pub pstate_cnt: u8,

    /// System I/O port address of PM1a Event Register Block.
    pub pm1a_evt_blk: u32,

    /// System I/O port address of PM1b Event Register Block (optional).
    pub pm1b_evt_blk: u32,

    /// System I/O port address of PM1a Control Register Block.
    pub pm1a_cnt_blk: u32,

    /// System I/O port address of PM1b Control Register Block (optional).
    pub pm1b_cnt_blk: u32,

    /// System I/O port address of PM2 Control Register Block (optional).
    pub pm2_cnt_blk: u32,

    /// System I/O port address of Power Management Timer Block.
    pub pm_timer_blk: u32,

    /// System I/O port address of General Purpose Event 0 Block.
    pub gpe0_blk: u32,

    /// System I/O port address of General Purpose Event 1 Block.
    pub gpe1_blk: u32,

    /// Byte length of `pm1a_evt_blk` and `pm1b_evt_blk`.
    pub pm1_evt_len: u8,

    /// Byte length of `pm1a_cnt_blk` and `pm1b_cnt_blk`.
    pub pm1_cnt_len: u8,

    /// Byte length of `pm2_cnt_blk`.
    pub pm2_cnt_len: u8,

    /// Byte length of `pm_timer_blk`.
    pub pm_tm_len: u8,

    /// Byte length of `gpe0_blk`.
    pub gpe0_blk_len: u8,

    /// Byte length of `gpe1_blk`.
    pub gpe1_blk_len: u8,

    /// Offset within ACPI GPE model where GPE1 interrupts start.
    pub gpe1_base: u8,

    /// System I/O port written to support C-state transition notifications.
    pub cst_cnt: u8,

    /// Worst-case latency (in microseconds) to enter and exit C2 state.
    pub p_lvl2_lat: u16,

    /// Worst-case latency (in microseconds) to enter and exit C3 state.
    pub p_lvl3_lat: u16,

    /// Size of the cache line flush area in quadwords.
    pub flush_size: u16,

    /// Stride of the cache line flush area.
    pub flush_stride: u16,

    /// Zero-based bit offset of processor duty cycle settings within P_CNT register.
    pub duty_offset: u8,

    /// Bit width of processor duty cycle settings within P_CNT register.
    pub duty_width: u8,

    /// Day of month alarm register index in RTC CMOS space.
    pub day_alrm: u8,

    /// Month alarm register index in RTC CMOS space.
    pub mon_alrm: u8,

    /// Century register index in RTC CMOS space.
    pub century: u8,

    /// IA-PC Boot Architecture Flags (e.g., legacy device capabilities).
    pub iapc_boot_arch: u16,

    /// Reserved byte (must be zero).
    pub reserved2: u8,

    /// Fixed ACPI Feature Flags.
    pub flags: u32,

    /// Generic Address Structure for the Reset Register.
    pub reset_reg: GenericAddressStructure,

    /// Value written to `reset_reg` to initiate system reset.
    pub reset_value: u8,

    /// Reserved bytes (must be zero).
    pub reserved3: [u8; 3],

    /// 64-bit physical address of the FACS table.
    pub x_firmware_ctrl: u64,

    /// 64-bit physical address of the DSDT table.
    pub x_dsdt: u64,

    /// 64-bit Extended GAS for PM1a Event Register Block.
    pub x_pm1a_evt_blk: GenericAddressStructure,

    /// 64-bit Extended GAS for PM1b Event Register Block.
    pub x_pm1b_evt_blk: GenericAddressStructure,

    /// 64-bit Extended GAS for PM1a Control Register Block.
    pub x_pm1a_cnt_blk: GenericAddressStructure,

    /// 64-bit Extended GAS for PM1b Control Register Block.
    pub x_pm1b_cnt_blk: GenericAddressStructure,

    /// 64-bit Extended GAS for PM2 Control Register Block.
    pub x_pm2_cnt_blk: GenericAddressStructure,

    /// 64-bit Extended GAS for PM Timer Register Block.
    pub x_pm_timer_blk: GenericAddressStructure,

    /// 64-bit Extended GAS for GPE0 Register Block.
    pub x_gpe0_blk: GenericAddressStructure,

    /// 64-bit Extended GAS for GPE1 Register Block.
    pub x_gpe1_blk: GenericAddressStructure,

    /// 64-bit Extended GAS for Sleep Control Register.
    pub sleep_control_reg: GenericAddressStructure,

    /// 64-bit Extended GAS for Sleep Status Register.
    pub sleep_status_reg: GenericAddressStructure,

    /// Hypervisor Vendor Identity tag string (8 bytes).
    pub hypervisor_vendor_identity: [u8; 8],
}

/// Multiple APIC Description Table (MADT) main header.
///
/// Ref: ACPI 6.3 Spec, Section 5.2.12 (Table 5-43).
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct MadtHeader {
    /// Common ACPI header with signature `"APIC"`.
    pub header: DescriptionHeader,

    /// Physical base address of the Local APIC for each CPU (usually `0xFEE00000`).
    pub local_apic_address: u32,

    /// Multiple APIC flags. Bit 0: PC-AT dual 8259 PIC compatibility.
    pub flags: u32,
}

/// Local APIC Structure (MADT Entry Type 0).
///
/// Ref: ACPI 6.3 Spec, Section 5.2.12.2 (Table 5-46).
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct MadtLocalApic {
    /// Entry type (`0` for Processor Local APIC).
    pub entry_type: u8,

    /// Entry length in bytes (`8`).
    pub length: u8,

    /// ACPI Processor ID.
    pub processor_id: u8,

    /// Physical Local APIC ID.
    pub apic_id: u8,

    /// Flags. Bit 0: Enabled, Bit 1: Online Capable.
    pub flags: u32,
}

/// I/O APIC Structure (MADT Entry Type 1).
///
/// Ref: ACPI 6.3 Spec, Section 5.2.12.3 (Table 5-47).
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct MadtIoApic {
    /// Entry type (`1` for I/O APIC).
    pub entry_type: u8,

    /// Entry length in bytes (`12`).
    pub length: u8,

    /// System I/O APIC ID.
    pub io_apic_id: u8,

    /// Reserved (must be zero).
    pub reserved: u8,

    /// 32-bit physical address of the I/O APIC (usually `0xFEC00000`).
    pub io_apic_address: u32,

    /// Global System Interrupt (GSI) base number for this I/O APIC.
    pub global_system_interrupt_base: u32,
}

/// Interrupt Source Override Structure (MADT Entry Type 2).
///
/// Ref: ACPI 6.3 Spec, Section 5.2.12.5 (Table 5-49).
#[derive(Debug, Copy, Clone)]
#[repr(C, packed)]
pub struct MadtInterruptSourceOverride {
    /// Entry type (`2` for Interrupt Source Override).
    pub entry_type: u8,

    /// Entry length in bytes (`10`).
    pub length: u8,

    /// Source bus ID (`0` for ISA).
    pub bus: u8,

    /// Source IRQ vector on the ISA bus (e.g., IRQ0 for PIT timer).
    pub source: u8,

    /// Global System Interrupt (GSI) to which the source IRQ is mapped.
    pub gsi: u32,

    /// MPS INTI flags (polarity and trigger mode bits).
    pub flags: u16,
}

/// High Precision Event Timer Table (HPET) structure layout.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct HpetTable {
    /// Common ACPI description header with signature `"HPET"`.
    pub header: DescriptionHeader,

    /// Hardware Block ID providing Information about vendor ID, revision,
    /// number of comparators, and counter size (32 or 64 bit).
    pub id: u32,

    /// Generic Address Structure (GAS) specifying the physical MMIO base address.
    pub address: GenericAddressStructure,

    /// Sequence number assigned to this HPET unit (usually `0`).
    pub hpet_number: u8,

    /// Minimum clock ticks needed for periodic mode (lower bound for timer main counter).
    pub minimum_tick: u16,

    /// OEM Page Protection and OEM attribute requirements for memory mapping (e.g. `0` = No protection).
    pub page_protection: u8,
}

const _: () = assert!(size_of::<RsdpAcpiHeader>() == 36);
const _: () = assert!(size_of::<DescriptionHeader>() == 36);
const _: () = assert!(size_of::<GenericAddressStructure>() == 12);
const _: () = assert!(size_of::<FadtAcpiHeader>() == 276);

/// Builder context responsible for serializing ACPI system tables into byte buffers.
pub struct AcpiTablesBuilder {}

impl AcpiTablesBuilder {
    /// Creates a new `AcpiTablesBuilder` instance.
    pub fn new() -> Self {
        Self {}
    }

    /// Builds a binary RSDP table buffer with both ACPI 1.0 and 2.0+ extended checksums computed.
    ///
    /// # Arguments
    /// * `rsdt_address` - Physical address pointing to the RSDT table.
    /// * `xsdt_address` - Physical address pointing to the XSDT table.
    pub fn build_rsdp(&self, rsdt_address: u32, xsdt_address: u64) -> Vec<u8> {
        let mut rsdp = RsdpAcpiHeader {
            signature: *RSDP_SIGNATURE,
            checksum: 0,
            oem_id: *OEM_ID,
            revision: 2,
            rsdt_address,
            length: 36,
            xsdt_address,
            extended_checksum: 0,
            reserved: [0u8; 3],
        };

        let rsdp_ptr = &rsdp as *const _ as *const u8;
        let first_part = unsafe { core::slice::from_raw_parts(rsdp_ptr, 20) };
        rsdp.checksum = self.calculate_acpi_checksum(first_part);

        let full_part = unsafe { core::slice::from_raw_parts(rsdp_ptr, 36) };
        rsdp.extended_checksum = self.calculate_acpi_checksum(full_part);

        let size = core::mem::size_of::<RsdpAcpiHeader>();
        let mut result = alloc::vec![0u8; size];

        unsafe {
            ptr::copy_nonoverlapping(&rsdp as *const _ as *const u8, result.as_mut_ptr(), size);
        }

        result
    }

    /// Builds a binary RSDT table buffer containing 32-bit physical pointers to ACPI tables.
    ///
    /// # Arguments
    /// * `tables` - Vector of 32-bit physical addresses to include in the RSDT array.
    pub fn build_rsdt(&self, tables: Vec<u32>) -> Vec<u8> {
        let header_size = mem::size_of::<DescriptionHeader>();
        let entry_size = mem::size_of::<u32>();
        let total_size = header_size + (tables.len() * entry_size);

        let mut buffer = alloc::vec![0u8; total_size];

        let header = DescriptionHeader {
            signature: *RSDT_SIGNATURE,
            length: total_size as u32,
            revision: 1,
            checksum: 0,
            oem_id: *OEM_ID,
            oem_table_id: *OEM_TABLE_ID,
            oem_revision: 1,
            creator_id: CREATOR_ID,
            creator_revision: 1,
        };

        unsafe {
            ptr::copy_nonoverlapping(
                &header as *const _ as *const u8,
                buffer.as_mut_ptr(),
                header_size,
            );
        }

        for (i, table_addr) in tables.iter().enumerate() {
            let offset = header_size + (i * entry_size);
            let bytes = table_addr.to_le_bytes();
            buffer[offset..offset + 4].copy_from_slice(&bytes);
        }

        let checksum = self.calculate_acpi_checksum(&buffer);

        buffer[offset_of!(DescriptionHeader, checksum)] = checksum;

        buffer
    }

    /// Builds a binary XSDT table buffer containing 64-bit physical pointers to ACPI tables.
    ///
    /// # Arguments
    /// * `tables` - Vector of 64-bit physical addresses to include in the XSDT array.
    pub fn build_xsdt(&self, tables: Vec<u64>) -> Vec<u8> {
        let header_size = mem::size_of::<DescriptionHeader>();
        let entry_size = mem::size_of::<u64>();
        let total_size = header_size + (tables.len() * entry_size);

        let mut buffer = alloc::vec![0u8; total_size];

        let header = DescriptionHeader {
            signature: *XSDT_SIGNATURE,
            length: total_size as u32,
            revision: 1,
            checksum: 0,
            oem_id: *OEM_ID,
            oem_table_id: *OEM_TABLE_ID,
            oem_revision: 1,
            creator_id: CREATOR_ID,
            creator_revision: 1,
        };

        unsafe {
            ptr::copy_nonoverlapping(
                &header as *const _ as *const u8,
                buffer.as_mut_ptr(),
                header_size,
            );
        }

        for (i, table_addr) in tables.iter().enumerate() {
            let offset = header_size + (i * entry_size);
            let bytes = table_addr.to_le_bytes();
            buffer[offset..offset + 8].copy_from_slice(&bytes);
        }

        let checksum = self.calculate_acpi_checksum(&buffer);

        buffer[offset_of!(DescriptionHeader, checksum)] = checksum;

        buffer
    }

    /// Builds a binary FADT (Fixed ACPI Description Table) buffer pointing to the DSDT.
    ///
    /// # Arguments
    /// * `dsdt_address` - 64-bit physical address of the DSDT byte payload.
    pub fn build_fadt(&self, dsdt_address: u64) -> Vec<u8> {
        let fadt = FadtAcpiHeader {
            header: DescriptionHeader {
                signature: *FADT_SIGNATURE,
                length: mem::size_of::<FadtAcpiHeader>() as u32,
                revision: 5,
                checksum: 0,
                oem_id: *OEM_ID,
                oem_table_id: *OEM_TABLE_ID,
                oem_revision: 1,
                creator_id: CREATOR_ID,
                creator_revision: 1,
            },
            firmware_ctrl: 0, // FACS is optional
            dsdt: dsdt_address as u32,
            reserved: 0,
            preferred_pm_profile: 1, // 1 = Desktop
            sci_int: 9,
            smi_cmd: 0,
            acpi_enable: 0,
            acpi_disable: 0,
            s4bios_req: 0,
            pstate_cnt: 0,

            // Power-management block bases.
            pm1a_evt_blk: 0x600,
            pm1b_evt_blk: 0,
            pm1a_cnt_blk: 0x604,
            pm1b_cnt_blk: 0,
            pm2_cnt_blk: 0,
            pm_timer_blk: 0x608,
            gpe0_blk: 0,
            gpe1_blk: 0,

            // Register block lengths.
            pm1_evt_len: 4,
            pm1_cnt_len: 2,
            pm2_cnt_len: 0,
            pm_tm_len: 4,
            gpe0_blk_len: 0,
            gpe1_blk_len: 0,
            gpe1_base: 0,
            cst_cnt: 0,
            p_lvl2_lat: 101,  // > 100 means no support for C2
            p_lvl3_lat: 1001, // > 1000 means no support for C3
            flush_size: 0,
            flush_stride: 0,
            duty_offset: 0,
            duty_width: 0,
            day_alrm: 0,
            mon_alrm: 0,
            century: 0x32,

            iapc_boot_arch: 0x00,
            reserved2: 0,
            flags: 0x00000525, // WBINVD, PROC_C1, SLP_BUTTON, RESET_REG, TMR_VAL_EXT

            reset_reg: GenericAddressStructure::io(0xCF9, 8),
            reset_value: 0x06,
            reserved3: [0u8; 3],

            x_firmware_ctrl: 0,
            x_dsdt: dsdt_address,
            x_pm1a_evt_blk: GenericAddressStructure::io(0x600, 32),
            x_pm1b_evt_blk: GenericAddressStructure::default(),
            x_pm1a_cnt_blk: GenericAddressStructure::io(0x604, 16),
            x_pm1b_cnt_blk: GenericAddressStructure::default(),
            x_pm2_cnt_blk: GenericAddressStructure::default(),
            x_pm_timer_blk: GenericAddressStructure::io(0x608, 32),
            x_gpe0_blk: GenericAddressStructure::default(),
            x_gpe1_blk: GenericAddressStructure::default(),

            sleep_control_reg: GenericAddressStructure::default(),
            sleep_status_reg: GenericAddressStructure::default(),
            hypervisor_vendor_identity: *OEM_TABLE_ID,
        };

        let size = mem::size_of::<FadtAcpiHeader>();
        let mut buffer = alloc::vec![0u8; size];

        unsafe {
            ptr::copy_nonoverlapping(&fadt as *const _ as *const u8, buffer.as_mut_ptr(), size);
        }

        let checksum = self.calculate_acpi_checksum(&buffer);
        buffer[9] = checksum;

        buffer
    }

    /// Builds a binary HPET (High Precision Event Timer) table buffer.
    ///
    /// # Arguments
    /// * `base` - 64-bit physical MMIO base address of the HPET registers.
    pub fn build_hpet(&self, base: u64) -> Vec<u8> {
        let hpet = HpetTable {
            header: DescriptionHeader {
                signature: *HPET_SIGNATURE,
                length: mem::size_of::<HpetTable>() as u32,
                revision: 1,
                checksum: 0,
                oem_id: *OEM_ID,
                oem_table_id: *OEM_TABLE_ID,
                oem_revision: 1,
                creator_id: CREATOR_ID,
                creator_revision: 1,
            },
            id: 0x8086_2210,
            address: GenericAddressStructure {
                address_space_id: 0,
                register_bit_width: 64,
                register_bit_offset: 0,
                access_size: 0,
                address: base,
            },
            hpet_number: 0,
            minimum_tick: 128,
            page_protection: 0,
        };

        let size = mem::size_of::<HpetTable>();
        let mut buffer = alloc::vec![0u8; size];
        unsafe {
            ptr::copy_nonoverlapping(&hpet as *const _ as *const u8, buffer.as_mut_ptr(), size);
        }

        buffer[9] = self.calculate_acpi_checksum(&buffer);

        buffer
    }

    /// Builds a binary MADT (Multiple APIC Description Table) buffer containing LAPIC entries,
    /// a PIT IRQ0 interrupt override entry, and one I/O APIC entry.
    ///
    /// # Arguments
    /// * `vcpu_count` - Number of virtual CPUs to encode as Processor Local APIC entries.
    pub fn build_madt(&self, vcpu_count: u8) -> Vec<u8> {
        let mut buffer = Vec::new();

        let mut madt_header = MadtHeader {
            header: DescriptionHeader {
                signature: *MADT_SIGNATURE,
                length: 0,
                revision: 1,
                checksum: 0,
                oem_id: *OEM_ID,
                oem_table_id: *OEM_TABLE_ID,
                oem_revision: 1,
                creator_id: CREATOR_ID,
                creator_revision: 1,
            },
            local_apic_address: 0xFEE00000,
            flags: 1, // PC-AT Compatible
        };

        let mut entries_data = Vec::new();
        for i in 0..vcpu_count {
            let lapic = MadtLocalApic {
                entry_type: 0,
                length: 8,
                processor_id: i,
                apic_id: i,
                flags: 1,
            };

            entries_data.extend_from_slice(unsafe {
                slice::from_raw_parts(&lapic as *const _ as *const u8, 8)
            });
        }

        let pit_override = MadtInterruptSourceOverride {
            entry_type: 2,
            length: 10,
            bus: 0,    // ISA
            source: 0, // IRQ 0
            gsi: 2,    // Global System Interrupt 2
            flags: 0,  // Edge-triggered, Active High
        };

        entries_data.extend_from_slice(unsafe {
            slice::from_raw_parts(&pit_override as *const _ as *const u8, 10)
        });

        let io_apic = MadtIoApic {
            entry_type: 1,
            length: 12,
            io_apic_id: 0,
            reserved: 0,
            io_apic_address: 0xFEC00000,
            global_system_interrupt_base: 0,
        };

        entries_data.extend_from_slice(unsafe {
            slice::from_raw_parts(&io_apic as *const _ as *const u8, 12)
        });

        madt_header.header.length = (mem::size_of::<MadtHeader>() + entries_data.len()) as u32;

        buffer.extend_from_slice(unsafe {
            slice::from_raw_parts(
                &madt_header as *const _ as *const u8,
                mem::size_of::<MadtHeader>(),
            )
        });

        buffer.extend_from_slice(&entries_data);

        let checksum = self.calculate_acpi_checksum(&buffer);

        buffer[9] = checksum;

        buffer
    }

    /// Computes the 8-bit wrapping checksum for an ACPI table slice.
    ///
    /// In ACPI, the sum of all bytes in a valid table modulo 256 must sum to 0.
    fn calculate_acpi_checksum(&self, data: &[u8]) -> u8 {
        let sum = data.iter().fold(0u8, |acc, &x| acc.wrapping_add(x));
        0u8.wrapping_sub(sum)
    }
}
