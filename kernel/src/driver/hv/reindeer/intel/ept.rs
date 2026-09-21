//! Intel Extended Page Table (EPT) implementation for Second-Level Address Translation (SLAT).

use core::ptr;

use bitflags::bitflags;

use crate::{
    driver::hv::reindeer::{
        GuestPhysAddr, HostPhysAddr, HypervisorError, MemoryAccessRights, SlatManager,
    },
    subsystem::memory::{
        Exact, Frame, MapTarget, PAGE_SIZE, Page, PageFlags, PhysicalAddress, VirtualAddress,
        memory_manager,
    },
};

/// Represents an entry in an Intel Extended Page Table (EPT).
///
/// Wraps a 64-bit integer containing both the 4KiB-aligned physical frame base address
/// and permission/attribute flags.
///
/// # Bit Layout (4KiB Leaf / Page Table Entry)
///
/// ```text
///  63          52 51                               12 11     7 6 5   3 2 1 0
/// +--------------+----------------------------------+---------+-+-----+-----+
/// | Reserved /   | Physical Frame Address           | Reserved|I| EPT |X|W|R|
/// | Ignored      | (Host Physical Address, 4KiB)    | / Flags | | Mem | | | |
/// +--------------+----------------------------------+---------+-+-----+-----+
///                                                             |   |    | | |
///                                                             |   |    | | +-- [Bit 0] Read Access
///                                                             |   |    | +---- [Bit 1] Write Access
///                                                             |   |    +------ [Bit 2] Execute Access
///                                                             |   +----------- [Bits 3..5] EPT Memory Type (e.g. 6 = WB)
///                                                             +--------------- [Bit 6] Ignore PAT Memory Type
/// ```
///
/// # References
///
/// * **Intel® 64 and IA-32 Architectures Software Developer's Manual (SDM)**
///   * Volume 3C: System Programming Guide, Part 3
///   * Chapter 30 (*VMX Support for Address Translation*), Section 30.3.2 (EPT Translation Mechanism)
#[derive(Copy, Clone, Default)]
#[repr(transparent)]
pub struct EptEntry(u64);

impl EptEntry {
    /// Extracts the physical frame base address from the EPT entry.
    ///
    /// Masked to retain bits 12 through 47/51 (0xFFFF_FFFF_FFFF_F000).
    pub fn address(&self) -> u64 {
        self.0 & 0xFFFF_FFFF_FFFF_F000
    }

    /// Sets the physical base address in the entry while preserving existing flags.
    pub fn set_address(&mut self, addr: u64) {
        assert_eq!(addr & 0xFFF, 0);

        self.0 = (addr & 0x000F_FFFF_FFFF_F000) | self.flags().bits();
    }

    /// Extracts the permission and attribute flags from the lower 12 bits of the entry.
    pub fn flags(&self) -> EptFlags {
        EptFlags::from_bits_truncate(self.0 & 0xFFF)
    }

    /// Sets the permission and attribute flags while preserving the physical frame address.
    pub fn set_flags(&mut self, flags: EptFlags) {
        self.0 = self.address() | flags.bits();
    }
}

bitflags! {
    /// Bitflags representing EPT entry permissions and memory attributes.
    #[derive(Debug)]
    pub struct EptFlags: u64 {
        /// Read permission flag (bit 0).
        const READ = (1 << 0);

        /// Write permission flag (bit 1).
        const WRITE = (1 << 1);

        /// Execute permission flag (bit 2).
        const EXECUTE = (1 << 2);

        /// Write-Back (WB) memory type (bits 3..5 set to `6`).
        const WRITE_BACK = (6 << 3);

        /// Ignore PAT/EPT memory type bit (bit 6).
        const IGNORE_EPT = (1 << 6);
    }
}

/// Manager for Intel 4-Level Extended Page Tables (EPT).
///
/// Provides functionality to dynamically map, translate, and manage guest physical
/// memory pages using hardware SLAT.
pub struct IntelEpt {
    /// Host Physical Address (HPA) pointing to the root level-4 EPT table (PML4).
    eptp: HostPhysAddr,
}

impl IntelEpt {
    /// Creates and initializes a new `IntelEpt` instance.
    ///
    /// Allocates a 4KiB physical frame for the top-level PML4 table and maps it into
    /// the host virtual address space.
    pub fn new() -> Self {
        let mut memory_manager = memory_manager().write();

        let eptp = memory_manager.allocate_frame().unwrap().address().as_u64();
        unsafe {
            let page = Page::new(VirtualAddress::new(eptp));
            let frame = Frame::new(PhysicalAddress::new(eptp));

            memory_manager
                .map(
                    MapTarget::CurrentAddressSpace(),
                    Exact(&page, &frame),
                    PageFlags::WRITABLE,
                )
                .unwrap();
        }

        IntelEpt { eptp }
    }

    /// Allocates a new lower-level page table, zeroes its contents, and links it
    /// to a parent EPT entry.
    fn allocate_lower_level_page_table(&mut self, parent_ept_entry: &mut EptEntry) {
        let mut memory_manager = memory_manager().write();

        let frame = memory_manager.allocate_frame().unwrap().address().as_u64();

        unsafe {
            let page = Page::new(VirtualAddress::new(frame));
            let phys = Frame::new(PhysicalAddress::new(frame));
            memory_manager
                .map(
                    MapTarget::CurrentAddressSpace(),
                    Exact(&page, &phys),
                    PageFlags::WRITABLE,
                )
                .unwrap();

            ptr::write_bytes(frame as *mut u8, 0, 4096);
        }

        let lower_level = frame as *mut [EptEntry; 512];
        unsafe { *lower_level = [EptEntry::default(); 512] };

        parent_ept_entry.set_address(frame);
        parent_ept_entry.set_flags(EptFlags::READ | EptFlags::WRITE | EptFlags::EXECUTE);
        // TODO: Finer-grained EPT permission mapping.
    }
}

impl SlatManager for IntelEpt {
    /// Maps a single 4KiB Guest Physical Address (GPA) to a Host Physical Address (HPA).
    ///
    /// Traverses the 4-level EPT tree (`L4 -> L3 -> L2 -> L1`), automatically allocating
    /// missing intermediate page tables as required.
    fn map(
        &mut self,
        gpa: GuestPhysAddr,
        hpa: HostPhysAddr,
        access_rights: MemoryAccessRights,
    ) -> Result<(), HypervisorError> {
        // Extract 9-bit indices for each 512-entry page table level
        let l1_pte_index = ((gpa >> 12) & 0b1_1111_1111) as usize;
        let l2_pte_index = ((gpa >> 21) & 0b1_1111_1111) as usize;
        let l3_pte_index = ((gpa >> 30) & 0b1_1111_1111) as usize;
        let l4_pte_index = ((gpa >> 39) & 0b1_1111_1111) as usize;

        let l4_pte = &mut unsafe { &mut *(self.eptp as *mut [EptEntry; 512]) }[l4_pte_index];
        if !l4_pte.flags().contains(EptFlags::READ) {
            self.allocate_lower_level_page_table(l4_pte);
        }

        let l3_pte = &mut unsafe { &mut *(l4_pte.address() as *mut [EptEntry; 512]) }[l3_pte_index];
        if !l3_pte.flags().contains(EptFlags::READ) {
            self.allocate_lower_level_page_table(l3_pte);
        }

        let l2_pte = &mut unsafe { &mut *(l3_pte.address() as *mut [EptEntry; 512]) }[l2_pte_index];
        if !l2_pte.flags().contains(EptFlags::READ) {
            self.allocate_lower_level_page_table(l2_pte);
        }

        let l1_pte = &mut unsafe { &mut *(l2_pte.address() as *mut [EptEntry; 512]) }[l1_pte_index];
        l1_pte.set_address(hpa);

        let flags = match access_rights {
            MemoryAccessRights::Read => EptFlags::READ,
            MemoryAccessRights::Write => EptFlags::READ | EptFlags::WRITE,
            MemoryAccessRights::Execute => EptFlags::READ | EptFlags::EXECUTE,
            MemoryAccessRights::ReadWrite => EptFlags::READ | EptFlags::WRITE,
            MemoryAccessRights::ReadExecute => EptFlags::READ | EptFlags::EXECUTE,
            MemoryAccessRights::ReadWriteExecute => {
                EptFlags::READ | EptFlags::WRITE | EptFlags::EXECUTE
            }
        };

        l1_pte.set_flags(flags | EptFlags::WRITE_BACK); // TODO: Finer-grained EPT permission mapping.

        // TODO: Issue INVEPT after map changes to invalidate EPT-derived TLB entries.
        Ok(())
    }

    /// Maps a contiguous block of guest physical pages to a contiguous host physical frame block.
    fn map_contiguous(
        &mut self,
        gpa: GuestPhysAddr,
        hpa: HostPhysAddr,
        size_in_pages: usize,
        access_rights: MemoryAccessRights,
    ) -> Result<(), HypervisorError> {
        for i in 0..size_in_pages as u64 {
            let nth_gpa = (gpa + i * PAGE_SIZE as u64) as GuestPhysAddr;
            let nth_hpa = (hpa + i * PAGE_SIZE as u64) as HostPhysAddr;

            self.map(nth_gpa, nth_hpa, access_rights)?;
        }

        Ok(())
    }

    /// Updates access permissions for an existing GPA range.
    fn protect(
        &mut self,
        _gpa: GuestPhysAddr,
        _size: usize,
        _rights: MemoryAccessRights,
    ) -> Result<(), HypervisorError> {
        unimplemented!()
    }

    /// Translates a Guest Physical Address (GPA) to its corresponding Host Physical Address (HPA).
    fn translate(&self, gpa: GuestPhysAddr) -> Option<HostPhysAddr> {
        let l1_pte_index = ((gpa >> 12) & 0b1_1111_1111) as usize;
        let l2_pte_index = ((gpa >> 21) & 0b1_1111_1111) as usize;
        let l3_pte_index = ((gpa >> 30) & 0b1_1111_1111) as usize;
        let l4_pte_index = ((gpa >> 39) & 0b1_1111_1111) as usize;

        let l4_pte = &mut unsafe { &mut *(self.eptp as *mut [EptEntry; 512]) }[l4_pte_index];
        if !l4_pte.flags().contains(EptFlags::READ) {
            return None;
        }

        let l3_pte = &mut unsafe { &mut *(l4_pte.address() as *mut [EptEntry; 512]) }[l3_pte_index];
        if !l3_pte.flags().contains(EptFlags::READ) {
            return None;
        }

        let l2_pte = &mut unsafe { &mut *(l3_pte.address() as *mut [EptEntry; 512]) }[l2_pte_index];
        if !l2_pte.flags().contains(EptFlags::READ) {
            return None;
        }

        let l1_pte = &mut unsafe { &mut *(l2_pte.address() as *mut [EptEntry; 512]) }[l1_pte_index];
        if !l1_pte.flags().contains(EptFlags::READ) {
            return None;
        }

        Some(l1_pte.address() + (gpa & 0b1111_1111_1111) as HostPhysAddr)
    }

    /// Removes a mapping for a Guest Physical Address (GPA).
    fn unmap(&mut self, _gpa: GuestPhysAddr) -> Result<(), HypervisorError> {
        unimplemented!()
    }

    /// Returns the Host Physical Address of the root EPT PML4 table (EPTP).
    fn root_pointer(&self) -> HostPhysAddr {
        self.eptp
    }
}
