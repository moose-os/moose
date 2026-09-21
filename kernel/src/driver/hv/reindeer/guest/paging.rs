//! Guest Memory Management Unit (MMU) address translation helpers.
//!
//! This module provides page table walking utilities to translate Guest Virtual Addresses
//! (GVA) to Guest Physical Addresses (GPA). It relies on a [`SlatManager`] implementation
//! to resolve GPAs to Host Virtual Addresses (HVA) during table traversal.
//!
//! * 64-bit Long Mode: 4-level paging (PML4 → PDPT → PD → PT) supporting standard 4 KiB pages,
//!   2 MiB large pages, and 1 GiB huge pages.
//! * 32-bit Protected Mode: 2-level non-PAE paging (PDE → PTE) supporting 4 KiB standard pages
//!   and 4 MiB PSE (Page Size Extension) pages.
//! * Unpaged Mode: Identity translation when paging is disabled.

use crate::driver::hv::reindeer::SlatManager;

/// Performs a 4-level IA-32e / Long Mode page walk (PML4 → PDPT → PD → PT).
///
/// Translates a 64-bit Guest Virtual Address (GVA) into a Guest Physical Address (GPA)
/// by evaluating guest page tables starting from the base address in `guest_cr3`.
pub fn translate_long_mode(slat: &dyn SlatManager, guest_va: u64, guest_cr3: u64) -> Option<u64> {
    let pml4_idx = (guest_va >> 39) & 0x1FF;
    let pdpt_idx = (guest_va >> 30) & 0x1FF;
    let pd_idx = (guest_va >> 21) & 0x1FF;
    let pt_idx = (guest_va >> 12) & 0x1FF;
    let offset = guest_va & 0xFFF;

    // Internal helper to read a 64-bit entry from guest physical memory.
    let read_gpa = |gpa: u64| -> Option<u64> {
        let hpa = slat.translate(gpa)?;
        Some(unsafe { *(hpa as *const u64) })
    };

    // 1. Traverse PML4 (Page Map Level 4)
    let pml4_entry = read_gpa((guest_cr3 & !0xFFF) + pml4_idx * 8)?;
    if (pml4_entry & 1) == 0 {
        return None; // Present bit (bit 0) cleared
    }

    // 2. Traverse PDPT (Page Directory Pointer Table)
    let pdpt_entry = read_gpa((pml4_entry & 0x000F_FFFF_FFFF_F000) + pdpt_idx * 8)?;
    if (pdpt_entry & 1) == 0 {
        return None; // Present bit cleared
    }

    // Check for 1 GiB leaf page (Page Size bit 7 = 1)
    if (pdpt_entry & 0x80) != 0 {
        return Some((pdpt_entry & !0x3FFF_FFFF) + (guest_va & 0x3FFF_FFFF));
    }

    // 3. Traverse PD (Page Directory)
    let pd_entry = read_gpa((pdpt_entry & 0x000F_FFFF_FFFF_F000) + pd_idx * 8)?;
    if (pd_entry & 1) == 0 {
        return None; // Present bit cleared
    }

    // Check for 2 MiB leaf page (Page Size bit 7 = 1)
    if (pd_entry & 0x80) != 0 {
        return Some((pd_entry & !0x1F_FFFF) + (guest_va & 0x1F_FFFF));
    }

    // 4. Traverse PT (Page Table)
    let pt_entry = read_gpa((pd_entry & 0x000F_FFFF_FFFF_F000) + pt_idx * 8)?;
    if (pt_entry & 1) == 0 {
        return None; // Present bit cleared
    }

    // 4 KiB standard leaf page
    Some((pt_entry & 0x000F_FFFF_FFFF_F000) + offset)
}

/// Performs a 32-bit Protected Mode non-PAE page walk (PDE → PTE).
///
/// Translates a 32-bit Guest Virtual Address (GVA) into a Guest Physical Address (GPA)
/// using standard legacy x86 2-level paging.
pub fn translate_protected_mode(slat: &dyn SlatManager, gva: u32, cr3: u32) -> Option<u64> {
    let pd_gpa = (cr3 & !0xFFF) as u64;
    let pd_hva = slat.translate(pd_gpa)? as *const u32;
    if pd_hva.is_null() {
        return None;
    }

    let directory_idx = (gva >> 22) as usize;
    let pde = unsafe { pd_hva.add(directory_idx).read_volatile() };

    // Check Present bit (bit 0)
    if (pde & 0x1) == 0 {
        return None;
    }

    // Check Page Size bit (bit 7) for 4 MiB PSE page
    if (pde & (1 << 7)) != 0 {
        return Some((pde as u64 & 0xFFC0_0000) | (gva as u64 & 0x003F_FFFF));
    }

    // Traverse Page Table for 4 KiB page
    let pt_gpa = pde as u64 & !0xFFF;
    let pt_hva = slat.translate(pt_gpa)? as *const u32;
    if pt_hva.is_null() {
        return None;
    }

    let table_idx = ((gva >> 12) & 0x3FF) as usize;
    let pte = unsafe { pt_hva.add(table_idx).read_volatile() };

    if (pte & 0x1) == 0 {
        return None; // Present bit cleared
    }

    let gpa = (pte as u64 & !0xFFF) | (gva as u64 & 0xFFF);

    Some(gpa)
}

/// Resolves the Guest Virtual Address (GVA) to a Guest Physical Address (GPA).
///
/// Automatically dispatches translation based on the guest CPU's active execution mode
/// and paging state (`CR0.PG`).
pub fn translate_instruction_gpa(
    slat: &dyn SlatManager,
    address: u64,
    cr0: u64,
    cr3: u64,
    bitness: u32,
) -> Option<u64> {
    if bitness == 64 {
        translate_long_mode(slat, address, cr3)
    } else if (cr0 & (1 << 31)) != 0 {
        translate_protected_mode(slat, address as u32, cr3 as u32)
    } else {
        Some(address)
    }
}
