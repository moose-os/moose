pub mod asm;
pub mod gdt;
pub mod idt;

use core::arch;
use x86_64::{
    instructions::tlb,
    registers::control::{Cr0, Cr0Flags, Cr3, Cr3Flags, Cr4, Cr4Flags},
    structures::paging::{PhysFrame, Size4KiB},
    PhysAddr,
};

use crate::KERNEL_PAGE_TABLE_PHYSICAL_ADDRESS;

pub fn perform_arch_initialization() {
    unsafe {
        Cr0::write(
            Cr0::read().difference(Cr0Flags::EMULATE_COPROCESSOR)
                | Cr0Flags::NUMERIC_ERROR
                | Cr0Flags::MONITOR_COPROCESSOR,
        );
        // We don't really need to check whether SSE and SSE2 is present as long mode requires them.
        // We wouldn't even get here without those extensions.
        Cr4::write(Cr4::read() | Cr4Flags::OSFXSR | Cr4Flags::OSXMMEXCPT_ENABLE | Cr4Flags::PCID);

        arch::asm!("fninit");
    }

    // @TODO: GDT
    idt::init_idt();
}

pub fn use_kernel_page_table(closure: impl FnOnce()) {
    let (previous_page_table_frame, previous_page_table_flags) = Cr3::read();

    unsafe {
        Cr3::write(
            PhysFrame::<Size4KiB>::from_start_address(PhysAddr::new(
                KERNEL_PAGE_TABLE_PHYSICAL_ADDRESS,
            ))
            .unwrap(),
            Cr3Flags::empty(),
        );

        tlb::flush_all();
    }

    closure();

    unsafe {
        Cr3::write(previous_page_table_frame, previous_page_table_flags);

        tlb::flush_all();
    }
}
