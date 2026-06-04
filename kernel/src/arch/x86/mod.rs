pub mod asm;
pub mod cpu;
pub mod gdt;
pub mod idt;

use core::{
    alloc::Layout,
    arch::{self, asm},
};

use x86_64::{
    PhysAddr,
    instructions::tlb,
    registers::control::{Cr0, Cr0Flags, Cr3, Cr3Flags, Cr4, Cr4Flags, Efer, EferFlags},
    structures::paging::{PhysFrame, Size4KiB},
};

use crate::{
    arch::x86::gdt::{load_gdt, setup_gdt},
    kernel::kernel_ref,
};

pub unsafe fn perform_arch_initialization(is_bsp: bool) {
    unsafe {
        Efer::write(Efer::read() | EferFlags::NO_EXECUTE_ENABLE);

        Cr0::write(
            Cr0::read().difference(Cr0Flags::EMULATE_COPROCESSOR)
                | Cr0Flags::NUMERIC_ERROR
                | Cr0Flags::MONITOR_COPROCESSOR,
        );
        // We don't really need to check whether SSE and SSE2 is present as long mode requires them.
        // We wouldn't even get here without those extensions.
        Cr4::write(
            Cr4::read()
                | Cr4Flags::PAGE_GLOBAL
                | Cr4Flags::FSGSBASE
                | Cr4Flags::OSFXSR
                | Cr4Flags::OSXMMEXCPT_ENABLE,
        );

        arch::asm!("fninit");

        if is_bsp {
            setup_gdt();
        }

        load_gdt();

        idt::init_idt();
    }
}

pub fn use_kernel_page_table(closure: impl FnOnce()) {
    let (previous_page_table_frame, previous_page_table_flags) = Cr3::read();

    unsafe {
        Cr3::write(
            PhysFrame::<Size4KiB>::from_start_address(PhysAddr::new(
                kernel_ref().kernel_page_table_physical_address(),
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

#[inline(always)]
pub fn disable_interrupts() {
    unsafe {
        asm!("cli", options(nomem, nostack, preserves_flags));
    }
}

#[inline(always)]
pub fn enable_interrupts() {
    unsafe {
        asm!("sti", options(nomem, nostack, preserves_flags));
    }
}

#[inline(always)]
pub fn read_rsp() -> u64 {
    let rsp: u64;

    unsafe {
        asm!("mov {rsp}, rsp", rsp = out(reg) rsp, options(nomem, nostack, preserves_flags));
    }

    rsp
}

#[repr(C)]
#[repr(align(4096))]
pub struct InterruptStack([u8; 16 * 1024]);

impl InterruptStack {
    #[inline]
    pub unsafe fn allocate() -> *mut InterruptStack {
        (unsafe { alloc::alloc::alloc_zeroed(Layout::new::<InterruptStack>()) })
            as *mut InterruptStack
    }
}
