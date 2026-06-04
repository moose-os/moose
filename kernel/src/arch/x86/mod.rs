pub mod asm;
pub mod cpu;
pub mod gdt;
pub mod idt;

use core::{alloc::Layout, arch};

use raw_cpuid::CpuId;
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
    let cpu_id = CpuId::new();

    let feature_info = cpu_id
        .get_feature_info()
        .expect("Failed to read CPU's feature info");
    let extended_feature_info = cpu_id
        .get_extended_feature_info()
        .expect("Failed to read CPU's extended feature info");

    let extended_feature_ids = cpu_id
        .get_extended_processor_and_feature_identifiers()
        .expect("Failed to read CPU's extended feature identifiers");

    if !extended_feature_ids.has_64bit_mode() {
        panic!("CPU doesn't support x86_64");
    }

    if !feature_info.has_sse() {
        panic!("CPU doesn't support SSE");
    }

    if !feature_info.has_sse2() {
        panic!("CPU doesn't support SSE2");
    }

    if !feature_info.has_pge() {
        panic!("CPU doesn't support PGE");
    }

    if !extended_feature_info.has_fsgsbase() {
        panic!("CPU doesn't support FSGSBASE");
    }

    if !extended_feature_ids.has_execute_disable() {
        panic!("CPU doesn't support NX/XD");
    }

    unsafe {
        Efer::write(Efer::read() | EferFlags::NO_EXECUTE_ENABLE);

        Cr0::write(
            Cr0::read().difference(Cr0Flags::EMULATE_COPROCESSOR)
                | Cr0Flags::NUMERIC_ERROR
                | Cr0Flags::MONITOR_COPROCESSOR,
        );

        Cr4::write(
            Cr4::read()
                | Cr4Flags::FSGSBASE
                | Cr4Flags::PAGE_GLOBAL
                | Cr4Flags::OSFXSR
                | Cr4Flags::OSXMMEXCPT_ENABLE,
        );

        arch::asm!("fninit");

        if is_bsp {
            setup_gdt();
        }

        load_gdt();

        if is_bsp {
            idt::init_idt();
        }
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
