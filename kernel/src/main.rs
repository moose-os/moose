#![allow(dead_code)]
#![feature(allocator_api, const_default, const_trait_impl)]
#![no_std]
#![no_main]

extern crate alloc;

#[macro_use]
extern crate static_assertions;

#[macro_use]
extern crate log;

mod arch;
mod driver;
mod font;
mod kernel;
mod panic;
mod subsystem;

use core::{alloc::Layout, arch::asm, mem, ptr::NonNull};

use raw_cpuid::CpuId;

use crate::{
    arch::x86::{
        cpu::ProcessorControlBlock,
        disable_interrupts, enable_interrupts,
        gdt::{TSS, TSS_INDEX},
        read_rsp,
    },
    driver::{acpi::initialize_acpica, apic::LocalApic},
    kernel::kernel_ref,
    subsystem::{
        logger::init_logger,
        memory::{memory_manager, Frame, PageFlags, PageTable, PhysicalAddress},
        process::DEFAULT_THREAD_PRIORITY,
        scheduler::Scheduler,
    },
};

const_assert!(size_of::<arch::x86::idt::Idt>() == 256 * 16);

#[no_mangle]
unsafe extern "C" fn _start() -> ! {
    let stack_pointer = read_rsp();

    disable_interrupts();

    let kernel = kernel_ref();

    kernel.initialize_serial();

    kernel.set_bsp_stack(stack_pointer);

    // According to the documentation,
    // this can only error out if the logger was previously set,
    // which obviously will never be the case here.
    init_logger().unwrap();

    kernel.gather_boot_context();

    let cpu_id = CpuId::new();
    let feature_info = cpu_id.get_feature_info().expect("...");

    arch::x86::perform_arch_initialization(true);

    kernel.initialize_memory();

    let interrupt_stack = InterruptStack::allocate();

    setup_tss(interrupt_stack);

    kernel.retrieve_gdt();

    kernel.initialize_terminal();

    info!("Hello, moose!");

    kernel.allocate_timer_irq();

    info!("Initializing PIC...");

    kernel.initialize_pic();

    info!("Initializing PIT...");

    kernel.initialize_pit();

    initialize_acpica().expect("ACPICA initialization failed");

    ProcessorControlBlock::create_pcb_for_current_processor(
        feature_info.initial_local_apic_id() as u16
    );

    info!("Initializing ACPI...");

    kernel.initialize_acpi();

    info!("Initializing APIC...");

    kernel.initialize_apic();

    info!("Building device tree...");

    kernel.build_device_tree();

    info!("Initializing local APIC...");

    let bsp_lapic = LocalApic::initialize_for_current_processor();

    let pcb = ProcessorControlBlock::current();
    pcb.is_bsp = true;
    _ = pcb.local_apic.set(bsp_lapic);

    info!("Initializing devices...");

    kernel.initialize_devices();

    info!("Spawning kernel processes...");

    kernel.initialize_kernel_process();

    info!("Enabling application processors...");

    kernel
        .apic()
        .read()
        .setup_other_processors(pcb.local_apic());

    info!("Scheduling");

    spawn_test_processes(interrupt_stack);

    enable_interrupts();

    pcb.local_apic().enable_timer();

    Scheduler::run();
}

unsafe fn map_kernel_page_table(kernel_page_table_physical_address: u64) -> NonNull<PageTable> {
    let page_table_virtual_address = {
        let mut memory_manager = memory_manager().write();

        unsafe {
            memory_manager.map_any_for_current_address_space(
                &Frame::new(PhysicalAddress::new(kernel_page_table_physical_address)),
                PageFlags::empty(),
            )
        }
        .address()
    };

    NonNull::new(page_table_virtual_address.as_mut_ptr()).expect("...")
}

unsafe fn setup_tss(interrupt_stack: *mut InterruptStack) {
    TSS[0].rsp0 = interrupt_stack as u64 + mem::size_of::<InterruptStack>() as u64 - 16;
    TSS[0].rsp1 = 0;
    TSS[0].rsp2 = 0;

    asm!(
        "
        ltr {segment:x}
    ",
        segment = in(reg_abcd) ((TSS_INDEX << 3) | 3) as u16,
        options(nostack, nomem)
    );
}

fn spawn_test_processes(interrupt_stack: *mut InterruptStack) {
    static PROGRAM_1: &[u8] = include_bytes!("../../program1/target/x86_64-moose/release/program1");
    static PROGRAM_2: &[u8] = include_bytes!("../../program2/target/x86_64-moose/release/program2");

    let kernel = kernel_ref();

    kernel
        .spawn_process(PROGRAM_1, interrupt_stack, DEFAULT_THREAD_PRIORITY)
        .unwrap();
    kernel
        .spawn_process(PROGRAM_2, interrupt_stack, DEFAULT_THREAD_PRIORITY)
        .unwrap();
}

#[repr(C)]
#[repr(align(4096))]
pub struct InterruptStack([u8; 16 * 1024]);

impl InterruptStack {
    #[inline]
    pub unsafe fn allocate() -> *mut InterruptStack {
        alloc::alloc::alloc_zeroed(Layout::new::<InterruptStack>()) as *mut InterruptStack
    }
}
