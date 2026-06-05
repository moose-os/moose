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

use raw_cpuid::CpuId;

use crate::{
    arch::x86::{
        asm::{disable_interrupts, enable_interrupts, read_rsp},
        cpu::ProcessorControlBlock,
        gdt::{load_tss, setup_tss},
    },
    driver::{acpi::initialize_acpica, apic::LocalApic},
    kernel::kernel_ref,
    subsystem::{logger::init_logger, process::DEFAULT_THREAD_PRIORITY, scheduler::Scheduler},
};

#[unsafe(no_mangle)]
unsafe extern "C" fn _start() -> ! {
    let stack_pointer = read_rsp();

    disable_interrupts();

    let kernel = kernel_ref();

    kernel.retrieve_gdt();
    kernel.set_bsp_stack(stack_pointer);

    kernel.initialize_serial();
    // According to the documentation,
    // this can only error out if the logger was previously set,
    // which obviously will never be the case here.
    init_logger().unwrap();

    kernel.gather_boot_context();

    let cpu_id = CpuId::new();
    let feature_info = cpu_id
        .get_feature_info()
        .expect("Failed to get CPU's feature info");

    unsafe { arch::x86::perform_arch_initialization(true) };

    kernel.initialize_memory();

    unsafe {
        setup_tss(0);
        load_tss(0);
    }

    kernel.initialize_terminal();

    info!("Hello, moose!");

    info!("Initializing PIC...");
    kernel.initialize_pic();

    info!("Initializing ACPICA...");
    unsafe {
        initialize_acpica().expect("ACPICA initialization failed");

        ProcessorControlBlock::create_pcb_for_current_processor(
            feature_info.initial_local_apic_id() as u16,
        );
    }

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

    info!("Initializing clock...");
    kernel.initialize_clock();

    info!("Initializing devices...");
    kernel.initialize_devices();

    info!("Spawning kernel processes...");
    kernel.initialize_kernel_process();

    info!("Enabling application processors...");
    kernel
        .apic()
        .read()
        .setup_other_processors(pcb.local_apic());

    info!("Spawning test processes...");
    spawn_test_processes();

    enable_interrupts();

    info!("Scheduling...");
    Scheduler::run();
}

fn spawn_test_processes() {
    static PROGRAM_1: &[u8] = include_bytes!("../../program1/target/x86_64-moose/release/program1");
    static PROGRAM_2: &[u8] = include_bytes!("../../program2/target/x86_64-moose/release/program2");

    let kernel = kernel_ref();

    kernel
        .spawn_process(PROGRAM_1, DEFAULT_THREAD_PRIORITY)
        .unwrap();
    kernel
        .spawn_process(PROGRAM_2, DEFAULT_THREAD_PRIORITY)
        .unwrap();
}
