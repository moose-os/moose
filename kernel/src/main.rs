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

use alloc::{boxed::Box, sync::Arc};

use raw_cpuid::{CpuId, Hypervisor};

use crate::{
    arch::x86::{
        asm::{disable_interrupts, enable_interrupts, read_rsp},
        cpu::ProcessorControlBlock,
        gdt::{load_tss, setup_tss},
    },
    driver::{
        acpi::initialize_acpica,
        apic::LocalApic,
        hv::{
            hyperv::HyperV,
            reindeer::{
                BootSource, VmOptionsBuilder,
                backend::initialize_hypervisor,
                device::{
                    legacy::{
                        rtc::VirtualRealTimeClockDevice,
                        serial::{VirtualSerialPort, VirtualSerialPortBackingDevice},
                    },
                    pci::VirtualPciHostBridge,
                },
                run_loop::run_guest_loop,
            },
        },
        serial::SerialPort,
    },
    kernel::{VirtualizedDevicesManager, kernel_ref},
    subsystem::{
        logger::init_logger,
        monocle_logger::{MonocleLogger, monocle_logger, try_register},
        process::DEFAULT_THREAD_PRIORITY,
        scheduler::Scheduler,
    },
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

    info!("Checking support for hypervisor...");
    if CpuId::new().get_hypervisor_info().unwrap().identify() == Hypervisor::HyperV {
        info!("Found HyperV. Spawning worker thread...");
        let t = kernel
            .virtualized_devices_manager
            .call_once(|| VirtualizedDevicesManager::VMBus(HyperV::new()));

        let VirtualizedDevicesManager::VMBus(hv) = t else {
            panic!("")
        };

        hv.spawn_worker_thread();

        kernel_ref()
            .spawn_kernel_thread(init_vm, 0, DEFAULT_THREAD_PRIORITY + 1)
            .unwrap();
    }

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

extern "C" fn init_vm(_arg: u64) -> ! {
    let vmm = initialize_hypervisor().expect("hypervisor initialization failed");

    // @TODO: need to call this for each core once in a lifetime
    vmm.initialize().unwrap();

    try_register(MonocleLogger::connect().unwrap());

    let serial_backing = monocle_logger()
        .map(|logger| VirtualSerialPortBackingDevice::Remote(Arc::clone(logger)))
        .unwrap_or_else(|| {
            let guest_serial = SerialPort::COM1
                .open()
                .expect("failed to open host serial for guest UART passthrough");
            VirtualSerialPortBackingDevice::Com(guest_serial)
        });

    let options = VmOptionsBuilder::default()
        .memory(256)
        .vcpus(1)
        .device(VirtualSerialPort::new(0x3F8, serial_backing, 1))
        .device(VirtualPciHostBridge::new())
        .device(VirtualRealTimeClockDevice::new())
        .boot_source(BootSource::LinuxBootProtocol {
            vmlinuz: Box::from(LINUX_VMLINUZ),
            initial_ramdisk: Box::from(LINUX_INITRAMFS),
            command_line: alloc::string::String::from(
                "moose=serial-initrd loglevel=8 ignore_loglevel console=ttyS0,115200 earlyprintk=serial,ttyS0,115200 rdinit=/bin/sh initramfs_async=0 retain_initrd pata_legacy.probe_mask=0 libata.force=disable scsi_mod.scan=none mitigations=off srbds=off pci=off",
            ),
        })
        .build()
        .expect("invalid VM options");

    let vm = vmm.create_vm(&options).expect("Failed to create VM");
    let vcpu = vm.write().add_vcpu(0).expect("Failed to add vCPU");

    run_guest_loop(vm, vcpu).expect("vCPU run loop returned unexpectedly");

    panic!("vCPU run loop exited");
}

static LINUX_VMLINUZ: &[u8] = include_bytes!("../../assets/vmlinuz");
static LINUX_INITRAMFS: &[u8] = include_bytes!("../../assets/initramfs.cpio");
