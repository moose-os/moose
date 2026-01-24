#![allow(dead_code)]
#![feature(allocator_api)]
#![feature(string_remove_matches)]
#![no_std]
#![no_main]

extern crate alloc;

mod allocator;
mod arch;
mod cpu;
mod driver;
mod font;
mod kernel;
mod linker;
mod logger;
mod memory;
mod process;
mod scheduler;
mod serial;
mod terminal;
mod vga;

use crate::allocator::initialize_heap;
use crate::driver::{pic::PIC, pit::PIT};
use crate::memory::initialize_memory_manager;
use crate::process::DEFAULT_THREAD_PRIORITY;
use crate::terminal::Terminal;
use alloc::sync::Arc;
use arch::x86::gdt::{
    GlobalDescriptorTableDescriptor, SegmentFlags, SystemSegmentDescriptor,
    SystemSegmentDescriptorAttributes, SystemSegmentType, GDT, GDT_DESCRIPTOR, TSS, TSS_INDEX,
};
use core::alloc::Layout;
use core::arch::asm;
use core::ptr::addr_of;
use core::{mem, ptr};
use driver::acpi::{create_device_list, initialize_acpica};
use driver::net::nic::rtl8139::Rtl8139;
use kernel::set_kernel;
use limine::paging::Mode;
use limine::request::{
    FramebufferRequest, HhdmRequest, KernelAddressRequest, MemoryMapRequest, PagingModeRequest,
    RsdpRequest, StackSizeRequest,
};
use limine::BaseRevision;
use log::{debug, error, info};
use memory::{memory_manager, Frame, PageFlags, PageTable, PhysicalAddress};
use raw_cpuid::CpuId;
use scheduler::Scheduler;
use spin::{Mutex, RwLock};
use x86_64::registers::control::{Cr3, Cr4, Cr4Flags, Efer, EferFlags};
use x86_64::structures::tss::TaskStateSegment;

use crate::arch::irq::{IrqAllocator, IrqLevel};
use crate::driver::acpi::{Acpi, Rsdp};
use crate::driver::apic::{Apic, LocalApic};
use crate::driver::pci::Pci;
use crate::kernel::Kernel;
use crate::{
    logger::{init_logger, switch_to_post_boot_logger},
    memory::FrameAllocator,
    serial::SerialPort,
    vga::Vga,
};

/// Sets the base revision to the latest revision supported by the crate.
/// See specification for further info.
#[used]
static BASE_REVISION: BaseRevision = BaseRevision::new();

#[used]
static PAGING_MODE_REQUEST: PagingModeRequest =
    PagingModeRequest::new().with_mode(Mode::FOUR_LEVEL);

#[used]
static MEMORY_MAP_REQUEST: MemoryMapRequest = MemoryMapRequest::new();

#[used]
static HIGHER_HALF_DIRECT_MAPPING_REQUEST: HhdmRequest = HhdmRequest::new();

#[used]
static FRAMEBUFFER_REQUEST: FramebufferRequest = FramebufferRequest::new();

#[used]
static RSDP_REQUEST: RsdpRequest = RsdpRequest::new();

#[used]
static STACK_SIZE_REQUEST: StackSizeRequest = StackSizeRequest::new().with_size(4 * 1024 * 1024); // 4 MiB

#[used]
static KERNEL_ADDRESS_REQUEST: KernelAddressRequest = KernelAddressRequest::new();

static mut KERNEL_PAGE_TABLE: *mut PageTable = ptr::null_mut();
static mut KERNEL_PAGE_TABLE_PHYSICAL_ADDRESS: u64 = 0;

#[no_mangle]
unsafe extern "C" fn _start() -> ! {
    let stack_pointer: u64;

    asm!("mov {stack_pointer}, rsp", stack_pointer = out(reg) stack_pointer, options(nomem, nostack, preserves_flags));

    assert!(BASE_REVISION.is_supported());
    assert!(STACK_SIZE_REQUEST.get_response().is_some());

    Efer::write(Efer::read() | EferFlags::NO_EXECUTE_ENABLE);
    Cr4::write(Cr4::read() | Cr4Flags::PAGE_GLOBAL | Cr4Flags::PCID | Cr4Flags::FSGSBASE);

    KERNEL_PAGE_TABLE_PHYSICAL_ADDRESS = Cr3::read().0.start_address().as_u64();

    asm!("cli", options(nostack, nomem));

    {
        for (index, tss_segment) in GDT.tss_segments.iter_mut().enumerate() {
            *tss_segment = SystemSegmentDescriptor::new(
                addr_of!(TSS) as u64 + (index * mem::size_of::<TaskStateSegment>()) as u64,
                mem::size_of::<TaskStateSegment>() as u32,
                SystemSegmentDescriptorAttributes::new()
                    .with_present(true)
                    .with_segment_type(SystemSegmentType::SixtyFourBitAvailableTaskStateSegment),
                SegmentFlags::empty(),
            );
        }

        GDT_DESCRIPTOR = GlobalDescriptorTableDescriptor::new(
            mem::size_of_val(&GDT) as u16 - 1,
            addr_of!(GDT) as u64,
        );

        asm!(
            "lgdt [{gdt}]",
            gdt = in(reg) addr_of!(GDT_DESCRIPTOR) as u64,
        );
    }

    arch::x86::perform_arch_initialization();

    let memory_map_response = MEMORY_MAP_REQUEST.get_response().unwrap();

    let physical_memory_offset = {
        let higher_half_direct_mapping_response =
            HIGHER_HALF_DIRECT_MAPPING_REQUEST.get_response().unwrap();

        higher_half_direct_mapping_response.offset()
    };

    let frame_allocator = FrameAllocator::new(memory_map_response);

    initialize_memory_manager(frame_allocator, physical_memory_offset);

    initialize_heap().expect("Failed to initialize heap");

    {
        let page_table_virtual_address = {
            let mut memory_manager = memory_manager().write();

            unsafe {
                memory_manager.map_any_for_current_address_space(
                    &Frame::new(PhysicalAddress::new(KERNEL_PAGE_TABLE_PHYSICAL_ADDRESS)),
                    PageFlags::empty(),
                )
            }
            .address()
        };

        KERNEL_PAGE_TABLE = page_table_virtual_address.as_mut_ptr();
    }

    let serial = Arc::new(Mutex::new(SerialPort::COM1.open().unwrap()));

    let terminal = Arc::new(Mutex::new({
        let vga = {
            let framebuffer_response = FRAMEBUFFER_REQUEST.get_response().unwrap();
            let framebuffer = framebuffer_response.framebuffers().next().unwrap();

            Vga::new(framebuffer)
        };

        Terminal::new(vga)
    }));

    init_logger(serial.clone(), terminal.clone()).unwrap();

    info!("Hello, moose!");

    assert_eq!(size_of::<arch::x86::idt::Idt>(), 256 * 16);

    let interrupt_stack =
        alloc::alloc::alloc_zeroed(Layout::new::<InterruptStack>()) as *mut InterruptStack;

    TSS[0].rsp0 = interrupt_stack as u64 + mem::size_of::<InterruptStack>() as u64 - 16;
    TSS[0].rsp1 = interrupt_stack as u64 + mem::size_of::<InterruptStack>() as u64 - 16;
    TSS[0].rsp2 = interrupt_stack as u64 + mem::size_of::<InterruptStack>() as u64 - 16;

    asm!(
        "
            ltr {segment:x}
            sti
        ",
        segment = in(reg_abcd) ((TSS_INDEX << 3) | 3) as u16,
        options(nostack, nomem)
    );

    PIC.initialize();
    PIT.initialize();

    initialize_acpica().unwrap();

    let devices = create_device_list();

    for device in &devices {
        debug!("Device :{:#?}", device);
    }

    info!("Waiting started");
    PIT.wait_seconds(1);
    info!("Waiting has ended");

    cpu::ProcessorControlBlock::create_pcb_for_current_processor(
        CpuId::new()
            .get_feature_info()
            .unwrap()
            .initial_local_apic_id() as u16,
    );

    let rsdp_response = RSDP_REQUEST.get_response().unwrap();

    let mut irq_allocator = IrqAllocator::new();
    let timer_irq = irq_allocator.allocate_irq(IrqLevel::Clock);

    let acpi = Arc::new(Acpi::from_rsdp(rsdp_response.address() as *const Rsdp));
    let apic = Arc::new(RwLock::new(Apic::initialize(Arc::clone(&acpi), timer_irq)));

    let kernel = Arc::new(Kernel::new(
        physical_memory_offset,
        stack_pointer,
        acpi,
        apic,
        x86_64::instructions::tables::sgdt(),
        timer_irq,
        Arc::new(Mutex::new(irq_allocator)),
        KERNEL_PAGE_TABLE,
    ));

    set_kernel(Arc::clone(&kernel));

    let pci_devices = Pci::build_device_tree();

    let bsp_lapic = LocalApic::initialize_for_current_processor(Arc::clone(&kernel));
    let pcb = cpu::ProcessorControlBlock::get_pcb_for_current_processor();
    (*pcb).is_bsp = true;

    _ = (*pcb).local_apic.set(bsp_lapic);

    pci_devices
        .into_iter()
        .filter(|dev| dev.device_id == 0x8139)
        .for_each(|dev| {
            let mut rtl8139 = Rtl8139::new(Arc::new(Mutex::new(dev)), Arc::clone(&kernel));
            rtl8139.initialize();
        });

    kernel
        .apic
        .read()
        .setup_other_application_processors(Arc::clone(&kernel), (*pcb).local_apic.get().unwrap());

    switch_to_post_boot_logger(serial, terminal);

    info!("Scheduling");

    static PROGRAM_1: &[u8] = include_bytes!("../../program1/target/x86_64-moose/release/program1");
    static PROGRAM_2: &[u8] = include_bytes!("../../program2/target/x86_64-moose/release/program2");

    kernel
        .spawn_process(PROGRAM_1, interrupt_stack, DEFAULT_THREAD_PRIORITY)
        .unwrap();
    kernel
        .spawn_process(PROGRAM_2, interrupt_stack, DEFAULT_THREAD_PRIORITY)
        .unwrap();

    (*pcb).local_apic.get().unwrap().enable_timer();

    Scheduler::run();
}

#[repr(C)]
#[repr(align(4096))]
pub struct InterruptStack([u8; 16 * 1024]);

#[panic_handler]
fn rust_panic(info: &core::panic::PanicInfo) -> ! {
    error!("{info}");

    loop {}
}
