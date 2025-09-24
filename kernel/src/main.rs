#![allow(dead_code)]
#![feature(allocator_api)]
#![feature(naked_functions)]
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
mod serial;
mod terminal;
mod vga;

use crate::allocator::initialize_heap;
use crate::driver::{pic::PIC, pit::PIT};
use crate::memory::{
    current_page_table, initialize_memory_manager, memory_manager, Page, PageFlags, PageTable,
    VirtualAddress,
};
use crate::terminal::Terminal;
use alloc::boxed::Box;
use alloc::sync::Arc;
use allocator::HEAP_START;
use arch::x86::gdt::{
    GlobalDescriptorTableDescriptor, SegmentFlags, SystemSegmentDescriptor,
    SystemSegmentDescriptorAttributes, SystemSegmentType, GDT, GDT_DESCRIPTOR, TSS, TSS_INDEX,
    USER_MODE_CODE_SEGMENT_INDEX, USER_MODE_DATA_SEGMENT_INDEX,
};
use core::alloc::Layout;
use core::arch::asm;
use core::ptr::addr_of;
use core::{mem, ptr};
use driver::acpi::{create_device_list, initialize_acpica};
use driver::net::nic::rtl8139::Rtl8139;
use limine::paging::Mode;
use limine::request::{
    FramebufferRequest, HhdmRequest, KernelAddressRequest, MemoryMapRequest, PagingModeRequest,
    RsdpRequest, StackSizeRequest,
};
use limine::BaseRevision;
use linker::Linker;
use log::{debug, error, info};
use memory::{Frame, PAGE_SIZE};
use raw_cpuid::CpuId;
use spin::{Mutex, RwLock};
use x86_64::instructions::tlb;
use x86_64::registers::control::{Cr3, Cr3Flags, Cr4, Cr4Flags, Efer, EferFlags};
use x86_64::structures::paging::{PhysFrame, Size4KiB};
use x86_64::structures::tss::TaskStateSegment;
use x86_64::PhysAddr;

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

static mut KERNEL_PAGE_TABLE: *const () = ptr::null();

#[no_mangle]
unsafe extern "C" fn _start() -> ! {
    let stack_pointer: u64;

    asm!("mov {stack_pointer}, rsp", stack_pointer = out(reg) stack_pointer, options(nomem, nostack, preserves_flags));

    assert!(BASE_REVISION.is_supported());
    assert!(STACK_SIZE_REQUEST.get_response().is_some());

    Efer::write(Efer::read() | EferFlags::NO_EXECUTE_ENABLE);
    Cr4::write(Cr4::read() | Cr4Flags::PAGE_GLOBAL | Cr4Flags::FSGSBASE);

    KERNEL_PAGE_TABLE = Cr3::read().0.start_address().as_u64() as *const ();

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

    let kernel = Arc::new(RwLock::new(Kernel {
        physical_memory_offset,
        acpi,
        apic,
        gdt: x86_64::instructions::tables::sgdt(),
        timer_irq,
        irq_allocator: Arc::new(Mutex::new(irq_allocator)),
    }));

    let pci_devices = Pci::build_device_tree();

    let bsp_lapic = LocalApic::initialize_for_current_processor(Arc::clone(&kernel));
    let pcb = cpu::ProcessorControlBlock::get_pcb_for_current_processor();

    _ = (*pcb).local_apic.set(bsp_lapic);

    pci_devices
        .into_iter()
        .filter(|dev| dev.device_id == 0x8139)
        .for_each(|dev| {
            let mut rtl8139 = Rtl8139::new(Arc::new(Mutex::new(dev)), Arc::clone(&kernel));
            rtl8139.initialize();
        });

    kernel
        .read()
        .apic
        .read()
        .setup_other_application_processors(Arc::clone(&kernel), (*pcb).local_apic.get().unwrap());

    switch_to_post_boot_logger(serial, terminal);

    (*pcb).local_apic.get().unwrap().enable_timer();

    info!("Entering user mode!");

    static PROGRAM: &[u8] = include_bytes!("../../sandbox/target/x86_64-moose/release/sandbox");

    start_program(
        PROGRAM,
        physical_memory_offset,
        stack_pointer,
        interrupt_stack,
    );
}

pub fn start_program(
    program: &[u8],
    physical_memory_offset: u64,
    kernel_stack: u64,
    interrupt_stack: *mut InterruptStack,
) -> ! {
    let mut memory_manager = memory_manager().write();

    let stack = unsafe { alloc::alloc::alloc_zeroed(Layout::new::<ThreadStack>()) };

    let program_page_table = Box::leak(Box::new(PageTable::new()));

    // map kernel in program's address space
    {
        let kernel_virtual_base_address = KERNEL_ADDRESS_REQUEST
            .get_response()
            .unwrap()
            .virtual_base();

        let kernel_level_4_page_table_entry_index =
            ((kernel_virtual_base_address >> 39) & 0b1_1111_1111) as usize;

        let kernel_page_table = unsafe { current_page_table(physical_memory_offset) };

        let level_4_page_table_entry =
            &unsafe { &*kernel_page_table }[kernel_level_4_page_table_entry_index];

        program_page_table[kernel_level_4_page_table_entry_index]
            .set_address(level_4_page_table_entry.address());
        program_page_table[kernel_level_4_page_table_entry_index]
            .set_flags(level_4_page_table_entry.flags());
    }

    // map kernel's stack in program's address space
    {
        let kernel_page_table = unsafe { current_page_table(physical_memory_offset) };

        let level_4_page_table_entry_index = ((kernel_stack >> 39) & 0b1_1111_1111) as usize;
        let level_4_page_table_entry =
            &unsafe { &*kernel_page_table }[level_4_page_table_entry_index];

        program_page_table[level_4_page_table_entry_index]
            .set_address(level_4_page_table_entry.address());
        program_page_table[level_4_page_table_entry_index]
            .set_flags(level_4_page_table_entry.flags());
    }

    // map kernel's heap in program's address space
    {
        let kernel_page_table = unsafe { current_page_table(physical_memory_offset) };

        let level_4_page_table_entry_index = (HEAP_START >> 39) & 0b1_1111_1111;
        let level_4_page_table_entry =
            &unsafe { &*kernel_page_table }[level_4_page_table_entry_index];

        program_page_table[level_4_page_table_entry_index]
            .set_address(level_4_page_table_entry.address());
        program_page_table[level_4_page_table_entry_index]
            .set_flags(level_4_page_table_entry.flags());
    }

    // remap interrupt's stack in program's address space
    for page_index in 0..(mem::size_of::<InterruptStack>() / PAGE_SIZE) as u64 {
        let interrupt_stack_virtual_address =
            VirtualAddress::new(interrupt_stack as u64 + (page_index * PAGE_SIZE as u64));
        let interrupt_stack_physical_address = memory_manager
            .translate_virtual_address_to_physical_for_current_address_space(
                interrupt_stack_virtual_address,
            )
            .unwrap();

        unsafe {
            _ = memory_manager.unmap(
                program_page_table,
                &Page::new(interrupt_stack_virtual_address),
            );

            memory_manager
                .map(
                    program_page_table,
                    &Page::new(interrupt_stack_virtual_address),
                    &Frame::new(interrupt_stack_physical_address),
                    PageFlags::WRITABLE,
                )
                .unwrap();
        }
    }

    // FIXME: Handle linkage errors properly
    let entry_point = Linker::link(program, &mut memory_manager, program_page_table).unwrap();

    // map program's stack in program's address space
    for page_index in 0..(mem::size_of::<ThreadStack>() / PAGE_SIZE) as u64 {
        let stack_virtual_address =
            VirtualAddress::new(stack as u64 + (page_index * PAGE_SIZE as u64));
        let stack_physical_address = memory_manager
            .translate_virtual_address_to_physical_for_current_address_space(stack_virtual_address)
            .unwrap();

        unsafe {
            _ = memory_manager.unmap(program_page_table, &Page::new(stack_virtual_address));

            memory_manager
                .map(
                    program_page_table,
                    &Page::new(stack_virtual_address),
                    &Frame::new(stack_physical_address),
                    PageFlags::USER_MODE_ACCESSIBLE | PageFlags::WRITABLE,
                )
                .unwrap();
        }
    }

    // switch page table
    {
        let program_page_table_physical_address = memory_manager
            .translate_virtual_address_to_physical_for_current_address_space(VirtualAddress::new(
                program_page_table as *const _ as u64,
            ))
            .unwrap()
            .as_u64();

        let program_page_table_frame = PhysFrame::<Size4KiB>::from_start_address(PhysAddr::new(
            program_page_table_physical_address,
        ))
        .unwrap();

        unsafe { Cr3::write(program_page_table_frame, Cr3Flags::empty()) };

        tlb::flush_all();
    }

    // We need to drop memory_manager manually because:
    // > A noreturn asm block behaves just like a function which doesn't return; notably,
    // > local variables in scope are not dropped before it is invoked.
    drop(memory_manager);

    enter_user_mode(entry_point as *const _, unsafe {
        stack.add(mem::size_of::<ThreadStack>()).offset(-16)
    });
}

#[repr(C)]
#[repr(align(4096))]
pub struct InterruptStack([u8; 16 * 1024]);

#[repr(C)]
#[repr(align(4096))]
struct ThreadStack([u8; 16 * 1024]);

impl ThreadStack {
    fn new() -> Self {
        Self([0; 16 * 1024])
    }
}

extern "C" fn enter_user_mode(program: *const u8, stack: *const u8) -> ! {
    unsafe {
        asm!(
            "
                mov ds, {data_segment_index_reg:r}
                mov es, {data_segment_index_reg:r}
                push ({data_segment_index} << 3) | 3
                push {stack}
                pushf
                push ({code_segment_index} << 3) | 3
                push {program}
                iretq
            ",
            program = in(reg) program,
            stack = in(reg) stack,
            code_segment_index = const(USER_MODE_CODE_SEGMENT_INDEX as u8),
            data_segment_index = const(USER_MODE_DATA_SEGMENT_INDEX as u8),
            data_segment_index_reg = in(reg) (USER_MODE_DATA_SEGMENT_INDEX << 3) | 3,
            options(nomem, noreturn)
        );
    };
}

#[panic_handler]
fn rust_panic(info: &core::panic::PanicInfo) -> ! {
    error!("{info}");

    loop {}
}
