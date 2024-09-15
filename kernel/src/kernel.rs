use core::alloc::Layout;
use core::ffi::c_void;
use core::mem;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use crate::allocator::HEAP_START;
use crate::driver::acpi::Acpi;
use crate::driver::apic::Apic;
use crate::linker::Linker;
use crate::memory::{
    current_page_table, memory_manager, Frame, Page, PageFlags, VirtualAddress, PAGE_SIZE,
};
use crate::process::{Process, ProcessInner, Registers, Status, Thread, ThreadInner, ThreadStack};
use crate::{arch::irq::IrqAllocator, memory::PageTable};
use crate::{scheduler, InterruptStack, KERNEL_ADDRESS_REQUEST};
use alloc::vec::Vec;
use alloc::{boxed::Box, sync::Arc};
use spin::{Mutex, Once, RwLock};
use x86_64::registers::rflags;
use x86_64::registers::segmentation::{Segment64, GS};
use x86_64::structures::DescriptorTablePointer;

static KERNEL: Once<Arc<Kernel>> = Once::new();

pub struct Kernel {
    pub physical_memory_offset: u64,
    pub bsp_stack: u64,
    pub acpi: Arc<Acpi>,
    pub apic: Arc<RwLock<Apic>>,
    pub gdt: DescriptorTablePointer,
    pub timer_irq: u8,
    pub irq_allocator: Arc<Mutex<IrqAllocator>>,
    pub ticks: AtomicU64,
    current_usable_process_id: AtomicUsize,
    current_usable_thread_id: AtomicUsize,
    processes: RwLock<Vec<Process>>,
}

impl Kernel {
    pub fn new(
        physical_memory_offset: u64,
        bsp_stack: u64,
        acpi: Arc<Acpi>,
        apic: Arc<RwLock<Apic>>,
        gdt: DescriptorTablePointer,
        timer_irq: u8,
        irq_allocator: Arc<Mutex<IrqAllocator>>,
    ) -> Self {
        Self {
            physical_memory_offset,
            bsp_stack,
            acpi,
            apic,
            gdt,
            timer_irq,
            irq_allocator,
            ticks: AtomicU64::new(0),
            current_usable_process_id: AtomicUsize::new(0),
            current_usable_thread_id: AtomicUsize::new(0),
            processes: RwLock::new(Vec::new()),
        }
    }

    pub fn spawn_process(
        &self,
        program: &[u8],
        interrupt_stack: *mut InterruptStack,
    ) -> Result<Process, ()> {
        let stack =
            unsafe { alloc::alloc::alloc_zeroed(Layout::new::<ThreadStack>()) } as *mut ThreadStack;

        let mut program_page_table = self.create_address_space(self.bsp_stack, interrupt_stack);

        let mut memory_manager = memory_manager().write();

        let entry_point =
            Linker::link(program, &mut memory_manager, &mut program_page_table).map_err(|_| ())?;

        // remap program's stack in program's address space
        {
            for page_index in 0..(mem::size_of::<ThreadStack>() / PAGE_SIZE) as u64 {
                let stack_virtual_address = VirtualAddress::new(stack as u64 + (page_index * 4096));
                let stack_physical_address = memory_manager
                    .translate_virtual_address_to_physical_for_current_address_space(
                        stack_virtual_address,
                    )
                    .unwrap();

                unsafe {
                    memory_manager
                        .unmap(&mut *program_page_table, &Page::new(stack_virtual_address))
                        .unwrap();

                    memory_manager
                        .map(
                            &mut *program_page_table,
                            &Page::new(stack_virtual_address),
                            &Frame::new(stack_physical_address),
                            PageFlags::USER_MODE_ACCESSIBLE | PageFlags::WRITABLE,
                        )
                        .unwrap();
                }
            }
        }

        let page_table_physical_address = memory_manager
            .translate_virtual_address_to_physical_for_current_address_space(VirtualAddress::new(
                &*program_page_table as *const _ as u64,
            ))
            .unwrap()
            .as_u64();

        drop(memory_manager);

        let process_id = self
            .current_usable_process_id
            .fetch_add(1, Ordering::SeqCst);

        let process = Process(Arc::new(ProcessInner {
            id: process_id,
            page_table: Box::leak(program_page_table),
            page_table_physical_address,
            threads: Mutex::new(Vec::new()),
        }));

        let thread_id = self.current_usable_thread_id.fetch_add(1, Ordering::SeqCst);

        let thread = Thread(Arc::new(ThreadInner {
            process: process.clone(),
            id: thread_id,
            status: Mutex::new(Status::Running),
            entry: entry_point as *const c_void,
            registers: Mutex::new(Registers {
                rip: entry_point,
                rsp: stack as u64 + mem::size_of::<ThreadStack>() as u64 - 16,
                cs: (7 << 3) | 3,
                ss: (8 << 3) | 3,
                gs: GS::read_base().as_u64(),
                rflags: rflags::read_raw(),
                ..Default::default()
            }),
            stack,
            reschedule: AtomicBool::new(true),
        }));

        process.0.threads.lock().push(thread.clone());

        self.processes.write().push(process.clone());

        scheduler::schedule(thread);

        Ok(process)
    }

    pub fn create_address_space(
        &self,
        kernel_stack: u64,
        interrupt_stack: *mut InterruptStack,
    ) -> Box<PageTable> {
        let mut page_table = Box::new(PageTable::new());

        // map kernel in program's address space
        {
            let kernel_virtual_base_address = KERNEL_ADDRESS_REQUEST
                .get_response()
                .unwrap()
                .virtual_base();

            let kernel_level_4_page_table_entry_index =
                ((kernel_virtual_base_address >> 39) & 0b1_1111_1111) as usize;

            let kernel_page_table = unsafe { current_page_table(self.physical_memory_offset) };

            let level_4_page_table_entry =
                &unsafe { &*kernel_page_table }[kernel_level_4_page_table_entry_index];

            page_table[kernel_level_4_page_table_entry_index]
                .set_address(level_4_page_table_entry.address());
            page_table[kernel_level_4_page_table_entry_index]
                .set_flags(level_4_page_table_entry.flags());
        }

        // map kernel's stack in program's address space
        {
            let kernel_page_table = unsafe { current_page_table(self.physical_memory_offset) };

            let level_4_page_table_entry_index = ((kernel_stack >> 39) & 0b1_1111_1111) as usize;
            let level_4_page_table_entry =
                &unsafe { &*kernel_page_table }[level_4_page_table_entry_index];

            page_table[level_4_page_table_entry_index]
                .set_address(level_4_page_table_entry.address());
            page_table[level_4_page_table_entry_index].set_flags(level_4_page_table_entry.flags());
        }

        // map kernel's heap in program's address space
        {
            let kernel_page_table = unsafe { current_page_table(self.physical_memory_offset) };

            let level_4_page_table_entry_index = (HEAP_START >> 39) & 0b1_1111_1111;
            let level_4_page_table_entry =
                &unsafe { &*kernel_page_table }[level_4_page_table_entry_index];

            page_table[level_4_page_table_entry_index]
                .set_address(level_4_page_table_entry.address());
            page_table[level_4_page_table_entry_index].set_flags(level_4_page_table_entry.flags());
        }

        let mut memory_manager = memory_manager().write();

        // remap interrupt's stack in program's address space
        {
            for page_index in 0..4 {
                let interrupt_stack_virtual_address =
                    VirtualAddress::new(interrupt_stack as u64 + (page_index * 4096));
                let interrupt_stack_physical_address = memory_manager
                    .translate_virtual_address_to_physical_for_current_address_space(
                        interrupt_stack_virtual_address,
                    )
                    .unwrap();

                unsafe {
                    memory_manager
                        .unmap(
                            &mut *page_table,
                            &Page::new(interrupt_stack_virtual_address),
                        )
                        .unwrap();

                    memory_manager
                        .map(
                            &mut *page_table,
                            &Page::new(interrupt_stack_virtual_address),
                            &Frame::new(interrupt_stack_physical_address),
                            PageFlags::WRITABLE,
                        )
                        .unwrap();
                }
            }
        }

        page_table
    }
}

pub fn kernel() -> Arc<Kernel> {
    Arc::clone(KERNEL.get().unwrap())
}

pub fn kernel_ref<'a>() -> &'a Kernel {
    KERNEL.get().unwrap()
}

pub(crate) fn set_kernel(kernel: Arc<Kernel>) {
    KERNEL.call_once(|| kernel);
}
