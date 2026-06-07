use alloc::{boxed::Box, sync::Arc, vec::Vec};
use core::{
    ffi::c_void,
    mem,
    ptr::NonNull,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};

use spin::{Mutex, Once, RwLock};
use x86_64::{
    instructions::hlt,
    registers::{
        control::Cr3,
        rflags,
        segmentation::{GS, Segment64},
    },
    structures::DescriptorTablePointer,
};

use crate::{
    arch::{irq::IrqAllocator, x86::idt::TIMER_IRQ},
    driver::{
        acpi::{Acpi, Device, MadtEntryInner, create_device_list},
        apic::Apic,
        pci::{Pci, PciDevice},
        pic::ProgrammableInterruptController,
        serial::{Serial, SerialPort},
        vga::Vga,
    },
    subsystem::{
        allocator::initialize_heap,
        boot::limine::LimineBootContext,
        clock::system_clock::SystemClock,
        linker::Linker,
        memory::{
            AddressSpace, Exact, Frame, FrameAllocator, MemoryManager, PAGE_SIZE, Page, PageFlags,
            PageTable, VirtualAddress, memory_manager,
        },
        process::{
            HIGHEST_THREAD_PRIORITY, LOWEST_THREAD_PRIORITY, Process, ProcessInner, Registers,
            Status, Thread, ThreadInner, ThreadStack,
        },
        scheduler::{self, Scheduler},
        terminal::Terminal,
    },
};

static KERNEL: Kernel = Kernel::new();

pub struct Kernel {
    pub boot_context: Once<LimineBootContext>,

    pub kernel_page_table: Once<NonNull<PageTable>>,
    pub kernel_page_table_physical_address: Once<u64>,

    pub memory_manager: Once<RwLock<MemoryManager>>,

    pub bsp_stack: Once<u64>,
    pub gdt: Once<DescriptorTablePointer>,

    pub irq_allocator: Mutex<IrqAllocator>,

    pub platform_devices: PlatformDevices,
    pub devices: Mutex<Vec<Arc<Mutex<Device>>>>,
    pub pci_devices: Mutex<Vec<PciDevice>>,

    pub terminal: Once<Mutex<Terminal>>,

    pub clock: Once<SystemClock>,

    current_usable_process_id: AtomicUsize,
    current_usable_thread_id: AtomicUsize,
    pub processes: RwLock<Vec<Process>>,

    pub scheduler: Scheduler,
}

unsafe impl Send for Kernel {}

// TODO: Remove this
unsafe impl Sync for Kernel {}

impl Kernel {
    pub const fn new() -> Self {
        Self {
            boot_context: Once::new(),

            kernel_page_table: Once::new(),
            kernel_page_table_physical_address: Once::new(),

            memory_manager: Once::new(),

            bsp_stack: Once::new(),
            gdt: Once::new(),

            irq_allocator: Mutex::new(IrqAllocator::new()),

            platform_devices: PlatformDevices {
                serial: Once::new(),
                pic: Mutex::new(ProgrammableInterruptController::new()),
                acpi: Once::new(),
                apic: Once::new(),
            },
            devices: Mutex::new(Vec::new()),
            pci_devices: Mutex::new(Vec::new()),

            terminal: Once::new(),

            clock: Once::new(),

            current_usable_process_id: AtomicUsize::new(0),
            current_usable_thread_id: AtomicUsize::new(0),
            processes: RwLock::new(Vec::new()),

            scheduler: Scheduler::new(),
        }
    }

    // |----------------|
    // | Initialization |
    // |----------------|

    pub(crate) fn initialize_memory(&self) {
        self.resolve_kernel_page_table();
        self.initialize_memory_manager();
        initialize_heap().expect("Failed to initialize heap");
    }

    pub(crate) fn initialize_memory_manager(&self) {
        let boot_context = self.boot_context();

        let frame_allocator = FrameAllocator::new(boot_context.memory_map_entries);

        self.memory_manager.call_once(|| {
            RwLock::new(MemoryManager {
                frame_allocator,
                physical_memory_offset: boot_context.physical_memory_offset,
            })
        });
    }

    pub(crate) fn resolve_kernel_page_table(&self) {
        let physical_memory_offset = self.boot_context().physical_memory_offset;

        let kernel_page_table_physical_address = Cr3::read().0.start_address().as_u64();

        self.kernel_page_table_physical_address
            .call_once(|| kernel_page_table_physical_address);

        let kernel_page_table_virtual_address =
            VirtualAddress::new(kernel_page_table_physical_address + physical_memory_offset);
        let kernel_page_table: NonNull<PageTable> =
            NonNull::new(kernel_page_table_virtual_address.as_mut_ptr())
                .expect("kernel_page_table_virtual_address was zero");

        self.kernel_page_table.call_once(|| kernel_page_table);
    }

    pub(crate) fn retrieve_gdt(&self) {
        self.gdt.call_once(x86_64::instructions::tables::sgdt);
    }

    pub(crate) fn gather_boot_context(&self) {
        self.boot_context
            .call_once(|| LimineBootContext::gather().expect("Failed to initialize boot context"));
    }

    pub(crate) fn initialize_serial(&self) {
        self.platform_devices
            .serial
            .call_once(|| Mutex::new(SerialPort::COM1.open().unwrap()));
    }

    pub(crate) fn initialize_terminal(&'static self) {
        self.terminal
            .call_once(|| Mutex::new(Terminal::new(Vga::new(&self.boot_context().framebuffer))));
    }

    pub(crate) fn set_bsp_stack(&self, stack_pointer: u64) {
        self.bsp_stack.call_once(|| stack_pointer);
    }

    #[inline(always)]
    pub(crate) fn initialize_pic(&self) {
        self.platform_devices.pic.lock().initialize();
    }

    #[inline(always)]
    pub(crate) fn initialize_acpi(&self) {
        self.platform_devices
            .acpi
            .call_once(|| Acpi::from_rsdp(self.boot_context().rsdp));
    }

    #[inline(always)]
    pub(crate) fn initialize_apic(&self) {
        self.platform_devices
            .apic
            .call_once(|| RwLock::new(Apic::initialize(TIMER_IRQ)));
    }

    pub(crate) fn build_device_tree(&self) {
        *self.devices.lock() = create_device_list();
        *self.pci_devices.lock() = Pci::build_device_tree();
    }

    pub(crate) fn initialize_clock(&self) {
        self.clock.call_once(SystemClock::new);
    }

    pub(crate) fn initialize_devices(&self) {
        /*self.pci_devices
        .iter()
        .filter(|dev| dev.device_id == 0x8139)
        .for_each(|dev| {
            let mut rtl8139 = Rtl8139::new(Arc::new(Mutex::new(dev)));
            rtl8139.initialize();
        });*/
    }

    pub(crate) fn initialize_kernel_process(&self) {
        let mut processes = self.processes.write();

        let process_id = self
            .current_usable_process_id
            .fetch_add(1, Ordering::SeqCst);

        let page_table_physical_address = self.kernel_page_table_physical_address();

        processes.push(Process(Arc::new(ProcessInner {
            id: process_id,
            page_table: unsafe { self.kernel_page_table().as_mut() },
            page_table_physical_address,
            threads: Mutex::new(Vec::new()),
        })));

        drop(processes);

        let cpu_core_count = self
            .acpi()
            .madt
            .entries
            .iter()
            .filter(|entry| {
                matches!(
                    &entry.inner,
                    MadtEntryInner::ProcessorLocalApic(_local_apic)
                )
            })
            .count();

        // Spawn separate idle thread for every CPU
        for _ in 0..cpu_core_count {
            let _ = self.spawn_kernel_thread(idle_thread, LOWEST_THREAD_PRIORITY);
        }
    }

    // |-------------------------------|
    // | Process and thread management |
    // |-------------------------------|

    pub fn spawn_process(&self, program: &[u8], priority: usize) -> Result<Process, ()> {
        if priority > HIGHEST_THREAD_PRIORITY {
            return Err(());
        }

        let stack = unsafe { ThreadStack::allocate() };

        let mut program_page_table = self.create_address_space();

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
                        .unmap(
                            AddressSpace(&mut *program_page_table),
                            &Page::new(stack_virtual_address),
                        )
                        .unwrap();

                    memory_manager
                        .map(
                            AddressSpace(&mut *program_page_table),
                            Exact(
                                &Page::new(stack_virtual_address),
                                &Frame::new(stack_physical_address),
                            ),
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
            is_kernel_mode: false,
            reschedule: AtomicBool::new(true),
            priority,
        }));

        process.0.threads.lock().push(thread.clone());

        self.processes.write().push(process.clone());

        scheduler::schedule(thread);

        Ok(process)
    }

    pub fn spawn_kernel_thread(
        &self,
        entry_point: extern "C" fn() -> !,
        priority: usize,
    ) -> Result<Thread, ()> {
        if priority > HIGHEST_THREAD_PRIORITY {
            return Err(());
        }

        let kernel_process = self.processes.read().first().unwrap().clone();

        let thread_id = self.current_usable_thread_id.fetch_add(1, Ordering::SeqCst);

        let stack = unsafe { ThreadStack::allocate() };

        let thread = Thread(Arc::new(ThreadInner {
            process: kernel_process.clone(),
            id: thread_id,
            status: Mutex::new(Status::Running),
            entry: entry_point as *const c_void,
            registers: Mutex::new(Registers {
                rip: entry_point as usize as u64,
                rsp: stack as u64 + mem::size_of::<ThreadStack>() as u64 - 16,
                cs: (5 << 3),
                ss: (6 << 3),
                gs: GS::read_base().as_u64(),
                rflags: rflags::read_raw() | (1 << 9), // IF=1, enable interrupts in new thread regardless current CPU state
                ..Default::default()
            }),
            stack,
            is_kernel_mode: true,
            reschedule: AtomicBool::new(true),
            priority,
        }));

        kernel_process.0.threads.lock().push(thread.clone());

        scheduler::schedule(thread.clone());

        Ok(thread)
    }

    pub fn create_address_space(&self) -> Box<PageTable> {
        let mut page_table = Box::new(PageTable::new());

        let kernel_page_table: *mut PageTable = self.kernel_page_table().as_ptr();

        for level_4_page_table_entry_index in 256..512 {
            let level_4_page_table_entry =
                &unsafe { &*kernel_page_table }[level_4_page_table_entry_index];

            page_table[level_4_page_table_entry_index]
                .set_address(level_4_page_table_entry.address());
            page_table[level_4_page_table_entry_index].set_flags(level_4_page_table_entry.flags());
        }

        page_table
    }

    // |-----------|
    // | Accessors |
    // |-----------|

    #[inline(always)]
    pub fn boot_context(&self) -> &LimineBootContext {
        self.boot_context
            .get()
            .expect("boot_context was accessed before being initialized")
    }

    #[inline(always)]
    pub fn clock(&self) -> &SystemClock {
        self.clock
            .get()
            .expect("clock was accessed before being initialized")
    }

    #[inline(always)]
    pub fn memory_manager(&self) -> &RwLock<MemoryManager> {
        self.memory_manager
            .get()
            .expect("memory_manager was accessed before being initialized")
    }

    #[inline(always)]
    pub fn serial(&self) -> &Mutex<Serial> {
        self.platform_devices
            .serial
            .get()
            .expect("serial was accessed before being initialized")
    }

    #[inline(always)]
    pub fn pic(&self) -> &Mutex<ProgrammableInterruptController> {
        &self.platform_devices.pic
    }

    #[inline(always)]
    pub fn acpi(&self) -> &Acpi {
        self.platform_devices
            .acpi
            .get()
            .expect("acpi was accessed before being initialized")
    }

    #[inline(always)]
    pub fn apic(&self) -> &RwLock<Apic> {
        self.platform_devices
            .apic
            .get()
            .expect("apic was accessed before being initialized")
    }

    #[inline(always)]
    pub fn kernel_page_table_physical_address(&self) -> u64 {
        *self
            .kernel_page_table_physical_address
            .get()
            .expect("kernel_page_table_physical_address was accessed before being initialized")
    }

    #[inline(always)]
    pub fn kernel_page_table(&self) -> NonNull<PageTable> {
        *self
            .kernel_page_table
            .get()
            .expect("kernel_page_table was accessed before being initialized")
    }

    #[inline(always)]
    pub fn bsp_stack(&self) -> u64 {
        *self
            .bsp_stack
            .get()
            .expect("bsp_stack was accessed before being initialized")
    }
}

pub struct PlatformDevices {
    pub(crate) serial: Once<Mutex<Serial>>,
    pub(crate) pic: Mutex<ProgrammableInterruptController>,
    pub(crate) acpi: Once<Acpi>,
    pub(crate) apic: Once<RwLock<Apic>>,
}

#[inline(always)]
pub fn kernel_ref() -> &'static Kernel {
    &KERNEL
}

extern "C" fn idle_thread() -> ! {
    loop {
        hlt();
    }
}
