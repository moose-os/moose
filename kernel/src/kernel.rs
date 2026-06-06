use alloc::{boxed::Box, collections::VecDeque, sync::Arc, vec::Vec};
use core::{
    ffi::c_void,
    mem,
    ptr::NonNull,
    sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
};

use spin::{Mutex, Once, RwLock};
use x86_64::{
    registers::{
        control::Cr3,
        rflags,
        segmentation::{GS, Segment64},
    },
    structures::DescriptorTablePointer,
};

use crate::{
    arch::{
        irq::{IrqAllocator, IrqLevel},
        x86::{InterruptStack, cpu::MAXIMUM_CPU_CORES, gdt::TSS},
    },
    driver::{
        acpi::{Acpi, Device, create_device_list},
        apic::Apic,
        pci::{Pci, PciDevice},
        pic::ProgrammableInterruptController,
        pit::ProgrammableIntervalTimer,
        serial::{Serial, SerialPort},
        vga::Vga,
    },
    subsystem::{
        allocator::{HEAP_START, initialize_heap},
        boot::limine::LimineBootContext,
        linker::Linker,
        memory::{
            AddressSpace, Any, CurrentAddressSpace, Exact, Frame, FrameAllocator, MemoryManager,
            PAGE_SIZE, Page, PageFlags, PageTable, PhysicalAddress, VirtualAddress,
            current_page_table, memory_manager,
        },
        process::{
            HIGHEST_THREAD_PRIORITY, Process, ProcessInner, Registers, Status, Thread, ThreadInner,
            ThreadStack,
        },
        scheduler::{self, Scheduler},
        terminal::Terminal,
    },
};

static KERNEL: Kernel = Kernel::new();

pub struct Kernel {
    pub boot_context: Once<LimineBootContext>,

    pub kernel_page_table_physical_address: Once<u64>,
    pub kernel_page_table: Once<NonNull<PageTable>>,
    pub memory_manager: Once<RwLock<MemoryManager>>,

    pub bsp_stack: Once<u64>,
    pub gdt: Once<DescriptorTablePointer>,

    pub irq_allocator: Mutex<IrqAllocator>,

    pub platform_devices: PlatformDevices,
    pub devices: Mutex<Vec<Arc<Mutex<Device>>>>,
    pub pci_devices: Mutex<Vec<PciDevice>>,

    pub terminal: Once<Mutex<Terminal>>,

    pub timer_irq: Once<u8>,
    pub ticks: AtomicU64,

    current_usable_process_id: AtomicUsize,
    current_usable_thread_id: AtomicUsize,
    processes: RwLock<Vec<Process>>,

    pub scheduler: Scheduler,
    /// A global queue for threads waiting on a timed sleep or timeout.
    ///
    /// ### Data Structure:
    /// Entry in the vector is a tuple of `(usize, Thread)`:
    /// * `usize`: The absolute tick count at which the timeout expires.
    /// * `Thread`: The handle or descriptor of the thread to be woken up.
    pub timeout_queue: Mutex<VecDeque<(u64, Thread)>>,
}

unsafe impl Send for Kernel {}

// TODO: Remove this
unsafe impl Sync for Kernel {}

impl Kernel {
    pub const fn new() -> Self {
        Self {
            boot_context: Once::new(),

            kernel_page_table_physical_address: Once::new(),
            kernel_page_table: Once::new(),
            memory_manager: Once::new(),

            bsp_stack: Once::new(),
            gdt: Once::new(),

            irq_allocator: Mutex::new(IrqAllocator::new()),

            platform_devices: PlatformDevices {
                serial: Once::new(),
                pic: Mutex::new(ProgrammableInterruptController::new()),
                pit: RwLock::new(ProgrammableIntervalTimer::new()),
                acpi: Once::new(),
                apic: Once::new(),
            },
            devices: Mutex::new(Vec::new()),
            pci_devices: Mutex::new(Vec::new()),

            terminal: Once::new(),

            timer_irq: Once::new(),
            ticks: AtomicU64::new(0),

            current_usable_process_id: AtomicUsize::new(0),
            current_usable_thread_id: AtomicUsize::new(0),
            processes: RwLock::new(Vec::new()),

            scheduler: Scheduler::new(),
            timeout_queue: Mutex::new(VecDeque::new()),
        }
    }

    // |----------------|
    // | Initialization |
    // |----------------|

    pub(crate) fn initialize_memory(&self) {
        self.retrieve_kernel_page_table_physical_address();
        self.initialize_memory_manager();
        initialize_heap().expect("Failed to initialize heap");
        self.map_kernel_page_table();
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

    pub(crate) fn map_kernel_page_table(&self) {
        let page_table_virtual_address = {
            let mut memory_manager = memory_manager().write();

            let frame = Frame::new(PhysicalAddress::new(
                self.kernel_page_table_physical_address(),
            ));

            unsafe { memory_manager.map(CurrentAddressSpace, Any(&frame), PageFlags::empty()) }
                .unwrap()
                .page
                .address()
        };

        self.kernel_page_table.call_once(|| {
            NonNull::new(page_table_virtual_address.as_mut_ptr())
                .expect("page_table_virtual_address was zero")
        });
    }

    pub(crate) fn retrieve_gdt(&self) {
        self.gdt.call_once(x86_64::instructions::tables::sgdt);
    }

    pub(crate) fn retrieve_kernel_page_table_physical_address(&self) {
        self.kernel_page_table_physical_address
            .call_once(|| Cr3::read().0.start_address().as_u64());
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

    pub(crate) fn allocate_timer_irq(&self) {
        self.timer_irq
            .call_once(|| self.irq_allocator.lock().allocate_irq(IrqLevel::Clock));
    }

    pub(crate) fn set_bsp_stack(&self, stack_pointer: u64) {
        self.bsp_stack.call_once(|| stack_pointer);
    }

    #[inline(always)]
    pub(crate) fn initialize_pic(&self) {
        self.platform_devices.pic.lock().initialize();
    }

    #[inline(always)]
    pub(crate) fn initialize_pit(&self) {
        self.platform_devices.pit.write().initialize();
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
            .call_once(|| RwLock::new(Apic::initialize(self.timer_irq())));
    }

    pub(crate) fn build_device_tree(&self) {
        *self.devices.lock() = create_device_list();
        *self.pci_devices.lock() = Pci::build_device_tree();
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

        let page_table_physical_address = {
            let memory_manager = memory_manager().read();

            memory_manager
                .translate_virtual_address_to_physical_for_current_address_space(
                    VirtualAddress::new(
                        unsafe { self.kernel_page_table().as_mut() } as *mut _ as u64
                    ),
                )
                .unwrap()
                .as_u64()
        };

        processes.push(Process(Arc::new(ProcessInner {
            id: process_id,
            page_table: unsafe { self.kernel_page_table().as_mut() },
            page_table_physical_address,
            threads: Mutex::new(Vec::new()),
        })));
    }

    // |-------------------------------|
    // | Process and thread management |
    // |-------------------------------|

    pub fn spawn_process(&self, program: &[u8], priority: usize) -> Result<Process, ()> {
        if priority > HIGHEST_THREAD_PRIORITY {
            return Err(());
        }

        let stack = unsafe { ThreadStack::allocate() };

        let mut program_page_table = self.create_address_space(self.bsp_stack());

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
                rflags: rflags::read_raw(),
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

    pub fn create_address_space(&self, kernel_stack: u64) -> Box<PageTable> {
        let mut page_table = Box::new(PageTable::new());

        let kernel_virtual_base_address = self.boot_context().kernel_virtual_base_address;
        let physical_memory_offset = self.boot_context().physical_memory_offset;

        // map kernel in program's address space
        {
            let kernel_level_4_page_table_entry_index =
                ((kernel_virtual_base_address >> 39) & 0b1_1111_1111) as usize;

            let kernel_page_table = unsafe { current_page_table(physical_memory_offset) };

            let level_4_page_table_entry =
                &unsafe { &*kernel_page_table }[kernel_level_4_page_table_entry_index];

            page_table[kernel_level_4_page_table_entry_index]
                .set_address(level_4_page_table_entry.address());
            page_table[kernel_level_4_page_table_entry_index]
                .set_flags(level_4_page_table_entry.flags());
        }

        // map kernel's stack in program's address space
        {
            let kernel_page_table = unsafe { current_page_table(physical_memory_offset) };

            let level_4_page_table_entry_index = ((kernel_stack >> 39) & 0b1_1111_1111) as usize;
            let level_4_page_table_entry =
                &unsafe { &*kernel_page_table }[level_4_page_table_entry_index];

            page_table[level_4_page_table_entry_index]
                .set_address(level_4_page_table_entry.address());
            page_table[level_4_page_table_entry_index].set_flags(level_4_page_table_entry.flags());
        }

        // map kernel's heap in program's address space
        {
            let kernel_page_table = unsafe { current_page_table(physical_memory_offset) };

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
            let tss = TSS.lock();

            for processor_idx in 0..MAXIMUM_CPU_CORES {
                if tss[processor_idx].rsp0 == 0 {
                    continue;
                }

                let interrupt_stack = tss[processor_idx].rsp0 as *mut InterruptStack as u64
                    - mem::size_of::<InterruptStack>() as u64
                    + 16;

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
                                AddressSpace(&mut *page_table),
                                &Page::new(interrupt_stack_virtual_address),
                            )
                            .unwrap();

                        memory_manager
                            .map(
                                AddressSpace(&mut *page_table),
                                Exact(
                                    &Page::new(interrupt_stack_virtual_address),
                                    &Frame::new(interrupt_stack_physical_address),
                                ),
                                PageFlags::WRITABLE,
                            )
                            .unwrap();
                    }
                }
            }
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
    pub fn pit(&self) -> &RwLock<ProgrammableIntervalTimer> {
        &self.platform_devices.pit
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

    #[inline(always)]
    pub fn timer_irq(&self) -> u8 {
        *self
            .timer_irq
            .get()
            .expect("timer_irq was accessed before being initialized")
    }
}

pub struct PlatformDevices {
    pub(crate) serial: Once<Mutex<Serial>>,
    pub(crate) pic: Mutex<ProgrammableInterruptController>,
    pub(crate) pit: RwLock<ProgrammableIntervalTimer>,
    pub(crate) acpi: Once<Acpi>,
    pub(crate) apic: Once<RwLock<Apic>>,
}

#[inline(always)]
pub fn kernel_ref() -> &'static Kernel {
    &KERNEL
}
