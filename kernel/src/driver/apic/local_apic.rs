use crate::arch::x86::gdt::{GDT_DESCRIPTOR, TSS};
use crate::arch::x86::idt::{ExceptionFrame, IDT};
use crate::arch::x86::use_kernel_page_table;
use crate::cpu::ProcessorControlBlock;
use crate::driver::pit::PIT;
use crate::kernel::Kernel;
use crate::memory::{memory_manager, MemoryError, Page, PageFlags, VirtualAddress};
use crate::{start_program, InterruptStack};
use alloc::sync::Arc;
use core::alloc::Layout;
use core::arch::asm;
use core::{
    mem,
    ptr::{self, addr_of},
};
use log::info;
use spin::RwLock;
use x86_64::registers::control::{Cr4, Cr4Flags};

pub const LOCAL_APIC_LAPIC_ID_REGISTER: u32 = 0x20;
pub const LOCAL_APIC_LAPIC_VERSION_REGISTER: u32 = 0x23;
// 0x40-0x70 - Reserved
pub const LOCAL_APIC_TASK_PRIORITY_REGISTER: u32 = 0x80;
pub const LOCAL_APIC_ARBITRATION_PRIORITY_REGISTER: u32 = 0x90;
pub const LOCAL_APIC_PROCESSOR_PRIORITY_REGISTER: u32 = 0xA0;
pub const LOCAL_APIC_END_OF_INTERRUPT_REGISTER: u32 = 0xB0;
pub const LOCAL_APIC_REMOTE_READ_REGISTER: u32 = 0xC0;
pub const LOCAL_APIC_LOGICAL_DESTINATION_REGISTER: u32 = 0xD0;
pub const LOCAL_APIC_DESTINATION_FORMAT_REGISTER: u32 = 0xE0;
pub const LOCAL_APIC_SPURIOUS_INTERRUPT_VECTOR_REGISTER: u32 = 0xF0;
// ISR
// TMR
// IRR
pub const LOCAL_APIC_ERROR_STATUS_REGISTER: u32 = 0x280;
pub const LOCAL_APIC_INTERRUPT_OPTIONS_REGISTER: u32 = 0x300;
pub const LOCAL_APIC_INTERRUPT_TARGET_PROCESSOR_REGISTER: u32 = 0x310;
pub const LOCAL_APIC_LVT_TIMER_REGISTER: u32 = 0x320;
pub const LOCAL_APIC_LVT_ERROR_REGISTER: u32 = 0x370;
pub const LOCAL_APIC_INITIAL_COUNT_REGISTER: u32 = 0x380;
pub const LOCAL_APIC_CURRENT_COUNT_REGISTER: u32 = 0x390;
pub const LOCAL_APIC_DIVIDE_CONFIGURATION_REGISTER: u32 = 0x3E0;
pub const IA32_APIC_BASE_MSR: u32 = 0x1B;
pub const APIC_BASE_MSR_BSP_FLAG: u64 = 1 << 8;
pub const APIC_BASE_MSR_APIC_GLOBAL_ENABLE_FLAG: u64 = 1 << 11;
pub const APIC_BASE_MSR_APIC_BASE_FIELD_MASK: u64 = 0xFFFFFF000;

pub const STACK_SIZE: usize = 4 * 1024 * 1024;
pub const LOCAL_APIC_TIMER_PERIODIC: u32 = 1 << 17;

pub static TRAMPOLINE_CODE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/trampoline"));
pub static mut AP_STARTUP_SPINLOCK: RwLock<u8> = RwLock::new(0);

pub unsafe extern "C" fn ap_start(apic_processor_id: u64, kernel_ptr: *const RwLock<Kernel>) -> ! {
    let stack_pointer: u64;

    asm!("mov {stack_pointer}, rsp", stack_pointer = out(reg) stack_pointer);

    // @TODO: Move to perform_arch_initialization()
    let kernel = Arc::from_raw(kernel_ptr);

    IDT.load();
    Cr4::write(Cr4::read() | Cr4Flags::FSGSBASE);

    asm!(
        "
            cli
            lgdt [{gdt}]
        ",
        options(nomem, nostack),
        gdt = in(reg) addr_of!(GDT_DESCRIPTOR) as u64,
    );

    let physical_memory_offset = kernel.read().physical_memory_offset;

    ProcessorControlBlock::create_pcb_for_current_processor(apic_processor_id as u16);
    let pcb = ProcessorControlBlock::get_pcb_for_current_processor();
    let local_apic = LocalApic::initialize_for_current_processor(kernel);
    local_apic.enable_timer();

    _ = (*pcb).local_apic.set(local_apic);

    let processor_index = unsafe { (*pcb).apic_processor_id }; // NOTE: APIC Processor ID's behavior isn't guaranteed but seems to always work this way in practice

    let interrupt_stack =
        alloc::alloc::alloc_zeroed(Layout::new::<InterruptStack>()) as *mut InterruptStack;

    TSS[processor_index as usize].rsp0 =
        interrupt_stack as u64 + mem::size_of::<InterruptStack>() as u64 - 16;
    TSS[processor_index as usize].rsp1 =
        interrupt_stack as u64 + mem::size_of::<InterruptStack>() as u64 - 16;
    TSS[processor_index as usize].rsp2 =
        interrupt_stack as u64 + mem::size_of::<InterruptStack>() as u64 - 16;

    asm!(
        "ltr {segment_selector:x}",
        options(nomem, nostack, preserves_flags),
        segment_selector = in(reg) (((9 + (processor_index * 2)) << 3) | 3)
    );

    asm!("sti", options(nomem, nostack));

    info!("Processor {} has started", processor_index);

    *AP_STARTUP_SPINLOCK.write() = 1;

    static PROGRAM: &[u8] =
        include_bytes!("../../../../sandbox/target/x86_64-moose/release/sandbox");

    start_program(
        PROGRAM,
        physical_memory_offset,
        stack_pointer,
        interrupt_stack,
    );
}

pub struct LocalApic {
    local_apic_base: u64,
    kernel: Arc<RwLock<Kernel>>,
}

impl LocalApic {
    pub fn initialize_for_current_processor(kernel: Arc<RwLock<Kernel>>) -> LocalApic {
        let apic_base =
            unsafe { x86_64::registers::model_specific::Msr::new(IA32_APIC_BASE_MSR).read() };
        let local_apic_base = apic_base & APIC_BASE_MSR_APIC_BASE_FIELD_MASK;

        // Make sure local apic base is mapped into memory
        // It is always on 4KiB boundary
        {
            let mut memory_manager = memory_manager().write();

            match unsafe {
                memory_manager.map_identity_for_current_address_space(
                    &Page::new(VirtualAddress::new(local_apic_base)),
                    PageFlags::WRITABLE | PageFlags::WRITE_THROUGH | PageFlags::DISABLE_CACHING,
                )
            } {
                Ok(()) => {}
                Err(MemoryError::AlreadyMapped) => {}
                Err(err) => {
                    panic!("{}", err);
                }
            }
        }

        let apic = LocalApic {
            local_apic_base,
            kernel,
        };

        // Enable Local APIC
        //
        // Local APIC can be enabled by setting 8th bit of spurious interrupt vector register
        apic.write_register(
            LOCAL_APIC_SPURIOUS_INTERRUPT_VECTOR_REGISTER,
            apic.read_register(LOCAL_APIC_SPURIOUS_INTERRUPT_VECTOR_REGISTER) | (1 << 8),
        );

        // Remap spurious interrupt vector register
        apic.write_register(LOCAL_APIC_LVT_ERROR_REGISTER, 0x1F);

        if apic_base & APIC_BASE_MSR_BSP_FLAG != 0 {
            // We're running first LocalAPIC initialization on the bootstrap processor and need to
            // check the speed of APIC timer.
            apic.check_timer_speed()
        }

        apic
    }

    pub fn enable_timer(&self) {
        // Fire timer every 10ms
        let ticks_per_10ms = self
            .kernel
            .read()
            .apic
            .read()
            .local_apic_timer_ticks_per_second
            / 100;

        // Enable interrupts
        self.write_register(LOCAL_APIC_TASK_PRIORITY_REGISTER, 0);

        // Set divider 16
        self.write_register(LOCAL_APIC_DIVIDE_CONFIGURATION_REGISTER, 0x3);

        self.write_register(
            LOCAL_APIC_LVT_TIMER_REGISTER,
            self.kernel.read().timer_irq as u32 | LOCAL_APIC_TIMER_PERIODIC,
        );

        // Start the timer
        self.write_register(LOCAL_APIC_INITIAL_COUNT_REGISTER, ticks_per_10ms as u32);
    }

    pub fn signal_end_of_interrupt(&self) {
        self.write_register(LOCAL_APIC_END_OF_INTERRUPT_REGISTER, 0);
    }

    pub fn reset_error_register(&self) {
        self.write_register(LOCAL_APIC_ERROR_STATUS_REGISTER, 0);
    }

    fn check_timer_speed(&self) {
        // This function is run only once during BSP's Local APIC initialization

        // APIC timer tick speed is not standardized, and every platform can have custom speed, so
        // we need to somehow measure it.
        //
        // It can be done by running APIC timer, sleeping for measurable amount of time (with use of
        // PIT) and checking how many times APIC "ticked".

        // Tell APIC timer to use divider 16
        self.write_register(LOCAL_APIC_DIVIDE_CONFIGURATION_REGISTER, 0x3);

        // Set APIC timer init counter to -1
        //
        // After every write to this register, current countdown is discarded and new initial count
        // is copied to current count register and countdown starts.
        self.write_register(LOCAL_APIC_INITIAL_COUNT_REGISTER, 0xFFFFFFFF);

        // Perform PIT-assisted sleep for 1 second
        unsafe { PIT.wait_seconds(1) };

        let ticks_per_second = 0xFFFFFFFF - self.read_register(LOCAL_APIC_CURRENT_COUNT_REGISTER);

        self.kernel
            .read()
            .apic
            .write()
            .local_apic_timer_ticks_per_second = ticks_per_second as u64;
    }

    pub(crate) fn read_register(&self, register: u32) -> u32 {
        let ptr = (self.local_apic_base + register as u64) as *mut u32;
        unsafe { ptr::read_volatile(ptr) }
    }

    pub(crate) fn write_register(&self, register: u32, value: u32) {
        let ptr = (self.local_apic_base + register as u64) as *mut u32;

        unsafe { ptr::write_volatile(ptr, value) }
    }
}

pub extern "C" fn timer_interrupt_handler(_interrupt_stack_frame: &ExceptionFrame) {
    use_kernel_page_table(|| unsafe {
        _ = &(*ProcessorControlBlock::get_pcb_for_current_processor())
            .local_apic
            .get()
            .unwrap()
            .signal_end_of_interrupt();
    });
}
