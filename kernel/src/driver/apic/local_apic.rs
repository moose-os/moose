use core::{
    arch::{
        asm,
        x86_64::{__cpuid, _rdtsc},
    },
    ptr,
};

use spin::RwLock;
use x86_64::{
    PhysAddr,
    registers::control::{Cr3, Cr3Flags, Cr4, Cr4Flags},
    structures::paging::{PhysFrame, Size4KiB},
};

use crate::{
    arch::x86::{
        asm::{disable_interrupts, enable_interrupts},
        cpu::ProcessorControlBlock,
        gdt::{load_tss, setup_tss},
        idt::IDT,
        perform_arch_initialization,
    },
    kernel::{Kernel, kernel_ref},
    subsystem::{
        memory::{AnyIn, CurrentAddressSpace, Frame, PageFlags, PhysicalAddress, memory_manager},
        process::{Registers, Status},
        scheduler::{self, current_thread, has_current_thread},
        syscall::write_syscall,
    },
};

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
pub const LOCAL_APIC_TIMER_ONESHOT: u32 = 0;
pub const LOCAL_APIC_TIMER_PERIODIC: u32 = 1 << 17;

pub static TRAMPOLINE_CODE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/trampoline"));
pub static AP_STARTUP_SPINLOCK: RwLock<u8> = RwLock::new(0);

pub unsafe extern "C" fn ap_start(apic_processor_id: u64, _kernel_ptr: *const Kernel) -> ! {
    unsafe {
        IDT.lock().load();
        Cr4::write(Cr4::read() | Cr4Flags::FSGSBASE);
    }

    disable_interrupts();

    unsafe {
        perform_arch_initialization(false);

        ProcessorControlBlock::create_pcb_for_current_processor(apic_processor_id as u16);
    }

    let pcb = ProcessorControlBlock::current();
    let local_apic = LocalApic::initialize_for_current_processor();

    _ = pcb.local_apic.set(local_apic);

    let processor_index = pcb.apic_processor_id; // NOTE: APIC Processor ID's behavior isn't guaranteed but seems to always work this way in practice

    unsafe {
        setup_tss(processor_index);
        load_tss(processor_index);
    }

    enable_interrupts();

    info!("Processor {} has started", processor_index);

    *AP_STARTUP_SPINLOCK.write() = 1;

    loop {
        unsafe {
            asm!("hlt");
        }
    }
}

pub struct LocalApic {
    local_apic_base: u64,
    x2apic: bool,
}

impl LocalApic {
    pub fn initialize_for_current_processor() -> LocalApic {
        let apic_base =
            unsafe { x86_64::registers::model_specific::Msr::new(IA32_APIC_BASE_MSR).read() };
        let local_apic_base_physical =
            PhysicalAddress::new(apic_base & APIC_BASE_MSR_APIC_BASE_FIELD_MASK);

        let local_apic_base_virtual = {
            let mut memory_manager = memory_manager().write();

            let frame = Frame::new(local_apic_base_physical);

            unsafe {
                memory_manager
                    .map(
                        CurrentAddressSpace,
                        AnyIn(&frame, 256..512),
                        PageFlags::WRITABLE | PageFlags::WRITE_THROUGH | PageFlags::DISABLE_CACHING,
                    )
                    .expect("Map any failed")
                    .page
                    .address()
            }
        };

        let apic = LocalApic {
            local_apic_base: local_apic_base_virtual.as_u64(),
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

    fn is_x2apic_supported() -> bool {
        let result = __cpuid(1);
        let x2apic_mask = 1 << 21;

        (result.ecx & x2apic_mask) != 0
    }

    #[inline(always)]
    pub(crate) fn read_register(&self, register: u32) -> u32 {
        if self.x2apic {
            let msr = 0x800 + (register >> 4);
            let low: u32;
            let _high: u32;

            unsafe {
                asm!(
                    "rdmsr",
                    in("ecx") msr,
                    out("eax") low,
                    out("edx") _high,
                    options(nomem, nostack, preserves_flags)
                );
            }
            low
        } else {
            let ptr = (self.local_apic_base + register as u64) as *mut u32;
            unsafe { ptr::read_volatile(ptr) }
        }
    }

    #[inline(always)]
    pub(crate) fn write_register(&self, register: u32, value: u32) {
        if self.x2apic {
            let msr = 0x800 + (register >> 4);
            let low = value;
            let high = 0u32;

            unsafe {
                asm!(
                    "wrmsr",
                    in("ecx") msr,
                    in("eax") low,
                    in("edx") high,
                    options(nomem, nostack, preserves_flags)
                );
            }
        } else {
            let ptr = (self.local_apic_base + register as u64) as *mut u32;
            unsafe { ptr::write_volatile(ptr, value) }
        }
    }

    pub fn is_isr(&self, vector: u8) -> bool {
        let reg_offset = (vector / 32) as u32 * 0x10;
        let bit = vector % 32;

        let isr_val = self.read_register(0x100 + reg_offset);

        (isr_val & (1 << bit)) != 0
    }
}

macro_rules! define_raw_interrupt_handler_fn {
    ($name:ident, $handler:ident) => {
        #[unsafe(naked)]
        pub(crate) extern "C" fn $name() -> ! {
            core::arch::naked_asm!(
                // allocate space for GPRs
                "sub rsp, {regs_size}",

                // save all GPRs
                "mov [rsp + {rax_offset}], rax",
                "mov [rsp + {rbx_offset}], rbx",
                "mov [rsp + {rcx_offset}], rcx",
                "mov [rsp + {rdx_offset}], rdx",
                "mov [rsp + {rsi_offset}], rsi",
                "mov [rsp + {rdi_offset}], rdi",
                "mov [rsp + {rbp_offset}], rbp",
                "mov [rsp + {r8_offset}], r8",
                "mov [rsp + {r9_offset}], r9",
                "mov [rsp + {r10_offset}], r10",
                "mov [rsp + {r11_offset}], r11",
                "mov [rsp + {r12_offset}], r12",
                "mov [rsp + {r13_offset}], r13",
                "mov [rsp + {r14_offset}], r14",
                "mov [rsp + {r15_offset}], r15",

                // copy hardware-created IRET frame
                "mov rax, [rsp + {regs_size} + 0]",  "mov [rsp + {rip_offset}], rax",
                "mov rax, [rsp + {regs_size} + 8]",  "mov [rsp + {cs_offset}], rax",
                "mov rax, [rsp + {regs_size} + 16]", "mov [rsp + {rflags_offset}], rax",
                "mov rax, [rsp + {regs_size} + 24]", "mov [rsp + {rsp_offset}], rax",
                "mov rax, [rsp + {regs_size} + 32]", "mov [rsp + {ss_offset}], rax",

                // save segments bases
                "rdfsbase rax", "mov [rsp + {fs_offset}], rax",
                "rdgsbase rax", "mov [rsp + {gs_offset}], rax",

                // call the rust handler
                "mov rdi, rsp",
                concat!("call ", stringify!($handler)),

                // restore segment bases
                "mov rax, [rsp + {fs_offset}]", "wrfsbase rax",
                "mov rax, [rsp + {gs_offset}]", "wrgsbase rax",

                // write modified IRET frame back to the stack
                "mov rax, [rsp + {rip_offset}]",     "mov [rsp + {regs_size} + 0], rax",
                "mov rax, [rsp + {cs_offset}]",      "mov [rsp + {regs_size} + 8], rax",
                "mov rax, [rsp + {rflags_offset}]",  "mov [rsp + {regs_size} + 16], rax",
                "mov rax, [rsp + {rsp_offset}]",     "mov [rsp + {regs_size} + 24], rax",
                "mov rax, [rsp + {ss_offset}]",      "mov [rsp + {regs_size} + 32], rax",

                // restore GPRs
                "mov r15, [rsp + {r15_offset}]",
                "mov r14, [rsp + {r14_offset}]",
                "mov r13, [rsp + {r13_offset}]",
                "mov r12, [rsp + {r12_offset}]",
                "mov r11, [rsp + {r11_offset}]",
                "mov r10, [rsp + {r10_offset}]",
                "mov r9,  [rsp + {r9_offset}]",
                "mov r8,  [rsp + {r8_offset}]",
                "mov rbp, [rsp + {rbp_offset}]",
                "mov rsi, [rsp + {rsi_offset}]",
                "mov rdi, [rsp + {rdi_offset}]",
                "mov rdx, [rsp + {rdx_offset}]",
                "mov rcx, [rsp + {rcx_offset}]",
                "mov rbx, [rsp + {rbx_offset}]",
                "mov rax, [rsp + {rax_offset}]",

                "add rsp, {regs_size}",
                "iretq",

                regs_size    = const(core::mem::size_of::<Registers>()),
                rax_offset   = const(core::mem::offset_of!(Registers, rax)),
                rbx_offset   = const(core::mem::offset_of!(Registers, rbx)),
                rcx_offset   = const(core::mem::offset_of!(Registers, rcx)),
                rdx_offset   = const(core::mem::offset_of!(Registers, rdx)),
                rsi_offset   = const(core::mem::offset_of!(Registers, rsi)),
                rdi_offset   = const(core::mem::offset_of!(Registers, rdi)),
                rbp_offset   = const(core::mem::offset_of!(Registers, rbp)),
                rsp_offset   = const(core::mem::offset_of!(Registers, rsp)),
                r8_offset    = const(core::mem::offset_of!(Registers, r8)),
                r9_offset    = const(core::mem::offset_of!(Registers, r9)),
                r10_offset   = const(core::mem::offset_of!(Registers, r10)),
                r11_offset   = const(core::mem::offset_of!(Registers, r11)),
                r12_offset   = const(core::mem::offset_of!(Registers, r12)),
                r13_offset   = const(core::mem::offset_of!(Registers, r13)),
                r14_offset   = const(core::mem::offset_of!(Registers, r14)),
                r15_offset   = const(core::mem::offset_of!(Registers, r15)),
                rip_offset   = const(core::mem::offset_of!(Registers, rip)),
                rflags_offset = const(core::mem::offset_of!(Registers, rflags)),
                cs_offset    = const(core::mem::offset_of!(Registers, cs)),
                ss_offset    = const(core::mem::offset_of!(Registers, ss)),
                fs_offset    = const(core::mem::offset_of!(Registers, fs)),
                gs_offset    = const(core::mem::offset_of!(Registers, gs)),
            )
        }
    };
}

define_raw_interrupt_handler_fn!(raw_timer_interrupt_handler, timer_interrupt_handler);
define_raw_interrupt_handler_fn!(raw_syscall_interrupt_handler, syscall_interrupt_handler);
define_raw_interrupt_handler_fn!(raw_yield_handler, yield_handler);

#[unsafe(no_mangle)]
extern "C" fn timer_interrupt_handler(registers: *mut Registers) {
    let mut pt = Cr3::read().0.start_address().as_u64();

    use_kernel_page_table(|| {
        let now = kernel_ref().clock().monotonic_ns();
        let mut timers = ProcessorControlBlock::current().hr_timers.write();
        let mut need_reschedule = false;

        while let Some(expired_timer) = timers.poll_expired(now) {
            match expired_timer.action.clone() {
                TimerAction::ExecuteCallback { function } => {
                    function(registers.addr() as u64);
                }
                TimerAction::Reschedule => {
                    need_reschedule = true;
                }
                TimerAction::WakeUp {
                    process_id,
                    thread_id,
                } => {
                    let processes = kernel_ref().processes.read();
                    let process = processes.iter().find(|p| p.id() == process_id);

                    let threads = process.unwrap().threads();
                    let thread = threads.iter().find(|t| t.id() == thread_id);

                    thread.unwrap().set_status(Status::Running);
                }
            };
        }

        if need_reschedule {
            scheduler::run(registers);
            pt = current_thread().0.process.0.page_table_physical_address;
        }

        // SAFETY: There is always going to be at least one (scheduler) timer
        let clock = kernel_ref().clock();
        let next_expiration = timers.next_expiry().unwrap();
        let current_time = clock.monotonic_ns();

        let diff = next_expiration.saturating_sub(current_time).max(1);

        let ticks = clock.ns_to_apic_ticks(diff);

        ProcessorControlBlock::current()
            .local_apic()
            .set_timer(ticks);

        ProcessorControlBlock::current()
            .local_apic()
            .signal_end_of_interrupt();
    });

    let frame = PhysFrame::<Size4KiB>::from_start_address(PhysAddr::new(pt)).unwrap();

    unsafe {
        Cr3::write(frame, Cr3Flags::empty());
    }
}

#[unsafe(no_mangle)]
extern "C" fn syscall_interrupt_handler(registers: *mut Registers) {
    let regs = unsafe { &*registers };

    // Keep the process page table active while dispatching syscalls so user
    // pointers remain accessible. write_syscall switches to the kernel page
    // table only for the parts that touch kernel memory.
    match regs.rax {
        1 => write_syscall(regs.rdi, regs.rsi as *const u8, regs.rdx),
        _ => unimplemented!(),
    };

    // Fast return if thread still wants to run
    if current_thread().status() != Status::Waiting {
        return;
    }

    // Run scheduler if thread is sleeping
    let mut pt = Cr3::read().0.start_address().as_u64();
    use_kernel_page_table(|| {
        scheduler::run(registers);

        if !has_current_thread() {
            loop {
                x86_64::instructions::hlt();
            }
        }

        pt = current_thread().0.process.0.page_table_physical_address;
    });

    let frame = PhysFrame::<Size4KiB>::from_start_address(PhysAddr::new(pt)).unwrap();

    unsafe {
        Cr3::write(frame, Cr3Flags::empty());
    }
}

#[unsafe(no_mangle)]
extern "C" fn yield_handler(registers: *mut Registers) {
    disable_interrupts();

    let mut pt = Cr3::read().0.start_address().as_u64();

    use_kernel_page_table(|| {
        scheduler::run(registers);
        pt = current_thread().0.process.0.page_table_physical_address;
    });

    let frame = PhysFrame::<Size4KiB>::from_start_address(PhysAddr::new(pt)).unwrap();

    unsafe {
        Cr3::write(frame, Cr3Flags::empty());
    }

    enable_interrupts();
}
