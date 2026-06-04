use alloc::{boxed::Box, vec::Vec};
use core::arch::{asm, naked_asm};

use bitfield_struct::bitfield;
use spin::Mutex;
use x86_64::registers::control::Cr2;

use crate::subsystem::syscall::write_syscall;

use super::{gdt::KERNEL_MODE_CODE_SEGMENT_INDEX, use_kernel_page_table};

pub static IDT: Mutex<Idt> = Mutex::new(Idt::new());

static mut REGISTERED_INTERRUPT_HANDLERS: [Vec<ExceptionHandler>; 224] = {
    const DEFAULT: Vec<ExceptionHandler> = Vec::new();

    [DEFAULT; 224]
};

const SYSCALL_IRQ: u8 = 0x80;

macro_rules! register_indexed_interrupt_handlers {
    ($idt:expr, $($idx:literal),* $(,)?) => {
        $(
            $idt.interrupts[$idx] =
                IdtEntry::kernel_mode_ring3_accessible_interrupt(
                    generate_exception_handler_stub_addr!(interrupt_handler::<$idx>),
                );
        )*
    };
}

macro_rules! generate_exception_handler_stub_addr {
    ($name: expr) => {
        generate_exception_handler_stub!($name) as *const () as u64
    };
}

macro_rules! generate_exception_handler_stub {
    ($name: expr) => {
        {
            #[unsafe(naked)]
            pub extern "C" fn raw_handler() -> ! {
                naked_asm!(
                    "
                        push rax
                        push rcx
                        push rdx
                        push rsi
                        push rdi
                        push r8
                        push r9
                        push r10
                        push r11

                        mov rdi, rsp
                        add rdi, 9 * 8
                        mov rsi, rsp

                        call {}

                        pop r11
                        pop r10
                        pop r9
                        pop r8
                        pop rdi
                        pop rsi
                        pop rdx
                        pop rcx
                        pop rax

                        iretq
                    ",
                    sym $name
                );
            }

            raw_handler as extern "C" fn() -> !
        }
    };
}

pub fn init_idt() {
    let mut idt = IDT.lock();

    idt.divide_error = IdtEntry::kernel_mode_ring3_accessible_interrupt(
        generate_exception_handler_stub_addr!(division_error_handler),
    );
    // Debug
    idt.non_maskable_interrupt = IdtEntry::kernel_mode_ring3_accessible_interrupt(
        generate_exception_handler_stub_addr!(non_maskable_interrupt_handler),
    );
    idt.breakpoint = IdtEntry::kernel_mode_ring3_accessible_interrupt(
        generate_exception_handler_stub_addr!(breakpoint_handler),
    );
    idt.overflow = IdtEntry::kernel_mode_ring3_accessible_interrupt(
        generate_exception_handler_stub_addr!(overflow_handler),
    );
    idt.bound_range_exceeded = IdtEntry::kernel_mode_ring3_accessible_interrupt(
        generate_exception_handler_stub_addr!(bound_range_exceeded_handler),
    );
    idt.invalid_opcode = IdtEntry::kernel_mode_ring3_accessible_interrupt(
        generate_exception_handler_stub_addr!(invalid_opcode_handler),
    );
    idt.device_not_available = IdtEntry::kernel_mode_ring3_accessible_interrupt(
        generate_exception_handler_stub_addr!(device_not_available_handler),
    );
    idt.double_fault = IdtEntry::kernel_mode_ring3_accessible_interrupt(
        generate_exception_handler_stub_addr!(double_fault_handler),
    );
    // Coprocessor segment overrun
    idt.invalid_tss = IdtEntry::kernel_mode_ring3_accessible_interrupt(
        generate_exception_handler_stub_addr!(invalid_tss_handler),
    );
    idt.segment_not_present = IdtEntry::kernel_mode_ring3_accessible_interrupt(
        generate_exception_handler_stub_addr!(segment_not_present_handler),
    );
    idt.stack_segment_fault = IdtEntry::kernel_mode_ring3_accessible_interrupt(
        generate_exception_handler_stub_addr!(stack_segment_fault_handler),
    );
    idt.general_protection_fault = IdtEntry::kernel_mode_ring3_accessible_interrupt(
        generate_exception_handler_stub_addr!(general_protection_fault_handler),
    );
    idt.page_fault = IdtEntry::kernel_mode_ring3_accessible_interrupt(
        generate_exception_handler_stub_addr!(page_fault_handler),
    );
    // Reserved
    idt.x87_floating_point = IdtEntry::kernel_mode_ring3_accessible_interrupt(
        generate_exception_handler_stub_addr!(x87_floating_point_exception_handler),
    );
    idt.alignment_check = IdtEntry::kernel_mode_ring3_accessible_interrupt(
        generate_exception_handler_stub_addr!(alignment_check_handler),
    );
    idt.machine_check = IdtEntry::kernel_mode_ring3_accessible_interrupt(
        generate_exception_handler_stub_addr!(machine_check_handler),
    );
    idt.simd_floating_point = IdtEntry::kernel_mode_ring3_accessible_interrupt(
        generate_exception_handler_stub_addr!(simd_floating_point_exception_handler),
    );
    idt.virtualization = IdtEntry::kernel_mode_ring3_accessible_interrupt(
        generate_exception_handler_stub_addr!(virtualization_exception_handler),
    );
    idt.cp_protection_exception = IdtEntry::kernel_mode_ring3_accessible_interrupt(
        generate_exception_handler_stub_addr!(control_protection_exception_handler),
    );
    // Reserved
    // Hypervisor injection exception
    idt.vmm_communication_exception = IdtEntry::kernel_mode_ring3_accessible_interrupt(
        generate_exception_handler_stub_addr!(vmm_communication_exception_handler),
    );
    idt.security_exception = IdtEntry::kernel_mode_ring3_accessible_interrupt(
        generate_exception_handler_stub_addr!(security_exception_handler),
    );
    // Reserved
    // FPU error interrupt

    register_indexed_interrupt_handlers!(
        idt, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
        24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46,
        47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69,
        70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92,
        93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111,
        112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 129, 130,
        131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148,
        149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166,
        167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180, 181, 182, 183, 184,
        185, 186, 187, 188, 189, 190, 191, 192, 193, 194, 195, 196, 197, 198, 199, 200, 201, 202,
        203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220,
        221, 222, 223
    );

    idt.interrupts[SYSCALL_IRQ as usize - 32] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
        generate_exception_handler_stub_addr!(syscall_handler),
    );

    unsafe {
        idt.load();
    }
}

pub fn register_interrupt_handler_function(n: u8, handler: ExceptionHandlerFn) {
    assert!(n != SYSCALL_IRQ);

    unsafe {
        REGISTERED_INTERRUPT_HANDLERS[n as usize - 32].push(ExceptionHandler::Function(handler));
    }
}

pub fn register_interrupt_handler_closure(n: u8, handler: Box<ExceptionHandlerClosure>) {
    assert!(n != SYSCALL_IRQ);

    unsafe {
        REGISTERED_INTERRUPT_HANDLERS[n as usize - 32].push(ExceptionHandler::Closure(handler));
    }
}

#[repr(C, packed)]
pub struct Idtr {
    limit: u16,
    base: u64,
}

impl Idtr {
    pub const fn new(base: u64) -> Self {
        Self {
            base,
            limit: (core::mem::size_of::<Idt>() - 1) as u16,
        }
    }
}

#[repr(C, align(16))]
pub struct Idt {
    divide_error: IdtEntry,
    debug: IdtEntry,
    non_maskable_interrupt: IdtEntry,
    breakpoint: IdtEntry,
    overflow: IdtEntry,
    bound_range_exceeded: IdtEntry,
    invalid_opcode: IdtEntry,
    device_not_available: IdtEntry,
    double_fault: IdtEntry,
    coprocessor_segment_overrun: IdtEntry,
    invalid_tss: IdtEntry,
    segment_not_present: IdtEntry,
    stack_segment_fault: IdtEntry,
    general_protection_fault: IdtEntry,
    page_fault: IdtEntry,
    reserved_1: IdtEntry,
    x87_floating_point: IdtEntry,
    alignment_check: IdtEntry,
    machine_check: IdtEntry,
    simd_floating_point: IdtEntry,
    virtualization: IdtEntry,
    cp_protection_exception: IdtEntry,
    reserved_2: [IdtEntry; 6],
    hv_injection_exception: IdtEntry,
    vmm_communication_exception: IdtEntry,
    security_exception: IdtEntry,
    reserved_3: IdtEntry,
    interrupts: [IdtEntry; 224],
}

impl Idt {
    pub const fn new() -> Self {
        Self {
            divide_error: IdtEntry::default(),
            debug: IdtEntry::default(),
            non_maskable_interrupt: IdtEntry::default(),
            breakpoint: IdtEntry::default(),
            overflow: IdtEntry::default(),
            bound_range_exceeded: IdtEntry::default(),
            invalid_opcode: IdtEntry::default(),
            device_not_available: IdtEntry::default(),
            double_fault: IdtEntry::default(),
            coprocessor_segment_overrun: IdtEntry::default(),
            invalid_tss: IdtEntry::default(),
            segment_not_present: IdtEntry::default(),
            stack_segment_fault: IdtEntry::default(),
            general_protection_fault: IdtEntry::default(),
            page_fault: IdtEntry::default(),
            reserved_1: IdtEntry::default(),
            x87_floating_point: IdtEntry::default(),
            alignment_check: IdtEntry::default(),
            machine_check: IdtEntry::default(),
            simd_floating_point: IdtEntry::default(),
            virtualization: IdtEntry::default(),
            cp_protection_exception: IdtEntry::default(),
            reserved_2: [IdtEntry::default(); 6],
            hv_injection_exception: IdtEntry::default(),
            vmm_communication_exception: IdtEntry::default(),
            security_exception: IdtEntry::default(),
            reserved_3: IdtEntry::default(),
            interrupts: [IdtEntry::default(); 224],
        }
    }

    pub unsafe fn set_interrupt_entry(&mut self, idx: usize, entry: IdtEntry) {
        self.interrupts[idx] = entry;
    }

    pub unsafe fn load(&mut self) {
        unsafe {
            asm!(
                "lidt [{}]",
                in(reg) &Idtr {
                    limit: (core::mem::size_of::<Idt>() - 1) as u16,
                    base: self as *const _ as u64,
                } as *const Idtr,
                options(nostack, preserves_flags)
            )
        };
    }
}

#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct IdtEntry {
    offset_low: u16,
    selector: u16,
    interrupt_stack_table_offset: InterruptStackTableOffset,
    attributes: u8,
    offset_middle: u16,
    offset_high: u32,
    reserved: u32,
}

impl IdtEntry {
    pub const fn new(offset: u64, selector: u16, attributes: IdtAttributes) -> Self {
        Self {
            offset_low: (offset & 0xFFFF) as u16,
            selector,
            interrupt_stack_table_offset: InterruptStackTableOffset::new(0),
            attributes: attributes.into_bits(),
            offset_middle: ((offset >> 16) & 0xFFFF) as u16,
            offset_high: (offset >> 32) as u32,
            reserved: 0,
        }
    }

    pub const fn kernel_mode_ring3_accessible_interrupt(offset: u64) -> Self {
        Self::new(
            offset,
            (KERNEL_MODE_CODE_SEGMENT_INDEX as u16) << 3,
            IdtAttributes::new()
                .with_kind(GateKind::Interrupt)
                .with_privilege_level(PrivilegeLevel::Ring3)
                .with_present(true),
        )
    }
}

impl const Default for IdtEntry {
    fn default() -> Self {
        Self::new(
            0,
            0,
            IdtAttributes::new()
                .with_present(false)
                .with_privilege_level(PrivilegeLevel::Ring3)
                .with_kind(GateKind::Interrupt),
        )
    }
}

#[bitfield(u8)]
pub struct IdtAttributes {
    #[bits(4, default = GateKind::Interrupt)]
    kind: GateKind,
    #[bits(1)]
    __: u8,
    #[bits(2)]
    privilege_level: PrivilegeLevel,
    present: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum GateKind {
    Interrupt = 0xE,
    Trap = 0xF,
}

impl GateKind {
    pub const fn into_bits(self) -> u8 {
        match self {
            GateKind::Interrupt => 0xE,
            GateKind::Trap => 0xF,
        }
    }

    const fn from_bits(bits: u8) -> Self {
        match bits {
            0xE => GateKind::Interrupt,
            0xF => GateKind::Trap,
            _ => unreachable!(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PrivilegeLevel {
    Ring0,
    Ring1,
    Ring2,
    Ring3,
}

impl PrivilegeLevel {
    pub const fn into_bits(self) -> u8 {
        match self {
            PrivilegeLevel::Ring0 => 0,
            PrivilegeLevel::Ring1 => 1,
            PrivilegeLevel::Ring2 => 2,
            PrivilegeLevel::Ring3 => 3,
        }
    }

    const fn from_bits(bits: u8) -> Self {
        match bits {
            0 => PrivilegeLevel::Ring0,
            1 => PrivilegeLevel::Ring1,
            2 => PrivilegeLevel::Ring2,
            3 => PrivilegeLevel::Ring3,
            _ => unreachable!(),
        }
    }
}

#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct InterruptStackTableOffset(u8);

impl InterruptStackTableOffset {
    pub const fn new(value: u8) -> Self {
        assert!(
            value < 8,
            "Interrupt stack table offset must be less than 8"
        );

        Self(value)
    }

    pub const fn value(self) -> u8 {
        self.0
    }
}

#[derive(Debug)]
#[repr(C)]
pub struct ExceptionFrame {
    rip: usize,
    cs: usize,
    rflags: usize,
    rsp: usize,
    ss: usize,
}

#[derive(Debug)]
#[repr(C)]
pub struct ErrorCodeExceptionFrame {
    error_code: usize,
    rip: usize,
    cs: usize,
    rflags: usize,
    rsp: usize,
    ss: usize,
}

/// Volatile (caller-saved) registers in the 64-bit SysV calling convention.
///
/// Used in interrupt handlers to access saved register values.
///
/// Layout and field order must not be changed.
#[repr(C, packed)]
pub struct VolatileRegisters {
    r11: usize,
    r10: usize,
    r9: usize,
    r8: usize,
    rdi: usize,
    rsi: usize,
    rdx: usize,
    rcx: usize,
    rax: usize,
}

type ExceptionHandlerFn = fn(&ExceptionFrame, &VolatileRegisters);
type ExceptionHandlerClosure = dyn Fn(&ExceptionFrame, &VolatileRegisters);

enum ExceptionHandler {
    Function(ExceptionHandlerFn),
    Closure(Box<ExceptionHandlerClosure>),
}

impl ExceptionHandler {
    #[inline]
    fn call(&self, frame: &ExceptionFrame, registers: &VolatileRegisters) {
        match self {
            ExceptionHandler::Function(func) => func(frame, registers),
            ExceptionHandler::Closure(func) => func(frame, registers),
        }
    }
}

extern "C" fn interrupt_handler<const N: usize>(
    frame: &ExceptionFrame,
    registers: &VolatileRegisters,
) {
    use_kernel_page_table(|| {
        let interrupt_handlers = unsafe { &REGISTERED_INTERRUPT_HANDLERS[N] };

        for interrupt_handler in interrupt_handlers {
            interrupt_handler.call(frame, registers);
        }
    });
}

extern "C" fn division_error_handler(frame: &ExceptionFrame, _registers: &VolatileRegisters) {
    use_kernel_page_table(|| {
        warn!("Division error");

        info!("Stack frame: {frame:?}");
    });

    loop {
        x86_64::instructions::hlt();
    }
}

extern "C" fn debug_handler(frame: &ExceptionFrame, _registers: &VolatileRegisters) {
    use_kernel_page_table(|| {
        info!("Debug");

        info!("Stack frame: {frame:?}");
    });
}

extern "C" fn non_maskable_interrupt_handler(
    frame: &ExceptionFrame,
    _registers: &VolatileRegisters,
) {
    use_kernel_page_table(|| {
        info!("Non-maskable interrupt");

        info!("Stack frame: {frame:?}");
    });
}

extern "C" fn breakpoint_handler(frame: &ExceptionFrame, _registers: &VolatileRegisters) {
    use_kernel_page_table(|| {
        info!("Breakpoint");

        info!("Stack frame: {frame:?}");
    });
}

extern "C" fn overflow_handler(frame: &ExceptionFrame, _registers: &VolatileRegisters) {
    use_kernel_page_table(|| {
        warn!("Overflow");

        info!("Stack frame: {frame:?}");
    });

    loop {
        x86_64::instructions::hlt();
    }
}

extern "C" fn bound_range_exceeded_handler(frame: &ExceptionFrame, _registers: &VolatileRegisters) {
    use_kernel_page_table(|| {
        warn!("Bound range exceeded");

        info!("Stack frame: {frame:?}");
    });

    loop {
        x86_64::instructions::hlt();
    }
}

extern "C" fn invalid_opcode_handler(frame: &ExceptionFrame, _registers: &VolatileRegisters) {
    use_kernel_page_table(|| {
        warn!("Invalid opcode");

        info!("Stack frame: {frame:?}");
    });

    loop {
        x86_64::instructions::hlt();
    }
}

extern "C" fn device_not_available_handler(frame: &ExceptionFrame, _registers: &VolatileRegisters) {
    use_kernel_page_table(|| {
        warn!("Device not available");

        info!("Stack frame: {frame:?}");
    });

    loop {
        x86_64::instructions::hlt();
    }
}

extern "C" fn double_fault_handler(
    frame: &ErrorCodeExceptionFrame,
    _registers: &VolatileRegisters,
) -> ! {
    use_kernel_page_table(|| {
        error!("Double fault");

        info!("Stack frame: {frame:?}");
    });

    loop {
        x86_64::instructions::hlt();
    }
}

extern "C" fn invalid_tss_handler(frame: &ErrorCodeExceptionFrame, _registers: &VolatileRegisters) {
    use_kernel_page_table(|| {
        warn!("Invalid TSS");

        info!("Stack frame: {frame:?}");
    });

    loop {
        x86_64::instructions::hlt();
    }
}

extern "C" fn segment_not_present_handler(
    frame: &ErrorCodeExceptionFrame,
    _registers: &VolatileRegisters,
) {
    use_kernel_page_table(|| {
        warn!("Segment not present");

        info!("Stack frame: {frame:?}");
    });

    loop {
        x86_64::instructions::hlt();
    }
}

extern "C" fn stack_segment_fault_handler(
    frame: &ErrorCodeExceptionFrame,
    _registers: &VolatileRegisters,
) {
    use_kernel_page_table(|| {
        warn!("Stack segment fault");

        info!("Stack frame: {frame:?}");
    });

    loop {
        x86_64::instructions::hlt();
    }
}

extern "C" fn general_protection_fault_handler(
    frame: &ErrorCodeExceptionFrame,
    _registers: &VolatileRegisters,
) {
    use_kernel_page_table(|| {
        warn!("General protection fault");

        info!("Stack frame: {frame:#?}");

        if frame.error_code != 0 {
            info!("Is external: {}", frame.error_code & 1 == 1);
            info!("GDT/IDT/LDT/IDT: {}", (frame.error_code >> 1) & 0b11);
            info!("Segment selector index: {}", frame.error_code >> 3);
        }
    });

    loop {
        x86_64::instructions::hlt();
    }
}

extern "C" fn page_fault_handler(frame: &ErrorCodeExceptionFrame, _registers: &VolatileRegisters) {
    use_kernel_page_table(|| {
        error!("Page fault");

        if let Ok(address) = Cr2::read() {
            error!("Accessed virtual address: {:#0x}", address.as_u64());
        } else {
            error!("Accessed unknown virtual address");
        }

        info!("Stack frame: {frame:?}");
    });

    loop {
        unsafe {
            asm!("hlt", options(nomem, nostack, preserves_flags));
        }
    }
}

extern "C" fn x87_floating_point_exception_handler(
    frame: &ExceptionFrame,
    _registers: &VolatileRegisters,
) {
    use_kernel_page_table(|| {
        warn!("x87 floating point exception");

        info!("Stack frame: {frame:?}");
    });

    loop {
        x86_64::instructions::hlt();
    }
}

extern "C" fn alignment_check_handler(
    frame: &ErrorCodeExceptionFrame,
    _registers: &VolatileRegisters,
) {
    use_kernel_page_table(|| {
        warn!("Alignment check");

        info!("Stack frame: {frame:?}");
    });

    loop {
        x86_64::instructions::hlt();
    }
}

extern "C" fn machine_check_handler(frame: &ExceptionFrame, _registers: &VolatileRegisters) -> ! {
    use_kernel_page_table(|| {
        warn!("Machine check");

        info!("Stack frame: {frame:?}");
    });

    loop {
        x86_64::instructions::hlt();
    }
}

extern "C" fn simd_floating_point_exception_handler(
    frame: &ExceptionFrame,
    _registers: &VolatileRegisters,
) {
    use_kernel_page_table(|| {
        warn!("SIMD floating point exception");

        info!("Stack frame: {frame:?}");
    });

    loop {
        x86_64::instructions::hlt();
    }
}

extern "C" fn virtualization_exception_handler(
    frame: &ExceptionFrame,
    _registers: &VolatileRegisters,
) {
    use_kernel_page_table(|| {
        warn!("Virtualization exception");

        info!("Stack frame: {frame:?}");
    });

    loop {
        x86_64::instructions::hlt();
    }
}

extern "C" fn control_protection_exception_handler(
    frame: &ErrorCodeExceptionFrame,
    _registers: &VolatileRegisters,
) {
    use_kernel_page_table(|| {
        warn!("Control protection exception");

        info!("Stack frame: {frame:?}");
    });

    loop {
        x86_64::instructions::hlt();
    }
}

extern "C" fn vmm_communication_exception_handler(
    frame: &ErrorCodeExceptionFrame,
    _registers: &VolatileRegisters,
) {
    use_kernel_page_table(|| {
        warn!("VMM communication exception");

        info!("Stack frame: {frame:?}");
    });

    loop {
        x86_64::instructions::hlt();
    }
}

extern "C" fn security_exception_handler(
    frame: &ErrorCodeExceptionFrame,
    _registers: &VolatileRegisters,
) {
    use_kernel_page_table(|| {
        warn!("Security exception");

        info!("Stack frame: {frame:?}");
    });

    loop {
        x86_64::instructions::hlt();
    }
}

extern "C" fn syscall_handler(_frame: &ExceptionFrame, registers: &VolatileRegisters) {
    let rax = registers.rax as u64;
    let rdi = registers.rdi as u64;
    let rsi = registers.rsi as u64;
    let rdx = registers.rdx as u64;
    let _r10 = registers.r10 as u64;
    let _r8 = registers.r8 as u64;
    let _r9 = registers.r9 as u64;

    let id = rax;

    match id {
        1 => {
            write_syscall(rdi, rsi as *const u8, rdx);
        }
        _ => unimplemented!(),
    }
}

extern "C" fn unknown_interrupt_handler(frame: &ExceptionFrame, _registers: &VolatileRegisters) {
    use_kernel_page_table(|| {
        info!("Unknown interrupt");

        info!("Stack frame: {frame:?}");
    });

    loop {
        x86_64::instructions::hlt();
    }
}
