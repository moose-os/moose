use alloc::{boxed::Box, vec::Vec};
use bitfield_struct::bitfield;
use core::{
    arch::{asm, naked_asm},
    ffi::CStr,
};
use log::{error, info, warn};
use x86_64::registers::control::Cr2;

use super::{gdt::KERNEL_MODE_CODE_SEGMENT_INDEX, use_kernel_page_table};

pub static mut IDT: Idt = Idt::new();

type ExceptionHandler = dyn Fn(&ExceptionFrame, &VolatileRegisters);

static mut REGISTERED_INTERRUPT_HANDLERS: [Vec<Box<ExceptionHandler>>; 224] = {
    const DEFAULT: Vec<Box<ExceptionHandler>> = Vec::new();

    [DEFAULT; 224]
};

const SYSCALL_IRQ: u8 = 0x80;

macro_rules! exception_handler {
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

            raw_handler
        }
    };
}

pub fn init_idt() {
    unsafe {
        IDT.divide_error = IdtEntry::kernel_mode_ring3_accessible_interrupt(exception_handler!(
            division_error_handler
        ) as usize
            as u64);
        IDT.breakpoint = IdtEntry::kernel_mode_ring3_accessible_interrupt(exception_handler!(
            breakpoint_handler
        ) as usize
            as u64);
        IDT.page_fault = IdtEntry::kernel_mode_ring3_accessible_interrupt(exception_handler!(
            page_fault_handler
        ) as usize
            as u64);
        IDT.non_maskable_interrupt = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            exception_handler!(non_maskable_interrupt_handler) as usize as u64,
        );
        IDT.breakpoint = IdtEntry::kernel_mode_ring3_accessible_interrupt(exception_handler!(
            breakpoint_handler
        ) as usize
            as u64);
        IDT.overflow = IdtEntry::kernel_mode_ring3_accessible_interrupt(exception_handler!(
            overflow_handler
        ) as usize as u64);
        IDT.bound_range_exceeded = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            exception_handler!(bound_range_exceeded_handler) as usize as u64,
        );
        IDT.invalid_opcode = IdtEntry::kernel_mode_ring3_accessible_interrupt(exception_handler!(
            invalid_opcode_handler
        ) as usize
            as u64);
        IDT.device_not_available = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            exception_handler!(device_not_available_handler) as usize as u64,
        );
        IDT.double_fault = IdtEntry::kernel_mode_ring3_accessible_interrupt(exception_handler!(
            double_fault_handler
        ) as usize
            as u64);
        // Coprocessor segment overrun
        IDT.invalid_tss = IdtEntry::kernel_mode_ring3_accessible_interrupt(exception_handler!(
            invalid_tss_handler
        ) as usize
            as u64);
        IDT.segment_not_present = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            exception_handler!(segment_not_present_handler) as usize as u64,
        );
        IDT.stack_segment_fault = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            exception_handler!(stack_segment_fault_handler) as usize as u64,
        );
        IDT.general_protection_fault = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            exception_handler!(general_protection_fault_handler) as usize as u64,
        );
        IDT.page_fault = IdtEntry::kernel_mode_ring3_accessible_interrupt(exception_handler!(
            page_fault_handler
        ) as usize
            as u64);
        // Reserved
        IDT.x87_floating_point = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            exception_handler!(x87_floating_point_exception_handler) as usize as u64,
        );
        IDT.alignment_check = IdtEntry::kernel_mode_ring3_accessible_interrupt(exception_handler!(
            alignment_check_handler
        ) as usize
            as u64);
        IDT.machine_check = IdtEntry::kernel_mode_ring3_accessible_interrupt(exception_handler!(
            machine_check_handler
        ) as usize
            as u64);
        IDT.simd_floating_point = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            exception_handler!(simd_floating_point_exception_handler) as usize as u64,
        );
        IDT.virtualization = IdtEntry::kernel_mode_ring3_accessible_interrupt(exception_handler!(
            virtualization_exception_handler
        ) as usize
            as u64);
        IDT.cp_protection_exception = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            exception_handler!(control_protection_exception_handler) as usize as u64,
        );
        // Reserved
        // Hypervisor injection exception
        IDT.vmm_communication_exception = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            exception_handler!(vmm_communication_exception_handler) as usize as u64,
        );
        IDT.security_exception = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            exception_handler!(security_exception_handler) as usize as u64,
        );
        // Reserved
        // FPU error interrupt

        IDT.interrupts[0] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<0>) as usize) as u64,
        );
        IDT.interrupts[1] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<1>) as usize) as u64,
        );
        IDT.interrupts[2] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<2>) as usize) as u64,
        );
        IDT.interrupts[3] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<3>) as usize) as u64,
        );
        IDT.interrupts[4] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<4>) as usize) as u64,
        );
        IDT.interrupts[5] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<5>) as usize) as u64,
        );
        IDT.interrupts[6] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<6>) as usize) as u64,
        );
        IDT.interrupts[7] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<7>) as usize) as u64,
        );
        IDT.interrupts[8] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<8>) as usize) as u64,
        );
        IDT.interrupts[9] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<9>) as usize) as u64,
        );
        IDT.interrupts[10] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<10>) as usize) as u64,
        );
        IDT.interrupts[11] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<11>) as usize) as u64,
        );
        IDT.interrupts[12] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<12>) as usize) as u64,
        );
        IDT.interrupts[13] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<13>) as usize) as u64,
        );
        IDT.interrupts[14] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<14>) as usize) as u64,
        );
        IDT.interrupts[15] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<15>) as usize) as u64,
        );
        IDT.interrupts[16] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<16>) as usize) as u64,
        );
        IDT.interrupts[17] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<17>) as usize) as u64,
        );
        IDT.interrupts[18] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<18>) as usize) as u64,
        );
        IDT.interrupts[19] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<19>) as usize) as u64,
        );
        IDT.interrupts[20] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<20>) as usize) as u64,
        );
        IDT.interrupts[21] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<21>) as usize) as u64,
        );
        IDT.interrupts[22] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<22>) as usize) as u64,
        );
        IDT.interrupts[23] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<23>) as usize) as u64,
        );
        IDT.interrupts[24] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<24>) as usize) as u64,
        );
        IDT.interrupts[25] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<25>) as usize) as u64,
        );
        IDT.interrupts[26] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<26>) as usize) as u64,
        );
        IDT.interrupts[27] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<27>) as usize) as u64,
        );
        IDT.interrupts[28] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<28>) as usize) as u64,
        );
        IDT.interrupts[29] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<29>) as usize) as u64,
        );
        IDT.interrupts[30] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<30>) as usize) as u64,
        );
        IDT.interrupts[31] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<31>) as usize) as u64,
        );
        IDT.interrupts[32] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<32>) as usize) as u64,
        );
        IDT.interrupts[33] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<33>) as usize) as u64,
        );
        IDT.interrupts[34] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<34>) as usize) as u64,
        );
        IDT.interrupts[35] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<35>) as usize) as u64,
        );
        IDT.interrupts[36] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<36>) as usize) as u64,
        );
        IDT.interrupts[37] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<37>) as usize) as u64,
        );
        IDT.interrupts[38] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<38>) as usize) as u64,
        );
        IDT.interrupts[39] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<39>) as usize) as u64,
        );
        IDT.interrupts[40] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<40>) as usize) as u64,
        );
        IDT.interrupts[41] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<41>) as usize) as u64,
        );
        IDT.interrupts[42] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<42>) as usize) as u64,
        );
        IDT.interrupts[43] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<43>) as usize) as u64,
        );
        IDT.interrupts[44] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<44>) as usize) as u64,
        );
        IDT.interrupts[45] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<45>) as usize) as u64,
        );
        IDT.interrupts[46] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<46>) as usize) as u64,
        );
        IDT.interrupts[47] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<47>) as usize) as u64,
        );
        IDT.interrupts[48] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<48>) as usize) as u64,
        );
        IDT.interrupts[49] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<49>) as usize) as u64,
        );
        IDT.interrupts[50] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<50>) as usize) as u64,
        );
        IDT.interrupts[51] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<51>) as usize) as u64,
        );
        IDT.interrupts[52] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<52>) as usize) as u64,
        );
        IDT.interrupts[53] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<53>) as usize) as u64,
        );
        IDT.interrupts[54] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<54>) as usize) as u64,
        );
        IDT.interrupts[55] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<55>) as usize) as u64,
        );
        IDT.interrupts[56] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<56>) as usize) as u64,
        );
        IDT.interrupts[57] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<57>) as usize) as u64,
        );
        IDT.interrupts[58] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<58>) as usize) as u64,
        );
        IDT.interrupts[59] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<59>) as usize) as u64,
        );
        IDT.interrupts[60] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<60>) as usize) as u64,
        );
        IDT.interrupts[61] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<61>) as usize) as u64,
        );
        IDT.interrupts[62] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<62>) as usize) as u64,
        );
        IDT.interrupts[63] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<63>) as usize) as u64,
        );
        IDT.interrupts[64] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<64>) as usize) as u64,
        );
        IDT.interrupts[65] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<65>) as usize) as u64,
        );
        IDT.interrupts[66] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<66>) as usize) as u64,
        );
        IDT.interrupts[67] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<67>) as usize) as u64,
        );
        IDT.interrupts[68] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<68>) as usize) as u64,
        );
        IDT.interrupts[69] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<69>) as usize) as u64,
        );
        IDT.interrupts[70] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<70>) as usize) as u64,
        );
        IDT.interrupts[71] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<71>) as usize) as u64,
        );
        IDT.interrupts[72] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<72>) as usize) as u64,
        );
        IDT.interrupts[73] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<73>) as usize) as u64,
        );
        IDT.interrupts[74] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<74>) as usize) as u64,
        );
        IDT.interrupts[75] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<75>) as usize) as u64,
        );
        IDT.interrupts[76] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<76>) as usize) as u64,
        );
        IDT.interrupts[77] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<77>) as usize) as u64,
        );
        IDT.interrupts[78] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<78>) as usize) as u64,
        );
        IDT.interrupts[79] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<79>) as usize) as u64,
        );
        IDT.interrupts[80] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<80>) as usize) as u64,
        );
        IDT.interrupts[81] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<81>) as usize) as u64,
        );
        IDT.interrupts[82] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<82>) as usize) as u64,
        );
        IDT.interrupts[83] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<83>) as usize) as u64,
        );
        IDT.interrupts[84] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<84>) as usize) as u64,
        );
        IDT.interrupts[85] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<85>) as usize) as u64,
        );
        IDT.interrupts[86] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<86>) as usize) as u64,
        );
        IDT.interrupts[87] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<87>) as usize) as u64,
        );
        IDT.interrupts[88] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<88>) as usize) as u64,
        );
        IDT.interrupts[89] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<89>) as usize) as u64,
        );
        IDT.interrupts[90] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<90>) as usize) as u64,
        );
        IDT.interrupts[91] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<91>) as usize) as u64,
        );
        IDT.interrupts[92] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<92>) as usize) as u64,
        );
        IDT.interrupts[93] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<93>) as usize) as u64,
        );
        IDT.interrupts[94] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<94>) as usize) as u64,
        );
        IDT.interrupts[95] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<95>) as usize) as u64,
        );
        IDT.interrupts[96] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<96>) as usize) as u64,
        );
        IDT.interrupts[97] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<97>) as usize) as u64,
        );
        IDT.interrupts[98] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<98>) as usize) as u64,
        );
        IDT.interrupts[99] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<99>) as usize) as u64,
        );
        IDT.interrupts[100] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<100>) as usize) as u64,
        );
        IDT.interrupts[101] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<101>) as usize) as u64,
        );
        IDT.interrupts[102] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<102>) as usize) as u64,
        );
        IDT.interrupts[103] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<103>) as usize) as u64,
        );
        IDT.interrupts[104] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<104>) as usize) as u64,
        );
        IDT.interrupts[105] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<105>) as usize) as u64,
        );
        IDT.interrupts[106] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<106>) as usize) as u64,
        );
        IDT.interrupts[107] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<107>) as usize) as u64,
        );
        IDT.interrupts[108] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<108>) as usize) as u64,
        );
        IDT.interrupts[109] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<109>) as usize) as u64,
        );
        IDT.interrupts[110] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<110>) as usize) as u64,
        );
        IDT.interrupts[111] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<111>) as usize) as u64,
        );
        IDT.interrupts[112] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<112>) as usize) as u64,
        );
        IDT.interrupts[113] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<113>) as usize) as u64,
        );
        IDT.interrupts[114] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<114>) as usize) as u64,
        );
        IDT.interrupts[115] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<115>) as usize) as u64,
        );
        IDT.interrupts[116] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<116>) as usize) as u64,
        );
        IDT.interrupts[117] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<117>) as usize) as u64,
        );
        IDT.interrupts[118] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<118>) as usize) as u64,
        );
        IDT.interrupts[119] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<119>) as usize) as u64,
        );
        IDT.interrupts[120] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<120>) as usize) as u64,
        );
        IDT.interrupts[121] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<121>) as usize) as u64,
        );
        IDT.interrupts[122] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<122>) as usize) as u64,
        );
        IDT.interrupts[123] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<123>) as usize) as u64,
        );
        IDT.interrupts[124] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<124>) as usize) as u64,
        );
        IDT.interrupts[125] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<125>) as usize) as u64,
        );
        IDT.interrupts[126] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<126>) as usize) as u64,
        );
        IDT.interrupts[127] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<127>) as usize) as u64,
        );
        IDT.interrupts[128] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<128>) as usize) as u64,
        );
        IDT.interrupts[129] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<129>) as usize) as u64,
        );
        IDT.interrupts[130] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<130>) as usize) as u64,
        );
        IDT.interrupts[131] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<131>) as usize) as u64,
        );
        IDT.interrupts[132] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<132>) as usize) as u64,
        );
        IDT.interrupts[133] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<133>) as usize) as u64,
        );
        IDT.interrupts[134] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<134>) as usize) as u64,
        );
        IDT.interrupts[135] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<135>) as usize) as u64,
        );
        IDT.interrupts[136] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<136>) as usize) as u64,
        );
        IDT.interrupts[137] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<137>) as usize) as u64,
        );
        IDT.interrupts[138] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<138>) as usize) as u64,
        );
        IDT.interrupts[139] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<139>) as usize) as u64,
        );
        IDT.interrupts[140] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<140>) as usize) as u64,
        );
        IDT.interrupts[141] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<141>) as usize) as u64,
        );
        IDT.interrupts[142] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<142>) as usize) as u64,
        );
        IDT.interrupts[143] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<143>) as usize) as u64,
        );
        IDT.interrupts[144] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<144>) as usize) as u64,
        );
        IDT.interrupts[145] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<145>) as usize) as u64,
        );
        IDT.interrupts[146] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<146>) as usize) as u64,
        );
        IDT.interrupts[147] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<147>) as usize) as u64,
        );
        IDT.interrupts[148] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<148>) as usize) as u64,
        );
        IDT.interrupts[149] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<149>) as usize) as u64,
        );
        IDT.interrupts[150] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<150>) as usize) as u64,
        );
        IDT.interrupts[151] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<151>) as usize) as u64,
        );
        IDT.interrupts[152] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<152>) as usize) as u64,
        );
        IDT.interrupts[153] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<153>) as usize) as u64,
        );
        IDT.interrupts[154] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<154>) as usize) as u64,
        );
        IDT.interrupts[155] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<155>) as usize) as u64,
        );
        IDT.interrupts[156] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<156>) as usize) as u64,
        );
        IDT.interrupts[157] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<157>) as usize) as u64,
        );
        IDT.interrupts[158] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<158>) as usize) as u64,
        );
        IDT.interrupts[159] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<159>) as usize) as u64,
        );
        IDT.interrupts[160] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<160>) as usize) as u64,
        );
        IDT.interrupts[161] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<161>) as usize) as u64,
        );
        IDT.interrupts[162] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<162>) as usize) as u64,
        );
        IDT.interrupts[163] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<163>) as usize) as u64,
        );
        IDT.interrupts[164] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<164>) as usize) as u64,
        );
        IDT.interrupts[165] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<165>) as usize) as u64,
        );
        IDT.interrupts[166] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<166>) as usize) as u64,
        );
        IDT.interrupts[167] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<167>) as usize) as u64,
        );
        IDT.interrupts[168] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<168>) as usize) as u64,
        );
        IDT.interrupts[169] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<169>) as usize) as u64,
        );
        IDT.interrupts[170] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<170>) as usize) as u64,
        );
        IDT.interrupts[171] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<171>) as usize) as u64,
        );
        IDT.interrupts[172] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<172>) as usize) as u64,
        );
        IDT.interrupts[173] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<173>) as usize) as u64,
        );
        IDT.interrupts[174] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<174>) as usize) as u64,
        );
        IDT.interrupts[175] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<175>) as usize) as u64,
        );
        IDT.interrupts[176] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<176>) as usize) as u64,
        );
        IDT.interrupts[177] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<177>) as usize) as u64,
        );
        IDT.interrupts[178] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<178>) as usize) as u64,
        );
        IDT.interrupts[179] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<179>) as usize) as u64,
        );
        IDT.interrupts[180] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<180>) as usize) as u64,
        );
        IDT.interrupts[181] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<181>) as usize) as u64,
        );
        IDT.interrupts[182] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<182>) as usize) as u64,
        );
        IDT.interrupts[183] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<183>) as usize) as u64,
        );
        IDT.interrupts[184] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<184>) as usize) as u64,
        );
        IDT.interrupts[185] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<185>) as usize) as u64,
        );
        IDT.interrupts[186] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<186>) as usize) as u64,
        );
        IDT.interrupts[187] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<187>) as usize) as u64,
        );
        IDT.interrupts[188] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<188>) as usize) as u64,
        );
        IDT.interrupts[189] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<189>) as usize) as u64,
        );
        IDT.interrupts[190] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<190>) as usize) as u64,
        );
        IDT.interrupts[191] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<191>) as usize) as u64,
        );
        IDT.interrupts[192] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<192>) as usize) as u64,
        );
        IDT.interrupts[193] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<193>) as usize) as u64,
        );
        IDT.interrupts[194] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<194>) as usize) as u64,
        );
        IDT.interrupts[195] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<195>) as usize) as u64,
        );
        IDT.interrupts[196] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<196>) as usize) as u64,
        );
        IDT.interrupts[197] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<197>) as usize) as u64,
        );
        IDT.interrupts[198] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<198>) as usize) as u64,
        );
        IDT.interrupts[199] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<199>) as usize) as u64,
        );
        IDT.interrupts[200] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<200>) as usize) as u64,
        );
        IDT.interrupts[201] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<201>) as usize) as u64,
        );
        IDT.interrupts[202] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<202>) as usize) as u64,
        );
        IDT.interrupts[203] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<203>) as usize) as u64,
        );
        IDT.interrupts[204] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<204>) as usize) as u64,
        );
        IDT.interrupts[205] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<205>) as usize) as u64,
        );
        IDT.interrupts[206] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<206>) as usize) as u64,
        );
        IDT.interrupts[207] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<207>) as usize) as u64,
        );
        IDT.interrupts[208] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<208>) as usize) as u64,
        );
        IDT.interrupts[209] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<209>) as usize) as u64,
        );
        IDT.interrupts[210] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<210>) as usize) as u64,
        );
        IDT.interrupts[211] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<211>) as usize) as u64,
        );
        IDT.interrupts[212] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<212>) as usize) as u64,
        );
        IDT.interrupts[213] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<213>) as usize) as u64,
        );
        IDT.interrupts[214] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<214>) as usize) as u64,
        );
        IDT.interrupts[215] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<215>) as usize) as u64,
        );
        IDT.interrupts[216] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<216>) as usize) as u64,
        );
        IDT.interrupts[217] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<217>) as usize) as u64,
        );
        IDT.interrupts[218] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<218>) as usize) as u64,
        );
        IDT.interrupts[219] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<219>) as usize) as u64,
        );
        IDT.interrupts[220] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<220>) as usize) as u64,
        );
        IDT.interrupts[221] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<221>) as usize) as u64,
        );
        IDT.interrupts[222] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<222>) as usize) as u64,
        );
        IDT.interrupts[223] = IdtEntry::kernel_mode_ring3_accessible_interrupt(
            (exception_handler!(interrupt_handler::<223>) as usize) as u64,
        );

        IDT.interrupts[SYSCALL_IRQ as usize - 32] =
            IdtEntry::kernel_mode_ring3_accessible_interrupt(
                exception_handler!(syscall_handler) as usize as u64
            );

        IDT.load();
    }

    /*unsafe {
        IDT.divide_error.set_handler_fn(division_error_handler);
        IDT.debug.set_handler_fn(debug_handler);
        IDT.non_maskable_interrupt
            .set_handler_fn(non_maskable_interrupt_handler);
        IDT.breakpoint.set_handler_fn(breakpoint_handler);
        IDT.overflow.set_handler_fn(overflow_handler);
        IDT.bound_range_exceeded
            .set_handler_fn(bound_range_exceeded_handler);
        IDT.invalid_opcode.set_handler_fn(invalid_opcode_handler);
        IDT.device_not_available
            .set_handler_fn(device_not_available_handler);
        IDT.double_fault.set_handler_fn(double_fault_handler);
        // Coprocessor segment overrun
        IDT.invalid_tss.set_handler_fn(invalid_tss_handler);
        IDT.segment_not_present
            .set_handler_fn(segment_not_present_handler);
        IDT.stack_segment_fault
            .set_handler_fn(stack_segment_fault_handler);
        IDT.general_protection_fault
            .set_handler_fn(general_protection_fault_handler);
        IDT.page_fault.set_handler_fn(page_fault_handler);
        // Reserved
        IDT.x87_floating_point
            .set_handler_fn(x87_floating_point_exception_handler);
        IDT.alignment_check.set_handler_fn(alignment_check_handler);
        IDT.machine_check.set_handler_fn(machine_check_handler);
        IDT.simd_floating_point
            .set_handler_fn(simd_floating_point_exception_handler);
        IDT.virtualization
            .set_handler_fn(virtualization_exception_handler);
        IDT.cp_protection_exception
            .set_handler_fn(control_protection_exception_handler);
        // Reserved
        // Hypervisor injection exception
        IDT.vmm_communication_exception
            .set_handler_fn(vmm_communication_exception_handler);
        IDT.security_exception
            .set_handler_fn(security_exception_handler);
        // Reserved
        // FPU error interrupt

        IDT[32].set_handler_fn(interrupt_handler::<0>);
        IDT[33].set_handler_fn(interrupt_handler::<1>);
        IDT[34].set_handler_fn(interrupt_handler::<2>);
        IDT[35].set_handler_fn(interrupt_handler::<3>);
        IDT[36].set_handler_fn(interrupt_handler::<4>);
        IDT[37].set_handler_fn(interrupt_handler::<5>);
        IDT[38].set_handler_fn(interrupt_handler::<6>);
        IDT[39].set_handler_fn(interrupt_handler::<7>);
        IDT[40].set_handler_fn(interrupt_handler::<8>);
        IDT[41].set_handler_fn(interrupt_handler::<9>);
        IDT[42].set_handler_fn(interrupt_handler::<10>);
        IDT[43].set_handler_fn(interrupt_handler::<11>);
        IDT[44].set_handler_fn(interrupt_handler::<12>);
        IDT[45].set_handler_fn(interrupt_handler::<13>);
        IDT[46].set_handler_fn(interrupt_handler::<14>);
        IDT[47].set_handler_fn(interrupt_handler::<15>);
        IDT[48].set_handler_fn(interrupt_handler::<16>);
        IDT[49].set_handler_fn(interrupt_handler::<17>);
        IDT[50].set_handler_fn(interrupt_handler::<18>);
        IDT[51].set_handler_fn(interrupt_handler::<19>);
        IDT[52].set_handler_fn(interrupt_handler::<20>);
        IDT[53].set_handler_fn(interrupt_handler::<21>);
        IDT[54].set_handler_fn(interrupt_handler::<22>);
        IDT[55].set_handler_fn(interrupt_handler::<23>);
        IDT[56].set_handler_fn(interrupt_handler::<24>);
        IDT[57].set_handler_fn(interrupt_handler::<25>);
        IDT[58].set_handler_fn(interrupt_handler::<26>);
        IDT[59].set_handler_fn(interrupt_handler::<27>);
        IDT[60].set_handler_fn(interrupt_handler::<28>);
        IDT[61].set_handler_fn(interrupt_handler::<29>);
        IDT[62].set_handler_fn(interrupt_handler::<30>);
        IDT[63].set_handler_fn(interrupt_handler::<31>);
        IDT[64].set_handler_fn(interrupt_handler::<32>);
        IDT[65].set_handler_fn(interrupt_handler::<33>);
        IDT[66].set_handler_fn(interrupt_handler::<34>);
        IDT[67].set_handler_fn(interrupt_handler::<35>);
        IDT[68].set_handler_fn(interrupt_handler::<36>);
        IDT[69].set_handler_fn(interrupt_handler::<37>);
        IDT[70].set_handler_fn(interrupt_handler::<38>);
        IDT[71].set_handler_fn(interrupt_handler::<39>);
        IDT[72].set_handler_fn(interrupt_handler::<40>);
        IDT[73].set_handler_fn(interrupt_handler::<41>);
        IDT[74].set_handler_fn(interrupt_handler::<42>);
        IDT[75].set_handler_fn(interrupt_handler::<43>);
        IDT[76].set_handler_fn(interrupt_handler::<44>);
        IDT[77].set_handler_fn(interrupt_handler::<45>);
        IDT[78].set_handler_fn(interrupt_handler::<46>);
        IDT[79].set_handler_fn(interrupt_handler::<47>);
        IDT[81].set_handler_fn(interrupt_handler::<49>);
        IDT[82].set_handler_fn(interrupt_handler::<50>);
        IDT[83].set_handler_fn(interrupt_handler::<51>);
        IDT[84].set_handler_fn(interrupt_handler::<52>);
        IDT[85].set_handler_fn(interrupt_handler::<53>);
        IDT[86].set_handler_fn(interrupt_handler::<54>);
        IDT[87].set_handler_fn(interrupt_handler::<55>);
        IDT[88].set_handler_fn(interrupt_handler::<56>);
        IDT[89].set_handler_fn(interrupt_handler::<57>);
        IDT[90].set_handler_fn(interrupt_handler::<58>);
        IDT[91].set_handler_fn(interrupt_handler::<59>);
        IDT[92].set_handler_fn(interrupt_handler::<60>);
        IDT[93].set_handler_fn(interrupt_handler::<61>);
        IDT[94].set_handler_fn(interrupt_handler::<62>);
        IDT[95].set_handler_fn(interrupt_handler::<63>);
        IDT[96].set_handler_fn(interrupt_handler::<64>);
        IDT[97].set_handler_fn(interrupt_handler::<65>);
        IDT[98].set_handler_fn(interrupt_handler::<66>);
        IDT[99].set_handler_fn(interrupt_handler::<67>);
        IDT[100].set_handler_fn(interrupt_handler::<68>);
        IDT[101].set_handler_fn(interrupt_handler::<69>);
        IDT[102].set_handler_fn(interrupt_handler::<70>);
        IDT[103].set_handler_fn(interrupt_handler::<71>);
        IDT[104].set_handler_fn(interrupt_handler::<72>);
        IDT[105].set_handler_fn(interrupt_handler::<73>);
        IDT[106].set_handler_fn(interrupt_handler::<74>);
        IDT[107].set_handler_fn(interrupt_handler::<75>);
        IDT[108].set_handler_fn(interrupt_handler::<76>);
        IDT[109].set_handler_fn(interrupt_handler::<77>);
        IDT[110].set_handler_fn(interrupt_handler::<78>);
        IDT[111].set_handler_fn(interrupt_handler::<79>);
        IDT[112].set_handler_fn(interrupt_handler::<80>);
        IDT[113].set_handler_fn(interrupt_handler::<81>);
        IDT[114].set_handler_fn(interrupt_handler::<82>);
        IDT[115].set_handler_fn(interrupt_handler::<83>);
        IDT[116].set_handler_fn(interrupt_handler::<84>);
        IDT[117].set_handler_fn(interrupt_handler::<85>);
        IDT[118].set_handler_fn(interrupt_handler::<86>);
        IDT[119].set_handler_fn(interrupt_handler::<87>);
        IDT[120].set_handler_fn(interrupt_handler::<88>);
        IDT[121].set_handler_fn(interrupt_handler::<89>);
        IDT[122].set_handler_fn(interrupt_handler::<90>);
        IDT[123].set_handler_fn(interrupt_handler::<91>);
        IDT[124].set_handler_fn(interrupt_handler::<92>);
        IDT[125].set_handler_fn(interrupt_handler::<93>);
        IDT[126].set_handler_fn(interrupt_handler::<94>);
        IDT[127].set_handler_fn(interrupt_handler::<95>);
        IDT[128].set_handler_fn(interrupt_handler::<96>);
        IDT[129].set_handler_fn(interrupt_handler::<97>);
        IDT[130].set_handler_fn(interrupt_handler::<98>);
        IDT[131].set_handler_fn(interrupt_handler::<99>);
        IDT[132].set_handler_fn(interrupt_handler::<100>);
        IDT[133].set_handler_fn(interrupt_handler::<101>);
        IDT[134].set_handler_fn(interrupt_handler::<102>);
        IDT[135].set_handler_fn(interrupt_handler::<103>);
        IDT[136].set_handler_fn(interrupt_handler::<104>);
        IDT[137].set_handler_fn(interrupt_handler::<105>);
        IDT[138].set_handler_fn(interrupt_handler::<106>);
        IDT[139].set_handler_fn(interrupt_handler::<107>);
        IDT[140].set_handler_fn(interrupt_handler::<108>);
        IDT[141].set_handler_fn(interrupt_handler::<109>);
        IDT[142].set_handler_fn(interrupt_handler::<110>);
        IDT[143].set_handler_fn(interrupt_handler::<111>);
        IDT[144].set_handler_fn(interrupt_handler::<112>);
        IDT[145].set_handler_fn(interrupt_handler::<113>);
        IDT[146].set_handler_fn(interrupt_handler::<114>);
        IDT[147].set_handler_fn(interrupt_handler::<115>);
        IDT[148].set_handler_fn(interrupt_handler::<116>);
        IDT[149].set_handler_fn(interrupt_handler::<117>);
        IDT[150].set_handler_fn(interrupt_handler::<118>);
        IDT[151].set_handler_fn(interrupt_handler::<119>);
        IDT[152].set_handler_fn(interrupt_handler::<120>);
        IDT[153].set_handler_fn(interrupt_handler::<121>);
        IDT[154].set_handler_fn(interrupt_handler::<122>);
        IDT[155].set_handler_fn(interrupt_handler::<123>);
        IDT[156].set_handler_fn(interrupt_handler::<124>);
        IDT[157].set_handler_fn(interrupt_handler::<125>);
        IDT[158].set_handler_fn(interrupt_handler::<126>);
        IDT[159].set_handler_fn(interrupt_handler::<127>);
        IDT[160].set_handler_fn(interrupt_handler::<128>);
        IDT[161].set_handler_fn(interrupt_handler::<129>);
        IDT[162].set_handler_fn(interrupt_handler::<130>);
        IDT[163].set_handler_fn(interrupt_handler::<131>);
        IDT[164].set_handler_fn(interrupt_handler::<132>);
        IDT[165].set_handler_fn(interrupt_handler::<133>);
        IDT[166].set_handler_fn(interrupt_handler::<134>);
        IDT[167].set_handler_fn(interrupt_handler::<135>);
        IDT[168].set_handler_fn(interrupt_handler::<136>);
        IDT[169].set_handler_fn(interrupt_handler::<137>);
        IDT[170].set_handler_fn(interrupt_handler::<138>);
        IDT[171].set_handler_fn(interrupt_handler::<139>);
        IDT[172].set_handler_fn(interrupt_handler::<140>);
        IDT[173].set_handler_fn(interrupt_handler::<141>);
        IDT[174].set_handler_fn(interrupt_handler::<142>);
        IDT[175].set_handler_fn(interrupt_handler::<143>);
        IDT[176].set_handler_fn(interrupt_handler::<144>);
        IDT[177].set_handler_fn(interrupt_handler::<145>);
        IDT[178].set_handler_fn(interrupt_handler::<146>);
        IDT[179].set_handler_fn(interrupt_handler::<147>);
        IDT[180].set_handler_fn(interrupt_handler::<148>);
        IDT[181].set_handler_fn(interrupt_handler::<149>);
        IDT[182].set_handler_fn(interrupt_handler::<150>);
        IDT[183].set_handler_fn(interrupt_handler::<151>);
        IDT[184].set_handler_fn(interrupt_handler::<152>);
        IDT[185].set_handler_fn(interrupt_handler::<153>);
        IDT[186].set_handler_fn(interrupt_handler::<154>);
        IDT[187].set_handler_fn(interrupt_handler::<155>);
        IDT[188].set_handler_fn(interrupt_handler::<156>);
        IDT[189].set_handler_fn(interrupt_handler::<157>);
        IDT[190].set_handler_fn(interrupt_handler::<158>);
        IDT[191].set_handler_fn(interrupt_handler::<159>);
        IDT[192].set_handler_fn(interrupt_handler::<160>);
        IDT[193].set_handler_fn(interrupt_handler::<161>);
        IDT[194].set_handler_fn(interrupt_handler::<162>);
        IDT[195].set_handler_fn(interrupt_handler::<163>);
        IDT[196].set_handler_fn(interrupt_handler::<164>);
        IDT[197].set_handler_fn(interrupt_handler::<165>);
        IDT[198].set_handler_fn(interrupt_handler::<166>);
        IDT[199].set_handler_fn(interrupt_handler::<167>);
        IDT[200].set_handler_fn(interrupt_handler::<168>);
        IDT[201].set_handler_fn(interrupt_handler::<169>);
        IDT[202].set_handler_fn(interrupt_handler::<170>);
        IDT[203].set_handler_fn(interrupt_handler::<171>);
        IDT[204].set_handler_fn(interrupt_handler::<172>);
        IDT[205].set_handler_fn(interrupt_handler::<173>);
        IDT[206].set_handler_fn(interrupt_handler::<174>);
        IDT[207].set_handler_fn(interrupt_handler::<175>);
        IDT[208].set_handler_fn(interrupt_handler::<176>);
        IDT[209].set_handler_fn(interrupt_handler::<177>);
        IDT[210].set_handler_fn(interrupt_handler::<178>);
        IDT[211].set_handler_fn(interrupt_handler::<179>);
        IDT[212].set_handler_fn(interrupt_handler::<180>);
        IDT[213].set_handler_fn(interrupt_handler::<181>);
        IDT[214].set_handler_fn(interrupt_handler::<182>);
        IDT[215].set_handler_fn(interrupt_handler::<183>);
        IDT[216].set_handler_fn(interrupt_handler::<184>);
        IDT[217].set_handler_fn(interrupt_handler::<185>);
        IDT[218].set_handler_fn(interrupt_handler::<186>);
        IDT[219].set_handler_fn(interrupt_handler::<187>);
        IDT[220].set_handler_fn(interrupt_handler::<188>);
        IDT[221].set_handler_fn(interrupt_handler::<189>);
        IDT[222].set_handler_fn(interrupt_handler::<190>);
        IDT[223].set_handler_fn(interrupt_handler::<191>);
        IDT[224].set_handler_fn(interrupt_handler::<192>);
        IDT[225].set_handler_fn(interrupt_handler::<193>);
        IDT[226].set_handler_fn(interrupt_handler::<194>);
        IDT[227].set_handler_fn(interrupt_handler::<195>);
        IDT[228].set_handler_fn(interrupt_handler::<196>);
        IDT[229].set_handler_fn(interrupt_handler::<197>);
        IDT[230].set_handler_fn(interrupt_handler::<198>);
        IDT[231].set_handler_fn(interrupt_handler::<199>);
        IDT[232].set_handler_fn(interrupt_handler::<200>);
        IDT[233].set_handler_fn(interrupt_handler::<201>);
        IDT[234].set_handler_fn(interrupt_handler::<202>);
        IDT[235].set_handler_fn(interrupt_handler::<203>);
        IDT[236].set_handler_fn(interrupt_handler::<204>);
        IDT[237].set_handler_fn(interrupt_handler::<205>);
        IDT[238].set_handler_fn(interrupt_handler::<206>);
        IDT[239].set_handler_fn(interrupt_handler::<207>);
        IDT[240].set_handler_fn(interrupt_handler::<208>);
        IDT[241].set_handler_fn(interrupt_handler::<209>);
        IDT[242].set_handler_fn(interrupt_handler::<210>);
        IDT[243].set_handler_fn(interrupt_handler::<211>);
        IDT[244].set_handler_fn(interrupt_handler::<212>);
        IDT[245].set_handler_fn(interrupt_handler::<213>);
        IDT[246].set_handler_fn(interrupt_handler::<214>);
        IDT[247].set_handler_fn(interrupt_handler::<215>);
        IDT[248].set_handler_fn(interrupt_handler::<216>);
        IDT[249].set_handler_fn(interrupt_handler::<217>);
        IDT[250].set_handler_fn(interrupt_handler::<218>);
        IDT[251].set_handler_fn(interrupt_handler::<219>);
        IDT[252].set_handler_fn(interrupt_handler::<220>);
        IDT[253].set_handler_fn(interrupt_handler::<221>);
        IDT[254].set_handler_fn(interrupt_handler::<222>);
        IDT[255].set_handler_fn(interrupt_handler::<223>);

        IDT[SYSCALL_IRQ] = Entry::missing();
        IDT[SYSCALL_IRQ]
            .set_handler_fn(syscall_handler)
            .set_code_selector(SegmentSelector::new(
                KERNEL_MODE_CODE_SEGMENT_INDEX as u16,
                PrivilegeLevel::Ring0,
            ))
            .set_privilege_level(PrivilegeLevel::Ring3);

        IDT.load();
    }*/
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
            divide_error: IdtEntry::new(
                0,
                0,
                IdtAttributes::new()
                    .with_present(false)
                    .with_privilege_level(PrivilegeLevel::Ring3)
                    .with_kind(GateKind::Interrupt),
            ),
            debug: IdtEntry::new(
                0,
                0,
                IdtAttributes::new()
                    .with_present(false)
                    .with_privilege_level(PrivilegeLevel::Ring3)
                    .with_kind(GateKind::Interrupt),
            ),
            non_maskable_interrupt: IdtEntry::new(
                0,
                0,
                IdtAttributes::new()
                    .with_present(false)
                    .with_privilege_level(PrivilegeLevel::Ring3)
                    .with_kind(GateKind::Interrupt),
            ),
            breakpoint: IdtEntry::new(
                0,
                0,
                IdtAttributes::new()
                    .with_present(false)
                    .with_privilege_level(PrivilegeLevel::Ring3)
                    .with_kind(GateKind::Interrupt),
            ),
            overflow: IdtEntry::new(
                0,
                0,
                IdtAttributes::new()
                    .with_present(false)
                    .with_privilege_level(PrivilegeLevel::Ring3)
                    .with_kind(GateKind::Interrupt),
            ),
            bound_range_exceeded: IdtEntry::new(
                0,
                0,
                IdtAttributes::new()
                    .with_present(false)
                    .with_privilege_level(PrivilegeLevel::Ring3)
                    .with_kind(GateKind::Interrupt),
            ),
            invalid_opcode: IdtEntry::new(
                0,
                0,
                IdtAttributes::new()
                    .with_present(false)
                    .with_privilege_level(PrivilegeLevel::Ring3)
                    .with_kind(GateKind::Interrupt),
            ),
            device_not_available: IdtEntry::new(
                0,
                0,
                IdtAttributes::new()
                    .with_present(false)
                    .with_privilege_level(PrivilegeLevel::Ring3)
                    .with_kind(GateKind::Interrupt),
            ),
            double_fault: IdtEntry::new(
                0,
                0,
                IdtAttributes::new()
                    .with_present(false)
                    .with_privilege_level(PrivilegeLevel::Ring3)
                    .with_kind(GateKind::Interrupt),
            ),
            coprocessor_segment_overrun: IdtEntry::new(
                0,
                0,
                IdtAttributes::new()
                    .with_present(false)
                    .with_privilege_level(PrivilegeLevel::Ring3)
                    .with_kind(GateKind::Interrupt),
            ),
            invalid_tss: IdtEntry::new(
                0,
                0,
                IdtAttributes::new()
                    .with_present(false)
                    .with_privilege_level(PrivilegeLevel::Ring3)
                    .with_kind(GateKind::Interrupt),
            ),
            segment_not_present: IdtEntry::new(
                0,
                0,
                IdtAttributes::new()
                    .with_present(false)
                    .with_privilege_level(PrivilegeLevel::Ring3)
                    .with_kind(GateKind::Interrupt),
            ),
            stack_segment_fault: IdtEntry::new(
                0,
                0,
                IdtAttributes::new()
                    .with_present(false)
                    .with_privilege_level(PrivilegeLevel::Ring3)
                    .with_kind(GateKind::Interrupt),
            ),
            general_protection_fault: IdtEntry::new(
                0,
                0,
                IdtAttributes::new()
                    .with_present(false)
                    .with_privilege_level(PrivilegeLevel::Ring3)
                    .with_kind(GateKind::Interrupt),
            ),
            page_fault: IdtEntry::new(
                0,
                0,
                IdtAttributes::new()
                    .with_present(false)
                    .with_privilege_level(PrivilegeLevel::Ring3)
                    .with_kind(GateKind::Interrupt),
            ),
            reserved_1: IdtEntry::new(
                0,
                0,
                IdtAttributes::new()
                    .with_present(false)
                    .with_privilege_level(PrivilegeLevel::Ring3)
                    .with_kind(GateKind::Interrupt),
            ),
            x87_floating_point: IdtEntry::new(
                0,
                0,
                IdtAttributes::new()
                    .with_present(false)
                    .with_privilege_level(PrivilegeLevel::Ring3)
                    .with_kind(GateKind::Interrupt),
            ),
            alignment_check: IdtEntry::new(
                0,
                0,
                IdtAttributes::new()
                    .with_present(false)
                    .with_privilege_level(PrivilegeLevel::Ring3)
                    .with_kind(GateKind::Interrupt),
            ),
            machine_check: IdtEntry::new(
                0,
                0,
                IdtAttributes::new()
                    .with_present(false)
                    .with_privilege_level(PrivilegeLevel::Ring3)
                    .with_kind(GateKind::Interrupt),
            ),
            simd_floating_point: IdtEntry::new(
                0,
                0,
                IdtAttributes::new()
                    .with_present(false)
                    .with_privilege_level(PrivilegeLevel::Ring3)
                    .with_kind(GateKind::Interrupt),
            ),
            virtualization: IdtEntry::new(
                0,
                0,
                IdtAttributes::new()
                    .with_present(false)
                    .with_privilege_level(PrivilegeLevel::Ring3)
                    .with_kind(GateKind::Interrupt),
            ),
            cp_protection_exception: IdtEntry::new(
                0,
                0,
                IdtAttributes::new()
                    .with_present(false)
                    .with_privilege_level(PrivilegeLevel::Ring3)
                    .with_kind(GateKind::Interrupt),
            ),
            reserved_2: [IdtEntry::new(
                0,
                0,
                IdtAttributes::new()
                    .with_present(false)
                    .with_privilege_level(PrivilegeLevel::Ring3)
                    .with_kind(GateKind::Interrupt),
            ); 6],
            hv_injection_exception: IdtEntry::new(
                0,
                0,
                IdtAttributes::new()
                    .with_present(false)
                    .with_privilege_level(PrivilegeLevel::Ring3)
                    .with_kind(GateKind::Interrupt),
            ),
            vmm_communication_exception: IdtEntry::new(
                0,
                0,
                IdtAttributes::new()
                    .with_present(false)
                    .with_privilege_level(PrivilegeLevel::Ring3)
                    .with_kind(GateKind::Interrupt),
            ),
            security_exception: IdtEntry::new(
                0,
                0,
                IdtAttributes::new()
                    .with_present(false)
                    .with_privilege_level(PrivilegeLevel::Ring3)
                    .with_kind(GateKind::Interrupt),
            ),
            reserved_3: IdtEntry::new(
                0,
                0,
                IdtAttributes::new()
                    .with_present(false)
                    .with_privilege_level(PrivilegeLevel::Ring3)
                    .with_kind(GateKind::Interrupt),
            ),
            interrupts: [IdtEntry::new(
                0,
                0,
                IdtAttributes::new()
                    .with_present(false)
                    .with_privilege_level(PrivilegeLevel::Ring3)
                    .with_kind(GateKind::Interrupt),
            ); 224],
        }
    }

    pub fn load(&'static self) {
        unsafe {
            asm!(
                "lidt [{}]",
                in(reg) &Idtr {
                    limit: (core::mem::size_of::<Idt>() - 1) as u16,
                    base: self as *const _ as u64,
                } as *const Idtr,
                options(nostack, preserves_flags)
            );
        }
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

impl Default for IdtEntry {
    fn default() -> Self {
        Self::new(0, 0, IdtAttributes::new())
    }
}

#[bitfield(u8)]
pub struct IdtAttributes {
    #[bits(4, default = GateKind::Interrupt)]
    pub kind: GateKind,
    #[bits(1)]
    __: u8,
    #[bits(2)]
    pub privilege_level: PrivilegeLevel,
    pub present: bool,
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

pub fn register_interrupt_handler(n: u8, handler: Box<ExceptionHandler>) {
    assert!(n != SYSCALL_IRQ);

    unsafe {
        REGISTERED_INTERRUPT_HANDLERS[n as usize - 32].push(handler);
    }
}

extern "C" fn interrupt_handler<const N: usize>(
    frame: &ExceptionFrame,
    registers: &VolatileRegisters,
) {
    use_kernel_page_table(|| {
        let interrupt_handlers = unsafe { &REGISTERED_INTERRUPT_HANDLERS[N] };

        for interrupt_handler in interrupt_handlers {
            interrupt_handler(frame, registers);
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
            let descriptor = rdi;
            let buffer = rsi as *const u8;
            let count = rdx;

            let mut buffer_copied = [0u8; 512];

            assert!(count < 512);

            for i in 0..count as usize {
                buffer_copied[i] = unsafe { *buffer.add(i) };
            }

            buffer_copied[count as usize] = 0;

            use_kernel_page_table(|| {
                info!("sys_write ({descriptor}, {buffer:p}, {count})");
                info!(
                    "{}",
                    CStr::from_bytes_until_nul(&buffer_copied[..])
                        .unwrap()
                        .to_string_lossy()
                );
            });
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
