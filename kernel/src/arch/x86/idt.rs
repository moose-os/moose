use alloc::{boxed::Box, vec::Vec};
use core::{arch::asm, ffi::CStr};
use log::{error, info, warn};
use x86_64::{
    registers::control::Cr2,
    structures::{
        gdt::SegmentSelector,
        idt::{Entry, InterruptDescriptorTable, InterruptStackFrame, PageFaultErrorCode},
    },
    PrivilegeLevel,
};

use super::{gdt::KERNEL_MODE_CODE_SEGMENT_INDEX, use_kernel_page_table};

pub static mut IDT: InterruptDescriptorTable = InterruptDescriptorTable::new();

static mut REGISTERED_INTERRUPT_HANDLERS: [Vec<Box<dyn Fn(&InterruptStackFrame)>>; 224] = {
    const DEFAULT: Vec<Box<dyn Fn(&InterruptStackFrame)>> = Vec::new();

    [DEFAULT; 224]
};

const SYSCALL_IRQ: u8 = 0x80;

pub fn init_idt() {
    unsafe {
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
    }
}

pub fn register_interrupt_handler(n: u8, handler: Box<dyn Fn(&InterruptStackFrame)>) {
    assert!(n != SYSCALL_IRQ);

    unsafe {
        REGISTERED_INTERRUPT_HANDLERS[n as usize - 32].push(handler);
    }
}

extern "x86-interrupt" fn interrupt_handler<const N: usize>(
    interrupt_stack_frame: InterruptStackFrame,
) {
    use_kernel_page_table(|| {
        let interrupt_handlers = unsafe { &REGISTERED_INTERRUPT_HANDLERS[N] };

        for interrupt_handler in interrupt_handlers {
            interrupt_handler(&interrupt_stack_frame);
        }
    });
}

extern "x86-interrupt" fn division_error_handler(interrupt_stack_frame: InterruptStackFrame) {
    use_kernel_page_table(|| {
        warn!("Division error");

        info!("Stack frame: {interrupt_stack_frame:?}");
    });

    loop {
        x86_64::instructions::hlt();
    }
}

extern "x86-interrupt" fn debug_handler(interrupt_stack_frame: InterruptStackFrame) {
    use_kernel_page_table(|| {
        info!("Debug");

        info!("Stack frame: {interrupt_stack_frame:?}");
    });
}

extern "x86-interrupt" fn non_maskable_interrupt_handler(
    interrupt_stack_frame: InterruptStackFrame,
) {
    use_kernel_page_table(|| {
        info!("Non-maskable interrupt");

        info!("Stack frame: {interrupt_stack_frame:?}");
    });
}

extern "x86-interrupt" fn breakpoint_handler(interrupt_stack_frame: InterruptStackFrame) {
    use_kernel_page_table(|| {
        info!("Breakpoint");

        info!("Stack frame: {interrupt_stack_frame:?}");
    });
}

extern "x86-interrupt" fn overflow_handler(interrupt_stack_frame: InterruptStackFrame) {
    use_kernel_page_table(|| {
        warn!("Overflow");

        info!("Stack frame: {interrupt_stack_frame:?}");
    });

    loop {
        x86_64::instructions::hlt();
    }
}

extern "x86-interrupt" fn bound_range_exceeded_handler(interrupt_stack_frame: InterruptStackFrame) {
    use_kernel_page_table(|| {
        warn!("Bound range exceeded");

        info!("Stack frame: {interrupt_stack_frame:?}");
    });

    loop {
        x86_64::instructions::hlt();
    }
}

extern "x86-interrupt" fn invalid_opcode_handler(interrupt_stack_frame: InterruptStackFrame) {
    use_kernel_page_table(|| {
        warn!("Invalid opcode");

        info!("Stack frame: {interrupt_stack_frame:?}");
    });

    loop {
        x86_64::instructions::hlt();
    }
}

extern "x86-interrupt" fn device_not_available_handler(interrupt_stack_frame: InterruptStackFrame) {
    use_kernel_page_table(|| {
        warn!("Device not available");

        info!("Stack frame: {interrupt_stack_frame:?}");
    });

    loop {
        x86_64::instructions::hlt();
    }
}

extern "x86-interrupt" fn double_fault_handler(
    interrupt_stack_frame: InterruptStackFrame,
    error_code: u64,
) -> ! {
    use_kernel_page_table(|| {
        error!("Double fault");

        info!("Stack frame: {interrupt_stack_frame:?}");
        info!("Error code: {error_code}");
    });

    loop {
        x86_64::instructions::hlt();
    }
}

extern "x86-interrupt" fn invalid_tss_handler(
    interrupt_stack_frame: InterruptStackFrame,
    error_code: u64,
) {
    use_kernel_page_table(|| {
        warn!("Invalid TSS");

        info!("Stack frame: {interrupt_stack_frame:?}");
        info!("Error code: {error_code}");
    });

    loop {
        x86_64::instructions::hlt();
    }
}

extern "x86-interrupt" fn segment_not_present_handler(
    interrupt_stack_frame: InterruptStackFrame,
    error_code: u64,
) {
    use_kernel_page_table(|| {
        warn!("Segment not present");

        info!("Stack frame: {interrupt_stack_frame:?}");
        info!("Error code: {error_code}");
    });

    loop {
        x86_64::instructions::hlt();
    }
}

extern "x86-interrupt" fn stack_segment_fault_handler(
    interrupt_stack_frame: InterruptStackFrame,
    error_code: u64,
) {
    use_kernel_page_table(|| {
        warn!("Stack segment fault");

        info!("Stack frame: {interrupt_stack_frame:?}");
        info!("Error code: {error_code}");
    });

    loop {
        x86_64::instructions::hlt();
    }
}

extern "x86-interrupt" fn general_protection_fault_handler(
    interrupt_stack_frame: InterruptStackFrame,
    error_code: u64,
) {
    use_kernel_page_table(|| {
        warn!("General protection fault");

        info!("Stack frame: {interrupt_stack_frame:#?}");

        if error_code != 0 {
            info!("Is external: {}", error_code & 1 == 1);
            info!("GDT/IDT/LDT/IDT: {}", (error_code >> 1) & 0b11);
            info!("Segment selector index: {}", error_code >> 3);
        }
    });

    loop {
        x86_64::instructions::hlt();
    }
}

extern "x86-interrupt" fn page_fault_handler(
    interrupt_stack_frame: InterruptStackFrame,
    error_code: PageFaultErrorCode,
) {
    use_kernel_page_table(|| {
        error!("Page fault");

        if let Ok(address) = Cr2::read() {
            error!("Accessed virtual address: {:#0x}", address.as_u64());
        } else {
            error!("Accessed unknown virtual address");
        }

        info!("Stack frame: {interrupt_stack_frame:#?}");
        info!("Error code: {error_code:?}");
    });

    loop {
        x86_64::instructions::hlt();
    }
}

extern "x86-interrupt" fn x87_floating_point_exception_handler(
    interrupt_stack_frame: InterruptStackFrame,
) {
    use_kernel_page_table(|| {
        warn!("x87 floating point exception");

        info!("Stack frame: {interrupt_stack_frame:?}");
    });

    loop {
        x86_64::instructions::hlt();
    }
}

extern "x86-interrupt" fn alignment_check_handler(
    interrupt_stack_frame: InterruptStackFrame,
    error_code: u64,
) {
    use_kernel_page_table(|| {
        warn!("Alignment check");

        info!("Stack frame: {interrupt_stack_frame:?}");
        info!("Error code: {error_code}");
    });

    loop {
        x86_64::instructions::hlt();
    }
}

extern "x86-interrupt" fn machine_check_handler(interrupt_stack_frame: InterruptStackFrame) -> ! {
    use_kernel_page_table(|| {
        warn!("Machine check");

        info!("Stack frame: {interrupt_stack_frame:?}");
    });

    loop {
        x86_64::instructions::hlt();
    }
}

extern "x86-interrupt" fn simd_floating_point_exception_handler(
    interrupt_stack_frame: InterruptStackFrame,
) {
    use_kernel_page_table(|| {
        warn!("SIMD floating point exception");

        info!("Stack frame: {interrupt_stack_frame:?}");
    });

    loop {
        x86_64::instructions::hlt();
    }
}

extern "x86-interrupt" fn virtualization_exception_handler(
    interrupt_stack_frame: InterruptStackFrame,
) {
    use_kernel_page_table(|| {
        warn!("Virtualization exception");

        info!("Stack frame: {interrupt_stack_frame:?}");
    });

    loop {
        x86_64::instructions::hlt();
    }
}

extern "x86-interrupt" fn control_protection_exception_handler(
    interrupt_stack_frame: InterruptStackFrame,
    error_code: u64,
) {
    use_kernel_page_table(|| {
        warn!("Control protection exception");

        info!("Stack frame: {interrupt_stack_frame:?}");
        info!("Error code: {error_code}");
    });

    loop {
        x86_64::instructions::hlt();
    }
}

extern "x86-interrupt" fn vmm_communication_exception_handler(
    interrupt_stack_frame: InterruptStackFrame,
    error_code: u64,
) {
    use_kernel_page_table(|| {
        warn!("VMM communication exception");

        info!("Stack frame: {interrupt_stack_frame:?}");
        info!("Error code: {error_code}");
    });

    loop {
        x86_64::instructions::hlt();
    }
}

extern "x86-interrupt" fn security_exception_handler(
    interrupt_stack_frame: InterruptStackFrame,
    error_code: u64,
) {
    use_kernel_page_table(|| {
        warn!("Security exception");

        info!("Stack frame: {interrupt_stack_frame:?}");
        info!("Error code: {error_code}");
    });

    loop {
        x86_64::instructions::hlt();
    }
}

extern "x86-interrupt" fn syscall_handler(_interrupt_stack_frame: InterruptStackFrame) {
    unsafe {
        asm!(
            "
                push r9
                push r8
                push r10
                push rdx
                push rsi
                push rdi
                push rax
            ",
            options(nomem, preserves_flags)
        );
    }

    let mut rax: u64;
    let mut rdi: u64;
    let mut rsi: u64;
    let mut rdx: u64;
    let mut r10: u64;
    let mut r8: u64;
    let mut r9: u64;

    unsafe {
        asm!(
            "
                pop {rax}
                pop {rdi}
                pop {rsi}
                pop {rdx}
                pop {r10}
                pop {r8}
                pop {r9}
            ",
            options(nomem, preserves_flags),
            rax = out(reg) rax,
            rdi = out(reg) rdi,
            rsi = out(reg) rsi,
            rdx = out(reg) rdx,
            r10 = out(reg) r10,
            r8 = out(reg) r8,
            r9 = out(reg) r9,
        );
    }

    let id = rax;

    match id {
        1 => {
            write_syscall(rdi, rsi as *const u8, rdx);
        }
        _ => unimplemented!(),
    }
}

extern "x86-interrupt" fn unknown_interrupt_handler(interrupt_stack_frame: InterruptStackFrame) {
    use_kernel_page_table(|| {
        info!("Unknown interrupt");

        info!("Stack frame: {interrupt_stack_frame:?}");
    });

    loop {
        x86_64::instructions::hlt();
    }
}

extern "C" fn write_syscall(descriptor: u64, buffer: *const u8, count: u64) {
    info!("sys_write ({descriptor}, {buffer:p}, {count})");

    let mut buffer_copied = [0u8; 512];

    assert!(count < 512);

    for i in 0..count as usize {
        buffer_copied[i] = unsafe { *buffer.add(i) };
    }

    buffer_copied[count as usize] = 0;

    use_kernel_page_table(|| {
        info!(
            "{}",
            CStr::from_bytes_until_nul(&buffer_copied[..])
                .unwrap()
                .to_string_lossy()
        );
    });
}
