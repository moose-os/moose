use crate::driver::apic::LocalApic;
use alloc::boxed::Box;
use core::cell::OnceCell;
use x86_64::registers::segmentation::{Segment64, GS};
use x86_64::VirtAddr;

pub(crate) const MAXIMUM_CPU_CORES: usize = 4;

pub struct ProcessorControlBlock {
    pub apic_processor_id: u16,
    pub is_bsp: bool,
    pub local_apic: OnceCell<LocalApic>,
}

impl ProcessorControlBlock {
    pub unsafe fn create_pcb_for_current_processor(apic_processor_id: u16) {
        let ptr = Box::leak(Box::new(ProcessorControlBlock {
            apic_processor_id: 0xFFFF,
            is_bsp: false,
            local_apic: OnceCell::new(),
        }));

        GS::write_base(VirtAddr::new(ptr as *mut _ as u64));

        (*ProcessorControlBlock::get_pcb_for_current_processor()).apic_processor_id =
            apic_processor_id;
    }

    // @TODO: SWAPGS

    // PCB is created
    //   - if current processor is BSP, just after memory manager initialization,
    //   - if current processor is AP, just after jump from assembly code to kernel's initialization
    //     routine,
    // so GS will be properly initialized nearly always, and it's safe function.
    pub fn get_pcb_for_current_processor() -> *mut ProcessorControlBlock {
        GS::read_base().as_u64() as *mut ProcessorControlBlock
    }
}
