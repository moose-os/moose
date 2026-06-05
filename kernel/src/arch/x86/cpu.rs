use alloc::boxed::Box;
use core::cell::OnceCell;
use spin::rwlock::RwLock;

use x86_64::{
    VirtAddr,
    registers::segmentation::{GS, Segment64},
};

use crate::{driver::apic::LocalApic, subsystem::clock::timer::HrTimerSubsystem};

pub(crate) const MAXIMUM_CPU_CORES: usize = 4;

pub struct ProcessorControlBlock {
    pub apic_processor_id: u16,
    pub is_bsp: bool,
    pub local_apic: OnceCell<LocalApic>,
    pub hr_timers: RwLock<HrTimerSubsystem>,
}

impl ProcessorControlBlock {
    pub unsafe fn create_pcb_for_current_processor(apic_processor_id: u16) {
        let ptr = Box::leak(Box::new(ProcessorControlBlock {
            apic_processor_id,
            is_bsp: false,
            local_apic: OnceCell::new(),
            hr_timers: RwLock::new(HrTimerSubsystem::new()),
        }));

        unsafe { GS::write_base(VirtAddr::new(ptr as *mut _ as u64)) };
    }

    // @TODO: SWAPGS

    // PCB is created
    //   - if current processor is BSP, just after memory manager initialization,
    //   - if current processor is AP, just after jump from assembly code to kernel's initialization
    //     routine,
    // so GS will be properly initialized nearly always, and it's safe function.
    pub fn current() -> &'static mut ProcessorControlBlock {
        unsafe { &mut *(GS::read_base().as_u64() as *mut ProcessorControlBlock) }
    }

    pub fn local_apic(&self) -> &LocalApic {
        self.local_apic
            .get()
            .expect("Tried to access local APIC before initialization")
    }
}
