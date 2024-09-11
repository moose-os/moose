use core::{arch::asm, mem};

use alloc::{collections::VecDeque, sync::Arc};
use spin::Mutex;
use x86_64::{
    registers::control::{Cr3, Cr3Flags},
    structures::paging::{PhysFrame, Size4KiB},
    PhysAddr,
};

use crate::process::{Registers, Thread, ThreadStack};

static SCHEDULER: Scheduler = Scheduler::new();

pub struct Scheduler {
    queue: Mutex<VecDeque<Thread>>,
}

impl Scheduler {
    const fn new() -> Self {
        Self {
            queue: Mutex::new(VecDeque::new()),
        }
    }
}

impl Scheduler {
    pub fn run() -> ! {
        let queue = SCHEDULER.queue.lock();
        let thread = queue.front().unwrap();
        let process = thread.process();

        // switch page table
        {
            let program_page_table_frame = PhysFrame::<Size4KiB>::from_start_address(
                PhysAddr::new(process.0.page_table_physical_address),
            )
            .unwrap();

            unsafe { Cr3::write(program_page_table_frame, Cr3Flags::empty()) };
        }

        let entry = thread.entry();
        let stack = thread.stack();

        drop(queue);

        enter_user_mode(entry as *const _, unsafe {
            (stack as *const u8)
                .add(mem::size_of::<ThreadStack>())
                .offset(-16)
        });
    }
}

pub fn current_thread() -> Thread {
    SCHEDULER.queue.lock().front().unwrap().clone()
}

pub fn schedule(thread: Thread) {
    SCHEDULER.queue.lock().push_back(thread);
}

pub fn run(registers: *mut Registers) {
    save_registers(registers);
    schedule_next_thread();
    restore_registers(registers);

    let current_thread = current_thread();
    let current_process = current_thread.process();

    let program_page_table_frame = PhysFrame::<Size4KiB>::from_start_address(PhysAddr::new(
        current_process.0.page_table_physical_address,
    ))
    .unwrap();

    unsafe { Cr3::write(program_page_table_frame, Cr3Flags::empty()) };
}

pub fn unschedule(thread: &Thread) {
    let mut queue = SCHEDULER.queue.lock();

    let index = queue
        .iter()
        .enumerate()
        .find_map(|(index, current_thread)| {
            if Arc::ptr_eq(&thread.0, &current_thread.0) {
                Some(index)
            } else {
                None
            }
        });

    if let Some(index) = index {
        queue.remove(index);
    }
}

fn save_registers(registers: *const Registers) {
    let current_thread = current_thread();

    *current_thread.0.registers.lock() = unsafe { (*registers).clone() };
}

fn restore_registers(registers: *mut Registers) {
    let current_thread = current_thread();

    unsafe { *registers = current_thread.0.registers.lock().clone() };
}

fn schedule_next_thread() {
    let mut queue = SCHEDULER.queue.lock();

    if queue.is_empty() {
        return;
    }

    let thread = queue.pop_front().unwrap();

    queue.push_back(thread);
}

extern "C" fn enter_user_mode(program: *const u8, stack: *const u8) -> ! {
    unsafe {
        asm!(
            "
                mov ds, {data_segment:r}
                mov es, {data_segment:r}

                push (8 << 3) | 3
                push {stack}
                pushf
                push (7 << 3) | 3
                push {program}

                iretq
            ",
            data_segment = in(reg) (8 << 3) | 3,
            program = in(reg) program,
            stack = in(reg) stack,
            options(noreturn)
        );
    };
}
