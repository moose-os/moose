use core::{arch::asm, mem, sync::atomic::Ordering};

use alloc::{collections::VecDeque, sync::Arc, vec::Vec};
use spin::Mutex;
use x86_64::{
    registers::control::{Cr3, Cr3Flags},
    structures::paging::{PhysFrame, Size4KiB},
    PhysAddr,
};

use crate::process::{Registers, Status, Thread, ThreadStack};

static SCHEDULER: Scheduler = Scheduler::new();

pub struct Scheduler {
    current_thread: Mutex<Option<Thread>>,
    execution_queue: Mutex<VecDeque<Thread>>,
}

impl Scheduler {
    const fn new() -> Self {
        Self {
            current_thread: Mutex::new(None),
            execution_queue: Mutex::new(VecDeque::new()),
        }
    }
}

impl Scheduler {
    pub fn run() -> ! {
        let mut execution_queue = SCHEDULER.execution_queue.lock();

        if execution_queue.is_empty() {
            loop {
                unsafe {
                    asm!("hlt");
                }
            }
        }

        let thread = execution_queue.pop_front().unwrap();

        drop(execution_queue);

        *SCHEDULER.current_thread.lock() = Some(thread.clone());

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

        let is_kernel_mode = thread.is_kernel_mode();

        drop(thread);

        if is_kernel_mode {
            enter_kernel_mode(entry as *const _, unsafe {
                (stack as *const u8)
                    .add(mem::size_of::<ThreadStack>())
                    .offset(-16)
            });
        } else {
            enter_user_mode(entry as *const _, unsafe {
                (stack as *const u8)
                    .add(mem::size_of::<ThreadStack>())
                    .offset(-16)
            });
        }
    }
}

#[derive(Clone)]
pub struct Event(Arc<EventInner>);

impl Event {
    pub fn new() -> Self {
        Self(Arc::new(EventInner {
            waiting_threads: Mutex::new(Vec::new()),
        }))
    }

    pub fn wait_on(&self, thread: &Thread) {
        thread.set_status(Status::Waiting { timeout: None });

        self.0.waiting_threads.lock().push(thread.clone());
    }

    pub fn notify(&self) {
        let mut waiting_threads = self.0.waiting_threads.lock();

        for waiting_thread in &*waiting_threads {
            waiting_thread.set_status(Status::Running);
        }

        waiting_threads.clear();
    }
}

struct EventInner {
    waiting_threads: Mutex<Vec<Thread>>,
}

pub fn current_thread() -> Thread {
    SCHEDULER.current_thread.lock().as_ref().unwrap().clone()
}

pub fn schedule(thread: Thread) {
    match thread.status() {
        Status::Running => {}
        Status::Stopped => return,
        Status::Waiting { timeout: _ } => return,
    }

    thread.0.reschedule.store(true, Ordering::SeqCst);

    let mut execution_queue = SCHEDULER.execution_queue.lock();

    if !execution_queue
        .iter()
        .any(|thread_in_queue| Arc::ptr_eq(&thread_in_queue.0, &thread.0))
    {
        execution_queue.push_back(thread);
    }
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
    thread.0.reschedule.store(false, Ordering::SeqCst);

    let mut execution_queue = SCHEDULER.execution_queue.lock();

    let index = execution_queue
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
        execution_queue.remove(index);
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
    let mut current_thread = SCHEDULER.current_thread.lock();
    let mut execution_queue = SCHEDULER.execution_queue.lock();

    if current_thread.is_none() && execution_queue.is_empty() {
        return;
    }

    let previous_thread = current_thread.as_ref().unwrap();

    if previous_thread.0.reschedule.load(Ordering::SeqCst) {
        execution_queue.push_back(previous_thread.clone());
    }

    let next_thread = execution_queue.pop_front().unwrap();

    *current_thread = Some(next_thread);
}

extern "C" fn enter_kernel_mode(program: *const u8, stack: *const u8) -> ! {
    unsafe {
        asm!(
            "
                mov ds, {data_segment:r}
                mov es, {data_segment:r}

                push 6 << 3
                push {stack}
                pushf
                push 5 << 3
                push {program}

                iretq
            ",
            data_segment = in(reg) 6 << 3,
            program = in(reg) program,
            stack = in(reg) stack,
            options(noreturn)
        );
    };
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
