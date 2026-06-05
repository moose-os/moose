use alloc::{collections::VecDeque, sync::Arc, vec::Vec};
use core::{arch::asm, mem, sync::atomic::Ordering};

use spin::Mutex;
use x86_64::{
    PhysAddr,
    instructions::interrupts,
    registers::control::{Cr3, Cr3Flags},
    structures::paging::{PhysFrame, Size4KiB},
};

use crate::{
    arch::x86::{cpu::ProcessorControlBlock, idt::YIELD_IRQ},
    kernel::kernel_ref,
    subsystem::{
        clock::{time::Duration, timer::TimerAction},
        process::{Registers, Status, Thread, ThreadStack},
    },
};

pub const PRIORITIES_NUM: usize = 16;

pub struct Scheduler {
    current_thread: Mutex<Option<Thread>>,
    execution_queues: Mutex<[VecDeque<Thread>; PRIORITIES_NUM]>,
}

impl Scheduler {
    pub const fn new() -> Self {
        const EMPTY_QUEUE: VecDeque<Thread> = VecDeque::new();

        Self {
            current_thread: Mutex::new(None),
            execution_queues: Mutex::new([EMPTY_QUEUE; PRIORITIES_NUM]),
        }
    }
}

impl Scheduler {
    pub fn run() -> ! {
        // Spawn periodic task responsible for preemption
        let nanos_since_boot = kernel_ref().clock().monotonic_ns();
        let next_wakeup = Duration::from_millis(500).as_nanos();

        let expires = nanos_since_boot + next_wakeup;

        ProcessorControlBlock::current()
            .hr_timers
            .get_mut()
            .add_timer(
                expires,
                true,
                Some(Duration::from_millis(500)),
                TimerAction::Reschedule,
            );

        loop {
            // Find new thread to execute.
            //
            // Execution queues is mutex-guarded array of vectors for each thread priority.
            // Priority 16 is more important than priority 15, so we need to take reversed iterator.
            let next_thread = kernel_ref()
                .scheduler
                .execution_queues
                .lock()
                .iter_mut()
                .rev()
                .find_map(|queue| queue.pop_front());

            // Check if next thread has been found - if no, then execute `hlt` instruction waiting for the next
            // timer tick.
            let thread = match next_thread {
                Some(trd) => trd,
                None => {
                    interrupts::enable_and_hlt();

                    continue;
                }
            };

            // Set newly elected thread as current
            *kernel_ref().scheduler.current_thread.lock() = Some(thread.clone());

            // Prepare processor context
            let process = thread.process();
            let entry = thread.entry();
            let stack = thread.stack();
            let is_kernel_mode = thread.is_kernel_mode();

            // Switch page table
            {
                let program_page_table_frame = PhysFrame::<Size4KiB>::from_start_address(
                    PhysAddr::new(process.0.page_table_physical_address),
                )
                .unwrap();

                unsafe { Cr3::write(program_page_table_frame, Cr3Flags::empty()) };
            }

            let stack_top = unsafe {
                (stack as *const u8)
                    .add(mem::size_of::<ThreadStack>())
                    .offset(-16)
            };

            // Begin thread execution
            if is_kernel_mode {
                enter_kernel_mode(entry as *const _, stack_top);
            } else {
                enter_user_mode(entry as *const _, stack_top);
            }
        }
    }
}

/// Manually triggers a context switch by simulating a software-induced interrupt.
///
/// This function is used for cooperative multitasking, allowing a thread
/// to voluntarily relinquish its remaining time slice and return control
/// to the scheduler.
///
/// When `INT YIELD_IRQ` is executed:
/// 1. The CPU automatically pushes the current Interrupt Stack Frame
///    (SS, RSP, RFLAGS, CS, and RIP) onto the stack.
/// 2. The CPU jumps to the interrupt handler registered for `YIELD_IRQ`.
/// 3. The handler executes the scheduling logic and switches the context.
///
pub extern "C" fn yield_to_scheduler() {
    unsafe {
        asm!(
            "int {irq}",
            irq = const YIELD_IRQ,
        )
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
        thread.set_status(Status::Waiting);

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
    kernel_ref()
        .scheduler
        .current_thread
        .lock()
        .as_ref()
        .unwrap()
        .clone()
}

pub fn has_current_thread() -> bool {
    kernel_ref().scheduler.current_thread.lock().is_some()
}

pub fn schedule(thread: Thread) {
    match thread.status() {
        Status::Running => {}
        Status::Stopped => return,
        Status::Waiting => return,
    }

    thread.0.reschedule.store(true, Ordering::SeqCst);

    let mut queues = kernel_ref().scheduler.execution_queues.lock();
    let priority = thread.priority().min(PRIORITIES_NUM - 1);
    let target_queue = &mut queues[priority];

    // Check if this thread isn't already scheduled to execute in its priority queue
    if !target_queue
        .iter()
        .any(|thread_in_queue| Arc::ptr_eq(&thread_in_queue.0, &thread.0))
    {
        target_queue.push_back(thread);
    }
}

pub fn run(registers: *mut Registers) {
    save_registers(registers);
    schedule_next_thread();
    restore_registers(registers);

    switch_to_current_thread_page_table();
}

fn switch_to_current_thread_page_table() {
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

    let mut queues = kernel_ref().scheduler.execution_queues.lock();

    let priority = thread.priority().min(PRIORITIES_NUM - 1);
    let target_queue = &mut queues[priority];

    let index = target_queue
        .iter()
        .position(|current_thread| Arc::ptr_eq(&thread.0, &current_thread.0));

    if let Some(index) = index {
        target_queue.remove(index);
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
    let mut current_thread = kernel_ref().scheduler.current_thread.lock();
    let mut queues = kernel_ref().scheduler.execution_queues.lock();

    // Handle thread that was executed previously
    if let Some(previous_thread) = current_thread.take() {
        // If it has reschedule flag set, add it to execution queue again
        if previous_thread.0.reschedule.load(Ordering::SeqCst) {
            let previous_priority = previous_thread.priority().min(PRIORITIES_NUM - 1);

            queues[previous_priority].push_back(previous_thread);
        }
    }

    // Find next thread to execute. We take reversed iterator, because priority 15 is higher than 14.
    let next_thread = queues.iter_mut().rev().find_map(|queue| queue.pop_front());

    *current_thread = next_thread;
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
