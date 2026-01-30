use core::{
    arch::{asm, naked_asm},
    mem,
    sync::atomic::Ordering,
};

use alloc::{collections::VecDeque, sync::Arc, vec::Vec};
use spin::{once::Once, Mutex};
use x86_64::{
    instructions::interrupts,
    registers::control::{Cr3, Cr3Flags},
    structures::paging::{PhysFrame, Size4KiB},
    PhysAddr,
};

use crate::process::{Registers, Status, Thread, ThreadStack};

static SCHEDULER: Scheduler = Scheduler::new();

/// A global queue for threads waiting on a timed sleep or timeout.
///
/// ### Data Structure:
/// Entry in the vector is a tuple of `(usize, Thread)`:
/// * `usize`: The absolute tick count at which the timeout expires.
/// * `Thread`: The handle or descriptor of the thread to be woken up.
pub static TIMEOUT_QUEUE: Once<Mutex<VecDeque<(u64, Thread)>>> = Once::new();

pub const PRIORITIES_NUM: usize = 16;

pub struct Scheduler {
    current_thread: Mutex<Option<Thread>>,
    execution_queues: Mutex<[VecDeque<Thread>; PRIORITIES_NUM]>,
}

impl Scheduler {
    const fn new() -> Self {
        const EMPTY_QUEUE: VecDeque<Thread> = VecDeque::new();

        Self {
            current_thread: Mutex::new(None),
            execution_queues: Mutex::new([EMPTY_QUEUE; PRIORITIES_NUM]),
        }
    }
}

impl Scheduler {
    pub fn run() -> ! {
        if !TIMEOUT_QUEUE.is_completed() {
            TIMEOUT_QUEUE.call_once(|| Mutex::new(VecDeque::new()));
        }

        loop {
            // Find new thread to execute.
            //
            // Execution queues is mutex-guarded array of vectors for each thread priority.
            // Priority 16 is more important than priority 15, so we need to take reversed iterator.
            let next_thread = SCHEDULER
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
            *SCHEDULER.current_thread.lock() = Some(thread.clone());

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

/// Manually triggers a context switch by simulating a hardware timer interrupt.
///
/// This function is used for cooperative multitasking. It allows a thread (especially kernel mode thread)
/// to voluntarily give up its remaining time slice and return control to the scheduler.
///
/// ### Mechanism
/// Since the system's interrupt handler (`raw_timer_interrupt_handler`) expects the CPU
/// to have pushed an **Interrupt Stack Frame** (due to a hardware event), this function
/// manually constructs that frame on the current stack before jumping to the handler.
/// It's the easiest solution possible.
///
/// The constructed stack frame follows the x86_64 ABI requirements for an `IRETQ` instruction:
///
/// | Value      | Description                                                |
/// | :--------- | :--------------------------------------------------------- |
/// | **SS**     | Stack Segment selector                                     |
/// | **RSP**    | Stack Pointer (pointing to the instruction after the call) |
/// | **RFLAGS** | Processor flags (captured at the moment of call)           |
/// | **CS**     | Code Segment selector                                      |
/// | **RIP**    | Instruction Pointer (the return address)                   |
///
#[unsafe(naked)]
pub extern "C" fn yield_to_scheduler() {
    naked_asm!(
        "mov rcx, [rsp]",

        "pushfq",
        "pop rax",

        "lea rdx, [rsp + 8]",

        "mov r8, ss",
        "push r8",         // SS
        "push rdx",        // RSP
        "push rax",        // RFLAGS
        "mov r8, cs",
        "push r8",         // CS
        "push rcx",        // RIP

        "jmp {raw_handler}",

        raw_handler = sym crate::driver::apic::raw_timer_interrupt_handler,
    )
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
    SCHEDULER.current_thread.lock().as_ref().unwrap().clone()
}

pub fn schedule(thread: Thread) {
    match thread.status() {
        Status::Running => {}
        Status::Stopped => return,
        Status::Waiting => return,
    }

    thread.0.reschedule.store(true, Ordering::SeqCst);

    let mut queues = SCHEDULER.execution_queues.lock();
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

    let mut queues = SCHEDULER.execution_queues.lock();

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
    let mut current_thread = SCHEDULER.current_thread.lock();
    let mut queues = SCHEDULER.execution_queues.lock();

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
