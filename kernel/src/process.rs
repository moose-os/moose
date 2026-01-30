use crate::{
    kernel::kernel_ref,
    memory::PageTable,
    scheduler::{self, PRIORITIES_NUM, TIMEOUT_QUEUE},
};
use alloc::{sync::Arc, vec::Vec};
use core::{
    ffi::c_void,
    sync::atomic::{AtomicBool, AtomicUsize},
};
use spin::{Mutex, MutexGuard};

/// Default priority assigned to new threads (middle of the range).
pub const DEFAULT_THREAD_PRIORITY: usize = PRIORITIES_NUM / 2;

/// Minimum execution priority (least urgent).
pub const LOWEST_THREAD_PRIORITY: usize = 0;

/// Maximum execution priority (most urgent).
pub const HIGHEST_THREAD_PRIORITY: usize = PRIORITIES_NUM - 1;

static CURRENT_USABLE_PROCESS_ID: AtomicUsize = AtomicUsize::new(0);
static CURRENT_USABLE_THREAD_ID: AtomicUsize = AtomicUsize::new(0);

static mut PROCESSES: Vec<Process> = Vec::new();

pub type ProcessId = usize;

#[derive(Clone)]
pub struct Process(pub(crate) Arc<ProcessInner>);

impl Process {
    pub fn id(&self) -> ProcessId {
        self.0.id
    }

    pub fn threads(&self) -> MutexGuard<'_, Vec<Thread>> {
        self.0.threads.lock()
    }
}

pub(crate) struct ProcessInner {
    pub(crate) id: ProcessId,
    pub(crate) page_table: *mut PageTable,
    pub(crate) page_table_physical_address: u64,
    pub(crate) threads: Mutex<Vec<Thread>>,
}

unsafe impl Send for ProcessInner {}
unsafe impl Sync for ProcessInner {}

pub type ThreadId = usize;

#[derive(Clone)]
pub struct Thread(pub(crate) Arc<ThreadInner>);

impl Thread {
    pub fn process(&self) -> &Process {
        &self.0.process
    }

    pub fn priority(&self) -> usize {
        self.0.priority
    }

    pub fn id(&self) -> ThreadId {
        self.0.id
    }

    pub fn status(&self) -> Status {
        *self.0.status.lock()
    }

    pub fn set_status(&self, new_status: Status) {
        let current_status = self.0.status.lock().clone();
        *self.0.status.lock() = new_status;

        match current_status {
            Status::Running => match new_status {
                Status::Stopped | Status::Waiting => scheduler::unschedule(self),
                _ => {}
            },
            Status::Stopped | Status::Waiting => {
                if new_status == Status::Running {
                    scheduler::schedule(self.clone());
                }
            }
        }
    }

    pub fn sleep(&self, time_in_ms: usize) {
        // Need to convert relative time in miliseconds to absolute kernel tick count
        let sleep_time_in_ticks = time_in_ms as u64 / kernel_ref().apic.read().ms_per_tick;
        let expiration_time = kernel_ref()
            .ticks
            .load(core::sync::atomic::Ordering::SeqCst)
            + sleep_time_in_ticks;

        // Insert thread to TIMEOUT_QUEUE and change its status to Status::Waiting
        if let Some(mutex) = TIMEOUT_QUEUE.get() {
            let mut queue = mutex.lock();

            // Find the correct position for the new timeout.
            // If multiple threads have the same expiration, this inserts after them.
            let position = queue
                .binary_search_by(|(expiration_tick_count, _)| {
                    expiration_tick_count.cmp(&expiration_time)
                })
                .unwrap_or_else(|e| e);

            queue.insert(position, (expiration_time, self.clone()));
        }

        self.set_status(Status::Waiting);
    }

    pub(crate) fn entry(&self) -> *const c_void {
        self.0.entry
    }

    pub(crate) fn stack(&self) -> *mut ThreadStack {
        self.0.stack
    }

    pub(crate) fn is_kernel_mode(&self) -> bool {
        self.0.is_kernel_mode
    }
}

pub(crate) struct ThreadInner {
    pub(crate) process: Process,
    pub(crate) id: ThreadId,
    pub(crate) status: Mutex<Status>,
    pub(crate) entry: *const c_void,
    pub(crate) registers: Mutex<Registers>,
    pub(crate) stack: *mut ThreadStack,
    pub(crate) is_kernel_mode: bool,
    pub(crate) reschedule: AtomicBool,
    pub(crate) priority: usize,
}

unsafe impl Send for ThreadInner {}
unsafe impl Sync for ThreadInner {}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Running,
    Stopped,
    Waiting,
}

#[repr(C)]
#[repr(align(4096))]
pub(crate) struct ThreadStack([u8; 16 * 1024]);

impl ThreadStack {
    fn new() -> Self {
        Self([0; 16 * 1024])
    }
}

#[derive(Clone, Debug, Default)]
#[repr(C, packed)]
pub struct Registers {
    pub(crate) rax: u64,
    pub(crate) rbx: u64,
    pub(crate) rcx: u64,
    pub(crate) rdx: u64,
    pub(crate) rsi: u64,
    pub(crate) rdi: u64,
    pub(crate) rbp: u64,
    pub(crate) rsp: u64,
    pub(crate) r8: u64,
    pub(crate) r9: u64,
    pub(crate) r10: u64,
    pub(crate) r11: u64,
    pub(crate) r12: u64,
    pub(crate) r13: u64,
    pub(crate) r14: u64,
    pub(crate) r15: u64,
    pub(crate) rip: u64,
    pub(crate) rflags: u64,
    pub(crate) cs: u16,
    pub(crate) ss: u16,
    pub(crate) fs: u64,
    pub(crate) gs: u64,
}
