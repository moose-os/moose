use alloc::{sync::Arc, vec::Vec};
use core::{alloc::Layout, ffi::c_void, sync::atomic::AtomicBool};

use spin::{Mutex, MutexGuard, Spin};

use crate::{
    arch::x86::cpu::ProcessorControlBlock,
    kernel::kernel_ref,
    subsystem::{
        clock::{time::Duration, timer::TimerAction},
        memory::PageTable,
        scheduler::{self, PRIORITIES_NUM},
    },
};

/// Default priority assigned to new threads (middle of the range).
pub const DEFAULT_THREAD_PRIORITY: usize = PRIORITIES_NUM / 2;

/// Minimum execution priority (least urgent).
pub const LOWEST_THREAD_PRIORITY: usize = 0;

/// Maximum execution priority (most urgent).
pub const HIGHEST_THREAD_PRIORITY: usize = PRIORITIES_NUM - 1;

pub type ProcessId = usize;

#[derive(Clone)]
pub struct Process(pub(crate) Arc<ProcessInner>);

impl Process {
    pub fn id(&self) -> ProcessId {
        self.0.id
    }

    pub fn threads(&self) -> MutexGuard<'_, Vec<Thread>, Spin> {
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
        let current_status = *self.0.status.lock();
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
        let nanos_since_boot = kernel_ref().clock().monotonic_ns();
        let sleep_in_nanos = Duration::from_millis(time_in_ms as u64).as_nanos();

        let expires = nanos_since_boot + sleep_in_nanos;

        // @TODO: Better timers distribution?
        let _ = ProcessorControlBlock::current()
            .hr_timers
            .get_mut()
            .add_timer(
                expires,
                false,
                None,
                TimerAction::WakeUp {
                    process_id: self.process().id(),
                    thread_id: self.id(),
                },
            );

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
    pub fn new() -> Self {
        Self([0; 16 * 1024])
    }

    #[inline]
    pub unsafe fn allocate() -> *mut ThreadStack {
        (unsafe { alloc::alloc::alloc_zeroed(Layout::new::<ThreadStack>()) }) as *mut ThreadStack
    }
}

#[derive(Clone, Debug, Default)]
#[repr(C)]
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
    pub(crate) cs: u64,
    pub(crate) ss: u64,
    pub(crate) fs: u64,
    pub(crate) gs: u64,
    pub(crate) padding_: u64,
}
