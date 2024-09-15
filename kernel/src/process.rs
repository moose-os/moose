use crate::{memory::PageTable, scheduler};
use alloc::{sync::Arc, vec::Vec};
use core::{
    ffi::c_void,
    sync::atomic::{AtomicBool, AtomicUsize},
};
use spin::{Mutex, MutexGuard};

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

    pub fn threads(&self) -> MutexGuard<Vec<Thread>> {
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

    pub fn id(&self) -> ThreadId {
        self.0.id
    }

    pub fn status(&self) -> Status {
        *self.0.status.lock()
    }

    pub fn set_status(&self, status: Status) {
        let mut current_status = self.0.status.lock();

        if *current_status == status {
            return;
        }

        match *current_status {
            Status::Running => match status {
                Status::Stopped => scheduler::unschedule(self),
                Status::Waiting { timeout: _ } => scheduler::unschedule(self),
                _ => {}
            },
            Status::Stopped => {
                if status == Status::Running {
                    scheduler::schedule(self.clone());
                }
            }
            Status::Waiting { timeout: _ } => {
                if status == Status::Running {
                    scheduler::schedule(self.clone());
                }
            }
        }

        *current_status = status;
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
}

unsafe impl Send for ThreadInner {}
unsafe impl Sync for ThreadInner {}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Running,
    Stopped,
    Waiting { timeout: Option<u64> },
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
