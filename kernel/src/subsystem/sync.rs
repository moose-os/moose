use core::{
    mem::ManuallyDrop,
    ops::{Deref, DerefMut},
};

use spin::{Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard, Spin};
use x86_64::instructions::interrupts;

struct IrqRestore {
    interrupts_were_enabled: bool,
}

impl IrqRestore {
    fn disable_and_capture() -> Self {
        let interrupts_were_enabled = interrupts::are_enabled();
        interrupts::disable();
        Self {
            interrupts_were_enabled,
        }
    }
}

impl Drop for IrqRestore {
    fn drop(&mut self) {
        if self.interrupts_were_enabled {
            interrupts::enable();
        }
    }
}

pub struct IrqGuardedMutex<T> {
    inner: Mutex<T>,
}

impl<T> IrqGuardedMutex<T> {
    pub const fn new(value: T) -> Self {
        Self {
            inner: Mutex::new(value),
        }
    }

    pub fn lock(&self) -> IrqGuardedMutexGuard<'_, T> {
        let irq_restore = IrqRestore::disable_and_capture();
        let guard = self.inner.lock();
        IrqGuardedMutexGuard { irq_restore, guard }
    }

    pub fn try_lock(&self) -> Option<IrqGuardedMutexGuard<'_, T>> {
        let irq_restore = IrqRestore::disable_and_capture();
        let guard = self.inner.try_lock()?;
        Some(IrqGuardedMutexGuard { irq_restore, guard })
    }

    pub fn force_unlock(&self) {
        unsafe { self.inner.force_unlock() };
    }
}

pub struct IrqGuardedMutexGuard<'a, T> {
    irq_restore: IrqRestore,
    guard: MutexGuard<'a, T, Spin>,
}

impl<T> Deref for IrqGuardedMutexGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.guard
    }
}

impl<T> DerefMut for IrqGuardedMutexGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.guard
    }
}

impl<T: core::fmt::Debug> core::fmt::Debug for IrqGuardedMutex<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.inner.try_lock() {
            Some(guard) => core::fmt::Debug::fmt(&*guard, f),
            None => f.write_str("IrqGuardedMutex { <locked> }"),
        }
    }
}

pub struct IrqGuardedRwLock<T> {
    inner: RwLock<T>,
}

impl<T> IrqGuardedRwLock<T> {
    pub const fn new(value: T) -> Self {
        Self {
            inner: RwLock::new(value),
        }
    }

    pub fn read(&self) -> IrqGuardedRwLockReadGuard<'_, T> {
        let irq_restore = IrqRestore::disable_and_capture();
        let guard = self.inner.read();
        IrqGuardedRwLockReadGuard { irq_restore, guard }
    }

    pub fn write(&self) -> IrqGuardedRwLockWriteGuard<'_, T> {
        let irq_restore = IrqRestore::disable_and_capture();
        let guard = self.inner.write();
        IrqGuardedRwLockWriteGuard {
            guard: ManuallyDrop::new(guard),
            irq_restore: ManuallyDrop::new(irq_restore),
        }
    }

    pub fn try_read(&self) -> Option<IrqGuardedRwLockReadGuard<'_, T>> {
        let irq_restore = IrqRestore::disable_and_capture();
        let guard = self.inner.try_read()?;
        Some(IrqGuardedRwLockReadGuard { irq_restore, guard })
    }

    pub fn try_write(&self) -> Option<IrqGuardedRwLockWriteGuard<'_, T>> {
        let irq_restore = IrqRestore::disable_and_capture();
        let guard = self.inner.try_write()?;
        Some(IrqGuardedRwLockWriteGuard {
            guard: ManuallyDrop::new(guard),
            irq_restore: ManuallyDrop::new(irq_restore),
        })
    }
}

pub struct IrqGuardedRwLockReadGuard<'a, T> {
    irq_restore: IrqRestore,
    guard: RwLockReadGuard<'a, T, Spin>,
}

impl<T> Deref for IrqGuardedRwLockReadGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.guard
    }
}

pub struct IrqGuardedRwLockWriteGuard<'a, T> {
    guard: ManuallyDrop<RwLockWriteGuard<'a, T>>,
    irq_restore: ManuallyDrop<IrqRestore>,
}

impl<T> Deref for IrqGuardedRwLockWriteGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.guard
    }
}

impl<T> DerefMut for IrqGuardedRwLockWriteGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.guard
    }
}

impl<T> Drop for IrqGuardedRwLockWriteGuard<'_, T> {
    fn drop(&mut self) {
        unsafe {
            ManuallyDrop::drop(&mut self.guard);
            ManuallyDrop::drop(&mut self.irq_restore);
        }
    }
}
