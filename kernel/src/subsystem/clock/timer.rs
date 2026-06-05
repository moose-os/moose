//! Per-CPU high-resolution timer queue for kernel deadlines.
//!
//! [`HrTimerSubsystem`] stores timers in an expiry-ordered red-black tree keyed by
//! absolute nanoseconds since boot. When a new timer becomes the nearest deadline,
//! it reprograms the local APIC one-shot timer.
//!
//! Expired timers are drained by [`HrTimerSubsystem::poll_expired`] from the LAPIC
//! interrupt handler and dispatched as [`TimerAction`]:
//!
//! - [`TimerAction::Reschedule`] — scheduler preemption
//! - [`TimerAction::WakeUp`] — resume a sleeping thread
//! - [`TimerAction::ExecuteCallback`] — run a kernel callback
//!
//! Periodic timers are automatically re-queued after firing. Each CPU owns its own
//! [`HrTimerSubsystem`] in [`ProcessorControlBlock::hr_timers`].
//!
use common::rb_tree::RedBlackTree;
use core::cmp::Ordering;
use generational_arena::Index as ArenaIndex;

use crate::{
    arch::x86::cpu::ProcessorControlBlock,
    kernel::kernel_ref,
    subsystem::{
        clock::time::Duration,
        process::{ProcessId, ThreadId},
    },
};

/// Opaque handle returned when a timer is registered; used to cancel it later.
pub type TimerHandle = ArenaIndex;

/// Function invoked when a timer fires via [`TimerAction::ExecuteCallback`].
///
/// The return value tells the caller whether to reschedule; the subsystem does
/// not interpret it automatically (use [`Timer::is_periodic`] for that).
pub type TimerCallback = fn(expires_at: u64) -> TimerAction;

/// Timer.
#[derive(Clone)]
pub struct Timer {
    /// Absolute expiry time in nanoseconds since boot.
    pub expires_at: u64,

    /// Whether the subsystem should re-queue this timer after it fires.
    pub is_periodic: bool,

    /// Period between firings; required when [`Timer::is_periodic`] is true.
    pub interval: Option<Duration>,

    /// What the executor should do when this timer is dispatched.
    pub action: TimerAction,
}

/// Action associated with a timer at expiry.
#[derive(Clone)]
pub enum TimerAction {
    /// Run `function` with the expiry timestamp.
    ExecuteCallback { function: TimerCallback },

    /// Special timer action dedicated for the scheduler.
    Reschedule,

    /// Wake the given thread.
    WakeUp {
        process_id: ProcessId,
        thread_id: ThreadId,
    },
}

/// High-resolution timer queue backed by a generational red-black tree.
pub struct HrTimerSubsystem {
    /// Expiry-ordered timer map. Keys are unique per registration.
    queue: RedBlackTree<TimerQueueKey, Timer>,

    /// Monotonic tie-breaker so equal `expires_at` values remain distinct keys.
    next_order: u64,
}

/// Sort key: primary `expires_at`, secondary registration order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TimerQueueKey {
    expires_at: u64,
    order: u64,
}

impl PartialOrd for TimerQueueKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for TimerQueueKey {
    fn cmp(&self, other: &Self) -> Ordering {
        self.expires_at
            .cmp(&other.expires_at)
            .then_with(|| self.order.cmp(&other.order))
    }
}

impl HrTimerSubsystem {
    /// Creates an empty timer subsystem.
    pub fn new() -> Self {
        Self {
            queue: RedBlackTree::new(),
            next_order: 0,
        }
    }

    /// Registers a timer and returns a stable [`TimerHandle`].
    ///
    /// `expires` is the absolute expiry in nanoseconds since boot.
    /// When `is_periodic` is true, `interval` must be [`Some`]; periodic timers are
    /// automatically re-queued by [`Self::poll_expired`].
    pub fn add_timer(
        &mut self,
        expires: u64,
        is_periodic: bool,
        interval: Option<Duration>,
        action: TimerAction,
    ) -> TimerHandle {
        assert!(
            !is_periodic || interval.is_some(),
            "periodic timer requires an interval"
        );

        if self
            .next_expiry()
            .map(|next| next < expires)
            .unwrap_or_default()
            || self.next_expiry().is_none()
        {
            let clock = kernel_ref().clock();
            let current = clock.monotonic_ns();
            let diff = expires - current;

            ProcessorControlBlock::current()
                .local_apic
                .get()
                .unwrap()
                .set_timer(clock.ns_to_apic_ticks(diff));
        }

        self.insert_timer(expires, is_periodic, interval, action)
    }

    /// Removes one timer that expires at `expires` (earliest registered among ties).
    ///
    /// Returns `true` if a timer was removed.
    pub fn remove_timer(&mut self, expires: u64) -> bool {
        let Some(key) = self.find_first_key_at_expiry(expires) else {
            return false;
        };

        self.queue.remove(&key).is_some()
    }

    /// Cancels the timer identified by `handle`.
    ///
    /// Returns `true` if the handle was valid and the entry was removed.
    pub fn cancel(&mut self, handle: TimerHandle) -> bool {
        let Some(key) = self.queue_key_of(handle) else {
            return false;
        };

        self.queue.remove(&key).is_some()
    }

    /// Returns a timer that expires at `expires`, if any.
    ///
    /// When several timers share that instant, the one with the smallest
    /// registration order is returned.
    pub fn find(&self, expires: u64) -> Option<&Timer> {
        let key = self.find_first_key_at_expiry(expires)?;

        self.queue.get(&key)
    }

    /// Returns the expiry time of the soonest timer in the queue, if non-empty.
    pub fn next_expiry(&self) -> Option<u64> {
        self.queue.min().map(|key| key.expires_at)
    }

    /// Number of active timers.
    pub fn len(&self) -> usize {
        self.queue.len()
    }

    /// Returns `true` if there are no active timers.
    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    /// Removes and returns the soonest timer whose expiry is at or before `now`.
    ///
    /// Returns `None` if the queue is empty or every timer expires after `now`.
    pub fn poll_expired(&mut self, now: u64) -> Option<Timer> {
        let key = self.earliest_expired_key(now)?;
        let timer = self.queue.remove(&key)?;

        self.reinsert_periodic(&timer);

        Some(timer)
    }

    fn insert_timer(
        &mut self,
        expires_at: u64,
        is_periodic: bool,
        interval: Option<Duration>,
        action: TimerAction,
    ) -> TimerHandle {
        let key = TimerQueueKey {
            expires_at,
            order: self.next_order,
        };

        self.next_order = self.next_order.wrapping_add(1);

        let timer = Timer {
            expires_at,
            is_periodic,
            interval,
            action,
        };

        self.queue.insert(key, timer)
    }

    fn min_key(&self) -> Option<TimerQueueKey> {
        self.queue.min().copied()
    }

    fn earliest_expired_key(&self, now: u64) -> Option<TimerQueueKey> {
        let key = self.min_key()?;
        if key.expires_at <= now {
            Some(key)
        } else {
            None
        }
    }

    fn queue_key_of(&self, handle: TimerHandle) -> Option<TimerQueueKey> {
        self.queue.arena_get(handle).map(|node| node.key)
    }

    fn find_first_key_at_expiry(&self, expires_at: u64) -> Option<TimerQueueKey> {
        let mut found = None;

        self.queue.for_each_in_order(|key, _| {
            if found.is_none() && key.expires_at == expires_at {
                found = Some(*key);
            }
        });

        found
    }

    fn reinsert_periodic(&mut self, fired: &Timer) {
        if !fired.is_periodic {
            return;
        }

        let Some(interval) = fired.interval else {
            debug_assert!(false, "periodic timer missing interval");
            return;
        };

        let next_expires = fired.expires_at.saturating_add(interval.as_nanos());

        let _ = self.insert_timer(
            next_expires,
            fired.is_periodic,
            fired.interval,
            fired.action.clone(),
        );
    }
}

impl Default for HrTimerSubsystem {
    fn default() -> Self {
        Self::new()
    }
}
