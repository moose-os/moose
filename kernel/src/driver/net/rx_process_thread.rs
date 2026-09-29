//! RX bottom-half worker.
//!
//! The NIC driver's own bottom half (see e.g. `VmBusNic::handle_rndis_message`)
//! copies each incoming Ethernet frame into a preallocated slot here and
//! wakes this thread; protocol processing (Ethernet → IP → TCP/UDP/...) then
//! runs entirely in this thread's own context, never in the driver's.
//!
//! Sending is no longer something this thread has to coordinate. TCP (and
//! everything else) hands frames to a per-interface `InterfaceTxQueue`,
//! which never blocks the caller -- so protocol processing here can send
//! ACKs, retransmits, and outgoing data directly, inline, wherever the
//! decision to send one is made. There's no separate flush pass.

use alloc::collections::VecDeque;

use crate::{
    driver::net::{
        NetworkInterfaceId,
        proto::{DEFAULT_HEADER_RESERVE, PacketBuffer, SLOT_SIZE},
    },
    kernel::kernel_ref,
    subsystem::{scheduler::OneshotGate, sync::IrqGuardedMutex},
};

const RX_STORAGE_SIZE: usize = DEFAULT_HEADER_RESERVE + SLOT_SIZE;
const RX_SLOTS: usize = 128;

struct RxSlot {
    interface_id: NetworkInterfaceId,
    len: usize,
    storage: [u8; RX_STORAGE_SIZE],
}

pub struct RxProcessThread {
    queue: IrqGuardedMutex<VecDeque<RxSlot>>,
    wake: OneshotGate,
}

impl RxProcessThread {
    pub fn new() -> Self {
        let mut queue = VecDeque::new();
        // IRQ `enqueue_frame` must not grow the deque (no heap in interrupt context).
        queue.reserve_exact(RX_SLOTS);
        Self {
            queue: IrqGuardedMutex::new(queue),
            wake: OneshotGate::new(),
        }
    }

    /// Driver-side bottom half: copy a received frame into a preallocated
    /// slot and wake the worker. Frames larger than a slot, or empty
    /// frames, are dropped here rather than queued.
    ///
    /// Safe to call from IRQ provided the queue was reserved at init.
    pub fn enqueue_frame(&self, interface_id: NetworkInterfaceId, frame: &[u8]) {
        if frame.is_empty() || frame.len() > SLOT_SIZE {
            return;
        }

        {
            let mut queue = self.queue.lock();
            if queue.len() >= RX_SLOTS {
                log::warn!("RX queue full, dropping frame len={}", frame.len());
            } else {
                let mut slot = RxSlot {
                    interface_id,
                    len: frame.len(),
                    storage: [0u8; RX_STORAGE_SIZE],
                };
                let dst =
                    &mut slot.storage[DEFAULT_HEADER_RESERVE..DEFAULT_HEADER_RESERVE + frame.len()];
                dst.copy_from_slice(frame);
                debug_assert!(queue.capacity() >= RX_SLOTS);
                queue.push_back(slot);
            }
        }

        // Always open — including on drop — so a sleeping worker cannot miss
        // a full queue (bare Event notify-before-wait used to lose that wake).
        self.wake.open();
    }

    /// Driver-side bottom half: wake the RX worker to drain the VMBus ring
    /// in thread context, without going through the software queue above
    /// (used when the driver just needs the ring polled again, e.g. after a
    /// TX-completion interrupt that also carries RX work).
    pub fn wake_for_vmbus(&self) {
        self.wake.open();
    }

    pub fn worker_loop(&self) -> ! {
        loop {
            // Pop under the lock, then drop the guard before process_data.
            // Keeping the guard alive across the whole `if let` body (Rust
            // temporary lifetime) deadlocks when TCP TX re-enters enqueue_frame.
            let slot = { self.queue.lock().pop_front() };
            if let Some(mut slot) = slot {
                let mut packet = PacketBuffer::from_received_slot(
                    &mut slot.storage,
                    DEFAULT_HEADER_RESERVE,
                    slot.len,
                );

                let ns = kernel_ref().network_subsystem();
                let _ = ns.ethernet().process_data(&mut packet, slot.interface_id);
                continue;
            }

            // Arm for the next open(). Re-drain + re-check so enqueue /
            // wake_for_vmbus that raced with the empty pop is not lost.
            unsafe { self.wake.reset() };

            if !self.queue.lock().is_empty() || self.wake.is_open() {
                continue;
            }

            self.wake.wait();
        }
    }
}

extern "C" fn rx_worker(_arg: u64) -> ! {
    kernel_ref()
        .network_subsystem()
        .rx_process_thread()
        .worker_loop();
}

/// Spawns the RX bottom-half worker (call once during network init).
pub fn spawn_rx_worker() {
    kernel_ref().network_subsystem().set_rx_worker_active(true);
    kernel_ref()
        .spawn_kernel_thread(rx_worker, 0, 13)
        .expect("RX worker thread");
}
