//! Hyper-V VMBus Synthetic Devices Core Infrastructure.
//!
//! This module defines the foundational abstractions, traits, and shared data
//! structures used by all Hyper-V Synthetic Devices (VSP/VSC pairs) running
//! over the VMBus transport layer.
//!
//! Submodules implement specialized device drivers ranging from input peripherals
//! to high-performance networking and graphics.

use core::any::Any;

pub mod disk;
pub mod gpu;
pub mod integration;
pub mod keyboard;
pub mod mouse;
pub mod nic;

/// Core interface implemented by all Hyper-V synthetic devices.
///
/// Every virtual device managed via the VMBus protocol must implement this trait
/// to tie into the kernel's central device polling, interrupt dispatching,
/// and initialization lifecycles.
pub trait VmBusSyntheticDevice: Any + Sync + Send {
    /// Initializes the synthetic device hardware state and sets up basic handshake protocols.
    ///
    /// Returns `true` if the device was successfully probed, negotiated, and marked active.
    fn initialize(&self) -> bool;

    /// Checks if the underlying VMBus ring buffers contain pending data packets
    /// awaiting consumption by the driver.
    fn has_data_to_process(&self) -> bool;

    /// Drains the incoming VMBus ring buffer and dispatches packets to their
    /// respective subsystem handlers (e.g., input events, network frames, frame buffers).
    fn process_incoming_data(&self);

    /// Handles the revocation of the channel by the host, safely terminating
    /// active I/O operations and initiating the subsystem teardown sequence.
    fn on_rescind(&self) {
        panic!("Rescind offer")
    }
}

/// Represents the dimensional resolution of a display or framebuffer context.
#[derive(Copy, Clone, Debug)]
pub struct Resolution {
    /// The horizontal width specified in pixels.
    pub width: usize,

    /// The vertical height specified in pixels.
    pub height: usize,
}

/// Defines a bounding box around a modified or "dirty" sub-region of a screen matrix.
///
/// Utilized in synthetic graphics ([`gpu`]) to optimize
/// VMBus throughput by transmitting only the specific pixel regions that
/// have mutated since the last frame update.
pub struct DirtyRectangle {
    /// The left-most X coordinate (inclusive boundary).
    x1: i32,
    /// The top-most Y coordinate (inclusive boundary).
    y1: i32,

    /// The right-most X coordinate (exclusive boundary).
    x2: i32,
    /// The bottom-most Y coordinate (exclusive boundary).
    y2: i32,
}
