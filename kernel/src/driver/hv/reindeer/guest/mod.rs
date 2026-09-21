//! Architectural and execution state management for guest vCPUs.
//!
//! This module encapsulates all hardware-agnostic vCPU state structures, registers
//! and software emulation modules. It bridges the gap between
//! hardware-specific hypervisor backends (Intel VT-x and AMD-V) and the common VMM core.

pub mod bios;
pub mod boot;
pub mod clock;
pub mod initial_state;
pub mod mmio_decode;
pub mod paging;
pub mod registers;
