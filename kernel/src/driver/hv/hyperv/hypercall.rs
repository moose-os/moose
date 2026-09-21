//! # Hypercalls
//!
//! This module implements hypercalls — the low-level interface between the guest
//! and the Hyper-V hypervisor.
//!
//! ## What are Hypercalls?
//!
//! A *hypercall* is a special call from a guest partition (VM) to the Hyper-V hypervisor,
//! similar to a system call but for virtualization.
//!
//! Hypercalls allow the guest to request privileged services from the hypervisor that
//! are not directly accessible via normal instructions.
//!
//! Examples include:
//! - Posting messages to VMBus
//! - Signaling events
//!
//! ---
//!
//! ## How Hypercalls Work
//!
//! - Hypercalls are made by writing arguments to specific registers or memory locations,
//!   then executing a `call` instrution to the start of Hypercall Page.
//! - On Hyper-V, the Hypercall Page is provided by the guest to the host,
//!   allowing fast calls through a predefined memory location instead of a slow trap (like `VMCALL`/`VMMCALL`).
//!
//! Typical Steps:
//! 1. Guest set the address of the hypercall page.
//! 2. Guest prepares parameters and stores them in registers.
//! 3. Guest executes a hypercall opcode.
//! 4. Hypervisor processes the request and writes back a result.
//!
//! ---
//!
//! ## VMBus and Hypercalls
//!
//! VMBus operations often rely on hypercalls for efficient signaling:
//!
//! - **Post Message Hypercall**
//!   Used to send small control messages to the host (e.g., to notify about new data).
//!
//! - **Signal Event Hypercall**
//!   Used to notify the host that something is ready to be processed (e.g., buffer filled).
//!
//! These calls bypass the slower interrupt injection mechanism and directly alert the host.
//!
//! ---
//!
//! ## Notes
//!
//! - Hypercalls are the lowest-level API to interact with Hyper-V from the guest.
//! - They are essential for efficient device communication (VMBus, synthetic devices).
//! - This module abstracts argument passing, and calling sequence to make
//!   usage safer and easier from Rust code.

use crate::subsystem::memory::PhysicalAddress;

/// Represents a raw 64-bit hypercall input value.
pub type HypercallInput = u64;

unsafe extern "C" {
    /// Performs a raw Hyper-V hypercall.
    ///
    /// This issues a hypercall by writing to the hypercall page with the specified
    /// input values. The exact semantics of the call are determined by the `input`
    /// control code.
    ///
    /// # Parameters
    /// - `input`: Hypercall control value (includes call code and input/output sizes).
    /// - `input_parameters`: Guest physical address (GPA) of the input parameter block.
    /// - `output_parameters`: GPA of the output parameter block.
    /// - `hypercall_page`: GPA of the hypercall page mapped by the guest.
    ///
    /// # Returns
    /// The raw return status from the hypercall (as defined by the Hyper-V spec).
    ///
    /// # Safety
    /// - This function directly triggers a Hyper-V hypercall and is inherently unsafe.
    /// - Caller must ensure:
    ///   - The `hypercall_page` GPA is correctly set up by `HvCallSetHypercallPage`.
    ///   - Input and output parameter GPAs are valid and accessible to the hypervisor.
    ///   - The CPU is in a valid state to perform a hypercall.
    ///
    /// # References
    /// - Hyper-V Hypercall Interface Specification
    fn _do_hypercall(
        input: u64,
        input_parameters: u64,
        output_parameters: u64,
        hypercall_page: u64,
    ) -> u64;

    /// Performs a raw Hyper-V fast hypercall.
    ///
    /// A fast hypercall uses registers for parameters instead of a parameter page,
    /// reducing overhead when only a small amount of data needs to be passed.
    ///
    /// # Parameters
    /// - `input`: Hypercall control value (includes call code and parameter size).
    /// - `data`: Packed data for the hypercall.
    /// - `hypercall_page`: GPA of the hypercall page mapped by the guest.
    ///
    /// # Returns
    /// The raw return status from the hypercall (as defined by the Hyper-V spec).
    ///
    /// # Safety
    /// - This function directly triggers a Hyper-V hypercall and is inherently unsafe.
    /// - Caller must ensure:
    ///   - The `hypercall_page` GPA is correctly set up by `HvCallSetHypercallPage`.
    ///   - `data` fits the expected encoding for the requested hypercall.
    ///   - CPU state allows execution of hypercalls.
    pub fn _do_fast_hypercall(input: u64, data: u64, hypercall_page: u64) -> u64;
}

/// Creates a packed [`HypercallInput`] according to the Hyper-V TLFS.
///
/// The bit layout (from TLFS 3.7 “Hypercall Inputs”):
///
/// ```text
/// +--------------------------------------------------------------------------------------+
/// | 63:60 |           59:48 | 47:44 |     43:32 | 31:27 |       26:17 |   16 | 15:0      |
/// | Rsvd  | Rep start index | Rsvd  | Rep count | Rsvd  | Header size | Fast | Call code |
/// +--------------------------------------------------------------------------------------+
/// ```
///
/// # Parameters
/// - `rep_start_index`: Repetition start index (must fit in 12 bits: 0–0xFFF).
/// - `rep_count`: Number of repetitions (must fit in 12 bits: 0–0xFFF).
/// - `header_size`: Header size in 16-byte units (must fit in 10 bits: 0–0x3FF).
/// - `fast`: Whether this is a fast hypercall (bit 16).
/// - `call_code`: Hypercall code (bits 0–15).
///
/// # Panics
/// Panics if any parameter exceeds its allowed bit width.
///
/// # Returns
/// A [`HypercallInput`] ready to be used in `_do_hypercall` or `_do_fast_hypercall`.
pub fn create_hypercall_input(
    rep_start_index: u16,
    rep_count: u16,
    header_size: u16,
    fast: bool,
    call_code: u16,
) -> HypercallInput {
    assert!(rep_start_index < (1 << 12), "rep_start_index too large");
    assert!(rep_count < (1 << 12), "rep_count too large");
    assert!(header_size < (1 << 10), "header_size too large");

    let rep_start_index = rep_start_index as u64;
    let rep_count = rep_count as u64;
    let header_size = header_size as u64;
    let call_code = call_code as u64;

    let value = (rep_start_index << 48)
        | (rep_count << 32)
        | (header_size << 17)
        | ((fast as u64) << 16)
        | call_code;

    value as HypercallInput
}

/// Issues a standard (non-fast) Hyper-V hypercall.
///
/// This is a safe wrapper over [`_do_hypercall`], taking typed
/// [`HypercallInput`] and [`PhysicalAddress`] arguments instead of raw `u64`s.
///
/// # Parameters
/// - `input`: The [`HypercallInput`] value constructed via [`create_hypercall_input`].
/// - `input_parameters`: Physical address of the input parameter block.
/// - `output_parameters`: Physical address of the output parameter block.
/// - `hypercall_page`: Physical address of the mapped hypercall page.
///
/// # Returns
/// The raw status code returned by the hypercall.
pub unsafe fn hypercall(
    input: HypercallInput,
    input_parameters: PhysicalAddress,
    output_parameters: PhysicalAddress,
    hypercall_page: u64,
) -> u64 {
    unsafe {
        _do_hypercall(
            input,
            input_parameters.as_u64(),
            output_parameters.as_u64(),
            hypercall_page,
        )
    }
}
