//! # Hyper-V Ring Buffer Abstraction
//!
//! ## Overview
//!
//! The Hyper‑V ring buffer is a **shared memory structure** organized as a
//! circular queue. It is widely used by virtual devices and Hyper‑V services
//! (e.g., VMBus channels) to exchange TX (transmit) and RX (receive) data.
//!
//! The ring buffer is divided into two sections: TX and RX. Each of this sections
//! have the same layout and synchronization primitives, so we divide a Hyper-V Ring Buffer
//! into two separate [`HyperVSingleRingBuffer`]s, which together are represented as [`HyperVDoubledRingBuffer`].
//!
//! Each ring buffer consists of:
//! - A [`HyperVRingBufferHeader`] containing metadata such as read/write
//!   offsets and interrupt mask.
//! - A contiguous **data region** used as a circular buffer for payload data.
//!
//! ## Memory Layout
//!
//! The Hyper‑V single ring buffer layout (in memory):
//! ```text
//! +----------------------------+
//! | HyperVRingBufferHeader     |  (always HYPERV_PAGE_SIZE bytes)
//! +----------------------------+
//! |                            |
//! | Ring buffer data region    |  (the size is always HYPERV_PAGE_SIZE aligned, and consists of at least one page)
//! |                            |
//! +----------------------------+
//! ```
//!
//! In doubled configuration:
//! ```text
//! +-------------------------------+
//! | TX HyperVRingBufferHeader     |
//! +-------------------------------+
//! |                               |
//! | TX Ring buffer data region    |
//! |                               |
//! +-------------------------------+  (RX buffer comes just after TX)
//! | RX HyperVRingBufferHeader     |
//! +-------------------------------+
//! |                               |
//! | RX Ring buffer data region    |
//! |                               |
//! +-------------------------------+
//! ```
//!
//! Ring buffers have to be physically contiguous, as the Hyper-V only operates on GPAs (Guest Physical Addresses).
//!
//! ## Safety
//!
//! Working with the Hyper‑V ring buffer involves `unsafe` code because:
//! - It uses **raw pointers** to guest/host shared memory.
//! - **Synchronization** with the host is the caller’s responsibility.

use core::{ptr, range::Range};

use crate::{
    driver::hv::hyperv::HYPERV_PAGE_SIZE,
    subsystem::memory::{
        CurrentAddressSpace, Frame, FrameRange, PageFlags, PhysicalAddress, memory_manager,
    },
};

/// Represents the header of a Hyper-V ring buffer.
///
/// # Fields
/// - `write_offset` — The current write position in the ring buffer (in bytes).
/// - `read_offset` — The current read position in the ring buffer (in bytes).
/// - `interrupt_mask` — Controls interrupt behavior for TX and RX ring buffers.
/// - `reserved` — Padding/reserved bytes to align the structure size.
///
/// # Interrupt Mask Behavior
///
/// - **TX ring buffer:**
///   - Set by the host to `1` when processing the TX buffer.
///   - When set, the guest can safely skip TX event notifications to the host.
///
/// - **RX ring buffer:**
///   - Set by the guest to `1` to prevent the host from dispatching further
///     interrupts, even if RX data is pending.
///   - This effectively disables the interrupt for the channel associated with
///     the RX buffer.
#[derive(Debug, Copy, Clone)]
#[repr(C, packed)]
pub struct HyperVRingBufferHeader {
    /// Current write position in the ring buffer (in bytes).
    pub write_offset: u32,

    /// Current read position in the ring buffer (in bytes).
    pub read_offset: u32,

    /// Interrupt mask control (0 or 1).
    ///
    /// - `0`: Interrupts allowed (default).
    /// - `1`: Interrupts masked based on TX/RX context.
    pub interrupt_mask: u32,

    /// Reserved padding bytes to align structure size.
    pub reserved: [u8; 4084],
}

const _: () = assert!(size_of::<HyperVRingBufferHeader>() == HYPERV_PAGE_SIZE);

/// Represents a single Hyper-V ring buffer.
///
/// A single ring buffer consists of:
/// - A header containing metadata such as read/write offsets and interrupt control.
/// - A contiguous memory region containing the actual buffer data.
///
/// # Safety
/// - The `header` and `data_start` pointers must be valid and correctly aligned
///   for the lifetime of this structure.
/// - The caller must ensure that read/write operations do not exceed `size_in_bytes`.
#[derive(Debug)]
pub struct HyperVSingleRingBuffer {
    /// Pointer to the ring buffer header (metadata).
    pub header: *mut HyperVRingBufferHeader,

    /// Pointer to the start of the ring buffer's data region.
    pub data_start: *mut u8,

    /// Size of the ring buffer (in bytes).
    pub size_in_bytes: u32,
}

unsafe impl Send for HyperVSingleRingBuffer {}
unsafe impl Sync for HyperVSingleRingBuffer {}

impl HyperVSingleRingBuffer {
    /// Creates a new `HyperVSingleRingBuffer` from a starting memory frame.
    ///
    /// # Parameters
    /// - `starting_frame`: Reference to a memory frame containing both the
    ///   header and data region for the ring buffer.
    /// - `size_in_bytes`: Total size of the allocated memory for ring buffer (in bytes)
    ///
    /// # Safety
    /// - Assumes `starting_frame` points to a valid memory region large enough
    ///   to contain one page of `HyperVRingBufferHeader` and n pages of data buffer.
    /// - Caller is responsible for ensuring correct memory alignment and lifetime.
    pub fn new(starting_frame: &Frame, size_in_bytes: u32) -> HyperVSingleRingBuffer {
        // Safety check that the ring buffer is at least 2 pages wide (one page for header and at least one page for data)
        assert!(size_in_bytes >= (2 * HYPERV_PAGE_SIZE).try_into().unwrap());

        let mut memory_manager = memory_manager().write();

        // Map header somewhere in memory
        let header = unsafe {
            memory_manager
                .map_any_contiguous(
                    CurrentAddressSpace,
                    Range::from(256..512),
                    FrameRange::new(
                        starting_frame.address(),
                        PhysicalAddress::new(
                            starting_frame.address().as_u64() + size_in_bytes as u64,
                        ),
                    ),
                    PageFlags::WRITABLE | PageFlags::DISABLE_CACHING,
                )
                .start()
        };

        HyperVSingleRingBuffer {
            header: header.as_mut_ptr(),
            data_start: unsafe { header.as_mut_ptr::<u8>().add(HYPERV_PAGE_SIZE) },
            size_in_bytes,
        }
    }

    /// Checks whether the ring buffer is empty.
    ///
    /// A ring buffer is considered empty if the `write_offset` equals the `read_offset`.
    pub fn is_empty(&self) -> bool {
        let read_offset = unsafe { ptr::read_volatile(ptr::addr_of!((*self.header).read_offset)) };
        let write_offset =
            unsafe { ptr::read_volatile(ptr::addr_of!((*self.header).write_offset)) };

        read_offset == write_offset
    }

    /// Returns the number of bytes available for writing into the ring buffer.
    pub fn get_available_write_space(&self) -> usize {
        let write_index = self.get_write_index();
        let read_index = self.get_read_index();

        if write_index >= read_index {
            self.ring_buffer_data_size() - (write_index - read_index)
        } else {
            read_index - write_index
        }
    }

    /// Advances the read index by the specified number of bytes.
    ///
    /// This updates `read_offset` in the header and wraps around if the end
    /// of the buffer is reached.
    pub fn advance_read_index(&self, read_bytes: u32) {
        let current_offset = unsafe { (*self.header).read_offset };
        let new_offset = (current_offset + read_bytes) % self.ring_buffer_data_size() as u32;

        // @TODO: Check write_offset

        unsafe {
            (*self.header).read_offset = new_offset;
        }
    }

    /// Returns the maximum usable data size of the ring buffer (excluding reserved header space).
    #[inline]
    fn ring_buffer_data_size(&self) -> usize {
        self.size_in_bytes as usize - HYPERV_PAGE_SIZE
    }

    /// Returns the current write index (offset) in the ring buffer.
    #[inline]
    fn get_write_index(&self) -> usize {
        unsafe { (*self.header).write_offset as usize }
    }

    /// Returns the current read index (offset) in the ring buffer.
    #[inline]
    fn get_read_index(&self) -> usize {
        unsafe { (*self.header).read_offset as usize }
    }
}

/// Represents a doubled (TX/RX) Hyper-V ring buffer pair.
///
/// A doubled ring buffer contains two separate ring buffers:
/// - **TX buffer** (`tx`) for transmitting data to the host.
/// - **RX buffer** (`rx`) for receiving data from the host.
///
/// This struct bundles them together for convenience, because every Hyper-V channel
/// is full-duplex.
#[derive(Debug)]
pub struct HyperVDoubledRingBuffer {
    /// The transmit (TX) ring buffer.
    pub tx: HyperVSingleRingBuffer,

    /// The receive (RX) ring buffer.
    pub rx: HyperVSingleRingBuffer,
}

impl HyperVDoubledRingBuffer {
    /// Creates a new `HyperVDoubledRingBuffer` from a contiguous memory region.
    ///
    /// # Parameters
    /// - `starting_gpa`: Frame pointing to the start of the allocated TX+RX memory.
    /// - `size_in_pages`: Total number of pages allocated for the doubled buffer.
    /// - `outbound_offset`: Byte offset (from `starting_gpa`) to the TX buffer.
    ///
    /// # Layout
    /// ```
    /// [ RX buffer at offset 0 ] [ TX buffer at outbound_offset ]
    /// ```
    ///
    /// # Safety
    /// - Caller must ensure that `starting_gpa` points to valid memory for the
    ///   given `size_in_pages`.
    pub fn new(
        starting_gpa: &Frame,
        _size_in_pages: usize,
        outbound_offset: usize,
    ) -> HyperVDoubledRingBuffer {
        // @TODO: What about RX and TX buffer of different sizes?
        let tx_size_in_bytes = outbound_offset * HYPERV_PAGE_SIZE;
        let rx_size_in_bytes = outbound_offset * HYPERV_PAGE_SIZE;

        let tx_starting_frame = starting_gpa;
        let rx_starting_frame = &Frame::new(PhysicalAddress::new(
            tx_starting_frame.address().as_u64() + tx_size_in_bytes as u64,
        ));

        HyperVDoubledRingBuffer {
            tx: HyperVSingleRingBuffer::new(tx_starting_frame, tx_size_in_bytes as u32),
            rx: HyperVSingleRingBuffer::new(rx_starting_frame, rx_size_in_bytes as u32),
        }
    }

    /// Checks whether the RX (receive) ring buffer is empty.
    ///
    /// Returns `true` if there is no data pending in the RX buffer.
    #[inline]
    pub fn is_rx_buffer_empty(&self) -> bool {
        self.rx.is_empty()
    }

    /// Checks whether the TX buffer has enough free space to send `len` bytes.
    ///
    /// # Returns
    /// `true` if there is enough available space in the TX buffer to send `len` bytes.
    pub fn has_enough_space_to_send(&self, len: u32) -> bool {
        len < self.tx.get_available_write_space() as u32
    }

    /// Sends data into the TX buffer at the given write offset.
    ///
    /// This copies `len` bytes from `data` into the TX buffer. If the write
    /// wraps past the end of the buffer, the doubly-mapped ring buffer will handle it.
    ///
    /// # Parameters
    /// - `data`: Pointer to the source data to be sent.
    /// - `len`: Number of bytes to write.
    /// - `write_offset`: Current write offset in the TX buffer.
    ///
    /// # Returns
    /// The new write offset after the data is written (wrapped to buffer size).
    ///
    /// # Safety
    /// - `data` must be valid for `len` bytes.
    /// - TX buffer memory must be valid for writing `len` bytes starting at `write_offset`.
    /// - Caller is responsible for checking if the buffer has enough space with `self.has_enough_space_to_send()`
    pub fn send(&self, data: *const u8, len: usize, write_offset: u32) -> u32 {
        let buffer_size = self.tx.ring_buffer_data_size();
        let offset = write_offset as usize;

        let bytes_to_end = buffer_size - offset;

        unsafe {
            if len <= bytes_to_end {
                ptr::copy(data, self.tx.data_start.add(offset), len);
            } else {
                ptr::copy(data, self.tx.data_start.add(offset), bytes_to_end);

                let remaining_bytes = len - bytes_to_end;
                ptr::copy(data.add(bytes_to_end), self.tx.data_start, remaining_bytes);
            }
        }

        ((offset + len) % buffer_size) as u32
    }

    /// Updates the TX buffer's write index in the header.
    ///
    /// # Parameters
    /// - `index`: New write offset (must be within buffer size).
    ///
    /// # Safety
    /// - Caller must ensure `index` is valid for the TX buffer size.
    #[inline]
    pub fn update_tx_writer_index(&self, index: u32) {
        unsafe { (*self.tx.header).write_offset = index };
    }

    /// Determines whether the host should be signaled.
    ///
    /// This checks the `interrupt_mask` in the TX buffer header.
    /// - If `interrupt_mask == 0`, signaling is allowed.
    /// - If `interrupt_mask == 1`, the host has disabled signaling temporarily.
    ///
    /// # Returns
    /// `true` if we should signal the host.
    #[inline]
    pub fn should_signal_host(&self) -> bool {
        unsafe { (*self.tx.header).interrupt_mask == 0 }
    }
}
