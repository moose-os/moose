//! Packet Buffer Infrastructure

use bitflags::parser::ParseError;

pub mod arp;
pub mod dhcp;
pub mod dns;
pub mod ethernet;
pub mod icmp;
pub mod ip;
pub mod tcp;
pub mod tcp_socket;
pub mod udp;

/// Number of pre-allocated packet slots.
pub const SLOT_COUNT: usize = 64;

/// Size of one packet slot in bytes - enough for a full Ethernet frame
/// (1500 MTU + 14-byte header, plus a little slack).
pub const SLOT_SIZE: usize = 1522;

/// A fixed pool of `SLOT_COUNT` packet-sized buffers.
pub struct PacketAllocator {
    pub preallocated_slots: [[u8; SLOT_SIZE]; SLOT_COUNT],

    // bit i = 1 --> slot free
    available: u64,
}

impl PacketAllocator {
    pub fn new() -> Self {
        Self {
            preallocated_slots: [[0; SLOT_SIZE]; SLOT_COUNT],
            available: !0,
        }
    }
}

impl PacketAllocator {
    /// Claims the lowest-numbered free slot, if any.
    pub fn try_acquire_slot(&mut self) -> Option<usize> {
        if self.available == 0 {
            return None;
        }

        let index = self.available.trailing_zeros() as usize;
        self.available &= !(1 << index);

        Some(index)
    }

    /// Mutable access to one slot's raw storage, by index.
    pub fn slot_mut(&mut self, index: usize) -> &mut [u8] {
        &mut self.preallocated_slots[index][..]
    }

    /// Returns a slot to the free pool.
    pub fn release_slot(&mut self, index: usize) {
        assert!(index < SLOT_COUNT);

        self.available |= 1 << index;
    }
}

/// Headroom for L2/L3/L4 headers prepended in front of the payload.
///
/// Worst case on the transmit path:
///   Ethernet(14) + IPv4(20) + TCP(20) + options(up to 40) = 94 bytes.
pub const DEFAULT_HEADER_RESERVE: usize = 96;

/// A cursor over one packet slot's raw storage, tracking where the live
/// payload currently sits within it (`payload_start..payload_end`) and
/// how far it's allowed to grow in either direction
/// (`buffer_start..buffer_end`).
///
/// The actual payload bytes are written into `storage` exactly once,
/// because headers are added by moving `payload_start` and writing
/// into the space that opens up, never by copying the payload
/// itself.
pub struct PacketBuffer<'storage> {
    storage: &'storage mut [u8],
    buffer_start: usize,
    payload_start: usize,
    payload_end: usize,
    buffer_end: usize,
}

impl<'storage> PacketBuffer<'storage> {
    /// Wraps a slot that already holds `received_length` bytes of a
    /// just-received frame, starting at `header_reserve`.
    pub fn from_received_slot(
        storage: &'storage mut [u8],
        header_reserve: usize,
        received_length: usize,
    ) -> Self {
        let buffer_start = header_reserve;
        let payload_start = header_reserve;
        let payload_end = header_reserve + received_length;
        let buffer_end = storage.len();

        Self {
            storage,
            buffer_start,
            payload_start,
            payload_end,
            buffer_end,
        }
    }

    /// Starts an empty buffer for building an outgoing packet, with
    /// `header_reserve` bytes of blank space before the payload for
    /// later [`prepend_header`](Self::prepend_header) calls to fill in.
    pub fn for_transmit(storage: &'storage mut [u8], header_reserve: usize) -> Self {
        assert!(
            storage.len() >= header_reserve,
            "TX buffer {} < header_reserve {}",
            storage.len(),
            header_reserve
        );

        let buffer_end = storage.len();

        Self {
            storage,
            buffer_start: 0,
            payload_start: header_reserve,
            payload_end: header_reserve,
            buffer_end,
        }
    }
}

impl PacketBuffer<'_> {
    /// The data payload.
    pub fn payload(&self) -> &[u8] {
        &self.storage[self.payload_start..self.payload_end]
    }

    /// Mutable data payload.
    pub fn payload_mut(&mut self) -> &mut [u8] {
        &mut self.storage[self.payload_start..self.payload_end]
    }

    /// Appends `data` to the end of the payload (transmit-side building).
    pub fn append_data(&mut self, data: &[u8]) {
        let new_end = self.payload_end + data.len();

        assert!(new_end <= self.buffer_end);

        self.storage[self.payload_end..new_end].copy_from_slice(data);

        self.payload_end = new_end;
    }

    /// Writes `header` into the space immediately before the current
    /// payload and moves `payload_start` back to include it.
    pub fn prepend_header<H>(&mut self, header: &H)
    where
        H: zerocopy::IntoBytes + zerocopy::Immutable,
    {
        let header_bytes = header.as_bytes();
        let header_length = header_bytes.len();

        assert!(self.payload_start >= self.buffer_start + header_length);

        self.payload_start -= header_length;

        self.storage[self.payload_start..self.payload_start + header_length]
            .copy_from_slice(header_bytes);
    }

    /// Like [`prepend_header`](Self::prepend_header), but for raw bytes.
    pub fn prepend_bytes(&mut self, bytes: &[u8]) {
        let byte_length = bytes.len();

        assert!(self.payload_start >= self.buffer_start + byte_length);

        self.payload_start -= byte_length;

        self.storage[self.payload_start..self.payload_start + byte_length].copy_from_slice(bytes);
    }

    /// Reads and strips one header of type `T` off the front of the
    /// remaining payload, and advances `payload_start` past it so the
    /// next layer sees only what's left.
    pub fn consume_header<T>(&mut self) -> Result<T, ParseError>
    where
        T: zerocopy::FromBytes + zerocopy::Immutable + zerocopy::KnownLayout,
    {
        let remaining = &self.storage[self.payload_start..self.payload_end];
        let (header, rest) = T::read_from_prefix(remaining).unwrap();
        let consumed = remaining.len() - rest.len();

        self.payload_start += consumed;

        Ok(header)
    }

    /// Skips `count` bytes off the front.
    pub fn consume_bytes(&mut self, count: usize) {
        assert!(self.payload_start + count <= self.payload_end);

        self.payload_start += count;
    }

    /// The full remaining region, `payload_start..payload_end.
    pub fn frame(&self) -> &[u8] {
        &self.storage[self.payload_start..self.payload_end]
    }

    /// Truncates the payload to at most `len` bytes (e.g. IPv4 `total_length`).
    pub fn trim_payload(&mut self, len: usize) {
        let end = self.payload_start + len;
        if end < self.payload_end {
            self.payload_end = end;
        }
    }
}
