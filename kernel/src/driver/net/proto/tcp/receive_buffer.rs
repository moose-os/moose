//! TCP receive buffer (circular reassembly window).
//!
//! RFC: [RFC 9293](https://www.rfc-editor.org/rfc/rfc9293.html) (receive window);
//! out-of-order reassembly cooperates with SACK ([`super::sack`], RFC 2018).
//!
//! A plain ring buffer would only ever accept bytes in order - anything
//! that arrives out of sequence (a segment jumping ahead of a gap) has
//! nowhere to go until the gap is filled, so you either drop it and make
//! the sender retransmit data it already sent, or you keep a separate
//! `Vec` per out-of-order chunk and stitch them back in later.
//!
//! This buffer does neither: with SACK on, an out-of-order segment is written
//! directly into its final position in the ring - `head + (seq -
//! RCV.NXT)` - one memcpy, no side storage. It just doesn't count toward
//! what the application can read yet. Once the gap in front of it fills
//! in, [`TcpReceiveBuffer::advance_contig`] just slides the readable
//! prefix forward over bytes that are already sitting there - no second
//! copy needed.
//!
//! So there are really two watermarks here: `size`, how much is
//! contiguous from RCV.NXT and safe to hand to the app, and `occupied`,
//! how far into the ring data has been written at all (contiguous or
//! not)-— which is what actually bounds free space, since an
//! out-of-order write still uses up ring capacity even before it's
//! readable. The SACK scoreboard in `sack.rs` tracks which ranges
//! exist; this buffer just holds the bytes.

use alloc::vec::Vec;

/// Circular buffer for incoming TCP data, doing double duty as the SACK
/// reassembly window. `[tail, head)` is the classic contiguous
/// ring-buffer region the app can read from; anything SACK writes
/// out-of-order lands further ahead in the ring, past `head`, without
/// yet extending it.
#[derive(Debug, Clone)]
pub struct TcpReceiveBuffer {
    /// Data buffer.
    data: Vec<u8>,

    /// Write pointer - end of the contiguous, app-readable prefix.
    head: usize,

    /// Read pointer - where the app's next read starts.
    tail: usize,

    /// Contiguous bytes currently readable by the app.
    size: usize,

    /// How far into the ring bytes have been written at all, including
    /// out-of-order data past `head`. Equal to `size` unless SACK has
    /// something out-of-order buffered; this, not `size`, is what
    /// actually limits free space.
    occupied: usize,

    /// Capacity of the entire buffer.
    capacity: usize,
}

impl TcpReceiveBuffer {
    pub fn new(capacity: usize) -> Self {
        log::trace!("TCP recv buffer alloc: capacity={}", capacity);

        Self {
            data: alloc::vec![0; capacity],
            head: 0,
            tail: 0,
            size: 0,
            occupied: 0,
            capacity,
        }
    }

    /// Room left in the ring - accounts for out-of-order bytes already
    /// written past `head`, not just the contiguous region.
    pub fn free_space(&self) -> usize {
        self.capacity - self.occupied.max(self.size)
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Plain contiguous append at `head` - the non-SACK fast path.
    pub fn write(&mut self, buf: &[u8]) -> usize {
        let to_write = buf.len().min(self.free_space());
        if to_write == 0 {
            return 0;
        }

        let first = to_write.min(self.capacity - self.head);
        unsafe {
            core::ptr::copy_nonoverlapping(
                buf.as_ptr(),
                self.data.as_mut_ptr().add(self.head),
                first,
            );
        }

        if to_write > first {
            unsafe {
                core::ptr::copy_nonoverlapping(
                    buf.as_ptr().add(first),
                    self.data.as_mut_ptr(),
                    to_write - first,
                );
            }
        }

        self.head = (self.head + to_write) % self.capacity;
        self.size += to_write;
        self.occupied = self.occupied.max(self.size);

        to_write
    }

    /// Store `buf` at sequence `seq` inside the window that starts at
    /// `rcv_nxt` - the SACK-aware write.
    ///
    /// - `seq == rcv_nxt`: this segment closes the gap right at the
    ///   front, so it behaves like a normal contiguous append and `size`
    ///   grows immediately.
    /// - `seq > rcv_nxt`: this segment is ahead of a gap, so it's written
    ///   straight into its future position in the ring (`head + (seq -
    ///   rcv_nxt)`) but doesn't extend what the app can read yet - that
    ///   only happens once [`advance_contig`] confirms the gap in front
    ///   of it has been filled.
    /// - `seq < rcv_nxt`: already-seen data (duplicate/overlap), dropped.
    pub fn write_at(&mut self, rcv_nxt: u32, seq: u32, buf: &[u8]) -> usize {
        if buf.is_empty() {
            return 0;
        }

        let off = seq.wrapping_sub(rcv_nxt) as i32;
        if off < 0 {
            return 0;
        }

        let off = off as usize;
        if off >= self.capacity {
            return 0;
        }

        let max_len = self.capacity - off;
        let n = buf.len().min(max_len);
        if n == 0 {
            return 0;
        }

        // Contig ends at `head`; OOO sits further ahead in the ring.
        let idx = (self.head + off) % self.capacity;
        let first = n.min(self.capacity - idx);
        unsafe {
            core::ptr::copy_nonoverlapping(buf.as_ptr(), self.data.as_mut_ptr().add(idx), first);

            if n > first {
                core::ptr::copy_nonoverlapping(
                    buf.as_ptr().add(first),
                    self.data.as_mut_ptr(),
                    n - first,
                );
            }
        }

        let end_off = off + n;
        if end_off > self.occupied {
            self.occupied = end_off;
        }

        if seq == rcv_nxt {
            self.size = self.size.saturating_add(n);
            self.head = (self.head + n) % self.capacity;
            self.occupied = self.occupied.max(self.size);
        }

        n
    }

    /// Called once a hole right in front of `head` has been filled -
    /// widens the app-readable prefix by `n` bytes that [`write_at`]
    /// already wrote into the ring, with no extra copy.
    pub fn advance_contig(&mut self, n: usize) {
        let n = n.min(self.capacity.saturating_sub(self.size));
        if n == 0 {
            return;
        }

        self.size += n;
        self.head = (self.head + n) % self.capacity;
        self.occupied = self.occupied.max(self.size);
    }

    pub fn read(&mut self, out: &mut [u8]) -> usize {
        let to_read = out.len().min(self.size);
        if to_read == 0 {
            return 0;
        }

        let first = to_read.min(self.capacity - self.tail);
        unsafe {
            core::ptr::copy_nonoverlapping(
                self.data.as_ptr().add(self.tail),
                out.as_mut_ptr(),
                first,
            );
        }

        if to_read > first {
            unsafe {
                core::ptr::copy_nonoverlapping(
                    self.data.as_ptr(),
                    out.as_mut_ptr().add(first),
                    to_read - first,
                );
            }
        }

        self.tail = (self.tail + to_read) % self.capacity;
        self.size -= to_read;

        // App consumed contig bytes; OOO still sits at absolute indices that
        // stay valid because offsets are measured from `head`/`rcv_nxt`, not tail.
        self.occupied = self.occupied.saturating_sub(to_read);

        if self.occupied < self.size {
            self.occupied = self.size;
        }

        to_read
    }
}
