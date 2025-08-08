//! # VMBus Channels
//!
//! This module implements support for VMBus channels, the primary communication mechanism
//! between the guest (child partition) and the Hyper-V host (parent partition).
//!
//! ## Overview
//!
//! VMBus channels are lightweight, message-oriented communication endpoints used for
//! device emulation and synthetic device interaction. They allow the guest to talk to
//! various host-provided synthetic devices such as storage, networking, input, video, etc.
//!
//! ---
//!
//! ## Offers
//!
//! **Where do offers come from?**  
//! - When a virtual machine boots, the host (parent partition) enumerates synthetic
//!   devices assigned to the guest. For each device, the host sends an *Offer* over the
//!   **VMBus connection**.  
//! - Each *Offer* represents the host saying:  
//!   > *"I have a channel available for a device or service. Would you like to connect?"*
//!
//! **What is contained in an offer?**  
//! - A unique channel ID (per connection)  
//! - The device GUID (to identify the type of device, e.g., network, storage, HID input)  
//!
//! **Guest action:**  
//! - The guest driver inspects the offer, matches it to the appropriate driver logic,
//!   and then *opens* the channel.
//!
//! ---
//!
//! ## GPADL (Guest Physical Address Descriptor List)
//!
//! **What is GPADL?**  
//! GPADL is a mechanism to share **guest physical memory pages** with the host over a VMBus channel.  
//! It is essentially a *descriptor list* describing a contiguous or scattered set of guest memory pages.
//!
//! **Why is GPADL needed?**
//! - Many devices require large buffers for I/O (network packets, framebuffers, storage requests).
//! - Rather than copying data into each VMBus message, the guest and host can map shared
//!   memory buffers directly.
//! - GPADL eliminates unnecessary copies by allowing zero-copy transfer between guest
//!   and host memory.
//!
//! **How does it work?**
//! 1. Guest allocates a buffer in its memory.  
//! 2. Guest creates a GPADL descriptor that lists the physical addresses of those pages.  
//! 3. Guest sends a **Create GPADL** request to the host over the channel.  
//! 4. Host maps that memory into its address space, enabling direct access.
//!
//! ---
//!
//! ## Channel Workflow in More Detail
//!
//! ```text
//! Host -> Guest: Offer (channel for device X)
//! Guest -> Host: Open Channel
//! Guest -> Host: Create GPADL (map shared buffers)
//! Host -> Guest: GPADL Created (acknowledgement)
//! Guest <-> Host: Exchange Messages / Data using shared buffers
//! Guest -> Host: Teardown GPADL (when done)
//! Guest -> Host: Close Channel
//! ```
//!
//! ---
//!
//! ## Key Points
//!
//! - **Offers** are notifications from host about available synthetic devices.  
//! - **GPADLs** are mappings for efficient large data transfer.  
//! - **Channels** serve as lightweight transport for control messages and events.  
//!
use core::{
    arch::x86_64::_mm_mfence,
    ptr::{self, null},
};

use alloc::{borrow::ToOwned, boxed::Box, slice, sync::Arc, vec::Vec};
use log::debug;

use crate::{
    driver::hv::hyperv::{
        convert_message_to_slice, ring_buffer::HyperVDoubledRingBuffer, HyperV, HyperVPostMessage,
        VmBusGPADLHeader, VmBusGpaDirectHeader, VmBusGpaRange, VmBusGpadlCreated,
        VmBusMessageHeader, VmBusMessageType, VmBusNormalPacketHeader, VmBusOfferChannel,
        VmBusOpenChannel, VmBusOpenChannelResult, VmBusPacketFooter, VmBusPacketHeader,
        VmBusPacketType, VmBusXferPageHeader, HYPERV_PAGE_SIZE, HYPERV_POST_MESSAGE_MESSAGE_TYPE,
        HYPERV_VMBUS_CONNECTION_ID,
    },
    kernel::{self, kernel_ref},
    memory::{self, memory_manager, Frame, PhysicalAddress, VirtualAddress},
};

/// Represents a single VMBus channel in Hyper‑V.
///
/// A `VmBusChannel` encapsulates the connection state for a VMBus device
/// channel, including:
/// - The negotiated channel offer (`VmbusOfferChannel`).
/// - The ring buffer (`HyperVDoubledRingBuffer`).
/// - Backing memory frames for the ring buffers.
///
/// This struct is typically created after accepting a channel offer from
/// Hyper‑V and binding the channel to a GPADL mapping, or after successful negotiation
/// of subchannels usage in some specialized synthetic devices.
///
/// # Fields
/// - `offer`: The offer describing this channel from the host.
/// - `ring_buffer`: The ring buffer used for communication.
/// - `hyper_v`: Shared reference to the Hyper‑V instance handling low‑level ops.
/// - `gpadl_id`: Guest Physical Address Descriptor List ID assigned for the ring buffer mapping.
/// - `channel_id`: Unique channel identifier within the VMBus.
/// - `starting_frame`: The first memory frame backing the channel ring buffer.
/// - `channel_size`: The total size of the channel buffer in bytes.
pub struct VmBusChannel {
    offer: VmBusOfferChannel,
    pub ring_buffer: HyperVDoubledRingBuffer,
    hyper_v: Arc<HyperV>,
    gpadl_id: u32,
    channel_id: u32,
    starting_frame: Frame,
    channel_size: usize,
}

impl VmBusChannel {
    /// Creates a new [`VmBusChannel`] from a VMBus channel offer.
    ///
    /// This will:
    /// 1. Allocate the necessary ring buffer memory.
    /// 2. Map the buffer into a [`HyperVDoubledRingBuffer`].
    /// 3. Prepare the channel IDs and GPADL mapping.
    ///
    /// # Parameters
    /// - `offer`: The VMBus channel offer provided by the host.
    /// - `tx_byte_count`: Requested TX ring buffer size in bytes (always HYPERV_PAGE_SIZE aligned).
    /// - `rx_byte_count`: Requested RX ring buffer size in bytes (always HYPERV_PAGE_SIZE aligned).
    pub fn new(
        offer: &VmBusOfferChannel,
        tx_byte_count: usize,
        rx_byte_count: usize,
    ) -> VmBusChannel {
        assert_eq!(tx_byte_count % HYPERV_PAGE_SIZE, 0);
        assert_eq!(rx_byte_count % HYPERV_PAGE_SIZE, 0);
        // @TODO: Implement different sizes of TX and RX buffers
        assert_eq!(tx_byte_count, rx_byte_count);

        let tx_pages = tx_byte_count / HYPERV_PAGE_SIZE;
        let rx_pages = rx_byte_count / HYPERV_PAGE_SIZE;

        let size_in_pages = tx_pages + rx_pages;

        // Allocate frames used for a ring buffer. It's our responsibility to free them after connection termination.
        let starting_gpa = memory_manager()
            .write()
            .allocate_frames_contiguous(size_in_pages + 2) // +2 = need to allocate 2 more pages for ['HyperVSingleRingBuffer']s headers
            .unwrap();

        VmBusChannel {
            offer: *offer,
            ring_buffer: HyperVDoubledRingBuffer::new(
                &starting_gpa,
                size_in_pages + 2,
                tx_pages + 1,
            ),
            hyper_v: Arc::clone(&kernel_ref().hyperv),
            gpadl_id: 0,
            channel_id: 0,
            starting_frame: starting_gpa,
            channel_size: size_in_pages + 2,
        }
    }

    /// Initializes the VMBus channel by creating a GPADL mapping and opening the channel.
    /// Needs to be called as soon as possible after creating the channel and before sending first message.
    pub fn initialize(&mut self) {
        self.gpadl_id = self.hyper_v.create_gpadl(
            self.offer.channel_id,
            self.starting_frame.address(),
            self.channel_size * HYPERV_PAGE_SIZE,
        );

        self.channel_id = self.open_channel(
            self.offer.channel_id,
            self.gpadl_id,
            self.channel_size as u32 / 2,
        );
    }

    /// Sends a normal packet over the VMBus channel.
    ///
    /// # Parameters
    /// - `data`: Pointer to the raw packet data to send.
    /// - `len`: Length of the packet data in bytes.
    /// - `xid`: Transaction ID or unique identifier for this packet.
    /// - `completion_requested`: If true, requests a completion notification for the packet.
    /// - `packet_type`: The type of VMBus packet being sent (e.g., data, control).
    ///
    /// # Safety
    /// - `data` must be valid for reads of `len` bytes.
    /// - Caller must ensure that:
    ///   - `len` does not exceed the maximum allowed packet size,
    ///   - channel is initialized by calling `initialize()`.
    ///
    /// # Panics
    /// Panics if the channel’s TX ring buffer does not have enough space to accept `len` bytes.
    pub fn send_packet(
        &self,
        data: *const u8,
        len: usize,
        xid: u64,
        completion_requested: bool,
        packet_type: VmBusPacketType,
    ) {
        // Actually, this function is only safe wrapper around `self.send_raw()`.
        // This function only prepares VMBus packet header and sends it to the `self.send_raw()`.
        let mut header = VmBusNormalPacketHeader {
            packet_type: packet_type as u16,
            header_len_qword: (size_of::<VmBusNormalPacketHeader>() / 8) as u16,
            packet_len_qword: 0, // will be set by self.send_raw
            flags: completion_requested as u16,
            xid,
        };

        unsafe {
            self.send_raw(&mut header, data, len);
        }
    }

    /// Sends a VMBus data packet with an additional I/O buffer using GPA direct mechanism.
    ///
    /// # Parameters
    /// - `data`: Pointer to the packet header or main packet data.
    /// - `len`: Length of the main packet data in bytes.
    /// - `xid`: Transaction ID for tracking this packet.
    /// - `buffer`: Pointer to an optional additional data buffer (e.g., I/O buffer).
    /// - `buffer_len`: Length of the additional buffer in bytes.
    ///
    /// # Safety
    /// - `data` must be valid for reads of `len` bytes.
    /// - `buffer` must be valid for reads of `buffer_len` bytes.
    /// - Caller must ensure enough space is available in the TX ring buffer.
    pub fn send_data_packet(
        &self,
        netvsc_packet_buffer: *const u8,
        netvsc_packet_len: usize,
        xid: u64,
        rndis_buffer: *const u8,
        rndis_buffer_len: usize,
    ) {
        // Calculate PFNs of additional buffer.
        let pfn_count = {
            let first_pfn = rndis_buffer.addr() / HYPERV_PAGE_SIZE;
            let last_pfn = (rndis_buffer.addr() + rndis_buffer_len - 1) / HYPERV_PAGE_SIZE;

            last_pfn - first_pfn + 1
        };

        // GPA Direct packet constists of header and list of PFNs of additional buffer
        let header_size = size_of::<VmBusGpaDirectHeader>();
        let needed_len = header_size + pfn_count * 8;
        let mut packet_buffer = alloc::vec![0u8; needed_len];
        let packet_data: *mut u8 = packet_buffer.as_mut_ptr();

        // Create header
        let gpa = VmBusGpaDirectHeader {
            header: VmBusNormalPacketHeader {
                packet_type: VmBusPacketType::DataUsingGpaDirect as u16,
                header_len_qword: (needed_len / 8) as u16,
                packet_len_qword: 0, // will be computed in `self.send_raw()`
                flags: 1,
                xid,
            },
            reserved: 0,
            range_count: 1,
            range: VmBusGpaRange {
                byte_count: rndis_buffer_len as u32,
                starting_byte_offset: (rndis_buffer.addr() & (HYPERV_PAGE_SIZE - 1)) as u32,
            },
        };

        // Copy header into the buffer
        unsafe { ptr::copy(&gpa as *const _ as *const u8, packet_data, header_size) };

        // Fill the PFN list
        let pointer_to_pfn_list = unsafe { packet_data.add(header_size) } as *mut u64;
        for i in 0..pfn_count {
            // Get PFN from address
            let pfn = memory_manager()
                .read()
                .translate_virtual_address_to_physical_for_current_address_space(
                    VirtualAddress::new(
                        rndis_buffer.addr() as u64 + i as u64 * HYPERV_PAGE_SIZE as u64,
                    ),
                )
                .unwrap()
                .as_u64()
                / HYPERV_PAGE_SIZE as u64;

            // Write PFN into the PFN list
            unsafe { *pointer_to_pfn_list.add(i) = pfn };
        }

        // Send GPA Direct Packet via the normal `send.send_raw()` path
        unsafe {
            self.send_raw(
                &mut *(packet_data as *mut VmBusNormalPacketHeader),
                netvsc_packet_buffer,
                netvsc_packet_len,
            )
        };
    }

    /// Checks whether there is incoming data waiting in the RX ring buffer.
    #[inline]
    pub fn has_data_to_process(&self) -> bool {
        !self.ring_buffer.is_rx_buffer_empty()
    }

    /// Enables interrupts for the RX ring buffer.
    ///
    /// Setting the `interrupt_mask` field to `0` allows the host to
    /// deliver interrupt notifications for incoming data.
    pub fn enable_interrupts(&self) {
        unsafe {
            (*self.ring_buffer.rx.header).interrupt_mask = 0;
        }
    }

    /// Disables interrupts for the RX ring buffer.
    ///
    /// Setting the `interrupt_mask` field to `1` prevents the host
    /// from sending further interrupt notifications, even if data
    /// arrives in the RX buffer.
    pub fn disable_interrupts(&self) {
        unsafe {
            (*self.ring_buffer.rx.header).interrupt_mask = 1;
        }
    }

    /// Reads a packet from the RX ring buffer if available.
    ///
    /// # Returns
    /// - `Some((header, data))` containing the packet header and payload bytes.
    /// - `None` if there is no data to read.
    pub fn read(&self) -> Option<(VmBusPacketHeader, Box<[u8]>)> {
        // Check if we have any data to read
        if !self.has_data_to_process() {
            return None;
        }

        let rx = &self.ring_buffer.rx;
        let read_offset = unsafe { (*rx.header).read_offset as usize };

        let header = unsafe { *(rx.data_start.add(read_offset) as *const VmBusNormalPacketHeader) };
        let header_size = header.header_len_qword as usize * 8;
        let packet_type = VmBusPacketType::from(header.packet_type as u64);

        // VMBus Packet Header can be normal or extended, when using transfer with separate pages.
        // For higher levels we need to pass transmitted data, as well as the header, because it carries information
        // about data length and - when packet is VmbusPacketType::DataUsingXferPages - information about additional data location.
        let packet_header = if (packet_type == VmBusPacketType::DataUsingXferPages) {
            let xfer = unsafe { *(rx.data_start.add(read_offset) as *const VmBusXferPageHeader) };

            VmBusPacketHeader::Xfer(xfer)
        } else {
            VmBusPacketHeader::Packet(header)
        };

        // Safety check
        assert_eq!(header.header_len_qword as usize * 8, header_size);

        // Create Rust slice from transmitted data over VMBus channel.
        let data_len = header.packet_len_qword as usize * 8 - header_size;
        let data_ptr = unsafe { rx.data_start.add(read_offset + header_size) };
        let data = unsafe {
            slice::from_raw_parts(data_ptr, data_len)
                .to_owned()
                .into_boxed_slice()
        };

        // @TODO: Take care of packet footer?

        let consumed_len = header.packet_len_qword as usize * 8 + size_of::<VmBusPacketFooter>();

        self.ring_buffer.rx.advance_read_index(consumed_len as u32);

        Some((packet_header, data))
    }

    /// Sends a raw packet directly into the TX ring buffer.
    ///
    /// # Parameters
    /// - `header`: The VMBus packet header (will be written first).
    /// - `data`: Pointer to the payload data.
    /// - `len`: Length of the payload in bytes.
    ///
    /// # Safety
    /// - The caller must ensure that `data` points to at least `len` bytes of valid memory.
    /// - The TX ring buffer must have enough free space for the header plus payload.
    unsafe fn send_raw(&self, header: &mut VmBusNormalPacketHeader, data: *const u8, len: usize) {
        // VMBus Ring Buffer Packet Format
        // --------------------------------
        //
        // Each packet placed in the TX or RX ring buffer has the following structure:
        //
        //     +--------------------------+
        //     | Packet Header            |  <-- VmbusNormalPacketHeader / VmbusXferPageHeader
        //     +--------------------------+
        //     | Payload Data             |  <-- The actual packet contents (aligned start)
        //     +--------------------------+
        //     | Padding (optional)       |  <-- Aligns the footer to 8-byte boundary
        //     +--------------------------+
        //     | Footer (4 bytes)         |  <-- Packet trailing signature:
        //     |                          |      - Contains offset of first byte of the header
        //     +--------------------------+
        //

        // This function can send normal VMBus header, as well as Xfer header which have different sizes.
        // To properly distinguish between various header lengths, we will use field embedded inside the VMBus
        // packet header to get the real length of the header.
        let header_len = (header.header_len_qword * 8) as usize;
        // Compute padding size
        let padding_complement = (8 - (len & 7)) & 0b111;
        let footer_len = size_of::<VmBusPacketFooter>();
        // Transmission length consists of header length, data length, padding and footer length
        let tx_len = header_len + len + padding_complement + footer_len;
        let padding = [0u8; 8];

        // Check that we have enough space in out ring buffer
        if !self.ring_buffer.has_enough_space_to_send(tx_len as u32) {
            panic!("Ring buffer does not have enough space to send the data");
        }

        // Here we fill in packet_len in QWORDs. Note: Header does not take into account the footer length.
        header.packet_len_qword = ((tx_len - footer_len) / 8) as u16;

        let mut starting_offset = unsafe { *self.ring_buffer.tx.header }.write_offset;
        let footer = VmBusPacketFooter {
            reserved: 0,
            first_byte_of_packet: starting_offset,
        };

        // Send header
        starting_offset = self.ring_buffer.send(
            unsafe { header as *const _ as *const u8 },
            header_len,
            starting_offset,
        );

        // Send packet data (if any)
        starting_offset = if !data.is_null() {
            self.ring_buffer.send(data, len, starting_offset)
        } else {
            starting_offset
        };

        // Send padding
        starting_offset = self.ring_buffer.send(
            unsafe { &padding as *const _ as *const u8 },
            padding_complement,
            starting_offset,
        );

        // Send footer
        starting_offset = self.ring_buffer.send(
            unsafe { &footer as *const _ as *const u8 },
            size_of::<VmBusPacketFooter>(),
            starting_offset,
        );

        // Update TX writer index and issue a `mfence` instruction to serialize all store instructions. We want the host to
        // notice new data as soon as possible, so updating TX writer index shouldn't be delayed. Microsoft also recommends
        // issuing a full memory barrier here.
        //
        // @TODO: MFENCE/LFENCE/SFENCE?
        self.ring_buffer.update_tx_writer_index(starting_offset);
        _mm_mfence();

        // Check if host needs to be signalled about new incoming data in this channel. Host doesn't need to be signalled only if
        // it's already reading the ring buffer from another CPU core. Otherwise, tell the Hyper-V that new packet has been sent.
        if self.ring_buffer.should_signal_host() {
            self.hyper_v
                .signal_event(HYPERV_VMBUS_CONNECTION_ID, self.offer.connection_id as u16);
        }
    }

    /// Opens a VMBus channel with the specified GPADL mapping.
    ///
    /// This sends a `VmBusMessageType::OpenChannel` request to the host to
    /// activate the channel using the already established GPADL for
    /// the ring buffer memory.
    ///
    /// # Parameters
    /// - `channel_id`: ID of the channel to open (from the offer).
    /// - `gpadl_id`: GPADL ID created for the channel’s ring buffer.
    /// - `outbound_pages`: Number of pages available for outbound traffic.
    ///
    /// # Returns
    /// Returns the open ID.
    ///
    /// # Panics
    /// Panics if the host fails to open the channel.
    fn open_channel(&self, channel_id: u32, gpadl_id: u32, outbound_pages: u32) -> u32 {
        let open_id = channel_id;

        // Create channel opening request
        let open_channel = VmBusOpenChannel {
            header: VmBusMessageHeader::with_message_type(VmBusMessageType::OpenChannel),
            channel_id,
            open_id,
            gpadl_id,
            target_vp: 0,
            outbound_page_offset: outbound_pages,
            data: [0u8; 120],
        };

        // Send channel opening request using main VMBus connection ID
        let message = HyperVPostMessage {
            connection_id: HYPERV_VMBUS_CONNECTION_ID,
            reserved: 0,
            message_type: HYPERV_POST_MESSAGE_MESSAGE_TYPE,
            payload_size: size_of::<VmBusOpenChannel>() as u32,
            payload: convert_message_to_slice(&open_channel),
        };

        // Post message
        self.hyper_v.reset_reception_status();
        unsafe { self.hyper_v.post_message(&message) };
        let response = self.hyper_v.wait_for_message::<VmBusOpenChannelResult>();

        // Check if opening was successful. If it wasn't then we consider it as a fatal error and panic.
        if response.status != 0 {
            panic!("Failed to open VMBus channel");
        }

        open_id
    }
}
