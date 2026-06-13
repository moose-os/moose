//! # Hyper-V Synthetic Video Protocol
//!
//! The communication happens over the VMBus channel for synthetic video, using a sequence of
//! well-defined messages in a fixed initialization and runtime order.
//!
//! ## Protocol Flow
//!
//! The typical initialization and update flow is as follows:
//!
//! 1. **Guest → Host**
//!    [`SyntheticVideoProtocolVersionRequest`]
//!    The guest negotiates the supported protocol version with the host.
//!
//! 2. **Host → Guest**
//!    [`SyntheticVideoProtocolVersionResponse`]
//!    The host responds, indicating whether the requested version is accepted and providing its own version information.
//!
//! 3. **Host → Guest**
//!    [`SyntheticVideoFeatureChange`]
//!    The host informs the guest of required updates or features that need attention (e.g., resolution change, cursor update).
//!
//! 4. **Guest → Host**
//!    [`SyntheticVideoSupportedResolutionsRequest`]
//!    The guest requests the list of supported resolutions and related EDID data.
//!
//! 5. **Host → Guest**
//!    [`SyntheticVideoSupportedResolutionsResponse`]
//!    The host provides available resolutions, default resolution index, and display configuration details.
//!
//! 6. **Guest → Host**
//!    [`SyntheticVideoVramLocation`]
//!    The guest specifies the location of the video framebuffer in guest physical address space.
//!
//! 7. **Host → Guest**
//!    [`SyntheticVideoVramLocationAck`]
//!    The host acknowledges the framebuffer location.
//!
//! 8. **Guest → Host**
//!    [`SyntheticVideoPointerPosition`]
//!    The guest communicates the position and visibility state of the pointer (cursor).
//!
//! 9. **Guest → Host**
//!    [`SyntheticVideoPointerShape`]
//!    The guest sends pointer (cursor) bitmap.
//!
//! 10. **Guest → Host**
//!     [`SyntheticVideoSituationUpdate`]
//!     The guest provides information about the current display situation (resolution, pitch, VRAM offsets).
//!
//! 11. **Host → Guest**
//!     [`SyntheticVideoSituationUpdateAck`]
//!     The host acknowledges the situation update.
//!
//! 12. **Guest → Host**
//!     [`SyntheticVideoDirt`] (repeated many times during operation)
//!     The guest periodically informs the host of dirty rectangles in the framebuffer that need to be redrawn.
//!
//! ## Runtime Behavior
//!
//! After initialization, the protocol mainly revolves around `Dirt` messages, where the guest keeps notifying
//! the host about updated framebuffer regions. Pointer position/shape changes can also be sent at any time
//! if user input or cursor state changes.
//!
//! This sequence ensures the host is always aware of the current screen configuration and can refresh
//! the display efficiently.
//!
//! ## Sequence Diagram
//!
//! ```text
//! +--------+                                 +------+
//! | Guest  |                                 | Host |
//! +--------+                                 +------+
//!     |  ProtocolVersionRequest  ------------>  |
//!     |  <------------  ProtocolVersionResponse |
//!     |  <------------  FeatureChange           |
//!     |  SupportedResolutionsRequest  --------> |
//!     |  <------------  SupportedResolutionsResponse
//!     |  VramLocation  -----------------------> |
//!     |  <------------  VramLocationAck         |
//!     |  PointerPosition  --------------------> |
//!     |  PointerShape  -----------------------> |
//!     |  SituationUpdate  --------------------> |
//!     |  <------------  SituationUpdateAck      |
//!     |---------------------------------------->|
//!     |         Dirt (repeated updates)         |
//!     |---------------------------------------->|
//! ```
//!
use core::{
    ptr,
    range::Range,
    sync::atomic::{AtomicU64, Ordering},
};

use alloc::{sync::Arc, vec::Vec};
use spin::RwLock;

use crate::{
    driver::hv::hyperv::{
        HYPERV_PAGE_SIZE, VmBusOfferChannel, VmBusPacketType, VmBusPipeHeader,
        VmBusPipeMessageType,
        channel::VmBusChannel,
        synthetic_device::{DirtyRectangle, Resolution, VmBusSyntheticDevice},
    },
    subsystem::{
        memory::{
            CurrentAddressSpace, FrameRange, PageFlags, PhysicalAddress, VirtualAddress,
            memory_manager,
        },
        scheduler::OneshotGate,
    },
};

/// Size (in bytes) of a single EDID (Extended Display Identification Data) block.
///
/// EDID is a standard data structure provided by a display to describe its
/// capabilities (e.g., supported resolutions, refresh rates, and color formats).
const EDID_BLOCK_SIZE: usize = 128;

/// Maximum number of resolutions that can be reported by the synthetic video device.
///
/// This is the upper bound for the `supported_resolutions` array in
/// [SyntheticVideoSupportedResolutionsResponse].
const SYNTHETIC_VIDEO_MAX_RESOLUTION_COUNT: usize = 64;

/// Value included in certain messages and responses to confirm
/// successful processing or indicate that the operation completed
/// without errors.
const SYNTHETIC_VIDEO_USER_CONTEXT: u64 = 0xDEAD;

/// Synthetic Video message types exchanged over the Hyper-V VMBus channel.
///
/// These messages are used to negotiate protocol versions, share VRAM locations,
/// update screen state, and handle pointer or resolution changes.
#[derive(Debug, Copy, Clone)]
#[repr(u32)]
enum SyntheticVideoMessageType {
    /// Indicates an error in communication
    Error = 0,

    /// Request to negotiate the protocol version.
    VersionRequest = 1,

    /// Response to a [SyntheticVideoMessageType::VersionRequest].
    VersionResponse = 2,

    /// Guest sends information about VRAM physical location.
    VramLocation = 3,

    /// Acknowledgement of [SyntheticVideoMessageType::VramLocation].
    VramLocationAck = 4,

    /// Information about screen resolution and BPP.
    SituationUpdate = 5,

    /// Acknowledgement of [SyntheticVideoMessageType::SituationUpdate].
    SituationUpdateAck = 6,

    /// Updates the on-screen cursor position.
    PointerPosition = 7,

    /// Updates the cursor bitmap.
    PointerShape = 8,

    /// List of updates the host expects from guest.
    FeatureChange = 9,

    /// Dirty rectangle update, indicating regions of VRAM that changed and needs redraw.
    Dirt = 10,

    /// Request to get all supported resolutions by the device.
    ResolutionRequest = 13,

    /// Response to [SyntheticVideoMessageType::ResolutionRequest].
    ResolutionResponse = 14,
}

/// Header for control messages on the Synthetic Video VMBus channel.
///
/// This header precedes all control messages exchanged between the guest and the host.
#[derive(Debug, Copy, Clone)]
#[repr(C, packed)]
struct SyntheticVideoHeader {
    ///  Specifies the type of message being sent.
    message_type: SyntheticVideoMessageType,

    /// The size of the payload in bytes.
    payload_size: u32,
}

impl SyntheticVideoHeader {
    pub fn with_type_and_size(
        message_type: SyntheticVideoMessageType,
        payload_size: u32,
    ) -> SyntheticVideoHeader {
        SyntheticVideoHeader {
            message_type,
            payload_size,
        }
    }
}

/// Versions of the Synthetic Video Protocol supported by Hyper-V.
#[derive(Debug, Copy, Clone)]
#[repr(u32)]
enum SyntheticVideoProtocolVersion {
    VersionWin7 = 3, // (0 << 16) | 3
    VersionWin8 = (2 << 16) | 3,
    VersionWin10 = (5 << 16) | 3,
}

/// Represents a request message to negotiate the synthetic video protocol version.
///
/// This message is sent by the guest to the host to indicate
/// which version of the synthetic video protocol it supports.
#[derive(Debug, Copy, Clone)]
#[repr(C, packed)]
struct SyntheticVideoProtocolVersionRequest {
    /// The common synthetic video message header containing the message type and payload size.
    header: SyntheticVideoHeader,

    /// The requested protocol version
    version: SyntheticVideoProtocolVersion,
}

/// Represents a response message from the host indicating the accepted synthetic video protocol version.
#[derive(Debug, Copy, Clone)]
#[repr(C, packed)]
struct SyntheticVideoProtocolVersionResponse {
    /// The common synthetic video message header containing the message type and payload size.
    header: SyntheticVideoHeader,

    /// The synthetic video protocol version supported by the host.
    host_version: SyntheticVideoProtocolVersion,

    /// Bool indicating if the requested version was accepted.
    accepted: bool,

    /// The maximum number of video outputs supported by the host (we assume it's always 1).
    max_video_outputs: u8,
}

/// Request from the guest to the host asking for a list of supported video resolutions.
///
/// This message is sent after protocol version negotiation to discover which screen
/// resolutions the host's synthetic video device supports.
#[derive(Debug, Copy, Clone)]
#[repr(C, packed)]
struct SyntheticVideoSupportedResolutionsRequest {
    /// The common synthetic video message header containing the message type and payload size.
    header: SyntheticVideoHeader,

    /// The maximum number of resolutions the guest wants the host to return in response limited by [SYNTHETIC_VIDEO_MAX_RESOLUTION_COUNT]
    maximum_resolution_count: u8,
}

/// Response from the host providing supported video resolutions and EDID information.
///
/// This message is sent in reply to [SyntheticVideoSupportedResolutionsRequest].
/// It contains detailed information about the display capabilities supported by
/// the synthetic video device.
#[derive(Debug, Copy, Clone)]
#[repr(C, packed)]
struct SyntheticVideoSupportedResolutionsResponse {
    /// The common synthetic video message header containing the message type and payload size.
    header: SyntheticVideoHeader,

    /// A raw EDID (Extended Display Identification Data) block describing the monitor capabilities.
    edid_block: [u8; EDID_BLOCK_SIZE],

    /// The number of supported resolutions included in the response.
    resolution_count: u8,

    ///  The index of the default resolution within the `supported_resolutions` array.
    default_resolution_index: u8,

    /// Indicates whether the supported resolutions is standard.
    is_standard: bool,

    /// An array containing detailed information about each supported resolution, such as width and height.
    supported_resolutions: [SyntheticVideoResolutionInfo; SYNTHETIC_VIDEO_MAX_RESOLUTION_COUNT],
}

/// Information about a single supported video resolution.
#[derive(Debug, Copy, Clone)]
#[repr(C, packed)]
struct SyntheticVideoResolutionInfo {
    /// Width in pixels.
    width: u16,

    /// Height in pixels.
    height: u16,
}

/// Notification from the host indicating which video features require updates.
#[derive(Debug, Copy, Clone)]
#[repr(C, packed)]
struct SyntheticVideoFeatureChange {
    /// The common synthetic video message header containing the message type and payload size.
    header: SyntheticVideoHeader,

    /// Indicates that host expects VRAM update.
    is_iamge_update_needed: bool,

    /// Indicates that host expects cursor position update.
    is_cursor_position_needed: bool,

    /// Indicates that host expects cursor shape update.
    is_cursor_shape_needed: bool,

    /// Indicates that host expects resolution update.
    is_resolution_update_needed: bool,
}

/// Represents a message that specifies the location of the video RAM (VRAM) buffer
/// used by the synthetic video device.
#[derive(Debug, Copy, Clone)]
#[repr(C, packed)]
struct SyntheticVideoVramLocation {
    /// The common synthetic video message header containing the message type and payload size.
    header: SyntheticVideoHeader,

    /// User-defined context.
    user_context: u64,

    /// Indicates whether the VRAM GPA (Guest Physical Address) is specified.
    is_vram_gpa_specified: bool,

    /// The Guest Physical Address of the VRAM if specified.
    vram_gpa: u64,
}

/// Acknowledgment message sent by the host in response to a [SyntheticVideoVramLocation]
/// message from the guest.
///
/// The `user_context` field matches the context provided in the original VRAM location
/// message.
#[derive(Debug, Copy, Clone)]
#[repr(C, packed)]
struct SyntheticVideoVramLocationAck {
    /// The common synthetic video message header containing the message type and payload size.
    header: SyntheticVideoHeader,

    /// User-defined context matching the original VRAM location message.
    user_context: u64,
}

/// Represents the position and visibility state of the pointer (mouse cursor) on the synthetic video output.
#[derive(Debug, Copy, Clone)]
#[repr(C, packed)]
struct SyntheticVideoPointerPosition {
    /// The common synthetic video message header containing the message type and payload size.
    header: SyntheticVideoHeader,

    /// Whether the pointer is currently visible. This field seems to does not work correctly.
    is_visible: bool,

    /// Identifier of the video output (usually 0).
    video_output: u8,

    /// Horizontal position of the pointer.
    x: i32,

    /// Vertical position of the pointer.
    y: i32,
}

/// Defines the shape and appearance of the pointer (mouse cursor) in the synthetic video interface.
#[derive(Debug, Copy, Clone)]
#[repr(C, packed)]
struct SyntheticVideoPointerShape {
    /// The common synthetic video message header containing the message type and payload size.
    header: SyntheticVideoHeader,

    /// Index of this shape part (used if cursor shape is split into multiple parts).
    part_index: u8,

    /// Whether the pixel data is in ARGB format.
    is_argb: bool,

    /// Width of the cursor shape in pixels (maximum 96).
    width: u32,

    /// Height of the cursor shape in pixels (maximum 96).
    height: u32,

    /// Horizontal hotspot coordinate — the cursor’s "active point" relative to the shape.
    hot_x: u32,

    /// Vertical hotspot coordinate — the cursor’s "active point" relative to the shape.
    hot_y: u32,

    /// Raw pixel data representing the cursor shape bitmap.
    data: [u8; 4],
}

/// Represents a situation update message in the synthetic video protocol.
#[derive(Debug, Copy, Clone)]
#[repr(C, packed)]
struct SyntheticVideoSituationUpdate {
    /// The common synthetic video message header containing the message type and payload size.
    header: SyntheticVideoHeader,

    /// User context identifier.
    user_ctx: u64,

    /// Number of video outputs being reported (always 1).
    video_output_count: u8,

    /// Array of video output situations (always contains a single entry).
    video_output: [SyntheticVideoOutputSituation; 1],
}

/// Describes the current configuration of a video output.
#[derive(Debug, Copy, Clone)]
#[repr(C, packed)]
struct SyntheticVideoOutputSituation {
    /// Whether the video output is active.
    active: bool,

    /// Offset in VRAM where this output's framebuffer begins (usually 0).
    vram_offset: u32,

    /// Number of bits used per pixel (color depth).
    depth_bits: u8,

    /// Width of the display in pixels.
    width_pixels: u32,

    /// Height of the display in pixels.
    height_pixels: u32,

    /// This value represents the number of bytes in a single scanline of the framebuffer.
    /// It is calculated as:
    ///
    /// ```text
    /// pitch_bytes = width_pixels * bits_per_pixel / 8
    /// ```
    ///
    /// For example, with `width_pixels = 1920` and `depth_bits = 32`,
    /// the pitch would be:
    ///
    /// ```text
    /// pitch_bytes = 1920 * 32 / 8 = 7680 bytes per scanline
    /// ```
    pitch_bytes: u32,
}

/// Represents a "dirt" (dirty region) notification from the guest.
///
/// This message tells the host which areas of the framebuffer have been updated
/// and need to be redrawn.
#[derive(Debug, Copy, Clone)]
#[repr(C, packed)]
struct SyntheticVideoDirt {
    /// The common synthetic video message header containing the message type and payload size.
    header: SyntheticVideoHeader,

    /// Number of video output being updated (always 1).
    video_output: u8,

    /// Number of dirty rectangles described in `rectangle`.
    dirt_count: u8,

    /// Array of rectangles marking updated regions of VRAM.
    ///
    /// Typically this is a variable-length array, but often only one rectangle
    /// is sent per message.
    rectange: [SyntheticVideoRectangle; 1],
}

/// Represents a rectangular region within the framebuffer.
///
/// Used in [SyntheticVideoDirt] messages to describe updated ("dirty") areas
/// that need to be redrawn.
#[derive(Debug, Copy, Clone)]
#[repr(C, packed)]
struct SyntheticVideoRectangle {
    /// X coordinate of the top-left corner.
    x1: i32,

    /// Y coordinate of the top-left corner.
    y1: i32,

    /// X coordinate of the bottom-right corner.
    x2: i32,

    /// Y coordinate of the bottom-right corner.
    y2: i32,
}

pub struct VmBusSyntheticVideoDriver {
    pub channel: VmBusChannel,
    pub offer: VmBusOfferChannel,
    pub state: RwLock<VmBusSyntheticVideoDriverState>,
}

pub struct VmBusSyntheticVideoDriverState {
    pub initialized: bool,
    pub message_received: Arc<OneshotGate>,

    pub next_xid: AtomicU64,
    pub supported_resolutions: Vec<Resolution>,
    pub current_resolution: Resolution,
    pub framebuffer_base: VirtualAddress,
}

impl VmBusSyntheticVideoDriver {
    pub fn new(channel: VmBusChannel, offer: VmBusOfferChannel) -> Self {
        Self {
            channel,
            offer,
            state: RwLock::new(VmBusSyntheticVideoDriverState {
                initialized: false,
                next_xid: AtomicU64::new(200),
                supported_resolutions: Vec::new(),
                current_resolution: Resolution {
                    height: 0,
                    width: 0,
                },
                framebuffer_base: VirtualAddress::new(0),
                message_received: Arc::new(OneshotGate::new()),
            }),
        }
    }
}

impl VmBusSyntheticDevice for VmBusSyntheticVideoDriver {
    fn initialize(&self) -> bool {
        let gate = Arc::clone(&self.state.read().message_received);

        // Synthetic device seems to always send packets with transaction id=0, so it's unable to do proper
        // transaction system with waiting for answers. For every error in protocol negotiation, we panic at
        // ISR anyways, so let's just assume we can send bulk of messages for the VSP.

        // The initialization begins by negotiating protocol version
        let protocol_request = SyntheticVideoProtocolVersionRequest {
            header: SyntheticVideoHeader::with_type_and_size(
                SyntheticVideoMessageType::VersionRequest,
                size_of::<SyntheticVideoProtocolVersionRequest>() as u32,
            ),
            version: SyntheticVideoProtocolVersion::VersionWin10,
        };

        self.send_packet(&protocol_request);

        gate.wait();
        unsafe { gate.reset() };

        // Query all supported resolutions from the guest. We will save them at ISR for further processing.
        let resolutions_request = SyntheticVideoSupportedResolutionsRequest {
            header: SyntheticVideoHeader::with_type_and_size(
                SyntheticVideoMessageType::ResolutionRequest,
                size_of::<SyntheticVideoSupportedResolutionsRequest>() as u32,
            ),
            maximum_resolution_count: SYNTHETIC_VIDEO_MAX_RESOLUTION_COUNT as u8,
        };

        self.send_packet(&resolutions_request);

        gate.wait();
        unsafe { gate.reset() };

        // Calculate framebuffer size. mmio_megabytes contains value that will be big enough to handle the biggest
        // supported resolutions with ARGB mode.
        let fb_page_count = (self.offer.mmio_megabytes as usize * 1024 * 1024) / HYPERV_PAGE_SIZE;

        let mut memory_manager = memory_manager().write();

        // Framebuffer must be physically contiguous
        let framebuffer_frame = memory_manager
            .allocate_frames_contiguous(fb_page_count)
            .unwrap();

        let framebuffer_base = unsafe {
            memory_manager.map_any_contiguous(
                CurrentAddressSpace,
                Range::from(256..512),
                FrameRange::new(
                    framebuffer_frame.address(),
                    PhysicalAddress::new(
                        framebuffer_frame.address().as_u64()
                            + (fb_page_count * HYPERV_PAGE_SIZE) as u64,
                    ),
                ),
                PageFlags::WRITABLE | PageFlags::DISABLE_CACHING,
            )
        };

        self.state.write().framebuffer_base = framebuffer_base.start();

        // Send VRAM location to the host.
        let vram_location = SyntheticVideoVramLocation {
            header: SyntheticVideoHeader::with_type_and_size(
                SyntheticVideoMessageType::VramLocation,
                size_of::<SyntheticVideoVramLocation>() as u32,
            ),
            user_context: SYNTHETIC_VIDEO_USER_CONTEXT,
            is_vram_gpa_specified: true,
            vram_gpa: framebuffer_frame.address().as_u64(),
        };

        self.send_packet(&vram_location);

        gate.wait();
        unsafe { gate.reset() };

        // Set pointer position. `is_visible` field seems to not work correctly, so let's just put the pointer somewhere in memory, because
        // we won't use it anyways, but the device protocol requires us to send this packet.
        let pointer = SyntheticVideoPointerPosition {
            header: SyntheticVideoHeader::with_type_and_size(
                SyntheticVideoMessageType::PointerPosition,
                size_of::<SyntheticVideoPointerPosition>() as u32,
            ),
            is_visible: true,
            video_output: 0,
            x: 32,
            y: 32,
        };

        self.send_packet(&pointer);

        gate.wait();
        unsafe { gate.reset() };

        // Send pointer bitmap. We don't use Hyper-V provided pointer - the GUI subsystem will be responsible for this.
        // Send empty pointer, because Hyper-V requires us to send this packet.
        let shape = SyntheticVideoPointerShape {
            header: SyntheticVideoHeader::with_type_and_size(
                SyntheticVideoMessageType::PointerShape,
                size_of::<SyntheticVideoPointerShape>() as u32,
            ),
            part_index: u8::MAX,
            is_argb: true,
            width: 1,
            height: 1,
            hot_x: 0,
            hot_y: 0,
            data: [0, 1, 1, 1],
        };

        self.send_packet(&shape);

        gate.wait();
        unsafe { gate.reset() };

        // Send packet with resolution and pitch bytes. Those are default values we use, but GUI subsystem can change
        // resolution at any time using self.set_resolution.
        self.set_resolution(Resolution {
            width: 1600,
            height: 900,
        });

        // Now, when we didn't panic in ISR, the graphic device is fully initialized.
        self.state.write().initialized = true;

        true
    }

    fn has_data_to_process(&self) -> bool {
        self.channel.has_data_to_process()
    }

    fn process_incoming_data(&self) {
        self.channel.disable_interrupts();

        while let Some(packet) = self.channel.read() {
            let _pipe_header =
                unsafe { *(packet.data.as_ptr() as *const _ as *const VmBusPipeHeader) };
            let synthvid_data_ptr =
                unsafe { packet.data.as_ptr().add(size_of::<SyntheticVideoHeader>()) };
            let synthvid_header = unsafe { *(synthvid_data_ptr as *const SyntheticVideoHeader) };

            match synthvid_header.message_type {
                SyntheticVideoMessageType::VersionResponse => {
                    let pkt = unsafe {
                        *(synthvid_data_ptr as *const SyntheticVideoProtocolVersionResponse)
                    };

                    self.state.read().message_received.open();

                    assert!(pkt.accepted);
                }
                SyntheticVideoMessageType::FeatureChange => {
                    let _pkt =
                        unsafe { *(synthvid_data_ptr as *const SyntheticVideoFeatureChange) };

                    self.state.read().message_received.open();

                    assert!(!self.state.read().initialized);
                }
                SyntheticVideoMessageType::VramLocationAck => {
                    let pkt =
                        unsafe { *(synthvid_data_ptr as *const SyntheticVideoVramLocationAck) };

                    self.state.read().message_received.open();

                    let context = pkt.user_context;
                    assert_eq!(context, SYNTHETIC_VIDEO_USER_CONTEXT);
                }
                SyntheticVideoMessageType::ResolutionResponse => {
                    let pkt = unsafe {
                        *(synthvid_data_ptr as *const SyntheticVideoSupportedResolutionsResponse)
                    };

                    let resolution_count = pkt.resolution_count;
                    let mut resolutions = Vec::with_capacity(resolution_count as usize);
                    for i in 0..resolution_count {
                        let res = pkt.supported_resolutions[i as usize];

                        resolutions.push(Resolution {
                            width: res.width as usize,
                            height: res.height as usize,
                        });
                    }

                    let mut state = self.state.write();
                    state.supported_resolutions = resolutions;

                    let current_resolution_index = pkt.default_resolution_index;
                    state.current_resolution =
                        state.supported_resolutions[current_resolution_index as usize];

                    state.message_received.open();
                }
                SyntheticVideoMessageType::SituationUpdateAck => {
                    // Nothing to do here
                }
                _ => unreachable!(),
            }
        }

        self.channel.enable_interrupts();
    }
}

impl VmBusSyntheticVideoDriver {
    fn set_resolution(&self, resolution: Resolution) {
        assert!(
            self.state
                .read()
                .supported_resolutions
                .iter()
                .any(|res| { res.height == resolution.height && res.width == resolution.width })
        );

        let situation_update = SyntheticVideoSituationUpdate {
            header: SyntheticVideoHeader::with_type_and_size(
                SyntheticVideoMessageType::SituationUpdate,
                size_of::<SyntheticVideoSituationUpdate>() as u32,
            ),
            user_ctx: SYNTHETIC_VIDEO_USER_CONTEXT,
            video_output_count: 1,
            video_output: [SyntheticVideoOutputSituation {
                active: true,
                vram_offset: 0,
                depth_bits: 32,
                width_pixels: resolution.width as u32,
                height_pixels: resolution.height as u32,
                pitch_bytes: resolution.width as u32 * 32 / 8,
            }],
        };

        self.send_packet(&situation_update);
    }

    fn update_dirty_rectangle(&self, rect: DirtyRectangle) {
        let current_resolution = self.state.read().current_resolution;
        assert!(rect.x1 <= current_resolution.width as i32);
        assert!(rect.x2 <= current_resolution.width as i32);
        assert!(rect.y1 <= current_resolution.height as i32);
        assert!(rect.y2 <= current_resolution.height as i32);

        let dirt = SyntheticVideoDirt {
            header: SyntheticVideoHeader::with_type_and_size(
                SyntheticVideoMessageType::Dirt,
                size_of::<SyntheticVideoDirt>() as u32,
            ),
            video_output: 0,
            dirt_count: 1,
            rectange: [SyntheticVideoRectangle {
                x1: rect.x1,
                y1: rect.y1,
                x2: rect.x2,
                y2: rect.y2,
            }],
        };

        self.send_packet(&dirt);
    }

    fn send_packet<T>(&self, packet: &T) {
        let pipe_header_len = size_of::<VmBusPipeHeader>();
        let pipe = VmBusPipeHeader {
            message_type: VmBusPipeMessageType::Data,
            size: size_of::<T>() as u32,
        };

        let buffer_len = pipe_header_len + size_of::<T>();

        let mut buffer = alloc::vec![0u8; buffer_len];
        let buffer_ptr = buffer.as_mut_ptr();
        unsafe {
            ptr::copy(&pipe as *const _ as *const u8, buffer_ptr, pipe_header_len);
            ptr::copy(
                packet as *const _ as *const u8,
                buffer_ptr.add(pipe_header_len),
                size_of::<T>(),
            );
        }

        let xid = self.state.read().next_xid.fetch_add(1, Ordering::Relaxed);

        self.channel.send_packet(
            buffer_ptr as *const u8,
            buffer_len,
            xid,
            true,
            VmBusPacketType::DataInband,
        );
    }
}

unsafe impl Sync for VmBusSyntheticVideoDriver {}
unsafe impl Send for VmBusSyntheticVideoDriver {}
