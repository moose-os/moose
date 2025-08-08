//! # VMBus Packet Layout
//!
//! VMBus packets stored in the ring buffer follow a consistent structure to
//! allow both the host and guest to parse them efficiently.
//!
//! ## Memory Layout in the Ring Buffer
//! ```text
//!  ┌──────────────────────────────────────────────────────────────────────┐
//!  │                       VMBus Packet (in ring buffer)                  │
//!  ├──────────────────────────────────────────────────────────────────────┤
//!  │ Packet Header                                                        │
//!  │   - VmBusNormalPacketHeader or derived type                          │
//!  │   - Contains type, length, flags, transaction ID, etc.               │
//!  ├──────────────────────────────────────────────────────────────────────┤
//!  │ Optional GPA Range(s) or Xfer Page Header                            │
//!  │   - Used if the packet includes references to guest physical memory  │
//!  ├──────────────────────────────────────────────────────────────────────┤
//!  │ Packet Data                                                          │
//!  │   - Payload data (size depends on `packet_len_qword`)                │
//!  ├──────────────────────────────────────────────────────────────────────┤
//!  │ Padding (Alignment)                                                  │
//!  │   - Aligns packet to 8-byte boundary                                 │
//!  ├──────────────────────────────────────────────────────────────────────┤
//!  │ Packet Footer                                                        │
//!  │   - VmBusPacketFooter                                                │
//!  │   - Contains `first_byte_of_packet` offset to rewind if needed       │
//!  └──────────────────────────────────────────────────────────────────────┘
//!
//! ## Notes
//! - The `packet_len_qword` in the header determines how much space the
//!   packet occupies (including header and data without the footer).
//! - Padding ensures that packets start at properly aligned boundaries
//!   for performance reasons.
//!
//! ## Visual Summary
//! ```text
//! [Header] → [Optional GPA/Xfer] → [Data] → [Padding] → [Footer]
//! ```
//!
//!
//! # VMBus Packet Types: Normal vs GPA Direct vs Xfer Page
//!
//! VMBus supports several packet formats, all of which begin with a
//! `VmBusNormalPacketHeader`. The differences are in the fields that
//! follow the header.
//!
//! ## 1️⃣ Normal Packet
//! - The most common packet type.
//! - Contains only a header + payload data.
//!
//! ```text
//! ┌───────────────────────────────────────────────┐
//! │ VmBusNormalPacketHeader                       │
//! │   - packet_type (u16)                         │
//! │   - header_len_qword                          │
//! │   - packet_len_qword                          │
//! │   - flags                                     │
//! │   - xid (transaction id)                      │
//! ├───────────────────────────────────────────────┤
//! │ Payload Data                                  │
//! ├───────────────────────────────────────────────┤
//! │ Padding (alignment)                           │
//! ├───────────────────────────────────────────────┤
//! │ VmBusPacketFooter                             │
//! └───────────────────────────────────────────────┘
//! ```
//!
//! ## 2️⃣ GPA Direct Packet
//! - Used when referencing **guest physical addresses** directly.
//! - Contains GPA ranges that point to memory pages holding the data.
//! - It always comes within a data packet placed in the channel's ring buffer holding
//!   an information about the operation the driver wants to perform (i.e. write some data
//!   to the IDE disk) and separate buffer at the PFN specified in `VmBusGpaRange` containing
//!   the actual data we want to write to the disk (most of the time data packet will be small,
//!   like 50 bytes and buffer will be huge, like megabytes of data).
//! - Used in guest->host transfers mostly
//!
//! ```text
//! ┌───────────────────────────────────────────────┐
//! │ VmBusNormalPacketHeader                       │
//! ├───────────────────────────────────────────────┤
//! │ Reserved (u32)                                │
//! │ Range Count (u32)                             │
//! │ VmBusGpaRange                                 │
//! │   - byte_count                                │
//! │   - starting_byte_offset                      │
//! │   - PFNs follow inline (variable length)      │
//! ├───────────────────────────────────────────────┤
//! │ Payload                                       │
//! ├───────────────────────────────────────────────┤
//! │ Padding + Footer                              │
//! └───────────────────────────────────────────────┘
//! ```
//!
//! ## 3️⃣ Xfer Page Packet
//! - Used for transfers from previously allocated block of memory and sent to the host before the transaction.
//!   It can be used for example in NIC card driver, where we send to the host big receive buffer (n megabytes), and
//!   host writes network packets to this buffer directly.
//! - Contains a page set ID and a list of GPA ranges (usually just one).
//!
//! ```text
//! ┌───────────────────────────────────────────────┐
//! │ VmBusNormalPacketHeader                       │
//! ├───────────────────────────────────────────────┤
//! │ Page Set ID (u16)                             │
//! │ Sender Owns Page Set (bool)                   │
//! │ Reserved (u8)                                 │
//! │ Range Count (u32)                             │
//! │ [VmBusGpaRange; Range Count]                  │
//! │   - byte_count                                │
//! │   - starting_byte_offset                      │
//! │   - PFNs follow inline                        │
//! ├───────────────────────────────────────────────┤
//! │ Payload                                       │
//! ├───────────────────────────────────────────────┤
//! │ Padding + Footer                              │
//! └───────────────────────────────────────────────┘
//! ```
//!
//! ## Summary Table
//! | Packet Type      | Extra Fields After Header      | Usage                          
//! |------------------|--------------------------------|---------------------------------------------------------------------------|
//! | Normal           | None                           | Standard data packets                                                     |
//! | GPA Direct       | GPA ranges + PFNs              | Guest->Host transfers with separate data buffer somewhere in memory       |
//! | Xfer Page        | Page set ID + GPA ranges + PFNs| Host->Guest transfers with separate data buffer allocated previously      |
//!
//! # VMBus Channel Setup Flow
//!
//! This diagram shows the **typical sequence of `HvMessage` exchanges**
//! between the guest (VM) and the Hyper-V host during channel setup.
//!
//! ## Legend
//! - **VM → Host** : Message sent from guest to Hyper-V.
//! - **Host → VM** : Message sent from Hyper-V to guest.
//!
//! ```text
//! ┌─────────────────────────────┐          ┌─────────────────────────────┐
//! │           Guest VM          │          │         Hyper-V Host        │
//! └─────────────────────────────┘          └─────────────────────────────┘
//!               │                                      │
//!               │ InitiateContact (14)                 │
//!               │─────────────────────────────────────>│
//!               │                                      │
//!               │      VersionResponse (15)            │
//!               │<─────────────────────────────────────│
//!               │                                      │
//!               │      RequestOffers (3)               │
//!               │─────────────────────────────────────>│
//!               │                                      │
//!               │      OfferChannel (1)                │
//!               │<─────────────────────────────────────│
//!               │                                      │
//!               │      GpadlHeader(8)                  │
//!               │─────────────────────────────────────>│
//!               │                                      │
//!               │      GpadlCreated (10)               │
//!               │<─────────────────────────────────────│
//!               │                                      │
//!               │      OpenChannel (5)                 │
//!               │─────────────────────────────────────>│
//!               │                                      │
//!               │      OpenChannelResult (6)           │
//!               │<─────────────────────────────────────│
//!               │                                      │
//!          [Channel is now OPEN and ready for I/O]     │
//!               │                                      │
//! ```
//!
//! ## Notes
//! - [VmBusMessageType::InitiateContact] and [VmBusMessageType::VersionResponse] negotiate protocol version and message pages.
//! - [VmBusMessageType::RequestOffers] asks the host to enumerate available channels.
//! - [VmBusMessageType::OfferChannel] is sent by the host for each available channel.
//! - [VmBusMessageType::OpenChannel] along with [VmBusMessageType::GpadlHeader] maps ring buffers into shared memory.
//! - [VmBusMessageType::GpadlCreated] confirms that the shared memory mapping is ready.
//! - [VmBusMessageType::OpenChannelResult] signals that the channel is ready for packet exchange.
//!
//!
//!
//! # VMBus initialization sequence flow
//!
//! ```text
/// ┌───────────────────────────────────────────┐
/// │ Guest VM Boot                             │
/// └───────────────────────────────────────────┘
///                  │
///                  ▼
///        Set Guest OS ID (MSR 0x40000000)
///        ┌────────────────────────────────────┐
///        │ RAX = HYPERVISOR_OS_ID             │
///        │ WRMSR(HYPERV_X64_MSR_GUEST_OS_ID)  │
///        └────────────────────────────────────┘
///                  │
///                  ▼
///        Configure Hypercall Page (MSR 0x40000001)
///        ┌───────────────────────────────────┐
///        │ RAX = Hypercall GPA | ENABLE BIT  │
///        │ WRMSR(HYPERV_X64_MSR_HYPERCALL)   │
///        └───────────────────────────────────┘
///                  │
///                  ▼
///        Configure Message & Event Pages
///        ┌──────────────────────────────────────────┐
///        │ RAX = Message Page GPA                   │
///        │ WRMSR(HYPERV_X64_MSR_SIMP)               │
///        │                                          │
///        │ RAX = Event Page GPA                     │
///        │ WRMSR(HYPERV_X64_MSR_SIEFP)              │
///        └──────────────────────────────────────────┘
///                  │
///                  ▼
///        Configure Synthetic Interrupt (SINT)
///        ┌──────────────────────────────────────────┐
///        │ RAX = VECTOR(HYPERV_IRQ_VECTOR) | ENABLE │
///        │ WRMSR(HYPERV_X64_MSR_SINT0)              │
///        └──────────────────────────────────────────┘
///                  │
///                  ▼
///        Initiate Contact (Message Type 14)
///        ┌────────────────────────────────────────────────┐
///        │ Send VMBus InitiateContact                     │
///        │   - Version = VERSION_WIN10_V5                 │
///        │   - Connection ID = HYPERV_VMBUS_CONNECTION_ID │
///        └────────────────────────────────────────────────┘
///                  │
///                  ▼
///        VMBus Connection Established
/// ```
use core::{
    alloc::Layout,
    arch::{
        asm,
        x86_64::{__cpuid, _mm_mfence},
    },
    convert, fmt,
    ptr::{self, null, null_mut, write_bytes},
    sync::atomic::{AtomicU32, AtomicU64, Ordering},
};

use alloc::{alloc::dealloc, boxed::Box, string::String, sync::Arc, vec::Vec};
use hashbrown::HashMap;
use log::debug;
use raw_cpuid::{CpuId, Hypervisor};
use spin::{mutex::Mutex, rwlock::RwLock};
use x86_64::{
    instructions::interrupts::without_interrupts, registers::model_specific::Msr,
    structures::idt::InterruptStackFrame,
};

use crate::{
    arch::x86::idt::register_interrupt_handler,
    cpu::ProcessorControlBlock,
    driver::hv::{
        guid::Guid,
        hyperv::{
            channel::VmBusChannel,
            hypercall::{_do_fast_hypercall, create_hypercall_input, hypercall},
            synthetic_device::{
                gpu::{VmBusSyntheticVideoDriver, VmBusSyntheticVideoDriverState},
                keyboard::VmBusKeyboard,
                mouse::VmBusMouseDriver,
                nic::{VmBusNic, VmBusNicState, NETVSC_BASE_XID, NETVSC_RNDIS_BASE_XID},
                Resolution, VmBusSyntheticDevice,
            },
        },
    },
    kernel::kernel_ref,
    memory::{memory_manager, Frame, PageFlags, PhysicalAddress, VirtualAddress, PAGE_SIZE},
};

pub mod channel;
pub mod hypercall;
pub mod ring_buffer;
pub mod synthetic_device;

pub const HVCALL_POST_MESSAGE: u16 = 0x005c;
pub const HVCALL_FAST_SIGNAL_EVENT: u64 = 0x1005D;

pub struct HyperV {
    state: RwLock<HyperVState>,
}

struct HyperVState {
    hypercall_page: u64,
    simp_page: u64,
    siefp_page: u64,
    monitor_page1: u64,
    monitor_page2: u64,

    vmbus_connection_id: u32,
    got_version_response: Mutex<bool>,
    all_offers_delivered: Mutex<bool>,
    offers: RwLock<Vec<VmBusOfferChannel>>,
    next_gpadl_id: AtomicU32,

    new_message_arrived: bool,
    latest_message: HyperVPostMessage,

    drivers: Vec<Arc<dyn VmBusSyntheticDevice>>,
}

/// The size of a Hyper-V memory page.
pub const HYPERV_PAGE_SIZE: usize = PAGE_SIZE;

// Message type used by `PostMessage` hypercall.
pub const HYPERV_POST_MESSAGE_MESSAGE_TYPE: u32 = 1;

/// Default connection ID used by VMBus channels.
const HYPERV_VMBUS_CONNECTION_ID: u32 = 1;

/// MSR for setting the Guest OS ID (used for identifying guest OS to Hyper-V).
const HYPERV_X64_MSR_GUEST_OS_ID: u32 = 0x40000000;

/// MSR used by the guest to register hypercall page.
const HYPERV_X64_MSR_HYPERCALL: u32 = 0x40000001;

/// CPUID leaf to query Hyper-V hypervisor version information.
const HYPERVISOR_VERSION_LEAF: u32 = 0x40000002;

/// MSR to control various Hyper-V features
const HYPERV_X64_MSR_SCONTROL: u32 = 0x40000080;

/// MSR for setting address of the Synthetic Interrupt Event Flags Page.
const HYPERV_X64_MSR_SIEFP: u32 = 0x40000082;

/// MSR for setting address of the Synthetic Interrupt Message Page.
const HYPERV_X64_MSR_SIMP: u32 = 0x40000083;

/// MSR for End-Of-Message notifications to Hyper-V (similar to ACPI's EOI (End of Interrupt)).
const HYPERV_X64_MSR_EOM: u32 = 0x40000084;

/// MSR for synthetic interrupt vector 0 configuration.
const HYPERV_X64_MSR_SINT0: u32 = 0x40000090;

/// MSR for configuring Synthetic Timer 0.
const HYPERV_X64_MSR_STIMER0_CONFIG: u32 = 0x400000B0;

/// MSR for reading Synthetic Timer 0 count value.
const HYPERV_X64_MSR_STIMER0_COUNT: u32 = 0x400000B1;

/// The vector number used by STIMER0.
const STIMER0_SINT: u32 = 1;

/// The vector number used by VMBus synthetic interrupt.
const VMBUS_MESSAGE_SINT: u32 = 2;

/// Version code for Windows 10, version 5 (used in negotiation).
/// We don't support other versions currently.
#[allow(clippy::identity_op)]
const VERSION_WIN10_V5: u32 = ((5 << 16) | (0));

/// Interrupt vector assigned for Synthetic Timer 0.
const HYPERV_STIMER0_VECTOR: u8 = 246;

/// Interrupt vector assigned for general Hyper-V IRQ.
const HYPERV_VMBUS_IRQ_VECTOR: u8 = 247;

// Each Hyper-V device or service is uniquely identified by a GUID (Globally Unique Identifier).
// These GUIDs enable the guest and host to recognize and communicate with specific virtual devices,
// ensuring correct routing of messages and proper initialization of services.

/// GUID for the Hyper-V Network Interface Card (NIC) service.
pub const HYPERV_NIC_GUID: Guid = Guid::from_str("f8615163-df3e-46c5-913f-f2d2f965ed0e");

/// GUID for the Hyper-V IDE controller service.
pub const HYPERV_IDE_GUID: Guid = Guid::from_str("32412632-86cb-44a2-9b5c-50d1417354f5");

/// GUID for the Hyper-V SCSI controller service.
pub const HYPERV_SCSI_GUID: Guid = Guid::from_str("ba6163d9-04a1-4d29-b605-72e2ffb1dc7f");

/// GUID for the Hyper-V Shutdown service (handles guest shutdown requests).
pub const HYPERV_SHUTDOWN_GUID: Guid = Guid::from_str("0e0b6031-5213-4934-818b-38d90ced39db");

/// GUID for the Hyper-V Time Synchronization service.
pub const HYPERV_TIME_SYNCH_GUID: Guid = Guid::from_str("9527e630-d0ae-497b-adce-e80ab0175caf");

/// GUID for the Hyper-V Heartbeat service (guest health monitoring).
pub const HYPERV_HEARTBEAT_GUID: Guid = Guid::from_str("57164f39-9115-4e78-ab55-382f3bd5422d");

/// GUID for the Hyper-V Key-Value Pair (KVP) service (guest-host data exchange).
pub const HYPERV_KVP_GUID: Guid = Guid::from_str("a9a0f4e7-5a45-4d96-b827-8a841e8c03e6");

/// GUID for the Hyper-V Dynamic Memory service.
pub const HYPERV_DYNAMIC_MEMORY_GUID: Guid = Guid::from_str("525074dc-8985-46e2-8057-a307dc18a502");

/// GUID for the Hyper-V Synthetic Mouse service.
pub const HYPERV_MOUSE_GUID: Guid = Guid::from_str("cfa8b69e-5b4a-4cc0-b98b-8ba1a1f3f95a");

/// GUID for the Hyper-V Synthetic Keyboard service.
pub const HYPERV_KEYBOARD_GUID: Guid = Guid::from_str("f912ad6d-2b17-48ea-bd65-f927a61c7684");

/// GUID for the Hyper-V Volume Shadow Copy Service (VSS) used for backup and restore.
pub const HYPERV_VSS_GUID: Guid = Guid::from_str("35fa2e29-ea23-4236-96ae-3a6ebacba440");

/// GUID for the Hyper-V Synthetic Video service.
pub const HYPERV_SYNTHETIC_VIDEO_GUID: Guid =
    Guid::from_str("da0a7802-e377-4aac-8e77-0558eb1073f8");

/// GUID for the Hyper-V Synthetic Fibre Channel (FC) service.
pub const HYPERV_SYNTHETIC_FC_GUID: Guid = Guid::from_str("2f9bcc4a-0069-4af3-b76b-6fd0be528cda");

/// GUID for the Hyper-V Guest File Copy service.
pub const HYPERV_GUEST_FC_GUID: Guid = Guid::from_str("34d14be3-dee4-41c8-9ae7-6b174977c192");

/// GUID for the Hyper-V Network Direct service (guest RDMA support).
pub const HYPERV_NETWORK_DIRECT_GUID: Guid = Guid::from_str("8c2eaf3d-32a7-4b09-ab99-bd1f1c86b501");

/// GUID for the Hyper-V PCI Express Pass-through service.
pub const HYPERV_PCIE_GUID: Guid = Guid::from_str("44c4f61d-4444-4400-9d52-802e27ede16f");

// Automatic Virtual Machine Activation, Remote Desktop Virtualization and Initial Machine Configuration are used
// only by Windows hosts, but are listed here for completness.
pub const HYPERV_AVMA1_GUID: Guid = Guid::from_str("f8e65716-3cb3-4a06-9a60-1889c5cccab5");
pub const HYPERV_AVMA2_GUID: Guid = Guid::from_str("3375baf4-9e15-4b30-b765-67acb10d607b");
pub const HYPERV_RDV_GUID: Guid = Guid::from_str("276aacf4-ac15-426c-98dd-7521ad3f01fe");
pub const HYPERV_IMC_GUID: Guid = Guid::from_str("c376c1c3-d276-48d2-90a9-c04748072c60");

/// A list of known Hyper-V device and service GUIDs paired with human-readable names.
pub const HYPERV_DEVICE_GUIDS: [(Guid, &str); 20] = [
    (HYPERV_NIC_GUID, "NIC"),
    (HYPERV_IDE_GUID, "IDE"),
    (HYPERV_SCSI_GUID, "SCSI"),
    (HYPERV_SHUTDOWN_GUID, "Shutdown service"),
    (HYPERV_TIME_SYNCH_GUID, "Time synch service"),
    (HYPERV_HEARTBEAT_GUID, "Heartbeat service"),
    (HYPERV_KVP_GUID, "KVP"),
    (HYPERV_DYNAMIC_MEMORY_GUID, "Dynamic memory"),
    (HYPERV_MOUSE_GUID, "Mouse"),
    (HYPERV_KEYBOARD_GUID, "Keyboard"),
    (HYPERV_VSS_GUID, "VSS Backup/Restore"),
    (HYPERV_SYNTHETIC_VIDEO_GUID, "Synthetic video"),
    (HYPERV_SYNTHETIC_FC_GUID, "Synthetic FC"),
    (HYPERV_GUEST_FC_GUID, "Guest file-copy service"),
    (HYPERV_NETWORK_DIRECT_GUID, "Network Direct service"),
    (HYPERV_PCIE_GUID, "PCI-e Pass-through"),
    (
        HYPERV_AVMA1_GUID,
        "Automatic Virtual Machine Activation 1 (Windows only)",
    ),
    (
        HYPERV_AVMA2_GUID,
        "Automatic Virtual Machine Activation 2 (Windows only)",
    ),
    (
        HYPERV_RDV_GUID,
        "Remote Desktop Virtualization (Windows only)",
    ),
    (
        HYPERV_IMC_GUID,
        "Initial Machine Configuration (Windows only)",
    ),
];

/// Starting GPADL (Guest Physical Address Descriptor List) ID.
///
/// Hyper‑V requires each GPADL mapping to have a unique ID.  
/// This constant is the base ID from which new GPADL IDs are assigned.
///
/// The value is the policy decision only.
const HYPERV_GPADL_ID_STARTING_INDEX: u32 = 0x0C89;

/// Represents the VMBus interrupt page shared between guest and host.
///
/// The interrupt page is split into two halves:
/// - **Inbound**: Signals from host to guest (e.g., notifying about incoming data).
/// - **Outbound**: Signals from guest to host (e.g., notifying about sent packets).
///
/// Each half is `HV_PAGE_SIZE / 2` bytes.
#[derive(Copy, Clone, Debug)]
#[repr(C, packed)]
pub struct VmBusInterruptPage {
    inbound: [u8; PAGE_SIZE / 2],
    outbound: [u8; PAGE_SIZE / 2],
}

/// Represents a Hyper‑V post message structure used with the
/// `HYPERV_POST_MESSAGE` hypercall to send messages between
/// partitions or channels.
#[derive(Copy, Clone, Debug)]
#[repr(C, packed)] //align(16))]
pub struct HyperVPostMessage {
    /// Target channel connection ID.
    connection_id: u32,

    /// Reserved (should be set to 0).
    reserved: u32,

    /// Message type
    message_type: u32,

    /// Payload size in bytes (must not exceed 240).
    payload_size: u32,

    /// Message payload.
    payload: [u8; 240],
}

const _: () = assert!(size_of::<HyperVPostMessage>() == 256);

/// Represents the common header for all VMBus messages.
///
/// Every VMBus message starts with this 8‑byte header, which includes
/// the message type and an alignment padding field.
#[derive(Copy, Clone, Debug)]
#[repr(C, packed)]
pub struct VmBusMessageHeader {
    message_type: VmBusMessageType,
    padding: u32,
}

// This enum defines all known message types as defined in the Hyper‑V VMBus protocol.
///
/// > **Note:** Values `18`, `19`, and `20` are currently undefined.
///
/// Reference: Hyper‑V VMBus protocol documentation.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum VmBusMessageType {
    /// Invalid / uninitialized message type.
    Invalid = 0,

    /// Offer a new channel from host to guest.
    OfferChannel = 1,

    /// Rescind a previously offered channel.
    RescindChannelOffer = 2,

    /// Request all pending channel offers from host.
    RequestOffers = 3,

    /// Indicates that all offers have been delivered.
    AllOffersDelivered = 4,

    /// Open a channel to the host.
    OpenChannel = 5,

    /// Result of an open channel request.
    OpenChannelResult = 6,

    /// Close an existing channel.
    CloseChannel = 7,

    /// First GPADL header for mapping guest memory.
    GpadlHeader = 8,

    /// Continuation of GPADL mapping (additional pages).
    GpadlBody = 9,

    /// Acknowledge that a GPADL has been successfully created.
    GpadlCreated = 10,

    /// Request to tear down a GPADL mapping.
    GpadlTeardown = 11,

    /// Acknowledge that a GPADL has been torn down.
    GpadlTorndown = 12,

    /// Release a relative ID (openid) assigned to a channel.
    RelidReleased = 13,

    /// Initiate contact between guest and host (version negotiation).
    InitiateContact = 14,

    /// Response to [`VmBusMessageType::InitiateContact`].
    VersionResponse = 15,

    /// Request to unload VMBus.
    Unload = 16,

    /// Response to [`VmBusMessageType::Unload`].
    UnloadResponse = 17,

    // 18, 19 and 20 are undefined
    /// TL connect request (used by newer VMBus transports).
    TlConnectRequest = 21,

    /// Modify an existing channel.
    ModifyChannel = 22,

    /// Response to [`VmBusMessageType::TlConnectRequest`].
    TlConnectResult = 23,

    /// Response to [`VmBusMessageType::ModifyChannel`].
    ModifyChannelResponse = 24,
}

impl From<u32> for VmBusMessageType {
    fn from(value: u32) -> Self {
        match value {
            0 => VmBusMessageType::Invalid,
            1 => VmBusMessageType::OfferChannel,
            2 => VmBusMessageType::RescindChannelOffer,
            3 => VmBusMessageType::RequestOffers,
            4 => VmBusMessageType::AllOffersDelivered,
            5 => VmBusMessageType::OpenChannel,
            6 => VmBusMessageType::OpenChannelResult,
            7 => VmBusMessageType::CloseChannel,
            8 => VmBusMessageType::GpadlHeader,
            9 => VmBusMessageType::GpadlBody,
            10 => VmBusMessageType::GpadlCreated,
            11 => VmBusMessageType::GpadlTeardown,
            12 => VmBusMessageType::GpadlTorndown,
            13 => VmBusMessageType::RelidReleased,
            14 => VmBusMessageType::InitiateContact,
            15 => VmBusMessageType::VersionResponse,
            16 => VmBusMessageType::Unload,
            17 => VmBusMessageType::UnloadResponse,
            21 => VmBusMessageType::TlConnectRequest,
            22 => VmBusMessageType::ModifyChannel,
            23 => VmBusMessageType::TlConnectResult,
            24 => VmBusMessageType::ModifyChannelResponse,
            _ => unreachable!(),
        }
    }
}

impl VmBusMessageHeader {
    pub fn with_message_type(message_type: VmBusMessageType) -> VmBusMessageHeader {
        VmBusMessageHeader {
            message_type,
            padding: 0,
        }
    }
}

/// VMBus `InitiateContact` message sent by the guest to the host.
///
/// This message is used during the initial handshake to establish
/// communication parameters between the guest and the host. It specifies
/// the requested VMBus protocol version, the target VCPU, and the guest
/// physical addresses of the interrupt and monitor pages.
#[repr(C, packed)]
pub struct VmBusChannelInitiateContact {
    /// Common VMBus message header.
    header: VmBusMessageHeader,

    /// Requested VMBus protocol version.
    requested_version: u32,

    /// VCPU number to which VMBus interrupts should be delivered.
    target_vcpu: u32,

    /// Guest physical address of the interrupt page.
    interrupt_page: u64,

    /// Guest physical address of the first monitor page.
    monitor_page1: u64,

    /// Guest physical address of the second monitor page.
    monitor_page2: u64,
}

/// VMBus `RequestOffers` message.
///
/// Sent by the guest to request all pending channel offers from the host.
#[repr(C, packed)]
pub struct VmBusRequestOffers {
    /// Common VMBus message header.
    header: VmBusMessageHeader,
}

/// VMBus `VersionResponse` message.
///
/// Sent by the host in response to the guest's `InitiateContact` message,
/// indicating whether the requested VMBus protocol version is supported,
/// the connection state, and the assigned connection ID.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct VmBusVersionResponse {
    /// Common VMBus message header.
    header: VmBusMessageHeader,

    /// Boolean flag indicating if the requested version is supported.
    ///  
    /// Represented as a `u8` in memory: 1 = true, 0 = false.
    version_supported: bool,

    /// Current connection state.
    connection_state: u8,

    /// Reserved padding (should be zero).
    padding: u16,

    /// Connection ID assigned by the host.
    new_connection_id: u32,
}

/// Header for a GPADL (Guest Physical Address Descriptor List) message.
///
/// This message is sent to describe memory ranges that the guest wants to
/// share with the host via VMBus. It includes metadata plus one or more
/// `VmBusGpaRange` descriptors describing the physical address ranges.
///
/// The full message layout is:
/// ```text
/// [VmBusGPADLHeader] + [VmBusGpaRange; number_of_range_descriptors] + PFNs array
/// ```
///
/// Note:  
/// - The `range` field here represents the first `VmBusGpaRange`.
/// - Additional `VmBusGpaRange` structs and PFNs (Page Frame Numbers)
///   immediately follow this header in memory but are not represented directly
///   in this Rust struct due to Rust's lack of native support for flexible array members.
#[derive(Copy, Clone, Debug)]
#[repr(C, packed)]
pub struct VmBusGPADLHeader {
    /// Common VMBus message header.
    header: VmBusMessageHeader,

    /// Channel identifier this GPADL relates to.
    channel_id: u32,

    /// GPADL identifier for this memory mapping.
    gpadl_id: u32,

    /// Total length in bytes of all the range descriptors.
    length_of_range_descriptors: u16,

    /// Number of `VmBusGpaRange` descriptors following this header.
    number_of_range_descriptors: u16,

    ///
    /// Originally, message is defined as
    /// range: [VmBusGpaRange; N], where N can be computed using
    ///                            `length_of_range_descriptors` and
    ///                            `number_of_range_descriptors`
    ///
    /// And VmBusGpaRange is defined with
    /// variable sized array of PFNs for each VmBusGpaRange,
    /// but it's hard to implement variable-sized arrays in Rust,
    /// and we don't need so much Ranges separately, because we use
    /// only small subset of VmBus exposed services at the moment.
    ///
    range: VmBusGpaRange,
    // Array of PFNs comes after this structure
    //pfn: [u64]
}

/// Represents a single memory range descriptor in a GPADL (Guest Physical Address Descriptor List).
///
/// This describes a contiguous physical memory region by its byte count and starting offset.
/// The actual page frame numbers (PFNs) that back this memory range follow this structure
/// in memory but are not represented directly in Rust due to variable length.
#[derive(Copy, Clone, Debug)]
#[repr(C, packed)]
pub struct VmBusGpaRange {
    /// Size of this memory range in bytes.
    byte_count: u32,

    /// Starting byte offset within the larger buffer or memory region.
    starting_byte_offset: u32,
    // Followed in memory by an implicit array of PFNs (`[u64; T]`),
    // where the length T can be computed from byte_count and page size.
}

/// GPADL Body message.
///
/// This message contains a continuation of a GPADL message describing
/// additional PFNs (Page Frame Numbers) associated with a previously
/// described GPADL ID.
#[derive(Copy, Clone, Debug)]
#[repr(C, packed)]
pub struct VmBusGPADLBody {
    /// Common VMBus message header.
    header: VmBusMessageHeader,

    /// Sequential message number.
    message_number: u32,

    /// GPADL ID this body is associated with.
    gpadl_id: u32,
    // Followed in memory by an array of PFNs (`u64`),
    // which represent physical page frame numbers.
}

/// Represents a VMBus Offer Channel message.
///
/// Sent by the host to offer a channel to the guest. Contains channel metadata,
/// identifiers, flags, and additional channel-specific data.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct VmBusOfferChannel {
    /// Common VMBus message header.
    header: VmBusMessageHeader,

    /// GUID identifying the channel type.
    channel_type: Guid,

    /// GUID identifying the channel instance.
    channel_instance: Guid,

    /// Reserved padding bytes.
    reserved: [u8; 16],

    /// Flags indicating channel features.
    flags: u16,

    /// Size of MMIO region in megabytes.
    mmio_megabytes: u16,

    /// Channel-specific data
    data: [u8; 120],

    /// Additional reserved padding.
    reserved2: [u8; 4],

    /// Unique channel identifier assigned by the host.
    channel_id: u32,

    /// Monitor ID used for monitoring the channel.
    monitor_id: u8,

    /// Flag indicating if monitor exists.
    monitor_exists: bool,

    /// Bitfield indicating interrupt properties.
    /// Only first bit is used for dedicated interrupt flag.
    has_dedicated_interrupt: u16,

    /// Connection ID associated with the channel.
    connection_id: u32,
}

/// Message sent by the host to confirm the creation of a GPADL (Guest Physical Address Descriptor List).
#[derive(Debug, Copy, Clone)]
#[repr(C, packed)]
pub struct VmBusGpadlCreated {
    /// Common VMBus message header.
    header: VmBusMessageHeader,

    /// Channel ID associated with this GPADL.
    channel_id: u32,

    /// GPADL ID assigned to the created mapping.
    gpadl_id: u32,

    /// Status of the creation operation. Zero indicates success.
    status: u32,
}

/// Message to open a VMBus channel.
///
/// Sent by the guest to request opening a channel with specific parameters.
#[derive(Copy, Clone, Debug)]
#[repr(C, packed)]
pub struct VmBusOpenChannel {
    /// Common VMBus message header.
    header: VmBusMessageHeader,

    /// Channel identifier.
    channel_id: u32,

    /// Identifier for this open request.
    open_id: u32,

    /// GPADL ID of the ring buffer.
    gpadl_id: u32,

    /// Target virtual processor ID.
    target_vp: u32,

    /// Used to determine size of TX and RX buffers.
    outbound_page_offset: u32,

    /// Additional opaque data.
    data: [u8; 120],
}

/// Response message to a channel open request.
#[derive(Copy, Clone, Debug)]
#[repr(C, packed)]
pub struct VmBusOpenChannelResult {
    /// Common VMBus message header.
    header: VmBusMessageHeader,

    /// Channel identifier.
    channel_id: u32,

    /// Identifier matching the open request.
    open_id: u32,

    /// Status of the open operation. Zero indicates success.
    status: u32,
}

/// Header for a normal VMBus packet.
///
/// The `packet_type` field corresponds to `VmBusPacketType` values,  
/// but here it is stored as a `u16` (instead of the usual `u64`).
#[derive(Copy, Clone, Debug)]
#[repr(C, packed)]
pub struct VmBusNormalPacketHeader {
    /// Packet type identifier (u16), representing a VmBusPacketType.
    packet_type: u16,

    /// Length of this header in 8-byte units (qwords).
    header_len_qword: u16,

    /// Total packet length in qwords.
    packet_len_qword: u16,

    /// Flags associated with this packet.
    flags: u16,

    /// Transaction ID for matching requests and responses.
    xid: u64,
}

/// Header for a VMBus GPA Direct message.
///
/// This structure extends the normal VMBus packet header to describe one or more
/// physical memory ranges (GPAs) directly included in the message. It is typically
/// used when transferring large buffers or memory regions.
///
/// Note: The array of PFNs (page frame numbers) follows this struct in memory, and
/// its length is derived from the GPA ranges.
///
/// # Difference from `VmBusNormalPacketHeader`
///
/// - The `VmBusNormalPacketHeader` is a generic header for typical VMBus packets,
///   containing basic fields such as packet type, header length, total packet length,
///   flags, and a transaction ID (`xid`).
///
/// - The `VmBusGpaDirectHeader` embeds the `VmBusNormalPacketHeader` but adds additional
///   fields (`reserved`, `range_count`, and `range`) to describe one or more physical
///   memory ranges (GPAs) directly in the message.
///
/// - `VmBusGpaDirectHeader` is used when the packet needs to convey physical memory
///   descriptors (GPAs and PFNs), enabling the recipient to directly access or map
///   these memory ranges.
///
/// - `VmBusGpaDirectHeader` is used typically in guest->host transfers because guest can specify
///   any rangeof GPAs with specific data.
#[derive(Copy, Clone, Debug)]
#[repr(C, packed)]
pub struct VmBusGpaDirectHeader {
    /// Embedded normal VMBus packet header.
    header: VmBusNormalPacketHeader,

    /// Reserved field, must be zero.
    reserved: u32,

    /// Number of GPA ranges described by this message.
    range_count: u32,

    /// The first GPA range descriptor.
    range: VmBusGpaRange,
    // Array of PFNs (page frame numbers) follows this structure in memory.
    // pfn: [u64]
}

/// VMBus Transfer Page Header.
///
/// This packet header is used for VMBus "transfer page" operations, which are
/// similar to GPA Direct packets but are used mostly in host->guest transfers, and
/// the PFN always have to be inside previously allocated memory region.
///
/// After the `range` field, an array of PFNs (page frame numbers) follows in memory,
/// as with GPA Direct.
#[derive(Copy, Clone, Debug)]
#[repr(C, packed)]
pub struct VmBusXferPageHeader {
    /// Embedded normal VMBus packet header.
    header: VmBusNormalPacketHeader,

    /// Identifier for the page set.
    page_set_id: u16,

    /// Indicates if the sender retains ownership of the page set.
    sender_owns_page_set: bool,

    /// Reserved field, must be zero.
    reserved: u8,

    /// Number of GPA ranges described.
    range_count: u32,

    /// First GPA range descriptor.
    range: [VmBusGpaRange; 1],
}

/// Represents a generic VMBus packet header.
///
/// VMBus packets can come in multiple formats depending on the type of operation.
/// This enum abstracts over the two common header types:
/// - **Normal Packet Header** (`VmBusNormalPacketHeader`) —
///   Standard header for most channel messages.
/// - **Transfer Page Header** (`VmBusXferPageHeader`) —
///   Used when sending a page set (GPAs allocated before).
///
/// The packet type can be determined from the `packet_type` field inside the
/// `VmBusNormalPacketHeader` embedded in either variant.
#[derive(Debug, Copy, Clone)]
pub enum VmBusPacketHeader {
    Packet(VmBusNormalPacketHeader),
    Xfer(VmBusXferPageHeader),
}

/// Footer structure for a VMBus packet.
///
/// The packet footer is placed at the **end** of a VMBus packet in the ring buffer.
/// It serves two main purposes:
/// - Provides alignment/padding at the end of the packet.
/// - Stores a pointer (offset) to the **first byte of the packet**, allowing
///   traversal of packets in reverse if needed.
#[derive(Copy, Clone, Debug)]
#[repr(C, packed)]
pub struct VmBusPacketFooter {
    /// Reserved (should be zero).
    reserved: u32,

    /// Offset in the ring buffer to the first byte of the packet.
    first_byte_of_packet: u32,
}

/// # HvMessage
///
/// The `HvMessage` structure represents a **Hyper-V message** passed
/// between the guest and the hypervisor through the VMBus message page.
///
/// ## Usage
/// - Messages are exchanged over the **message page**, a shared memory page between the guest and host.
///- The `data` section often embeds another structure depending on `message_type`.
/// - Examples of embedded payloads include:
///   - `VmBusOfferChannel`
///   - `VmBusGpadlHeader` / `VmBusGpadlBody`
///   - `VmBusOpenChannel` / `VmBusOpenChannelResult`
#[derive(Copy, Clone, Debug)]
#[repr(C, packed)]
pub struct HvMessage {
    message_type: u32,
    len: u8,
    flags: u8,
    reserved: u16,
    origin: u64,
    data: [u8; 240],
}

/// Represents the type of a VMBus packet exchanged between the guest and the Hyper-V host.
/// Packets correspond to actual data transfer operations or control messages over the VMBus channel.
/// Examples include synchronous requests, establishing or tearing down GPADLs (guest physical address descriptors),
/// and different modes of data transfer (inband, using transfer pages, GPADL, or direct GPA).
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[repr(u64)]
pub enum VmBusPacketType {
    Invalid = 0,
    Synch = 1,
    AddXferPageSet = 2,
    RemoveXferPageSet = 3,
    EstablishGpadl = 4,
    TeardownGpadl = 5,
    DataInband = 6,
    DataUsingXferPages = 7,
    DataUsingGpadl = 8,
    DataUsingGpaDirect = 9,
    CancelRequest = 10,
    Completion = 11,
    DataUsingAdditionalPacket = 12,
    AdditionalData = 13,
}

impl From<u64> for VmBusPacketType {
    fn from(value: u64) -> Self {
        match value {
            0 => VmBusPacketType::Invalid,
            1 => VmBusPacketType::Synch,
            2 => VmBusPacketType::AddXferPageSet,
            3 => VmBusPacketType::RemoveXferPageSet,
            4 => VmBusPacketType::EstablishGpadl,
            5 => VmBusPacketType::TeardownGpadl,
            6 => VmBusPacketType::DataInband,
            7 => VmBusPacketType::DataUsingXferPages,
            8 => VmBusPacketType::DataUsingGpadl,
            9 => VmBusPacketType::DataUsingGpaDirect,
            10 => VmBusPacketType::CancelRequest,
            11 => VmBusPacketType::Completion,
            12 => VmBusPacketType::DataUsingAdditionalPacket,
            13 => VmBusPacketType::AdditionalData,
            _ => unreachable!(),
        }
    }
}

impl HyperV {
    pub fn new() -> HyperV {
        HyperV {
            state: RwLock::new(HyperVState {
                hypercall_page: 0,
                simp_page: 0,
                siefp_page: 0,
                monitor_page1: 0,
                monitor_page2: 0,

                vmbus_connection_id: 1,
                offers: RwLock::new(Vec::new()),
                next_gpadl_id: AtomicU32::new(HYPERV_GPADL_ID_STARTING_INDEX),
                new_message_arrived: false,
                latest_message: HyperVPostMessage {
                    connection_id: 0,
                    reserved: 0,
                    message_type: 0,
                    payload_size: 0,
                    payload: [0u8; 240],
                },
                drivers: Vec::new(),
                got_version_response: Mutex::new(false),
                all_offers_delivered: Mutex::new(false),
            }),
        }
    }

    pub unsafe fn initialize_hv(&self) {
        // Safety assert that we're really running under Hyper-V
        assert_eq!(
            CpuId::new().get_hypervisor_info().unwrap().identify(),
            Hypervisor::HyperV
        );

        let mut memory_manager = memory_manager().write();

        // Query and display the hypervisor version for debugging purposes
        let result = unsafe { __cpuid(HYPERVISOR_VERSION_LEAF) };
        debug!("Build number: 0x{:x}, Major version: 0x{:x}, Minor version: 0x{:x}, ServicePack: {}, ServiceBranch: {}, ServiceNumber: {}",
    result.eax, result.ebx >> 16, result.ebx & 0xFFFF, result.ecx, result.edx >> 24, result.edx & 0xFFF);

        // Identify ourselves to the host
        let mut os_id_msr = Msr::new(HYPERV_X64_MSR_GUEST_OS_ID);
        os_id_msr.write(Self::guest_id());

        // Allocate, map and tell the hypervisor address of Hypercall Page.
        let hypercall_page_frame = memory_manager.allocate_frame().unwrap();
        let mut hypercall_msr = Msr::new(HYPERV_X64_MSR_HYPERCALL);

        // (1 << 0) is enable bit
        hypercall_msr.write(hypercall_msr.read() | hypercall_page_frame.address().as_u64() | 1);

        self.state.write().hypercall_page = memory_manager
            .map_any_for_current_address_space(&hypercall_page_frame, PageFlags::EXECUTABLE)
            .address()
            .as_u64();

        // Setup SynIC

        // Allocate, map and tell the hypervisor address of SIMP page.
        let simp_page_frame = memory_manager.allocate_frame().unwrap();
        assert!(simp_page_frame.address().as_u64() & 0xFFF == 0);
        let mut simp_msr = Msr::new(HYPERV_X64_MSR_SIMP);
        simp_msr.write(simp_msr.read() | simp_page_frame.address().as_u64() | 1);

        // Allocate, map and tell the hypervisor address of SIEFP page.
        let siefp_page_frame = memory_manager.allocate_frame().unwrap();
        assert!(siefp_page_frame.address().as_u64() & 0xFFF == 0);
        let mut siefp_msr = Msr::new(HYPERV_X64_MSR_SIEFP);
        siefp_msr.write(siefp_msr.read() | siefp_page_frame.address().as_u64() | 1);

        // Setup shared SINT
        let mut vmbus_sint_msr = Msr::new(HYPERV_X64_MSR_SINT0 + VMBUS_MESSAGE_SINT);
        let vmbus_sint_value = vmbus_sint_msr.read() & !((1 << 18) | (1 << 17) | (1 << 16) | 0xFF); // clear polling and masked bits
        vmbus_sint_msr.write(vmbus_sint_value | HYPERV_VMBUS_IRQ_VECTOR as u64 | (1 << 17)); // Enable AutoEOI

        // Enable SynIC
        let mut scontrol_msr = Msr::new(HYPERV_X64_MSR_SCONTROL);
        scontrol_msr.write(scontrol_msr.read() | 1);

        // Check if SynIC was enabled successfully (hypervisor change the Enabled bit to 0 in case of any problems)
        assert_eq!(scontrol_msr.read() & 1, 1);
        assert_eq!(simp_msr.read() & 1, 1);

        // Map SIMP and SIEFP
        self.state.write().simp_page = memory_manager
            .map_any_for_current_address_space(&simp_page_frame, PageFlags::WRITABLE)
            .address()
            .as_u64();
        self.state.write().siefp_page = memory_manager
            .map_any_for_current_address_space(&siefp_page_frame, PageFlags::WRITABLE)
            .address()
            .as_u64();

        // Map monitor pages
        self.state.write().monitor_page1 =
            memory_manager.allocate_frame().unwrap().address().as_u64();
        self.state.write().monitor_page2 =
            memory_manager.allocate_frame().unwrap().address().as_u64();

        drop(memory_manager);

        // Register interrupt handler for VMBus related events.
        // It will be responisible for handling VMBus initialization, channel opening and other low level stuff.
        register_interrupt_handler(
            HYPERV_VMBUS_IRQ_VECTOR,
            Box::new(|isf: &InterruptStackFrame| handle_vmbus_irq(isf)),
        );

        // Currently, we still rely on the APIC timer for timekeeping and scheduling.
        // However, Hyper-V also exposes 4 synthetic timers that can be used like regular timers.
        //
        // Normally, when the host writes data to a VMBus channel, it signals the child partition
        // to indicate new data availability.
        // For safety and responsiveness, we also schedule synthetic TIMER0 to fire every 0.5 seconds,
        // polling all channels for incoming data.
        // This prevents potential input lag in case a signal is missed.
        self.enable_timer();

        // Now, when the Hypervisor is initialized, initialize the VMBus itself.
        self.initialize_vmbus();
    }

    /// Initializes the VMBus connection between the guest and Hyper-V host.
    ///
    /// - Sends the `Initiate Contact` message to the host.
    /// - Waits for a version negotiation response.
    /// - Prepares channel offer handling.
    ///
    /// This must be called only once during Hyper-V initialization, after
    /// synthetic timers and Guest OS ID are configured.
    unsafe fn initialize_vmbus(&self) {
        // First, send InitiateContact message
        self.send_initiate_contact();

        // Busy wait for the host response
        //
        // @TODO: Can we do this better?
        loop {
            let mut exit = false;
            without_interrupts(|| {
                let state = self.state.read();

                if *state.got_version_response.lock() {
                    exit = true;
                }
            });

            if exit {
                break;
            }
        }

        // Now, request all channel offers from the host.
        // The host will send approx 12-16 offers on the normal VM, so need to wait for
        // AllOffersDelivered message.
        self.request_offers();

        loop {
            let mut exit = false;
            without_interrupts(|| {
                let state = self.state.read();

                if *state.all_offers_delivered.lock() {
                    exit = true;
                }
            });

            if exit {
                break;
            }
        }

        let offers = self.state.read().offers.read().clone();

        // Map offers to device drivers
        for offer in &*offers {
            for (guid, name) in HYPERV_DEVICE_GUIDS {
                if offer.channel_type == guid {
                    debug!("Found {name}");

                    if name == "Keyboard" {
                        // let mut channel = VmBusChannel::new(offer, HV_PAGE_SIZE, HV_PAGE_SIZE);
                        // channel.initialize();

                        // let kbd = Arc::new(VmBusKeyboard {
                        //     channel,
                        //     offer: *offer,
                        // });

                        // let k: Arc<dyn VmBusSyntheticDevice> = kbd;

                        // self.state.write().drivers.push(Arc::clone(&k));
                    }
                    if name == "NIC" {
                        let mut channel = VmBusChannel::new(offer, PAGE_SIZE, PAGE_SIZE);
                        channel.initialize();

                        let kbd = Arc::new(VmBusNic {
                            channel,
                            offer: *offer,
                            hyper_v: Arc::clone(&kernel_ref().hyperv),
                            state: RwLock::new(VmBusNicState {
                                rx_buf_base: null_mut(),
                                tx_buf_base: null_mut(),
                                netvsc_xid_counter: AtomicU64::new(NETVSC_BASE_XID),
                                rndis_xid_counter: AtomicU64::new(NETVSC_RNDIS_BASE_XID),
                                netvsc_packet_buffer: HashMap::new(),
                                rx_starting_frame: Frame::new(PhysicalAddress::new(0)),
                                tx_starting_frame: Frame::new(PhysicalAddress::new(0)),
                                rx_gpadl: 0,
                                tx_gpadl: 0,
                                tx_section_size: 0,
                                tx_section_count: 0,
                                rndis_packet_buffer: HashMap::new(),
                                current_section_index: 0,
                            }),
                        });

                        let k: Arc<dyn VmBusSyntheticDevice> = kbd;

                        self.state.write().drivers.push(Arc::clone(&k));
                    }
                    if name == "Synthetic video" {
                        // let mut channel = VmBusChannel::new(offer, HV_PAGE_SIZE, HV_PAGE_SIZE);
                        // channel.initialize();

                        // let kbd = Arc::new(VmBusSyntheticVideoDriver {
                        //     channel,
                        //     offer: *offer,
                        //     framebuffer: null_mut(),
                        //     state: RwLock::new(VmBusSyntheticVideoDriverState {
                        //         initialized: false,
                        //         next_xid: AtomicU64::new(200),
                        //         supported_resolutions: Vec::new(),
                        //         current_resolution: Resolution {
                        //             height: 0,
                        //             width: 0,
                        //         },
                        //     }),
                        // });

                        // let k: Arc<dyn VmBusSyntheticDevice> = kbd;

                        // self.state.write().drivers.push(Arc::clone(&k));
                    }
                    if name == "Mouse" {
                        // let mut channel = VmBusChannel::new(offer, HV_PAGE_SIZE, HV_PAGE_SIZE);
                        // channel.initialize();

                        // let kbd = Arc::new(VmBusMouseDriver {
                        //     channel,
                        //     offer: *offer,
                        // });

                        // let k: Arc<dyn VmBusSyntheticDevice> = kbd;

                        // self.state.write().drivers.push(Arc::clone(&k));
                    }

                    break;
                }
            }
        }

        // Initialize device drivers
        let drivers = { &self.state.read().drivers.clone() };
        for driver in drivers {
            (*driver).initialize();
        }
    }

    /// Enables the Hyper-V synthetic timer (TIMER0) for periodic interrupts.
    ///
    /// This sets up the synthetic timer MSRs to generate regular timer events
    /// that are used to poll VMBus channels.
    ///
    /// Even though the APIC timer is still used for primary scheduling, TIMER0
    /// serves as a safety mechanism to ensure timely processing of events in
    /// case interrupt signaling is delayed or missed.
    fn enable_timer(&self) {
        // We will use SINT1 for TIMER0 (SINT2 is used for VMBus already)
        let mut vmbus_sint_msr = Msr::new(HYPERV_X64_MSR_SINT0 + 1);

        // Read the value and unset some bits responsible for AutoEOI, masking the interrupt and irq vector value
        let vmbus_sint_value =
            unsafe { vmbus_sint_msr.read() & !((1 << 18) | (1 << 17) | (1 << 16) | 0xFF) };

        // Enable AutoEOI and write a STIMER0 IRQ vector
        unsafe {
            vmbus_sint_msr.write(vmbus_sint_value | HYPERV_STIMER0_VECTOR as u64 | (1 << 17))
        };

        // Register interrupt handler
        register_interrupt_handler(
            HYPERV_STIMER0_VECTOR,
            Box::new(|isf: &InterruptStackFrame| handle_stimer0_irq(isf)),
        );

        let mut count = Msr::new(HYPERV_X64_MSR_STIMER0_COUNT);
        // Count is measured in 100ns units. We want to fire every 500ms (0.5s), so 500ms/100ns is 5_000_000.
        unsafe { count.write(5_000_000) };

        // Enable the timer
        let mut config = Msr::new(HYPERV_X64_MSR_STIMER0_CONFIG);
        unsafe {
            config.write(
                (1 << 0) | // Enable
                (1 << 1) | // Periodic
                (1 << 16), // SINT 1
            )
        };
    }

    /// Sends a `Request Offsets` message to the Hyper-V host.
    unsafe fn request_offers(&self) {
        let mut msg = VmBusRequestOffers {
            header: VmBusMessageHeader::with_message_type(VmBusMessageType::RequestOffers),
        };

        let message = HyperVPostMessage {
            connection_id: 1,
            reserved: 0,
            message_type: HYPERV_POST_MESSAGE_MESSAGE_TYPE,
            payload_size: size_of::<VmBusRequestOffers>() as u32,
            payload: convert_message_to_slice(&msg),
        };

        self.post_message(&message);
    }

    /// Sends the `Initiate Contact` message to the Hyper-V host over VMBus.
    unsafe fn send_initiate_contact(&self) {
        let mut msg = VmBusChannelInitiateContact {
            header: VmBusMessageHeader::with_message_type(VmBusMessageType::InitiateContact),
            requested_version: VERSION_WIN10_V5,
            interrupt_page: (2 << 56), // SINT2
            target_vcpu: 0,            // current CPU
            monitor_page1: self.state.read().monitor_page1,
            monitor_page2: self.state.read().monitor_page2,
        };

        let message = HyperVPostMessage {
            connection_id: 1,
            reserved: 0,
            message_type: HYPERV_POST_MESSAGE_MESSAGE_TYPE,
            payload_size: size_of::<VmBusChannelInitiateContact>() as u32,
            payload: convert_message_to_slice(&msg),
        };

        self.post_message(&message);
    }

    /// Posts a message to the Hyper-V host via the `HYPERCALL_POST_MESSAGE` hypercall.
    ///
    /// - The `message` parameter must contain a valid, properly formatted
    ///   VMBus message (e.g., `InitiateContact`, `RequestOffers`,
    ///   `OpenChannel`, etc.).
    /// - This is the primary mechanism for sending control messages to the
    ///   host during VMBus initialization and channel management.
    unsafe fn post_message(&self, message: &HyperVPostMessage) {
        let layout = Layout::from_size_align(size_of::<HyperVPostMessage>(), 16).unwrap();
        let ptr = alloc::alloc::alloc(layout) as *mut HyperVPostMessage;
        *ptr = *message;

        let input = create_hypercall_input(0, 0, 0, false, HVCALL_POST_MESSAGE);

        let return_value = unsafe {
            hypercall(
                input,
                PhysicalAddress::new(
                    memory_manager()
                        .read()
                        .translate_virtual_address_to_physical_for_current_address_space(
                            VirtualAddress::new(ptr.addr() as u64),
                        )
                        .unwrap()
                        .as_u64(),
                ),
                PhysicalAddress::new(0),
                without_interrupts(|| self.state.read().hypercall_page),
            )
        };

        dealloc(ptr as *mut u8, layout);

        assert_eq!(return_value, 0);
    }

    /// Constructs a 64-bit guest OS identity value formatted according to
    /// the Hypervisor Top Level Functional Specification (Section 2.6).
    ///
    /// The guest ID encodes the following fields (bit positions):
    /// - bit 63: OS type (1 = open source)
    /// - bits 62-48: Vendor ID (0x666)
    /// - bits 47-40: OS ID (0x42)
    /// - bits 39-32: Major version (0x0)
    /// - bits 31-24: Minor version (0x1)
    /// - bits 23-16: Service version (1)
    /// - bits 15-0: Build number (2025)
    ///
    /// This 64-bit value uniquely identifies the guest OS version to the Hyper-V host.
    const fn guest_id() -> u64 {
        // @TODO: Macros?

        // Format is described in
        // Hypervisor Top Level Functional Specification, 2.6 Reporting the Guest OS Identity, p. 24
        let os_type = 1; // open source
        let vendor_id = 0x666; // vendor id
        let os_id = 0x42;
        let major_version = 0x0;
        let minor_version = 0x1;
        let service_version = 1;
        let build_number = 2025;

        (os_type << 63)
            | (vendor_id << 48)
            | (os_id << 40)
            | (major_version << 32)
            | (minor_version << 24)
            | (service_version << 16)
            | build_number
    }

    /// Handles the Synthetic Interrupt Message Page (SIMP) interrupt.
    ///
    /// # Overview
    /// This function is invoked when the VMBus synthetic interrupt (SINT)
    /// assigned to the Synthetic Interrupt Message Page (SIMP) fires.  
    /// It processes pending messages sent from the Hyper-V host to the
    /// guest through the message page.
    pub fn handle_simp_irq(&self) {
        without_interrupts(|| {
            // SIMP page contains array of 16 messages for 16 SINTs.
            let simp: *mut [HvMessage; 16] = self.state.read().simp_page as *mut [HvMessage; 16];

            // Get VMBus SINT message (others are unused currently)
            let hyperv_message = &mut unsafe { &mut *simp }[VMBUS_MESSAGE_SINT as usize];

            let message_length = hyperv_message.len;
            let embedded_message = hyperv_message.data;
            let msg = unsafe { *(&embedded_message as *const _ as *const VmBusMessageHeader) };
            let msg_type = msg.message_type;

            match msg_type {
                VmBusMessageType::VersionResponse => {
                    // Parse the message
                    let msg =
                        unsafe { *(&embedded_message as *const _ as *const VmBusVersionResponse) };

                    // Safety assert that Hyper-V agrees on protocol version.
                    // Note: Currently we don't support older PCs with WindowsServer2008/Windows8,
                    // so we panic when Hyper-V does not recognize current protocol version. For future
                    // newer systems and protocol versions, Hyper-V will still support Windows10 proto
                    // and emulate old interface.
                    assert!(msg.version_supported);

                    let mut state = self.state.write();
                    state.vmbus_connection_id = msg.new_connection_id;
                    let mut lock = state.got_version_response.lock();
                    *lock = true;
                }
                VmBusMessageType::OfferChannel => {
                    let msg =
                        unsafe { *(&embedded_message as *const _ as *const VmBusOfferChannel) };

                    // Store this offer temporarily. All offers will be processed together
                    // once the `AllOffersDelivered` message indicates that no more offers
                    // are pending.
                    let state = self.state.read();
                    let mut offers = state.offers.write();
                    offers.push(msg);
                }
                VmBusMessageType::AllOffersDelivered => {
                    // All offers are delivered now. Change the mutex value the driver code waits for and start processing.
                    let mut state = self.state.read();
                    let mut lock = state.all_offers_delivered.lock();
                    *lock = true;
                }
                VmBusMessageType::GpadlCreated => {
                    let msg =
                        unsafe { *(&embedded_message as *const _ as *const VmBusGpadlCreated) };

                    let status = msg.status;
                    assert_eq!(status, 0);
                }
                VmBusMessageType::OpenChannelResult => {
                    let msg = unsafe {
                        *(&embedded_message as *const _ as *const VmBusOpenChannelResult)
                    };

                    let status = msg.status;
                    assert_eq!(status, 0);
                }
                VmBusMessageType::Invalid => {
                    // If message type is invalid, then it's probably notification about new data in VMBus channels.
                    for driver in &self.state.read().drivers.clone() {
                        if driver.has_data_to_process() {
                            driver.process_incoming_data();
                        }
                    }
                }
                _ => unimplemented!(),
            }

            // Zero message from current SIMP slot. It marks message as delivered.
            unsafe {
                write_bytes(
                    hyperv_message as *mut _ as *mut u8,
                    0,
                    size_of::<HvMessage>(),
                )
            };

            // Copy whole message for current processing
            {
                if msg_type != VmBusMessageType::Invalid {
                    let mut state = self.state.write();
                    state.new_message_arrived = true;
                    state.latest_message =
                        unsafe { *(&embedded_message as *const _ as *const HyperVPostMessage) };
                }
            }

            // Send end of message to host. From now, we can't trust any data in VMBus channels' receive buffers nor any data in SIMP.
            let mut eom_msr = Msr::new(HYPERV_X64_MSR_EOM);
            unsafe { eom_msr.write(0) };
        });
    }

    /// Handle Synthetic Timer 0 (STIMER0) interrupt event.
    /// Used for periodic checks of VMBus channels.
    pub fn handle_stimer0(&self) {
        // Every 0.5s try to poll all channels ring buffers.
        without_interrupts(|| {
            for driver in &self.state.read().drivers.clone() {
                if driver.has_data_to_process() {
                    driver.process_incoming_data();
                }
            }

            // Mark timer interrupt as handled
            let simp: *mut [HvMessage; 16] = self.state.read().simp_page as *mut [HvMessage; 16];

            let hyperv_message = &mut unsafe { &mut *simp }[STIMER0_SINT as usize];
            unsafe {
                write_bytes(
                    hyperv_message as *mut _ as *mut u8,
                    0,
                    size_of::<HvMessage>(),
                )
            };

            let mut eom_msr = Msr::new(HYPERV_X64_MSR_EOM);
            unsafe { eom_msr.write(0) };
        });
    }

    /// Returns the next available GPADL (Guest Physical Address Descriptor List) ID.
    /// GPADL IDs are unique identifiers for shared memory mappings between guest and host.
    pub fn next_gpadl_id(&self) -> u32 {
        self.state
            .read()
            .next_gpadl_id
            .fetch_add(1, Ordering::Relaxed)
    }

    /// Creates a GPADL (Guest Physical Address Descriptor List) for a memory region
    /// that will be shared with the host through the specified channel.
    ///
    /// # Arguments
    /// * `channel_id` - The ID of the channel to associate the GPADL with.
    /// * `starting_address` - The physical start address of the memory to map. It has to be at least HV_PAGE_SIZE aligned.
    /// * `length` - The length (in bytes) of the memory region.
    ///
    /// # Returns
    /// The newly allocated GPADL ID.
    pub fn create_gpadl(
        &self,
        channel_id: u32,
        starting_address: PhysicalAddress,
        length: usize,
    ) -> u32 {
        // @TODO: Implement support for GpadlBody

        // Safety checks
        assert!(length >= PAGE_SIZE);
        assert!(starting_address.is_aligned_to(PAGE_SIZE as u64));
        assert!((size_of::<VmBusGPADLHeader>() + (length / PAGE_SIZE) * 8) < 240);

        let pfn_count = length / PAGE_SIZE;
        let gpadl_id = self.next_gpadl_id();

        // Create GPADL Header.
        // Currently we support one range descriptor
        let gpadl = VmBusGPADLHeader {
            header: VmBusMessageHeader::with_message_type(VmBusMessageType::GpadlHeader),
            channel_id,
            gpadl_id,
            length_of_range_descriptors: (size_of::<VmBusGpaRange>() + pfn_count * 8) as u16,
            number_of_range_descriptors: 1, // we support only one range desciptor currently
            range: VmBusGpaRange {
                byte_count: length as u32,
                starting_byte_offset: 0, // we allow only GPADL starting from the offset 0 from the page boundary
            },
        };

        // Create Hyper-V message buffer. It will contain GPADL header and PFN list.
        let mut buffer = [0u8; 240];

        let src = &gpadl as *const _ as *const u8;
        let dst = buffer.as_mut_ptr();
        unsafe { ptr::copy_nonoverlapping(src, dst, size_of::<VmBusGPADLHeader>()) };

        let starting_index = size_of::<VmBusGPADLHeader>();
        let mut pfn_start = buffer[starting_index..].as_mut_ptr() as *mut u64;
        for i in 0..pfn_count {
            unsafe {
                pfn_start
                    .add(i)
                    .write_unaligned((starting_address.as_u64() / PAGE_SIZE as u64) + i as u64)
            };
        }

        let message = HyperVPostMessage {
            connection_id: 1,
            reserved: 0,
            message_type: HYPERV_POST_MESSAGE_MESSAGE_TYPE,
            payload_size: (starting_index + pfn_count * 8) as u32,
            payload: buffer,
        };

        // Wait for GPADL created message
        self.reset_reception_status();
        unsafe { self.post_message(&message) };
        let response = self.wait_for_message::<VmBusGpadlCreated>();

        if response.status != 0 {
            panic!("Failed to create GPADL mapping between guest and host");
        }

        gpadl_id
    }

    /// Signals an event to the host over Hypercall interface.
    ///
    /// This triggers an interrupt and notifies the host that there is data or a
    /// state change associated with the specified connection.
    unsafe fn signal_event(&self, connection_id: u32, event: u16) {
        let return_value = unsafe {
            _do_fast_hypercall(
                HVCALL_FAST_SIGNAL_EVENT,
                event as u64,
                without_interrupts(|| self.state.read().hypercall_page),
            )
        };
    }

    /// Resets the reception status flag for SIMP messages.
    fn reset_reception_status(&self) {
        without_interrupts(|| self.state.write().new_message_arrived = false);
    }

    /// Waits for the next SIMP message and returns it as type `T`.
    ///
    /// This function blocks (or spins) until a new message arrives on the
    /// SIM page, then reads and returns the message content as `T`.
    ///
    /// # Type Parameters
    /// - `T`: Must implement `Clone` and `Copy` since the message is read
    ///   directly from memory without heap allocation.
    fn wait_for_message<T: Clone + Copy>(&self) -> T {
        loop {
            let mut exit = false;
            without_interrupts(|| {
                let state = self.state.read();

                if state.new_message_arrived {
                    exit = true;
                }
            });

            if exit {
                break;
            }
        }

        without_interrupts(|| {
            let mut state = self.state.write();
            state.new_message_arrived = false;

            let message = state.latest_message;

            unsafe { *(&message as *const _ as *const T) }
        })
    }
}

/// Converts message ready to be sent over SIM page to the SIMP payload ([u8; 240])
fn convert_message_to_slice<T>(message: &T) -> [u8; 240] {
    assert!(size_of::<T>() < 240);

    let mut buffer = [0u8; 240];

    let src = message as *const _ as *const u8;
    let dst = buffer.as_mut_ptr();
    unsafe { ptr::copy_nonoverlapping(src, dst, size_of::<T>()) };

    buffer
}

/// Handles the VMBus interrupt request.
fn handle_vmbus_irq(_isf: &InterruptStackFrame) {
    kernel_ref().hyperv.handle_simp_irq();

    unsafe {
        (*ProcessorControlBlock::get_pcb_for_current_processor())
            .local_apic
            .get()
            .unwrap()
            .signal_end_of_interrupt();
    }
}

/// Handles the STIMER0 interrupt request.
fn handle_stimer0_irq(_isf: &InterruptStackFrame) {
    kernel_ref().hyperv.handle_stimer0();

    unsafe {
        (*ProcessorControlBlock::get_pcb_for_current_processor())
            .local_apic
            .get()
            .unwrap()
            .signal_end_of_interrupt();
    }
}
