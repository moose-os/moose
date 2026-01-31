//! # Hyper-V Synthetic Network Card Protocol
//!
//! ## NetVsc - Network Virtualization Service Client
//!
//! This crate provides a Rust implementation of the Network Virtualization Service Consumer (NetVsc)
//! protocol and Remote Network Driver Interface Specification (RNDIS) for communication with
//! virtualized network devices.
//!
//! ## Overview
//!
//! NetVsc and RNDIS work together to provide network connectivity in virtualized environments:
//!
//! - **NetVsc** is the lower-level transport protocol that handles communication between a guest
//!   virtual machine and the Hyper-V host's virtual switch through the VMBus (Virtual Machine Bus).
//!   It manages the fundamental message passing, buffer management, and channel establishment.
//!
//! - **RNDIS** (Remote Network Driver Interface Specification) is the higher-level network protocol
//!   that runs on top of NetVsc. It provides a standardized interface for network device operations
//!   such as initialization, configuration, status queries, and data packet transmission.
//!
//! ## Protocol Stack
//!
//! ```text
//! ┌─────────────────────────────────────┐
//! │        Network Applications         │
//! ├─────────────────────────────────────┤
//! │         TCP/IP Stack                │
//! ├─────────────────────────────────────┤
//! │         Ethernet Layer              │
//! ├─────────────────────────────────────┤
//! │     RNDIS Protocol Layer            │  ← This crate implements
//! ├─────────────────────────────────────┤
//! │      NetVsc Transport Layer         │  ← This crate implements
//! ├─────────────────────────────────────┤
//! │           VMBus Layer               │
//! ├─────────────────────────────────────┤
//! │        Hyper-V Hypervisor           │
//! └─────────────────────────────────────┘
//! ```
//!
//! ## How NetVsc and RNDIS Relate
//!
//! ### NetVsc Responsibilities
//! - Establishes and manages VMBus channels for network communication
//! - Handles low-level message framing and buffer management
//! - Manages shared memory regions for efficient data transfer
//!
//! ### RNDIS Responsibilities
//! - Provides standardized network device abstraction
//! - Handles network device initialization and capability negotiation
//! - Manages network configuration through Object Identifiers (OIDs)
//! - Encapsulates Ethernet frames for transmission
//! - Reports network status changes and events
//!
//! ### Integration
//! RNDIS messages are transported over NetVsc channels. The typical flow is:
//!
//! 1. **Channel Establishment**: NetVsc establishes a communication channel with the host
//! 2. **RNDIS Initialization**: RNDIS initialization messages are exchanged to negotiate capabilities
//! 3. **Configuration**: RNDIS OID operations configure the network device
//! 4. **Data Transfer**: Ethernet frames are wrapped in RNDIS packet messages and sent via NetVsc
//! 5. **Status Reporting**: Network events are reported through RNDIS indication messages
//!
//! # RNDIS
//! ## Message Flow Patterns
//!
//! ### Request-Response Pattern
//! Most RNDIS operations use a synchronous request-response pattern:
//!
//! ```text
//! Guest                           Host
//!   │                              │
//!   │  Request (e.g., Init)        │
//!   │ ──────────────────────────►  │
//!   │                              │
//!   │  Complete (e.g., InitComplete)
//!   │ ◄──────────────────────────  │
//!   │                              │
//! ```
//!
//! These request and responses are tracked by the driver using `request_id` field present in every request-response packet.
//!
//! ## Asynchronous Indications
//! The host can send unsolicited status messages:
//!
//! ```text
//! Guest                           Host
//!   │                              │
//!   │  Indicate (e.g., MediaConnect)
//!   │ ◄──────────────────────────  │
//!   │                              │
//!   │  (No response required)      │
//!   │                              │
//! ```
//!
//! Those packets does not require response and can come in any time during normal NIC operation.
//!
//! ### Multi-packet Messages
//! RNDIS supports aggregating multiple packets in a single message for efficiency:
//!
//! ```text
//! ┌─────────────────────────────────────┐
//! │ RNDIS_PACKET_MSG                    │
//! ├─────────────────────────────────────┤
//! │ Ethernet Frame 1                    │
//! ├─────────────────────────────────────┤
//! │ Ethernet Frame 2                    │
//! ├─────────────────────────────────────┤
//! │ Ethernet Frame 3                    │
//! └─────────────────────────────────────┘
//! ```
//!
//! We do not support it yet.
//!
use core::{
    any::type_name,
    fmt,
    ptr::{copy, null, null_mut},
    sync::atomic::{AtomicU64, Ordering},
};

use alloc::{
    boxed::Box,
    slice,
    sync::Arc,
    vec::{self, Vec},
};
use bytemuck::offset_of;
use hashbrown::HashMap;
use spin::rwlock::RwLock;
use x86_64::instructions::interrupts::without_interrupts;

use crate::{
    driver::{
        hv::hyperv::{
            channel::VmBusChannel, ring_buffer::HyperVDoubledRingBuffer,
            synthetic_device::VmBusSyntheticDevice, HyperV, VmBusGpaRange, VmBusOfferChannel,
            VmBusPacketHeader, VmBusPacketType, VmBusXferPageHeader, HYPERV_PAGE_SIZE,
        },
        net::{EtherType, EthernetFrameHeader, Ipv4Header, MacAddress},
    },
    kernel::kernel_ref,
    memory::{self, memory_manager, Frame, Page, PageFlags, PhysicalAddress, VirtualAddress},
};

/// Size of the receive ring buffer in bytes (8 pages).
const NETVSC_RECEIVE_BUFFER_SIZE: u32 = 8 * HYPERV_PAGE_SIZE as u32;

/// Size of the send ring buffer in bytes (8 pages).
const NETVSC_SEND_BUFFER_SIZE: u32 = 8 * HYPERV_PAGE_SIZE as u32;

/// Identifier for the receive buffer. NetVsc requires 0xCAFE here, it's not Moose-chosen value.
const NETVSC_RECEIVE_BUFFER_ID: u16 = 0xCAFE;

/// Identifier for the send buffer. NetVsc requires 0 here, it's not Moose-chosen value.
const NETVSC_SEND_BUFFER_ID: u16 = 0;

/// Base XID for NetVsc packets. It will be monotonically increased for every packet.
pub const NETVSC_BASE_XID: u64 = 0xBEE5;

/// Base XID for RNDIS packets. It will be monotonically increased for every packet.
pub const NETVSC_RNDIS_BASE_XID: u64 = 0xF00D;

/// Currently supported RNDIS major version.
const NETVSC_RNDIS_MAJOR_VERSION: u32 = 1;

/// Currently supported RNDIS minor version.
const NETVSC_RNDIS_MINOR_VERSION: u32 = 0;

/// Receive packets sent directly to current device MAC address.
const NETVSC_RNDIS_FILTER_PACKET_TYPE_DIRECTED: u32 = 0x1;

/// Receive multicast packets.
const NETVSC_RNDIS_FILTER_PACKET_TYPE_MULTICAST: u32 = 0x2;

/// Receive all multicast packets.
const NETVSC_RNDIS_FILTER_PACKET_TYPE_ALL_MULTICAST: u32 = 0x4;

/// Receive broadcast packets.
const NETVSC_RNDIS_FILTER_PACKET_TYPE_BROADCAST: u32 = 0x8;

/// Obsolete.
const NETVSC_RNDIS_FILTER_PACKET_TYPE_SOURCE_ROUTING: u32 = 0x10;

/// Receive all packets (promiscuous mode)
const NETVSC_RNDIS_FILTER_PACKET_TYPE_PROMISCUOUS: u32 = 0x20;

/// All known NetVSC protocol versions negotiated between guest and host NICs.
///
/// Currently, our NIC driver supports only `Version6_1`.
/// Future versions exist for reference.
///
/// The numeric values follow the Hyper-V specification.
#[repr(u32)]
#[derive(Debug, Copy, Clone)]
enum NetVscProtocolVersion {
    Version1 = 2, // ☺

    Version2 = 0x30002,
    Version4 = 0x40000,
    Version5 = 0x50000,
    Version6 = 0x60000,
    Version6_1 = 0x60001,
}

impl From<u32> for NetVscProtocolVersion {
    fn from(value: u32) -> Self {
        match value {
            2 => Self::Version1,
            0x30002 => Self::Version2,
            0x40000 => Self::Version4,
            0x50000 => Self::Version5,
            0x60000 => Self::Version6,
            0x60001 => Self::Version6_1,
            _ => unreachable!(),
        }
    }
}

/// Common header for all NetVSC messages exchanged over VMBus.
#[derive(Debug, Copy, Clone)]
#[repr(C, packed)]
struct NetVscHeader {
    /// Type of the NetVSC message.
    message_type: NetVscMessageType,
}

impl NetVscHeader {
    pub fn with_message_type(message_type: NetVscMessageType) -> NetVscHeader {
        NetVscHeader { message_type }
    }
}

/// Status codes returned by the NetVSC protocol.
///
/// These indicate the result of a request or operation
/// performed by the NetVSC device over VMBus.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(u32)]
enum NetVscStatus {
    /// Operation completed successfully.
    Success = 1,

    /// Operation failed.
    Fail = 2,

    /// Guest protocol version is newer than supported by the host.
    ProtocolTooNew = 3,

    /// Guest protocol version is older than supported by the host.
    ProtocolTooOld = 4,

    /// Provided RNDIS packet is invalid.
    InvalidRndisPacket = 5,

    /// Device is busy and cannot process the request right now.
    Busy = 6,

    /// Requested protocol is not supported.
    ProtocolUnsupported = 7,
}

impl From<u32> for NetVscStatus {
    fn from(value: u32) -> Self {
        match value {
            1 => Self::Success,
            2 => Self::Fail,
            3 => Self::ProtocolTooNew,
            4 => Self::ProtocolTooOld,
            5 => Self::InvalidRndisPacket,
            6 => Self::Busy,
            7 => Self::ProtocolUnsupported,
            _ => unreachable!(),
        }
    }
}

/// Message types exchanged between guest and host in the NetVSC protocol.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(u32)]
enum NetVscMessageType {
    Init = 1,
    InitComplete = 2,

    // Version 1 messages
    SendNdisVersion = 100,
    SendReceiveBuffer = 101,
    SendReceiveBufferCompletion = 102,
    RevokeReceiveBuffer = 103,
    SendSendBuffer = 104,
    SendSendBufferCompletion = 105,
    RevokeSendBuffer = 106,
    SendRndisPacket = 107,
    SendRndisPacketCompletion = 108,

    // Version 2 messages
    SendChimneyDelegatedBuffer = 109,
    SendChimneyDelegatedBufferCompletion = 110,
    RevokeChimneyDelegatedBuffer = 111,
    ResumeChimneyRxIndiciation = 112,
    TerminateChimney = 113,
    TerminateChimneyCompletion = 114,
    IndicateChimneyEvent = 115,
    SendChimneyPacket = 116,
    SendChimneyPacketCompletion = 117,
    PostChimneyRecvReq = 118,
    PostChimneyRecvReqCompletion = 119,
    AllocRxBuffer = 120,
    AllocRxBufferCompletion = 121,
    FreeRxBuffer = 122,
    SendVmqRndisPkt = 123,
    SendVmqRndisPktCompletion = 124,
    SendNdisConfig = 125,
    AllocChimneyHandle = 126,
    AllocChimneyHandleCompletion = 127,

    // Version 4 messages
    SendVfAssociation = 128,
    SwitchDataPath = 129,
    UpLinkConnectStateDeprecated = 130,

    // Version 5 messages
    OidQueryEx = 131,
    OidQueryExCompletion = 132,
    Subchannel = 133,
    SendIndirectionTable = 134,

    // Version 6
    PdApi = 135,
    PdPostBatch = 136,
}

impl From<u32> for NetVscMessageType {
    fn from(value: u32) -> Self {
        match value {
            1 => Self::Init,
            2 => Self::InitComplete,

            100 => Self::SendNdisVersion,
            101 => Self::SendReceiveBuffer,
            102 => Self::SendReceiveBufferCompletion,
            103 => Self::RevokeReceiveBuffer,
            104 => Self::SendSendBuffer,
            105 => Self::SendSendBufferCompletion,
            106 => Self::RevokeSendBuffer,
            107 => Self::SendRndisPacket,
            108 => Self::SendRndisPacketCompletion,

            109 => Self::SendChimneyDelegatedBuffer,
            110 => Self::SendChimneyDelegatedBufferCompletion,
            111 => Self::RevokeChimneyDelegatedBuffer,
            112 => Self::ResumeChimneyRxIndiciation,
            113 => Self::TerminateChimney,
            114 => Self::TerminateChimneyCompletion,
            115 => Self::IndicateChimneyEvent,
            116 => Self::SendChimneyPacket,
            117 => Self::SendChimneyPacketCompletion,
            118 => Self::PostChimneyRecvReq,
            119 => Self::PostChimneyRecvReqCompletion,
            120 => Self::AllocRxBuffer,
            121 => Self::AllocRxBufferCompletion,
            122 => Self::FreeRxBuffer,
            123 => Self::SendVmqRndisPkt,
            124 => Self::SendVmqRndisPktCompletion,
            125 => Self::SendNdisConfig,
            126 => Self::AllocChimneyHandle,
            127 => Self::AllocChimneyHandleCompletion,

            128 => Self::SendVfAssociation,
            129 => Self::SwitchDataPath,
            130 => Self::UpLinkConnectStateDeprecated,

            131 => Self::OidQueryEx,
            132 => Self::OidQueryExCompletion,
            133 => Self::Subchannel,
            134 => Self::SendIndirectionTable,

            135 => Self::PdApi,
            136 => Self::PdPostBatch,

            _ => unreachable!(),
        }
    }
}

/// Initial protocol negotiation message sent from the guest to the host.
///
/// This message seems to be broken and minimum_supported_version must be
/// equal to maximum_supported_version. The protocol version negotiation works
/// by querying host with multiple protocol versions from newest to the oldest
/// util host responds with successful status.
#[derive(Debug, Copy, Clone)]
#[repr(C, packed)]
pub struct NetVscInitMessage {
    /// Common NetVSC message header containing the message type.
    header: NetVscHeader,

    /// The lowest protocol version that the guest can support.
    minimum_supported_version: NetVscProtocolVersion,

    /// The highest protocol version that the guest can support.
    maximum_supported_version: NetVscProtocolVersion,

    /// Reserved (must be 0).
    reserved: [u8; 20],
}

/// Response to [NetVscInitMessage], sent from the host to the guest
/// to confirm the negotiated protocol and initialization parameters.
///
/// This message completes the protocol negotiation step.
///
/// The negotiated protocol version field seems to be broken and we can't trust
/// it (that's why protocol negotiation requires multiple messages with min
/// version == max version).
#[derive(Debug, Copy, Clone)]
#[repr(C, packed)]
pub struct NetVscInitCompleteMessage {
    /// Common NetVSC message header containing the message type.
    header: NetVscHeader,

    /// The protocol version that was successfully negotiated between
    /// the guest and the host. This field is valid only for protocol
    /// version 1.
    negotiated_protocol_version: NetVscProtocolVersion,

    // Maximum number of MDL entries
    max_mdl_chain_len: u32,

    /// Status of the initialization. If [NetVscStatus::Success], then
    /// initialization is complete, otherwise the protocol version is too new
    /// and need to perform initialization again.
    status: NetVscStatus,
}

/// Message sent by the guest to configure NDIS (Network Driver Interface Specification)
/// parameters such as MTU and advertised capabilities.
///
/// This message must be sent before normal packet transmission begins.
///
/// ### Capabilities Bitfield
///
/// | Bit | Capability         | Description                                |
/// |-----|--------------------|--------------------------------------------|
/// | 0   | VMQ                | Virtual Machine Queue support              |
/// | 1   | Chimney             | TCP Chimney Offload support               |
/// | 2   | SR-IOV             | Single Root I/O Virtualization support     |
/// | 3   | IEEE 802.1Q        | VLAN tagging support                       |
#[derive(Debug, Copy, Clone)]
#[repr(C, packed)]
pub struct NetVscSendNdisConfig {
    /// Common NetVSC message header indicating the message type.
    header: NetVscHeader,

    /// Maximum Transmission Unit (MTU) in bytes for network packets.
    mtu: u32,

    /// Reserved (must be 0).
    reserved: u32,

    /// Bitmask of capabilities.
    capabilities: u64,

    /// Reserved (must be 0).
    reserved2: [u8; 12 + 8],
}

/// Message sent by the guest to inform the host about the NDIS (Network Driver Interface Specification)
/// version it will be using.
#[derive(Debug, Copy, Clone)]
#[repr(C, packed)]
pub struct NetVscSendNdisVersion {
    /// Common NetVSC message header indicating the message type.
    header: NetVscHeader,

    /// Major version of the NDIS protocol.
    major: u32,

    /// Minor version of the NDIS protocol.
    minor: u32,

    /// Reserved (must be 0).
    reserved: [u8; 20 + 8],
}

/// Message sent by the guest to inform the host about the location of the
/// receive buffer that will be used for network packets.
///
/// GPADL needs to be previously created and big enough to handle big amounts of data.
/// The id field have to be [NETVSC_RECEIVE_BUFFER_ID].
#[derive(Debug, Copy, Clone)]
#[repr(C, packed)]
pub struct NetVscSendReceiveBuffer {
    /// Standard NetVSC message header.
    header: NetVscHeader,

    /// GPADL identifier of the mapped receive buffer.
    gpadl_id: u32,

    /// Buffer identifier (must be [NETVSC_RECEIVE_BUFFER_ID]).
    id: u16,

    /// Reserved (must be 0).
    reserved: [u8; 22 + 8],
}

/// Message sent by the host in response to a [`NetVscSendReceiveBuffer`] message.
///
/// This message confirms that the receive buffer GPADL mapping was accepted
/// and specifies how the buffer is divided into **sections** for suballocations.
///
/// Each section is subdivided into fixed-size suballocations.
/// These suballocations are used as packet buffers.
///
/// Example layout:
///
/// |          Large Section            |   |    Small Section    |
/// ----------------------------------------------------------------
/// |   L0   |   L1   |   L2   |   L3   |   | S0|S1|S2|S3|S4|S5|S6|
/// |   L4   |   L5   |                             S7|S8|S9       |
/// |
/// LargeOffset (start of large section)         SmallOffset (start of small section)
///
#[derive(Debug, Copy, Clone)]
#[repr(C, packed)]
pub struct NetVscSendReceiveBufferCompletion {
    /// Standard NetVSC message header.
    header: NetVscHeader,

    /// Status of the receive buffer mapping.
    status: NetVscStatus,

    /// Number of valid buffer sections.
    number_of_sections: u32,

    /// List of buffer section descriptors. Usually 1.
    sections: [NetVscReceiveBufferSection; 1],
}

/// Describes a contiguous portion of the receive buffer.
///
/// Each section specifies the range of memory in the buffer, how large
/// each suballocation is, and how many suballocations exist.
#[derive(Debug, Copy, Clone)]
#[repr(C, packed)]
pub struct NetVscReceiveBufferSection {
    /// Offset of the section start in the buffer.
    offset: u32,

    /// Size of each suballocation (bytes).
    suballocation_size: u32,

    /// Number of suballocations in this section.
    suballocations_count: u32,

    /// Offset of the section end in the buffer.
    end_offset: u32,
}

/// Message sent by the guest to inform the host about the location of the
/// send buffer that will be used for network packets.
///
/// GPADL needs to be previously created and big enough to handle big amounts of data.
/// The id field have to be [NETVSC_SEND_BUFFER_ID].
#[derive(Debug, Copy, Clone)]
#[repr(C, packed)]
pub struct NetVscSendSendBuffer {
    /// Standard NetVSC message header.
    header: NetVscHeader,

    /// GPADL identifier of the mapped receive buffer.
    gpadl_id: u32,

    /// Buffer identifier (must be [NETVSC_RECEIVE_BUFFER_ID]).
    id: u16,

    /// Reserved (must be 0).
    reserved: [u8; 22 + 8],
}

/// Completion message from the host acknowledging a **send buffer registration**.
///
/// This is sent by the host in response to a [`NetVscSendSendBuffer`] message.
/// It indicates whether the buffer was successfully registered, and provides
/// information about the usable section size for packet transmissions.
#[derive(Debug, Copy, Clone)]
#[repr(C, packed)]
pub struct NetVscSendSendBufferCompletion {
    /// Standard NetVSC message header.
    header: NetVscHeader,

    /// Status of the send buffer registration.
    status: NetVscStatus,

    /// Size of each suballocation section in bytes.
    section_size: u32,
}

/// Types of RNDIS (Remote Network Driver Interface Specification) channels.
#[derive(Debug, Copy, Clone)]
#[repr(u32)]
enum RndisChannelType {
    /// Channel used for regular network data packets.
    Data = 0,

    /// Channel used for control and management messages.
    Control = 1,
}

/// Represents a packet sent over the NetVSC interface using the RNDIS protocol.
///
/// This structure contains information about the type of RNDIS channel,
/// the location and size of the send buffer section containing the packet data.
#[derive(Debug, Copy, Clone)]
#[repr(C, packed)]
pub struct NetVscSendRndisPacket {
    /// Common NetVSC message header.
    header: NetVscHeader,

    /// Indicates if the packet is sent over Data or Control channel.
    channel_type: RndisChannelType,

    /// Index of the buffer section to send.
    send_buffer_section_index: u32,

    /// Length of the data in the buffer to send.
    send_buffer_section_size: u32,

    /// Reserved
    reserved: [u8; 24],
}

/// Indicates the completion status of a previously sent RNDIS packet.
#[derive(Debug, Copy, Clone)]
#[repr(C, packed)]
pub struct NetVscSendRndisPacketComplete {
    /// Common NetVSC message header.
    header: NetVscHeader,

    /// Status of the RNDIS packet send operation
    status: NetVscStatus,
}

// Safety asserts. We need to make sure that messages sent by the guest
// to the host have exactly 40 bytes, even if they are shorter.
const _: () = assert!(size_of::<NetVscSendNdisConfig>() == 40);
const _: () = assert!(size_of::<NetVscSendNdisVersion>() == 40);
const _: () = assert!(size_of::<NetVscSendReceiveBuffer>() == 40);
const _: () = assert!(size_of::<NetVscSendSendBuffer>() == 40);
const _: () = assert!(size_of::<NetVscSendRndisPacket>() == 40);
const _: () = assert!(size_of::<NetVscSendSendBuffer>() == 40);

// RNDIS stuff starts here

/// RNDIS Message Header
///
/// The `RndisMessageHeader` struct represents the common header present in all Remote Network
/// Driver Interface Specification (RNDIS) messages. This header provides the fundamental
/// information needed to identify and process RNDIS packets.
///
/// # Design Notes
///
/// While most RNDIS packets include a `request_id` field for correlating requests with
/// responses, this field is not universal across all message types. Therefore, the
/// `request_id` is not included in this base header structure and must be handled by
/// specific message type implementations where applicable.
///
/// This minimal header design ensures compatibility with all RNDIS message variants.
#[derive(Debug, Copy, Clone)]
#[repr(C, packed)]
struct RndisMessageHeader {
    /// Specifies the type of RNDIS message being transmitted.
    message_type: RndisMessageType,

    /// The total length of the entire RNDIS message in bytes excluding this header.
    length: u32,
}

impl RndisMessageHeader {
    pub fn with_message_type_and_length(
        message_type: RndisMessageType,
        length: u32,
    ) -> RndisMessageHeader {
        RndisMessageHeader {
            message_type,
            length,
        }
    }
}

/// RNDIS Message Types
///
/// This enum defines all valid message types used in the Remote Network Driver Interface
/// Specification (RNDIS) protocol. RNDIS uses a request-response pattern for most operations,
/// where completion messages (with the high bit set) correspond to their respective request
/// messages.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[repr(u32)]
enum RndisMessageType {
    /// Data packet transmission message
    ///
    /// Used to encapsulate network data packets for transmission over the RNDIS interface.
    /// This is the most common message type during normal network operation.
    Packet = 1,

    /// Initialization request message
    ///
    /// Sent by the host to initialize the RNDIS device. Contains version information and
    /// maximum transfer size parameters. Must be the first message sent to establish
    /// communication.
    Init = 2,

    /// Initialization completion message
    ///
    /// Response to the [RndisMessageType::Init] message, sent by the device to acknowledge initialization.
    /// Contains device capabilities, supported features, and agreed-upon parameters.
    InitComplete = 0x80000002,

    /// Halt request message
    ///
    /// Instructs the device to halt operations and prepare for disconnection. This is
    /// typically the last message sent before terminating the RNDIS session.
    Halt = 3,

    /// Object Identifier (OID) query request
    ///
    /// Requests the current value of a specific network adapter property or statistic.
    /// The OID parameter specifies which property to query (e.g., MAC address, link status).
    GetOid = 4,

    /// OID query completion message
    ///
    /// Response to [RndisMessageType::GetOid] request, containing the requested OID value or an error status
    /// if the query failed.
    GetOidComplete = 0x80000004,

    /// Object Identifier (OID) set request
    ///
    /// Attempts to modify a specific network adapter property. Used to configure device
    /// settings such as packet filters, multicast lists, or power management options.
    SetOid = 5,

    /// OID set completion message
    ///
    /// Response to [RndisMessageType::SetOid] request, indicating success or failure of the configuration
    /// change attempt.
    SetOidComplete = 0x80000005,

    /// Reset request message
    ///
    /// Instructs the device to perform a soft reset, clearing any pending operations
    /// and returning to a known state. Does not require re-initialization.
    Reset = 6,

    /// Reset completion message
    ///
    /// Response to [RndisMessageType::Reset] request, indicating the device has completed the reset operation
    /// and is ready to resume normal communication.
    ResetComplete = 0x80000006,

    /// Status indication message
    ///
    /// Unsolicited message sent by the device to report status changes such as link
    /// state changes, media connect/disconnect events, or error conditions.
    Indicate = 7,

    /// Keepalive request message
    ///
    /// Periodic message sent to verify that the communication channel is still active.
    /// Used to detect connection failures and maintain the RNDIS session.
    Keepalive = 8,

    /// Keepalive completion message
    ///
    /// Response to [RndisMessageType::Keepalive] request, confirming that the device is still responsive
    /// and the communication channel is operational.
    KeepaliveComplete = 0x80000008,
}

/// RNDIS Status Codes
#[repr(u32)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum RndisStatus {
    /// Operation completed successfully
    Success = 0,

    /// Network media connected
    MediaConnect = 0x4001000B,

    /// Network media disconnected
    MediaDisconnect = 0x4001000C,

    /// Link speed has changed
    LinkSpeedChange = 0x40010013,

    /// Network configuration changed
    NetworkChange = 0x40010018,
}

/// RNDIS Initialization Request Message
///
/// This structure represents an RNDIS initialization request sent by the host to initialize
/// communication with an RNDIS device. The Init message must be the first message sent to
/// establish the RNDIS session and negotiate communication parameters.
#[derive(Debug, Copy, Clone)]
#[repr(C, packed)]
struct RndisInitRequestMessage {
    /// Common RNDIS message header
    header: RndisMessageHeader,

    /// Request identifier
    request_id: u32,

    /// Major version number
    major_version: u32,

    /// Minor version number
    minor_version: u32,

    /// Maximum transfer size
    ///
    /// The maximum size in bytes that the host can handle for a single RNDIS message.
    /// This includes both control messages and data packets.
    max_transfer_size: u32,
}

/// Describes possible values of medium type connected to the NIC.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[repr(u32)]
enum RndisMediumType {
    /// Ethernet (IEEE 802.3)
    ///
    /// Standard Ethernet networking medium. This is the most common medium type
    /// for RNDIS devices, representing traditional wired or wireless Ethernet
    /// connections with standard Ethernet frame formatting.
    Ethernet = 0,

    /// Token Ring (IEEE 802.5)
    ///
    /// Token Ring networking medium. A legacy networking technology that uses
    /// a token-passing protocol on a ring topology.
    TokenRing = 1,

    /// Fiber Distributed Data Interface (FDDI)
    ///
    /// FDDI networking medium using fiber optic connections in a dual ring
    /// topology. A legacy high-speed networking technology primarily used
    /// in backbone networks.
    Fddi = 2,

    /// Wide Area Network (WAN)
    ///
    /// Generic WAN connection medium for various wide area networking
    /// technologies such as serial connections, frame relay, or other
    /// point-to-point WAN protocols.
    Wan = 3,

    /// LocalTalk
    ///
    /// Apple's LocalTalk networking protocol medium. A legacy networking
    /// technology primarily used in older Apple computer networks.
    LocalTalk = 6,

    /// Wireless WAN
    ///
    /// Wireless wide area network medium for cellular or other wireless
    /// WAN technologies such as CDMA, GSM, or other mobile data connections.
    WirelessWan = 9,

    /// Native 802.11 Wireless
    ///
    /// IEEE 802.11 wireless networking medium in native mode. Represents
    /// Wi-Fi connections where the device operates as a native wireless
    /// adapter rather than bridged Ethernet.
    Native802_11 = 14,

    /// Bluetooth
    ///
    /// Bluetooth networking medium for personal area network connections.
    /// Used for Bluetooth network access points or personal area networking
    /// over Bluetooth connections.
    Bluetooth = 15,

    /// InfiniBand
    ///
    /// InfiniBand high-performance networking medium. Used in high-performance
    /// computing and data center environments for low-latency, high-bandwidth
    /// interconnects.
    Infiniband = 16,
}

/// RNDIS Initialization Complete Message
///
/// This message is sent in response to an `RndisInitRequestMessage` and uses the same
/// `request_id` for correlation.
#[derive(Debug, Copy, Clone)]
#[repr(C, packed)]
struct RndisInitCompleteMessage {
    /// Common RNDIS message header
    header: RndisMessageHeader,

    /// Request identifier
    request_id: u32,

    /// Initialization status
    status: RndisStatus,

    /// Device major version number
    major_version: u32,

    /// Device minor version number
    minor_version: u32,

    /// Device flags
    dev_flags: u32,

    /// Network medium type
    medium: RndisMediumType,

    /// Maximum packets per message
    ///
    /// The maximum number of data packets that can be concatenated into a single
    /// RNDIS message. A value of 1 indicates only single packets are supported.
    max_packets_per_message: u32,

    /// Maximum transfer size
    max_transfer_size: u32,

    /// Packet alignment factor
    packet_alignment_factor: u32,

    /// Address family list offset
    af_list_offset: u32,

    /// Address family list size
    af_list_size: u32,
}

/// RNDIS Object Identifiers (OIDs)
///
/// This enum defines Object Identifiers used in RNDIS GetOid and SetOid operations.
/// OIDs are standardized identifiers that represent specific network adapter properties,
/// statistics, and configuration parameters. They follow the Windows NDIS OID convention.
///
/// OIDs are used to query device capabilities, retrieve statistics, configure settings,
/// and monitor device status.
#[derive(Debug, Copy, Clone)]
#[repr(u32)]
enum RndisOid {
    /// Link speed in bits per second
    GeneralLinkSpeed = 0x00010107,

    /// Current packet filter settings
    GeneralCurrentPacketFilter = 0x0001010E,

    /// Media connection status
    MediaConnectStatus = 0x00010114,

    /// Permanent Ethernet MAC address
    EthernetPermanentAddress = 0x1010101,

    /// Current Ethernet MAC address
    EthernetCurrentAddress = 0x01010102,
}

/// RNDIS Get OID Request Message
///
/// This structure represents a request to query the value of a specific Object Identifier (OID)
/// from an RNDIS device.
#[derive(Debug, Copy, Clone)]
#[repr(C, packed)]
struct RndisGetOidRequestMessage {
    /// Common RNDIS message header
    header: RndisMessageHeader,

    /// Request identifier
    request_id: u32,

    /// Object Identifier to query
    ///
    /// Specifies which device property or statistic to retrieve. The OID determines
    /// the type and format of data that will be returned in the response.
    oid: RndisOid,

    /// Information buffer length
    info_buffer_length: u32,

    /// Information buffer offset
    info_buffer_offset: u32,

    /// Device virtual circuit handle. Should be 0 for Ethernet devices.
    device_vc_handle: u32,
}

/// RNDIS Get OID Complete Message
///
/// The GetOidComplete message contains the requested OID value or indicates an error
/// if the query failed. The actual OID data follows this header at the specified
/// offset when the operation is successful.
#[derive(Debug, Copy, Clone)]
#[repr(C, packed)]
struct RndisGetOidCompleteMessage {
    /// Common RNDIS message header
    header: RndisMessageHeader,

    /// Request identifier
    request_id: u32,

    /// Operation status
    status: RndisStatus,

    /// Information buffer length
    ///
    /// The length in bytes of the OID data returned with this response.
    info_buffer_length: u32,

    /// Information buffer offset
    ///
    /// Byte offset from the start of this message to the returned OID data buffer.
    info_buffer_offset: u32,
}

/// RNDIS Set OID Request Message
///
/// This structure represents a request to modify the value of a specific Object Identifier (OID)
/// on an RNDIS device. SetOid requests are used to configure device properties, settings,
/// and operational parameters.
#[derive(Debug, Copy, Clone)]
#[repr(C, packed)]
struct RndisSetOidRequestMessage {
    /// Common RNDIS message header
    header: RndisMessageHeader,

    /// Request identifier
    request_id: u32,

    /// Object Identifier to modify
    oid: RndisOid,

    /// Information buffer length
    ///
    /// The length in bytes of the new value data provided with this request.
    info_buffer_length: u32,

    /// Information buffer offset
    ///
    /// Byte offset from the start of this message to the new value data buffer.
    info_buffer_offset: u32,

    /// Device virtual circuit handle. Should be 0 for Ethernet devices.
    device_vc_handle: u32,
}

/// RNDIS Set OID Complete Message
///
/// This structure represents the response sent by an RNDIS device to a SetOid request.
/// The SetOidComplete message indicates whether the requested configuration change
/// was successful or failed.
#[derive(Debug, Copy, Clone)]
#[repr(C, packed)]
struct RndisSetOidCompleteMessage {
    /// Common RNDIS message header
    header: RndisMessageHeader,

    /// Request identifier
    request_id: u32,

    /// Operation status
    status: RndisStatus,
}

/// RNDIS Indicate Message
///
/// This structure represents an unsolicited status indication message sent by an RNDIS device
/// to report asynchronous events or status changes to the host. Unlike request-response
/// messages, indications are sent spontaneously by the device when noteworthy events occur.
///
/// Common uses include reporting link state changes (connect/disconnect), speed changes,
/// network configuration updates, or error conditions.
#[derive(Debug, Copy, Clone)]
#[repr(C, packed)]
struct RndisIndicateMessage {
    /// Common RNDIS message header
    header: RndisMessageHeader,

    /// Status code being reported
    status: RndisStatus,

    /// Status buffer length
    status_buffer_length: u32,

    /// Status buffer offset
    status_buffer_offset: u32,
}

/// RNDIS Packet Message
///
/// This structure represents an RNDIS data packet message used to transmit network data
/// over the RNDIS interface. The network data (typically an Ethernet frame) immediately
/// follows this header structure in memory.
#[derive(Debug, Copy, Clone)]
#[repr(C, packed)]
struct RndisPacketMessage {
    /// Common RNDIS message header
    header: RndisMessageHeader,

    /// Data field descriptor
    ///
    /// Describes the location and size of the main network data payload within this
    /// message. Points to the actual network frame data (e.g., Ethernet frame)
    /// that is being transmitted.
    data: RndisPacketField,

    /// Out-of-band data field descriptor
    out_of_band_data: RndisPacketField,

    /// Number of out-of-band entries
    number_of_out_of_band_entries: u32,

    /// Per-packet information record descriptor
    per_packet_information_record: RndisPacketField,

    /// Virtual circuit handle. Should be 0 for Ethernet devices.
    vc_handle: u32,

    /// Reserved field
    reserved: u32,
    // The actual network data (e.g., Ethernet frame) follows immediately after
    // this structure at the offset specified by the `data` field descriptor.
}

/// RNDIS Packet Field Descriptor
///
/// This structure describes the location and size of variable-length data within an
/// RNDIS message.
#[derive(Debug, Copy, Clone)]
#[repr(C, packed)]
struct RndisPacketField {
    /// Byte offset from message start
    offset: u32,

    /// Data length in bytes
    len: u32,
}

pub struct VmBusNic {
    pub channel: VmBusChannel,
    pub offer: VmBusOfferChannel,
    pub hyper_v: Arc<HyperV>,
    pub state: RwLock<VmBusNicState>,
}

/// This struct maintains all necessary information and buffers required
/// for sending and receiving network packets through the NetVsc.
pub struct VmBusNicState {
    /// First allocated frame of RX buffer.
    pub rx_starting_frame: Frame,

    /// First allocated frame of TX buffer.
    pub tx_starting_frame: Frame,

    /// Pointer to the start of RX buffer.
    pub rx_buf_base: *mut u8,

    /// Pointer to the start of TX buffer.
    pub tx_buf_base: *mut u8,

    /// GPADL ID of RX buffer.
    pub rx_gpadl: u32,

    /// GPADL ID of TX buffer.
    pub tx_gpadl: u32,

    /// Section size inside TX buffer.
    pub tx_section_size: u32,

    /// Number of sections into which the transmit (TX) buffer is divided.
    pub tx_section_count: u32,

    /// Next free section index.
    pub current_section_index: u32,

    /// Counter of NetVSC transmit IDs.
    pub netvsc_xid_counter: AtomicU64,

    /// Counter of RNDIS transmit IDs.
    pub rndis_xid_counter: AtomicU64,

    /// Buffer of received NetVsc messages. (packet_id, packet_data)
    pub netvsc_packet_buffer: HashMap<u64, [u8; 50]>,

    /// Buffer of received RNDIS messages. (packet_id, packet_data)
    pub rndis_packet_buffer: HashMap<u32, Box<[u8]>>,
}

unsafe impl Sync for VmBusNicState {}
unsafe impl Send for VmBusNicState {}

impl VmBusSyntheticDevice for VmBusNic {
    fn initialize(&self) -> bool {
        // Allocate RX and TX buffers
        self.allocate_buffers();

        // Negotiate protocol version with NetVsp and RNDIS host
        self.negotiate_protocol_versions();

        // Send TX and RX buffers location to the NetVsp.
        self.register_buffers();

        // Perform RNDIS initialization
        self.initialize_rndis();

        log::debug!("MAC addr: {:?}", self.get_mac_address());
        log::debug!("Link status: {}", self.is_link_conntected());
        log::debug!("Link speed: {} Mbps", self.get_link_speed());

        // Enable receiver
        self.set_nic_state(true, true);

        // Dummy packet data for testing the NIC driver. Remove it when network stack will be up.
        let dhcp_discover: [u8; 342] = [
            // ---------------- Ethernet II Header ----------------
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // target mac
            0x00, 0x15, 0x5d, 0x01, 0x66, 0x0c, // source mac
            0x08, 0x00, // EtherType: IPv4 (0x0800)
            // ---------------- IPv4 ----------------
            0x45, // version + len
            0x00, // DSCP/ECN
            0x01, 0x48, // len
            0x00, 0x00, // id
            0x40, 0x00, // flags
            0x40, // ttl
            0x11, // udp
            0xb8, 0x6e, // checksum
            0x00, 0x00, 0x00, 0x00, // source ip
            0xff, 0xff, 0xff, 0xff, // target ip
            // ---------------- UDP ----------------
            0x00, 0x44, // Source port
            0x00, 0x43, // Dest port
            0x01, 0x34, // Len
            0x00, 0x00, // Checksum
            // BOOTP
            0x01, // op: BOOTREQUEST (1)
            0x01, // htype: Ethernet (1)
            0x06, // hlen
            0x00, // hops
            0x12, 0x34, 0x56, 0x78, // xid
            0x00, 0x00, // secs
            0x80, 0x00, // flags
            0x00, 0x00, 0x00, 0x00, // ciaddr
            0x00, 0x00, 0x00, 0x00, // yiaddr
            0x00, 0x00, 0x00, 0x00, // siaddr
            0x00, 0x00, 0x00, 0x00, // giaddr
            // chaddr
            0x00, 0x15, 0x5d, 0x01, 0x66, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, // sname
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // file
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, // DHCP
            // Magic Cookie
            0x63, 0x82, 0x53, 0x63, // DHCP Message Type (DHCPDISCOVER)
            0x35, 0x01, 0x01, // Parameter Request List
            0x37, 0x04, 0x01, 0x03, 0x06, 0x0f, // Client identifier
            0x3d, 0x07, 0x01, 0x78, 0x04, 0x18, 0x07, 0x00, 0x80, // End
            0xff, // padding
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        // Send this packet 4 times
        self.send_rndis_data_packet(unsafe { dhcp_discover.as_ptr() }, 342);
        self.send_rndis_data_packet(unsafe { dhcp_discover.as_ptr() }, 342);
        self.send_rndis_data_packet(unsafe { dhcp_discover.as_ptr() }, 342);
        self.send_rndis_data_packet(unsafe { dhcp_discover.as_ptr() }, 342);

        true
    }

    fn has_data_to_process(&self) -> bool {
        self.channel.has_data_to_process()
    }

    fn process_incoming_data(&self) {
        let (header, data_slice) = self.channel.read().unwrap();
        let data = data_slice.as_ptr();
        let net_hdr = unsafe { *(data as *const NetVscHeader) };
        let message_type = net_hdr.message_type;

        match message_type {
            NetVscMessageType::SendRndisPacketCompletion => {
                let net_pkt = unsafe { *(data as *const NetVscSendRndisPacketComplete) };
                let status = net_pkt.status;

                // We don't track completions of our RNDIS packets, so just assert it's success.
                assert_eq!(status, NetVscStatus::Success);
            }
            NetVscMessageType::SendRndisPacket => {
                // NIC packets are always sent using Xfer Page Header.
                if let VmBusPacketHeader::Xfer(xfer) = header {
                    // Handle RNDIS message in separate function.
                    self.handle_rndis_message(&xfer);

                    // Send completion to received packet. It's just a data-layer Ack that we received this data,
                    // it does not imply that we accept the content inside.
                    let completion = NetVscSendRndisPacketComplete {
                        header: NetVscHeader::with_message_type(
                            NetVscMessageType::SendRndisPacketCompletion,
                        ),
                        status: NetVscStatus::Success,
                    };

                    self.channel.send_packet(
                        unsafe { &completion as *const _ as *const u8 },
                        size_of::<NetVscSendRndisPacketComplete>(),
                        xfer.header.xid,
                        false,
                        VmBusPacketType::Completion,
                    );
                } else {
                    unreachable!()
                }
            }
            _ => {
                // Every other packet type is response to our request, so save it for further processing.
                without_interrupts(|| {
                    let packet_xid = match header {
                        VmBusPacketHeader::Packet(hdr) => hdr.xid,
                        VmBusPacketHeader::Xfer(hdr) => hdr.header.xid,
                    };

                    self.state
                        .write()
                        .netvsc_packet_buffer
                        .insert(packet_xid, unsafe { *(data as *const [u8; 50]) })
                });
            }
        }
    }
}

impl VmBusNic {
    /// Returns the next available transaction ID (xid) for NetVSC operations.
    fn next_netvsc_xid(&self) -> u64 {
        without_interrupts(|| {
            self.state
                .read()
                .netvsc_xid_counter
                .fetch_add(1, Ordering::Relaxed)
        })
    }

    /// Returns the next available transaction ID (xid) for RNDIS operations.
    fn next_rndis_xid(&self) -> u32 {
        without_interrupts(|| {
            self.state
                .read()
                .rndis_xid_counter
                .fetch_add(1, Ordering::Relaxed) as u32
        })
    }

    /// Handles an incoming RNDIS message received over the VMBus channel.
    fn handle_rndis_message(&self, xfer: &VmBusXferPageHeader) {
        for i in 0..xfer.range_count {
            let range_ptr = unsafe { &xfer.range[0] as *const VmBusGpaRange };
            let range = unsafe { *range_ptr.add(i as usize) };

            let data_ptr = unsafe {
                self.state
                    .read()
                    .rx_buf_base
                    .add(range.starting_byte_offset as usize)
            };

            let rndis_header = unsafe { *(data_ptr as *const RndisMessageHeader) };
            let message_length = rndis_header.length;
            let page_set_id = xfer.page_set_id;
            let rndis_message_type = rndis_header.message_type;

            // Safety assert that our packet is in receive buffer.
            assert_eq!(page_set_id, NETVSC_RECEIVE_BUFFER_ID);

            if rndis_message_type != RndisMessageType::Indicate
                && rndis_message_type != RndisMessageType::Packet
            {
                // It's response to our request packet, so save it in the `rndis_packet_buffer` for
                // further processing.
                without_interrupts(|| {
                    let slice = unsafe {
                        slice::from_raw_parts(
                            data_ptr,
                            rndis_header.length as usize + size_of::<RndisMessageHeader>(),
                        )
                    };

                    // Extract `request_id` from the received RNDIS packet.
                    //
                    // At this point, we don't yet know the exact message type of the packet.
                    // However, we *do* know that for all RNDIS response messages that are replies
                    // to a guest-initiated request, the `request_id` field is located at a fixed
                    // position immediately *after* the RNDIS message header.
                    //
                    // Since `RndisInitCompleteMessage` has `request_id` at that expected location,
                    // we temporarily cast the raw data pointer to `RndisInitCompleteMessage` solely
                    // to access the `request_id` field.
                    let packet_as_init = unsafe { *(data_ptr as *const RndisInitCompleteMessage) };
                    let request_id = packet_as_init.request_id;

                    self.state
                        .write()
                        .rndis_packet_buffer
                        .insert(request_id, slice.to_vec().into_boxed_slice())
                });

                return;
            }

            if rndis_message_type == RndisMessageType::Packet {
                let rndis_message = unsafe { *(data_ptr as *const RndisPacketMessage) };

                let eth_data =
                    unsafe { data_ptr.add(8 + rndis_message.data.offset as usize) as *const u8 };

                // Now the data is extracted
                // @TODO: Call higher level drivers to handle Ethernet packet and decapsulate it.

                let eth_frame = unsafe { *(eth_data as *const _ as *const EthernetFrameHeader) };
                let ether_type = eth_frame.ether_type;
                log::debug!("Got Ethernet frame: {eth_frame:x?}");
                if ether_type == EtherType::Ipv4 {
                    let ip_header = unsafe {
                        *(eth_data.add(size_of::<EthernetFrameHeader>()) as *const Ipv4Header)
                    };

                    log::debug!("with ip packet header: {ip_header:?}")
                }
            } else if rndis_message_type == RndisMessageType::Indicate {
                // link went up/went down/something changed, need to track NIC state internally and react for such messages
                let rndis_message = unsafe { *(data_ptr as *const RndisIndicateMessage) };

                log::debug!("Got rndis indicate message: {rndis_message:?}");
            }
        }
    }

    /// Allocates send and receive buffers for the NetVSC device.
    fn allocate_buffers(&self) {
        // @TODO: Refactor
        let rx_starting_frame = memory_manager()
            .write()
            .allocate_frames_contiguous(NETVSC_RECEIVE_BUFFER_SIZE as usize / HYPERV_PAGE_SIZE)
            .unwrap();

        let rx_virt_start = unsafe {
            memory_manager()
                .write()
                .map_any_for_current_address_space(&rx_starting_frame, PageFlags::WRITABLE)
        };
        self.state.write().rx_starting_frame = rx_starting_frame;
        self.state.write().rx_buf_base = unsafe { rx_virt_start.address().as_u64() as *mut u8 };

        for i in 1..(NETVSC_RECEIVE_BUFFER_SIZE as usize / HYPERV_PAGE_SIZE) {
            unsafe {
                memory_manager().write().map_for_current_address_space(
                    &Page::new(VirtualAddress::new(
                        (rx_virt_start.address().as_u64() as usize + i * HYPERV_PAGE_SIZE) as u64,
                    )),
                    &Frame::new(PhysicalAddress::new(
                        (rx_starting_frame.address().as_u64() as usize + i * HYPERV_PAGE_SIZE)
                            as u64,
                    )),
                    PageFlags::WRITABLE,
                );
            }
        }

        let tx_starting_frame = memory_manager()
            .write()
            .allocate_frames_contiguous(NETVSC_SEND_BUFFER_SIZE as usize / HYPERV_PAGE_SIZE)
            .unwrap();

        let tx_virt_start = unsafe {
            memory_manager()
                .write()
                .map_any_for_current_address_space(&tx_starting_frame, PageFlags::WRITABLE)
        };
        self.state.write().tx_starting_frame = tx_starting_frame;
        self.state.write().tx_buf_base = unsafe { tx_virt_start.address().as_u64() as *mut u8 };

        for i in 1..(NETVSC_SEND_BUFFER_SIZE as usize / HYPERV_PAGE_SIZE) {
            unsafe {
                memory_manager().write().map_for_current_address_space(
                    &Page::new(VirtualAddress::new(
                        (tx_virt_start.address().as_u64() as usize + i * HYPERV_PAGE_SIZE) as u64,
                    )),
                    &Frame::new(PhysicalAddress::new(
                        (tx_starting_frame.address().as_u64() as usize + i * HYPERV_PAGE_SIZE)
                            as u64,
                    )),
                    PageFlags::WRITABLE,
                );
            }
        }
    }

    /// Performs protocol version negotiation with the host for NetVSC and NDIS.
    fn negotiate_protocol_versions(&self) {
        // NetVscInitMessage specifies protocol version supported by the guest.
        // We don't support any older version, so specify Version6_1 and panic in
        // case Hyper-V does not support it.
        let mut init = NetVscInitMessage {
            header: NetVscHeader::with_message_type(NetVscMessageType::Init),
            minimum_supported_version: NetVscProtocolVersion::Version6_1,
            maximum_supported_version: NetVscProtocolVersion::Version6_1,
            reserved: [0u8; 20],
        };

        let init_complete: NetVscInitCompleteMessage =
            self.send_netvsc_packet_and_wait_for_reply(&init, true);

        // We don't support any other protocol versions. Newer version will provide backward compatibility
        // to the 6.1, older are not supported.
        assert_eq!({ init_complete.status }, NetVscStatus::Success);

        // Send NDIS config - max MTU size (1538) and enable SR-IOV.
        let ndis_config = NetVscSendNdisConfig {
            header: NetVscHeader::with_message_type(NetVscMessageType::SendNdisConfig),
            mtu: 1538,
            reserved: 0,
            capabilities: 8 | 4, // Enable Chimney and SR-IOV
            reserved2: [0u8; 12 + 8],
        };

        // This packet does not have completion message associated with it.
        self.send_netvsc_packet(&ndis_config, false);

        // Send supported NDIS version. It's also hardcoded.
        let mut ndis_version = NetVscSendNdisVersion {
            header: NetVscHeader::with_message_type(NetVscMessageType::SendNdisVersion),
            major: 0x6,
            minor: 0x1e,
            reserved: [0u8; 20 + 8],
        };

        // This packet does not have completion as well.
        self.send_netvsc_packet(&ndis_version, false);
    }

    /// Registers send and receive buffers with the host by creating GPADL mapping
    /// and notifying the VSP using NetVsc packets.
    fn register_buffers(&self) {
        // Share RX and TX buffers with Hyper-V
        let rx_starting_frame = self.state.read().rx_starting_frame;
        let tx_starting_frame = self.state.read().tx_starting_frame;

        let rx_gpadl = self.hyper_v.create_gpadl(
            self.offer.channel_id,
            rx_starting_frame.address(),
            NETVSC_RECEIVE_BUFFER_SIZE as usize,
        );
        let tx_gpadl = self.hyper_v.create_gpadl(
            self.offer.channel_id,
            tx_starting_frame.address(),
            NETVSC_SEND_BUFFER_SIZE as usize,
        );

        // Save GPADL IDs to be able to revoke GPADL in case we get a RescindOffer message.
        without_interrupts(|| {
            let mut state = self.state.write();

            state.rx_gpadl = rx_gpadl;
            state.tx_gpadl = tx_gpadl;
        });

        // Send receive buffer to the NetVsp. ID needs to be `NETVSC_RECEIVE_BUFFER_ID`
        // as it is required by VMBus.
        let mut send_rx_buffer = NetVscSendReceiveBuffer {
            header: NetVscHeader::with_message_type(NetVscMessageType::SendReceiveBuffer),
            gpadl_id: rx_gpadl,
            id: NETVSC_RECEIVE_BUFFER_ID,
            reserved: [0u8; 22 + 8],
        };

        let send_rx_buffer_completion: NetVscSendReceiveBufferCompletion =
            self.send_netvsc_packet_and_wait_for_reply(&send_rx_buffer, true);

        // Make sure that host registered the buffer and divided the buffer into one big section.
        // We don't save suballocation count nor size for further processing, because RNDIS driver
        // will send us the offset from the beginning of the buffer where the packet starts. Honestly,
        // I don't know why is it even a thing.
        assert_eq!({ send_rx_buffer_completion.status }, NetVscStatus::Success);
        assert_eq!({ send_rx_buffer_completion.number_of_sections }, 1);
        assert!({ send_rx_buffer_completion.sections[0].suballocation_size } > 1518);

        // Send TX buffer to the NetVsp. ID is hardcoded and can't be changed.
        let send_send_buffer = NetVscSendSendBuffer {
            header: NetVscHeader::with_message_type(NetVscMessageType::SendSendBuffer),
            gpadl_id: tx_gpadl,
            id: NETVSC_SEND_BUFFER_ID,
            reserved: [0u8; 22 + 8],
        };

        let send_send_buffer_completion: NetVscSendSendBufferCompletion =
            self.send_netvsc_packet_and_wait_for_reply(&send_send_buffer, true);

        // Make sure the host agreed on TX buffer address and section size is bigger than maximum MTU.
        assert_eq!(
            { send_send_buffer_completion.status },
            NetVscStatus::Success
        );
        assert!({ send_send_buffer_completion.section_size } > 1518);

        // Save section size, because we will need it while sending packets.
        without_interrupts(|| {
            let mut state = self.state.write();
            state.tx_section_size = send_send_buffer_completion.section_size;
            state.tx_section_count = NETVSC_SEND_BUFFER_SIZE / state.tx_section_size;
        });
    }

    /// Sends the initial `RNDIS_INIT` message from the guest to the host,
    /// which begins the RNDIS protocol handshake.
    fn initialize_rndis(&self) {
        let rndis_init = RndisInitRequestMessage {
            header: RndisMessageHeader::with_message_type_and_length(
                RndisMessageType::Init,
                size_of::<RndisInitRequestMessage>() as u32,
            ),
            request_id: 0,
            major_version: NETVSC_RNDIS_MAJOR_VERSION,
            minor_version: NETVSC_RNDIS_MINOR_VERSION,
            max_transfer_size: 0x4000,
        };

        let reply: RndisInitCompleteMessage = self
            .send_rndis_control_packet_and_wait_for_reply_packet(
                unsafe { &rndis_init as *const _ as *const u8 },
                size_of::<RndisInitRequestMessage>(),
            );

        // Make sure that initialization completed successfully, we have an Ethernet card and
        // the card supports our protocol version.
        assert_eq!({ reply.status }, RndisStatus::Success);
        assert_eq!({ reply.medium }, RndisMediumType::Ethernet);
        assert_eq!({ reply.major_version }, NETVSC_RNDIS_MAJOR_VERSION);
        assert_eq!({ reply.minor_version }, NETVSC_RNDIS_MINOR_VERSION);
    }

    /// Returns MAC address by querying EthernetPermanentAddress OID.
    pub fn get_mac_address(&self) -> MacAddress {
        let rndis_mac_oid = RndisGetOidRequestMessage {
            header: RndisMessageHeader::with_message_type_and_length(
                RndisMessageType::GetOid,
                size_of::<RndisGetOidRequestMessage>() as u32,
            ),
            request_id: 0,
            oid: RndisOid::EthernetPermanentAddress,
            info_buffer_length: 0,
            info_buffer_offset: size_of::<RndisGetOidRequestMessage>() as u32
                - size_of::<RndisMessageHeader>() as u32, // even with buffer_len=0 this has to be set
            device_vc_handle: 0,
        };

        let (oid_response, buffer): (RndisGetOidCompleteMessage, _) = self
            .send_rndis_control_packet_and_wait_for_reply(
                unsafe { &rndis_mac_oid as *const _ as *const u8 },
                size_of::<RndisGetOidRequestMessage>(),
            );

        // Safety assert that returned MAC address is exactly 6 bytes long.
        assert_eq!({ oid_response.info_buffer_length }, 6);

        let mac = unsafe {
            *(buffer.as_ptr().add(
                // It's the offset from the end of the header - we can do size_of::<T> - size_of::<Header> but it's more clean
                core::mem::offset_of!(RndisGetOidCompleteMessage, request_id)
                    + oid_response.info_buffer_offset as usize,
            ) as *const [u8; 6])
        };

        MacAddress(mac)
    }

    /// Checks if link is connected by querying MediaConnectStatus OID.
    pub fn is_link_conntected(&self) -> bool {
        let rndis_link_oid = RndisGetOidRequestMessage {
            header: RndisMessageHeader::with_message_type_and_length(
                RndisMessageType::GetOid,
                size_of::<RndisGetOidRequestMessage>() as u32,
            ),
            request_id: 0,
            oid: RndisOid::MediaConnectStatus,
            info_buffer_length: 0,
            info_buffer_offset: size_of::<RndisGetOidRequestMessage>() as u32
                - size_of::<RndisMessageHeader>() as u32, // even with buffer_len=0 this has to be set
            device_vc_handle: 0,
        };

        let (oid_response, buffer): (RndisGetOidCompleteMessage, _) = self
            .send_rndis_control_packet_and_wait_for_reply(
                unsafe { &rndis_link_oid as *const _ as *const u8 },
                size_of::<RndisGetOidRequestMessage>(),
            );

        // Safety assert that returned link status is exactly 4 bytes long.
        assert_eq!({ oid_response.info_buffer_length }, 4);

        let link_status = unsafe {
            *(buffer.as_ptr().add(
                // It's the offset from the end of the header - we can do size_of::<T> - size_of::<Header> but it's more clean
                core::mem::offset_of!(RndisGetOidCompleteMessage, request_id)
                    + oid_response.info_buffer_offset as usize,
            ) as *const u32)
        };

        // 0 means connected, any other value indicates error.
        link_status == 0
    }

    /// Returns link speed in Mbps by querying GeneralLinkSpeed OID.
    pub fn get_link_speed(&self) -> u32 {
        let rndis_link_oid = RndisGetOidRequestMessage {
            header: RndisMessageHeader::with_message_type_and_length(
                RndisMessageType::GetOid,
                size_of::<RndisGetOidRequestMessage>() as u32,
            ),
            request_id: 0,
            oid: RndisOid::GeneralLinkSpeed,
            info_buffer_length: 0,
            info_buffer_offset: size_of::<RndisGetOidRequestMessage>() as u32
                - size_of::<RndisMessageHeader>() as u32, // even with buffer_len=0 this has to be set
            device_vc_handle: 0,
        };

        let (oid_response, buffer): (RndisGetOidCompleteMessage, _) = self
            .send_rndis_control_packet_and_wait_for_reply(
                unsafe { &rndis_link_oid as *const _ as *const u8 },
                size_of::<RndisGetOidRequestMessage>(),
            );

        // Safety assert that returned link speed is exactly 4 bytes long.
        assert_eq!({ oid_response.info_buffer_length }, 4);

        // The returned buffer from ISR is Box[u8], which contains entire packet. Here we only get the casted
        // start as our structure, but the following bytes still exist.
        let link_speed = unsafe {
            *(buffer.as_ptr().add(
                // It's the offset from the end of the header - we can do size_of::<T> - size_of::<Header> but it's more clean
                core::mem::offset_of!(RndisGetOidCompleteMessage, request_id)
                    + oid_response.info_buffer_offset as usize,
            ) as *const u32)
        };

        // Link speed is returned in bits per second, so divide it by 10_000 to get Mbps.
        link_speed / 10_000
    }

    /// Updates the virtual NIC (Network Interface Card) operational state.
    /// It configures whether the NIC is enabled and whether it operates in promiscuous mode.
    pub fn set_nic_state(&self, enabled: bool, promiscuous: bool) {
        let mut filter_mode = 0;
        if enabled {
            filter_mode |= NETVSC_RNDIS_FILTER_PACKET_TYPE_DIRECTED;
            filter_mode |= NETVSC_RNDIS_FILTER_PACKET_TYPE_MULTICAST;
            filter_mode |= NETVSC_RNDIS_FILTER_PACKET_TYPE_BROADCAST;

            if promiscuous {
                filter_mode |= NETVSC_RNDIS_FILTER_PACKET_TYPE_PROMISCUOUS;
            }
        }

        let mut rndis_filter_update_oid = RndisSetOidRequestMessage {
            header: RndisMessageHeader::with_message_type_and_length(
                RndisMessageType::SetOid,
                size_of::<RndisSetOidRequestMessage>() as u32 + 4,
            ),
            request_id: 0,
            oid: RndisOid::GeneralCurrentPacketFilter,
            info_buffer_length: 4,
            info_buffer_offset: size_of::<RndisSetOidRequestMessage>() as u32
                - size_of::<RndisMessageHeader>() as u32,
            device_vc_handle: 0,
        };

        // Allocate buffer for SetOid message
        let mut data_vec = alloc::vec![0u8; size_of::<RndisSetOidRequestMessage>() + 4];
        let mut data_buf = data_vec.as_mut_ptr();
        unsafe {
            // Copy request packet to the buffer
            copy(
                &mut rndis_filter_update_oid as *mut _ as *mut u8,
                data_buf,
                size_of::<RndisSetOidRequestMessage>(),
            );

            // Copy filter status to the buffer
            copy(
                &filter_mode as *const _ as *const u8,
                data_buf.add(size_of::<RndisSetOidRequestMessage>()),
                4,
            )
        };

        // Send buffer
        let completion: RndisSetOidCompleteMessage = self
            .send_rndis_control_packet_and_wait_for_reply_packet(
                unsafe { data_buf },
                size_of::<RndisSetOidRequestMessage>() + 4,
            );

        assert_eq!({ completion.status }, RndisStatus::Success);
    }

    /// Sends a NetVSC control packet to the host over the VMBus channel.
    /// Returns a transaction ID used to track the packet.
    fn send_netvsc_packet<T>(&self, packet: &T, completion_requested: bool) -> u64 {
        let xid = self.next_netvsc_xid();

        self.channel.send_packet(
            unsafe { packet as *const T as *const u8 },
            size_of::<T>(),
            xid,
            completion_requested,
            VmBusPacketType::DataInband,
        );

        xid
    }

    /// Sends a typed NetVSC control message to the host over the VMBus channel,
    /// then blocks execution until a response is received.
    fn send_netvsc_packet_and_wait_for_reply<RequestType, ResponseType: Copy + Clone>(
        &self,
        packet: &RequestType,
        completion_requested: bool,
    ) -> ResponseType {
        let rndis_xid = self.send_netvsc_packet(packet, completion_requested);

        loop {
            if without_interrupts(|| {
                self.state
                    .read()
                    .netvsc_packet_buffer
                    .contains_key(&rndis_xid)
            }) {
                let buffer = without_interrupts(|| {
                    let mut state = self.state.write();
                    state.netvsc_packet_buffer.remove(&rndis_xid).unwrap()
                });

                return unsafe { *(&buffer as *const _ as *const ResponseType) };
            }
        }
    }

    /// Sends a raw RNDIS control packet to the host over the control channel. It does not use
    /// any send buffer sections, the bufferr is sent via GPA Direct VMBus message type.
    fn send_rndis_control_packet(&self, buffer: *const u8, buffer_len: usize) -> u32 {
        // We send NetVsc message with type SendRndisPacket with RNDIS packet sent to the separate data buffer
        // outside of VMBus Channel. The NetVsc packet only has to inform the host about the buffer location
        let netvsc_rndis_packet = NetVscSendRndisPacket {
            header: NetVscHeader::with_message_type(NetVscMessageType::SendRndisPacket),
            channel_type: RndisChannelType::Control,
            send_buffer_section_index: u32::MAX, // no send buffer used
            send_buffer_section_size: 0,
            reserved: [0u8; 24],
        };

        // Write request_id
        //
        // All RNDIS messages sent from the **guest to the host** include a `request_id` field
        // immediately following the message header. This field is used to associate responses
        // from the host with the corresponding request.
        //
        // However, not all RNDIS messages contain this field—particularly those sent *from the host
        // to the guest* that are unsolicited (e.g., when a new Ethernet frame arrives). Because of
        // this inconsistency, the `request_id` field cannot be part of the common `RndisMessageHeader`.
        //
        // Nevertheless, for all **guest-to-host** messages, it's safe to assume that the `request_id`
        // appears just after the header. Therefore, we locate the appropriate offset based on the
        // specific message struct (e.g., `RndisInitRequestMessage`) and write the ID directly to memory.
        let rndis_xid = self.next_rndis_xid();
        unsafe {
            let request_id_ptr =
                buffer.add(core::mem::offset_of!(RndisInitRequestMessage, request_id)) as *mut u32;
            *request_id_ptr = rndis_xid;
        };

        let netvsc_xid = self.next_netvsc_xid();

        self.channel.send_data_packet(
            unsafe { &netvsc_rndis_packet as *const _ as *const u8 },
            size_of::<NetVscSendRndisPacket>(),
            netvsc_xid,
            buffer,
            buffer_len,
        );

        rndis_xid
    }

    /// Sends a raw RNDIS control packet to the host and waits synchronously for the reply.
    /// It returns the Reply instance and buffer of bytes that the host transmitted. It is
    /// helpful in functions querying the OID, because OID value is appended at the end of the
    /// packet, and it's meaning is determined by the specific OID.
    fn send_rndis_control_packet_and_wait_for_reply<T: Copy + Clone>(
        &self,
        packet: *const u8,
        packet_len: usize,
    ) -> (T, Box<[u8]>) {
        let xid = self.send_rndis_control_packet(packet, packet_len);

        loop {
            if without_interrupts(|| self.state.read().rndis_packet_buffer.contains_key(&xid)) {
                let buffer = without_interrupts(|| {
                    let mut state = self.state.write();
                    state.rndis_packet_buffer.remove(&xid).unwrap()
                });

                return (
                    unsafe { *(buffer.as_ptr() as *const _ as *const T) },
                    buffer,
                );
            }
        }
    }

    /// Sends a raw RNDIS control packet to the host and waits synchronously for the reply.
    /// It returns the Reply instance only.
    fn send_rndis_control_packet_and_wait_for_reply_packet<T: Copy + Clone>(
        &self,
        packet: *const u8,
        packet_len: usize,
    ) -> T {
        self.send_rndis_control_packet_and_wait_for_reply(packet, packet_len)
            .0
    }

    /// Sends an Ethernet packet.
    fn send_rndis_data_packet(&self, buffer: *const u8, buffer_len: usize) {
        // Allocate section
        let (section_index, section_pointer) = without_interrupts(|| {
            let mut state = self.state.write();

            // Save section index and calculate pointer
            let section_index = state.current_section_index;
            let section_pointer = unsafe {
                state
                    .tx_buf_base
                    .add((section_index * state.tx_section_size) as usize)
            };

            // Increase current section index and dont allow it to go beyond section_count.
            state.current_section_index += 1;
            state.current_section_index %= state.tx_section_count;

            (section_index, section_pointer)
        });

        let packet_message = RndisPacketMessage {
            header: RndisMessageHeader::with_message_type_and_length(
                RndisMessageType::Packet,
                (size_of::<RndisPacketMessage>() + buffer_len) as u32,
            ),
            data: RndisPacketField {
                offset: (size_of::<RndisPacketMessage>() - size_of::<RndisMessageHeader>()) as u32,
                len: buffer_len as u32,
            },
            out_of_band_data: RndisPacketField { offset: 0, len: 0 },
            number_of_out_of_band_entries: 0,
            per_packet_information_record: RndisPacketField { offset: 0, len: 0 },
            vc_handle: 0,
            reserved: 0,
        };

        let netvsc_rndis_packet = NetVscSendRndisPacket {
            header: NetVscHeader::with_message_type(NetVscMessageType::SendRndisPacket),
            channel_type: RndisChannelType::Data,
            send_buffer_section_index: section_index,
            send_buffer_section_size: packet_message.header.length,
            reserved: [0u8; 24],
        };

        unsafe {
            copy(
                &packet_message as *const _ as *const u8,
                section_pointer,
                size_of::<RndisPacketMessage>(),
            );

            copy(
                buffer,
                section_pointer.add(size_of::<RndisPacketMessage>()),
                buffer_len,
            )
        };

        self.send_netvsc_packet(&netvsc_rndis_packet, true);
    }
}
