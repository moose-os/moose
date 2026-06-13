//! # Hyper-V Synthetic Mouse Protocol
//!
//! This crate implements the communication protocol for the synthetic mouse device used in
//! Hyper-V virtual machines.
//!
//! ## Protocol Flow
//!
//! ```text
//! Guest                         Host
//!   |                            |
//!   | --- ProtocolRequest -----> |
//!   | <--- ProtocolResponse ---- |
//!   | <--- InitialDeviceInfo ----|
//!   | --- InitialDeviceInfoAck ->|
//!   |                            |
//!   | <--- InputReport (many) ---|
//! ```
//!
//! After the handshake, the host continuously sends `InputReport` packets representing mouse events.
//!
//! ## InputReport Packet
//!
//! The `InputReport` packet reports mouse state including button presses, movement, wheel scrolling,
//! and panning. The packet layout:
//!
//! | Field    | Type | Description                            |
//! |----------|-------|---------------------------------------|
//! | buttons  | u8    | Bitfield representing pressed buttons |
//! | x        | u16   | X position                            |
//! | y        | u16   | Y position                            |
//! | wheel    | i8    | Wheel scroll                          |
//! | pan      | i8    | Horizontal pan scroll                 |
//!
//! ### Buttons bitfield
//!
//! | Bit | Meaning            |
//! |-----|--------------------|
//! | 0   | Left button (LPM)  |
//! | 1   | Right button (PPM) |
//! | 2   | Wheel button       |
//!
use core::ptr;

use alloc::vec;
use log::debug;

use crate::driver::hv::hyperv::{
    VmBusOfferChannel, VmBusPacketType, VmBusPipeHeader, VmBusPipeMessageType,
    channel::VmBusChannel, synthetic_device::VmBusSyntheticDevice,
};

pub struct VmBusMouseDriver {
    pub channel: VmBusChannel,
    pub offer: VmBusOfferChannel,
}

/// Represents the different packet types exchanged between the guest and host
/// over the VMBus synthetic mouse channel.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[repr(u32)]
enum VmBusMousePacketType {
    /// Requests negotiation of a protocol version for the mouse device.
    ProtocolRequest = 0,

    /// Responds to the [VmBusMousePacketType::ProtocolRequest], indicating whether the version is accepted.
    ProtocolResponse = 1,

    /// Sends initial information about the mouse device capabilities
    InitialDeviceInfo = 2,

    /// Acknowledges receipt of the initial device information.
    InitialDeviceInfoAck = 3,

    /// Sends mouse input events such as movement, button presses, or scroll wheel actions.
    InputReport = 4,
}

/// Defines supported protocol versions for the VMBus synthetic mouse.
/// Encodes major and minor version numbers in the upper and lower 16 bits.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[repr(u32)]
enum VmBusMouseProtocolVersion {
    Version2 = 2 << 16,
}

/// HID descriptor for the VMBus synthetic mouse device.
///
/// This structure describes the HID (Human Interface Device) capabilities
/// and descriptor metadata of the synthetic mouse.
#[derive(Debug, Copy, Clone)]
#[repr(C, packed)]
struct VmBusMouseHidDescriptor {
    /// Length of this descriptor in bytes.
    descriptor_length: u8,

    /// Type of this descriptor.
    descriptor_type: u8,

    /// Version number of the HID specification supported.
    descriptor_version_number: u16,

    /// Country code of the HID device.
    hid_country_code: u8,

    /// Number of HID class descriptors.
    hid_number_of_descriptors: u8,

    /// Type of the HID class descriptor.
    hid_descriptor_type: u8,

    /// Length of the HID class descriptor.
    hid_descriptor_length: u16,
}

/// Device information for the VMBus synthetic mouse.
#[derive(Debug, Copy, Clone)]
#[repr(C, packed)]
struct VmBusMouseDeviceInfo {
    size: u32,

    /// Vendor identifier for the device.
    vendor: u16,

    /// Product identifier for the device.
    product: u16,

    /// Version number of the device.
    version: u16,

    /// Reserved.
    reserved: [u16; 11],
}

/// Header for VMBus synthetic mouse packets.
///
/// Contains the type of the packet and the length of the entire packet data.
#[derive(Debug, Copy, Clone)]
#[repr(C, packed)]
struct VmBusMousePacketHeader {
    /// The type of mouse packet being sent.
    packet_type: VmBusMousePacketType,

    /// The length in bytes of the packet excluding this header.
    length: u32,
}

impl VmBusMousePacketHeader {
    pub fn with_packet_type_and_length(
        packet_type: VmBusMousePacketType,
        length: u32,
    ) -> VmBusMousePacketHeader {
        VmBusMousePacketHeader {
            packet_type,
            length,
        }
    }
}

/// Packet sent by the guest to request a specific mouse protocol version.
#[derive(Debug, Copy, Clone)]
#[repr(C, packed)]
struct VmBusMouseProtocolRequestPacket {
    /// Common mouse packet header.
    header: VmBusMousePacketHeader,

    /// The requested mouse protocol version.
    requested_version: VmBusMouseProtocolVersion,
}

/// Packet sent by the host in response to a mouse protocol request from the guest.
#[derive(Debug, Copy, Clone)]
#[repr(C, packed)]
struct VmBusMouseProtocolResponsePacket {
    /// Common mouse packet header.
    header: VmBusMousePacketHeader,

    /// The protocol version that was requested by the guest.
    requested_version: VmBusMouseProtocolVersion,

    /// Status code indicating the result of the protocol request. 1 means success.
    status: u8,

    /// Reserved.
    reserved: [u8; 3],
}

/// Packet containing initial device information sent by the host.
///
/// This packet provides details about the mouse device,
/// including device info and HID descriptor.
#[derive(Debug, Copy, Clone)]
#[repr(C, packed)]
struct VmBusMouseInitialDeviceInfoPacket {
    /// Common mouse packet header.
    header: VmBusMousePacketHeader,

    /// Device information such as vendor and product IDs.
    info: VmBusMouseDeviceInfo,

    /// HID (Human Interface Device) descriptor details.
    hid_descriptor: VmBusMouseHidDescriptor,

    /// HID data starts here.
    data: u8,
}

/// Acknowledgment packet for the initial device information.
#[derive(Debug, Copy, Clone)]
#[repr(C, packed)]
struct VmBusMouseInitialDeviceInfoAckPacket {
    /// Common mouse packet header.
    header: VmBusMousePacketHeader,

    /// Reserved.
    reserved: u8,
}

/// Mouse input report packet.
///
/// Represents the state of mouse buttons and movement since the last report.
#[derive(Debug, Copy, Clone)]
#[repr(C, packed)]
struct VmBusMouseInputReportPacket {
    /// Common mouse packet header.
    header: VmBusMousePacketHeader,

    /// Button state bitmask:
    /// - 1: Left mouse button (LMB)
    /// - 2: Right mouse button (RMB)
    /// - 4: Wheel button (middle button)
    buttons: u8,

    /// Current position on X axis.
    x: u16,

    /// Current position on Y axis.
    y: u16,

    /// Wheel movement (scrolling).
    wheel: i8,

    /// Horizontal panning (sideways scrolling).
    pan: i8,
}

impl VmBusMouseDriver {
    pub fn new(channel: VmBusChannel, offer: VmBusOfferChannel) -> Self {
        Self { channel, offer }
    }
}

impl VmBusSyntheticDevice for VmBusMouseDriver {
    fn initialize(&self) -> bool {
        // Entire mouse initialization consists of ProtocolRequest specifying the protocol version
        // and response to InitialDeviceInfo (which will be sent at ISR)
        let protocol_request = VmBusMouseProtocolRequestPacket {
            header: VmBusMousePacketHeader::with_packet_type_and_length(
                VmBusMousePacketType::ProtocolRequest,
                (size_of::<VmBusMouseProtocolRequestPacket>() - size_of::<VmBusMousePacketHeader>())
                    as u32,
            ),
            requested_version: VmBusMouseProtocolVersion::Version2,
        };

        self.send_packet(&protocol_request);

        true
    }

    fn has_data_to_process(&self) -> bool {
        self.channel.has_data_to_process()
    }

    fn process_incoming_data(&self) {
        self.channel.disable_interrupts();

        loop {
            let packet = self.channel.read();
            if packet.is_none() {
                break;
            }

            let packet = packet.unwrap();
            let data = packet.data.as_ptr();

            let pipe_hdr = data as *const _ as *const VmBusPipeHeader;
            let mouse_packet =
                unsafe { *(pipe_hdr.add(1) as *const _ as *const VmBusMousePacketHeader) };
            let mouse_packet_type = mouse_packet.packet_type;

            match mouse_packet_type {
                VmBusMousePacketType::ProtocolResponse => {
                    let protocol_response = unsafe {
                        *(pipe_hdr.add(1) as *const _ as *const VmBusMouseProtocolResponsePacket)
                    };

                    // 1 means success, in case of any failure (unlikely) panic
                    assert_eq!(protocol_response.status, 1);
                }
                VmBusMousePacketType::InitialDeviceInfo => {
                    let _device_info = unsafe {
                        *(pipe_hdr.add(1) as *const _ as *const VmBusMouseInitialDeviceInfoPacket)
                    };

                    // InitialDeviceInfo does not contain any useful information for us right now,
                    // so send an Ack packet and complete mouse initialization process.
                    let ack = VmBusMouseInitialDeviceInfoAckPacket {
                        header: VmBusMousePacketHeader::with_packet_type_and_length(
                            VmBusMousePacketType::InitialDeviceInfoAck,
                            (size_of::<VmBusMouseInitialDeviceInfoAckPacket>()
                                - size_of::<VmBusMousePacketHeader>())
                                as u32,
                        ),
                        reserved: 0,
                    };

                    self.send_packet(&ack);
                }
                VmBusMousePacketType::InputReport => {
                    let report = unsafe {
                        *(pipe_hdr.add(1) as *const _ as *const VmBusMouseInputReportPacket)
                    };

                    // @TODO: Pass it to other drivers for further processing.
                    debug!("Mouse: {report:?}");
                }
                _ => unreachable!(),
            }
        }

        self.channel.enable_interrupts();
    }
}

impl VmBusMouseDriver {
    fn send_packet<T>(&self, packet: &T) {
        let pipe_header_len = size_of::<VmBusPipeHeader>();
        let pipe = VmBusPipeHeader {
            message_type: VmBusPipeMessageType::Data,
            size: size_of::<T>() as u32,
        };

        let buffer_len = pipe_header_len + size_of::<T>();

        let mut buffer = vec![0u8; buffer_len];
        let buffer_ptr = buffer.as_mut_ptr();
        unsafe {
            ptr::copy(&pipe as *const _ as *const u8, buffer_ptr, pipe_header_len);
            ptr::copy(
                packet as *const _ as *const u8,
                buffer_ptr.add(pipe_header_len),
                size_of::<T>(),
            );
        }

        self.channel.send_packet(
            buffer_ptr as *const u8,
            buffer_len,
            1,
            true,
            VmBusPacketType::DataInband,
        );
    }
}
