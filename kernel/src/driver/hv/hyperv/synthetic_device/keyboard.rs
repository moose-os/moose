//! # Hyper-V Synthetic Keyboard Protocol
//!
//! This driver implements the Hyper-V synthetic keyboard protocol over VMBus,
//! allowing a guest operating system to receive keyboard input from the host
//! without emulating a PS/2 controller.
//!
//! ---
//!
//! ## Overview
//!
//! The Hyper-V keyboard device is exposed as a VMBus channel identified by its GUID
//! (`HYPERV_KEYBOARD_GUID`).
//! Communication occurs through keyboard protocol messages, which are exchanged
//! between the guest and host to negotiate protocol versions and deliver keyboard events.
//!
//! ---
//!
//! ## Protocol Flow
//!
//! ```text
//!   Guest                                Host
//!    │                                    │
//!    │ -- ProtocolRequest --------------> │
//!    │    (Version1 = 0x10000)            │
//!    │                                    │
//!    │ <------------- ProtocolResponse -- │
//!    │            (Status = OK)           │
//!    │                                    │
//!    │ <---- Event (KeyDown: 'A') ------- │
//!    │                                    │
//!    │ <---- Event (KeyUp: 'A') --------- │
//!    │                                    │
//!    │ <---- Event (KeyDown: 'B') ------- │
//!    │                                    │
//!    │ <---- Event (KeyUp: 'B') --------- │
//!    │                                    │
//!    │ <---- Event (KeyDown: 'C') ------- │
//!    │                                    │
//!    │ <---- Event (KeyUp: 'C') --------- │
//! ```
//!
//! ---
//!
//! ## Message Types
//!
//! Messages are prefixed with a [`KeyboardMessageHeader`] containing
//! a [`KeyboardMessageType`]:
//!
//! - `ProtocolRequest` (1)
//!   Guest requests the supported keyboard protocol version.
//! - `ProtocolResponse` (2)
//!   Host responds with status (success/failure).
//! - `Event` (3)
//!   Host sends a key press or release event (`scancode` + `flags`).
//!
//! ---
//!
//! ## Flags
//!
//! The `flags` field in [`KeyboardEvent`] describes additional key event attributes:
//!
//! | Bit | Meaning                                      |
//! |-----|----------------------------------------------|
//! | 0   | Unicode (set if event contains Unicode char) |
//! | 1   | Break (key release)                          |
//! | 2   | E0 prefix (extended scan code)               |
//! | 3   | E1 prefix (extended scan code)               |
//!
//! ---
//!
use phf::phf_map;

use crate::driver::hv::hyperv::{
    VmBusOfferChannel, VmBusPacketType, channel::VmBusChannel,
    synthetic_device::VmBusSyntheticDevice,
};

const KEYBOARD_BASE_XID: u64 = 0xC0C0A0000;

pub struct VmBusKeyboard {
    channel: VmBusChannel,
    offer: VmBusOfferChannel,
}

/// Represents the different message types exchanged over the Hyper-V synthetic keyboard channel.
///
/// These messages define the communication protocol between the guest and host
/// for keyboard input and LED state management.
#[repr(u32)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum KeyboardMessageType {
    /// Guest requests protocol version negotiation.
    ProtocolRequest = 1,

    /// Host responds with supported protocol version.
    ProtocolResponse = 2,

    /// Host sends keyboard input events (key press/release).
    Event = 3,

    /// Guest sets keyboard LED indicators (e.g., Num Lock, Caps Lock, Scroll Lock).
    LedIndicators = 4,
}

/// Header structure for messages sent over the Hyper-V synthetic keyboard channel.
///
/// This header precedes all keyboard protocol messages and identifies the
/// specific [`KeyboardMessageType`] being transmitted.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[repr(C, packed)]
struct KeyboardMessageHeader {
    message_type: KeyboardMessageType,
}

impl KeyboardMessageHeader {
    pub fn with_message_type(message_type: KeyboardMessageType) -> KeyboardMessageHeader {
        KeyboardMessageHeader { message_type }
    }
}

/// Supported protocol versions for the Hyper-V synthetic keyboard device.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[repr(u32)]
enum KeyboardProtocolVersion {
    /// Initial protocol version for the synthetic keyboard (0x10000).
    Version1 = 0x10_000,
}

/// Request message sent by the guest to negotiate the keyboard protocol version.
///
/// This message is sent after the VMBus channel for the synthetic keyboard is opened.
/// The guest specifies the desired `KeyboardProtocolVersion`, and the host will reply
/// with a `ProtocolResponse` indicating acceptance or rejection.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[repr(C, packed)]
struct KeyboardProtocolRequest {
    /// Common keyboard message header containing the message type.
    header: KeyboardMessageHeader,

    /// The protocol version the guest is requesting to use.
    requested_protocol_version: KeyboardProtocolVersion,
}

/// Response message sent by the host to indicate the result of a keyboard
/// protocol version negotiation.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[repr(C, packed)]
struct KeyboardProtocolResponse {
    /// Common keyboard message header containing the message type.
    header: KeyboardMessageHeader,

    /// Negotiation status:
    /// `0` = success (protocol version accepted)
    /// nonzero = failure (protocol version not supported).
    status: u32,
}

/// Represents a keyboard input event sent over the VMBus keyboard channel.
///
/// The `flags` field uses a bitfield to indicate details about the key:
/// * Bit 0 (`0x01`) - **Unicode**: If set, the `code` field represents a Unicode character.
/// * Bit 1 (`0x02`) - **Break**: If set, this is a key release (break); otherwise, it is a key press (make).
/// * Bit 2 (`0x04`) - **E0**: Indicates an E0 extended scan code.
/// * Bit 3 (`0x08`) - **E1**: Indicates an E1 extended scan code.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[repr(C, packed)]
struct KeyboardEvent {
    /// Common keyboard message header containing the message type.
    header: KeyboardMessageHeader,

    /// Keyboard scan code.
    code: u16,

    /// Reserved (should be 0).
    reserved: u16,

    /// Bitfield describing key event details (Unicode, Break, E0, E1).
    flags: u32,
}

/// Maps keyboard scancodes to their corresponding ASCII characters.
static SCANCODE_MAP: phf::Map<u8, char> = phf_map! {
    0x01u8 => '\u{001B}', // Escape
    0x02u8 => '1',
    0x03u8 => '2',
    0x04u8 => '3',
    0x05u8 => '4',
    0x06u8 => '5',
    0x07u8 => '6',
    0x08u8 => '7',
    0x09u8 => '8',
    0x0Au8 => '9',
    0x0Bu8 => '0',
    0x0Cu8 => '-',
    0x0Du8 => '=',
    0x0Eu8 => '\u{0008}', // Backspace
    0x0Fu8 => '\u{0009}', // Tab
    0x10u8 => 'q',
    0x11u8 => 'w',
    0x12u8 => 'e',
    0x13u8 => 'r',
    0x14u8 => 't',
    0x15u8 => 'y',
    0x16u8 => 'u',
    0x17u8 => 'i',
    0x18u8 => 'o',
    0x19u8 => 'p',
    0x1Au8 => '[',
    0x1Bu8 => ']',
    0x1Cu8 => '\u{000D}', // Enter
    0x1Du8 => '\u{001D}', // Left Control
    0x1Eu8 => 'a',
    0x1Fu8 => 's',
    0x20u8 => 'd',
    0x21u8 => 'f',
    0x22u8 => 'g',
    0x23u8 => 'h',
    0x24u8 => 'j',
    0x25u8 => 'k',
    0x26u8 => 'l',
    0x27u8 => ';',
    0x28u8 => '\'',
    0x29u8 => '`',
    0x2Au8 => '\u{002A}', // Left Shift
    0x2Bu8 => '\\',
    0x2Cu8 => 'z',
    0x2Du8 => 'x',
    0x2Eu8 => 'c',
    0x2Fu8 => 'v',
    0x30u8 => 'b',
    0x31u8 => 'n',
    0x32u8 => 'm',
    0x33u8 => ',',
    0x34u8 => '.',
    0x35u8 => '/',
    0x36u8 => '\u{002A}', // Right Shift (using same symbol)
    0x37u8 => '\u{002A}', // Numpad *
    0x38u8 => '\u{0018}', // Left Alt
    0x39u8 => ' ',
};

impl VmBusKeyboard {
    pub fn new(channel: VmBusChannel, offer: VmBusOfferChannel) -> Self {
        Self { channel, offer }
    }
}

impl VmBusSyntheticDevice for VmBusKeyboard {
    fn initialize(&self) -> bool {
        // Keyboard initialization is as simple, as sending one packet with protocol version.
        let init = KeyboardProtocolRequest {
            header: KeyboardMessageHeader::with_message_type(KeyboardMessageType::ProtocolRequest),
            requested_protocol_version: KeyboardProtocolVersion::Version1,
        };

        self.channel.send_packet(
            &init as *const _ as *const u8,
            size_of::<KeyboardProtocolRequest>(),
            KEYBOARD_BASE_XID,
            true,
            VmBusPacketType::DataInband,
        );

        true
    }

    fn has_data_to_process(&self) -> bool {
        self.channel.has_data_to_process()
    }

    fn process_incoming_data(&self) {
        // Disable interrupts for now, because we are draining the queue
        self.channel.disable_interrupts();

        while let Some(packet) = self.channel.read() {
            let data = packet.data.as_ptr();
            let kbd_hdr = unsafe { *(data as *const KeyboardMessageHeader) };
            let message_type = kbd_hdr.message_type;

            match message_type {
                KeyboardMessageType::ProtocolResponse => {
                    let kbd_pkt = unsafe { *(data as *const KeyboardProtocolResponse) };
                    let status = kbd_pkt.status;

                    assert_eq!(status, 1);
                }
                KeyboardMessageType::Event => {
                    let kbd_pkt = unsafe { *(data as *const KeyboardEvent) };

                    let chr = SCANCODE_MAP.get(&(kbd_pkt.code as u8)).unwrap_or(&'X');
                    let _is_unicode = (kbd_pkt.flags & 1) != 0;
                    let is_break = (kbd_pkt.flags & 2) != 0;
                    let _is_e0 = (kbd_pkt.flags & 4) != 0;
                    let _is_e1 = (kbd_pkt.flags & 8) != 0;
                    let _code = kbd_pkt.code;

                    log::debug!("Keyboard event: char={chr}, break={is_break}");
                }
                _ => unreachable!(),
            }
        }

        // No more data available, enable interrupts for future packets.
        self.channel.enable_interrupts();
    }
}
