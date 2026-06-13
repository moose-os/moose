//! # Hyper-V Key-Value Pair (KVP) Integration Component
//!
//! ## Overview
//!
//! The KVP IC service provides a bidirectional key-value store shared between
//! the Hyper-V host and the guest VM.  It is used to exchange metadata such as
//! network configuration, OS version strings, and custom application data.
//!
//! ## Key and Value Encoding
//!
//! Both keys and values are UTF-16LE encoded and zero-padded to fixed-size
//! buffers.

use alloc::{fmt, string::String, vec::Vec};
use spin::rwlock::RwLock;

use crate::driver::hv::hyperv::{
    VmBusOfferChannel, VmBusPacketHeader, VmBusPacketType,
    channel::VmBusChannel,
    synthetic_device::{
        VmBusSyntheticDevice,
        integration::{
            IcVersionSet, UtilMessageHeader, UtilMessageType, UtilVersion, decode_utf16_buf,
            encode_utf16le, mark_as_response, negotiate_versions,
        },
    },
};

/// Maximum size of a KVP key in bytes (256 UTF-16LE code units).
pub const KVP_MAX_KEY_SIZE: usize = 512;

/// Maximum size of a KVP value in bytes (1024 UTF-16LE code units).
pub const KVP_MAX_VALUE_SIZE: usize = 2048;

/// Maximum number of entries per logical store.
const KVP_STORE_CAPACITY: usize = 256;

const KVP_VERSION1_0: UtilVersion = UtilVersion::new(1, 0);
const KVP_VERSION3_0: UtilVersion = UtilVersion::new(3, 0);
const KVP_VERSION4_0: UtilVersion = UtilVersion::new(4, 0);

const KVP_VERSIONS: IcVersionSet = &[KVP_VERSION4_0, KVP_VERSION3_0, KVP_VERSION1_0];

/// A single entry in the KVP store.
#[derive(Debug, Clone)]
pub struct KvpEntry {
    pub key: String,
    pub value: KvpValue,
}

/// Typed KVP value decoded from the wire representation.
#[derive(Debug, Clone)]
pub enum KvpValue {
    String(String),
    U32(u32),
    U64(u64),
}

impl fmt::Display for KvpValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KvpValue::String(s) => f.write_str(s),
            KvpValue::U32(v) => write!(f, "{}", v),
            KvpValue::U64(v) => write!(f, "{}", v),
        }
    }
}

/// Simple linear in-place key-value store.
pub struct KvpStore {
    entries: Vec<KvpEntry>,
}

impl KvpStore {
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Insert or overwrite `key`.  Returns `true` if a new entry was created.
    pub fn set(&mut self, key: String, value: KvpValue) -> bool {
        if let Some(e) = self.entries.iter_mut().find(|e| e.key == key) {
            e.value = value;
            return false;
        }

        if self.entries.len() >= KVP_STORE_CAPACITY {
            return false;
        }

        self.entries.push(KvpEntry { key, value });

        true
    }

    /// Return a reference to the entry for `key`, if present.
    pub fn get(&self, key: &str) -> Option<&KvpEntry> {
        self.entries.iter().find(|e| e.key == key)
    }

    /// Return the entry at `index`, used for host-driven enumeration.
    pub fn get_at(&self, index: usize) -> Option<&KvpEntry> {
        self.entries.get(index)
    }

    /// Remove the entry for `key`.  Returns `true` if something was removed.
    /// Uses `swap_remove` for O(1) deletion (order is not guaranteed).
    pub fn delete(&mut self, key: &str) -> bool {
        match self.entries.iter().position(|e| e.key == key) {
            Some(pos) => {
                self.entries.swap_remove(pos);

                true
            }
            None => false,
        }
    }

    /// Number of entries currently held.
    pub fn len(&self) -> usize {
        self.entries.len()
    }
}

/// Represents the type of operation to be performed on the Key-Value Pair (KVP) store.
#[repr(u8)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum KvpOperation {
    /// Retrieve a value associated with a specific key.
    Get = 0,

    /// Insert or update a key-value pair in the store.
    Set = 1,

    /// Remove a key-value pair from the store.
    Delete = 2,

    /// List all key-value pairs currently in the store.
    Enumerate = 3,

    /// Query networking and IP configuration information from the guest.
    GetIpInfo = 4,

    /// Configure or update networking and IP information for the guest.
    SetIpInfo = 5,
}

/// Identifies the specific Key-Value Pair (KVP) registry store or pool to target.
#[repr(u8)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum KvpStoreId {
    External = 0,
    Guest = 1,
    Auto = 2,
    AutoExternal = 3,
    AutoInternal = 4,
}

/// Defines the underlying data type of a value stored in the Key-Value Pair (KVP) system.
#[repr(u32)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum KvpValueType {
    /// A null-terminated UTF-16LE string value.
    String = 1,

    /// A 32-bit unsigned integer value.
    U32 = 4,

    /// A 64-bit unsigned integer value.
    U64 = 8,
}

/// Wire payload for `KvpExchange`, immediately following `UtilMessageHeader`.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
struct KvpExchangeMessage {
    /// The specific operation being requested or responded to.
    operation: KvpOperation,

    /// The target KVP registry pool/store configuration to apply this operation to.
    store: KvpStoreId,

    /// Padding.
    padding: u16,

    /// The data type of the data contained within the `value` buffer.
    value_type: KvpValueType,

    /// The actual length of the key string in bytes, excluding null terminators.
    /// Must not exceed [`KVP_MAX_KEY_SIZE`].
    key_size: u32,

    /// The actual length of the value data in bytes.
    /// Must not exceed [`KVP_MAX_VALUE_SIZE`].
    value_size: u32,

    /// A fixed-size raw byte buffer containing the key string.
    /// Only the first `key_size` bytes are considered valid data.
    key: [u8; KVP_MAX_KEY_SIZE],

    /// A fixed-size raw byte buffer containing the value payload.
    /// Only the first `value_size` bytes are considered valid data.
    value: [u8; KVP_MAX_VALUE_SIZE],
}

impl KvpExchangeMessage {
    fn decode_key(&self) -> String {
        decode_utf16_buf(&self.key[..self.key_size as usize])
    }

    fn decode_value(&self) -> KvpValue {
        let len = self.value_size as usize;
        match self.value_type {
            KvpValueType::String => KvpValue::String(decode_utf16_buf(&self.value[..len])),
            KvpValueType::U32 => {
                assert!(len >= 4, "U32 KVP value truncated");
                KvpValue::U32(u32::from_le_bytes(self.value[..4].try_into().unwrap()))
            }
            KvpValueType::U64 => {
                assert!(len >= 8, "U64 KVP value truncated");
                KvpValue::U64(u64::from_le_bytes(self.value[..8].try_into().unwrap()))
            }
        }
    }

    fn encode_key(&mut self, s: &str) {
        self.key_size = encode_utf16le(s, &mut self.key) as u32;
    }

    fn encode_value(&mut self, v: &KvpValue) {
        match v {
            KvpValue::String(s) => {
                self.value_size = encode_utf16le(s, &mut self.value) as u32;
                self.value_type = KvpValueType::String;
            }
            KvpValue::U32(n) => {
                self.value[..4].copy_from_slice(&n.to_le_bytes());
                self.value_size = 4;
                self.value_type = KvpValueType::U32;
            }
            KvpValue::U64(n) => {
                self.value[..8].copy_from_slice(&n.to_le_bytes());
                self.value_size = 8;
                self.value_type = KvpValueType::U64;
            }
        }
    }

    fn clear_payload(&mut self) {
        self.key = [0u8; KVP_MAX_KEY_SIZE];
        self.key_size = 0;
        self.value = [0u8; KVP_MAX_VALUE_SIZE];
        self.value_size = 0;
    }
}

/// Hyper-V KVP Integration Component device.
pub struct VmBusKvpService {
    /// Channel used by the service for communication with the host.
    pub(crate) channel: VmBusChannel,

    /// Offer sent by VMBus.
    offer: VmBusOfferChannel,

    /// External store.
    store_external: RwLock<KvpStore>,

    /// Guest store.
    store_guest: RwLock<KvpStore>,
}

impl VmBusKvpService {
    pub fn new(channel: VmBusChannel, offer: VmBusOfferChannel) -> Self {
        Self {
            channel,
            offer,
            store_external: RwLock::new(KvpStore::new()),
            store_guest: RwLock::new(KvpStore::new()),
        }
    }
}

impl VmBusSyntheticDevice for VmBusKvpService {
    fn initialize(&self) -> bool {
        true
    }

    fn has_data_to_process(&self) -> bool {
        self.channel.has_data_to_process()
    }

    fn process_incoming_data(&self) {
        self.channel.disable_interrupts();

        while let Some(packet) = self.channel.read() {
            let data_ptr = packet.data.as_ptr() as *mut u8;

            let util_hdr = unsafe { *(data_ptr as *const UtilMessageHeader) };

            let xid = match packet.header {
                VmBusPacketHeader::Packet(h) => h.xid,
                VmBusPacketHeader::Xfer(h) => h.header.xid,
            };

            match util_hdr.message_type {
                UtilMessageType::NegotiateProtocol => {
                    negotiate_versions(data_ptr, KVP_VERSIONS);
                }

                UtilMessageType::KvpExchange => {
                    let kvp_ptr = unsafe {
                        data_ptr.add(size_of::<UtilMessageHeader>()) as *mut KvpExchangeMessage
                    };
                    let mut msg: KvpExchangeMessage = unsafe { kvp_ptr.read_unaligned() };

                    match msg.operation {
                        KvpOperation::Set => {
                            let key = msg.decode_key();
                            let value = msg.decode_value();
                            debug!(
                                "kvp: Set store={:?} key='{}' value='{}'",
                                msg.store, key, value
                            );

                            match msg.store {
                                KvpStoreId::Guest => self.store_guest.write().set(key, value),
                                _ => self.store_external.write().set(key, value),
                            };
                        }

                        KvpOperation::Get => {
                            let key = msg.decode_key();
                            debug!("kvp: Get store={:?} key='{}'", msg.store, key);

                            let found: Option<KvpValue> = match msg.store {
                                KvpStoreId::Guest => {
                                    self.store_guest.read().get(&key).map(|e| e.value.clone())
                                }
                                _ => self
                                    .store_external
                                    .read()
                                    .get(&key)
                                    .map(|e| e.value.clone()),
                            };

                            match found {
                                Some(ref v) => {
                                    msg.encode_value(v);
                                }
                                None => {
                                    msg.value_size = 0;
                                    msg.value = [0u8; KVP_MAX_VALUE_SIZE];
                                }
                            }
                        }

                        KvpOperation::Delete => {
                            let key = msg.decode_key();
                            let removed = match msg.store {
                                KvpStoreId::Guest => self.store_guest.write().delete(&key),
                                _ => self.store_external.write().delete(&key),
                            };
                            debug!(
                                "kvp: Delete store={:?} key='{}' removed={}",
                                msg.store, key, removed
                            );
                        }

                        unknown => unreachable!("Unknown KVP operation {:?}", unknown),
                    }
                }

                unknown => unreachable!("Unknown KVP message type {:?}", unknown),
            }

            mark_as_response(data_ptr);

            self.channel.send_packet(
                packet.data.as_ptr(),
                packet.data.len(),
                xid,
                false,
                VmBusPacketType::DataInband,
            );
        }

        self.channel.enable_interrupts();
    }
}
