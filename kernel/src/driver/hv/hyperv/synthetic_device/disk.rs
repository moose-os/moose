//! Hyper-V Storage VSC — StorVSC driver.
//!
//! Implements the VMBus storage driver, which exposes virtual
//! SCSI disks provided by the Hyper-V host to this guest.
//!
//! # Protocol flow
//!
//! ```text
//! Guest (VSC)                                        Host (VSP)
//!  |                                                      |
//!  |── BEGIN_INITIALIZATION ──────────────────────────►   |
//!  |◄─ COMPLETE_IO (ack) ────────────────────────────     |
//!  |                                                      |
//!  |── QUERY_PROTOCOL_VERSION (ver=6.0) ──────────────►   |
//!  |◄─ COMPLETE_IO (status=0 → accepted) ────────────     |
//!  |                                                      |
//!  |── QUERY_PROPERTIES ──────────────────────────────►   |
//!  |◄─ COMPLETE_IO (max_transfer_bytes, ...) ─────────     |
//!  |                                                      |
//!  |── END_INITIALIZATION ────────────────────────────►   |
//!  |◄─ COMPLETE_IO (ack) ────────────────────────────     |
//!  |                                                      |
//!  |── EXECUTE_SRB (READ/WRITE/FLUSH/...) ───────────►    |
//!  |◄─ COMPLETE_IO (srb_status, scsi_status, data) ──     |
//!  |                   ...                                |
//! ```
//!
//! # SCSI commands issued
//!
//! | Operation        | CDB opcode | Notes                                    |
//! |------------------|------------|------------------------------------------|
//! | Read sectors     | `0x28`     | READ(10) — up to 65535 sectors per call  |
//! | Write sectors    | `0x2A`     | WRITE(10) — up to 65535 sectors per call |
//! | Flush cache      | `0x35`     | SYNCHRONIZE CACHE(10)                    |
//! | Read capacity    | `0x25`     | READ CAPACITY(10) — returns sector count |
//!
//! For transfers larger than [`MAX_SECTORS_PER_REQUEST`] the public API
//! automatically splits the I/O into multiple sequential SRBs.
//!
//! # Per-request gates
//!
//! Every in-flight SRB gets its own [`OneshotGate`] stored in
//! [`PendingRequest`]. The ISR looks up the gate by `request_id` in a
//! [`BTreeMap`] and opens it; the submitting thread blocks only on its own
//! gate, so multiple callers can issue concurrent I/Os without interfering
//! with each other.
//!
//! # References
//! - Linux kernel: `drivers/scsi/storvsc_drv.c`
//! - Hyper-V TLFS (Top-Level Functional Specification)

use core::{
    mem::size_of,
    ptr,
    sync::atomic::{AtomicU64, Ordering},
};

use alloc::{collections::BTreeMap, sync::Arc, vec::Vec};
use spin::RwLock;
use x86_64::instructions::interrupts::without_interrupts;

use crate::{
    driver::hv::hyperv::{
        HYPERV_PAGE_SIZE, VmBusGpaDirectHeader, VmBusOfferChannel, VmBusPacketHeader,
        VmBusPacketType, channel::VmBusChannel, synthetic_device::VmBusSyntheticDevice,
    },
    subsystem::scheduler::OneshotGate,
};

/// Major version of the storvsc protocol.
const STORVSC_PROTOCOL_VERSION_MAJOR: u16 = 6;

/// Minor version of the storvsc protocol.
const STORVSC_PROTOCOL_VERSION_MINOR: u16 = 2;

/// Combined `(major << 8) | minor` version word sent during negotiation.
const STORVSC_PROTOCOL_VERSION: u16 =
    ((STORVSC_PROTOCOL_VERSION_MAJOR) << 8) | STORVSC_PROTOCOL_VERSION_MINOR;

/// Maximum number of simultaneously in-flight I/O requests.
///
/// The host will reject SRBs beyond this limit. Matches the Linux storvsc
/// default (`STORVSC_MAX_IO_REQUESTS`).
const STORVSC_MAX_IO_REQUESTS: usize = 128;

/// Logical sector size for READ(10) / WRITE(10) address calculations.
pub const SECTOR_SIZE: usize = 512;

/// Maximum sectors per single READ(10) / WRITE(10) CDB, limited by the
/// 16-bit transfer-length field.
pub const MAX_SECTORS_PER_REQUEST: u32 = 0xFFFF;

/// VMBus per-packet framing overhead in bytes (descriptor + padding).
const VMBUS_PKT_OVERHEAD: usize = 16;

/// Usable capacity of the VMBus ring buffer in bytes.
const STORVSC_RING_BUFFER_SIZE: usize = 2 * 4096;

/// Number of retries attempted when the device returns
/// [`ScsiStatus::Busy`] before giving up with [`StorVscError::DeviceBusy`].
const STORVSC_BUSY_RETRY_COUNT: usize = 16;

/// Host expects a completion reply for this packet (`REQUEST_COMPLETION_FLAG`).
const REQUEST_COMPLETION_FLAG: u32 = 1;

/// SCSI SRB status: command completed successfully (`SRB_STATUS_SUCCESS`).
const SRB_STATUS_SUCCESS: u8 = 0x01;

/// SRB flag bits — see Linux `storvsc_drv.c`.
const SRB_FLAGS_DISABLE_SYNCH_TRANSFER: u32 = 0x0000_0008;
const SRB_FLAGS_DATA_IN: u32 = 0x0000_0040;
const SRB_FLAGS_DATA_OUT: u32 = 0x0000_0080;
const SRB_FLAGS_NO_DATA_TRANSFER: u32 = 0;

/// Untagged queue slot (`SP_UNTAGGED`).
const SRB_QUEUE_TAG_UNTAGGED: u8 = 0xFF;

/// Simple tagged queue action (`SRB_SIMPLE_TAG_REQUEST`).
const SRB_SIMPLE_TAG_REQUEST: u8 = 0x20;

/// Message types exchanged between the VSC and VSP.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(u32)]
pub enum StorVscMessageType {
    /// Complete request issued previously by [`ExecuteSrb`].
    CompleteIo = 1,

    RemoveDevice = 2,

    /// Submit SRB block for execution.
    ExecuteSrb = 3,

    ResetLun = 4,
    ResetAdapter = 5,
    ResetBus = 6,

    /// Open the channel and start version negotiation.
    BeginInitialization = 7,

    /// End of initialization; the host will now accept EXECUTE_SRB packets.
    EndInitialization = 8,

    /// Propose a protocol version.
    QueryProtocolVersion = 9,

    /// Request host adapter properties.
    QueryProperties = 10,

    EnumerateBus = 11,
    FchbaData = 12,
}

/// Common header prepended to every message.
#[derive(Debug, Copy, Clone)]
#[repr(C, packed)]
pub struct StorVscMessageHeader {
    /// Type of message being sent.
    message_type: StorVscMessageType,

    /// Flags.
    flags: u32,

    /// Status returned from Hyper-V. 0 means success.
    status: u32,
}

impl StorVscMessageHeader {
    pub(crate) fn with_message_type(message_type: StorVscMessageType) -> Self {
        Self {
            message_type,
            flags: 1,
            status: 0,
        }
    }
}

/// Full StorVsc packet: 12-byte header + 52-byte payload union = 64 bytes.
#[derive(Copy, Clone)]
#[repr(C, packed)]
pub struct StorVscPacket {
    /// Standard message header.
    pub header: StorVscMessageHeader,

    /// Actual message being sent.
    pub msg: StorVscMessage,
}

/// QUERY_PROTOCOL_VERSION packet.
///
/// The VSC proposes `(MAJOR << 8) | MINOR`; the host replies with
/// `header.status == 0` if the version is acceptable or non-zero to refuse.
#[derive(Debug, Copy, Clone)]
#[repr(C, packed)]
pub struct StorVscQueryProtocolVersion {
    /// Proposed version word: `(major << 8) | minor`.
    version: u16,

    /// Revision number; mismatch does not indicate incompatibility — used by
    /// Windows only to signal mismatched builds.
    revision: u16,
}

/// QUERY_PROPERTIES request payload.
///
/// Sent with zeroed fields; the host fills in the response in the
/// corresponding `CompleteIo`.
#[derive(Debug, Copy, Clone)]
#[repr(C, packed)]
pub struct StorVscQueryProperties {
    /// Reseved.
    reserved: u32,

    /// Max subchannel count for this channel. Not used currently.
    max_channel_count: u16,

    /// Reserved.
    reserved2: u16,

    /// Flags.
    flags: u32,

    /// Maximum data payload accepted by the host in a single EXECUTE_SRB.
    max_transfer_bytes: u32,
}

/// Union of all protocol message variants.
///
/// Sized to exactly 52 bytes (0x34) so that the full [`StorVscPacket`] is
/// 64 bytes on the wire.
#[derive(Copy, Clone)]
#[repr(C)]
pub union StorVscMessage {
    // Initialization messages (no payload beyond the header).
    _begin_init: (),
    _end_init: (),

    // Negotiation / capability discovery.
    pub query_version: StorVscQueryProtocolVersion,
    pub query_properties: StorVscQueryProperties,

    // I/O path.
    pub execute_srb: StorVscExecuteSrb,

    /// Raw padding that fixes the union size at exactly 52 bytes, ensuring a
    /// stable 64-byte wire packet regardless of which variant is active.
    pub raw_padding: [u8; 0x34],
}

/// Size of the SCSI CDB field in [`StorVscExecuteSrb`].
///
/// READ(10), WRITE(10), SYNCHRONIZE CACHE(10), and READ CAPACITY(10) all fit
/// in 10 bytes; the remaining bytes are zero-padded to match the ABI.
const STORVSC_CDB_SIZE: usize = 16;

/// Maximum bytes of SCSI sense data the host may return on CHECK CONDITION.
const STORVSC_SENSE_BUFFER_SIZE: usize = 20;

/// Data-transfer direction as seen by the SCSI initiator (this guest).
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(u8)]
enum StorVscDataDirection {
    /// No data transfer (e.g. SYNCHRONIZE CACHE).
    None = 0,

    /// Device to guest (READ).
    Read = 1,

    /// Guest to device (WRITE).
    Write = 2,
}

/// EXECUTE_SRB request — submits a single SCSI command to the host.
///
/// `data` holds the 16-byte CDB. The data buffer itself is described via
/// GPA Direct (see [`VmBusGpaDirectHeader`]); the host DMA-copies the payload
/// directly from/to the supplied guest-physical page(s).
#[derive(Debug, Copy, Clone)]
#[repr(C, packed)]
pub struct StorVscExecuteSrb {
    length: u16,
    srb_status: u8,
    scsi_status: u8,

    port_number: u8,
    path_id: u8,
    target_id: u8,
    lun: u8,

    cdb_length: u8,
    sense_info_length: u8,

    /// Direction flag: 0 = write, 1 = read, 2 = none.
    data_in: u8,
    reserved: u8,

    data_transfer_length: u32,

    /// Holds the CDB (up to [`STORVSC_CDB_SIZE`] bytes) for outgoing SRBs;
    /// the host writes sense data here on `CHECK CONDITION`.
    data: [u8; 0x14],

    reserve: u16,
    queue_tag: u8,
    queue_action: u8,
    srb_flags: u32,
    time_out_value: u32,
    queue_sort_ey: u32,
}

/// SCSI status bytes returned in the `scsi_status` field of a completed SRB.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(u8)]
pub enum ScsiStatus {
    /// Command completed successfully.
    Good = 0x00,

    /// Command completed with a condition; inspect sense data for details.
    CheckCondition = 0x02,

    /// Device is temporarily busy; the command should be retried.
    Busy = 0x08,
}

/// Parameter data returned by READ CAPACITY(16).
#[derive(Debug, Copy, Clone)]
#[repr(C, packed)]
struct ScsiReadCapacity16Response {
    /// LBA of the last logical block (total sectors − 1), big-endian.
    last_lba_be: u64,

    /// Logical block length in bytes, big-endian (typically 512).
    block_length_be: u32,
}

/// Parameter data returned by READ CAPACITY(10).
///
/// The host writes this into the GPA buffer supplied in the SRB.
#[derive(Debug, Copy, Clone)]
#[repr(C, packed)]
struct ScsiReadCapacity10Response {
    /// LBA of the last logical block (total sectors − 1), big-endian.
    last_lba_be: u32,

    /// Logical block length in bytes, big-endian (typically 512).
    block_length_be: u32,
}

/// Maximum LUNs per target that we allocate space for in the REPORT LUNS
/// response buffer.  Hyper-V synthetic SCSI exposes at most 64 LUNs per
/// target.
const STORVSC_MAX_LUNS_PER_TARGET: usize = 64;

/// Allocation length passed in the REPORT LUNS CDB:
/// 8-byte response header + one 8-byte entry per LUN slot.
const REPORT_LUNS_ALLOC_LENGTH: u32 = (8 + STORVSC_MAX_LUNS_PER_TARGET * 8) as u32;

/// REPORT LUNS response: 8-byte header followed by variable-length LUN list.
#[derive(Debug, Copy, Clone)]
#[repr(C, packed)]
struct ScsiReportLunsResponse {
    /// Byte length of the LUN list that follows (excludes this header).
    lun_list_length_be: u32,

    /// Reserved.
    _reserved: u32,

    /// Up to [`STORVSC_MAX_LUNS_PER_TARGET`] eight-byte LUN descriptors.
    /// Only the lower byte of each entry carries the LUN number when the
    /// addressing mode (top two bits) is 0b00 (peripheral device addressing).
    luns: [u64; STORVSC_MAX_LUNS_PER_TARGET],
}

/// Builds a zero-padded 16-byte READ(10) CDB (opcode `0x28`).
///
/// Transfers `sector_count` sectors starting at `lba` from the device into
/// the guest buffer.
///
/// ```text
/// Byte  0    : 0x28  (READ 10)
/// Bytes 2–5  : LBA   (big-endian u32)
/// Bytes 7–8  : transfer length (big-endian u16)
/// All others : 0x00
/// ```
#[inline]
fn build_read10_cdb(lba: u32, sector_count: u16) -> [u8; STORVSC_CDB_SIZE] {
    let mut cdb = [0u8; STORVSC_CDB_SIZE];

    cdb[0] = 0x28;
    cdb[2] = (lba >> 24) as u8;
    cdb[3] = (lba >> 16) as u8;
    cdb[4] = (lba >> 8) as u8;
    cdb[5] = lba as u8;
    cdb[7] = (sector_count >> 8) as u8;
    cdb[8] = sector_count as u8;

    cdb
}

/// Builds a zero-padded 16-byte WRITE(10) CDB (opcode `0x2A`).
///
/// Transfers `sector_count` sectors from the guest buffer to the device
/// starting at `lba`.
///
/// ```text
/// Byte  0    : 0x2A  (WRITE 10)
/// Bytes 2–5  : LBA   (big-endian u32)
/// Bytes 7–8  : transfer length (big-endian u16)
/// All others : 0x00
/// ```
#[inline]
fn build_write10_cdb(lba: u32, sector_count: u16) -> [u8; STORVSC_CDB_SIZE] {
    let mut cdb = [0u8; STORVSC_CDB_SIZE];

    cdb[0] = 0x2A;
    cdb[2] = (lba >> 24) as u8;
    cdb[3] = (lba >> 16) as u8;
    cdb[4] = (lba >> 8) as u8;
    cdb[5] = lba as u8;
    cdb[7] = (sector_count >> 8) as u8;
    cdb[8] = sector_count as u8;

    cdb
}

/// Builds a zero-padded 16-byte SYNCHRONIZE CACHE(10) CDB (opcode `0x35`).
///
/// Flushes the device write-back cache to persistent media.
///
/// ```text
/// Byte  0    : 0x35  (SYNCHRONIZE CACHE 10)
/// All others : 0x00
/// ```
#[inline]
fn build_sync_cache_cdb() -> [u8; STORVSC_CDB_SIZE] {
    let mut cdb = [0u8; STORVSC_CDB_SIZE];

    cdb[0] = 0x35;

    cdb
}

/// Builds a zero-padded 16-byte READ CAPACITY(10) CDB (opcode `0x25`).
///
/// Returns the last LBA and block size from the device.
///
/// ```text
/// Byte  0    : 0x25  (READ CAPACITY 10)
/// All others : 0x00
/// ```
#[inline]
fn build_read_capacity10_cdb() -> [u8; STORVSC_CDB_SIZE] {
    let mut cdb = [0u8; STORVSC_CDB_SIZE];

    cdb[0] = 0x25;

    cdb
}

/// Builds a READ CAPACITY(16) service-action CDB (opcode `0x9E`, SA `0x10`).
///
/// Returns a 64-bit last LBA and block size. Required for accurate capacity
/// on disks larger than 2 TiB and on modern Hyper-V hosts.
#[inline]
fn build_read_capacity16_cdb(alloc_length: u32) -> [u8; STORVSC_CDB_SIZE] {
    let mut cdb = [0u8; STORVSC_CDB_SIZE];

    cdb[0] = 0x9E;
    cdb[1] = 0x10;
    cdb[10] = (alloc_length >> 24) as u8;
    cdb[11] = (alloc_length >> 16) as u8;
    cdb[12] = (alloc_length >> 8) as u8;
    cdb[13] = alloc_length as u8;

    cdb
}

/// Builds a REPORT LUNS(12) CDB (opcode `0xA0`).
///
/// Returns all LUNs accessible via the addressed target.
///
/// ```text
/// Byte  0    : 0xA0  (REPORT LUNS)
/// Byte  2    : 0x00  (select report — all well-known and normal LUNs)
/// Bytes 6–9  : allocation length (big-endian u32)
/// All others : 0x00
/// ```
#[inline]
fn build_report_luns_cdb(alloc_length: u32) -> [u8; STORVSC_CDB_SIZE] {
    let mut cdb = [0u8; STORVSC_CDB_SIZE];

    cdb[0] = 0xA0;
    cdb[2] = 0x00;
    cdb[6] = (alloc_length >> 24) as u8;
    cdb[7] = (alloc_length >> 16) as u8;
    cdb[8] = (alloc_length >> 8) as u8;
    cdb[9] = alloc_length as u8;

    cdb
}

/// Errors returned by the storvsc I/O API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StorVscError {
    /// The driver has not completed initialization.
    NotInitialized,

    /// Protocol version rejected by the host.
    VersionNegotiationFailed,

    /// The packet (SRB + overhead) is too large to fit in the VMBus ring
    /// buffer. Split the I/O into smaller chunks.
    RingBufferFull,

    /// The data buffer size is inconsistent with `sector_count * SECTOR_SIZE`.
    InvalidBufferSize,

    /// The host's miniport layer rejected the SRB before it reached the
    /// device. The inner byte is the raw `srb_status`.
    SrbError(u8),

    /// The device returned a non-`GOOD` SCSI status. The inner values are
    /// `(scsi_status, sense_data_length)`. Retrieve full sense data by
    /// re-issuing a REQUEST SENSE CDB if needed.
    ScsiError(u8, u8),

    /// The device returned [`ScsiStatus::Busy`] on every retry attempt.
    /// The caller may retry the operation after a delay.
    DeviceBusy,
}

/// Identifies a specific SCSI disk on the virtual HBA.
///
/// Hyper-V synthetic storage supports up to 4 targets, each with up to 256
/// LUNs.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct VmBusDisk {
    /// VMBus channel ID of the [`VmBusStorVscDriver`] that owns this disk.
    /// Use [`HyperV::storvsc_for`] to resolve the driver from this handle.
    pub channel_id: u32,

    /// SCSI target identifier (0–3).
    pub target_id: u8,

    /// SCSI Logical Unit Number within the target (0–255).
    pub lun: u8,
}

impl VmBusDisk {
    pub const fn new(channel_id: u32, target_id: u8, lun: u8) -> Self {
        Self {
            channel_id,
            target_id,
            lun,
        }
    }

    /// Disk 0 on the given controller (target 0, LUN 0).
    pub const fn primary(channel_id: u32) -> Self {
        Self::new(channel_id, 0, 0)
    }
}

/// State kept for a single in-flight SRB.
///
/// The submitter allocates one of these before sending the packet; the ISR
/// fills in [`completion`] and opens [`gate`] when the host replies.
pub struct PendingRequest {
    /// Opened by the ISR when the `CompleteIo` for this request arrives.
    gate: Arc<OneshotGate>,

    /// Written by the ISR; read by the submitter after the gate is opened.
    /// `None` until the completion arrives.
    completion: Option<StorVscPacket>,
}

/// Mutable runtime state of [`VmBusStorVscDriver`].
pub struct VmBusStorVscDriverState {
    /// `true` after the four-step initialization handshake has succeeded.
    pub initialized: bool,

    /// Gate used exclusively during the blocking initialization steps.
    ///
    /// After `initialized` becomes `true` this gate is no longer used;
    /// per-request gates in [`pending`] are used instead.
    pub init_gate: Arc<OneshotGate>,

    /// Packet captured by the ISR during each initialization step.
    pub init_data: RwLock<StorVscPacket>,

    /// Monotonically increasing counter used as both the VMBus transaction ID
    /// and the `request_id` cookie in [`StorVscExecuteSrb`].
    pub next_xid: AtomicU64,

    /// Maximum data payload accepted by the host in a single EXECUTE_SRB.
    /// Populated from the QUERY_PROPERTIES reply during initialization.
    pub max_transfer_bytes: u32,

    /// In-flight requests keyed by their `request_id`.
    ///
    /// Entries are inserted before the packet is sent and removed after the
    /// gate is opened and the completion has been consumed by the submitter.
    pub pending: BTreeMap<u64, PendingRequest>,
}

/// Hyper-V Storage VSC driver (storvsc).
///
/// Exposes virtual SCSI disks provided by the Hyper-V host as a sector-
/// addressed block device.
///
/// | Method              | SCSI command        |
/// |---------------------|---------------------|
/// | [`read_sectors`]    | READ(10)             |
/// | [`write_sectors`]   | WRITE(10)            |
/// | [`flush`]           | SYNCHRONIZE CACHE    |
/// | [`read_capacity`]   | READ CAPACITY(10/16) |
pub struct VmBusStorVscDriver {
    /// VMBus ring-buffer channel to the host VSP.
    channel: VmBusChannel,

    /// Offer descriptor received during VMBus enumeration.
    pub offer: VmBusOfferChannel,

    /// Mutable driver state.
    pub state: RwLock<VmBusStorVscDriverState>,
}

impl VmBusStorVscDriver {
    /// Creates a new, uninitialized driver from a connected channel.
    pub fn new(channel: VmBusChannel, offer: VmBusOfferChannel) -> Self {
        Self {
            channel,
            offer,
            state: RwLock::new(VmBusStorVscDriverState {
                initialized: false,
                init_gate: Arc::new(OneshotGate::new()),
                init_data: RwLock::new(StorVscPacket {
                    header: StorVscMessageHeader::with_message_type(
                        StorVscMessageType::BeginInitialization,
                    ),
                    msg: StorVscMessage { _begin_init: () },
                }),
                next_xid: AtomicU64::new(1),
                max_transfer_bytes: 0,
                pending: BTreeMap::new(),
            }),
        }
    }

    pub fn channel_id(&self) -> u32 {
        self.offer.channel_id
    }

    /// Reads `sector_count` sectors starting at `lba` into `buf`.
    ///
    /// If `sector_count` exceeds [`MAX_SECTORS_PER_REQUEST`] the transfer is
    /// automatically split into multiple sequential SRBs of at most
    /// [`MAX_SECTORS_PER_REQUEST`] sectors each.
    ///
    /// `buf` must be exactly `sector_count * SECTOR_SIZE` bytes long.
    pub fn read_sectors(
        &self,
        disk: VmBusDisk,
        lba: u32,
        sector_count: u32,
        buf: &mut [u8],
    ) -> Result<(), StorVscError> {
        if buf.len() != sector_count as usize * SECTOR_SIZE {
            return Err(StorVscError::InvalidBufferSize);
        }

        self.chunked_io(disk, lba, sector_count, buf, false)
    }

    /// Returns all accessible disks on this controller.
    ///
    /// Issues REPORT LUNS to each target (0..3). Only meaningful on the
    /// primary channel — sub-channels expose the same LUN set.
    pub fn enumerate(&self) -> Result<Vec<VmBusDisk>, StorVscError> {
        if !self.state.read().initialized {
            return Err(StorVscError::NotInitialized);
        }

        let channel_id = self.channel_id();
        let mut disks = Vec::new();

        for target in 0..4u8 {
            match self.enumerate_luns(target) {
                Ok(luns) => {
                    for lun in luns {
                        disks.push(VmBusDisk::new(channel_id, target, lun));
                    }
                }
                // Targets that don't exist return a SCSI error — ignore them.
                Err(StorVscError::ScsiError(..)) => {}
                Err(e) => warn!("storvsc: ch={} target {}: {:?}", channel_id, target, e),
            }
        }

        Ok(disks)
    }

    /// Writes `sector_count` sectors from `buf` to `disk` starting at `lba`.
    ///
    /// Transfers larger than [`MAX_SECTORS_PER_REQUEST`] are split
    /// automatically. `buf` must be exactly `sector_count * SECTOR_SIZE` bytes.
    pub fn write_sectors(
        &self,
        disk: VmBusDisk,
        lba: u32,
        sector_count: u32,
        buf: &mut [u8],
    ) -> Result<(), StorVscError> {
        if buf.len() != sector_count as usize * SECTOR_SIZE {
            return Err(StorVscError::InvalidBufferSize);
        }

        self.chunked_io(disk, lba, sector_count, buf, true)
    }

    /// Flushes the write-back cache of `disk` to persistent media.
    ///
    /// Issues a SCSI SYNCHRONIZE CACHE(10) command and blocks until the host
    /// confirms the flush is complete.
    pub fn flush(&self, disk: VmBusDisk) -> Result<(), StorVscError> {
        if !self.state.read().initialized {
            return Err(StorVscError::NotInitialized);
        }

        self.execute_srb(
            disk,
            build_sync_cache_cdb(),
            10, // SYNCHRONIZE CACHE(10) CDB length
            None,
            StorVscDataDirection::None,
        )
    }

    /// Returns the total sector count and sector size (in bytes) of `disk`.
    ///
    /// Tries READ CAPACITY(16) first for 64-bit LBA support, then falls back
    /// to READ CAPACITY(10) when the host does not support the 16-byte
    /// variant. Returns `(total_sectors, bytes_per_sector)`.
    pub fn read_capacity(&self, disk: VmBusDisk) -> Result<(u64, u32), StorVscError> {
        if !self.state.read().initialized {
            return Err(StorVscError::NotInitialized);
        }

        let rc16_len = size_of::<ScsiReadCapacity16Response>() as u32;
        let response16 = ScsiReadCapacity16Response {
            last_lba_be: 0,
            block_length_be: 0,
        };

        match self.execute_srb(
            disk,
            build_read_capacity16_cdb(rc16_len),
            16,
            Some((&response16 as *const _ as *const u8, rc16_len)),
            StorVscDataDirection::Read,
        ) {
            Ok(()) => {
                let last_lba = u64::from_be(unsafe {
                    ptr::read_volatile(ptr::addr_of!(response16.last_lba_be))
                });
                let block_size = u32::from_be(unsafe {
                    ptr::read_volatile(ptr::addr_of!(response16.block_length_be))
                });

                return Ok((last_lba + 1, block_size));
            }
            // host does not support read capacity(16)
            Err(StorVscError::ScsiError(..)) => {}
            Err(e) => return Err(e),
        }

        let response10 = ScsiReadCapacity10Response {
            last_lba_be: 0,
            block_length_be: 0,
        };

        self.execute_srb(
            disk,
            build_read_capacity10_cdb(),
            10,
            Some((
                &response10 as *const _ as *const u8,
                size_of::<ScsiReadCapacity10Response>() as u32,
            )),
            StorVscDataDirection::Read,
        )?;

        let last_lba =
            u32::from_be(unsafe { ptr::read_volatile(ptr::addr_of!(response10.last_lba_be)) });
        let block_size =
            u32::from_be(unsafe { ptr::read_volatile(ptr::addr_of!(response10.block_length_be)) });

        Ok((last_lba as u64 + 1, block_size))
    }

    /// Returns all LUN numbers accessible on `target_id`.
    ///
    /// Issues a SCSI REPORT LUNS(12) command to the well-known LUN 0 of the
    /// target. Returns a list of active LUN numbers.
    pub fn enumerate_luns(&self, target_id: u8) -> Result<Vec<u8>, StorVscError> {
        if !self.state.read().initialized {
            return Err(StorVscError::NotInitialized);
        }

        // REPORT LUNS is always addressed to LUN 0.
        let mgmt_disk = VmBusDisk::new(self.channel_id(), target_id, 0);

        let response = ScsiReportLunsResponse {
            lun_list_length_be: 0,
            _reserved: 0,
            luns: [0u64; STORVSC_MAX_LUNS_PER_TARGET],
        };

        self.execute_srb(
            mgmt_disk,
            build_report_luns_cdb(REPORT_LUNS_ALLOC_LENGTH),
            12, // REPORT LUNS is a 12-byte CDB
            Some((&response as *const _ as *const u8, REPORT_LUNS_ALLOC_LENGTH)),
            StorVscDataDirection::Read,
        )?;

        // `lun_list_length` is the byte count of all LUN entries combined
        // (excluding the 8-byte response header itself); each entry is 8 bytes.
        let lun_list_length =
            u32::from_be(unsafe { ptr::read_volatile(ptr::addr_of!(response.lun_list_length_be)) });
        let lun_count = (lun_list_length / 8) as usize;

        let mut luns = Vec::with_capacity(lun_count);
        for i in 0..lun_count {
            let entry =
                u64::from_be(unsafe { ptr::read_volatile(ptr::addr_of!(response.luns[i])) });

            // Top two bits of the first byte encode the addressing mode.
            let first_byte = (entry >> 56) as u8;
            let addressing_mode = first_byte >> 6;

            if addressing_mode == 0b00 {
                // Peripheral device addressing: LUN number in lower 6 bits.
                luns.push(first_byte & 0x3F);
            } else {
                warn!(
                    "storvsc: target={} lun entry[{}] uses unsupported addressing mode {}",
                    target_id, i, addressing_mode
                );
            }
        }

        Ok(luns)
    }

    /// Asserts that the `StorVscMessageHeader` stored in `init_data` carries
    /// a success status (0).  Panics on mismatch during initialization.
    fn assert_init_status_ok(&self) {
        let header = self.state.read().init_data.read().header;

        assert_eq!({ header.status }, 0);
    }

    /// Sends an initialization packet, then blocks on `init_gate` until the
    /// ISR opens it.  Resets the gate afterwards so it can be reused.
    ///
    /// Returns `false` if the packet could not be serialized into the ring.
    fn send_init_packet<T>(&self, packet: &T, gate: &OneshotGate) -> bool
    where
        T: Sized,
    {
        let xid = self.state.read().next_xid.fetch_add(1, Ordering::Relaxed);

        if self.send_packet(packet, xid).is_err() {
            return false;
        }

        gate.wait();
        unsafe { gate.reset() };

        true
    }

    /// Splits a large I/O into chunks of at most [`MAX_SECTORS_PER_REQUEST`]
    /// sectors and issues each chunk as a separate SRB.
    ///
    /// `write = true` selects WRITE(10); `write = false` selects READ(10).
    fn chunked_io(
        &self,
        disk: VmBusDisk,
        lba: u32,
        sector_count: u32,
        buf: &mut [u8],
        write: bool,
    ) -> Result<(), StorVscError> {
        if !self.state.read().initialized {
            return Err(StorVscError::NotInitialized);
        }

        let mut remaining = sector_count;
        let mut current_lba = lba;
        let mut buf_offset: usize = 0;

        while remaining > 0 {
            // Clamp to the protocol maximum (fits in the 16-bit CDB field).
            let chunk = remaining.min(MAX_SECTORS_PER_REQUEST) as u16;
            let byte_count = chunk as usize * SECTOR_SIZE;

            let chunk_buf = &mut buf[buf_offset..buf_offset + byte_count];

            let (cdb, direction) = if write {
                (
                    build_write10_cdb(current_lba, chunk),
                    StorVscDataDirection::Write,
                )
            } else {
                (
                    build_read10_cdb(current_lba, chunk),
                    StorVscDataDirection::Read,
                )
            };

            self.execute_srb(
                disk,
                cdb,
                10,
                Some((chunk_buf.as_ptr(), byte_count as u32)),
                direction,
            )?;

            buf_offset += byte_count;
            current_lba += chunk as u32;
            remaining -= chunk as u32;
        }

        Ok(())
    }

    /// Submits a single SRB and blocks until the host completes it.
    ///
    /// # Retry behaviour
    ///
    /// On [`ScsiStatus::Busy`] the SRB is retried up to
    /// [`STORVSC_BUSY_RETRY_COUNT`] times before returning
    /// [`StorVscError::DeviceBusy`]. Each attempt allocates a fresh `xid` and
    /// a fresh [`OneshotGate`].
    fn execute_srb(
        &self,
        disk: VmBusDisk,
        cdb: [u8; STORVSC_CDB_SIZE],
        cdb_len: u8,
        data_buffer: Option<(*const u8, u32)>,
        data_direction: StorVscDataDirection,
    ) -> Result<(), StorVscError> {
        let (data_in, srb_flags) = match data_direction {
            StorVscDataDirection::Write => (0u8, SRB_FLAGS_DATA_OUT),
            StorVscDataDirection::Read => (1u8, SRB_FLAGS_DATA_IN),
            StorVscDataDirection::None => (2u8, SRB_FLAGS_NO_DATA_TRANSFER),
        };
        let data_transfer_length = data_buffer.map(|(_, len)| len).unwrap_or(0);

        for _attempt in 0..=STORVSC_BUSY_RETRY_COUNT {
            let xid = self.state.read().next_xid.fetch_add(1, Ordering::Relaxed);

            // Register the pending slot before sending so the ISR cannot
            // race us and open a gate that nobody is waiting on yet.
            let gate = self.register_pending_request(xid);

            let packet = self.build_execute_srb_packet(
                disk,
                &cdb,
                cdb_len,
                data_in,
                srb_flags,
                data_transfer_length,
            );

            self.send_srb_packet(&packet, xid, data_buffer)?;

            // Block until the ISR opens our gate.
            gate.wait();
            unsafe { gate.reset() };

            let srb = self.consume_completion(xid);

            // Interpret the SRB and SCSI status fields.
            if srb.srb_status != 0x00 && srb.srb_status != SRB_STATUS_SUCCESS {
                return Err(StorVscError::SrbError(srb.srb_status));
            }

            match srb.scsi_status {
                s if s == ScsiStatus::Good as u8 => return Ok(()),
                s if s == ScsiStatus::Busy as u8 => continue, // retry
                _ => {
                    return Err(StorVscError::ScsiError(
                        srb.scsi_status,
                        srb.sense_info_length,
                    ));
                }
            }
        }

        Err(StorVscError::DeviceBusy)
    }

    /// Inserts a fresh [`PendingRequest`] into the pending map for `xid` and
    /// returns a clone of its gate.
    fn register_pending_request(&self, xid: u64) -> Arc<OneshotGate> {
        let entry = PendingRequest {
            gate: Arc::new(OneshotGate::new()),
            completion: None,
        };

        let gate_clone = Arc::clone(&entry.gate);

        without_interrupts(|| self.state.write().pending.insert(xid, entry));

        gate_clone
    }

    /// Constructs the [`StorVscPacket`] for an EXECUTE_SRB request.
    fn build_execute_srb_packet(
        &self,
        disk: VmBusDisk,
        cdb: &[u8; STORVSC_CDB_SIZE],
        cdb_len: u8,
        data_in: u8,
        srb_flags: u32,
        data_transfer_length: u32,
    ) -> StorVscPacket {
        // Copy the CDB into the fixed-size `data` array of the SRB.
        let mut cdb_data = [0u8; 0x14];
        cdb_data[..STORVSC_CDB_SIZE].copy_from_slice(cdb);

        StorVscPacket {
            header: StorVscMessageHeader {
                message_type: StorVscMessageType::ExecuteSrb,
                flags: REQUEST_COMPLETION_FLAG,
                status: 0,
            },
            msg: StorVscMessage {
                execute_srb: StorVscExecuteSrb {
                    length: size_of::<StorVscExecuteSrb>() as u16,
                    srb_status: 0,
                    scsi_status: 0,
                    port_number: 0,
                    path_id: 0,
                    target_id: disk.target_id,
                    lun: disk.lun,
                    cdb_length: cdb_len,
                    sense_info_length: STORVSC_SENSE_BUFFER_SIZE as u8,
                    data_in,
                    reserved: 0,
                    data_transfer_length,
                    data: cdb_data,
                    reserve: 0,
                    queue_tag: SRB_QUEUE_TAG_UNTAGGED,
                    queue_action: SRB_SIMPLE_TAG_REQUEST,
                    srb_flags: srb_flags | SRB_FLAGS_DISABLE_SYNCH_TRANSFER,
                    time_out_value: 60, // arbitrary, @TODO: Check it
                    queue_sort_ey: 0,
                },
            },
        }
    }

    /// Removes the completed [`PendingRequest`] for `xid` from the pending map
    /// and returns the inner [`StorVscExecuteSrb`].
    fn consume_completion(&self, xid: u64) -> StorVscExecuteSrb {
        let completion = without_interrupts(|| {
            self.state
                .write()
                .pending
                .remove(&xid)
                .unwrap()
                .completion
                .unwrap()
        });

        unsafe { completion.msg.execute_srb }
    }

    /// Sends an EXECUTE_SRB packet, using GPA Direct when a data buffer is present.
    ///
    /// For transfers with `data_buffer`, the in-band portion carries the
    /// [`StorVscPacket`] while the payload pages are described via
    /// [`VmBusGpaDirectHeader`] + PFN array (built by
    /// [`VmBusChannel::send_data_packet`]).
    fn send_srb_packet(
        &self,
        packet: &StorVscPacket,
        xid: u64,
        data_buffer: Option<(*const u8, u32)>,
    ) -> Result<(), StorVscError> {
        let inband_len = size_of::<StorVscPacket>();

        if let Some((buf, len)) = data_buffer {
            if len == 0 {
                // Nothing to DMA — fall back to a plain inband packet.
                return self.send_packet(packet, xid);
            }

            // Calculate how many 4 KiB pages the buffer spans.
            let pfn_count = {
                let first_pfn = buf.addr() / HYPERV_PAGE_SIZE;
                let last_pfn = (buf.addr() + len as usize - 1) / HYPERV_PAGE_SIZE;
                last_pfn - first_pfn + 1
            };

            // Validate that the complete wire packet fits in the ring buffer.
            let wire_size =
                size_of::<VmBusGpaDirectHeader>() + pfn_count * 8 + inband_len + VMBUS_PKT_OVERHEAD;
            if wire_size > STORVSC_RING_BUFFER_SIZE {
                return Err(StorVscError::RingBufferFull);
            }

            trace!(
                "storvsc: send EXECUTE_SRB GPA Direct xid={} len=0x{:x} pfns={}",
                xid, len, pfn_count
            );

            self.channel.send_data_packet(
                packet as *const _ as *const u8,
                inband_len,
                xid,
                buf,
                len as usize,
            );
        } else {
            // No data buffer: plain inband packet.
            if inband_len + VMBUS_PKT_OVERHEAD > STORVSC_RING_BUFFER_SIZE {
                return Err(StorVscError::RingBufferFull);
            }

            self.send_packet(packet, xid)?;
        }

        Ok(())
    }

    /// Serialises `packet` into a VMBus `DataInband` packet and writes it to
    /// the ring buffer.
    fn send_packet<T>(&self, packet: &T, xid: u64) -> Result<(), StorVscError> {
        let len = size_of::<T>();

        if len + VMBUS_PKT_OVERHEAD > STORVSC_RING_BUFFER_SIZE {
            return Err(StorVscError::RingBufferFull);
        }

        let mut buf = alloc::vec![0u8; len];
        unsafe {
            ptr::copy_nonoverlapping(packet as *const T as *const u8, buf.as_mut_ptr(), len);
        }

        self.channel
            .send_packet(buf.as_ptr(), len, xid, true, VmBusPacketType::DataInband);

        Ok(())
    }

    /// Parses the `QUERY_PROPERTIES` response from `init_data` and stores
    /// `max_transfer_bytes` in the driver state.
    fn apply_query_properties_response(&self) {
        let pkt = unsafe { self.state.read().init_data.read().msg.query_properties };

        self.state.write().max_transfer_bytes = pkt.max_transfer_bytes;
    }
}

impl VmBusSyntheticDevice for VmBusStorVscDriver {
    /// Runs the four-step storvsc initialization handshake.
    ///
    /// Each step sends a packet, blocks on `init_gate` until the host's
    /// `CompleteIo` arrives (gate opened by [`process_incoming_data`]), then
    /// asserts the response status is 0.
    ///
    /// Returns `true` on success, `false` if any step fails.
    fn initialize(&self) -> bool {
        let gate = Arc::clone(&self.state.read().init_gate);

        // begin initialization
        let begin_init = StorVscPacket {
            header: StorVscMessageHeader::with_message_type(
                StorVscMessageType::BeginInitialization,
            ),
            msg: StorVscMessage { _begin_init: () },
        };
        if !self.send_init_packet(&begin_init, &gate) {
            return false;
        }
        self.assert_init_status_ok();

        // query protocol version
        let ver_query = StorVscPacket {
            header: StorVscMessageHeader::with_message_type(
                StorVscMessageType::QueryProtocolVersion,
            ),
            msg: StorVscMessage {
                query_version: StorVscQueryProtocolVersion {
                    version: STORVSC_PROTOCOL_VERSION,
                    revision: 0,
                },
            },
        };
        if !self.send_init_packet(&ver_query, &gate) {
            return false;
        }
        self.assert_init_status_ok();

        // query properties
        let props_query = StorVscPacket {
            header: StorVscMessageHeader::with_message_type(StorVscMessageType::QueryProperties),
            msg: StorVscMessage {
                query_properties: StorVscQueryProperties {
                    reserved: 0,
                    max_channel_count: 0,
                    reserved2: 0,
                    flags: 0,
                    max_transfer_bytes: 0,
                },
            },
        };
        if !self.send_init_packet(&props_query, &gate) {
            return false;
        }
        self.assert_init_status_ok();
        self.apply_query_properties_response();

        // end initialization
        let end_init = StorVscPacket {
            header: StorVscMessageHeader::with_message_type(StorVscMessageType::EndInitialization),
            msg: StorVscMessage { _end_init: () },
        };
        if !self.send_init_packet(&end_init, &gate) {
            return false;
        }
        self.assert_init_status_ok();

        // Mark the driver ready for I/O.
        self.state.write().initialized = true;

        true
    }

    fn has_data_to_process(&self) -> bool {
        self.channel.has_data_to_process()
    }

    fn process_incoming_data(&self) {
        self.channel.disable_interrupts();

        while let Some(packet) = self.channel.read() {
            let xid = match packet.header {
                VmBusPacketHeader::Packet(hdr) => hdr.xid,
                VmBusPacketHeader::Xfer(hdr) => hdr.header.xid,
            };
            let data_ptr = packet.data.as_ptr();
            let header = unsafe { ptr::read_unaligned(data_ptr as *const StorVscMessageHeader) };

            match header.message_type {
                StorVscMessageType::CompleteIo => {
                    if self.state.read().initialized {
                        let completion =
                            unsafe { (data_ptr as *const StorVscPacket).as_ref().unwrap() };

                        let mut state = self.state.write();
                        if let Some(pending) = state.pending.get_mut(&xid) {
                            pending.completion = Some(*completion);

                            let gate = Arc::clone(&pending.gate);

                            drop(state);

                            gate.open();
                        } else {
                            panic!("got completion for unknown xid={}", xid);
                        }
                    } else {
                        let raw = unsafe { (data_ptr as *const StorVscPacket).as_ref().unwrap() };

                        *self.state.write().init_data.write() = *raw;
                        self.state.read().init_gate.open();
                    }
                }

                unknown => {
                    panic!("got unexpected message type {:?}", unknown);
                }
            }
        }

        self.channel.enable_interrupts();
    }
}
