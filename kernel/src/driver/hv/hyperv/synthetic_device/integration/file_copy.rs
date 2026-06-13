//! Hyper-V File Copy Integration Service (FCopy IC).
//!
//! Implements the VMBus FCopy Integration Component, which allows a Hyper-V
//! host to push files into this guest without requiring a network connection
//! or shared folder. The host initiates a transfer by sending a
//! [`VmBusFileCopyOperation::StartCopy`] packet, followed by one or more
//! [`VmBusFileCopyOperation::WriteToFile`] packets, and finally a
//! [`VmBusFileCopyOperation::CompleteCopy`] or
//! [`VmBusFileCopyOperation::CancelCopy`] packet.
//!
//! # Transfer flow
//!
//! ```text
//! Host                                    Guest
//!  |                                        |
//!  |-- StartCopy (file_name, path, size) -->|  open / create destination file
//!  |-- WriteToFile (offset, data) --------->|  write chunk at offset
//!  |-- WriteToFile (offset, data) --------->|  write chunk at offset
//!  |           ...                          |
//!  |-- CompleteCopy ----------------------->|  flush & close file
//!  |<-- ACK (each packet echoed back) ------|
//! ```
//!
//! On error or user cancellation the host may send
//! [`VmBusFileCopyOperation::CancelCopy`] at any point, after which the
//! guest should discard any partially written data.

use alloc::string::String;
use bitflags::bitflags;
use core::slice;

use crate::driver::hv::hyperv::{
    VmBusOfferChannel, VmBusPacketType,
    channel::VmBusChannel,
    synthetic_device::{
        VmBusSyntheticDevice,
        integration::{
            IcVersionSet, UtilMessageHeader, UtilMessageType, UtilVersion, decode_utf16_buf,
            mark_as_response, negotiate_versions,
        },
    },
};

/// Maximum length of a file name or path in the FCopy protocol, in UTF-16 code units.
const FCOPY_MAX_PATH_LEN: usize = 260;

/// FCopy protocol version 1.0.
const FILE_COPY_VERSION_1_0: UtilVersion = UtilVersion::new(1, 0);

/// FCopy protocol version 1.1.
const FILE_COPY_VERSION_1_1: UtilVersion = UtilVersion::new(1, 1);

/// Ordered set of FCopy protocol versions supported by this guest,
/// from most-preferred (newest) to least-preferred.
///
/// Version negotiation selects the first entry the host also accepts.
const FILE_COPY_VERSIONS: IcVersionSet = &[FILE_COPY_VERSION_1_1, FILE_COPY_VERSION_1_0];

/// Identifies the operation carried by a VMBus FCopy packet.
///
/// The host always initiates transfers; the guest only ever receives these
/// operations and responds with an ACK echo.
#[derive(Debug, Copy, Clone)]
#[repr(u32)]
enum VmBusFileCopyOperation {
    /// Begin a new file transfer.
    StartCopy = 0,

    /// Write a chunk of file data at a given offset.
    WriteToFile = 1,

    /// The transfer completed successfully.
    CompleteCopy = 2,

    /// The host cancelled the transfer before it completed.
    CancelCopy = 3,
}

bitflags! {
    /// Flags that modify the behaviour of a file copy operation.
    #[repr(transparent)]
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    struct VmBusFileCopyFlags: u32 {
        const NONE        = 0;

        /// Overwrite the destination file if it already exists.
        const OVERWRITE   = 1 << 0;

        /// Create all intermediate directories in the destination path if they
        /// do not already exist.
        const CREATE_PATH = 1 << 1;
    }
}

/// Common header prefixed to every FCopy payload.
#[derive(Debug, Copy, Clone)]
#[repr(C, packed)]
struct VmBusFileCopyHeader {
    /// Identifies which FCopy operation this packet carries.
    operation: VmBusFileCopyOperation,

    /// Reserved.
    service_id0: [u8; 16],

    /// Reserved.
    service_id1: [u8; 16],
}

/// Sent once at the beginning of each file transfer. The guest should use
/// `path` and `file_name` to determine the destination, `file_size` to
/// pre-allocate space, and `copy_flags` to decide overwrite / mkdir behaviour.
#[derive(Debug, Copy, Clone)]
#[repr(C, packed)]
struct VmBusFileCopyStartCopy {
    /// Common FCopy header
    header: VmBusFileCopyHeader,

    /// Destination file name as a null-terminated UTF-16LE string, padded to
    /// `FCOPY_MAX_PATH_LEN * 2` bytes.
    file_name: [u8; FCOPY_MAX_PATH_LEN * 2],

    /// Destination directory path as a null-terminated UTF-16LE string,
    /// padded to `FCOPY_MAX_PATH_LEN * 2` bytes.
    path: [u8; FCOPY_MAX_PATH_LEN * 2],

    /// Flags controlling overwrite and path-creation behaviour.
    copy_flags: VmBusFileCopyFlags,

    /// Total size of the file being transferred, in bytes.
    file_size: u64,
}

/// Carries a single chunk of file data. Chunks are not guaranteed to arrive
/// in order; the guest must write `data[..size]` at byte `offset` within the
/// destination file.
#[derive(Debug, Copy, Clone)]
#[repr(C, packed)]
struct VmBusFileCopyWriteToFile {
    /// Common FCopy header.
    header: VmBusFileCopyHeader,

    /// Alignment padding.
    padding: u32,

    /// Byte offset within the destination file at which `data` should be written.
    offset: u64,

    /// Number of valid bytes in `data`. Always `<= 6144`.
    size: u32,

    /// Raw file data for this chunk. Only the first `size` bytes are valid.
    data: [u8; 6 * 1024],
}

/// Hyper-V Integration Service: File Copy (FCopy IC).
///
/// Receives files pushed from the Hyper-V host and writes them to the guest
/// filesystem.
pub struct VmBusFileCopyService {
    /// The VMBus channel used to exchange packets with the host.
    channel: VmBusChannel,

    /// The original offer descriptor received from the host during channel
    /// enumeration.
    offer: VmBusOfferChannel,
}

impl VmBusFileCopyService {
    pub fn new(channel: VmBusChannel, offer: VmBusOfferChannel) -> Self {
        Self { channel, offer }
    }
}

impl VmBusSyntheticDevice for VmBusFileCopyService {
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

            match util_hdr.message_type {
                UtilMessageType::NegotiateProtocol => {
                    negotiate_versions(data_ptr, FILE_COPY_VERSIONS);
                }
                UtilMessageType::Fcopy => {
                    let fcopy_header = unsafe {
                        (data_ptr.add(size_of::<UtilMessageHeader>()) as *mut VmBusFileCopyHeader)
                            .as_ref()
                            .unwrap()
                    };

                    match fcopy_header.operation {
                        VmBusFileCopyOperation::StartCopy => {
                            let message = unsafe {
                                (data_ptr.add(size_of::<UtilMessageHeader>())
                                    as *mut VmBusFileCopyStartCopy)
                                    .as_ref()
                                    .unwrap()
                            };

                            // @TODO: Open a file descriptor?

                            debug!(
                                "fcopy: start copy, file_name: {}, path: {}",
                                decode_utf16_buf(unsafe {
                                    slice::from_raw_parts(
                                        message.file_name.as_ptr(),
                                        FCOPY_MAX_PATH_LEN * 2,
                                    )
                                }),
                                decode_utf16_buf(unsafe {
                                    slice::from_raw_parts(
                                        message.path.as_ptr(),
                                        FCOPY_MAX_PATH_LEN * 2,
                                    )
                                })
                            );
                        }
                        VmBusFileCopyOperation::WriteToFile => {
                            let message = unsafe {
                                (data_ptr.add(size_of::<UtilMessageHeader>())
                                    as *mut VmBusFileCopyWriteToFile)
                                    .as_ref()
                                    .unwrap()
                            };

                            // @TODO: Write to previously opened fd?

                            debug!(
                                "fcopy: write, offset={}, size={}, data={:x?}, string=[{}]",
                                { message.offset },
                                { message.size },
                                { &message.data[..{ message.size as usize }] },
                                String::from_utf8_lossy({
                                    &message.data[..{ message.size as usize }]
                                })
                                .into_owned()
                            );
                        }
                        VmBusFileCopyOperation::CompleteCopy => {
                            // @TODO: Close fd?
                            debug!("fcopy completed");
                        }
                        unknown => panic!("Unknown FCopy operation: {:?}", unknown),
                    }
                }
                _ => {}
            }

            mark_as_response(data_ptr);

            // Echo the (modified) packet back as acknowledgement.
            self.channel.send_packet(
                packet.data.as_ptr(),
                packet.data.len(),
                0,
                false,
                VmBusPacketType::DataInband,
            );
        }

        self.channel.enable_interrupts();
    }
}
