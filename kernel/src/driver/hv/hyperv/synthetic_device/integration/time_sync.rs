//! Hyper-V Time Synchronization Integration Service (TimeSync IC).
//!
//! Implements the VMBus TimeSync Integration Component, which allows a Hyper-V
//! host to push accurate wall-clock time to this guest. The service negotiates
//! a protocol version with the host and then handles periodic
//! [`UtilMessageType::TimeSync`] packets, applying the received timestamp to
//! the [`SystemClock`].
//!
//! # Protocol versions
//!
//! | Version | Payload struct           | Notable additions                        |
//! |---------|--------------------------|------------------------------------------|
//! | 1.0     | [`VmBusTimeSyncData`]    | `parent_time`, `child_time`, RTT, flags  |
//! | 3.0     | [`VmBusTimeSyncData`]    | Same wire format as v1, different caps   |
//! | 4.0     | [`VmBusTimeSyncRefData`] | TSC `reference_time`, stratum, leap flags|
//!
//! # Clock correction
//!
//! All host timestamps are in 100-nanosecond intervals since the Windows
//! FILETIME epoch (1601-01-01 UTC). Before applying them to the guest clock,
//! subtract `116_444_736_000_000_000` and multiply by 100 to obtain
//! nanoseconds since the Unix epoch.
//!
//! Corrections are applied exclusively to [`SystemClock::wall_clock_base_ns`];
//! the TSC-derived monotonic offset and hardware frequencies are never touched.
//!
//! The [`TimeSyncFlags`] bitmask in each packet determines the correction
//! strategy:
//!
//! - [`PROBE`](TimeSyncFlags::PROBE) — host is measuring RTT; echo the packet
//!   back without modifying the clock.
//! - [`SYNC`](TimeSyncFlags::SYNC) — apply a hard (step) correction
//!   immediately; safe to use even after large discontinuities such as
//!   resume-from-hibernate.
//! - [`SAMPLE`](TimeSyncFlags::SAMPLE) — optionally apply a bounded slew
//!   correction to reduce drift gradually; may be ignored.

use core::{arch::x86_64::_rdtsc, sync::atomic::Ordering};

use bitflags::bitflags;

use crate::{
    driver::hv::hyperv::{
        VmBusOfferChannel, VmBusPacketHeader, VmBusPacketType,
        channel::VmBusChannel,
        synthetic_device::{
            VmBusSyntheticDevice,
            integration::{
                IcVersionSet, UtilMessageHeader, UtilMessageType, UtilVersion, mark_as_response,
                negotiate_versions,
            },
        },
    },
    kernel::kernel_ref,
};

/// TimeSync protocol version 1.0..
const TIMESYNC_VERSION1_0: UtilVersion = UtilVersion::new(1, 0);

/// TimeSync protocol version 3.0.
const TIMESYNC_VERSION3_0: UtilVersion = UtilVersion::new(3, 0);

/// TimeSync protocol version 4.0.
const TIMESYNC_VERSION4_0: UtilVersion = UtilVersion::new(4, 0);

/// Ordered set of TimeSync protocol versions supported by this guest.
///
/// Listed from most-preferred (newest) to least-preferred. Version negotiation
/// selects the first entry that the host also accepts.
const TIMESYNC_VERSIONS: IcVersionSet = &[
    TIMESYNC_VERSION4_0,
    TIMESYNC_VERSION3_0,
    TIMESYNC_VERSION1_0,
];

bitflags! {
    /// Flags carried in every TimeSync message, indicating what action the host
    /// expects from the guest.
    ///
    /// A single message may combine multiple flags; handle each independently.
    #[repr(transparent)]
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    struct TimeSyncFlags: u8 {
        /// No action requested. Used as a zero/default value.
        const NONE   = 0;

        /// The host is measuring round-trip latency to the guest.
        ///
        /// The guest must echo the packet back immediately without adjusting
        /// its own clock. The host uses the RTT sample to compensate for
        /// transmission delay in subsequent [`SYNC`](TimeSyncFlags::SYNC) messages.
        const PROBE  = 1 << 0;

        /// The host requests a hard clock correction.
        ///
        /// The guest should set its system clock to `parent_time` (adjusted for
        /// any measured RTT). This is a step correction — the clock is moved
        /// instantly rather than slewed gradually.
        const SYNC   = 1 << 1;

        /// The host is providing a time sample for statistical tracking.
        ///
        /// The guest may use this for gradual slew-based drift correction, or
        /// ignore it entirely. No hard clock update is required.
        const SAMPLE = 1 << 2;
    }
}

/// NTP stratum of the host's reference clock.
///
/// Indicates how many hops the host's clock source is from a physical reference.
/// Lower values mean higher accuracy. Guests may use this to decide whether to
/// trust and apply the synchronization. Defined by RFC 5905.
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
enum VmBusTimeSyncStratum {
    /// Stratum 0 — hardware reference clock directly attached to the host
    /// (e.g. atomic clock, GPS receiver, TSC). Not reachable over a network.
    UnspecifiedOrHardware = 0,

    /// Stratum 1 — primary time server synchronized directly with a stratum-0
    /// device via a local, hardware interface.
    PrimaryReference = 1,

    /// Stratum 2–15 — secondary server synchronized over a network.
    ///
    /// The inner value is the hop count from the hardware source; higher means
    /// more network hops and typically more accumulated error.
    SecondaryReference(u8),

    /// Stratum 16 — clock is unsynchronized; the reported time is unreliable
    /// and should not be used for synchronization.
    Unsynchronized = 16,
}

/// TimeSync payload for protocol versions 1.0 and 3.0.
///
/// All timestamps are in 100-nanosecond intervals since the Windows FILETIME
/// epoch (00:00:00 UTC, 1 January 1601).
#[derive(Debug, Copy, Clone)]
#[repr(C, packed)]
struct VmBusTimeSyncData {
    /// Current time on the host at the moment the packet was sent, in 100 ns
    /// units since 1601-01-01. This is the value the guest should apply to its
    /// clock when [`TimeSyncFlags::SYNC`] is set.
    parent_time: u64,

    /// Guest clock value sampled by the host just before transmission, in the
    /// same 100 ns epoch. Returned so the guest can compute the delta between
    /// its current time and the host's view of it.
    child_time: u64,

    /// Measured round-trip time between host and guest, in 100 ns units.
    ///
    /// The guest should add `round_trip_time / 2` to `parent_time` when
    /// applying a [`TimeSyncFlags::SYNC`] correction to compensate for
    /// one-way transmission delay.
    round_trip_time: u64,

    /// Bitmask of [`TimeSyncFlags`] indicating the purpose of this message.
    flags: TimeSyncFlags,
}

/// TimeSync payload for protocol version 4.0.
///
/// Extends the v1/v3 format with a TSC-derived `reference_time`, NTP leap
/// flags, and a stratum level. All timestamps are in 100-nanosecond intervals
/// since the Windows FILETIME epoch (1601-01-01 UTC).
#[derive(Debug, Copy, Clone)]
#[repr(C, packed)]
struct VmBusTimeSyncRefData {
    /// Current host time at packet transmission, in 100 ns units since
    /// 1601-01-01. Need to set the guest clock to this value when flag
    /// [`TimeSyncFlags::SYNC`] is set.
    parent_time: u64,

    /// TSC-backed hardware reference time on the host, in 100 ns units since
    /// 1601-01-01. More stable than `parent_time` for drift calculations
    /// because it is derived directly from the host's invariant TSC rather
    /// than the software clock.
    reference_time: u64,

    /// Bitmask of [`TimeSyncFlags`] indicating the purpose of this message.
    flags: TimeSyncFlags,

    /// NTP leap-second indicator.
    leap_flags: u8,

    /// NTP stratum of the host's clock source. See [`VmBusTimeSyncStratum`].
    stratum: VmBusTimeSyncStratum,

    /// Reserved.
    reserved: [u8; 3],
}

/// Hyper-V Integration Service: Time Synchronization.
///
/// Implements the VMBus TimeSync IC (Integration Component), which allows the
/// Hyper-V host to push accurate wall-clock time to this guest.
///
/// # Time epoch conversion
/// Host timestamps use the Windows FILETIME epoch (1601-01-01 UTC). To obtain
/// a Unix timestamp:
/// ```text
/// unix_100ns = parent_time - 116_444_736_000_000_000
/// unix_secs  = unix_100ns / 10_000_000
/// unix_nanos = (unix_100ns % 10_000_000) * 100
/// ```
pub struct VmBusTimeSyncService {
    /// The VMBus channel used to exchange packets with the host.
    channel: VmBusChannel,

    /// The original offer descriptor received from the host during channel
    /// enumeration.
    offer: VmBusOfferChannel,
}

impl VmBusTimeSyncService {
    pub fn new(channel: VmBusChannel, offer: VmBusOfferChannel) -> Self {
        Self { channel, offer }
    }
}

impl VmBusTimeSyncService {
    /// Decodes a raw TimeSync payload and returns the new wall-clock base.
    fn decode_timesync_packet(
        &self,
        data_ptr: *const u8,
        packet_size: usize,
        tsc_now: u64,
        ns_per_tsc_mult: u64,
        ns_per_tsc_shift: u32,
    ) -> Option<TimeSyncUpdate> {
        if data_ptr.is_null() {
            return None;
        }

        let payload_ptr = unsafe { data_ptr.add(size_of::<UtilMessageHeader>()) };

        if packet_size - 2 == size_of::<VmBusTimeSyncData>() {
            // v1/3
            let msg = unsafe { *(payload_ptr as *const VmBusTimeSyncData) };
            let rtt_compensation_ns = (msg.round_trip_time * 100) / 2;
            let host_wall_ns =
                filetime_to_unix_ns(msg.parent_time)?.saturating_add(rtt_compensation_ns);

            Some(TimeSyncUpdate {
                new_wall_clock_base_ns: compute_wall_clock_base(
                    host_wall_ns,
                    tsc_now,
                    ns_per_tsc_mult,
                    ns_per_tsc_shift,
                ),
                flags: msg.flags,
            })
        } else {
            // v4
            let msg = unsafe { *(payload_ptr as *const VmBusTimeSyncRefData) };

            // Stratum 16 means the host itself is unsynchronized.
            if msg.stratum == VmBusTimeSyncStratum::Unsynchronized {
                return None;
            }

            if msg.flags.contains(TimeSyncFlags::PROBE) {
                return None;
            }

            let host_wall_ns = filetime_to_unix_ns(msg.parent_time)?;

            Some(TimeSyncUpdate {
                new_wall_clock_base_ns: compute_wall_clock_base(
                    host_wall_ns,
                    tsc_now,
                    ns_per_tsc_mult,
                    ns_per_tsc_shift,
                ),
                flags: msg.flags,
            })
        }
    }
}

impl VmBusSyntheticDevice for VmBusTimeSyncService {
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

            let VmBusPacketHeader::Packet(vmbus_hdr) = packet.header else {
                panic!("Got time_sync with Xfer packet header")
            };

            match util_hdr.message_type {
                UtilMessageType::NegotiateProtocol => {
                    negotiate_versions(data_ptr, TIMESYNC_VERSIONS);
                }
                UtilMessageType::TimeSync => {
                    let packet_size = util_hdr.message_size as usize;
                    let clock = kernel_ref().clock();

                    if packet_size < 24 {
                        continue;
                    }

                    let update = self.decode_timesync_packet(
                        data_ptr,
                        packet_size,
                        unsafe { _rdtsc() },
                        clock.ns_per_tsc_mult,
                        clock.ns_per_tsc_shift,
                    );

                    if let Some(update) = update {
                        if update.flags.contains(TimeSyncFlags::PROBE) {
                            // Host is measuring RTT only — do not touch the clock.
                        } else if update.flags.contains(TimeSyncFlags::SYNC) {
                            // Host forces us to update the clock
                            clock
                                .wall_clock_base_ns
                                .store(update.new_wall_clock_base_ns, Ordering::SeqCst);
                        } else if update.flags.contains(TimeSyncFlags::SAMPLE) {
                            // Small drift in time

                            let current = clock.wall_clock_base_ns.load(Ordering::SeqCst);
                            let delta = update.new_wall_clock_base_ns as i64 - current as i64;
                            let adjustment = delta.clamp(-500_000, 500_000);
                            clock
                                .wall_clock_base_ns
                                .store(current.wrapping_add_signed(adjustment), Ordering::SeqCst);
                        }
                    }
                }
                _ => {}
            }

            mark_as_response(data_ptr);

            // Echo the (modified) packet back as acknowledgement.
            self.channel.send_packet(
                packet.data.as_ptr(),
                packet.data.len(),
                vmbus_hdr.xid,
                false,
                VmBusPacketType::DataInband,
            );
        }

        self.channel.enable_interrupts();
    }
}

/// Converts a Windows FILETIME timestamp to nanoseconds since the Unix epoch.
///
/// FILETIME counts 100-nanosecond intervals since 1601-01-01 UTC. This
/// subtracts the epoch delta and scales to nanoseconds.
#[inline]
fn filetime_to_unix_ns(filetime: u64) -> Option<u64> {
    const FILETIME_TO_UNIX_100NS: u64 = 116_444_736_000_000_000;

    let unix_100ns = filetime.checked_sub(FILETIME_TO_UNIX_100NS)?;
    unix_100ns.checked_mul(100)
}

/// Computes the new [`SystemClock::wall_clock_base_ns`] from a TimeSync packet.
///
/// The base is defined as:
/// ```text
/// wall_clock_base_ns = host_wall_ns - tsc_monotonic_ns
/// ```
/// so that at any point in time:
/// ```text
/// wall_time_ns = wall_clock_base_ns + (tsc * mult >> shift)
/// ```
#[inline]
fn compute_wall_clock_base(
    host_wall_ns: u64,
    tsc_now: u64,
    ns_per_tsc_mult: u64,
    ns_per_tsc_shift: u32,
) -> u64 {
    let tsc_ns = ((tsc_now as u128 * ns_per_tsc_mult as u128) >> ns_per_tsc_shift) as u64;
    host_wall_ns.saturating_sub(tsc_ns)
}

/// Decoded, version-independent result of a TimeSync packet.
///
/// Produced by [`decode_timesync_packet`] and consumed by the clock update
/// logic in [`VmBusTimeSyncService::process_incoming_data`].
#[derive(Debug, Clone, Copy)]
struct TimeSyncUpdate {
    /// New wall-clock base in nanoseconds since the Unix epoch, ready to be
    /// stored directly into [`SystemClock::wall_clock_base_ns`].
    new_wall_clock_base_ns: u64,

    /// The correction strategy requested by the host.
    flags: TimeSyncFlags,
}
