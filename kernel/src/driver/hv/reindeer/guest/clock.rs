//! Guest time source shared across hypervisor backends.
//!
//! The [`GuestClock`] tracks guest-visible time metrics, including Time Stamp Counter (TSC)
//! frequencies, virtual Local APIC (LAPIC) bus rates, and CPUID time reporting.
//!
//! Platform-specific TSC offset and multiplier programming stays in the respective
//! hypervisor backends.

use alloc::sync::Arc;

use x86::time::rdtsc;

use crate::kernel::kernel_ref;

/// Default guest TSC frequency in Hz (2.4 GHz).
pub const DEFAULT_GUEST_TSC_HZ: u64 = 2_400_000_000;

/// Nominal core crystal clock frequency in Hz (24 MHz) used for CPUID leaf `0x15` ratios.
const CPUID_CRYSTAL_HZ: u64 = 24_000_000;

/// Default virtual LAPIC bus frequency in Hz.
pub const DEFAULT_GUEST_APIC_BUS_HZ: u64 = CPUID_CRYSTAL_HZ;

/// Guest-visible clock tracking TSC frequency, LAPIC bus rate, and monotonic time.
///
/// Manages frequency scaling fallbacks and provides helper methods to convert host time
/// into guest TSC ticks, compute LAPIC timer progress, and report CPUID time leaves.
#[derive(Debug)]
pub struct GuestClock {
    /// Effective guest TSC frequency in Hz.
    tsc_hz: u64,

    /// Virtual LAPIC bus frequency in Hz.
    apic_bus_hz: u64,

    /// Host TSC sampled at clock initialization.
    base_host_tsc: u64,

    /// Baseline guest TSC offset at clock initialization.
    base_guest_tsc: u64,

    /// Physical host TSC frequency in Hz.
    host_tsc_hz: u64,

    /// Whether hardware-assisted TSC frequency scaling (e.g., VMX TSC scaling / AMD ratio) is available.
    tsc_scaling_supported: bool,
}

impl GuestClock {
    /// Create a guest clock with the requested TSC and APIC-bus frequencies.
    ///
    /// `tsc_scaling_supported` comes from the backend.
    /// Falls back to the host TSC frequency when the guest requests a different rate but
    /// hardware scaling is unavailable.
    pub fn new(requested_tsc_hz: u64, apic_bus_hz: u64, tsc_scaling_supported: bool) -> Arc<Self> {
        let host_tsc_hz = kernel_ref().clock().tsc_frequency().max(1);
        let apic_bus_hz = apic_bus_hz.max(1);

        let tsc_hz = host_tsc_hz;
        if requested_tsc_hz != host_tsc_hz {
            log::info!(
                "GuestClock: using host TSC {} Hz (requested {} Hz ignored)",
                host_tsc_hz,
                requested_tsc_hz
            );
        }

        Arc::new(Self {
            tsc_hz,
            apic_bus_hz,
            base_host_tsc: unsafe { rdtsc() },
            base_guest_tsc: 0,
            host_tsc_hz,
            tsc_scaling_supported,
        })
    }

    /// Guest TSC frequency in Hz.
    pub fn tsc_hz(&self) -> u64 {
        self.tsc_hz
    }

    /// Convert a host TSC sample into the guest-visible TSC.
    ///
    /// Must match VMCS `TSC_OFFSET` / `TSC_MULTIPLIER` exactly, so RDTSC,
    /// ACPI PM, PIT and LAPIC all see the same counter.
    pub fn host_to_guest_tsc(&self, host_tsc: u64) -> u64 {
        let scale = |tsc: u64| -> u64 {
            if self.needs_tsc_scaling() {
                let multiplier = ((self.tsc_hz as u128) << 48) / self.host_tsc_hz.max(1) as u128;
                ((tsc as u128 * multiplier) >> 48) as u64
            } else {
                tsc
            }
        };

        self.base_guest_tsc
            .wrapping_add(scale(host_tsc).wrapping_sub(scale(self.base_host_tsc)))
    }

    /// Current guest TSC. Same value the guest `RDTSC` returns.
    pub fn now_tsc(&self) -> u64 {
        self.host_to_guest_tsc(unsafe { rdtsc() })
    }

    /// APIC timer divide configuration (DCR bits 0–3) to divider value.
    pub fn apic_timer_divider(dcr: u64) -> u32 {
        match dcr & 0b1011 {
            0b0000 => 2,
            0b0001 => 4,
            0b0010 => 8,
            0b0011 => 16,
            0b1000 => 32,
            0b1001 => 64,
            0b1010 => 128,
            0b1011 => 1,
            _ => 16,
        }
    }

    /// LAPIC timer ticks elapsed since `start_guest_tsc` for the given DCR.
    pub fn lapic_ticks_elapsed(&self, start_guest_tsc: u64, dcr: u64) -> u64 {
        let delta_tsc = self.now_tsc().saturating_sub(start_guest_tsc);
        let divider = Self::apic_timer_divider(dcr).max(1) as u64;

        ((delta_tsc as u128 * self.apic_bus_hz as u128) / self.tsc_hz as u128 / divider as u128)
            as u64
    }

    /// CPUID leaf 0x15 values for guest TSC/core crystal reporting.
    ///
    /// CPUID leaf `0x15` reports Time Stamp Counter and Nominal Core Crystal Clock Information:
    /// - `EAX`: Denominator of the TSC/crystal ratio (`1`).
    /// - `EBX`: Rounded TSC/crystal multiplier.
    /// - `ECX`: Nominal crystal frequency, also used by the emulated LAPIC.
    /// - `EDX`: Reserved.
    pub fn cpuid_leaf_15(&self) -> (u32, u32, u32, u32) {
        // Linux multiplies crystal_khz by EBX before
        // dividing by EAX, and older kernels can perform that product in u32.
        let eax = 1;
        let ebx = ((self.tsc_hz + self.apic_bus_hz / 2) / self.apic_bus_hz) as u32;
        let ecx = self.apic_bus_hz as u32;
        let edx = 0;

        (eax, ebx, ecx, edx)
    }

    /// Host physical TSC frequency used for scaling calculations.
    pub fn host_tsc_hz(&self) -> u64 {
        self.host_tsc_hz
    }

    /// Whether hardware TSC scaling must be used to hit `tsc_hz`.
    pub fn needs_tsc_scaling(&self) -> bool {
        self.tsc_hz != self.host_tsc_hz && self.tsc_scaling_supported
    }
}
