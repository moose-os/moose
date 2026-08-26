//! Intel VMCS TSC offset / multiplier programming and related capability probes.

use x86::{
    bits64::vmx::vmwrite,
    time::rdtsc,
    vmx::vmcs::{
        self,
        control::{PrimaryControls, SecondaryControls},
    },
};
use x86_64::registers::model_specific::Msr;

use crate::driver::hv::reindeer::{
    HypervisorError, guest::clock::GuestClock, intel::IA32_VMX_PROCBASED_CTLS2,
};

const SECONDARY_USE_TSC_SCALING: u64 = 1 << 25;

/// Whether IA32_VMX_PROCBASED_CTLS2 allows TSC scaling.
pub fn tsc_scaling_supported() -> bool {
    let msr = unsafe { Msr::new(IA32_VMX_PROCBASED_CTLS2).read() };
    let allowed_1 = (msr >> 32) & 0xFFFF_FFFF;
    (allowed_1 & SECONDARY_USE_TSC_SCALING) != 0
}

/// Primary processor-based controls required for guest TSC offsetting.
pub fn primary_tsc_controls(_clock: &GuestClock) -> PrimaryControls {
    PrimaryControls::USE_TSC_OFFSETTING
}

/// Secondary processor-based controls for TSC scaling when required.
pub fn secondary_tsc_controls(clock: &GuestClock) -> SecondaryControls {
    if clock.needs_tsc_scaling() {
        SecondaryControls::USE_TSC_SCALING
    } else {
        SecondaryControls::empty()
    }
}

/// Write VMCS `TSC_OFFSET` / `TSC_MULTIPLIER` from the shared [`GuestClock`] state.
pub fn sync_vmcs_tsc(clock: &GuestClock) -> Result<(), HypervisorError> {
    let host_tsc = unsafe { rdtsc() };
    let guest_tsc = clock.host_to_guest_tsc(host_tsc);
    let needs_scaling = clock.needs_tsc_scaling();

    if needs_scaling {
        let host_hz = clock.host_tsc_hz().max(1);
        let tsc_hz = clock.tsc_hz();
        let multiplier = ((tsc_hz as u128) << 48) / host_hz as u128;
        let scaled = ((host_tsc as u128 * multiplier) >> 48) as u64;
        let offset = guest_tsc.wrapping_sub(scaled) as i64;

        unsafe { vmwrite(vmcs::control::TSC_MULTIPLIER_FULL, multiplier as u64) }.map_err(
            |_| {
                log::error!("vmwrite TSC_MULTIPLIER failed");
                HypervisorError::VirtualizationError
            },
        )?;

        unsafe { vmwrite(vmcs::control::TSC_OFFSET_FULL, offset as u64) }.map_err(|_| {
            log::error!("vmwrite TSC_OFFSET (scaled) failed");
            HypervisorError::VirtualizationError
        })?;
    } else {
        let offset = guest_tsc.wrapping_sub(host_tsc) as i64;

        unsafe { vmwrite(vmcs::control::TSC_OFFSET_FULL, offset as u64) }.map_err(|_| {
            log::error!("vmwrite TSC_OFFSET failed");
            HypervisorError::VirtualizationError
        })?;
    }
    Ok(())
}
