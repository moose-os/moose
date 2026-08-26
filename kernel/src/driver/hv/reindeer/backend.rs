//! Hypervisor backend detection and initialization.
//!
//! Selects Intel VMX (or AMD SVM) at runtime and returns the
//! appropriate [`VirtualMachineMonitor`] implementation.

use alloc::boxed::Box;

use raw_cpuid::CpuId;

use crate::driver::hv::reindeer::{
    HypervisorError, VirtualMachineMonitor, intel::IntelVirtualMachineMonitor,
};

/// Supported hardware virtualization backends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HypervisorBackend {
    /// Intel VT-x (VMX).
    IntelVmx,

    /// AMD-V (SVM) - not implemented yet.
    AmdSvm,
}

/// Detect which virtualization extension is available on the current CPU.
pub fn detect_hypervisor_backend() -> Result<HypervisorBackend, HypervisorError> {
    let cpuid = CpuId::new();

    if cpuid.get_feature_info().is_some_and(|feat| feat.has_vmx()) {
        return Ok(HypervisorBackend::IntelVmx);
    }

    if cpuid
        .get_extended_processor_and_feature_identifiers()
        .is_some_and(|ext| ext.has_svm())
    {
        return Ok(HypervisorBackend::AmdSvm);
    }

    Err(HypervisorError::PlatformNotSupported)
}

/// Creates a VMM for the current CPU backend.
pub fn initialize_hypervisor() -> Result<Box<dyn VirtualMachineMonitor>, HypervisorError> {
    let backend = detect_hypervisor_backend()?;

    match backend {
        HypervisorBackend::IntelVmx => Ok(Box::new(IntelVirtualMachineMonitor {})),
        HypervisorBackend::AmdSvm => unimplemented!(),
    }
}
