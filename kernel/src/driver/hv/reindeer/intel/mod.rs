//! Intel VT-x (VMX) backend.
//!
//! EPT, VMCS, VM-entry/VM-exit, and the guest execution loop live here.

pub mod ept;
pub mod tsc;
pub mod vcpu;
pub mod vm;
pub mod vmm;

pub use vmm::IntelVirtualMachineMonitor;

// ============================================================================
// VMX Exception & Interruption Definitions
// ============================================================================

/// Hardware Vector 14 (#PF - Page Fault Exception)
pub const EXCEPTION_VECTOR_PAGE_FAULT: u8 = 14;

/// Interruption Types (Bits 10:8 of Interruption-Information Field)
pub const INTR_TYPE_HARDWARE_EXCEPTION: u32 = 3;

/// Bitmasks for Interruption-Information Fields
pub const INTR_INFO_VALID: u32 = 1 << 31;
pub const INTR_INFO_DELIVER_ERROR_CODE: u32 = 1 << 11;
pub const INTR_INFO_TYPE_MASK: u32 = 0x7;
pub const INTR_INFO_VECTOR_MASK: u32 = 0xFF;

pub const IA32_FEATURE_CONTROL: u32 = 0x3a;
pub const IA32_VMX_BASIC: u32 = 0x480;
pub const IA32_VMX_PINBASED_CTLS: u32 = 0x481;
pub const IA32_VMX_PROCBASED_CTLS: u32 = 0x482;
pub const IA32_VMX_EXIT_CTLS: u32 = 0x483;
pub const IA32_VMX_ENTRY_CTLS: u32 = 0x484;
pub const IA32_VMX_CR0_FIXED0: u32 = 0x486;
pub const IA32_VMX_CR0_FIXED1: u32 = 0x487;
pub const IA32_VMX_CR4_FIXED0: u32 = 0x488;
pub const IA32_VMX_CR4_FIXED1: u32 = 0x489;
pub const IA32_VMX_PROCBASED_CTLS2: u32 = 0x48b;
