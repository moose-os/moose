//! Vendor-neutral guest CPU state used to program initial guest contexts.
//!
//! This module provides vendor-neutral representations of guest registers, segments,
//! and descriptor tables required to set up a vCPU at boot time.

use crate::driver::hv::reindeer::{BootSource, CpuExecutionMode};

/// Vendor-neutral representation of x86 segment access rights and attributes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SegmentAccessRights {
    /// Segment type (4 bits, e.g., Code/Data, Read/Write, Accessed).
    pub segment_type: u8,

    /// Descriptor type: `false` = System segment, `true` = Code/Data segment.
    pub descriptor_type: bool,

    /// Descriptor Privilege Level (0..=3).
    pub dpl: u8,

    /// Segment present flag.
    pub present: bool,

    /// Available for use by system software.
    pub avl: bool,

    /// 64-bit code segment flag (Long Mode).
    pub long_mode: bool,

    /// Default operation size (0 = 16-bit, 1 = 32-bit).
    pub default_size: bool,

    /// Granularity (0 = 1B, 1 = 4KB).
    pub granularity: bool,

    /// Segment marked as unusable (Intel VMX specific concept).
    pub unusable: bool,
}

impl SegmentAccessRights {
    /// Encodes access rights into Intel VMX VMCS 32-bit format.
    ///
    /// Bits [0..7]: Type, S, DPL, P
    /// Bits [12..15]: AVL, L, D/B, G
    /// Bit 16: Unusable
    pub fn as_intel(&self) -> u32 {
        if self.unusable {
            return 0x1_0000; // Bit 16 marks segment as unusable in VMCS
        }

        let mut ar = 0u32;
        ar |= (self.segment_type & 0xF) as u32;
        ar |= (self.descriptor_type as u32) << 4;
        ar |= ((self.dpl & 0x3) as u32) << 5;
        ar |= (self.present as u32) << 7;

        ar |= (self.avl as u32) << 12;
        ar |= (self.long_mode as u32) << 13;
        ar |= (self.default_size as u32) << 14;
        ar |= (self.granularity as u32) << 15;

        ar
    }

    /// Encodes access rights into AMD SVM VMCB 16-bit format.
    ///
    /// Bits [0..7]: Type, S, DPL, P
    /// Bits [8..11]: AVL, L, D/B, G
    pub fn as_amd(&self) -> u16 {
        if self.unusable {
            return 0; // AMD marks unusable/invalid segments by clearing Present / attributes
        }

        let mut ar = 0u16;
        ar |= (self.segment_type & 0xF) as u16;
        ar |= (self.descriptor_type as u16) << 4;
        ar |= ((self.dpl & 0x3) as u16) << 5;
        ar |= (self.present as u16) << 7;

        ar |= (self.avl as u16) << 8;
        ar |= (self.long_mode as u16) << 9;
        ar |= (self.default_size as u16) << 10;
        ar |= (self.granularity as u16) << 11;

        ar
    }

    /// Unusable / invalid segment.
    pub const fn unusable() -> Self {
        Self {
            segment_type: 0,
            descriptor_type: false,
            dpl: 0,
            present: false,
            avl: false,
            long_mode: false,
            default_size: false,
            granularity: false,
            unusable: true,
        }
    }

    /// Flat 32-bit Code Segment (PL0, Exec/Read).
    pub const fn flat_code_32() -> Self {
        Self {
            segment_type: 0xB, // Code, Execute/Read, Accessed
            descriptor_type: true,
            dpl: 0,
            present: true,
            avl: false,
            long_mode: false,
            default_size: true, // 32-bit
            granularity: true,  // 4KB
            unusable: false,
        }
    }

    /// Flat 32-bit Data Segment (PL0, Read/Write).
    pub const fn flat_data_32() -> Self {
        Self {
            segment_type: 0x3, // Data, Read/Write, Accessed
            descriptor_type: true,
            dpl: 0,
            present: true,
            avl: false,
            long_mode: false,
            default_size: true, // 32-bit
            granularity: true,  // 4KB
            unusable: false,
        }
    }

    /// Real-mode Code Segment.
    pub const fn real_code() -> Self {
        Self {
            segment_type: 0xB, // Code, Execute/Read, Accessed
            descriptor_type: true,
            dpl: 0,
            present: true,
            avl: false,
            long_mode: false,
            default_size: false, // 16-bit
            granularity: false,  // Byte
            unusable: false,
        }
    }

    /// Real-mode Data Segment.
    pub const fn real_data() -> Self {
        Self {
            segment_type: 0x3, // Data, Read/Write, Accessed
            descriptor_type: true,
            dpl: 0,
            present: true,
            avl: false,
            long_mode: false,
            default_size: false, // 16-bit
            granularity: false,  // Byte
            unusable: false,
        }
    }

    /// 32-bit Task State Segment (TSS Busy).
    pub const fn tss_busy_32() -> Self {
        Self {
            segment_type: 0xB,      // 32-bit TSS (Busy)
            descriptor_type: false, // System
            dpl: 0,
            present: true,
            avl: false,
            long_mode: false,
            default_size: false,
            granularity: false,
            unusable: false,
        }
    }
}

/// Segment register state encoding base, limit, selector, and access rights.
///
/// Access rights follow the Intel VMX VMCS encoding format.
#[derive(Debug, Clone, Copy)]
pub struct SegmentState {
    /// Segment selector value.
    pub selector: u16,

    /// Base linear address of the segment.
    pub base: u64,

    /// Segment limit in bytes.
    pub limit: u32,

    /// Intel VMX-encoded segment access rights and attributes.
    pub access_rights: SegmentAccessRights,
}

/// State of a Global or Interrupt Descriptor Table Register (GDTR / IDTR).
#[derive(Debug, Clone, Copy)]
pub struct DescriptorTableState {
    /// Base linear address of the descriptor table.
    pub base: u64,

    /// Table limit in bytes (size minus 1).
    pub limit: u32,
}

/// Initial guest architectural state derived from a [`BootSource`].
///
/// Backends write this initial state into the guest area of the VMCS (Intel) or VMCB (AMD).
/// Control and execution interception fields (intercept flags, EPT/NPT root pointers,
/// host state) remain vendor-specific and are managed separately by backend implementations.
#[derive(Debug, Clone)]
pub struct GuestInitialState {
    /// Initial guest CPU execution mode.
    pub execution_mode: CpuExecutionMode,

    /// Control Register 0 (CR0).
    pub cr0: u64,

    /// Control Register 3 (CR3 / Page Directory Base Register).
    pub cr3: u64,

    /// Control Register 4 (CR4).
    pub cr4: u64,

    /// CPU Flags register (RFLAGS / EFLAGS).
    pub rflags: u64,

    /// Instruction Pointer (RIP).
    pub rip: u64,

    /// Stack Pointer (RSP).
    pub rsp: u64,

    /// General-purpose register RAX.
    pub rax: u64,

    /// General-purpose register RBX.
    pub rbx: u64,

    /// General-purpose register RDX.
    pub rdx: u64,

    /// General-purpose register RSI.
    pub rsi: u64,

    /// Page Attribute Table (PAT) MSR value.
    pub pat: u64,

    /// Code Segment (CS).
    pub cs: SegmentState,

    /// Stack Segment (SS).
    pub ss: SegmentState,

    /// Data Segment (DS).
    pub ds: SegmentState,

    /// Extra Segment (ES).
    pub es: SegmentState,

    /// FS Segment.
    pub fs: SegmentState,

    /// GS Segment.
    pub gs: SegmentState,

    /// Task Register (TR).
    pub tr: SegmentState,

    /// Local Descriptor Table Register (LDTR).
    pub ldtr: SegmentState,

    /// Global Descriptor Table Register (GDTR).
    pub gdtr: DescriptorTableState,

    /// Interrupt Descriptor Table Register (IDTR).
    pub idtr: DescriptorTableState,
}

impl GuestInitialState {
    /// Creates a flat 32-bit protected-mode state image.
    ///
    /// Configures flat 4 GB code and data segments with `0` base and `0xFFFFFFFF` limits,
    /// suitable for 32-bit boot entry points.
    fn protected_flat(rip: u64, rsp: u64) -> Self {
        let data = SegmentState {
            selector: 0,
            base: 0,
            limit: 0xFFFF_FFFF,
            access_rights: SegmentAccessRights::flat_data_32(),
        };

        Self {
            execution_mode: CpuExecutionMode::ProtectedMode,
            cr0: 0x21, // PE | ET
            cr3: 0,
            cr4: 0,
            rflags: 2,
            rip,
            rsp,
            rax: 0,
            rbx: 0,
            rdx: 0,
            rsi: 0,
            pat: 0x0007_0406_0000_0105,
            cs: SegmentState {
                selector: 0,
                base: 0,
                limit: 0xFFFF_FFFF,
                access_rights: SegmentAccessRights::flat_code_32(),
            },
            ss: data,
            ds: data,
            es: data,
            fs: data,
            gs: data,
            tr: SegmentState {
                selector: 0,
                base: 0,
                limit: 0xFFFF,
                access_rights: SegmentAccessRights::tss_busy_32(),
            },
            ldtr: SegmentState {
                selector: 0,
                base: 0,
                limit: 0xFFFF,
                access_rights: SegmentAccessRights::unusable(),
            },
            gdtr: DescriptorTableState {
                base: 0,
                limit: 0xFFFF,
            },
            idtr: DescriptorTableState {
                base: 0,
                limit: 0x3FF,
            },
        }
    }

    /// Creates a 16-bit real-mode state image.
    ///
    /// Configures real-mode segment attributes with 64 KB limits, standard execution
    /// flags, and IDT limits suitable for traditional BIOS/MBR boot environments.
    fn real_mode(rip: u64, rsp: u64) -> Self {
        let data = SegmentState {
            selector: 0,
            base: 0,
            limit: 0xFFFF,
            access_rights: SegmentAccessRights::real_data(),
        };

        Self {
            execution_mode: CpuExecutionMode::RealMode,
            cr0: 0x20, // ET only
            cr3: 0,
            cr4: 0,
            rflags: 2,
            rip,
            rsp,
            rax: 0,
            rbx: 0,
            rdx: 0,
            rsi: 0,
            pat: 0x0007_0406_0000_0105,
            cs: SegmentState {
                selector: 0,
                base: 0,
                limit: 0xFFFF_FFFF,
                access_rights: SegmentAccessRights::real_code(),
            },
            ss: data,
            ds: data,
            es: data,
            fs: data,
            gs: data,
            tr: SegmentState {
                selector: 0x8,
                base: 0,
                limit: 0xFFFF,
                access_rights: SegmentAccessRights::tss_busy_32(),
            },
            ldtr: SegmentState {
                selector: 0,
                base: 0,
                limit: 0xFFFF,
                access_rights: SegmentAccessRights::unusable(),
            },
            gdtr: DescriptorTableState {
                base: 0,
                limit: 0xFFFF,
            },
            idtr: DescriptorTableState {
                base: 0,
                limit: 0x3FF,
            },
        }
    }

    /// Constructs a [`GuestInitialState`] tailored to a specific [`BootSource`].
    ///
    /// Configures initial register states, segment registers, instruction pointers (`RIP`),
    /// stack pointers (`RSP`), and boot-protocol-specific register conventions
    /// (e.g., boot drive ID in `RDX` for BIOS, `boot_params` pointer in `RSI` for Linux).
    pub fn from_boot_source(boot: &BootSource) -> Self {
        match boot {
            BootSource::Raw { entry_ip, mode } => {
                let mut state = match mode {
                    CpuExecutionMode::RealMode => Self::real_mode(*entry_ip, 0x7A00),
                    CpuExecutionMode::ProtectedMode | CpuExecutionMode::LongMode => {
                        Self::protected_flat(*entry_ip, 0x7A00)
                    }
                };

                state.execution_mode = *mode;
                state.rip = *entry_ip;

                state
            }
            BootSource::Bios { .. } => {
                let mut state = Self::real_mode(0x7C00, 0x7A00);

                state.rdx = 0x80; // First hard disk (0x80)

                state
            }
            BootSource::LinuxBootProtocol { .. } => {
                let mut state = Self::protected_flat(0x10_0000, 0x9000);

                state.rsi = 0x1_0000; // Pointer to boot_params (zero page)

                state
            }
            BootSource::Unknown => panic!("Unknown boot source"),
        }
    }
}
