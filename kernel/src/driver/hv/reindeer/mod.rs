//! Core interfaces and definitions for the hypervisor.
//!
//! This module provides the foundational traits, constants, and structures
//! required to manage virtual machines, virtual CPUs, memory translation (SLAT),
//! and hardware emulation.
use alloc::{boxed::Box, string::String, sync::Arc, vec::Vec};
use core::{cmp, ptr};

use iced_x86::Register;
use spin::rwlock::RwLock;

use crate::{
    driver::hv::reindeer::{
        device::{VirtualDevice, interrupt::pic::ProgrammableInterruptControllerDevice},
        guest::{
            clock::{DEFAULT_GUEST_APIC_BUS_HZ, DEFAULT_GUEST_TSC_HZ},
            registers::CpuState,
        },
        guest_machine::GuestMachineState,
    },
    subsystem::memory::PAGE_SIZE,
};

pub mod acpi;
pub mod backend;
pub mod device;
pub mod guest;
pub mod guest_machine;
pub mod intel;
pub mod run_loop;
pub mod setup;

/// Guest Physical Address.
pub type GuestPhysAddr = u64;

/// Host Physical Address.
pub type HostPhysAddr = u64;

/// Guest Virtual Address.
pub type GuestVirtAddr = u64;

/// Thread-safe reference to a Virtual Machine.
pub type VmHandle = Arc<RwLock<dyn VirtualMachine>>;

/// Thread-safe reference to a vCPU.
pub type VcpuHandle = Arc<RwLock<dyn Vcpu>>;

/// Intel Processor Trace Control MSR.
pub const MSR_IA32_RTIT_CTL: u32 = 0x0000_017A;

/// Feature Control MSR (controls VMX/SMX enablement and lock state).
pub const MSR_IA32_FEATURE_CONTROL: u32 = 0x0000_003A;

/// SMI (System Management Interrupt) counter.
pub const MSR_SMI_COUNT: u32 = 0x0000_0034;

/// Architectural Time Stamp Counter.
pub const MSR_IA32_TIME_STAMP_COUNTER: u32 = 0x0000_0010;

/// Maximum Performance Frequency Clock Count.
pub const MSR_IA32_MPERF: u32 = 0x0000_00E7;

/// Actual Performance Frequency Clock Count.
pub const MSR_IA32_APERF: u32 = 0x0000_00E8;

/// Architectural Capabilities (speculative execution side-channel mitigations).
pub const MSR_IA32_ARCH_CAPABILITIES: u32 = 0x0000_010A;

/// Variable MTRR Physical Base Probe Range Start.
pub const MSR_MTRR_PHYS_BASE_MASK_START: u32 = 0x0000_0200;
/// Variable MTRR Physical Base Probe Range End.
pub const MSR_MTRR_PHYS_BASE_MASK_END: u32 = 0x0000_020F;

/// Fixed MTRR (16K range at 0xA0000 - VGA Frame Buffer region).
pub const MSR_MTRR_FIX16K_A0000: u32 = 0x0000_0259;

/// Fixed MTRR 4K range start (0x268..=0x26F).
pub const MSR_MTRR_FIX4K_C0000: u32 = 0x0000_0268;

/// Unused gap index between fixed MTRRs and MTRR_DEF_TYPE.
pub const MSR_MTRR_GAP_27F: u32 = 0x0000_027F;

/// MTRR Default Memory Type and Enable Flags.
pub const MSR_IA32_MTRR_DEF_TYPE: u32 = 0x0000_02FF;

/// Running Average Power Limit Range Start.
pub const MSR_RAPL_RANGE_START: u32 = 0x0000_0600;

/// Running Average Power Limit Range End.
pub const MSR_RAPL_RANGE_END: u32 = 0x0000_065F;

/// SYSENTER CS register (0x174).
pub const MSR_IA32_SYSENTER_CS: u32 = 0x0000_0174;

/// SYSENTER ESP register (0x175).
pub const MSR_IA32_SYSENTER_ESP: u32 = 0x0000_0175;

/// SYSENTER EIP register (0x176).
pub const MSR_IA32_SYSENTER_EIP: u32 = 0x0000_0176;

/// Miscellaneous Features Enable register (0x140).
pub const MSR_IA32_MISC_FEATURES_ENABLE: u32 = 0x0000_0140;

/// Memory Type: Write-Back (0x06) repeated 8 times -> 0x0606_0606_0606_0606
const MTRR_PAT_PACKED_WB: u32 = 0x0606_0606;

/// Memory Type: Uncacheable (0x01) repeated 8 times -> 0x0101_0101_0101_0101
const MTRR_PAT_PACKED_UC: u32 = 0x0101_0101;

/// Memory Type: Write-Protect (0x05) repeated 8 times -> 0x0505_0505_0505_0505
const MTRR_PAT_PACKED_WP: u32 = 0x0505_0505;

/// Interface for managing the global hypervisor environment.
pub trait VirtualMachineMonitor {
    /// Initializes the hypervisor on the current host.
    fn initialize(&self) -> Result<(), HypervisorError>;

    /// Creates and configures a new Virtual Machine.
    fn create_vm(&self, vm_options: &VmOptions) -> Result<VmHandle, HypervisorError>;
}

/// Interface representing a single Virtual Machine.
pub trait VirtualMachine {
    /// Creates and registers a new vCPU for this VM.
    fn add_vcpu(&mut self, id: u32) -> Result<VcpuHandle, HypervisorError>;

    /// Returns a reference to the SLAT manager.
    fn memory_manager(&mut self) -> Arc<RwLock<dyn SlatManager>>;

    /// Flushes translation lookaside buffers across all remote vCPUs.
    fn flush_remote_tlbs(&self);

    /// Returns a read-only reference to the guest machine state.
    fn state(&self) -> Result<&GuestMachineState, HypervisorError>;

    /// Returns a mutable reference to the guest machine state.
    fn state_mut(&mut self) -> Result<&mut GuestMachineState, HypervisorError>;
}

/// Guest segment whose base is needed by firmware / real-mode helpers.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SegmentRegister {
    /// Stack Segment.
    Ss,

    /// Data Segment.
    Ds,

    /// Extra Segment.
    Es,
}

/// Interface representing a single vCPU.
pub trait Vcpu {
    /// Retrieves a reference to the Programmable Interrupt Controller (PIC).
    fn pic(&self) -> Arc<RwLock<ProgrammableInterruptControllerDevice>>;

    /// Enables single-stepping mode for the vCPU.
    fn enable_single_step(&self);

    /// Disables single-stepping mode for the vCPU.
    fn disable_single_step(&self);

    /// Enter guest mode until the next VM-exit or injection point.
    fn run(&mut self) -> Result<VmExit, HypervisorError>;

    /// Returns the unique ID of this vCPU.
    fn id(&self) -> usize;

    /// Returns the current architectural execution mode of the vCPU.
    fn execution_mode(&self) -> CpuExecutionMode;

    /// Retrieves mutable access to the guest's general-purpose registers.
    fn gpr(&mut self) -> &mut CpuState;

    /// Current guest RSP.
    fn guest_rsp(&self) -> u64;

    /// Update guest RSP for the next VM-entry.
    fn set_guest_rsp(&mut self, value: u64);

    /// Linear base of a guest segment.
    fn segment_base(&self, segment: SegmentRegister) -> u64;

    /// Guest CR0.
    fn guest_cr0(&self) -> u64;

    /// Queue an interrupt or exception for delivery on the next VM-entry.
    fn inject_interrupt(&mut self, vector: u8, type_: InterruptionType, error_code: Option<u32>);

    /// Request a VM-exit when the guest opens an interrupt window.
    fn set_interrupt_window_exit(&mut self, enable: bool);

    /// Flushes all TLB entries for this vCPU.
    fn flush_tlb_all(&mut self);

    /// Flushes a specific guest virtual address from the TLB.
    fn flush_tlb_gva(&mut self, gva: GuestVirtAddr);

    /// Advance guest RIP by the length of the instruction that caused the last exit.
    fn advance_rip(&mut self);

    /// Reads a control register (CR).
    fn cr(&self, cr: u8) -> u64;

    /// Writes a value to a control register (CR).
    fn set_cr(&self, cr: u8, value: u64);

    /// Sets the Page Attribute Table (PAT) MSR.
    fn set_pat_msr(&self, value: u64);

    /// Reads the Page Attribute Table (PAT) MSR.
    fn pat_msr(&self) -> u64;

    /// Sets the SYSENTER Code Segment MSR.
    fn set_sysenter_cs_msr(&self, value: u64);

    /// Reads the SYSENTER Code Segment MSR.
    fn sysenter_cs_msr(&self) -> u64;

    /// Sets the SYSENTER Stack Pointer MSR.
    fn set_sysenter_esp_msr(&self, value: u64);

    /// Reads the SYSENTER Stack Pointer MSR.
    fn sysenter_esp_msr(&self) -> u64;

    /// Sets the SYSENTER Instruction Pointer MSR.
    fn set_sysenter_eip_msr(&self, value: u64);

    /// Reads the SYSENTER Instruction Pointer MSR.
    fn sysenter_eip_msr(&self) -> u64;

    /// Sets the Extended Feature Enable Register (EFER) MSR.
    fn set_efer_msr(&self, value: u64);

    /// Reads the Extended Feature Enable Register (EFER) MSR.
    fn efer_msr(&self) -> u64;
}

/// Represents the architectural execution mode of the processor.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[allow(clippy::enum_variant_names)]
pub enum CpuExecutionMode {
    /// 16-bit Real Mode.
    RealMode,

    /// 32-bit Protected Mode.
    ProtectedMode,

    /// 64-bit Long Mode.
    LongMode,
}

/// Defines memory access permissions for SLAT mappings.
#[derive(Debug, Clone, Copy)]
pub enum MemoryAccessRights {
    /// Read-only access.
    Read,

    /// Write-only access.
    Write,

    /// Execute-only access.
    Execute,

    /// Read and write access.
    ReadWrite,

    /// Read and execute access.
    ReadExecute,

    /// Read, write, and execute access.
    ReadWriteExecute,
}

/// Second-level address translation (Intel EPT / AMD NPT).
pub trait SlatManager: Send + Sync {
    /// Maps a single guest page to a host page.
    fn map(
        &mut self,
        gpa: GuestPhysAddr,
        hpa: HostPhysAddr,
        access_rights: MemoryAccessRights,
    ) -> Result<(), HypervisorError>;

    /// Maps a contiguous block of memory.
    fn map_contiguous(
        &mut self,
        gpa: GuestPhysAddr,
        hpa: HostPhysAddr,
        size: usize,
        access_rights: MemoryAccessRights,
    ) -> Result<(), HypervisorError>;

    /// Removes the mapping for a specific guest physical address.
    fn unmap(&mut self, gpa: GuestPhysAddr) -> Result<(), HypervisorError>;

    /// Changes the access rights for a specific mapped region.
    fn protect(
        &mut self,
        gpa: GuestPhysAddr,
        size: usize,
        rights: MemoryAccessRights,
    ) -> Result<(), HypervisorError>;

    /// Translates a guest physical address to a host physical address.
    fn translate(&self, gpa: GuestPhysAddr) -> Option<HostPhysAddr>;

    /// Root page-table HPA (EPT PML4 / NPT nCR3).
    fn root_pointer(&self) -> HostPhysAddr;
}

/// Provides safe access to guest physical memory through SLAT mappings.
pub struct GuestMemoryAccessor<'a> {
    /// Reference to the underlying SLAT manager.
    slat: &'a dyn SlatManager,
}

impl<'a> GuestMemoryAccessor<'a> {
    /// Creates a new memory accessor using the provided SLAT manager.
    pub fn new(slat: &'a dyn SlatManager) -> Self {
        Self { slat }
    }

    /// Reads a slice of bytes from guest physical memory.
    pub fn read_slice(&self, start: GuestPhysAddr, buf: &mut [u8]) -> Result<(), HypervisorError> {
        let mut gpa = start;
        let mut offset = 0;

        while offset < buf.len() {
            let page_offset = gpa as usize & (PAGE_SIZE - 1);
            let chunk_len = cmp::min(PAGE_SIZE - page_offset, buf.len() - offset);
            let host_address = self
                .slat
                .translate(gpa)
                .ok_or(HypervisorError::MemoryMappingError)?;

            unsafe {
                ptr::copy_nonoverlapping(
                    host_address as *const u8,
                    buf.as_mut_ptr().add(offset),
                    chunk_len,
                );
            }

            gpa = gpa
                .checked_add(chunk_len as u64)
                .ok_or(HypervisorError::MemoryMappingError)?;
            offset += chunk_len;
        }

        Ok(())
    }

    /// Writes a slice of bytes to guest physical memory.
    pub fn write_slice(&self, start: GuestPhysAddr, buf: &[u8]) -> Result<(), HypervisorError> {
        let mut gpa = start;
        let mut offset = 0;

        while offset < buf.len() {
            let page_offset = gpa as usize & (PAGE_SIZE - 1);
            let chunk_len = cmp::min(PAGE_SIZE - page_offset, buf.len() - offset);
            let host_address = self
                .slat
                .translate(gpa)
                .ok_or(HypervisorError::MemoryMappingError)?;

            unsafe {
                ptr::copy_nonoverlapping(
                    buf.as_ptr().add(offset),
                    host_address as *mut u8,
                    chunk_len,
                );
            }

            gpa = gpa
                .checked_add(chunk_len as u64)
                .ok_or(HypervisorError::MemoryMappingError)?;
            offset += chunk_len;
        }

        Ok(())
    }

    /// Reads a single byte (u8) from guest physical memory.
    pub fn read_u8(&self, addr: GuestPhysAddr) -> Result<u8, HypervisorError> {
        let mut buf = [0u8; 1];
        self.read_slice(addr, &mut buf)?;

        Ok(buf[0])
    }

    /// Writes a single byte (u8) to guest physical memory.
    pub fn write_u8(&self, addr: GuestPhysAddr, val: u8) -> Result<(), HypervisorError> {
        self.write_slice(addr, &[val])
    }

    /// Reads a 16-bit integer (u16) from guest physical memory.
    pub fn read_u16(&self, addr: GuestPhysAddr) -> Result<u16, HypervisorError> {
        let mut buf = [0u8; 2];

        self.read_slice(addr, &mut buf)?;

        Ok(u16::from_le_bytes(buf))
    }

    /// Writes a 16-bit integer (u16) to guest physical memory.
    pub fn write_u16(&self, addr: GuestPhysAddr, val: u16) -> Result<(), HypervisorError> {
        self.write_slice(addr, &val.to_le_bytes())
    }

    /// Reads a 32-bit integer (u32) from guest physical memory.
    pub fn read_u32(&self, addr: GuestPhysAddr) -> Result<u32, HypervisorError> {
        let mut buf = [0u8; 4];

        self.read_slice(addr, &mut buf)?;

        Ok(u32::from_le_bytes(buf))
    }

    /// Writes a 32-bit integer (u32) to guest physical memory.
    pub fn write_u32(&self, addr: GuestPhysAddr, val: u32) -> Result<(), HypervisorError> {
        self.write_slice(addr, &val.to_le_bytes())
    }

    /// Reads a 64-bit integer (u64) from guest physical memory.
    pub fn read_u64(&self, addr: GuestPhysAddr) -> Result<u64, HypervisorError> {
        let mut buf = [0u8; 8];

        self.read_slice(addr, &mut buf)?;

        Ok(u64::from_le_bytes(buf))
    }

    /// Writes a 64-bit integer (u64) to guest physical memory.
    pub fn write_u64(&self, addr: GuestPhysAddr, val: u64) -> Result<(), HypervisorError> {
        self.write_slice(addr, &val.to_le_bytes())
    }
}

/// Errors that can occur during hypervisor operations.
#[derive(Debug)]
pub enum HypervisorError {
    /// Failed to map or access memory.
    MemoryMappingError,

    /// Invalid VM or hardware configuration.
    InvalidConfiguration,

    /// The current hardware platform is not supported.
    PlatformNotSupported,

    /// A generic virtualization error.
    VirtualizationError,
}

/// Specifies the type of interruption to inject into the guest.
#[derive(Debug, Clone, Copy)]
pub enum InterruptionType {
    /// External hardware interrupt.
    External,

    /// Non-Maskable Interrupt.
    Nmi,

    /// Hardware-generated exception.
    HardwareException,

    /// Software-generated interrupt.
    Software,
}

/// Represents the reason for a vCPU exit.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum VmExit {
    /// Port I/O instruction (IN/OUT).
    Io {
        /// I/O port address.
        port: u16,

        /// `true` if writing, `false` if reading.
        write: bool,

        /// Access length (in bytes).
        len: u8,

        /// Data read or written.
        data: u64,
    },

    /// Control Register (CR) access.
    CrAccess {
        /// Register number (e.g., 0 for CR0).
        cr: u8,

        /// `true` if writing to the CR.
        write: bool,

        /// Value written or read.
        value: u64,

        /// Associated general-purpose register, if applicable.
        register: Option<Register>,
    },

    /// Model-Specific Register (MSR) access.
    Msr {
        /// MSR index.
        index: u32,

        /// `true` if writing, `false` if reading.
        write: bool,

        /// Value written or read.
        val: u64,
    },

    /// CPUID instruction executed.
    Cpuid,

    /// HLT instruction executed.
    Hlt,

    /// Hardware exception occurred.
    Exception {
        /// Exception vector number.
        vector: u8,

        /// Optional exception error code.
        error_code: Option<u32>,
    },

    /// Second-level address translation fault (Intel EPT / AMD NPT).
    SlatViolation {
        /// Faulting guest physical address.
        gpa: u64,

        /// `true` if the fault occurred during a read.
        data_read: bool,

        /// `true` if the fault occurred during a write.
        data_write: bool,

        /// `true` if the fault occurred during an instruction fetch.
        instruction_fetch: bool,

        /// `true` if the page was present but permissions failed.
        present: bool,

        /// `true` if the violation occurred during a guest page walk.
        during_page_walk: bool,

        /// Access length in bytes.
        access_length: u64,

        /// Register used for the memory access.
        register: Option<Register>,

        /// Data associated with the memory access.
        data: Option<u64>,

        /// Length of the instruction causing the fault.
        instruction_length: usize,
    },

    /// The guest has opened an interrupt window.
    InterruptWindow,

    /// PAUSE with PAUSE_EXITING enabled.
    Pause,

    /// Guest instruction that should be skipped.
    AdvanceRip,

    /// VMCALL or VMMCALL executed.
    Hypercall,

    /// An external interrupt triggered a VM-exit.
    ExternalInterrupt,

    /// Unknown or unhandled VM-exit reason.
    Unknown(u64),
}

/// Configuration options for creating a Virtual Machine.
#[derive(Clone)]
pub struct VmOptions {
    /// Total amount of guest RAM in bytes.
    pub mem_size: u64,

    /// Number of virtual CPUs to create.
    pub vcpu_count: u32,

    /// Optional starting RSP (Stack Pointer) value.
    pub entry_rsp: Option<u64>,

    /// Initial architectural CPU mode.
    pub cpu_mode: GuestCpuMode,

    /// Method and payload for booting the guest.
    pub boot_source: BootSource,

    /// List of virtual hardware devices attached to the VM.
    pub devices: Vec<Arc<RwLock<dyn VirtualDevice>>>,

    /// Simulated TSC frequency in Hz.
    pub guest_tsc_hz: u64,

    /// Simulated APIC bus frequency in Hz.
    pub guest_apic_bus_hz: u64,
}

/// Target CPU architecture mode for the guest.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum GuestCpuMode {
    /// 16-bit Real Mode.
    RealMode16,

    /// 32-bit Protected Mode.
    ProtectedMode32,

    /// 64-bit Long Mode.
    LongMode64,
}

/// Source and method used to boot the virtual machine.
#[derive(Debug, Clone, PartialEq, Default)]
pub enum BootSource {
    /// Unknown or unconfigured boot source.
    #[default]
    Unknown,

    /// Raw binary execution at a specific entry point.
    Raw {
        /// Initial Instruction Pointer.
        entry_ip: u64,

        /// Starting CPU execution mode.
        mode: CpuExecutionMode,
    },

    /// Boot using a BIOS/Firmware payload.
    Bios {
        /// File path to the BIOS ROM.
        path: String,
    },

    /// Boot using the standard Linux boot protocol.
    LinuxBootProtocol {
        /// Kernel binary buffer.
        vmlinuz: Box<[u8]>,

        /// Initial Ramdisk (initrd) buffer.
        initial_ramdisk: Box<[u8]>,

        /// Kernel command line parameters.
        command_line: String,
    },
}

/// Builder pattern structure for configuring VmOptions.
#[derive(Default)]
pub struct VmOptionsBuilder {
    /// Optional memory size in bytes.
    mem_size: Option<u64>,

    /// Configured vCPU count.
    vcpu_count: u32,

    /// Configured initial CPU mode.
    cpu_mode: Option<GuestCpuMode>,

    /// Configured boot source.
    boot_source: BootSource,

    /// Attached virtual devices.
    devices: Vec<Arc<RwLock<dyn VirtualDevice>>>,

    /// Target guest TSC frequency.
    guest_tsc_hz: Option<u64>,

    /// Target guest APIC bus frequency.
    guest_apic_bus_hz: Option<u64>,
}

impl VmOptionsBuilder {
    /// Attaches a new virtual device to the VM.
    pub fn device(mut self, device: Arc<RwLock<dyn VirtualDevice>>) -> Self {
        self.devices.push(device);
        self
    }

    /// Sets the total guest memory size in Megabytes.
    pub fn memory(mut self, size_mb: u64) -> Self {
        self.mem_size = Some(size_mb * 1024 * 1024);
        self
    }

    /// Sets the number of virtual CPUs.
    pub fn vcpus(mut self, count: u32) -> Self {
        self.vcpu_count = count;
        self
    }

    /// Sets the initial architectural CPU mode.
    pub fn mode(mut self, mode: GuestCpuMode) -> Self {
        self.cpu_mode = Some(mode);
        self
    }

    /// Specifies the payload and method for booting the guest.
    pub fn boot_source(mut self, boot_source: BootSource) -> Self {
        self.boot_source = boot_source;

        self
    }

    /// Sets the simulated Time Stamp Counter (TSC) frequency.
    pub fn guest_tsc_hz(mut self, hz: u64) -> Self {
        self.guest_tsc_hz = Some(hz);
        self
    }

    /// Sets the simulated APIC bus frequency.
    pub fn guest_apic_bus_hz(mut self, hz: u64) -> Self {
        self.guest_apic_bus_hz = Some(hz);
        self
    }

    /// Finalizes the configuration and returns built `VmOptions`.
    pub fn build(self) -> Result<VmOptions, String> {
        Ok(VmOptions {
            mem_size: self.mem_size.ok_or("Memory size not set")?,
            vcpu_count: if self.vcpu_count == 0 {
                1
            } else {
                self.vcpu_count
            },
            entry_rsp: None,
            cpu_mode: self.cpu_mode.unwrap_or(GuestCpuMode::RealMode16),
            boot_source: self.boot_source,
            devices: self.devices,
            guest_tsc_hz: self.guest_tsc_hz.unwrap_or(DEFAULT_GUEST_TSC_HZ),
            guest_apic_bus_hz: self.guest_apic_bus_hz.unwrap_or(DEFAULT_GUEST_APIC_BUS_HZ),
        })
    }
}
