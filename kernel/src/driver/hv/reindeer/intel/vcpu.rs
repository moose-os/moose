use alloc::sync::Arc;
use core::slice;

use spin::rwlock::RwLock;
use x86::{
    bits64::vmx::{vmread, vmwrite},
    msr::{IA32_FS_BASE, IA32_GS_BASE, IA32_PAT, rdmsr},
    vmx::{
        VmFail,
        vmcs::{
            self,
            control::{
                EntryControls, ExitControls, PinbasedControls, PrimaryControls, SecondaryControls,
            },
        },
    },
};
use x86_64::{
    instructions::tables::{sgdt, sidt},
    registers::{
        self,
        control::{Cr0, Cr3, Cr4, Efer},
        model_specific::Msr,
        segmentation::Segment,
    },
};

use crate::{
    arch::x86::gdt::TSS,
    driver::hv::reindeer::{
        CpuExecutionMode, GuestVirtAddr, HypervisorError, InterruptionType, SegmentRegister,
        SlatManager, Vcpu, VmExit, VmOptions,
        device::{
            interrupt::{lapic::LocalApicDevice, pic::ProgrammableInterruptControllerDevice},
            legacy::{hpet::VirtualHpet, pit::VirtualPit},
        },
        guest::{
            clock::GuestClock,
            initial_state::GuestInitialState,
            mmio_decode, paging,
            registers::{CpuState, X86RegisterOperations},
        },
        intel::{
            EXCEPTION_VECTOR_PAGE_FAULT, IA32_VMX_BASIC, IA32_VMX_CR0_FIXED0, IA32_VMX_CR0_FIXED1,
            IA32_VMX_CR4_FIXED0, IA32_VMX_CR4_FIXED1, IA32_VMX_ENTRY_CTLS, IA32_VMX_EXIT_CTLS,
            IA32_VMX_PINBASED_CTLS, IA32_VMX_PROCBASED_CTLS, IA32_VMX_PROCBASED_CTLS2,
            INTR_INFO_DELIVER_ERROR_CODE, INTR_INFO_TYPE_MASK, INTR_INFO_VALID,
            INTR_INFO_VECTOR_MASK, INTR_TYPE_HARDWARE_EXCEPTION, tsc,
        },
    },
    subsystem::memory::{
        Exact, Frame, MapTarget, Page, PageFlags, PhysicalAddress, VirtualAddress, memory_manager,
    },
};

/// Carry Flag (CF)
const CARRY_FLAG: u64 = 1 << 0; // 0x0001

/// Zero Flag (ZF)
const ZERO_FLAG: u64 = 1 << 6; // 0x0040

/// Descriptor used by the INVEPT instruction to invalidate EPT translation caches.
#[repr(C)]
struct InveptDescriptor {
    /// The Extended Page Table Pointer (EPTP).
    eptp: u64,

    /// Reserved field, must be zero.
    reserved: u64,
}

/// Represents an Intel VT-x Virtual CPU (vCPU).
pub struct IntelVcpu {
    /// The Virtual Machine Control Structure (VMCS) managing this vCPU.
    vmcs: Vmcs,

    /// Indicates whether the vCPU is about to be launched for the first time.
    first_run: bool,

    /// Second-level address translation (SLAT) manager.
    slat: Arc<RwLock<dyn SlatManager>>,

    /// CPU register state of the host machine.
    host_registers: CpuState,

    /// CPU register state of the guest virtual machine.
    guest_registers: CpuState,

    /// The current architectural execution mode of the guest.
    execution_mode: CpuExecutionMode,

    /// Reference to the Programmable Interrupt Controller (PIC).
    pic: Arc<RwLock<ProgrammableInterruptControllerDevice>>,

    /// Unique identifier for this vCPU instance.
    id: usize,

    /// Reference to the virtual High Precision Event Timer (HPET).
    hpet: Arc<RwLock<VirtualHpet>>,

    /// Reference to the virtual Local APIC (LAPIC).
    lapic: Arc<RwLock<LocalApicDevice>>,

    /// Reference to the virtual Programmable Interval Timer (PIT).
    pit: Arc<RwLock<VirtualPit>>,

    /// Reference to the guest's system clock.
    guest_clock: Arc<GuestClock>,

    /// Software TPR used when injecting interrupts (kept in sync with LAPIC MMIO writes).
    lapic_tpr: u64,
}

impl IntelVcpu {
    /// Creates a new vCPU instance from VM options.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        options: &VmOptions,
        slat: Arc<RwLock<dyn SlatManager>>,
        pic: Arc<RwLock<ProgrammableInterruptControllerDevice>>,
        hpet: Arc<RwLock<VirtualHpet>>,
        id: usize,
        lapic: Arc<RwLock<LocalApicDevice>>,
        pit: Arc<RwLock<VirtualPit>>,
        guest_clock: Arc<GuestClock>,
    ) -> Result<Self, HypervisorError> {
        let vmcs = Vmcs::new()?;
        let initial = GuestInitialState::from_boot_source(&options.boot_source);
        let execution_mode = initial.execution_mode;

        let mut guest_registers = CpuState::default();
        guest_registers.gpr.rax = initial.rax;
        guest_registers.gpr.rbx = initial.rbx;
        guest_registers.gpr.rdx = initial.rdx;
        guest_registers.gpr.rsi = initial.rsi;
        guest_registers.gpr.rip = initial.rip;
        guest_registers.gpr.rsp = initial.rsp;
        guest_registers.gpr.rflags = initial.rflags;

        Ok(Self {
            vmcs,
            first_run: true,
            slat,
            hpet,
            host_registers: CpuState::default(),
            guest_registers,
            execution_mode,
            pic,
            id,
            lapic_tpr: 0,
            lapic,
            pit,
            guest_clock,
        })
    }

    /// Initializes VMCS state at the entry.
    pub fn initialize(
        &self,
        options: &VmOptions,
        _bsp: bool,
        _apic_access_page: u64,
    ) -> Result<(), VmFail> {
        unsafe {
            self.vmcs.load().map_err(|_| VmFail::VmFailInvalid)?;

            let primary_controls = (PrimaryControls::HLT_EXITING
                | PrimaryControls::PAUSE_EXITING
                | PrimaryControls::SECONDARY_CONTROLS
                | PrimaryControls::UNCOND_IO_EXITING
                | tsc::primary_tsc_controls(&self.guest_clock))
            .bits() as u64;
            vmwrite(
                vmcs::control::PRIMARY_PROCBASED_EXEC_CONTROLS,
                self.vmcs
                    .adjust_controls(IA32_VMX_PROCBASED_CTLS, primary_controls),
            )?;

            let secondary_controls = (SecondaryControls::ENABLE_EPT
                | SecondaryControls::UNRESTRICTED_GUEST
                | SecondaryControls::ENABLE_INVPCID
                | SecondaryControls::ENABLE_RDTSCP
                | tsc::secondary_tsc_controls(&self.guest_clock))
            .bits() as u64;
            vmwrite(
                vmcs::control::SECONDARY_PROCBASED_EXEC_CONTROLS,
                self.vmcs
                    .adjust_controls(IA32_VMX_PROCBASED_CTLS2, secondary_controls),
            )?;

            let vmentry_controls =
                (EntryControls::LOAD_IA32_PAT | EntryControls::LOAD_IA32_EFER).bits() as u64;
            vmwrite(
                vmcs::control::VMENTRY_CONTROLS,
                self.vmcs
                    .adjust_controls(IA32_VMX_ENTRY_CTLS, vmentry_controls),
            )?;

            let vmexit_controls = (ExitControls::HOST_ADDRESS_SPACE_SIZE
                | ExitControls::LOAD_IA32_PAT
                | ExitControls::SAVE_IA32_PAT
                | ExitControls::SAVE_IA32_EFER
                | ExitControls::LOAD_IA32_EFER)
                .bits() as u64;
            vmwrite(
                vmcs::control::VMEXIT_CONTROLS,
                self.vmcs
                    .adjust_controls(IA32_VMX_EXIT_CTLS, vmexit_controls),
            )
            .unwrap();

            let pinbased_controls = PinbasedControls::EXTERNAL_INTERRUPT_EXITING.bits() as u64;
            vmwrite(
                vmcs::control::PINBASED_EXEC_CONTROLS,
                self.vmcs
                    .adjust_controls(IA32_VMX_PINBASED_CTLS, pinbased_controls),
            )?;

            // @TODO: Zeros there?
            vmwrite(vmcs::control::CR0_GUEST_HOST_MASK, 0xFFFF_FFFF)?;
            vmwrite(vmcs::control::CR4_GUEST_HOST_MASK, 0xFFFF_FFFF)?;

            // Let common guest-side exceptions run natively in guest context:
            // #BP (3), #UD (6), #PF (14), #MF (16), #XM (19).
            let mut exception_bitmap = u32::MAX as u64;
            for vector in [3u8, 6, 14, 16, 19] {
                exception_bitmap &= !(1u64 << vector);
            }
            vmwrite(vmcs::control::EXCEPTION_BITMAP, exception_bitmap)?;

            vmwrite(
                vmcs::host::ES_SELECTOR,
                (registers::segmentation::ES::get_reg().0 as u64) & 0xF8,
            )?;
            vmwrite(
                vmcs::host::CS_SELECTOR,
                (registers::segmentation::CS::get_reg().0 as u64) & 0xF8,
            )?;
            vmwrite(
                vmcs::host::SS_SELECTOR,
                (registers::segmentation::SS::get_reg().0 as u64) & 0xF8,
            )?;
            vmwrite(
                vmcs::host::DS_SELECTOR,
                (registers::segmentation::DS::get_reg().0 as u64) & 0xF8,
            )?;
            vmwrite(vmcs::host::GS_SELECTOR, 0)?;
            vmwrite(vmcs::host::FS_SELECTOR, 0)?;
            vmwrite(
                vmcs::host::TR_SELECTOR,
                (x86::task::tr().index() << 3) as u64,
            )?;

            vmwrite(vmcs::host::TR_BASE, {
                let tss = TSS.lock();
                tss.as_ptr() as u64
            })?;
            vmwrite(vmcs::host::GDTR_BASE, sgdt().base.as_u64())?;
            vmwrite(vmcs::host::IDTR_BASE, sidt().base.as_u64())?;
            vmwrite(vmcs::host::FS_BASE, Msr::new(IA32_FS_BASE).read())?;
            vmwrite(vmcs::host::GS_BASE, Msr::new(IA32_GS_BASE).read())?;

            vmwrite(vmcs::host::IA32_PAT_FULL, rdmsr(IA32_PAT))?;
            vmwrite(vmcs::host::IA32_EFER_FULL, Efer::read_raw())?;
            vmwrite(vmcs::host::CR0, self.vmcs.adjust_cr0(Cr0::read_raw()))?;
            vmwrite(vmcs::host::CR3, Cr3::read_raw().0.start_address().as_u64())?;
            vmwrite(vmcs::host::CR4, self.vmcs.adjust_cr4(Cr4::read_raw()))?;

            vmwrite(vmcs::guest::LINK_PTR_FULL, 0xFFFF_FFFF_FFFF_FFFF)?;

            /*
             * EPTP (Extended-Page-Table Pointer) Format - 64-bit:
             *
             *  63          52 51                                 12 11     7  6  5     3 2   0
             * +-------------+-------------------------------------+--------+--+-----+-----+
             * |   Reserved  |  PML4 Table Physical Address (4KB)  |  Rsvd  |AD| PWL | Mem |
             * | (Must be 0) |            (Bits 51..12)            | (0000) |  | (-1)| Type|
             * +-------------+-------------------------------------+--------+--+-----+-----+
             *
             * Field details:
             * - Bits 2:0  [Mem Type] : EPT memory type (6 = Write-Back / WB)
             * - Bits 5:3  [PWL]      : Page-walk length - 1 (3 = 4-level EPT paging)
             * - Bit 6     [AD]       : Access/Dirty flags enable (0 = disabled)
             * - Bits 11:7 [Rsvd]     : Reserved, must be 0
             * - Bits 51:12[Address]  : Physical base address of PML4 structure (4KB aligned)
             * - Bits 63:52[Rsvd]     : Reserved, must be 0
             */
            vmwrite(
                vmcs::control::EPTP_FULL,
                (self.slat.read().root_pointer() & !0b111111) | (3 << 3) | 6, // 4-level EPT, write-back.
            )?;

            let initial = GuestInitialState::from_boot_source(&options.boot_source);
            self.apply_guest_state(&initial)?;

            Ok(())
        }
    }

    /// Write vendor-neutral guest image into the current VMCS.
    fn apply_guest_state(&self, state: &GuestInitialState) -> Result<(), VmFail> {
        unsafe {
            vmwrite(vmcs::guest::CR0, state.cr0)?;
            vmwrite(vmcs::guest::CR4, self.vmcs.adjust_cr4(state.cr4))?;
            vmwrite(vmcs::guest::CR3, state.cr3)?;
            vmwrite(vmcs::guest::RFLAGS, state.rflags)?;
            vmwrite(vmcs::guest::RSP, state.rsp)?;
            vmwrite(vmcs::guest::RIP, state.rip)?;
            vmwrite(vmcs::guest::IA32_PAT_FULL, state.pat)?;

            for (seg, (sel, base, lim, ar)) in [
                (
                    state.cs,
                    (
                        vmcs::guest::CS_SELECTOR,
                        vmcs::guest::CS_BASE,
                        vmcs::guest::CS_LIMIT,
                        vmcs::guest::CS_ACCESS_RIGHTS,
                    ),
                ),
                (
                    state.ss,
                    (
                        vmcs::guest::SS_SELECTOR,
                        vmcs::guest::SS_BASE,
                        vmcs::guest::SS_LIMIT,
                        vmcs::guest::SS_ACCESS_RIGHTS,
                    ),
                ),
                (
                    state.ds,
                    (
                        vmcs::guest::DS_SELECTOR,
                        vmcs::guest::DS_BASE,
                        vmcs::guest::DS_LIMIT,
                        vmcs::guest::DS_ACCESS_RIGHTS,
                    ),
                ),
                (
                    state.es,
                    (
                        vmcs::guest::ES_SELECTOR,
                        vmcs::guest::ES_BASE,
                        vmcs::guest::ES_LIMIT,
                        vmcs::guest::ES_ACCESS_RIGHTS,
                    ),
                ),
                (
                    state.fs,
                    (
                        vmcs::guest::FS_SELECTOR,
                        vmcs::guest::FS_BASE,
                        vmcs::guest::FS_LIMIT,
                        vmcs::guest::FS_ACCESS_RIGHTS,
                    ),
                ),
                (
                    state.gs,
                    (
                        vmcs::guest::GS_SELECTOR,
                        vmcs::guest::GS_BASE,
                        vmcs::guest::GS_LIMIT,
                        vmcs::guest::GS_ACCESS_RIGHTS,
                    ),
                ),
                (
                    state.tr,
                    (
                        vmcs::guest::TR_SELECTOR,
                        vmcs::guest::TR_BASE,
                        vmcs::guest::TR_LIMIT,
                        vmcs::guest::TR_ACCESS_RIGHTS,
                    ),
                ),
                (
                    state.ldtr,
                    (
                        vmcs::guest::LDTR_SELECTOR,
                        vmcs::guest::LDTR_BASE,
                        vmcs::guest::LDTR_LIMIT,
                        vmcs::guest::LDTR_ACCESS_RIGHTS,
                    ),
                ),
            ] {
                vmwrite(sel, seg.selector as u64)?;
                vmwrite(base, seg.base)?;
                vmwrite(lim, seg.limit as u64)?;
                vmwrite(ar, seg.access_rights.as_intel() as u64)?;
            }

            vmwrite(vmcs::guest::GDTR_BASE, state.gdtr.base)?;
            vmwrite(vmcs::guest::GDTR_LIMIT, state.gdtr.limit as u64)?;
            vmwrite(vmcs::guest::IDTR_BASE, state.idtr.base)?;
            vmwrite(vmcs::guest::IDTR_LIMIT, state.idtr.limit as u64)?;

            tsc::sync_vmcs_tsc(&self.guest_clock).unwrap();

            Ok(())
        }
    }
}

impl Vcpu for IntelVcpu {
    fn pic(&self) -> Arc<RwLock<ProgrammableInterruptControllerDevice>> {
        self.pic.clone()
    }

    fn id(&self) -> usize {
        self.id
    }

    fn enable_single_step(&self) {
        unsafe {
            self.vmcs.load().unwrap();

            vmwrite(
                vmcs::control::PRIMARY_PROCBASED_EXEC_CONTROLS,
                vmread(vmcs::control::PRIMARY_PROCBASED_EXEC_CONTROLS).unwrap()
                    | PrimaryControls::MONITOR_TRAP_FLAG.bits() as u64,
            )
            .unwrap();
        }
    }

    fn disable_single_step(&self) {
        unsafe {
            self.vmcs.load().unwrap();

            vmwrite(
                vmcs::control::PRIMARY_PROCBASED_EXEC_CONTROLS,
                self.vmcs.adjust_controls(
                    IA32_VMX_PROCBASED_CTLS,
                    vmread(vmcs::control::PRIMARY_PROCBASED_EXEC_CONTROLS).unwrap()
                        & !(PrimaryControls::MONITOR_TRAP_FLAG.bits() as u64),
                ),
            )
            .unwrap();
        }
    }

    fn execution_mode(&self) -> CpuExecutionMode {
        self.execution_mode
    }

    fn gpr(&mut self) -> &mut CpuState {
        &mut self.guest_registers
    }

    fn guest_rsp(&self) -> u64 {
        unsafe {
            self.vmcs.load().unwrap();

            vmread(vmcs::guest::RSP).unwrap()
        }
    }

    fn set_guest_rsp(&mut self, value: u64) {
        unsafe {
            self.vmcs.load().unwrap();

            vmwrite(vmcs::guest::RSP, value).unwrap();
        }

        self.guest_registers.gpr.rsp = value;
    }

    fn segment_base(&self, segment: SegmentRegister) -> u64 {
        let field = match segment {
            SegmentRegister::Ss => vmcs::guest::SS_BASE,
            SegmentRegister::Ds => vmcs::guest::DS_BASE,
            SegmentRegister::Es => vmcs::guest::ES_BASE,
        };

        unsafe {
            self.vmcs.load().unwrap();

            vmread(field).unwrap()
        }
    }

    fn guest_cr0(&self) -> u64 {
        unsafe {
            self.vmcs.load().unwrap();

            vmread(vmcs::guest::CR0).unwrap()
        }
    }

    fn flush_tlb_all(&mut self) {
        let descriptor = InveptDescriptor {
            eptp: self.slat.read().root_pointer(),
            reserved: 0,
        };

        let type_raw: u64 = 1; // INVEPT type: single-context.
        let descriptor_ptr = &descriptor as *const InveptDescriptor;

        unsafe {
            core::arch::asm!(
                "invept {0}, [{1}]",
                in(reg) type_raw,
                in(reg) descriptor_ptr,
                options(nostack, preserves_flags)
            );
        }
    }

    fn flush_tlb_gva(&mut self, _gva: GuestVirtAddr) {
        unimplemented!()
    }

    fn advance_rip(&mut self) {
        unsafe {
            let _ = self.vmcs.load();

            let len = vmread(vmcs::ro::VMEXIT_INSTRUCTION_LEN).unwrap_or(0);

            self.guest_registers.gpr.rip = self.guest_registers.gpr.rip.wrapping_add(len);
        }
    }

    fn inject_interrupt(&mut self, vector: u8, type_: InterruptionType, error_code: Option<u32>) {
        self.vmcs.load().unwrap();

        let irq_type = match type_ {
            InterruptionType::External => 0,
            InterruptionType::Nmi => 2,
            InterruptionType::HardwareException => 3,
            InterruptionType::Software => 4,
        };

        unsafe {
            let mut intr_info = (1 << 31) | ((irq_type & 0x7) as u64) << 8 | (vector as u64);
            if error_code.is_some() {
                intr_info |= 1 << 11;
            }

            vmwrite(vmcs::control::VMENTRY_INTERRUPTION_INFO_FIELD, intr_info)
                .expect("Failed to write Intr Info");
        }
    }

    /// Arm or disarm VM-exit on guest interrupt window (IF transitions, STI shadow).
    fn set_interrupt_window_exit(&mut self, enable: bool) {
        unsafe {
            self.vmcs.load().unwrap();
            let mut primary = vmread(vmcs::control::PRIMARY_PROCBASED_EXEC_CONTROLS).unwrap_or(0);

            if enable {
                primary |= PrimaryControls::INTERRUPT_WINDOW_EXITING.bits() as u64;
            } else {
                primary &= !PrimaryControls::INTERRUPT_WINDOW_EXITING.bits() as u64;
            }

            vmwrite(
                vmcs::control::PRIMARY_PROCBASED_EXEC_CONTROLS,
                self.vmcs.adjust_controls(IA32_VMX_PROCBASED_CTLS, primary),
            )
            .unwrap();
        }
    }

    fn run(&mut self) -> Result<VmExit, HypervisorError> {
        unsafe {
            // Load the current vCPU's VMCS.
            self.vmcs.load()?;

            // Set RFLAGS/RIP; GPRs are restored by the assembly context-switch routine.
            vmwrite(vmcs::guest::RFLAGS, self.guest_registers.gpr.rflags)
                .map_err(|_| HypervisorError::VirtualizationError)?;
            vmwrite(vmcs::guest::RIP, self.guest_registers.gpr.rip)
                .map_err(|_| HypervisorError::VirtualizationError)?;

            // Check whether emulated timers expired and need interrupt injection.
            self.pit.read().check_timer();
            self.hpet.read().check_timer();
            self.lapic.read().check_lapic_timer(self.id);

            // If VMENTRY interruption info is still valid, the guest exited before handling the prior VM-entry interrupt.
            let entry_interruption =
                vmread(vmcs::control::VMENTRY_INTERRUPTION_INFO_FIELD).unwrap_or(0);
            let exception_pending =
                (entry_interruption & (1 << 31)) != 0 && ((entry_interruption >> 8) & 7) == 3;

            let pending_interrupt = self.lapic.read().get_pending_interrupt(
                self.id,
                &mut self.pic.write(),
                self.lapic_tpr,
            );

            if exception_pending {
                // Lets try to reinject hardware injection. Defer other IRQs to a later entry.
                //
                // @TODO: set interrupt window exiting here?
            } else if let Some(interrupt) = pending_interrupt {
                // Check if guest is able to receive interrupts
                let guest_rflags = vmread(vmcs::guest::RFLAGS).unwrap();
                let interrupts_enabled = (guest_rflags & (1 << 9)) != 0;

                // Bits 0–1: STI/MOV SS blocking; cannot inject IRQs now.
                let interruptibility = vmread(vmcs::guest::INTERRUPTIBILITY_STATE).unwrap_or(0);
                let irq_blocked = (interruptibility & 0x3) != 0;

                if interrupts_enabled && !irq_blocked {
                    // Inject the interrupt; commit it in the Local APIC (IRR → ISR).

                    if let Some(vector) = {
                        let lapic = self.lapic.read();
                        lapic.commit_delivered_interrupt(interrupt, &mut self.pic.write(), self.id)
                    } {
                        self.inject_interrupt(vector, InterruptionType::External, None);
                    }
                } else {
                    // Pending interrupt but injection blocked; VM-exit when the guest opens an interrupt window.

                    self.set_interrupt_window_exit(true);
                }
            }

            // VM-entry (VMLAUNCH/VMRESUME).
            let mut launch_flags: u64;
            core::arch::asm!(
                include_str!("run.asm"),
                "pushfq",
                "pop {flags}",
                in("rcx") &mut self.host_registers,
                in("rdx") &mut self.guest_registers,
                in("edi") self.first_run as i32,
                flags = out(reg) launch_flags,
            );

            // CF/ZF set means VMLAUNCH/VMRESUME failed without a VM-exit.
            if (launch_flags & (ZERO_FLAG | CARRY_FLAG)) != 0 {
                let instr_err = vmread(vmcs::ro::VM_INSTRUCTION_ERROR).unwrap_or(u64::MAX);

                panic!(
                    "VMLAUNCH/VMRESUME failed: RFLAGS={:#x} VM_INSTRUCTION_ERROR={} first_run={}",
                    launch_flags, instr_err, self.first_run
                );
            }

            // Refresh vCPU state from the VMCS.
            self.guest_registers.gpr.rflags = vmread(vmcs::guest::RFLAGS).unwrap();
            self.guest_registers.gpr.rip = vmread(vmcs::guest::RIP).unwrap();
            self.guest_registers.gpr.rsp = vmread(vmcs::guest::RSP).unwrap();

            // Read the VM-exit reason.
            let reason_full =
                vmread(vmcs::ro::EXIT_REASON).map_err(|_| HypervisorError::VirtualizationError)?;
            let reason = (reason_full & 0xFFFF) as u32;
            let qualification = vmread(vmcs::ro::EXIT_QUALIFICATION)
                .map_err(|_| HypervisorError::VirtualizationError)?;

            // Subsequent entries use VMRESUME.
            self.first_run = false;

            match reason {
                // Exception or NMI
                0 => {
                    // Read the VM-exit interruption-information field
                    let intr_info = vmread(vmcs::ro::VMEXIT_INTERRUPTION_INFO)
                        .map_err(|_| HypervisorError::VirtualizationError)?
                        as u32;

                    let vector = (intr_info & INTR_INFO_VECTOR_MASK) as u8;
                    let interruption_type = (intr_info >> 8) & INTR_INFO_TYPE_MASK;
                    let has_error_code = (intr_info & INTR_INFO_DELIVER_ERROR_CODE) != 0;

                    // Retrieve error code if present
                    let error_code = if has_error_code {
                        Some(
                            vmread(vmcs::ro::VMEXIT_INTERRUPTION_ERR_CODE)
                                .map_err(|_| HypervisorError::VirtualizationError)?
                                as u32,
                        )
                    } else {
                        None
                    };

                    // Handle Page Fault (#PF): Exit qualification contains the faulting linear address (CR2)
                    if vector == EXCEPTION_VECTOR_PAGE_FAULT {
                        let faulting_address = vmread(vmcs::ro::EXIT_QUALIFICATION)
                            .map_err(|_| HypervisorError::VirtualizationError)?;

                        // Update CR2 with the faulting address prior to re-entering host/guest handling
                        core::arch::asm!(
                            "mov cr2, {0}",
                            in(reg) faulting_address,
                            options(nostack, preserves_flags)
                        );
                    }

                    // Reinject hardware exceptions back into the guest VMCS
                    if interruption_type == INTR_TYPE_HARDWARE_EXCEPTION {
                        let mut entry_intr_info =
                            INTR_INFO_VALID | (interruption_type << 8) | (vector as u32);

                        if has_error_code {
                            entry_intr_info |= INTR_INFO_DELIVER_ERROR_CODE;
                        }

                        vmwrite(
                            vmcs::control::VMENTRY_INTERRUPTION_INFO_FIELD,
                            entry_intr_info as u64,
                        )
                        .map_err(|_| HypervisorError::VirtualizationError)?;

                        if let Some(code) = error_code {
                            vmwrite(vmcs::control::VMENTRY_EXCEPTION_ERR_CODE, code as u64)
                                .map_err(|_| HypervisorError::VirtualizationError)?;
                        }
                    }

                    Ok(VmExit::Exception { vector, error_code })
                }

                // External Interrupt
                1 => Ok(VmExit::ExternalInterrupt),

                // Interrupt Window
                7 => {
                    // Disable interrupt-window exiting and return to the run loop.
                    let mut primary_controls =
                        vmread(vmcs::control::PRIMARY_PROCBASED_EXEC_CONTROLS).unwrap();
                    primary_controls &= !PrimaryControls::INTERRUPT_WINDOW_EXITING.bits() as u64;

                    vmwrite(
                        vmcs::control::PRIMARY_PROCBASED_EXEC_CONTROLS,
                        self.vmcs
                            .adjust_controls(IA32_VMX_PROCBASED_CTLS, primary_controls),
                    )
                    .unwrap();

                    Ok(VmExit::InterruptWindow)
                }

                // CPUID
                10 => Ok(VmExit::Cpuid),

                // HLT
                12 => Ok(VmExit::Hlt),

                // VMCALL
                18 => Ok(VmExit::Hypercall),

                // PAUSE
                27 => Ok(VmExit::Pause),

                // Control Register Accesses
                28 => {
                    let cr = (qualification & 0xF) as u8;
                    let access_type = (qualification >> 4) & 0x3; // 0 = Move to CR, 1 = Move from CR
                    let reg_idx = (qualification >> 8) & 0xF;
                    let write = access_type == 0;

                    let register = if !write {
                        Some(reg_idx_to_register(reg_idx as u8))
                    } else {
                        None
                    };

                    Ok(VmExit::CrAccess {
                        cr,
                        write,
                        value: self.guest_registers.gpr.rax,
                        register,
                    })
                }

                // MONITOR/MWAIT/INVEPT: advance RIP and resume.
                29 | 40 => Ok(VmExit::AdvanceRip),

                // I/O Instruction
                30 => {
                    let port = ((qualification >> 16) & 0xFFFF) as u16;
                    let write = (qualification & (1 << 3)) == 0; // Bit 3: 0 = OUT, 1 = IN.
                    let len = ((qualification & 0x7) + 1) as u8;
                    let data = match len {
                        1 => self.guest_registers.gpr.rax & 0xFF,
                        2 => self.guest_registers.gpr.rax & 0xFFFF,
                        4 => self.guest_registers.gpr.rax & 0xFFFF_FFFF,
                        8 => self.guest_registers.gpr.rax,
                        _ => unreachable!(),
                    };

                    Ok(VmExit::Io {
                        port,
                        write,
                        len,
                        data,
                    })
                }

                // MSR Access
                31 | 32 => {
                    let index = self.guest_registers.gpr.rcx as u32;
                    let write = reason == 32;
                    let val = if write {
                        (self.guest_registers.gpr.rax.low_u32() as u64)
                            | (self.guest_registers.gpr.rdx << 32)
                    } else {
                        0
                    };

                    Ok(VmExit::Msr { index, write, val })
                }

                // EPT violation (SLAT fault).
                48 => {
                    let gpa = vmread(vmcs::ro::GUEST_PHYSICAL_ADDR_FULL).unwrap();
                    let qual = qualification;
                    let is_read = (qual & 0x1) != 0;
                    let is_write = (qual & 0x2) != 0;

                    let cr0 = vmread(vmcs::guest::CR0).unwrap();
                    let efer = vmread(vmcs::guest::IA32_EFER_FULL).unwrap();
                    let cs_ar = vmread(vmcs::guest::CS_ACCESS_RIGHTS).unwrap();
                    let rip = vmread(vmcs::guest::RIP).unwrap();
                    let guest_cr3 = vmread(vmcs::guest::CR3).unwrap();

                    let cr0_pe = (cr0 & 1) != 0; // CR0.PE (Bit 0)
                    let efer_lma = (efer & (1 << 10)) != 0; // EFER.LMA (Bit 10)
                    let cs_l = ((cs_ar >> 13) & 1) != 0; // CS.L (Bit 13)
                    let cs_db = ((cs_ar >> 14) & 1) != 0; // CS.D/B (Bit 14)

                    // LMA + CS.L => 64-bit; else D/B => 32-bit; else 16-bit.
                    let bitness: u32 = if !cr0_pe {
                        // Real Mode is always 16-bit execution
                        16
                    } else if efer_lma && cs_l {
                        // 64-bit Long Mode
                        64
                    } else if cs_db {
                        // 32-bit Protected / Compatibility Mode
                        32
                    } else {
                        // 16-bit Protected / Compatibility Mode
                        16
                    };

                    let slat = self.slat.read();
                    let instr_gpa =
                        paging::translate_instruction_gpa(&*slat, rip, cr0, guest_cr3, bitness)
                            .expect("Failed to translate Guest RIP");

                    let hpa = slat
                        .translate(instr_gpa)
                        .expect("Failed to translate GPA to HPA");

                    let instr_bytes = slice::from_raw_parts(hpa as *const u8, 15);

                    let mut decoder = iced_x86::Decoder::with_ip(
                        bitness,
                        instr_bytes,
                        rip,
                        iced_x86::DecoderOptions::NONE,
                    );
                    let instruction = decoder.decode();

                    if instruction.is_invalid() {
                        panic!("Failed to decode instruction at SLAT violation");
                    }

                    let decoded = mmio_decode::decode_mmio_access(
                        &instruction,
                        is_read,
                        is_write,
                        &self.guest_registers.gpr,
                    );

                    Ok(VmExit::SlatViolation {
                        gpa,
                        data_read: is_read,
                        data_write: is_write,
                        instruction_fetch: (qual & 0x4) != 0,
                        present: (qual & 0x38) != 0,
                        during_page_walk: (qual & 0x1000) != 0,
                        access_length: decoded.access_length,
                        data: decoded.data,
                        register: decoded.register,
                        instruction_length: decoded.instruction_length,
                    })
                }

                _ => Ok(VmExit::Unknown(reason_full)),
            }
        }
    }

    fn cr(&self, cr: u8) -> u64 {
        match cr {
            0 => unsafe { vmread(vmcs::guest::CR0) }.unwrap(),
            3 => unsafe { vmread(vmcs::guest::CR3) }.unwrap(),
            4 => unsafe { vmread(vmcs::guest::CR4) }.unwrap(),
            _ => panic!("Unknown CR to read from: {}", cr),
        }
    }

    fn set_cr(&self, cr: u8, value: u64) {
        match cr {
            0 => unsafe {
                vmwrite(vmcs::guest::CR0, value).unwrap();
                vmwrite(vmcs::control::CR0_READ_SHADOW, value).unwrap();
            },
            3 => unsafe { vmwrite(vmcs::guest::CR3, value) }.unwrap(),
            4 => unsafe {
                vmwrite(vmcs::guest::CR4, self.vmcs.adjust_cr4(value)).unwrap();
                vmwrite(vmcs::control::CR4_READ_SHADOW, value).unwrap();
            },

            _ => panic!("Unknown CR to read from: {}", cr),
        }
    }

    fn efer_msr(&self) -> u64 {
        unsafe { vmread(vmcs::guest::IA32_EFER_FULL) }.unwrap()
    }

    fn set_efer_msr(&self, value: u64) {
        unsafe { vmwrite(vmcs::guest::IA32_EFER_FULL, value) }.unwrap()
    }

    fn pat_msr(&self) -> u64 {
        unsafe { vmread(vmcs::guest::IA32_PAT_FULL) }.unwrap()
    }

    fn set_pat_msr(&self, value: u64) {
        unsafe { vmwrite(vmcs::guest::IA32_PAT_FULL, value) }.unwrap()
    }

    fn sysenter_cs_msr(&self) -> u64 {
        unsafe { vmread(vmcs::guest::IA32_SYSENTER_CS) }.unwrap()
    }

    fn set_sysenter_cs_msr(&self, value: u64) {
        unsafe { vmwrite(vmcs::guest::IA32_SYSENTER_CS, value) }.unwrap()
    }

    fn sysenter_eip_msr(&self) -> u64 {
        unsafe { vmread(vmcs::guest::IA32_SYSENTER_EIP) }.unwrap()
    }

    fn set_sysenter_eip_msr(&self, value: u64) {
        unsafe { vmwrite(vmcs::guest::IA32_SYSENTER_EIP, value) }.unwrap()
    }

    fn sysenter_esp_msr(&self) -> u64 {
        unsafe { vmread(vmcs::guest::IA32_SYSENTER_ESP) }.unwrap()
    }

    fn set_sysenter_esp_msr(&self, value: u64) {
        unsafe { vmwrite(vmcs::guest::IA32_SYSENTER_ESP, value) }.unwrap()
    }
}

pub struct Vmcs {
    address: u64,
}

impl Vmcs {
    pub fn new() -> Result<Self, HypervisorError> {
        let mut memory_manager = memory_manager().write();
        let vmcs_address = memory_manager.allocate_frame().unwrap().address().as_u64();

        unsafe {
            let page = Page::new(VirtualAddress::new(vmcs_address));
            let frame = Frame::new(PhysicalAddress::new(vmcs_address));
            memory_manager
                .map(
                    MapTarget::CurrentAddressSpace(),
                    Exact(&page, &frame),
                    PageFlags::WRITABLE,
                )
                .unwrap();
        }

        drop(memory_manager);

        let vmcs_region = vmcs_address as *mut CpuVmcs;
        unsafe {
            (*vmcs_region).revision_id = Self::revision_id();

            let status: u8;

            core::arch::asm!(
                "vmclear [{addr}]",
                "setbe {status}",
                addr = in(reg) &vmcs_address,
                status = out(reg_byte) status,
                options(nostack)
            );

            if status != 0 {
                panic!("Error while executing VMCLEAR for new VMCS");
            }
        };

        Ok(Self {
            address: vmcs_address,
        })
    }

    pub fn load(&self) -> Result<(), HypervisorError> {
        let addr_ptr = &self.address as *const u64;
        let status: u8;

        unsafe {
            core::arch::asm!(
                "vmptrld [{addr}]",
                "setbe {status}",
                addr = in(reg) addr_ptr,
                status = out(reg_byte) status,
                options(readonly, nostack, preserves_flags)
            );
        }

        if status != 0 {
            panic!("Error loading VMCS using VMPTRLD");
        }

        Ok(())
    }

    pub fn adjust_controls(&self, msr: u32, requested: u64) -> u64 {
        assert!(
            [
                IA32_VMX_PINBASED_CTLS,
                IA32_VMX_ENTRY_CTLS,
                IA32_VMX_PROCBASED_CTLS,
                IA32_VMX_PROCBASED_CTLS2,
                IA32_VMX_EXIT_CTLS
            ]
            .contains(&msr)
        );

        let msr = unsafe { Msr::new(msr).read() };

        // Intel SDM: allowed-0 (low) bits must be 1; allowed-1 (high) bits may be 1.
        let allowed_0 = msr & 0xFFFF_FFFF;
        let allowed_1 = (msr >> 32) & 0xFFFF_FFFF;

        (requested | allowed_0) & allowed_1
    }

    pub fn adjust_cr0(&self, cr0: u64) -> u64 {
        let fixed0 = unsafe { Msr::new(IA32_VMX_CR0_FIXED0).read() };
        let fixed1 = unsafe { Msr::new(IA32_VMX_CR0_FIXED1).read() };

        let mut cr0 = cr0;
        cr0 |= fixed0;
        cr0 &= fixed1;

        cr0
    }

    pub fn adjust_cr4(&self, cr4: u64) -> u64 {
        let fixed0 = unsafe { Msr::new(IA32_VMX_CR4_FIXED0).read() };
        let fixed1 = unsafe { Msr::new(IA32_VMX_CR4_FIXED1).read() };

        let mut cr4 = cr4;
        cr4 |= fixed0;
        cr4 &= fixed1;

        cr4
    }

    fn revision_id() -> u32 {
        unsafe { (Msr::new(IA32_VMX_BASIC).read() as u32) & 0x7FFF_FFFF }
    }
}

#[repr(C, align(4096))]
struct CpuVmcs {
    pub revision_id: u32,
    pub data: [u8; 4096 - 4],
}

fn reg_idx_to_register(reg_idx: u8) -> iced_x86::Register {
    match reg_idx {
        0 => iced_x86::Register::RAX,
        1 => iced_x86::Register::RCX,
        2 => iced_x86::Register::RDX,
        3 => iced_x86::Register::RBX,
        4 => iced_x86::Register::RSP,
        5 => iced_x86::Register::RBP,
        6 => iced_x86::Register::RSI,
        7 => iced_x86::Register::RDI,
        8 => iced_x86::Register::R8,
        9 => iced_x86::Register::R9,
        10 => iced_x86::Register::R10,
        11 => iced_x86::Register::R11,
        12 => iced_x86::Register::R12,
        13 => iced_x86::Register::R13,
        14 => iced_x86::Register::R14,
        15 => iced_x86::Register::R15,
        _ => unreachable!("Nieprawidłowy indeks rejestru VMX: {}", reg_idx),
    }
}
