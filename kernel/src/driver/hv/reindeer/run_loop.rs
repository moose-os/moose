//! Shared guest vCPU execution loop.

use core::arch::asm;

use iced_x86::Register;
use x86::{
    cpuid::native_cpuid::cpuid_count,
    msr::{
        IA32_BIOS_SIGN_ID, IA32_EFER, IA32_MCG_CAP, IA32_MISC_ENABLE, IA32_MTRRCAP, IA32_PAT,
        MSR_PLATFORM_INFO,
    },
};
use x86_64::registers::model_specific::Msr;

use crate::driver::{
    apic::IA32_APIC_BASE_MSR,
    hv::reindeer::{
        CpuExecutionMode, HypervisorError, MSR_IA32_APERF, MSR_IA32_ARCH_CAPABILITIES,
        MSR_IA32_FEATURE_CONTROL, MSR_IA32_MISC_FEATURES_ENABLE, MSR_IA32_MPERF,
        MSR_IA32_MTRR_DEF_TYPE, MSR_IA32_RTIT_CTL, MSR_IA32_SYSENTER_CS, MSR_IA32_SYSENTER_EIP,
        MSR_IA32_SYSENTER_ESP, MSR_IA32_TIME_STAMP_COUNTER, MSR_MTRR_FIX4K_C0000,
        MSR_MTRR_FIX16K_A0000, MSR_MTRR_GAP_27F, MSR_MTRR_PHYS_BASE_MASK_END,
        MSR_MTRR_PHYS_BASE_MASK_START, MSR_RAPL_RANGE_END, MSR_RAPL_RANGE_START, MSR_SMI_COUNT,
        MTRR_PAT_PACKED_UC, MTRR_PAT_PACKED_WB, MTRR_PAT_PACKED_WP, Vcpu, VcpuHandle, VmExit,
        VmHandle,
        guest::{
            clock::GuestClock,
            registers::{CpuState, RegisterState, X86RegisterOperations},
        },
    },
};

/// Action to be taken by the run loop after handling a VM-exit.
enum ExitAction {
    /// Skip the faulting instruction by advancing the instruction pointer.
    AdvanceRip,

    /// Yield execution back to the host, temporarily suspending the vCPU loop.
    Yield,

    /// Immediately resume guest execution without advancing the instruction pointer.
    Resume,
}

/// Context provided to handlers processing a VM-exit.
struct ExitContext<'a> {
    /// Handle to the virtual machine instance.
    pub vm: &'a VmHandle,

    /// Handle to the vCPU that triggered the exit.
    pub vcpu: &'a VcpuHandle,
}

/// Main guest vCPU dispatch loop: run -> decode exit -> emulate -> repeat.
pub fn run_guest_loop(vm: VmHandle, vcpu: VcpuHandle) -> Result<(), HypervisorError> {
    vm.read()
        .state()?
        .lapic
        .write()
        .initialize(vcpu.read().id(), vcpu.read().pic());

    let mut exit_context = ExitContext {
        vm: &vm,
        vcpu: &vcpu,
    };

    loop {
        let exit_reason = vcpu.write().run()?;

        let action = match exit_reason {
            VmExit::ExternalInterrupt => handle_external_interrupt(&exit_context)?,
            VmExit::Hypercall => handle_hypercall(&mut exit_context)?,
            VmExit::Cpuid => handle_cpuid(&exit_context)?,
            VmExit::Hlt => handle_hlt(&exit_context)?,
            VmExit::Io {
                port,
                write,
                len,
                data,
            } => handle_io(&exit_context, port, write, len, data)?,

            VmExit::Exception {
                vector: _,
                error_code: _,
            } => ExitAction::Resume,

            VmExit::CrAccess {
                cr,
                write,
                value,
                register,
            } => handle_cr_access(&exit_context, cr, write, value, register)?,

            VmExit::Msr { index, write, val } => {
                handle_msr_access(&exit_context, index, write, val)?
            }

            VmExit::SlatViolation {
                gpa,
                data_read,
                data_write,
                instruction_fetch: _,
                present: _,
                during_page_walk: _,
                access_length,
                register,
                data,
                instruction_length,
            } => handle_slat_violation(
                &exit_context,
                gpa,
                data_read,
                data_write,
                access_length as u8,
                register,
                data,
                instruction_length,
            )?,

            VmExit::AdvanceRip => ExitAction::AdvanceRip,
            VmExit::InterruptWindow => ExitAction::Resume,

            unknown => panic!("Unknown VmExit: {:?}", unknown),
        };

        match action {
            ExitAction::AdvanceRip => vcpu.write().advance_rip(),
            ExitAction::Resume => {}
            ExitAction::Yield => {} //yield_to_scheduler(),
        }
    }
}

fn handle_external_interrupt(_context: &ExitContext) -> Result<ExitAction, HypervisorError> {
    unsafe { asm!("sti") }

    Ok(ExitAction::Resume)
}

fn handle_hypercall(context: &mut ExitContext) -> Result<ExitAction, HypervisorError> {
    let execution_mode = context.vcpu.clone().read().execution_mode();

    match execution_mode {
        CpuExecutionMode::RealMode => context
            .vm
            .write()
            .state_mut()?
            .handle_bios_call(context.vcpu.clone())?,

        _ => panic!("Got HYPERCALL/VMCALL in execution mode other than 16-bit!"),
    }

    Ok(ExitAction::Resume) // RIP is being handled in `handle_bios_call`
}

fn handle_cpuid(context: &ExitContext) -> Result<ExitAction, HypervisorError> {
    const CPUID_PASSTHROUGH_LEAFS: [CpuLeaf; 16] = [
        CpuLeaf::BasicVendorInfo,
        CpuLeaf::ThermalPowerManagement,
        CpuLeaf::ExtendedControlRegisterStates,
        CpuLeaf::ResourceDirectorTechnologyMon,
        CpuLeaf::ResourceDirectorTechnologyAlloc,
        CpuLeaf::SoftwareGuardExtensions,
        CpuLeaf::ExtendedTopology,
        CpuLeaf::ExtendedMaxFunction,
        CpuLeaf::ExtendedProcessorInfo,
        CpuLeaf::VirtualPhysicalAddressSize,
        CpuLeaf::ProcessorBrandString1,
        CpuLeaf::ProcessorBrandString2,
        CpuLeaf::ProcessorBrandString3,
        CpuLeaf::DeterministicCacheParams,
        CpuLeaf::ArchitecturalPerformanceMon,
        CpuLeaf::CacheDescriptors,
    ];

    let mut lock = context.vcpu.write();
    let regs = lock.gpr();

    let leaf = regs.gpr.rax.low_u32();
    let subleaf = regs.gpr.rcx.low_u32();

    let mut res = cpuid_count(leaf, subleaf);

    if (0x40000000..0x40010000).contains(&leaf) {
        // Unsupported hypervisor leaves.
        res.eax = 0;
        res.ebx = 0;
        res.ecx = 0;
        res.edx = 0;
    } else if let Ok(parsed_leaf) = CpuLeaf::try_from(leaf) {
        if !CPUID_PASSTHROUGH_LEAFS.contains(&parsed_leaf) {
            match parsed_leaf {
                CpuLeaf::ProcessorInfo => {
                    res.ecx |= (1 << 31) | (1 << 30); // Hypervisor Present | RDRAND
                    res.ecx &= !((1 << 24) | // TSC Deadline
                                         (1 << 0)  | // SSE3
                                         (1 << 19) | // SSE4_1
                                         (1 << 20) | // SSE4_2
                                         (1 << 26) | // XSAVE
                                         (1 << 27) | // OSXSAVE
                                         (1 << 28) | // AVX
                                         (1 << 29)); // F16C

                    res.ebx &= !(0xFF << 24); // Clear initial APIC ID.
                }
                CpuLeaf::ExtendedFeatures => {
                    if subleaf == 0 {
                        res.ebx |= (1 << 18) | (1 << 10); // RDSEED | INVPCID

                        res.ebx &= !((1 << 5)  | // AVX2
                                             (1 << 16) | // AVX512F
                                             (1 << 17) | // AVX512DQ
                                             (1 << 25) | // IntelPT
                                             (1 << 26) | (1 << 27) | (1 << 28) | (1 << 30) | (1 << 31)); // Misc. AVX-512 feature bits.

                        res.edx &= !(1 << 26); // Speculative execution mitigation
                    }
                }
                CpuLeaf::TimeStampCounterInfo => {
                    let (eax, ebx, ecx, edx) =
                        context.vm.read().state()?.guest_clock.cpuid_leaf_15();

                    res.eax = eax;
                    res.ebx = ebx;
                    res.ecx = ecx;
                    res.edx = edx;
                }
                CpuLeaf::ProcessorFrequencyInfo => {
                    let mhz = (context.vm.read().state()?.guest_clock.tsc_hz() / 1_000_000) as u32;
                    res.eax = mhz;
                    res.ebx = mhz;
                    res.ecx = mhz;
                    res.edx = 0;
                }
                CpuLeaf::AdvancedPowerManagement => {
                    res.edx |= 1 << 8;
                }
                CpuLeaf::HypervisorLimit
                | CpuLeaf::HypervisorXenSpecific
                | CpuLeaf::HypervisorXenSpecific2
                | CpuLeaf::ProcessorTraceInfo => {
                    res.eax = 0;
                    res.ebx = 0;
                    res.ecx = 0;
                    res.edx = 0;
                }
                unknown => panic!("Guest queried unknown CPUID leaf={:?}", unknown),
            }
        }
    } else {
        panic!(
            "Guest queried unknown CPUID leaf={:#x} sub={:#x}",
            leaf, subleaf
        );
    }

    regs.gpr.rax = res.eax as u64;
    regs.gpr.rbx = res.ebx as u64;
    regs.gpr.rcx = res.ecx as u64;
    regs.gpr.rdx = res.edx as u64;

    Ok(ExitAction::AdvanceRip)
}

fn handle_io(
    context: &ExitContext,
    port: u16,
    write: bool,
    len: u8,
    data: u64,
) -> Result<ExitAction, HypervisorError> {
    let mut lock = context.vcpu.write();
    let cpu_id = lock.id();
    let regs = lock.gpr();

    match port {
        // --- POST Code Port ---
        0x80 => {}

        // --- FPU / Math Coprocessor Ports ---
        0xF0 | 0xF1 => {
            if write {
                debug!("IO Write {:#x}: FPU Reset/Clear (ignored)", port);
            } else {
                warn!("IO Read from FPU port {:#x} - returning dummy 0", port);
                set_register_by_len(regs, 0, len);
            }
        }

        // Unclaimed port: dispatch via system bus.
        _ => {
            let vm = context.vm.read();
            let bus = vm.state()?.system_bus.read();

            if write {
                bus.dispatch_io_write(cpu_id, port, len, data);
            } else {
                let return_value = bus.dispatch_io_read(cpu_id, port, len);

                set_register_by_len(regs, return_value, len);
            }
        }
    }

    Ok(ExitAction::AdvanceRip)
}

fn handle_hlt(context: &ExitContext) -> Result<ExitAction, HypervisorError> {
    let cpu_id = context.vcpu.read().id();
    let vm = context.vm.read();
    let state = vm.state()?;

    state.pit.read().check_timer();
    state.lapic.read().check_lapic_timer(cpu_id);

    let mut lock = context.vcpu.write();
    let gpr = lock.gpr();
    gpr.gpr.rip = gpr.gpr.rip.wrapping_add(1); // HLT opcode (0xF4).

    Ok(ExitAction::Yield)
}

fn handle_cr_access(
    context: &ExitContext,
    cr: u8,
    write: bool,
    value: u64,
    register: Option<Register>,
) -> Result<ExitAction, HypervisorError> {
    assert_ne!(cr, 1); // The CPU should raise #UD here.

    let mut vcpu = context.vcpu.write();

    if write {
        vcpu.set_cr(cr, value);
    } else {
        let Some(reg) = register else { unreachable!() };
        let value = vcpu.cr(cr);

        vcpu.gpr().gpr.set(reg, value);
    }

    Ok(ExitAction::AdvanceRip)
}

fn handle_msr_access(
    context: &ExitContext,
    index: u32,
    write: bool,
    value: u64,
) -> Result<ExitAction, HypervisorError> {
    let mut vcpu = context.vcpu.write();
    let vm = context.vm.read();

    if handle_utility_msrs(
        index,
        write,
        value,
        &mut vcpu.gpr().gpr,
        &vm.state()?.guest_clock,
    ) || handle_architectural_msrs(index, write, value, &mut *vcpu)
    {
        Ok(ExitAction::AdvanceRip)
    } else {
        panic!("Unknown MSR: 0x{:x}", index)
    }
}

#[allow(clippy::too_many_arguments)]
fn handle_slat_violation(
    context: &ExitContext,
    gpa: u64,
    data_read: bool,
    data_write: bool,
    access_length: u8,
    register: Option<Register>,
    data: Option<u64>,
    instruction_length: usize,
) -> Result<ExitAction, HypervisorError> {
    let mut cpu = context.vcpu.write();
    let cpu_id = cpu.id();
    let gpr = cpu.gpr();

    if data_read {
        let value = context
            .vm
            .read()
            .state()?
            .system_bus
            .read()
            .dispatch_mmio_read(cpu_id, gpa, access_length, register.unwrap(), gpr);

        // Unclaimed MMIO: return all-ones so
        // guest probes (e.g. 0xFE001818) don't kill the hypervisor.
        let value = value.unwrap_or_else(|| {
            log::debug!("Unclaimed MMIO read gpa={:#x} len={}", gpa, access_length);

            match access_length {
                1 => 0xFF,
                2 => 0xFFFF,
                4 => 0xFFFF_FFFF,
                _ => 0xFFFF_FFFF_FFFF_FFFF,
            }
        });

        gpr.gpr.set(register.unwrap(), value);
    } else if data_write {
        let success = context
            .vm
            .read()
            .state()?
            .system_bus
            .write()
            .dispatch_mmio_write(cpu_id, gpa, access_length, data.unwrap());

        if !success {
            log::debug!(
                "Unclaimed MMIO write gpa={:#x} len={} val={:#x}",
                gpa,
                access_length,
                data.unwrap_or(0)
            );
        }
    }

    // VM-exit instruction length is sometimes wrong.
    gpr.gpr.rip += instruction_length as u64;

    Ok(ExitAction::Resume)
}

#[inline]
fn set_register_by_len(regs: &mut CpuState, val: u64, len: u8) {
    match len {
        1 => regs.gpr.rax.set_low_u8(val as u8),
        2 => regs.gpr.rax.set_low_u16(val as u16),
        4 => regs.gpr.rax.set_low_u32(val as u32),
        8 => regs.gpr.rax = val,
        _ => debug_assert!(false, "Invalid length of IO instruction: {}", len),
    }
}

fn write_edx_eax(gpr: &mut RegisterState, value: u64) {
    gpr.rax = value & 0xFFFF_FFFF;
    gpr.rdx = value >> 32;
}

/// Handle utility guest MSR accesses. Returns `true` when the index was recognized.
pub fn handle_utility_msrs(
    index: u32,
    write: bool,
    val: u64,
    gpr: &mut RegisterState,
    clock: &GuestClock,
) -> bool {
    match index {
        // --------------------------------------------------------------------
        // Processor Features & Debugging
        // --------------------------------------------------------------------
        MSR_IA32_RTIT_CTL => {
            if write {
                panic!("Write to read-only register IA32_RTIT_CTL requires #GP injection");
            }

            // Report Intel PT (Processor Trace) as unsupported (0).
            write_edx_eax(gpr, 0);

            true
        }

        MSR_IA32_FEATURE_CONTROL => {
            if write {
                panic!("Write to read-only IA32_FEATURE_CONTROL requires #GP injection");
            }

            // Bit 0 = Lock bit (1). VMX outside SMX disabled. Prevents guest from trying nested VMX.
            write_edx_eax(gpr, 1);

            true
        }

        IA32_MISC_ENABLE => {
            if write {
                panic!("Write to IA32_MISC_ENABLE is not supported");
            }

            // Pass-through host's MISC_ENABLE settings so the guest sees supported features (e.g., Fast String).
            let host_misc = unsafe { Msr::new(IA32_MISC_ENABLE).read() };
            write_edx_eax(gpr, host_misc);

            true
        }

        IA32_BIOS_SIGN_ID => {
            if write {
                log::debug!("Ignoring guest write to IA32_BIOS_SIGN_ID (microcode update trigger)");
            } else {
                // Return microcode revision 0 to signal no microcode update is loaded.
                write_edx_eax(gpr, 0);
            }

            true
        }

        MSR_IA32_ARCH_CAPABILITIES => {
            if write {
                panic!("Write to read-only IA32_ARCH_CAPABILITIES");
            }

            // 0x16B advertises hardware mitigation against Meltdown, Spectre v2, MDS, etc.
            write_edx_eax(gpr, 0x16B);

            true
        }

        IA32_MCG_CAP => {
            if write {
                panic!("Write to read-only IA32_MCG_CAP");
            }

            // Report 0 Machine Check Banks supported.
            write_edx_eax(gpr, 0);

            true
        }

        // --------------------------------------------------------------------
        // Clocks, Timing & Performance
        // --------------------------------------------------------------------
        MSR_IA32_TIME_STAMP_COUNTER => {
            if write {
                log::debug!("Ignoring guest write to IA32_TIME_STAMP_COUNTER");
            } else {
                write_edx_eax(gpr, clock.now_tsc());
            }

            true
        }

        MSR_IA32_MPERF | MSR_IA32_APERF => {
            if write {
                log::debug!(
                    "Ignoring write to IA32_{}PERF",
                    if index == MSR_IA32_MPERF { "M" } else { "A" }
                );
            } else {
                // Return guest TSC for both so the ratio (APERF/MPERF) = 1.0 (constant 100% nominal frequency).
                write_edx_eax(gpr, clock.now_tsc());
            }

            true
        }

        MSR_SMI_COUNT => {
            if write {
                panic!("Write to read-only MSR_SMI_COUNT");
            }

            // Report zero SMI interrupts encountered.
            write_edx_eax(gpr, 0);

            true
        }

        // --------------------------------------------------------------------
        // System Architecture & Local APIC
        // --------------------------------------------------------------------
        IA32_APIC_BASE_MSR => {
            if write {
                panic!("Write to IA32_APIC_BASE_MSR is not supported");
            }

            // Base Address: 0xFEE0_0000 | Bit 8 (BSP) | Bit 11 (APIC Global Enable)
            let apic_base_val: u64 = 0xFEE0_0000 | (1 << 8) | (1 << 11);
            write_edx_eax(gpr, apic_base_val);

            true
        }

        // --------------------------------------------------------------------
        // MTRR (Memory Type Range Registers) Probes & Mocking
        // --------------------------------------------------------------------
        IA32_MTRRCAP => {
            if write {
                panic!("Write to read-only IA32_MTRRCAP");
            }

            // Report 0 variable range MTRRs supported.
            write_edx_eax(gpr, 0x500);

            true
        }

        mtrr @ MSR_MTRR_PHYS_BASE_MASK_START..=MSR_MTRR_PHYS_BASE_MASK_END if !write => {
            let value = if mtrr & 1 == 0 { 0x6 } else { 0x0 };

            write_edx_eax(gpr, value);

            true
        }

        // Standard fixed-range MTRRs mapped to Write-Back (WB = 0x06).
        0x250 | 0x258 | 0x269..=0x26D => {
            if write {
                panic!("Write to fixed MTRR range");
            }

            gpr.rax.set_low_u32(MTRR_PAT_PACKED_WB);
            gpr.rdx.set_low_u32(MTRR_PAT_PACKED_WB);

            true
        }

        // Legacy Video Buffer Region (0xA0000-0xBFFFF) mapped to Uncacheable (UC = 0x01).
        MSR_MTRR_FIX16K_A0000 => {
            if write {
                panic!("Write to fixed MTRR 0x259");
            }

            gpr.rax.set_low_u32(MTRR_PAT_PACKED_UC);
            gpr.rdx.set_low_u32(MTRR_PAT_PACKED_UC);

            true
        }

        // Upper ROM / Extension regions (0xC0000+) mapped to Write-Protect (WP = 0x05).
        MSR_MTRR_FIX4K_C0000 | 0x26E | 0x26F => {
            if write {
                panic!("Write to fixed MTRR ROM region");
            }

            gpr.rax.set_low_u32(MTRR_PAT_PACKED_WP);
            gpr.rdx.set_low_u32(MTRR_PAT_PACKED_WP);

            true
        }

        MSR_IA32_MTRR_DEF_TYPE => {
            if write {
                // Ignore guest write.
            } else {
                write_edx_eax(gpr, 0x0c06);
            }

            true
        }

        MSR_MTRR_GAP_27F => {
            if write {
                log::debug!(
                    "Ignoring guest write to unused MTRR gap register 0x27F val={:#x}",
                    val
                );
            } else {
                write_edx_eax(gpr, 0);
            }

            true
        }

        // --------------------------------------------------------------------
        // Power Management & RAPL (Running Average Power Limit)
        // --------------------------------------------------------------------
        MSR_RAPL_RANGE_START..=MSR_RAPL_RANGE_END => {
            if write {
                log::debug!("Ignoring write to RAPL MSR {:#x} val={:#x}", index, val);
            } else {
                // Return 0 so guest power management tools do not crash.
                write_edx_eax(gpr, 0);
            }

            true
        }
        _ => false,
    }
}

/// Handle architectural guest MSR accesses. Returns `true` when the index was recognized.
pub fn handle_architectural_msrs(index: u32, write: bool, value: u64, vcpu: &mut dyn Vcpu) -> bool {
    match index {
        MSR_PLATFORM_INFO => {
            if write {
                // Ignore guest write.
            } else {
                write_edx_eax(&mut vcpu.gpr().gpr, 0);
            }
        }
        // PAT defines memory caching behavior for pages (WB, WT, UC, etc.).
        IA32_PAT => {
            if write {
                vcpu.set_pat_msr(value);
            } else {
                let pat = vcpu.pat_msr();

                write_edx_eax(&mut vcpu.gpr().gpr, pat);
            }
        }

        // Target Code Segment for the SYSENTER instruction.
        MSR_IA32_SYSENTER_CS => {
            if write {
                vcpu.set_sysenter_cs_msr(value);
            } else {
                let cs = vcpu.sysenter_cs_msr();

                write_edx_eax(&mut vcpu.gpr().gpr, cs);
            }
        }

        // Target Stack Pointer for the SYSENTER instruction.
        MSR_IA32_SYSENTER_ESP => {
            if write {
                vcpu.set_sysenter_esp_msr(value);
            } else {
                let esp = vcpu.sysenter_esp_msr();

                write_edx_eax(&mut vcpu.gpr().gpr, esp);
            }
        }

        // Target Instruction Pointer for the SYSENTER instruction.
        MSR_IA32_SYSENTER_EIP => {
            if write {
                vcpu.set_sysenter_eip_msr(value);
            } else {
                let eip = vcpu.sysenter_eip_msr();

                write_edx_eax(&mut vcpu.gpr().gpr, eip);
            }
        }

        // Controls Ring 3 MWAIT
        MSR_IA32_MISC_FEATURES_ENABLE => {
            if write {
                log::trace!("Wanted to write to read-only MSR FEATURES_ENABLE",);
            } else {
                write_edx_eax(&mut vcpu.gpr().gpr, unsafe {
                    Msr::new(MSR_IA32_MISC_FEATURES_ENABLE).read()
                });
            }
        }

        // Controls Long Mode (LME/LMA), NX-bit, and SYSCALL/SYSRET instructions.
        IA32_EFER => {
            if write {
                vcpu.set_efer_msr(value);
            } else {
                let efer = vcpu.efer_msr();

                write_edx_eax(&mut vcpu.gpr().gpr, efer);
            }
        }

        _ => return false,
    }

    true
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub(crate) enum CpuLeaf {
    BasicVendorInfo = 0x0000_0000,
    ProcessorInfo = 0x0000_0001,
    CacheDescriptors = 0x0000_0002,
    ProcessorSerialNumber = 0x0000_0003,
    DeterministicCacheParams = 0x0000_0004,
    MonitorMwaitParams = 0x0000_0005,
    ThermalPowerManagement = 0x0000_0006,
    ExtendedFeatures = 0x0000_0007,
    DirectCacheAccessInfo = 0x0000_0009,
    ArchitecturalPerformanceMon = 0x0000_000A,
    ExtendedTopology = 0x0000_000B,
    ExtendedControlRegisterStates = 0x0000_000D,
    ResourceDirectorTechnologyMon = 0x0000_000F,
    ResourceDirectorTechnologyAlloc = 0x0000_0010,
    SoftwareGuardExtensions = 0x0000_0012,
    ProcessorTraceInfo = 0x0000_0014,
    TimeStampCounterInfo = 0x0000_0015,
    ProcessorFrequencyInfo = 0x0000_0016,
    SoCVendorAttribute = 0x0000_0017,
    DeterministicAddressTranslation = 0x0000_0018,
    V2ExtendedTopology = 0x0000_001F,

    HypervisorLimit = 0x4000_0000,
    HypervisorSignature = 0x4000_0001,
    HypervisorFeatures = 0x4000_0002,
    HypervisorRecommendations = 0x4000_0003,
    HypervisorXenSpecific = 0x4000_0100,
    HypervisorXenSpecific2 = 0x4000_0200,

    ExtendedMaxFunction = 0x8000_0000,
    ExtendedProcessorInfo = 0x8000_0001,
    ProcessorBrandString1 = 0x8000_0002,
    ProcessorBrandString2 = 0x8000_0003,
    ProcessorBrandString3 = 0x8000_0004,
    L1CacheIdentifiers = 0x8000_0005,
    L2CacheIdentifiers = 0x8000_0006,
    AdvancedPowerManagement = 0x8000_0007,
    VirtualPhysicalAddressSize = 0x8000_0008,
    SVMCapabilities = 0x8000_000A, // AMD specific
    InstructionOptimizations = 0x8000_0019,
    Tlb1GPageIdentifiers = 0x8000_001A,
    PerformanceOptimization = 0x8000_001B,
    HostPhysicalAddressSize = 0x8000_001F,
}

impl TryFrom<u32> for CpuLeaf {
    type Error = u32;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0x0000_0000 => Ok(Self::BasicVendorInfo),
            0x0000_0001 => Ok(Self::ProcessorInfo),
            0x0000_0002 => Ok(Self::CacheDescriptors),
            0x0000_0003 => Ok(Self::ProcessorSerialNumber),
            0x0000_0004 => Ok(Self::DeterministicCacheParams),
            0x0000_0005 => Ok(Self::MonitorMwaitParams),
            0x0000_0006 => Ok(Self::ThermalPowerManagement),
            0x0000_0007 => Ok(Self::ExtendedFeatures),
            0x0000_0009 => Ok(Self::DirectCacheAccessInfo),
            0x0000_000A => Ok(Self::ArchitecturalPerformanceMon),
            0x0000_000B => Ok(Self::ExtendedTopology),
            0x0000_000D => Ok(Self::ExtendedControlRegisterStates),
            0x0000_000F => Ok(Self::ResourceDirectorTechnologyMon),
            0x0000_0010 => Ok(Self::ResourceDirectorTechnologyAlloc),
            0x0000_0012 => Ok(Self::SoftwareGuardExtensions),
            0x0000_0014 => Ok(Self::ProcessorTraceInfo),
            0x0000_0015 => Ok(Self::TimeStampCounterInfo),
            0x0000_0016 => Ok(Self::ProcessorFrequencyInfo),
            0x0000_0017 => Ok(Self::SoCVendorAttribute),
            0x0000_0018 => Ok(Self::DeterministicAddressTranslation),
            0x0000_001F => Ok(Self::V2ExtendedTopology),

            0x4000_0000 => Ok(Self::HypervisorLimit),
            0x4000_0001 => Ok(Self::HypervisorSignature),
            0x4000_0002 => Ok(Self::HypervisorFeatures),
            0x4000_0003 => Ok(Self::HypervisorRecommendations),
            0x4000_0100 => Ok(Self::HypervisorXenSpecific),
            0x4000_0200 => Ok(Self::HypervisorXenSpecific2),

            0x8000_0000 => Ok(Self::ExtendedMaxFunction),
            0x8000_0001 => Ok(Self::ExtendedProcessorInfo),
            0x8000_0002 => Ok(Self::ProcessorBrandString1),
            0x8000_0003 => Ok(Self::ProcessorBrandString2),
            0x8000_0004 => Ok(Self::ProcessorBrandString3),
            0x8000_0005 => Ok(Self::L1CacheIdentifiers),
            0x8000_0006 => Ok(Self::L2CacheIdentifiers),
            0x8000_0007 => Ok(Self::AdvancedPowerManagement),
            0x8000_0008 => Ok(Self::VirtualPhysicalAddressSize),
            0x8000_000A => Ok(Self::SVMCapabilities),
            0x8000_0019 => Ok(Self::InstructionOptimizations),
            0x8000_001A => Ok(Self::Tlb1GPageIdentifiers),
            0x8000_001B => Ok(Self::PerformanceOptimization),
            0x8000_001F => Ok(Self::HostPhysicalAddressSize),

            unknown => Err(unknown),
        }
    }
}
