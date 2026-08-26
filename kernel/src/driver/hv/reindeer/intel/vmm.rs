use alloc::sync::Arc;

use raw_cpuid::CpuId;
use spin::rwlock::RwLock;
use x86_64::registers::{
    control::{Cr4, Cr4Flags},
    model_specific::Msr,
};

use crate::{
    driver::hv::reindeer::{
        HostPhysAddr, HypervisorError, VirtualMachineMonitor, VmHandle, VmOptions,
        intel::{IA32_FEATURE_CONTROL, IA32_VMX_BASIC, vm::IntelVirtualMachine},
    },
    subsystem::memory::{
        Exact, Frame, MapTarget, PAGE_SIZE, Page, PageFlags, PhysicalAddress, VirtualAddress,
        memory_manager,
    },
};

/// Intel VT-x implementation of the Virtual Machine Monitor.
pub struct IntelVirtualMachineMonitor {}

impl VirtualMachineMonitor for IntelVirtualMachineMonitor {
    /// Initializes the virtual machine monitor and enables VMX on the current host CPU.
    fn initialize(&self) -> Result<(), HypervisorError> {
        let cpuid = CpuId::new();

        // Check if VMX is supported
        if !cpuid.get_feature_info().unwrap().has_vmx() {
            return Err(HypervisorError::PlatformNotSupported);
        }

        // Enable VMX (Virtual Machine Extensions).
        unsafe { Cr4::write(Cr4::read() | Cr4Flags::VIRTUAL_MACHINE_EXTENSIONS) };

        let feature_control = unsafe { Msr::new(IA32_FEATURE_CONTROL).read() };
        assert_ne!(feature_control & 1, 0); // @TODO: What about this bit later?

        // @TODO: For each CPU
        VmxOnRegion::initialize_for_current_cpu()?;

        Ok(())
    }

    /// Creates a new Intel VT-x virtual machine instance with the specified options.
    fn create_vm(&self, vm_options: &VmOptions) -> Result<VmHandle, HypervisorError> {
        let vm = IntelVirtualMachine::new(vm_options.clone())?;

        #[allow(clippy::arc_with_non_send_sync)]
        Ok(Arc::new(RwLock::new(vm)))
    }
}

/// Memory region used by the VMXON instruction to enable VMX operation. Must be 4KB aligned.
#[repr(C, align(4096))]
pub struct VmxOnRegion {
    /// VMCS revision identifier required by the processor.
    pub revision_id: u32,

    /// VMXON region data reserved for use by the logical processor.
    pub data: [u8; PAGE_SIZE - size_of::<u32>()],
}

impl VmxOnRegion {
    /// Allocates and initializes the VMXON region, then enables VMX operation on the current CPU.
    pub fn initialize_for_current_cpu() -> Result<HostPhysAddr, HypervisorError> {
        let mut memory_manager = memory_manager().write();
        let region = memory_manager.allocate_frame().unwrap().address();

        unsafe {
            let page = Page::new(VirtualAddress::new(region.as_u64()));
            let frame = Frame::new(PhysicalAddress::new(region.as_u64()));
            memory_manager
                .map(
                    MapTarget::CurrentAddressSpace(),
                    Exact(&page, &frame),
                    PageFlags::WRITABLE,
                )
                .unwrap();

            let revision_id = Msr::new(IA32_VMX_BASIC).read() as u32 & 0x7FFF_FFFF;

            (*(region.as_u64() as *mut VmxOnRegion)).revision_id = revision_id;

            Self::vmxon(region.as_u64() as *const u64).map(|_| region.as_u64())
        }
    }

    /// Executes the VMXON instruction using the provided region pointer.
    unsafe fn vmxon(vmxon_region_ptr: *const u64) -> Result<(), HypervisorError> {
        let rflags: u64;

        unsafe {
            core::arch::asm!(
                "vmxon [{0}]",
                "pushfq",
                "pop {1}",
                in(reg) &vmxon_region_ptr,
                lateout(reg) rflags,
                options(readonly, nostack, preserves_flags)
            );
        }

        if (rflags & 0x41) != 0 {
            panic!("VMXON failed! RFLAGS: {:#x}", rflags);
        }

        Ok(())
    }
}
