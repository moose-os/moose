use alloc::sync::Arc;

use spin::rwlock::RwLock;

use crate::driver::hv::reindeer::{
    HypervisorError, SlatManager, VcpuHandle, VirtualMachine, VmOptions,
    guest_machine::GuestMachineState,
    intel::{ept::IntelEpt, tsc, vcpu::IntelVcpu},
    setup,
};

pub struct IntelVirtualMachine {
    state: GuestMachineState,
}

impl IntelVirtualMachine {
    pub fn new(options: VmOptions) -> Result<Self, HypervisorError> {
        let mut ept = IntelEpt::new();
        let memory_descriptors = setup::default_pc_memory_map(options.mem_size as usize);
        setup::map_guest_ram(&mut ept, &memory_descriptors)?;
        setup::load_boot_source(&ept, &options, &memory_descriptors, setup::HYPERCALL_VMCALL)?;

        let slat: Arc<RwLock<dyn SlatManager>> = Arc::new(RwLock::new(ept));
        let guest = GuestMachineState::attach_devices(
            options,
            slat,
            memory_descriptors,
            tsc::tsc_scaling_supported(),
        )?;
        setup::write_bda_com_ports(
            &*guest.slat.read(),
            &guest.system_bus.read().uart_io_bases(),
        );
        guest.build_acpi();

        Ok(Self { state: guest })
    }
}

impl VirtualMachine for IntelVirtualMachine {
    fn add_vcpu(&mut self, id: u32) -> Result<VcpuHandle, HypervisorError> {
        let state = self.state()?;
        let vcpu = IntelVcpu::new(
            &state.options,
            state.slat.clone(),
            state.pic.clone(),
            state.hpet.clone(),
            id as usize,
            state.lapic.clone(),
            state.pit.clone(),
            state.guest_clock.clone(),
        )?;

        vcpu.initialize(
            &state.options,
            true,
            state.apic_access_page.address().as_u64(),
        )
        .unwrap();

        let vcpu_handle = Arc::new(RwLock::new(vcpu)) as VcpuHandle;
        Ok(vcpu_handle)
    }

    fn memory_manager(&mut self) -> Arc<RwLock<dyn SlatManager>> {
        self.state().unwrap().slat.clone()
    }

    fn flush_remote_tlbs(&self) {}

    fn state(&self) -> Result<&GuestMachineState, HypervisorError> {
        Ok(&self.state)
    }

    fn state_mut(&mut self) -> Result<&mut GuestMachineState, HypervisorError> {
        Ok(&mut self.state)
    }
}
