//! Backend-neutral guest machine state (devices, memory map, interrupt controllers).
//!
//! Intel and AMD backends share this structure; only vCPU run/exit handling differs.

use alloc::{format, sync::Arc, vec::Vec};
use core::{ptr, range::RangeInclusive};

use spin::rwlock::RwLock;

use crate::{
    driver::hv::reindeer::{
        HypervisorError, SlatManager, VmOptions,
        acpi::{
            AcpiTablesBuilder, COMPILER_ID, OEM_ID, OEM_TABLE_ID,
            aml::{AmlBuilder, AmlOp},
        },
        device::{
            DeviceContext, SystemBus,
            interrupt::{
                io_apic::VirtualIoApic, lapic::LocalApicDevice,
                pic::ProgrammableInterruptControllerDevice,
            },
            legacy::{
                acpi_pm::VirtualAcpiPm,
                hpet::{HPET_MMIO_BASE, VirtualHpet},
                pit::VirtualPit,
                pm_timer::VirtualPmTimer,
                speaker::VirtualSpeaker,
            },
        },
        guest::clock::GuestClock,
    },
    subsystem::memory::{
        Exact, Frame, MapTarget, Page, PageFlags, PhysicalAddress, VirtualAddress, memory_manager,
    },
};

/// E820 memory region descriptor used during guest RAM setup.
#[derive(Clone, Copy)]
pub struct VirtualMachineMemoryDescriptor {
    pub range: RangeInclusive<u64>,
    pub memory_type: MemoryDescriptorType,
    pub allocate: bool,
}

/// ACPI / firmware memory typing for e820 entries.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoryDescriptorType {
    AvailableToOs = 1,
    Reserved = 2,
    AcpiReclaim = 3,
    AcpiNvsMemory = 4,
}

/// Shared per-VM state: SLAT, interrupt controllers, emulated devices, and boot options.
///
/// Backend-specific code (VMCS / VMCB) holds a vCPU handle and dereferences this for I/O,
/// MMIO, ACPI, and interrupt delivery.
#[derive(Clone)]
pub struct GuestMachineState {
    pub options: VmOptions,
    pub slat: Arc<RwLock<dyn SlatManager>>,
    pub memory_descriptors: Vec<VirtualMachineMemoryDescriptor>,
    pub pic: Arc<RwLock<ProgrammableInterruptControllerDevice>>,
    pub system_bus: Arc<RwLock<SystemBus>>,
    pub pit: Arc<RwLock<VirtualPit>>,
    pub io_apic: Arc<RwLock<VirtualIoApic>>,
    pub lapic: Arc<RwLock<LocalApicDevice>>,
    pub hpet: Arc<RwLock<VirtualHpet>>,
    pub guest_clock: Arc<GuestClock>,
    pub last_cursor_row: usize,
    pub apic_access_page: Frame,
}

impl GuestMachineState {
    /// Wire emulated devices and interrupt controllers after guest RAM has been mapped.
    ///
    /// Caller is responsible for SLAT population and boot-source loading before this runs.
    pub fn attach_devices(
        options: VmOptions,
        slat: Arc<RwLock<dyn SlatManager>>,
        memory_descriptors: Vec<VirtualMachineMemoryDescriptor>,
        tsc_scaling_supported: bool,
    ) -> Result<Self, HypervisorError> {
        let guest_clock = GuestClock::new(
            options.guest_tsc_hz,
            options.guest_apic_bus_hz,
            tsc_scaling_supported,
        );
        let lapic = LocalApicDevice::new(guest_clock.clone());
        let pic = ProgrammableInterruptControllerDevice::new();
        let io_apic = VirtualIoApic::new(lapic.clone(), 0);
        let pit = VirtualPit::new(pic.clone(), io_apic.clone(), guest_clock.clone());
        let speaker = VirtualSpeaker::new(pit.clone());
        let pm_timer = VirtualPmTimer::new(guest_clock.clone());
        let acpi_pm = VirtualAcpiPm::new();
        let hpet = VirtualHpet::new(io_apic.clone(), guest_clock.clone());

        let device_context = DeviceContext {
            io_apic: io_apic.clone(),
        };

        let mut system_bus = SystemBus::new();
        for device in options.devices.clone() {
            log::debug!("Registered device: {:?}", device.read().name());

            device.write().attach(&device_context);
            system_bus.register_device(device);
        }

        system_bus.register_device(pic.clone());
        system_bus.register_device(pit.clone());
        system_bus.register_device(pm_timer);
        system_bus.register_device(acpi_pm);
        system_bus.register_device(hpet.clone());
        system_bus.register_device(lapic.clone());
        system_bus.register_device(io_apic.clone());
        system_bus.register_device(speaker.clone());

        let apic_access_page = memory_manager().write().allocate_frame().unwrap();
        unsafe {
            let mut mm = memory_manager().write();
            let page = Page::new(VirtualAddress::new(apic_access_page.address().as_u64()));
            let frame = Frame::new(PhysicalAddress::new(page.address().as_u64()));

            mm.map(
                MapTarget::CurrentAddressSpace(),
                Exact(&page, &frame),
                PageFlags::WRITABLE,
            )
            .map_err(|_| HypervisorError::MemoryMappingError)?;
        }

        Ok(Self {
            options,
            slat,
            memory_descriptors,
            pic,
            #[allow(clippy::arc_with_non_send_sync)]
            system_bus: Arc::new(RwLock::new(system_bus)),
            pit,
            hpet,
            io_apic,
            lapic,
            guest_clock,
            last_cursor_row: 0,
            apic_access_page,
        })
    }

    /// Build RSDP/RSDT/XSDT/FADT/MADT/DSDT and copy them into guest ACPI reclaim RAM.
    pub fn build_acpi(&self) {
        const RSDP_ADDRESS: usize = 0x000E_0000;
        const RSDT_ADDRESS: usize = 0x7F6E_1000;
        const XSDT_ADDRESS: usize = 0x7F6E_2000;
        const FADT_ADDRESS: usize = 0x7F6E_3000;
        const MADT_ADDRESS: usize = 0x7F6E_4000;
        const DSDT_ADDRESS: usize = 0x7F6E_5000;
        const HPET_ADDRESS: usize = 0x7F6E_6000;

        let mut devices = alloc::vec![];

        for i in 0..self.options.vcpu_count {
            let name = format!("CPU{}", i);

            let cpu_device = crate::aml!(@ROOT
                Device (name.as_str()) {
                    Name ("_HID", "ACPI0007")
                    Name ("_UID", i)

                    Method ("_STA", 0) {
                        Return (0x0Fu8)
                    }
                }
            );

            devices.push(cpu_device);
        }

        for device in self.system_bus.read().devices() {
            if let Some(device_bytecode) = device.read().generate_aml() {
                devices.push(device_bytecode);
            }
        }

        let dsdt = self.merge_to_dsdt(devices);
        let builder = AcpiTablesBuilder::new();
        let madt = builder.build_madt(self.options.vcpu_count as u8);
        let fadt = builder.build_fadt(DSDT_ADDRESS as u64);
        let rsdp = builder.build_rsdp(RSDT_ADDRESS as u32, XSDT_ADDRESS as u64);
        let rsdt = builder.build_rsdt(alloc::vec![
            FADT_ADDRESS as u32,
            MADT_ADDRESS as u32,
            HPET_ADDRESS as u32
        ]);
        let xsdt = builder.build_xsdt(alloc::vec![
            FADT_ADDRESS as u64,
            MADT_ADDRESS as u64,
            HPET_ADDRESS as u64
        ]);
        let hpet = builder.build_hpet(HPET_MMIO_BASE);

        let tables = [
            (RSDP_ADDRESS, &rsdp),
            (RSDT_ADDRESS, &rsdt),
            (XSDT_ADDRESS, &xsdt),
            (FADT_ADDRESS, &fadt),
            (MADT_ADDRESS, &madt),
            (DSDT_ADDRESS, &dsdt),
            (HPET_ADDRESS, &hpet),
        ];

        for (guest_addr, data) in tables.iter() {
            if let Some(host_ptr) = self.slat.read().translate(*guest_addr as u64) {
                unsafe {
                    ptr::copy_nonoverlapping(data.as_ptr(), host_ptr as *mut u8, data.len());
                }
            } else {
                panic!("Error maping ACPI at address: {:#x}", guest_addr);
            }
        }
    }

    fn merge_to_dsdt(&self, device_vecs: Vec<Vec<u8>>) -> Vec<u8> {
        let mut builder = AmlBuilder::new();

        builder.emit_op(AmlOp::ScopeOp);
        builder.begin_block();
        builder.emit_name("_SB");

        for device_bytecode in device_vecs {
            builder.stream.extend_from_slice(&device_bytecode);
        }

        builder.end_block();

        self.finalize_table(b"DSDT", OEM_ID, builder.stream)
    }

    fn finalize_table(&self, signature: &[u8; 4], oem_id: &[u8; 6], aml_data: Vec<u8>) -> Vec<u8> {
        let header_len = 36;
        let total_len = aml_data.len() + header_len;

        let mut table = Vec::with_capacity(total_len);

        table.extend_from_slice(signature);
        table.extend_from_slice(&(total_len as u32).to_le_bytes());
        table.push(2);

        let checksum_pos = table.len();
        table.push(0);

        table.extend_from_slice(oem_id);
        table.extend_from_slice(OEM_TABLE_ID);
        table.extend_from_slice(&[1, 0, 0, 0]);
        table.extend_from_slice(COMPILER_ID);
        table.extend_from_slice(&[1, 0, 0, 0]);
        table.extend_from_slice(aml_data.as_slice());

        let mut sum: u8 = 0;
        for byte in &table {
            sum = sum.wrapping_add(*byte);
        }

        table[checksum_pos] = u8::MIN.wrapping_sub(sum);

        table
    }
}
