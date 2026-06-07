use alloc::alloc::Global;
use core::{
    alloc::{Allocator, Layout},
    ffi::c_void,
    ptr::{self, NonNull},
};

use acpica_rs::{
    ACPI_CPU_FLAGS, ACPI_MUTEX, ACPI_SEMAPHORE, ACPI_SPINLOCK, ACPI_THREAD_ID, AE_BAD_PARAMETER,
    AE_OK, AcpicaOsServices, sys::*,
};
use libm::ceil;

use crate::{
    arch::x86::asm::{inb, inl, inw, outb, outl, outw},
    driver::pci::Pci,
    subsystem::memory::{
        CurrentAddressSpace, Identity, MemoryError, PAGE_SIZE, Page, PageFlags, VirtualAddress,
        memory_manager,
    },
};

struct SizePrefixedAllocation {
    size: usize,
    data: [u8],
}

pub struct MooseAcpicaOsImplementation {}

// All unimplemented functions were not implemented, because ACPICA never call them in our use case.
impl AcpicaOsServices for MooseAcpicaOsImplementation {
    fn initialize(&self) -> ACPI_STATUS {
        // Don't need to do any initialization work here
        AE_OK
    }

    fn terminate(&self) -> ACPI_STATUS {
        // We never call AcpiTerminate
        todo!()
    }

    fn map(&self, physical_address: ACPI_PHYSICAL_ADDRESS, length: ACPI_SIZE) -> *mut c_void {
        let address = physical_address as usize;
        let offset = address & 0xFFF;
        let pages_to_map = ceil((offset as f64 + length as f64) / PAGE_SIZE as f64) as usize;

        let mut memory_manager = memory_manager().write();
        for i in 0..pages_to_map {
            let page = Page::new(VirtualAddress::new(
                ((address & 0xFFFF_FFFF_FFFF_F000) + i * PAGE_SIZE) as u64,
            ));

            match unsafe {
                memory_manager.map(CurrentAddressSpace, Identity(&page), PageFlags::WRITABLE)
            } {
                // If page was unmapped, and we've just mapped it, it's ok
                Ok(_) => {}
                // If page was already mapped, it means that we have mapped it in previous loop
                // iteration, and it's ok
                Err(MemoryError::AlreadyMapped) => {}
                // In case of any other error bail out
                Err(err) => {
                    panic!("Memory error: {}", err);
                }
            };
        }

        physical_address as *mut c_void
    }

    fn unmap(&self, _logical_address: *mut c_void, _length: ACPI_SIZE) {
        // Unmap isn't called only on page granularity, so a lot of work must be done to make sure, we won't unmap
        // something that is used currently.
        //
        // We can afford mapping ACPI tables for whole OS lifetime.
    }

    fn get_physical_address(
        &self,
        _logical_address: *mut c_void,
        _physical_address: &mut ACPI_PHYSICAL_ADDRESS,
    ) -> ACPI_STATUS {
        todo!()
    }

    fn allocate(&self, size: ACPI_SIZE) -> *mut c_void {
        unsafe {
            let allocation_size = size as usize + size_of::<usize>();
            let allocation = Global
                .allocate(Layout::from_size_align(allocation_size, 2).unwrap())
                .unwrap()
                .as_ptr() as *mut u8;

            // We can't free memory without knowing it's size, so store it as a metadata
            // just before start of the allocated memory region we return to the ACPICA.
            *(allocation as *mut usize) = allocation_size;

            allocation.add(size_of::<usize>()) as *mut c_void
        }
    }

    fn free(&self, address: *mut c_void) {
        unsafe {
            let address = address as *mut u8;
            assert_ne!(address, ptr::null_mut());

            let allocation_start = address.sub(size_of::<usize>());
            let allocation_size = *(allocation_start as *mut usize);

            Global.deallocate(
                NonNull::new_unchecked(allocation_start),
                Layout::from_size_align(allocation_size, 2).unwrap(),
            )
        }
    }

    fn is_readable(&self, _address: *mut c_void, _length: ACPI_SIZE) -> bool {
        todo!()
    }

    fn is_writable(&self, _address: *mut c_void, _length: ACPI_SIZE) -> bool {
        todo!()
    }

    fn get_thread_id(&self) -> ACPI_THREAD_ID {
        // Can't return 0, because it's ACPICA reserved value
        1
    }

    fn sleep(&self, _milliseconds: u64) {
        todo!()
    }

    fn stall(&self, _microseconds: u32) {
        todo!()
    }

    fn wait_events_complete(&self) {
        todo!()
    }

    fn create_mutex(&self, _handle: *mut ACPI_MUTEX) -> ACPI_STATUS {
        todo!()
    }

    fn delete_mutex(&self, _handle: ACPI_MUTEX) {
        todo!()
    }

    fn acquire_mutex(&self, _handle: ACPI_MUTEX, _timeout: u16) -> ACPI_STATUS {
        todo!()
    }

    fn release_mutex(&self, _handle: ACPI_MUTEX) {
        todo!()
    }

    fn create_semaphore(
        &self,
        _max_units: u32,
        _initial_units: u32,
        _handle: *mut ACPI_SEMAPHORE,
    ) -> ACPI_STATUS {
        // Single threaded implementations are allowed to just return OK

        AE_OK
    }

    fn delete_semaphore(&self, _handle: ACPI_SEMAPHORE) -> ACPI_STATUS {
        todo!()
    }

    fn wait_semaphore(&self, _handle: ACPI_SEMAPHORE, _units: u32, _timeout: u16) -> ACPI_STATUS {
        // Single threaded implementations are allowed to just return OK

        AE_OK
    }

    fn signal_semaphore(&self, _handle: ACPI_SEMAPHORE, _units: u32) -> ACPI_STATUS {
        // Single threaded implementations are allowed to just return OK

        AE_OK
    }

    fn create_lock(&self, _handle: *mut ACPI_SPINLOCK) -> ACPI_STATUS {
        // Single threaded implementations are allowed to just return OK

        AE_OK
    }

    fn delete_lock(&self, _handle: ACPI_SPINLOCK) {
        todo!()
    }

    fn acquire_lock(&self, _handle: ACPI_SPINLOCK) -> ACPI_CPU_FLAGS {
        // Single threaded implementations are allowed to just return OK

        AE_OK as ACPI_CPU_FLAGS
    }

    fn release_lock(&self, _handle: ACPI_SPINLOCK, _flags: ACPI_CPU_FLAGS) {}

    fn install_interrupt_handler(
        &self,
        _interrupt_level: u32,
        _handler: ACPI_OSD_HANDLER,
        _context: *mut c_void,
    ) -> ACPI_STATUS {
        AE_OK
    }

    fn remove_interrupt_handler(
        &self,
        _interrupt_level: u32,
        _handler: ACPI_OSD_HANDLER,
    ) -> ACPI_STATUS {
        todo!()
    }

    fn read_memory(
        &self,
        _address: ACPI_PHYSICAL_ADDRESS,
        _value: *mut u64,
        _width: u32,
    ) -> ACPI_STATUS {
        todo!()
    }

    fn write_memory(
        &self,
        _address: ACPI_PHYSICAL_ADDRESS,
        _value: u64,
        _width: u32,
    ) -> ACPI_STATUS {
        todo!()
    }

    fn read_port(&self, address: ACPI_IO_ADDRESS, value: &mut u32, width: u32) -> ACPI_STATUS {
        let address = address as u16;

        let val = match width {
            8 => inb(address) as u32,
            16 => inw(address) as u32,
            32 => inl(address),
            _ => unreachable!(),
        };

        *value = val;

        AE_OK
    }

    fn write_port(&self, address: ACPI_IO_ADDRESS, value: u32, width: u32) -> ACPI_STATUS {
        let address = address as u16;

        match width {
            8 => outb(address, value as u8),
            16 => outw(address, value as u16),
            32 => outl(address, value),
            _ => unreachable!(),
        };

        AE_OK
    }

    fn read_pci_configuration(
        &self,
        pci_id: *mut ACPI_PCI_ID,
        register: u32,
        value: *mut u64,
        width: u32,
    ) -> ACPI_STATUS {
        let segment = unsafe { (*pci_id).Segment } as u32;
        let bus = unsafe { (*pci_id).Bus } as u32;
        let device = unsafe { (*pci_id).Device } as u32;
        let function = unsafe { (*pci_id).Function } as u32;

        assert_eq!(segment, 0);

        let read = match width {
            8 => Pci::read_u8(bus, device, function, register) as u64,
            16 => Pci::read_u16(bus, device, function, register) as u64,
            32 => Pci::read_u32(bus, device, function, register) as u64,
            _ => unreachable!(),
        };

        unsafe { *value = read };

        AE_OK
    }

    fn write_pci_configuration(
        &self,
        _pci_id: *mut ACPI_PCI_ID,
        _register: u32,
        _value: u64,
        _width: u32,
    ) -> ACPI_STATUS {
        todo!()
    }

    fn override_predefined(
        &self,
        predefined_object: *mut ACPI_PREDEFINED_NAMES,
        new_value: *mut ACPI_STRING,
    ) -> ACPI_STATUS {
        unsafe {
            if predefined_object.addr() == 0 || new_value.addr() == 0 {
                return AE_BAD_PARAMETER;
            }

            *new_value = core::ptr::null_mut();

            AE_OK
        }
    }

    fn override_table(
        &self,
        existing_table: *mut ACPI_TABLE_HEADER,
        new_table: *mut *mut ACPI_TABLE_HEADER,
    ) -> ACPI_STATUS {
        unsafe {
            if existing_table.addr() == 0 || new_table.addr() == 0 {
                return AE_BAD_PARAMETER;
            }

            *new_table = core::ptr::null_mut();

            AE_OK
        }
    }

    fn override_physical_table(
        &self,
        existing_table: *mut ACPI_TABLE_HEADER,
        new_address: *mut ACPI_PHYSICAL_ADDRESS,
        new_table_length: *mut u32,
    ) -> ACPI_STATUS {
        if existing_table.addr() == 0 || new_address.addr() == 0 || new_table_length.addr() == 0 {
            return AE_BAD_PARAMETER;
        }

        unsafe {
            *new_address = 0;
            *new_table_length = 0;
        }

        AE_OK
    }

    fn execute(
        &self,
        _type_: ACPI_EXECUTE_TYPE,
        _function: ACPI_OSD_EXEC_CALLBACK,
        _context: *mut c_void,
    ) -> ACPI_STATUS {
        todo!()
    }

    fn get_timer(&self) -> u64 {
        0
    }

    fn signal(&self, _function: u32, _info: *mut c_void) -> ACPI_STATUS {
        todo!()
    }

    fn initialize_debugger(&self) {
        // Dont plan to support this
        unimplemented!()
    }

    fn terminate_debugger(&self) {
        // Dont plan to support this
        unimplemented!()
    }

    fn wait_command_ready(&self) {
        todo!()
    }

    fn notify_command_complete(&self) {
        todo!()
    }

    fn enter_sleep(&self, _sleep_state: u32, _register_a_value: u32, _register_b_value: u32) {
        todo!()
    }

    fn disassemble(&self, _walk_state: u64, _origin: u64, _num_opcodes: u32) {
        // Dont plan to support this
        unimplemented!()
    }

    fn parse_deferred_operations(&self, _root: u64) {
        // Dont plan to support this
        unimplemented!()
    }

    fn print(&self, _text: core::fmt::Arguments) {
        // Intentionally left blank
    }
}
