use alloc::{sync::Arc, vec::Vec};
use core::{any::Any, fmt::Debug, sync::atomic::AtomicU64};
use device_manager::DeviceRef;

use crate::driver::pci::{Pci, PciDevice, PciDeviceClass};

pub mod device_manager;

pub static mut DEVICE_ID_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug)]
pub struct Device {
    pub id: DeviceId,
    pub vendor_id: u32,
    pub device_id: u32,
    pub properties: DeviceProperties,
    pub driver: Option<Arc<dyn Driver>>,
    pub children: Vec<Arc<Device>>,
    pub can_be_bus_controller: bool,
}

impl Device {
    pub fn is_pci_device(&self) -> bool {
        matches!(
            self.properties,
            DeviceProperties::PCI {
                address: _,
                inner_identificator: _
            }
        )
    }

    pub fn to_pci_device(&self) -> Option<PciDevice> {
        assert!(self.is_pci_device());

        let DeviceProperties::PCI {
            address,
            inner_identificator: _,
        } = self.properties;

        Pci::scan_device(
            address.bus.into(),
            address.device.into(),
            address.function.into(),
        )
    }
}

pub enum DriverPredicate {
    PciClass(PciDeviceClass),
    PciDeviceAndVendorId { vendor_id: u16, device_id: u16 },
}

pub trait DriverBase {
    fn attach(&self, device: DeviceRef) -> Result<(), DriverError>;
    fn detach(&self, device: DeviceRef) -> Result<(), DriverError>;

    fn supported_devices(&self) -> Result<DriverPredicate, DriverError>;

    //fn handle_interrupt(&self, device: &Device, interrupt: Interrupt) -> Result<(), DriverError>;
}

pub trait BlockDriver: DriverBase {
    fn supports_block_capabilities(&self) -> bool {
        false
    }

    fn read_block(&self, device_id: DeviceId, block_id: u64) -> Result<Vec<u8>, DriverError> {
        panic!("Unsupported operation");
    }

    fn write_block(
        &self,
        device_id: DeviceId,
        block_id: u64,
        data: &[u8],
    ) -> Result<(), DriverError> {
        panic!("Unsupported operation");
    }

    fn block_size(&self) -> u64 {
        unimplemented!()
    }
}

pub trait NetworkDriver: DriverBase {
    fn supports_network_capabilities(&self) -> bool {
        false
    }

    fn send_packet(&self, device: &Device, packet: &[u8]) -> Result<(), DriverError> {
        panic!("Unsupported operation");
    }

    fn receive_packet(&self, device: &Device) -> Result<Option<Vec<u8>>, DriverError> {
        panic!("Unsupported operation");
    }

    fn mac_address(&self, device: &Device) -> [u8; 6] {
        panic!("Unsupported operation");
    }

    fn set_state(&self, device: &Device, state: NetworkState) -> Result<(), DriverError> {
        panic!("Unsupported operation");
    }
}

pub trait BusDriver: DriverBase {
    fn supports_bus_capability(&self) -> bool {
        false
    }

    fn enumerate_devices(&self, device: &Device) -> Result<Vec<Device>, DriverError> {
        unimplemented!()
    }
}

pub trait Driver: Debug + DriverBase + BlockDriver + NetworkDriver + BusDriver {}

// BlockDriver
// NetworkDriver
// BusDriver

#[macro_export]
macro_rules! block_driver {
    ($type:ty) => {
        impl $crate::io::Driver for $type {}

        impl $crate::io::NetworkDriver for $type {}
        impl $crate::io::BusDriver for $type {}
    };
}

#[macro_export]
macro_rules! network_driver {
    ($type:ty) => {
        impl $crate::driver::io::Driver for $type {}

        impl $crate::driver::io::BlockDriver for $type {}
        impl $crate::driver::io::BusDriver for $type {}
    };
}

#[macro_export]
macro_rules! bus_driver {
    ($type:ty) => {
        impl io::Driver for $type {}

        impl io::BlockDriver for $type {}
        impl io::NetworkDriver for $type {}
    };
}

pub enum DeviceType {
    Storage,
    Network,
    Input,
    Display,
    Bus,
}

pub type DeviceId = u64;

pub struct DeviceFeatures {
    // Add fields for device-specific features.
    pub supports_dma: bool,
    pub max_speed: Option<u32>,
}

#[derive(Copy, Clone, Debug)]
pub enum DeviceProperties {
    PCI {
        address: PciAddress,
        inner_identificator: u64,
    },
}

/*pub trait DependencyResolver {
    /// Finds a driver for a specific device or capability.
    fn find_driver(&self, device_type: DeviceType) -> Option<Arc<dyn Driver>>;

    /// Finds a specific device by its unique identifier.
    fn find_device(&self, device_id: DeviceId) -> Option<Arc<dyn Device>>;
}*/

pub enum NetworkState {
    Up,
    Down,
}

pub enum BusType {
    Ata,
    Pci,
    Usb,
}

#[derive(Copy, Clone, Debug)]
pub struct PciAddress {
    pub bus: u16,
    pub device: u16,
    pub function: u16,
}

impl PciAddress {
    pub fn new(bus: u16, device: u16, function: u16) -> Self {
        Self {
            bus,
            device,
            function,
        }
    }
}

pub trait PciBusDriver {
    /// Reads a configuration register.
    fn read_config(&self, device: Arc<Device>, offset: u32) -> u32;

    /// Writes to a configuration register.
    fn write_config(&self, device: Arc<Device>, offset: u32, value: u32);

    /// Allocates a memory or IO resource for a device.
    fn allocate_resource(
        &self,
        device: Arc<Device>,
        resource_type: ResourceType,
    ) -> Result<Resource, DriverError>;

    fn read_u8(address: PciAddress, offset: u32) -> u8;
    fn read_u16(address: PciAddress, offset: u32) -> u16;
    fn read_u32(address: PciAddress, offset: u32) -> u32;

    fn write_u8(address: PciAddress, offset: u32, value: u8);
    fn write_u16(address: PciAddress, offset: u32, value: u16);
    fn write_u32(address: PciAddress, offset: u32, value: u32);
}

pub struct PciBusEnumDriver {}
impl PciBusDriver for PciBusEnumDriver {
    fn read_config(&self, device: Arc<Device>, offset: u32) -> u32 {
        todo!()
    }

    fn write_config(&self, device: Arc<Device>, offset: u32, value: u32) {
        todo!()
    }

    fn allocate_resource(
        &self,
        device: Arc<Device>,
        resource_type: ResourceType,
    ) -> Result<Resource, DriverError> {
        todo!()
    }

    fn read_u8(address: PciAddress, offset: u32) -> u8 {
        todo!()
    }

    fn read_u16(address: PciAddress, offset: u32) -> u16 {
        todo!()
    }

    fn read_u32(address: PciAddress, offset: u32) -> u32 {
        todo!()
    }

    fn write_u8(address: PciAddress, offset: u32, value: u8) {
        todo!()
    }

    fn write_u16(address: PciAddress, offset: u32, value: u16) {
        todo!()
    }

    fn write_u32(address: PciAddress, offset: u32, value: u32) {
        todo!()
    }
}

pub enum ResourceType {
    Memory,
    IO,
}

pub struct Resource {
    pub base: u64,
    pub size: u64,
}

#[derive(Debug)]
pub enum DeviceError {
    InitializationFailed,
    ShutdownFailed,
    UnsupportedOperation,
}

#[derive(Debug)]
pub enum DriverError {
    AttachFailed,
    DetachFailed,
    InterruptHandlingFailed,
}

#[derive(Debug)]
pub enum DeviceManagerError {
    DeviceError(DeviceError),
    DriverError(DriverError),
    UnknownDevice,
    UnknownDriver,
}
