use core::{any::Any, sync::atomic::Ordering};

use alloc::{
    boxed::Box, sync::Arc, vec::{self, Vec}
};
use hashbrown::HashMap;
use log::debug;
use spin::RwLock;

use crate::{arch::x86::idt::register_interrupt_handler, driver::{
    ata::{AtaBusDriver, AtaDiskDriver},
    io::DEVICE_ID_COUNTER,
    pci::{Pci, PciDeviceClass, PciDeviceClassMassStorageControllerSubclass},
}};

use super::{
    Device, DeviceId, DeviceManagerError, DeviceProperties, DeviceType, Driver, DriverBase,
    PciAddress,
};

pub type DeviceRef = Arc<Device>;
pub type DriverRef = Arc<dyn Driver>;

pub struct DeviceManager {
    devices: RwLock<HashMap<DeviceId, DeviceRef>>,
    drivers: RwLock<HashMap<DeviceType, DriverRef>>,
}

impl DeviceManager {
    pub fn new() -> Self {
        Self {
            devices: RwLock::new(HashMap::new()),
            drivers: RwLock::new(HashMap::new()),
        }
    }

    pub fn enumerate_devices(&self) {
        let mut class_to_driver_map: HashMap<PciDeviceClass, Vec<Arc<dyn Driver>>> = HashMap::new();
        //   let mut id_to_driver_map = HashMap::new();

        class_to_driver_map.insert(
            PciDeviceClass::MassStorageController(
                PciDeviceClassMassStorageControllerSubclass::IdeController,
            ),
            alloc::vec![
                Arc::new(AtaBusDriver {}),
                Arc::new(AtaDiskDriver {
                    disks: RwLock::new(HashMap::new())
                })
            ],
        );

        let pci_devices = Pci::build_device_tree();
        let mut devices = alloc::vec![];

        for dev in pci_devices {
            // debug!(
            //        "PCI dev: {:?} {} {}",
            //         dev.class, dev.vendor_id, dev.device_id
            //   );

            let mut device = Device {
                properties: DeviceProperties::PCI {
                    address: dev.address,
                    inner_identificator: 0,
                },
                id: unsafe { DEVICE_ID_COUNTER.fetch_add(1, Ordering::SeqCst) },
                vendor_id: dev.vendor_id as u32,
                device_id: dev.device_id as u32,
                driver: None,
                children: alloc::vec![],
                can_be_bus_controller: true,
            };

            self.find_driver(&mut device, &class_to_driver_map, &mut devices);

            devices.push(Arc::new(device));
        }

        fn callback(device: &Arc<Device>) {
            let mut driver = device.driver.clone().unwrap();
            if driver.supports_block_capabilities() {
                debug!("Driver block size: {}", driver.block_size());
                driver.attach(device.clone()).unwrap();

                debug!("Data: {:x?}", driver.read_block(device.id, 0).unwrap());
                let data = [0xAAu8; 512];
                driver.write_block(device.id, 0, &data);
            }

            for child in device.children.iter() {
                if device.driver.is_none() {
                    continue;
                }

                callback(child);
            }
        }

        for device in &devices {
            if device.driver.is_none() {
                continue;
            }

            callback(device);
        }

        //    debug!("Devices: {:#?}", devices);
    }

    fn find_driver(
        &self,
        device: &mut Device,
        map: &HashMap<PciDeviceClass, Vec<Arc<dyn Driver>>>,
        devices_list: &mut Vec<Arc<Device>>,
    ) -> bool {
        if device.is_pci_device() {
            let can_be_bus_controller = device.can_be_bus_controller;
            let pci_device = device.to_pci_device().unwrap();
            let class = pci_device.class;
            let vendor_id = pci_device.vendor_id;
            let device_id = pci_device.device_id;

            map.iter()
                .filter(|(pci_class, _)| **pci_class == class)
                .for_each(|(_, drivers)| {
                    for driver in drivers {
                        if (device.can_be_bus_controller && !driver.supports_bus_capability())
                            || (!device.can_be_bus_controller && driver.supports_bus_capability())
                        {
                            // cringe workaround
                            continue;
                        }

                        device.driver = Some(Arc::clone(driver));

                        if driver.supports_bus_capability() {
                            let mut children = driver.enumerate_devices(device).unwrap();

                            for child in children.iter_mut() {
                                self.find_driver(child, map, devices_list);
                            }

                            device.children.extend(children.into_iter().map(Arc::new));
                        }
                    }
                });
        }

        true
    }
    /*
        pub fn register_device(&self, device: Arc<dyn Device>) {
            let mut devices = self.devices.write();
            devices.insert(device.id(), device);
        }

        pub fn register_driver(&self, device_type: DeviceType, driver: Arc<dyn Driver>) {
            let mut drivers = self.drivers.write();
            drivers.insert(device_type, driver);
        }
    */
    pub fn initialize(&self) -> Result<(), DeviceManagerError> {
        /*     let devices = self.devices.read();
        let drivers = self.drivers.read();

        for (_, device) in devices.iter() {
            let device_type = device.device_type();
            if let Some(driver) = drivers.get(&device_type) {
                device
                    .initialize(DeviceProperties::PCI { address: PciAddress { bus: 0, device: 0, function: 0 } })
                    .map_err(|e| DeviceManagerError::DeviceError(e));
                driver
                    .attach(device.as_ref(), self)
                    .map_err(|e| DeviceManagerError::DriverError(e));
            }
        }*/
        Ok(())
    }

    /*pub fn handle_interrupt(&self, device_id: DeviceId, interrupt: Interrupt) -> Result<(), DeviceManagerError> {
        let devices = self.devices.read().unwrap();
        let drivers = self.drivers.read().unwrap();

        if let Some(device) = devices.get(&device_id) {
            if let Some(driver) = drivers.get(&device.device_type()) {
                driver.handle_interrupt(interrupt)?;
            }
        }
        Ok(())
    }*/

    fn register_interrupt_handlers(self) {
        for i in 32..=255 {
            register_interrupt_handler(i, Box::new(|isf| {
                
            }));
        }
    }
}
