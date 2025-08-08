use core::{any::Any, sync::atomic::Ordering};

use alloc::{
    borrow::ToOwned,
    boxed::Box,
    sync::Arc,
    vec::{self, Vec},
};
use hashbrown::HashMap;
use log::debug;
use spin::RwLock;

use crate::{
    arch::x86::idt::register_interrupt_handler,
    cpu::ProcessorControlBlock,
    driver::{
        acpi::create_device_list,
        ata::{AtaBusDriver, AtaDiskDriver},
        io::DEVICE_ID_COUNTER,
        net::nic::rtl8139::Rtl8139Driver,
        pci::{
            Pci, PciDeviceClass, PciDeviceClassMassStorageControllerSubclass,
            PciDeviceClassNetworkControllerSubclass,
        },
    },
    kernel::kernel_ref,
};

use super::{
    Device, DeviceId, DeviceManagerError, DeviceProperties, DeviceType, Driver, DriverBase,
    DriverId, PciAddress,
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
                    disks: RwLock::new(HashMap::new()),
                    // @TODO: Replace it with global counter? dynamic registration?
                    driver_id: 1,
                })
            ],
        );
        /*       class_to_driver_map.insert(
            PciDeviceClass::NetworkController(
                PciDeviceClassNetworkControllerSubclass::EthernetController,
            ),
            alloc::vec![Arc::new(Rtl8139Driver {
                devices: RwLock::new(HashMap::new()),
                driver_id: 2,
            }),],
        );*/

        // @TODO: Need to register every driver in `drivers_map`, otherwise interrupts wont work.
        /*     kernel_ref().drivers_map.lock().insert(
            2,
            class_to_driver_map
                .get(&PciDeviceClass::NetworkController(
                    PciDeviceClassNetworkControllerSubclass::EthernetController,
                ))
                .unwrap()[0]
                .clone(),
        );*/

        /* let pci_devices = Pci::build_device_tree();
        let mut devices = alloc::vec![];

        for dev in pci_devices {
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
                can_be_bus_controller: self.can_be_bus_controller(dev.class),
            };

            self.find_driver(&mut device, &class_to_driver_map, &mut devices);

            devices.push(Arc::new(device));
        }

        // @TODO: Take care of ACPI device tree here
        //
        //let acpi_devices = create_device_list();
        //for dev in acpi_devices {
        //    debug!("Device :{:#?}", dev);
        //}

        fn callback(device: &Arc<Device>) {
            let mut driver = device.driver.clone().unwrap();
            if driver.supports_block_capabilities() {
                driver.attach(device.clone()).unwrap();

                debug!("Data: {:x?}", driver.read_block(device.id, 0).unwrap());
            }
            if driver.supports_network_capabilities() {
                driver.attach(device.clone()).unwrap();
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
        }*/

        self.register_interrupt_handlers();
    }

    fn can_be_bus_controller(&self, pci_class: PciDeviceClass) -> bool {
        pci_class
            == PciDeviceClass::MassStorageController(
                PciDeviceClassMassStorageControllerSubclass::IdeController,
            )
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
    pub fn initialize(&self) -> Result<(), DeviceManagerError> {
        Ok(())
    }

    fn register_interrupt_handlers(&self) {
        for i in 32..=255 {
            if i == 0x80 {
                continue;
            }

            register_interrupt_handler(
                i,
                Box::new(move |isf| {
                    debug!("GOT INTERRUPT");
                    let kernel = kernel_ref();
                    if let Some(devices) = kernel.devices_interrupt_map.lock().get(&i) {
                        devices.iter().for_each(|device| {
                            let drivers = kernel.drivers_map.lock();
                            let driver = drivers.get(device).unwrap();
                            driver.on_interrupt(i);
                        });
                    }

                    unsafe {
                        _ = &(*ProcessorControlBlock::get_pcb_for_current_processor())
                            .local_apic
                            .get()
                            .unwrap()
                            .signal_end_of_interrupt();
                    }
                }),
            );
        }
    }
}

pub fn register_device_interrupt(driver: DriverId, irq: u8) -> bool {
    let kernel = kernel_ref();

    let mut map = kernel.devices_interrupt_map.lock();

    let current_list = map.get_mut(&irq);
    if let Some(list) = current_list {
        list.push(driver);
    } else {
        let list = Vec::from([driver]);

        map.insert(irq, list);
    }

    true
}
