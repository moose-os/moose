use crate::arch::x86::asm::{inl, outl};
use alloc::vec;
use alloc::vec::Vec;
use log::debug;

use super::io::PciAddress;

const CONFIG_ADDRESS: u16 = 0xCF8;
const CONFIG_DATA: u16 = 0xCFC;

const BAR_START: u32 = 0x10;
const COMMAND_REGISTER: u32 = 0x4;

pub struct Pci {}

impl Pci {
    pub fn build_device_tree() -> Vec<PciDevice> {
        Pci::perform_brute_force_scan()
    }

    fn perform_brute_force_scan() -> Vec<PciDevice> {
        let mut devices = vec![];

        for bus in 0..256u16 {
            for device in 0..32u16 {
                for function in 0..8u16 {
                    // @TODO: Make tree-like structure of detected
                    // devices in system (not only on PCI bus ofc, maybe use some AML and ACPI tables?)
                    if let Some(dev) = Pci::scan_device(bus, device, function) {
                        devices.push(dev);
                    }
                }
            }
        }

        devices
    }

    pub fn scan_device(bus: u16, device: u16, function: u16) -> Option<PciDevice> {
        let vendor_id = Pci::read_u16(bus, device, function, 0);
        if vendor_id == 0xFFFF {
            // Device does not exist
            return None;
        }

        let device_id = Pci::read_u16(bus, device, function, 2);
        let class_code = Pci::read_u16(bus, device, function, 10) >> 8;
        let subclass_code = Pci::read_u16(bus, device, function, 10) & 0xF;
        let device = PciDevice {
            address: PciAddress {
                bus,
                device,
                function,
            },
            vendor_id,
            device_id,
            class: PciDeviceClass::parse(class_code as u32, subclass_code as u32),
        };

        debug!(
            "[PCI] Found new device: {:#x?}:{:#x?} (class: {:?}, vendor: {}, device: {})",
            vendor_id,
            device_id,
            device.class,
            get_device_manufacturer_string(&device),
            get_device_name(&device)
        );

        Some(device)
    }

    pub fn read_u8(bus: u16, device: u16, function: u16, offset: u32) -> u8 {
        let address: u32 = ((bus as u32) << 16)
            | ((device as u32) << 11)
            | ((function as u32) << 8)
            | (offset & 0xFC)
            | 0x80000000;
        outl(CONFIG_ADDRESS, address);

        ((inl(CONFIG_DATA) >> ((offset & 2) * 8)) & 0xFF) as u8
    }

    pub fn read_u16(bus: u16, device: u16, function: u16, offset: u32) -> u16 {
        let address: u32 = ((bus as u32) << 16)
            | ((device as u32) << 11)
            | ((function as u32) << 8)
            | (offset & 0xFC)
            | 0x80000000;
        outl(CONFIG_ADDRESS, address);

        ((inl(CONFIG_DATA) >> ((offset & 2) * 8)) & 0xFFFF) as u16
    }

    pub fn read_u32(bus: u16, device: u16, function: u16, offset: u32) -> u32 {
        let address: u32 = ((bus as u32) << 16)
            | ((device as u32) << 11)
            | ((function as u32) << 8)
            | (offset & 0xFC)
            | 0x80000000;
        outl(CONFIG_ADDRESS, address);

        inl(CONFIG_DATA) >> ((offset & 2) * 8)
    }

    pub fn write_u8(bus: u16, device: u16, function: u16, offset: u32, value: u8) {
        let address: u32 = ((bus as u32) << 16)
            | ((device as u32) << 11)
            | ((function as u32) << 8)
            | (offset & 0xFC)
            | 0x80000000;
        outl(CONFIG_ADDRESS, address);

        outl(CONFIG_DATA, value as u32);
    }

    pub fn write_u16(bus: u16, device: u16, function: u16, offset: u32, value: u16) {
        let address: u32 = ((bus as u32) << 16)
            | ((device as u32) << 11)
            | ((function as u32) << 8)
            | (offset & 0xFC)
            | 0x80000000;
        outl(CONFIG_ADDRESS, address);

        outl(CONFIG_DATA, value as u32);
    }

    pub fn write_u32(bus: u16, device: u16, function: u16, offset: u32, value: u32) {
        let address: u32 = ((bus as u32) << 16)
            | ((device as u32) << 11)
            | ((function as u32) << 8)
            | (offset & 0xFC)
            | 0x80000000;
        outl(CONFIG_ADDRESS, address);

        outl(CONFIG_DATA, value);
    }
}

pub struct PciDevice {
    pub address: PciAddress,

    pub vendor_id: u16,
    pub device_id: u16,
    pub class: PciDeviceClass,
}

impl PciDevice {
    pub fn get_bar(&self, bar: u8) -> u32 {
        // Don't need to check if bar is bigger or equal 0 because of used type (unsigned byte)
        assert!(
            bar < 6,
            "There are only 6 BARs on PCI devices numbered from 0 to 5"
        );

        let bar_offset = BAR_START + (bar * 4) as u32;

        let lower_word = self.read(bar_offset);
        let higher_word = self.read(bar_offset + 2);

        return (higher_word << 16) | lower_word;
    }

    pub fn get_interrupt_pin(&self) -> u8 {
        (self.read(0x3C) >> 8) as u8
    }

    pub fn get_interrupt_line(&self) -> u8 {
        (self.read(0x3C) & 0xFF) as u8
    }

    pub fn enable_dma(&self) {
        // Enable Bus Mastering, I/O and Memory Access
        self.write(COMMAND_REGISTER, self.read(COMMAND_REGISTER) | 0b111);
    }

    fn read(&self, offset: u32) -> u32 {
        let address: u32 = ((self.address.bus as u32) << 16)
            | ((self.address.device as u32) << 11)
            | ((self.address.function as u32) << 8)
            | (offset & 0xFC)
            | 0x80000000;
        outl(CONFIG_ADDRESS, address);

        return inl(CONFIG_DATA);
    }

    fn write(&self, offset: u32, value: u32) {
        let address: u32 = ((self.address.bus as u32) << 16)
            | ((self.address.device as u32) << 11)
            | ((self.address.function as u32) << 8)
            | (offset & 0xFC)
            | 0x80000000;
        outl(CONFIG_ADDRESS, address);

        outl(CONFIG_DATA, value);
    }
}

// Feel free to add more manufacturer names
fn get_device_manufacturer_string(device: &PciDevice) -> &str {
    match device.vendor_id {
        0x1234 => "QEMU emulated device",
        0x8086 => "Intel Corp.",
        _ => "Unknown",
    }
}

fn get_device_name(device: &PciDevice) -> &str {
    match (device.vendor_id, device.device_id) {
        (0x1234, 0x1111) => "VGA compatible graphic card",
        (0x8086, 0x100e) => "82540EM Gigabit Ethernet Controller",
        (0x8086, 0x1237) => "440FX - 82441FX PMC [Natoma]",
        (0x8086, 0x7000) => "82371SB PIIX3 ISA [Natoma/Triton II]",
        (0x8086, 0x7010) => "82371SB PIIX3 IDE [Natoma/Triton II]",
        (0x8086, 0x7113) => "82371AB/EB/MB PIIX4 ACPI",
        _ => "Unknown",
    }
}

#[derive(Debug, Eq, PartialEq, Hash)]
pub enum PciDeviceClass {
    Undefined(PciDeviceClassUndefinedSubclass),
    MassStorageController(PciDeviceClassMassStorageControllerSubclass),
    NetworkController(PciDeviceClassNetworkControllerSubclass),
    DisplayController(PciDeviceClassDisplayControllerSubclass),
    MultimediaDevice(PciDeviceClassMultimediaControllerSubclass),
    MemoryController(PciDeviceClassMemoryControllerSubclass),
    Bridge(PciDeviceClassBridgeSubclass),
    SimpleCommunicationController(PciDeviceClassSimpleCommunicationControllerSubclass),
    BaseSystemPeripheral(PciDeviceClassBaseSystemPeripheralSubclass),
    InputDevice(PciDeviceClassInputDeviceControllerSubclass),
    DockingStation(PciDeviceClassDockingStationSubclass),
    Processor(PciDeviceClassProcessorSubclass),
    SerialBusController(PciDeviceClassSerialBusControllerSubclass),
    WirelessController(PciDeviceClassWirelessControllerSubclass),
    IntelligentIoController(PciDeviceClassIntelligentControllerSubclass),
    SatelliteCommunicationController(PciDeviceClassSatelliteCommunicationControllerSubclass),
    EncryptionOrDecryptionController(PciDeviceClassEncryptionControllerSubclass),
    DataAcquisitionAndSignalProcessingController(PciDeviceClassSignalProcessingControllerSubclass),
    ProcessingAccelerator,
    NonEssentialInstrumentation,
    // Reserved
    Unknown,
}

impl PciDeviceClass {
    pub fn parse(class_id: u32, subclass_id: u32) -> PciDeviceClass {
        match class_id {
            0x0 => PciDeviceClass::Undefined(match subclass_id {
                0x0 => PciDeviceClassUndefinedSubclass::NonVgaCompatibleUnclassifiedDevice,
                0x1 => PciDeviceClassUndefinedSubclass::VgaCompatibleUnclassifiedDevice,
                _ => unreachable!(),
            }),
            0x1 => PciDeviceClass::MassStorageController(match subclass_id {
                0x0 => PciDeviceClassMassStorageControllerSubclass::ScsiBusController,
                0x1 => PciDeviceClassMassStorageControllerSubclass::IdeController,
                0x2 => PciDeviceClassMassStorageControllerSubclass::FloppyDiskController,
                0x3 => PciDeviceClassMassStorageControllerSubclass::IpiBusController,
                0x4 => PciDeviceClassMassStorageControllerSubclass::RaidController,
                0x5 => PciDeviceClassMassStorageControllerSubclass::AtaController,
                0x6 => PciDeviceClassMassStorageControllerSubclass::SataController,
                0x7 => PciDeviceClassMassStorageControllerSubclass::SerialAttachedScsiController,
                0x8 => PciDeviceClassMassStorageControllerSubclass::NonVolatileMemoryController,
                _ => unreachable!(),
            }),
            0x2 => PciDeviceClass::NetworkController(match subclass_id {
                0x0 => PciDeviceClassNetworkControllerSubclass::EthernetController,
                0x1 => PciDeviceClassNetworkControllerSubclass::TokenRingController,
                0x2 => PciDeviceClassNetworkControllerSubclass::FddiController,
                0x3 => PciDeviceClassNetworkControllerSubclass::AtmController,
                0x4 => PciDeviceClassNetworkControllerSubclass::IsdnController,
                0x5 => PciDeviceClassNetworkControllerSubclass::WorldFipController,
                0x6 => PciDeviceClassNetworkControllerSubclass::PicmgMultimComputingController,
                0x7 => PciDeviceClassNetworkControllerSubclass::InfinibandController,
                0x8 => PciDeviceClassNetworkControllerSubclass::FabricController,
                _ => unreachable!(),
            }),
            0x3 => PciDeviceClass::DisplayController(match subclass_id {
                0x0 => PciDeviceClassDisplayControllerSubclass::VgaCompatibleController,
                0x1 => PciDeviceClassDisplayControllerSubclass::XgaController,
                0x2 => PciDeviceClassDisplayControllerSubclass::NotVgaCompatible3dController,
                _ => unreachable!(),
            }),
            0x4 => PciDeviceClass::MultimediaDevice(match subclass_id {
                0x0 => PciDeviceClassMultimediaControllerSubclass::MultimediaVideoController,
                0x1 => PciDeviceClassMultimediaControllerSubclass::MultimediaAudioController,
                0x2 => PciDeviceClassMultimediaControllerSubclass::ComputerTelephonyDevice,
                0x3 => PciDeviceClassMultimediaControllerSubclass::AudioDevice,
                _ => unreachable!(),
            }),
            0x5 => PciDeviceClass::MemoryController(match subclass_id {
                0x0 => PciDeviceClassMemoryControllerSubclass::RamController,
                0x1 => PciDeviceClassMemoryControllerSubclass::FlashController,
                _ => unreachable!(),
            }),
            0x6 => PciDeviceClass::Bridge(match subclass_id {
                0x0 => PciDeviceClassBridgeSubclass::HostBridge,
                0x1 => PciDeviceClassBridgeSubclass::IsaBridge,
                0x2 => PciDeviceClassBridgeSubclass::EisaBridge,
                0x3 => PciDeviceClassBridgeSubclass::McaBridge,
                0x4 => PciDeviceClassBridgeSubclass::PciToPciBridge,
                0x5 => PciDeviceClassBridgeSubclass::PcmciaBridge,
                0x6 => PciDeviceClassBridgeSubclass::NuBusBridge,
                0x7 => PciDeviceClassBridgeSubclass::CardBusBridge,
                0x8 => PciDeviceClassBridgeSubclass::RaceWayBridge,
                0x9 => PciDeviceClassBridgeSubclass::PciToPciBridge2,
                0xA => PciDeviceClassBridgeSubclass::InfiniBandToPciHostBridge,
                _ => unreachable!(),
            }),
            0x7 => PciDeviceClass::SimpleCommunicationController(match subclass_id {
                0x0 => PciDeviceClassSimpleCommunicationControllerSubclass::SerialController,
                0x1 => PciDeviceClassSimpleCommunicationControllerSubclass::ParallelController,
                0x2 => PciDeviceClassSimpleCommunicationControllerSubclass::MultiportSerialController,
                0x3 => PciDeviceClassSimpleCommunicationControllerSubclass::Modem,
                0x4 => PciDeviceClassSimpleCommunicationControllerSubclass::GpibController,
                0x5 => PciDeviceClassSimpleCommunicationControllerSubclass::SmartCardController,
                _ => unreachable!(),
            }),
            0x8 => PciDeviceClass::BaseSystemPeripheral(match subclass_id {
                0x0 => PciDeviceClassBaseSystemPeripheralSubclass::Pic,
                0x1 => PciDeviceClassBaseSystemPeripheralSubclass::DmaController,
                0x2 => PciDeviceClassBaseSystemPeripheralSubclass::Timer,
                0x3 => PciDeviceClassBaseSystemPeripheralSubclass::RtcController,
                0x4 => PciDeviceClassBaseSystemPeripheralSubclass::PciHotPlugController,
                0x5 => PciDeviceClassBaseSystemPeripheralSubclass::SdHostController,
                0x6 => PciDeviceClassBaseSystemPeripheralSubclass::IoMmu,
                _ => unreachable!(),
            }),
            0x9 => PciDeviceClass::InputDevice(match subclass_id {
                0x0 => PciDeviceClassInputDeviceControllerSubclass::KeyboardController,
                0x1 => PciDeviceClassInputDeviceControllerSubclass::DigitizerPen,
                0x2 => PciDeviceClassInputDeviceControllerSubclass::MouseController,
                0x3 => PciDeviceClassInputDeviceControllerSubclass::ScannerController,
                0x4 => PciDeviceClassInputDeviceControllerSubclass::GameportController,
                _ => unreachable!(),
            }),
            0xA => PciDeviceClass::DockingStation(match subclass_id {
                0x0 => PciDeviceClassDockingStationSubclass::Generic,
                _ => unreachable!(),
            }),
            0xB => PciDeviceClass::Processor(match subclass_id {
                0x0 => PciDeviceClassProcessorSubclass::x386,
                0x1 => PciDeviceClassProcessorSubclass::x486,
                0x2 => PciDeviceClassProcessorSubclass::Pentium,
                0x3 => PciDeviceClassProcessorSubclass::PentiumPro,
                0x10 => PciDeviceClassProcessorSubclass::Alpha,
                0x20 => PciDeviceClassProcessorSubclass::PowerPc,
                0x30 => PciDeviceClassProcessorSubclass::Mips,
                0x40 => PciDeviceClassProcessorSubclass::CoProcessor,
                _ => unreachable!(),
            }),
            0xC => PciDeviceClass::SerialBusController(match subclass_id {
                0x0 => PciDeviceClassSerialBusControllerSubclass::FireWireController,
                0x1 => PciDeviceClassSerialBusControllerSubclass::AccessBusController,
                0x2 => PciDeviceClassSerialBusControllerSubclass::Ssa,
                0x3 => PciDeviceClassSerialBusControllerSubclass::UsbController,
                0x4 => PciDeviceClassSerialBusControllerSubclass::FibreChannel,
                0x5 => PciDeviceClassSerialBusControllerSubclass::SmbusController,
                0x6 => PciDeviceClassSerialBusControllerSubclass::InfiniBandController,
                0x7 => PciDeviceClassSerialBusControllerSubclass::IpmiInterface,
                0x8 => PciDeviceClassSerialBusControllerSubclass::SercosInterface,
                0x9 => PciDeviceClassSerialBusControllerSubclass::CanbusController,
                _ => unreachable!(),
            }),
            0xD => PciDeviceClass::WirelessController(match subclass_id {
                0x0 => PciDeviceClassWirelessControllerSubclass::IrdaCompatibleController,
                0x1 => PciDeviceClassWirelessControllerSubclass::ConsumerIrController,
                0x10 => PciDeviceClassWirelessControllerSubclass::RfController,
                0x11 => PciDeviceClassWirelessControllerSubclass::BluetoothController,
                0x12 => PciDeviceClassWirelessControllerSubclass::BroadbandController,
                0x20 => PciDeviceClassWirelessControllerSubclass::EthernetControllerA,
                0x21 => PciDeviceClassWirelessControllerSubclass::EthernetControllerB,
                _ => unreachable!(),
            }),
            0xE => PciDeviceClass::IntelligentIoController(match subclass_id {
                0x0 => PciDeviceClassIntelligentControllerSubclass::I20,
                _ => unreachable!(),
            }),
            0xF => PciDeviceClass::SatelliteCommunicationController(match subclass_id {
                0x1 => PciDeviceClassSatelliteCommunicationControllerSubclass::SatelliteTvController,
                0x2 => PciDeviceClassSatelliteCommunicationControllerSubclass::SatelliteAudioController,
                0x3 => PciDeviceClassSatelliteCommunicationControllerSubclass::SatelliteVoiceController,
                0x4 => PciDeviceClassSatelliteCommunicationControllerSubclass::SatelliteDataController,
                _ => unreachable!(),
            }),
            0x10 => PciDeviceClass::EncryptionOrDecryptionController(match subclass_id {
                0x0 => PciDeviceClassEncryptionControllerSubclass::NetworkAndComputingEncryptionOrDecryption,
                0x10 => PciDeviceClassEncryptionControllerSubclass::EntertainmentEncryptionOrDecryption,
                _ => unreachable!(),
            }),
            0x11 => PciDeviceClass::DataAcquisitionAndSignalProcessingController(match subclass_id {
                0x0 => PciDeviceClassSignalProcessingControllerSubclass::DpioModules,
                0x1 => PciDeviceClassSignalProcessingControllerSubclass::PerformanceCounters,
                0x10 => PciDeviceClassSignalProcessingControllerSubclass::CommunicationSynchronizer,
                0x20 => PciDeviceClassSignalProcessingControllerSubclass::SignalProcessingManagement,
                _ => unreachable!(),
            }),
            0x12 => PciDeviceClass::ProcessingAccelerator,
            0x13 => PciDeviceClass::NonEssentialInstrumentation,
            _ => unreachable!(),
        }
    }
}

#[derive(Debug, Eq, PartialEq, Hash)]
pub enum PciDeviceClassUndefinedSubclass {
    NonVgaCompatibleUnclassifiedDevice,
    VgaCompatibleUnclassifiedDevice,
}

#[derive(Debug, Eq, PartialEq, Hash)]
pub enum PciDeviceClassMassStorageControllerSubclass {
    ScsiBusController,
    IdeController,
    FloppyDiskController,
    IpiBusController,
    RaidController,
    AtaController,
    SataController,
    SerialAttachedScsiController,
    NonVolatileMemoryController,
}

#[derive(Debug, Eq, PartialEq, Hash)]
pub enum PciDeviceClassNetworkControllerSubclass {
    EthernetController,
    TokenRingController,
    FddiController,
    AtmController,
    IsdnController,
    WorldFipController,
    PicmgMultimComputingController,
    InfinibandController,
    FabricController,
}

#[derive(Debug, Eq, PartialEq, Hash)]
pub enum PciDeviceClassDisplayControllerSubclass {
    VgaCompatibleController,
    XgaController,
    NotVgaCompatible3dController,
}

#[derive(Debug, Eq, PartialEq, Hash)]
pub enum PciDeviceClassMultimediaControllerSubclass {
    MultimediaVideoController,
    MultimediaAudioController,
    ComputerTelephonyDevice,
    AudioDevice,
}

#[derive(Debug, Eq, PartialEq, Hash)]
pub enum PciDeviceClassMemoryControllerSubclass {
    RamController,
    FlashController,
}

#[derive(Debug, Eq, PartialEq, Hash)]
pub enum PciDeviceClassBridgeSubclass {
    HostBridge,
    IsaBridge,
    EisaBridge,
    McaBridge,
    PciToPciBridge,
    PcmciaBridge,
    NuBusBridge,
    CardBusBridge,
    RaceWayBridge,
    PciToPciBridge2,
    InfiniBandToPciHostBridge,
}

#[derive(Debug, Eq, PartialEq, Hash)]
pub enum PciDeviceClassSimpleCommunicationControllerSubclass {
    SerialController,
    ParallelController,
    MultiportSerialController,
    Modem,
    GpibController,
    SmartCardController,
}

#[derive(Debug, Eq, PartialEq, Hash)]
pub enum PciDeviceClassBaseSystemPeripheralSubclass {
    Pic,
    DmaController,
    Timer,
    RtcController,
    PciHotPlugController,
    SdHostController,
    IoMmu,
}

#[derive(Debug, Eq, PartialEq, Hash)]
pub enum PciDeviceClassInputDeviceControllerSubclass {
    KeyboardController,
    DigitizerPen,
    MouseController,
    ScannerController,
    GameportController,
}

#[derive(Debug, Eq, PartialEq, Hash)]
pub enum PciDeviceClassDockingStationSubclass {
    Generic,
}

#[allow(nonstandard_style)]
#[derive(Debug, Eq, PartialEq, Hash)]
pub enum PciDeviceClassProcessorSubclass {
    x386,
    x486,
    Pentium,
    PentiumPro,
    Alpha,
    PowerPc,
    Mips,
    CoProcessor,
}

#[derive(Debug, Eq, PartialEq, Hash)]
pub enum PciDeviceClassSerialBusControllerSubclass {
    FireWireController,
    AccessBusController,
    Ssa,
    UsbController,
    FibreChannel,
    SmbusController,
    InfiniBandController,
    IpmiInterface,
    SercosInterface,
    CanbusController,
}

#[derive(Debug, Eq, PartialEq, Hash)]
pub enum PciDeviceClassWirelessControllerSubclass {
    IrdaCompatibleController,
    ConsumerIrController,
    RfController,
    BluetoothController,
    BroadbandController,
    EthernetControllerA,
    EthernetControllerB,
}

#[derive(Debug, Eq, PartialEq, Hash)]
pub enum PciDeviceClassIntelligentControllerSubclass {
    I20,
}

#[derive(Debug, Eq, PartialEq, Hash)]
pub enum PciDeviceClassSatelliteCommunicationControllerSubclass {
    SatelliteTvController,
    SatelliteAudioController,
    SatelliteVoiceController,
    SatelliteDataController,
}

#[derive(Debug, Eq, PartialEq, Hash)]
pub enum PciDeviceClassEncryptionControllerSubclass {
    NetworkAndComputingEncryptionOrDecryption,
    EntertainmentEncryptionOrDecryption,
}

#[derive(Debug, Eq, PartialEq, Hash)]
pub enum PciDeviceClassSignalProcessingControllerSubclass {
    DpioModules,
    PerformanceCounters,
    CommunicationSynchronizer,
    SignalProcessingManagement,
}
