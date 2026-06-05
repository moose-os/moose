use alloc::{vec, vec::Vec};

use crate::arch::x86::asm::{inl, outl};

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

        for bus in 0..256 {
            for device in 0..32 {
                for function in 0..8 {
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

    fn scan_device(bus: u32, device: u32, function: u32) -> Option<PciDevice> {
        let vendor_id = Pci::read_u16(bus, device, function, 0);
        if vendor_id == 0xFFFF {
            // Device does not exist
            return None;
        }

        let device_id = Pci::read_u16(bus, device, function, 2);
        let class_code = Pci::read_u16(bus, device, function, 10) >> 8;
        let subclass_code = Pci::read_u16(bus, device, function, 10) & 0xF;
        let device = PciDevice {
            bus,
            device,
            function,
            vendor_id,
            device_id,
            class: PciDeviceClass::parse(class_code as u32, subclass_code as u32),
        };

        debug!(
            "Found new device: {:#x?}:{:#x?} (class: {:?}, vendor: {}, device: {})",
            vendor_id,
            device_id,
            device.class,
            get_device_manufacturer_string(&device),
            get_device_name(&device)
        );

        Some(device)
    }

    pub fn read_u8(bus: u32, device: u32, function: u32, offset: u32) -> u8 {
        let address: u32 =
            (bus << 16) | (device << 11) | (function << 8) | (offset & 0xFC) | 0x80000000;
        outl(CONFIG_ADDRESS, address);

        ((inl(CONFIG_DATA) >> ((offset & 2) * 8)) & 0xFF) as u8
    }

    pub fn read_u16(bus: u32, device: u32, function: u32, offset: u32) -> u16 {
        let address: u32 =
            (bus << 16) | (device << 11) | (function << 8) | (offset & 0xFC) | 0x80000000;
        outl(CONFIG_ADDRESS, address);

        ((inl(CONFIG_DATA) >> ((offset & 2) * 8)) & 0xFFFF) as u16
    }

    pub fn read_u32(bus: u32, device: u32, function: u32, offset: u32) -> u32 {
        let address: u32 =
            (bus << 16) | (device << 11) | (function << 8) | (offset & 0xFC) | 0x80000000;
        outl(CONFIG_ADDRESS, address);

        inl(CONFIG_DATA) >> ((offset & 2) * 8)
    }

    pub fn write_u8(bus: u32, device: u32, function: u32, offset: u32, value: u8) {
        let address: u32 =
            (bus << 16) | (device << 11) | (function << 8) | (offset & 0xFC) | 0x80000000;
        outl(CONFIG_ADDRESS, address);

        outl(CONFIG_DATA, value as u32);
    }

    pub fn write_u16(bus: u32, device: u32, function: u32, offset: u32, value: u16) {
        let address: u32 =
            (bus << 16) | (device << 11) | (function << 8) | (offset & 0xFC) | 0x80000000;
        outl(CONFIG_ADDRESS, address);

        outl(CONFIG_DATA, value as u32);
    }

    pub fn write_u32(bus: u32, device: u32, function: u32, offset: u32, value: u32) {
        let address: u32 =
            (bus << 16) | (device << 11) | (function << 8) | (offset & 0xFC) | 0x80000000;
        outl(CONFIG_ADDRESS, address);

        outl(CONFIG_DATA, value);
    }
}

pub struct PciDevice {
    bus: u32,
    device: u32,
    function: u32,

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

        (higher_word << 16) | lower_word
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
        let address: u32 = (self.bus << 16)
            | (self.device << 11)
            | (self.function << 8)
            | (offset & 0xFC)
            | 0x80000000;
        outl(CONFIG_ADDRESS, address);

        inl(CONFIG_DATA)
    }

    fn write(&self, offset: u32, value: u32) {
        let address: u32 = (self.bus << 16)
            | (self.device << 11)
            | (self.function << 8)
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

#[derive(Debug, Eq, PartialEq)]
pub enum PciDeviceClass {
    Undefined(UndefinedSubclass),
    MassStorageController(MassStorageControllerSubclass),
    NetworkController(NetworkControllerSubclass),
    DisplayController(DisplayControllerSubclass),
    MultimediaDevice(MultimediaControllerSubclass),
    MemoryController(MemoryControllerSubclass),
    Bridge(BridgeSubclass),
    SimpleCommunicationController(SimpleCommunicationControllerSubclass),
    BaseSystemPeripheral(BaseSystemPeripheralSubclass),
    InputDevice(InputDeviceControllerSubclass),
    DockingStation(DockingStationSubclass),
    Processor(ProcessorSubclass),
    SerialBusController(SerialBusControllerSubclass),
    WirelessController(WirelessControllerSubclass),
    IntelligentIoController(IntelligentControllerSubclass),
    SatelliteCommunicationController(SatelliteCommunicationControllerSubclass),
    EncryptionController(EncryptionControllerSubclass),
    DataAcquisitionAndSignalProcessingController(SignalProcessingControllerSubclass),
    ProcessingAccelerator,
    NonEssentialInstrumentation,
    // Reserved
    Unknown,
}

impl PciDeviceClass {
    pub fn parse(class_id: u32, subclass_id: u32) -> PciDeviceClass {
        match class_id {
            0x0 => PciDeviceClass::Undefined(match subclass_id {
                0x0 => UndefinedSubclass::NonVgaCompatibleUnclassifiedDevice,
                0x1 => UndefinedSubclass::VgaCompatibleUnclassifiedDevice,
                _ => unreachable!(),
            }),
            0x1 => PciDeviceClass::MassStorageController(match subclass_id {
                0x0 => MassStorageControllerSubclass::ScsiBus,
                0x1 => MassStorageControllerSubclass::Ide,
                0x2 => MassStorageControllerSubclass::FloppyDisk,
                0x3 => MassStorageControllerSubclass::IpiBus,
                0x4 => MassStorageControllerSubclass::Raid,
                0x5 => MassStorageControllerSubclass::Ata,
                0x6 => MassStorageControllerSubclass::Sata,
                0x7 => MassStorageControllerSubclass::SerialAttachedScsi,
                0x8 => MassStorageControllerSubclass::NonVolatileMemory,
                _ => unreachable!(),
            }),
            0x2 => PciDeviceClass::NetworkController(match subclass_id {
                0x0 => NetworkControllerSubclass::Ethernet,
                0x1 => NetworkControllerSubclass::TokenRing,
                0x2 => NetworkControllerSubclass::Fddi,
                0x3 => NetworkControllerSubclass::Atm,
                0x4 => NetworkControllerSubclass::Isdn,
                0x5 => NetworkControllerSubclass::WorldFip,
                0x6 => NetworkControllerSubclass::PicmgMultimComputing,
                0x7 => NetworkControllerSubclass::Infiniband,
                0x8 => NetworkControllerSubclass::Fabric,
                _ => unreachable!(),
            }),
            0x3 => PciDeviceClass::DisplayController(match subclass_id {
                0x0 => DisplayControllerSubclass::VgaCompatible,
                0x1 => DisplayControllerSubclass::Xga,
                0x2 => DisplayControllerSubclass::NotVgaCompatible3d,
                _ => unreachable!(),
            }),
            0x4 => PciDeviceClass::MultimediaDevice(match subclass_id {
                0x0 => MultimediaControllerSubclass::MultimediaVideo,
                0x1 => MultimediaControllerSubclass::MultimediaAudio,
                0x2 => MultimediaControllerSubclass::ComputerTelephonyDevice,
                0x3 => MultimediaControllerSubclass::AudioDevice,
                _ => unreachable!(),
            }),
            0x5 => PciDeviceClass::MemoryController(match subclass_id {
                0x0 => MemoryControllerSubclass::Ram,
                0x1 => MemoryControllerSubclass::Flash,
                _ => unreachable!(),
            }),
            0x6 => PciDeviceClass::Bridge(match subclass_id {
                0x0 => BridgeSubclass::Host,
                0x1 => BridgeSubclass::Isa,
                0x2 => BridgeSubclass::Eisa,
                0x3 => BridgeSubclass::Mca,
                0x4 => BridgeSubclass::PciToPci,
                0x5 => BridgeSubclass::Pcmcia,
                0x6 => BridgeSubclass::NuBus,
                0x7 => BridgeSubclass::CardBus,
                0x8 => BridgeSubclass::RaceWay,
                0x9 => BridgeSubclass::PciToPci2,
                0xA => BridgeSubclass::InfiniBandToPciHost,
                _ => unreachable!(),
            }),
            0x7 => PciDeviceClass::SimpleCommunicationController(match subclass_id {
                0x0 => SimpleCommunicationControllerSubclass::Serial,
                0x1 => SimpleCommunicationControllerSubclass::Parallel,
                0x2 => SimpleCommunicationControllerSubclass::MultiportSerial,
                0x3 => SimpleCommunicationControllerSubclass::Modem,
                0x4 => SimpleCommunicationControllerSubclass::Gpib,
                0x5 => SimpleCommunicationControllerSubclass::SmartCard,
                _ => unreachable!(),
            }),
            0x8 => PciDeviceClass::BaseSystemPeripheral(match subclass_id {
                0x0 => BaseSystemPeripheralSubclass::Pic,
                0x1 => BaseSystemPeripheralSubclass::DmaController,
                0x2 => BaseSystemPeripheralSubclass::Timer,
                0x3 => BaseSystemPeripheralSubclass::RtcController,
                0x4 => BaseSystemPeripheralSubclass::PciHotPlugController,
                0x5 => BaseSystemPeripheralSubclass::SdHostController,
                0x6 => BaseSystemPeripheralSubclass::IoMmu,
                _ => unreachable!(),
            }),
            0x9 => PciDeviceClass::InputDevice(match subclass_id {
                0x0 => InputDeviceControllerSubclass::Keyboard,
                0x1 => InputDeviceControllerSubclass::DigitizerPen,
                0x2 => InputDeviceControllerSubclass::Mouse,
                0x3 => InputDeviceControllerSubclass::Scanner,
                0x4 => InputDeviceControllerSubclass::Gameport,
                _ => unreachable!(),
            }),
            0xA => PciDeviceClass::DockingStation(match subclass_id {
                0x0 => DockingStationSubclass::Generic,
                _ => unreachable!(),
            }),
            0xB => PciDeviceClass::Processor(match subclass_id {
                0x0 => ProcessorSubclass::x386,
                0x1 => ProcessorSubclass::x486,
                0x2 => ProcessorSubclass::Pentium,
                0x3 => ProcessorSubclass::PentiumPro,
                0x10 => ProcessorSubclass::Alpha,
                0x20 => ProcessorSubclass::PowerPc,
                0x30 => ProcessorSubclass::Mips,
                0x40 => ProcessorSubclass::CoProcessor,
                _ => unreachable!(),
            }),
            0xC => PciDeviceClass::SerialBusController(match subclass_id {
                0x0 => SerialBusControllerSubclass::FireWire,
                0x1 => SerialBusControllerSubclass::AccessBus,
                0x2 => SerialBusControllerSubclass::Ssa,
                0x3 => SerialBusControllerSubclass::UsbController,
                0x4 => SerialBusControllerSubclass::FibreChannel,
                0x5 => SerialBusControllerSubclass::SmbusController,
                0x6 => SerialBusControllerSubclass::InfiniBand,
                0x7 => SerialBusControllerSubclass::IpmiInterface,
                0x8 => SerialBusControllerSubclass::SercosInterface,
                0x9 => SerialBusControllerSubclass::Canbus,
                _ => unreachable!(),
            }),
            0xD => PciDeviceClass::WirelessController(match subclass_id {
                0x0 => WirelessControllerSubclass::IrdaCompatible,
                0x1 => WirelessControllerSubclass::ConsumerIr,
                0x10 => WirelessControllerSubclass::Rf,
                0x11 => WirelessControllerSubclass::Bluetooth,
                0x12 => WirelessControllerSubclass::Broadband,
                0x20 => WirelessControllerSubclass::EthernetA,
                0x21 => WirelessControllerSubclass::EthernetB,
                _ => unreachable!(),
            }),
            0xE => PciDeviceClass::IntelligentIoController(match subclass_id {
                0x0 => IntelligentControllerSubclass::I20,
                _ => unreachable!(),
            }),
            0xF => PciDeviceClass::SatelliteCommunicationController(match subclass_id {
                0x1 => SatelliteCommunicationControllerSubclass::Tv,
                0x2 => SatelliteCommunicationControllerSubclass::Audio,
                0x3 => SatelliteCommunicationControllerSubclass::Voice,
                0x4 => SatelliteCommunicationControllerSubclass::Data,
                _ => unreachable!(),
            }),
            0x10 => PciDeviceClass::EncryptionController(match subclass_id {
                0x0 => EncryptionControllerSubclass::NetworkAndComputing,
                0x10 => EncryptionControllerSubclass::Entertainment,
                _ => unreachable!(),
            }),
            0x11 => {
                PciDeviceClass::DataAcquisitionAndSignalProcessingController(match subclass_id {
                    0x0 => SignalProcessingControllerSubclass::DpioModules,
                    0x1 => SignalProcessingControllerSubclass::PerformanceCounters,
                    0x10 => SignalProcessingControllerSubclass::CommunicationSynchronizer,
                    0x20 => SignalProcessingControllerSubclass::SignalProcessingManagement,
                    _ => unreachable!(),
                })
            }
            0x12 => PciDeviceClass::ProcessingAccelerator,
            0x13 => PciDeviceClass::NonEssentialInstrumentation,
            _ => unreachable!(),
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum UndefinedSubclass {
    NonVgaCompatibleUnclassifiedDevice,
    VgaCompatibleUnclassifiedDevice,
}

#[derive(Debug, Eq, PartialEq)]
pub enum MassStorageControllerSubclass {
    ScsiBus,
    Ide,
    FloppyDisk,
    IpiBus,
    Raid,
    Ata,
    Sata,
    SerialAttachedScsi,
    NonVolatileMemory,
}

#[derive(Debug, Eq, PartialEq)]
pub enum NetworkControllerSubclass {
    Ethernet,
    TokenRing,
    Fddi,
    Atm,
    Isdn,
    WorldFip,
    PicmgMultimComputing,
    Infiniband,
    Fabric,
}

#[derive(Debug, Eq, PartialEq)]
pub enum DisplayControllerSubclass {
    VgaCompatible,
    Xga,
    NotVgaCompatible3d,
}

#[derive(Debug, Eq, PartialEq)]
pub enum MultimediaControllerSubclass {
    MultimediaVideo,
    MultimediaAudio,
    ComputerTelephonyDevice,
    AudioDevice,
}

#[derive(Debug, Eq, PartialEq)]
pub enum MemoryControllerSubclass {
    Ram,
    Flash,
}

#[derive(Debug, Eq, PartialEq)]
pub enum BridgeSubclass {
    Host,
    Isa,
    Eisa,
    Mca,
    PciToPci,
    Pcmcia,
    NuBus,
    CardBus,
    RaceWay,
    PciToPci2,
    InfiniBandToPciHost,
}

#[derive(Debug, Eq, PartialEq)]
pub enum SimpleCommunicationControllerSubclass {
    Serial,
    Parallel,
    MultiportSerial,
    Modem,
    Gpib,
    SmartCard,
}

#[derive(Debug, Eq, PartialEq)]
pub enum BaseSystemPeripheralSubclass {
    Pic,
    DmaController,
    Timer,
    RtcController,
    PciHotPlugController,
    SdHostController,
    IoMmu,
}

#[derive(Debug, Eq, PartialEq)]
pub enum InputDeviceControllerSubclass {
    Keyboard,
    DigitizerPen,
    Mouse,
    Scanner,
    Gameport,
}

#[derive(Debug, Eq, PartialEq)]
pub enum DockingStationSubclass {
    Generic,
}

#[allow(nonstandard_style)]
#[derive(Debug, Eq, PartialEq)]
pub enum ProcessorSubclass {
    x386,
    x486,
    Pentium,
    PentiumPro,
    Alpha,
    PowerPc,
    Mips,
    CoProcessor,
}

#[derive(Debug, Eq, PartialEq)]
pub enum SerialBusControllerSubclass {
    FireWire,
    AccessBus,
    Ssa,
    UsbController,
    FibreChannel,
    SmbusController,
    InfiniBand,
    IpmiInterface,
    SercosInterface,
    Canbus,
}

#[derive(Debug, Eq, PartialEq)]
pub enum WirelessControllerSubclass {
    IrdaCompatible,
    ConsumerIr,
    Rf,
    Bluetooth,
    Broadband,
    EthernetA,
    EthernetB,
}

#[derive(Debug, Eq, PartialEq)]
pub enum IntelligentControllerSubclass {
    I20,
}

#[derive(Debug, Eq, PartialEq)]
pub enum SatelliteCommunicationControllerSubclass {
    Tv,
    Audio,
    Voice,
    Data,
}

#[derive(Debug, Eq, PartialEq)]
pub enum EncryptionControllerSubclass {
    NetworkAndComputing,
    Entertainment,
}

#[derive(Debug, Eq, PartialEq)]
pub enum SignalProcessingControllerSubclass {
    DpioModules,
    PerformanceCounters,
    CommunicationSynchronizer,
    SignalProcessingManagement,
}
