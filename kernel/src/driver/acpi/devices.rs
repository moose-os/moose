use core::{
    ffi::{c_void, CStr},
    fmt::{Debug, Formatter},
    ops::Range,
    ptr::null_mut,
    slice,
};

use acpica_rs::{
    sys::{
        AcpiGetCurrentResources, AcpiGetObjectInfo, AcpiWalkNamespace, ACPI_BUFFER,
        ACPI_DEVICE_INFO, ACPI_HANDLE, ACPI_RESOURCE, ACPI_RESOURCE_TYPE_ADDRESS16,
        ACPI_RESOURCE_TYPE_ADDRESS32, ACPI_RESOURCE_TYPE_ADDRESS64, ACPI_RESOURCE_TYPE_DMA,
        ACPI_RESOURCE_TYPE_END_TAG, ACPI_RESOURCE_TYPE_EXTENDED_IRQ,
        ACPI_RESOURCE_TYPE_FIXED_MEMORY32, ACPI_RESOURCE_TYPE_IO, ACPI_RESOURCE_TYPE_IRQ,
        ACPI_RESOURCE_TYPE_VENDOR, ACPI_STATUS, ACPI_TYPE_ANY, ACPI_TYPE_DEVICE, ACPI_TYPE_METHOD,
    },
    AE_OK,
};

use alloc::{borrow::ToOwned, boxed::Box, fmt, string::String, sync::Arc, vec::Vec};
use spin::Mutex;

use super::hid::AcpiHid;

pub type DeviceHandle = Arc<Mutex<Device>>;
pub type AcpiHandle = ACPI_HANDLE;

/// Represents a device in the system, retrieved from the ACPI AML bytecode.
pub struct Device {
    /// Declared short name of the device.
    name: String,
    /// Name derived from evaluating `_HID` method on device.
    hid_name: Option<AcpiHid>,
    /// ACPICA object handle.
    handle: AcpiHandle,
    /// Optional parent of the device.
    parent: Option<DeviceHandle>,
    /// List of children devices (e.g. childrens of PCI bus are all connected devices).
    children: Vec<DeviceHandle>,
    /// List of declared methods.
    methods: Vec<Method>,
    /// List of declared resources.
    resources: Vec<Resource>,
}

impl Debug for Device {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Device")
            .field("name", &self.name)
            .field("hid_name", &self.hid_name)
            .field("methods", &self.methods)
            .field("resources", &self.resources)
            .field("children", &self.children)
            .finish()
    }
}

/// Represents an ACPI method associated with a device.
struct Method {
    /// Method name, typically four-character string.
    name: String,
    /// ACPICA object handle
    handle: AcpiHandle,
    /// Number of arguments the method expects.
    arg_count: usize,
}

impl Debug for Method {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Method")
            .field("name", &self.name)
            .field("arg_count", &self.arg_count)
            .finish()
    }
}

/// Represents a resource declared by a device in the ACPI AML bytecode.
///
/// Resources are hardware-related elements such as memory regions, I/O ports, interrupt numbers
#[derive(Debug)]
enum Resource {
    /// Describes a range of memory addresses used by the device.
    ///
    /// - `fixed`: Indicates whether the memory address is fixed or can be relocated.
    /// - `addresses`: The range of memory addresses allocated to the device.
    Memory { fixed: bool, addresses: Range<u64> },

    /// IO port that the device uses to communicate with the processor.
    ///
    /// - `port`: The specific I/O port number occupied by the device.
    IoPort { port: u16 },

    /// IRQ line that the device uses to signal the CPU.
    ///
    /// - `number`: The IRQ number assigned to the device.
    /// - `wake_capable`: Indicates if the device can wake the system from a low-power state
    /// - `shared`: Indicates whether this IRQ is shared with other devices.
    /// - `polarity`: Specifies the polarity of the interrupt signal (active high or active low)
    /// - `mode`: Specifies the triggering mode of the interrupt (edge triggered or level triggered)
    Irq {
        number: u16,
        wake_capable: bool,
        shared: bool,
        polarity: InterruptPolarity,
        mode: InterruptMode,
    },
}

/// Represents the polarity of an interrupt signal.
#[derive(Debug)]
pub enum InterruptPolarity {
    ActiveHigh,
    ActiveLow,
}

/// Represents the triggering mode of an interrupt.
#[derive(Debug)]
pub enum InterruptMode {
    LevelTriggered,
    EdgeTriggered,
}

struct Context {
    devices: Vec<DeviceHandle>,
    current: Option<DeviceHandle>,
    current_method: Option<String>,
}

/// This functions scans the ACPI tables and returns a list of devices detected on the system.
pub fn create_device_list() -> Vec<DeviceHandle> {
    let mut return_value = 0;
    let mut return_value_ptr = &mut return_value as *mut _ as *mut c_void;

    let mut context = Context {
        devices: Vec::new(),
        current: None,
        current_method: None,
    };

    let status = unsafe {
        AcpiWalkNamespace(
            ACPI_TYPE_ANY,
            usize::MAX as *mut c_void,
            15,
            Some(descending_callback),
            Some(ascending_callback),
            &mut context as *mut Context as *mut _,
            &mut return_value_ptr as *mut *mut c_void,
        )
    };
    // @TODO: Processors?
    assert_eq!(status, AE_OK);

    context.devices
}

extern "C" fn ascending_callback(
    object: ACPI_HANDLE,
    _nesting_level: u32,
    context: *mut c_void,
    return_value: *mut *mut c_void,
) -> ACPI_STATUS {
    unsafe { *return_value = null_mut() };

    let mut device_info = null_mut::<ACPI_DEVICE_INFO>();

    // SAFETY: Trivially safe, supplied pointer is valid and we trust ACPICA :>
    assert_eq!(
        unsafe { AcpiGetObjectInfo(object, &mut device_info) },
        AE_OK
    );

    assert_ne!(device_info, null_mut());
    assert_ne!(context, null_mut());

    let context = unsafe { &mut *(context as *mut Context) };
    let device_info = unsafe { &*device_info };

    match device_info.Type {
        ACPI_TYPE_DEVICE => handle_device_object(object, device_info, context),
        ACPI_TYPE_METHOD => handle_method_object(object, device_info, context),
        _ => {}
    };

    if device_info.Type != ACPI_TYPE_DEVICE {
        return AE_OK;
    }

    context.current = context
        .current
        .as_ref()
        .map(|current| current.lock().parent.clone())
        .unwrap_or(None);

    AE_OK
}

extern "C" fn descending_callback(
    object: ACPI_HANDLE,
    _nesting_level: u32,
    context: *mut c_void,
    return_value: *mut *mut c_void,
) -> ACPI_STATUS {
    unsafe { *return_value = null_mut() };

    let mut device_info = null_mut::<ACPI_DEVICE_INFO>();

    // SAFETY: Trivially safe, supplied pointer is valid and we trust ACPICA :>
    assert_eq!(
        unsafe { AcpiGetObjectInfo(object, &mut device_info) },
        AE_OK
    );

    assert_ne!(device_info, null_mut());
    assert_ne!(context, null_mut());

    let context = unsafe { &mut *(context as *mut Context) };

    let device_info = unsafe { &*device_info };

    match device_info.Type {
        ACPI_TYPE_DEVICE => handle_device_object(object, device_info, context),
        ACPI_TYPE_METHOD => handle_method_object(object, device_info, context),
        _ => {}
    };

    AE_OK
}

fn handle_device_object(
    handle: ACPI_HANDLE,
    device_info: &ACPI_DEVICE_INFO,
    context: &mut Context,
) {
    let name = get_object_name(device_info);

    let device = Arc::new(Mutex::new(Device {
        name,
        hid_name: get_device_hardware_id(device_info).map(AcpiHid::new),
        handle,
        parent: context.current.clone(),
        children: Vec::new(),
        methods: Vec::new(),
        resources: Vec::new(),
    }));

    if let Some(current) = &context.current {
        let mut current = current.lock();

        current.children.push(device.clone());
    }

    context.current = Some(device.clone());

    context.devices.push(device);
}

fn handle_method_object(
    handle: ACPI_HANDLE,
    device_info: &ACPI_DEVICE_INFO,
    context: &mut Context,
) {
    if let Some(device) = &context.current {
        let mut device = device.lock();
        let name = get_object_name(device_info);

        // Check if the device declares any resources
        if name == "_CRS" {
            let data = Box::new([0u8; 4096]);

            let mut resources_buffer = ACPI_BUFFER {
                Length: 4096,
                Pointer: data.as_ptr() as *mut _,
            };

            let status = unsafe { AcpiGetCurrentResources(device.handle, &mut resources_buffer) };
            assert_eq!(status, AE_OK);

            let mut pointer = resources_buffer.Pointer;

            loop {
                let resource = pointer as *const ACPI_RESOURCE;
                let res = unsafe { &*(pointer as *const ACPI_RESOURCE) };

                if res.Type == ACPI_RESOURCE_TYPE_END_TAG {
                    break;
                }

                match res.Type {
                    ACPI_RESOURCE_TYPE_IO => {
                        let io = unsafe { (*resource).Data.Io.as_ref() };

                        device.resources.extend(
                            (io.Minimum..=io.Maximum).map(|port| Resource::IoPort { port }),
                        );
                    }
                    ACPI_RESOURCE_TYPE_IRQ => {
                        let irq = unsafe { (*resource).Data.Irq.as_ref() };

                        device.resources.push(Resource::Irq {
                            number: unsafe { *irq.__bindgen_anon_1.Interrupt.as_ref() } as u16,
                            wake_capable: irq.WakeCapable != 0,
                            shared: irq.Shareable != 0,
                            polarity: if irq.Polarity == 0 {
                                InterruptPolarity::ActiveHigh
                            } else {
                                InterruptPolarity::ActiveLow
                            },
                            mode: if irq.Triggering == 0 {
                                InterruptMode::LevelTriggered
                            } else {
                                InterruptMode::EdgeTriggered
                            },
                        })
                    }
                    ACPI_RESOURCE_TYPE_EXTENDED_IRQ => {
                        let irq = unsafe { (*resource).Data.ExtendedIrq.as_ref() };

                        assert_eq!(irq.InterruptCount, 1);

                        device.resources.push(Resource::Irq {
                            number: unsafe { *irq.__bindgen_anon_1.Interrupt.as_ref() } as u16,
                            wake_capable: irq.WakeCapable != 0,
                            shared: irq.Shareable != 0,
                            polarity: if irq.Polarity == 0 {
                                InterruptPolarity::ActiveHigh
                            } else {
                                InterruptPolarity::ActiveLow
                            },
                            mode: if irq.Triggering == 0 {
                                InterruptMode::LevelTriggered
                            } else {
                                InterruptMode::EdgeTriggered
                            },
                        })
                    }
                    ACPI_RESOURCE_TYPE_ADDRESS16 => {
                        let memory = unsafe { (*resource).Data.Address16.as_ref() };

                        device.resources.push(Resource::Memory {
                            fixed: false,
                            addresses: (memory.MinAddressFixed as u64
                                ..memory.MaxAddressFixed as u64),
                        })
                    }
                    ACPI_RESOURCE_TYPE_ADDRESS32 => {
                        let memory = unsafe { (*resource).Data.Address32.as_ref() };

                        device.resources.push(Resource::Memory {
                            fixed: false,
                            addresses: (memory.MinAddressFixed as u64
                                ..memory.MaxAddressFixed as u64),
                        })
                    }
                    ACPI_RESOURCE_TYPE_ADDRESS64 => {
                        let memory = unsafe { (*resource).Data.Address64.as_ref() };

                        device.resources.push(Resource::Memory {
                            fixed: false,
                            addresses: (memory.MinAddressFixed as u64
                                ..memory.MaxAddressFixed as u64),
                        })
                    }
                    ACPI_RESOURCE_TYPE_DMA => {}
                    ACPI_RESOURCE_TYPE_FIXED_MEMORY32 => {
                        let memory = unsafe { (*resource).Data.FixedMemory32.as_ref() };

                        device.resources.push(Resource::Memory {
                            fixed: true,
                            addresses: (memory.Address as u64
                                ..(memory.Address as u64 + memory.AddressLength as u64)),
                        })
                    }
                    ACPI_RESOURCE_TYPE_VENDOR => {}
                    invalid => panic!("Invalid resource type {}", invalid),
                }

                unsafe { pointer = pointer.add(res.Length as usize) };
            }
        }

        if let Some(current_method) = &context.current_method {
            if *current_method != name {
                device.methods.push(Method {
                    name: name.clone(),
                    handle,
                    arg_count: device_info.ParamCount as usize,
                });
            }
        }

        context.current_method = Some(name);
    }
}

fn get_object_name(device_info: &ACPI_DEVICE_INFO) -> String {
    let parts = [
        (device_info.Name & 0xFF) as u8,
        ((device_info.Name >> 8) & 0xFF) as u8,
        ((device_info.Name >> 16) & 0xFF) as u8,
        ((device_info.Name >> 24) & 0xFF) as u8,
        0,
    ];

    CStr::from_bytes_until_nul(&parts[..]).map_or_else(
        |_| String::new(),
        |string| string.to_string_lossy().into_owned(),
    )
}

fn get_device_hardware_id(device_info: &ACPI_DEVICE_INFO) -> Option<String> {
    assert_eq!(device_info.Type, ACPI_TYPE_DEVICE);

    if device_info.HardwareId.String.addr() == 0 {
        return None;
    }

    let string_pointer = device_info.HardwareId.String as *mut u8;
    let string_length = device_info.HardwareId.Length;

    let slice = unsafe { slice::from_raw_parts(string_pointer, string_length as usize) };

    Some(
        CStr::from_bytes_until_nul(slice)
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned(),
    )
}
