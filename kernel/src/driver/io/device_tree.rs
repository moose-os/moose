use alloc::{string::String, vec::Vec};

pub struct DeviceTree {
    root: Device,
}

pub struct Device {
    name: String,
    type_: DeviceType,
    children: Vec<Device>, // arc rwlock?
    driver: DeviceDriver // arc?
}

struct DeviceDriver {
    // ???
}

pub enum DeviceType {
    Device,
    Hub,
    Bus,
}