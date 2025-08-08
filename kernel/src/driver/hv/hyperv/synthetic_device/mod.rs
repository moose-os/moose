use crate::driver::hv::hyperv::VmBusOfferChannel;

pub mod gpu;
pub mod keyboard;
pub mod mouse;
pub mod nic;

pub trait VmBusSyntheticDevice: Sync + Send {
    fn initialize(&self) -> bool;
    fn has_data_to_process(&self) -> bool;
    fn process_incoming_data(&self);
}

#[derive(Copy, Clone, Debug)]
pub struct Resolution {
    pub width: usize,
    pub height: usize,
}

pub struct DirtyRectangle {
    x1: i32,
    y1: i32,

    x2: i32,
    y2: i32,
}
