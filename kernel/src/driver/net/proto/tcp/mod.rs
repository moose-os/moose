//! TCP protocol implementation.

mod abc;
mod cc;
mod checksum;
mod cwv;
mod driver;
mod ecn;
mod eifel;
mod frto;
mod options;
mod pacing;
mod receive_buffer;
mod sack;
mod timestamp;
mod types;

#[allow(unused_imports)]
pub use cc::{CongestionControl, CubicState, RenoState, TcpCcSnapshot};
pub use driver::TcpDriver;
#[allow(unused_imports)]
pub use options::{TcpOption, TcpOptionsParser, TcpOptionsWriter};
#[allow(unused_imports)]
pub use receive_buffer::TcpReceiveBuffer;
pub use types::*;

extern "C" fn tcp_worker(_arg: u64) -> ! {
    use crate::kernel::kernel_ref;

    kernel_ref().network_subsystem().tcp().tcp_timer_thread();
}
