use core::fmt::Write;

use crate::kernel::kernel_ref;

#[panic_handler]
fn rust_panic(info: &core::panic::PanicInfo) -> ! {
    let mut serial = kernel_ref().serial().lock();

    if let Some(location) = info.location() {
        _ = write!(
            serial,
            "[\x1b[31mPANIC\x1b[0m]: {} @ {}:{}:{}",
            info.message(),
            location.file(),
            location.line(),
            location.column(),
        );

        if let Some(terminal) = kernel_ref().terminal.get() {
            let mut terminal = terminal.lock();

            _ = write!(
                terminal,
                "[PANIC]: {} @ {}:{}:{}",
                info.message(),
                location.file(),
                location.line(),
                location.column(),
            );
        }
    } else {
        _ = write!(serial, "[\033[91mPANIC\033[0m]: {}", info.message());
    }

    loop {}
}
