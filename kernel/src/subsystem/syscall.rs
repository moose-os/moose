use core::{ffi::CStr, ptr};

use crate::subsystem::{clock::time::Duration, scheduler::current_thread};

pub extern "C" fn write_syscall(descriptor: u64, buffer: *const u8, count: u64) {
    info!("sys_write ({descriptor}, {buffer:p}, {count})");

    let mut buffer_copied = [0u8; 512];

    assert!(count < 512);

    unsafe { ptr::copy_nonoverlapping(buffer, buffer_copied.as_mut_ptr(), count as usize) };

    buffer_copied[count as usize] = 0;

    info!(
        "{}",
        CStr::from_bytes_until_nul(&buffer_copied[..])
            .unwrap()
            .to_string_lossy()
    );

    // @TODO: Remove it later, only for testing purposes
    current_thread().sleep(Duration::from_millis(500));
}
