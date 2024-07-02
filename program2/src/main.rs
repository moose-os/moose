#![no_std]
#![no_main]

use core::arch::asm;

#[used]
static MESSAGE: &str = "Second";

#[no_mangle]
extern "C" fn _start() {
    unsafe {
        asm!(
            "
                xor rcx, rcx

                mov rsi, {message}
                mov rdx, {length}
                mov rax, 1
                mov rdi, 1

                2:
                    add rcx, 1
                    test rcx, 10000
                    jz 3f
                    jnz 2b

                3:
                    xor rcx, rcx
                    int 80h
                    jmp 2b
            ",
            message = in(reg) MESSAGE as *const _ as *const u8 as u64,
            length = const(MESSAGE.len()),
        );
    }
}

#[panic_handler]
fn rust_panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
