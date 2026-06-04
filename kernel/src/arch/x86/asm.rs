use core::arch::asm;

#[inline(always)]
pub fn disable_interrupts() {
    unsafe {
        asm!("cli", options(nomem, nostack, preserves_flags));
    }
}

#[inline(always)]
pub fn enable_interrupts() {
    unsafe {
        asm!("sti", options(nomem, nostack, preserves_flags));
    }
}

#[inline(always)]
pub fn read_rsp() -> u64 {
    let rsp: u64;

    unsafe {
        asm!("mov {rsp}, rsp", rsp = out(reg) rsp, options(nomem, nostack, preserves_flags));
    }

    rsp
}

#[inline(always)]
pub fn outb(port: u16, byte: u8) {
    unsafe {
        asm!(
            "out dx, al",
            in("dx") port,
            in("al") byte,
        );
    }
}

#[inline(always)]
pub fn inb(port: u16) -> u8 {
    let mut value;

    unsafe {
        asm!(
            "in al, dx",
            out("al") value,
            in("dx") port,
        );
    }

    value
}

#[inline(always)]
pub fn outw(port: u16, byte: u16) {
    unsafe {
        asm!(
            "out dx, ax",
            in("dx") port,
            in("ax") byte,
        );
    }
}

#[inline(always)]
pub fn inw(port: u16) -> u16 {
    let mut value;

    unsafe {
        asm!(
            "in ax, dx",
            out("ax") value,
            in("dx") port,
        );
    }

    value
}

#[inline(always)]
pub fn outl(port: u16, byte: u32) {
    unsafe {
        asm!(
            "out dx, eax",
            in("dx") port,
            in("eax") byte,
        );
    }
}

#[inline(always)]
pub fn inl(port: u16) -> u32 {
    let mut value;

    unsafe {
        asm!(
            "in eax, dx",
            out("eax") value,
            in("dx") port,
        );
    }

    value
}
