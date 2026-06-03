use spin::Mutex;

use crate::arch::x86::asm::{inb, outb};

const COM1: u16 = 0x3f8;

static COM_MUTEX: Mutex<()> = Mutex::new(());

static mut IS_COM1_USED: bool = false;

#[derive(Clone, Copy)]
pub enum SerialPort {
    COM1,
}

impl SerialPort {
    pub fn open(&self) -> Result<Serial, ()> {
        let _lock = COM_MUTEX.lock();

        // SAFETY: This is safe because we synchronize all reads and writes.
        if unsafe { IS_COM1_USED } {
            return Err(());
        }

        // SAFETY: This is safe because we synchronize all reads and writes.
        unsafe { IS_COM1_USED = true };

        // Source: https://wiki.osdev.org/Serial_Ports

        let port = match *self {
            SerialPort::COM1 => COM1,
        };

        outb(port + 1, 0x00); // Disable all interrupts

        outb(port + 3, 0x80); // Enable DLAB (set baud rate divisor)
        outb(port, 0x03); // Set divisor to 3 (lo byte) 38400 baud
        outb(port + 1, 0x00); //                  (hi byte)
        outb(port + 3, 0x03); // 8 bits, no parity, one stop bit

        outb(port + 2, 0xC7); // Enable FIFO, clear them, with 14-byte threshold

        outb(port + 4, 0x0B); // IRQs enabled, RTS/DSR set

        outb(port + 4, 0x1E); // Set in loopback mode, test the serial chip

        // Test serial chip (send byte 0xAE and check if serial returns same byte)
        outb(port, 0xAE);

        if inb(port) != 0xAE {
            return Err(());
        }

        // If serial is not faulty set it in normal operation mode
        // (not-loopback with IRQs enabled and OUT#1 and OUT#2 bits enabled)
        outb(port + 4, 0x0F);

        Ok(Serial { port })
    }
}

pub struct Serial {
    port: u16,
}

impl Serial {
    pub fn output(&mut self, string: &str) {
        for byte in string.bytes() {
            while inb(self.port + 5) & 0x20 == 0 {}

            outb(self.port, byte);
        }
    }
}

impl core::fmt::Write for Serial {
    fn write_str(&mut self, string: &str) -> core::fmt::Result {
        self.output(string);

        Ok(())
    }
}
