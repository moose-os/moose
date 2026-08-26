//! Virtual 16550A UART Serial Port Device Model.
//!
//! Emulates a standard 16550A High-Speed UART with FIFO buffering capabilities and configurable
//! backing devices (Physical Serial Port, Monocle Logger, or Debug Console).
//!
//! ### Architecture & Operation
//! The 16550A UART exposes an 8-byte I/O port window (typically `0x3F8` for COM1, `0x2F8` for COM2).
//! Primary registers include:
//! - Offset 0: Receiver Buffer Register (RBR, Read) / Transmitter Holding Register (THR, Write) / Divisor Latch LSB (DLAB=1).
//! - Offset 1: Interrupt Enable Register (IER) / Divisor Latch MSB (DLAB=1).
//! - Offset 2: Interrupt Identification Register (IIR, Read) / FIFO Control Register (FCR, Write).
//! - Offset 3: Line Control Register (LCR) — Bit 7 controls the Divisor Latch Access Bit (DLAB).
//! - Offset 4: Modem Control Register (MCR) — Bit 4 controls internal Loopback Mode.
//! - Offset 5: Line Status Register (LSR) — Indicates Data Ready (DR), Transmitter Empty (THRE/TEMT).
//! - Offset 6: Modem Status Register (MSR).
//! - Offset 7: Scratchpad Register (SCR).
//!
//! ### Interrupt Handling
//! Emulates standard PC/AT ISA IRQs (`IRQ4` for COM1/COM3, `IRQ3` for COM2/COM4). Priority is resolved as:
//! 1. Received Data Available (RDA) - Triggered when `rx_fifo` has pending data and `IER.RDA` is set.
//! 2. Transmitter Holding Register Empty (THRE) - Triggered when THR is empty and `IER.THRE` is set.

use alloc::{collections::vec_deque::VecDeque, format, sync::Arc, vec::Vec};

use monocle_protocol::MonocleLogSource;
use spin::rwlock::RwLock;

use crate::{
    driver::{
        hv::reindeer::device::{DeviceContext, DeviceResource, VirtualDevice},
        serial::Serial,
    },
    kernel::kernel_ref,
    subsystem::{
        monocle_logger::MonocleLogger,
        process::{DEFAULT_THREAD_PRIORITY, Status},
        scheduler::{current_thread, yield_to_scheduler},
    },
};

/// Offset 0: Receive Buffer Register (RBR)
const RECEIVE_BUFFER_REGISTER_OFFSET: u64 = 0;

/// Offset 0: Transmit Holding Register (THR)
const TRANSMIT_BUFFER_REGISTER_OFFSET: u64 = 0;

/// Offset 1: Interrupt Enable Register (IER)
const INTERRUPT_ENABLE_REGISTER_OFFSET: u64 = 1;

/// Offset 2: Interrupt Identification Register (IIR)
const INTERRUPT_IDENTIFICATION_REGISTER_OFFSET: u64 = 2;

/// Offset 2: FIFO Control Register (FCR)
const FIFO_CONTROL_REGISTER_OFFSET: u64 = 2;

/// Offset 3: Line Control Register (LCR)
const LINE_CONTROL_REGISTER_OFFSET: u64 = 3;

/// Offset 4: Modem Control Register (MCR)
const MODEM_CONTROL_REGISTER_OFFSET: u64 = 4;

/// Offset 5: Line Status Register (LSR)
const LINE_STATUS_REGISTER_OFFSET: u64 = 5;

/// Offset 6: Modem Status Register (MSR)
const MODEM_STATUS_REGISTER_OFFSET: u64 = 6;

/// Offset 7: Scratchpad Register (SCR)
const SCRATCH_REGISTER_OFFSET: u64 = 7;

/// IER Bit 0: Received Data Available Interrupt Enable
const IER_RDA: u8 = 1 << 0;

/// IER Bit 1: Transmitter Holding Register Empty Interrupt Enable
const IER_THRE: u8 = 1 << 1;

/// IIR Code: No interrupt pending (Bit 0 = 1, FIFO Enabled Bits 6-7 = 1)
const IIR_NO_INTERRUPT: u8 = 0xC1;

/// IIR Code: Transmitter Holding Register Empty Interrupt Pending
const IIR_THRE: u8 = 0xC2;

/// IIR Code: Received Data Available Interrupt Pending
const IIR_RDA: u8 = 0xC4;

/// Maximum size of a buffered guest log line.
const TX_LINE_BUFFER_SIZE: usize = 1024;

/// Backing implementation target for guest serial transmission.
pub enum VirtualSerialPortBackingDevice {
    /// Routes output to a physical host serial port driver.
    Com(Serial),

    /// Routes output to a Monocle logging subsystem.
    Remote(Arc<MonocleLogger>),

    /// Prints formatted characters to the internal host debug logger.
    Debug,

    /// Discards all transmitted output.
    None,
}

/// Virtual 16550A UART device state container.
pub struct VirtualSerialPort {
    /// Base I/O Port address.
    base_port: u16,

    /// Output destination for guest writes.
    backing_device: Arc<VirtualSerialPortBackingDevice>,

    /// Port index number.
    n: usize,

    /// Assigned ISA IRQ line (`4` for COM1/COM3, `3` for COM2/COM4).
    irq_line: u8,

    /// Divisor Latch Access Bit (LCR Bit 7).
    dlab: bool,

    /// Loopback Mode Flag (MCR Bit 4).
    loopback: bool,

    /// Line Control Register cache.
    lcr: u8,

    /// Modem Control Register cache.
    mcr: u8,

    /// Scratchpad Register cache.
    scratch: u8,

    /// Last byte received during loopback testing.
    last_byte: u64,

    /// Interrupt Enable Register cache.
    ier: u8,

    /// Flag indicating if a Transmitter Empty Interrupt is currently active.
    thr_irq_pending: bool,

    /// Flag indicating if a Received Data Available Interrupt is currently active.
    rda_irq_pending: bool,

    /// Internal RX FIFO buffer storing bytes injected from host to guest.
    rx_fifo: VecDeque<u8>,

    /// Buffers guest output until a complete newline-terminated log message is available.
    tx_line_buffer: [u8; TX_LINE_BUFFER_SIZE],

    /// Number of bytes currently stored in `tx_line_buffer`.
    tx_line_buffer_len: usize,

    /// Guest platform services assigned after interrupt controllers are initialized.
    device_context: Option<DeviceContext>,
}

impl VirtualSerialPort {
    /// Instantiates a new `VirtualSerialPort` with default registers and allocated RX buffer.
    pub fn new(
        base_port: u16,
        backing_device: VirtualSerialPortBackingDevice,
        n: usize,
    ) -> Arc<RwLock<Self>> {
        let irq_line = match base_port {
            0x3F8 | 0x3E8 => 4,
            0x2F8 | 0x2E8 => 3,
            _ => 4,
        };

        let port = Arc::new(RwLock::new(VirtualSerialPort {
            base_port,
            backing_device: Arc::new(backing_device),
            n,
            irq_line,
            dlab: false,
            loopback: false,
            last_byte: 0,
            lcr: 0,
            mcr: 0,
            scratch: 0,
            ier: 0,
            thr_irq_pending: false,
            rda_irq_pending: false,
            rx_fifo: VecDeque::with_capacity(64),
            tx_line_buffer: [0; TX_LINE_BUFFER_SIZE],
            tx_line_buffer_len: 0,
            device_context: None,
        }));

        kernel_ref()
            .spawn_kernel_thread(
                receive_thread,
                Arc::into_raw(Arc::clone(&port)) as usize as u64,
                DEFAULT_THREAD_PRIORITY + 1,
            )
            .unwrap();

        port
    }

    /// Dispatches guest output byte to the designated backing device.
    fn handle_output(&mut self, value: u8) {
        match &*self.backing_device {
            VirtualSerialPortBackingDevice::Com(_serial) => {
                // serial.write_byte(value);
            }
            VirtualSerialPortBackingDevice::Remote(logger) => {
                if self.tx_line_buffer_len < self.tx_line_buffer.len() {
                    self.tx_line_buffer[self.tx_line_buffer_len] = value;
                    self.tx_line_buffer_len += 1;
                } else if value == b'\n' {
                    self.tx_line_buffer[TX_LINE_BUFFER_SIZE - 1] = value;
                }

                if value == b'\n' {
                    logger.log(
                        MonocleLogSource::Guest(1),
                        &self.tx_line_buffer[..self.tx_line_buffer_len],
                    );

                    self.tx_line_buffer_len = 0;
                }
            }
            VirtualSerialPortBackingDevice::Debug => {
                log::debug!("Received char: {}", value as char);
            }
            VirtualSerialPortBackingDevice::None => {}
        }
    }

    /// Asserts the assigned IRQ line via the I/O APIC.
    fn raise_irq_line(&self) {
        if let Some(context) = &self.device_context {
            context
                .io_apic
                .write()
                .set_irq(self.irq_line as usize, true);
        }
    }

    /// Injects a stream of bytes from host into guest RX FIFO and triggers the RDA interrupt line.
    pub fn inject_rx(&mut self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }

        for &b in bytes {
            self.rx_fifo.push_back(b);
        }

        self.rda_irq_pending = true;
        self.update_irq();
    }

    /// Re-evaluates interrupt pending flags and raises the IRQ line if necessary.
    fn update_irq(&mut self) {
        let iir = self.current_iir();

        if iir != IIR_NO_INTERRUPT {
            self.raise_irq_line();
        }
    }

    /// Computes current Interrupt Identification Register value based on interrupt priorities.
    fn current_iir(&self) -> u8 {
        // Priority order: RLS > RDA > THRE > MS
        if (self.ier & IER_RDA) != 0 && self.rda_irq_pending && !self.rx_fifo.is_empty() {
            return IIR_RDA;
        }

        if (self.ier & IER_THRE) != 0 && self.thr_irq_pending {
            return IIR_THRE;
        }

        IIR_NO_INTERRUPT
    }
}

impl VirtualDevice for VirtualSerialPort {
    /// Connects the UART to the guest interrupt controller.
    fn attach(&mut self, context: &DeviceContext) {
        self.device_context = Some(context.clone());

        // Deliver any interrupt that became pending before the device was attached.
        self.update_irq();
    }

    /// Returns human-readable device name.
    fn name(&self) -> &str {
        "UART 16550A Serial Device"
    }

    /// Declares the 8-byte I/O port window reserved by this UART.
    fn get_resources(&self) -> Vec<DeviceResource> {
        alloc::vec![DeviceResource::IoPortRange {
            base: self.base_port,
            size: 8,
        }]
    }

    /// Handles guest I/O port reads based on offset relative to `base_port`.
    fn handle_io_read(&mut self, _cpu_id: usize, addr: u64, _width: u8) -> u64 {
        let offset = addr - (self.base_port as u64);

        match offset {
            INTERRUPT_ENABLE_REGISTER_OFFSET => {
                if self.dlab {
                    0 // Divisor Latch MSB stub
                } else {
                    self.ier as u64
                }
            }
            RECEIVE_BUFFER_REGISTER_OFFSET => {
                if self.dlab {
                    return 0; // Divisor Latch LSB stub
                }

                if self.loopback {
                    return self.last_byte;
                }

                if let Some(b) = self.rx_fifo.pop_front() {
                    if self.rx_fifo.is_empty() {
                        self.rda_irq_pending = false;
                    } else {
                        // Keep RDA asserted if more bytes remain in queue
                        self.rda_irq_pending = true;
                    }

                    self.update_irq();

                    b as u64
                } else {
                    0
                }
            }
            LINE_CONTROL_REGISTER_OFFSET => self.lcr as u64,
            MODEM_CONTROL_REGISTER_OFFSET => self.mcr as u64,
            LINE_STATUS_REGISTER_OFFSET => {
                // Bit 5 (THRE) | Bit 6 (TEMT) always set; Bit 0 (DR) set if RX data present
                let mut lsr = 0x60u8;
                if self.loopback || !self.rx_fifo.is_empty() {
                    lsr |= 0x01; // Data Ready
                }

                lsr as u64
            }
            INTERRUPT_IDENTIFICATION_REGISTER_OFFSET => {
                let iir = self.current_iir();

                // Reading IIR clears pending THRE interrupt
                if iir == IIR_THRE {
                    self.thr_irq_pending = false;
                }

                iir as u64
            }
            MODEM_STATUS_REGISTER_OFFSET => 0xB0, // Standard DSR/CTS/DCD active bits
            SCRATCH_REGISTER_OFFSET => self.scratch as u64,
            unknown => unimplemented!("unimplemented serial register {}", unknown),
        }
    }

    /// Handles guest I/O port writes based on offset relative to `base_port`.
    fn handle_io_write(&mut self, _cpu_id: usize, addr: u64, value: u64, _width: u8) {
        let offset = addr - (self.base_port as u64);

        match offset {
            TRANSMIT_BUFFER_REGISTER_OFFSET => {
                if self.dlab {
                    // Divisor Latch LSB — ignored
                } else {
                    let should_raise_thre = !self.thr_irq_pending;

                    if self.loopback {
                        self.last_byte = value;
                        self.rx_fifo.push_back(value as u8);
                        self.rda_irq_pending = true;
                    } else {
                        self.handle_output(value as u8);
                    }

                    self.thr_irq_pending = true;

                    if should_raise_thre {
                        self.update_irq();
                    }
                }
            }
            INTERRUPT_ENABLE_REGISTER_OFFSET => {
                if self.dlab {
                    // Divisor Latch MSB — ignored
                } else {
                    self.ier = (value as u8) & 0x0F;
                    self.thr_irq_pending = (self.ier & IER_THRE) != 0;

                    if (self.ier & IER_RDA) != 0 && !self.rx_fifo.is_empty() {
                        self.rda_irq_pending = true;
                    }

                    self.update_irq();
                }
            }
            FIFO_CONTROL_REGISTER_OFFSET => {}
            LINE_CONTROL_REGISTER_OFFSET => {
                self.lcr = value as u8;
                self.dlab = (value & 0x80) != 0;
            }
            MODEM_CONTROL_REGISTER_OFFSET => {
                self.mcr = value as u8;
                self.loopback = (value & 0x10) != 0;
            }
            SCRATCH_REGISTER_OFFSET => {
                self.scratch = value as u8;
            }
            _ => {
                log::warn!("Unhandled IO write to serial port offset={}", offset);
            }
        }
    }

    /// Generates an AML byte stream for the ACPI namespace.
    ///
    /// Declares PNP Identifier `PNP0501` (Standard 16550A UART Serial Port) with associated IRQ and Fixed I/O window.
    fn generate_aml(&self) -> Option<Vec<u8>> {
        let com = format!("COM{}", self.n);
        let ddn = com.as_str();

        Some(crate::aml!(@ROOT
            Device (ddn) {
                Name ("_HID", "PNP0501") // Standard 16550A UART
                Name ("_DDN", ddn)
                Name ("_UID", self.n as u32)

                Name ("_CRS", ResourceTemplate() {
                    FixedIO (self.base_port, 8)
                    IRQEdge (self.irq_line)
                })

                Method ("_STA", 0) {
                    Return (0x0Fu8)
                }
            }
        ))
    }
}

extern "C" fn receive_thread(arg: u64) -> ! {
    let serial: Arc<RwLock<VirtualSerialPort>> = unsafe { Arc::from_raw(arg as usize as *const _) };

    let backing_device = serial.read().backing_device.clone();
    let mut buffer = [0u8; 256];

    loop {
        if let VirtualSerialPortBackingDevice::Remote(port) = backing_device.as_ref() {
            match port.socket().read(&mut buffer) {
                Ok(0) => {
                    log::warn!("SERIAL: Remote socket closed (0 bytes read)");
                }
                Ok(n) => {
                    if let Ok((frame, _)) = monocle_protocol::decode_frame(&buffer[..n]) {
                        serial.write().inject_rx(frame.payload);
                    }
                }
                Err(e) => {
                    log::error!("SERIAL: Socket read error: {}, retrying...", e);
                }
            }
        } else {
            // We can't really get any useful input from stubbed device or moose logger, so just stop this thread.
            current_thread().set_status(Status::Stopped);
            yield_to_scheduler();
        }
    }
}
