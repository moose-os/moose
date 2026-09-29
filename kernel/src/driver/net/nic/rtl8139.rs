use alloc::{boxed::Box, sync::Arc};
use core::{range::Range, slice};

use raw_cpuid::{CpuId, Hypervisor};
use x86_64::instructions::interrupts::without_interrupts;

use crate::{
    arch::{
        irq::IrqLevel,
        x86::{
            asm::{inb, inw, outb, outl, outw},
            cpu::ProcessorControlBlock,
            idt::{ExceptionFrame, VolatileRegisters, register_interrupt_handler_closure},
        },
    },
    driver::{
        apic::{DeliveryMode, DestinationMode, PinPolarity, RedirectionEntry, TriggerMode},
        net::{MacAddress, NetworkCard, NetworkInterfaceId},
        pci::PciDevice,
    },
    kernel::kernel_ref,
    subsystem::{
        memory::{
            AnyIn, CurrentAddressSpace, Exact, Frame, FrameRange, PAGE_SIZE, Page, PageFlags,
            PhysicalAddress, VirtualAddress, memory_manager,
        },
        sync::IrqGuardedMutex,
    },
};

const BUFE_BIT: u8 = 0x1;
const RST_BIT: u8 = 0x10;
const RBSTART_REGISTER: u16 = 0x30;
const COMMAND_REGISTER: u16 = 0x37;
const CAPR: u16 = 0x38;
const INTERRUPT_MASK_REGISTER: u16 = 0x3C;
const INTERRUPT_STATUS_REGISTER: u16 = 0x3E;
const RECEIVE_CONFIGURATION_REGISTER: u16 = 0x44;
const CONFIG_1_REGISTER: u16 = 0x52;

// Possible values: 8192, 16384, 32768, 65536
const RX_RING_BUFFER_SIZE: usize = 65536;
const RX_BUFFER_SIZE: usize = RX_RING_BUFFER_SIZE + 1518 + 4 + 4;
const TX_BUF_SIZE: usize = 2048;
const TX_BUFS: usize = 4;

pub struct Rtl8139 {
    inner: Arc<IrqGuardedMutex<Rtl8139Inner>>,
}

impl Clone for Rtl8139 {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl Rtl8139 {
    pub fn new(pci_device: Arc<IrqGuardedMutex<PciDevice>>) -> Rtl8139 {
        let mut memory_manager = memory_manager().write();

        let rx_page_count = RX_RING_BUFFER_SIZE / PAGE_SIZE;
        let rx_first_frame = memory_manager
            .allocate_frames_contiguous(rx_page_count)
            .expect("physically contiguous RX ring");
        let rx_last_frame = Frame::new(PhysicalAddress::new(
            rx_first_frame.address().as_u64() + RX_RING_BUFFER_SIZE as u64,
        ));

        let rx_virt = unsafe {
            memory_manager
                .map_any_contiguous(
                    CurrentAddressSpace,
                    Range::from(256..512),
                    FrameRange::new(rx_first_frame.address(), rx_last_frame.address()),
                    PageFlags::WRITABLE,
                )
                .start()
        };

        let wrap_page = Page::new(VirtualAddress::new(
            rx_virt.as_u64() + RX_RING_BUFFER_SIZE as u64,
        ));

        unsafe {
            memory_manager
                .map(
                    CurrentAddressSpace,
                    Exact(&wrap_page, &rx_first_frame),
                    PageFlags::WRITABLE,
                )
                .unwrap();
        }

        let rx_buffer = rx_virt.as_mut_ptr();
        let rx_buffer_phys = rx_first_frame.address().as_u64() as u32;

        let mut tx_buf: [*mut u8; TX_BUFS] = [core::ptr::null_mut(); TX_BUFS];
        let mut tx_phys: [u32; TX_BUFS] = [0; TX_BUFS];
        for i in 0..TX_BUFS {
            let frame = memory_manager.allocate_frame().unwrap();
            tx_buf[i] = unsafe {
                memory_manager
                    .map(
                        CurrentAddressSpace,
                        AnyIn(&frame, 256..512),
                        PageFlags::WRITABLE,
                    )
                    .expect("map TX buffer")
                    .page
                    .address()
                    .as_mut_ptr()
            };
            tx_phys[i] = frame.address().as_u64() as u32;
        }

        let bar0 = pci_device.lock().get_bar(0);
        assert_eq!(bar0 & 1, 1); // Safety check that device reports I/O address in first BAR.

        Self {
            inner: Arc::new(IrqGuardedMutex::new(Rtl8139Inner {
                pci_device,
                io_base: (bar0 & !0x3) as u16,
                rx_buffer,
                rx_buffer_phys,
                current_rx_offset: 0,
                current_tx_index: 0,
                interface_id: None,
                tx_buf,
                tx_phys,
            })),
        }
    }

    pub fn initialize(&mut self) {
        assert_eq!(
            CpuId::new().get_hypervisor_info().unwrap().identify(),
            Hypervisor::QEMU,
            "RTL8139 interrupts are only supported on QEMU currently, due to very unpleasant way of handling interrupts without MSI/MSI-X on PCI devices."
        );

        assert!(
            [8192, 16384, 32768, 65536].contains(&RX_RING_BUFFER_SIZE),
            "Ring buffer size must be 8kb, 16kb, 32kb or 64kb"
        );

        without_interrupts(|| {
            let rtl8139 = self.inner.lock();

            {
                let pci_device = rtl8139.pci_device.lock();

                // Enable DMA (Bus Master)
                pci_device.enable_dma();

                // Get interrupt line from the PCI configuration space
                //
                // This is weird actually, because it should be totally random when using APIC + IRQ sharing, but in QEMU
                // for some reason it works.
                let interrupt_line = pci_device.get_interrupt_line();
                let irq = kernel_ref()
                    .irq_allocator
                    .lock()
                    .allocate_irq(IrqLevel::NetworkInterfaceCard);

                debug!(
                    "[RTL8139] Using IRQ#{} with interrupt line {}",
                    irq, interrupt_line
                );

                let inner = Arc::clone(&self.inner);

                register_interrupt_handler_closure(
                    irq,
                    Box::new(
                        move |_isf: &ExceptionFrame, _registers: &VolatileRegisters| {
                            handle_rtl8139_interrupt(&mut inner.lock());
                        },
                    ),
                );

                let redirection_entry = RedirectionEntry::new()
                    .with_delivery_mode(DeliveryMode::Fixed)
                    .with_destination(0)
                    .with_mask(false)
                    .with_destination_mode(DestinationMode::Physical)
                    .with_interrupt_vector(irq)
                    .with_pin_polarity(PinPolarity::ActiveHigh)
                    .with_trigger_mode(TriggerMode::Edge);

                kernel_ref()
                    .apic()
                    .read()
                    .redirect_interrupt(redirection_entry, interrupt_line);
            }

            // Set the LWAKE and LWPTN to active high. This should power on the device.
            outb(rtl8139.io_base + CONFIG_1_REGISTER, 0x00);

            // Perform software reset to make sure there's no garbage in buffers or registers.
            outb(rtl8139.io_base + COMMAND_REGISTER, RST_BIT);

            // Wait until the device reports success.
            loop {
                if (inb(rtl8139.io_base + COMMAND_REGISTER) & RST_BIT) == 0 {
                    break;
                }
            }

            // Initialize receive buffer (RX)
            outl(rtl8139.io_base + RBSTART_REGISTER, rtl8139.rx_buffer_phys);

            // Program TSAD[0..3] once with physical addresses.
            for idx in 0..TX_BUFS {
                outl(
                    rtl8139.io_base + (0x20 + (idx as u16) * 4),
                    rtl8139.tx_phys[idx],
                );
            }

            // Initialize interrupts
            //
            // We're setting Tx OK Interrupt (bit 2) and Rx OK Interrupt (bit 0)
            // For more settings see Realtek RTL8139 DataSheet table at page 18
            outw(
                rtl8139.io_base + INTERRUPT_MASK_REGISTER,
                (1 << 2) | 1 | (1 << 4),
            );

            let rx_buffer_size_bits = match RX_RING_BUFFER_SIZE {
                8192 => 0b00,
                16384 => 0b01,
                32768 => 0b10,
                65536 => 0b11,
                _ => unreachable!(),
            };

            // Initialize receiver options
            outl(
                rtl8139.io_base + RECEIVE_CONFIGURATION_REGISTER,
                // WRAP bit would be the best setting, but for some reason
                // QEMU does not support it
                (rx_buffer_size_bits << 11) |
                (1 << 3) | // Accept Broadcast Packets
                (1 << 2) | // Accept Multicast Packets
                (1 << 1) | // Accept Physical Match Packets
                1, // Accept All Packets
            );

            // Finally, enable receiver and transmitter
            //                                        RE      |  TE
            outb(rtl8139.io_base + COMMAND_REGISTER, (1 << 3) | (1 << 2));
        });
    }

    pub fn send_packet(&self, data: &[u8]) {
        // Safety checks
        assert!(data.len() < 1518);
        assert!(!data.is_empty());

        let mut inner = self.inner.lock();
        let idx = inner.current_tx_index % TX_BUFS;
        unsafe {
            let dst = core::slice::from_raw_parts_mut(inner.tx_buf[idx], TX_BUF_SIZE);
            dst[..data.len()].copy_from_slice(data);
        }

        outl(inner.io_base + (0x10 + (idx as u16) * 4), data.len() as u32);

        inner.current_tx_index = (inner.current_tx_index + 1) % TX_BUFS;
    }

    pub fn mac_address(&self) -> MacAddress {
        let io_base = self.inner.lock().io_base;
        let mut mac = [0u8; 6];

        for (i, slot) in mac.iter_mut().enumerate() {
            *slot = inb(io_base + i as u16);
        }

        MacAddress(mac)
    }

    pub fn set_interface_id(&self, interface_id: NetworkInterfaceId) {
        self.inner.lock().interface_id = Some(interface_id);
    }

    fn get_current_transmit_registers(&self) -> (u16, u16) {
        match self.inner.lock().current_tx_index {
            0 => (0x20, 0x10),
            1 => (0x24, 0x14),
            2 => (0x28, 0x18),
            3 => (0x2C, 0x1C),
            _ => unreachable!(),
        }
    }

    fn adjust_transmit_registers(&self) {
        // RTL8139 has 4 transmit registers for sending data, and they are used with round-robin style.
        let mut inner = self.inner.lock();

        inner.current_tx_index += 1;

        if inner.current_tx_index >= 4 {
            inner.current_tx_index = 0;
        }
    }
}

struct Rtl8139Inner {
    pci_device: Arc<IrqGuardedMutex<PciDevice>>,
    io_base: u16,
    rx_buffer: *mut u8,
    rx_buffer_phys: u32,
    current_rx_offset: usize,
    current_tx_index: usize,
    interface_id: Option<NetworkInterfaceId>,
    tx_buf: [*mut u8; TX_BUFS],
    tx_phys: [u32; TX_BUFS],
}

impl Rtl8139Inner {
    fn handle_received_packet(&mut self) {
        // NIC can copy a lot of frames during one DMA transfer, and instead of doing
        // one interrupt-one frame thing, we can process multiple frames during one interrupt
        loop {
            // Received data from the wire are preceded by two u16's:
            //   - data status
            //   - data length

            let data_start = unsafe { self.rx_buffer.add(self.current_rx_offset) };
            let status = unsafe { (data_start.add(0) as *const u16).read_volatile() };
            let length = unsafe { (data_start.add(2) as *const u16).read_volatile() };

            // If the NIC marked packet as invalid OR rx buffer is empty (because we've processed
            // all packets), then quit
            if ((status & (1 << 0)) != 1)
                || ((inb(self.io_base + COMMAND_REGISTER) & BUFE_BIT) != 0)
            {
                break;
            }

            debug!(
                "Received data with length {}, status={}, offset={}",
                length, status, self.current_rx_offset
            );

            // 4 is the data status and data length
            // 1518 is maximum Ethernet frame length
            // 4 is CRC32 checksum appended at the end of the data
            let total = length as usize;
            if total >= 8
                && let Some(interface_id) = self.interface_id
            {
                let frame = unsafe { slice::from_raw_parts(data_start.add(4), total - 4) };
                kernel_ref()
                    .network_subsystem()
                    .rx_process_thread()
                    .enqueue_frame(interface_id, frame);

                debug!("queued for further processing");
            }

            self.current_rx_offset = (self.current_rx_offset + length as usize + 4 + 3) & !3;

            // It's ring buffer, so if we overflow, just go back to the start. We're parsing frames
            // one by one, so there's no possibility it would overflow two or more times.
            if self.current_rx_offset > RX_RING_BUFFER_SIZE {
                self.current_rx_offset -= RX_RING_BUFFER_SIZE;
            }

            // Notify network card about new RX buffer reading offset
            outw(
                self.io_base + CAPR,
                (self.current_rx_offset as u16).overflowing_sub(0x10).0,
            );
        }
    }
}

impl NetworkCard for Rtl8139 {
    fn send_packet(&self, frame: &[u8]) {
        self.send_packet(frame);
    }
}

unsafe impl Send for Rtl8139Inner {}

#[repr(C, align(4096))]
struct RxBuffer([u8; RX_BUFFER_SIZE]);

fn handle_rtl8139_interrupt(nic: &mut Rtl8139Inner) {
    let status = inw(nic.io_base + INTERRUPT_STATUS_REGISTER);

    // Can't use smarter way, because flags are not exclusive
    if (status & (1 << 2)) != 0 {
        debug!("Packet sent");
    }

    if (status & (1 << 0)) != 0 {
        // Packet received
        nic.handle_received_packet();
    }

    if (status & (1 << 1)) != 0 {
        panic!("Rcv err!");
    }

    if (status & (1 << 4)) != 0 {
        panic!("RX buffer overflow")
    }

    // Acknowledge interrupt
    // This also allows RTL8139 to overwrite our data, so from this moment we can't rely on rx buffer
    outw(nic.io_base + INTERRUPT_STATUS_REGISTER, status);

    ProcessorControlBlock::current()
        .local_apic()
        .signal_end_of_interrupt();
}
