pub struct IrqAllocator {
    buckets: [u8; 16],
}

impl IrqAllocator {
    pub const fn new() -> Self {
        Self { buckets: [0u8; 16] }
    }

    pub fn allocate_irq(&mut self, irq_level: IrqLevel) -> u8 {
        let free_irq = self.buckets[irq_level as usize];

        if free_irq == 16 {
            panic!("The pool of free Irq numbers has been exhausted")
        }

        self.buckets[irq_level as usize] += 1;

        ((irq_level as u8) << 4) | free_irq
    }
}

#[derive(Copy, Clone)]
#[repr(u8)]
pub enum IrqLevel {
    High = 15,
    InterProcessorInterrupt = 14,
    Clock = 13,
    // 12-1 are free, probably for device drivers use
    NetworkInterfaceCard = 7,
    Passive = 0,
}
