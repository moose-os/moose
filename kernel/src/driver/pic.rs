use pic8259::ChainedPics;

pub const PIC_1_OFFSET: u8 = 32;
pub const PIC_2_OFFSET: u8 = PIC_1_OFFSET + 8;

// Basically it's wrapper around pic8259's ChainedPics structure with some
// extra helper functions
pub struct ProgrammableInterruptController {
    chained_pics: ChainedPics,
}

impl ProgrammableInterruptController {
    pub const fn new() -> Self {
        ProgrammableInterruptController {
            chained_pics: unsafe { ChainedPics::new(PIC_1_OFFSET, PIC_2_OFFSET) },
        }
    }

    // Need to initialize PIC after early setup
    pub fn initialize(&mut self) {
        unsafe { self.chained_pics.initialize() }
    }

    pub fn mask_interrupt(&mut self, interrupt_number: u8) {
        let mut masks = unsafe { self.chained_pics.read_masks() };

        // don't even ask
        let mut mask = ((masks[1] as u16) << 8) | masks[0] as u16;
        mask |= 1 << interrupt_number;
        masks = [(mask & 0xFF) as u8, (mask >> 8) as u8];

        unsafe { self.chained_pics.write_masks(masks[0], masks[1]) };
    }

    pub fn unmask_interrupt(&mut self, interrupt_number: u8) {
        let mut masks = unsafe { self.chained_pics.read_masks() };

        // don't even ask
        let mut mask = ((masks[1] as u16) << 8) | masks[0] as u16;
        mask &= !(1 << interrupt_number);
        masks = [(mask & 0xFF) as u8, (mask >> 8) as u8];

        unsafe { self.chained_pics.write_masks(masks[0], masks[1]) };
    }
}
