use core::{arch::asm, mem, ptr::addr_of};

use bitfield_struct::bitfield;
use bitflags::bitflags;

use crate::arch::x86::cpu::MAXIMUM_CPU_CORES;

pub(crate) static mut GDT_DESCRIPTOR: GlobalDescriptorTableDescriptor =
    GlobalDescriptorTableDescriptor::new(0, 0); // We can't obtain the address of GDT at compile-time, so we have to initialize this in _start
pub(crate) static mut GDT: GlobalDescriptorTable = GlobalDescriptorTable::new(); // We can't obtain the address of TSS at compile-time, so we have to initialize it in _start
pub(crate) static mut TSS: [TaskStateSegment; MAXIMUM_CPU_CORES] = {
    const DEFAULT: TaskStateSegment = TaskStateSegment {
        reserved1: 0,
        rsp0: 0,
        rsp1: 0,
        rsp2: 0,
        reserved2: 0,
        reserved3: 0,
        ist1: 0,
        ist2: 0,
        ist3: 0,
        ist4: 0,
        ist5: 0,
        ist6: 0,
        ist7: 0,
        reserved4: 0,
        reserved5: 0,
        reserved6: 0,
        iopb: mem::size_of::<TaskStateSegment>() as u16,
    }; // We have to allocate stacks first, thus we need to initialize rsps in _start

    [DEFAULT; MAXIMUM_CPU_CORES]
};

pub(crate) const KERNEL_MODE_CODE_SEGMENT_INDEX: usize = 5;
pub(crate) const KERNEL_MODE_DATA_SEGMENT_INDEX: usize = 6;
pub(crate) const USER_MODE_CODE_SEGMENT_INDEX: usize = 7;
pub(crate) const USER_MODE_DATA_SEGMENT_INDEX: usize = 8;
pub(crate) const TSS_INDEX: usize = 9;

// See Intel Manuals Combined, Volume C, 3.5.1, p. 3087, Fig. 3-11 for details
#[repr(C, packed)]
pub(crate) struct GlobalDescriptorTableDescriptor {
    pub(crate) size: u16,
    pub(crate) offset: u64,
}

impl GlobalDescriptorTableDescriptor {
    pub(crate) const fn new(size: u16, offset: u64) -> Self {
        Self { size, offset }
    }
}

#[repr(C, packed)]
pub(crate) struct GlobalDescriptorTable {
    pub(crate) null_entry: SegmentDescriptor,
    pub(crate) kernel_mode_sixteen_bit_code_segment: SegmentDescriptor, // TODO: Unused, present for compatibility with Limine, see whether this can be removed
    pub(crate) kernel_mode_sixteen_bit_data_segment: SegmentDescriptor, // TODO: Unused, present for compatibility with Limine, see whether this can be removed
    pub(crate) kernel_mode_thirty_two_bit_code_segment: SegmentDescriptor, // TODO: Unused, present for compatibility with Limine, see whether this can be removed
    pub(crate) kernel_mode_thirty_two_bit_data_segment: SegmentDescriptor, // TODO: Unused, present for compatibility with Limine, see whether this can be removed
    pub(crate) kernel_mode_sixty_four_code_segment: SegmentDescriptor,
    pub(crate) kernel_mode_sixty_four_data_segment: SegmentDescriptor,
    pub(crate) user_mode_sixty_four_code_segment: SegmentDescriptor,
    pub(crate) user_mode_sixty_four_data_segment: SegmentDescriptor,
    pub(crate) tss_segments: [SystemSegmentDescriptor; MAXIMUM_CPU_CORES],
}

impl GlobalDescriptorTable {
    pub(crate) const fn new() -> Self {
        Self {
            null_entry: SegmentDescriptor::zero(),
            kernel_mode_sixteen_bit_code_segment: SegmentDescriptor::zero(),
            kernel_mode_sixteen_bit_data_segment: SegmentDescriptor::zero(),
            kernel_mode_thirty_two_bit_code_segment: SegmentDescriptor::zero(),
            kernel_mode_thirty_two_bit_data_segment: SegmentDescriptor::zero(),
            kernel_mode_sixty_four_code_segment: SegmentDescriptor::new(
                0,
                0,
                SegmentDescriptorAttributes::new()
                    .with_present(true)
                    .with_descriptor_type(true)
                    .with_executable(true)
                    .with_readable_or_writable(true)
                    .with_accessed(true),
                SegmentFlags::SixtyFourBitCodeSegment,
            ),
            kernel_mode_sixty_four_data_segment: SegmentDescriptor::new(
                0,
                0,
                SegmentDescriptorAttributes::new()
                    .with_present(true)
                    .with_descriptor_type(true)
                    .with_readable_or_writable(true)
                    .with_accessed(true),
                SegmentFlags::empty(),
            ),
            user_mode_sixty_four_code_segment: SegmentDescriptor::new(
                0,
                0,
                SegmentDescriptorAttributes::new()
                    .with_present(true)
                    .with_privilege_level(3)
                    .with_descriptor_type(true)
                    .with_executable(true)
                    .with_readable_or_writable(true)
                    .with_accessed(true),
                SegmentFlags::SixtyFourBitCodeSegment,
            ),
            user_mode_sixty_four_data_segment: SegmentDescriptor::new(
                0,
                0,
                SegmentDescriptorAttributes::new()
                    .with_present(true)
                    .with_privilege_level(3)
                    .with_descriptor_type(true)
                    .with_readable_or_writable(true)
                    .with_accessed(true),
                SegmentFlags::empty(),
            ),
            tss_segments: {
                const DEFAULT: SystemSegmentDescriptor = SystemSegmentDescriptor::zero();

                [DEFAULT; MAXIMUM_CPU_CORES]
            },
        }
    }
}

// See Intel Manuals Combined, Volume C, 8.2.3, p. 3250, Fig. 8-4 for details
#[derive(Clone, Copy, Default)]
#[repr(C, packed)]
pub(crate) struct SegmentDescriptor {
    pub(crate) limit_low: u16,
    pub(crate) base_low: u16,
    pub(crate) base_mid: u8,
    pub(crate) attributes: u8,
    pub(crate) flags_and_limit_high: u8,
    pub(crate) base_high: u8,
}

impl SegmentDescriptor {
    pub(crate) const fn zero() -> Self {
        Self {
            limit_low: 0,
            base_low: 0,
            base_mid: 0,
            attributes: 0,
            flags_and_limit_high: 0,
            base_high: 0,
        }
    }

    pub(crate) const fn new(
        base: u32,
        limit: u32,
        attributes: SegmentDescriptorAttributes,
        flags: SegmentFlags,
    ) -> Self {
        assert!(limit <= 0b1111_1111_1111_1111_1111);

        if flags.contains(SegmentFlags::SixtyFourBitCodeSegment) {
            assert!(base == 0);
            assert!(limit == 0);
        }

        let base_high = ((base >> 24) & 0xFF) as u8;
        let base_mid = ((base >> 16) & 0xFF) as u8;
        let base_low = (base & 0xFFFF) as u16;

        let limit_low = limit as u16;

        let attributes = attributes.into_bits();

        let flags_and_limit_high = (((limit >> 16) & 0xF) as u8) | ((flags.bits() & 0xF) << 4);

        Self {
            limit_low,
            base_low,
            base_mid,
            attributes,
            flags_and_limit_high,
            base_high,
        }
    }
}

// See Intel Manuals Combined, Volume C, 3.4.5, p. 3081 for details
#[bitfield(u8)]
pub(crate) struct SegmentDescriptorAttributes {
    pub(crate) accessed: bool,
    pub(crate) readable_or_writable: bool,
    pub(crate) direction_or_conforming: bool,
    pub(crate) executable: bool,
    pub(crate) descriptor_type: bool,
    #[bits(2)]
    pub(crate) privilege_level: u8,
    pub(crate) present: bool,
}

// See Intel Manuals Combined, Volume C, 8.2.3, p. 3250, Fig. 8-4 for details
#[repr(C, packed)]
pub(crate) struct SystemSegmentDescriptor {
    pub(crate) limit_low: u16,
    pub(crate) base_low: u16,
    pub(crate) base_mid: u8,
    pub(crate) attributes: u8,
    pub(crate) flags_and_limit_high: u8,
    pub(crate) base_high: u8,
    pub(crate) base_higher: u32,
    pub(crate) reserved: u32,
}

impl SystemSegmentDescriptor {
    pub(crate) const fn zero() -> Self {
        Self {
            limit_low: 0,
            base_low: 0,
            base_mid: 0,
            attributes: 0,
            flags_and_limit_high: 0,
            base_high: 0,
            base_higher: 0,
            reserved: 0,
        }
    }

    pub(crate) const fn new(
        base: u64,
        limit: u32,
        attributes: SystemSegmentDescriptorAttributes,
        flags: SegmentFlags,
    ) -> Self {
        assert!(limit <= 0b1111_1111_1111_1111_1111);

        let limit_low = (limit & 0xFFFF) as u16;
        let base_low = (base & 0xFFFF) as u16;
        let base_mid = ((base >> 16) & 0xFF) as u8;
        let attributes = attributes.into_bits();
        let flags_and_limit_high = ((flags.bits() & 0xF) << 4) | (((limit >> 16) & 0xF) as u8);
        let base_high = ((base >> 24) & 0xFF) as u8;
        let base_higher = ((base >> 32) & 0xFFFF_FFFF) as u32;

        Self {
            limit_low,
            base_low,
            base_mid,
            attributes,
            flags_and_limit_high,
            base_high,
            base_higher,
            reserved: 0,
        }
    }

    pub(crate) fn base(&self) -> u64 {
        ((self.base_higher as u64) << 32)
            | ((self.base_high as u64) << 24)
            | ((self.base_mid as u64) << 16)
            | (self.base_low as u64)
    }
}

// // See Intel Manuals Combined, Volume C, 3.4.5, p. 3081 for details
#[bitfield(u8)]
pub(crate) struct SystemSegmentDescriptorAttributes {
    #[bits(4, default =  SystemSegmentType::LocalDescriptorTable)]
    pub(crate) segment_type: SystemSegmentType,
    pub(crate) _unused: bool,
    #[bits(2)]
    pub(crate) privilege_level: u8,
    pub(crate) present: bool,
}

// See Intel Manuals Combined, Volume B, p. 1208, Table 3-66 for details
#[derive(Debug)]
pub(crate) enum SystemSegmentType {
    LocalDescriptorTable,
    SixtyFourBitAvailableTaskStateSegment,
    SixtyFourBitBusyTaskStateSegment,
}

impl SystemSegmentType {
    pub(crate) const fn from_bits(bits: u8) -> Self {
        match bits {
            0x2 => Self::LocalDescriptorTable,
            0x9 => Self::SixtyFourBitAvailableTaskStateSegment,
            0xB => Self::SixtyFourBitBusyTaskStateSegment,
            _ => panic!(),
        }
    }

    pub(crate) const fn into_bits(self) -> u8 {
        match self {
            SystemSegmentType::LocalDescriptorTable => 0x2,
            SystemSegmentType::SixtyFourBitAvailableTaskStateSegment => 0x9,
            SystemSegmentType::SixtyFourBitBusyTaskStateSegment => 0xB,
        }
    }
}

bitflags! {
    pub(crate) struct SegmentFlags: u8 {
        const SixtyFourBitCodeSegment = 0b00000010;
        const ThirtyTwoBitProtectedModeSegment = 0b0000100;
        const IsLimitScaledBy4KiB = 0b00001000;

        const _ = !0;
    }
}

// See Intel Manuals Combined, Volume C, 8.7, p. 3263, Fig. 8-11 for details
#[repr(C, packed)]
pub(crate) struct TaskStateSegment {
    pub(crate) reserved1: u32,
    pub(crate) rsp0: u64,
    pub(crate) rsp1: u64,
    pub(crate) rsp2: u64,
    pub(crate) reserved2: u32,
    pub(crate) reserved3: u32,
    pub(crate) ist1: u64,
    pub(crate) ist2: u64,
    pub(crate) ist3: u64,
    pub(crate) ist4: u64,
    pub(crate) ist5: u64,
    pub(crate) ist6: u64,
    pub(crate) ist7: u64,
    pub(crate) reserved4: u32,
    pub(crate) reserved5: u32,
    pub(crate) reserved6: u16,
    pub(crate) iopb: u16,
}

pub unsafe fn setup_gdt() {
    for (index, tss_segment) in GDT.tss_segments.iter_mut().enumerate() {
        *tss_segment = SystemSegmentDescriptor::new(
            addr_of!(TSS) as u64 + (index * mem::size_of::<TaskStateSegment>()) as u64,
            mem::size_of::<TaskStateSegment>() as u32,
            SystemSegmentDescriptorAttributes::new()
                .with_present(true)
                .with_segment_type(SystemSegmentType::SixtyFourBitAvailableTaskStateSegment),
            SegmentFlags::empty(),
        );
    }

    GDT_DESCRIPTOR = GlobalDescriptorTableDescriptor::new(
        mem::size_of::<GlobalDescriptorTable>() as u16 - 1,
        addr_of!(GDT) as u64,
    );
}

#[inline(always)]
pub unsafe fn load_gdt() {
    asm!(
        "lgdt [{gdt}]",
        gdt = in(reg) addr_of!(GDT_DESCRIPTOR) as u64,
    );
}
