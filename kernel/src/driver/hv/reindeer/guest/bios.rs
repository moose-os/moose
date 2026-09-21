//! Real-Mode BIOS Interrupt Vector Table emulation for guest boot paths.
//!
//! This module provides vendor-neutral BIOS interrupt stubs required by
//! real-mode bootloaders (e.g., SYSLINUX, GRUB, Limine).
//!
//! Interrupt calls are trapped from a dedicated BIOS trampoline region placed
//! in guest memory (starting at address `0x500`).
//!
//! All structures located here are based on Ralph Brown's Interrupt List (RBIL).

use core::{cmp, mem, slice};

use crate::driver::hv::reindeer::{
    HypervisorError, SegmentRegister, VcpuHandle,
    guest::{boot::linux::HYPERVISOR_SECTOR_SIZE, registers::X86RegisterOperations},
    guest_machine::{GuestMachineState, MemoryDescriptorType},
};

/// Drive parameters structure returned by EDD (Enhanced Disk Drive) extensions.
///
/// Used by extended disk function INT 13h, AH=48h.
///
/// # RBIL Reference
/// * RBIL: `INT 13,48 - IBM/MS INT 13 Extensions - GET DRIVE PARAMETERS`
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
struct BiosDriveParameters {
    /// Buffer size in bytes (typically 0x001A or 0x001E for EDD 1.x/2.x).
    size_of_buffer: u16,

    /// Information flags (e.g., bit 0 = DMA, bit 1 = LBA).
    flags: u16,

    /// Physical or emulated number of cylinders.
    cylinders_on_drive: u32,

    /// Physical or emulated number of heads.
    heads_on_drive: u32,

    /// Physical or emulated sectors per track.
    sectors_per_track: u32,

    /// Total sector count on drive (64-bit LBA addressing).
    total_sectors_on_drive: u64,

    /// Sector size in bytes (standard is 512).
    bytes_per_sector: u16,

    /// Pointer to EDD configuration (optional / 0xFFFFFFFF in EDD 1.1).
    edd_configuration: u32,
}

/// Disk Address Packet (DAP) for LBA extensions.
///
/// Used by functions INT 13h, AH=42h (Extended Read) and INT 13h, AH=43h (Extended Write).
///
/// # RBIL Reference
/// * RBIL: `INT 13,42 - IBM/MS INT 13 Extensions - EXTENDED READ`
/// * RBIL: `INT 13,43 - IBM/MS INT 13 Extensions - EXTENDED WRITE`
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
struct BiosDiskAddressPacket {
    /// DAP packet size (typically 16 bytes, or 24 with 64-bit byte count).
    size_of_packet: u8,

    /// Reserved field (must be 0).
    reserved: u8,

    /// Number of blocks/sectors to transfer.
    number_of_blocks_to_transfer: u16,

    /// Buffer offset in guest memory.
    buffer_offset: u16,

    /// Buffer segment in guest memory.
    buffer_segment: u16,

    /// Starting 64-bit LBA block number.
    starting_block_number: u64,
}

/// Memory range descriptor for INT 15h, AX=E820h system address map.
///
/// # RBIL Reference
/// * RBIL: `INT 15,E820 - SYSTEM - GET SYSTEM ADDRESS MAP`
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
struct BiosMemoryMapAddressRangeDescriptor {
    /// Physical base address of the memory range.
    base: u64,

    /// Length of the memory range in bytes.
    length: u64,

    /// Type of memory region (e.g., 1 = Usable RAM, 2 = Reserved).
    range_type: MemoryDescriptorType,
}

impl GuestMachineState {
    /// Main entry point for BIOS interrupt handling (Software Interrupts).
    ///
    /// Traps vCPU execution caused by `INT n` instructions from the BIOS
    /// trampoline area, decodes the interrupt vector based on the instruction pointer (`RIP`)
    /// and corresponding GPRs, then applies the appropriate vCPU state modification.
    pub(crate) fn handle_bios_call(&mut self, vcpu: VcpuHandle) -> Result<(), HypervisorError> {
        let mut cpu = vcpu.write();

        let ss_base = cpu.segment_base(SegmentRegister::Ss);
        let ds_base = cpu.segment_base(SegmentRegister::Ds);
        let es_base = cpu.segment_base(SegmentRegister::Es);

        let cr0 = cpu.guest_cr0();
        let mut rsp = cpu.guest_rsp();
        let rip = cpu.gpr().gpr.rip;

        // Require real mode (CR0.PE = 0).
        assert!(cr0 & 1 == 0);

        // BIOS trampolines are located at address 0x500. Each handler is 6 bytes long.
        // Decode the interrupt vector based on the RIP value at the trap point.
        let handlers_start = 0x500;
        let handler_size = 6;
        let interrupt_number = ((rip - 2 - handlers_start) / handler_size) as u8;

        // Simulate popping the return address off the stack
        rsp = (rsp & 0xFFFF) + 2;
        cpu.set_guest_rsp(rsp);

        let registers = cpu.gpr();
        let ah = registers.gpr.rax.high_u8();

        match interrupt_number {
            // =========================================================================
            // INT 10h - VIDEO BIOS SERVICES
            // =========================================================================
            // RBIL: INT 10 - VIDEO BIOS SERVICES
            0x10 => {
                match ah {
                    // -----------------------------------------------------------------
                    // INT 10h, AH=00h - SET VIDEO MODE
                    // -----------------------------------------------------------------
                    // RBIL: INT 10,00 - SET VIDEO MODE
                    // INPUT: AL = Video mode (e.g., 0x03 for 80x25 text)
                    // OUTPUT: AL = Video flags / AH = Clears options
                    //
                    // The hypervisor is headless. We fake a successful text/graphics mode switch.
                    0x00 => {
                        registers.gpr.rax.set_high_u8(0); // Clear AH (success)

                        self.set_cf_value(ss_base, rsp, false); // success in RFLAGS
                    }

                    // -----------------------------------------------------------------
                    // INT 10h, AH=02h - SET CURSOR POSITION
                    // -----------------------------------------------------------------
                    // RBIL: INT 10,02 - SET CURSOR POSITION
                    // INPUT: DH = Row, DL = Column, BH = Page number
                    // OUTPUT: None
                    //
                    // Catch newline attempts from the bootloader and redirect them to physical
                    // serial port COM2 (0x2F8) to format clean hypervisor logs.
                    //
                    // @TODO: Use some logging proxy
                    0x02 => {
                        let new_row = registers.gpr.rdx.high_u8();

                        if new_row > self.last_cursor_row as u8 {
                            // \r\n on output
                            self.last_cursor_row = new_row as usize;
                        }

                        self.last_cursor_row = new_row as usize;

                        self.set_cf_value(ss_base, rsp, false); // success
                    }

                    // -----------------------------------------------------------------
                    // INT 10h, AH=03h - GET CURSOR POSITION AND SIZE
                    // -----------------------------------------------------------------
                    // RBIL: INT 10,03 - GET CURSOR POSITION AND SIZE
                    // INPUT: BH = Page number
                    // OUTPUT: DH = Row, DL = Column, CH = Start line, CL = End line
                    //
                    // Return coordinates (0,0), indicating default position.
                    0x03 => {
                        registers.gpr.rax.set_low_u16(0);
                        registers.gpr.rdx.set_low_u16(0);

                        self.set_cf_value(ss_base, rsp, false); // success
                    }

                    // -----------------------------------------------------------------
                    // INT 10h, AH=06h - SCROLL UP WINDOW / CLEAR SCREEN
                    // -----------------------------------------------------------------
                    // RBIL: INT 10,06 - SCROLL UP WINDOW
                    // INPUT: AL = Lines to scroll (0 = clear entire window)
                    //
                    // When AL=0, interpret as clearing the window.
                    // Otherwise, emit a `\n` byte over serial port COM2.
                    0x06 => {
                        let lines_to_scroll = registers.gpr.rax.low_u8();

                        if lines_to_scroll == 0 {
                            log::debug!("INT 10h AH=06h: Screen Cleared via ANSI");
                        } else {
                            // '\n' * lines_to_scroll

                            self.last_cursor_row += 1;
                        }

                        self.set_cf_value(ss_base, rsp, false); // success
                    }

                    // -----------------------------------------------------------------
                    // INT 10h, AH=09h - WRITE CHARACTER AND ATTRIBUTE AT CURSOR
                    // -----------------------------------------------------------------
                    // RBIL: INT 10,09 - WRITE CHARACTER AND ATTRIBUTE AT CURSOR POSITION
                    // INPUT: AL = ASCII character, CX = Repeat count, BL = Color attribute
                    //
                    // Redirect output directly to UART/Serial controller.
                    0x09 => {
                        let character = registers.gpr.rax.low_u8();
                        let count = registers.gpr.rcx.low_u16();

                        //let mut serial = Serial::from_port(0x2F8);
                        for _ in 0..count {
                            //serial.write_byte(character);

                            if character == b'\n' {
                                self.last_cursor_row += 1;
                            }
                        }

                        self.set_cf_value(ss_base, rsp, false); // success
                    }

                    // -----------------------------------------------------------------
                    // INT 10h, AH=12h - ALTERNATE FUNCTION SELECT (EGA/VGA)
                    // -----------------------------------------------------------------
                    // RBIL: INT 10,12 - ALTERNATE FUNCTION SELECT (EGA/VGA)
                    // INPUT: BL = 10h (Get EGA Information)
                    // OUTPUT: BH = Color mode, BL = RAM (3 = 256k), CH = Flags, CL = Switch settings
                    //
                    // Inform OS/bootloader that a fully functional VGA adapter
                    // with 256 KB video RAM is present.
                    0x12 => {
                        registers.gpr.rbx.set_low_u16(0x0003);
                        registers.gpr.rcx.set_low_u16(0x0009);

                        self.set_cf_value(ss_base, rsp, false); // success
                    }

                    // -----------------------------------------------------------------
                    // INT 10h, AH=1Ah - DISPLAY COMBINATION CODE (DCC)
                    // -----------------------------------------------------------------
                    // RBIL: INT 10,1A - DISPLAY COMBINATION CODE
                    // INPUT: AL = 00h (Get DCC)
                    // OUTPUT: AL = 1Ah (Supported), BL = Active display code (08h = Color VGA with monitor)
                    //
                    // Report presence of an active color VGA display.
                    0x1A => {
                        registers.gpr.rax.set_low_u16(0x001A);
                        registers.gpr.rbx.set_low_u16(0x0008);

                        self.set_cf_value(ss_base, rsp, false); // success
                    }

                    // -----------------------------------------------------------------
                    // INT 10h, AH=0Eh - TELETYPE OUTPUT
                    // -----------------------------------------------------------------
                    // RBIL: INT 10,0E - TELETYPE OUTPUT
                    // INPUT: AL = ASCII character to output
                    //
                    // Write output character directly to hypervisor debug log.
                    0x0E => {
                        let ch = registers.gpr.rax.low_u8() as char;

                        log::debug!("Got char: {}", ch);
                    }

                    // -----------------------------------------------------------------
                    // INT 10h, AH=0Fh - GET CURRENT VIDEO MODE
                    // -----------------------------------------------------------------
                    // RBIL: INT 10,0F - GET CURRENT VIDEO MODE
                    // OUTPUT: AH = Number of columns (80), AL = Mode (03h), BH = Active page (0)
                    //
                    // Standard report for 80x25 text mode.
                    0x0F => {
                        let mode: u8 = 0x03;
                        let columns: u8 = 80;
                        let active_page: u8 = 0;

                        registers.gpr.rax.set_low_u8(mode);
                        registers.gpr.rax.set_high_u8(columns);

                        registers.gpr.rbx.set_high_u8(active_page);
                    }

                    // -----------------------------------------------------------------
                    // INT 10h, AH=4Fh - VESA SUPERVGA BIOS EXTENSIONS (VBE)
                    // -----------------------------------------------------------------
                    // RBIL: INT 10,4F - VESA SuperVGA BIOS EXTENSIONS
                    // INPUT: AL = VBE Subfunction
                    // OUTPUT: AX = Status (0000h = Error / VBE graphics extensions not supported)
                    //
                    // Return zero status signaling no support for VESA graphics extensions.
                    0x4F => {
                        registers.gpr.rax.set_low_u16(0);
                    }

                    unknown => panic!(
                        "Got unknown int10h with AH=0x{:x} (eax: 0x{:x})",
                        unknown,
                        registers.gpr.rax.low_u32()
                    ),
                }
            }

            // =========================================================================
            // INT 11h - GET EQUIPMENT LIST
            // =========================================================================
            // RBIL: INT 11 - GET EQUIPMENT LIST
            // OUTPUT: AX = Hardware equipment word
            //
            // Return value `(2 << 4)` = 0x0020 (Bits 4-5 indicate initial
            // 80x25 color video mode and presence of 80x87 math coprocessor).
            0x11 => match registers.gpr.rax {
                0x00 => {
                    registers.gpr.rax.set_low_u16(2 << 4);

                    self.set_cf_value(ss_base, rsp, false); // success
                }
                unknown => panic!("Got unknown int11h with RAX=0x{:x}", unknown),
            },

            // =========================================================================
            // INT 12h - GET CONVENTIONAL MEMORY SIZE
            // =========================================================================
            // RBIL: INT 12 - GET MEMORY SIZE
            // OUTPUT: AX = Continuous conventional base memory size in KB (0 to 640 KB)
            //
            // Return standard full 640 KB conventional x86 memory.
            0x12 => {
                registers.gpr.rax.set_low_u16(640);

                self.set_cf_value(ss_base, rsp, false); // success
            }

            // =========================================================================
            // INT 13h - DISK BIOS SERVICES
            // =========================================================================
            // RBIL: INT 13 - DISK BIOS SERVICES
            0x13 => match ah {
                // -----------------------------------------------------------------
                // INT 13h, AH=08h - GET CURRENT DRIVE PARAMETERS
                // -----------------------------------------------------------------
                // RBIL: INT 13,08 - GET CURRENT DRIVE PARAMETERS
                // INPUT: DL = Drive number (0x80 = First hard disk)
                // OUTPUT: AH = Error status (0), BL = Drive type (04h), DH = Max head,
                //         CX = Max cylinder & sector, CF = 0 (Success) / 1 (Error)
                //
                // Compute virtual CHS geometry for drive `0x80` based on
                // total RAM size allocated for the guest.
                0x08 => {
                    let dl = registers.gpr.rdx.low_u8();

                    // We only support boot disk (0x80)
                    if dl != 0x80 {
                        registers.gpr.rax.set_high_u8(0x07); // Drive parameter activity failed

                        self.set_cf_value(ss_base, rsp, true); // error
                    } else {
                        let sectors_per_track = 63u8;
                        let heads = 16u16;

                        let total_sectors = (self.options.mem_size / HYPERVISOR_SECTOR_SIZE as u64)
                            .max((heads as u64) * (sectors_per_track as u64));

                        let cylinders =
                            (total_sectors / (heads as u64 * sectors_per_track as u64)) as u16;

                        let max_cylinder = cylinders.saturating_sub(1) & 0x03FF;
                        let max_head = heads.saturating_sub(1) as u8;
                        let max_sector = sectors_per_track & 0x3F;

                        registers.gpr.rax.set_high_u8(0);
                        registers.gpr.rbx.set_low_u8(0x04); // Fixed disk / HD
                        registers.gpr.rdx.set_high_u8(max_head);
                        registers.gpr.rdx.set_low_u8(1); // Number of attached drives = 1
                        registers.gpr.rcx.set_high_u8((max_cylinder & 0xFF) as u8);

                        let cl_val = (((max_cylinder >> 8) << 6) as u8) | max_sector;
                        registers.gpr.rcx.set_low_u8(cl_val);

                        self.set_cf_value(ss_base, rsp, false); // success
                    }
                }

                // -----------------------------------------------------------------
                // INT 13h, AH=41h - EDD INSTALLATION CHECK
                // -----------------------------------------------------------------
                // RBIL: INT 13,41 - IBM/MS INT 13 Extensions - INSTALLATION CHECK
                // INPUT: BX = 55AAh, DL = Drive number (0x80)
                // OUTPUT: CF = 0 (EDD installed), BX = AA55h, AH = EDD version (0x21), CX = LBA bitmask
                //
                // Informs bootloader (e.g., GRUB) that the system supports LBA addressing (DAP packets).
                0x41 => {
                    let drive = registers.gpr.rdx.low_u8();
                    let magic = registers.gpr.rbx.low_u16();

                    if magic == 0x55AA && drive >= 0x80 {
                        registers.gpr.rbx.set_low_u16(0xAA55); // magic
                        registers.gpr.rax.set_low_u16(0x2100); // EDD 1.1 / 2.0
                        registers.gpr.rcx.set_low_u16(5); // Fixed disk subset + EDD extensions
                        self.set_cf_value(ss_base, rsp, false); // success
                    } else {
                        registers.gpr.rax = (registers.gpr.rax & !0xFF00) | 0x0100; // Invalid command
                        self.set_cf_value(ss_base, rsp, true); // error
                    }
                }

                // -----------------------------------------------------------------
                // INT 13h, AH=42h - EXTENDED READ (LBA)
                // -----------------------------------------------------------------
                // RBIL: INT 13,42 - IBM/MS INT 13 Extensions - EXTENDED READ
                // INPUT: DL = Drive, DS:SI = Pointer to DAP packet (`BiosDiskAddressPacket`)
                // OUTPUT: AH = Status, CF = 1 (Error if no backing image attached)
                //
                // Signal absence of backing ISO/image file by returning read failure status.
                0x42 => {
                    let dl = registers.gpr.rdx.low_u8();
                    let si = registers.gpr.rsi.low_u16();
                    let packet_gpa = ds_base + si as u64;

                    let packet_ptr = self.slat.read().translate(packet_gpa).unwrap()
                        as *mut BiosDiskAddressPacket;
                    let packet = unsafe { *packet_ptr };

                    let packet_lba = packet.starting_block_number;
                    let packet_blocks = packet.number_of_blocks_to_transfer;
                    let packet_segment = packet.buffer_segment;
                    let packet_offset = packet.buffer_offset;

                    assert!(packet.size_of_packet == 16);

                    // Support only disk reads on boot device (0x80)
                    if dl != 0x80 {
                        registers.gpr.rax.set_high_u8(0x01);

                        self.set_cf_value(ss_base, rsp, true); // error
                    } else {
                        log::debug!(
                            "INT 13h AH=42h requested LBA={} blocks={} buf={:04x}:{:04x}, no backing ISO attached",
                            packet_lba,
                            packet_blocks,
                            packet_segment,
                            packet_offset
                        );

                        // @TODO: Implement read

                        registers.gpr.rax.set_high_u8(0x01);

                        self.set_cf_value(ss_base, rsp, true); // error
                    }
                }

                // -----------------------------------------------------------------
                // INT 13h, AH=43h - EXTENDED WRITE (LBA)
                // -----------------------------------------------------------------
                // RBIL: INT 13,43 - IBM/MS INT 13 Extensions - EXTENDED WRITE
                // INPUT: DL = Drive, DS:SI = Pointer to DAP packet
                //
                // Translates guest segment address to physical memory GPA
                // and performs a dummy write with CF=0.
                0x43 => {
                    let dl = registers.gpr.rdx.low_u16();
                    assert_eq!(dl, 0x80); // only boot disk supported

                    let packet_gpa = ds_base + registers.gpr.rsi.low_u16() as u64;
                    let packet_ptr = self.slat.read().translate(packet_gpa).unwrap()
                        as *mut BiosDiskAddressPacket;
                    let packet = unsafe { *packet_ptr };

                    let packet_segment = packet.buffer_segment;
                    let packet_offset = packet.buffer_offset;
                    let packet_blocks = packet.number_of_blocks_to_transfer;
                    let packet_lba = packet.starting_block_number;

                    log::debug!(
                        "Ptr=0x{:x}, Packet={:x?}",
                        packet_segment as u64 * 16 + packet_offset as u64,
                        packet
                    );

                    let source_ptr = self
                        .slat
                        .read()
                        .translate(packet_segment as u64 * 16 + packet_offset as u64)
                        .unwrap();

                    let source_slice = unsafe {
                        slice::from_raw_parts(
                            source_ptr as *const u8,
                            packet_blocks as usize * HYPERVISOR_SECTOR_SIZE,
                        )
                    };

                    let _start = packet_lba as usize * HYPERVISOR_SECTOR_SIZE;
                    let _end = _start + source_slice.len();

                    // @TODO: Implement write

                    self.set_cf_value(ss_base, rsp, false); // success
                }

                // -----------------------------------------------------------------
                // INT 13h, AH=48h - GET EXTENDED DRIVE PARAMETERS (EDD)
                // -----------------------------------------------------------------
                // RBIL: INT 13,48 - IBM/MS INT 13 Extensions - GET DRIVE PARAMETERS
                // INPUT: DL = Drive, DS:SI = Pointer to `BiosDriveParameters` structure
                // OUTPUT: AH = 0 (Success), structure populated with LBA parameters
                //
                // Passes full EDD geometry and total sector count calculated
                // from `mem_size` to bootloader.
                0x48 => {
                    let dl = registers.gpr.rdx.low_u8();
                    let si = registers.gpr.rsi.low_u16();

                    // support only boot disk
                    if dl != 0x80 {
                        self.set_cf_value(ss_base, rsp, true); // error

                        registers.gpr.rip += 3; // omit VMCALL instruction
                        return Ok(());
                    }

                    let extensions_gpa = ds_base + si as u64;
                    let extensions_ptr = self.slat.read().translate(extensions_gpa).unwrap();
                    let extensions = unsafe { &mut *(extensions_ptr as *mut BiosDriveParameters) };

                    let sectors_per_track = 63u32;
                    let heads = 16u32;

                    let total_sectors = (self.options.mem_size / HYPERVISOR_SECTOR_SIZE as u64)
                        .max((heads as u64) * (sectors_per_track as u64));
                    let cylinders =
                        (total_sectors / (heads as u64 * sectors_per_track as u64)) as u32;

                    extensions.size_of_buffer = mem::size_of::<BiosDriveParameters>() as u16;
                    extensions.flags = 0;
                    extensions.cylinders_on_drive = cylinders;
                    extensions.heads_on_drive = heads;
                    extensions.sectors_per_track = sectors_per_track;
                    extensions.total_sectors_on_drive = total_sectors;
                    extensions.bytes_per_sector = HYPERVISOR_SECTOR_SIZE as u16;
                    extensions.edd_configuration = 0;

                    registers.gpr.rax.set_high_u8(0);

                    self.set_cf_value(ss_base, rsp, false); // success
                }

                // -----------------------------------------------------------------
                // INT 13h, AH=00h - RESET DISK SYSTEM
                // -----------------------------------------------------------------
                // RBIL: INT 13,00 - RESET DISK SYSTEM
                // INPUT: DL = Drive number
                // OUTPUT: AH = Status (00h = Success for DL=0x80)
                0x00 => {
                    if registers.gpr.rdx.low_u8() != 0x80 {
                        registers.gpr.rax.set_high_u8(0x01);

                        self.set_cf_value(ss_base, rsp, true); // error
                    } else {
                        registers.gpr.rax.set_high_u8(0x00);

                        self.set_cf_value(ss_base, rsp, false); // success
                    }
                }
                unknown => panic!("Unknown BIOS call with AH=0x{:X}", unknown),
            },

            // =========================================================================
            // INT 15h - SYSTEM BIOS SERVICES
            // =========================================================================
            // RBIL: INT 15 - SYSTEM BIOS SERVICES
            0x15 => {
                let eax = registers.gpr.rax.low_u32();

                match eax {
                    // -----------------------------------------------------------------
                    // INT 15h, AX=5300h - APM INSTALLATION CHECK
                    // -----------------------------------------------------------------
                    // RBIL: INT 15,5300 - APM - INSTALLATION CHECK
                    // INPUT: AX = 5300h, BX = 0000h
                    // OUTPUT: AH = 86h (APM not supported), CF = 1
                    //
                    // Explicitly decline legacy APM power management support,
                    // forcing the guest OS kernel to switch to modern ACPI.
                    0x5300 => {
                        registers.gpr.rax.set_high_u8(0x86);

                        self.set_cf_value(ss_base, rsp, true); // error
                    }

                    // -----------------------------------------------------------------
                    // INT 15h, AH=88h - GET EXTENDED MEMORY SIZE (ABOVE 1MB)
                    // -----------------------------------------------------------------
                    // RBIL: INT 15,88 - SYSTEM - GET EXTENDED MEMORY SIZE
                    // OUTPUT: AX = Number of continuous 1KB memory blocks above 1MB (max 65535 KB)
                    //
                    // Return maximum representable value 0xFC00 (63 MB).
                    0x8800 => {
                        registers.gpr.rax.set_low_u16(0xFC00);

                        self.set_cf_value(ss_base, rsp, false); // success
                    }

                    // -----------------------------------------------------------------
                    // INT 15h, AX=E801h - GET MEMORY SIZE FOR >64M CONFIGURATIONS
                    // -----------------------------------------------------------------
                    // RBIL: INT 15,E801 - SYSTEM - GET MEMORY SIZE FOR >64M CONFIGURATIONS
                    // OUTPUT: AX/CX = KB between 1MB and 16MB (max 15360)
                    //          BX/DX = 64KB blocks above 16MB
                    //
                    // Supplies older kernels with accurate RAM size
                    // information without requiring full E820 parsing.
                    0xE801 => {
                        let total_ram_bytes = self.options.mem_size;
                        let total_ram_kb = total_ram_bytes / 1024;

                        let mem_1_to_16_mb = if total_ram_kb > 1024 {
                            cmp::min(total_ram_kb - 1024, 15360)
                        } else {
                            0
                        };

                        let mem_above_16_mb_64k_blocks = if total_ram_kb > 16384 {
                            (total_ram_kb - 16384) / 64
                        } else {
                            0
                        };

                        registers.gpr.rax.set_low_u16(mem_1_to_16_mb as u16);
                        registers.gpr.rcx.set_low_u16(mem_1_to_16_mb as u16);
                        registers
                            .gpr
                            .rbx
                            .set_low_u16(mem_above_16_mb_64k_blocks as u16);
                        registers
                            .gpr
                            .rdx
                            .set_low_u16(mem_above_16_mb_64k_blocks as u16);

                        self.set_cf_value(ss_base, rsp, false); // success

                        log::debug!(
                            "Returned E801 memory info: 1-16MB: {} KB, Above 16MB: {} * 64KB",
                            mem_1_to_16_mb,
                            mem_above_16_mb_64k_blocks
                        );
                    }

                    // -----------------------------------------------------------------
                    // INT 15h, AX=E820h - GET SYSTEM ADDRESS MAP
                    // -----------------------------------------------------------------
                    // RBIL: INT 15,E820 - SYSTEM - GET SYSTEM ADDRESS MAP
                    // INPUT: EAX = E820h, EDX = 534D4150h ('SMAP'), EBX = Entry index,
                    //        ECX = Buffer size, ES:DI = Buffer destination address
                    // OUTPUT: EAX = 'SMAP', EBX = Next index (or 0 if end),
                    //         ECX = Bytes written (20), CF = 0
                    //
                    // Standard memory mapping mechanism used by x86/x86_64 kernels.
                    // Iterates over the hypervisor's `memory_descriptors` vector.
                    0xE820 => {
                        let edx = registers.gpr.rdx.low_u32();
                        assert_eq!(edx, 0x534D4150); // 'SMAP' signature

                        let index = registers.gpr.rbx.low_u32();
                        let size_of_buffer = registers.gpr.rcx.low_u32();

                        if size_of_buffer < 20 {
                            log::debug!(
                                "Issued E820 memory map request with insufficient buffer size"
                            );

                            registers.gpr.rip += 3; // omit VMCALL instruction
                            self.set_cf_value(ss_base, rsp, true); // error

                            return Ok(());
                        }

                        if index as usize >= self.memory_descriptors.len() {
                            log::debug!(
                                "Issued E820 memory map request with index bigger than memory descriptor vector length"
                            );

                            registers.gpr.rip += 3; // omit VMCALL instruction
                            self.set_cf_value(ss_base, rsp, true); // error

                            return Ok(());
                        }

                        let descriptor = self.memory_descriptors[index as usize];
                        let entry = BiosMemoryMapAddressRangeDescriptor {
                            base: descriptor.range.start,
                            length: (descriptor.range.last - descriptor.range.start) + 1,
                            range_type: descriptor.memory_type,
                        };

                        let di = registers.gpr.rdi.low_u16();
                        let structure_buffer_ptr =
                            self.slat.read().translate(es_base + di as u64).unwrap()
                                as *mut BiosMemoryMapAddressRangeDescriptor;
                        unsafe { *structure_buffer_ptr = entry };

                        // Return next index or 0 when reaching end of descriptor list
                        registers.gpr.rbx.set_low_u32(
                            if (index as usize + 1) >= self.memory_descriptors.len() {
                                0
                            } else {
                                index + 1
                            },
                        );
                        registers.gpr.rcx.set_low_u32(20);
                        registers.gpr.rax.set_low_u32(0x534D4150); // 'SMAP' signature in EAX

                        self.set_cf_value(ss_base, rsp, false); // success
                    }

                    // -----------------------------------------------------------------
                    // INT 15h, AX=E980h - USB ENDPOINT SUPPORT CHECK
                    // -----------------------------------------------------------------
                    // RBIL: (Vendor extension check)
                    //
                    // Signal absence of USB support in BIOS layer.
                    0xE980 => {
                        registers.gpr.rax.set_high_u8(0x86);

                        self.set_cf_value(ss_base, rsp, true); // error
                    }

                    // -----------------------------------------------------------------
                    // INT 15h, AX=EC00h - TARGET OPERATING SYSTEM SPECIFICATION
                    // -----------------------------------------------------------------
                    // RBIL: INT 15,EC00 - SYSTEM - TARGET OPERATING SYSTEM SPECIFICATION
                    // INPUT: BL = OS mode (1 = 16-bit Protected, 2 = 32-bit Protected, 3 = 64-bit Long Mode)
                    //
                    // Ignore notification without raising error.
                    0xEC00 => {}

                    _ => panic!("Unknown BIOS call with EAX=0x{:x}", eax),
                }
            }

            // =========================================================================
            // INT 16h - KEYBOARD BIOS SERVICES
            // =========================================================================
            // RBIL: INT 16 - KEYBOARD BIOS SERVICES
            0x16 => {
                match ah {
                    // -----------------------------------------------------------------
                    // INT 16h, AH=02h - GET SHIFT STATUS
                    // -----------------------------------------------------------------
                    // RBIL: INT 16,02 - GET SHIFT STATUS
                    // OUTPUT: AL = Shift/Ctrl/Alt status flags (00h = None pressed)
                    0x02 => {
                        registers.gpr.rax.set_low_u8(0); // false

                        self.set_cf_value(ss_base, rsp, false); // success
                    }

                    // -----------------------------------------------------------------
                    // INT 16h, AH=03h - SET TYPEMATIC RATE AND DELAY
                    // -----------------------------------------------------------------
                    // RBIL: INT 16,03 - SET TYPEMATIC RATE AND DELAY
                    //
                    // Ignore attempt to modify physical keyboard rate/delay.
                    0x03 => {
                        registers.gpr.rax.set_high_u8(0);

                        self.set_cf_value(ss_base, rsp, false); // success
                    }

                    // -----------------------------------------------------------------
                    // INT 16h, AH=10h - READ EXTENDED KEYSTROKE
                    // -----------------------------------------------------------------
                    // RBIL: INT 16,10 - READ EXTENDED KEYSTROKE
                    //
                    // Return AX=0 when no key is pressed.
                    0x10 => {
                        registers.gpr.rax.set_low_u16(0);

                        self.set_cf_value(ss_base, rsp, false); // success
                    }

                    // -----------------------------------------------------------------
                    // INT 16h, AH=11h - CHECK FOR EXTENDED KEYSTROKE
                    // -----------------------------------------------------------------
                    // RBIL: INT 16,11 - CHECK FOR EXTENDED KEYSTROKE
                    // OUTPUT: ZF = 1 (Buffer empty / no key pending), ZF = 0 (Key pending in buffer)
                    0x11 => {
                        registers.gpr.rax.set_high_u8(0);

                        self.set_zf_value(ss_base, rsp, true); // Empty keyboard buffer
                        self.set_cf_value(ss_base, rsp, false); // success
                    }

                    _ => {
                        log::debug!("Unsupported INT 0x16 function: AH=0x{:x}", ah);
                        registers.gpr.rax.set_low_u16(0);

                        self.set_cf_value(ss_base, rsp, false); // success
                    }
                }
            }

            unknown => {
                log::debug!("uhandled interrupt number: {}", interrupt_number);
                log::debug!("rip=0x{:x}", registers.gpr.rip);

                panic!("Unknown RIP for BIOS call: 0x{:x}", unknown)
            }
        }

        // Advance RIP by 3 bytes to skip the BIOS trap instruction in guest frame
        registers.gpr.rip += 3;

        Ok(())
    }

    /// Helper function to set/clear the Carry Flag (CF, bit 0) in the EFLAGS/FLAGS word
    /// saved on the guest stack.
    ///
    /// # Parameters
    /// * `ss_base`: Guest SS segment base address.
    /// * `rsp`: Guest stack pointer RSP.
    /// * `set`: `true` to set CF=1 (signal error), `false` to clear CF=0 (success).
    fn set_cf_value(&self, ss_base: u64, rsp: u64, set: bool) {
        let flags_ptr = self.slat.read().translate(ss_base + rsp + 4).unwrap() as *mut u16;
        let mut flags = unsafe { *flags_ptr };

        if set {
            flags |= 1;
        } else {
            flags &= !0x1;
        }

        unsafe { *flags_ptr = flags };
    }

    /// Helper function to set/clear the Zero Flag (ZF, bit 6) in the EFLAGS/FLAGS word
    /// saved on the guest stack.
    ///
    /// # Parameters
    /// * `ss_base`: Guest SS segment base address.
    /// * `rsp`: Guest stack pointer RSP.
    /// * `set`: `true` to set ZF=1, `false` to clear ZF=0.
    fn set_zf_value(&self, ss_base: u64, rsp: u64, set: bool) {
        let flags_ptr = self.slat.read().translate(ss_base + rsp + 4).unwrap() as *mut u16;
        let mut flags = unsafe { *flags_ptr };

        if set {
            flags |= 1 << 6;
        } else {
            flags &= !(1 << 6);
        }

        unsafe { *flags_ptr = flags };
    }
}
