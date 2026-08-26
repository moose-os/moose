//! This module provides hardware-agnostic routines to initialize an x86/x86_64 guest
//! virtual machine before execution starts. It handles guest memory allocation,
//! Second-level address translation (SLAT / EPT / NPT) mappings, minimal BIOS emulation
//! via Real-Mode Interrupt Vector Tables (IVT) and BIOS Data Area (BDA), as well as
//! kernel payload loading.
//!
//! # Architecture Overview
//!
//! ```text
//! +------------------------------------+ 0x0000_0000 (0 KiB)
//! | IVT Table (256 * 4 bytes)          |
//! +------------------------------------+ 0x0000_0400 (1 KiB)
//! | BIOS Data Area (BDA)               |
//! +------------------------------------+ 0x0000_0500
//! | Real-Mode Hypercall Stubs          |
//! +------------------------------------+ 0x0000_9000 (36 KiB)
//! | Multiboot Info Structs (if ELF)    |
//! +------------------------------------+ 0x0001_0000 (64 KiB)
//! | Linux Zero-Page (BootParams)       |
//! +------------------------------------+ 0x0002_0000 (128 KiB)
//! | Kernel Command Line string         |
//! +------------------------------------+ 0x000A_0000 - 0x000F_FFFF (640 KiB - 1 MiB)
//! | Reserved (VRAM, Video/System BIOS) |
//! +------------------------------------+ 0x0010_0000 (1 MiB)
//! | Extended Memory (OS RAM / Kernel)  |
//! +------------------------------------+
//! ```

use core::{cmp, ptr, range::RangeInclusive};

use crate::{
    driver::hv::reindeer::{
        BootSource, GuestPhysAddr, HostPhysAddr, HypervisorError, MemoryAccessRights, SlatManager,
        VmOptions,
        guest::boot::linux::{BootParams, E820Entry, SetupHeader},
        guest_machine::{MemoryDescriptorType, VirtualMachineMemoryDescriptor},
    },
    subsystem::memory::{
        Exact, Frame, MapTarget, PAGE_SIZE, Page, PageFlags, PhysicalAddress, VirtualAddress,
        memory_manager,
    },
};

/// Intel VT-x hypercall opcode bytes (`VMCALL`).
pub const HYPERCALL_VMCALL: [u8; 3] = [0x0F, 0x01, 0xC1];

/// AMD-V hypercall opcode bytes (`VMMCALL`).
pub const HYPERCALL_VMMCALL: [u8; 3] = [0x0F, 0x01, 0xD9];

/// Represents an entry in the 16-bit Real-Mode Interrupt Vector Table (IVT).
///
/// In x86 real-mode, each interrupt vector is 4 bytes long, consisting of a 16-bit
/// segment offset followed by a 16-bit segment selector.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
struct IvtEntry {
    /// The offset portion of the logical far address (`segment:offset`).
    pub offset: u16,

    /// The segment portion of the logical far address (`segment:offset`).
    pub segment: u16,
}

/// Constructs a classic PC e820 memory map.
pub fn default_pc_memory_map(mem_size: usize) -> alloc::vec::Vec<VirtualMachineMemoryDescriptor> {
    alloc::vec![
        // `0x0000_0000..=0x0009_EFFF` (640 KiB): Conventional Memory (Available).
        //   Lower RAM usable by Real Mode, DOS, and early bootloaders.
        VirtualMachineMemoryDescriptor {
            range: RangeInclusive::from(0x0000_0000..=0x0009_EFFF),
            memory_type: MemoryDescriptorType::AvailableToOs,
            allocate: true,
        },
        // `0x0009_F000..=0x0009_FFFF` (4 KiB): Extended BIOS Data Area (Reserved).
        //   Typically used by system BIOS for internal state tracking.
        VirtualMachineMemoryDescriptor {
            range: RangeInclusive::from(0x0009_F000..=0x0009_FFFF),
            memory_type: MemoryDescriptorType::Reserved,
            allocate: true,
        },
        // `0x000A_0000..=0x000F_FFFF` (384 KiB): MMIO / Firmware Area (Reserved).
        //   Encompasses Video RAM (`0xA0000-0xC7FFF`), Option ROMs (`0xC8000-0xEFFFF`),
        //   and System BIOS (`0xF0000-0xFFFFF`).
        VirtualMachineMemoryDescriptor {
            range: RangeInclusive::from(0x000A_0000..=0x000F_FFFF),
            memory_type: MemoryDescriptorType::Reserved,
            allocate: true,
        },
        // `0x0010_0000..=(0x0010_0000 + mem_size)`: Extended Memory (Available).
        //   High memory above the 1 MiB boundary where the operating system kernel and application RAM reside.
        VirtualMachineMemoryDescriptor {
            range: RangeInclusive::from(0x0010_0000..=(0x0010_0000 + mem_size as u64)),
            memory_type: MemoryDescriptorType::AvailableToOs,
            allocate: true,
        },
        // `0x7F6E_0000..=0x7F6E_FFFF` (64 KiB): ACPI Reclaim Memory.
        //   Non-volatile or ACPI table reservation area.
        VirtualMachineMemoryDescriptor {
            range: RangeInclusive::from(0x7F6E_0000..=0x7F6E_FFFF),
            memory_type: MemoryDescriptorType::AcpiReclaim,
            allocate: true,
        },
    ]
}

/// Allocates physical host frames and maps them into the guest SLAT for each region.
pub fn map_guest_ram(
    slat: &mut dyn SlatManager,
    memory_descriptors: &[VirtualMachineMemoryDescriptor],
) -> Result<(), HypervisorError> {
    for memory_descriptor in memory_descriptors {
        if !memory_descriptor.allocate {
            continue;
        }

        for gpa in memory_descriptor.range.into_iter().step_by(PAGE_SIZE) {
            let mut mm = memory_manager().write();
            let frame = mm.allocate_frame().unwrap().address().as_u64();

            unsafe {
                let page = Page::new(VirtualAddress::new(frame));
                let phys = Frame::new(PhysicalAddress::new(frame));
                mm.map(
                    MapTarget::CurrentAddressSpace(),
                    Exact(&page, &phys),
                    PageFlags::WRITABLE,
                )
                .map_err(|_| HypervisorError::MemoryMappingError)?;
            }

            drop(mm);

            slat.map(
                gpa as GuestPhysAddr,
                frame as HostPhysAddr,
                MemoryAccessRights::ReadWriteExecute,
            )?;
        }
    }
    Ok(())
}

/// Installs Real-Mode BIOS Interrupt Vector Table (IVT) handlers and sets initial BIOS Data Area (BDA) state.
///
/// Real-Mode Interrupt Vector Table (IVT) occupies physical address range `0x0000_0000` to `0x0000_03FF`
/// (256 vectors * 4 bytes each). When a real-mode interrupt occurs the CPU looks up `IVT[vector]` to
/// find the target `CS:IP`.
///
/// # Trapping via Hypercalls
/// Rather than hosting full legacy BIOS ROM firmware, this function constructs 256 minimal interrupt handler
/// trampolines starting at offset `0x0500`. Each handler executes:
/// ```x86asm
/// PUSH  imm8          ; Push interrupt vector number (0x00 - 0xFF)
/// VMCALL / VMMCALL    ; 3-byte architecture hypercall instruction
/// IRET                ; Return from real-mode interrupt
/// ```
/// When executed inside the VM, the hypercall instruction immediately triggers a VM-Exit into the host
/// hypervisor, which inspects the pushed vector number on the guest stack to emulate BIOS service requests.
///
/// # BIOS Data Area (BDA) Setup
/// Populates critical memory locations within `0x0000_0400..=0x0000_04FF`:
/// - `0x0408` (uint16): LPT1 base I/O port address (`0x0378`).
/// - `0x0413` (uint16): Conventional memory size in KiB (`640` KiB).
/// - `0x0475` (uint8): Number of hard drives detected (`1`).
/// - `0x0463` (uint16): Base I/O port address of the display controller (`0x03D4` = Color/VGA).
pub fn install_bios_ivt_stubs(slat: &dyn SlatManager, hypercall_insn: [u8; 3]) {
    let bios_call_page = slat.translate(0x0000).unwrap();

    unsafe {
        let ivt = bios_call_page as *mut [IvtEntry; 256];

        let handlers_start_offset = 0x500;
        let handler_size = 6;

        for i in 0..256 {
            let handler_offset = (handlers_start_offset + (i * handler_size)) as u16;

            // Point IVT[i] to offset 0x0500 + (i * 6), Segment 0x0000
            (*ivt)[i] = IvtEntry {
                offset: handler_offset,
                segment: 0,
            };

            let ptr = slat.translate(handler_offset as u64).unwrap() as *mut u8;

            // Assembly trampoline sequence:
            // Opcode 0x6A [i]:      PUSH i (push 8-bit immediate vector)
            // Opcode [h0, h1, h2]:  VMCALL or VMMCALL
            // Opcode 0xCF:          IRET
            let code = [
                0x6A,
                i as u8,
                hypercall_insn[0],
                hypercall_insn[1],
                hypercall_insn[2],
                0xCF,
            ];

            ptr::copy_nonoverlapping(code.as_ptr(), ptr, 6);
        }

        // 0x0408: LPT1 Parallel Port Base Address
        (slat.translate(0x408).unwrap() as *mut u16).write_unaligned(0x0378);

        // 0x0413: Base Conventional Memory Size in KiB (640 KB)
        (slat.translate(0x413).unwrap() as *mut u16).write_unaligned(640);

        // 0x0475: Hard Drive Count
        (slat.translate(0x475).unwrap() as *mut u8).write(1);

        // 0x0463: Base Port Address for Active Video Controller (0x03D4 = Color/VGA)
        (slat.translate(0x463).unwrap() as *mut u16).write_unaligned(0x03D4);
    }
}

/// Loads a guest boot image into guest RAM.
pub fn load_boot_source(
    slat: &dyn SlatManager,
    options: &VmOptions,
    memory_descriptors: &[VirtualMachineMemoryDescriptor],
    hypercall_insn: [u8; 3],
) -> Result<(), HypervisorError> {
    match options.boot_source.clone() {
        BootSource::Unknown => panic!("Unknown boot source"),
        BootSource::Bios { path } => {
            let _ = path;
            return Err(HypervisorError::InvalidConfiguration);
        }
        // Linux Boot Protocol
        // - Installs real-mode BIOS IVT and BDA stubs via [`install_bios_ivt_stubs`].
        // - Prepares the Linux Zero-Page ([`BootParams`]) structure at GPA `0x10000`:
        //   - Parses `SetupHeader` at offset `0x01F1` within `vmlinuz`.
        //   - Sets loader type to `0x71` (generic bootloader), configures kernel load flags,
        //     kernel entry point (`0x1000000`), command line pointer (`0x20000`), and initrd pointer (`0x8000000`).
        //   - Converts provided `memory_descriptors` into standard Linux E820 memory entries.
        // - Writes the command line string to GPA `0x20000`.
        // - Extracts the 32-bit setup sectors and copies the protected-mode kernel payload (`bzImage`) to GPA `0x1000000`.
        // - Copies the initrd ramdisk to GPA `0x8000000`.
        BootSource::LinuxBootProtocol {
            vmlinuz,
            initial_ramdisk,
            command_line,
        } => {
            let command_line_addr = 0x2_0000u32;
            let initrd_addr = 0x0800_0000u32;
            let vmlinuz_addr = 0x100_0000u64;

            // Install BIOS IVT stubs.
            install_bios_ivt_stubs(slat, hypercall_insn);

            // Initialize the Linux zero page.
            let mut params = BootParams::default();

            let setup_header = unsafe { vmlinuz.as_ptr().add(0x1f1) as *const SetupHeader };
            params.setup_header = unsafe { ptr::read_unaligned(setup_header) };

            params.setup_header.type_of_loader = 0x71;

            let initrd_len = initial_ramdisk.len() as u32;

            params.setup_header.cmd_line_ptr = command_line_addr;
            params.setup_header.cmdline_size = command_line.len() as u32 + 1;
            params.setup_header.loadflags = (params.setup_header.loadflags | 0x01) & !0x80;
            params.setup_header.code32_start = 0x1000000;
            params.setup_header.ramdisk_image = initrd_addr;
            params.setup_header.ramdisk_size = initrd_len;
            params.setup_header.boot_flag = 0xAA55;
            params.setup_header.header = 0x5372_6448; // "HdrS"
            params.sentinel = 0;
            params.ext_ramdisk_image = 0;
            params.ext_ramdisk_size = 0;
            params.ext_cmd_line_ptr = 0;

            // Populate the E820 memory map in the zero page.
            for (i, desc) in memory_descriptors.iter().enumerate() {
                params.e820_table[i] = E820Entry {
                    addr: desc.range.start,
                    size: desc.range.last - desc.range.start + 1,
                    typ: desc.memory_type as u32,
                };
            }
            params.e820_entries = memory_descriptors.len() as u8;

            let init_size = u32::from_le_bytes(vmlinuz[0x260..0x264].try_into().unwrap());
            params.setup_header.init_size = init_size;

            // Write zero page to GPA 0x10000.

            // https://www.kernel.org/doc/Documentation/x86/boot.rst
            //
            // ===========	========	=====================	============================================
            // 01F1/1		ALL(1)		setup_sects		        The size of the setup in sectors
            // 01F2/2		ALL		    root_flags		        If set, the root is mounted readonly
            // 01F4/4		2.04+(2)	syssize			        The size of the 32-bit code in 16-byte paras
            // 01F8/2		ALL		    ram_size		        DO NOT USE - for bootsect.S use only
            // 01FA/2		ALL		    vid_mode		        Video mode control
            // 01FC/2		ALL		    root_dev		        Default root device number
            // 01FE/2		ALL		    boot_flag		        0xAA55 magic number
            // 0200/2		2.00+		jump			        Jump instruction
            // 0202/4		2.00+		header			        Magic signature "HdrS"
            // 0206/2		2.00+		version			        Boot protocol version supported
            // 0208/4		2.00+		realmode_swtch		    Boot loader hook (see below)
            // 020C/2		2.00+		start_sys_seg		    The load-low segment (0x1000) (obsolete)
            // 020E/2		2.00+		kernel_version		    Pointer to kernel version string
            // 0210/1		2.00+		type_of_loader		    Boot loader identifier
            // 0211/1		2.00+		loadflags		        Boot protocol option flags
            // 0212/2		2.00+		setup_move_size		    Move to high memory size (used with hooks)
            // 0214/4		2.00+		code32_start		    Boot loader hook (see below)
            // 0218/4		2.00+		ramdisk_image		    initrd load address (set by boot loader)
            // 021C/4		2.00+		ramdisk_size		    initrd size (set by boot loader)
            // 0220/4		2.00+		bootsect_kludge		    DO NOT USE - for bootsect.S use only
            // 0224/2		2.01+		heap_end_ptr		    Free memory after setup end
            // 0226/1		2.02+(3)	ext_loader_ver		    Extended boot loader version
            // 0227/1		2.02+(3)	ext_loader_type		    Extended boot loader ID
            // 0228/4		2.02+		cmd_line_ptr		    32-bit pointer to the kernel command line
            // 022C/4		2.03+		initrd_addr_max		    Highest legal initrd address
            // 0230/4		2.05+		kernel_alignment	    Physical addr alignment required for kernel
            // 0234/1		2.05+		relocatable_kernel	    Whether kernel is relocatable or not
            // 0235/1		2.10+		min_alignment		    Minimum alignment, as a power of two
            // 0236/2		2.12+		xloadflags	            Boot protocol option flags
            // 0238/4		2.06+		cmdline_size		    Maximum size of the kernel command line
            // 023C/4		2.07+		hardware_subarch	    Hardware subarchitecture
            // 0240/8		2.07+		hardware_subarch_data	Subarchitecture-specific data
            // 0248/4		2.08+		payload_offset		    Offset of kernel payload
            // 024C/4		2.08+		payload_length		    Length of kernel payload
            // 0250/8		2.09+		setup_data		        64-bit physical pointer to linked list of struct setup_data
            // 0258/8		2.10+		pref_address		    Preferred loading address
            // 0260/4		2.10+		init_size		        Linear memory required during initialization
            // 0264/4		2.11+		handover_offset		    Offset of handover entry point
            // 0268/4		2.15+		kernel_info_offset	    Offset of the kernel_info
            // ===========	========	=====================	============================================
            unsafe {
                let boot_params = slat.translate(0x10000).unwrap() as *mut BootParams;
                *boot_params = params;

                let base = slat.translate(0x10000).unwrap() as *mut u8;

                base.add(0x1EF).write(0); // setup_sects
                base.add(0x210).write(0xFF); // type of loader == 0xFF == custom hv loader
                let lf = base.add(0x211).read(); // loadflags
                base.add(0x211).write((lf | 0x01) & !0x80); // 0x1 - CAN_USE_HEAP, 0x80 - KEEP_SEGMENTS

                ptr::write_unaligned(base.add(0x218) as *mut u32, initrd_addr);
                ptr::write_unaligned(base.add(0x21C) as *mut u32, initrd_len);
                ptr::write_unaligned(base.add(0x228) as *mut u32, command_line_addr);
                ptr::write_unaligned(base.add(0x0C0) as *mut u32, 0u32); // ext_ramdisk_image
                ptr::write_unaligned(base.add(0x0C4) as *mut u32, 0u32); // ext_ramdisk_size
            }

            // Copy kernel command-line string to GPA 0x20000.
            {
                let command_line_str = command_line.as_str();
                let bytes = command_line_str.as_bytes();
                let len = bytes.len();

                let dst_ptr = slat.translate(command_line_addr as u64).unwrap() as *mut u8;

                unsafe {
                    ptr::copy_nonoverlapping(bytes.as_ptr(), dst_ptr, len);
                    dst_ptr.add(len).write(0); // null terminator
                }
            }

            // Copy kernel payload to GPA 0x1000000.
            {
                let mut setup_sects = vmlinuz[0x1F1] as usize;

                // Compatibility: if setup_sects == 0, assume 4 sectors.
                if setup_sects == 0 {
                    setup_sects = 4;
                }

                // Kernel image follows the setup sectors.
                let kernel_start_offset = (setup_sects + 1) * 512;
                let vmlinuz_payload = &vmlinuz[kernel_start_offset..];
                let payload_len = vmlinuz_payload.len();

                let magic = &vmlinuz[0x202..0x206];
                if magic != b"HdrS" {
                    panic!("Not a valid bzImage!");
                }

                for offset in (0..payload_len).step_by(PAGE_SIZE) {
                    let chunk_size = cmp::min(PAGE_SIZE, payload_len - offset);

                    let guest_memory = slat
                        .translate(vmlinuz_addr + offset as u64)
                        .expect("Mapping error") as *mut u8;

                    unsafe {
                        ptr::copy_nonoverlapping(
                            vmlinuz_payload.as_ptr().add(offset),
                            guest_memory,
                            chunk_size,
                        );
                    }
                }
            }

            // Copy initrd payload to GPA 0x0800_0000.
            {
                for offset in (0..initial_ramdisk.len()).step_by(PAGE_SIZE) {
                    let chunk_size = core::cmp::min(PAGE_SIZE, initial_ramdisk.len() - offset);
                    let guest_memory =
                        slat.translate(initrd_addr as u64 + offset as u64)
                            .expect("Initrd mapping error") as *mut u8;

                    unsafe {
                        ptr::copy_nonoverlapping(
                            initial_ramdisk.as_ptr().add(offset),
                            guest_memory,
                            chunk_size,
                        );
                    }
                }
            }
        }
        _ => panic!("unsupported boot source"),
    }

    Ok(())
}

/// Writes serial (COM) port base addresses into the BIOS Data Area (BDA) and updates the Equipment Word.
pub fn write_bda_com_ports(slat: &dyn SlatManager, com_bases: &[u16]) {
    let count = cmp::min(com_bases.len(), 4);

    unsafe {
        // Populate COM1-COM4 ports in BDA
        for (i, port) in com_bases.iter().copied().take(4).enumerate() {
            (slat.translate(0x400 + (i as u64) * 2).unwrap() as *mut u16).write_unaligned(port);
        }

        // Zero unused slots
        for i in count..4 {
            (slat.translate(0x400 + (i as u64) * 2).unwrap() as *mut u16).write_unaligned(0);
        }

        // Equipment Word at 0x0410 (bits 9-11: serial port count)
        let equipment_ptr = slat.translate(0x410).unwrap() as *mut u16;
        let mut equipment = equipment_ptr.read_unaligned();
        equipment &= !(0b111 << 9);
        equipment |= ((count as u16) & 0b111) << 9;
        equipment_ptr.write_unaligned(equipment);
    }
}
