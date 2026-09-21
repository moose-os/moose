//! # Linux x86 Boot Protocol Definitions (`bootparam.h`)
//!
//! This module defines the essential C-compatible data structures and constants required by the
//! x86/x86_64 Linux Boot Protocol (as specified in `arch/x86/include/uapi/asm/bootparam.h` in the Linux kernel).
//!
//! ## Overview & Boot Flow
//!
//! When booting a 32-bit or 64-bit Linux kernel directly,
//! the VMM acts as a 32-bit/64-bit boot loader and must construct a 4096-byte memory structure
//! historically referred to as the Zero Page ([`BootParams`]).
//!
//! The hypervisor initializes this page in guest RAM and passes its physical base address in the `RSI`
//! CPU register prior to jumping to the kernel entry point.
//!
//! Key responsibilities of the hypervisor during boot setup:
//! 1. Read the kernel image header into memory and parse [`SetupHeader`].
//! 2. Ensure magic signatures (`boot_flag == 0xAA55` and `header == 0x53726448` / `"HdrS"`) are valid.
//! 3. Populate [`BootParams`] with system topology:
//!    * E820 Memory Map: Handled via [`E820Entry`] items in [`BootParams::e820_table`].
//!    * Kernel Command Line: Configured via `cmd_line_ptr` (and optionally `ext_cmd_line_ptr`).
//!    * Initrd / Ramdisk: Configured via `ramdisk_image` and `ramdisk_size`.
//!    * ACPI RSDP Location: Stored at `acpi_rsdp_addr` for modern ACPI table discovery.

/// Standard x86 hypervisor disk sector size (512 bytes).
///
/// Used as a block unit size when calculating setup sector offsets and real-mode header boundaries.
pub const HYPERVISOR_SECTOR_SIZE: usize = 512;

/// System Memory Map Entry as reported by BIOS/ACPI interrupt `INT 15h, AX=E820h`.
///
/// The Linux kernel uses an array of these structures inside [`BootParams`] to map physical RAM,
/// reserved system regions, ACPI tables, and MMIO address ranges.
#[repr(C, packed)]
#[derive(Copy, Clone, Debug, Default)]
pub struct E820Entry {
    /// Physical base address of the memory range.
    pub addr: u64,

    /// Size of the memory range in bytes.
    pub size: u64,

    /// Memory region type classification.
    ///
    /// Standard values defined by the E820 spec:
    /// * `1` (`E820_TYPE_RAM`): Usable system RAM available to the operating system.
    /// * `2` (`E820_TYPE_RESERVED`): Reserved region (e.g., system ROM, motherboard memory).
    /// * `3` (`E820_TYPE_ACPI`): ACPI reclaimable memory (can be freed after reading ACPI tables).
    /// * `4` (`E820_TYPE_NVS`): ACPI Non-Volatile Storage (must not be touched by OS).
    /// * `5` (`E820_TYPE_UNUSABLE`): Unusable memory (defective memory blocks).
    pub typ: u32,
}

// ============================================================
//  Linux x86 boot protocol structures
//  Source: arch/x86/include/uapi/asm/bootparam.h
// ============================================================

/// Linux kernel setup header embedded inside the real-mode code of the kernel image.
///
/// Located at byte offset `0x01F1` within [`BootParams`]. This structure contains kernel metadata
/// read by the bootloader (e.g. protocol version, kernel entry points, alignment constraints) as well as
/// parameters populated by the bootloader for the kernel (e.g. command line pointer, initrd address).
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct SetupHeader {
    /// Number of setup sectors (0x1F1). If 0, defaults to 4 sectors (2048 bytes).
    pub setup_sects: u8,

    /// Root filesystem flags (0x1F2). Legacy flag passed to kernel.
    pub root_flags: u16,

    /// Protected-mode code size in 16-byte paragraphs (0x1F4).
    pub syssize: u32,

    /// Obsolete RAM size specification (0x1F8). Unused in modern boot protocols.
    pub ram_size: u16,

    /// Video mode control word (0x1FA). `0xFFFF` indicates default/normal video mode.
    pub vid_mode: u16,

    /// Default root device number (0x1FC). Legacy parameter.
    pub root_dev: u16,

    /// MBR / Boot sector magic signature (0x1FE). Must equal `0xAA55`.
    pub boot_flag: u16,

    /// Jump instruction bytes for real-mode entry (0x200).
    pub jump: u16,

    /// Linux boot protocol header magic (0x202). Must equal `0x53726448` (ASCII `"HdrS"`).
    pub header: u32,

    /// Boot protocol version implemented by the kernel (0x206). Encoded as `(major << 8) | minor` (e.g. `0x020F` = 2.15).
    pub version: u16,

    /// Real-mode switch hook function address (0x208).
    pub realmode_swtch: u32,

    /// Start segment for protected-mode code (0x20C). Legacy real-mode parameter.
    pub start_sys_seg: u16,

    /// Pointer to kernel version string offset (0x20E).
    pub kernel_version: u16,

    /// Loader identification identifier (0x210).
    ///
    /// Set by bootloader to indicate its type (e.g., GRUB, QEMU/KVM, custom VMM). `0xFF` represents an undefined/custom loader.
    pub type_of_loader: u8,

    /// Bitmask flags modifying boot behavior (0x211).
    /// * Bit 0 (`LOADED_HIGH`): Kernel protected-mode code loaded at `0x100000` (1MB+).
    /// * Bit 5 (`CAN_USE_HEAP`): Bootloader has configured `heap_end_ptr`.
    pub loadflags: u8,

    /// Move size limit for setup code (0x212).
    pub setup_move_size: u16,

    /// Protected-mode kernel entry point address (0x214). Defaults to `0x100000` (1MB).
    pub code32_start: u32,

    /// Physical 32-bit address of the loaded initial ramdisk (initrd/initramfs) image (0x218).
    pub ramdisk_image: u32,

    /// Size of the loaded initial ramdisk in bytes (0x21C).
    pub ramdisk_size: u32,

    /// Boot sector kludge address (0x220). Reserved/obsolete.
    pub bootsect_kludge: u32,

    /// Offset to the end of the bootloader real-mode heap (0x224).
    pub heap_end_ptr: u16,

    /// Extended bootloader version suffix (0x226).
    pub ext_loader_ver: u8,

    /// Extended bootloader type identifier (0x227).
    pub ext_loader_type: u8,

    /// Physical 32-bit address of the null-terminated ASCII kernel command-line string (0x228).
    pub cmd_line_ptr: u32,

    /// Maximum physical address reachable by the initrd (0x22C). Default is `0x37FFFFFF` (896MB).
    pub initrd_addr_max: u32,

    /// Hardware alignment requirement for relocatable kernel (0x230).
    pub kernel_alignment: u32,

    /// Non-zero if the kernel binary is relocatable in physical memory (0x234).
    pub relocatable_kernel: u8,

    /// Minimum physical alignment order required by relocatable kernel (0x235).
    pub min_alignment: u8,

    /// Extended feature capabilities flags (0x236).
    /// * Bit 0 (`XLFD_KERNEL_64`): Kernel supports 64-bit entry protocol (`code64_start`).
    /// * Bit 1 (`XLFD_CAN_BE_LOADED_ABOVE_4G`): Kernel can be loaded above 4GB physical boundary.
    pub xloadflags: u16,

    /// Maximum supported length of the command-line string in bytes (0x238).
    pub cmdline_size: u32,

    /// Hardware subarchitecture identifier (0x23C). Default `0` for standard PC x86 hardware.
    pub hardware_subarch: u32,

    /// Subarchitecture-specific data payload pointer (0x240).
    pub hardware_subarch_data: u64,

    /// Offset to kernel payload within setup image (0x248).
    pub payload_offset: u32,

    /// Length of compressed kernel payload in bytes (0x24C).
    pub payload_length: u32,

    /// Physical pointer to linked list of `setup_data` extension headers (0x250).
    pub setup_data: u64,

    /// Preferred physical base address for loading the kernel (0x258).
    pub pref_address: u64,

    /// Total runtime memory footprint size required by kernel initialization (0x260).
    pub init_size: u32,

    /// Offset to EFI handover entry point (0x264).
    pub handover_offset: u32,

    /// Offset to `kernel_info` structure (0x268).
    pub kernel_info_offset: u32,
}

impl Default for SetupHeader {
    /// Creates a default `SetupHeader` initialized with mandatory boot protocol magic constants.
    ///
    /// Sets:
    /// * `boot_flag = 0xAA55`
    /// * `header = 0x53726448` (`"HdrS"`)
    /// * `vid_mode = 0xFFFF` (Normal video)
    /// * `type_of_loader = 0xFF` (Custom/Undefined bootloader)
    /// * `initrd_addr_max = 0x37FFFFFF` (896MB legacy maximum initrd boundary)
    fn default() -> Self {
        Self {
            setup_sects: 0,
            root_flags: 0,
            syssize: 0,
            ram_size: 0,
            vid_mode: 0xFFFF, // NORMAL_VID_MODE
            root_dev: 0,
            boot_flag: 0xAA55, // Magic MBR signature
            jump: 0,
            header: 0x53726448, // ASCII "HdrS"
            version: 0,
            realmode_swtch: 0,
            start_sys_seg: 0,
            kernel_version: 0,
            type_of_loader: 0xFF, // Undefined loader type
            loadflags: 0,
            setup_move_size: 0,
            code32_start: 0,
            ramdisk_image: 0,
            ramdisk_size: 0,
            bootsect_kludge: 0,
            heap_end_ptr: 0,
            ext_loader_ver: 0,
            ext_loader_type: 0,
            cmd_line_ptr: 0,
            initrd_addr_max: 0x37FFFFFF, // Default Linux initrd upper limit
            kernel_alignment: 0,
            relocatable_kernel: 0,
            min_alignment: 0,
            xloadflags: 0,
            cmdline_size: 0,
            hardware_subarch: 0,
            hardware_subarch_data: 0,
            payload_offset: 0,
            payload_length: 0,
            setup_data: 0,
            pref_address: 0,
            init_size: 0,
            handover_offset: 0,
            kernel_info_offset: 0,
        }
    }
}

/// Linux Boot Parameters structure representing the complete Zero Page (`struct boot_params`).
///
/// This 4096-byte page is constructed by the hypervisor and placed in physical RAM before passing
/// control to the guest Linux kernel. It aggregates hardware detection details, video modes, EFI info,
/// ACPI RSDP pointers, setup headers, and the primary E820 physical memory map.
#[derive(Debug)]
#[repr(C, packed)]
pub struct BootParams {
    /// Screen and display topology information (0x000).
    pub screen_info: [u8; 0x40],

    /// APM BIOS specification details (0x040).
    pub apm_bios_info: [u8; 0x14],

    /// Padding alignment buffer (0x054).
    pub _pad2: [u8; 4],

    /// Tboot physical address pointer (0x058).
    pub tboot_addr: u64,

    /// Intel SpeedStep IST information (0x060).
    pub ist_info: [u8; 0x10],

    /// Physical address of the ACPI RSDP (Root System Description Pointer) table (0x070).
    pub acpi_rsdp_addr: u64,

    /// Padding alignment buffer (0x078).
    pub _pad3: [u8; 8],

    /// First hard disk geometry details from BIOS (0x080).
    pub hd0_info: [u8; 0x10],

    /// Second hard disk geometry details from BIOS (0x090).
    pub hd1_info: [u8; 0x10],

    /// System description table header (0x0A0).
    pub sys_desc_table: [u8; 0x10],

    /// OLPC OFW header (0x0B0).
    pub olpc_ofw_header: [u8; 0x10],

    /// High 32 bits of 64-bit initial ramdisk physical address (0x0C0).
    pub ext_ramdisk_image: u32,

    /// High 32 bits of 64-bit initial ramdisk size (0x0C4).
    pub ext_ramdisk_size: u32,

    /// High 32 bits of 64-bit kernel command-line physical pointer (0x0C8).
    pub ext_cmd_line_ptr: u32,

    /// Reserved padding buffer (0x0CC).
    pub _pad4: [u8; 0x74],

    /// EDID display identification information (0x140).
    pub edid_info: [u8; 0x80],

    /// EFI boot system information (0x1C0).
    pub efi_info: [u8; 0x20],

    /// Alternative memory size in kilobytes (0x1E0).
    pub alt_mem_k: u32,

    /// Scratch space for bootloader use (0x1E4).
    pub scratch: u32,

    /// Number of valid entries populated in [`BootParams::e820_table`] (0x1E8). Max value is 128.
    pub e820_entries: u8,

    /// Number of EDD buffer entries (0x1E9).
    pub eddbuf_entries: u8,

    /// Number of EDD MBR signature buffer entries (0x1EA).
    pub edd_mbr_sig_buf_entries: u8,

    /// Keyboard status byte from BIOS (0x1EB).
    pub kbd_status: u8,

    /// Secure boot status flags (0x1EC).
    pub secure_boot: u8,

    /// Alignment padding (0x1ED).
    pub _pad5: [u8; 2],

    /// Sentinel byte indicating valid setup header presence (0x1EF).
    pub sentinel: u8,

    /// Alignment padding (0x1F0).
    pub _pad6: [u8; 1],

    /// Embedded Linux Kernel Setup Header (0x1F1).
    pub setup_header: SetupHeader,

    /// Explicit alignment padding calculated to ensure `e820_table` begins precisely at offset `0x02D0`.
    pub _reserved6: [u8; 0x2D0 - 0x1F1 - core::mem::size_of::<SetupHeader>()],

    /// E820 physical memory map array (0x02D0).
    ///
    /// Contains up to 128 [`E820Entry`] elements defining the memory layout exposed to the guest OS.
    /// The number of valid active entries is specified by [`BootParams::e820_entries`].
    pub e820_table: [E820Entry; 128],
}

impl Default for BootParams {
    /// Constructs a zeroed `BootParams` instance initialized with default [`SetupHeader`] configuration.
    fn default() -> Self {
        Self {
            screen_info: [0u8; 0x40],
            apm_bios_info: [0u8; 0x14],
            _pad2: [0u8; 4],
            tboot_addr: 0,
            ist_info: [0u8; 0x10],
            acpi_rsdp_addr: 0,
            _pad3: [0u8; 8],
            hd0_info: [0u8; 0x10],
            hd1_info: [0u8; 0x10],
            sys_desc_table: [0u8; 0x10],
            olpc_ofw_header: [0u8; 0x10],
            ext_ramdisk_image: 0,
            ext_ramdisk_size: 0,
            ext_cmd_line_ptr: 0,
            _pad4: [0u8; 0x74],
            edid_info: [0u8; 0x80],
            efi_info: [0u8; 0x20],
            alt_mem_k: 0,
            scratch: 0,
            e820_entries: 0,
            eddbuf_entries: 0,
            edd_mbr_sig_buf_entries: 0,
            kbd_status: 0,
            secure_boot: 0,
            _pad5: [0u8; 2],
            sentinel: 0,
            _pad6: [0u8; 1],
            setup_header: SetupHeader::default(),
            _reserved6: [0u8; 0x2D0 - 0x1F1 - core::mem::size_of::<SetupHeader>()],
            e820_table: [E820Entry::default(); 128],
        }
    }
}
