//! Representation of the vCPU architectural state (x86_64).

use core::mem;

/// Complete architectural state of a vCPU core.
///
/// Combines general-purpose registers (GPRs), control/status registers, and
/// the complete FPU/SSE/MMX register state area compliant with the `FXSAVE` instruction.
#[repr(C, align(64))]
#[derive(Debug, Default)]
pub struct CpuState {
    /// General-purpose registers (GPRs) and control registers.
    pub gpr: RegisterState,

    /// 512-byte buffer for floating-point and vector register state (x87 FPU, MMX, SSE).
    pub fxsave_area: FxSaveArea,
}

/// 512-byte save area for FPU, MMX, and SSE state (`FXSAVE` / `FXRSTOR`).
/// `FXSAVE` and `FXRSTOR` require 16-byte alignment.
#[repr(C, align(16))]
#[derive(Debug, Clone, Copy)]
pub struct FxSaveArea {
    /// Raw 512-byte buffer containing FPU/SSE state.
    pub data: [u8; 512],
}

impl Default for FxSaveArea {
    /// Creates a default `FxSaveArea` buffer matching the CPU reset state.
    ///
    /// # Default Configuration
    /// * FCW (x87 Control Word, offset 0..2): `0x037F`
    ///   - All exceptions (IM, DM, ZM, OM, UM, PM) masked.
    ///   - Precision: 64-bit (Extended Precision).
    ///   - Rounding: to nearest.
    /// * MXCSR (SSE Control/Status, offset 24..28): `0x1F80`
    ///   - Masks all SIMD/SSE floating-point exceptions (bits 7..12).
    fn default() -> Self {
        let mut area = FxSaveArea { data: [0; 512] };

        // FCW (offset 0, 2 bytes) = 0x037F
        area.data[0..2].copy_from_slice(&0x037Fu16.to_le_bytes());

        // MXCSR (offset 24, 4 bytes) = 0x1f80
        area.data[24..28].copy_from_slice(&0x1f80u32.to_le_bytes());

        area
    }
}

/// General-purpose registers (GPRs) and core vCPU control register state.
///
/// All offsets are closely tied to assembly routines responsible for performing a
/// full context switch when running VMs.
#[derive(Debug)]
#[repr(C, align(16))]
pub struct RegisterState {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rbp: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub rsp: u64,

    /// Flags register. Defaults to 0x2 (one reserved bit).
    pub rflags: u64,

    /// Padding field to make [`FxSaveArea`] aligned as well.
    pub pad: u64,
}

// Compile-time assertions verifying memory layout and structure sizes.
const _: () = assert!(mem::size_of::<RegisterState>() == 0xA0);
const _: () = assert!(mem::offset_of!(CpuState, gpr) == 0);
const _: () = assert!(mem::offset_of!(CpuState, fxsave_area) == 0xA0);

impl RegisterState {
    /// Reads a register value based on the ModR/M byte index and `iced-x86` register enum.
    pub fn get(&self, index: u8, reg: iced_x86::Register) -> u64 {
        use iced_x86::Register::*;

        let val = match index {
            0 => self.rax,
            1 => self.rcx,
            2 => self.rdx,
            3 => self.rbx,
            4 => unreachable!(), // RSP is not directly indexed this way in ModR/M without context
            5 => self.rbp,
            6 => self.rsi,
            7 => self.rdi,
            8 => self.r8,
            9 => self.r9,
            10 => self.r10,
            11 => self.r11,
            12 => self.r12,
            13 => self.r13,
            14 => self.r14,
            15 => self.r15,
            _ => unreachable!(),
        };

        match reg {
            AH | CH | DH | BH => (val >> 8) & 0xFF,
            _ => val,
        }
    }

    /// Writes a value to the specified register adhering to x86_64 architectural rules.
    /// 1. 32-bit Writes (E-x / R-D): Writing to a 32-bit register (e.g., `EAX`, `R8D`)
    ///    zero-extends upper 32 bits of the corresponding 64-bit register (`RAX`, `R8`).
    /// 2. 16-bit and 8-bit Writes (AX, AL, AH): Writes preserve the upper bits of the
    ///    destination register.
    pub fn set(&mut self, reg: iced_x86::Register, value: u64) {
        use iced_x86::Register::*;

        let (ptr, size) = match reg {
            RAX => (&mut self.rax, 8),
            RCX => (&mut self.rcx, 8),
            RDX => (&mut self.rdx, 8),
            RBX => (&mut self.rbx, 8),
            RSP => (&mut self.rsp, 8),
            RBP => (&mut self.rbp, 8),
            RSI => (&mut self.rsi, 8),
            RDI => (&mut self.rdi, 8),
            R8 => (&mut self.r8, 8),
            R9 => (&mut self.r9, 8),
            R10 => (&mut self.r10, 8),
            R11 => (&mut self.r11, 8),
            R12 => (&mut self.r12, 8),
            R13 => (&mut self.r13, 8),
            R14 => (&mut self.r14, 8),
            R15 => (&mut self.r15, 8),

            EAX => (&mut self.rax, 4),
            ECX => (&mut self.rcx, 4),
            EDX => (&mut self.rdx, 4),
            EBX => (&mut self.rbx, 4),
            ESP => (&mut self.rsp, 4),
            EBP => (&mut self.rbp, 4),
            ESI => (&mut self.rsi, 4),
            EDI => (&mut self.rdi, 4),
            R8D => (&mut self.r8, 4),
            R9D => (&mut self.r9, 4),
            R10D => (&mut self.r10, 4),
            R11D => (&mut self.r11, 4),
            R12D => (&mut self.r12, 4),
            R13D => (&mut self.r13, 4),
            R14D => (&mut self.r14, 4),
            R15D => (&mut self.r15, 4),

            AX => (&mut self.rax, 2),
            CX => (&mut self.rcx, 2),
            DX => (&mut self.rdx, 2),
            BX => (&mut self.rbx, 2),
            SP => (&mut self.rsp, 2),
            BP => (&mut self.rbp, 2),
            SI => (&mut self.rsi, 2),
            DI => (&mut self.rdi, 2),
            R8W => (&mut self.r8, 2),
            R9W => (&mut self.r9, 2),
            R10W => (&mut self.r10, 2),
            R11W => (&mut self.r11, 2),
            R12W => (&mut self.r12, 2),
            R13W => (&mut self.r13, 2),
            R14W => (&mut self.r14, 2),
            R15W => (&mut self.r15, 2),

            AL => (&mut self.rax, 1),
            CL => (&mut self.rcx, 1),
            DL => (&mut self.rdx, 1),
            BL => (&mut self.rbx, 1),
            SPL => (&mut self.rsp, 1),
            BPL => (&mut self.rbp, 1),
            SIL => (&mut self.rsi, 1),
            DIL => (&mut self.rdi, 1),
            R8L => (&mut self.r8, 1),
            R9L => (&mut self.r9, 1),
            R10L => (&mut self.r10, 1),
            R11L => (&mut self.r11, 1),
            R12L => (&mut self.r12, 1),
            R13L => (&mut self.r13, 1),
            R14L => (&mut self.r14, 1),
            R15L => (&mut self.r15, 1),

            AH => {
                self.rax = (self.rax & !0xFF00) | ((value & 0xFF) << 8);
                return;
            }
            CH => {
                self.rcx = (self.rcx & !0xFF00) | ((value & 0xFF) << 8);
                return;
            }
            DH => {
                self.rdx = (self.rdx & !0xFF00) | ((value & 0xFF) << 8);
                return;
            }
            BH => {
                self.rbx = (self.rbx & !0xFF00) | ((value & 0xFF) << 8);
                return;
            }

            _ => return,
        };

        match size {
            8 => *ptr = value,

            // 32-bit writes zero-extend upper 32 bits
            4 => *ptr = value & 0xFFFFFFFF,

            // 16-bit writes preserve upper bits
            2 => *ptr = (*ptr & !0xFFFF) | (value & 0xFFFF),

            // 8-bit writes preserve upper bits
            1 => *ptr = (*ptr & !0xFF) | (value & 0xFF),

            _ => unreachable!(),
        }
    }
}

impl Default for RegisterState {
    /// Creates a zeroed register state with the default `RFLAGS` value.
    ///
    /// Bit 1 of `RFLAGS` is architecturally reserved and must be `1` (`rflags = 2`).
    fn default() -> Self {
        Self {
            rax: 0,
            rbx: 0,
            rcx: 0,
            rdx: 0,
            rbp: 0,
            rsi: 0,
            rdi: 0,
            r8: 0,
            r9: 0,
            r10: 0,
            r11: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            rip: 0,
            rsp: 0,
            rflags: 2, // Bit 1 is strictly mandated to be 1 in x86 execution environments
            pad: 0,
        }
    }
}

/// Helper trait facilitating direct manipulation of sub-registers (bytes/words)
/// embedded within a `u64`.
pub trait X86RegisterOperations {
    /// Retrieves the lower 8 bits (`AL`/`CL`/etc.).
    fn low_u8(&self) -> u8;

    /// Sets the lower 8 bits (`AL`/`CL`/etc.), preserving higher bits.
    fn set_low_u8(&mut self, value: u8);

    /// Retrieves the high 8 bits of a 16-bit register (`AH`/`CH`/etc.).
    fn high_u8(&self) -> u8;

    /// Sets the high 8 bits of a 16-bit register (`AH`/`CH`/etc.), preserving the remaining bits.
    fn set_high_u8(&mut self, value: u8);

    /// Retrieves the lower 16 bits (`AX`/`CX`/etc.).
    fn low_u16(&self) -> u16;

    /// Sets the lower 16 bits (`AX`/`CX`/etc.), preserving higher bits.
    fn set_low_u16(&mut self, value: u16);

    /// Retrieves the lower 32 bits (`EAX`/`ECX`/etc.).
    fn low_u32(&self) -> u32;

    /// Sets the lower 32 bits (`EAX`/`ECX`/etc.) and zero-extends the upper 32 bits (x86_64 architecture rule).
    fn set_low_u32(&mut self, value: u32);
}

impl X86RegisterOperations for u64 {
    fn low_u8(&self) -> u8 {
        *self as u8
    }

    fn set_low_u8(&mut self, value: u8) {
        *self = (*self & !0xFF) | (value as u64);
    }

    fn high_u8(&self) -> u8 {
        (*self >> 8) as u8
    }

    fn set_high_u8(&mut self, value: u8) {
        *self = (*self & !0xFF00) | ((value as u64) << 8);
    }

    fn low_u16(&self) -> u16 {
        *self as u16
    }

    fn set_low_u16(&mut self, value: u16) {
        *self = (*self & !0xFFFF) | (value as u64);
    }

    fn low_u32(&self) -> u32 {
        *self as u32
    }

    fn set_low_u32(&mut self, value: u32) {
        // Casting u32 -> u64 automatically zero-extends bits 32..63 per x86_64 specs.
        *self = value as u64;
    }
}
