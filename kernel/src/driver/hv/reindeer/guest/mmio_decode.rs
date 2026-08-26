//! Guest memory operand decoding for Second-Level Address Translation (SLAT) violations.
//!
//! When the guest attempts to access unmapped MMIO (memory-mapped I/O)
//! memory regions, a SLAT violation occurs.
//!
//! This module utilizes [`iced_x86`] to disassemble and inspect the faulting guest
//! instruction. It extracts critical execution context—such as register indices, operand
//! sizes, immediate values, and instruction length—required to emulate the access.

use iced_x86::{Instruction, MemorySize, OpKind, Register};

use crate::driver::hv::reindeer::guest::registers::RegisterState;

/// Maps an `iced_x86` [`Register`] to its corresponding general-purpose register (GPR) index
/// and operand width in bytes.
///
/// # Returns
///
/// A tuple containing:
/// 1. `u8`: The 0-based index of the base register in [`RegisterState`] (e.g., `RAX`/`EAX`/`AX`/`AL` -> `0`).
/// 2. `u64`: The width of the register operand in bytes (1, 2, 4, or 8).
pub fn reg_info(reg: Register) -> (u8, u64) {
    use Register::*;

    match reg {
        // 64-bit general-purpose registers.
        RAX => (0, 8),
        RCX => (1, 8),
        RDX => (2, 8),
        RBX => (3, 8),
        RSP => (4, 8),
        RBP => (5, 8),
        RSI => (6, 8),
        RDI => (7, 8),
        R8 => (8, 8),
        R9 => (9, 8),
        R10 => (10, 8),
        R11 => (11, 8),
        R12 => (12, 8),
        R13 => (13, 8),
        R14 => (14, 8),
        R15 => (15, 8),

        // 32-bit sub-registers.
        EAX => (0, 4),
        ECX => (1, 4),
        EDX => (2, 4),
        EBX => (3, 4),
        ESP => (4, 4),
        EBP => (5, 4),
        ESI => (6, 4),
        EDI => (7, 4),
        R8D => (8, 4),
        R9D => (9, 4),
        R10D => (10, 4),
        R11D => (11, 4),
        R12D => (12, 4),
        R13D => (13, 4),
        R14D => (14, 4),
        R15D => (15, 4),

        // 16-bit sub-registers.
        AX => (0, 2),
        CX => (1, 2),
        DX => (2, 2),
        BX => (3, 2),
        SP => (4, 2),
        BP => (5, 2),
        SI => (6, 2),
        DI => (7, 2),
        R8W => (8, 2),
        R9W => (9, 2),
        R10W => (10, 2),
        R11W => (11, 2),
        R12W => (12, 2),
        R13W => (13, 2),
        R14W => (14, 2),
        R15W => (15, 2),

        // 8-bit sub-registers (low and high bytes).
        AL => (0, 1),
        CL => (1, 1),
        DL => (2, 1),
        BL => (3, 1),
        AH => (0, 1),
        CH => (1, 1),
        DH => (2, 1),
        BH => (3, 1),
        SPL => (4, 1),
        BPL => (5, 1),
        SIL => (6, 1),
        DIL => (7, 1),
        R8L => (8, 1),
        R9L => (9, 1),
        R10L => (10, 1),
        R11L => (11, 1),
        R12L => (12, 1),
        R13L => (13, 1),
        R14L => (14, 1),
        R15L => (15, 1),

        // Fallback for non-GPR or unsupported registers.
        _ => (0xFF, 0),
    }
}

/// Determines the byte length of an integer memory access operand.
pub fn memory_access_length(mem_size: MemorySize) -> u64 {
    match mem_size {
        MemorySize::UInt8 | MemorySize::Int8 => 1,
        MemorySize::UInt16 | MemorySize::Int16 => 2,
        MemorySize::UInt32 | MemorySize::Int32 => 4,
        MemorySize::UInt64 | MemorySize::Int64 => 8,
        _ => unreachable!(),
    }
}

/// Contains decoded metadata for a faulting MMIO instruction.
///
/// This structure encapsulates all parameters necessary for the hypervisor to execute
/// or emulate a guest memory read or write operation resulting from a SLAT fault.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodedMmioAccess {
    /// The size of the memory operand in bytes.
    pub access_length: u64,

    /// The payload value associated with the memory write access.
    ///
    /// * For write operations, this contains the value being written (extracted either from
    ///   a guest register or an immediate value).
    /// * For read operations, this is set to [`None`].
    pub data: Option<u64>,

    /// The primary register involved in the memory access, if applicable.
    ///
    /// * For read operations, this is the target register (`op0`) where the MMIO read result
    ///   should be stored.
    /// * For write operations, this is the source register (`op1`) containing the data to write,
    ///   or [`None`] if the write source was an immediate value.
    pub register: Option<Register>,

    /// The length of the faulting instruction in bytes.
    pub instruction_length: usize,
}

/// Decodes a faulting guest instruction to determine MMIO read/write details.
///
/// Inspects the provided `iced_x86` [`Instruction`] alongside guest CPU state to determine
/// operand sizes, source/target registers, and immediate data values.
pub fn decode_mmio_access(
    instruction: &Instruction,
    is_read: bool,
    is_write: bool,
    gpr: &RegisterState,
) -> DecodedMmioAccess {
    let mut data: Option<u64> = None;
    let mut target_reg: Option<Register> = None;

    let access_length = memory_access_length(instruction.memory_size());

    if is_read {
        // Memory read: destination is op0.
        if instruction.op0_kind() == OpKind::Register {
            target_reg = Some(instruction.op0_register());
        } else {
            unreachable!()
        }
    } else if is_write {
        // Memory write with register source: op1.
        if instruction.op1_kind() == OpKind::Register {
            let reg = instruction.op1_register();
            target_reg = Some(reg);
            let (idx, _) = reg_info(reg);
            data = Some(gpr.get(idx, reg));
        } else {
            // Memory write with an immediate source value.
            data = match instruction.op1_kind() {
                OpKind::Immediate8 => Some(instruction.immediate8() as u64),
                OpKind::Immediate16 => Some(instruction.immediate16() as u64),
                OpKind::Immediate32 => Some(instruction.immediate32() as u64),
                OpKind::Immediate64 => Some(instruction.immediate64()),
                _ => unreachable!(),
            };
        }
    }

    DecodedMmioAccess {
        access_length,
        data,
        register: target_reg,
        instruction_length: instruction.len(),
    }
}
