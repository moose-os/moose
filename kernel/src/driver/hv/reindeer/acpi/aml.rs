//! Lightweight ACPI Machine Language (AML) byte-code generator.
//!
//! Provides dynamic AML construct builders (scopes, devices, control methods)
//! and ACPI resource descriptors to dynamically construct tables like DSDT.

use alloc::vec::Vec;

/// AML Opcodes and Type Prefixes defined by the ACPI specification.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AmlOp {
    /// Represent integer value 0 without an explicit data prefix.
    ZeroOp = 0x00,

    /// Represents integer value 1 without an explicit data prefix.
    OneOp = 0x01,

    /// Defines a named object in the ACPI namespace (`NameOp`).
    NameOp = 0x08,

    /// Prefix for an 8-bit unsigned integer literal (`ByteData`).
    BytePrefix = 0x0A,

    /// Prefix for a 16-bit unsigned integer literal (`WordData`).
    WordPrefix = 0x0B,

    /// Prefix for a 32-bit unsigned integer literal (`DWordData`).
    DWordPrefix = 0x0C,

    /// Prefix for an ASCII null-terminated string literal.
    StringPrefix = 0x0D,

    /// Prefix for a 64-bit unsigned integer literal (`QWordData`).
    QWordPrefix = 0x0E,

    /// Opens or refers to an existing scope in the ACPI namespace (`ScopeOp`).
    ScopeOp = 0x10,

    /// Defines a raw byte buffer object (`BufferOp`).
    BufferOp = 0x11,

    /// Defines an evaluation package/array object (`PackageOp`).
    PackageOp = 0x12,

    /// Defines a control method with execution parameters (`MethodOp`).
    MethodOp = 0x14,

    /// Escape prefix for two-byte AML opcodes (`0x5B`).
    ExtOpPrefix = 0x5B,

    /// Defines a bus/hardware device in the namespace (`DeviceOp`, requires `ExtOpPrefix`).
    DeviceOp = 0x82,
}

/// A sequential stream builder for raw AML byte-code.
///
/// Keeps track of active block lengths (scopes, devices, methods) via an internal stack.
pub struct AmlBuilder {
    pub stream: Vec<u8>,
    scope_stack: Vec<usize>,
}

impl AmlBuilder {
    /// Creates a new builder initialized with default stream capacity.
    pub fn new() -> Self {
        Self {
            stream: Vec::with_capacity(512),
            scope_stack: Vec::new(),
        }
    }

    /// Emits a raw byte directly to the stream.
    pub fn emit_byte(&mut self, byte: u8) {
        self.stream.push(byte);
    }

    /// Emits a single-byte AML opcode.
    pub fn emit_op(&mut self, op: AmlOp) {
        self.stream.push(op as u8);
    }

    /// Emits a two-byte extended AML opcode (`0x5B` prefix).
    pub fn emit_ext_op(&mut self, op: AmlOp) {
        self.stream.push(AmlOp::ExtOpPrefix as u8);
        self.stream.push(op as u8);
    }

    /// Emits a standard 4-character ACPI SegName (padded with `_` if needed).
    pub fn emit_name(&mut self, name: &str) {
        let mut seg = [0x5F; 4]; // Padding '_'
        for (i, &b) in name.as_bytes().iter().take(4).enumerate() {
            seg[i] = b;
        }
        self.stream.extend_from_slice(&seg);
    }

    /// Marks the start of a variable-length AML PkgLength block.
    /// Pushes a 3-byte length placeholder onto the stream.
    pub fn begin_block(&mut self) {
        self.scope_stack.push(self.stream.len());
        self.stream.extend_from_slice(&[0x00, 0x00, 0x00]);
    }

    /// Resolves the PkgLength for the current block and updates its placeholder header.
    pub fn end_block(&mut self) {
        let start_pos = self.scope_stack.pop().expect("Stack underflow");
        let end_pos = self.stream.len();

        let pkg_len = (end_pos - start_pos) as u32;

        self.stream[start_pos] = 0x80 | (pkg_len as u8 & 0x0F);
        self.stream[start_pos + 1] = ((pkg_len >> 4) & 0xFF) as u8;
        self.stream[start_pos + 2] = ((pkg_len >> 12) & 0xFF) as u8;
    }

    /// Encodes an integer value using the most optimal AML prefix (Zero, One, Byte, Word, DWord, QWord).
    pub fn emit_integer(&mut self, val: u64) {
        match val {
            0 => self.emit_op(AmlOp::ZeroOp),
            1 => self.emit_op(AmlOp::OneOp),
            v if v <= 0xFF => {
                self.emit_op(AmlOp::BytePrefix);
                self.emit_byte(v as u8);
            }
            v if v <= 0xFFFF => {
                self.emit_op(AmlOp::WordPrefix);
                self.stream.extend_from_slice(&(v as u16).to_le_bytes());
            }
            v if v <= 0xFFFF_FFFF => {
                self.emit_op(AmlOp::DWordPrefix);
                self.stream.extend_from_slice(&(v as u32).to_le_bytes());
            }
            v => {
                self.emit_op(AmlOp::QWordPrefix);
                self.stream.extend_from_slice(&v.to_le_bytes());
            }
        }
    }

    /// Emits a null-terminated AML string.
    pub fn emit_string(&mut self, s: &str) {
        self.emit_op(AmlOp::StringPrefix);
        self.stream.extend_from_slice(s.as_bytes());
        self.emit_byte(0x00);
    }
}

/// Helper builder for constructing `ResourceTemplate` descriptor buffers.
pub struct AmlResourceBuilder {
    stream: Vec<u8>,
}

impl AmlResourceBuilder {
    /// Creates an empty resource builder.
    pub fn new() -> Self {
        Self { stream: Vec::new() }
    }

    /// Appends the required `EndTag` (with checksum byte) and returns the encoded buffer.
    pub fn finish(mut self) -> Vec<u8> {
        self.stream.push(0x79); // EndTag
        self.stream.push(0x00); // Checksum
        self.stream
    }

    /// Emits a Fixed I/O Port resource descriptor (Small item tag 0x4B).
    pub fn emit_fixed_io(&mut self, base: u16, len: u8) {
        self.stream.push(0x4B);
        self.stream.extend_from_slice(&base.to_le_bytes());
        self.stream.push(len);
    }

    /// Emits a standard IRQ mask resource descriptor (Small item tag 0x22).
    pub fn emit_irq(&mut self, irq: u8) {
        self.stream.push(0x22);
        let mask = 1u16 << irq;
        self.stream.extend_from_slice(&mask.to_le_bytes());
    }

    /// Emits an edge-triggered, active-high, exclusive IRQ descriptor (Small item tag 0x23).
    pub fn emit_irq_edge(&mut self, irq: u8) {
        self.stream.push(0x23);
        let mask = 1u16 << irq;
        self.stream.extend_from_slice(&mask.to_le_bytes());
        self.stream.push(0x10); // Edge-triggered, active-high, exclusive
    }

    /// Emits a 32-bit Fixed Memory range descriptor (Large item tag 0x86).
    pub fn emit_mem32_fixed(&mut self, base: u32, len: u32, rw: bool) {
        self.stream.push(0x86);
        self.stream.extend_from_slice(&9u16.to_le_bytes());
        self.stream.push(if rw { 0x01 } else { 0x00 });
        self.stream.extend_from_slice(&base.to_le_bytes());
        self.stream.extend_from_slice(&len.to_le_bytes());
    }

    /// Emits a 64-bit Memory range resource descriptor (Large item tag 0x8A).
    pub fn emit_qword_memory(&mut self, min: u64, max: u64, len: u64, rw: bool) {
        self.stream.push(0x8A);
        self.stream.extend_from_slice(&43u16.to_le_bytes());
        self.stream.push(0x00); // Resource Type: Memory
        self.stream.push(0x0D); // Flags: Consumer, MinFixed, MaxFixed
        self.stream.push(if rw { 0x01 } else { 0x00 });
        self.stream.extend_from_slice(&0u64.to_le_bytes()); // Granularity
        self.stream.extend_from_slice(&min.to_le_bytes());
        self.stream.extend_from_slice(&max.to_le_bytes());
        self.stream.extend_from_slice(&0u64.to_le_bytes()); // Translation
        self.stream.extend_from_slice(&len.to_le_bytes());
    }
}

/// Trait implemented by types that can serialize themselves into an AML stream.
pub trait AmlEmit {
    fn emit_to(&self, b: &mut AmlBuilder);
}

impl AmlEmit for u8 {
    fn emit_to(&self, b: &mut AmlBuilder) {
        b.emit_integer(*self as u64);
    }
}

impl AmlEmit for u32 {
    fn emit_to(&self, b: &mut AmlBuilder) {
        b.emit_integer(*self as u64);
    }
}

impl AmlEmit for u64 {
    fn emit_to(&self, b: &mut AmlBuilder) {
        b.emit_integer(*self);
    }
}

impl AmlEmit for &str {
    fn emit_to(&self, b: &mut AmlBuilder) {
        b.emit_string(self);
    }
}

impl AmlEmit for i32 {
    fn emit_to(&self, b: &mut AmlBuilder) {
        b.emit_integer(*self as u64);
    }
}

impl AmlEmit for usize {
    fn emit_to(&self, b: &mut AmlBuilder) {
        b.emit_integer(*self as u64);
    }
}

/// Declarative macro for constructing AML byte-code payloads.
#[macro_export]
macro_rules! aml {
    (@ROOT $($tt:tt)*) => {{
        let mut b = $crate::driver::hv::reindeer::acpi::aml::AmlBuilder::new();
        $crate::aml!(@RECURSE b, $($tt)*);
        b.stream
    }};

    (@RECURSE $b:ident, Scope ($name:expr) { $($body:tt)* } $($rest:tt)*) => {
        $b.emit_op($crate::driver::hv::reindeer::acpi::aml::AmlOp::ScopeOp); $b.begin_block(); $b.emit_name($name);
        $crate::aml!(@RECURSE $b, $($body)*); $b.end_block(); $crate::aml!(@RECURSE $b, $($rest)*);
    };

    (@RECURSE $b:ident, Device ($name:expr) { $($body:tt)* } $($rest:tt)*) => {
        $b.emit_ext_op($crate::driver::hv::reindeer::acpi::aml::AmlOp::DeviceOp); $b.begin_block(); $b.emit_name($name);
        $crate::aml!(@RECURSE $b, $($body)*); $b.end_block(); $crate::aml!(@RECURSE $b, $($rest)*);
    };

    (@RECURSE $b:ident, Name ($name:expr, ResourceTemplate() { $($res:tt)* }) $($rest:tt)*) => {
        $b.emit_op($crate::driver::hv::reindeer::acpi::aml::AmlOp::NameOp); $b.emit_name($name);
        $b.emit_op($crate::driver::hv::reindeer::acpi::aml::AmlOp::BufferOp); $b.begin_block();
        let mut rb = $crate::driver::hv::reindeer::acpi::aml::AmlResourceBuilder::new();
        $crate::aml!(@RESOURCE rb, $($res)*);
        let res_data = rb.finish();
        $b.emit_integer(res_data.len() as u64);
        $b.stream.extend_from_slice(res_data.as_slice());
        $b.end_block(); $crate::aml!(@RECURSE $b, $($rest)*);
    };

    (@RECURSE $b:ident, Name ($name:expr, $val:expr) $($rest:tt)*) => {
        $b.emit_op($crate::driver::hv::reindeer::acpi::aml::AmlOp::NameOp); $b.emit_name($name);
        $crate::driver::hv::reindeer::acpi::aml::AmlEmit::emit_to(&$val, &mut $b); $crate::aml!(@RECURSE $b, $($rest)*);
    };

    (@RECURSE $b:ident, PciRoutingTable { $([$a:expr, $p:expr, $s:expr, $i:expr]),* } $($rest:tt)*) => {
        $b.emit_op($crate::driver::hv::reindeer::acpi::aml::AmlOp::NameOp); $b.emit_name("_PRT");
        $b.emit_op($crate::driver::hv::reindeer::acpi::aml::AmlOp::PackageOp); $b.begin_block();
        let mut count = 0; $( { let _ = $a; count += 1; } )*
        $b.emit_byte(count as u8);
        $(
            $b.emit_op($crate::driver::hv::reindeer::acpi::aml::AmlOp::PackageOp); $b.begin_block(); $b.emit_byte(4);
            $crate::driver::hv::reindeer::acpi::aml::AmlEmit::emit_to(&$a, &mut $b); $crate::driver::hv::reindeer::acpi::aml::AmlEmit::emit_to(&$p, &mut $b);
            $crate::driver::hv::reindeer::acpi::aml::AmlEmit::emit_to(&$s, &mut $b); $crate::driver::hv::reindeer::acpi::aml::AmlEmit::emit_to(&$i, &mut $b);
            $b.end_block();
        )*
        $b.end_block(); $crate::aml!(@RECURSE $b, $($rest)*);
    };

    (@RECURSE $b:ident, Method ($name:expr, $args:expr) { $($body:tt)* } $($rest:tt)*) => {
        $b.emit_op($crate::driver::hv::reindeer::acpi::aml::AmlOp::MethodOp); $b.begin_block(); $b.emit_name($name);
        $b.emit_byte($args as u8); $crate::aml!(@RECURSE $b, $($body)*); $b.end_block();
        $crate::aml!(@RECURSE $b, $($rest)*);
    };

    (@RECURSE $b:ident, Return ($val:expr) $($rest:tt)*) => {
        $b.emit_byte(0xA4); $crate::driver::hv::reindeer::acpi::aml::AmlEmit::emit_to(&$val, &mut $b); $crate::aml!(@RECURSE $b, $($rest)*);
    };

    (@RECURSE $b:ident, ) => {};

    (@RESOURCE $rb:ident, FixedIO ($base:expr, $len:expr) $($rest:tt)*) => {
        $rb.emit_fixed_io($base, $len); $crate::aml!(@RESOURCE $rb, $($rest)*);
    };

    (@RESOURCE $rb:ident, IRQ ($irq:expr) $($rest:tt)*) => {
        $rb.emit_irq($irq); $crate::aml!(@RESOURCE $rb, $($rest)*);
    };

    (@RESOURCE $rb:ident, IRQEdge ($irq:expr) $($rest:tt)*) => {
        $rb.emit_irq_edge($irq); $crate::aml!(@RESOURCE $rb, $($rest)*);
    };

    (@RESOURCE $rb:ident, Memory64 ($rw:expr, $min:expr, $max:expr, $len:expr) $($rest:tt)*) => {
        $rb.emit_qword_memory($min, $max, $len, $rw); $crate::aml!(@RESOURCE $rb, $($rest)*);
    };

    (@RESOURCE $rb:ident, ) => {};
}
