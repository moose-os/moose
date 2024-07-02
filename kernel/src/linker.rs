use crate::memory::{MemoryManager, Page, PageFlags, PageTable, VirtualAddress, PAGE_SIZE};

use common::{Cursor, Read, Seek};
use core::{cmp::min, slice};
use goblin::elf::{
    program_header::{self, PF_R, PF_W, PF_X},
    Elf,
};
use snafu::Snafu;

pub struct Linker;

impl Linker {
    pub fn link(
        binary: &[u8],
        memory_manager: &mut MemoryManager,
        page_table: &mut PageTable,
    ) -> Result<u64, LinkageError> {
        let elf = Elf::parse(binary).map_err(|_| LinkageError::InvalidBinary)?;

        if !elf.is_64 {
            return Err(LinkageError::InvalidArchitecture);
        }

        if elf.is_lib {
            return Err(LinkageError::NotAnExecutable);
        }

        if !elf.little_endian {
            return Err(LinkageError::InvalidEndianness);
        }

        if !elf.libraries.is_empty() {
            unimplemented!();
        }

        if !elf.shdr_relocs.is_empty() {
            unimplemented!();
        }

        if !elf.pltrelocs.is_empty() {
            unimplemented!();
        }

        if !elf.dynrels.is_empty() {
            unimplemented!();
        }

        if !elf.dynrelas.is_empty() {
            unimplemented!();
        }

        if !elf.dynsyms.is_empty() {
            unimplemented!();
        }

        let mut reader = Cursor::new(binary);
        let mut buffer = [0u8; PAGE_SIZE];

        for header in elf.program_headers {
            if header.p_type != program_header::PT_LOAD {
                continue;
            }

            if header.p_flags & PF_R == 0 {
                unimplemented!();
            }

            if header.p_align != PAGE_SIZE as u64 {
                unimplemented!();
            }

            let required_frames = (header.p_filesz + (PAGE_SIZE as u64 - 1)) as usize / PAGE_SIZE; // Rounds up to the next PAGE_SIZE

            // FIXME: This shouldn't panic
            reader.seek(header.p_offset).unwrap();

            let mut remaining_size = header.p_filesz as usize;

            for frame_idx in 0..required_frames {
                let size = min(remaining_size, PAGE_SIZE);

                let bytes_read = reader.read(&mut buffer[..size]).unwrap();

                assert_eq!(bytes_read, size);

                remaining_size -= bytes_read;

                let page = Page::new(VirtualAddress::new(
                    (header.p_vaddr + (frame_idx * PAGE_SIZE) as u64) & 0xfff_ffff_ffff_f000,
                ));
                // FIXME: This shouldn't panic
                let frame = memory_manager.allocate_frame().unwrap();

                let offset = header.p_vaddr
                    - ((header.p_vaddr + (frame_idx * PAGE_SIZE) as u64) & 0xfff_ffff_ffff_f000);

                unsafe {
                    // FIXME: This shouldn't panic
                    memory_manager
                        .map_any_temporary_for_current_address_space(
                            &frame,
                            PageFlags::WRITABLE,
                            |page| {
                                let destination = page.address().as_mut_ptr::<u8>();

                                slice::from_raw_parts_mut(
                                    destination.add(offset as usize),
                                    bytes_read,
                                )
                                .copy_from_slice(&buffer[..bytes_read]);
                            },
                        )
                        .unwrap();

                    let mut flags = PageFlags::USER_MODE_ACCESSIBLE;

                    if header.p_flags & PF_W != 0 {
                        flags |= PageFlags::WRITABLE;
                    }

                    if header.p_flags & PF_X != 0 {
                        flags |= PageFlags::EXECUTABLE;
                    }

                    // FIXME: This shouldn't panic
                    memory_manager
                        .map(page_table, &page, &frame, flags)
                        .unwrap();
                }
            }
        }

        Ok(elf.entry)
    }
}

#[derive(Debug, Snafu)]
pub enum LinkageError {
    #[snafu(display("Invalid binary"))]
    InvalidBinary,
    #[snafu(display("Not an executable"))]
    NotAnExecutable,
    #[snafu(display("Invalid architecture"))]
    InvalidArchitecture,
    #[snafu(display("Invalid endianness"))]
    InvalidEndianness,
}
