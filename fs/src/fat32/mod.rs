extern crate alloc;

pub mod fat;
pub mod lfn;

mod directory;
mod file;

use crate::{Attributes, FileSystemError, fat32::lfn::LongFileName};

use bitfield_struct::bitfield;
use bitflags::bitflags;
use bitvec::prelude::*;
use bytemuck::{Pod, Zeroable, cast};
use chrono::{Datelike, NaiveDateTime, Timelike};
use core::{
    clone::Clone,
    cmp::PartialEq,
    convert::From,
    default::Default,
    iter::Iterator,
    marker::Sized,
    result::Result::{self, Ok},
};
use deku::{DekuContainerWrite, DekuError, DekuRead, DekuUpdate, DekuWrite};

#[cfg(feature = "no_std")]
use alloc::{
    rc::Rc,
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
    {format, vec},
};
#[cfg(feature = "no_std")]
use spin::Mutex;

/// Defines FAT sector size in bytes. It's independent of underlying storage medium sector size.
pub const FAT_SECTOR_SIZE: usize = 512;
/// Defines FAT's sector type. It's independent of underlying storage medium sector.
pub type Sector = [u8; FAT_SECTOR_SIZE];

/// The `FatDataSource` trait defines an interface for reading and writing sectors in a FAT filesystem.
/// This trait includes methods for reading sectors into a buffer, reading sectors into a vector, and writing a sector from a buffer.
pub trait FatDataSource {
    /// Reads `n` sectors starting from the specified `starting_sector` and returns them as a `Vec<Sector>`.
    fn read_sectors(
        &mut self,
        starting_sector: u32,
        n: u32,
    ) -> Result<Vec<Sector>, FileSystemError> {
        let mut sectors = vec![[0u8; FAT_SECTOR_SIZE]; n as usize];

        self.read_sectors_to(starting_sector, &mut sectors)?;

        Ok(sectors)
    }

    /// Reads sectors starting from the specified `starting_sector` into the provided `buffer`.
    fn read_sectors_to(
        &mut self,
        starting_sector: u32,
        buffer: &mut [Sector],
    ) -> Result<(), FileSystemError>;

    /// Writes data from the provided `buffer` to the specified `sector`.
    fn write_sector(&mut self, sector: u32, buffer: &[u8]) -> Result<(), FileSystemError>;
}

/// A trait for retrieving the current date and time.
pub trait FatTimeSource {
    /// The `now` function provides a way to get the current date and time
    /// from the underlying time source. The returned `NaiveDateTime` does not
    /// contain any timezone information.
    ///
    /// # Returns
    ///
    /// * `NaiveDateTime` - The current date and time.
    fn now(&self) -> NaiveDateTime;
}

// BPB definition
#[allow(dead_code)]
#[derive(DekuRead, Debug)]
pub(crate) struct BiosParameterBlock {
    jmp_boot: [u8; 3],
    #[deku(
        map = "|value: [u8; 8]| -> Result<_, DekuError> { Ok(String::from_utf8_lossy(&value[..]).into_owned()) }"
    )]
    oem_name: String,
    bytes_per_sector: u16,
    sectors_per_cluster: u8,
    reserved_sector_count: u16,
    number_of_fats: u8,
    // see Table `Boot Sector and BPB Structure` at `documents/FAT32 Specification.pdf`, p. 9
    #[deku(assert = "*root_entries_count == 0")]
    root_entries_count: u16,
    // see Table `Boot Sector and BPB Structure` at `documents/FAT32 Specification.pdf`, p. 9
    #[deku(assert = "*total_count_of_sectors == 0")]
    total_count_of_sectors: u16,
    #[deku(assert = "[0xF0, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF].contains(media_type)")]
    media_type: u8,
    // see Table `Boot Sector and BPB Structure` at `documents/FAT32 Specification.pdf`, p. 9
    #[deku(assert = "*sectors_per_fat == 0")]
    sectors_per_fat: u16,
    sectors_per_track: u16,
    number_of_heads: u16,
    hidden_sectors_count: u32,
    total_count_of_sectors_32: u32,
    sectors_per_fat_32: u32,
    ext_flags: u16,
    filesystem_version: u16,
    root_directory_first_cluster: u32,
    fs_info_sector: u16,
    boot_sector_copy_sector_number: u16,
    #[deku(pad_bytes_before = "12")]
    drive_number: u8,
    // see Table `Boot Sector and BPB Structure` at `documents/FAT32 Specification.pdf`, p. 9
    #[deku(assert = "*boot_signature == 0x29", pad_bytes_before = "1")]
    boot_signature: u8,
    volume_id: u32,
    #[deku(
        map = "|value: [u8; 11]| -> Result<_, DekuError> { Ok(String::from_utf8_lossy(&value[..]).into_owned()) }"
    )]
    volume_label: String,
    #[deku(
        map = "|value: [u8; 8]| -> Result<_, DekuError> { Ok(String::from_utf8_lossy(&value[..]).into_owned()) }"
    )]
    filesystem_type: String,
    // see Table `Boot Sector and BPB Structure` at `documents/FAT32 Specification.pdf`, p. 9
    #[deku(assert = "*signature == [0x55, 0xAA]", pad_bytes_before = "420")]
    signature: [u8; 2],
}

#[derive(Debug)]
enum FatEntry {
    FileEntry(RawFatFileEntry),
    LongFileNameEntry(LongFileNameFatEntry),
}

#[derive(DekuRead, Debug)]
pub(crate) struct FileListing {
    #[deku(reader = "FileListing::read_files(deku::rest)")]
    files: Vec<FatEntry>,
}

impl FileListing {
    fn read_files(
        rest: &BitSlice<u8, Msb0>,
    ) -> Result<(&BitSlice<u8, Msb0>, Vec<FatEntry>), DekuError> {
        let mut buffer: Vec<FatEntry> =
            Vec::with_capacity((rest.len() / 8) / size_of::<RawFatFileEntry>());
        let mut remaining_slice = rest;

        loop {
            let mut processed_slice = remaining_slice;

            // We need to read the attributes and, based on them, decide whether it is SFN or LFN file entry.
            // The attributes are right after the filename, so we have to skip it
            for _ in 0..11 {
                (processed_slice, _) = u8::read(processed_slice, ())?;
            }

            // Read attributes
            let (_, attr) = FatFileAttributes::read(processed_slice, ())?;

            // Decide if we need to parse LFN entry or classical SFN
            if attr.is_long_name_entry() {
                let entry;

                (remaining_slice, entry) = LongFileNameFatEntry::read(remaining_slice, ())?;
                buffer.push(FatEntry::LongFileNameEntry(entry));
            } else {
                let entry;

                (remaining_slice, entry) = RawFatFileEntry::read(remaining_slice, ())?;
                buffer.push(FatEntry::FileEntry(entry));
            }

            if remaining_slice.is_empty() {
                break;
            }
        }

        Ok((remaining_slice, buffer))
    }
}

#[derive(DekuRead, DekuWrite, Debug)]
pub(crate) struct RawFileListing {
    #[deku(
        reader = "RawFileListing::read_files_raw(deku::rest)",
        writer = "RawFileListing::write_files_raw(&self.files, deku::output)"
    )]
    files: Vec<RawFatFileEntry>,
}

impl RawFileListing {
    fn read_files_raw(
        rest: &BitSlice<u8, Msb0>,
    ) -> Result<(&BitSlice<u8, Msb0>, Vec<RawFatFileEntry>), DekuError> {
        let buffer_size = (rest.len() / 8) / size_of::<RawFatFileEntry>();
        let mut buffer: Vec<RawFatFileEntry> = Vec::with_capacity(buffer_size);
        let mut remaining_slice = rest;

        loop {
            let entry: RawFatFileEntry;

            (remaining_slice, entry) = RawFatFileEntry::read(remaining_slice, ())?;
            buffer.push(entry);

            if remaining_slice.is_empty() {
                break;
            }
        }

        Ok((remaining_slice, buffer))
    }

    fn write_files_raw(
        files: &[RawFatFileEntry],
        output: &mut BitVec<u8, Msb0>,
    ) -> Result<(), DekuError> {
        assert!(files.len() <= 16);

        for file in files {
            file.write(output, ())?;
        }

        Ok(())
    }
}

#[derive(Copy, Clone, DekuRead, Debug, Pod, Zeroable)]
#[repr(C, packed)]
// Same role as `RawFatFileEntry` but another format
pub(crate) struct LongFileNameFatEntry {
    sequence_number: u8,
    name1: [u16; 5],
    attr: u8,
    reserved: u8,
    checksum: u8,
    name2: [u16; 6],
    first_cluster_low: u16,
    name3: [u16; 2],
}

#[derive(DekuRead, Debug, Default, Clone, Copy, Zeroable, Pod)]
#[repr(C)]
// On-disk file entry structure
pub(crate) struct RawFatFileEntry {
    name: [u8; 11],
    attr: u8,
    nt_res: u8, // actually it's NT reserved field, but specification mentions it as `nt_res`. For more info see Table `Fat32 Byte Directory Entry Structure` at `documents/FAT32 Specification.pdf`, p. 23
    creation_time_milliseconds: u8,
    creation_time: u16,
    creation_date: u16,
    last_access_date: u16,
    first_cluster_high: u16,
    last_write_time: u16,
    last_write_date: u16,
    first_cluster_low: u16,
    file_size: u32,
}

impl DekuWrite for RawFatFileEntry {
    fn write(&self, output: &mut BitVec<u8, Msb0>, _ctx: ()) -> Result<(), DekuError> {
        for byte in self.name {
            byte.write(output, ())?;
        }

        self.attr.write(output, ())?;
        self.nt_res.write(output, ())?;
        self.creation_time_milliseconds.write(output, ())?;
        self.creation_time.write(output, ())?;
        self.creation_date.write(output, ())?;
        self.last_access_date.write(output, ())?;
        self.first_cluster_high.write(output, ())?;
        self.last_write_time.write(output, ())?;
        self.last_write_date.write(output, ())?;
        self.first_cluster_low.write(output, ())?;
        self.file_size.write(output, ())?;

        Ok(())
    }
}

// High level representation of FAT file, which consists of multiple raw, on-disk fat file entries
#[derive(Debug, Clone, Default)]
pub struct FatFileEntry {
    name: String,
    attr: FatFileAttributes,
    creation_date_time: NaiveDateTime,
    last_access_date_time: NaiveDateTime,
    last_write_date_time: NaiveDateTime,
    file_size: u32,
    raw: Vec<RawFatFileEntry>,
}

impl FatFileEntry {
    pub fn set_name(&mut self, name: String) {
        self.name = name;

        // Remove all LFN entries
        self.raw.resize(1, RawFatFileEntry::default());

        // If name fits in 11 bytes, we don't need to allocate any LFN entries, so fill SFN data and
        // return
        if self.name.len() <= 11 {
            for i in 0..self.name.len() {
                self.raw[0].name[i] = self.name.as_bytes()[i];
            }

            // Names need to be padded to 11 characters with spaces
            for i in self.name.len()..11 {
                self.raw[0].name[i] = b' ';
            }

            return;
        }

        let binding = LongFileName::padded_sfn(&self.name);
        let bytes = binding.as_bytes();

        self.raw[0].name = bytes[0..11].to_vec().try_into().unwrap();

        let lfn_checksum = self.compute_lfn_checksum(&self.raw[0].name);
        let lfn_name_length = ucs2::str_num_ucs2_chars(&self.name).unwrap();
        let lfn_name_buffer_length = (lfn_name_length / 13) * 13 + 13;
        let mut lfn_buffer: Vec<u16> = vec![0u16; lfn_name_buffer_length];
        ucs2::encode(self.name.as_str(), lfn_buffer.as_mut_slice()).unwrap();

        lfn_buffer
            .chunks(13)
            .rev()
            .enumerate()
            .for_each(|(index, ucs2_part)| {
                let lfn = LongFileNameFatEntry {
                    sequence_number: (index + 1) as u8,
                    name1: ucs2_part[0..5].try_into().unwrap(),
                    // LFN entry attributes
                    attr: (FatFileAttributes::READ_ONLY
                        | FatFileAttributes::HIDDEN
                        | FatFileAttributes::SYSTEM
                        | FatFileAttributes::VOLUME_ID)
                        .bits(),
                    reserved: 0,
                    checksum: lfn_checksum,
                    name2: ucs2_part[5..11].try_into().unwrap(),
                    first_cluster_low: 0,
                    name3: ucs2_part[11..=12].try_into().unwrap(),
                };

                // It's safe cast because SFN has the same layout as LFN
                let lfn_as_sfn: RawFatFileEntry = cast(lfn);

                self.raw.push(lfn_as_sfn);
            });
    }

    pub fn set_attr(&mut self, attr: FatFileAttributes) {
        self.attr = attr;

        self.raw[0].attr = attr.bits();
    }

    pub fn set_creation_date_time(&mut self, creation_date_time: NaiveDateTime) {
        self.creation_date_time = creation_date_time;

        let (date, time) = Self::create_fields_from_date_time(&self.creation_date_time);
        self.raw[0].creation_date = date.into_bits();
        self.raw[0].creation_time = time.into_bits();
    }

    pub fn set_last_access_date_time(&mut self, last_access_date_time: NaiveDateTime) {
        self.last_access_date_time = last_access_date_time;

        let (date, _) = Self::create_fields_from_date_time(&self.last_access_date_time);
        self.raw[0].last_access_date = date.into_bits();
        // There's no last_access_time sadly
    }

    pub fn set_last_write_date_time(&mut self, last_write_date_time: NaiveDateTime) {
        self.last_write_date_time = last_write_date_time;

        let (date, time) = Self::create_fields_from_date_time(&self.last_write_date_time);
        self.raw[0].last_write_date = date.into_bits();
        self.raw[0].last_write_time = time.into_bits();
    }

    pub fn set_file_size(&mut self, file_size: u32) {
        self.file_size = file_size;

        self.raw[0].file_size = file_size;
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn attr(&self) -> FatFileAttributes {
        self.attr
    }

    pub fn creation_date_time(&self) -> NaiveDateTime {
        self.creation_date_time
    }

    pub fn last_access_date_time(&self) -> NaiveDateTime {
        self.last_access_date_time
    }

    pub fn last_write_date_time(&self) -> NaiveDateTime {
        self.last_write_date_time
    }

    pub fn file_size(&self) -> u32 {
        self.file_size
    }

    pub(crate) fn sfn(&self) -> &RawFatFileEntry {
        self.raw.first().unwrap()
    }

    fn create_date_time_from_fields(date: FatDateFormat, time: FatTimeFormat) -> NaiveDateTime {
        // For the FAT's format of encoding datetime, see
        // `Date and Time Formats` at `documents/FAT32 Specification.pdf`, p. 25

        NaiveDateTime::default()
            .with_year(1980 + date.year() as i32)
            .unwrap()
            .with_month(date.month() as u32)
            .unwrap()
            .with_day(date.day() as u32)
            .unwrap()
            .with_hour(time.hours() as u32)
            .unwrap()
            .with_minute(time.minutes() as u32)
            .unwrap()
            .with_second(time.seconds() as u32)
            .unwrap()
    }

    fn create_fields_from_date_time(date_time: &NaiveDateTime) -> (FatDateFormat, FatTimeFormat) {
        // For the FAT's format of encoding datetime, see
        // `Date and Time Formats` at `documents/FAT32 Specification.pdf`, p. 25

        let fat_date = FatDateFormat::default()
            .with_day(date_time.day() as u8)
            .with_month(date_time.month() as u8)
            .with_year((date_time.year() - 1980) as u8);

        let fat_time = FatTimeFormat::default()
            .with_hours(date_time.hour() as u8)
            .with_minutes(date_time.minute() as u8)
            .with_seconds((date_time.second() / 2) as u8);

        (fat_date, fat_time)
    }

    fn compute_lfn_checksum(&self, name: &[u8; 11]) -> u8 {
        let mut lfn_checksum: u8 = 0;

        for i in (0..=10).rev() {
            let checksum_copy = lfn_checksum;

            if (checksum_copy & 1) == 1 {
                lfn_checksum = 0x80;
            } else {
                lfn_checksum = 0;
            }

            lfn_checksum = lfn_checksum.wrapping_add((checksum_copy >> 1) + name[10 - i]);
        }

        lfn_checksum
    }
}

impl From<RawFatFileEntry> for FatFileEntry {
    fn from(value: RawFatFileEntry) -> Self {
        let creation_date_time = {
            let date = FatDateFormat::from_bits(value.creation_date);
            let time = FatTimeFormat::from_bits(value.creation_time);

            Self::create_date_time_from_fields(date, time)
        };

        let last_access_date_time = {
            let date = FatDateFormat::from_bits(value.last_access_date);
            let time = FatTimeFormat::from_bits(value.last_write_time);

            Self::create_date_time_from_fields(date, time)
        };

        let last_write_date_time = {
            let date = FatDateFormat::from_bits(value.last_write_date);
            let time = FatTimeFormat::from_bits(value.last_write_time);

            Self::create_date_time_from_fields(date, time)
        };

        FatFileEntry {
            name: String::from_utf8_lossy(&value.name[..]).trim().to_string(),
            attr: FatFileAttributes::from_bits(value.attr).unwrap(),
            creation_date_time,
            last_access_date_time,
            last_write_date_time,
            file_size: value.file_size,
            raw: vec![value],
        }
    }
}

bitflags! {
    #[derive(Copy, Clone, Debug, Default)]
    pub struct FatFileAttributes: u8 {
        const READ_ONLY = 1;
        const HIDDEN = 1 << 1;
        const SYSTEM = 1 << 2;
        const VOLUME_ID = 1 << 3;
        const DIRECTORY = 1 << 4;
        const ARCHIVE = 1 << 5;
    }
}

impl FatFileAttributes {
    pub fn is_long_name_entry(&self) -> bool {
        self.contains(FatFileAttributes::READ_ONLY)
            && self.contains(FatFileAttributes::HIDDEN)
            && self.contains(FatFileAttributes::SYSTEM)
            && self.contains(FatFileAttributes::VOLUME_ID)
    }

    pub fn is_directory(&self) -> bool {
        self.contains(FatFileAttributes::DIRECTORY)
    }
}

impl From<Attributes> for FatFileAttributes {
    fn from(value: Attributes) -> Self {
        let mut fat_attributes = FatFileAttributes::default();

        if value.contains(Attributes::ARCHIVE) {
            fat_attributes |= FatFileAttributes::ARCHIVE;
        }

        if value.contains(Attributes::HIDDEN) {
            fat_attributes |= FatFileAttributes::HIDDEN;
        }

        if value.contains(Attributes::READ_ONLY) {
            fat_attributes |= FatFileAttributes::READ_ONLY;
        }

        if value.contains(Attributes::SYSTEM_FILE) {
            fat_attributes |= FatFileAttributes::SYSTEM;
        }

        if value.contains(Attributes::DIRECTORY) {
            fat_attributes |= FatFileAttributes::DIRECTORY;
        }

        fat_attributes
    }
}

impl From<FatFileAttributes> for Attributes {
    fn from(value: FatFileAttributes) -> Self {
        let mut fat_attributes = Attributes::default();

        if value.contains(FatFileAttributes::ARCHIVE) {
            fat_attributes |= Attributes::ARCHIVE;
        }

        if value.contains(FatFileAttributes::HIDDEN) {
            fat_attributes |= Attributes::HIDDEN;
        }

        if value.contains(FatFileAttributes::READ_ONLY) {
            fat_attributes |= Attributes::READ_ONLY;
        }

        if value.contains(FatFileAttributes::SYSTEM) {
            fat_attributes |= Attributes::SYSTEM_FILE;
        }

        if value.contains(FatFileAttributes::DIRECTORY) {
            fat_attributes |= Attributes::DIRECTORY;
        }

        fat_attributes
    }
}

impl DekuRead<'_> for FatFileAttributes {
    fn read(input: &BitSlice<u8, Msb0>, _ctx: ()) -> Result<(&BitSlice<u8, Msb0>, Self), DekuError>
    where
        Self: Sized,
    {
        let (slice, byte) = u8::read(input, ())?;

        Ok((slice, FatFileAttributes::from_bits_retain(byte)))
    }
}

/// Date Format. A FAT directory entry date stamp is a 16-bit field that is basically a date relative to the
/// MS-DOS epoch of 01/01/1980. Here is the format (bit 0 is the LSB of the 16-bit word, bit 15 is the
/// MSB of the 16-bit word):
/// Bits 0–4: Day of month, valid value range 1-31 inclusive.
/// Bits 5–8: Month of year, 1 = January, valid value range 1–12 inclusive.
/// Bits 9–15: Count of years from 1980, valid value range 0–127 inclusive (1980–2107).
#[bitfield(u16)]
struct FatDateFormat {
    #[bits(5)]
    pub day: u8,
    #[bits(4)]
    pub month: u8,
    #[bits(7)]
    pub year: u8,
}

/// Time Format. A FAT directory entry time stamp is a 16-bit field that has a granularity of 2 seconds.
/// Here is the format (bit 0 is the LSB of the 16-bit word, bit 15 is the MSB of the 16-bit word).
/// Bits 0–4: 2-second count, valid value range 0–29 inclusive (0 – 58 seconds).
/// Bits 5–10: Minutes, valid value range 0–59 inclusive.
/// Bits 11–15: Hours, valid value range 0–23 inclusive.
#[bitfield(u16)]
struct FatTimeFormat {
    #[bits(5)]
    seconds: u8,
    #[bits(6)]
    minutes: u8,
    #[bits(5)]
    hours: u8,
}

#[used]
static IMAGE1_DATA: &[u8] = include_bytes!("../../assets/test1.img");

#[cfg(test)]
mod tests {
    use chrono::{NaiveDateTime, Utc};
    use std::{
        cell::RefCell,
        rc::Rc,
        sync::{Arc, Mutex},
    };

    use crate::fat32::fat::Fat;
    use crate::{
        Attributes, Directory, File as FileTrait, FileSystem, FileSystemEntry, FileSystemError,
    };
    use sha2::{Digest, Sha256};

    use super::{FAT_SECTOR_SIZE, FatDataSource, FatTimeSource, IMAGE1_DATA, Sector};

    struct InMemoryFatDataSource {
        data: Vec<u8>,
    }

    impl FatDataSource for InMemoryFatDataSource {
        fn read_sectors_to(
            &mut self,
            starting_sector: u32,
            buffer: &mut [Sector],
        ) -> Result<(), FileSystemError> {
            let starting_offset = (starting_sector * FAT_SECTOR_SIZE as u32) as usize;
            let n = buffer.len() * FAT_SECTOR_SIZE;

            let buf = buffer.as_flattened_mut();
            buf.copy_from_slice(&self.data[starting_offset..(starting_offset + n)]);

            Ok(())
        }

        fn write_sector(&mut self, sector: u32, buffer: &[u8]) -> Result<(), FileSystemError> {
            assert_eq!(buffer.len(), 512);

            let starting_offset = (sector * FAT_SECTOR_SIZE as u32) as usize;

            self.data[starting_offset..(starting_offset + buffer.len())].copy_from_slice(buffer);

            Ok(())
        }
    }

    struct StdFatTimeSource {}
    impl FatTimeSource for StdFatTimeSource {
        fn now(&self) -> NaiveDateTime {
            Utc::now().naive_utc()
        }
    }

    fn setup_fat() -> Rc<RefCell<Fat>> {
        let mut vec = Vec::with_capacity(IMAGE1_DATA.len());
        vec.extend_from_slice(IMAGE1_DATA);

        let data_source = InMemoryFatDataSource { data: vec };
        Fat::new(
            Arc::new(Mutex::new(data_source)),
            Arc::new(StdFatTimeSource {}),
            0,
        )
    }

    fn user_entry_names<D: Directory>(dir: &D) -> Vec<String> {
        dir.entries()
            .filter(|entry| entry.name() != "." && entry.name() != "..")
            .map(|entry| entry.name().to_string())
            .collect()
    }

    fn read_file_at_once(fat: &Rc<RefCell<Fat>>, path: &str) -> Result<Vec<u8>, FileSystemError> {
        let mut file = fat.open_file(path)?;
        let mut data = vec![0u8; file.file_size()];
        file.read(0, &mut data)?;
        Ok(data)
    }

    fn read_file_in_chunks(
        fat: &Rc<RefCell<Fat>>,
        path: &str,
        chunk_size: usize,
    ) -> Result<Vec<u8>, FileSystemError> {
        assert!(chunk_size > 0);

        let mut file = fat.open_file(path)?;
        let size = file.file_size();
        let mut data = vec![0u8; size];
        let mut offset = 0;

        while offset < size {
            let end = (offset + chunk_size).min(size);
            file.read(offset, &mut data[offset..end])?;
            offset = end;
        }

        Ok(data)
    }

    fn sha256_hex(data: &[u8]) -> String {
        format!("{:x}", Sha256::digest(data))
    }

    /// Reads the whole file, checks SHA-256, then re-reads it in several chunk sizes
    /// (including cluster boundaries) and requires byte-identical results.
    fn assert_full_file_integrity(
        fat: &Rc<RefCell<Fat>>,
        path: &str,
        expected_size: usize,
        expected_sha256: &str,
        chunk_sizes: &[usize],
    ) -> Result<(), FileSystemError> {
        let whole = read_file_at_once(fat, path)?;
        assert_eq!(whole.len(), expected_size);
        assert_eq!(sha256_hex(&whole), expected_sha256);

        for &chunk_size in chunk_sizes {
            let chunked = read_file_in_chunks(fat, path, chunk_size)?;
            assert_eq!(
                chunked, whole,
                "full-file read != chunked read (chunk_size={chunk_size}) for {path}"
            );
        }

        Ok(())
    }

    const CLUSTER_STRESS_CHUNK_SIZES: &[usize] = &[512, 4095, 4096, 4097, 8192];

    #[test]
    fn test_file_listing_in_root_directory() {
        let expected_names = vec!["lorem_ipsum.txt", "books", "filesystems", "fruits"];

        let fat = setup_fat();
        let dir = fat.open_directory("").unwrap();
        let names: Vec<String> = dir
            .entries()
            .map(|entry| (*entry.name()).to_string())
            .collect();

        assert_eq!(expected_names, names);
    }

    #[test]
    fn test_read_from_sfn_file_in_root_directory() -> Result<(), FileSystemError> {
        let fat = setup_fat();

        let mut file = fat.open_file("lorem_ipsum.txt")?;

        // Start of the file
        let mut buffer1 = [0u8; 11];
        file.read(0, &mut buffer1)?;

        // Somewhere in the first cluster
        let mut buffer2 = [0u8; 11];
        file.read(250, &mut buffer2)?;

        // End of the first cluster and start of the second
        let mut buffer3 = [0u8; 50];
        file.read(508, &mut buffer3)?;

        // Last cluster
        let mut buffer4 = [0u8; 50];
        file.read(file.file_size as usize - 70, &mut buffer4)?;

        // Last 11 characters
        let mut buffer5 = [0u8; 11];
        file.read(file.file_size as usize - 12, &mut buffer5)?;

        // Last character
        let mut buffer6 = [0u8; 1];
        file.read(file.file_size as usize - 1, &mut buffer6)?;

        // Read outside the boundary
        let mut buffer7 = [0u8; 1];
        let result = file.read(file.file_size as usize, &mut buffer7);

        assert_eq!(String::from_utf8_lossy(&buffer1), "Lorem ipsum");
        assert_eq!(String::from_utf8_lossy(&buffer2), "ricies dict");
        assert_eq!(
            String::from_utf8_lossy(&buffer3),
            " nibh. Sed at porttitor tellus. Proin vulputate se"
        );
        assert_eq!(
            String::from_utf8_lossy(&buffer4),
            "rtis enim. Quisque porta elit tellus, ut ullamcorp"
        );
        assert_eq!(String::from_utf8_lossy(&buffer5), "eleifend ut");
        assert_eq!(String::from_utf8_lossy(&buffer6), ".");
        assert!(result.is_err());

        Ok(())
    }

    #[test]
    fn test_file_creation_in_directory() -> Result<(), FileSystemError> {
        let fat = setup_fat();

        let expected_names = vec![
            "lorem_ipsum.txt",
            "books",
            "filesystems",
            "fruits",
            "Long directory name",
            "Long filename",
        ];
        let dir_path = "".to_string();
        let mut dir = fat.open_directory(&dir_path)?;

        dir.create_directory("Long directory name".to_string(), Attributes::READ_ONLY)?;
        dir.create_file("Long filename".to_string(), Attributes::READ_ONLY)?;

        let names: Vec<String> = dir
            .entries()
            .map(|entry| (*entry.name()).to_string())
            .collect();

        assert_eq!(names, expected_names);

        Ok(())
    }

    #[test]
    fn test_new_file_attributes() -> Result<(), FileSystemError> {
        let fat = setup_fat();

        let dir_path = "".to_string();
        let mut dir = fat.open_directory(&dir_path)?;

        dir.create_file(
            "file1".to_string(),
            Attributes::HIDDEN | Attributes::SYSTEM_FILE,
        )?;
        dir.create_directory("dir1".to_string(), Attributes::DIRECTORY)?;

        let file = fat.open_file("file1")?;
        let directory = fat.open_directory("dir1")?;

        assert_eq!(
            file.attributes(),
            Attributes::HIDDEN | Attributes::SYSTEM_FILE
        );
        assert_eq!(directory.attributes(), Attributes::DIRECTORY);

        Ok(())
    }

    #[test]
    fn test_date_times() -> Result<(), FileSystemError> {
        let fat = setup_fat();

        let mut file = fat.open_file("books/english/macbeth.txt")?;
        let mut directory = fat.open_directory("books/polish")?;
        let current_time = Utc::now().naive_utc();

        assert_eq!(
            file.creation_date_time(),
            NaiveDateTime::parse_from_str("2024-06-16 15:06:04", "%Y-%m-%d %H:%M:%S").unwrap()
        );
        assert_eq!(
            directory.creation_date_time(),
            NaiveDateTime::parse_from_str("2024-06-16 15:06:04", "%Y-%m-%d %H:%M:%S").unwrap()
        );

        file.set_creation_date_time(current_time)?;
        file.set_modification_date_time(current_time)?;

        directory.set_creation_date_time(current_time)?;
        directory.set_modification_date_time(current_time)?;

        // re-read file information from the disk
        let file2 = fat.open_file("books/english/macbeth.txt")?;
        let directory2 = fat.open_directory("books/polish")?;

        assert!(
            file2
                .creation_date_time()
                .signed_duration_since(current_time)
                .num_seconds()
                <= 3
        );
        assert!(
            file2
                .modification_date_time()
                .signed_duration_since(current_time)
                .num_seconds()
                <= 3
        );

        assert!(
            directory2
                .creation_date_time()
                .signed_duration_since(current_time)
                .num_seconds()
                <= 3
        );
        assert!(
            directory2
                .modification_date_time()
                .signed_duration_since(current_time)
                .num_seconds()
                <= 3
        );

        Ok(())
    }

    #[test]
    fn test_attributes() -> Result<(), FileSystemError> {
        let fat = setup_fat();

        let mut file = fat.open_file("books/polish/pan-tadeusz.txt")?;
        let mut directory = fat.open_directory("books/english")?;

        file.set_attributes(Attributes::SYSTEM_FILE)?;
        directory.set_attributes(Attributes::HIDDEN | Attributes::DIRECTORY)?;

        // Re-read files from the disk
        let file2 = fat.open_file("books/polish/pan-tadeusz.txt")?;
        let directory2 = fat.open_directory("books/english")?;

        assert_eq!(file2.attributes(), Attributes::SYSTEM_FILE);
        assert_eq!(
            directory2.attributes(),
            Attributes::HIDDEN | Attributes::DIRECTORY
        );

        Ok(())
    }

    #[test]
    fn test_rename() -> Result<(), FileSystemError> {
        let fat = setup_fat();

        let mut file = fat.open_file("fruits/random things/random2/Methamphetamine.txt")?;
        let mut dir = fat.open_directory("filesystems/Resilient File System")?;

        file.rename("meth.txt".to_string())?;
        dir.rename("ReFS".to_string())?;

        fat.open_file("fruits/random things/random2/meth.txt")?;
        fat.open_directory("filesystems/ReFS")?;

        Ok(())
    }

    #[test]
    fn test_file_move() -> Result<(), FileSystemError> {
        let fat = setup_fat();

        let mut file1 = fat.open_file("fruits/random things/random2/File Allocation Table.txt")?;
        let destination_directory = fat.open_directory("filesystems/File Allocation Table")?;

        file1.move_to(&destination_directory)?;

        fat.open_file("filesystems/File Allocation Table/File Allocation Table.txt")?;
        let file3 = fat.open_file("fruits/random things/random2/File Allocation Table.txt");

        let entries: Vec<String> = destination_directory
            .entries()
            .map(|entry| entry.name().to_string())
            .collect();
        let expected_entries = vec![
            ".",
            "..",
            "File Allocation Table 16",
            "File Allocation Table 32",
            "File Allocation Table 12",
            "File Allocation Table.txt",
        ];

        assert_eq!(entries, expected_entries);
        assert!(file3.is_err());

        Ok(())
    }

    #[test]
    fn test_directory_move() -> Result<(), FileSystemError> {
        let fat = setup_fat();

        let mut directory = fat.open_directory("fruits")?;
        let expected_entries: Vec<FileSystemEntry> = directory.entries().collect();

        let destination_directory = fat.open_directory("books")?;

        directory.move_to(&destination_directory)?;

        let directory2 = fat.open_directory("books/fruits")?;
        let entries: Vec<FileSystemEntry> = directory2.entries().collect();

        assert_eq!(entries, expected_entries);

        Ok(())
    }

    #[test]
    fn test_file_removal() -> Result<(), FileSystemError> {
        let fat = setup_fat();

        let mut file = fat.open_file("lorem_ipsum.txt")?;
        file.delete()?;

        let directory = fat.open_directory("")?;
        let entries: Vec<String> = directory
            .entries()
            .map(|entry| entry.name().to_string())
            .collect();
        let expected_entries = vec!["books", "filesystems", "fruits"];

        assert_eq!(entries, expected_entries);

        Ok(())
    }

    #[test]
    fn test_directory_removal() -> Result<(), FileSystemError> {
        let fat = setup_fat();

        let mut directory = fat.open_directory("fruits")?;
        directory.delete()?;

        let directory = fat.open_directory("fruits");

        assert!(directory.is_err());

        Ok(())
    }

    #[test]
    fn test_file_write() -> Result<(), FileSystemError> {
        let fat = setup_fat();

        let mut file = fat.open_file("fruits/STRAWBERRY.TXT")?;
        let buffer = "Test";
        file.write(3, buffer.as_bytes())?;

        let mut buffer2 = [0u8; 7];
        file.read(0, &mut buffer2[..])?;

        assert_eq!(String::from_utf8_lossy(&buffer2), "STRTest");

        Ok(())
    }

    #[test]
    fn test_file_shrink_in_the_same_cluster() -> Result<(), FileSystemError> {
        let fat = setup_fat();
        let mut file = fat.open_file("fruits/random things/random2/AxelF.txt")?;
        file.shrink(file.file_size() - 11)?; // 1811 - 11 = 1800

        let mut buffer = [0u8; 8];
        file.read(1800 - 8, &mut buffer[..])?;

        assert_eq!(String::from_utf8_lossy(&buffer), "Shoot Ou");
        assert!(file.read(1805, &mut buffer[..]).is_err());

        Ok(())
    }

    #[test]
    fn test_file_shrink_in_another_cluster() -> Result<(), FileSystemError> {
        let fat = setup_fat();
        let mut file = fat.open_file("fruits/random things/random2/Till Lindemann.txt")?;
        file.shrink(0x168A)?;

        let mut buffer = [0u8; 14];
        file.read(0x168A - 14, &mut buffer[..])?;

        assert_eq!(String::from_utf8_lossy(&buffer), "Ich tu dir weh");
        assert!(file.read(0x168A + 2, &mut buffer[..]).is_err());

        Ok(())
    }

    #[test]
    fn test_books_polish_directory_listing() {
        let fat = setup_fat();
        let dir = fat.open_directory("books/polish").unwrap();
        let mut names = user_entry_names(&dir);
        names.sort();

        assert_eq!(names, vec!["pan-tadeusz.txt", "wesele.txt"]);
    }

    #[test]
    fn test_books_english_file_sizes() -> Result<(), FileSystemError> {
        let fat = setup_fat();

        assert_eq!(
            fat.open_file("books/english/macbeth.txt")?.file_size(),
            119_097
        );
        assert_eq!(
            fat.open_file("books/english/romeojuliet.txt")?.file_size(),
            158_052
        );

        Ok(())
    }

    #[test]
    fn test_read_wesele_header() -> Result<(), FileSystemError> {
        let fat = setup_fat();
        let mut file = fat.open_file("books/polish/wesele.txt")?;

        assert_eq!(file.file_size(), 171_474);

        let mut buffer = [0u8; 64];
        file.read(0, &mut buffer)?;
        let text = String::from_utf8_lossy(&buffer);
        assert!(text.contains("Wesele"));
        assert!(text.contains("Dramat w trzech aktach"));

        Ok(())
    }

    #[test]
    fn test_read_romeo_juliet_header() -> Result<(), FileSystemError> {
        let fat = setup_fat();
        let mut file = fat.open_file("books/english/romeojuliet.txt")?;

        let mut buffer = [0u8; 80];
        file.read(0, &mut buffer)?;
        let text = String::from_utf8_lossy(&buffer);
        assert!(text.contains("ROMEO AND JULIET"));
        assert!(text.contains("Shakespeare"));

        Ok(())
    }

    #[test]
    fn test_fruits_directory_listing() {
        let fat = setup_fat();
        let dir = fat.open_directory("fruits").unwrap();
        let mut names = user_entry_names(&dir);
        names.sort();

        assert_eq!(names.len(), 16);
        assert!(names.iter().any(|name| name.starts_with("MANGO")));
        assert!(names.contains(&"STRAWBERRY.TXT".to_string()));
        assert!(names.contains(&"random things".to_string()));
    }

    #[test]
    fn test_read_small_fruit_file_contents() -> Result<(), FileSystemError> {
        let fat = setup_fat();
        let dir = fat.open_directory("fruits")?;
        let names = user_entry_names(&dir);

        let mango_name = names.iter().find(|n| n.starts_with("MANGO")).unwrap();
        let pear_name = names.iter().find(|n| n.starts_with("PEAR")).unwrap();
        let banana_name = names.iter().find(|n| n.starts_with("BANANA")).unwrap();

        let mut mango = fat.open_file(&format!("fruits/{mango_name}"))?;
        let mut pear = fat.open_file(&format!("fruits/{pear_name}"))?;
        let mut banana = fat.open_file(&format!("fruits/{banana_name}"))?;

        let mut mango_buf = [0u8; 5];
        let mut pear_buf = [0u8; 4];
        let mut banana_buf = [0u8; 6];
        mango.read(0, &mut mango_buf)?;
        pear.read(0, &mut pear_buf)?;
        banana.read(0, &mut banana_buf)?;

        assert_eq!(&mango_buf, b"MANGO");
        assert_eq!(&pear_buf, b"PEAR");
        assert_eq!(&banana_buf, b"BANANA");

        Ok(())
    }

    #[test]
    fn test_read_fat32_txt() -> Result<(), FileSystemError> {
        let fat = setup_fat();
        let mut file =
            fat.open_file("filesystems/File Allocation Table/File Allocation Table 32/fat32.txt")?;

        assert_eq!(file.file_size(), 5);

        let mut buffer = [0u8; 5];
        file.read(0, &mut buffer)?;
        assert_eq!(&buffer, b"fat32");

        Ok(())
    }

    #[test]
    fn test_open_wrong_entry_type() {
        let fat = setup_fat();

        assert!(matches!(
            fat.open_file("books"),
            Err(FileSystemError::NotAFile)
        ));
        assert!(matches!(
            fat.open_directory("lorem_ipsum.txt"),
            Err(FileSystemError::NotADirectory)
        ));
    }

    #[test]
    fn test_open_missing_path() {
        let fat = setup_fat();

        assert!(matches!(
            fat.open_file("no/such/file.txt"),
            Err(FileSystemError::NotFound)
        ));
        assert!(matches!(
            fat.open_directory("filesystems/ghost directory"),
            Err(FileSystemError::NotFound)
        ));
    }

    #[test]
    fn test_read_glossary_large_file() -> Result<(), FileSystemError> {
        let fat = setup_fat();
        let mut file = fat.open_file("fruits/random things/random2/Methamphetamine.txt")?;

        assert_eq!(file.file_size(), 45_613);

        let mut buffer = [0u8; 96];
        file.read(0, &mut buffer)?;
        assert!(buffer.iter().any(|byte| *byte != 0));

        file.read(20_000, &mut buffer)?;
        assert!(buffer.iter().any(|byte| *byte != 0));

        Ok(())
    }

    #[test]
    fn test_read_script_py() -> Result<(), FileSystemError> {
        let fat = setup_fat();
        let mut file = fat.open_file("fruits/random things/script.py")?;

        assert_eq!(file.file_size(), 1_215);

        let mut buffer = [0u8; 32];
        file.read(0, &mut buffer)?;
        assert_eq!(&buffer[..8], b"words = ");

        Ok(())
    }

    #[test]
    fn test_read_drive_letter_assignment() -> Result<(), FileSystemError> {
        let fat = setup_fat();
        let mut file = fat.open_file("fruits/random things/random2/Drive letter assignment.txt")?;

        assert_eq!(file.file_size(), 18_545);

        let mut buffer = [0u8; 80];
        file.read(0, &mut buffer)?;
        let text = String::from_utf8_lossy(&buffer);
        assert!(text.starts_with("In computer data storage, drive letter assignment"));

        Ok(())
    }

    #[test]
    fn test_filesystems_nested_directories() -> Result<(), FileSystemError> {
        let fat = setup_fat();

        let fat_dir = fat.open_directory("filesystems/File Allocation Table")?;
        let mut names = user_entry_names(&fat_dir);
        names.sort();
        assert_eq!(
            names,
            vec![
                "File Allocation Table 12",
                "File Allocation Table 16",
                "File Allocation Table 32",
            ]
        );

        assert_eq!(
            user_entry_names(&fat.open_directory("filesystems/New Technology File System")?),
            Vec::<String>::new()
        );
        assert_eq!(
            user_entry_names(&fat.open_directory("filesystems/Resilient File System")?),
            Vec::<String>::new()
        );

        Ok(())
    }

    #[test]
    fn test_write_append_extends_file_size() -> Result<(), FileSystemError> {
        let fat = setup_fat();
        let grape_name = user_entry_names(&fat.open_directory("fruits")?)
            .into_iter()
            .find(|name| name.starts_with("GRAPE"))
            .unwrap();
        let mut file = fat.open_file(&format!("fruits/{grape_name}"))?;

        assert_eq!(file.file_size(), 5);
        file.write(5, b"!")?;

        let mut buffer = [0u8; 6];
        file.read(0, &mut buffer)?;
        assert_eq!(&buffer, b"GRAPE!");
        assert_eq!(file.file_size(), 6);

        Ok(())
    }

    #[test]
    fn test_pan_tadeusz_file_size_and_read() -> Result<(), FileSystemError> {
        let fat = setup_fat();
        let mut file = fat.open_file("books/polish/pan-tadeusz.txt")?;

        assert_eq!(file.file_size(), 493_758);

        let mut buffer = [0u8; 32];
        file.read(0, &mut buffer)?;
        let text = String::from_utf8_lossy(&buffer);
        assert!(text.contains("Adam Mickiewicz"));
        assert!(text.contains("Pan Tadeusz"));

        Ok(())
    }

    #[test]
    fn test_random2_directory_listing() -> Result<(), FileSystemError> {
        let fat = setup_fat();
        let dir = fat.open_directory("fruits/random things/random2")?;
        let mut names = user_entry_names(&dir);
        names.sort();

        assert_eq!(names.len(), 6);
        assert!(names.contains(&"AxelF.txt".to_string()));
        assert!(names.contains(&"Methamphetamine.txt".to_string()));
        assert!(names.contains(&"Till Lindemann.txt".to_string()));

        Ok(())
    }

    #[test]
    fn test_lorem_ipsum_file_size() -> Result<(), FileSystemError> {
        let fat = setup_fat();
        let file = fat.open_file("lorem_ipsum.txt")?;

        assert_eq!(file.file_size(), 3_574);

        Ok(())
    }

    #[test]
    fn test_read_lorem_ipsum_full_integrity() -> Result<(), FileSystemError> {
        let fat = setup_fat();
        assert_full_file_integrity(
            &fat,
            "lorem_ipsum.txt",
            3_574,
            "008a23e4428bfa0e33058eee8766230ff3912afc49e865e43d2d7cffa14f50f2",
            &[1, 512, 4096, 4097],
        )
    }

    #[test]
    fn test_read_macbeth_full_integrity() -> Result<(), FileSystemError> {
        let fat = setup_fat();
        assert_full_file_integrity(
            &fat,
            "books/english/macbeth.txt",
            119_097,
            "1781445953af1c93864ae20a8c16416d8d04e91a5010b981a8eb76a14f1deb92",
            CLUSTER_STRESS_CHUNK_SIZES,
        )
    }

    #[test]
    fn test_read_pan_tadeusz_full_integrity() -> Result<(), FileSystemError> {
        let fat = setup_fat();
        assert_full_file_integrity(
            &fat,
            "books/polish/pan-tadeusz.txt",
            493_758,
            "f9038b0f9cb70efce5090921c3a73356527066eadeee1050c021d65720950574",
            CLUSTER_STRESS_CHUNK_SIZES,
        )
    }

    #[test]
    fn test_read_methamphetamine_full_integrity() -> Result<(), FileSystemError> {
        let fat = setup_fat();
        assert_full_file_integrity(
            &fat,
            "fruits/random things/random2/Methamphetamine.txt",
            45_613,
            "daa5e710cf69cfac62069dccc24bc8d48da43fe430eba91f5d4a93e9ac012aa9",
            CLUSTER_STRESS_CHUNK_SIZES,
        )
    }

    #[test]
    fn test_read_till_lindemann_full_integrity() -> Result<(), FileSystemError> {
        let fat = setup_fat();
        assert_full_file_integrity(
            &fat,
            "fruits/random things/random2/Till Lindemann.txt",
            14_114,
            "bcf0003939dbcc43bf7d9ac23717c57680860bcd9558e70cca8c1ee348c2e0bc",
            CLUSTER_STRESS_CHUNK_SIZES,
        )
    }
}
