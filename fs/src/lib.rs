//! Filesystem crate for Moose operating system
//!
//! Contains definitions of FileSystem, File and Directory traits and mutual errors and attributes

pub mod fat32;

use bitflags::bitflags;
use chrono::NaiveDateTime;
use snafu::Snafu;

/// Main filesystem trait
pub trait FileSystem {
    type File: File;
    type Directory: Directory<File = Self::File>;

    /// Opens a file with specified path.
    fn open_file(&self, path: &str) -> Result<Self::File, FileSystemError>;
    /// Opens a directory with specified path.
    fn open_directory(&self, path: &str) -> Result<Self::Directory, FileSystemError>;
}

/// The `File` trait defines a common interface for file operations. This trait includes methods for reading,
/// writing, deleting, renaming, moving, and modifying file attributes. It also provides methods for querying
/// file metadata such as size, creation date, and modification date.
///
/// Types that implement this trait should also define an associated type `Directory`, which represents the
/// directory structure used for moving files.
///
/// # Associated Types
///
/// * `Directory`: The type representing a directory to which a file can be moved.
pub trait File: Sized {
    /// The type representing a directory.
    type Directory;

    /// Reads data from the file starting at the given offset and fills the provided buffer.
    fn read(&mut self, offset: usize, buffer: &mut [u8]) -> Result<(), FileSystemError>;

    /// Writes data to the file starting at the given offset from the provided buffer.
    fn write(&mut self, offset: usize, buffer: &[u8]) -> Result<(), FileSystemError>;

    /// Deletes the file.
    fn delete(&mut self) -> Result<(), FileSystemError>;

    /// Renames the file to the given name.
    fn rename(&mut self, name: String) -> Result<(), FileSystemError>;

    /// Moves the file to the specified directory.
    fn move_to(&mut self, directory: &Self::Directory) -> Result<(), FileSystemError>;

    /// Shrinks the file to the specified new size.
    fn shrink(&mut self, new_size: usize) -> Result<(), FileSystemError>;

    /// Sets the creation date time of the file.
    fn set_creation_date_time(
        &mut self,
        creation_date_time: NaiveDateTime,
    ) -> Result<(), FileSystemError>;

    /// Sets the modification date time of the file.
    fn set_modification_date_time(
        &mut self,
        modification_date_time: NaiveDateTime,
    ) -> Result<(), FileSystemError>;

    /// Sets the attributes of the file.
    fn set_attributes(&mut self, attributes: Attributes) -> Result<(), FileSystemError>;

    /// Returns the size of the file in bytes.
    fn file_size(&self) -> usize;

    /// Returns the creation date time of the file.
    fn creation_date_time(&self) -> NaiveDateTime;

    /// Returns the modification date time of the file.
    fn modification_date_time(&self) -> NaiveDateTime;

    /// Returns the attributes of the file.
    fn attributes(&self) -> Attributes;

    /// Returns the name of the file.
    fn name(&self) -> &str;
}

/// The `Directory` trait defines a common interface for directory operations. This trait includes methods for
/// creating files and subdirectories, listing directory entries, deleting, renaming, moving, and modifying
/// directory attributes. It also provides methods for querying directory metadata such as creation and
/// modification dates.
///
/// Types that implement this trait should also define an associated type `File`, which represents the files
/// within the directory.
///
/// # Associated Types
///
/// * `File`: The type representing a file within the directory.
pub trait Directory: Sized {
    /// The type representing a file within the directory.
    type File;

    /// Returns an iterator over the entries in the directory. Each entry is a `FileSystemEntry`.
    fn entries(&self) -> impl Iterator<Item = FileSystemEntry>;

    /// Creates a new file in the directory with the specified name and attributes.
    fn create_file(
        &mut self,
        name: String,
        attributes: Attributes,
    ) -> Result<Self::File, FileSystemError>;

    /// Creates a new subdirectory in the directory with the specified name and attributes.
    fn create_directory(
        &mut self,
        name: String,
        attributes: Attributes,
    ) -> Result<Self, FileSystemError>;

    /// Deletes the directory.
    fn delete(&mut self) -> Result<(), FileSystemError>;

    /// Renames the directory to the given name.
    fn rename(&mut self, name: String) -> Result<(), FileSystemError>;

    /// Moves the directory to another directory.
    fn move_to(&mut self, directory: &Self) -> Result<(), FileSystemError>;

    /// Sets the creation date time of the directory.
    fn set_creation_date_time(
        &mut self,
        creation_date_time: NaiveDateTime,
    ) -> Result<(), FileSystemError>;

    /// Sets the modification date time of the directory.
    fn set_modification_date_time(
        &mut self,
        modification_date_time: NaiveDateTime,
    ) -> Result<(), FileSystemError>;

    /// Sets the attributes of the directory.
    fn set_attributes(&mut self, attributes: Attributes) -> Result<(), FileSystemError>;

    /// Returns the creation date time of the directory.
    fn creation_date_time(&self) -> NaiveDateTime;

    /// Returns the modification date time of the directory.
    fn modification_date_time(&self) -> NaiveDateTime;

    /// Returns the attributes of the directory.
    fn attributes(&self) -> Attributes;

    /// Returns the name of the directory.
    fn name(&self) -> &str;
}

/// `FileSystemEntry` is an enum representing an entry in a filesystem, which can either be a file or a directory.
/// It includes metadata such as the name, creation time, modification time, and attributes of the entry.
#[derive(Debug, Clone, PartialEq)]
pub enum FileSystemEntry {
    /// Represents a file entry in the filesystem.
    File {
        /// The name of the file.
        name: String,
        /// The creation date time of the file.
        creation_date_time: NaiveDateTime,
        /// The modification date time of the file.
        modification_date_time: NaiveDateTime,
        /// The attributes of the file.
        attributes: Attributes,
    },
    /// Represents a directory entry in the filesystem.
    Directory {
        /// The name of the directory.
        name: String,
        /// The creation date time of the directory.
        creation_date_time: NaiveDateTime,
        /// The modification date time of the directory.
        modification_date_time: NaiveDateTime,
        /// The attributes of the directory.
        attributes: Attributes,
    },
}

impl FileSystemEntry {
    pub fn name(&self) -> &str {
        match self {
            FileSystemEntry::File { name, .. } => name,
            FileSystemEntry::Directory { name, .. } => name,
        }
    }
}

bitflags! {
    #[derive(Debug, Default, PartialEq, Clone)]
    pub struct Attributes: u8 {
        const ARCHIVE = 1;
        const HIDDEN = 1 << 1;
        const READ_ONLY = 1 << 2;
        const SYSTEM_FILE = 1 << 3;
        const DIRECTORY = 1 << 4;
    }
}

/// `FileSystemError` is an enum representing various errors that can occur in a filesystem. Each variant
/// corresponds to a specific type of error that might be encountered during filesystem operations.
#[derive(Debug, Snafu)]
pub enum FileSystemError {
    #[snafu(display("Not found"))]
    NotFound,

    #[snafu(display("Found directory, not a file"))]
    NotAFile,

    #[snafu(display("Found file, not a directory"))]
    NotADirectory,

    #[snafu(display("Not enough space on device"))]
    NotEnoughSpace,

    #[snafu(display("Entry already exists"))]
    AlreadyExists,

    #[snafu(display("Name too long"))]
    NameTooLong,

    #[snafu(display("Invalid argument"))]
    InvalidArgument,

    #[snafu(display("Read out of bounds"))]
    ReadOutOfBounds,

    #[snafu(display("Bad data"))]
    BadData,
}
