use chrono::NaiveDateTime;
use std::{cell::RefCell, rc::Rc};

use super::{FatFileAttributes, FatFileEntry, RawFatFileEntry, fat::Fat, file::FatFile};
use crate::{Attributes, Directory, FileSystemEntry, FileSystemError};

/// Implementation of filesystems' Directory
pub struct FatDirectory {
    pub(crate) filesystem: Rc<RefCell<Fat>>,
    pub(crate) content_cluster: u32,
    pub(crate) file_entry: FatFileEntry,
    pub(crate) file_entry_cluster: u32,
}

impl FatDirectory {
    fn create_entry(
        &mut self,
        name: String,
        attributes: Attributes,
        is_directory: bool,
    ) -> Result<(FatFileEntry, u32), FileSystemError> {
        let mut fat = self.filesystem.borrow_mut();

        if name.len() > 255 {
            return Err(FileSystemError::NameTooLong);
        }

        let current_time = fat.current_datetime();

        let raw_file_entry = RawFatFileEntry::default();
        let mut fat_entry = FatFileEntry::default();
        let fat_attributes = if is_directory {
            FatFileAttributes::from(attributes) | FatFileAttributes::DIRECTORY
        } else {
            FatFileAttributes::from(attributes)
        };

        fat_entry.raw.push(raw_file_entry);
        fat_entry.set_name(name);
        fat_entry.set_attr(fat_attributes);
        fat_entry.set_creation_date_time(current_time);
        fat_entry.set_last_access_date_time(current_time);
        fat_entry.set_last_write_date_time(current_time);

        let cluster = fat
            .get_clusters_for_file(self.content_cluster)
            .next()
            .unwrap();

        fat.serialize_file_entry(None, &fat_entry, cluster);

        Ok((fat_entry, cluster))
    }
}

impl Directory for FatDirectory {
    type File = FatFile;

    fn entries(&self) -> impl Iterator<Item = FileSystemEntry> {
        // I guess we can't assume anything more
        let mut directory_entries = Vec::with_capacity(16);

        let filesystem = self.filesystem.borrow();

        for cluster in filesystem.get_clusters_for_file(self.content_cluster) {
            directory_entries.extend(
                filesystem
                    .get_file_listing_from_cluster(cluster)
                    .unwrap()
                    .into_iter()
                    .map(|entry| {
                        if entry.attr().is_directory() {
                            FileSystemEntry::Directory {
                                name: entry.name().to_string(),
                                creation_date_time: entry.creation_date_time,
                                modification_date_time: entry.last_write_date_time,
                                attributes: Attributes::from(entry.attr),
                            }
                        } else {
                            FileSystemEntry::File {
                                name: entry.name().to_string(),
                                creation_date_time: entry.creation_date_time,
                                modification_date_time: entry.last_write_date_time,
                                attributes: Attributes::from(entry.attr),
                            }
                        }
                    }),
            );
        }

        directory_entries.into_iter()
    }

    fn create_file(
        &mut self,
        name: String,
        attributes: Attributes,
    ) -> Result<Self::File, FileSystemError> {
        let (file_entry, starting_cluster) = self.create_entry(name, attributes, false)?;

        Ok(FatFile {
            file_entry,
            file_entry_cluster: self.file_entry_cluster,
            file_size: 0,
            filesystem: Rc::clone(&self.filesystem),
            starting_cluster,
        })
    }

    fn create_directory(
        &mut self,
        name: String,
        attributes: Attributes,
    ) -> Result<Self, FileSystemError> {
        let (file_entry, starting_cluster) = self.create_entry(name, attributes, true)?;

        Ok(FatDirectory {
            filesystem: Rc::clone(&self.filesystem),
            content_cluster: starting_cluster,
            file_entry,
            file_entry_cluster: self.file_entry_cluster,
        })
    }

    fn delete(&mut self) -> Result<(), FileSystemError> {
        let mut fat = self.filesystem.borrow_mut();

        fat.remove_file_entry(&self.file_entry, self.file_entry_cluster)?;
        fat.mark_clusters_as_free(self.content_cluster)?;

        Ok(())
    }

    fn rename(&mut self, name: String) -> Result<(), FileSystemError> {
        let old = self.file_entry.clone();

        self.file_entry.set_name(name);

        self.filesystem.borrow_mut().serialize_file_entry(
            Some(&old),
            &self.file_entry,
            self.file_entry_cluster,
        );

        Ok(())
    }

    fn move_to(&mut self, directory: &Self) -> Result<(), FileSystemError> {
        self.filesystem.borrow_mut().move_file(
            &self.file_entry,
            directory,
            self.file_entry_cluster,
        )?;

        Ok(())
    }

    fn set_creation_date_time(
        &mut self,
        creation_date_time: NaiveDateTime,
    ) -> Result<(), FileSystemError> {
        self.file_entry.set_creation_date_time(creation_date_time);

        self.filesystem.borrow_mut().serialize_file_entry(
            Some(&self.file_entry),
            &self.file_entry,
            self.file_entry_cluster,
        );

        Ok(())
    }

    fn set_modification_date_time(
        &mut self,
        modification_date_time: NaiveDateTime,
    ) -> Result<(), FileSystemError> {
        self.file_entry
            .set_last_write_date_time(modification_date_time);

        self.filesystem.borrow_mut().serialize_file_entry(
            Some(&self.file_entry),
            &self.file_entry,
            self.file_entry_cluster,
        );

        Ok(())
    }

    fn set_attributes(&mut self, attributes: Attributes) -> Result<(), FileSystemError> {
        self.file_entry
            .set_attr(FatFileAttributes::from(attributes));

        self.filesystem.borrow_mut().serialize_file_entry(
            Some(&self.file_entry),
            &self.file_entry,
            self.file_entry_cluster,
        );

        Ok(())
    }

    fn creation_date_time(&self) -> NaiveDateTime {
        self.file_entry.creation_date_time
    }

    fn modification_date_time(&self) -> NaiveDateTime {
        self.file_entry.last_write_date_time
    }

    fn attributes(&self) -> Attributes {
        Attributes::from(self.file_entry.attr)
    }

    fn name(&self) -> &str {
        &self.file_entry.name
    }
}
