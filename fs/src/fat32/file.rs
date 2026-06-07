use chrono::NaiveDateTime;
use libm::ceil;
use std::{cell::RefCell, cmp::min, rc::Rc};

use super::fat::{ContiguousClusterRuns, FAT_END_OF_FILE_MARK, FAT_FREE_SECTOR, Fat};
use crate::{
    Attributes, File, FileSystemError,
    fat32::{FatFileAttributes, FatFileEntry, directory::FatDirectory},
};

pub struct FatFile {
    pub(crate) filesystem: Rc<RefCell<Fat>>,
    pub(crate) starting_cluster: u32,
    pub(crate) file_size: u32,
    pub(crate) file_entry: FatFileEntry,
    pub(crate) file_entry_cluster: u32,
}

impl File for FatFile {
    type Directory = FatDirectory;

    fn read(&mut self, offset: usize, buffer: &mut [u8]) -> Result<(), FileSystemError> {
        assert!(!buffer.is_empty());

        if (offset + buffer.len()) > (self.file_size as usize) {
            return Err(FileSystemError::ReadOutOfBounds);
        }

        let cluster_size = (self.filesystem.borrow().bpb.sectors_per_cluster as u16
            * self.filesystem.borrow().bpb.bytes_per_sector) as usize;
        let clusters_to_skip = libm::floorf((offset / cluster_size) as f32) as usize;
        let mut offset_within_cluster = offset % cluster_size;

        let mut to_read = buffer.len();
        let mut reading_offset = 0;

        let mut temp_buffer: Vec<u8> = vec![0; cluster_size];
        let temp_slice = temp_buffer.as_mut_slice();

        let fat = self.filesystem.borrow();
        let mut runs = ContiguousClusterRuns::new(
            fat.get_clusters_for_file(self.starting_cluster)
                .skip(clusters_to_skip),
        );
        let mut current_run: Option<(u32, u32)> = None;

        while to_read > 0 {
            if offset_within_cluster != 0 || to_read < cluster_size {
                let cluster = take_next_cluster(&mut current_run, &mut runs)
                    .ok_or(FileSystemError::ReadOutOfBounds)?;

                fat.read_cluster_to(cluster, temp_slice)?;

                let copy_size = min(to_read, cluster_size - offset_within_cluster);
                buffer[reading_offset..(reading_offset + copy_size)].copy_from_slice(
                    &temp_slice[offset_within_cluster..(offset_within_cluster + copy_size)],
                );

                to_read -= copy_size;
                reading_offset += copy_size;
                offset_within_cluster = 0;
                continue;
            }

            if current_run.is_none() {
                current_run = runs.next();
            }

            let Some((first, count)) = current_run else {
                return Err(FileSystemError::ReadOutOfBounds);
            };

            let batch_clusters = min(count, (to_read / cluster_size) as u32);
            let batch_bytes = batch_clusters as usize * cluster_size;

            if batch_clusters == 1 {
                fat.read_cluster_to(
                    first,
                    &mut buffer[reading_offset..(reading_offset + cluster_size)],
                )?;
                current_run = if count > 1 {
                    Some((first + 1, count - 1))
                } else {
                    None
                };
            } else {
                fat.read_contiguous_clusters_to(
                    first,
                    batch_clusters,
                    &mut buffer[reading_offset..(reading_offset + batch_bytes)],
                )?;
                current_run = if batch_clusters == count {
                    None
                } else {
                    Some((first + batch_clusters, count - batch_clusters))
                };
            }

            to_read -= batch_bytes;
            reading_offset += batch_bytes;
        }

        assert_eq!(to_read, 0);

        Ok(())
    }

    fn write(&mut self, offset: usize, buffer: &[u8]) -> Result<(), FileSystemError> {
        // Writing n bytes after end of the file is forbidden
        assert!(offset <= self.file_size as usize);

        let cluster_size = (self.filesystem.borrow().bpb.sectors_per_cluster as u16
            * self.filesystem.borrow().bpb.bytes_per_sector) as usize;
        let clusters_to_skip = libm::floorf((offset / cluster_size) as f32) as usize;
        let mut offset_within_cluster = offset % cluster_size;

        let mut to_write = buffer.len();
        let mut writing_offset = 0;
        let last_cluster = self
            .filesystem
            .borrow()
            .last_cluster_in_chain(self.starting_cluster)?;

        let mut temp_buffer: Vec<u8> = vec![0; cluster_size];
        let temp_slice = temp_buffer.as_mut_slice();

        for cluster in self
            .filesystem
            .borrow()
            .get_clusters_for_file(self.starting_cluster)
            .skip(clusters_to_skip)
        {
            if to_write == 0 {
                break;
            }

            let copy_size = min(to_write, cluster_size - offset_within_cluster);

            if offset_within_cluster == 0 {
                if copy_size < cluster_size {
                    // Copy whole cluster to the temporary buffer
                    self.filesystem
                        .borrow()
                        .read_cluster_to(cluster, temp_slice)?;

                    // Overwrite read cluster with user supplied data starting at the writing_offset
                    temp_slice[0..copy_size]
                        .copy_from_slice(&buffer[writing_offset..(writing_offset + copy_size)]);

                    // Write cluster to the disk
                    self.filesystem
                        .borrow()
                        .write_cluster(cluster, temp_slice)?;

                    to_write -= copy_size;
                    writing_offset += copy_size;

                    // Start next read from first byte of next cluster
                    offset_within_cluster = 0;
                } else {
                    self.filesystem.borrow().write_cluster(
                        cluster,
                        &buffer[writing_offset..(writing_offset + cluster_size)],
                    )?;

                    to_write -= cluster_size;
                    writing_offset += cluster_size;
                }
            } else {
                // Copy whole cluster to the temporary buffer
                self.filesystem
                    .borrow()
                    .read_cluster_to(cluster, temp_slice)?;

                // Overwrite read cluster with user supplied data starting at the writing_offset
                temp_slice[offset_within_cluster..(offset_within_cluster + copy_size)]
                    .copy_from_slice(&buffer[writing_offset..(writing_offset + copy_size)]);

                // Write cluster to the disk
                self.filesystem
                    .borrow()
                    .write_cluster(cluster, temp_slice)?;

                to_write -= copy_size;
                writing_offset += copy_size;

                // Start next read from first byte of next cluster
                offset_within_cluster = 0;
            }
        }

        if self.file_size < (offset + buffer.len()) as u32 {
            // Adjust filesize in file entry
            let difference = (offset + buffer.len()) - self.file_size as usize;

            let old_file_entry = self.file_entry.clone();
            let mut new_file_entry = old_file_entry.clone();
            new_file_entry.file_size += difference as u32;
            self.file_size += difference as u32;

            self.filesystem.borrow_mut().serialize_file_entry(
                Some(&old_file_entry),
                &new_file_entry,
                self.file_entry_cluster,
            );

            self.file_entry = new_file_entry;
        }

        if to_write == 0 {
            return Ok(());
        }

        // Data does not fit into current file, so need to allocate new clusters at the end of the file
        let needed_clusters = ceil((to_write / cluster_size) as f64) as usize;
        let allocated_clusters: Vec<(usize, u32)> = self
            .filesystem
            .borrow_mut()
            .allocate_and_link_clusters(needed_clusters)?
            .collect();

        // Link current last cluster to the newly allocated chain of clusters
        self.filesystem
            .borrow()
            .write_fat_entry(last_cluster, allocated_clusters.first().unwrap().0 as u32)?;

        let mut temp_buffer: Vec<u8> = vec![0; cluster_size];
        let temp_slice = temp_buffer.as_mut_slice();

        // Perform write
        for new_cluster in allocated_clusters {
            let copy_size = min(to_write, cluster_size) - 1;

            // Overwrite read cluster with user supplied data starting at the writing_offset
            temp_slice[0..copy_size]
                .copy_from_slice(&buffer[writing_offset..(writing_offset + copy_size)]);

            // Write cluster to the disk
            self.filesystem
                .borrow()
                .write_cluster(new_cluster.0 as u32, temp_slice)?;

            to_write -= copy_size;
            writing_offset += copy_size;
        }

        Ok(())
    }

    fn delete(&mut self) -> Result<(), FileSystemError> {
        let mut fat = self.filesystem.borrow_mut();

        fat.remove_file_entry(&self.file_entry, self.file_entry_cluster)?;
        fat.mark_clusters_as_free(self.starting_cluster)?;

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

    fn move_to(&mut self, directory: &Self::Directory) -> Result<(), FileSystemError> {
        self.filesystem.borrow_mut().move_file(
            &self.file_entry,
            directory,
            self.file_entry_cluster,
        )?;

        Ok(())
    }

    fn shrink(&mut self, new_size: usize) -> Result<(), FileSystemError> {
        if self.file_size as usize <= new_size {
            return Err(FileSystemError::InvalidArgument);
        }

        let mut fat = self.filesystem.borrow_mut();
        let old_file_entry = self.file_entry.clone();
        let cluster_size = fat.bpb.bytes_per_sector * fat.bpb.sectors_per_cluster as u16;

        let current_last_cluster = self.file_size / cluster_size as u32;
        let new_last_cluster = new_size / cluster_size as usize;
        self.file_size = new_size as u32;
        self.file_entry.set_file_size(new_size as u32);

        // if new file size still fits in the same cluster, then just update file_size in file_entry and finish
        if current_last_cluster as usize == new_last_cluster {
            fat.serialize_file_entry(
                Some(&old_file_entry),
                &self.file_entry,
                self.file_entry_cluster,
            );

            return Ok(());
        }

        // if new file size is somewhere in previous clusters, then find last cluster, remove
        // subsequent clusters from FAT table and update file_size in file_entry

        let last_kept_cluster = fat
            .get_clusters_for_file(self.starting_cluster)
            .nth(new_last_cluster)
            .ok_or(FileSystemError::InvalidArgument)?;

        for cluster in fat
            .get_clusters_for_file(self.starting_cluster)
            .skip(new_last_cluster + 1)
        {
            fat.write_fat_entry(cluster, FAT_FREE_SECTOR)?;
        }

        fat.write_fat_entry(last_kept_cluster, FAT_END_OF_FILE_MARK)?;

        // Write changes to the disk
        fat.serialize_file_entry(
            Some(&old_file_entry),
            &self.file_entry,
            self.file_entry_cluster,
        );

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

    fn file_size(&self) -> usize {
        self.file_entry.file_size as usize
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

fn take_next_cluster<I: Iterator<Item = u32>>(
    current_run: &mut Option<(u32, u32)>,
    runs: &mut ContiguousClusterRuns<I>,
) -> Option<u32> {
    if current_run.is_none() {
        *current_run = runs.next();
    }

    let (first, count) = current_run.as_mut()?;
    let cluster = *first;
    if *count == 1 {
        *current_run = None;
    } else {
        *first += 1;
        *count -= 1;
    }

    Some(cluster)
}
