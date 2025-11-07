// CRIU image file reader
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use prost::Message;

use crate::error::{CrustError, Result};
use crate::proto::{InventoryEntry, PstreeEntry, CoreEntry, MmEntry, PagemapHead, PagemapEntry};
use super::checkpoint::{CriuCheckpoint, Pagemap};

// CRIU image magic: 0x54564319 (not currently validated)

pub struct ImageDir {
    path: PathBuf,
}

impl ImageDir {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        if !path.is_dir() {
            return Err(CrustError::ImageNotFound {
                path: path.display().to_string(),
            });
        }
        Ok(ImageDir { path })
    }

    fn read_image_file(&self, filename: &str) -> Result<Vec<u8>> {
        let img_path = self.path.join(filename);
        let mut file = File::open(&img_path).map_err(|_| CrustError::ImageNotFound {
            path: img_path.display().to_string(),
        })?;

        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)?;

        // CRIU image format:
        // - 4 bytes: magic number
        // - 4 bytes: image type identifier
        // - 4 bytes: payload size (little-endian u32)
        // - N bytes: protobuf data

        if buffer.len() < 12 {
            return Err(CrustError::InvalidImage {
                reason: format!("{} is too small (< 12 bytes)", filename),
            });
        }

        // Skip the 12-byte header and return just the protobuf payload
        Ok(buffer[12..].to_vec())
    }

    /// Read inventory.img to get checkpoint metadata
    pub fn read_inventory(&self) -> Result<InventoryEntry> {
        let data = self.read_image_file("inventory.img")?;
        let inventory = InventoryEntry::decode(&data[..]).map_err(|e| {
            CrustError::InvalidImage {
                reason: format!("Failed to decode inventory: {}", e),
            }
        })?;
        Ok(inventory)
    }

    /// Read pstree.img to get process tree
    pub fn read_pstree(&self) -> Result<PstreeEntry> {
        let data = self.read_image_file("pstree.img")?;
        let pstree = PstreeEntry::decode(&data[..]).map_err(|e| {
            CrustError::InvalidImage {
                reason: format!("Failed to decode pstree: {}", e),
            }
        })?;
        Ok(pstree)
    }

    /// Read core image for a specific PID
    pub fn read_core(&self, pid: u32) -> Result<CoreEntry> {
        let filename = format!("core-{}.img", pid);
        let data = self.read_image_file(&filename)?;
        let core = CoreEntry::decode(&data[..]).map_err(|e| {
            CrustError::InvalidImage {
                reason: format!("Failed to decode core: {}", e),
            }
        })?;
        Ok(core)
    }

    /// Read memory map for a specific PID
    pub fn read_mm(&self, pid: u32) -> Result<MmEntry> {
        let filename = format!("mm-{}.img", pid);
        let data = self.read_image_file(&filename)?;
        let mm = MmEntry::decode(&data[..]).map_err(|e| {
            CrustError::InvalidImage {
                reason: format!("Failed to decode mm: {}", e),
            }
        })?;
        Ok(mm)
    }

    /// Read pagemap for a specific PID
    /// Returns PagemapHead and vector of PagemapEntry
    pub fn read_pagemap(&self, pid: u32) -> Result<Pagemap> {
        let filename = format!("pagemap-{}.img", pid);
        let img_path = self.path.join(&filename);
        let mut file = File::open(&img_path).map_err(|_| CrustError::ImageNotFound {
            path: img_path.display().to_string(),
        })?;

        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)?;

        if buffer.len() < 12 {
            return Err(CrustError::InvalidImage {
                reason: format!("{} is too small (< 12 bytes)", filename),
            });
        }

        // Read the size of PagemapHead from bytes 8-11
        let head_size = u32::from_le_bytes([buffer[8], buffer[9], buffer[10], buffer[11]]) as usize;

        if buffer.len() < 12 + head_size {
            return Err(CrustError::InvalidImage {
                reason: format!("{} truncated (missing PagemapHead)", filename),
            });
        }

        // Decode PagemapHead
        let head_data = &buffer[12..12 + head_size];
        let head = PagemapHead::decode(head_data).map_err(|e| {
            CrustError::InvalidImage {
                reason: format!("Failed to decode PagemapHead: {}", e),
            }
        })?;

        // Parse stream of PagemapEntry messages
        // After PagemapHead, entries are stored with 4-byte size prefix (little-endian u32)
        let mut entries = Vec::new();
        let mut pos = 12 + head_size;

        while pos + 4 <= buffer.len() {
            // Read entry size (4 bytes, little-endian)
            let entry_size = u32::from_le_bytes([
                buffer[pos],
                buffer[pos + 1],
                buffer[pos + 2],
                buffer[pos + 3],
            ]) as usize;
            pos += 4;

            if pos + entry_size > buffer.len() {
                break; // Incomplete entry at end of file
            }

            // Decode the entry
            let entry_data = &buffer[pos..pos + entry_size];
            match PagemapEntry::decode(entry_data) {
                Ok(entry) => entries.push(entry),
                Err(e) => {
                    log::warn!("Failed to decode PagemapEntry at offset {}: {}", pos, e);
                    break;
                }
            }
            pos += entry_size;
        }

        Ok(Pagemap {
            pages_id: head.pages_id,
            entries,
        })
    }

    /// Read pages file containing actual memory data
    pub fn read_pages(&self, pages_id: u32) -> Result<Vec<u8>> {
        let filename = format!("pages-{}.img", pages_id);
        let img_path = self.path.join(&filename);
        let mut file = File::open(&img_path).map_err(|_| CrustError::ImageNotFound {
            path: img_path.display().to_string(),
        })?;

        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)?;

        // Pages file has same 12-byte header
        if buffer.len() < 12 {
            return Err(CrustError::InvalidImage {
                reason: format!("{} is too small (< 12 bytes)", filename),
            });
        }

        Ok(buffer[12..].to_vec())
    }

    /// Load a complete CRIU checkpoint
    pub fn load_checkpoint(&self) -> Result<CriuCheckpoint> {
        let pstree = self.read_pstree()?;
        let pid = pstree.pid;

        let core = self.read_core(pid)?;
        let mm = self.read_mm(pid)?;
        let pagemap = self.read_pagemap(pid)?;

        let pages_data = self.read_pages(pagemap.pages_id)?;

        Ok(CriuCheckpoint {
            pstree,
            core,
            mm,
            pagemap,
            pages_data,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}
