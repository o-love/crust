//! Premap layout management with RAII semantics
//!
//! This module provides the PremapLayout structure for managing VMA premapping
//! in the parent process before forking. All mappings are owned by this struct
//! and automatically cleaned up on error via Drop.

use crate::images::checkpoint::{CriuCheckpoint, Pagemap};
use crate::proto::VmaEntry as ProtoVma;
use crate::restore::args::VmaEntry;
use crate::restore::inject::find_bootstrap_gap;
use crate::Result;
use crust_syscall::constants::*;
use crust_syscall::syscalls;

const PAGE_SIZE: usize = 4096;
const MIN_BLOB_ADDR: usize = 0x7000_0000_0000;
const MIN_PREMAP_ADDR: usize = 0x0100_0000; // 16MB

/// Owns all premap state for a process restore
///
/// This structure manages the complete memory layout for restore:
/// - Premapped VMAs at temporary addresses
/// - Restorer blob location
/// - Bootstrap region for args and VMA array
///
/// RAII: All mappings are automatically cleaned up via Drop if restore fails.
pub struct PremapLayout {
    /// VMA entries with premap addresses (for restorer blob)
    pub vmas: Vec<VmaEntry>,

    /// Address where restorer blob should be mapped
    pub blob_addr: usize,

    /// Size of blob region
    pub blob_size: usize,

    /// Address where bootstrap args + VMA array should be written
    pub bootstrap_addr: usize,

    /// Size of bootstrap region
    pub bootstrap_size: usize,

    /// Whether this layout has been transferred to child (prevents double-unmap)
    transferred: bool,
}

impl PremapLayout {
    /// Create and execute complete premap layout in parent process
    ///
    /// This function:
    /// 1. Premaps all VMAs to safe temporary addresses
    /// 2. Populates VMAs with page data from checkpoint
    /// 3. Finds gaps for blob and bootstrap regions
    /// 4. Maps blob and bootstrap regions
    ///
    /// All mappings will be inherited by child via fork's COW.
    pub unsafe fn create_and_map(checkpoint: &CriuCheckpoint, self_pid: u32) -> Result<Self> {
        log::info!("Creating premap layout in parent process");

        // Step 1: Premap all VMAs and populate with page data
        let vmas = premap_and_populate_vmas(checkpoint, self_pid)?;

        // Step 2: Find gaps for blob and bootstrap
        let blob_size = {
            use crate::restorer_blob::RESTORER_SIZE;
            (RESTORER_SIZE + PAGE_SIZE - 1) & !(PAGE_SIZE - 1) // Round up to page size
        };

        let bootstrap_size = 64 * 1024; // 64KB for args + VMA array

        log::debug!("Finding gaps for blob ({} bytes) and bootstrap ({} bytes)",
                   blob_size, bootstrap_size);

        let blob_addr = find_bootstrap_gap(
            &checkpoint.mm.vmas,
            self_pid,
            MIN_BLOB_ADDR,
            blob_size,
        )?;

        let bootstrap_addr = find_bootstrap_gap(
            &checkpoint.mm.vmas,
            self_pid,
            blob_addr + blob_size + PAGE_SIZE,
            bootstrap_size,
        )?;

        log::info!("Blob region: 0x{:x} ({} bytes)", blob_addr, blob_size);
        log::info!("Bootstrap region: 0x{:x} ({} bytes)", bootstrap_addr, bootstrap_size);

        // Step 3: Map blob region (RWX for now, will contain executable code)
        let blob_ptr = syscalls::mmap(
            blob_addr,
            blob_size,
            PROT_READ | PROT_WRITE | PROT_EXEC,
            MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
            -1,
            0,
        ).map_err(|e| crate::CrustError::InvalidImage {
            reason: format!("Failed to map blob region at 0x{:x}: {:?}", blob_addr, e),
        })?;

        if blob_ptr != blob_addr {
            return Err(crate::CrustError::InvalidImage {
                reason: format!("Blob mmap returned wrong address: expected 0x{:x}, got 0x{:x}",
                               blob_addr, blob_ptr),
            });
        }

        log::debug!("Mapped blob region at 0x{:x}", blob_addr);

        // Copy restorer blob code to the mapped region
        {
            use crate::restorer_blob::RESTORER_BLOB;
            std::ptr::copy_nonoverlapping(
                RESTORER_BLOB.as_ptr(),
                blob_addr as *mut u8,
                RESTORER_BLOB.len(),
            );
            log::debug!("Copied restorer blob ({} bytes) to 0x{:x}", RESTORER_BLOB.len(), blob_addr);
        }

        // Step 4: Map bootstrap region (RW for args and VMA array)
        let bootstrap_ptr = syscalls::mmap(
            bootstrap_addr,
            bootstrap_size,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
            -1,
            0,
        ).map_err(|e| crate::CrustError::InvalidImage {
            reason: format!("Failed to map bootstrap region at 0x{:x}: {:?}", bootstrap_addr, e),
        })?;

        if bootstrap_ptr != bootstrap_addr {
            return Err(crate::CrustError::InvalidImage {
                reason: format!("Bootstrap mmap returned wrong address: expected 0x{:x}, got 0x{:x}",
                               bootstrap_addr, bootstrap_ptr),
            });
        }

        log::debug!("Mapped bootstrap region at 0x{:x}", bootstrap_addr);

        Ok(Self {
            vmas,
            blob_addr,
            blob_size,
            bootstrap_addr,
            bootstrap_size,
            transferred: false,
        })
    }

    /// Mark layout as transferred to child (disables Drop cleanup)
    ///
    /// Call this after successful fork - child now owns the mappings,
    /// parent should not unmap them.
    pub fn mark_transferred(&mut self) {
        self.transferred = true;
        log::debug!("Premap layout marked as transferred to child");
    }

    /// Get the number of VMAs in this layout
    pub fn vma_count(&self) -> usize {
        self.vmas.len()
    }
}

impl Drop for PremapLayout {
    fn drop(&mut self) {
        // Only unmap if we haven't transferred to child
        if !self.transferred {
            log::warn!("PremapLayout dropped before transfer - cleaning up {} VMAs", self.vmas.len());

            unsafe {
                // Unmap all premap VMAs
                for vma in &self.vmas {
                    let _ = libc::munmap(
                        vma.premap_addr as *mut libc::c_void,
                        vma.len(),
                    );
                }

                // Unmap blob region
                let _ = libc::munmap(
                    self.blob_addr as *mut libc::c_void,
                    self.blob_size,
                );

                // Unmap bootstrap region
                let _ = libc::munmap(
                    self.bootstrap_addr as *mut libc::c_void,
                    self.bootstrap_size,
                );
            }
        }
    }
}

/// Premap all VMAs at safe addresses and populate with page data
///
/// For each VMA in the checkpoint:
/// 1. Find safe gap that won't conflict
/// 2. mmap at premap address with correct protections
/// 3. Write page data if VMA has pages
///
/// Returns list of VMA entries with premap addresses for restorer blob.
unsafe fn premap_and_populate_vmas(
    checkpoint: &CriuCheckpoint,
    self_pid: u32,
) -> Result<Vec<VmaEntry>> {
    let mm = &checkpoint.mm;
    let vmas_proto = mm.vmas.as_slice();
    let mut vma_entries = Vec::new();
    let mut pages_offset = 0usize;
    let mut entries_started = std::collections::HashSet::new();

    log::info!("Premapping {} VMAs", vmas_proto.len());

    for (idx, vma_proto) in vmas_proto.iter().enumerate() {
        let start = vma_proto.start;
        let end = vma_proto.end;
        let size = (end - start) as usize;

        // Extract protection and flags from VMA entry
        let prot = vma_proto.prot as i32;
        let flags = vma_proto.flags as i32;

        log::debug!(
            "  [{}] VMA 0x{:x}-0x{:x} ({} bytes) prot=0x{:x} flags=0x{:x}",
            idx,
            start,
            end,
            size,
            prot,
            flags
        );

        // Find safe premap address
        let premap_addr = find_premap_address(vmas_proto, self_pid, size)?;

        log::debug!("    Premapping at 0x{:x}", premap_addr);

        // Determine if this VMA is file-backed or anonymous
        // File-backed VMAs have MAP_PRIVATE/MAP_SHARED without MAP_ANONYMOUS
        let is_file_backed = (flags & MAP_ANONYMOUS) == 0;

        // For MVP: hardcode sleeper binary path for file-backed mappings
        // TODO: Parse exe_file_id from mm_entry and map to actual file path
        let file_path = "/home/vince/crust/test/sleeper";

        // Temporarily add PROT_WRITE so we can populate page data (overlay dirty pages)
        let premap_prot = prot | PROT_WRITE;

        let addr = if is_file_backed {
            // Map from original file with correct offset
            // pgoff in checkpoint is already in bytes (not page units)
            let file_offset = vma_proto.pgoff;

            log::debug!("    File-backed VMA - mapping from {} offset 0x{:x} (pgoff={})",
                       file_path, file_offset, vma_proto.pgoff);

            // Open file (will be closed when fd goes out of scope)
            let fd = std::fs::OpenOptions::new()
                .read(true)
                .open(file_path)
                .map_err(|e| crate::CrustError::InvalidImage {
                    reason: format!("Failed to open {} for VMA restore: {}", file_path, e),
                })?;

            use std::os::unix::io::AsRawFd;
            let raw_fd = fd.as_raw_fd();

            // Map file at premap address
            // CRITICAL: Use MAP_POPULATE to prefault all file pages into memory
            // This causes them to become anonymous (COW'd) before fork,
            // ensuring child can access all code pages after mremap
            let map_flags = if flags & MAP_SHARED != 0 {
                MAP_SHARED | MAP_FIXED | MAP_POPULATE
            } else {
                MAP_PRIVATE | MAP_FIXED | MAP_POPULATE
            };

            log::debug!("    Using MAP_POPULATE to prefault all {} bytes from file", size);

            syscalls::mmap(
                premap_addr,
                size,
                premap_prot,
                map_flags,
                raw_fd,
                file_offset as i64,
            )
            .map_err(|e| crate::CrustError::InvalidImage {
                reason: format!("mmap file-backed failed for VMA 0x{:x}-0x{:x}: {:?}",
                               start, end, e),
            })?
        } else {
            // Anonymous mapping - allocate new memory
            let map_flags = if flags & MAP_SHARED != 0 {
                MAP_SHARED | MAP_ANONYMOUS | MAP_FIXED
            } else {
                MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED
            };

            syscalls::mmap(
                premap_addr,
                size,
                premap_prot,
                map_flags,
                -1,
                0,
            )
            .map_err(|e| crate::CrustError::InvalidImage {
                reason: format!("mmap anonymous failed for VMA 0x{:x}-0x{:x}: {:?}",
                               start, end, e),
            })?
        };

        if addr != premap_addr {
            return Err(crate::CrustError::InvalidImage {
                reason: format!(
                    "mmap returned wrong address: expected 0x{:x}, got 0x{:x}",
                    premap_addr, addr
                ),
            });
        }

        log::debug!("mmap returned 0x{:x} (expected 0x{:x})", addr, premap_addr);

        // Verify the mapping actually exists in /proc/self/maps
        if let Ok(maps) = std::fs::read_to_string("/proc/self/maps") {
            if verify_addresses_in_maps(&maps, &[premap_addr]) {
                log::debug!("Verified premap at 0x{:x} exists in /proc/self/maps", premap_addr);
            } else {
                log::error!("Premap at 0x{:x} not found in /proc/self/maps", premap_addr);
                log::error!("Maps content:\n{}", maps);
            }
        }

        // Populate with page data if this VMA has pages
        populate_vma_pages(
            premap_addr,
            start,
            size,
            &checkpoint.pagemap,
            &checkpoint.pages_data,
            &mut pages_offset,
            &mut entries_started,
        )?;

        // Verify mapping still exists after populate
        if let Ok(maps) = std::fs::read_to_string("/proc/self/maps") {
            if !verify_addresses_in_maps(&maps, &[premap_addr]) {
                log::error!("Premap at 0x{:x} disappeared after populate_vma_pages", premap_addr);
            }
        }

        vma_entries.push(VmaEntry {
            start: start as usize,
            end: end as usize,
            prot,
            flags,
            premap_addr,
        });
    }

    log::info!("Premapped {} VMAs successfully", vma_entries.len());

    // Final verification: check all premap VMAs still exist in /proc/self/maps
    // Note: Kernel may merge adjacent VMAs with compatible permissions,
    // so we check if addresses are *contained* in VMA ranges, not exact matches
    if let Ok(maps) = std::fs::read_to_string("/proc/self/maps") {
        let premap_addrs: Vec<usize> = vma_entries.iter().map(|e| e.premap_addr).collect();
        if verify_addresses_in_maps(&maps, &premap_addrs) {
            log::info!("All {} premap VMAs verified in /proc/self/maps (kernel may have merged some)", vma_entries.len());
        } else {
            log::error!("Some premap VMAs missing from /proc/self/maps");
        }
    }

    Ok(vma_entries)
}

/// Parse /proc/*/maps and check if all addresses are covered by VMAs
///
/// Returns true if all addresses are found within VMA ranges (accounting for kernel VMA merging)
fn verify_addresses_in_maps(maps_content: &str, addresses: &[usize]) -> bool {
    // Parse each line to extract VMA ranges
    let mut vma_ranges: Vec<(usize, usize)> = Vec::new();

    for line in maps_content.lines() {
        // Format: "start-end perms ..."
        // Example: "01000000-01001000 rw-p ..."
        if let Some(range_part) = line.split_whitespace().next() {
            if let Some((start_str, end_str)) = range_part.split_once('-') {
                if let (Ok(start), Ok(end)) = (
                    usize::from_str_radix(start_str, 16),
                    usize::from_str_radix(end_str, 16)
                ) {
                    vma_ranges.push((start, end));
                }
            }
        }
    }

    // Check each address is contained in some VMA range
    for &addr in addresses {
        let found = vma_ranges.iter().any(|(start, end)| addr >= *start && addr < *end);
        if !found {
            log::error!("Address 0x{:x} not found in any VMA range", addr);
            return false;
        }
    }

    true
}

/// Find safe address to premap a VMA
///
/// Must not conflict with:
/// - Target process's final VMA addresses
/// - Current process's existing VMAs
fn find_premap_address(
    target_vmas: &[ProtoVma],
    self_pid: u32,
    size: usize,
) -> Result<usize> {
    find_bootstrap_gap(target_vmas, self_pid, MIN_PREMAP_ADDR, size)
}

/// Populate premapped VMA with page data from checkpoint
///
/// Finds pagemap entries that overlap with this VMA and copies
/// the corresponding page data from pages_data buffer.
fn populate_vma_pages(
    premap_addr: usize,
    vma_start: u64,
    vma_size: usize,
    pagemap: &Pagemap,
    pages_data: &[u8],
    pages_offset: &mut usize,
    entries_started: &mut std::collections::HashSet<usize>,
) -> Result<()> {
    let vma_end = vma_start + vma_size as u64;

    for (entry_idx, entry) in pagemap.entries.iter().enumerate() {
        let entry_start = entry.vaddr;
        let nr_pages = entry.nr_pages.or(Some(entry.compat_nr_pages as u64)).unwrap();
        let entry_end = entry_start + (nr_pages * PAGE_SIZE as u64);
        let entry_size = (nr_pages as usize) * PAGE_SIZE;

        log::debug!(
            "      Entry[{}]: vaddr=0x{:x} pages={} offset={} entry_size={}",
            entry_idx,
            entry_start,
            nr_pages,
            *pages_offset,
            entry_size
        );

        // Skip if this pagemap entry doesn't overlap with current VMA
        if entry_end <= vma_start || entry_start >= vma_end {
            log::debug!("        Skipped (no overlap)");
            continue;
        }

        // This entry overlaps with our VMA - calculate what to copy
        let copy_start = if entry_start >= vma_start {
            entry_start
        } else {
            vma_start
        };
        let copy_end = if entry_end <= vma_end {
            entry_end
        } else {
            vma_end
        };

        // Calculate offset within VMA for destination
        let offset_in_vma = (copy_start - vma_start) as usize;

        // Calculate offset within this pagemap entry's data for source
        // NOTE: offset_in_entry tells us where in the entry's data this copy starts
        let offset_in_entry = if entry_start < vma_start {
            (vma_start - entry_start) as usize
        } else {
            0
        };

        let copy_size = (copy_end - copy_start) as usize;
        // BUG FIX: Only add offset_in_entry the FIRST time we process this entry.
        // For subsequent VMAs that overlap the same entry, pages_offset has already
        // been advanced, so we should NOT add offset_in_entry again.
        let is_first_time = entries_started.insert(entry_idx);
        let src_offset = if is_first_time {
            *pages_offset + offset_in_entry
        } else {
            *pages_offset
        };
        let dest_ptr = (premap_addr + offset_in_vma) as *mut u8;

        if src_offset + copy_size > pages_data.len() {
            return Err(crate::CrustError::InvalidImage {
                reason: format!(
                    "Page data overflow: VMA 0x{:x}-0x{:x}, entry[{}] vaddr=0x{:x} nr_pages={}, \
                     src_offset={} copy_size={} total={} (trying to read {}..{})",
                    vma_start, vma_start + vma_size as u64,
                    entry_idx, entry_start, nr_pages,
                    src_offset, copy_size, pages_data.len(),
                    src_offset, src_offset + copy_size
                ),
            });
        }

        log::debug!(
            "    Copying {} bytes of page data to 0x{:x} (vaddr 0x{:x})",
            copy_size,
            dest_ptr as usize,
            copy_start
        );

        unsafe {
            std::ptr::copy_nonoverlapping(
                pages_data[src_offset..].as_ptr(),
                dest_ptr,
                copy_size,
            );
        }

        // DEBUG: Check if we just wrote the stdout pointer location (0x4aa6d0)
        if copy_start <= 0x4aa6d0 && copy_end > 0x4aa6d0 {
            let offset_in_copy = (0x4aa6d0 - copy_start) as usize;
            let ptr_location = (dest_ptr as usize + offset_in_copy) as *const u64;
            let value = unsafe { *ptr_location };
            let src_in_pages = src_offset + offset_in_copy;
            let expected_value = if src_in_pages + 8 <= pages_data.len() {
                unsafe { *(pages_data[src_in_pages..].as_ptr() as *const u64) }
            } else {
                0xdeadbeef
            };
            log::warn!("Wrote stdout pointer at vaddr 0x{:x} (premap 0x{:x})",
                      0x4aa6d0, ptr_location as usize);
            log::warn!("  Wrote value: 0x{:x}", value);
            log::warn!("  Source offset in pages_data: {} (0x{:x})", src_in_pages, src_in_pages);
            log::warn!("  Expected value from pages_data: 0x{:x}", expected_value);
            log::warn!("  Entry: vaddr=0x{:x} nr_pages={} offset_in_entry={}",
                      entry_start, nr_pages, offset_in_entry);
        }

        // Advance offset by the amount we actually copied (not full entry size)
        *pages_offset += copy_size;
    }

    Ok(())
}
