//! Memory restoration logic
//!
//! Handles premapping VMAs and populating them with page data from checkpoint images.

use crate::images::checkpoint::{CriuCheckpoint, Pagemap};
use crate::proto::VmaEntry as ProtoVma;
use crate::restore::args::VmaEntry;
use crate::restore::inject::find_bootstrap_gap;
use crate::Result;
use crust_syscall::constants::*;
use crust_syscall::syscalls;

const PAGE_SIZE: usize = 4096;

/// Premap all VMAs at safe addresses and populate with page data
///
/// For each VMA in the checkpoint:
/// 1. Find safe gap that won't conflict
/// 2. mmap at premap address with correct protections
/// 3. Write page data if VMA has pages
///
/// Returns list of VMA entries with premap addresses for restorer blob.
pub unsafe fn premap_and_populate_vmas(
    checkpoint: &CriuCheckpoint,
    self_pid: u32,
) -> Result<Vec<VmaEntry>> {
    let mm = &checkpoint.mm;
    let vmas_proto = mm.vmas.as_slice();
    let mut vma_entries = Vec::new();
    let mut pages_offset = 0usize;

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

        // Map at premap address as anonymous (we'll populate from pages data)
        // Force MAP_ANONYMOUS since we're restoring from checkpoint, not from files
        // Keep MAP_PRIVATE/MAP_SHARED from original flags
        let map_flags = if flags & MAP_SHARED != 0 {
            MAP_SHARED | MAP_ANONYMOUS | MAP_FIXED
        } else {
            MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED
        };

        // Temporarily add PROT_WRITE so we can populate page data
        // Restorer blob will restore final protections after mremap
        let premap_prot = prot | PROT_WRITE;

        let addr = syscalls::mmap(
            premap_addr,
            size,
            premap_prot,
            map_flags,
            -1,
            0,
        )
        .map_err(|e| crate::CrustError::InvalidImage {
            reason: format!("mmap failed for VMA 0x{:x}-0x{:x}: {:?}", start, end, e),
        })?;

        if addr != premap_addr {
            return Err(crate::CrustError::InvalidImage {
                reason: format!(
                    "mmap returned wrong address: expected 0x{:x}, got 0x{:x}",
                    premap_addr, addr
                ),
            });
        }

        // Populate with page data if this VMA has pages
        populate_vma_pages(
            premap_addr,
            start,
            size,
            &checkpoint.pagemap,
            &checkpoint.pages_data,
            &mut pages_offset,
        )?;

        vma_entries.push(VmaEntry {
            start: start as usize,
            end: end as usize,
            prot,
            flags,
            premap_addr,
        });
    }

    log::info!("Premapped {} VMAs successfully", vma_entries.len());
    Ok(vma_entries)
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
    // Use first available gap after 16MB mark
    const MIN_ADDR: usize = 0x0100_0000;
    find_bootstrap_gap(target_vmas, self_pid, MIN_ADDR, size)
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
        let offset_in_entry = if entry_start < vma_start {
            (vma_start - entry_start) as usize
        } else {
            0
        };

        let copy_size = (copy_end - copy_start) as usize;
        let src_offset = *pages_offset + offset_in_entry;
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

        // Advance offset by the amount we actually copied (not full entry size)
        *pages_offset += copy_size;
    }

    Ok(())
}

