//! Restorer blob injection
//!
//! This module handles injecting the restorer blob into a target process's
//! address space. The blob must be mapped to an address that doesn't conflict
//! with existing VMAs.

use crate::restorer_blob::RESTORER_BLOB;
use crate::Result;
use crate::proto::VmaEntry;
use std::fs;

/// Address space gap suitable for restorer blob injection
#[derive(Debug, Clone)]
pub struct AddressGap {
    pub start: usize,
    pub end: usize,
}

impl AddressGap {
    /// Size of this gap in bytes
    pub fn size(&self) -> usize {
        self.end - self.start
    }

    /// Check if this gap can fit the given size with alignment
    pub fn can_fit(&self, size: usize, align: usize) -> bool {
        let aligned_start = (self.start + align - 1) & !(align - 1);
        aligned_start + size <= self.end
    }

    /// Get aligned address within this gap
    pub fn aligned_addr(&self, align: usize) -> usize {
        (self.start + align - 1) & !(align - 1)
    }
}

/// Parse /proc/[pid]/maps to find gaps in address space
///
/// Returns list of gaps sorted by start address. Only includes gaps
/// larger than min_size.
pub fn find_address_gaps(pid: u32, min_size: usize) -> Result<Vec<AddressGap>> {
    let maps_path = format!("/proc/{}/maps", pid);
    let content = fs::read_to_string(&maps_path)
        .map_err(crate::CrustError::Io)?;

    let mut gaps = Vec::new();
    let mut prev_end: usize = 0;

    for line in content.lines() {
        // Parse address range (first field: "start-end")
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.is_empty() {
            continue;
        }

        let addr_range = parts[0];
        let addrs: Vec<&str> = addr_range.split('-').collect();
        if addrs.len() != 2 {
            continue;
        }

        let start = usize::from_str_radix(addrs[0], 16)
            .map_err(|_| crate::CrustError::InvalidImage {
                reason: format!("Invalid address in maps: {}", addrs[0])
            })?;
        let end = usize::from_str_radix(addrs[1], 16)
            .map_err(|_| crate::CrustError::InvalidImage {
                reason: format!("Invalid address in maps: {}", addrs[1])
            })?;

        // Record gap between previous mapping and this one
        if prev_end > 0 && start > prev_end {
            let gap_size = start - prev_end;
            if gap_size >= min_size {
                gaps.push(AddressGap {
                    start: prev_end,
                    end: start,
                });
            }
        }

        prev_end = end;
    }

    Ok(gaps)
}

/// Find suitable gap for restorer blob injection
///
/// Looks for gaps that can fit the blob with required alignment.
/// Prefers gaps in lower memory addresses for simplicity.
pub fn find_restorer_gap(pid: u32) -> Result<AddressGap> {
    const PAGE_SIZE: usize = 4096;
    let blob_size = RESTORER_BLOB.len();

    // Round up to page size
    let required_size = (blob_size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);

    let gaps = find_address_gaps(pid, required_size)?;

    // Find first gap that can fit the blob with page alignment
    gaps.into_iter()
        .find(|gap| gap.can_fit(required_size, PAGE_SIZE))
        .ok_or_else(|| crate::CrustError::InvalidImage {
            reason: format!(
                "No suitable gap found for restorer blob (need {} bytes)",
                required_size
            )
        })
}

/// VMA representation for gap finding
#[derive(Debug, Clone)]
struct Vma {
    start: usize,
    end: usize,
}

/// Parse /proc/[pid]/maps and return list of VMAs
///
/// Single responsibility: Parse maps file format into VMA list
fn parse_proc_maps(pid: u32) -> Result<Vec<Vma>> {
    let maps_path = format!("/proc/{}/maps", pid);
    let content = fs::read_to_string(&maps_path).map_err(crate::CrustError::Io)?;

    let mut vmas = Vec::new();
    for line in content.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.is_empty() {
            continue;
        }

        let addr_range = parts[0];
        let addrs: Vec<&str> = addr_range.split('-').collect();
        if addrs.len() != 2 {
            continue;
        }

        let start = usize::from_str_radix(addrs[0], 16).map_err(|_| {
            crate::CrustError::InvalidImage {
                reason: format!("Invalid address in maps: {}", addrs[0]),
            }
        })?;
        let end = usize::from_str_radix(addrs[1], 16).map_err(|_| {
            crate::CrustError::InvalidImage {
                reason: format!("Invalid address in maps: {}", addrs[1]),
            }
        })?;

        vmas.push(Vma { start, end });
    }

    Ok(vmas)
}

/// Convert protobuf VMAs to internal VMA format
///
/// Single responsibility: Type conversion
fn convert_vmas_from_proto(proto_vmas: &[VmaEntry]) -> Vec<Vma> {
    proto_vmas
        .iter()
        .map(|v| Vma {
            start: v.start as usize,
            end: v.end as usize,
        })
        .collect()
}

/// Find gap that doesn't conflict with two VMA lists
///
/// Walks target and self VMA lists simultaneously to find first gap that
/// fits before both lists' next VMA.
fn find_gap_in_two_lists(
    mut target_vmas: Vec<Vma>,
    mut self_vmas: Vec<Vma>,
    min_addr: usize,
    size: usize,
) -> Result<usize> {
    const TASK_SIZE: usize = 0x0000_7fff_ffff_f000; // x86_64: 128TB

    // Add sentinels
    target_vmas.push(Vma { start: TASK_SIZE, end: TASK_SIZE });
    self_vmas.push(Vma { start: TASK_SIZE, end: TASK_SIZE });

    let mut prev_end = min_addr;
    let mut self_idx = 0;
    let mut target_idx = 0;

    loop {
        let self_vma = &self_vmas[self_idx];
        let target_vma = &target_vmas[target_idx];

        // Check if gap fits before both VMAs
        if prev_end + size <= self_vma.start && prev_end + size <= target_vma.start {
            return Ok(prev_end);
        }

        // Advance the list with the earlier VMA
        if self_vma.start < target_vma.start {
            if prev_end < self_vma.end {
                prev_end = self_vma.end;
            }
            self_idx += 1;
            if self_idx >= self_vmas.len() || self_vmas[self_idx].start >= TASK_SIZE {
                break;
            }
        } else {
            if prev_end < target_vma.end {
                prev_end = target_vma.end;
            }
            target_idx += 1;
            if target_idx >= target_vmas.len() || target_vmas[target_idx].start >= TASK_SIZE {
                break;
            }
        }
    }

    Err(crate::CrustError::InvalidImage {
        reason: format!(
            "No suitable bootstrap gap found (need {} bytes, min_addr: 0x{:x})",
            size, min_addr
        ),
    })
}

/// Find bootstrap region that doesn't conflict with target or current process
///
/// Finds a gap that won't conflict with the target process's future VMAs
/// or the current process's existing VMAs.
pub fn find_bootstrap_gap(
    target_vmas: &[VmaEntry],
    self_pid: u32,
    min_addr: usize,
    size: usize,
) -> Result<usize> {
    let target_list = convert_vmas_from_proto(target_vmas);
    let self_list = parse_proc_maps(self_pid)?;
    find_gap_in_two_lists(target_list, self_list, min_addr, size)
}

/// Inject restorer blob into target process at specified address
///
/// Maps RWX anonymous memory and copies the blob bytes.
/// Returns the entry point address (base address of the mapping).
///
/// # Safety
/// This function performs raw memory mapping and must be called with
/// a valid target address that doesn't conflict with existing mappings.
pub unsafe fn inject_restorer_blob(target_addr: usize) -> Result<usize> {
    use crust_syscall::constants::*;
    use crust_syscall::syscalls;

    const PAGE_SIZE: usize = 4096;
    let blob_size = RESTORER_BLOB.len();

    // Round up to page size
    let map_size = (blob_size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);

    // Map RWX memory at target address
    let prot = PROT_READ | PROT_WRITE | PROT_EXEC;
    let flags = MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED;

    let addr = syscalls::mmap(
        target_addr,
        map_size,
        prot,
        flags,
        -1,  // fd = -1 for anonymous mapping
        0,   // offset
    ).map_err(|e| crate::CrustError::InvalidImage {
        reason: format!("mmap failed: {:?}", e)
    })?;

    if addr != target_addr {
        return Err(crate::CrustError::InvalidImage {
            reason: format!(
                "mmap returned wrong address: expected 0x{:x}, got 0x{:x}",
                target_addr, addr
            )
        });
    }

    // Copy blob to mapped region
    std::ptr::copy_nonoverlapping(
        RESTORER_BLOB.as_ptr(),
        addr as *mut u8,
        blob_size,
    );

    Ok(addr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_address_gap() {
        let gap = AddressGap {
            start: 0x1000,
            end: 0x3000,
        };

        assert_eq!(gap.size(), 0x2000);
        assert!(gap.can_fit(0x1000, 0x1000));
        assert!(!gap.can_fit(0x3000, 0x1000));
        assert_eq!(gap.aligned_addr(0x1000), 0x1000);

        let gap2 = AddressGap {
            start: 0x1500,
            end: 0x3000,
        };
        assert_eq!(gap2.aligned_addr(0x1000), 0x2000);
    }

    #[test]
    fn test_find_address_gaps_self() {
        // Find gaps in current process
        let gaps = find_address_gaps(std::process::id(), 4096).unwrap();

        // Should find at least some gaps
        assert!(!gaps.is_empty());

        // Gaps should be sorted
        for i in 1..gaps.len() {
            assert!(gaps[i].start > gaps[i-1].end);
        }

        // All gaps should be at least min_size
        for gap in &gaps {
            assert!(gap.size() >= 4096);
        }
    }

    #[test]
    fn test_find_restorer_gap() {
        // Should find a gap suitable for the restorer blob
        let gap = find_restorer_gap(std::process::id()).unwrap();

        assert!(gap.size() >= RESTORER_BLOB.len());
        assert!(gap.can_fit(RESTORER_BLOB.len(), 4096));
    }

    #[test]
    #[ignore]  // Requires root and modifies address space
    fn test_inject_restorer_blob() {
        let gap = find_restorer_gap(std::process::id()).unwrap();
        let target_addr = gap.aligned_addr(4096);

        unsafe {
            let entry_point = inject_restorer_blob(target_addr).unwrap();
            assert_eq!(entry_point, target_addr);

            // Verify blob was copied correctly
            let mapped_slice = std::slice::from_raw_parts(
                entry_point as *const u8,
                RESTORER_BLOB.len()
            );
            assert_eq!(mapped_slice, RESTORER_BLOB);
        }
    }
}
