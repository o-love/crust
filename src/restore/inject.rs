//! Restorer blob injection
//!
//! This module handles injecting the restorer blob into a target process's
//! address space. The blob must be mapped to an address that doesn't conflict
//! with existing VMAs.

use crate::restorer_blob::{RESTORER_BLOB, RESTORER_ENTRY_OFFSET};
use crate::Result;
use crate::images::checkpoint::CriuCheckpoint;
use crate::restore::args::{TaskRestoreArgs, VmaEntry as ArgsVmaEntry};
use crate::restore::sigframe::RtSigframe64;
use crate::proto::VmaEntry as ProtoVmaEntry;
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
fn convert_vmas_from_proto(proto_vmas: &[ProtoVmaEntry]) -> Vec<Vma> {
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
    target_vmas: &[ProtoVmaEntry],
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

/// Execute the restorer blob in a child process
///
/// Uses ptrace to attach to the paused child, set its RIP to the blob,
/// and monitor execution through rt_sigreturn completion.
pub unsafe fn execute_restorer_blob(
    child_pid: i32,
    premap: &crate::restore::PremapLayout,
    checkpoint: &CriuCheckpoint,
) -> Result<()> {
    use crate::CrustError;

    log::info!("Attaching to child PID {} with ptrace...", child_pid);

    // Attach to child using PTRACE_SEIZE (non-stopping attach)
    if libc::ptrace(libc::PTRACE_SEIZE, child_pid, 0, 0) < 0 {
        return Err(CrustError::InvalidImage {
            reason: format!("PTRACE_SEIZE failed: {}", std::io::Error::last_os_error()),
        });
    }

    log::info!("Attached successfully, interrupting child...");

    // Interrupt the child to stop it
    if libc::ptrace(libc::PTRACE_INTERRUPT, child_pid, 0, 0) < 0 {
        return Err(CrustError::InvalidImage {
            reason: format!("PTRACE_INTERRUPT failed: {}", std::io::Error::last_os_error()),
        });
    }

    // Wait for child to stop
    let mut status = 0;
    if libc::waitpid(child_pid, &mut status, 0) < 0 {
        return Err(CrustError::InvalidImage {
            reason: "waitpid failed after PTRACE_INTERRUPT".to_string(),
        });
    }

    log::info!("Child stopped (status=0x{:x})", status);

    // BUILD ARGUMENTS FOR BLOB
    log::info!("Building arguments for restorer blob...");

    // 1. Build sigframe from checkpoint
    let mut sigframe = RtSigframe64::from_checkpoint(checkpoint)?;
    log::info!("Built sigframe ({} bytes)", std::mem::size_of::<RtSigframe64>());

    // 2. Calculate addresses in bootstrap region
    let args_addr = premap.bootstrap_addr;
    let vma_array_addr = args_addr + std::mem::size_of::<TaskRestoreArgs>();
    let vma_array_size = premap.vmas.len() * std::mem::size_of::<ArgsVmaEntry>();
    let sigframe_addr = (vma_array_addr + vma_array_size + 4095) & !4095;  // page-align

    log::info!("Bootstrap memory layout:");
    log::info!("  TaskRestoreArgs at 0x{:x}", args_addr);
    log::info!("  VMA array at 0x{:x} ({} entries)", vma_array_addr, premap.vmas.len());
    log::info!("  Sigframe at 0x{:x}", sigframe_addr);

    // 3. Build TaskRestoreArgs structure
    let thread_info = checkpoint.core.thread_info.as_ref()
        .ok_or_else(|| CrustError::InvalidImage {
            reason: "No thread_info in checkpoint".to_string(),
        })?;

    // Bootstrap region for unmap_old_vmas() must span from blob start to bootstrap end
    // This preserves both blob and args/sigframe in a single contiguous region

    // Calculate premap region bounds (min and max of all premapped VMAs)
    // Blob will use these to avoid unmapping premapped memory
    let (premap_start, premap_end) = premap.vmas.iter().fold(
        (usize::MAX, 0usize),
        |(min_addr, max_addr), vma| {
            let vma_start = vma.premap_addr;
            let vma_end = vma.premap_addr + vma.len();
            (min_addr.min(vma_start), max_addr.max(vma_end))
        }
    );

    let args = TaskRestoreArgs {
        bootstrap_base: premap.blob_addr,
        bootstrap_len: (premap.bootstrap_addr + premap.bootstrap_size) - premap.blob_addr,
        premap_addr: premap_start,
        premap_len: premap_end - premap_start,
        vma_count: premap.vmas.len(),
        vmas: vma_array_addr as *const ArgsVmaEntry,
        sigframe: sigframe_addr as *const u8,
        fs_base: thread_info.gpregs.fs_base,
        gs_base: thread_info.gpregs.gs_base,
    };

    log::info!("TaskRestoreArgs: vma_count={}, fs_base=0x{:x}",
               args.vma_count, args.fs_base);

    // 4. Set fpregs pointer before writing sigframe to child memory
    // CRITICAL: Must set fpregs to point to FPU state within the sigframe
    // The kernel's rt_sigreturn will dereference this pointer to restore FPU state
    sigframe.set_fpstate_pointer(sigframe_addr as u64);

    // 5. Write structures to child's memory via /proc/pid/mem
    log::info!("Writing args structures to child memory...");
    write_to_child_memory(child_pid, args_addr, &args)?;

    // Debug: log all VMA entries being passed to blob
    log::debug!("VMA entries being passed to blob:");
    for (i, vma) in premap.vmas.iter().enumerate() {
        log::debug!("  [{}] premap=0x{:x} -> final=0x{:x}-0x{:x} size=0x{:x} prot=0x{:x}",
                   i, vma.premap_addr, vma.start, vma.end, vma.end - vma.start, vma.prot);
    }

    write_slice_to_child_memory(child_pid, vma_array_addr, &premap.vmas)?;
    write_to_child_memory(child_pid, sigframe_addr, &sigframe)?;
    log::info!("All structures written successfully");

    // 5. Set registers: RIP=blob entry, RDI=args pointer
    let mut regs: libc::user_regs_struct = std::mem::zeroed();
    if libc::ptrace(
        libc::PTRACE_GETREGS,
        child_pid,
        std::ptr::null_mut::<libc::c_void>(),
        &mut regs as *mut _ as *mut libc::c_void,
    ) < 0 {
        return Err(CrustError::InvalidImage {
            reason: "Failed to get registers".to_string(),
        });
    }

    regs.rip = (premap.blob_addr + RESTORER_ENTRY_OFFSET) as u64;
    regs.rdi = args_addr as u64;  // ← THE CRITICAL FIX!

    log::info!("Setting RIP=0x{:x} (blob entry+{}), RDI=0x{:x} (args pointer)",
               regs.rip, RESTORER_ENTRY_OFFSET, regs.rdi);

    if libc::ptrace(
        libc::PTRACE_SETREGS,
        child_pid,
        std::ptr::null_mut::<libc::c_void>(),
        &regs as *const _ as *const libc::c_void,
    ) < 0 {
        return Err(CrustError::InvalidImage {
            reason: "Failed to set registers".to_string(),
        });
    }

    // Verify child has premap VMAs before starting blob
    // Note: Kernel may merge adjacent VMAs, so we check if addresses are contained in ranges
    log::info!("Verifying child's premap VMAs before blob execution...");
    if let Ok(child_maps) = std::fs::read_to_string(format!("/proc/{}/maps", child_pid)) {
        // Collect all premap addresses we expect to find
        let premap_addrs: Vec<usize> = premap.vmas.iter().map(|e| e.premap_addr).collect();

        log::debug!("Expected premap addresses: {:x?}", premap_addrs);

        // Show premap VMAs from child's maps
        log::debug!("Child premap VMAs (01xxxxxx, 70xxxxxx):");
        for line in child_maps.lines() {
            if line.starts_with("01") || line.starts_with("70") {
                log::debug!("  {}", line);
            }
        }

        // Parse child's maps to extract VMA ranges
        let mut vma_ranges: Vec<(usize, usize)> = Vec::new();
        for line in child_maps.lines() {
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

        // Check all premap addresses are contained in child's VMAs
        let mut found_count = 0;
        for &addr in &premap_addrs {
            if vma_ranges.iter().any(|(s, e)| addr >= *s && addr < *e) {
                found_count += 1;
            } else {
                log::warn!("Premap address 0x{:x} NOT found in child maps", addr);
            }
        }

        log::info!("Child PID {} has {}/{} premap VMAs verified (kernel may merge adjacent VMAs)",
                   child_pid, found_count, premap_addrs.len());

        if found_count == 0 {
            log::error!("Child has no premap VMAs before blob execution");
            log::error!("Child /proc/{}/maps:\n{}", child_pid, child_maps);
        } else if found_count < premap_addrs.len() {
            log::warn!("Some premap VMAs missing: {}/{} found", found_count, premap_addrs.len());
        } else {
            log::info!("Child premap VMAs verified, blob can proceed");
        }
    }

    log::info!("Starting blob execution with args...");

    // Continue child execution - blob will execute and call rt_sigreturn
    if libc::ptrace(libc::PTRACE_CONT, child_pid, 0, 0) < 0 {
        return Err(CrustError::InvalidImage {
            reason: format!("PTRACE_CONT failed: {}", std::io::Error::last_os_error()),
        });
    }

    log::info!("Child executing blob...");

    // After rt_sigreturn, child is restored and running independently
    // We don't wait for blob to "complete" because rt_sigreturn doesn't return!
    // Instead, give child time to execute blob, then detach and monitor

    // Small delay to let blob start execution
    std::thread::sleep(std::time::Duration::from_millis(50));

    // Detach from child immediately - it's restored and should run freely
    // NOTE: PTRACE_DETACH may fail with ESRCH if rt_sigreturn already detached the child
    // This is expected and not an error - it means restore succeeded!
    log::info!("Detaching from child to let it run restored code...");
    if libc::ptrace(libc::PTRACE_DETACH, child_pid, 0, 0) < 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ESRCH) {
            log::info!("Child already detached (expected after rt_sigreturn)");
        } else {
            log::warn!("PTRACE_DETACH failed: {}", err);
        }
    } else {
        log::info!("Detached successfully");
    }

    // Verify child process still exists
    if std::fs::metadata(format!("/proc/{}", child_pid)).is_ok() {
        log::info!("Child process {} running", child_pid);
        Ok(())
    } else {
        Err(CrustError::InvalidImage {
            reason: format!("Child process {} not found after restore", child_pid),
        })
    }
}

/// Write data to child process memory via /proc/pid/mem
///
/// This writes a structure to the child's address space at the specified address.
/// Uses /proc/pid/mem for direct memory access while process is ptraced.
unsafe fn write_to_child_memory<T: Sized>(pid: i32, addr: usize, data: &T) -> Result<()> {
    use std::io::{Seek, Write};

    let mem_path = format!("/proc/{}/mem", pid);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .open(&mem_path)
        .map_err(|e| crate::CrustError::InvalidImage {
            reason: format!("Failed to open {}: {}", mem_path, e),
        })?;

    file.seek(std::io::SeekFrom::Start(addr as u64))?;

    let bytes = std::slice::from_raw_parts(
        data as *const T as *const u8,
        std::mem::size_of::<T>()
    );

    file.write_all(bytes)?;
    Ok(())
}

/// Write slice data to child process memory via /proc/pid/mem
unsafe fn write_slice_to_child_memory<T: Sized>(pid: i32, addr: usize, data: &[T]) -> Result<()> {
    use std::io::{Seek, Write};

    let mem_path = format!("/proc/{}/mem", pid);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .open(&mem_path)
        .map_err(|e| crate::CrustError::InvalidImage {
            reason: format!("Failed to open {}: {}", mem_path, e),
        })?;

    file.seek(std::io::SeekFrom::Start(addr as u64))?;

    let bytes = std::slice::from_raw_parts(
        data.as_ptr() as *const u8,
        data.len() * std::mem::size_of::<T>()
    );

    file.write_all(bytes)?;
    Ok(())
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
