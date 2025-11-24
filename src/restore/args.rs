//! Restorer blob arguments and data structures
//!
//! These structures match the ones in crust-restorer and are used to pass
//! data from the parent process to the restorer blob.

/// Task restore arguments passed to restorer blob
///
/// This structure is passed to the blob's _start() function via RDI register.
/// It must match the definition in crust-restorer/src/lib.rs exactly.
#[repr(C)]
#[derive(Debug, Clone)]
pub struct TaskRestoreArgs {
    /// Base address of bootstrap region (includes blob + args, for unmapping parent memory)
    pub bootstrap_base: usize,
    /// Length of bootstrap region (from blob start to bootstrap end)
    pub bootstrap_len: usize,
    /// Base address of premap region (where VMAs are temporarily mapped)
    pub premap_addr: usize,
    /// Length of premap region (total size of all premapped VMAs)
    pub premap_len: usize,
    /// Number of VMAs to restore
    pub vma_count: usize,
    /// Pointer to VMA array (must be valid in target process)
    pub vmas: *const VmaEntry,
    /// Pointer to sigframe for rt_sigreturn (must be 64-byte aligned)
    pub sigframe: *const u8,
    /// FS base register value (for TLS)
    pub fs_base: u64,
    /// GS base register value (for TLS)
    pub gs_base: u64,
}

/// VMA entry describing a memory region to restore
///
/// Describes a virtual memory area that needs to be restored to its final
/// address via mremap. Must match crust-restorer/src/lib.rs definition.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct VmaEntry {
    /// Final start address
    pub start: usize,
    /// Final end address (exclusive)
    pub end: usize,
    /// Protection flags (PROT_READ | PROT_WRITE | PROT_EXEC)
    pub prot: i32,
    /// Mapping flags (MAP_PRIVATE | MAP_ANONYMOUS, etc)
    pub flags: i32,
    /// Address where VMA was premapped (before mremap)
    pub premap_addr: usize,
}

impl VmaEntry {
    /// Create a new VMA entry
    pub fn new(start: usize, end: usize, prot: i32, flags: i32, premap_addr: usize) -> Self {
        Self {
            start,
            end,
            prot,
            flags,
            premap_addr,
        }
    }

    /// Size of this VMA in bytes
    pub fn len(&self) -> usize {
        self.end - self.start
    }

    /// Check if VMA is empty
    pub fn is_empty(&self) -> bool {
        self.start >= self.end
    }
}

// Safety: TaskRestoreArgs can be safely sent between threads
// (though we won't actually do this in practice)
unsafe impl Send for TaskRestoreArgs {}
unsafe impl Sync for TaskRestoreArgs {}

// Compile-time verification of struct layout
#[cfg(test)]
mod layout_tests {
    use super::*;
    use std::mem;

    #[test]
    fn verify_taskrestoreargs_layout() {
        // Blob expects these exact offsets
        assert_eq!(mem::offset_of!(TaskRestoreArgs, bootstrap_base), 0x00);
        assert_eq!(mem::offset_of!(TaskRestoreArgs, bootstrap_len), 0x08);
        assert_eq!(mem::offset_of!(TaskRestoreArgs, premap_addr), 0x10);
        assert_eq!(mem::offset_of!(TaskRestoreArgs, premap_len), 0x18);
        assert_eq!(mem::offset_of!(TaskRestoreArgs, vma_count), 0x20);
        assert_eq!(mem::offset_of!(TaskRestoreArgs, vmas), 0x28);
        assert_eq!(mem::offset_of!(TaskRestoreArgs, sigframe), 0x30);
        assert_eq!(mem::offset_of!(TaskRestoreArgs, fs_base), 0x38);
        assert_eq!(mem::offset_of!(TaskRestoreArgs, gs_base), 0x40);
        assert_eq!(mem::size_of::<TaskRestoreArgs>(), 72);
    }
}
