// CRIU checkpoint data structures
use crate::error::Result;
use crate::proto::{PstreeEntry, CoreEntry, MmEntry, PagemapEntry};

pub struct Pagemap {
    pub pages_id: u32,
    pub entries: Vec<PagemapEntry>,
}

/// CRIU checkpoint
pub struct CriuCheckpoint {
    pub pstree: PstreeEntry,
    pub core: CoreEntry,
    pub mm: MmEntry,
    pub pagemap: Pagemap,
    pub pages_data: Vec<u8>,
}

impl CriuCheckpoint {
    /// Display checkpoint information for debugging
    pub fn display(&self) -> Result<()> {
        // Process info
        log::debug!("Process:");
        log::debug!("PID: {}", self.pstree.pid);

        // CPU state
        if let Some(thread_info) = &self.core.thread_info {
            let gpregs = &thread_info.gpregs;
            log::debug!("");
            log::debug!("CPU State:");
            log::debug!("RIP: 0x{:016x}", gpregs.ip);
            log::debug!("RSP: 0x{:016x}", gpregs.sp);
            log::debug!("RBP: 0x{:016x}", gpregs.bp);
            log::debug!("RAX: 0x{:016x}", gpregs.ax);
            log::debug!("RBX: 0x{:016x}", gpregs.bx);
            log::debug!("RCX: 0x{:016x}", gpregs.cx);
            log::debug!("RDX: 0x{:016x}", gpregs.dx);
        }

        // Memory regions
        log::debug!("");
        log::debug!("Memory Regions: {} VMAs", self.mm.vmas.len());

        // Display each VMA
        for (i, vma) in self.mm.vmas.iter().enumerate() {
            let size = vma.end - vma.start;
            let prot_str = format!(
                "{}{}{}",
                if vma.prot & 1 != 0 { "r" } else { "-" },
                if vma.prot & 2 != 0 { "w" } else { "-" },
                if vma.prot & 4 != 0 { "x" } else { "-" }
            );
            log::debug!(
                "[{:2}] 0x{:016x}-0x{:016x} ({:8} bytes) {}",
                i, vma.start, vma.end, size, prot_str
            );
        }

        // Page data
        const PAGE_SIZE: usize = 4096;
        let total_pages: u64 = self.pagemap.entries.iter()
            .map(|e| e.nr_pages.unwrap_or(e.compat_nr_pages as u64))
            .sum();
        let total_bytes = total_pages as usize * PAGE_SIZE;

        log::debug!("");
        log::debug!("Page Data:");
        log::debug!("Total pages: {}", total_pages);
        log::debug!("Total memory: {} bytes ({:.2} MB)", total_bytes, total_bytes as f64 / 1024.0 / 1024.0);
        log::debug!("Pagemap entries: {}", self.pagemap.entries.len());

        Ok(())
    }
}
