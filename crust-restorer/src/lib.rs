//! CRIU Restorer Blob
//!
//! This is a no_std, no_main PIE blob that executes inside the target process
//! to perform operations impossible from outside (rt_sigreturn, CLONE_THREAD, etc.).
//!
//! Design: Inline-only approach (Option 1 from restorer_blob_design.md)
//! Goal: Zero relocations by inlining all functions

#![no_std]
#![no_main]

use core::arch::asm;
use crust_syscall::*;

/// Task restore arguments passed from parent process
#[repr(C)]
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
    /// Pointer to VMA array (in bootstrap region)
    pub vmas: *const VmaEntry,
    /// Pointer to sigframe for rt_sigreturn
    pub sigframe: *const u8,
    /// FS base register value (for TLS)
    pub fs_base: u64,
    /// GS base register value (for TLS)
    pub gs_base: u64,
}

/// VMA entry describing memory region to restore
#[repr(C)]
pub struct VmaEntry {
    pub start: usize,
    pub end: usize,
    pub prot: i32,
    pub flags: i32,
    pub premap_addr: usize,  // Where it was premapped
}

/// Entry point called by parent process
///
/// This is the function the parent sets RIP to after injection.
/// It must never return.
#[no_mangle]
#[inline(never)]  // Entry point cannot be inlined
pub extern "C" fn _start(args_ptr: *const TaskRestoreArgs) -> ! {
    unsafe {
        let args = &*args_ptr;

        let _ = write(2, b"[BLOB] Entry\n".as_ptr(), 13);

        // Step 1: CRITICAL - Unregister rseq before unmapping (glibc 2.35+)
        // If rseq is registered and we unmap memory, kernel SIGSEGV when updating rseq
        unregister_libc_rseq();

        // Step 2: Unmap parent's memory (keep only premap + bootstrap)
        unmap_old_vmas(args);
        let _ = write(2, b"[BLOB] Unmap complete\n".as_ptr(), 22);

        // Step 3: Restore VMAs to final addresses via mremap (two-pass)
        restore_vmas(args);
        let _ = write(2, b"[BLOB] VMAs restored\n".as_ptr(), 21);

        // Step 4: Set fs_base via arch_prctl (TLS)
        // CRITICAL: Save args pointer before syscall clobbers registers
        let sigframe_ptr = args.sigframe;
        let fs_base = args.fs_base;

        if fs_base != 0 {
            const ARCH_SET_FS: u64 = 0x1002;
            const SYS_ARCH_PRCTL: u64 = 158;

            let ret: i64;
            asm!(
                "syscall",
                in("rax") SYS_ARCH_PRCTL,
                in("rdi") ARCH_SET_FS,
                in("rsi") fs_base,
                lateout("rax") ret,
                lateout("rcx") _,
                lateout("r11") _,
            );

            if ret < 0 {
                write(2, b"E".as_ptr(), 1);
                loop { core::hint::spin_loop(); }
            }
        }

        // Step 5: Jump to checkpoint RIP via rt_sigreturn
        // Pass sigframe pointer directly (args_ptr may be invalid after syscalls)
        let _ = write(2, b"[BLOB] Calling rt_sigreturn\n".as_ptr(), 28);
        restore_cpu_state(sigframe_ptr);
    }
}

/// Unregister rseq (restartable sequences) from glibc 2.35+
///
/// CRITICAL: Must be called BEFORE unmap_old_vmas() or kernel will SIGSEGV
/// when trying to update rseq structure in unmapped memory.
#[inline(always)]
unsafe fn unregister_libc_rseq() {
    // Note: For MVP, we're not tracking rseq from checkpoint
    // This is safe because:
    // 1. Parent process (crust) may have rseq registered
    // 2. We need to unregister parent's rseq before unmapping parent memory
    // 3. If child had rseq, it will be re-registered after rt_sigreturn
    //
    // For now, we attempt unregister but don't error if it fails
    // (it will fail with EINVAL if rseq wasn't registered)
    //
    // TODO: Full implementation would:
    // - Get rseq_abi_pointer from checkpoint
    // - Call sys_rseq() only if rseq was registered
    // - Match kernel semantics for when to check rseq_abi_pointer
    // We skip this for MVP since we don't have rseq in TaskRestoreArgs yet

    const SYS_RSEQ: i64 = 334;
    const RSEQ_FLAG_UNREGISTER: i32 = 1;

    // Try to unregister - ignore errors (EINVAL if not registered)
    // This is safe: unregistering when not registered is harmless
    let _ret: i64;
    asm!(
        "syscall",
        in("rax") SYS_RSEQ,
        in("rdi") 0,  // rseq_abi (NULL = try to unregister)
        in("rsi") 0,  // rseq_len
        in("rdx") RSEQ_FLAG_UNREGISTER,
        in("r10") 0,  // sig
        lateout("rax") _ret,
        lateout("rcx") _,
        lateout("r11") _,
    );
    // Ignore return value - may fail with EINVAL if not registered, which is fine
}

/// Unmap parent's memory (everything except bootstrap and premapped VMAs)
///
/// This unmaps all parent process memory except for:
/// 1. Premap region (where VMAs are currently located)
/// 2. Bootstrap region (this blob + args + sigframe)
///
/// Uses 3 munmap calls to preserve two regions while clearing rest of address space
#[inline(always)]
unsafe fn unmap_old_vmas(args: &TaskRestoreArgs) {
    // Three-phase unmapping preserves two regions (premap and bootstrap)
    // We need to determine which region comes first in address space

    let premap_start = args.premap_addr;
    let premap_end = args.premap_addr + args.premap_len;

    let bootstrap_start = args.bootstrap_base;
    let bootstrap_end = args.bootstrap_base + args.bootstrap_len;

    // task_size for x86_64: 128TB (0x800000000000)
    const TASK_SIZE: usize = 0x800000000000;

    // Sort regions by address to determine munmap order
    let (p1, s1, p2, s2) = if premap_start < bootstrap_start {
        (premap_start, premap_end - premap_start, bootstrap_start, bootstrap_end - bootstrap_start)
    } else {
        (bootstrap_start, bootstrap_end - bootstrap_start, premap_start, premap_end - premap_start)
    };

    // Unmap phase 1: [ NULL, p1 )
    // Skip page 0 (NULL), start at 0x1000
    if p1 > 0x1000 {
        let _ = munmap(0x1000, p1 - 0x1000);
    }

    // Unmap phase 2: [ p1 + s1, p2 )
    // This clears parent's binary, heap, libraries, etc.
    let gap_start = p1 + s1;
    if p2 > gap_start {
        let _ = munmap(gap_start, p2 - gap_start);
    }

    // Unmap phase 3: [ p2 + s2, task_size )
    let high_start = p2 + s2;
    if TASK_SIZE > high_start {
        // Note: munmap may return EINVAL for unmapped regions, but that's OK
        // We're cleaning up whatever is there.
        let _ = munmap(high_start, TASK_SIZE - high_start);
    }
}

/// Restore VMAs to their final addresses using mremap
///
/// Uses two-pass algorithm to avoid VMA overlap during remapping:
/// - Pass 1: Move left (final < premap) in ascending order
/// - Pass 2: Move right (final > premap) in descending order
#[inline(always)]
unsafe fn restore_vmas(args: &TaskRestoreArgs) {
    let vmas = core::slice::from_raw_parts(args.vmas, args.vma_count);

    // Pass 1: Shift VMAs to the left
    // Process VMAs moving left (final address < premap address) in ascending order
    // This prevents overwriting VMA sources during the move
    for vma in vmas.iter() {
        // Skip vDSO/vsyscall - kernel-provided special mappings
        if vma.start == 0xffffffffff600000 {
            continue;
        }

        // Only process VMAs moving left (final < premap)
        // While final <= premap, process; when final > premap, stop
        if vma.start > vma.premap_addr {
            break;  // Remaining VMAs are right-moving or stationary
        }

        // Skip VMAs already at correct address
        if vma.start == vma.premap_addr {
            continue;
        }

        // Move VMA from premap to final address
        remap_vma(vma);
    }

    // Pass 2: Shift VMAs to the right
    // Process VMAs moving right (final address > premap address) in descending order
    // This prevents overwriting VMA sources during the move
    for vma in vmas.iter().rev() {
        // Skip vDSO/vsyscall
        if vma.start == 0xffffffffff600000 {
            continue;
        }

        // Only process VMAs moving right (final > premap)
        // While final >= premap, process; when final < premap, stop
        if vma.start < vma.premap_addr {
            break;  // Remaining VMAs are left-moving or stationary
        }

        // Skip VMAs already at correct address
        if vma.start == vma.premap_addr {
            continue;
        }

        // Move VMA from premap to final address
        remap_vma(vma);
    }
}

/// Remap a single VMA from premap address to final address
#[inline(always)]
unsafe fn remap_vma(vma: &VmaEntry) {
    let len = vma.end - vma.start;

    // Use mremap with MREMAP_FIXED to atomically unmap target and remap
    let result = mremap(
        vma.premap_addr,
        len,
        len,
        MREMAP_FIXED | MREMAP_MAYMOVE,
        vma.start,
    );

    // Check if mremap succeeded
    match result {
        Ok(addr) if addr == vma.start => {
            // Success - set correct protection
        }
        Ok(addr) => {
            // mremap returned wrong address
            write(2, b"M".as_ptr(), 1);  // mremap error
            write(2, b"W".as_ptr(), 1);  // wrong address
            loop { core::hint::spin_loop(); }
        }
        Err(errno) => {
            // mremap failed - report errno
            write(2, b"M".as_ptr(), 1);  // mremap error
            write(2, b"F".as_ptr(), 1);  // failed
            write(2, b":".as_ptr(), 1);  // separator
            let e = errno.0 as u64;
            if e >= 10 {
                let tens = (e / 10) as u8;
                write(2, &(b'0' + tens) as *const u8, 1);
            }
            let ones = (e % 10) as u8;
            write(2, &(b'0' + ones) as *const u8, 1);
            loop { core::hint::spin_loop(); }
        }
    }

    // Set correct memory protection after remapping
    if mprotect(vma.start, len, vma.prot).is_err() {
        write(2, b"P".as_ptr(), 1);  // mprotect error
        loop { core::hint::spin_loop(); }
    }
}

/// Restore CPU state via rt_sigreturn
///
/// Following CRIU's approach: TLS has been set via arch_prctl above,
/// now use rt_sigreturn to restore all other registers and jump to target RIP.
///
/// IMPORTANT: Uses inline(never) to match CRIU's noinline attribute.
/// CRIU explicitly marks rst_sigreturn as noinline to ensure a proper function
/// call with stack frame, which may be important for rt_sigreturn behavior.
#[inline(never)]
unsafe fn restore_cpu_state(sigframe_ptr: *const u8) -> ! {
    // CRIU's approach: new_sp = (long)rt_sigframe + RT_SIGFRAME_OFFSET(rt_sigframe)
    // RT_SIGFRAME_OFFSET is 8 (skips the pretcode field)
    // The kernel expects RSP to point to the ucontext, not the pretcode
    asm!(
        // Skip pretcode field (8 bytes) to point to ucontext
        // RtSigframe64 = [pretcode: u64 (8 bytes), uc: RtUcontext, ...]
        // rt_sigreturn expects RSP to point to ucontext, not pretcode
        "add rdi, 8",            // rdi += 8, now points to uc (RT_SIGFRAME_OFFSET=8)

        // Call rt_sigreturn with RSP pointing to ucontext
        // The kernel will restore all registers from the sigframe at RSP
        "mov rsp, rdi",          // Set RSP to ucontext
        "mov eax, {nr_rt_sigreturn}",  // __NR_rt_sigreturn = 15
        "syscall",
        // This syscall never returns - kernel restores all registers and jumps to target RIP

        nr_rt_sigreturn = const SYS_RT_SIGRETURN as u32,
        in("rdi") sigframe_ptr,  // sigframe pointer in RDI
        options(noreturn)
    );
}

/// Panic handler (required for no_std)
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe {
        // Write "PANIC" to stderr (fd 2) and exit
        let msg = b"RESTORER PANIC\n";
        let _ = write(2, msg.as_ptr(), msg.len());

        // Infinite loop (can't exit from restorer)
        loop {
            core::hint::spin_loop();
        }
    }
}
