//! x86_64 Signal Frame Builder
//!
//! Constructs rt_sigframe for rt_sigreturn syscall to restore CPU state.
//!
//! The rt_sigreturn syscall expects RSP to point at a properly formatted
//! rt_sigframe structure. When invoked, the kernel restores registers,
//! signal mask, and stack state from this frame.

use crate::images::checkpoint::CriuCheckpoint;
use crate::proto::UserX86FpregsEntry;
use crate::Result;

/// Register indices for gregs[] array (from sys/ucontext.h)
/// These are used to index into RtMcontext.gregs[]
pub const REG_R8: usize = 0;
pub const REG_R9: usize = 1;
pub const REG_R10: usize = 2;
pub const REG_R11: usize = 3;
pub const REG_R12: usize = 4;
pub const REG_R13: usize = 5;
pub const REG_R14: usize = 6;
pub const REG_R15: usize = 7;
pub const REG_RDI: usize = 8;
pub const REG_RSI: usize = 9;
pub const REG_RBP: usize = 10;
pub const REG_RBX: usize = 11;
pub const REG_RDX: usize = 12;
pub const REG_RAX: usize = 13;
pub const REG_RCX: usize = 14;
pub const REG_RSP: usize = 15;
pub const REG_RIP: usize = 16;
pub const REG_EFL: usize = 17;
pub const REG_CSGSFS: usize = 18;  // Packed: cs, gs, fs, __pad0
pub const REG_ERR: usize = 19;
pub const REG_TRAPNO: usize = 20;
pub const REG_OLDMASK: usize = 21;
pub const REG_CR2: usize = 22;

/// x86_64 machine context - CPU register state
///
/// Layout matches glibc's mcontext_t (sys/ucontext.h).
/// CRITICAL: Uses gregs[] ARRAY like glibc, NOT named fields!
/// rt_sigreturn expects this exact layout with the gregs[] array.
///
/// This is 256 bytes total:
/// - gregs[23] = 184 bytes
/// - fpregs = 8 bytes (pointer)
/// - __reserved1[8] = 64 bytes
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RtMcontext {
    /// General purpose registers as array (THIS IS THE CORRECT LAYOUT!)
    /// Use REG_* constants to index into this array
    pub gregs: [u64; 23],

    /// Pointer to FPU state (set via set_fpstate_pointer)
    pub fpregs: u64,

    /// Reserved space for alignment
    pub __reserved1: [u64; 8],
}

/// Signal stack information
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RtSigaltstack {
    pub ss_sp: u64,        // Stack base (8 bytes, offset 0)
    pub ss_flags: i32,     // SS_ONSTACK, SS_DISABLE, etc. (4 bytes, offset 8)
    pub _pad: i32,         // Padding for alignment (4 bytes, offset 12)
    pub ss_size: u64,      // Stack size (8 bytes, offset 16)
}

/// Signal mask (kernel's sigset_t)
///
/// The kernel expects 128 bytes for sigset_t (verified via sizeof(sigset_t) = 128).
/// This is 1024 bits to represent all possible signals.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RtSigset {
    pub sig: [u64; 16],     // 128 bytes (matches kernel's sigset_t)
}

/// User context for signal handling
///
/// Layout matches kernel's struct ucontext_t (sys/ucontext.h).
/// CRITICAL: Must match kernel's 968-byte layout for rt_sigreturn to work.
/// The kernel's rt_sigreturn expects this standard layout, NOT CRIU's extended version.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RtUcontext {
    pub uc_flags: u64,              // 8 bytes at offset 0
    pub uc_link: u64,               // 8 bytes at offset 8 (pointer to next context)
    pub uc_stack: RtSigaltstack,    // 24 bytes at offset 16
    pub uc_mcontext: RtMcontext,    // 256 bytes at offset 40 (NOW USING GREGS[] ARRAY!)
    pub uc_sigmask: RtSigset,       // 128 bytes at offset 296 (sigset_t)
    // Padding to match kernel's ucontext_t (968 bytes total)
    // glibc has __fpregs_mem (512 bytes) + __ssp[4] (32 bytes) here
    pub __reserved: [u64; 68],      // 544 bytes of padding (68 * 8 = 544)
                                     // Total: 8+8+24+256+128+544 = 968 bytes
}

/// Signal information structure
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RtSiginfo {
    pub si_signo: i32,
    pub si_errno: i32,
    pub si_code: i32,
    pub _pad: [i32; 29],    // Padding to 128 bytes
}

/// FPU state for signal frame
///
/// Must be 64-byte aligned per kernel requirements.
/// Uses XSAVE format matching kernel's struct xsave_struct.
/// Layout:
///   - i387_fxsave (512 bytes): legacy FPU/SSE state
///   - xsave_hdr (64 bytes): XSAVE header with xstate_bv
///   - extended area (15804 bytes): extended state (AVX, etc.)
///   - magic2 (4 bytes): FP_XSTATE_MAGIC2 at end
/// Total: 16384 bytes (4*4096)
#[repr(C, align(64))]
#[derive(Debug, Clone, Copy)]
pub struct FpuState {
    pub i387_fxsave: [u8; 512],     // Legacy FPU/SSE state
    pub xsave_hdr: XsaveHeader,      // XSAVE header (64 bytes)
    pub extended: [u8; 15804],       // Extended state area
    pub magic2: u32,                 // FP_XSTATE_MAGIC2 at end
}

/// XSAVE header structure
///
/// Matches kernel's struct xsave_hdr_struct.
/// xstate_bv indicates which features are in use.
/// xcomp_bv indicates compact format when bit 63 is set.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct XsaveHeader {
    pub xstate_bv: u64,     // Feature bits (FP=1, SSE=2, YMM=4, etc.)
    pub xcomp_bv: u64,      // Compaction bit vector (0 for uncompacted)
    pub reserved: [u64; 6], // Reserved (must be zero)
}

/// Complete rt_sigframe for x86_64
///
/// This structure is placed on the stack for rt_sigreturn.
/// RSP must point 8 bytes before the structure (pretcode return address).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RtSigframe64 {
    pub pretcode: u64,          // Return address (unused by rt_sigreturn)
    pub uc: RtUcontext,
    pub info: RtSiginfo,
    pub fpu_state: FpuState,    // FPU state follows (64-byte aligned)
}

impl RtSigframe64 {
    /// Restore FPU state from checkpoint
    ///
    /// Translation of CRIU's restore_fpu() from arch/x86/crtools.c:425-540
    /// Populates the i387_fxsave structure and XSAVE extended state from
    /// checkpoint FPU register data.
    fn restore_fpu_state(fpregs: &UserX86FpregsEntry) -> Result<FpuState> {
        // Constants from CRIU's fpu.h
        const XFEATURE_MASK_FP: u64 = 0x1;
        const XFEATURE_MASK_SSE: u64 = 0x2;
        const XFEATURE_MASK_FPSSE: u64 = XFEATURE_MASK_FP | XFEATURE_MASK_SSE;
        const FP_XSTATE_MAGIC1: u32 = 0x46505853;
        const FP_XSTATE_MAGIC2: u32 = 0x46505845;
        const FP_XSTATE_MAGIC2_SIZE: u32 = 4;
        const XSAVE_SIZE: u32 = 4 * 4096;  // 16KB total XSAVE area

        // Build i387_fxsave structure (512 bytes)
        // Layout from compel/arch/x86/src/lib/include/uapi/asm/fpu.h:117-150
        let mut i387_fxsave = [0u8; 512];

        // Control/status words (offsets 0-7)
        i387_fxsave[0..2].copy_from_slice(&(fpregs.cwd as u16).to_le_bytes());
        i387_fxsave[2..4].copy_from_slice(&(fpregs.swd as u16).to_le_bytes());
        i387_fxsave[4..6].copy_from_slice(&(fpregs.twd as u16).to_le_bytes());
        i387_fxsave[6..8].copy_from_slice(&(fpregs.fop as u16).to_le_bytes());

        // Instruction/data pointers (offsets 8-23)
        i387_fxsave[8..16].copy_from_slice(&fpregs.rip.to_le_bytes());
        i387_fxsave[16..24].copy_from_slice(&fpregs.rdp.to_le_bytes());

        // MXCSR register (offsets 24-31)
        i387_fxsave[24..28].copy_from_slice(&fpregs.mxcsr.to_le_bytes());
        i387_fxsave[28..32].copy_from_slice(&fpregs.mxcsr_mask.to_le_bytes());

        // x87 FPU registers: st_space[32] = 128 bytes (offsets 32-159)
        // Each st_space entry is u32, total 32 entries
        if fpregs.st_space.len() != 32 {
            return Err(crate::CrustError::InvalidImage {
                reason: format!("Expected 32 st_space entries, got {}", fpregs.st_space.len()),
            });
        }
        for (i, &val) in fpregs.st_space.iter().enumerate() {
            let offset = 32 + i * 4;
            i387_fxsave[offset..offset+4].copy_from_slice(&val.to_le_bytes());
        }

        // SSE registers: xmm_space[64] = 256 bytes (offsets 160-415)
        // Each xmm_space entry is u32, total 64 entries (16 XMM regs * 4 u32s each)
        if fpregs.xmm_space.len() != 64 {
            return Err(crate::CrustError::InvalidImage {
                reason: format!("Expected 64 xmm_space entries, got {}", fpregs.xmm_space.len()),
            });
        }
        for (i, &val) in fpregs.xmm_space.iter().enumerate() {
            let offset = 160 + i * 4;
            i387_fxsave[offset..offset+4].copy_from_slice(&val.to_le_bytes());
        }

        // Compute xstate_bv from checkpoint data
        // Start with base FP + SSE, add extended features if present
        let mut xstate_bv = XFEATURE_MASK_FPSSE;

        // XSAVE header: struct fpx_sw_bytes at offset 464 (48 bytes)
        // From compel/arch/x86/src/lib/include/uapi/asm/fpu.h:109-115
        let fpx_sw_offset = 464;

        // Set xstate_bv based on what features are present in checkpoint
        if let Some(ref xsave) = fpregs.xsave {
            xstate_bv = xsave.xstate_bv;
            log::debug!("Restoring FPU with xstate_bv from checkpoint: 0x{:x}", xstate_bv);
        } else {
            log::debug!("No XSAVE data in checkpoint, using minimal xstate_bv: 0x{:x}", xstate_bv);
        }

        // fpx_sw_bytes.magic1 (offset 464)
        i387_fxsave[fpx_sw_offset..fpx_sw_offset+4]
            .copy_from_slice(&FP_XSTATE_MAGIC1.to_le_bytes());

        // fpx_sw_bytes.extended_size (offset 468)
        let extended_size = XSAVE_SIZE + FP_XSTATE_MAGIC2_SIZE;
        i387_fxsave[fpx_sw_offset+4..fpx_sw_offset+8]
            .copy_from_slice(&extended_size.to_le_bytes());

        // fpx_sw_bytes.xstate_bv (offset 472)
        i387_fxsave[fpx_sw_offset+8..fpx_sw_offset+16]
            .copy_from_slice(&xstate_bv.to_le_bytes());

        // fpx_sw_bytes.xstate_size (offset 480)
        i387_fxsave[fpx_sw_offset+16..fpx_sw_offset+20]
            .copy_from_slice(&XSAVE_SIZE.to_le_bytes());

        // Build XSAVE extended state (15804 bytes after i387_fxsave and xsave_hdr)
        // This includes AVX, AVX-512, MPX, PKRU, etc.
        let mut extended = [0u8; 15804];

        // If checkpoint has XSAVE data, restore extended state
        // Translation of CRIU's assign_xsave macros from crtools.c:451-473
        if let Some(ref xsave) = fpregs.xsave {
            // Note: Extended state layout is complex and feature-dependent
            // CRIU uses compel_fpu_feature_offset() to calculate offsets
            // For MVP, we restore YMM (AVX) if present, which is most common

            // YMM high 128 bits (AVX): offset 576 in XSAVE area
            // ymmh_space: 16 YMM registers * 128 bits high = 64 u32 values
            if !xsave.ymmh_space.is_empty() {
                const YMM_OFFSET: usize = 64;  // Offset in extended[] array (576 - 512 header)
                if xsave.ymmh_space.len() == 64 {
                    for (i, &val) in xsave.ymmh_space.iter().enumerate() {
                        let offset = YMM_OFFSET + i * 4;
                        if offset + 4 <= extended.len() {
                            extended[offset..offset+4].copy_from_slice(&val.to_le_bytes());
                        }
                    }
                    log::debug!("Restored YMM extended state ({} entries)", xsave.ymmh_space.len());
                }
            }

            // TODO: Restore other extended features if needed:
            // - MPX: bndreg_state, bndcsr_state
            // - AVX-512: opmask_reg, zmm_upper, hi16_zmm
            // - PKU: pkru
            // For now, FP + SSE + YMM covers most use cases
        }

        log::info!("Restored FPU state: cwd=0x{:x}, swd=0x{:x}, mxcsr=0x{:x}, xstate_bv=0x{:x}",
                   fpregs.cwd, fpregs.swd, fpregs.mxcsr, xstate_bv);

        Ok(FpuState {
            i387_fxsave,
            xsave_hdr: XsaveHeader {
                xstate_bv,
                xcomp_bv: 0,  // Uncompacted format
                reserved: [0; 6],
            },
            extended,
            magic2: FP_XSTATE_MAGIC2,
        })
    }

    /// Create a signal frame from checkpoint data
    ///
    /// Populates the sigframe with CPU registers from the checkpoint.
    /// When rt_sigreturn is invoked with RSP pointing to this frame,
    /// it will restore the process to the checkpointed state.
    pub fn from_checkpoint(checkpoint: &CriuCheckpoint) -> Result<Self> {
        // Log structure sizes for debugging
        log::debug!("Structure sizes:");
        log::debug!("  RtSigaltstack: {} bytes", std::mem::size_of::<RtSigaltstack>());
        log::debug!("  RtMcontext: {} bytes", std::mem::size_of::<RtMcontext>());
        log::debug!("  RtSigset: {} bytes", std::mem::size_of::<RtSigset>());
        log::debug!("  RtUcontext: {} bytes", std::mem::size_of::<RtUcontext>());
        log::debug!("  RtSiginfo: {} bytes", std::mem::size_of::<RtSiginfo>());
        log::debug!("  FpuState: {} bytes", std::mem::size_of::<FpuState>());
        log::debug!("  RtSigframe64: {} bytes", std::mem::size_of::<RtSigframe64>());

        let core = &checkpoint.core;

        let thread_info = core.thread_info.as_ref().ok_or_else(|| {
            crate::CrustError::InvalidImage {
                reason: "No thread_info in core".to_string(),
            }
        })?;

        let regs = &thread_info.gpregs;

        // Build signal context from checkpoint registers
        //
        // CRITICAL: fs/gs are segment SELECTORS, not base registers!
        // Modern x86_64 Linux uses fs_base/gs_base MSRs (set via arch_prctl),
        // so fs/gs selectors should be 0.
        // If rt_sigreturn restores non-zero selectors, it may reset the base registers!
        log::debug!("Sigframe segment registers: fs=0x{:x}, gs=0x{:x}, cs=0x{:x}, ss=0x{:x}",
                   regs.fs, regs.gs, regs.cs, regs.ss);
        log::debug!("Segment base registers: fs_base=0x{:x}, gs_base=0x{:x}",
                   regs.fs_base, regs.gs_base);

        // CRITICAL: Build mcontext using gregs[] ARRAY (not named fields!)
        // This matches glibc's mcontext_t layout that rt_sigreturn expects
        log::debug!("Checkpoint register values:");
        log::debug!("  regs.ip (should go to gregs[REG_RIP=16]): 0x{:x}", regs.ip);
        log::debug!("  regs.cx (should go to gregs[REG_RCX=14]): 0x{:x}", regs.cx);
        log::debug!("  regs.sp (should go to gregs[REG_RSP=15]): 0x{:x}", regs.sp);

        // Initialize mcontext with gregs[] array
        let mut mcontext = RtMcontext {
            gregs: [0; 23],
            fpregs: 0,  // Will be set later via set_fpstate_pointer()
            __reserved1: [0; 8],
        };

        // Populate gregs[] array using REG_* indices
        mcontext.gregs[REG_R8] = regs.r8;
        mcontext.gregs[REG_R9] = regs.r9;
        mcontext.gregs[REG_R10] = regs.r10;
        mcontext.gregs[REG_R11] = regs.r11;
        mcontext.gregs[REG_R12] = regs.r12;
        mcontext.gregs[REG_R13] = regs.r13;
        mcontext.gregs[REG_R14] = regs.r14;
        mcontext.gregs[REG_R15] = regs.r15;
        mcontext.gregs[REG_RDI] = regs.di;
        mcontext.gregs[REG_RSI] = regs.si;
        mcontext.gregs[REG_RBP] = regs.bp;
        mcontext.gregs[REG_RBX] = regs.bx;
        mcontext.gregs[REG_RDX] = regs.dx;
        mcontext.gregs[REG_RAX] = regs.ax;
        mcontext.gregs[REG_RCX] = regs.cx;
        mcontext.gregs[REG_RSP] = regs.sp;
        mcontext.gregs[REG_RIP] = regs.ip;
        mcontext.gregs[REG_EFL] = regs.flags;

        // CSGSFS is a packed field: [15:0]=cs, [31:16]=gs, [47:32]=fs, [63:48]=ss
        // This matches kernel's struct sigcontext_64 layout
        mcontext.gregs[REG_CSGSFS] = (regs.cs as u64)
            | ((regs.gs as u64) << 16)
            | ((regs.fs as u64) << 32)
            | ((regs.ss as u64) << 48);  // CRITICAL: Must include SS!

        // Exception/trap information
        mcontext.gregs[REG_ERR] = 0;
        mcontext.gregs[REG_TRAPNO] = 0;
        mcontext.gregs[REG_OLDMASK] = 0;
        mcontext.gregs[REG_CR2] = 0;

        // CRITICAL DEBUG: Verify mcontext values after assignment
        log::debug!("Mcontext gregs[] values after assignment:");
        log::debug!("  gregs[REG_RIP=16]: 0x{:x}", mcontext.gregs[REG_RIP]);
        log::debug!("  gregs[REG_RCX=14]: 0x{:x}", mcontext.gregs[REG_RCX]);
        log::debug!("  gregs[REG_RSP=15]: 0x{:x}", mcontext.gregs[REG_RSP]);

        // Build stack info (minimal for MVP)
        let stack = RtSigaltstack {
            ss_sp: 0,
            ss_flags: 0,   // Not using alternate stack
            _pad: 0,       // Padding for alignment
            ss_size: 0,
        };

        // Build user context
        // Match real signal handler uc_flags (all three flags set to 0x7)
        // UC_FP_XSTATE (0x1) indicates FPU state is in XSAVE format
        // UC_SIGCONTEXT_SS (0x2) indicates SS field is valid in sigcontext
        // UC_STRICT_RESTORE_SS (0x4) restores SS strictly (for 64-bit code)
        const UC_FP_XSTATE: u64 = 0x1;
        const UC_SIGCONTEXT_SS: u64 = 0x2;
        const UC_STRICT_RESTORE_SS: u64 = 0x4;
        let uc = RtUcontext {
            uc_flags: UC_FP_XSTATE | UC_SIGCONTEXT_SS | UC_STRICT_RESTORE_SS,  // All flags (0x7)
            uc_link: 0,
            uc_stack: stack,
            uc_mcontext: mcontext,  // NOW USING gregs[] ARRAY!
            uc_sigmask: RtSigset { sig: [0; 16] },  // Empty signal mask (128 bytes)
            __reserved: [0; 68],  // 544 bytes padding to match kernel's 968-byte ucontext_t
        };

        // Build signal info (minimal)
        let info = RtSiginfo {
            si_signo: 0,
            si_errno: 0,
            si_code: 0,
            _pad: [0; 29],
        };

        // Restore FPU state from checkpoint
        // Translation of CRIU's restore_fpu() from arch/x86/crtools.c:425-540
        let fpu_state = Self::restore_fpu_state(&thread_info.fpregs)?;

        let sigframe = Self {
            pretcode: 0,
            uc,
            info,
            fpu_state,
        };

        // Debug: Log sigframe field values
        log::debug!("Sigframe field values:");
        log::debug!("  pretcode: 0x{:x}", sigframe.pretcode);
        log::debug!("  uc.uc_flags: 0x{:x}", sigframe.uc.uc_flags);
        log::debug!("  uc.uc_mcontext.fpregs: 0x{:x}", sigframe.uc.uc_mcontext.fpregs);
        log::debug!("  uc.uc_mcontext.gregs[REG_RIP]: 0x{:x}", sigframe.uc.uc_mcontext.gregs[REG_RIP]);
        log::debug!("  uc.uc_mcontext.gregs[REG_RSP]: 0x{:x}", sigframe.uc.uc_mcontext.gregs[REG_RSP]);
        log::debug!("  uc.uc_mcontext.gregs[REG_CSGSFS]: 0x{:x}", sigframe.uc.uc_mcontext.gregs[REG_CSGSFS]);
        log::debug!("  fpu_state.xsave_hdr.xstate_bv: 0x{:x}", sigframe.fpu_state.xsave_hdr.xstate_bv);
        log::debug!("  fpu_state.magic2: 0x{:x}", sigframe.fpu_state.magic2);

        Ok(sigframe)
    }

    /// Size of the sigframe in bytes
    pub const fn size() -> usize {
        std::mem::size_of::<Self>()
    }

    /// Convert to byte slice for writing to memory
    pub fn as_bytes(&self) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts(
                self as *const Self as *const u8,
                Self::size(),
            )
        }
    }

    /// Set fpstate pointer to point to fpu_state field at given sigframe address
    ///
    /// Must be called after the sigframe is written to memory.
    /// The fpstate pointer must be 64-byte aligned.
    pub fn set_fpstate_pointer(&mut self, sigframe_addr: u64) {
        use std::mem::offset_of;

        // Calculate address of fpu_state.i387_fxsave field (start of XSAVE area)
        let fpu_state_offset = offset_of!(RtSigframe64, fpu_state) + offset_of!(FpuState, i387_fxsave);
        let fpstate_addr = sigframe_addr + fpu_state_offset as u64;

        // Verify 64-byte alignment (required by kernel)
        assert_eq!(fpstate_addr % 64, 0,
                   "fpstate address 0x{:x} is not 64-byte aligned", fpstate_addr);

        self.uc.uc_mcontext.fpregs = fpstate_addr;

        log::debug!("Set fpregs pointer to 0x{:x} (sigframe at 0x{:x} + offset {})",
                   fpstate_addr, sigframe_addr, fpu_state_offset);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sigframe_size() {
        // Verify structure sizes match kernel expectations
        assert_eq!(std::mem::size_of::<RtMcontext>(), 256, "RtMcontext should match glibc's mcontext_t (256 bytes)");
        assert_eq!(std::mem::size_of::<RtSigset>(), 128, "RtSigset should match kernel's sigset_t (128 bytes)");
        assert_eq!(std::mem::size_of::<RtSigaltstack>(), 24, "RtSigaltstack should match kernel's stack_t");
        assert_eq!(std::mem::size_of::<RtUcontext>(), 968, "RtUcontext should match kernel's ucontext_t (968 bytes)");
        assert_eq!(std::mem::size_of::<RtSiginfo>(), 128, "RtSiginfo should match kernel's siginfo_t");

        // Verify ucontext offsets match kernel
        use std::mem::offset_of;
        assert_eq!(offset_of!(RtUcontext, uc_flags), 0, "uc_flags offset");
        assert_eq!(offset_of!(RtUcontext, uc_link), 8, "uc_link offset");
        assert_eq!(offset_of!(RtUcontext, uc_stack), 16, "uc_stack offset");
        assert_eq!(offset_of!(RtUcontext, uc_mcontext), 40, "uc_mcontext offset");
        assert_eq!(offset_of!(RtUcontext, uc_sigmask), 296, "uc_sigmask offset");

        // Total sigframe with FPU state: 8 (pretcode) + 968 (ucontext) + 128 (siginfo) + 16384 (fpu_state)
        // Note: With 64-byte alignment, actual size may include padding
        let size = RtSigframe64::size();
        println!("RtSigframe64 size: {} bytes (includes FPU state)", size);

        // Verify FPU state is properly aligned
        assert_eq!(std::mem::align_of::<FpuState>(), 64, "FpuState must be 64-byte aligned");
        assert_eq!(std::mem::size_of::<FpuState>(), 16384, "FpuState should be 16KB");
        println!("RtUcontext size: {} bytes (kernel expects 968)", std::mem::size_of::<RtUcontext>());
        println!("Structure matches kernel rt_sigframe layout!");
    }

    #[test]
    fn test_sigframe_alignment() {
        // Sigframe alignment is 64 bytes due to FpuState field
        assert_eq!(std::mem::align_of::<RtSigframe64>(), 64);
    }
}
