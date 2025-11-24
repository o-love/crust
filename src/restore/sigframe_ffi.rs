//! FFI bindings to C sigframe builder
//!
//! Uses native C structures to build the sigframe, eliminating potential Rust ABI issues.

/// Checkpoint register data (matches C struct checkpoint_regs_t)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct CheckpointRegs {
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub bp: u64,
    pub bx: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub ax: u64,
    pub cx: u64,
    pub dx: u64,
    pub si: u64,
    pub di: u64,
    pub orig_ax: u64,
    pub ip: u64,
    pub cs: u64,
    pub flags: u64,
    pub sp: u64,
    pub ss: u64,
    pub fs_base: u64,
    pub gs_base: u64,
    pub fs: u32,
    pub gs: u32,
}

impl From<&crate::proto::UserX86RegsEntry> for CheckpointRegs {
    fn from(regs: &crate::proto::UserX86RegsEntry) -> Self {
        Self {
            r15: regs.r15,
            r14: regs.r14,
            r13: regs.r13,
            r12: regs.r12,
            bp: regs.bp,
            bx: regs.bx,
            r11: regs.r11,
            r10: regs.r10,
            r9: regs.r9,
            r8: regs.r8,
            ax: regs.ax,
            cx: regs.cx,
            dx: regs.dx,
            si: regs.si,
            di: regs.di,
            orig_ax: regs.orig_ax,
            ip: regs.ip,
            cs: regs.cs,
            flags: regs.flags,
            sp: regs.sp,
            ss: regs.ss,
            fs_base: regs.fs_base,
            gs_base: regs.gs_base,
            fs: regs.fs as u32,
            gs: regs.gs as u32,
        }
    }
}

/// Opaque handle to C sigframe
#[repr(C)]
pub struct SigframeHandle {
    _private: [u8; 0],
}

extern "C" {
    fn sigframe_create(regs: *const CheckpointRegs) -> *mut SigframeHandle;
    fn sigframe_destroy(handle: *mut SigframeHandle);
    fn sigframe_get_data(handle: *const SigframeHandle) -> *const u8;
    fn sigframe_get_size(handle: *const SigframeHandle) -> usize;
    fn sigframe_set_fpstate(handle: *mut SigframeHandle, sigframe_addr: u64);
    fn sigframe_debug_print(handle: *const SigframeHandle);
}

/// Safe wrapper around C sigframe builder
pub struct CSigframe {
    handle: *mut SigframeHandle,
}

impl CSigframe {
    /// Create a new sigframe using C FFI
    pub fn new(regs: &crate::proto::UserX86RegsEntry) -> Option<Self> {
        let c_regs = CheckpointRegs::from(regs);
        let handle = unsafe { sigframe_create(&c_regs) };
        if handle.is_null() {
            None
        } else {
            Some(CSigframe { handle })
        }
    }

    /// Get the sigframe data as a byte slice
    pub fn as_bytes(&self) -> &[u8] {
        unsafe {
            let data = sigframe_get_data(self.handle);
            let size = sigframe_get_size(self.handle);
            std::slice::from_raw_parts(data, size)
        }
    }

    /// Get the size of the sigframe
    pub fn size(&self) -> usize {
        unsafe { sigframe_get_size(self.handle) }
    }

    /// Set the fpstate pointer after writing sigframe to memory
    pub fn set_fpstate_pointer(&mut self, sigframe_addr: u64) {
        unsafe {
            sigframe_set_fpstate(self.handle, sigframe_addr);
        }
    }

    /// Print debug information about the sigframe
    pub fn debug_print(&self) {
        unsafe {
            sigframe_debug_print(self.handle);
        }
    }
}

impl Drop for CSigframe {
    fn drop(&mut self) {
        unsafe {
            sigframe_destroy(self.handle);
        }
    }
}

// Implement Send for CSigframe (the C code doesn't use thread-local state)
unsafe impl Send for CSigframe {}
