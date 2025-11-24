#ifndef SIGFRAME_BUILDER_H
#define SIGFRAME_BUILDER_H

#include <stdint.h>
#include <stddef.h>

// Opaque handle to sigframe (hides the actual structure from Rust)
typedef struct sigframe_handle sigframe_handle_t;

// Checkpoint register data (passed from Rust)
typedef struct {
    uint64_t r15, r14, r13, r12, bp, bx;
    uint64_t r11, r10, r9, r8, ax, cx, dx, si, di;
    uint64_t orig_ax, ip, cs, flags, sp, ss;
    uint64_t fs_base, gs_base;
    uint32_t fs, gs;
} checkpoint_regs_t;

// Create a sigframe using native C structures
// Returns an opaque handle that must be freed with sigframe_destroy()
sigframe_handle_t* sigframe_create(const checkpoint_regs_t* regs);

// Destroy a sigframe and free its memory
void sigframe_destroy(sigframe_handle_t* handle);

// Get pointer to the sigframe data for writing to memory
// The returned pointer is valid until sigframe_destroy() is called
const void* sigframe_get_data(const sigframe_handle_t* handle);

// Get the size of the sigframe in bytes
size_t sigframe_get_size(const sigframe_handle_t* handle);

// Set the fpstate pointer after the sigframe is written to memory
// sigframe_addr: the address where the sigframe was written
void sigframe_set_fpstate(sigframe_handle_t* handle, uint64_t sigframe_addr);

// Debug: Print sigframe layout and offsets
void sigframe_debug_print(const sigframe_handle_t* handle);

#endif // SIGFRAME_BUILDER_H
