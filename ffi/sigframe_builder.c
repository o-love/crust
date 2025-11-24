#define _GNU_SOURCE
#include "sigframe_builder.h"
#include <sys/ucontext.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stddef.h>

// FPU state constants (from CRIU)
// Note: FP_XSTATE_MAGIC1/2 are already defined in bits/sigcontext.h
#ifndef XSAVE_SIZE
#define XSAVE_SIZE (4 * 4096)  // 16KB
#endif
#define XFEATURE_MASK_FP 0x1
#define XFEATURE_MASK_SSE 0x2
#define XFEATURE_MASK_FPSSE (XFEATURE_MASK_FP | XFEATURE_MASK_SSE)

// ucontext flags
#define UC_FP_XSTATE 0x1
#define UC_SIGCONTEXT_SS 0x2
#define UC_STRICT_RESTORE_SS 0x4

// FPU state structure (matches kernel's XSAVE format)
typedef struct __attribute__((aligned(64))) {
    uint8_t i387_fxsave[512];     // Legacy FPU/SSE state
    uint64_t xstate_bv;            // Feature bits
    uint64_t xcomp_bv;             // Compaction bits
    uint64_t reserved[6];          // Reserved
    uint8_t extended[15804];       // Extended state
    uint32_t magic2;               // FP_XSTATE_MAGIC2
} fpu_state_t;

// Complete sigframe structure
typedef struct {
    uint64_t pretcode;          // Return address (unused)
    ucontext_t uc;              // User context (native kernel structure)
    siginfo_t info;             // Signal info (native kernel structure)
    fpu_state_t fpu_state;      // FPU state
} rt_sigframe_t;

// Opaque handle wraps the actual sigframe
struct sigframe_handle {
    rt_sigframe_t* sigframe;
};

sigframe_handle_t* sigframe_create(const checkpoint_regs_t* regs) {
    sigframe_handle_t* handle = malloc(sizeof(sigframe_handle_t));
    if (!handle) {
        return NULL;
    }

    // Allocate sigframe with proper alignment (64 bytes for FPU state)
    handle->sigframe = aligned_alloc(64, sizeof(rt_sigframe_t));
    if (!handle->sigframe) {
        free(handle);
        return NULL;
    }

    // Zero the entire structure
    memset(handle->sigframe, 0, sizeof(rt_sigframe_t));

    rt_sigframe_t* sf = handle->sigframe;

    // Populate ucontext using native structure and macros
    sf->uc.uc_flags = UC_FP_XSTATE | UC_SIGCONTEXT_SS | UC_STRICT_RESTORE_SS;
    sf->uc.uc_link = NULL;

    // Stack info (not using alternate stack)
    sf->uc.uc_stack.ss_sp = NULL;
    sf->uc.uc_stack.ss_flags = 0;
    sf->uc.uc_stack.ss_size = 0;

    // Signal mask (empty)
    sigemptyset(&sf->uc.uc_sigmask);

    // CRITICAL: Use the native mcontext_t.gregs[] array
    // This is the glibc/kernel standard way to set registers
    sf->uc.uc_mcontext.gregs[REG_R8] = regs->r8;
    sf->uc.uc_mcontext.gregs[REG_R9] = regs->r9;
    sf->uc.uc_mcontext.gregs[REG_R10] = regs->r10;
    sf->uc.uc_mcontext.gregs[REG_R11] = regs->r11;
    sf->uc.uc_mcontext.gregs[REG_R12] = regs->r12;
    sf->uc.uc_mcontext.gregs[REG_R13] = regs->r13;
    sf->uc.uc_mcontext.gregs[REG_R14] = regs->r14;
    sf->uc.uc_mcontext.gregs[REG_R15] = regs->r15;
    sf->uc.uc_mcontext.gregs[REG_RDI] = regs->di;
    sf->uc.uc_mcontext.gregs[REG_RSI] = regs->si;
    sf->uc.uc_mcontext.gregs[REG_RBP] = regs->bp;
    sf->uc.uc_mcontext.gregs[REG_RBX] = regs->bx;
    sf->uc.uc_mcontext.gregs[REG_RDX] = regs->dx;
    sf->uc.uc_mcontext.gregs[REG_RAX] = regs->ax;
    sf->uc.uc_mcontext.gregs[REG_RCX] = regs->cx;
    sf->uc.uc_mcontext.gregs[REG_RSP] = regs->sp;
    sf->uc.uc_mcontext.gregs[REG_RIP] = regs->ip;
    sf->uc.uc_mcontext.gregs[REG_EFL] = regs->flags;

    // CSGSFS is a packed field containing cs, gs, fs, and padding
    // Format: [15:0]=cs, [31:16]=gs, [47:32]=fs, [63:48]=__pad0
    uint64_t csgsfs = ((uint64_t)regs->cs) |
                      ((uint64_t)regs->gs << 16) |
                      ((uint64_t)regs->fs << 32);
    sf->uc.uc_mcontext.gregs[REG_CSGSFS] = csgsfs;

    // Exception info
    sf->uc.uc_mcontext.gregs[REG_ERR] = 0;
    sf->uc.uc_mcontext.gregs[REG_TRAPNO] = 0;
    sf->uc.uc_mcontext.gregs[REG_OLDMASK] = 0;
    sf->uc.uc_mcontext.gregs[REG_CR2] = 0;

    // fpstate pointer will be set later via sigframe_set_fpstate()
    sf->uc.uc_mcontext.fpregs = NULL;

    // Initialize FPU state
    fpu_state_t* fpu = &sf->fpu_state;

    // Set up fpx_sw_bytes in i387_fxsave (offset 464)
    // Use system-defined macros from bits/sigcontext.h
    uint8_t* fpx_sw = &fpu->i387_fxsave[464];
    *(uint32_t*)(fpx_sw + 0) = 0x46505853U;  // FP_XSTATE_MAGIC1
    *(uint32_t*)(fpx_sw + 4) = XSAVE_SIZE + 4;  // FP_XSTATE_MAGIC2_SIZE
    *(uint64_t*)(fpx_sw + 8) = XFEATURE_MASK_FPSSE;
    *(uint32_t*)(fpx_sw + 16) = XSAVE_SIZE;

    // Set XSAVE header
    fpu->xstate_bv = XFEATURE_MASK_FPSSE;
    fpu->xcomp_bv = 0;
    fpu->magic2 = 0x46505845U;  // FP_XSTATE_MAGIC2

    // Signal info (minimal)
    sf->info.si_signo = 0;
    sf->info.si_errno = 0;
    sf->info.si_code = 0;

    // Debug output
    printf("[C FFI] Created sigframe with native structures\n");
    printf("[C FFI] sizeof(ucontext_t) = %zu\n", sizeof(ucontext_t));
    printf("[C FFI] sizeof(siginfo_t) = %zu\n", sizeof(siginfo_t));
    printf("[C FFI] sizeof(rt_sigframe_t) = %zu\n", sizeof(rt_sigframe_t));
    printf("[C FFI] RIP register value: 0x%llx\n", (unsigned long long)regs->ip);
    printf("[C FFI] gregs[REG_RIP] = 0x%llx\n", (unsigned long long)sf->uc.uc_mcontext.gregs[REG_RIP]);
    printf("[C FFI] REG_RIP index = %d\n", REG_RIP);

    return handle;
}

void sigframe_destroy(sigframe_handle_t* handle) {
    if (handle) {
        if (handle->sigframe) {
            free(handle->sigframe);
        }
        free(handle);
    }
}

const void* sigframe_get_data(const sigframe_handle_t* handle) {
    if (!handle || !handle->sigframe) {
        return NULL;
    }
    return handle->sigframe;
}

size_t sigframe_get_size(const sigframe_handle_t* handle) {
    if (!handle || !handle->sigframe) {
        return 0;
    }
    return sizeof(rt_sigframe_t);
}

void sigframe_set_fpstate(sigframe_handle_t* handle, uint64_t sigframe_addr) {
    if (!handle || !handle->sigframe) {
        return;
    }

    // Calculate offset to fpu_state.i387_fxsave
    size_t fpu_offset = offsetof(rt_sigframe_t, fpu_state) +
                        offsetof(fpu_state_t, i387_fxsave);
    uint64_t fpstate_addr = sigframe_addr + fpu_offset;

    // Verify 64-byte alignment
    if (fpstate_addr % 64 != 0) {
        fprintf(stderr, "[C FFI] WARNING: fpstate address 0x%lx is not 64-byte aligned!\n",
                fpstate_addr);
    }

    // Set the fpstate pointer in mcontext
    handle->sigframe->uc.uc_mcontext.fpregs = (struct _libc_fpstate*)fpstate_addr;

    printf("[C FFI] Set fpstate pointer to 0x%lx\n", fpstate_addr);
}

void sigframe_debug_print(const sigframe_handle_t* handle) {
    if (!handle || !handle->sigframe) {
        printf("[C FFI] Invalid handle\n");
        return;
    }

    rt_sigframe_t* sf = handle->sigframe;

    printf("[C FFI] Sigframe structure layout:\n");
    printf("  pretcode offset: %zu\n", offsetof(rt_sigframe_t, pretcode));
    printf("  uc offset: %zu\n", offsetof(rt_sigframe_t, uc));
    printf("  info offset: %zu\n", offsetof(rt_sigframe_t, info));
    printf("  fpu_state offset: %zu\n", offsetof(rt_sigframe_t, fpu_state));
    printf("  Total size: %zu bytes\n", sizeof(rt_sigframe_t));

    printf("\n[C FFI] ucontext_t layout:\n");
    printf("  uc_flags offset: %zu\n", offsetof(ucontext_t, uc_flags));
    printf("  uc_link offset: %zu\n", offsetof(ucontext_t, uc_link));
    printf("  uc_stack offset: %zu\n", offsetof(ucontext_t, uc_stack));
    printf("  uc_mcontext offset: %zu\n", offsetof(ucontext_t, uc_mcontext));
    printf("  uc_sigmask offset: %zu\n", offsetof(ucontext_t, uc_sigmask));
    printf("  Total size: %zu bytes\n", sizeof(ucontext_t));

    printf("\n[C FFI] Register values from gregs[]:\n");
    printf("  RIP (gregs[%d]): 0x%llx\n", REG_RIP, sf->uc.uc_mcontext.gregs[REG_RIP]);
    printf("  RSP (gregs[%d]): 0x%llx\n", REG_RSP, sf->uc.uc_mcontext.gregs[REG_RSP]);
    printf("  RCX (gregs[%d]): 0x%llx\n", REG_RCX, sf->uc.uc_mcontext.gregs[REG_RCX]);
    printf("  RBP (gregs[%d]): 0x%llx\n", REG_RBP, sf->uc.uc_mcontext.gregs[REG_RBP]);

    printf("\n[C FFI] Flags and pointers:\n");
    printf("  uc_flags: 0x%lx\n", sf->uc.uc_flags);
    printf("  fpregs: %p\n", sf->uc.uc_mcontext.fpregs);
}
