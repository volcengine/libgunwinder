/* SPDX-License-Identifier: LGPL-3.0-or-later */

#ifndef _GUNWINDER_TYPES_H
#define _GUNWINDER_TYPES_H

#include <linux/types.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * GU_STACK_DATA_ALIGN - Alignment of a stack snapshot's first byte.
 *
 * Contract between every stack producer and the unwinder: stack_data[0] of
 * struct gu_stack_info is the byte at user address
 * sp & ~(GU_STACK_DATA_ALIGN - 1), where sp is the stack pointer in
 * gu_stack_info::regs, and stack_data[i] is the byte at that address + i.
 * The value is fixed at 4096 on every architecture and host page size (the
 * BPF producer copies the stack in 4 KiB chunks even on 64 KiB-page
 * kernels); it is not the host page size.
 */
#define GU_STACK_DATA_ALIGN 4096

/**
 * struct gu_elf_info - Read-only view of a cached ELF file.
 * @base_name:       File name without directories.
 * @elf_file_path:   Host path the ELF was opened from, as seen by the first
 *                   process that loaded it (entries are shared between
 *                   processes): normally /proc/<pid>/root/<maps path>;
 *                   /proc/<pid>/exe or /proc/<pid>/map_files/<range> for a
 *                   deleted file; a local dump file for [vdso].
 * @debug_file_path: File the symbols and CFI were read from: a separate
 *                   debuginfo file found by GNU build-id (host first, then
 *                   the target's root), otherwise the same as
 *                   @elf_file_path.
 * @build_id:        GNU or Go build-id bytes; when the ELF has none, the
 *                   MD5 of the file head and name, used only as a cache key.
 * @build_id_len:    Length of @build_id in bytes.
 * @golang:          True if the ELF has a Go build-id note.
 *
 * Owned by the context; never write or free it.  It is the public prefix of
 * the library's per-ELF cache entry, valid as long as that entry is (see
 * struct gu_frame_record).
 */
struct gu_elf_info {
	char *base_name;
	char *elf_file_path;
	char *debug_file_path;
	unsigned char *build_id;
	int build_id_len;
	bool golang;
};

/**
 * enum gu_frame_flag - Bits of gu_frame_record::flags.
 * @GU_FRAME_ANON_EXEC: The PC lies in an executable mapping that is not
 *                      backed by an ELF (JIT code, for example): @elf_info
 *                      and @symbol are NULL and @pc equals @abs_pc.
 */
enum gu_frame_flag {
	GU_FRAME_ANON_EXEC = (1U << 0),
};

/**
 * struct gu_frame_record - One unwound frame, passed to gu_frame_callback_t.
 * @pc:       PC as an ELF virtual address (@abs_pc minus the load bias of
 *            its mapping); equals @abs_pc for GU_FRAME_ANON_EXEC frames.
 * @abs_pc:   PC as a virtual address of the target process.  For caller
 *            frames this is the return address.
 * @offset:   Offset of the symbol-lookup address from the start of @symbol,
 *            0 when @symbol is NULL.  Caller frames look up @pc - 1 (inside
 *            the call instruction), whether unwound by DWARF, by its
 *            frame-pointer fallback or in GU_FLAG_HINT_SET_FP mode; the
 *            first frame and signal frames look up @pc itself, and so does
 *            a caller frame whose @pc - 1 is in no symbol while @pc starts
 *            one (the sigreturn trampoline a signal handler returns into).
 * @symbol:   Function name, or NULL when unknown.
 * @elf_info: ELF that maps @pc, or NULL for GU_FRAME_ANON_EXEC frames.
 * @flags:    See enum gu_frame_flag.
 *
 * The record itself is reused for every frame: it is valid only during the
 * callback.  @symbol and @elf_info point into the context's ELF cache and
 * stay valid until the next gu_unwind(), gu_preload_pid_debug_info(),
 * gu_event_occur() or gu_cleanup() on the same context, any of which may
 * evict unreferenced ELF entries.  Copy what must outlive that.
 */
struct gu_frame_record {
	uint64_t pc;
	uint64_t abs_pc;
	uint64_t offset;
	char *symbol;
	struct gu_elf_info *elf_info;
	uint32_t flags;
};

/**
 * struct gu_init_cfg - Configuration for gu_init(), copied by it.
 * @debug_print:       OFFLINE REPLAY mode, not a log switch (logging is
 *                     gu_set_verbose()).  For replaying dumps written by
 *                     gu_debug_dump_sample() on another machine:
 *                     gu_stack_info::unique_id is reinterpreted as a
 *                     "const char *" path of a saved maps file, ELF paths are
 *                     opened as is instead of under /proc/<pid>/root, and the
 *                     process liveness and pid-reuse (unique_id) checks are
 *                     skipped.  Must be false for live unwinding.
 * @go_not_strip_name: Keep Go symbol names verbatim.  By default each package
 *                     path component of a Go symbol is cut to its first
 *                     character ("github.com/a/b.F" becomes "g/a/b.F").
 * @go_buildid_only:   No longer supported: Go frames are always symbolized.
 *                     gu_init() fails when it is set; it stays so that
 *                     existing initializers that clear it still compile.
 * @no_kernel_symbols: Neither load nor reload /proc/kallsyms: kernel
 *                     addresses are resolved through another context
 *                     (gu_search_kernel_symbol() is safe to call on any
 *                     context from any thread).
 */
struct gu_init_cfg {
	bool debug_print;
	bool go_not_strip_name;
	bool go_buildid_only;
	bool no_kernel_symbols;
};

/* Capacity of gu_stack_info::ustack_fp is MAX_FP_STACK_LEVEL + 1 entries. */
#define MAX_FP_STACK_LEVEL (128 - 1)

/**
 * struct gu_stack_info - One sampled user stack, input of gu_unwind().
 * @pid:             Process id (tgid) the sample belongs to; selects the
 *                   per-process cache and /proc/<pid> files.
 * @tid:             The sampled thread of @pid, or 0.  Read instead of
 *                   /proc/<pid> to load the process' mappings once its
 *                   leader has exited before its other threads: the zombie
 *                   leader has none left.
 * @stack_size:      Number of valid bytes in @stack_data.
 * @unique_id:       Identity of the process instance: the process start time
 *                   (field 22 of /proc/<pid>/stat, in clock ticks), or 0 if
 *                   unknown.  When it differs from the cached instance the
 *                   pid was reused and the cache is rebuilt; 0 skips that
 *                   check.  Offline replay mode reinterprets it, see
 *                   gu_init_cfg::debug_print.
 * @regs:            Register snapshot laid out as the build architecture's
 *                   struct pt_regs: <asm/ptrace.h> on x86_64, the private
 *                   definition in include/arch/arm64/arch.h on arm64.
 *                   Required (non-NULL) in every mode.
 * @regs_size:       Size of @regs in bytes.  Informational: the unwinder
 *                   always accesses a full struct pt_regs.
 * @flags:           Input hints (enum gu_unwind_flag, low bits) and the stop
 *                   reason written back by gu_unwind() (enum
 *                   gu_unwind_reason, bits 16..23, see gu_flags_reason()).
 * @ustack_fp:       Return-address PCs of a frame-pointer walk, innermost
 *                   first, with [0] the sampled instruction pointer.  These
 *                   are code addresses, not frame pointers.  Used only with
 *                   GU_FLAG_HINT_SET_FP.
 * @ustack_fp_level: Number of valid entries in @ustack_fp; gu_unwind() uses
 *                   at most MAX_FP_STACK_LEVEL of them.
 * @stack_data:      Copy of the user stack starting at
 *                   sp & ~(GU_STACK_DATA_ALIGN - 1), @stack_size bytes long.
 *
 * The caller owns all buffers; the library keeps no reference after
 * gu_unwind() returns.  gu_unwind() modifies @regs and @flags in place.
 */
struct gu_stack_info {
	pid_t pid;
	pid_t tid;
	size_t stack_size;
	uint64_t unique_id;

	void *regs;
	uint32_t regs_size;

	uint64_t flags;

	uint64_t ustack_fp[MAX_FP_STACK_LEVEL + 1];
	uint64_t ustack_fp_level;

	uint8_t *stack_data;
};

/**
 * enum gu_unwind_flag - Input bits of gu_stack_info::flags.
 * @GU_FLAG_HINT_SET_FP:      Do not unwind with DWARF: symbolize the PCs in
 *                            gu_stack_info::ustack_fp instead.  gu_unwind()
 *                            also sets this bit itself when the pid's main
 *                            executable is a Go binary; it then applies from
 *                            the next unwind of the same struct, so clear it
 *                            when reusing a struct for another sample.
 * @GU_FLAG_FP_ALLOW_UNKNOWN: With GU_FLAG_HINT_SET_FP, report PCs outside any
 *                            known executable mapping as GU_FRAME_ANON_EXEC
 *                            frames instead of stopping with
 *                            GU_UNWIND_REASON_NO_EXEC_PC.
 */
enum gu_unwind_flag {
	GU_FLAG_HINT_SET_FP = (1ULL << 0),
	/*
	 * FP stacks may contain executable regions that are not backed by ELF
	 * mappings.  Keep this opt-in so native FP unwinds still stop on
	 * obviously broken frame chains by default.
	 */
	GU_FLAG_FP_ALLOW_UNKNOWN = (1ULL << 1),
};

/**
 * gu_flags_set() - Set an input flag in @info->flags.
 * @info: The stack info.
 * @flag: The flag to set.
 */
static inline void gu_flags_set(struct gu_stack_info *info, enum gu_unwind_flag flag)
{
	info->flags |= flag;
}

/**
 * gu_flags_clear() - Clear an input flag in @info->flags.
 * @info: The stack info.
 * @flag: The flag to clear.
 */
static inline void gu_flags_clear(struct gu_stack_info *info, enum gu_unwind_flag flag)
{
	info->flags &= ~flag;
}

/**
 * gu_flags_is_set() - Test an input flag in @info->flags.
 * @info: The stack info.
 * @flag: The flag to test.
 *
 * Return: True if @flag is set.
 */
static inline bool gu_flags_is_set(const struct gu_stack_info *info, enum gu_unwind_flag flag)
{
	return !!(info->flags & flag);
}

/* The stop reason occupies bits 16..23 of gu_stack_info::flags. */
#define GU_FLAG_REASON_SHIFT 16
#define GU_FLAG_REASON_MASK (0xffULL << GU_FLAG_REASON_SHIFT)

/**
 * enum gu_unwind_reason - Why gu_unwind() stopped, stored in flags bits 16..23.
 *
 * A successful gu_unwind() (return value >= 0) may still carry a failure
 * reason: the frames delivered before the failure are valid.
 */
enum gu_unwind_reason {
	GU_UNWIND_REASON_OK = 0, // No failure recorded (e.g. DWARF frame limit hit)
	GU_UNWIND_REASON_NO_REGS, // gu_stack_info::regs is NULL
	GU_UNWIND_REASON_NO_ELF, // No executable mapping known for the pid
	GU_UNWIND_REASON_NO_CFI, // The current frame's ELF has no usable CFI
	GU_UNWIND_REASON_CFI_FAIL, // Reserved, not set by the current implementation
	GU_UNWIND_REASON_ARCH_FAIL, // Reserved, not set by the current implementation
	GU_UNWIND_REASON_PROCESS_EXIT, // Process gone, or its maps could not be loaded
	GU_UNWIND_REASON_LANG_SKIP, // Reserved, not set by the current implementation
	GU_UNWIND_REASON_TRUNCATED, // Frame-pointer mode frame limit reached
	GU_UNWIND_REASON_NO_EXEC_PC, // PC not in a known executable ELF mapping
	GU_UNWIND_REASON_CFI_FRAME_DECODE_FAILED, // No CFI could be decoded for the PC
	GU_UNWIND_REASON_CFI_FRAME_CFA_FAILED, // No CFI rule available for a register
	GU_UNWIND_REASON_CFI_FRAME_CFA_CALC_FAILED, // Evaluating a CFI rule failed
	GU_UNWIND_REASON_END_OF_STACK, // Reached a known stack bottom
	GU_UNWIND_REASON_STACK_READ_OUT_OF_RANGE, // CFI needs stack bytes outside the dump
	GU_UNWIND_REASON_NO_PROGRESS, // Next frame did not advance the stack pointer (unwind loop)
	GU_UNWIND_REASON_UNKNOWN = 0xff, // Unknown failure
};

/**
 * gu_flags_reason() - Extract the stop reason from gu_stack_info::flags.
 * @flags: The flags field.
 *
 * Return: The reason stored in bits 16..23.
 */
static inline enum gu_unwind_reason gu_flags_reason(uint64_t flags)
{
	return (enum gu_unwind_reason)((flags & GU_FLAG_REASON_MASK) >> GU_FLAG_REASON_SHIFT);
}

/**
 * gu_flags_set_reason() - Store a stop reason in @info->flags.
 * @info:   The stack info.
 * @reason: The reason to store; the input flag bits are preserved.
 */
static inline void gu_flags_set_reason(struct gu_stack_info *info, enum gu_unwind_reason reason)
{
	info->flags &= ~GU_FLAG_REASON_MASK;
	info->flags |= ((uint64_t)reason << GU_FLAG_REASON_SHIFT);
}

/**
 * enum gu_event_type - Events for gu_event_occur().
 * @GU_EVENT_PROCESS_EXIT:  A process exited.  Payload: a
 *                          struct gu_process_exit_event *.
 * @GU_EVENT_MODULE_RELOAD: Kernel modules changed: reload /proc/kallsyms.
 *                          Payload: ignored, pass NULL.
 */
enum gu_event_type {
	GU_EVENT_PROCESS_EXIT,
	GU_EVENT_MODULE_RELOAD,
};

/**
 * struct gu_statistics - Counters of one context, see gu_copy_statistics().
 *
 * Gauges ("active", "mem") reflect the current state; the other fields are
 * cumulative since gu_init().
 */
struct gu_statistics {
	uint64_t elf_ctx_count; // Active ELF contexts
	uint64_t pid_ctx_count; // Active PID contexts

	uint64_t elf_ctx_alloc_count; // Total ELF context allocations
	uint64_t pid_ctx_alloc_count; // Total PID context allocations
	uint64_t pid_ctx_swept_count; // PID contexts of gone processes reclaimed at high water
	uint64_t retired_elf_ctx_count; // ELF contexts waiting for TTL cleanup
	uint64_t retired_elf_cache_hit; // Zero-ref ELF contexts reused before TTL
	uint64_t retired_elf_expired; // Retired ELF contexts expired by cache tick
	uint64_t pid_maps_reload_count; // PID maps reloads caused by executable PC misses
	uint64_t pid_maps_reload_throttle_count; // PC-miss reloads skipped by per-pid gate
	uint64_t elf_file_cache_hit; // ELF loads served by file identity, not parsed

	uint64_t symbols_mem_size; // Memory used for symbols
	uint64_t cfi_mem_size; // Memory used for CFI data
	uint64_t cfi_data_mem_size; // Memory used for CFI instruction data
	uint64_t kernel_symbols_mem_size; // Memory used for kernel symbols
	uint64_t unique_id_caused_reload_count; // Number of times unique_id caused a reload of pid
	uint64_t symbol_name_read_failures; // Symbol lookups whose compressed name did not decompress
};

#ifdef __cplusplus
}
#endif

#endif /* _GUNWINDER_TYPES_H */
