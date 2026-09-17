/* SPDX-License-Identifier: LGPL-3.0-or-later */

#ifndef _GUNWINDER_TYPES_H
#define _GUNWINDER_TYPES_H

#include <linux/types.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

/**
 * struct gu_elf_info - Public metadata for an ELF image.
 * @base_name: Base filename without the directory path.
 * @elf_file_path: Full path to the mapped ELF file.
 * @debug_file_path: Full path to the separate debug file, if any.
 * @build_id: Build ID bytes used for debug-file matching.
 * @build_id_len: Length of @build_id in bytes.
 * @golang: True when the image is detected as a Go binary.
 */
struct gu_elf_info {
	char *base_name;
	char *elf_file_path;
	char *debug_file_path;
	unsigned char *build_id;
	int build_id_len;
	bool golang;
};

enum gu_frame_flag {
	GU_FRAME_ANON_EXEC = (1U << 0),
};

/**
 * struct gu_frame_record - Frame emitted by gu_unwind().
 * @pc: Program counter relative to the owning ELF load bias.
 * @abs_pc: Process virtual address before ELF load-bias normalization.
 * @offset: Offset from the start of @symbol.
 * @symbol: Symbol/function name, or NULL when unresolved.
 * @elf_info: ELF metadata associated with this frame.
 * @flags: Frame metadata, see gu_frame_flag.
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
 * struct gu_init_cfg - Unwinder initialization configuration.
 * @debug_print: Enable debug output while initializing and unwinding.
 * @go_not_strip_name: Preserve full Go symbol names.
 * @go_buildid_only: Report Go frames by build ID and function entry only.
 */
struct gu_init_cfg {
	bool debug_print;
	bool go_not_strip_name;
	bool go_buildid_only;
};

#define MAX_FP_STACK_LEVEL (128 - 1)

/**
 * struct gu_stack_info - Caller-provided stack snapshot.
 * @pid: Process ID for the sampled task.
 * @stack_size: Size of @stack_data in bytes.
 * @unique_id: Process-instance ID used to detect PID reuse.
 * @regs: Architecture-specific register block.
 * @regs_size: Size of @regs in bytes.
 * @flags: Unwind flags and encoded stop reason.
 * @ustack_fp: Optional user stack frame-pointer chain.
 * @ustack_fp_level: Number of valid entries in @ustack_fp.
 * @stack_data: Raw user stack bytes captured by the caller.
 *
 * libgunwinder does not own @regs or @stack_data. They must remain valid until
 * gu_unwind() returns.
 */
struct gu_stack_info {
	pid_t pid;
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
 * enum gu_unwind_flag - Optional hints and controls for a stack snapshot.
 * @GU_FLAG_HINT_SET_FP: Use the frame-pointer unwind path when possible.
 * @GU_FLAG_FP_ALLOW_UNKNOWN: Keep executable frames without ELF backing.
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
 * gu_flags_set() - Set an unwind flag.
 * @info: Stack snapshot to update.
 * @flag: Flag to set.
 */
static inline void gu_flags_set(struct gu_stack_info *info, enum gu_unwind_flag flag)
{
	info->flags |= flag;
}

/**
 * gu_flags_clear() - Clear an unwind flag.
 * @info: Stack snapshot to update.
 * @flag: Flag to clear.
 */
static inline void gu_flags_clear(struct gu_stack_info *info, enum gu_unwind_flag flag)
{
	info->flags &= ~flag;
}

/**
 * gu_flags_is_set() - Test whether an unwind flag is set.
 * @info: Stack snapshot to inspect.
 * @flag: Flag to test.
 *
 * Return: true if @flag is set, otherwise false.
 */
static inline bool gu_flags_is_set(const struct gu_stack_info *info, enum gu_unwind_flag flag)
{
	return !!(info->flags & flag);
}

#define GU_FLAG_REASON_SHIFT 16
#define GU_FLAG_REASON_MASK (0xffULL << GU_FLAG_REASON_SHIFT)

/**
 * enum gu_unwind_reason - Stop reason encoded in struct gu_stack_info::flags.
 * @GU_UNWIND_REASON_OK: Unwind completed successfully.
 * @GU_UNWIND_REASON_NO_REGS: No register context was provided.
 * @GU_UNWIND_REASON_NO_ELF: Executable ELF metadata was unavailable.
 * @GU_UNWIND_REASON_NO_CFI: CFI data was unavailable.
 * @GU_UNWIND_REASON_CFI_FAIL: CFI evaluation failed.
 * @GU_UNWIND_REASON_ARCH_FAIL: Architecture-specific register handling failed.
 * @GU_UNWIND_REASON_PROCESS_EXIT: Target process exited during unwinding.
 * @GU_UNWIND_REASON_LANG_SKIP: Language-specific unwinder skipped the frame.
 * @GU_UNWIND_REASON_TRUNCATED: Stack data was truncated.
 * @GU_UNWIND_REASON_NO_EXEC_PC: Program counter was outside executable ranges.
 * @GU_UNWIND_REASON_CFI_FRAME_DECODE_FAILED: FDE/CIE decode failed.
 * @GU_UNWIND_REASON_CFI_FRAME_CFA_FAILED: CFA rule was unavailable.
 * @GU_UNWIND_REASON_CFI_FRAME_CFA_CALC_FAILED: CFA expression evaluation failed.
 * @GU_UNWIND_REASON_END_OF_STACK: Reached a known stack-bottom frame.
 * @GU_UNWIND_REASON_STACK_READ_OUT_OF_RANGE: CFI read outside stack snapshot.
 * @GU_UNWIND_REASON_NO_PROGRESS: Next frame did not advance the stack (unwind loop).
 * @GU_UNWIND_REASON_UNKNOWN: Unclassified stop reason.
 */
enum gu_unwind_reason {
	GU_UNWIND_REASON_OK = 0,
	GU_UNWIND_REASON_NO_REGS,
	GU_UNWIND_REASON_NO_ELF,
	GU_UNWIND_REASON_NO_CFI,
	GU_UNWIND_REASON_CFI_FAIL,
	GU_UNWIND_REASON_ARCH_FAIL,
	GU_UNWIND_REASON_PROCESS_EXIT,
	GU_UNWIND_REASON_LANG_SKIP,
	GU_UNWIND_REASON_TRUNCATED,
	GU_UNWIND_REASON_NO_EXEC_PC,
	GU_UNWIND_REASON_CFI_FRAME_DECODE_FAILED,
	GU_UNWIND_REASON_CFI_FRAME_CFA_FAILED,
	GU_UNWIND_REASON_CFI_FRAME_CFA_CALC_FAILED,
	GU_UNWIND_REASON_END_OF_STACK,
	GU_UNWIND_REASON_STACK_READ_OUT_OF_RANGE,
	GU_UNWIND_REASON_NO_PROGRESS,
	GU_UNWIND_REASON_UNKNOWN = 0xff,
};

/**
 * gu_flags_reason() - Extract the encoded unwind stop reason.
 * @flags: Flags value from struct gu_stack_info.
 *
 * Return: Unwind stop reason.
 */
static inline enum gu_unwind_reason gu_flags_reason(uint64_t flags)
{
	return (enum gu_unwind_reason)((flags & GU_FLAG_REASON_MASK) >> GU_FLAG_REASON_SHIFT);
}

/**
 * gu_flags_set_reason() - Store the unwind stop reason.
 * @info: Stack snapshot to update.
 * @reason: Stop reason to encode.
 */
static inline void gu_flags_set_reason(struct gu_stack_info *info, enum gu_unwind_reason reason)
{
	info->flags &= ~GU_FLAG_REASON_MASK;
	info->flags |= ((uint64_t)reason << GU_FLAG_REASON_SHIFT);
}

/**
 * enum gu_event_type - External lifecycle events.
 * @GU_EVENT_PROCESS_EXIT: Target process exited and cached PID state is stale.
 * @GU_EVENT_MODULE_RELOAD: Target process module mappings should be reloaded.
 */
enum gu_event_type {
	GU_EVENT_PROCESS_EXIT,
	GU_EVENT_MODULE_RELOAD,
};

/**
 * struct gu_statistics - Memory and cache statistics for a context.
 * @elf_ctx_count: Number of active ELF contexts.
 * @pid_ctx_count: Number of active PID contexts.
 * @elf_ctx_alloc_count: Total ELF context allocation count.
 * @pid_ctx_alloc_count: Total PID context allocation count.
 * @retired_elf_ctx_count: ELF contexts waiting for TTL cleanup.
 * @retired_elf_cache_hit: Zero-ref ELF contexts reused before TTL.
 * @retired_elf_expired: Retired ELF contexts expired by cache tick.
 * @pid_maps_reload_count: PID maps reloads caused by executable PC misses.
 * @pid_maps_reload_throttle_count: PC-miss reloads skipped by per-pid gate.
 * @symbols_mem_size: Bytes used by symbol metadata.
 * @cfi_mem_size: Bytes used by CFI metadata.
 * @cfi_data_mem_size: Bytes used by copied CFI instruction data.
 * @kernel_symbols_mem_size: Bytes used by kernel symbol metadata.
 * @unique_id_caused_reload_count: PID context reloads caused by unique_id changes.
 */
struct gu_statistics {
	uint64_t elf_ctx_count;
	uint64_t pid_ctx_count;

	uint64_t elf_ctx_alloc_count;
	uint64_t pid_ctx_alloc_count;
	uint64_t retired_elf_ctx_count;
	uint64_t retired_elf_cache_hit;
	uint64_t retired_elf_expired;
	uint64_t pid_maps_reload_count;
	uint64_t pid_maps_reload_throttle_count;

	uint64_t symbols_mem_size;
	uint64_t cfi_mem_size;
	uint64_t cfi_data_mem_size;
	uint64_t kernel_symbols_mem_size;
	uint64_t unique_id_caused_reload_count;
};

#endif /* _GUNWINDER_TYPES_H */
