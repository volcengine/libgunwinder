/* SPDX-License-Identifier: LGPL-3.0-or-later */

#ifndef _GUNWINDER_UNWINDER_H
#define _GUNWINDER_UNWINDER_H

#include "unwinder_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * typedef gu_frame_callback_t - Callback invoked for each unwound frame.
 * @frame: Frame metadata valid for the duration of the callback.
 * @cb_ctx: Caller-provided callback context.
 */
typedef void (*gu_frame_callback_t)(const struct gu_frame_record *frame, void *cb_ctx);

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

enum gu_pid_ctx_event_type {
	GU_PID_CTX_EVENT_CREATE = 1,
	GU_PID_CTX_EVENT_DESTROY = 2,
};

/**
 * struct gu_pid_ctx_event - PID context lifecycle event payload.
 * @pid:		Process id.
 * @type:		Event type, see enum gu_pid_ctx_event_type.
 * @start_time:		Unique id for the pid ctx instance.
 * @comm:		Process comm.
 */
struct gu_pid_ctx_event {
	int pid;
	unsigned int type;
	unsigned long long start_time;
	char comm[TASK_COMM_LEN];
};

/**
 * pid_ctx_callback - PID context lifecycle event callback.
 * @e:		Event payload.
 * @ctx:	Caller-provided context passed at registration time.
 */
typedef void (*pid_ctx_callback)(const struct gu_pid_ctx_event *e, void *ctx);

/**
 * gu_register_pid_ctx_event_listener() - Register a PID ctx event listener.
 * @callback:	Callback invoked on pid ctx create/destroy events.
 * @cb_ctx:	User context passed to @callback.
 *
 * Return: 0 on success, or -1 on failure.
 */
int gu_register_pid_ctx_event_listener(pid_ctx_callback callback, void *cb_ctx);

/**
 * gu_init() - Allocate and initialize an unwinder context.
 * @cfg: Unwinder configuration.
 *
 * Return: A new unwinder context, or NULL on failure.
 */
struct gu_context *gu_init(const struct gu_init_cfg *cfg);

/**
 * gu_cleanup() - Release an unwinder context and all cached state.
 * @ctx: Unwinder context to release.
 */
void gu_cleanup(struct gu_context *ctx);

/**
 * gu_unwind() - Unwind one caller-provided stack snapshot.
 * @ctx: Unwinder context.
 * @info: Stack snapshot and register state.
 * @callback: Callback invoked for each frame.
 * @user_ctx: User context passed to @callback.
 *
 * The memory referenced by @info must remain valid for the duration of this
 * call. The callback receives borrowed frame metadata and must copy anything it
 * needs after the callback returns.
 *
 * Return: Number of frames processed on success, or a negative value on
 * failure. The final stop reason is stored in @info->flags and can be read with
 * gu_flags_reason().
 */
int gu_unwind(struct gu_context *ctx, struct gu_stack_info *info, gu_frame_callback_t callback,
	      void *user_ctx);


/**
 * gu_preload_pid_debug_info() - Preload ELF, symbol, and CFI data for a PID.
 * @ctx: Unwinder context.
 * @pid: Process ID.
 *
 * Return: Unique ID for the process context, or 0 on failure.
 */
uint64_t gu_preload_pid_debug_info(struct gu_context *ctx, int pid);

/**
 * gu_set_pid_private_info() - Store caller-owned metadata for a PID.
 * @ctx: Unwinder context.
 * @pid: Process ID.
 * @private_info: Metadata buffer to copy.
 * @size: Metadata size in bytes.
 *
 * This function copies @private_info. If metadata already exists for @pid, it
 * is replaced.
 */
void gu_set_pid_private_info(struct gu_context *ctx, int pid, void *private_info, int size);

/**
 * gu_get_pid_private_info() - Get copied private metadata for a PID.
 * @ctx: Unwinder context.
 * @pid: Process ID.
 * @size: Output size of the returned metadata buffer.
 *
 * Return: Private metadata pointer owned by the unwinder context, or NULL if
 * not found.
 */
void *gu_get_pid_private_info(struct gu_context *ctx, int pid, int *size);

/**
 * gu_event_occur() - Notify the unwinder about an external lifecycle event.
 * @ctx: Unwinder context.
 * @type: Event type.
 * @event_data: Event-specific payload.
 *
 * Return: 0 on success, or a negative value on failure.
 */
int gu_event_occur(struct gu_context *ctx, enum gu_event_type type, void *event_data);

/**
 * gu_load_kernel_symbols() - Load kernel symbol metadata into the context.
 * @ctx: Unwinder context.
 *
 * Return: 0 on success, or a negative value on failure.
 */
int gu_load_kernel_symbols(struct gu_context *ctx);
/**
 * gu_search_kernel_address() - Search for a kernel address by symbol name.
 * @ctx:  The unwinder context.
 * @name: The symbol name to search for.
 *
 * Return: The address of the symbol, or 0 if not found.
 */
uint64_t gu_search_kernel_address(struct gu_context *ctx, const char *name);

/**
 * gu_search_kernel_symbol() - Search for a kernel symbol by address.
 * @ctx:    The unwinder context.
 * @addr:   The address to search for.
 * @buf:    Buffer to store the symbol name.
 * @len:    Size of the buffer.
 * @offset: Pointer to store the offset from the symbol start (optional).
 *
 * Return: 0 on success, or a negative value on failure.
 */
int gu_search_kernel_symbol(struct gu_context *ctx, uint64_t addr, char *buf, size_t len, uint64_t *offset);

/**
 * typedef gu_print_fn_t - Debug output callback.
 * @output_string: Null-terminated log line.
 */
typedef void (*gu_print_fn_t)(const char *output_string);

/**
 * gu_set_print_fn() - Set a custom debug output callback.
 * @fn: Print callback, or NULL to use the default output path.
 */
void gu_set_print_fn(gu_print_fn_t fn);

/**
 * gu_set_verbose() - Enable or disable verbose internal logging.
 * @verbose: Non-zero to enable verbose logging.
 */
void gu_set_verbose(int verbose);

/**
 * gu_get_statistics() - Get context statistics.
 * @ctx: Unwinder context.
 *
 * Return: Statistics owned by @ctx.
 */
struct gu_statistics *gu_get_statistics(struct gu_context *ctx);

/**
 * gu_debug_dump_sample() - Dump a stack snapshot and optional related files.
 * @info: Stack snapshot to dump.
 * @path: Destination path prefix.
 * @dump_related_files: Whether to copy maps and related ELF files.
 */
void gu_debug_dump_sample(struct gu_stack_info *info, const char *path, bool dump_related_files);

/**
 * gu_read_stack_dump() - Read a stack snapshot from a debug dump file.
 * @path: Debug dump path.
 *
 * Return: Newly allocated stack snapshot, or NULL on failure.
 */
struct gu_stack_info *gu_read_stack_dump(const char *path);

/**
 * enum gu_debug_dump_version_type - Debug dump file format version.
 * @GU_DEBUG_DUMP_VER_ERROR: Unknown or unsupported debug dump format.
 * @GU_DEBUG_DUMP_VERSION_V1: Version 1 debug dump format.
 * @GU_DEBUG_DUMP_VERSION_V2: Version 2 debug dump format.
 */
enum gu_debug_dump_version_type {
	GU_DEBUG_DUMP_VER_ERROR = 0,
	GU_DEBUG_DUMP_VERSION_V1 = 1,
	GU_DEBUG_DUMP_VERSION_V2 = 2,
};

/**
 * gu_debug_dump_version() - Detect the debug dump format version.
 * @path: Debug dump path.
 *
 * Return: Detected debug dump version, or GU_DEBUG_DUMP_VER_ERROR.
 */
enum gu_debug_dump_version_type gu_debug_dump_version(const char *path);

#ifdef __cplusplus
}
#endif

#endif
