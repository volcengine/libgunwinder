/* SPDX-License-Identifier: LGPL-3.0-or-later */

#ifndef _GUNWINDER_UNWINDER_H
#define _GUNWINDER_UNWINDER_H

#include <stddef.h>

#include "unwinder_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * libgunwinder - DWARF/frame-pointer unwinder for user stack snapshots.
 *
 * Usage: gu_init() a context, feed struct gu_stack_info snapshots to
 * gu_unwind(), report process exits with gu_event_occur(), gu_cleanup().
 *
 * Thread-safety model:
 *
 * - Each context has a recursive mutex.  Every gu_* function taking a
 *   context locks it for the whole call, except the kernel-symbol functions
 *   (a separate process-global read-write lock) and the deprecated
 *   gu_get_statistics().  Different
 *   threads may call into the same context; the calls are serialized.
 * - The unit of concurrency is the context.  Different contexts share
 *   nothing but the kernel-symbol lock (with the table size hint it
 *   guards), the pid-context listener registry (its own mutex), the
 *   one-time libelf initialization and the log hooks (gu_set_print_fn(),
 *   gu_set_verbose(): set them before any other call).  Every other piece
 *   of file-scope mutable state is __thread (the scratch of CFI evaluation,
 *   of the /proc/<pid>/maps parser and of the debug dump): a new one must be
 *   too, or locked and listed here.  Calls on different contexts may
 *   therefore run concurrently, one thread each; a process is best handled
 *   by one context, as two would each build and keep its state.
 * - Because that scratch is per thread, a frame callback or a listener
 *   must not call into a different context: it would reuse the scratch the
 *   interrupted call is still using.
 * - Kernel symbols live in the context that loaded them (gu_init_cfg::
 *   no_kernel_symbols unset); a lookup through it needs it alive, so it
 *   must outlive every lookup made through it.
 * - Nothing is async-signal-safe.
 * - Frame callbacks and pid-context listeners run synchronously on the
 *   calling thread, with the context mutex held.  A frame callback must not
 *   call any gu_* function on the same context.  A listener may call the
 *   private-info functions on it (the mutex is recursive) but not
 *   gu_unwind(), gu_preload_pid_debug_info(),
 *   gu_event_occur() or gu_cleanup().
 * - gu_cleanup() must not run concurrently with any other call on its
 *   context; afterwards every pointer obtained from the context is invalid.
 *
 * Unless stated otherwise, a NULL context or a NULL required pointer makes
 * a function fail (or do nothing for void functions).
 */

struct gu_context;

/**
 * typedef gu_frame_callback_t - Callback invoked for each unwound frame.
 * @frame:  The frame; valid only during the call, see struct gu_frame_record
 *          for the lifetime of the strings and ELF info it points to.
 * @cb_ctx: The user_ctx passed to gu_unwind().
 */
typedef void (*gu_frame_callback_t)(const struct gu_frame_record *frame, void *cb_ctx);

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

/**
 * enum gu_pid_ctx_event_type - Lifecycle events of a per-process context.
 * @GU_PID_CTX_EVENT_CREATE:  A process context was created by gu_unwind() or
 *                            gu_preload_pid_debug_info().  Handlers must be
 *                            idempotent: the same instance may be reported
 *                            more than once.
 * @GU_PID_CTX_EVENT_DESTROY: A process context was released by a
 *                            GU_EVENT_PROCESS_EXIT event or because gu_unwind()
 *                            saw a new unique_id for the pid.  Not sent by
 *                            gu_cleanup().
 */
enum gu_pid_ctx_event_type {
	GU_PID_CTX_EVENT_CREATE = 1,
	GU_PID_CTX_EVENT_DESTROY = 2,
};

/**
 * struct gu_pid_ctx_event - Payload of a pid-context listener call.
 * @pid:        Process id.
 * @type:       See enum gu_pid_ctx_event_type.
 * @start_time: unique_id of the process instance (see gu_stack_info), or 0
 *              if unknown.
 * @comm:       Process comm, NUL-terminated, possibly empty.
 */
struct gu_pid_ctx_event {
	int pid;
	unsigned int type;
	unsigned long long start_time;
	char comm[TASK_COMM_LEN];
};

/**
 * struct gu_debuginfo_mem_stat_elf - Debug-info memory of one ELF in a pid.
 * @path:           ELF path (gu_elf_info::elf_file_path), owned by the
 *                  snapshot.
 * @refcnt:         References to the shared ELF cache entry: one per
 *                  executable mapping of it, summed over all process
 *                  contexts (a process mapping it twice counts twice).
 * @symbol_bytes:   Symbol table cache bytes.
 * @cfi_fde_bytes:  CFI FDE interval cache bytes.
 * @cfi_data_bytes: CFI instruction cache bytes.
 * @total_bytes:    Sum of the three above: the whole ELF entry, not a share.
 * @pss_bytes:      @total_bytes / @refcnt.
 * @symbol_name_read_failures: Symbol lookups in this ELF whose name did not
 *                  decompress (the frame shows its address instead).
 */
struct gu_debuginfo_mem_stat_elf {
	char *path;
	uint64_t refcnt;
	uint64_t symbol_bytes;
	uint64_t cfi_fde_bytes;
	uint64_t cfi_data_bytes;
	uint64_t total_bytes;
	uint64_t pss_bytes;
	uint64_t symbol_name_read_failures;
};

/**
 * struct gu_debuginfo_mem_stat_pid - Debug-info memory of one process context.
 * @pid:         Process id.
 * @unique_id:   unique_id of the process instance.
 * @comm:        Process comm.
 * @key_path:    Path of the first mapped ELF (normally the main executable),
 *               owned by the snapshot.
 * @elf_count:   Number of entries in @elfs (each ELF listed once).
 * @total_bytes: Sum of @elfs[].total_bytes; ELFs shared with other
 *               processes are counted in full here.
 * @pss_bytes:   Sum of @elfs[].pss_bytes.
 * @elfs:        Per-ELF entries.
 */
struct gu_debuginfo_mem_stat_pid {
	int pid;
	uint64_t unique_id;
	char comm[TASK_COMM_LEN];
	char *key_path;
	size_t elf_count;
	uint64_t total_bytes;
	uint64_t pss_bytes;
	struct gu_debuginfo_mem_stat_elf *elfs;
};

/**
 * struct gu_debuginfo_mem_stat_snapshot - Debug-info memory of a context.
 * @pid_count:   Number of entries in @pids.
 * @total_bytes: Sum of @pids[].total_bytes.  An ELF shared by N processes is
 *               counted N times, so this overstates the memory held; prefer
 *               @pss_bytes.  Retired ELF entries are not included.
 * @pss_bytes:   Sum of @pids[].pss_bytes.
 * @pids:        Per-process entries.
 */
struct gu_debuginfo_mem_stat_snapshot {
	size_t pid_count;
	uint64_t total_bytes;
	uint64_t pss_bytes;
	struct gu_debuginfo_mem_stat_pid *pids;
};

/**
 * struct gu_process_exit_event - Payload of GU_EVENT_PROCESS_EXIT.
 * @pid:        Process id.
 * @start_time: unique_id of the exited instance, or 0 to match whatever
 *              instance is cached for @pid.
 */
struct gu_process_exit_event {
	int pid;
	unsigned long long start_time;
};

/**
 * typedef pid_ctx_callback - Pid-context listener.
 * @e:   Event payload, valid only during the call.
 * @ctx: The cb_ctx given at registration.
 *
 * Runs on the thread that created or released the process context, with
 * that context's mutex held; see the thread-safety model above for what it
 * may call.
 */
typedef void (*pid_ctx_callback)(const struct gu_pid_ctx_event *e, void *ctx);

/*
 * The listener registry is process-global: listeners receive the events of
 * every context.  It holds at most 16 listeners.  Never unregister a
 * listener from within a listener call.
 */

/**
 * gu_register_pid_ctx_event_listener() - Register a pid-context listener.
 * @callback: Listener, must not be NULL.
 * @cb_ctx:   Passed to @callback.
 *
 * For listeners whose @cb_ctx lives as long as the process: unregistering
 * does not wait for calls in flight on other threads, which may still run
 * (and use @cb_ctx) after gu_unregister_pid_ctx_event_listener() returned.
 * The same pair may be registered more than once and is then called once per
 * registration.
 *
 * Return: 0 on success, -1 if @callback is NULL or the registry is full.
 */
int gu_register_pid_ctx_event_listener(pid_ctx_callback callback, void *cb_ctx);

/**
 * gu_register_pid_ctx_event_listener_waitable() - Register a waitable listener.
 * @callback: Listener, must not be NULL.
 * @cb_ctx:   Passed to @callback.
 *
 * Like gu_register_pid_ctx_event_listener(), but
 * gu_unregister_pid_ctx_event_listener() waits until calls of this listener
 * in flight on other threads have returned, so @cb_ctx may be freed right
 * after it.  Costs one extra registry lock round trip per event.
 *
 * Return: 0 on success, -1 if @callback is NULL or the registry is full.
 */
int gu_register_pid_ctx_event_listener_waitable(pid_ctx_callback callback,
					       void *cb_ctx);

/**
 * gu_unregister_pid_ctx_event_listener() - Remove a pid-context listener.
 * @callback: Listener given at registration.
 * @cb_ctx:   cb_ctx given at registration.
 *
 * Removes every registration of the (@callback, @cb_ctx) pair.  Waits for
 * in-flight calls only for waitable registrations; must not be called from a
 * listener (a waitable one would wait for itself).
 *
 * Return: 0 if at least one registration was removed, otherwise -1.
 */
int gu_unregister_pid_ctx_event_listener(pid_ctx_callback callback, void *cb_ctx);

/**
 * gu_init() - Create an unwinder context.
 * @cfg: Configuration, copied; not referenced after the call.
 *
 * Also loads /proc/kallsyms (a failure there only makes the kernel-symbol
 * functions fail).  See the thread-safety model: one context per process at
 * a time.
 *
 * Return: The new context, or NULL if @cfg is NULL or sets the unsupported
 * go_buildid_only, libelf cannot be initialized or memory runs out.
 */
struct gu_context *gu_init(const struct gu_init_cfg *cfg);

/**
 * gu_cleanup() - Destroy a context and everything it owns.
 * @ctx: The context, may be NULL.
 *
 * Releases all process and ELF caches and kernel symbols without sending
 * GU_PID_CTX_EVENT_DESTROY (listeners stay registered).  All pointers
 * obtained from @ctx become invalid.  Must not run concurrently with any
 * other call on @ctx.
 */
void gu_cleanup(struct gu_context *ctx);

/**
 * gu_unwind() - Unwind one stack snapshot.
 * @ctx:      The context.
 * @info:     The snapshot, see struct gu_stack_info.  Modified: the DWARF
 *            path overwrites registers in @info->regs while walking, and
 *            @info->flags receives the stop reason (and possibly
 *            GU_FLAG_HINT_SET_FP, see enum gu_unwind_flag).
 * @callback: Called once per frame, innermost first; must not be NULL.
 * @user_ctx: Passed to @callback.
 *
 * Unwinds with DWARF CFI from @info->regs and @info->stack_data, falling
 * back to a frame-pointer walk inside the snapshot when CFI fails; with
 * GU_FLAG_HINT_SET_FP it only symbolizes @info->ustack_fp.  Creates the
 * process context on first use (reading /proc/<pid>/maps and the ELFs,
 * sending GU_PID_CTX_EVENT_CREATE) and rebuilds it when @info->unique_id
 * shows the pid was reused.  May also reload the mappings, at most once per
 * 30-90 s per process, when the sampled PC is not in a known mapping.  The
 * mappings are only read while the live process is the sample's instance
 * (the start time of the thread group @info->pid belongs to equals a
 * nonzero @info->unique_id; with 0, while the pid exists), and a view read
 * is only used if it still is once read: otherwise the sample creates,
 * reloads or replaces no context, and fails with _PROCESS_EXIT when it has
 * no context of its own instance.  They are read through /proc/@info->tid
 * when the leader has exited before that thread.
 *
 * Return: On success a value >= 0 that counts unwinder iterations; it is
 * NOT the number of frames delivered (count them in @callback), and the
 * stop reason in @info->flags may still be a failure.  -1 on failure, with
 * the reason in @info->flags (GU_UNWIND_REASON_NO_REGS, _PROCESS_EXIT or
 * _NO_ELF); @info->flags is left untouched if @ctx or @info is NULL.
 */
int gu_unwind(struct gu_context *ctx, struct gu_stack_info *info, gu_frame_callback_t callback,
	      void *user_ctx);

/**
 * gu_preload_pid_debug_info() - Create a process context ahead of sampling.
 * @ctx: The context.
 * @pid: Process id.
 *
 * Loads the mappings, symbols and CFI of @pid and sends
 * GU_PID_CTX_EVENT_CREATE, as the first gu_unwind() for it would.  An
 * existing context for @pid is returned as is, without a pid-reuse check.
 *
 * Return: The unique_id of the process context.  0 is ambiguous: the
 * process is gone, has no loadable executable mapping, or its start time is
 * unknown.
 */
uint64_t gu_preload_pid_debug_info(struct gu_context *ctx, int pid);

/**
 * gu_set_pid_private_info() - Attach caller data to a process context.
 * @ctx:     The context.
 * @pid:     Process id.
 * @data:    Data to copy; NULL (or @size <= 0) just drops the old data.
 * @size:    Size of @data in bytes.
 *
 * Replaces any previous data with a copy of @data.  The data lives until
 * the process context is released (process exit, pid reuse, gu_cleanup());
 * mapping reloads keep it.  Silently does nothing when no process context
 * exists for @pid, and silently drops the data if the copy cannot be
 * allocated.
 */
void gu_set_pid_private_info(struct gu_context *ctx, int pid, const void *data, int size);

/**
 * gu_get_pid_private_info() - Copy the caller data of a process context.
 * @ctx:  The context.
 * @pid:  Process id.
 * @size: Optional; receives the size of the copy, 0 when NULL is returned.
 *
 * Return: A malloc'd copy that the caller must free(), or NULL if there is
 * no data (or no memory).
 */
void *gu_get_pid_private_info(struct gu_context *ctx, int pid, int *size);

/**
 * gu_event_occur() - Report an event to the context.
 * @ctx:        The context.
 * @type:       The event, see enum gu_event_type.
 * @event_data: Payload as documented for @type.
 *
 * GU_EVENT_PROCESS_EXIT releases the matching process context (sending
 * GU_PID_CTX_EVENT_DESTROY); nothing happens if the
 * cached instance has a different unique_id or the payload is NULL.
 * GU_EVENT_MODULE_RELOAD reloads kernel symbols, unless the context was
 * created without them (gu_init_cfg.no_kernel_symbols).  Every event also releases
 * expired unreferenced ELF cache entries.
 *
 * Return: 0, or -1 if @ctx is NULL.  Failures while handling the event are
 * not reported.
 */
int gu_event_occur(struct gu_context *ctx, enum gu_event_type type, void *event_data);

/**
 * gu_load_kernel_symbols() - (Re)load kernel text symbols from /proc/kallsyms.
 * @ctx: The context.
 *
 * Replaces the context's kernel-symbol tables atomically.  Uses the
 * process-global kernel-symbol read-write lock, not the context mutex:
 * lookups, from any thread, share it, and only the swap of the tables
 * excludes them.  Addresses are 0 when
 * kallsyms hides them (kptr_restrict).
 *
 * Return: 0 on success, -1 on failure (the old tables are kept).
 */
int gu_load_kernel_symbols(struct gu_context *ctx);

/**
 * gu_search_kernel_address() - Look up a kernel text symbol by name.
 * @ctx:  The context.
 * @name: Symbol name.
 *
 * For a name listed several times, returns the first address in kallsyms
 * order.  Thread-safety as gu_load_kernel_symbols().
 *
 * Return: The address, or 0 if not found (or hidden).
 */
uint64_t gu_search_kernel_address(struct gu_context *ctx, const char *name);

/**
 * gu_search_kernel_symbol() - Look up the kernel text symbol containing an address.
 * @ctx:    The context.
 * @addr:   Kernel address.
 * @buf:    Optional; receives the symbol name, truncated and NUL-terminated.
 * @len:    Size of @buf.
 * @offset: Optional; receives @addr minus the symbol start.
 *
 * Thread-safety as gu_load_kernel_symbols().
 *
 * Return: 0 if found, -1 otherwise.
 */
int gu_search_kernel_symbol(struct gu_context *ctx, uint64_t addr, char *buf, size_t len, uint64_t *offset);

/**
 * typedef gu_print_fn_t - Log sink.
 * @output_string: Formatted message, valid only during the call.
 */
typedef void (*gu_print_fn_t)(const char *output_string);

/**
 * gu_set_print_fn() - Route library log output to @fn.
 * @fn: Sink, or NULL for stdout (errors go to stderr).
 *
 * Process-global and unsynchronized: set it before creating a context.
 */
void gu_set_print_fn(gu_print_fn_t fn);

/**
 * gu_set_verbose() - Enable or disable verbose (per-frame) logging.
 * @verbose: Non-zero to enable.
 *
 * Process-global and unsynchronized: set it before creating a context.
 */
void gu_set_verbose(int verbose);

/**
 * gu_get_statistics() - Deprecated: use gu_copy_statistics().
 * @ctx: The context, must not be NULL.
 *
 * Returns a pointer into @ctx that is read without the context mutex, so the
 * values may be torn while another thread uses @ctx.  Kept for the
 * single-threaded tools in this repository.
 *
 * Return: Pointer to the live counters, valid until gu_cleanup().
 */
struct gu_statistics *gu_get_statistics(struct gu_context *ctx);

/**
 * gu_copy_statistics() - Copy the counters of a context.
 * @ctx: The context.
 * @out: Receives the counters, copied under the context mutex.
 *
 * Return: 0 on success, -1 if @ctx or @out is NULL.
 */
int gu_copy_statistics(struct gu_context *ctx, struct gu_statistics *out);

/**
 * gu_export_debuginfo_mem_stat_snapshot() - Export debug-info memory per pid/ELF.
 * @ctx: The context.
 * @out: Receives an allocated snapshot on success, NULL on failure.
 *
 * Copies everything under the context mutex; the caller owns the snapshot
 * and frees it with gu_debuginfo_mem_stat_snapshot_free().
 *
 * Return: 0 on success, -1 on failure.
 */
int gu_export_debuginfo_mem_stat_snapshot(
	struct gu_context *ctx,
	struct gu_debuginfo_mem_stat_snapshot **out);

/**
 * gu_debuginfo_mem_stat_snapshot_free() - Free a snapshot and all its strings.
 * @snapshot: Snapshot from gu_export_debuginfo_mem_stat_snapshot(), may be NULL.
 */
void gu_debuginfo_mem_stat_snapshot_free(
	struct gu_debuginfo_mem_stat_snapshot *snapshot);

/*
 * Debug dumps: gu_debug_dump_sample() saves a snapshot so that bt_debug can
 * replay it offline (gu_init_cfg::debug_print).
 */

/**
 * gu_debug_dump_sample() - Write a snapshot to a "<pid>_<time>_<n>.dump.v2" file.
 * @info:               Snapshot; @info->regs must hold a full struct pt_regs.
 * @path:               Directory to write to.
 * @dump_related_files: Also copy the maps and mapped ELFs of the process.
 *
 * Uses a process-global file counter; errors are not reported.
 */
void gu_debug_dump_sample(const struct gu_stack_info *info, const char *path, bool dump_related_files);

/**
 * gu_read_stack_dump() - Load a snapshot written by gu_debug_dump_sample().
 * @path: Dump file; the ".dump" or ".dump.v2" suffix selects the format.
 *
 * Rejects files whose register block is not sizeof(struct pt_regs) of the
 * build architecture or whose FP level exceeds the ustack_fp capacity.
 * unique_id of the result is 0.
 *
 * Return: A snapshot to release with gu_free_stack_dump(), or NULL on
 * failure.
 */
struct gu_stack_info *gu_read_stack_dump(const char *path);

/**
 * gu_free_stack_dump() - Free a snapshot from gu_read_stack_dump().
 * @info: The snapshot, may be NULL.
 *
 * Frees @info, its regs and stack_data; nothing else.
 */
void gu_free_stack_dump(struct gu_stack_info *info);

/**
 * enum gu_debug_dump_version_type - Dump file format, from the file name.
 * @GU_DEBUG_DUMP_VER_ERROR:  Unknown suffix.
 * @GU_DEBUG_DUMP_VERSION_V1: ".dump".
 * @GU_DEBUG_DUMP_VERSION_V2: ".dump.v2".
 */
enum gu_debug_dump_version_type {
	GU_DEBUG_DUMP_VER_ERROR = 0,
	GU_DEBUG_DUMP_VERSION_V1 = 1,
	GU_DEBUG_DUMP_VERSION_V2 = 2,
};

/**
 * gu_debug_dump_version() - Classify a dump file by its name.
 * @path: File name.
 *
 * Return: The format, see enum gu_debug_dump_version_type.
 */
enum gu_debug_dump_version_type gu_debug_dump_version(const char *path);

#ifdef __cplusplus
}
#endif

#endif
