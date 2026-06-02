/* SPDX-License-Identifier: LGPL-3.0-or-later */

#ifndef GU_PRIVATE_STACKTRACE_H
#define GU_PRIVATE_STACKTRACE_H

#include <stdint.h>
#include <sys/types.h>

#include "gunwinder/unwinder.h"

#include "gu_interval_array.h"
#include "gu_unwinder.h"
#include "gu_elf.h"

#define DUMP_VDSO_PATH "/tmp/__vdso.so"

/**
 * enum elf_scn_type - ELF sections used by the unwinder.
 * @ELF_SCN_TYPE_GO_BUILD_ID: Go build ID section.
 * @ELF_SCN_TYPE_GNU_BUILD_ID: GNU build ID section.
 * @ELF_SCN_TYPE_SYMTAB: Static symbol table.
 * @ELF_SCN_TYPE_DYNSYM: Dynamic symbol table.
 * @ELF_SCN_TYPE_DWARF_FRAME: .debug_frame section.
 * @ELF_SCN_TYPE_DWARF_FRAME_HDR: .debug_frame_hdr section.
 * @ELF_SCN_TYPE_ZDWARF_FRAME: Compressed .debug_frame section.
 * @ELF_SCN_TYPE_ZDWARF_FRAME_HDR: Compressed .debug_frame_hdr section.
 * @ELF_SCN_TYPE_EH_FRAME: .eh_frame section.
 * @ELF_SCN_TYPE_EH_FRAME_HDR: .eh_frame_hdr section.
 * @ELF_SCN_TYPE_MAX: Number of tracked section slots.
 */
enum elf_scn_type {
	ELF_SCN_TYPE_GO_BUILD_ID = 0,
	ELF_SCN_TYPE_GNU_BUILD_ID,
	ELF_SCN_TYPE_SYMTAB,
	ELF_SCN_TYPE_DYNSYM,
	ELF_SCN_TYPE_DWARF_FRAME,
	ELF_SCN_TYPE_DWARF_FRAME_HDR,
	ELF_SCN_TYPE_ZDWARF_FRAME,
	ELF_SCN_TYPE_ZDWARF_FRAME_HDR,
	ELF_SCN_TYPE_EH_FRAME,
	ELF_SCN_TYPE_EH_FRAME_HDR,
	ELF_SCN_TYPE_MAX,
};

/**
 * struct per_elf_ctx - Cached metadata for one ELF image.
 * @base_name: Base filename.
 * @elf_file_path: Resolved path to the mapped ELF file.
 * @debug_file_path: Resolved path to separate debug information.
 * @build_id: Build ID or MD5 fallback key.
 * @build_id_len: Length of @build_id in bytes.
 * @golang: True when the ELF is detected as a Go binary.
 * @elf: libelf handle for @elf_file_path.
 * @elf_fd: File descriptor for @elf_file_path.
 * @debug_elf: libelf handle for @debug_file_path.
 * @debug_elf_fd: File descriptor for @debug_file_path.
 * @scn: Tracked ELF sections.
 * @scn_elf: ELF handle owning each tracked section.
 * @sym_scn: Active symbol section index.
 * @symbols: Relative-PC interval index for symbols.
 * @gu_cfi: Parsed CFI metadata.
 * @gu_ctx: Owning global context.
 * @sym_search_size: Bytes used by the symbol interval index.
 * @eh_frame_hdr_off: File offset of .eh_frame_hdr.
 * @refcnt: Number of PID mappings referencing this ELF context.
 * @exec_virt_addr: Lowest executable virtual address in the ELF image.
 * @exec_ranges: Executable PT_LOAD ranges used for per-mapping bias.
 * @hh: uthash handle keyed by @build_id.
 */
struct per_elf_ctx {
	char *base_name;
	char *elf_file_path;
	char *debug_file_path;
	unsigned char *build_id;
	int build_id_len;
	bool golang;

	Elf *elf;
	int elf_fd;

	Elf *debug_elf;
	int debug_elf_fd;

	Elf_Scn *scn[ELF_SCN_TYPE_MAX];
	Elf *scn_elf[ELF_SCN_TYPE_MAX];

	int sym_scn;

	struct interval_array *symbols;
	struct gu_symbol_name_arena_chunk *symbol_name_arena;
	struct gu_cfi *gu_cfi;
	struct gu_context *gu_ctx;

	unsigned long sym_search_size;
	unsigned long eh_frame_hdr_off;
	unsigned long refcnt, exec_virt_addr;
	struct gu_elf_exec_ranges exec_ranges;
	bool retired;
	uint64_t retire_deadline_ns;

	UT_hash_handle hh;
};

/**
 * struct per_elf_map_ctx - Per-mapping view of shared ELF metadata.
 * @elf_ctx: Shared ELF metadata and symbol/CFI cache.
 * @map_exec_virt_addr: ELF virtual address matching this maps interval.
 *
 * A process can map distinct executable PT_LOAD segments from the same ELF at
 * different file offsets.  The symbol and CFI caches are shared per ELF, while
 * each maps interval needs its own virtual start to compute load bias.
 */
struct per_elf_map_ctx {
	struct per_elf_ctx *elf_ctx;
	unsigned long map_exec_virt_addr;
};

/**
 * struct per_pid_ctx - Cached executable mappings for one process instance.
 * @gu_ctx: Owning global context.
 * @elf_ctx_list: Executable mapping interval index.
 * @pid: Process ID.
 * @golang: True when the main executable is a Go binary.
 * @preload: True when created by gu_preload_pid_debug_info().
 * @unique_id: Process-instance ID used to detect PID reuse.
 * @last_maps_load_ns: Monotonic time of the last maps load/reload.
 * @next_maps_reload_ns: Earliest monotonic time when a PC miss may reload maps.
 * @maps_reload_rand_state: Per-pid PRNG state used to jitter reloads.
 * @private: Caller metadata copied by gu_set_pid_private_info().
 * @private_size: Size of @private in bytes.
 * @hh: uthash handle keyed by @pid.
 */
struct per_pid_ctx {
	struct gu_context *gu_ctx;
	struct interval_array *elf_ctx_list;
	int pid;
	char comm[TASK_COMM_LEN];
	bool golang;
	bool preload;
	uint64_t unique_id;

	uint64_t last_maps_load_ns;
	uint64_t next_maps_reload_ns;
	uint64_t maps_reload_rand_state;

	void *private;
	int private_size;

	UT_hash_handle hh;
};

#endif
