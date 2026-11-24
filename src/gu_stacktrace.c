/* SPDX-License-Identifier: LGPL-3.0-or-later */

/*
 * Copyright (C) 2026 ByteDance Inc.
 *
 * This file is part of libgunwinder and is distributed under the
 * GNU Lesser General Public License v3.0 or later.
 *
 * The return-address CFI lookup rule used by the DWARF unwinder was designed
 * with conceptual guidance from elfutils/libdwfl frame unwinding behavior and
 * cross-checks, including behavior covered by
 * libdwfl/frame_unwind.c:
 *
 *   Copyright (C) 2013, 2014, 2016, 2024 Red Hat, Inc.
 *
 * elfutils is available under LGPL-3.0-or-later or GPL-2.0-or-later.
 * libgunwinder applies the rule inside its own stack-snapshot unwind flow.
 */

#define _GNU_SOURCE
#include "gunwinder/unwinder.h"
#include <ctype.h>
#include <stdatomic.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/stat.h>
#include <signal.h>
#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <stdatomic.h>
#include <time.h>
#include <sys/syscall.h>
#include <sys/eventfd.h>
#include <sys/uio.h>
#include <asm/unistd.h>
#include <linux/openat2.h>

#include "gunwinder/unwinder_types.h"
#include "gu_stacktrace.h"
#include "uthash.h"
#include "gu_interval_array.h"
#include "gu_unwinder.h"
#include "gu_cfi_helper.h"
#include "gu_comm.h"
#include "gu_elf.h"
#include "gu_symbol_names.h"

void gu_pid_ctx_event_notify_pid_ctx(int pid, unsigned long long start_time, const char *comm, unsigned int type);

static char *elf_scn_type_str[ELF_SCN_TYPE_MAX] = {
	".note.go.buildid", ".note.gnu.build-id", ".symtab", ".dynsym", ".debug_frame", ".debug_frame_hdr", ".zdebug_frame", ".zdebug_frame_hdr", ".eh_frame", ".eh_frame_hdr", ".gnu_debuglink",
};

#define STANDARD_BUILD_ID_LEN 20
#define GU_ELF_RETIRE_TTL_NS (10ULL * 1000000000ULL)
#define GU_PID_MAPS_RELOAD_MIN_INTERVAL_NS (30ULL * 1000000000ULL)
#define GU_PID_MAPS_RELOAD_MAX_INTERVAL_NS (90ULL * 1000000000ULL)
#define GU_OPEN_IN_ROOT_MAX_SYMLINKS 40
#define GU_OPEN_IN_ROOT_MAX_COMPONENTS (PATH_MAX / 2 + 1)

/* -1 unknown, 0 unavailable, 1 available; avoids repeated ENOSYS syscalls. */
static atomic_int gu_openat2_in_root_availability = ATOMIC_VAR_INIT(-1);

#ifndef SYS_openat2
#ifdef __NR_openat2
#define SYS_openat2 __NR_openat2
#endif
#endif

struct kernel_symbol_entry {
	char *name;
	uint64_t addr;
	UT_hash_handle hh;
};

struct gu_context {
	pthread_mutex_t lock;
	struct per_pid_ctx *pid_ctx_list;
	struct per_elf_ctx *elf_ctx_list;
	uint64_t next_retired_elf_deadline_ns;
	struct per_elf_ctx *elf_file_index;	/* by gu_file_key */
	/* /proc/<pid>/root held while one pid's mappings are loaded */
	int load_root_fd;
	int load_root_pid;
	bool debug;
	bool go_not_strip_name;

	char **record_env_name;
	int record_env_name_count;
	struct gu_statistics statistics;
	struct gu_frame_record frame_record;

	struct interval_array *kernel_symbols;
	struct kernel_symbol_entry *kernel_symbol_hash;
	struct per_elf_ctx tmp_ctx;
	bool vdso_dumped;
	char vdso_file_path[PATH_MAX];
	/* pid contexts at which the next dead-process sweep runs */
	uint64_t pid_ctx_sweep_at;
	/* kallsyms are neither loaded nor reloaded: another context has them */
	bool no_kernel_symbols;
	/* reads every ELF's packed symbol names, see gu_elf_symbol_name() */
	struct gu_symbol_names_reader *symbol_names_reader;
};

/*
 * Frames hand out a per_elf_ctx as a struct gu_elf_info (see
 * gu_frame_record::elf_info), so the public struct must be a byte-exact
 * prefix of the private one.
 */
#define GU_ELF_INFO_FIELD_MATCHES(field)					\
	_Static_assert(offsetof(struct gu_elf_info, field) ==			\
			       offsetof(struct per_elf_ctx, field) &&		\
		       sizeof(((struct gu_elf_info *)0)->field) ==		\
			       sizeof(((struct per_elf_ctx *)0)->field),	\
		       "gu_elf_info." #field " does not match per_elf_ctx")
GU_ELF_INFO_FIELD_MATCHES(base_name);
GU_ELF_INFO_FIELD_MATCHES(elf_file_path);
GU_ELF_INFO_FIELD_MATCHES(debug_file_path);
GU_ELF_INFO_FIELD_MATCHES(build_id);
GU_ELF_INFO_FIELD_MATCHES(build_id_len);
GU_ELF_INFO_FIELD_MATCHES(golang);
#undef GU_ELF_INFO_FIELD_MATCHES

static uint64_t gu_read_pid_start_ticks(int pid);
static uint64_t gu_read_pid_stat(int pid, char *state);

struct exec_scn_cache_entry {
	size_t shndx;
	bool is_exec;
	UT_hash_handle hh;
};

struct gu_symbol_name_arena_chunk {
	struct gu_symbol_name_arena_chunk *next;
	size_t used;
	size_t cap;
	char data[];
};

static void free_exec_scn_cache(struct exec_scn_cache_entry **cache)
{
	struct exec_scn_cache_entry *cur, *tmp;
	HASH_ITER(hh, *cache, cur, tmp)
	{
		HASH_DEL(*cache, cur);
		free(cur);
	}
}

static bool is_exec_scn_cached(Elf *elf, size_t shndx, struct exec_scn_cache_entry **cache)
{
	if (shndx == SHN_UNDEF || shndx == SHN_ABS || shndx == SHN_COMMON)
		return false;
	if (shndx >= SHN_LORESERVE)
		return false;

	struct exec_scn_cache_entry *entry = NULL;
	HASH_FIND(hh, *cache, &shndx, sizeof(shndx), entry);
	if (entry)
		return entry->is_exec;

	bool is_exec = false;
	Elf_Scn *scn = elf_getscn(elf, shndx);
	if (scn) {
		GElf_Shdr scn_shdr;
		if (gelf_getshdr(scn, &scn_shdr) == &scn_shdr)
			is_exec = ((scn_shdr.sh_flags & SHF_EXECINSTR) != 0);
	}

	entry = malloc(sizeof(*entry));
	if (!entry)
		return is_exec;
	entry->shndx = shndx;
	entry->is_exec = is_exec;
	HASH_ADD(hh, *cache, shndx, sizeof(entry->shndx), entry);
	return is_exec;
}

static uint64_t gu_monotonic_ns(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
		return 0;
	return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static void gu_unretire_elf_ctx(struct gu_context *ctx, struct per_elf_ctx *elf_ctx, bool activate)
{
	if (!ctx || !elf_ctx || !elf_ctx->retired)
		return;

	elf_ctx->retired = false;
	elf_ctx->retire_deadline_ns = 0;
	if (ctx->statistics.retired_elf_ctx_count)
		ctx->statistics.retired_elf_ctx_count--;
	if (activate)
		ctx->statistics.elf_ctx_count++;
}

static void clear_elf_ctx(struct per_elf_ctx *info)
{
	if (!info)
		return;

	struct gu_context *ctx = info->gu_ctx;
	struct gu_symbol_name_arena_chunk *chunk = info->symbol_name_arena;
	bool was_retired = info->retired;

	if (ctx && was_retired)
		gu_unretire_elf_ctx(ctx, info, false);

	if (info->base_name)
		free(info->base_name);
	if (info->elf_file_path)
		free(info->elf_file_path);
	if (info->debug_file_path)
		free(info->debug_file_path);
	if (info->build_id)
		free(info->build_id);
	gu_elf_exec_ranges_destroy(&info->exec_ranges);
	if (info->symbols) {
		ctx->statistics.symbols_mem_size -= info->sym_search_size;
		gu_interval_array_destroy(info->symbols);
	}
	gu_symbol_names_free(info->symbol_names);
	while (chunk) {
		struct gu_symbol_name_arena_chunk *next = chunk->next;
		free(chunk);
		chunk = next;
	}
	if (info->gu_cfi) {
		ctx->statistics.cfi_mem_size -= info->gu_cfi->cfi_mem_usage;
		ctx->statistics.cfi_data_mem_size -= info->gu_cfi->cfi_data_mem_usage;
		gu_cfi_destroy(info->gu_cfi);
	}
	if (info->elf)
		elf_end(info->elf);
	if (info->debug_elf)
		elf_end(info->debug_elf);
	if (info->elf_fd > 0)
		close(info->elf_fd);
	if (info->debug_elf_fd > 0)
		close(info->debug_elf_fd);
	if (info != &ctx->tmp_ctx) {
		HASH_DEL(ctx->elf_ctx_list, info);
		if (info->file_indexed)
			HASH_DELETE(hh_file, ctx->elf_file_index, info);
		if (!was_retired && ctx->statistics.elf_ctx_count)
			ctx->statistics.elf_ctx_count--;
		memset(info, 0, sizeof(*info));
		free(info);
	} else {
		memset(info, 0, sizeof(*info));
	}
}

static void gu_retire_elf_ctx(struct per_elf_ctx *elf_ctx)
{
	struct gu_context *ctx;
	uint64_t now_ns;

	if (!elf_ctx || elf_ctx->retired)
		return;

	ctx = elf_ctx->gu_ctx;
	if (!ctx) {
		clear_elf_ctx(elf_ctx);
		return;
	}

	now_ns = gu_monotonic_ns();
	elf_ctx->retired = true;
	elf_ctx->retire_deadline_ns = now_ns + GU_ELF_RETIRE_TTL_NS;
	if (ctx->statistics.elf_ctx_count)
		ctx->statistics.elf_ctx_count--;
	ctx->statistics.retired_elf_ctx_count++;
	if (ctx->next_retired_elf_deadline_ns == 0 ||
	    elf_ctx->retire_deadline_ns < ctx->next_retired_elf_deadline_ns)
		ctx->next_retired_elf_deadline_ns = elf_ctx->retire_deadline_ns;
}

static void gu_retired_elf_sweep(struct gu_context *ctx, uint64_t now_ns)
{
	struct per_elf_ctx *elf_ctx, *tmp;
	uint64_t next_deadline = 0;

	if (!ctx || now_ns == 0)
		return;
	if (now_ns != UINT64_MAX &&
	    (!ctx->statistics.retired_elf_ctx_count ||
	     (ctx->next_retired_elf_deadline_ns &&
	      now_ns < ctx->next_retired_elf_deadline_ns)))
		return;

	ctx->next_retired_elf_deadline_ns = 0;
	HASH_ITER(hh, ctx->elf_ctx_list, elf_ctx, tmp) {
		if (!elf_ctx->retired)
			continue;
		if (now_ns == UINT64_MAX || now_ns >= elf_ctx->retire_deadline_ns) {
			ctx->statistics.retired_elf_expired++;
			clear_elf_ctx(elf_ctx);
			continue;
		}
		if (next_deadline == 0 || elf_ctx->retire_deadline_ns < next_deadline)
			next_deadline = elf_ctx->retire_deadline_ns;
	}
	ctx->next_retired_elf_deadline_ns = next_deadline;
}

/*
 * Called per unwind.  Reads the clock only while retired ELFs wait for
 * their deadline; the sweep itself runs once a deadline has passed.
 */
static void gu_maybe_sweep_retired_elf(struct gu_context *ctx)
{
	if (!ctx || !ctx->statistics.retired_elf_ctx_count)
		return;
	gu_retired_elf_sweep(ctx, gu_monotonic_ns());
}

#define DEBUG_INFO_PATH_LENGTH 72

static char *get_debug_info_path_by_id(unsigned char *build_id)
{
	char path[73];
	char build_id_str[39];
	FILE *file;

	for (int i = 1; i < STANDARD_BUILD_ID_LEN; i++)
		sprintf(&build_id_str[(i - 1) * 2], "%02x", build_id[i]);

	build_id_str[38] = '\0';

	snprintf(path, sizeof(path), "/usr/lib/debug/.build-id/%02x/%s.debug", build_id[0], build_id_str);

	return strdup(path);
}

/*
 * .gnu_debuglink carries the basename of a separate debuginfo file followed
 * by padding and a 4-byte CRC32 (zlib/IEEE polynomial) of that file's full
 * contents.  The section ends with the CRC, so it is simply the last dword.
 */
#define GNU_DEBUGLINK_CRC_SIZE 4

static bool get_elf_gnu_debuglink(struct per_elf_ctx *info,
				  char *name_buf, size_t name_buf_size,
				  uint32_t *crc_out)
{
	Elf_Data *data = NULL;

	if (!info || !info->scn[ELF_SCN_TYPE_GNU_DEBUGLINK] || !name_buf ||
	    name_buf_size == 0 || !crc_out)
		return false;

	data = elf_getdata(info->scn[ELF_SCN_TYPE_GNU_DEBUGLINK], NULL);
	if (!data || data->d_size <= GNU_DEBUGLINK_CRC_SIZE)
		return false;

	const unsigned char *raw = data->d_buf;
	size_t crc_offset = data->d_size - GNU_DEBUGLINK_CRC_SIZE;
	size_t name_len = strnlen((const char *)raw, crc_offset);
	if (name_len == 0 || name_len >= crc_offset || name_len >= name_buf_size)
		return false;

	memcpy(name_buf, raw, name_len);
	name_buf[name_len] = '\0';
	/* The debuglink entry must be a plain basename. */
	if (strchr(name_buf, '/') != NULL)
		return false;

	uint32_t crc;
	memcpy(&crc, raw + crc_offset, sizeof(crc));
	*crc_out = crc;
	return true;
}

/* zlib-compatible CRC32 (init 0xffffffff, final xor), table-driven. */
static uint32_t gu_crc32_table[256];
static pthread_once_t gu_crc32_table_once = PTHREAD_ONCE_INIT;

static void gu_crc32_table_init(void)
{
	for (uint32_t i = 0; i < 256; i++) {
		uint32_t c = i;
		for (int j = 0; j < 8; j++)
			c = (c & 1) ? (0xedb88320U ^ (c >> 1)) : (c >> 1);
		gu_crc32_table[i] = c;
	}
}

static uint32_t gu_crc32_update(uint32_t crc, const unsigned char *buf, size_t len)
{
	pthread_once(&gu_crc32_table_once, gu_crc32_table_init);

	crc = ~crc;
	for (size_t i = 0; i < len; i++)
		crc = gu_crc32_table[(crc ^ buf[i]) & 0xff] ^ (crc >> 8);
	return ~crc;
}

static bool gu_debuglink_crc_matches(const char *path, uint32_t expected_crc)
{
	int fd = open(path, O_RDONLY | O_CLOEXEC, 0);
	if (fd < 0)
		return false;

	uint32_t crc = 0;
	unsigned char buf[65536];
	bool matched = false;

	for (;;) {
		ssize_t n = read(fd, buf, sizeof(buf));
		if (n < 0) {
			if (errno == EINTR)
				continue;
			break;
		}
		if (n == 0) {
			matched = (crc == expected_crc);
			break;
		}
		crc = gu_crc32_update(crc, buf, (size_t)n);
	}

	close(fd);
	return matched;
}

static char *gu_debuglink_try_candidate(const char *path, uint32_t expected_crc)
{
	struct stat st;

	if (!path || access(path, R_OK) != 0)
		return NULL;
	if (stat(path, &st) != 0 || !S_ISREG(st.st_mode))
		return NULL;
	if (!gu_debuglink_crc_matches(path, expected_crc)) {
		GU_VERBOSE("gnu_debuglink candidate crc mismatch: %s", path);
		return NULL;
	}
	GU_VERBOSE("gnu_debuglink resolved: %s", path);
	return strdup(path);
}

/*
 * Locate the debuginfo file named by .gnu_debuglink, following the standard
 * search order: object directory, its .debug subdir, then the global debug
 * root.  In live mode paths are resolved through the sampled process rootfs
 * first and the host root second.  When deleted_mapping is set the maps path
 * is not a real directory (/proc/<pid>/exe or map_files), so only global roots
 * are searched.
 */
static char *find_debug_info_path_by_debuglink(struct per_elf_ctx *info,
					       const char *file_name,
					       const char *pid_root_path,
					       bool live_mode,
					       bool deleted_mapping)
{
	char link_name[PATH_MAX];
	uint32_t expected_crc;

	if (!get_elf_gnu_debuglink(info, link_name, sizeof(link_name),
				   &expected_crc))
		return NULL;

	char obj_dir[PATH_MAX];
	char *result = NULL;

	strncpy(obj_dir, file_name, sizeof(obj_dir) - 1);
	obj_dir[sizeof(obj_dir) - 1] = '\0';
	char *slash = strrchr(obj_dir, '/');
	if (slash)
		*slash = '\0';
	else
		obj_dir[0] = '\0';

	if (!deleted_mapping && obj_dir[0] != '\0') {
		char candidate[PATH_MAX];

		/* Object directory, resolved through the target rootfs live. */
		snprintf(candidate, sizeof(candidate), "%s%s/%s",
			 pid_root_path, obj_dir, link_name);
		result = gu_debuglink_try_candidate(candidate, expected_crc);

		/* .debug subdirectory of the object directory. */
		if (!result) {
			snprintf(candidate, sizeof(candidate), "%s%s/.debug/%s",
				 pid_root_path, obj_dir, link_name);
			result = gu_debuglink_try_candidate(candidate, expected_crc);
		}
	}

	/*
	 * Global debug root of the target rootfs, then the host root.  For a
	 * host process the target root resolves to "/", so the two collapse
	 * and the access/CRC checks dedupe them.
	 */
	const char *global_roots[] = { pid_root_path, "" };
	size_t global_root_count = live_mode ? 2 : 1;

	for (size_t r = 0; r < global_root_count && !result; r++) {
		char candidate[PATH_MAX];

		snprintf(candidate, sizeof(candidate), "%s/usr/lib/debug%s/%s",
			 global_roots[r], obj_dir, link_name);
		result = gu_debuglink_try_candidate(candidate, expected_crc);
	}

	if (!result)
		GU_VERBOSE("gnu_debuglink %s not found with a matching crc",
			   link_name);
	return result;
}

static unsigned char *get_elf_build_id(struct per_elf_ctx *info, int *build_id_len)
{
	if (info->scn[ELF_SCN_TYPE_GO_BUILD_ID] == NULL && info->scn[ELF_SCN_TYPE_GNU_BUILD_ID] == NULL)
		return NULL;

	/*
	 * Both .note.go.buildid and .note.gnu.build-id are treated as cache
	 * identities here.  The note header is skipped so the hash key is only
	 * the producer-provided build-id payload.
	 */
	Elf_Data *data = NULL;
	if (info->scn[ELF_SCN_TYPE_GO_BUILD_ID] != NULL) {
		data = elf_getdata(info->scn[ELF_SCN_TYPE_GO_BUILD_ID], NULL);
	} else if (info->scn[ELF_SCN_TYPE_GNU_BUILD_ID] != NULL) {
		data = elf_getdata(info->scn[ELF_SCN_TYPE_GNU_BUILD_ID], NULL);
	} else {
		return NULL;
	}

	const char *id = (const char *)data->d_buf + 16;
	size_t build_id_size = data->d_size - 16;

	unsigned char *build_id = malloc(build_id_size);
	if (!build_id) {
		GU_ERROR("malloc build id failed");
		return NULL;
	}
	memcpy(build_id, id, build_id_size);

	*build_id_len = build_id_size;
	return build_id;
}

/*
 * A symbol item whose name was not read yet holds its ordinal in
 * per_elf_ctx::symbol_names, tagged with this bit (no pointer has it) and
 * the interval array's no-free bit.  See gu_elf_symbol_name().
 */
#define GU_SYMBOL_NAME_ORDINAL (1ULL << 62)

/* Add @name to @names; the private of its item, NULL when out of memory. */
static void *gu_symbol_name_add(struct gu_symbol_names_builder *names,
				const char *name)
{
	long ordinal = gu_symbol_names_add(names, name);

	if (ordinal < 0)
		return NULL;
	return (void *)mark_interval_array_pointer_no_free(
		GU_SYMBOL_NAME_ORDINAL | (uint64_t)ordinal);
}

static char *gu_symbol_name_arena_alloc(struct per_elf_ctx *info, size_t len)
{
	struct gu_symbol_name_arena_chunk *chunk;
	char *ptr;
	size_t cap;

	if (!info || len == 0)
		return NULL;

	chunk = info->symbol_name_arena;
	if (!chunk || chunk->cap - chunk->used < len) {
		cap = len > 4096 ? len : 4096;
		chunk = malloc(sizeof(*chunk) + cap);
		if (!chunk)
			return NULL;
		chunk->next = info->symbol_name_arena;
		chunk->used = 0;
		chunk->cap = cap;
		info->symbol_name_arena = chunk;
		info->symbol_name_arena_bytes += sizeof(*chunk) + cap;
	}

	ptr = chunk->data + chunk->used;
	chunk->used += len;
	return ptr;
}

static char *gu_symbol_name_arena_strdup(struct per_elf_ctx *info, const char *name)
{
	size_t len;
	char *dst;

	if (!name)
		return NULL;
	len = strlen(name) + 1;
	dst = gu_symbol_name_arena_alloc(info, len);
	if (!dst)
		return NULL;
	memcpy(dst, name, len);
	return dst;
}

static char *golang_strip_name_to_arena(struct per_elf_ctx *info, const char *name)
{
	if (strchr(name, '/') == NULL)
		return NULL;

	int count = 0;
	const char *c_last = NULL;
	const char *p = name;
	while (*p) {
		if (*p == '/') {
			count++;
			c_last = p;
		}
		p++;
	}

	if (*(p - 1) == '/')
		return gu_symbol_name_arena_strdup(info, name);

	size_t last_part_len = strlen(c_last);
	char *res = gu_symbol_name_arena_alloc(info, count * 2 + last_part_len + 1);
	if (res == NULL)
		return NULL;

	char *dst = res;
	const char *src = name;
	const char *end = c_last + 1;

	while (src < end) {
		if (*src == '/') {
			*dst++ = *src;
			src++;
			continue;
		}

		*dst++ = *src;
		while (*src && *src != '/')
			src++;
		if (*src == '/') {
			*dst++ = '/';
			src++;
		}
	}

	strcpy(dst, c_last + 1);

	return res;
}

struct gu_symbol_string_table_view {
	Elf *elf;
	size_t section_index;
	const char *data;
	size_t size;
	bool direct;
};

static void gu_symbol_string_table_view_init(Elf *elf, size_t section_index,
					     struct gu_symbol_string_table_view *view)
{
	Elf_Scn *scn;
	Elf_Data *data;
	GElf_Shdr shdr;

	memset(view, 0, sizeof(*view));
	view->elf = elf;
	view->section_index = section_index;

	if (!elf)
		return;

	scn = elf_getscn(elf, section_index);
	if (!scn)
		return;

	if (gelf_getshdr(scn, &shdr) != &shdr)
		return;

	data = elf_getdata(scn, NULL);
	if (!data || !data->d_buf || data->d_size == 0 || data->d_off != 0)
		return;

	if (elf_getdata(scn, data) != NULL)
		return;

	if (shdr.sh_size > data->d_size)
		return;

	view->data = data->d_buf;
	view->size = data->d_size;
	view->direct = true;
}

static const char *gu_symbol_string_table_view_get(struct gu_symbol_string_table_view *view,
						   size_t offset)
{
	const char *name;

	if (!view)
		return NULL;

	if (!view->direct)
		return view->elf ? elf_strptr(view->elf, view->section_index, offset) : NULL;

	if (offset >= view->size)
		return NULL;

	name = view->data + offset;
	if (!memchr(name, '\0', view->size - offset))
		return NULL;

	return name;
}

static bool is_arm_elf_mapping_symbol_name(const char *name)
{
	if (!name || name[0] != '$')
		return false;

	if (name[1] != 'a' && name[1] != 'd' && name[1] != 't' &&
	    name[1] != 'x')
		return false;

	return name[2] == '\0' || name[2] == '.';
}

struct gu_raw_sym {
	uint64_t value;
	uint64_t size;
	uint32_t name;
	uint16_t shndx;
	uint8_t type;
};

/*
 * Read a symbol table entry without gelf_getsym(): LTO-built production
 * binaries can carry a quarter-billion symbols and per-entry libelf
 * validation/conversion dominates parse time.
 *
 * Returns false when the section's entry size does not match the native
 * ELF class layout, in which case callers fall back to gelf_getsym().
 */
static bool gu_raw_sym_read(struct gu_raw_sym *out, const unsigned char *buf,
				   bool is_elf64, size_t index, size_t entsize)
{
	if (is_elf64) {
		if (entsize != sizeof(Elf64_Sym))
			return false;
		const Elf64_Sym *s = (const Elf64_Sym *)(buf + index * entsize);
		out->name = s->st_name;
		out->type = GELF_ST_TYPE(s->st_info);
		out->shndx = s->st_shndx;
		out->value = s->st_value;
		out->size = s->st_size;
	} else {
		if (entsize != sizeof(Elf32_Sym))
			return false;
		const Elf32_Sym *s = (const Elf32_Sym *)(buf + index * entsize);
		out->name = s->st_name;
		out->type = GELF_ST_TYPE(s->st_info);
		out->shndx = s->st_shndx;
		out->value = s->st_value;
		out->size = s->st_size;
	}
	return true;
}

/*
 * Dense set of SHF_EXECINSTR section indices; cheaper than a uthash
 * while scanning hundreds of millions of symbols.
 */
static unsigned char *gu_build_exec_section_map(Elf *elf, size_t shnum)
{
	unsigned char *exec = calloc(shnum ? shnum : 1, 1);
	if (!exec)
		return NULL;
	for (size_t i = 0; i < shnum; i++) {
		Elf_Scn *scn = elf_getscn(elf, i);
		GElf_Shdr sh;
		if (scn && gelf_getshdr(scn, &sh) == &sh &&
		    (sh.sh_flags & SHF_EXECINSTR))
			exec[i] = 1;
	}
	return exec;
}

/*
 * Per-executable-section byte coverage of STT_FUNC ranges.
 *
 * Function-local STT_NOTYPE symbols (LTO thunks/.Ltmp labels -- one
 * production LTO binary carried 254 million of them for only 0.9
 * million real functions) are skipped during symbol loading: such a
 * label never names a frame better than its containing function, and
 * keeping them inflates preload time and memory by well over an order
 * of magnitude.
 *
 * Coverage is keyed by section and uses byte granularity: adjacent
 * routines can differ by a single 2/4-byte instruction, so any coarser
 * bitmap cell could falsely drop a standalone assembly entry point.
 * Standalone NOTYPE assembly routines sit outside every STT_FUNC
 * range and are therefore always kept.
 *
 * Sections for which coverage could not be allocated (over the total
 * size budget) keep @map == NULL; queries then report "not covered",
 * i.e. their NOTYPE symbols are preserved (never a correctness loss).
 */
struct gu_section_cover {
	unsigned char *map;
	uint64_t addr;
	uint64_t size;
};

struct gu_func_cover {
	struct gu_section_cover *sec;
	size_t shnum;
};

/* Bound on total coverage memory: one byte per byte of executable
 * section.  Real .text totals are well below this; binaries over the
 * budget simply fall back to keeping their NOTYPE symbols. */
#define GU_FUNC_COVER_TOTAL_BUDGET (1024ull << 20)

static struct gu_func_cover *gu_func_cover_build(Elf *elf, size_t shnum)
{
	struct gu_func_cover *cov = calloc(1, sizeof(*cov));
	if (!cov)
		return NULL;
	cov->sec = calloc(shnum, sizeof(*cov->sec));
	if (!cov->sec) {
		free(cov);
		return NULL;
	}
	cov->shnum = shnum;

	uint64_t budget_used = 0;
	for (size_t i = 0; i < shnum; i++) {
		Elf_Scn *scn = elf_getscn(elf, i);
		GElf_Shdr sh;
		if (!scn || gelf_getshdr(scn, &sh) != &sh ||
		    !(sh.sh_flags & SHF_EXECINSTR))
			continue;
		cov->sec[i].addr = sh.sh_addr;
		cov->sec[i].size = sh.sh_size;
		if (sh.sh_size == 0 || sh.sh_size > GU_FUNC_COVER_TOTAL_BUDGET ||
		    budget_used + sh.sh_size > GU_FUNC_COVER_TOTAL_BUDGET)
			continue; /* map stays NULL: keep NOTYPE symbols */
		cov->sec[i].map = calloc(sh.sh_size, 1);
		if (!cov->sec[i].map)
			continue;
		budget_used += sh.sh_size;
	}
	return cov;
}

static void gu_func_cover_free(struct gu_func_cover *cov)
{
	if (!cov)
		return;
	if (cov->sec) {
		for (size_t i = 0; i < cov->shnum; i++)
			free(cov->sec[i].map);
		free(cov->sec);
	}
	free(cov);
}

static bool gu_func_cover_address(const struct gu_func_cover *cov,
				  uint16_t shndx, uint64_t addr)
{
	if (shndx >= cov->shnum)
		return false;
	const struct gu_section_cover *s = &cov->sec[shndx];
	if (!s->map || addr < s->addr)
		return false;
	uint64_t off = addr - s->addr;
	if (off >= s->size)
		return false;
	return s->map[off] != 0;
}

/*
 * True only when every byte of [addr, addr+len) is covered in this
 * section.  Used for STT_NOTYPE symbols that carry their own size:
 * such a symbol is dropped only when its whole range is inside typed
 * functions.  A tail that sticks out past the last covering function
 * (or a zero-length range whose start is uncovered) keeps the symbol,
 * matching the old gelf loader's behavior.
 */
static bool gu_func_cover_range(const struct gu_func_cover *cov,
				uint16_t shndx, uint64_t addr, uint64_t len)
{
	if (shndx >= cov->shnum)
		return false;
	const struct gu_section_cover *s = &cov->sec[shndx];
	if (!s->map || addr < s->addr)
		return false;
	uint64_t off = addr - s->addr;
	/* Empty range: covered iff the single start byte is covered. */
	uint64_t n = len ? len : 1;
	if (off >= s->size)
		return false;
	if (n > s->size - off)
		return false;
	for (uint64_t k = 0; k < n; k++) {
		if (!s->map[off + k])
			return false;
	}
	return true;
}

/*
 * A symbol's st_shndx is a real, usable section index only when it is
 * below the reserved range and within the file's section table.
 * SHN_UNDEF(0) is rejected separately by the caller's value/name
 * checks; SHN_ABS/SHN_COMMON/SHN_XINDEX (>= SHN_LORESERVE) never name
 * an executable section, mirroring the old is_exec_scn_cached() rule.
 */
static bool gu_sym_shndx_is_exec(const unsigned char *exec_map, size_t shnum,
				 uint16_t shndx)
{
	if (shndx == SHN_UNDEF || shndx >= SHN_LORESERVE || shndx >= shnum)
		return false;
	return exec_map[shndx] != 0;
}

static void gu_func_cover_mark(const struct gu_func_cover *cov,
			       uint16_t shndx, uint64_t value, uint64_t size)
{
	if (shndx == SHN_UNDEF || shndx >= SHN_LORESERVE || shndx >= cov->shnum)
		return;
	struct gu_section_cover *s = &cov->sec[shndx];
	if (!s->map || value < s->addr)
		return;
	uint64_t off = value - s->addr;
	if (off >= s->size)
		return;
	/* Zero-sized functions mark only their first byte; the
	 * interval fixup pass may extend the search interval, but
	 * being conservative here never drops a real label. */
	uint64_t n = size ? size : 1;
	/* Compare without off+n (can wrap for malformed st_size). */
	if (n > s->size - off)
		n = s->size - off;
	memset(s->map + off, 1, n);
}

/*
 * Fast symbol loading for mmap(2)-able symbol tables (file-backed
 * ELF).  Pass 1 collects STT_FUNC symbols and builds an address
 * coverage bitmap; pass 2 keeps every STT_FUNC and the STT_NOTYPE
 * symbols that live in an executable section outside of any function
 * range (hand-written assembly, etc.).
 *
 * Returns 0 when items_out/count_out hold the result (possibly
 * empty), -1 when the caller must use the gelf_getsym() fallback.
 */
static int gu_load_symbols_raw(struct per_elf_ctx *info, Elf *elf,
				const GElf_Shdr *shdr, Elf_Data *data,
				struct gu_symbol_string_table_view *name_view,
				struct gu_symbol_names_builder *names,
				struct interval_array_item **items_out, size_t *count_out)
{
	const unsigned char *buf = data->d_buf;
	if (!buf || data->d_size == 0 || data->d_off != 0 ||
	    shdr->sh_size > data->d_size)
		return -1;

	GElf_Ehdr ehdr;
	if (gelf_getehdr(elf, &ehdr) != &ehdr)
		return -1;
	bool is_elf64 = (ehdr.e_ident[EI_CLASS] == ELFCLASS64);
	if (!is_elf64 && ehdr.e_ident[EI_CLASS] != ELFCLASS32)
		return -1;

	struct gu_raw_sym probe;
	if (!gu_raw_sym_read(&probe, buf, is_elf64, 0, shdr->sh_entsize))
		return -1;

	size_t shnum = 0;
	if (elf_getshdrnum(elf, &shnum) != 0 || shnum == 0)
		return -1;
	size_t count = shdr->sh_size / shdr->sh_entsize;

	unsigned char *exec_map = gu_build_exec_section_map(elf, shnum);
	if (!exec_map)
		return -1;

	struct gu_func_cover *cover = gu_func_cover_build(elf, shnum);
	if (!cover)
		goto err_exec;

	size_t func_cap = 1024 * 1024;
	struct gu_raw_sym *funcs = malloc(func_cap * sizeof(*funcs));
	if (!funcs)
		goto err_cover;
	size_t func_count = 0;

	for (size_t i = 0; i < count; i++) {
		struct gu_raw_sym sym;
		if (!gu_raw_sym_read(&sym, buf, is_elf64, i, shdr->sh_entsize))
			goto err_cover;
		if (sym.type != STT_FUNC || sym.value == 0)
			continue;
		/* Coverage is contributed only by named STT_FUNC
		 * entries that will actually end up in the searchable
		 * table.  An unnamed function must not shadow a named
		 * NOTYPE range inside it (the old gelf path drops the
		 * empty-name FUNC but keeps the NOTYPE). */
		if (sym.name >= name_view->size)
			continue;
		const char *fname = gu_symbol_string_table_view_get(name_view, sym.name);
		if (!fname || fname[0] == '\0')
			continue;
		if (func_count == func_cap) {
			size_t new_cap = func_cap * 2;
			struct gu_raw_sym *grown = realloc(funcs, new_cap * sizeof(*grown));
			if (!grown)
				goto err_cover;
			funcs = grown;
			func_cap = new_cap;
		}
		funcs[func_count++] = sym;
	}

	/* Mark every typed function body in its section's byte map. */
	for (size_t i = 0; i < func_count; i++)
		gu_func_cover_mark(cover, funcs[i].shndx, funcs[i].value, funcs[i].size);

	size_t items_cap = func_count + 64;
	struct interval_array_item *items = malloc(items_cap * sizeof(*items));
	if (!items)
		goto err_items_outer;
	size_t actual_count = 0;

	for (size_t i = 0; i < count; i++) {
		struct gu_raw_sym sym;
		if (!gu_raw_sym_read(&sym, buf, is_elf64, i, shdr->sh_entsize))
			goto err_items;
		if (sym.value == 0)
			continue;
		if (sym.type != STT_FUNC && sym.type != STT_NOTYPE)
			continue;

		if (sym.type == STT_NOTYPE) {
			/*
			 * Match the old is_exec_scn_cached() rule: require
			 * the symbol to be defined in an executable
			 * section.  SHN_UNDEF/ABS/COMMON/XINDEX are
			 * dropped (the old code never resolved those).
			 */
			if (!gu_sym_shndx_is_exec(exec_map, shnum, sym.shndx))
				continue;
			/* Drop the symbol only when its ENTIRE range is
			 * inside typed function bodies.  A zero-size
			 * label inside a function is dropped; a sized
			 * NOTYPE whose tail reaches past a function, or a
			 * standalone asm routine, is kept. */
			if (gu_func_cover_range(cover, sym.shndx, sym.value, sym.size))
				continue;
			if (sym.name >= name_view->size)
				continue;
			const char *name = gu_symbol_string_table_view_get(name_view, sym.name);
			if (!name || name[0] == '\0')
				continue;
			if (is_arm_elf_mapping_symbol_name(name))
				continue;
		} else if (sym.name >= name_view->size) {
			continue;
		}

		const char *func_name = gu_symbol_string_table_view_get(name_view, sym.name);
		if (!func_name || func_name[0] == '\0')
			continue;

		if (actual_count == items_cap) {
			size_t new_cap = items_cap * 2;
			struct interval_array_item *grown =
				realloc(items, new_cap * sizeof(*grown));
			if (!grown)
				goto err_items;
			items = grown;
			items_cap = new_cap;
		}

		items[actual_count].start = sym.value;
		if (sym.type == STT_FUNC && sym.size == 0)
			items[actual_count].end = 0;
		else
			items[actual_count].end = sym.value + sym.size;

		items[actual_count].private = gu_symbol_name_add(names, func_name);
		if (items[actual_count].private == NULL)
			goto err_items;
		actual_count++;
	}

	gu_func_cover_free(cover);
	free(funcs);
	free(exec_map);
	*items_out = items;
	*count_out = actual_count;
	return 0;

err_items:
	/* every private is an ordinal of @names: nothing else to free */
	free(items);
err_items_outer:
	gu_func_cover_free(cover);
	free(funcs);
	free(exec_map);
	return -1;

err_cover:
	gu_func_cover_free(cover);
	free(funcs);
err_exec:
	free(exec_map);
	return -1;
}

static void fill_symbols_debug_info(struct per_elf_ctx *info)
{
	if (info->scn[ELF_SCN_TYPE_SYMTAB] != NULL)
		info->sym_scn = ELF_SCN_TYPE_SYMTAB;
	else if (info->scn[ELF_SCN_TYPE_DYNSYM] != NULL)
		info->sym_scn = ELF_SCN_TYPE_DYNSYM;
	else
		return;

	info->sym_search_size = 0;

	Elf *elf = info->scn_elf[info->sym_scn];
	Elf_Scn *scn = info->scn[info->sym_scn];
	if (elf == NULL || scn == NULL)
		return;

	GElf_Shdr shdr;
	if (gelf_getshdr(scn, &shdr) != &shdr)
		return;

	Elf_Data *data = elf_getdata(scn, NULL);
	if (data == NULL)
		return;

	struct gu_symbol_string_table_view name_view;
	gu_symbol_string_table_view_init(elf, shdr.sh_link, &name_view);

	struct interval_array_item *items = NULL;
	size_t actual_count = 0;
	struct exec_scn_cache_entry *exec_scn_cache = NULL;
	struct gu_symbol_names_builder *names = gu_symbol_names_builder_new();

	if (!names)
		return;
	if (gu_load_symbols_raw(info, elf, &shdr, data, &name_view, names,
				 &items, &actual_count) != 0) {
		/* gelf fallback: preserves original behavior for symbol
		 * data libelf cannot expose as a direct mmap view
		 * (compressed sections). */
		size_t count = shdr.sh_size / shdr.sh_entsize;
		gu_symbol_names_builder_free(names);
		names = gu_symbol_names_builder_new();
		items = calloc(count, sizeof(*items));
		if (!items || !names)
			goto err_free;
		actual_count = 0;
		for (size_t i = 0; i < count; ++i) {
			GElf_Sym sym;
			if (gelf_getsym(data, (int)i, &sym) != &sym)
				goto err_free;
			if (sym.st_value == 0)
				continue;
			unsigned int sym_type = GELF_ST_TYPE(sym.st_info);
			if (sym_type != STT_FUNC) {
				if (sym_type != STT_NOTYPE)
					continue;
				if (!is_exec_scn_cached(elf, sym.st_shndx, &exec_scn_cache))
					continue;
			}
			const char *name = gu_symbol_string_table_view_get(&name_view, sym.st_name);
			if (name == NULL)
				goto err_free;
			if (name[0] == '\0')
				continue;
			items[actual_count].start = sym.st_value;
			if (sym_type == STT_FUNC && sym.st_size == 0)
				items[actual_count].end = 0;
			else
				items[actual_count].end = sym.st_value + sym.st_size;
			if (sym_type == STT_NOTYPE && is_arm_elf_mapping_symbol_name(name))
				continue;
			items[actual_count].private = gu_symbol_name_add(names, name);
			if (items[actual_count].private == NULL)
				goto err_free;
			actual_count++;
		}
		free_exec_scn_cache(&exec_scn_cache);
	}

	if (actual_count == 0) {
		gu_symbol_names_builder_free(names);
		free(items);
		return;
	}

	info->symbol_names = gu_symbol_names_finish(names);
	names = NULL;
	if (!info->symbol_names)
		goto err_free;

	info->symbols = gu_interval_array_init(items, (int)actual_count);
	if (info->symbols == NULL)
		goto err_free;

	info->sym_search_size += gu_symbol_names_bytes(info->symbol_names);
	info->sym_search_size += actual_count *
		(info->symbols->type == INTERVAL_ARRAY_TYPE_U32 ?
		 sizeof(struct interval_array_item_u32) :
		 sizeof(struct interval_array_item_u64));
	info->gu_ctx->statistics.symbols_mem_size += info->sym_search_size;

	free(items);
	return;

err_free:
	/* every private is an ordinal: nothing else to free */
	free_exec_scn_cache(&exec_scn_cache);
	gu_symbol_names_builder_free(names);
	gu_symbol_names_free(info->symbol_names);
	info->symbol_names = NULL;
	free(items);
}

/*
 * A symbol's name did not decompress.  Counted per ELF (debuginfo memory
 * export) and per context (statistics); the first failure of an ELF is
 * logged with its build-id.  The lookup then fails as if the symbol had no
 * name, and the next hit tries again: the data is immutable, so a corrupt
 * block keeps failing and keeps counting, while a failed allocation may
 * succeed later.
 */
static void gu_elf_symbol_name_failed(struct per_elf_ctx *info)
{
	char build_id[2 * 20 + 1] = "";
	int len = info->build_id_len < 20 ? info->build_id_len : 20;

	info->gu_ctx->statistics.symbol_name_read_failures++;
	if (info->symbol_name_read_failures++)
		return;
	for (int i = 0; i < len; i++)
		snprintf(build_id + 2 * i, 3, "%02x", info->build_id[i]);
	GU_OUTPUT("symbol name read failed: %s build-id %s; its frames show addresses",
		  info->base_name ? info->base_name : "?", build_id);
}

/*
 * The name of the symbol at @index of @info->symbols, whose private is
 * @private: read from the packed names the first time, then kept in the
 * context's arena and the item pointed at it, so it lives as long as the
 * ELF context, like every name a frame hands out.  Go names are stripped
 * as they are read.  NULL if the name cannot be read.
 *
 * Single writer: the ELF context and the context's reader are only used
 * under its gu_context's lock.
 */
static char *gu_elf_symbol_name(struct per_elf_ctx *info, int index, void *private)
{
	struct gu_context *ctx = info->gu_ctx;
	uint64_t value = (uint64_t)private;
	const char *raw_name;
	char *name = NULL;
	size_t before, grown;

	if (!(value & GU_SYMBOL_NAME_ORDINAL))
		return private;

	if (!ctx->symbol_names_reader)
		ctx->symbol_names_reader = gu_symbol_names_reader_new();
	if (gu_symbol_names_read(info->symbol_names, ctx->symbol_names_reader,
				 value & ~GU_SYMBOL_NAME_ORDINAL, &raw_name) != 0) {
		gu_elf_symbol_name_failed(info);
		return NULL;
	}

	before = info->symbol_name_arena_bytes;
	if (info->golang && !ctx->go_not_strip_name)
		name = golang_strip_name_to_arena(info, raw_name);
	if (!name)
		name = gu_symbol_name_arena_strdup(info, raw_name);
	if (!name) {
		gu_elf_symbol_name_failed(info);
		return NULL;
	}

	gu_interval_array_set_private(info->symbols, index,
		(void *)mark_interval_array_pointer_no_free((uint64_t)name));
	grown = info->symbol_name_arena_bytes - before;
	info->sym_search_size += grown;
	ctx->statistics.symbols_mem_size += grown;
	return name;
}

static int scan_all_elf_scn(Elf *elf, struct per_elf_ctx *info)
{
	size_t shstrndx;
	if (elf_getshdrstrndx(elf, &shstrndx) != 0)
		return -1;

	Elf_Scn *scn = NULL;
	GElf_Shdr shdr;
	while ((scn = elf_nextscn(elf, scn)) != NULL) {
		if (gelf_getshdr(scn, &shdr) != &shdr) {
			GU_ERROR("gelf_getshdr() failed: %s", elf_errmsg(-1));
			return -1;
		}

		char *name = elf_strptr(elf, shstrndx, shdr.sh_name);
		if (!name) {
			GU_ERROR("elf_strptr() failed: %s", elf_errmsg(-1));
			return -1;
		}

		for (int i = 0; i < ELF_SCN_TYPE_MAX; i++) {
			if (info->scn[i] == NULL && strcmp(name, elf_scn_type_str[i]) == 0) {
				info->scn[i] = scn;
				info->scn_elf[i] = elf;

				if (i == ELF_SCN_TYPE_EH_FRAME_HDR) {
					info->eh_frame_hdr_off = shdr.sh_addr;
				}
			}
		}
	}

	return 0;
}

static const char *get_vdso_dump_path(struct gu_context *ctx)
{
	/*
	 * Keep the dump path unique per gu_context.  Different profilers in the
	 * same process can sample different target namespaces, and a shared
	 * /tmp/__vdso.so would make them race or reuse stale contents.
	 */
	if (ctx->vdso_file_path[0] == '\0')
		snprintf(ctx->vdso_file_path, sizeof(ctx->vdso_file_path), "%s.%d.%p",
			 DUMP_VDSO_PATH, getpid(), (void *)ctx);

	return ctx->vdso_file_path;
}

static int gu_openat2_in_root(int root_fd, const char *path, int flags)
{
	struct open_how how = {
		.flags = flags | O_CLOEXEC,
		.resolve = RESOLVE_IN_ROOT,
	};
	int fd;

	if (root_fd < 0 || !path || path[0] == '\0') {
		errno = EINVAL;
		return -1;
	}

#ifdef SYS_openat2
	if (atomic_load_explicit(&gu_openat2_in_root_availability,
				 memory_order_relaxed) == 0) {
		errno = ENOSYS;
		return -1;
	}

	fd = syscall(SYS_openat2, root_fd, path, &how, sizeof(how));
	if (fd >= 0)
		atomic_store_explicit(&gu_openat2_in_root_availability, 1,
				      memory_order_relaxed);
	else if (errno == ENOSYS)
		atomic_store_explicit(&gu_openat2_in_root_availability, 0,
				      memory_order_relaxed);
	return fd;
#else
	atomic_store_explicit(&gu_openat2_in_root_availability, 0,
				      memory_order_relaxed);
	errno = ENOSYS;
	return -1;
#endif
}

/*
 * Emulate RESOLVE_IN_ROOT only when the kernel has no openat2 syscall.  Every
 * component is pinned with O_PATH|O_NOFOLLOW before it is inspected, absolute
 * symlinks restart from root, and '..' is clamped at root.  Do not use a
 * /proc/<pid>/root string prefix here: absolute symlinks could escape it.
 */
static int gu_openat2_in_root_compat(int root_fd, const char *path, int flags)
{
	char pending_path[PATH_MAX];
	char next_path[PATH_MAX];
	char link_target[PATH_MAX];
	int dir_fds[GU_OPEN_IN_ROOT_MAX_COMPONENTS];
	char *cursor;
	int depth = 0;
	int symlink_count = 0;
	int fd = -1;
	int saved_errno = 0;

	if (root_fd < 0 || !path || path[0] == '\0') {
		errno = EINVAL;
		return -1;
	}
	if (snprintf(pending_path, sizeof(pending_path), "%s", path) >=
	    (int)sizeof(pending_path)) {
		errno = ENAMETOOLONG;
		return -1;
	}

	dir_fds[0] = fcntl(root_fd, F_DUPFD_CLOEXEC, 3);
	if (dir_fds[0] < 0)
		return -1;
	cursor = pending_path;

	for (;;) {
		char *component;
		char *remainder;
		struct stat st;
		int component_fd;
		ssize_t link_len;

		while (*cursor == '/')
			cursor++;
		if (*cursor == '\0') {
			fd = openat(dir_fds[depth], ".", flags | O_CLOEXEC | O_NOFOLLOW);
			break;
		}

		component = cursor;
		while (*cursor != '\0' && *cursor != '/')
			cursor++;
		if (*cursor != '\0')
			*cursor++ = '\0';
		remainder = cursor;

		if (strcmp(component, ".") == 0)
			continue;
		if (strcmp(component, "..") == 0) {
			if (depth > 0)
				close(dir_fds[depth--]);
			continue;
		}

		component_fd = openat(dir_fds[depth], component,
					      O_PATH | O_NOFOLLOW | O_CLOEXEC);
		if (component_fd < 0)
			break;
		if (fstat(component_fd, &st) < 0) {
			close(component_fd);
			break;
		}
		if (S_ISLNK(st.st_mode)) {
			link_len = readlinkat(component_fd, "", link_target,
					      sizeof(link_target) - 1);
			close(component_fd);
			if (link_len < 0)
				break;
			if (++symlink_count > GU_OPEN_IN_ROOT_MAX_SYMLINKS) {
				errno = ELOOP;
				break;
			}
			link_target[link_len] = '\0';
			if (snprintf(next_path, sizeof(next_path), "%s%s%s",
				     link_target, *remainder ? "/" : "", remainder) >=
			    (int)sizeof(next_path)) {
				errno = ENAMETOOLONG;
				break;
			}
			if (link_target[0] == '/') {
				while (depth > 0)
					close(dir_fds[depth--]);
			}
			strcpy(pending_path, next_path);
			cursor = pending_path;
			continue;
		}

		if (*remainder == '\0') {
			close(component_fd);
			fd = openat(dir_fds[depth], component,
				    flags | O_CLOEXEC | O_NOFOLLOW);
			break;
		}
		if (!S_ISDIR(st.st_mode)) {
			close(component_fd);
			errno = ENOTDIR;
			break;
		}
		if (depth + 1 >= GU_OPEN_IN_ROOT_MAX_COMPONENTS) {
			close(component_fd);
			errno = ENAMETOOLONG;
			break;
		}
		dir_fds[++depth] = component_fd;
	}

	if (fd < 0)
		saved_errno = errno;
	while (depth >= 0)
		close(dir_fds[depth--]);
	if (fd < 0)
		errno = saved_errno;
	return fd;
}

static int gu_open_pid_root(int pid)
{
	char pid_root_path[64];

	snprintf(pid_root_path, sizeof(pid_root_path), "/proc/%d/root", pid);
	return open(pid_root_path, O_PATH | O_DIRECTORY | O_CLOEXEC);
}

/* Uses the root held by gu_build_pid_elf_list() for its pid, if any. */
static int gu_open_pid_root_path(struct gu_context *ctx, int pid,
				 const char *path, int flags)
{
	bool held = ctx && ctx->load_root_fd >= 0 && ctx->load_root_pid == pid;
	int root_fd;
	int fd;

	if (!path || path[0] == '\0') {
		errno = EINVAL;
		return -1;
	}

	root_fd = held ? ctx->load_root_fd : gu_open_pid_root(pid);
	if (root_fd < 0)
		return -1;

	fd = gu_openat2_in_root(root_fd, path, flags);
	if (fd < 0 && errno == ENOSYS)
		fd = gu_openat2_in_root_compat(root_fd, path, flags);
	if (!held)
		close(root_fd);
	return fd;
}

/*
 * load_elf() - Load an ELF file's symbol/CFI data into a cached per-elf context.
 * @ctx:       libgunwinder context.
 * @file_name: Logical path of the mapped file, used to derive base_name and
 *             elf_file_path (for /usr/lib/debug/.build-id lookup).  In live
 *             mode this is resolved through /proc/<pid>/root.
 * @pid:       Target process id.
 * @open_path: Optional override for the file actually opened.  When non-NULL
 *             it is opened directly (not through /proc/<pid>/root) and
 *             @file_name is only used for naming.  This is used for deleted
 *             mappings, where the on-disk path may now name a different inode;
 *             /proc/<pid>/exe or /proc/<pid>/map_files/<start>-<end> always
 *             reference the bytes the process really has mapped.
 */
static int gu_file_key_of(int fd, struct gu_file_key *key)
{
	struct stat st;

	if (fstat(fd, &st))
		return -1;
	*key = (struct gu_file_key){
		.dev = st.st_dev,
		.ino = st.st_ino,
		.size = st.st_size,
		.mtime_sec = st.st_mtim.tv_sec,
		.mtime_nsec = st.st_mtim.tv_nsec,
		.ctime_sec = st.st_ctim.tv_sec,
		.ctime_nsec = st.st_ctim.tv_nsec,
	};
	return 0;
}

static struct per_elf_ctx *load_elf(struct gu_context *ctx, char *file_name, int pid,
				   const char *open_path)
{
	char pid_root_path[64];
	int len = 0;
	bool vdso_local = false;
	struct gu_file_key file_key;
	bool have_file_key = false;

	const char *base;

	if (strncmp(file_name, "[vdso]", 6) == 0) {
		/*
		 * vDSO is a kernel mapping, not a file in the target rootfs.
		 * Dump it locally and do not prefix it with /proc/<pid>/root.
		 * unlink() forces a fresh dump after a previous failed or partial
		 * attempt; otherwise stat() could validate stale contents.
		 */
		if (!ctx->vdso_dumped) {
			const char *vdso_path = get_vdso_dump_path(ctx);
			struct stat st;
			unlink(vdso_path);
			gu_dump_vdso(vdso_path);
			if (stat(vdso_path, &st) == 0)
				ctx->vdso_dumped = true;
			else
				return NULL;
		}

		if (ctx->vdso_dumped) {
			file_name = (char *)get_vdso_dump_path(ctx);
			vdso_local = true;
		}
	}

	base = strrchr(file_name, '/');
	if (base)
		base++;
	else
		base = file_name;

	memset(&ctx->tmp_ctx, 0, sizeof(ctx->tmp_ctx));

	ctx->tmp_ctx.gu_ctx = ctx;

	ctx->tmp_ctx.base_name = strdup(base);
	if (!ctx->tmp_ctx.base_name)
		goto exit;

	/*
	 * Live mode resolves target paths through /proc/<pid>/root so container
	 * and chroot paths are interpreted in the sampled process' namespace.
	 * Offline debug mode has already rewritten maps to dump-local files, so
	 * adding a proc-root prefix would point at the wrong machine.
	 */
	if (!ctx->debug)
		snprintf(pid_root_path, 64, "/proc/%d/root", pid);
	else
		snprintf(pid_root_path, 64, "");

	/*
	 * For deleted mappings open_path points at the live mapping
	 * (/proc/<pid>/exe or /proc/<pid>/map_files/...).  Use it as
	 * elf_file_path too so debug-file lookup (which falls back to
	 * elf_file_path when there is no standard build-id, and which
	 * resolves .gnu_debuglink relative to the ELF directory) operates
	 * on the same inode we actually opened.  Otherwise elf_file_path
	 * would name the (possibly replaced) file at /proc/<pid>/root/<path>,
	 * producing mismatched symbols or wrong debug info.
	 */
	if (open_path)
		ctx->tmp_ctx.elf_file_path = strdup(open_path);
	else
		ctx->tmp_ctx.elf_file_path = vdso_local ? strdup(file_name) : gu_path_join(pid_root_path, file_name);
	if (!ctx->tmp_ctx.elf_file_path)
		goto exit;

	GU_VERBOSE("Loading elf: %s", ctx->tmp_ctx.elf_file_path);

	if (open_path) {
		/*
		 * Deleted mapping: open the live mapping directly
		 * (/proc/<pid>/exe or /proc/<pid>/map_files/...) instead of
		 * the pathname, which may now name a different inode.
		 */
		ctx->tmp_ctx.elf_fd = open(open_path, O_RDONLY | O_CLOEXEC, 0);
	} else if (!ctx->debug && !vdso_local) {
		ctx->tmp_ctx.elf_fd =
			gu_open_pid_root_path(ctx, pid, file_name, O_RDONLY);
	} else {
		ctx->tmp_ctx.elf_fd =
			open(ctx->tmp_ctx.elf_file_path, O_RDONLY | O_CLOEXEC, 0);
	}
	if (ctx->tmp_ctx.elf_fd < 0) {
		GU_VERBOSE("open: %s failed: %s",
			   open_path ? open_path : ctx->tmp_ctx.elf_file_path,
			   strerror(errno));
		goto exit;
	}

	/*
	 * An unchanged file needs no parsing: reuse its context straight away,
	 * before elf_begin(), the section scan and the build-id (or MD5).
	 * Maps reloads mostly meet files that are already loaded.
	 */
	if (gu_file_key_of(ctx->tmp_ctx.elf_fd, &file_key) == 0) {
		struct per_elf_ctx *known = NULL;

		HASH_FIND(hh_file, ctx->elf_file_index, &file_key,
			  sizeof(file_key), known);
		if (known) {
			if (known->retired) {
				gu_unretire_elf_ctx(ctx, known, true);
				ctx->statistics.retired_elf_cache_hit++;
			}
			known->refcnt++;
			ctx->statistics.elf_file_cache_hit++;
			clear_elf_ctx(&ctx->tmp_ctx);
			return known;
		}
		have_file_key = true;
	}

	ctx->tmp_ctx.elf = elf_begin(ctx->tmp_ctx.elf_fd, ELF_C_READ, NULL);
	if (!ctx->tmp_ctx.elf) {
		GU_VERBOSE("open elf: %s failed: %s", ctx->tmp_ctx.elf_file_path, strerror(errno));
		goto exit;
	}

	if (scan_all_elf_scn(ctx->tmp_ctx.elf, &ctx->tmp_ctx) != 0) {
		GU_VERBOSE("scan_all_elf_scn: %s failed: %s", ctx->tmp_ctx.elf_file_path, strerror(errno));
		goto exit;
	}

	ctx->tmp_ctx.build_id = get_elf_build_id(&ctx->tmp_ctx, &ctx->tmp_ctx.build_id_len);
	if (!ctx->tmp_ctx.build_id) {
		/*
		 * Some ELFs do not carry a producer build-id.  Use the file MD5
		 * only as an internal cache key; it is not a standard build-id
		 * and therefore must not drive /usr/lib/debug/.build-id lookup.
		 */
		ctx->tmp_ctx.build_id = (unsigned char *)gu_calculate_md5(ctx->tmp_ctx.elf_fd, ctx->tmp_ctx.base_name);
		ctx->tmp_ctx.build_id_len = MD5_DIGEST_LENGTH;
	}

	struct per_elf_ctx *elf_ctx = NULL;
	HASH_FIND(hh, ctx->elf_ctx_list, ctx->tmp_ctx.build_id, ctx->tmp_ctx.build_id_len, elf_ctx);
	if (elf_ctx) {
		/*
		 * ELF metadata is keyed by build-id and shared across pids.
		 * A retired entry can be revived if a new process maps the same
		 * image before the retire sweep releases its symbol/CFI tables.
		 */
		if (elf_ctx->retired) {
			gu_unretire_elf_ctx(ctx, elf_ctx, true);
			ctx->statistics.retired_elf_cache_hit++;
		}
		elf_ctx->refcnt++;
		clear_elf_ctx(&ctx->tmp_ctx);
		GU_VERBOSE("find cached elf_ctx: %s", ctx->tmp_ctx.elf_file_path);
		return elf_ctx;
	}

	ctx->statistics.elf_ctx_alloc_count++;
	if (gu_elf_exec_ranges_load_from_elf(ctx->tmp_ctx.elf,
					     &ctx->tmp_ctx.exec_ranges) == 0) {
		ctx->tmp_ctx.exec_virt_addr =
			gu_elf_exec_ranges_first_start(&ctx->tmp_ctx.exec_ranges);
	}

	if (ctx->tmp_ctx.build_id_len == STANDARD_BUILD_ID_LEN) {
		char *tmp_path = get_debug_info_path_by_id(ctx->tmp_ctx.build_id);
		/* Prefer host-wide debuginfo, then try the target rootfs. */
		if (access(tmp_path, F_OK) == 0) {
			ctx->tmp_ctx.debug_file_path = tmp_path;
		} else {
			ctx->tmp_ctx.debug_file_path =
				gu_path_join(pid_root_path, tmp_path);
			free(tmp_path);
			if (access(ctx->tmp_ctx.debug_file_path, F_OK) != 0) {
				free(ctx->tmp_ctx.debug_file_path);
				ctx->tmp_ctx.debug_file_path = NULL;
			}
		}
	}

	/*
	 * No build-id debuginfo: fall back to .gnu_debuglink, which points at
	 * a separate debuginfo file (often under an adjacent .debug/ dir).
	 */
	if (!ctx->tmp_ctx.debug_file_path) {
		ctx->tmp_ctx.debug_file_path =
			find_debug_info_path_by_debuglink(
				&ctx->tmp_ctx, file_name, pid_root_path,
				!ctx->debug, open_path != NULL);
	}

	if (!ctx->tmp_ctx.debug_file_path) {
		/*
		 * Non-standard identities include the MD5 fallback above and
		 * Go build IDs, which do not match the GNU build-id directory
		 * layout.  ELFs without any usable external debuginfo keep
		 * resolving symbols from the mapped file itself.
		 */
		ctx->tmp_ctx.debug_file_path =
			strdup(ctx->tmp_ctx.elf_file_path);
	}

	if (strcmp(ctx->tmp_ctx.elf_file_path, ctx->tmp_ctx.debug_file_path) != 0) {
		GU_VERBOSE("elf_file_path: %s != debug_file_path: %s", ctx->tmp_ctx.elf_file_path, ctx->tmp_ctx.debug_file_path);
		ctx->tmp_ctx.debug_elf_fd = open(ctx->tmp_ctx.debug_file_path, O_RDONLY, 0);
		if (ctx->tmp_ctx.debug_elf_fd < 0)
			goto exit;

		ctx->tmp_ctx.debug_elf = elf_begin(ctx->tmp_ctx.debug_elf_fd, ELF_C_READ, NULL);
		if (!ctx->tmp_ctx.debug_elf)
			goto exit;

		if (scan_all_elf_scn(ctx->tmp_ctx.debug_elf, &ctx->tmp_ctx) != 0)
			goto exit;
	}

	if (ctx->tmp_ctx.scn[ELF_SCN_TYPE_GO_BUILD_ID] != NULL) {
		/*
		 * Go's frame data is not consumed through the generic DWARF CFI
		 * path in this unwinder.  Keep CFI disabled and rely on FP mode
		 * plus Go symbols loaded from the executable/debug sections.
		 */
		ctx->tmp_ctx.golang = true;
		ctx->tmp_ctx.gu_cfi = NULL;
		fill_symbols_debug_info(&ctx->tmp_ctx);
	} else {
		ctx->tmp_ctx.golang = false;
		ctx->tmp_ctx.gu_cfi = gu_cfi_init(&ctx->tmp_ctx);
		fill_symbols_debug_info(&ctx->tmp_ctx);
	}

	if (ctx->tmp_ctx.gu_cfi) {
		ctx->statistics.cfi_mem_size += ctx->tmp_ctx.gu_cfi->cfi_mem_usage;
		ctx->statistics.cfi_data_mem_size += ctx->tmp_ctx.gu_cfi->cfi_data_mem_usage;
	}

	elf_ctx = calloc(1, sizeof(struct per_elf_ctx));
	if (!elf_ctx)
		goto exit;

	memcpy(elf_ctx, &ctx->tmp_ctx, sizeof(ctx->tmp_ctx));
	memset(&ctx->tmp_ctx, 0, sizeof(ctx->tmp_ctx));

	HASH_ADD_KEYPTR(hh, ctx->elf_ctx_list, elf_ctx->build_id, elf_ctx->build_id_len, elf_ctx);
	if (have_file_key) {
		elf_ctx->file_key = file_key;
		elf_ctx->file_indexed = true;
		HASH_ADD(hh_file, ctx->elf_file_index, file_key,
			 sizeof(elf_ctx->file_key), elf_ctx);
	}
	ctx->statistics.elf_ctx_count++;
	GU_VERBOSE("[%s] elf_path [%s] debug [%s]", elf_ctx->base_name, elf_ctx->elf_file_path, elf_ctx->debug_file_path);

	elf_ctx->gu_ctx = ctx;
	elf_ctx->refcnt++;

	/*
	 * Section pointers are only valid while the ELF handles are open.  By
	 * this point symbols and CFI have been copied into interval arrays, so
	 * close the descriptors and clear section handles to avoid accidental
	 * reuse of invalid libelf pointers.
	 */
	if (elf_ctx->debug_elf) {
		elf_end(elf_ctx->debug_elf);
		elf_ctx->debug_elf = NULL;
		close(elf_ctx->debug_elf_fd);
		elf_ctx->debug_elf_fd = -1;
	}

	if (elf_ctx->elf) {
		elf_end(elf_ctx->elf);
		elf_ctx->elf = NULL;
		close(elf_ctx->elf_fd);
		elf_ctx->elf_fd = -1;
	}

	memset(elf_ctx->scn, 0, sizeof(elf_ctx->scn));
	memset(elf_ctx->scn_elf, 0, sizeof(elf_ctx->scn_elf));

	return elf_ctx;

exit:
	GU_VERBOSE("Loading elf: %s failed.", file_name);
	clear_elf_ctx(&ctx->tmp_ctx);
	return NULL;
}

struct hugepage_text_recovery {
	bool enabled;
	char path[PATH_MAX];
	struct gu_elf_exec_ranges exec_ranges;
	unsigned long load_bias;
};

static void hugepage_text_recovery_destroy(struct hugepage_text_recovery *recovery)
{
	if (!recovery)
		return;

	gu_elf_exec_ranges_destroy(&recovery->exec_ranges);
	memset(recovery, 0, sizeof(*recovery));
}

static bool hugepage_text_recovery_try_path(
	struct hugepage_text_recovery *recovery, const char *path,
	int fd, const struct maps_info *first_map)
{
	struct gu_elf_exec_ranges ranges = { 0 };
	unsigned long first_exec_virt_addr;
	unsigned long load_bias;
	unsigned long virt_start, virt_end;

	if (!recovery || !path || fd < 0 || !first_map ||
	    first_map->end <= first_map->start)
		return false;

	if (gu_elf_exec_ranges_load_fd(fd, &ranges) != 0 ||
	    ranges.count == 0)
		return false;

	first_exec_virt_addr = gu_elf_exec_ranges_first_start(&ranges);
	if (first_map->start < first_exec_virt_addr)
		goto out;

	load_bias = first_map->start - first_exec_virt_addr;
	if (first_map->start < load_bias || first_map->end < load_bias)
		goto out;

	virt_start = first_map->start - load_bias;
	virt_end = first_map->end - load_bias;
	if (!gu_elf_exec_ranges_find(&ranges, virt_start, virt_end, NULL))
		goto out;

	if (path != recovery->path)
		snprintf(recovery->path, sizeof(recovery->path), "%s", path);
	recovery->exec_ranges = ranges;
	recovery->load_bias = load_bias;
	recovery->enabled = true;
	return true;

out:
	gu_elf_exec_ranges_destroy(&ranges);
	return false;
}

static bool hugepage_text_recovery_init(struct gu_context *ctx, int pid,
					struct maps_info *maps, int count,
					struct hugepage_text_recovery *recovery)
{
	int fd = -1;
	bool ok = false;

	if (!ctx || !maps || count <= 0 || !recovery || ctx->debug)
		return false;

	memset(recovery, 0, sizeof(*recovery));

	if (!gu_maps_path_is_anonymous_exec_candidate(maps[0].path))
		return false;

	if (gu_get_pid_cmdline_argv0(pid, recovery->path,
				     sizeof(recovery->path)) != 0) {
		hugepage_text_recovery_destroy(recovery);
		return false;
	}

	fd = gu_open_pid_root_path(ctx, pid, recovery->path, O_RDONLY);
	if (fd >= 0) {
		ok = hugepage_text_recovery_try_path(recovery, recovery->path,
						     fd, &maps[0]);
		close(fd);
	}

	if (!ok)
		hugepage_text_recovery_destroy(recovery);
	return ok;
}

static bool hugepage_text_recovery_match(
	const struct hugepage_text_recovery *recovery, const struct maps_info *map,
	unsigned long *map_exec_virt_addr)
{
	unsigned long virt_start, virt_end;

	if (!recovery || !recovery->enabled || !map ||
	    !gu_maps_path_is_anonymous_exec_candidate(map->path) ||
	    map->end <= map->start)
		return false;

	if (map->start < recovery->load_bias || map->end < recovery->load_bias)
		return false;

	virt_start = map->start - recovery->load_bias;
	virt_end = map->end - recovery->load_bias;

	return gu_elf_exec_ranges_find(&recovery->exec_ranges, virt_start,
				       virt_end, map_exec_virt_addr);
}

static void gu_put_elf_ctx(struct per_elf_ctx *ctx)
{
	if (!ctx)
		return;

	ctx->refcnt--;
	if (ctx->refcnt == 0)
		gu_retire_elf_ctx(ctx);
}

static struct per_elf_map_ctx *
gu_alloc_elf_map_ctx(struct per_elf_ctx *elf_ctx,
		     unsigned long map_exec_virt_addr)
{
	struct per_elf_map_ctx *map_ctx;

	if (!elf_ctx)
		return NULL;

	map_ctx = calloc(1, sizeof(*map_ctx));
	if (!map_ctx)
		return NULL;

	map_ctx->elf_ctx = elf_ctx;
	map_ctx->map_exec_virt_addr =
		map_exec_virt_addr ? map_exec_virt_addr : elf_ctx->exec_virt_addr;
	return map_ctx;
}

static unsigned long gu_resolve_map_exec_virt_addr(struct per_elf_ctx *elf_ctx,
						   const struct maps_info *map)
{
	unsigned long map_exec_virt_addr = 0;

	if (!elf_ctx || !map || map->end <= map->start)
		return 0;

	if (gu_elf_exec_ranges_find_by_offset(&elf_ctx->exec_ranges,
					      map->offset,
					      map->end - map->start,
					      &map_exec_virt_addr))
		return map_exec_virt_addr;

	return 0;
}

static struct per_elf_ctx *
gu_get_elf_ctx_from_item(const struct interval_array_item *elf_item,
			 unsigned long *map_exec_virt_addr)
{
	struct per_elf_map_ctx *map_ctx;

	if (map_exec_virt_addr)
		*map_exec_virt_addr = 0;
	if (!elf_item || !elf_item->private)
		return NULL;

	map_ctx = (struct per_elf_map_ctx *)get_interval_array_pointer(
		(uint64_t)elf_item->private, NULL);
	if (!map_ctx)
		return NULL;

	if (map_exec_virt_addr)
		*map_exec_virt_addr = map_ctx->map_exec_virt_addr;
	return map_ctx->elf_ctx;
}

static void gu_cleanup_elf_map_items(struct interval_array_item *items,
				     int count);
static void gu_schedule_next_maps_reload(struct gu_context *ctx,
					 struct per_pid_ctx *pid_ctx);

static void __private_clean_elf_ctx(void *elf_map_ctx, void *_);

static void gu_destroy_pid_elf_list(struct interval_array *list)
{
	if (!list)
		return;
	gu_interval_array_for_each_private(list, __private_clean_elf_ctx, NULL);
	gu_interval_array_destroy(list);
}

/*
 * Map every executable mapping of @info->pid to its ELF, as /proc/@pid (the
 * process or one of its threads) shows them.  Returns the interval array,
 * or NULL when the pid has no executable mapping or on failure; *golang
 * tells whether the main executable is a Go binary.
 */
static struct interval_array *gu_build_pid_elf_list(struct gu_context *ctx,
						     struct gu_stack_info *info,
						     int pid, bool *golang)
{
	int count = 0;
	char *debug_maps_path = NULL;
	struct interval_array_item *items = NULL;
	struct interval_array *list = NULL;
	struct maps_info *maps = NULL;
	struct hugepage_text_recovery hugepage_text = { 0 };

	*golang = false;
	if (ctx->debug)
		debug_maps_path = (char *)info->unique_id;

	maps = gu_get_maps_info(pid, &count, PERMISSION_X, debug_maps_path);

	if (count == 0)
		goto exit;

	/*
	 * Private hugepage text optimization compatibility:
	 *
	 * Some internal Go launchers ptrace the child before it starts running,
	 * unmap the original file-backed executable mappings, recreate those
	 * ranges as MAP_ANON executable VMAs, copy the text bytes back, and then
	 * madvise the 2MB-aligned middle spans with MADV_HUGEPAGE. Profiling
	 * still samples PCs at the original virtual addresses, but
	 * /proc/<pid>/maps no longer has a pathname for the executable text.
	 *
	 * This is deliberately a narrow private heuristic, not generic JIT
	 * support.  The trigger is only "the first executable maps entry is
	 * anonymous", which matches tiexec after it remaps the main Go text.
	 * From that point we recover cmdline[0] through /proc/<pid>/root and
	 * read its executable PT_LOAD ranges.  Every later anonymous executable
	 * map is replaced only if subtracting the first text load bias places it
	 * wholly inside one of those ELF executable ranges.  That extra range
	 * check is what lets us cover split Go text with holes while still
	 * leaving unrelated anonymous/JIT executable mappings anonymous.
	 */
	hugepage_text_recovery_init(ctx, pid, maps, count, &hugepage_text);

	items = calloc(count, sizeof(struct interval_array_item));
	if (!items)
		goto exit;

	/* one /proc/<pid>/root for every mapping of the pid */
	if (!ctx->debug) {
		ctx->load_root_fd = gu_open_pid_root(pid);
		ctx->load_root_pid = pid;
	}
	for (int i = 0; i < count; i++) {
		char *elf_path = maps[i].path;
		unsigned long map_exec_virt_addr = 0;
		bool replace_hugepage_text =
			hugepage_text_recovery_match(&hugepage_text, &maps[i],
						     &map_exec_virt_addr);
		struct per_elf_map_ctx *map_ctx = NULL;
		char live_open_path[64] = {0};
		const char *open_path = NULL;

		items[i].start = maps[i].start;
		items[i].end = maps[i].end;
		if (replace_hugepage_text)
			elf_path = hugepage_text.path;

		/*
		 * A " (deleted)" mapping means the file was unlinked (and
		 * possibly replaced) after the process mapped it.  Opening the
		 * pathname from /proc/<pid>/root would either fail or, worse,
		 * read a different inode deployed at the same path - producing
		 * mismatched symbols and wrong load biases.  Read the live
		 * mapping instead: /proc/<pid>/exe for the main executable and
		 * /proc/<pid>/map_files/<start>-<end> for everything else.
		 */
		if (!ctx->debug && !replace_hugepage_text && maps[i].deleted) {
			if (i == 0) {
				snprintf(live_open_path, sizeof(live_open_path),
					 "/proc/%d/exe", pid);
			} else {
				snprintf(live_open_path, sizeof(live_open_path),
					 "/proc/%d/map_files/%lx-%lx", pid,
					 maps[i].start, maps[i].end);
			}
			open_path = live_open_path;
		}

		struct per_elf_ctx *elf = load_elf(ctx, elf_path, pid, open_path);
		if (!replace_hugepage_text)
			map_exec_virt_addr =
				gu_resolve_map_exec_virt_addr(elf, &maps[i]);
		if (replace_hugepage_text && elf) {
			GU_OUTPUT("hugepage optimize detected, replace anonymous executable segment [0x%lx-0x%lx] with %s\n",
				  maps[i].start, maps[i].end, hugepage_text.path);
		}
		if (i == 0 && elf && elf->golang)
			*golang = true;
		map_ctx = gu_alloc_elf_map_ctx(elf, map_exec_virt_addr);
		if (elf && !map_ctx) {
			gu_put_elf_ctx(elf);
			goto exit;
		}
		items[i].private =
			map_ctx ? (void *)mark_interval_array_pointer_no_free((uint64_t)map_ctx) : NULL;
		GU_VERBOSE("Load elf: %s [0x%lx - 0x%lx] elf_ctx: %p map_exec_virt_addr: 0x%lx",
			   elf_path, maps[i].start, maps[i].end, elf,
			   map_ctx ? map_ctx->map_exec_virt_addr : 0);
	}

	list = gu_interval_array_init(items, count);

exit:
	if (ctx->load_root_fd >= 0)
		close(ctx->load_root_fd);
	ctx->load_root_fd = -1;
	if (maps)
		gu_free_maps_info(maps, count);
	hugepage_text_recovery_destroy(&hugepage_text);
	if (items) {
		if (!list)
			gu_cleanup_elf_map_items(items, count);
		free(items);
	}
	return list;
}

/* Thread group (process) id of the live task @pid, 0 when it is gone. */
static int gu_read_pid_tgid(int pid)
{
	char path[64], line[256];
	FILE *fp;
	int tgid = 0;

	snprintf(path, sizeof(path), "/proc/%d/status", pid);
	fp = fopen(path, "r");
	if (!fp)
		return 0;
	while (fgets(line, sizeof(line), fp)) {
		if (sscanf(line, "Tgid: %d", &tgid) == 1)
			break;
	}
	fclose(fp);
	return tgid;
}

/*
 * Whether the task @task is of the instance @info was sampled from: a thread
 * of @info->pid, whose leader started at @info->unique_id.  unique_id is the
 * start time of the thread group's leader, and @task may be a thread (the
 * sampled one, or a caller's pid that is a thread id): compare the leader's,
 * a thread's own start time is a different instant.  *leader_state, if given, gets the leader's state
 * ('Z': exited before its threads).
 */
static bool gu_task_of_sample(const struct gu_stack_info *info, int task,
			      char *leader_state)
{
	int tgid = gu_read_pid_tgid(task);

	if (tgid <= 0 || (task != info->pid && tgid != info->pid))
		return false;
	return gu_read_pid_stat(tgid, leader_state) == info->unique_id;
}

/*
 * The live task whose /proc shows the instance @info was sampled from, 0 when
 * there is none: once the pid is reused, /proc/<pid>/maps describes another
 * program, and an old queued sample unwound against it yields frames that
 * look resolved and are wrong.  The process itself, unless its leader exited
 * before its other threads: that zombie has no mappings left, the sampled
 * thread (@info->tid) still shows them.  Slow paths only (cold load, leaf-miss
 * reload): two /proc reads, a third for a zombie leader.  A sample without an
 * identity (0) keeps the old liveness check; debug replays read recorded
 * maps, not live ones.
 */
static int gu_sample_task(struct gu_context *ctx, const struct gu_stack_info *info)
{
	char state = 0;

	if (ctx->debug)
		return info->pid;
	if (info->unique_id == 0)
		return kill(info->pid, 0) == 0 ? info->pid : 0;
	if (!gu_task_of_sample(info, info->pid, &state))
		return 0;
	if (state == 'Z' && info->tid > 0 && info->tid != info->pid &&
	    gu_task_of_sample(info, info->tid, NULL))
		return info->tid;
	return info->pid;
}

/*
 * The view of the instance @info was sampled from, staged: built from /proc of
 * a live task of that instance, and kept only if the task is still of it once
 * built.  The pid may be reused while its maps and ELFs are read; the instance
 * never comes back, so a view checked before and after is its own (short of
 * the task's id being reused twice during the read).  The caller commits it or
 * keeps its old view.  *task: the task read, 0 when the instance was not
 * there; *gone: the instance is not, or no longer, there.
 */
static struct interval_array *gu_stage_pid_elf_list(struct gu_context *ctx,
						    struct gu_stack_info *info,
						    bool *golang, int *task,
						    bool *gone)
{
	struct interval_array *list;

	*task = gu_sample_task(ctx, info);
	*gone = !*task;
	if (!*task)
		return NULL;
	list = gu_build_pid_elf_list(ctx, info, *task, golang);
	if (!list || ctx->debug || info->unique_id == 0 ||
	    gu_task_of_sample(info, *task, NULL))
		return list;
	gu_destroy_pid_elf_list(list);
	*gone = true;
	return NULL;
}

/*
 * A new context for the instance @info was sampled from, with its staged view;
 * NULL when the instance is gone or has no executable mapping.  Not yet in the
 * table: see gu_add_pid_ctx().
 */
static struct per_pid_ctx *gu_load_pid_instance(struct gu_context *ctx,
						struct gu_stack_info *info)
{
	int pid = info->pid;
	struct interval_array *list;
	struct per_pid_ctx *pid_ctx = NULL;
	bool golang, gone;
	int task;

	list = gu_stage_pid_elf_list(ctx, info, &golang, &task, &gone);
	if (!list)
		return NULL;
	pid_ctx = calloc(1, sizeof(struct per_pid_ctx));
	if (!pid_ctx) {
		gu_destroy_pid_elf_list(list);
		return NULL;
	}
	ctx->statistics.pid_ctx_alloc_count++;

	pid_ctx->gu_ctx = ctx;
	pid_ctx->elf_ctx_list = list;
	pid_ctx->golang = golang;
	pid_ctx->pid = pid;
	pid_ctx->unique_id = info->unique_id;
	gu_get_pid_comm(pid, pid_ctx->comm, sizeof(pid_ctx->comm));
	/*
	 * The first leaf miss of a pid may reload at once; the throttle starts
	 * with that reload.  A pid is often first seen at exec, when only the
	 * binary and ld.so are mapped: a process that dies inside libc within
	 * the throttle interval would otherwise never have libc in its view.
	 * Any pid costs at most one maps read more than before, and only when
	 * its leaf misses.
	 */
	pid_ctx->last_maps_load_ns = gu_monotonic_ns();
	pid_ctx->next_maps_reload_ns = pid_ctx->last_maps_load_ns;

	return pid_ctx;
}

struct per_pid_ctx *gu_load_pid(struct gu_context *ctx, struct gu_stack_info *info)
{
	struct per_pid_ctx *pid_ctx = NULL;

	HASH_FIND_INT(ctx->pid_ctx_list, &info->pid, pid_ctx);
	return pid_ctx ? pid_ctx : gu_load_pid_instance(ctx, info);
}

static void __private_clean_elf_ctx(void *elf_map_ctx, void *_)
{
	struct per_elf_map_ctx *map_ctx = (struct per_elf_map_ctx *)elf_map_ctx;
	if (!map_ctx)
		return;

	/* gu_put_elf_ctx preserves the existing gu_retire_elf_ctx transition. */
	gu_put_elf_ctx(map_ctx->elf_ctx);
	free(map_ctx);
}

static void gu_cleanup_elf_map_items(struct interval_array_item *items,
				     int count)
{
	for (int i = 0; items && i < count; i++) {
		void *private = get_interval_array_pointer(
			(uint64_t)items[i].private, NULL);

		if (private) {
			__private_clean_elf_ctx(private, NULL);
			items[i].private = NULL;
		}
	}
}

static uint64_t gu_maps_reload_random_u64(struct per_pid_ctx *pid_ctx)
{
	uint64_t x;

	if (!pid_ctx)
		return gu_monotonic_ns();

	x = pid_ctx->maps_reload_rand_state;
	if (x == 0)
		x = ((uint64_t)(uint32_t)pid_ctx->pid << 32) ^
		    pid_ctx->unique_id ^ gu_monotonic_ns() ^
		    (uintptr_t)pid_ctx;
	if (x == 0)
		x = 0x9e3779b97f4a7c15ULL;

	x ^= x << 13;
	x ^= x >> 7;
	x ^= x << 17;
	if (x == 0)
		x = 0xd1b54a32d192ed03ULL;
	pid_ctx->maps_reload_rand_state = x;
	return x;
}

static void gu_schedule_next_maps_reload(struct gu_context *ctx,
					 struct per_pid_ctx *pid_ctx)
{
	uint64_t now;
	uint64_t span;
	uint64_t delay;

	if (!ctx || !pid_ctx)
		return;

	now = gu_monotonic_ns();
	span = GU_PID_MAPS_RELOAD_MAX_INTERVAL_NS -
	       GU_PID_MAPS_RELOAD_MIN_INTERVAL_NS;
	delay = GU_PID_MAPS_RELOAD_MIN_INTERVAL_NS;
	if (span > 0)
		delay += gu_maps_reload_random_u64(pid_ctx) % (span + 1);

	pid_ctx->last_maps_load_ns = now;
	pid_ctx->next_maps_reload_ns = now + delay;

	GU_VERBOSE("schedule next maps reload for pid %d after %llu ns",
		   pid_ctx->pid, (unsigned long long)delay);
}

static bool gu_maps_reload_allowed(struct gu_context *ctx,
				   struct per_pid_ctx *pid_ctx,
				   unsigned long pc)
{
	uint64_t now;

	if (!ctx || !pid_ctx)
		return false;

	if (pid_ctx->next_maps_reload_ns == 0)
		gu_schedule_next_maps_reload(ctx, pid_ctx);

	now = gu_monotonic_ns();
	if (now >= pid_ctx->next_maps_reload_ns)
		return true;

	ctx->statistics.pid_maps_reload_throttle_count++;
	GU_VERBOSE("skip maps reload for pid %d pc 0x%lx until %llu, now %llu",
		   pid_ctx->pid, pc,
		   (unsigned long long)pid_ctx->next_maps_reload_ns,
		   (unsigned long long)now);
	return false;
}

void gu_clear_pid_ctx(struct per_pid_ctx *pid_ctx)
{
	if (!pid_ctx)
		return;

	struct gu_context *ctx = pid_ctx->gu_ctx;

	HASH_DEL(ctx->pid_ctx_list, pid_ctx);
	ctx->statistics.pid_ctx_count--;

	gu_destroy_pid_elf_list(pid_ctx->elf_ctx_list);

	if (pid_ctx->private) {
		free(pid_ctx->private);
		pid_ctx->private = NULL;
		pid_ctx->private_size = 0;
	}
	free(pid_ctx);
}

/*
 * A pid context leaves on its process exit event, and the caller's exit
 * stream loses events on a host whose exits outrun it (a full perf buffer or
 * exit queue): those contexts, and the state listeners keep per context,
 * would stay forever. They are reclaimed lazily, at a high-water
 * mark only: when the table reaches pid_ctx_sweep_at, one pass drops every
 * context whose process is gone, listeners hearing DESTROY first as on an
 * exit, and the mark becomes twice the survivors, never below the floor. A
 * sweep is paid for by as many insertions as it visits, and none runs while
 * the table stays small. A replay (debug) context holds dead pids by design.
 */
#define GU_PID_CTX_SWEEP_FLOOR 4096

static void gu_sweep_dead_pid_ctx(struct gu_context *ctx,
				  const struct per_pid_ctx *in_use)
{
	struct per_pid_ctx *pid_ctx = NULL;
	struct per_pid_ctx *tmp = NULL;
	uint64_t kept;

	HASH_ITER(hh, ctx->pid_ctx_list, pid_ctx, tmp) {
		if (pid_ctx == in_use || kill(pid_ctx->pid, 0) == 0 || errno == EPERM)
			continue;
		gu_pid_ctx_event_notify_pid_ctx(pid_ctx->pid,
						(unsigned long long)pid_ctx->unique_id,
						pid_ctx->comm, GU_PID_CTX_EVENT_DESTROY);
		gu_clear_pid_ctx(pid_ctx);
		ctx->statistics.pid_ctx_swept_count++;
	}
	kept = HASH_COUNT(ctx->pid_ctx_list);
	ctx->pid_ctx_sweep_at = kept * 2 > GU_PID_CTX_SWEEP_FLOOR ?
				kept * 2 : GU_PID_CTX_SWEEP_FLOOR;
}

/* Every new pid context enters the table here; the caller goes on using it. */
static void gu_add_pid_ctx(struct gu_context *ctx, struct per_pid_ctx *pid_ctx)
{
	HASH_ADD_INT(ctx->pid_ctx_list, pid, pid_ctx);
	ctx->statistics.pid_ctx_count++;
	if (ctx->statistics.pid_ctx_count >= ctx->pid_ctx_sweep_at && !ctx->debug)
		gu_sweep_dead_pid_ctx(ctx, pid_ctx);
}

/*
 * Refresh the mappings of a live process in place.  The process is the same
 * instance, so its identity and private data stay: a refresh must not look
 * like an exit, which would make listeners drop what they keep for it.  The
 * new list is built before the old one is released, so ELFs mapped by both
 * are just re-referenced, and only if it is still the sample's instance's
 * (see gu_stage_pid_elf_list()).  Listeners hear CREATE again: the process
 * may have loaded new code they want to look at.
 */
static struct per_pid_ctx *gu_reload_pid_ctx(struct gu_context *ctx,
					     struct per_pid_ctx *pid_ctx,
					     struct gu_stack_info *info)
{
	struct interval_array *list;
	bool golang, gone;
	int task;

	if (!ctx || !pid_ctx || !info)
		return pid_ctx;

	gu_schedule_next_maps_reload(ctx, pid_ctx);
	list = gu_stage_pid_elf_list(ctx, info, &golang, &task, &gone);
	if (task)
		ctx->statistics.pid_maps_reload_count++;
	if (gone)	/* or the pid now runs another instance */
		gu_flags_set_reason(info, GU_UNWIND_REASON_PROCESS_EXIT);
	if (!list)
		return pid_ctx;	/* keep the old view */

	gu_destroy_pid_elf_list(pid_ctx->elf_ctx_list);
	pid_ctx->elf_ctx_list = list;
	pid_ctx->golang = golang;
	if (golang)
		gu_flags_set(info, GU_FLAG_HINT_SET_FP);
	gu_get_pid_comm(pid_ctx->pid, pid_ctx->comm, sizeof(pid_ctx->comm));

	gu_pid_ctx_event_notify_pid_ctx(pid_ctx->pid,
					(unsigned long long)pid_ctx->unique_id,
					pid_ctx->comm, GU_PID_CTX_EVENT_CREATE);
	return pid_ctx;
}

static int gu_search_pid_elf_ctx(struct gu_context *ctx,
				 struct per_pid_ctx **pid_ctx,
				 struct gu_stack_info *info, unsigned long pc,
				 struct interval_array_item *elf_item,
				 bool *maps_reloaded)
{
	int ret;

	ret = gu_interval_array_search((*pid_ctx)->elf_ctx_list, pc, elf_item);
	/*
	 * Only a miss of the sampled instruction pointer can mean new code was
	 * mapped: whatever runs is sampled as a leaf sooner or later, while
	 * deeper frames of an FP walk may be garbage return addresses.  Callers
	 * pass @maps_reloaded for the leaf only.
	 */
	if (ret >= 0 || !maps_reloaded || *maps_reloaded)
		return ret;
	/*
	 * A PC miss may mean dlopen/JIT/tiexec changed executable mappings, so
	 * the unwinder still needs a reload path.  Keep it off the per-sample
	 * hot path: after each pid maps load/reload, wait for a jittered per-pid
	 * deadline before trying again.  The 30-90s spread avoids a restart herd
	 * where many processes loaded at the same time all reload at exactly 60s.
	 */
	if (!gu_maps_reload_allowed(ctx, *pid_ctx, pc))
		return ret;

	/*
	 * Process mappings are cached per pid, but Java/JNI and plugins can
	 * dlopen executable ELFs after the pid context was created. Refresh
	 * only on a real interval miss; PCs that hit known anonymous/JIT
	 * ranges keep the old fast path and do not repeatedly scan maps.
	 * Gone, or the pid now runs another instance: the view stays.
	 */
	*maps_reloaded = true;
	*pid_ctx = gu_reload_pid_ctx(ctx, *pid_ctx, info);
	if (!*pid_ctx || !(*pid_ctx)->elf_ctx_list)
		return ret;

	memset(elf_item, 0, sizeof(*elf_item));
	return gu_interval_array_search((*pid_ctx)->elf_ctx_list, pc, elf_item);
}

struct gu_context *gu_init(const struct gu_init_cfg *cfg)
{
	pthread_mutexattr_t lock_attr;

	if (!cfg)
		return NULL;
	if (cfg->go_buildid_only) {
		GU_ERROR("go_buildid_only is no longer supported");
		return NULL;
	}
	if (!gu_elf_init()) {
		GU_ERROR("ELF library initialization failed: %s", elf_errmsg(-1));
		return NULL;
	}
	struct gu_context *ctx = malloc(sizeof(*ctx));
	if (!ctx)
		return NULL;
	memset(ctx, 0, sizeof(*ctx));
	if (pthread_mutexattr_init(&lock_attr) != 0) {
		free(ctx);
		return NULL;
	}
	pthread_mutexattr_settype(&lock_attr, PTHREAD_MUTEX_RECURSIVE);
	if (pthread_mutex_init(&ctx->lock, &lock_attr) != 0) {
		pthread_mutexattr_destroy(&lock_attr);
		free(ctx);
		return NULL;
	}
	pthread_mutexattr_destroy(&lock_attr);

	ctx->debug = cfg->debug_print;
	ctx->go_not_strip_name = cfg->go_not_strip_name;
	ctx->pid_ctx_sweep_at = GU_PID_CTX_SWEEP_FLOOR;

	ctx->kernel_symbols = NULL;
	ctx->load_root_fd = -1;
	ctx->no_kernel_symbols = cfg->no_kernel_symbols;
	if (!ctx->no_kernel_symbols)
		gu_load_kernel_symbols(ctx);

	return ctx;
}

static void gu_kernel_symbol_hash_destroy(struct kernel_symbol_entry *hash)
{
	struct kernel_symbol_entry *entry, *tmp;

	if (!hash)
		return;

	HASH_ITER(hh, hash, entry, tmp) {
		HASH_DEL(hash, entry);
		free(entry);
	}
}

static void gu_cleanup_locked(struct gu_context *ctx)
{
	if (!ctx)
		return;

	if (ctx->kernel_symbols)
		gu_interval_array_destroy(ctx->kernel_symbols);

	gu_kernel_symbol_hash_destroy(ctx->kernel_symbol_hash);

	if (ctx->pid_ctx_list) {
		struct per_pid_ctx *pid_ctx, *tmp;
		HASH_ITER (hh, ctx->pid_ctx_list, pid_ctx, tmp) {
			gu_clear_pid_ctx(pid_ctx);
		}
	}
	gu_retired_elf_sweep(ctx, UINT64_MAX);

	if (ctx->vdso_file_path[0] != '\0')
		unlink(ctx->vdso_file_path);
}

void gu_cleanup(struct gu_context *ctx)
{
	if (!ctx)
		return;

	pthread_mutex_lock(&ctx->lock);
	gu_cleanup_locked(ctx);
	pthread_mutex_unlock(&ctx->lock);
	gu_symbol_names_reader_free(ctx->symbol_names_reader);
	pthread_mutex_destroy(&ctx->lock);
	free(ctx);
}

static void gu_set_pid_private_info_locked(struct gu_context *ctx, int pid,
					   const void *private, int size)
{
	struct per_pid_ctx *pid_ctx = NULL;

	HASH_FIND_INT(ctx->pid_ctx_list, &pid, pid_ctx);

	if (pid_ctx) {
		if (pid_ctx->private) {
			free(pid_ctx->private);
			pid_ctx->private = NULL;
			pid_ctx->private_size = 0;
		}

		if (private && size > 0) {
			pid_ctx->private = malloc(size);
			if (pid_ctx->private) {
				memcpy(pid_ctx->private, private, size);
				pid_ctx->private_size = size;
			}
		}
	}
}

void gu_set_pid_private_info(struct gu_context *ctx, int pid, const void *private, int size)
{
	if (!ctx)
		return;

	pthread_mutex_lock(&ctx->lock);
	gu_set_pid_private_info_locked(ctx, pid, private, size);
	pthread_mutex_unlock(&ctx->lock);
}

static void *gu_get_pid_private_info_locked(struct gu_context *ctx, int pid,
					    int *size)
{
	struct per_pid_ctx *pid_ctx = NULL;

	HASH_FIND_INT(ctx->pid_ctx_list, &pid, pid_ctx);

	if (pid_ctx && pid_ctx->private && pid_ctx->private_size > 0) {
		// Return a copy of private data to ensure caller gets independent memory
		void *copy = malloc(pid_ctx->private_size);
		if (copy) {
			memcpy(copy, pid_ctx->private, pid_ctx->private_size);
			if (size)
				*size = pid_ctx->private_size;
			return copy;
		}
	}

	if (size)
		*size = 0;
	return NULL;
}

void *gu_get_pid_private_info(struct gu_context *ctx, int pid, int *size)
{
	void *private = NULL;

	if (!ctx) {
		if (size)
			*size = 0;
		return NULL;
	}

	pthread_mutex_lock(&ctx->lock);
	private = gu_get_pid_private_info_locked(ctx, pid, size);
	pthread_mutex_unlock(&ctx->lock);
	return private;
}

/*
 * Start time of the live process @pid, in clock ticks (field 22 of
 * /proc/<pid>/stat): the unit of gu_stack_info::unique_id, which samples
 * carry as the task's start time divided by the 10 ms USER_HZ tick.  0 when
 * the process is gone or the field cannot be read.
 */
static uint64_t gu_read_pid_start_ticks(int pid)
{
	return gu_read_pid_stat(pid, NULL);
}

/* The same, and the process' state (field 3) in *state if given. */
static uint64_t gu_read_pid_stat(int pid, char *state)
{
	char stat_path[64];
	char stat_buf[4096];
	char *cur = NULL;
	FILE *fp = NULL;
	uint64_t start_time = 0;

	snprintf(stat_path, sizeof(stat_path), "/proc/%d/stat", pid);
	fp = fopen(stat_path, "r");
	if (!fp)
		return 0;
	if (!fgets(stat_buf, sizeof(stat_buf), fp))
		goto out;
	cur = strrchr(stat_buf, ')');
	if (!cur)
		goto out;
	cur++;
	for (int field = 3; field <= 22; field++) {
		char *end = NULL;
		unsigned long long parsed = 0;

		while (*cur && isspace((unsigned char)*cur))
			cur++;
		if (*cur == '\0')
			goto out;
		if (field == 3 && state)
			*state = *cur;
		if (field != 22) {
			while (*cur && !isspace((unsigned char)*cur))
				cur++;
			continue;
		}
		errno = 0;
		parsed = strtoull(cur, &end, 10);
		if (errno == 0 && end != cur)
			start_time = (uint64_t)parsed;
		break;
	}

out:
	fclose(fp);
	return start_time;
}

static uint64_t gu_get_pid_unique_id(struct gu_context *ctx, int pid)
{
	struct per_pid_ctx *pid_ctx = NULL;

	if (!ctx || pid <= 0)
		return 0;
	HASH_FIND_INT(ctx->pid_ctx_list, &pid, pid_ctx);
	if (pid_ctx && pid_ctx->unique_id != 0)
		return pid_ctx->unique_id;
	return gu_read_pid_start_ticks(pid);
}

static void gu_set_pid_exit_unique(struct gu_context *ctx, int pid, uint64_t unique_id)
{
	struct per_pid_ctx *pid_ctx = NULL;

	HASH_FIND_INT(ctx->pid_ctx_list, &pid, pid_ctx);
	if (pid_ctx && unique_id != 0 && pid_ctx->unique_id != unique_id)
		return;

	if (pid_ctx) {
		gu_pid_ctx_event_notify_pid_ctx(pid_ctx->pid, (unsigned long long)pid_ctx->unique_id, pid_ctx->comm, GU_PID_CTX_EVENT_DESTROY);
		gu_clear_pid_ctx(pid_ctx);
	}
}

void gu_set_pid_exit(struct gu_context *ctx, int pid)
{
	gu_set_pid_exit_unique(ctx, pid, 0);
}

static int gu_event_occur_locked(struct gu_context *ctx, enum gu_event_type type,
				 void *event_data)
{
	gu_maybe_sweep_retired_elf(ctx);

	switch (type) {
	case GU_EVENT_PROCESS_EXIT:
		if (event_data) {
			struct gu_process_exit_event *event = event_data;
			gu_set_pid_exit_unique(ctx, event->pid, event->start_time);
		}
		break;
	case GU_EVENT_MODULE_RELOAD:
		if (!ctx->no_kernel_symbols)
			gu_load_kernel_symbols(ctx);
		break;
	default:
		break;
	}
	return 0;
}

int gu_event_occur(struct gu_context *ctx, enum gu_event_type type, void *event_data)
{
	int ret;

	if (!ctx)
		return -1;

	pthread_mutex_lock(&ctx->lock);
	ret = gu_event_occur_locked(ctx, type, event_data);
	pthread_mutex_unlock(&ctx->lock);
	return ret;
}

static uint64_t gu_preload_pid_debug_info_locked(struct gu_context *ctx, int pid)
{
	struct gu_stack_info info = {
		.pid = pid,
		.unique_id = gu_get_pid_unique_id(ctx, pid),
	};
	struct per_pid_ctx *pid_ctx = NULL;

	gu_maybe_sweep_retired_elf(ctx);

	HASH_FIND_INT(ctx->pid_ctx_list, &info.pid, pid_ctx);
	if (pid_ctx)
		return pid_ctx->unique_id;

	if (!pid_ctx) {
		if (kill(info.pid, 0) != 0) {
			gu_flags_set_reason(&info, GU_UNWIND_REASON_PROCESS_EXIT);
			goto end;
		}

		pid_ctx = gu_load_pid(ctx, &info);
		if (!pid_ctx) {
			gu_flags_set_reason(&info, GU_UNWIND_REASON_NO_ELF);
			goto end;
		}

		pid_ctx->preload = true;

		if (pid_ctx->golang)
			gu_flags_set(&info, GU_FLAG_HINT_SET_FP);

		gu_add_pid_ctx(ctx, pid_ctx);
		gu_pid_ctx_event_notify_pid_ctx(pid_ctx->pid, (unsigned long long)pid_ctx->unique_id, pid_ctx->comm, GU_PID_CTX_EVENT_CREATE);
	}

end:

	return pid_ctx ? pid_ctx->unique_id : 0;
}

uint64_t gu_preload_pid_debug_info(struct gu_context *ctx, int pid)
{
	uint64_t unique_id;

	if (!ctx)
		return 0;

	pthread_mutex_lock(&ctx->lock);
	unique_id = gu_preload_pid_debug_info_locked(ctx, pid);
	pthread_mutex_unlock(&ctx->lock);
	return unique_id;
}

/*
 * Guards the kernel symbol tables of every context: lookups, the hot path of
 * kernel frames, share it; a (re)load replaces the tables exclusively.
 */
static pthread_rwlock_t kernel_symbols_lock = PTHREAD_RWLOCK_INITIALIZER;
static int g_ksym_items_count = 0;

int gu_load_kernel_symbols(struct gu_context *ctx)
{
	if (!ctx)
		return -1;

	FILE *f = fopen("/proc/kallsyms", "r");
	if (!f)
		return -1;

	char *line = NULL;
	size_t len = 0;
	ssize_t read;

	int items_cap;

	pthread_rwlock_rdlock(&kernel_symbols_lock);
	items_cap = g_ksym_items_count;
	pthread_rwlock_unlock(&kernel_symbols_lock);
	if (items_cap == 0) {
		int count = 0;
		while ((read = getline(&line, &len, f)) != -1) {
			if (strstr(line, " t ") || strstr(line, " T "))
				count++;
		}

		items_cap = 1;
		while (items_cap < count)
			items_cap <<= 1;
		if (count == 0)
			items_cap = 1024;

		fseek(f, 0, SEEK_SET);
	}

	struct interval_array_item *items = calloc(items_cap, sizeof(struct interval_array_item));
	if (!items) {
		fclose(f);
		free(line);
		return -1;
	}

	struct kernel_symbol_entry *new_hash = NULL;
	size_t temp_kernel_symbols_mem = 0;

	int i = 0;
	while ((read = getline(&line, &len, f)) != -1) {
		uint64_t addr;
		char type;
		char name[512];
		if (sscanf(line, "%lx %c %511s", &addr, &type, name) == 3) {
			if (type == 't' || type == 'T') {
				if (i >= items_cap) {
					items_cap *= 2;
					struct interval_array_item *new_items = realloc(items, items_cap * sizeof(struct interval_array_item));
					if (!new_items) {
						for (int j = 0; j < i; j++)
							free(items[j].private);
						free(items);
						gu_kernel_symbol_hash_destroy(new_hash);
						fclose(f);
						free(line);
						return -1;
					}
					items = new_items;
				}
				items[i].start = addr;
				items[i].private = strdup(name);
				if (items[i].private) {
					size_t name_len = strlen(name);
					temp_kernel_symbols_mem += name_len + 1;
					/*
					 * The name->addr hash must hold at most one entry
					 * per name. /proc/kallsyms legitimately contains huge
					 * numbers of duplicate local/assembler labels (tens of
					 * thousands of ".L0" on some architectures, ISA mapping
					 * symbols, hundreds of ".LM*"). Feeding those
					 * duplicates into uthash collapses them onto a single
					 * bucket chain that expansion can never split, so the
					 * table doubles num_buckets without bound until the
					 * 32-bit counter overflows to 0 and HASH_TO_BKT walks
					 * off the bucket array (SIGSEGV). De-duplicating keeps
					 * the hash well-formed and matches the correct semantics
					 * of a name lookup: a name with several addresses has no
					 * single meaningful address. The addr->name interval
					 * array below still records every symbol, so reverse
					 * symbolization coverage is unchanged.
					 */
					struct kernel_symbol_entry *existing = NULL;
					HASH_FIND(hh, new_hash, items[i].private, name_len, existing);
					if (!existing) {
						struct kernel_symbol_entry *entry = malloc(sizeof(struct kernel_symbol_entry));
						if (entry) {
							entry->name = items[i].private;
							entry->addr = addr;
							HASH_ADD_KEYPTR(hh, new_hash, entry->name, name_len, entry);
						}
					}
				}
				i++;
			}
		}
	}
	free(line);
	fclose(f);

	struct interval_array *new_array = gu_interval_array_init(items, i);
	struct interval_array *old_array;
	struct kernel_symbol_entry *old_hash;

	if (!new_array) {
		for (int j = 0; j < i; j++)
			free(items[j].private);
		free(items);
		gu_kernel_symbol_hash_destroy(new_hash);
		return -1;
	}

	/*
	 * Swap under the write lock and free what was swapped out: a concurrent
	 * reload then frees only the tables it replaced itself.
	 */
	pthread_rwlock_wrlock(&kernel_symbols_lock);
	g_ksym_items_count = items_cap;
	ctx->statistics.kernel_symbols_mem_size = temp_kernel_symbols_mem;
	old_array = ctx->kernel_symbols;
	old_hash = ctx->kernel_symbol_hash;
	ctx->kernel_symbols = new_array;
	ctx->kernel_symbol_hash = new_hash;
	pthread_rwlock_unlock(&kernel_symbols_lock);

	if (old_array)
		gu_interval_array_destroy(old_array);

	gu_kernel_symbol_hash_destroy(old_hash);

	free(items);

	return 0;
}

int gu_search_kernel_symbol(struct gu_context *ctx, uint64_t addr, char *buf, size_t len, uint64_t *offset)
{
	if (!ctx)
		return -1;

	pthread_rwlock_rdlock(&kernel_symbols_lock);
	if (!ctx->kernel_symbols) {
		pthread_rwlock_unlock(&kernel_symbols_lock);
		return -1;
	}

	struct interval_array_item item;
	int result = gu_interval_array_search(ctx->kernel_symbols, addr, &item);
	if (result >= 0) {
		if (offset)
			*offset = addr - item.start;
		if (buf && len > 0) {
			strncpy(buf, (const char *)item.private, len);
			buf[len - 1] = '\0';
		}
	}

	pthread_rwlock_unlock(&kernel_symbols_lock);

	return result >= 0 ? 0 : -1;
}

uint64_t gu_search_kernel_address(struct gu_context *ctx, const char *name)
{
	struct kernel_symbol_entry *entry = NULL;
	uint64_t addr = 0;

	if (!ctx || !name)
		return 0;

	pthread_rwlock_rdlock(&kernel_symbols_lock);
	HASH_FIND_STR(ctx->kernel_symbol_hash, name, entry);
	if (entry)
		addr = entry->addr;
	pthread_rwlock_unlock(&kernel_symbols_lock);

	return addr;
}

#define TAB_STR "\t"
#define DOUBLE_TAB_STR "\t\t"

static bool is_stack_bottom_symbol(const char *sym)
{
	static const char *const bottom_symbols[] = {
		"_start",
		"__libc_start_main",
		"__libc_start_call_main",
		"start_thread",
		"clone",
		"__clone",
	};

	if (!sym)
		return false;

	for (size_t i = 0; i < sizeof(bottom_symbols) / sizeof(bottom_symbols[0]); i++) {
		if (strcmp(sym, bottom_symbols[i]) == 0)
			return true;
	}

	return false;
}

static unsigned long gu_frame_lookup_pc_for_return_address(unsigned long pc,
							   bool initial_frame,
							   bool signal_frame)
{
	if (initial_frame || signal_frame || pc == 0)
		return pc;
	return pc - 1;
}

static unsigned long gu_cfi_lookup_pc_for_frame(unsigned long pc,
						bool initial_frame,
						bool signal_frame)
{
	return gu_frame_lookup_pc_for_return_address(pc, initial_frame,
						     signal_frame);
}

/* 1: found; 0: no symbol at the address; -1: its name cannot be read. */
static int gu_lookup_elf_symbol(struct per_elf_ctx *elf_ctx,
				unsigned long lookup_relative_pc,
				char **sym, uint64_t *func_offset)
{
	struct interval_array_item sym_item = { .private = NULL };
	char *symbol;
	int ret;

	if (sym)
		*sym = NULL;
	if (func_offset)
		*func_offset = 0;
	if (!elf_ctx || !elf_ctx->symbols)
		return 0;

	ret = gu_interval_array_search(elf_ctx->symbols, lookup_relative_pc,
				       &sym_item);
	if (ret < 0)
		return 0;

	symbol = gu_elf_symbol_name(elf_ctx, ret, sym_item.private);
	if (!symbol)
		return -1;

	if (sym)
		*sym = symbol;
	if (func_offset)
		*func_offset = lookup_relative_pc - sym_item.start;
	return 1;
}

/*
 * A caller frame is looked up at @lookup_relative_pc, its return address
 * minus one.  When that lies in no symbol but @relative_pc starts one, the
 * address is an entry the kernel pushed, not a return: the sigreturn
 * trampoline a signal handler returns into (glibc's __restore_rt, the
 * arm64 vDSO's __kernel_rt_sigreturn) has an unnamed nop before it for
 * unwinders that subtract one.  Name it by @relative_pc then; not when
 * the symbol there has a name that cannot be read: @relative_pc may start
 * the next function.
 */
static bool gu_lookup_frame_symbol(struct per_elf_ctx *elf_ctx,
				   unsigned long relative_pc,
				   unsigned long lookup_relative_pc,
				   char **sym, uint64_t *func_offset)
{
	int ret = gu_lookup_elf_symbol(elf_ctx, lookup_relative_pc, sym,
				       func_offset);

	if (ret != 0 || lookup_relative_pc == relative_pc)
		return ret > 0;
	return gu_lookup_elf_symbol(elf_ctx, relative_pc, sym, func_offset) > 0;
}

static bool gu_stack_snapshot_read_u64(struct gu_stack_info *info,
				       uint64_t raw_sp, uint64_t addr,
				       uint64_t *val)
{
	uint64_t stack_start;
	uint64_t stack_end;

	if (!info || !info->stack_data || !val)
		return false;

	stack_start = raw_sp & ~((uint64_t)GU_STACK_DATA_ALIGN - 1);
	stack_end = stack_start + info->stack_size;
	if (addr < stack_start || addr >= stack_end ||
	    addr + sizeof(*val) < addr ||
	    stack_end - addr < sizeof(*val))
		return false;

	memcpy(val, info->stack_data + (addr - stack_start), sizeof(*val));
	return true;
}

static bool gu_frame_pointer_sane(uint64_t bp, uint64_t next_bp)
{
	if (bp == 0 || next_bp == 0)
		return false;
	if ((bp & (sizeof(uint64_t) - 1)) != 0 ||
	    (next_bp & (sizeof(uint64_t) - 1)) != 0)
		return false;
	if (next_bp <= bp)
		return false;
	return true;
}

static bool gu_append_pc_frame(struct gu_context *ctx,
			       struct per_pid_ctx **pid_ctx,
			       struct gu_stack_info *info, uint64_t pc,
			       bool initial_frame, bool signal_frame,
			       struct interval_array_item *elf_item,
			       bool *maps_reloaded,
			       gu_frame_callback_t callback, void *user_ctx,
			       bool *end_of_stack)
{
	struct gu_frame_record *stack_frame = &ctx->frame_record;
	struct per_elf_ctx *elf_ctx = NULL;
	unsigned long map_exec_virt_addr;
	unsigned long bias;
	unsigned long relative_pc;
	unsigned long lookup_relative_pc;
	int ret;

	if (!callback || pc == 0)
		return false;

	if (!(elf_item->private != NULL && pc >= elf_item->start &&
	      pc < elf_item->end)) {
		memset(elf_item, 0, sizeof(*elf_item));
		ret = gu_search_pid_elf_ctx(ctx, pid_ctx, info, pc, elf_item,
					    initial_frame ? maps_reloaded : NULL);
		if (ret < 0)
			return false;
	}

	elf_ctx = gu_get_elf_ctx_from_item(elf_item, &map_exec_virt_addr);

	memset(stack_frame, 0, sizeof(*stack_frame));
	if (!elf_ctx) {
		stack_frame->pc = pc;
		stack_frame->abs_pc = pc;
		stack_frame->flags = GU_FRAME_ANON_EXEC;
		callback(stack_frame, user_ctx);
		return true;
	}

	bias = elf_item->start - map_exec_virt_addr;
	relative_pc = pc - bias;
	lookup_relative_pc = gu_frame_lookup_pc_for_return_address(
		relative_pc, initial_frame, signal_frame);

	stack_frame->elf_info = (struct gu_elf_info *)elf_ctx;
	stack_frame->pc = relative_pc;
	stack_frame->abs_pc = pc;
	gu_lookup_frame_symbol(elf_ctx, relative_pc, lookup_relative_pc,
			       &stack_frame->symbol, &stack_frame->offset);

	callback(stack_frame, user_ctx);
	if (end_of_stack && is_stack_bottom_symbol(stack_frame->symbol))
		*end_of_stack = true;
	return true;
}

static int gu_unwind_dwarf_tail_by_fp(struct gu_context *ctx,
				      struct per_pid_ctx **pid_ctx,
				      struct gu_stack_info *info,
				      uint64_t raw_sp, uint64_t bp,
				      uint64_t pc, bool append_current_pc,
				      gu_frame_callback_t callback,
				      void *user_ctx,
				      enum gu_unwind_reason *reason)
{
	struct interval_array_item elf_item = { 0, 0, NULL };
	bool maps_reloaded = false;
	bool end_of_stack = false;
	uint64_t next_bp;
	uint64_t next_pc;
	int appended = 0;
	int max_frames = MAX_FP_STACK_LEVEL;

	if (!ctx || !pid_ctx || !*pid_ctx || !info || !callback)
		return 0;

	if (append_current_pc &&
	    gu_append_pc_frame(ctx, pid_ctx, info, pc, true, false, &elf_item,
			       &maps_reloaded, callback, user_ctx,
			       &end_of_stack)) {
		appended++;
		if (end_of_stack) {
			if (reason)
				*reason = GU_UNWIND_REASON_END_OF_STACK;
			return appended;
		}
	}

	while (max_frames--) {
		if (!gu_stack_snapshot_read_u64(info, raw_sp, bp, &next_bp) ||
		    !gu_stack_snapshot_read_u64(info, raw_sp, bp + 8, &next_pc))
			break;
		if (!gu_frame_pointer_sane(bp, next_bp))
			break;
		if (next_pc == 0)
			break;

		end_of_stack = false;
		if (!gu_append_pc_frame(ctx, pid_ctx, info, next_pc, false,
					false, &elf_item, &maps_reloaded,
					callback, user_ctx, &end_of_stack))
			break;

		appended++;
		if (end_of_stack) {
			if (reason)
				*reason = GU_UNWIND_REASON_END_OF_STACK;
			break;
		}
		bp = next_bp;
	}

	if (appended > 0 && reason &&
	    *reason != GU_UNWIND_REASON_END_OF_STACK)
		*reason = GU_UNWIND_REASON_END_OF_STACK;
	return appended;
}

int gu_unwind_by_fp(struct per_pid_ctx *pid_ctx, struct gu_stack_info *info, gu_frame_callback_t callback, void *user_ctx)
{
	unsigned long pc, relative_pc, func_offset, bias;

	struct gu_context *ctx = pid_ctx->gu_ctx;
	struct gu_frame_record *stack_frame = &ctx->frame_record;

	uint64_t *fp_pc = (uint64_t *)info->ustack_fp;
	int fp_level = 0, max_fp_level = info->ustack_fp_level > MAX_FP_STACK_LEVEL ? MAX_FP_STACK_LEVEL : info->ustack_fp_level;
	bool allow_unknown = gu_flags_is_set(info, GU_FLAG_FP_ALLOW_UNKNOWN);

	int max_backtrace_level = MAX_FP_STACK_LEVEL;

	struct interval_array_item elf_item = { 0, 0, NULL };
	struct per_elf_ctx *elf_ctx = NULL;
	unsigned long map_exec_virt_addr = 0;
	enum gu_unwind_reason reason = GU_UNWIND_REASON_UNKNOWN;
	bool maps_reloaded = false;

	int loop_count = 0, ret = 0;

	GU_VERBOSE("fp backtrace started");

	if (max_fp_level <= 0) {
		gu_flags_set_reason(info, GU_UNWIND_REASON_END_OF_STACK);
		return 0;
	}

	pc = fp_pc[fp_level++];

	while (max_backtrace_level--) {
		GU_VERBOSE(TAB_STR "[%d] [FP] loop started. pc: 0x%lx", loop_count++, pc);

		if (pc == 0) {
			reason = GU_UNWIND_REASON_END_OF_STACK;
			break;
		}

		if (!(elf_item.private != NULL && pc >= elf_item.start && pc < elf_item.end)) {
			/* only the sampled IP may reload: deeper FP frames can be junk */
			ret = gu_search_pid_elf_ctx(ctx, &pid_ctx, info, pc,
						    &elf_item,
						    fp_level == 1 ? &maps_reloaded : NULL);
			if (ret >= 0) {
				elf_ctx = gu_get_elf_ctx_from_item(&elf_item,
								   &map_exec_virt_addr);
			} else {
				elf_ctx = NULL;
				if (!allow_unknown) {
					reason = GU_UNWIND_REASON_NO_EXEC_PC;
					break;
				}
			}
		}

		if (elf_ctx) {
			GU_VERBOSE(DOUBLE_TAB_STR "[FP] Found elf item from [%lx - %lx] [%s]", elf_item.start, elf_item.end, elf_ctx->base_name);

			bias = elf_item.start - map_exec_virt_addr;

			relative_pc = pc - bias;

			GU_VERBOSE(DOUBLE_TAB_STR "[FP] pc: 0x%lx relative pc to %s: 0x%lx", pc, elf_ctx->base_name, relative_pc);

			char *sym = NULL;
			uint64_t func_offset = 0;

			/* fp_pc[0] is the sampled PC, the rest are return addresses */
			gu_lookup_frame_symbol(elf_ctx, relative_pc,
					       gu_frame_lookup_pc_for_return_address(
						       relative_pc, fp_level == 1, false),
					       &sym, &func_offset);

			stack_frame->elf_info = (struct gu_elf_info *)elf_ctx;
			stack_frame->pc = relative_pc;
			stack_frame->offset = func_offset;
			stack_frame->symbol = sym;
			stack_frame->flags = 0;

			if (sym)
				GU_VERBOSE(DOUBLE_TAB_STR "[FP] symbol: %s + 0x%lx", sym, func_offset);
			else
				GU_VERBOSE(DOUBLE_TAB_STR "[FP] no found sym. return 0x%lx[%s]", relative_pc, elf_ctx->base_name);

			if (is_stack_bottom_symbol(sym))
				reason = GU_UNWIND_REASON_END_OF_STACK;
		} else {
			if (!allow_unknown) {
				reason = GU_UNWIND_REASON_NO_EXEC_PC;
				break;
			}
			stack_frame->pc = pc;
			stack_frame->offset = 0;
			stack_frame->symbol = NULL;
			stack_frame->elf_info = NULL;
			stack_frame->flags = GU_FRAME_ANON_EXEC;

			GU_VERBOSE(DOUBLE_TAB_STR "no found sym. return 0x%lx[anon exec segment]", pc);
		}

		stack_frame->abs_pc = pc;
		callback(stack_frame, user_ctx);

		if (reason == GU_UNWIND_REASON_END_OF_STACK)
			break;

		if (fp_level >= max_fp_level) {
			reason = GU_UNWIND_REASON_END_OF_STACK;
			break;
		}

		pc = fp_pc[fp_level++];
	}

	if (reason == GU_UNWIND_REASON_UNKNOWN)
		reason = GU_UNWIND_REASON_TRUNCATED;

	gu_flags_set_reason(info, reason);

	return MAX_FP_STACK_LEVEL - max_backtrace_level;
}

static int gu_unwind_locked(struct gu_context *ctx, struct gu_stack_info *info,
			    gu_frame_callback_t callback, void *user_ctx)
{
	enum gu_unwind_reason reason = GU_UNWIND_REASON_UNKNOWN;
	bool fp;

	if (info == NULL)
		return -1;
	fp = gu_flags_is_set(info, GU_FLAG_HINT_SET_FP);

	if (info->regs == NULL) {
		gu_flags_set_reason(info, GU_UNWIND_REASON_NO_REGS);
		return -1;
	}

	gu_maybe_sweep_retired_elf(ctx);

	struct per_pid_ctx *pid_ctx = NULL, *stale = NULL;
	struct gu_frame_record *stack_frame = &ctx->frame_record;

	HASH_FIND_INT(ctx->pid_ctx_list, &info->pid, pid_ctx);

	/*
	 * Another instance's view is cached under the pid: the sample's own one
	 * replaces it once staged.  A late sample of an instance that is gone
	 * must not replace the view of the pid's current one, nor be unwound
	 * against it.
	 */
	if (info->unique_id != 0 && pid_ctx && pid_ctx->unique_id != info->unique_id && !ctx->debug) {
		stale = pid_ctx;
		pid_ctx = NULL;
	}

	if (!pid_ctx) {
		pid_ctx = gu_load_pid_instance(ctx, info);
		if (!pid_ctx) {
			gu_flags_set_reason(info, GU_UNWIND_REASON_PROCESS_EXIT);
			return -1;
		}
		if (stale) {
			GU_VERBOSE("pid unique id: 0x%lx - 0x%lx\n", stale->unique_id, info->unique_id);
			ctx->statistics.unique_id_caused_reload_count++;
			gu_pid_ctx_event_notify_pid_ctx(stale->pid, (unsigned long long)stale->unique_id, stale->comm, GU_PID_CTX_EVENT_DESTROY);
			gu_clear_pid_ctx(stale);
		}

		if (pid_ctx->golang)
			gu_flags_set(info, GU_FLAG_HINT_SET_FP);

		gu_add_pid_ctx(ctx, pid_ctx);
		gu_pid_ctx_event_notify_pid_ctx(pid_ctx->pid, (unsigned long long)pid_ctx->unique_id, pid_ctx->comm, GU_PID_CTX_EVENT_CREATE);
	}

	if (!pid_ctx->elf_ctx_list) {
		gu_flags_set_reason(info, GU_UNWIND_REASON_NO_ELF);
		return -1;
	}

	// todo
	if (fp)
		return gu_unwind_by_fp(pid_ctx, info, callback, user_ctx);

	struct interval_array_item elf_item = { 0, 0, NULL };
	struct per_elf_ctx *elf_ctx = NULL;
	unsigned long map_exec_virt_addr = 0;
	Dwarf_Frame *frame = NULL;
	bool maps_reloaded = false;

	unsigned long pc, sp, raw_sp, relative_pc, lookup_relative_pc, func_offset, bias;
	int ret = 0, regno = 0, loop_count = 0;
	bool current_signal_frame = false;
	bool fp_tail_append_current_pc = false;
	unsigned long prev_sp = 0;
	unsigned long prev_pc = 0;

	int pc_regno = reg_name_rip;

	get_regs(info, pc_regno, &pc);
	get_regs(info, reg_name_rsp, &sp);

#ifdef GUNWINDER_ARM64
	pc_regno = reg_name_lr;
#else
	pc_regno = reg_name_rip;
#endif

	GU_VERBOSE("backtrace started");

	raw_sp = sp;
	prev_sp = sp;
	prev_pc = pc;

	int max_backtrace_level = 512;

	while (max_backtrace_level--) {
		/* not in GU_VERBOSE(): its arguments are evaluated only when verbose */
		bool initial_frame = loop_count++ == 0;

		GU_VERBOSE(TAB_STR "[%d] loop started. pc: 0x%lx sp: 0x%lx", loop_count - 1, pc, sp);

		if (!(elf_item.private != NULL && pc >= elf_item.start && pc < elf_item.end)) {
			ret = gu_search_pid_elf_ctx(ctx, &pid_ctx, info, pc,
						    &elf_item,
						    initial_frame ? &maps_reloaded : NULL);
			GU_VERBOSE(DOUBLE_TAB_STR "elf search, ret: %d elf_itme.start: 0x%lx elf_itme.end: 0x%lx", ret, elf_item.start, elf_item.end);
			if (ret < 0) {
				reason = GU_UNWIND_REASON_NO_EXEC_PC;
				break;
			}

			elf_ctx = gu_get_elf_ctx_from_item(&elf_item,
							   &map_exec_virt_addr);
			if (!elf_ctx) {
				fp_tail_append_current_pc = true;
				reason = GU_UNWIND_REASON_NO_EXEC_PC;
				break;
			}
			GU_VERBOSE(DOUBLE_TAB_STR "elf search, change to [%s]", elf_ctx->base_name);
		}

		GU_VERBOSE(DOUBLE_TAB_STR "Found elf item from [%lx - %lx] [%s]", elf_item.start, elf_item.end, elf_ctx->base_name);

		bias = elf_item.start - map_exec_virt_addr;

		relative_pc = pc - bias;
		lookup_relative_pc = gu_frame_lookup_pc_for_return_address(
			relative_pc, initial_frame, current_signal_frame);

		GU_VERBOSE(DOUBLE_TAB_STR "pc: 0x%lx relative pc to %s: 0x%lx", pc, elf_ctx->base_name, relative_pc);

		char *sym = NULL;
		uint64_t func_offset = 0;

		gu_lookup_frame_symbol(elf_ctx, relative_pc, lookup_relative_pc,
				       &sym, &func_offset);

		stack_frame->elf_info = (struct gu_elf_info *)elf_ctx;
		stack_frame->pc = relative_pc;
		stack_frame->offset = func_offset;
		stack_frame->symbol = sym;
		stack_frame->flags = 0;

		stack_frame->abs_pc = pc;
		callback(stack_frame, user_ctx);

		if (sym)
			GU_VERBOSE(DOUBLE_TAB_STR "symbol: %s + 0x%lx", sym, func_offset);
		else
			GU_VERBOSE(DOUBLE_TAB_STR "no found sym. return 0x%lx[%s]", relative_pc, elf_ctx->base_name);

		if (is_stack_bottom_symbol(sym)) {
			reason = GU_UNWIND_REASON_END_OF_STACK;
			break;
		}

		if (elf_ctx->gu_cfi == NULL) {
			reason = GU_UNWIND_REASON_NO_CFI;
			break;
		}

		unsigned long cfi_relative_pc =
			gu_cfi_lookup_pc_for_frame(relative_pc, initial_frame,
						   current_signal_frame);
		bool unwound_signal_frame = false;

		ret = gu_cfi_parse_cfi_ex(elf_ctx->gu_cfi, cfi_relative_pc,
					  initial_frame, &unwound_signal_frame);
		if (ret) {
			reason = GU_UNWIND_REASON_CFI_FRAME_DECODE_FAILED;
			break;
		}

		unsigned long _ra, _sp, _bp;

		reason = gen_reg(frame, pc_regno, bias, raw_sp, info, &_ra);
		if (reason != GU_UNWIND_REASON_OK)
			break;

		GU_VERBOSE(DOUBLE_TAB_STR "backtrace RIP 0x%lx", _ra);

		reason = gen_reg(frame, reg_name_rsp, bias, raw_sp, info, &_sp);
		if (reason != GU_UNWIND_REASON_OK)
			break;

		GU_VERBOSE(DOUBLE_TAB_STR "backtrace RSP 0x%lx", _sp);

		reason = gen_reg(frame, reg_name_rbp, bias, raw_sp, info, &_bp);
		if (reason == GU_UNWIND_REASON_OK)
			write_regs(info, reg_name_rbp, _bp);

		GU_VERBOSE(DOUBLE_TAB_STR "backtrace RBP 0x%lx", _bp);

		if (frame) {
			free(frame);
			frame = NULL;
		}

		pc = _ra;
		sp = _sp;
		current_signal_frame = unwound_signal_frame;

		if (pc == 0) {
			reason = GU_UNWIND_REASON_END_OF_STACK;
			break;
		}

		/*
		 * Loop guard: a valid caller frame always sits at a higher
		 * stack address, so the unwound SP must strictly increase, and
		 * the return address must differ from the frame we just emitted.
		 * When CFI is read from the wrong on-disk copy of a replaced
		 * ("(deleted)") library, the RA column can resolve to a stack
		 * slot holding a constant, producing the same PC every step
		 * while SP still creeps upward - an endless run of identical
		 * "0x... [libc.so.6]" frames up to the depth cap. Stop as soon
		 * as the stack fails to make forward progress in either SP or PC.
		 *
		 * The one step that may keep SP is the one out of the sampled
		 * frame: a leaf that saved nothing (arm64, where a call leaves
		 * the return address in x30 and moves no stack) returns to its
		 * caller with the same SP.  The PC must still change.
		 */
		if (sp < prev_sp || (sp == prev_sp && !initial_frame) || pc == prev_pc) {
			reason = GU_UNWIND_REASON_NO_PROGRESS;
			break;
		}
		prev_sp = sp;
		prev_pc = pc;

		write_regs(info, reg_name_rsp, sp);
		write_regs(info, pc_regno, pc);
	}

	if (frame) {
		free(frame);
		frame = NULL;
	}

	if (reason == GU_UNWIND_REASON_UNKNOWN)
		reason = GU_UNWIND_REASON_TRUNCATED;

	if (reason != GU_UNWIND_REASON_END_OF_STACK &&
	    reason != GU_UNWIND_REASON_PROCESS_EXIT) {
		uint64_t bp = 0;

		if (get_regs(info, reg_name_rbp, &bp))
			gu_unwind_dwarf_tail_by_fp(ctx, &pid_ctx, info, raw_sp,
						   bp, pc,
						   fp_tail_append_current_pc,
						   callback, user_ctx,
						   &reason);
	}

	GU_VERBOSE("backtrace stopped reason: %d", reason);
	gu_flags_set_reason(info, reason);

	return 512 - max_backtrace_level;
}

int gu_unwind(struct gu_context *ctx, struct gu_stack_info *info,
	      gu_frame_callback_t callback, void *user_ctx)
{
	int ret;

	if (!ctx)
		return -1;

	pthread_mutex_lock(&ctx->lock);
	ret = gu_unwind_locked(ctx, info, callback, user_ctx);
	pthread_mutex_unlock(&ctx->lock);
	return ret;
}

struct gu_statistics *gu_get_statistics(struct gu_context *ctx)
{
	return &ctx->statistics;
}

int gu_copy_statistics(struct gu_context *ctx, struct gu_statistics *out)
{
	if (!ctx || !out)
		return -1;

	pthread_mutex_lock(&ctx->lock);
	memcpy(out, &ctx->statistics, sizeof(*out));
	pthread_mutex_unlock(&ctx->lock);
	return 0;
}

static uint64_t gu_elf_debug_info_bytes(const struct per_elf_ctx *elf_ctx)
{
	uint64_t total = 0;

	if (!elf_ctx)
		return 0;
	total += elf_ctx->sym_search_size;
	if (elf_ctx->gu_cfi) {
		total += elf_ctx->gu_cfi->cfi_mem_usage;
		total += gu_cfi_runtime_mem_usage(elf_ctx->gu_cfi);
		total += elf_ctx->gu_cfi->cfi_data_mem_usage;
	}
	return total;
}

static int gu_pid_snapshot_has_elf(
	const struct gu_debuginfo_mem_stat_pid *pid_stat,
	const struct per_elf_ctx *elf_ctx)
{
	const char *path = elf_ctx && elf_ctx->elf_file_path ?
		elf_ctx->elf_file_path : "<unknown>";

	if (!pid_stat)
		return 0;
	for (size_t i = 0; i < pid_stat->elf_count; i++) {
		if (pid_stat->elfs[i].path &&
		    strcmp(pid_stat->elfs[i].path, path) == 0)
			return 1;
	}
	return 0;
}

struct gu_copy_pid_debuginfo_mem_stat_ctx {
	struct gu_debuginfo_mem_stat_pid *pid_stat;
	int err;
};

static void gu_copy_pid_debuginfo_mem_stat_elf(void *private, void *ctx_arg)
{
	struct gu_copy_pid_debuginfo_mem_stat_ctx *copy_ctx = ctx_arg;
	struct gu_debuginfo_mem_stat_pid *pid_stat;
	struct gu_debuginfo_mem_stat_elf *elf_stat;
	struct gu_debuginfo_mem_stat_elf *new_elfs;
	struct per_elf_map_ctx *map_ctx = private;
	struct per_elf_ctx *elf_ctx;
	const char *path;
	uint64_t total_bytes;
	uint64_t refcnt;

	if (!copy_ctx || copy_ctx->err || !map_ctx)
		return;
	pid_stat = copy_ctx->pid_stat;
	elf_ctx = map_ctx->elf_ctx;
	if (!elf_ctx)
		return;
	if (gu_pid_snapshot_has_elf(pid_stat, elf_ctx))
		return;

	new_elfs = realloc(pid_stat->elfs,
			   (pid_stat->elf_count + 1) * sizeof(*pid_stat->elfs));
	if (!new_elfs) {
		copy_ctx->err = -1;
		return;
	}
	pid_stat->elfs = new_elfs;
	elf_stat = &pid_stat->elfs[pid_stat->elf_count];
	memset(elf_stat, 0, sizeof(*elf_stat));

	path = elf_ctx->elf_file_path ? elf_ctx->elf_file_path : "<unknown>";
	elf_stat->path = strdup(path);
	if (!elf_stat->path) {
		copy_ctx->err = -1;
		return;
	}
	pid_stat->elf_count++;
	if (!pid_stat->key_path) {
		pid_stat->key_path = strdup(path);
		if (!pid_stat->key_path) {
			copy_ctx->err = -1;
			return;
		}
	}

	refcnt = elf_ctx->refcnt ? elf_ctx->refcnt : 1;
	total_bytes = gu_elf_debug_info_bytes(elf_ctx);
	elf_stat->refcnt = refcnt;
	elf_stat->symbol_bytes = elf_ctx->sym_search_size;
	elf_stat->symbol_name_read_failures = elf_ctx->symbol_name_read_failures;
	if (elf_ctx->gu_cfi) {
		elf_stat->cfi_fde_bytes = elf_ctx->gu_cfi->cfi_mem_usage +
					  gu_cfi_runtime_mem_usage(elf_ctx->gu_cfi);
		elf_stat->cfi_data_bytes = elf_ctx->gu_cfi->cfi_data_mem_usage;
	}
	elf_stat->total_bytes = total_bytes;
	elf_stat->pss_bytes = total_bytes / refcnt;

	pid_stat->total_bytes += elf_stat->total_bytes;
	pid_stat->pss_bytes += elf_stat->pss_bytes;
}

static int gu_copy_pid_debuginfo_mem_stat(
	struct per_pid_ctx *pid_ctx,
	struct gu_debuginfo_mem_stat_pid *pid_stat)
{
	struct gu_copy_pid_debuginfo_mem_stat_ctx copy_ctx = {
		.pid_stat = pid_stat,
		.err = 0,
	};

	if (!pid_ctx || !pid_stat)
		return -1;

	pid_stat->pid = pid_ctx->pid;
	pid_stat->unique_id = pid_ctx->unique_id;
	memcpy(pid_stat->comm, pid_ctx->comm, sizeof(pid_stat->comm));
	pid_stat->comm[sizeof(pid_stat->comm) - 1] = '\0';

	gu_interval_array_for_each_private(pid_ctx->elf_ctx_list,
					   gu_copy_pid_debuginfo_mem_stat_elf,
					   &copy_ctx);
	if (copy_ctx.err)
		return -1;
	if (!pid_stat->key_path) {
		pid_stat->key_path = strdup("<unknown>");
		if (!pid_stat->key_path)
			return -1;
	}
	return 0;
}

int gu_export_debuginfo_mem_stat_snapshot(
	struct gu_context *ctx,
	struct gu_debuginfo_mem_stat_snapshot **out)
{
	struct gu_debuginfo_mem_stat_snapshot *snapshot;
	struct per_pid_ctx *pid_ctx, *tmp;
	int ret = 0;

	if (!ctx || !out)
		return -1;
	*out = NULL;

	snapshot = calloc(1, sizeof(*snapshot));
	if (!snapshot)
		return -1;

	pthread_mutex_lock(&ctx->lock);
	snapshot->pid_count = HASH_COUNT(ctx->pid_ctx_list);
	if (snapshot->pid_count) {
		snapshot->pids = calloc(snapshot->pid_count,
					sizeof(*snapshot->pids));
		if (!snapshot->pids) {
			snapshot->pid_count = 0;
			ret = -1;
			goto unlock;
		}
	}

	snapshot->pid_count = 0;
	HASH_ITER (hh, ctx->pid_ctx_list, pid_ctx, tmp) {
		struct gu_debuginfo_mem_stat_pid *pid_stat =
			&snapshot->pids[snapshot->pid_count];

		if (gu_copy_pid_debuginfo_mem_stat(pid_ctx, pid_stat) != 0) {
			snapshot->pid_count++;
			ret = -1;
			goto unlock;
		}
		snapshot->total_bytes += pid_stat->total_bytes;
		snapshot->pss_bytes += pid_stat->pss_bytes;
		snapshot->pid_count++;
	}

unlock:
	pthread_mutex_unlock(&ctx->lock);

	if (ret != 0) {
		gu_debuginfo_mem_stat_snapshot_free(snapshot);
		return -1;
	}
	*out = snapshot;
	return 0;
}

void gu_debuginfo_mem_stat_snapshot_free(
	struct gu_debuginfo_mem_stat_snapshot *snapshot)
{
	if (!snapshot)
		return;

	for (size_t i = 0; i < snapshot->pid_count; i++) {
		struct gu_debuginfo_mem_stat_pid *pid_stat = &snapshot->pids[i];

		free(pid_stat->key_path);
		for (size_t j = 0; j < pid_stat->elf_count; j++)
			free(pid_stat->elfs[j].path);
		free(pid_stat->elfs);
	}
	free(snapshot->pids);
	free(snapshot);
}

