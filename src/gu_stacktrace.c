/* SPDX-License-Identifier: LGPL-3.0-or-later */
/*
 * Copyright (C) 2026 ByteDance Inc.
 *
 * This file is part of libgunwinder and is distributed under the
 * GNU Lesser General Public License v3.0 or later.
 *
 * The return-address CFI lookup rule used by the DWARF unwinder was designed
 * with conceptual guidance from elfutils/libdwfl frame unwinding behavior and
 * cross-checks, including behavior covered by libdwfl/frame_unwind.c:
 *
 *   Copyright (C) 2013, 2014, 2016, 2024 Red Hat, Inc.
 *
 * elfutils is available under LGPL-3.0-or-later or GPL-2.0-or-later.
 * libgunwinder applies the rule inside its own stack-snapshot unwind flow.
 */

#define _GNU_SOURCE
#include "gunwinder/unwinder.h"
#include <bfd.h>
#include <ctype.h>
#include <stdatomic.h>
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
#include <time.h>
#include <sys/eventfd.h>

#include "gunwinder/unwinder_types.h"
#include "gu_stacktrace.h"
#include "uthash.h"
#include "gu_interval_array.h"
#include "gu_unwinder.h"
#include "gu_cfi_helper.h"
#include "gu_comm.h"

void gu_pid_ctx_event_notify_pid_ctx(int pid, unsigned long long start_time, const char *comm, unsigned int type);

static char *elf_scn_type_str[ELF_SCN_TYPE_MAX] = {
	".note.go.buildid", ".note.gnu.build-id", ".symtab", ".dynsym", ".debug_frame", ".debug_frame_hdr", ".zdebug_frame", ".zdebug_frame_hdr", ".eh_frame", ".eh_frame_hdr",
};

#define STANDARD_BUILD_ID_LEN 20
#define GU_ELF_RETIRE_TTL_NS (10ULL * 1000000000ULL)
#define GU_ELF_RETIRE_TIMER_INTERVAL_MS 1000
#define GU_PID_MAPS_RELOAD_MIN_INTERVAL_NS (30ULL * 1000000000ULL)
#define GU_PID_MAPS_RELOAD_MAX_INTERVAL_NS (90ULL * 1000000000ULL)

struct kernel_symbol_entry {
	char *name;
	uint64_t addr;
	UT_hash_handle hh;
};

struct gu_context {
	struct per_pid_ctx *pid_ctx_list;
	struct per_elf_ctx *elf_ctx_list;
	uint64_t next_retired_elf_deadline_ns;
	pthread_t retire_timer_thread_id;
	int retire_timer_event_fd;
	bool retire_timer_started;
	atomic_bool retire_timer_stop;
	atomic_bool retire_sweep_pending;
	atomic_uint_fast64_t retire_timer_now_ns;
	bool debug;
	bool go_only_buildid;
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
};

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

static struct per_elf_ctx tmp_ctx = { 0 };

static uint64_t gu_monotonic_ns(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
		return 0;
	return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static uint64_t gu_cache_now_ns(struct gu_context *ctx)
{
	uint64_t timer_now_ns;

	if (ctx && ctx->retire_timer_started) {
		timer_now_ns = atomic_load_explicit(&ctx->retire_timer_now_ns, memory_order_acquire);
		if (timer_now_ns)
			return timer_now_ns;
	}
	return gu_monotonic_ns();
}

static void *gu_retire_timer_thread(void *arg)
{
	struct gu_context *ctx = arg;
	struct pollfd pfd;

	while (!atomic_load_explicit(&ctx->retire_timer_stop, memory_order_acquire)) {
		uint64_t now_ns = gu_monotonic_ns();
		if (now_ns) {
			atomic_store_explicit(&ctx->retire_timer_now_ns, now_ns, memory_order_release);
			atomic_store_explicit(&ctx->retire_sweep_pending, true, memory_order_release);
		}

		pfd.fd = ctx->retire_timer_event_fd;
		pfd.events = POLLIN;
		pfd.revents = 0;
		while (poll(&pfd, 1, GU_ELF_RETIRE_TIMER_INTERVAL_MS) < 0 && errno == EINTR) {
			if (atomic_load_explicit(&ctx->retire_timer_stop, memory_order_acquire))
				break;
		}
	}

	return NULL;
}

static int gu_retire_timer_start(struct gu_context *ctx)
{
	uint64_t now_ns;

	if (!ctx)
		return -1;

	atomic_init(&ctx->retire_timer_stop, false);
	atomic_init(&ctx->retire_sweep_pending, false);
	atomic_init(&ctx->retire_timer_now_ns, 0);
	ctx->retire_timer_event_fd = -1;

	now_ns = gu_monotonic_ns();
	if (now_ns)
		atomic_store_explicit(&ctx->retire_timer_now_ns, now_ns, memory_order_release);

	ctx->retire_timer_event_fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
	if (ctx->retire_timer_event_fd < 0)
		return -1;

	if (pthread_create(&ctx->retire_timer_thread_id, NULL, gu_retire_timer_thread, ctx) != 0) {
		close(ctx->retire_timer_event_fd);
		ctx->retire_timer_event_fd = -1;
		return -1;
	}

	ctx->retire_timer_started = true;
	return 0;
}

static void gu_retire_timer_stop(struct gu_context *ctx)
{
	uint64_t value = 1;

	if (!ctx || !ctx->retire_timer_started)
		return;

	atomic_store_explicit(&ctx->retire_timer_stop, true, memory_order_release);
	if (ctx->retire_timer_event_fd >= 0)
		(void)write(ctx->retire_timer_event_fd, &value, sizeof(value));

	pthread_join(ctx->retire_timer_thread_id, NULL);
	ctx->retire_timer_started = false;

	if (ctx->retire_timer_event_fd >= 0) {
		close(ctx->retire_timer_event_fd);
		ctx->retire_timer_event_fd = -1;
	}
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

	now_ns = gu_cache_now_ns(ctx);
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

static void gu_maybe_sweep_retired_elf(struct gu_context *ctx)
{
	uint64_t now_ns;

	if (!ctx || !ctx->statistics.retired_elf_ctx_count)
		return;

	if (ctx->retire_timer_started) {
		if (!atomic_exchange_explicit(&ctx->retire_sweep_pending, false, memory_order_acq_rel))
			return;
		now_ns = atomic_load_explicit(&ctx->retire_timer_now_ns, memory_order_acquire);
		if (!now_ns)
			now_ns = gu_monotonic_ns();
	} else {
		now_ns = gu_monotonic_ns();
	}

	gu_retired_elf_sweep(ctx, now_ns);
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

static void fill_symbols_debug_info(struct per_elf_ctx *info)
{
	if (info->scn[ELF_SCN_TYPE_SYMTAB] != NULL)
		info->sym_scn = ELF_SCN_TYPE_SYMTAB;
	else if (info->scn[ELF_SCN_TYPE_DYNSYM] != NULL)
		info->sym_scn = ELF_SCN_TYPE_DYNSYM;
	else
		return;

	bool golang = (info->scn[ELF_SCN_TYPE_GO_BUILD_ID] != NULL);
	bool only_buildid = (golang && info->gu_ctx->go_only_buildid);

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

	size_t count = shdr.sh_size / shdr.sh_entsize;
	size_t actual_count = 0;
	struct gu_symbol_string_table_view name_view;
	struct interval_array_item *items = calloc(count, sizeof(*items));
	if (!items)
		return;
	gu_symbol_string_table_view_init(elf, shdr.sh_link, &name_view);

	struct exec_scn_cache_entry *exec_scn_cache = NULL;

	for (size_t i = 0; i < count; ++i) {
		GElf_Sym sym;
		if (gelf_getsym(data, i, &sym) != &sym)
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

		items[actual_count].start = sym.st_value;
		items[actual_count].end = sym.st_value + sym.st_size;

		if (only_buildid) {
			items[actual_count].private = NULL;
			actual_count++;
			continue;
		}

		const char *name = gu_symbol_string_table_view_get(&name_view, sym.st_name);
		if (name == NULL)
			goto err_free;

		/*
		 * ARM/AArch64 ELF mapping symbols ($x, $d, $a, $t and suffixed
		 * forms) mark code/data regions inside a section.  They are
		 * local STT_NOTYPE symbols and often share the exact address of
		 * a real STT_FUNC entry.  Keeping them in the searchable symbol
		 * interval array can make binary search land on the marker
		 * instead of the function, or miss the overlapping function
		 * interval entirely.  They are never useful frame names, so drop
		 * them before building the interval table.
		 */
		if (sym_type == STT_NOTYPE && is_arm_elf_mapping_symbol_name(name))
			continue;

		if (!golang || info->gu_ctx->go_not_strip_name) {
			items[actual_count].private = strdup(name);
		} else {
			char *goname = golang_strip_name_to_arena(info, name);
			if (!goname)
				goname = gu_symbol_name_arena_strdup(info, name);
			if (goname)
				items[actual_count].private =
					(void *)mark_interval_array_pointer_no_free((uint64_t)goname);
		}
		if (items[actual_count].private == NULL)
			goto err_free;
		{
			bool no_free;
			char *private = get_interval_array_pointer((uint64_t)items[actual_count].private, &no_free);
			(void)no_free;
			info->sym_search_size += strlen(private) + 1;
		}
		actual_count++;
	}

	if (actual_count == 0) {
		free_exec_scn_cache(&exec_scn_cache);
		free(items);
		return;
	}

	struct interval_array_item *new_items = realloc(items, actual_count * sizeof(*items));
	if (!new_items)
		goto err_free;

	items = new_items;

	info->symbols = gu_interval_array_init(items, actual_count);
	if (info->symbols == NULL)
		goto err_free;

	info->sym_search_size += (sizeof(*items) * actual_count);
	info->gu_ctx->statistics.symbols_mem_size += info->sym_search_size;

	free(items);
	free_exec_scn_cache(&exec_scn_cache);
	return;

err_free:
	free_exec_scn_cache(&exec_scn_cache);
	if (items == NULL)
		return;

	for (size_t j = 0; j < actual_count; j++) {
		if (items[j].private) {
			bool no_free;
			void *private = get_interval_array_pointer((uint64_t)items[j].private, &no_free);
			if (!no_free)
				free(private);
		}
	}
	free(items);
	return;
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

static unsigned long get_elf_exec_virt_addr(struct per_elf_ctx *elf_ctx)
{
	unsigned long exec_virt_addr = 0;
	size_t phnum;

	if (elf_getphdrnum(elf_ctx->elf, &phnum) != 0)
		return exec_virt_addr;

	for (size_t i = 0; i < phnum; i++) {
		GElf_Phdr phdr;
		if (gelf_getphdr(elf_ctx->elf, i, &phdr) != &phdr)
			break;

		if (phdr.p_type == PT_LOAD && (phdr.p_flags & PF_X)) {
			/*
			 * /proc/<pid>/maps reports page-aligned mapping starts.
			 * Align p_vaddr down so maps start minus exec_virt_addr
			 * produces the load bias used for symbols and CFI.
			 */
			exec_virt_addr = (unsigned long)(phdr.p_vaddr -
				(phdr.p_align ? phdr.p_vaddr % phdr.p_align : 0));
			break;
		}
	}
	return exec_virt_addr;
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

static struct per_elf_ctx *load_elf(struct gu_context *ctx, char *file_name, int pid)
{
	char pid_root_path[64];
	int len = 0;
	bool vdso_local = false;

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

	ctx->tmp_ctx.elf_file_path = vdso_local ? strdup(file_name) : gu_path_join(pid_root_path, file_name);
	if (!ctx->tmp_ctx.elf_file_path)
		goto exit;

	GU_VERBOSE("Loading elf: %s", ctx->tmp_ctx.elf_file_path);

	ctx->tmp_ctx.elf_fd = open(ctx->tmp_ctx.elf_file_path, O_RDONLY, 0);
	if (ctx->tmp_ctx.elf_fd < 0) {
		GU_VERBOSE("open: %s failed: %s", ctx->tmp_ctx.elf_file_path, strerror(errno));
		goto exit;
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
	} else {
		ctx->tmp_ctx.exec_virt_addr = get_elf_exec_virt_addr(&ctx->tmp_ctx);
	}

	if (ctx->tmp_ctx.build_id_len != STANDARD_BUILD_ID_LEN) {
		/*
		 * Non-standard identities include the MD5 fallback above and Go
		 * build IDs.  They do not match the GNU build-id directory
		 * layout, so debug data can only come from the mapped ELF itself.
		 */
		ctx->tmp_ctx.debug_file_path = strdup(ctx->tmp_ctx.elf_file_path);
	} else {
		char *tmp_path = get_debug_info_path_by_id(ctx->tmp_ctx.build_id);
		ctx->tmp_ctx.debug_file_path = tmp_path;
		/* Prefer host-wide debuginfo, then try the target rootfs. */
		if (access(ctx->tmp_ctx.debug_file_path, F_OK) != 0) {
			ctx->tmp_ctx.debug_file_path = gu_path_join(pid_root_path, tmp_path);
			free(tmp_path);
			if (access(ctx->tmp_ctx.debug_file_path, F_OK) != 0) {
				free(ctx->tmp_ctx.debug_file_path);
				ctx->tmp_ctx.debug_file_path = strdup(ctx->tmp_ctx.elf_file_path);
			}
		}
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
	}

	if (ctx->tmp_ctx.gu_cfi) {
		ctx->statistics.cfi_mem_size += ctx->tmp_ctx.gu_cfi->cfi_mem_usage;
		ctx->statistics.cfi_data_mem_size += ctx->tmp_ctx.gu_cfi->cfi_data_mem_usage;
		fill_symbols_debug_info(&ctx->tmp_ctx);
	}

	elf_ctx = calloc(1, sizeof(struct per_elf_ctx));
	if (!elf_ctx)
		goto exit;

	memcpy(elf_ctx, &ctx->tmp_ctx, sizeof(ctx->tmp_ctx));
	memset(&ctx->tmp_ctx, 0, sizeof(tmp_ctx));

	HASH_ADD_KEYPTR(hh, ctx->elf_ctx_list, elf_ctx->build_id, elf_ctx->build_id_len, elf_ctx);
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

struct per_pid_ctx *gu_load_pid(struct gu_context *ctx, struct gu_stack_info *info)
{
	int count = 0;
	int pid = info->pid;
	char *debug_maps_path = NULL;
	struct interval_array_item *items = NULL;
	struct maps_info *maps = NULL;

	struct per_pid_ctx *pid_ctx = NULL;
	HASH_FIND_INT(ctx->pid_ctx_list, &pid, pid_ctx);
	if (pid_ctx)
		return pid_ctx;

	if (ctx->debug)
		debug_maps_path = (char *)info->unique_id;

	maps = gu_get_maps_info(pid, &count, PERMISSION_X, debug_maps_path);

	if (count == 0)
		goto exit;

	items = calloc(count, sizeof(struct interval_array_item));
	if (!items)
		goto exit;

	pid_ctx = calloc(1, sizeof(struct per_pid_ctx));
	if (!pid_ctx)
		goto exit;

	pid_ctx->gu_ctx = ctx;

	ctx->statistics.pid_ctx_alloc_count++;

	for (int i = 0; i < count; i++) {
		unsigned long map_exec_virt_addr = 0;
		struct per_elf_map_ctx *map_ctx = NULL;
		struct per_elf_ctx *elf;

		items[i].start = maps[i].start;
		items[i].end = maps[i].end;
		elf = load_elf(ctx, maps[i].path, pid);
		map_exec_virt_addr =
			gu_resolve_map_exec_virt_addr(elf, &maps[i]);
		if (i == 0 && elf && elf->golang)
			pid_ctx->golang = true;
		map_ctx = gu_alloc_elf_map_ctx(elf, map_exec_virt_addr);
		if (elf && !map_ctx) {
			gu_put_elf_ctx(elf);
			goto exit;
		}
		items[i].private =
			map_ctx ? (void *)mark_interval_array_pointer_no_free((uint64_t)map_ctx) : NULL;
		GU_VERBOSE("Load elf: %s [0x%lx - 0x%lx] elf_ctx: %p map_exec_virt_addr: 0x%lx",
			   maps[i].path, maps[i].start, maps[i].end, elf,
			   map_ctx ? map_ctx->map_exec_virt_addr : 0);
	}

	// check first items type
	pid_ctx->elf_ctx_list = gu_interval_array_init(items, count);
	if (!pid_ctx->elf_ctx_list)
		goto exit;
	free(items);
	items = NULL;

	gu_free_maps_info(maps, count);
	maps = NULL;

	pid_ctx->pid = pid;
	pid_ctx->unique_id = info->unique_id;
	gu_get_pid_comm(pid, pid_ctx->comm, sizeof(pid_ctx->comm));
	gu_schedule_next_maps_reload(ctx, pid_ctx);

	return pid_ctx;

exit:
	if (pid_ctx)
		free(pid_ctx);
	if (maps)
		gu_free_maps_info(maps, count);
	if (items) {
		gu_cleanup_elf_map_items(items, count);
		free(items);
	}

	return NULL;
}

static void __private_clean_elf_ctx(void *elf_map_ctx, void *_)
{
	struct per_elf_map_ctx *map_ctx =
		(struct per_elf_map_ctx *)elf_map_ctx;

	if (!map_ctx)
		return;

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

	now = gu_cache_now_ns(ctx);
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

	now = gu_cache_now_ns(ctx);
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

	if (pid_ctx->elf_ctx_list) {
		gu_interval_array_for_each_private(pid_ctx->elf_ctx_list, __private_clean_elf_ctx, NULL);
		gu_interval_array_destroy(pid_ctx->elf_ctx_list);
	}

	if (pid_ctx->private) {
		free(pid_ctx->private);
		pid_ctx->private = NULL;
		pid_ctx->private_size = 0;
	}
	free(pid_ctx);
}

static struct per_pid_ctx *gu_reload_pid_ctx(struct gu_context *ctx,
					     struct per_pid_ctx *old_ctx,
					     struct gu_stack_info *info)
{
	struct per_pid_ctx *new_ctx;
	void *private_copy = NULL;
	int private_size = 0;
	bool preload = false;

	if (!ctx || !old_ctx || !info)
		return NULL;

	preload = old_ctx->preload;
	if (old_ctx->private && old_ctx->private_size > 0) {
		private_copy = malloc(old_ctx->private_size);
		if (private_copy) {
			memcpy(private_copy, old_ctx->private, old_ctx->private_size);
			private_size = old_ctx->private_size;
		}
	}

	gu_pid_ctx_event_notify_pid_ctx(old_ctx->pid,
					(unsigned long long)old_ctx->unique_id,
					old_ctx->comm, GU_PID_CTX_EVENT_DESTROY);
	gu_clear_pid_ctx(old_ctx);

	new_ctx = gu_load_pid(ctx, info);
	if (!new_ctx) {
		free(private_copy);
		return NULL;
	}

	new_ctx->preload = preload;
	new_ctx->private = private_copy;
	new_ctx->private_size = private_size;
	if (new_ctx->golang)
		gu_flags_set(info, GU_FLAG_HINT_SET_FP);

	HASH_ADD_INT(ctx->pid_ctx_list, pid, new_ctx);
	ctx->statistics.pid_ctx_count++;
	gu_pid_ctx_event_notify_pid_ctx(new_ctx->pid,
					(unsigned long long)new_ctx->unique_id,
					new_ctx->comm, GU_PID_CTX_EVENT_CREATE);
	return new_ctx;
}

static int gu_search_pid_elf_ctx(struct gu_context *ctx,
				 struct per_pid_ctx **pid_ctx,
				 struct gu_stack_info *info, unsigned long pc,
				 struct interval_array_item *elf_item,
				 bool *maps_reloaded)
{
	int ret;

	ret = gu_interval_array_search((*pid_ctx)->elf_ctx_list, pc, elf_item);
	if (ret >= 0 || !maps_reloaded || *maps_reloaded)
		return ret;
	/*
	 * A PC miss may mean dlopen, plugin, or JIT code changed executable
	 * mappings, so
	 * the unwinder still needs a reload path.  Keep it off the per-sample
	 * hot path: after each pid maps load/reload, wait for a jittered per-pid
	 * deadline before trying again.  The 30-90s spread avoids a restart herd
	 * where many processes loaded at the same time all reload at exactly 60s.
	 */
	if (!gu_maps_reload_allowed(ctx, *pid_ctx, pc))
		return ret;

	if (!ctx->debug && kill(info->pid, 0) != 0) {
		gu_flags_set_reason(info, GU_UNWIND_REASON_PROCESS_EXIT);
		return ret;
	}

	/*
	 * Process mappings are cached per pid, but plugins and JIT runtimes can
	 * add executable mappings after the pid context was created. Refresh
	 * only on a real interval miss; PCs that hit known anonymous executable
	 * ranges keep the old fast path and do not repeatedly scan maps.
	 */
	*maps_reloaded = true;
	ctx->statistics.pid_maps_reload_count++;
	*pid_ctx = gu_reload_pid_ctx(ctx, *pid_ctx, info);
	if (!*pid_ctx || !(*pid_ctx)->elf_ctx_list)
		return ret;

	memset(elf_item, 0, sizeof(*elf_item));
	return gu_interval_array_search((*pid_ctx)->elf_ctx_list, pc, elf_item);
}

struct gu_context *gu_init(const struct gu_init_cfg *cfg)
{
	if (elf_version(EV_CURRENT) == EV_NONE) {
		GU_ERROR("ELF library initialization failed: %s", elf_errmsg(-1));
		return NULL;
	}
	struct gu_context *ctx = malloc(sizeof(*ctx));
	if (!ctx)
		return NULL;
	memset(ctx, 0, sizeof(*ctx));

	ctx->debug = cfg->debug_print;
	ctx->go_only_buildid = cfg->go_buildid_only;
	ctx->go_not_strip_name = cfg->go_not_strip_name;

	ctx->kernel_symbols = NULL;
	gu_retire_timer_start(ctx);
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

void gu_cleanup(struct gu_context *ctx)
{
	if (!ctx)
		return;

	gu_retire_timer_stop(ctx);

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

	free(ctx);
}

void gu_set_pid_private_info(struct gu_context *ctx, int pid, void *private, int size)
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

void *gu_get_pid_private_info(struct gu_context *ctx, int pid, int *size)
{
	struct per_pid_ctx *pid_ctx = NULL;

	HASH_FIND_INT(ctx->pid_ctx_list, &pid, pid_ctx);

	if (pid_ctx && pid_ctx->private && pid_ctx->private_size > 0) {
		/* Return a copy so caller-owned metadata cannot mutate the cache. */
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

static uint64_t gu_get_pid_unique_id(struct gu_context *ctx, int pid)
{
	struct per_pid_ctx *pid_ctx = NULL;
	char stat_path[64];
	char stat_buf[4096];
	char *cur = NULL;
	FILE *fp = NULL;
	uint64_t start_time = 0;

	if (!ctx || pid <= 0)
		return 0;
	HASH_FIND_INT(ctx->pid_ctx_list, &pid, pid_ctx);
	if (pid_ctx && pid_ctx->unique_id != 0)
		return pid_ctx->unique_id;

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

int gu_event_occur(struct gu_context *ctx, enum gu_event_type type, void *event_data)
{
	gu_maybe_sweep_retired_elf(ctx);

	switch (type) {
	case GU_EVENT_PROCESS_EXIT:
		if (event_data) {
			int pid = *((int *)event_data);
			gu_set_pid_exit_unique(ctx, pid, 0);
		}
		break;
	case GU_EVENT_MODULE_RELOAD:
		gu_load_kernel_symbols(ctx);
	default:
		break;
	}
	return 0;
}

uint64_t gu_preload_pid_debug_info(struct gu_context *ctx, int pid)
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

		HASH_ADD_INT(ctx->pid_ctx_list, pid, pid_ctx);
		ctx->statistics.pid_ctx_count++;
		gu_pid_ctx_event_notify_pid_ctx(pid_ctx->pid, (unsigned long long)pid_ctx->unique_id, pid_ctx->comm, GU_PID_CTX_EVENT_CREATE);
	}

end:

	return pid_ctx ? pid_ctx->unique_id : 0;
}

static pthread_mutex_t kernel_symbols_mutex = PTHREAD_MUTEX_INITIALIZER;
static int g_ksym_items_count = 0;

int gu_load_kernel_symbols(struct gu_context *ctx)
{
	FILE *f = fopen("/proc/kallsyms", "r");
	if (!f)
		return -1;

	char *line = NULL;
	size_t len = 0;
	ssize_t read;

	int items_cap;
	if (g_ksym_items_count == 0) {
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
	} else {
		items_cap = g_ksym_items_count;
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
					temp_kernel_symbols_mem += strlen(name) + 1;
					struct kernel_symbol_entry *entry = malloc(sizeof(struct kernel_symbol_entry));
					if (entry) {
						entry->name = items[i].private;
						entry->addr = addr;
						HASH_ADD_KEYPTR(hh, new_hash, entry->name, strlen(entry->name), entry);
					}
				}
				i++;
			}
		}
	}
	free(line);
	fclose(f);

	g_ksym_items_count = items_cap;

	struct interval_array *new_array = gu_interval_array_init(items, i);
	struct interval_array *old_array = ctx->kernel_symbols;
	struct kernel_symbol_entry *old_hash = ctx->kernel_symbol_hash;

	if (!new_array) {
		for (int j = 0; j < i; j++)
			free(items[j].private);
		free(items);
		gu_kernel_symbol_hash_destroy(new_hash);
		return -1;
	}

	pthread_mutex_lock(&kernel_symbols_mutex);
	ctx->statistics.kernel_symbols_mem_size = temp_kernel_symbols_mem;
	ctx->kernel_symbols = new_array;
	ctx->kernel_symbol_hash = new_hash;
	pthread_mutex_unlock(&kernel_symbols_mutex);

	if (old_array)
		gu_interval_array_destroy(old_array);

	gu_kernel_symbol_hash_destroy(old_hash);

	free(items);

	return 0;
}

int gu_search_kernel_symbol(struct gu_context *ctx, uint64_t addr, char *buf, size_t len, uint64_t *offset)
{
	pthread_mutex_lock(&kernel_symbols_mutex);
	if (!ctx->kernel_symbols) {
		pthread_mutex_unlock(&kernel_symbols_mutex);
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

	pthread_mutex_unlock(&kernel_symbols_mutex);

	return result >= 0 ? 0 : -1;
}

uint64_t gu_search_kernel_address(struct gu_context *ctx, const char *name)
{
	pthread_mutex_lock(&kernel_symbols_mutex);
	if (!ctx->kernel_symbol_hash) {
		pthread_mutex_unlock(&kernel_symbols_mutex);
		return 0;
	}

	struct kernel_symbol_entry *entry;
	HASH_FIND_STR(ctx->kernel_symbol_hash, name, entry);

	pthread_mutex_unlock(&kernel_symbols_mutex);

	return entry ? entry->addr : 0;
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

static unsigned long gu_cfi_lookup_pc_for_frame(unsigned long pc,
						bool initial_frame,
						bool signal_frame)
{
	if (initial_frame || signal_frame || pc == 0)
		return pc;
	return pc - 1;
}

static bool gu_stack_snapshot_read_u64(struct gu_stack_info *info,
				       uint64_t raw_sp, uint64_t addr,
				       uint64_t *val)
{
	uint64_t stack_page_size;
	uint64_t stack_start;
	uint64_t stack_end;

	if (!info || !info->stack_data || !val)
		return false;

	stack_page_size = getpagesize();
	stack_start = raw_sp - (raw_sp % stack_page_size);
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
			       struct interval_array_item *elf_item,
			       bool *maps_reloaded,
			       gu_frame_callback_t callback, void *user_ctx,
			       bool *end_of_stack)
{
	struct gu_frame_record *stack_frame = &ctx->frame_record;
	struct interval_array_item sym_item = { .private = NULL };
	struct per_elf_ctx *elf_ctx = NULL;
	unsigned long map_exec_virt_addr = 0;
	unsigned long bias;
	unsigned long relative_pc;
	int ret;

	if (!callback || pc == 0)
		return false;

	if (!(elf_item->private != NULL && pc >= elf_item->start &&
	      pc < elf_item->end)) {
		memset(elf_item, 0, sizeof(*elf_item));
		ret = gu_search_pid_elf_ctx(ctx, pid_ctx, info, pc, elf_item,
					    maps_reloaded);
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

	stack_frame->elf_info = (struct gu_elf_info *)elf_ctx;
	stack_frame->pc = relative_pc;
	stack_frame->abs_pc = pc;
	if (elf_ctx->symbols) {
		ret = gu_interval_array_search(elf_ctx->symbols, relative_pc,
					       &sym_item);
		if (ret >= 0) {
			stack_frame->symbol = (char *)get_interval_array_pointer(
				(uint64_t)sym_item.private, NULL);
			stack_frame->offset = relative_pc - sym_item.start;
		}
	}

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
	    gu_append_pc_frame(ctx, pid_ctx, info, pc, &elf_item,
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
		if (!gu_append_pc_frame(ctx, pid_ctx, info, next_pc, &elf_item,
					&maps_reloaded, callback, user_ctx,
					&end_of_stack))
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
	struct interval_array_item sym_item = { .private = NULL };
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
			ret = gu_search_pid_elf_ctx(ctx, &pid_ctx, info, pc,
						    &elf_item, &maps_reloaded);
			if (ret >= 0) {
				elf_ctx = gu_get_elf_ctx_from_item(
					&elf_item, &map_exec_virt_addr);
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

			if (elf_ctx->symbols) {
				sym_item.private = NULL;
				ret = gu_interval_array_search(elf_ctx->symbols, relative_pc, &sym_item);
				if (ret >= 0) {
					sym = (char *)get_interval_array_pointer((uint64_t)sym_item.private, NULL);
					func_offset = relative_pc - sym_item.start;
				} else {
					sym = NULL;
					func_offset = 0;
				}
			}

			stack_frame->elf_info = (struct gu_elf_info *)elf_ctx;
			stack_frame->flags = 0;

			if (ctx->go_only_buildid == 0 || elf_ctx->golang == false) {
				stack_frame->pc = relative_pc;
				stack_frame->offset = func_offset;
				stack_frame->symbol = sym;
			} else {
				stack_frame->pc = relative_pc - func_offset;
				stack_frame->offset = 0;
				stack_frame->symbol = NULL;
			}

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

int gu_unwind(struct gu_context *ctx, struct gu_stack_info *info, gu_frame_callback_t callback, void *user_ctx)
{
	enum gu_unwind_reason reason = GU_UNWIND_REASON_UNKNOWN;
	bool fp = gu_flags_is_set(info, GU_FLAG_HINT_SET_FP);

	if (info == NULL)
		return -1;

	if (info->regs == NULL) {
		gu_flags_set_reason(info, GU_UNWIND_REASON_NO_REGS);
		return -1;
	}

	gu_maybe_sweep_retired_elf(ctx);

	struct per_pid_ctx *pid_ctx = NULL;
	struct gu_frame_record *stack_frame = &ctx->frame_record;

	HASH_FIND_INT(ctx->pid_ctx_list, &info->pid, pid_ctx);

	if (info->unique_id != 0 && pid_ctx && pid_ctx->unique_id != info->unique_id && !ctx->debug) {
		GU_VERBOSE("pid unique id: 0x%lx - 0x%lx\n", pid_ctx->unique_id, info->unique_id);
		ctx->statistics.unique_id_caused_reload_count++;
		gu_pid_ctx_event_notify_pid_ctx(pid_ctx->pid, (unsigned long long)pid_ctx->unique_id, pid_ctx->comm, GU_PID_CTX_EVENT_DESTROY);
		gu_clear_pid_ctx(pid_ctx);
		pid_ctx = NULL;
	}

	if (!pid_ctx) {
		if (kill(info->pid, 0) != 0 && !ctx->debug) {
			gu_flags_set_reason(info, GU_UNWIND_REASON_PROCESS_EXIT);
			return -1;
		}

		pid_ctx = gu_load_pid(ctx, info);
		if (!pid_ctx) {
			gu_flags_set_reason(info, GU_UNWIND_REASON_PROCESS_EXIT);
			return -1;
		}

		if (pid_ctx->golang)
			gu_flags_set(info, GU_FLAG_HINT_SET_FP);

		HASH_ADD_INT(ctx->pid_ctx_list, pid, pid_ctx);
		ctx->statistics.pid_ctx_count++;
		gu_pid_ctx_event_notify_pid_ctx(pid_ctx->pid, (unsigned long long)pid_ctx->unique_id, pid_ctx->comm, GU_PID_CTX_EVENT_CREATE);
	}

	if (!pid_ctx->elf_ctx_list) {
		gu_flags_set_reason(info, GU_UNWIND_REASON_NO_ELF);
		return -1;
	}

	/* Frame-pointer unwinding is the preferred path for Go and hinted samples. */
	if (fp)
		return gu_unwind_by_fp(pid_ctx, info, callback, user_ctx);

	struct interval_array_item elf_item = { 0, 0, NULL };
	struct interval_array_item sym_item = { .private = NULL };
	struct per_elf_ctx *elf_ctx = NULL;
	unsigned long map_exec_virt_addr = 0;
	Dwarf_Frame *frame = NULL;
	bool maps_reloaded = false;

	unsigned long pc, sp, raw_sp, relative_pc, func_offset, bias;
	int ret = 0, regno = 0, loop_count = 0;
	bool current_signal_frame = false;
	bool fp_tail_append_current_pc = false;

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

	int max_backtrace_level = 512;

	while (max_backtrace_level--) {
		bool initial_frame = loop_count == 0;

		GU_VERBOSE(TAB_STR "[%d] loop started. pc: 0x%lx sp: 0x%lx", loop_count++, pc, sp);

		if (!(elf_item.private != NULL && pc >= elf_item.start && pc < elf_item.end)) {
			ret = gu_search_pid_elf_ctx(ctx, &pid_ctx, info, pc,
						    &elf_item, &maps_reloaded);
			GU_VERBOSE(DOUBLE_TAB_STR "elf search, ret: %d elf_itme.start: 0x%lx elf_itme.end: 0x%lx", ret, elf_item.start, elf_item.end);
			if (ret < 0) {
				reason = GU_UNWIND_REASON_NO_EXEC_PC;
				break;
			}

			elf_ctx = gu_get_elf_ctx_from_item(
				&elf_item, &map_exec_virt_addr);
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

		GU_VERBOSE(DOUBLE_TAB_STR "pc: 0x%lx relative pc to %s: 0x%lx", pc, elf_ctx->base_name, relative_pc);

		char *sym = NULL;
		uint64_t func_offset = 0;

		if (elf_ctx->symbols) {
			sym_item.private = NULL;
			ret = gu_interval_array_search(elf_ctx->symbols, relative_pc, &sym_item);
			if (ret >= 0) {
				sym = (char *)get_interval_array_pointer((uint64_t)sym_item.private, NULL);
				func_offset = relative_pc - sym_item.start;
			} else {
				sym = NULL;
				func_offset = 0;
			}
		}

		stack_frame->elf_info = (struct gu_elf_info *)elf_ctx;
		stack_frame->flags = 0;

		/*
		 * Go deployments can choose build-ID-only reporting to avoid
		 * exposing full package-qualified symbol names.
		 */
		if (ctx->go_only_buildid == 0 || elf_ctx->golang == false) {
			stack_frame->pc = relative_pc;
			stack_frame->offset = func_offset;
			stack_frame->symbol = sym;
		} else {
			stack_frame->pc = relative_pc - func_offset;
			stack_frame->offset = 0;
			stack_frame->symbol = NULL;
		}

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
					  &unwound_signal_frame);
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

struct gu_statistics *gu_get_statistics(struct gu_context *ctx)
{
	return &ctx->statistics;
}
