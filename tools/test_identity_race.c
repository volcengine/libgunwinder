/* SPDX-License-Identifier: LGPL-3.0-or-later */

/*
 * The instance check of a sample and the maps read it guards are two /proc
 * reads apart: the process may exit and its pid be reused in between.  This
 * test switches the instance /proc shows under this process' pid while its
 * maps are read (gu_get_maps_info and the /proc status and stat files are
 * wrapped: -Wl,--wrap=gu_get_maps_info,--wrap=fopen), on a cold load, a
 * leaf-miss reload and an identity replacement.  The view built then is the
 * new instance's: it must be dropped, and the old one kept, without a frame.
 * Controls: the same schedules without the switch commit the view, a stale
 * sample reads no maps at all, and a cached hit reads nothing.
 */
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../src/gu_stacktrace.c"

#define SAMPLE_ID 100

static uint64_t live_id;	/* the instance /proc shows under the pid */
static bool switch_at_maps;	/* the pid is reused while its maps are read */
static int maps_reads, proc_reads, frames;
static char status_buf[128], stat_buf[512];

FILE *__real_fopen(const char *path, const char *mode);
FILE *__wrap_fopen(const char *path, const char *mode)
{
	char status_path[64], stat_path[64];

	snprintf(status_path, sizeof(status_path), "/proc/%d/status", getpid());
	snprintf(stat_path, sizeof(stat_path), "/proc/%d/stat", getpid());
	if (!strcmp(path, status_path)) {
		proc_reads++;
		snprintf(status_buf, sizeof(status_buf), "Name:\tfixture\nTgid:\t%d\n",
			 getpid());
		return fmemopen(status_buf, strlen(status_buf), "r");
	}
	if (!strcmp(path, stat_path)) {
		size_t n;

		proc_reads++;
		n = snprintf(stat_buf, sizeof(stat_buf), "%d (fixture) S", getpid());
		for (int field = 4; field < 22; field++)
			n += snprintf(stat_buf + n, sizeof(stat_buf) - n, " 0");
		snprintf(stat_buf + n, sizeof(stat_buf) - n, " %llu 0\n",
			 (unsigned long long)live_id);
		return fmemopen(stat_buf, strlen(stat_buf), "r");
	}
	return __real_fopen(path, mode);
}

struct maps_info *__real_gu_get_maps_info(int pid, int *count, char perm,
					  char *debug_maps);
struct maps_info *__wrap_gu_get_maps_info(int pid, int *count, char perm,
					  char *debug_maps)
{
	maps_reads++;
	if (switch_at_maps)
		live_id = SAMPLE_ID + 1;
	return __real_gu_get_maps_info(pid, count, perm, debug_maps);
}

static __attribute__((noinline, used)) void probe_text(void)
{
	asm volatile("");
}

static void count_frames(const struct gu_frame_record *frame, void *arg)
{
	(void)arg;
	if (frame->elf_info)
		frames++;
}

static int unwind(struct gu_context *ctx, uint64_t pc)
{
	struct gu_stack_info info;
	uint64_t regs[64] = { 0 };

	memset(&info, 0, sizeof(info));
	info.pid = getpid();
	info.unique_id = SAMPLE_ID;
	info.regs = regs;
	info.regs_size = sizeof(regs);
	info.ustack_fp[0] = pc;
	info.ustack_fp_level = 1;
	gu_flags_set(&info, GU_FLAG_HINT_SET_FP);
	frames = 0;
	(void)gu_unwind(ctx, &info, count_frames, NULL);
	return gu_flags_reason(info.flags);
}

/* A view of @id cached under the pid, that resolves nothing, reload allowed. */
static struct per_pid_ctx *cache(struct gu_context *ctx, uint64_t id)
{
	struct interval_array_item empty = { .start = 0x1000, .end = 0x2000 };
	struct per_pid_ctx *p = calloc(1, sizeof(*p));

	p->gu_ctx = ctx;
	p->pid = getpid();
	p->unique_id = id;
	p->elf_ctx_list = gu_interval_array_init(&empty, 1);
	p->next_maps_reload_ns = 1;
	gu_add_pid_ctx(ctx, p);
	return p;
}

enum schedule { NO_SWITCH, SWITCH_AT_MAPS, STALE };
enum start { COLD, CACHED_SAME, CACHED_OTHER };

static int failures;

static void run(enum start start, enum schedule schedule)
{
	static const char *const starts[] = { "cold load", "leaf-miss reload",
					      "identity replacement" };
	static const char *const schedules[] = { "no reuse", "reuse while maps are read",
						 "reused before the check" };
	uint64_t pc = (uint64_t)(uintptr_t)&probe_text;
	struct gu_init_cfg cfg = { .no_kernel_symbols = true };
	struct gu_context *ctx = gu_init(&cfg);
	struct per_pid_ctx *old = NULL, *now = NULL;
	struct interval_array *old_list = NULL;
	struct interval_array_item hit;
	int pid = getpid(), reason, reads;
	bool attached, ok;

	maps_reads = proc_reads = 0;
	live_id = schedule == STALE ? SAMPLE_ID + 1 : SAMPLE_ID;
	switch_at_maps = schedule == SWITCH_AT_MAPS;
	if (start != COLD) {
		old = cache(ctx, start == CACHED_SAME ? SAMPLE_ID : SAMPLE_ID - 1);
		old_list = old->elf_ctx_list;
	}
	reason = unwind(ctx, pc);
	switch_at_maps = false;
	HASH_FIND_INT(ctx->pid_ctx_list, &pid, now);
	attached = now && gu_interval_array_search(now->elf_ctx_list, pc, &hit) >= 0;
	reads = maps_reads;

	if (schedule == NO_SWITCH) {
		ok = attached && frames > 0 && now->unique_id == SAMPLE_ID &&
		     reads == 1;
		if (ok && start == COLD) {
			/* a cached hit reads nothing from /proc */
			maps_reads = proc_reads = 0;
			unwind(ctx, pc);
			ok = frames > 0 && !maps_reads && !proc_reads;
		}
	} else {
		/*
		 * Nothing of the other instance, the old view as it was. (A
		 * refused reload leaves the walk to report the miss itself.)
		 */
		ok = !attached && !frames &&
		     (start == CACHED_SAME || reason == GU_UNWIND_REASON_PROCESS_EXIT) &&
		     now == old && (!old || old->elf_ctx_list == old_list) &&
		     reads == (schedule == SWITCH_AT_MAPS);
	}
	printf("%s %s, %s: maps_reads=%d attached=%d frames=%d reason=%d\n",
	       ok ? "PASS" : "FAIL", starts[start], schedules[schedule],
	       reads, attached, frames, reason);
	failures += !ok;
	gu_cleanup(ctx);
}

int main(void)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	for (int start = COLD; start <= CACHED_OTHER; start++)
		for (int schedule = NO_SWITCH; schedule <= STALE; schedule++)
			run(start, schedule);
	printf("failures=%d\n", failures);
	return failures ? 1 : 0;
}
