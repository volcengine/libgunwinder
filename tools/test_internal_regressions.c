/* SPDX-License-Identifier: LGPL-3.0-or-later */

#define _GNU_SOURCE

#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../src/gu_stacktrace.c"
#include "test_elf_symbol.h"

#define FAIL(...) do { \
	fprintf(stderr, __VA_ARGS__); \
	fprintf(stderr, "\n"); \
	return 1; \
} while (0)

static int file_has_elf_magic(const char *path)
{
	unsigned char magic[4];
	FILE *file = fopen(path, "rb");

	if (!file)
		return 0;
	if (fread(magic, 1, sizeof(magic), file) != sizeof(magic)) {
		fclose(file);
		return 0;
	}
	fclose(file);

	return magic[0] == 0x7f && magic[1] == 'E' &&
	       magic[2] == 'L' && magic[3] == 'F';
}

static int make_work_dir(char *buf, size_t len, const char *prefix)
{
	if (snprintf(buf, len, ".test-%s-XXXXXX", prefix) >= (int)len)
		return -1;
	if (!mkdtemp(buf))
		return -1;
	return 0;
}

static void remove_work_dir(const char *path)
{
	char child[PATH_MAX];
	DIR *dir;
	struct dirent *entry;

	if (!path || path[0] == '\0')
		return;

	dir = opendir(path);
	if (dir) {
		while ((entry = readdir(dir)) != NULL) {
			if (strcmp(entry->d_name, ".") == 0 ||
			    strcmp(entry->d_name, "..") == 0)
				continue;
			snprintf(child, sizeof(child), "%s/%s", path,
				 entry->d_name);
			unlink(child);
		}
		closedir(dir);
	}
	rmdir(path);
}

static int case_vdso(void)
{
	struct gu_init_cfg cfg = { 0 };
	struct gu_context *ctx;
	struct per_elf_ctx *elf_ctx;
	const char *vdso_path;
	FILE *stale;
	char dump_dir[PATH_MAX];
	char debug_vdso[PATH_MAX];
	struct gu_stack_info info;
	struct pt_regs regs;
	uint8_t stack_byte = 0;
	int ret = 1;

	ctx = gu_init(&cfg);
	if (!ctx)
		FAIL("gu_init failed");

	vdso_path = get_vdso_dump_path(ctx);
	stale = fopen(vdso_path, "wb");
	if (!stale) {
		fprintf(stderr, "failed to create stale vdso file %s: %s\n",
			vdso_path, strerror(errno));
		goto out;
	}
	fputs("not an elf", stale);
	fclose(stale);

	elf_ctx = load_elf(ctx, "[vdso]", getpid(), NULL);
	if (!elf_ctx) {
		fprintf(stderr, "load_elf([vdso]) failed\n");
		goto out;
	}
	if (!ctx->vdso_dumped) {
		fprintf(stderr, "load_elf did not mark vDSO dumped\n");
		goto out;
	}
	if (strcmp(elf_ctx->elf_file_path, vdso_path) != 0) {
		fprintf(stderr, "vDSO path was not local: %s != %s\n",
			elf_ctx->elf_file_path, vdso_path);
		goto out;
	}
	if (strncmp(elf_ctx->elf_file_path, "/proc/", 6) == 0) {
		fprintf(stderr, "vDSO path was incorrectly proc-root prefixed: %s\n",
			elf_ctx->elf_file_path);
		goto out;
	}
	if (!file_has_elf_magic(vdso_path)) {
		fprintf(stderr, "vDSO dump is missing ELF magic: %s\n", vdso_path);
		goto out;
	}

	if (make_work_dir(dump_dir, sizeof(dump_dir), "vdso-dump") != 0) {
		fprintf(stderr, "mkdtemp failed: %s\n", strerror(errno));
		goto out;
	}
	snprintf(debug_vdso, sizeof(debug_vdso), "%s/__vdso.so", dump_dir);
	memset(&info, 0, sizeof(info));
	memset(&regs, 0, sizeof(regs));
	info.pid = getpid();
	info.regs = &regs;
	info.regs_size = sizeof(regs);
	info.stack_data = &stack_byte;
	info.stack_size = sizeof(stack_byte);
	gu_debug_dump_sample(&info, dump_dir, true);
	if (!file_has_elf_magic(debug_vdso)) {
		fprintf(stderr, "debug vDSO dump is missing ELF magic: %s\n",
			debug_vdso);
		remove_work_dir(dump_dir);
		goto out;
	}
	remove_work_dir(dump_dir);

	puts("vdso fresh local dump ok");
	ret = 0;

out:
	gu_cleanup(ctx);
	return ret;
}

static int case_retire(void)
{
	struct gu_init_cfg cfg = { 0 };
	struct gu_context *ctx;
	struct gu_statistics *stats;
	struct per_elf_ctx *first;
	struct per_elf_ctx *again;
	int ret = 1;

	ctx = gu_init(&cfg);
	if (!ctx)
		FAIL("gu_init failed");
	ctx->debug = true;

	first = load_elf(ctx, "/proc/self/exe", getpid(), NULL);
	if (!first) {
		fprintf(stderr, "initial self ELF load failed\n");
		goto out;
	}
	if (first->refcnt != 1 || first->retired) {
		fprintf(stderr, "unexpected initial refcnt/retired state\n");
		goto out;
	}
	stats = gu_get_statistics(ctx);
	if (!stats || stats->elf_ctx_count != 1) {
		fprintf(stderr, "expected one active ELF context\n");
		goto out;
	}

	gu_put_elf_ctx(first);
	if (!first->retired || first->refcnt != 0 || first->retire_deadline_ns == 0) {
		fprintf(stderr, "ELF context did not enter retired cache\n");
		goto out;
	}
	if (stats->elf_ctx_count != 0 || stats->retired_elf_ctx_count != 1) {
		fprintf(stderr, "unexpected retire statistics: active=%llu retired=%llu\n",
			(unsigned long long)stats->elf_ctx_count,
			(unsigned long long)stats->retired_elf_ctx_count);
		goto out;
	}

	again = load_elf(ctx, "/proc/self/exe", getpid(), NULL);
	if (again != first) {
		fprintf(stderr, "retired ELF cache was not reused\n");
		goto out;
	}
	if (again->retired || again->refcnt != 1) {
		fprintf(stderr, "reused ELF was not unretired correctly\n");
		goto out;
	}
	if (stats->retired_elf_cache_hit != 1 || stats->elf_ctx_count != 1 ||
	    stats->retired_elf_ctx_count != 0) {
		fprintf(stderr, "unexpected retired-cache-hit statistics\n");
		goto out;
	}

	gu_put_elf_ctx(again);
	gu_retired_elf_sweep(ctx, UINT64_MAX);
	if (stats->retired_elf_ctx_count != 0 || stats->elf_ctx_count != 0 ||
	    stats->retired_elf_expired != 1) {
		fprintf(stderr, "retired ELF was not swept after forced deadline\n");
		goto out;
	}

	puts("retired elf cache lifecycle ok");
	ret = 0;

out:
	gu_cleanup(ctx);
	return ret;
}

static int case_maps_reload(void)
{
	struct gu_init_cfg cfg = { 0 };
	struct gu_context *ctx;
	struct per_pid_ctx pid_ctx = { 0 };
	uint64_t delays[16];
	size_t unique = 0;
	int ret = 1;

	ctx = gu_init(&cfg);
	if (!ctx)
		FAIL("gu_init failed");

	pid_ctx.gu_ctx = ctx;
	pid_ctx.pid = 4242;
	pid_ctx.unique_id = 0x1234;

	for (size_t i = 0; i < sizeof(delays) / sizeof(delays[0]); i++) {
		pid_ctx.pid = 4242 + (int)i;
		pid_ctx.unique_id = 0x1234 + i * 17;
		pid_ctx.last_maps_load_ns = 0;
		pid_ctx.next_maps_reload_ns = 0;
		pid_ctx.maps_reload_rand_state = 0;
		gu_schedule_next_maps_reload(ctx, &pid_ctx);
		if (pid_ctx.next_maps_reload_ns <= pid_ctx.last_maps_load_ns) {
			fprintf(stderr, "next reload deadline did not advance\n");
			goto out;
		}
		delays[i] = pid_ctx.next_maps_reload_ns - pid_ctx.last_maps_load_ns;
		if (delays[i] < GU_PID_MAPS_RELOAD_MIN_INTERVAL_NS ||
		    delays[i] > GU_PID_MAPS_RELOAD_MAX_INTERVAL_NS) {
			fprintf(stderr, "maps reload delay out of range: %llu\n",
				(unsigned long long)delays[i]);
			goto out;
		}
		if (i == 0 || delays[i] != delays[0])
			unique++;
	}
	if (unique < 2) {
		fprintf(stderr, "maps reload jitter did not vary across pids\n");
		goto out;
	}

	pid_ctx.pid = 9999;
	pid_ctx.unique_id = 0xbeef;
	pid_ctx.last_maps_load_ns = 0;
	pid_ctx.next_maps_reload_ns = 0;
	pid_ctx.maps_reload_rand_state = 0;
	gu_schedule_next_maps_reload(ctx, &pid_ctx);
	if (gu_maps_reload_allowed(ctx, &pid_ctx, 0xdeadbeef)) {
		fprintf(stderr, "maps reload was allowed before next deadline\n");
		goto out;
	}
	if (ctx->statistics.pid_maps_reload_throttle_count != 1) {
		fprintf(stderr, "maps reload throttle statistic was not updated\n");
		goto out;
	}
	pid_ctx.next_maps_reload_ns = 1;
	if (!gu_maps_reload_allowed(ctx, &pid_ctx, 0xdeadbeef)) {
		fprintf(stderr, "maps reload was not allowed after deadline\n");
		goto out;
	}

	puts("maps reload jitter ok");
	ret = 0;

out:
	gu_cleanup(ctx);
	return ret;
}

static int reload_destroy_events;
static int reload_create_events;

static void count_pid_ctx_events(const struct gu_pid_ctx_event *e, void *cb_ctx)
{
	(void)cb_ctx;
	if (e->type == GU_PID_CTX_EVENT_DESTROY)
		reload_destroy_events++;
	else if (e->type == GU_PID_CTX_EVENT_CREATE)
		reload_create_events++;
}

/*
 * A maps refresh of a live process keeps its identity: the same pid ctx and
 * its private data, and no DESTROY event (which would make listeners drop
 * what they keep for it); each refresh is told as a CREATE.
 */
static int case_reload_in_place(void)
{
	struct gu_init_cfg cfg = { 0 };
	struct gu_stack_info info;
	struct gu_context *ctx;
	struct per_pid_ctx *pid_ctx, *reloaded;
	struct interval_array *old_list;
	uint64_t alloc_before;
	void *marker;
	int ret = 1;

	ctx = gu_init(&cfg);
	if (!ctx)
		FAIL("gu_init failed");
	if (gu_register_pid_ctx_event_listener(count_pid_ctx_events, NULL) != 0) {
		fprintf(stderr, "listener registration failed\n");
		goto out;
	}

	memset(&info, 0, sizeof(info));
	info.pid = getpid();
	info.unique_id = gu_read_pid_start_ticks(info.pid);
	pid_ctx = gu_load_pid(ctx, &info);
	if (!pid_ctx || !pid_ctx->elf_ctx_list) {
		fprintf(stderr, "initial pid load failed\n");
		goto out;
	}
	HASH_ADD_INT(ctx->pid_ctx_list, pid, pid_ctx);
	marker = malloc(8);
	pid_ctx->private = marker;
	pid_ctx->private_size = 8;
	alloc_before = ctx->statistics.pid_ctx_alloc_count;
	old_list = pid_ctx->elf_ctx_list;

	reloaded = gu_reload_pid_ctx(ctx, pid_ctx, &info);
	if (reloaded != pid_ctx || pid_ctx->private != marker ||
	    !pid_ctx->elf_ctx_list || pid_ctx->elf_ctx_list == old_list ||
	    ctx->statistics.pid_ctx_alloc_count != alloc_before) {
		fprintf(stderr, "reload replaced the pid ctx instead of refreshing it\n");
		goto out;
	}
	if (reload_destroy_events != 0 || reload_create_events != 1) {
		fprintf(stderr, "unexpected events: destroy=%d create=%d\n",
			reload_destroy_events, reload_create_events);
		goto out;
	}

	reloaded = gu_reload_pid_ctx(ctx, pid_ctx, &info);
	if (reloaded != pid_ctx || pid_ctx->private != marker ||
	    reload_destroy_events != 0 || reload_create_events != 2) {
		fprintf(stderr, "second reload: destroy=%d create=%d\n",
			reload_destroy_events, reload_create_events);
		goto out;
	}

	puts("maps reload in place ok");
	ret = 0;

out:
	gu_unregister_pid_ctx_event_listener(count_pid_ctx_events, NULL);
	gu_cleanup(ctx);
	return ret;
}

static __attribute__((noinline, used)) void identity_probe_text(void)
{
	asm volatile("");
}

static int identity_frames;

static void count_identity_frames(const struct gu_frame_record *frame, void *arg)
{
	(void)arg;
	if (frame->elf_info)
		identity_frames++;
}

/* One leaf of @pid (sampled in its thread @tid), by frame pointer. */
static int identity_unwind_task(struct gu_context *ctx, int pid, int tid,
				uint64_t unique_id, uint64_t pc)
{
	struct gu_stack_info info;
	uint64_t regs[64] = { 0 };

	memset(&info, 0, sizeof(info));
	info.pid = pid;
	info.tid = tid;
	info.unique_id = unique_id;
	info.regs = regs;
	info.regs_size = sizeof(regs);
	info.ustack_fp[0] = pc;
	info.ustack_fp_level = 1;
	gu_flags_set(&info, GU_FLAG_HINT_SET_FP);
	identity_frames = 0;
	(void)gu_unwind(ctx, &info, count_identity_frames, NULL);
	return gu_flags_reason(info.flags);
}

/* One leaf of @pid, by frame pointer: the leaf-miss reload path. */
static int identity_unwind_pid(struct gu_context *ctx, int pid,
			       uint64_t unique_id, uint64_t pc)
{
	return identity_unwind_task(ctx, pid, 0, unique_id, pc);
}

static int identity_unwind(struct gu_context *ctx, uint64_t unique_id, uint64_t pc)
{
	return identity_unwind_pid(ctx, getpid(), unique_id, pc);
}

/*
 * A sample of an instance that is gone must not be unwound against the
 * mappings of the process now running under its pid, nor replace that
 * process' view.  This process plays the new instance; a start time one
 * tick earlier plays the old one.
 */
static int case_identity_reuse(void)
{
	struct gu_init_cfg cfg = { 0 };
	struct interval_array_item empty = { .start = 0x1000, .end = 0x2000 };
	uint64_t pc = (uint64_t)(uintptr_t)&identity_probe_text;
	struct per_pid_ctx *old, *cur = NULL;
	struct interval_array_item hit;
	struct gu_context *ctx;
	uint64_t live, reloads;
	int pid = getpid(), reason, ret = 1;

	ctx = gu_init(&cfg);
	if (!ctx)
		FAIL("gu_init failed");
	live = gu_read_pid_start_ticks(pid);
	if (live < 2)
		FAIL("cannot read this process' start time");

	/* 1. cold load for an old instance: refused, nothing cached */
	reason = identity_unwind(ctx, live - 1, pc);
	HASH_FIND_INT(ctx->pid_ctx_list, &pid, cur);
	if (cur || identity_frames || reason != GU_UNWIND_REASON_PROCESS_EXIT) {
		fprintf(stderr, "old instance cold-loaded the live view: ctx=%p frames=%d reason=%d\n",
			(void *)cur, identity_frames, reason);
		goto out;
	}

	/*
	 * 2. the old instance's cached view misses: no reload from the live
	 * maps (the walk then reports the miss itself, so no reason is checked)
	 */
	old = calloc(1, sizeof(*old));
	old->gu_ctx = ctx;
	old->pid = pid;
	old->unique_id = live - 1;
	old->elf_ctx_list = gu_interval_array_init(&empty, 1);
	old->next_maps_reload_ns = 1;	/* a reload would be allowed */
	gu_add_pid_ctx(ctx, old);
	reloads = ctx->statistics.pid_maps_reload_count;
	reason = identity_unwind(ctx, live - 1, pc);
	HASH_FIND_INT(ctx->pid_ctx_list, &pid, cur);
	if (cur != old || old->unique_id != live - 1 || identity_frames ||
	    ctx->statistics.pid_maps_reload_count != reloads ||
	    gu_interval_array_search(old->elf_ctx_list, pc, &hit) >= 0) {
		fprintf(stderr, "old instance reloaded the live view: frames=%d reloads=%llu reason=%d\n",
			identity_frames,
			(unsigned long long)(ctx->statistics.pid_maps_reload_count - reloads),
			reason);
		goto out;
	}

	/* 3. the live instance's own sample replaces the stale view and resolves */
	reason = identity_unwind(ctx, live, pc);
	HASH_FIND_INT(ctx->pid_ctx_list, &pid, cur);
	if (!cur || cur->unique_id != live || identity_frames < 1) {
		fprintf(stderr, "live instance did not load its own view: frames=%d reason=%d\n",
			identity_frames, reason);
		goto out;
	}

	/* 4. a late sample of the old instance leaves the live view alone */
	old = cur;
	reason = identity_unwind(ctx, live - 1, pc);
	HASH_FIND_INT(ctx->pid_ctx_list, &pid, cur);
	if (cur != old || cur->unique_id != live || identity_frames ||
	    reason != GU_UNWIND_REASON_PROCESS_EXIT) {
		fprintf(stderr, "old sample replaced or used the live view: frames=%d reason=%d\n",
			identity_frames, reason);
		goto out;
	}

	puts("instance identity on reuse ok");
	ret = 0;
out:
	gu_cleanup(ctx);
	return ret;
}

static int identity_thread_pipe[2];
static int identity_thread_tid;

static void *identity_thread_main(void *arg)
{
	char c;

	(void)arg;
	__atomic_store_n(&identity_thread_tid, (int)syscall(SYS_gettid),
			 __ATOMIC_RELEASE);
	while (read(identity_thread_pipe[0], &c, 1) < 0 && errno == EINTR)
		;
	return NULL;
}

/*
 * Off-CPU samples carry a thread's id as the pid and the group leader's
 * start time as the identity: a live thread of this very process must be
 * loaded and reloaded, not refused as another instance because the thread
 * itself started later than its leader.
 */
static int case_identity_thread(void)
{
	struct gu_init_cfg cfg = { 0 };
	uint64_t pc = (uint64_t)(uintptr_t)&identity_probe_text;
	struct per_pid_ctx *cur = NULL;
	struct gu_context *ctx = NULL;
	uint64_t leader, reloads;
	pthread_t thread;
	int tid = 0, reason, ret = 1;

	leader = gu_read_pid_start_ticks(getpid());
	/* a few ticks later, so the thread's own start time differs */
	usleep(50 * 1000);
	if (pipe(identity_thread_pipe) ||
	    pthread_create(&thread, NULL, identity_thread_main, NULL))
		FAIL("cannot start the thread");
	while (!(tid = __atomic_load_n(&identity_thread_tid, __ATOMIC_ACQUIRE)))
		usleep(1000);
	if (leader == 0 || gu_read_pid_start_ticks(tid) == leader) {
		fprintf(stderr, "thread start time not distinct: leader=%llu\n",
			(unsigned long long)leader);
		goto out;
	}
	ctx = gu_init(&cfg);
	if (!ctx) {
		fprintf(stderr, "gu_init failed\n");
		goto out;
	}

	/* 1. cold load keyed by the thread id */
	reason = identity_unwind_pid(ctx, tid, leader, pc);
	HASH_FIND_INT(ctx->pid_ctx_list, &tid, cur);
	if (!cur || identity_frames < 1) {
		fprintf(stderr, "live thread refused on cold load: ctx=%p frames=%d reason=%d\n",
			(void *)cur, identity_frames, reason);
		goto out;
	}

	/* 2. its leaf miss (a PC in no mapping) reloads the maps */
	cur->next_maps_reload_ns = 1;
	reloads = ctx->statistics.pid_maps_reload_count;
	reason = identity_unwind_pid(ctx, tid, leader, 0x1008);
	if (ctx->statistics.pid_maps_reload_count == reloads) {
		fprintf(stderr, "live thread refused on reload: frames=%d reason=%d\n",
			identity_frames, reason);
		goto out;
	}

	puts("thread of the live instance ok");
	ret = 0;
out:
	if (ctx)
		gu_cleanup(ctx);
	if (tid) {
		(void)!write(identity_thread_pipe[1], "x", 1);
		pthread_join(thread, NULL);
	}
	return ret;
}

static int zombie_leader_pipe[2], zombie_hold_pipe[2];

static void *zombie_worker_main(void *arg)
{
	int tid = (int)syscall(SYS_gettid);
	char c;

	(void)arg;
	(void)!write(zombie_leader_pipe[1], &tid, sizeof(tid));
	while (read(zombie_hold_pipe[0], &c, 1) < 0 && errno == EINTR)
		;
	return NULL;
}

/* The state of @pid ('Z' for a zombie), 0 when it is gone. */
static char pid_state(int pid)
{
	char state = 0;

	gu_read_pid_stat(pid, &state);
	return state;
}

/*
 * A process whose leader called pthread_exit() lives on in its other
 * threads.  /proc/<pid> of the zombie leader has no mapping left, the
 * thread's /proc does: a sample of the thread loads, reloads and replaces
 * the process' view through it, under the process' pid and identity.
 */
static int case_identity_zombie_leader(void)
{
	struct gu_init_cfg cfg = { 0 };
	uint64_t pc = (uint64_t)(uintptr_t)&identity_probe_text;
	struct interval_array_item empty = { .start = 0x1000, .end = 0x2000 };
	struct per_pid_ctx *cur = NULL, *stale;
	struct gu_context *ctx = NULL;
	struct maps_info *maps;
	uint64_t identity, reloads;
	int child, tid = 0, count = 0, reason, ret = 1;

	if (pipe(zombie_leader_pipe) || pipe(zombie_hold_pipe))
		FAIL("pipe failed");
	child = fork();
	if (child < 0)
		FAIL("fork failed");
	if (child == 0) {
		pthread_t thread;

		if (pthread_create(&thread, NULL, zombie_worker_main, NULL))
			_exit(1);
		pthread_exit(NULL);	/* the leader goes first */
	}
	if (read(zombie_leader_pipe[0], &tid, sizeof(tid)) != sizeof(tid)) {
		fprintf(stderr, "no worker thread\n");
		goto out;
	}
	for (int i = 0; i < 500 && pid_state(child) != 'Z'; i++)
		usleep(10 * 1000);
	maps = gu_get_maps_info(child, &count, PERMISSION_X, NULL);
	if (maps)
		gu_free_maps_info(maps, count);
	identity = gu_read_pid_start_ticks(child);
	if (pid_state(child) != 'Z' || count != 0 || !identity) {
		fprintf(stderr, "leader not a zombie without mappings: state=%c maps=%d\n",
			pid_state(child), count);
		goto out;
	}
	ctx = gu_init(&cfg);
	if (!ctx) {
		fprintf(stderr, "gu_init failed\n");
		goto out;
	}

	/* 1. without the thread: the leader's /proc has nothing to load */
	reason = identity_unwind_task(ctx, child, 0, identity, pc);
	HASH_FIND_INT(ctx->pid_ctx_list, &child, cur);
	if (cur || identity_frames || reason != GU_UNWIND_REASON_PROCESS_EXIT) {
		fprintf(stderr, "zombie leader loaded: ctx=%p frames=%d reason=%d\n",
			(void *)cur, identity_frames, reason);
		goto out;
	}

	/* 2. the thread's sample cold-loads the process' view */
	reason = identity_unwind_task(ctx, child, tid, identity, pc);
	HASH_FIND_INT(ctx->pid_ctx_list, &child, cur);
	if (!cur || cur->unique_id != identity || identity_frames < 1) {
		fprintf(stderr, "thread of a zombie leader not loaded: ctx=%p frames=%d reason=%d\n",
			(void *)cur, identity_frames, reason);
		goto out;
	}

	/* 3. its leaf miss reloads through the thread */
	cur->next_maps_reload_ns = 1;
	reloads = ctx->statistics.pid_maps_reload_count;
	reason = identity_unwind_task(ctx, child, tid, identity, 0x1008);
	if (ctx->statistics.pid_maps_reload_count == reloads ||
	    reason == GU_UNWIND_REASON_PROCESS_EXIT) {
		fprintf(stderr, "thread of a zombie leader not reloaded: reason=%d\n",
			reason);
		goto out;
	}

	/* 4. and replaces a stale instance's view */
	gu_clear_pid_ctx(cur);
	stale = calloc(1, sizeof(*stale));
	stale->gu_ctx = ctx;
	stale->pid = child;
	stale->unique_id = identity - 1;
	stale->elf_ctx_list = gu_interval_array_init(&empty, 1);
	gu_add_pid_ctx(ctx, stale);
	reason = identity_unwind_task(ctx, child, tid, identity, pc);
	HASH_FIND_INT(ctx->pid_ctx_list, &child, cur);
	if (!cur || cur->unique_id != identity || identity_frames < 1) {
		fprintf(stderr, "thread of a zombie leader did not replace a stale view: frames=%d reason=%d\n",
			identity_frames, reason);
		goto out;
	}

	puts("thread of a zombie leader ok");
	ret = 0;
out:
	if (ctx)
		gu_cleanup(ctx);
	kill(child, SIGKILL);
	waitpid(child, NULL, 0);
	return ret;
}

static bool copy_file(const char *from, const char *to)
{
	char buf[65536];
	FILE *in = fopen(from, "rb"), *out = fopen(to, "wb");
	size_t n;
	bool ok = in && out;

	while (ok && (n = fread(buf, 1, sizeof(buf), in)) > 0)
		ok = fwrite(buf, 1, n, out) == n;
	if (in)
		fclose(in);
	if (out)
		ok = fclose(out) == 0 && ok;
	return ok;
}

/* D1: an unchanged file is reused by identity, a changed one is parsed again. */
static int case_elf_file_cache(void)
{
	struct gu_init_cfg cfg = { 0 };
	struct gu_context *ctx;
	struct per_elf_ctx *first, *again, *changed;
	char path[] = "/tmp/gu_elf_file_cache_XXXXXX";
	struct timespec times[2] = { { 0, UTIME_OMIT }, { 12345, 0 } };
	int fd, ret = 1;

	fd = mkstemp(path);
	if (fd < 0)
		FAIL("mkstemp failed");
	close(fd);
	if (!copy_file("/proc/self/exe", path))
		FAIL("copy of self failed");

	ctx = gu_init(&cfg);
	if (!ctx)
		FAIL("gu_init failed");
	ctx->debug = true;	/* open @path as given */

	first = load_elf(ctx, path, getpid(), NULL);
	again = load_elf(ctx, path, getpid(), NULL);
	if (!first || again != first || first->refcnt != 2 ||
	    ctx->statistics.elf_file_cache_hit != 1) {
		fprintf(stderr, "unchanged file was not reused by identity\n");
		goto out;
	}
	/* same bytes, new mtime: a new identity, found again by build-id */
	utimensat(AT_FDCWD, path, times, 0);
	changed = load_elf(ctx, path, getpid(), NULL);
	if (changed != first || ctx->statistics.elf_file_cache_hit != 1) {
		fprintf(stderr, "a modified file was served from the identity cache\n");
		goto out;
	}
	gu_put_elf_ctx(first);
	gu_put_elf_ctx(first);
	gu_put_elf_ctx(first);
	gu_retired_elf_sweep(ctx, UINT64_MAX);
	if (ctx->elf_file_index != NULL) {
		fprintf(stderr, "released ELF left in the identity index\n");
		goto out;
	}

	puts("elf file cache ok");
	ret = 0;
out:
	gu_cleanup(ctx);
	unlink(path);
	return ret;
}

/* D8: no timer thread; a retired ELF is swept once its deadline passed. */
static int case_retire_without_timer(void)
{
	struct gu_init_cfg cfg = { 0 };
	struct gu_context *ctx;
	struct per_elf_ctx *elf;
	int ret = 1;

	ctx = gu_init(&cfg);
	if (!ctx)
		FAIL("gu_init failed");
	ctx->debug = true;
	elf = load_elf(ctx, "/proc/self/exe", getpid(), NULL);
	if (!elf)
		goto out;
	gu_put_elf_ctx(elf);
	gu_maybe_sweep_retired_elf(ctx);
	if (ctx->statistics.retired_elf_ctx_count != 1) {
		fprintf(stderr, "retired ELF swept before its deadline\n");
		goto out;
	}
	elf->retire_deadline_ns = 1;
	ctx->next_retired_elf_deadline_ns = 1;
	gu_maybe_sweep_retired_elf(ctx);
	if (ctx->statistics.retired_elf_ctx_count != 0 ||
	    ctx->statistics.retired_elf_expired != 1) {
		fprintf(stderr, "retired ELF not swept after its deadline\n");
		goto out;
	}
	puts("retire without timer ok");
	ret = 0;
out:
	gu_cleanup(ctx);
	return ret;
}

static int case_mapping_symbol_names(void)
{
	if (!is_arm_elf_mapping_symbol_name("$x") ||
	    !is_arm_elf_mapping_symbol_name("$x.1") ||
	    !is_arm_elf_mapping_symbol_name("$d") ||
	    !is_arm_elf_mapping_symbol_name("$a") ||
	    !is_arm_elf_mapping_symbol_name("$t"))
		FAIL("valid ARM mapping symbol name was not recognized");
	if (is_arm_elf_mapping_symbol_name("$") ||
	    is_arm_elf_mapping_symbol_name("$foo") ||
	    is_arm_elf_mapping_symbol_name("real_func") ||
	    is_arm_elf_mapping_symbol_name(NULL))
		FAIL("non-mapping symbol name was incorrectly recognized");

	puts("mapping symbol name filter ok");
	return 0;
}

static int case_exec_range_offsets(void)
{
	struct gu_elf_exec_ranges ranges = { 0 };
	unsigned long exec_virt_addr = 0;
	int ret = 1;

	ranges.ranges = calloc(2, sizeof(*ranges.ranges));
	if (!ranges.ranges)
		FAIL("calloc exec ranges failed");
	ranges.count = 2;

	ranges.ranges[0].start = 0x1d924000;
	ranges.ranges[0].end = 0x64d20000;
	ranges.ranges[0].offset = 0x1d723000;
	ranges.ranges[1].start = 0x67600000;
	ranges.ranges[1].end = 0x727e9000;
	ranges.ranges[1].offset = 0x65e00000;

	if (!gu_elf_exec_ranges_find_by_offset(&ranges, 0x65e00000,
					       0xb1e9000, &exec_virt_addr)) {
		fprintf(stderr, "failed to match second executable range by maps offset\n");
		goto out;
	}
	if (exec_virt_addr != 0x67600000) {
		fprintf(stderr, "wrong executable virtual address: 0x%lx\n",
			exec_virt_addr);
		goto out;
	}

	puts("exec range offset matching ok");
	ret = 0;

out:
	gu_elf_exec_ranges_destroy(&ranges);
	return ret;
}

static int case_string_table_view(void)
{
	int fd = -1;
	Elf *elf = NULL;
	Elf_Scn *scn = NULL;
	GElf_Shdr shdr;
	Elf_Data *data;
	struct gu_symbol_string_table_view view;
	struct gu_symbol_string_table_view fallback_view;
	const char *direct_name = NULL;
	const char *fallback_name = NULL;
	int ret = 1;

	if (elf_version(EV_CURRENT) == EV_NONE)
		FAIL("elf_version failed");

	fd = open("/proc/self/exe", O_RDONLY);
	if (fd < 0)
		FAIL("open /proc/self/exe failed: %s", strerror(errno));

	elf = elf_begin(fd, ELF_C_READ, NULL);
	if (!elf) {
		fprintf(stderr, "elf_begin failed: %s\n", elf_errmsg(-1));
		goto out;
	}

	while ((scn = elf_nextscn(elf, scn)) != NULL) {
		if (gelf_getshdr(scn, &shdr) != &shdr)
			continue;
		if (shdr.sh_type != SHT_SYMTAB && shdr.sh_type != SHT_DYNSYM)
			continue;

		data = elf_getdata(scn, NULL);
		if (!data || shdr.sh_entsize == 0)
			continue;

		gu_symbol_string_table_view_init(elf, shdr.sh_link, &view);
		if (!view.direct)
			continue;

		size_t count = shdr.sh_size / shdr.sh_entsize;
		for (size_t i = 0; i < count; i++) {
			GElf_Sym sym;
			if (gelf_getsym(data, i, &sym) != &sym)
				continue;
			if (sym.st_name == 0)
				continue;

			direct_name = gu_symbol_string_table_view_get(&view,
								      sym.st_name);
			if (!direct_name || direct_name[0] == '\0')
				continue;

			fallback_view = view;
			fallback_view.direct = false;
			fallback_view.data = NULL;
			fallback_view.size = 0;
			fallback_name =
				gu_symbol_string_table_view_get(&fallback_view,
								sym.st_name);
			if (!fallback_name ||
			    strcmp(direct_name, fallback_name) != 0) {
				fprintf(stderr, "direct/fallback strtab mismatch\n");
				goto out;
			}
			if (gu_symbol_string_table_view_get(&view,
							    view.size) != NULL) {
				fprintf(stderr, "strtab view accepted out-of-range offset\n");
				goto out;
			}
			puts("symbol string table view ok");
			ret = 0;
			goto out;
		}
	}

	fprintf(stderr, "no suitable symbol string table found\n");

out:
	if (elf)
		elf_end(elf);
	if (fd >= 0)
		close(fd);
	return ret;
}

static int case_symbol_lookup(int argc, char **argv)
{
	struct gu_init_cfg cfg = { 0 };
	struct gu_context *ctx;
	struct per_elf_ctx *elf_ctx;
	struct interval_array_item item = { 0 };
	const char *path;
	const char *expected;
	char *end = NULL;
	uint64_t addr;
	char *symbol;
	int ret = 1;

	if (argc != 5)
		FAIL("usage: %s symbol-lookup <elf> <addr> <expected>", argv[0]);

	path = argv[2];
	addr = strtoull(argv[3], &end, 0);
	expected = argv[4];
	if (!end || *end != '\0')
		FAIL("invalid address: %s", argv[3]);

	ctx = gu_init(&cfg);
	if (!ctx)
		FAIL("gu_init failed");
	ctx->debug = true;

	elf_ctx = load_elf(ctx, (char *)path, getpid(), NULL);
	if (!elf_ctx || !elf_ctx->symbols) {
		fprintf(stderr, "failed to load symbols from %s\n", path);
		goto out;
	}
	if (gu_lookup_elf_symbol(elf_ctx, addr, &symbol, NULL) != 1) {
		fprintf(stderr, "failed to find symbol at 0x%llx\n",
			(unsigned long long)addr);
		goto out;
	}
	if (!symbol || strcmp(symbol, expected) != 0) {
		fprintf(stderr, "unexpected symbol at 0x%llx: %s != %s\n",
			(unsigned long long)addr, symbol ? symbol : "(null)",
			expected);
		goto out;
	}

	puts("symbol lookup skip mapping symbol ok");
	ret = 0;

out:
	gu_cleanup(ctx);
	return ret;
}

static int case_frame_symbol_lookup(int argc, char **argv)
{
	struct gu_init_cfg cfg = { 0 };
	struct gu_context *ctx;
	struct per_elf_ctx *elf_ctx;
	const char *path;
	const char *expected;
	char *end = NULL;
	uint64_t addr;
	unsigned long lookup_addr;
	char *symbol = NULL;
	uint64_t offset = 0;
	int ret = 1;

	if (argc != 5)
		FAIL("usage: %s frame-symbol-lookup <elf> <addr> <expected>", argv[0]);

	path = argv[2];
	addr = strtoull(argv[3], &end, 0);
	expected = argv[4];
	if (!end || *end != '\0')
		FAIL("invalid address: %s", argv[3]);

	ctx = gu_init(&cfg);
	if (!ctx)
		FAIL("gu_init failed");
	ctx->debug = true;

	elf_ctx = load_elf(ctx, (char *)path, getpid(), NULL);
	if (!elf_ctx || !elf_ctx->symbols) {
		fprintf(stderr, "failed to load symbols from %s\n", path);
		goto out;
	}

	lookup_addr = gu_frame_lookup_pc_for_return_address(addr, false,
							    false);
	if (gu_lookup_elf_symbol(elf_ctx, lookup_addr, &symbol, &offset) != 1) {
		fprintf(stderr, "failed to find frame symbol at 0x%llx lookup=0x%lx\n",
			(unsigned long long)addr, lookup_addr);
		goto out;
	}
	if (!symbol || strcmp(symbol, expected) != 0) {
		fprintf(stderr, "unexpected frame symbol at 0x%llx: %s != %s\n",
			(unsigned long long)addr, symbol ? symbol : "(null)",
			expected);
		goto out;
	}

	puts("frame symbol lookup return-address rule ok");
	ret = 0;

out:
	gu_cleanup(ctx);
	return ret;
}

/*
 * Two adjacent functions: fp_boundary_caller's last instruction stands for a
 * call that does not return (abort(), a tail of noreturn calls), so the
 * return address it pushes is the first byte of fp_boundary_next.
 */
asm(".text\n"
    ".globl fp_boundary_caller\n"
    ".type fp_boundary_caller, %function\n"
    "fp_boundary_caller:\n"
    "	nop\n"
    "	nop\n"
    ".size fp_boundary_caller, .-fp_boundary_caller\n"
    ".globl fp_boundary_next\n"
    ".type fp_boundary_next, %function\n"
    "fp_boundary_next:\n"
    "	nop\n"
    "	nop\n"
    ".size fp_boundary_next, .-fp_boundary_next\n");

void fp_boundary_caller(void);
void fp_boundary_next(void);

struct fp_boundary_frames {
	int count;
	char symbol[2][64];
	uint64_t offset[2];
	uint64_t pc[2];
};

static void collect_fp_boundary_frames(const struct gu_frame_record *frame,
				       void *arg)
{
	struct fp_boundary_frames *out = arg;

	if (out->count < 2) {
		snprintf(out->symbol[out->count], sizeof(out->symbol[0]), "%s",
			 frame->symbol ? frame->symbol : "(null)");
		out->offset[out->count] = frame->offset;
		out->pc[out->count] = frame->abs_pc;
	}
	out->count++;
}

/*
 * A frame-pointer stack symbolizes its caller frames by the return address
 * minus one, as the DWARF walk does: the same address is the sampled PC of
 * fp_boundary_next in frame 0, and a return into fp_boundary_caller in
 * frame 1.
 */
static int case_fp_caller_return_address(void)
{
	struct gu_init_cfg cfg = { 0 };
	struct fp_boundary_frames out = { 0 };
	uint64_t caller = (uint64_t)(uintptr_t)&fp_boundary_caller;
	uint64_t next = (uint64_t)(uintptr_t)&fp_boundary_next;
	uint64_t regs[64] = { 0 };
	struct gu_stack_info info;
	struct gu_context *ctx;
	int ret = 1;

	if (next <= caller)
		FAIL("fp boundary functions are out of order");

	ctx = gu_init(&cfg);
	if (!ctx)
		FAIL("gu_init failed");

	memset(&info, 0, sizeof(info));
	info.pid = getpid();
	info.tid = getpid();
	info.unique_id = gu_read_pid_start_ticks(info.pid);
	info.regs = regs;
	info.regs_size = sizeof(regs);
	info.ustack_fp[0] = next;
	info.ustack_fp[1] = next;
	info.ustack_fp_level = 2;
	gu_flags_set(&info, GU_FLAG_HINT_SET_FP);
	(void)gu_unwind(ctx, &info, collect_fp_boundary_frames, &out);

	if (out.count != 2) {
		fprintf(stderr, "unexpected frame count %d\n", out.count);
		goto out;
	}
	if (strcmp(out.symbol[0], "fp_boundary_next") != 0 || out.offset[0] != 0) {
		fprintf(stderr, "sampled pc was adjusted: %s+0x%llx\n",
			out.symbol[0], (unsigned long long)out.offset[0]);
		goto out;
	}
	if (strcmp(out.symbol[1], "fp_boundary_caller") != 0 ||
	    out.offset[1] != next - caller - 1) {
		fprintf(stderr, "return address was not adjusted: %s+0x%llx\n",
			out.symbol[1], (unsigned long long)out.offset[1]);
		goto out;
	}
	if (out.pc[0] != next || out.pc[1] != next) {
		fprintf(stderr, "frame pcs were rewritten\n");
		goto out;
	}

	puts("fp caller return address ok");
	ret = 0;

out:
	gu_cleanup(ctx);
	return ret;
}

#if defined(__x86_64__) || defined(__aarch64__)
/*
 * A sigreturn trampoline laid out as glibc's __restore_rt: an unnamed nop
 * between it and the function before, for unwinders that subtract one.
 */
asm(".text\n"
    ".globl fp_sig_before\n"
    ".type fp_sig_before, %function\n"
    "fp_sig_before:\n"
    "	nop\n"
    ".size fp_sig_before, .-fp_sig_before\n"
    "	nop\n"
    ".globl fp_sig_restorer\n"
    ".type fp_sig_restorer, %function\n"
    "fp_sig_restorer:\n"
#if defined(__x86_64__)
    "	mov $15, %rax\n"
    "	syscall\n"
#else
    "	mov x8, #139\n"
    "	svc #0\n"
#endif
    ".size fp_sig_restorer, .-fp_sig_restorer\n");

void fp_sig_restorer(void);

/* the kernel's struct sigaction on x86_64 and arm64 */
struct fp_kernel_sigaction {
	void (*handler)(int);
	unsigned long flags;
	void (*restorer)(void);
	uint64_t mask;
};

#define FP_SA_RESTORER 0x04000000UL

static struct fp_boundary_frames fp_sig_frames;
static uint64_t fp_sig_return;

static __attribute__((noinline)) void fp_sig_handler(int sig)
{
	struct gu_init_cfg cfg = { 0 };
	uint64_t regs[64] = { 0 };
	struct gu_stack_info info;
	struct gu_context *ctx;

	(void)sig;
	/* the handler's return address is the restorer the kernel pushed */
	fp_sig_return = (uint64_t)(uintptr_t)__builtin_return_address(0);
	ctx = gu_init(&cfg);
	if (!ctx)
		return;
	memset(&info, 0, sizeof(info));
	info.pid = getpid();
	info.tid = getpid();
	info.unique_id = gu_read_pid_start_ticks(info.pid);
	info.regs = regs;
	info.regs_size = sizeof(regs);
	info.ustack_fp[0] = (uint64_t)(uintptr_t)&fp_sig_handler;
	info.ustack_fp[1] = fp_sig_return;
	info.ustack_fp_level = 2;
	gu_flags_set(&info, GU_FLAG_HINT_SET_FP);
	(void)gu_unwind(ctx, &info, collect_fp_boundary_frames, &fp_sig_frames);
	gu_cleanup(ctx);
}

/*
 * A frame-pointer stack taken in a signal handler holds the entry of the
 * sigreturn trampoline, not a return address: it is named by itself, not
 * by the nop before it.
 */
static int case_fp_sigreturn_trampoline(void)
{
	struct fp_kernel_sigaction sa = {
		.handler = fp_sig_handler,
		.flags = FP_SA_RESTORER,
		.restorer = fp_sig_restorer,
	};

	if (syscall(SYS_rt_sigaction, SIGUSR1, &sa, NULL, sizeof(sa.mask)) != 0)
		FAIL("rt_sigaction: %s", strerror(errno));
	raise(SIGUSR1);
	signal(SIGUSR1, SIG_DFL);

	if (fp_sig_return != (uint64_t)(uintptr_t)&fp_sig_restorer)
		FAIL("the handler did not return into the restorer");
	if (fp_sig_frames.count != 2)
		FAIL("unexpected frame count %d", fp_sig_frames.count);
	if (strcmp(fp_sig_frames.symbol[1], "fp_sig_restorer") != 0 ||
	    fp_sig_frames.offset[1] != 0)
		FAIL("sigreturn trampoline misnamed: %s+0x%llx",
		     fp_sig_frames.symbol[1],
		     (unsigned long long)fp_sig_frames.offset[1]);

	puts("fp sigreturn trampoline ok");
	return 0;
}
#else
static int case_fp_sigreturn_trampoline(void)
{
	puts("fp sigreturn trampoline unsupported on this architecture");
	return 0;
}
#endif

static int case_zero_size_func_lookup(void)
{
	struct gu_init_cfg cfg = { 0 };
	struct gu_context *ctx = NULL;
	struct per_elf_ctx *elf_ctx;
	struct interval_array_item item = { 0 };
	char work_dir[PATH_MAX];
	char asm_path[PATH_MAX];
	char elf_path[PATH_MAX];
	char cmd[PATH_MAX * 3];
	uint64_t zero_addr;
	uint64_t next_addr;
	char *symbol;
	int ret = 1;
	FILE *asm_file = NULL;

	work_dir[0] = '\0';
	if (make_work_dir(work_dir, sizeof(work_dir), "zero-size-func") != 0) {
		fprintf(stderr, "mkdtemp failed: %s\n", strerror(errno));
		goto out;
	}

	snprintf(asm_path, sizeof(asm_path), "%s/zero_size_func.s", work_dir);
	snprintf(elf_path, sizeof(elf_path), "%s/zero_size_func", work_dir);

	asm_file = fopen(asm_path, "w");
	if (!asm_file) {
		fprintf(stderr, "failed to create %s: %s\n", asm_path, strerror(errno));
		goto out;
	}
	if (fputs(
		    ".text\n"
		    ".globl asm_zero_size_func\n"
		    ".type asm_zero_size_func, @function\n"
		    "asm_zero_size_func:\n"
		    "  .cfi_startproc\n"
		    "  nop\n"
		    "  nop\n"
		    "  ret\n"
		    "  .cfi_endproc\n"
		    "\n"
		    ".globl asm_next_func\n"
		    ".type asm_next_func, @function\n"
		    "asm_next_func:\n"
		    "  .cfi_startproc\n"
		    "  ret\n"
		    "  .cfi_endproc\n"
		    ".size asm_next_func, .-asm_next_func\n",
		    asm_file) == EOF) {
		fprintf(stderr, "failed to write %s: %s\n", asm_path,
			strerror(errno));
		goto out;
	}
	if (fclose(asm_file) != 0) {
		asm_file = NULL;
		fprintf(stderr, "failed to close %s: %s\n", asm_path,
			strerror(errno));
		goto out;
	}
	asm_file = NULL;

	snprintf(cmd, sizeof(cmd),
		 "cc -nostdlib -no-pie -Wl,--build-id=sha1 "
		 "-Wl,-e,asm_zero_size_func -o %s %s",
		 elf_path, asm_path);
	if (system(cmd) != 0) {
		fprintf(stderr, "failed to compile asm test object: %s\n", cmd);
		goto out;
	}

	zero_addr = resolve_symbol_addr(elf_path, "asm_zero_size_func", 0);
	next_addr = resolve_symbol_addr(elf_path, "asm_next_func", 0);
	if (zero_addr == 0 || next_addr == 0 || next_addr <= zero_addr) {
		fprintf(stderr, "unexpected test symbol addresses: zero=0x%llx next=0x%llx\n",
			(unsigned long long)zero_addr,
			(unsigned long long)next_addr);
		goto out;
	}

	ctx = gu_init(&cfg);
	if (!ctx) {
		fprintf(stderr, "gu_init failed\n");
		goto out;
	}
	ctx->debug = true;

	elf_ctx = load_elf(ctx, elf_path, getpid(), NULL);
	if (!elf_ctx || !elf_ctx->symbols) {
		fprintf(stderr, "load_elf failed for %s\n", elf_path);
		goto out;
	}

	for (uint64_t addr = zero_addr; addr < zero_addr + 2; addr++) {
		if (gu_lookup_elf_symbol(elf_ctx, addr, &symbol, NULL) != 1) {
			fprintf(stderr, "failed to resolve symbol at 0x%llx\n",
				(unsigned long long)addr);
			goto out;
		}
		if (!symbol || strcmp(symbol, "asm_zero_size_func") != 0) {
			fprintf(stderr, "unexpected symbol at 0x%llx: %s != %s\n",
				(unsigned long long)addr,
				symbol ? symbol : "(null)", "asm_zero_size_func");
			goto out;
		}
	}

	puts("zero-size function symbol lookup ok");
	ret = 0;

out:
	gu_cleanup(ctx);
	if (asm_file)
		fclose(asm_file);
	remove_work_dir(work_dir);
	return ret;
}

static int case_debuginfo_mem_stat(void)
{
	struct gu_init_cfg cfg = { 0 };
	struct gu_context *ctx;
	struct gu_debuginfo_mem_stat_snapshot *snapshot = NULL;
	struct gu_debuginfo_mem_stat_pid *pid_stat = NULL;
	int self = getpid();
	int ret = 1;

	ctx = gu_init(&cfg);
	if (!ctx)
		FAIL("gu_init failed");

	if (gu_preload_pid_debug_info(ctx, self) == 0) {
		fprintf(stderr, "failed to preload self debug info\n");
		goto out;
	}

	if (gu_export_debuginfo_mem_stat_snapshot(ctx, &snapshot) != 0 ||
	    !snapshot) {
		fprintf(stderr, "failed to export debuginfo memory snapshot\n");
		goto out;
	}
	if (snapshot->pid_count == 0 || !snapshot->pids) {
		fprintf(stderr, "snapshot has no pid entries\n");
		goto out;
	}

	for (size_t i = 0; i < snapshot->pid_count; i++) {
		if (snapshot->pids[i].pid == self) {
			pid_stat = &snapshot->pids[i];
			break;
		}
	}
	if (!pid_stat) {
		fprintf(stderr, "snapshot does not contain self pid\n");
		goto out;
	}
	if (!pid_stat->key_path || pid_stat->key_path[0] == '\0') {
		fprintf(stderr, "pid key path is empty\n");
		goto out;
	}
	if (pid_stat->elf_count == 0 || !pid_stat->elfs) {
		fprintf(stderr, "pid entry has no elf entries\n");
		goto out;
	}
	if (pid_stat->total_bytes < pid_stat->pss_bytes) {
		fprintf(stderr, "pid pss exceeds total bytes\n");
		goto out;
	}
	for (size_t i = 0; i < pid_stat->elf_count; i++) {
		struct gu_debuginfo_mem_stat_elf *elf = &pid_stat->elfs[i];
		uint64_t component_total =
			elf->symbol_bytes + elf->cfi_fde_bytes +
			elf->cfi_data_bytes;

		if (!elf->path || elf->path[0] == '\0') {
			fprintf(stderr, "elf path is empty\n");
			goto out;
		}
		if (elf->refcnt == 0) {
			fprintf(stderr, "elf refcnt is zero\n");
			goto out;
		}
		if (elf->total_bytes != component_total) {
			fprintf(stderr, "elf total does not match components\n");
			goto out;
		}
		if (elf->pss_bytes > elf->total_bytes) {
			fprintf(stderr, "elf pss exceeds total bytes\n");
			goto out;
		}
	}

	puts("debuginfo memory snapshot ok");
	ret = 0;

out:
	gu_debuginfo_mem_stat_snapshot_free(snapshot);
	gu_cleanup(ctx);
	return ret;
}

static int case_cfi_lookup_pc_rule(void)
{
	if (gu_cfi_lookup_pc_for_frame(0x1000, true, false) != 0x1000)
		FAIL("initial frame CFI lookup pc was adjusted");
	if (gu_cfi_lookup_pc_for_frame(0x1000, false, true) != 0x1000)
		FAIL("signal frame CFI lookup pc was adjusted");
	if (gu_cfi_lookup_pc_for_frame(0x1000, false, false) != 0x0fff)
		FAIL("normal return-address frame CFI lookup pc was not decremented");
	if (gu_cfi_lookup_pc_for_frame(0, false, false) != 0)
		FAIL("zero pc CFI lookup underflowed");

	puts("cfi lookup pc rule ok");
	return 0;
}

int main(int argc, char **argv)
{
	if (argc < 2) {
		fprintf(stderr,
			"usage: %s <vdso|retire|maps-reload|reload-in-place|identity-reuse|identity-thread|identity-zombie-leader|elf-file-cache|retire-without-timer|mapping-symbol-names|exec-range-offsets|string-table-view|symbol-lookup|frame-symbol-lookup|zero-size-func-lookup|debuginfo-mem-stat|cfi-lookup-pc-rule|fp-caller-return-address|fp-sigreturn-trampoline>\n",
			argv[0]);
		return 1;
	}

	if (strcmp(argv[1], "vdso") == 0)
		return case_vdso();
	if (strcmp(argv[1], "retire") == 0)
		return case_retire();
	if (strcmp(argv[1], "maps-reload") == 0)
		return case_maps_reload();
	if (strcmp(argv[1], "reload-in-place") == 0)
		return case_reload_in_place();
	if (strcmp(argv[1], "identity-reuse") == 0)
		return case_identity_reuse();
	if (strcmp(argv[1], "identity-thread") == 0)
		return case_identity_thread();
	if (strcmp(argv[1], "identity-zombie-leader") == 0)
		return case_identity_zombie_leader();
	if (strcmp(argv[1], "elf-file-cache") == 0)
		return case_elf_file_cache();
	if (strcmp(argv[1], "retire-without-timer") == 0)
		return case_retire_without_timer();
	if (strcmp(argv[1], "mapping-symbol-names") == 0)
		return case_mapping_symbol_names();
	if (strcmp(argv[1], "exec-range-offsets") == 0)
		return case_exec_range_offsets();
	if (strcmp(argv[1], "string-table-view") == 0)
		return case_string_table_view();
	if (strcmp(argv[1], "symbol-lookup") == 0)
		return case_symbol_lookup(argc, argv);
	if (strcmp(argv[1], "frame-symbol-lookup") == 0)
		return case_frame_symbol_lookup(argc, argv);
	if (strcmp(argv[1], "zero-size-func-lookup") == 0)
		return case_zero_size_func_lookup();
	if (strcmp(argv[1], "debuginfo-mem-stat") == 0)
		return case_debuginfo_mem_stat();
	if (strcmp(argv[1], "cfi-lookup-pc-rule") == 0)
		return case_cfi_lookup_pc_rule();
	if (strcmp(argv[1], "fp-caller-return-address") == 0)
		return case_fp_caller_return_address();
	if (strcmp(argv[1], "fp-sigreturn-trampoline") == 0)
		return case_fp_sigreturn_trampoline();

	fprintf(stderr, "unknown case: %s\n", argv[1]);
	return 1;
}
