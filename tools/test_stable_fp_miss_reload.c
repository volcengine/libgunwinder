/* SPDX-License-Identifier: LGPL-3.0-or-later */

#include <dlfcn.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "gunwinder/unwinder.h"

#define REPEAT_UNWINDS 8
#define STABLE_UNKNOWN_PC 0xc0000f6000ULL

static void frame_callback(const struct gu_frame_record *frame, void *ctx)
{
	int *frames = ctx;

	(void)frame;
	(*frames)++;
}

struct leaf_probe {
	const char *want;
	bool found;
};

static void leaf_symbol_callback(const struct gu_frame_record *frame, void *ctx)
{
	struct leaf_probe *probe = ctx;

	if (frame->symbol && strstr(frame->symbol, probe->want))
		probe->found = true;
}

static __attribute__((noinline, used)) void known_text_function(void)
{
	asm volatile("");
}

/* @leaf_unknown: the sampled IP itself misses, not only a deeper frame. */
static int run_fp_unwind(struct gu_context *ctx, pid_t pid, bool leaf_unknown)
{
	struct gu_stack_info info;
	uint64_t regs[64] = { 0 };
	int frames = 0;

	memset(&info, 0, sizeof(info));
	info.pid = pid;
	info.regs = regs;
	info.regs_size = sizeof(regs);
	info.ustack_fp[0] = leaf_unknown ? STABLE_UNKNOWN_PC :
			    (uint64_t)(uintptr_t)&known_text_function;
	info.ustack_fp[1] = leaf_unknown ? (uint64_t)(uintptr_t)&known_text_function :
			    STABLE_UNKNOWN_PC;
	info.ustack_fp_level = 2;
	gu_flags_set(&info, GU_FLAG_HINT_SET_FP);

	(void)gu_unwind(ctx, &info, frame_callback, &frames);
	return frames;
}

static bool unwind_leaf_finds(struct gu_context *ctx, pid_t pid, uint64_t pc,
			      const char *want)
{
	struct gu_stack_info info;
	uint64_t regs[64] = { 0 };
	struct leaf_probe probe = { .want = want };

	memset(&info, 0, sizeof(info));
	info.pid = pid;
	info.regs = regs;
	info.regs_size = sizeof(regs);
	info.ustack_fp[0] = pc;
	info.ustack_fp_level = 1;
	gu_flags_set(&info, GU_FLAG_HINT_SET_FP);

	(void)gu_unwind(ctx, &info, leaf_symbol_callback, &probe);
	return probe.found;
}

/*
 * A pid first seen before a library is mapped (at exec, only ld.so and the
 * binary are there) must resolve a leaf in that library at once, not after
 * the 30-90s reload throttle: a process that dies in libc right after exec
 * would otherwise lose every user frame.  One reload, then the throttle.
 */
static int check_late_mapping(struct gu_context *ctx, const char *lib)
{
	int to_child[2], to_parent[2];
	struct gu_statistics *stats;
	uint64_t reloads, addr = 0;
	int status = 0, ret = 1;
	pid_t child;
	char go = 1;

	if (pipe(to_child) || pipe(to_parent)) {
		perror("pipe");
		return 1;
	}
	child = fork();
	if (child < 0) {
		perror("fork");
		return 1;
	}
	if (child == 0) {
		void *handle, *sym = NULL;

		if (read(to_child[0], &go, 1) == 1 &&
		    (handle = dlopen(lib, RTLD_NOW)) != NULL)
			sym = dlsym(handle, "deep_lib_entry");
		addr = (uint64_t)(uintptr_t)sym;
		if (write(to_parent[1], &addr, sizeof(addr)) != sizeof(addr))
			_exit(1);
		for (;;)
			pause();
	}

	/* the pid's view is built now, before the library exists in it */
	if (run_fp_unwind(ctx, child, false) <= 0) {
		fprintf(stderr, "late mapping: no frame before the dlopen\n");
		goto out;
	}
	reloads = gu_get_statistics(ctx)->pid_maps_reload_count;
	if (write(to_child[1], &go, 1) != 1 ||
	    read(to_parent[0], &addr, sizeof(addr)) != sizeof(addr) || !addr) {
		fprintf(stderr, "late mapping: child could not dlopen %s\n", lib);
		goto out;
	}
	if (!unwind_leaf_finds(ctx, child, addr, "deep_lib_entry")) {
		fprintf(stderr, "late mapping: leaf in a library mapped after the "
				"pid was first seen did not resolve\n");
		goto out;
	}
	stats = gu_get_statistics(ctx);
	printf("late_mapping_reloads=%llu\n",
	       (unsigned long long)(stats->pid_maps_reload_count - reloads));
	if (stats->pid_maps_reload_count != reloads + 1) {
		fprintf(stderr, "late mapping: expected exactly one maps reload\n");
		goto out;
	}
	/* a second miss of that pid waits for the throttle */
	run_fp_unwind(ctx, child, true);
	if (gu_get_statistics(ctx)->pid_maps_reload_count != reloads + 1) {
		fprintf(stderr, "late mapping: a second miss reloaded again\n");
		goto out;
	}
	ret = 0;
out:
	kill(child, SIGKILL);
	waitpid(child, &status, 0);
	return ret;
}

int main(int argc, char **argv)
{
	struct gu_init_cfg cfg = { 0 };
	struct gu_context *ctx = NULL;
	struct gu_statistics *stats = NULL;
	uint64_t alloc_after_first = 0;
	uint64_t alloc_after_repeat = 0;
	uint64_t throttle_after_repeat = 0;
	pid_t child;
	int status = 0;
	int ret = 1;

	child = fork();
	if (child < 0) {
		perror("fork");
		return 1;
	}
	if (child == 0) {
		for (;;)
			pause();
	}

	ctx = gu_init(&cfg);
	if (!ctx) {
		fprintf(stderr, "gu_init failed\n");
		goto out;
	}

	if (run_fp_unwind(ctx, child, false) <= 0) {
		fprintf(stderr, "expected at least one text frame\n");
		goto out;
	}

	stats = gu_get_statistics(ctx);
	if (!stats) {
		fprintf(stderr, "gu_get_statistics failed\n");
		goto out;
	}
	alloc_after_first = stats->pid_ctx_alloc_count;

	for (int i = 0; i < REPEAT_UNWINDS; i++) {
		if (run_fp_unwind(ctx, child, false) <= 0) {
			fprintf(stderr, "repeat unwind lost the known text frame\n");
			goto out;
		}
	}

	stats = gu_get_statistics(ctx);
	if (!stats) {
		fprintf(stderr, "gu_get_statistics failed after repeat\n");
		goto out;
	}
	alloc_after_repeat = stats->pid_ctx_alloc_count;
	throttle_after_repeat = stats->pid_maps_reload_throttle_count;

	printf("pid_ctx_alloc_after_first=%llu\n",
	       (unsigned long long)alloc_after_first);
	printf("pid_ctx_alloc_after_repeat=%llu\n",
	       (unsigned long long)alloc_after_repeat);
	printf("pid_maps_reload_throttle=%llu\n",
	       (unsigned long long)throttle_after_repeat);

	if (alloc_after_repeat != alloc_after_first) {
		fprintf(stderr,
			"stable missing FP PC triggered repeated pid ctx reloads: first=%llu repeat=%llu\n",
			(unsigned long long)alloc_after_first,
			(unsigned long long)alloc_after_repeat);
		goto out;
	}
	/* a deeper frame may be a junk return address: no reload attempt */
	if (throttle_after_repeat != 0 || stats->pid_maps_reload_count != 0) {
		fprintf(stderr, "a deeper missing FP PC attempted a maps reload\n");
		goto out;
	}
	/* a missing sampled IP may be new code: reload, then throttle */
	for (int i = 0; i < REPEAT_UNWINDS; i++)
		run_fp_unwind(ctx, child, true);
	stats = gu_get_statistics(ctx);
	printf("leaf_miss_throttle=%llu\n",
	       (unsigned long long)stats->pid_maps_reload_throttle_count);
	if (stats->pid_maps_reload_throttle_count == 0 ||
	    stats->pid_ctx_alloc_count != alloc_after_first) {
		fprintf(stderr, "a missing leaf PC was not gated by the reload throttle\n");
		goto out;
	}
	/* the first leaf miss reloads at once, every later one is throttled */
	printf("leaf_miss_reloads=%llu\n",
	       (unsigned long long)stats->pid_maps_reload_count);
	if (stats->pid_maps_reload_count != 1) {
		fprintf(stderr, "a pid that keeps missing cost more than one reload\n");
		goto out;
	}
	if (check_late_mapping(ctx, argc > 1 ? argv[1] : "bin/libdeep.so"))
		goto out;

	ret = 0;

out:
	if (ctx)
		gu_cleanup(ctx);
	kill(child, SIGTERM);
	waitpid(child, &status, 0);
	return ret;
}
