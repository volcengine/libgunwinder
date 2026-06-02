/* SPDX-License-Identifier: LGPL-3.0-or-later */

#include <signal.h>
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

static __attribute__((noinline, used)) void known_text_function(void)
{
	asm volatile("");
}

static int run_fp_unwind(struct gu_context *ctx, pid_t pid)
{
	struct gu_stack_info info;
	uint64_t regs[64] = { 0 };
	int frames = 0;

	memset(&info, 0, sizeof(info));
	info.pid = pid;
	info.regs = regs;
	info.regs_size = sizeof(regs);
	info.ustack_fp[0] = (uint64_t)(uintptr_t)&known_text_function;
	info.ustack_fp[1] = STABLE_UNKNOWN_PC;
	info.ustack_fp_level = 2;
	gu_flags_set(&info, GU_FLAG_HINT_SET_FP);

	(void)gu_unwind(ctx, &info, frame_callback, &frames);
	return frames;
}

int main(void)
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

	if (run_fp_unwind(ctx, child) <= 0) {
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
		if (run_fp_unwind(ctx, child) <= 0) {
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
	if (throttle_after_repeat == 0) {
		fprintf(stderr, "stable missing FP PC was not throttled\n");
		goto out;
	}

	ret = 0;

out:
	if (ctx)
		gu_cleanup(ctx);
	kill(child, SIGTERM);
	waitpid(child, &status, 0);
	return ret;
}
