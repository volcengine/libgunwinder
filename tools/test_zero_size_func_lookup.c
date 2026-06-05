/* SPDX-License-Identifier: LGPL-3.0-or-later */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "gunwinder/unwinder.h"

__asm__(".text\n"
	".globl asm_zero_size_func\n"
	".type asm_zero_size_func, @function\n"
	"asm_zero_size_func:\n"
	"  nop\n"
	"  nop\n"
	"  ret\n"
	"\n"
	".globl asm_next_func\n"
	".type asm_next_func, @function\n"
	"asm_next_func:\n"
	"  ret\n"
	".size asm_next_func, .-asm_next_func\n");

extern void asm_zero_size_func(void);

struct observed_frame {
	int frames;
	const char *symbol;
	uint64_t offset;
};

static void frame_callback(const struct gu_frame_record *frame, void *ctx)
{
	struct observed_frame *observed = ctx;

	if (observed->frames == 0) {
		observed->symbol = frame->symbol;
		observed->offset = frame->offset;
	}
	observed->frames++;
}

int main(void)
{
	struct gu_init_cfg cfg = { 0 };
	struct gu_stack_info info = { 0 };
	struct gu_context *ctx;
	struct observed_frame observed = { 0 };
	uint64_t regs[64] = { 0 };
	int ret = 1;

	ctx = gu_init(&cfg);
	if (!ctx) {
		fprintf(stderr, "gu_init failed\n");
		return 1;
	}

	info.pid = getpid();
	info.regs = regs;
	info.regs_size = sizeof(regs);
	info.ustack_fp[0] = (uint64_t)(uintptr_t)asm_zero_size_func + 1;
	info.ustack_fp_level = 1;
	gu_flags_set(&info, GU_FLAG_HINT_SET_FP);

	if (gu_unwind(ctx, &info, frame_callback, &observed) <= 0) {
		fprintf(stderr, "gu_unwind did not return a frame\n");
		goto out;
	}

	if (observed.frames == 0) {
		fprintf(stderr, "callback was not invoked\n");
		goto out;
	}

	if (!observed.symbol ||
	    strcmp(observed.symbol, "asm_zero_size_func") != 0) {
		fprintf(stderr, "unexpected symbol: %s\n",
			observed.symbol ? observed.symbol : "(null)");
		goto out;
	}

	if (observed.offset != 1) {
		fprintf(stderr, "unexpected offset: %llu\n",
			(unsigned long long)observed.offset);
		goto out;
	}

	puts("zero-size function symbol lookup ok");
	ret = 0;

out:
	gu_cleanup(ctx);
	return ret;
}
