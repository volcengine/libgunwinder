/* SPDX-License-Identifier: LGPL-3.0-or-later */

#include <dwarf.h>
#include <elfutils/libdw.h>
#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "../src/gu_cfi_helper.h"
#include "../src/gu_interval_array.h"
#include "../src/gu_unwinder.h"

#define DEFAULT_SET_SIZE 100
#define DEFAULT_FRAMES 5000000ULL
#define DEFAULT_WARMUP 10000ULL
#define TEST_STACK_SIZE 8192

struct byte_builder {
	uint8_t data[256];
	size_t len;
};

struct cfi_fixture {
	struct gu_cfi cfi;
	Elf_Data cfi_data;
	struct gu_cfi_cie cie;
	struct gu_cfi_fde fde;
	struct interval_array *intervals;
};

struct bench_frame {
	struct cfi_fixture cf;
	struct gu_stack_info info;
	struct pt_regs regs;
	uint8_t stack[TEST_STACK_SIZE];
	struct byte_builder ins;
	uint64_t raw_sp;
	uint64_t stack_base;
	uint64_t pc;
	uint64_t expected_ra;
	uint64_t expected_sp;
	uint64_t expected_bp;
};

struct bench_config {
	uint64_t frames;
	uint64_t warmup;
	size_t set_size;
};

static uint64_t now_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

static void emit_u8(struct byte_builder *b, uint8_t value)
{
	if (b->len >= sizeof(b->data)) {
		fprintf(stderr, "CFI byte buffer overflow\n");
		exit(2);
	}
	b->data[b->len++] = value;
}

static void emit_uleb(struct byte_builder *b, uint64_t value)
{
	do {
		uint8_t byte = value & 0x7f;

		value >>= 7;
		if (value)
			byte |= 0x80;
		emit_u8(b, byte);
	} while (value);
}

static void emit_def_cfa_rsp(struct byte_builder *b, uint64_t offset)
{
	emit_u8(b, DW_CFA_def_cfa);
	emit_uleb(b, reg_name_rsp);
	emit_uleb(b, offset);
}

static void emit_rip_offset(struct byte_builder *b, uint64_t offset)
{
	emit_u8(b, DW_CFA_offset + reg_name_rip);
	emit_uleb(b, offset);
}

static void emit_rbp_val_offset(struct byte_builder *b, uint64_t offset)
{
	emit_u8(b, DW_CFA_val_offset);
	emit_uleb(b, reg_name_rbp);
	emit_uleb(b, offset);
}

static void write_stack_u64(struct bench_frame *frame, uint64_t addr,
			    uint64_t value)
{
	uint64_t off = addr - frame->stack_base;

	if (off + sizeof(value) > sizeof(frame->stack)) {
		fprintf(stderr, "stack write out of range: addr=0x%" PRIx64 "\n",
			addr);
		exit(2);
	}
	memcpy(&frame->stack[off], &value, sizeof(value));
}

static int init_cfi_fixture(struct cfi_fixture *cf, struct byte_builder *ins,
			    uint64_t start, uint64_t end)
{
	struct interval_array_item item;

	memset(cf, 0, sizeof(*cf));
	cf->cfi_data.d_buf = ins->data;
	cf->cfi_data.d_size = ins->len;
	cf->cfi.cfi_data = &cf->cfi_data;

	cf->cie.code_alignment_factor = 1;
	cf->cie.data_alignment_factor = -8;
	cf->cie.return_address_register = reg_name_rip;
	cf->cie.fde_encoding = DW_EH_PE_udata8;
	cf->cie.lsda_encoding = DW_EH_PE_omit;

	cf->fde.cie = &cf->cie;
	cf->fde.start = start;
	cf->fde.end = end;
	cf->fde.instructions = ins->data;
	cf->fde.instructions_end = ins->data + ins->len;

	item.start = start;
	item.end = end;
	item.private = (void *)mark_interval_array_pointer_no_free((uint64_t)&cf->fde);
	cf->intervals = gu_interval_array_init(&item, 1);
	if (!cf->intervals)
		return -1;
	cf->cfi.hdr_interval_array = cf->intervals;

	return 0;
}

static void destroy_cfi_fixture(struct cfi_fixture *cf)
{
	if (cf->intervals)
		gu_interval_array_destroy(cf->intervals);
}

static int init_bench_frame(struct bench_frame *frame, size_t idx)
{
	uint64_t start = 0x1000 + idx * 0x100;
	uint64_t advance = 1 + (idx % 31);
	uint64_t cfa_offset = 16 + ((idx % 7) * 8);
	uint64_t saved_ra_addr;

	memset(frame, 0, sizeof(*frame));
	frame->raw_sp = 0x70000120ULL;
	frame->stack_base = frame->raw_sp - (frame->raw_sp % (uint64_t)getpagesize());
	frame->pc = start + advance;
	frame->expected_ra = 0x5555000000000000ULL + idx;
	frame->expected_sp = frame->raw_sp + cfa_offset;
	frame->expected_bp = frame->expected_sp;

	emit_def_cfa_rsp(&frame->ins, 8);
	emit_rip_offset(&frame->ins, 1);
	emit_rbp_val_offset(&frame->ins, 0);
	emit_u8(&frame->ins, DW_CFA_advance_loc + advance);
	emit_u8(&frame->ins, DW_CFA_def_cfa_offset);
	emit_uleb(&frame->ins, cfa_offset);

	frame->info.pid = getpid();
	frame->info.unique_id = 1;
	frame->info.regs = &frame->regs;
	frame->info.regs_size = sizeof(frame->regs);
	frame->info.stack_data = frame->stack;
	frame->info.stack_size = sizeof(frame->stack);

	write_regs(&frame->info, reg_name_rsp, frame->raw_sp);
	write_regs(&frame->info, reg_name_rbp, frame->raw_sp + 0xe0);
	write_regs(&frame->info, reg_name_rip, frame->pc);

	saved_ra_addr = frame->expected_sp - 8;
	write_stack_u64(frame, saved_ra_addr, frame->expected_ra);

	return init_cfi_fixture(&frame->cf, &frame->ins, start, start + 0x100);
}

static void destroy_bench_frames(struct bench_frame *frames, size_t set_size)
{
	for (size_t i = 0; i < set_size; i++)
		destroy_cfi_fixture(&frames[i].cf);
}

static int cmp_u64(const void *a, const void *b)
{
	uint64_t va = *(const uint64_t *)a;
	uint64_t vb = *(const uint64_t *)b;

	return (va > vb) - (va < vb);
}

static int run_one_frame(struct bench_frame *frame, uint64_t *checksum)
{
	uint64_t ra = 0, sp = 0, bp = 0;

	if (gu_cfi_parse_cfi(&frame->cf.cfi, frame->pc) != 0)
		return -1;
	if (gen_reg(NULL, reg_name_rip, frame->pc, frame->raw_sp, &frame->info,
		    &ra) != GU_UNWIND_REASON_OK)
		return -1;
	if (gen_reg(NULL, reg_name_rsp, frame->pc, frame->raw_sp, &frame->info,
		    &sp) != GU_UNWIND_REASON_OK)
		return -1;
	if (gen_reg(NULL, reg_name_rbp, frame->pc, frame->raw_sp, &frame->info,
		    &bp) != GU_UNWIND_REASON_OK)
		return -1;

	if (ra != frame->expected_ra || sp != frame->expected_sp ||
	    bp != frame->expected_bp) {
		fprintf(stderr,
			"bad unwind result: ra=0x%" PRIx64 " sp=0x%" PRIx64
			" bp=0x%" PRIx64 "\n",
			ra, sp, bp);
		return -1;
	}

	*checksum += ra ^ sp ^ bp;
	return 0;
}

static int parse_u64_arg(const char *name, const char *value, uint64_t *out)
{
	char *end = NULL;
	unsigned long long parsed;

	errno = 0;
	parsed = strtoull(value, &end, 10);
	if (errno || !end || *end != '\0') {
		fprintf(stderr, "invalid %s: %s\n", name, value);
		return -1;
	}
	*out = parsed;
	return 0;
}

static int parse_args(int argc, char **argv, struct bench_config *cfg)
{
	cfg->frames = DEFAULT_FRAMES;
	cfg->warmup = DEFAULT_WARMUP;
	cfg->set_size = DEFAULT_SET_SIZE;

	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--frames") == 0 && i + 1 < argc) {
			if (parse_u64_arg("--frames", argv[++i], &cfg->frames) != 0)
				return -1;
		} else if (strcmp(argv[i], "--warmup") == 0 && i + 1 < argc) {
			if (parse_u64_arg("--warmup", argv[++i], &cfg->warmup) != 0)
				return -1;
		} else if (strcmp(argv[i], "--set-size") == 0 && i + 1 < argc) {
			uint64_t set_size;

			if (parse_u64_arg("--set-size", argv[++i], &set_size) != 0)
				return -1;
			cfg->set_size = (size_t)set_size;
		} else if (strcmp(argv[i], "--help") == 0) {
			printf("usage: %s [--frames N] [--set-size N] [--warmup N]\n",
			       argv[0]);
			return 1;
		} else {
			fprintf(stderr,
				"usage: %s [--frames N] [--set-size N] [--warmup N]\n",
				argv[0]);
			return -1;
		}
	}

	if (cfg->frames == 0 || cfg->set_size == 0) {
		fprintf(stderr, "--frames and --set-size must be non-zero\n");
		return -1;
	}
	if (cfg->set_size > 10000) {
		fprintf(stderr, "--set-size must be <= 10000\n");
		return -1;
	}

	return 0;
}

int main(int argc, char **argv)
{
	struct bench_config cfg;
	struct bench_frame *frames = NULL;
	uint64_t *cycle_ns = NULL;
	uint64_t checksum = 0;
	uint64_t cycles;
	uint64_t total_frames;
	uint64_t start_ns, end_ns, total_ns;
	double frames_per_sec;
	double avg_ns;
	double p50_ns;
	double p99_ns;
	int parse_ret;
	int ret = 1;

	parse_ret = parse_args(argc, argv, &cfg);
	if (parse_ret > 0)
		return 0;
	if (parse_ret < 0)
		return 2;

	frames = calloc(cfg.set_size, sizeof(*frames));
	if (!frames)
		return 2;

	for (size_t i = 0; i < cfg.set_size; i++) {
		if (init_bench_frame(&frames[i], i) != 0) {
			fprintf(stderr, "failed to initialize benchmark frame %zu\n", i);
			goto out;
		}
	}

	for (uint64_t i = 0; i < cfg.warmup; i++) {
		if (run_one_frame(&frames[i % cfg.set_size], &checksum) != 0)
			goto out;
	}

	cycles = (cfg.frames + cfg.set_size - 1) / cfg.set_size;
	total_frames = cycles * cfg.set_size;
	cycle_ns = calloc(cycles, sizeof(*cycle_ns));
	if (!cycle_ns)
		goto out;

	start_ns = now_ns();
	for (uint64_t cycle = 0; cycle < cycles; cycle++) {
		uint64_t cycle_start = now_ns();

		for (size_t i = 0; i < cfg.set_size; i++) {
			if (run_one_frame(&frames[i], &checksum) != 0)
				goto out;
		}
		cycle_ns[cycle] = now_ns() - cycle_start;
	}
	end_ns = now_ns();
	total_ns = end_ns - start_ns;

	qsort(cycle_ns, cycles, sizeof(*cycle_ns), cmp_u64);

	frames_per_sec = (double)total_frames * 1000000000.0 / (double)total_ns;
	avg_ns = (double)total_ns / (double)total_frames;
	p50_ns = (double)cycle_ns[cycles / 2] / (double)cfg.set_size;
	p99_ns = (double)cycle_ns[(cycles * 99) / 100] / (double)cfg.set_size;

	printf("libgunwinder_cfi_bench frames=%" PRIu64
	       " set_size=%zu cycles=%" PRIu64 " total_ns=%" PRIu64
	       " frames_per_sec=%.2f avg_ns_per_frame=%.2f"
	       " p50_ns_per_frame=%.2f p99_ns_per_frame=%.2f"
	       " checksum=%" PRIu64 "\n",
	       total_frames, cfg.set_size, cycles, total_ns, frames_per_sec,
	       avg_ns, p50_ns, p99_ns, checksum);

	ret = 0;
out:
	free(cycle_ns);
	if (frames)
		destroy_bench_frames(frames, cfg.set_size);
	free(frames);
	return ret;
}
