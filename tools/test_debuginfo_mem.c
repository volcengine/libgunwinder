/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* SPDX-FileCopyrightText: 2026 ByteDance Inc. */

/*
 * Tests of the debuginfo memory layout: packed symbol names (round trip,
 * corrupt and truncated data, reader reuse), failed name reads counted per
 * ELF and per context, CFI bodies shared by identical FDEs only, the MD5
 * identity of ELFs without a build-id, and lookups from several threads.
 *
 * Usage: test_debuginfo_mem <case> [elf]
 *
 * Linked with --wrap=realloc (Makefile) so a case can fail one allocation.
 */
/*
 * First: it defines _GNU_SOURCE for the system headers.  The sources under
 * test are compiled in, so a sanitizer build instruments them too.
 */
#include "../src/gu_stacktrace.c"
#include "test_elf_symbol.h"
#include "../src/gu_symbol_names.c"
#include "../src/gu_cfi_helper.c"

#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/*
 * realloc() of exactly this many bytes fails while set (0: never), and
 * counts in fail_realloc_hits, so a case can tell the failure it meant
 * to cause did happen.
 */
static size_t fail_realloc_size;
static int fail_realloc_hits;

void *__real_realloc(void *ptr, size_t size);
void *__wrap_realloc(void *ptr, size_t size)
{
	if (fail_realloc_size && size == fail_realloc_size) {
		fail_realloc_hits++;
		return NULL;
	}
	return __real_realloc(ptr, size);
}

#define FAIL(...) do { fprintf(stderr, __VA_ARGS__); fputc('\n', stderr); return 1; } while (0)

static int make_work_dir(char *buf, size_t len, const char *tag)
{
	snprintf(buf, len, "/tmp/gu-debuginfo-mem-%s-XXXXXX", tag);
	return mkdtemp(buf) ? 0 : -1;
}

static void remove_work_dir(const char *dir)
{
	char cmd[PATH_MAX + 16];

	if (!dir[0])
		return;
	snprintf(cmd, sizeof(cmd), "rm -rf '%s'", dir);
	if (system(cmd) != 0)
		fprintf(stderr, "cleanup of %s failed\n", dir);
}

/* Name i: distinct, lengths from 1 to ~300 bytes, one of them 70000. */
static char *test_name(size_t i)
{
	size_t len = (i == 77) ? 70000 : 1 + (i * 37) % 300;
	char *s = malloc(len + 32);
	int n;

	if (!s)
		return NULL;
	n = snprintf(s, len + 32, "_ZN4test%zuE", i);
	for (; (size_t)n < len; n++)
		s[n] = 'a' + (char)((i + n) % 26);
	s[n] = '\0';
	return s;
}

static struct gu_symbol_names *build_names(size_t count)
{
	struct gu_symbol_names_builder *b = gu_symbol_names_builder_new();

	if (!b)
		return NULL;
	for (size_t i = 0; i < count; i++) {
		char *name = test_name(i);

		if (!name || gu_symbol_names_add(b, name) != (long)i) {
			free(name);
			gu_symbol_names_builder_free(b);
			return NULL;
		}
		free(name);
	}
	return gu_symbol_names_finish(b);
}

static int check_all(const struct gu_symbol_names *names,
		     struct gu_symbol_names_reader *reader, size_t count)
{
	/* a stride that visits every ordinal out of order */
	for (size_t k = 0, i = 0; k < count; k++, i = (i + 61) % count) {
		const char *got;
		char *want = test_name(i);

		if (!want)
			FAIL("oom");
		if (gu_symbol_names_read(names, reader, i, &got) != 0 ||
		    strcmp(got, want) != 0) {
			free(want);
			FAIL("ordinal %zu reads back wrong", i);
		}
		free(want);
	}
	return 0;
}

static int case_names_roundtrip(void)
{
	/* one name, exactly one block, and blocks with a partial last one */
	size_t counts[] = { 1, GU_SYMBOL_NAMES_PER_BLOCK, 3 * GU_SYMBOL_NAMES_PER_BLOCK + 17, 5000 };
	struct gu_symbol_names_reader *reader = gu_symbol_names_reader_new();
	const char *got;

	if (!reader)
		FAIL("reader");
	for (size_t c = 0; c < sizeof(counts) / sizeof(counts[0]); c++) {
		struct gu_symbol_names *names = build_names(counts[c]);
		size_t raw = 0;

		if (!names)
			FAIL("build %zu names", counts[c]);
		if (names->name_count != counts[c] ||
		    names->block_count != (counts[c] + GU_SYMBOL_NAMES_PER_BLOCK - 1) / GU_SYMBOL_NAMES_PER_BLOCK)
			FAIL("%zu names: %zu names in %zu blocks", counts[c],
			     names->name_count, names->block_count);
		/* the same reader across sets of names, blocks of every size */
		if (check_all(names, reader, counts[c]) != 0)
			return 1;
		for (size_t i = 0; i < counts[c]; i++) {
			char *n = test_name(i);
			raw += strlen(n) + 1;
			free(n);
		}
		if (gu_symbol_names_raw_bytes(names) != raw)
			FAIL("raw bytes %zu, want %zu", gu_symbol_names_raw_bytes(names), raw);
		if (gu_symbol_names_read(names, reader, counts[c], &got) == 0)
			FAIL("ordinal past the end read");
		if (gu_symbol_names_read(names, NULL, 0, &got) == 0)
			FAIL("read without a reader");
		gu_symbol_names_free(names);
	}
	gu_symbol_names_reader_free(reader);
	puts("symbol names round trip ok");
	return 0;
}

static int case_names_corrupt(void)
{
	size_t count = 3 * GU_SYMBOL_NAMES_PER_BLOCK + 5;
	struct gu_symbol_names *names = build_names(count);
	struct gu_symbol_names_reader *reader = gu_symbol_names_reader_new();
	const char *got;
	size_t mid, saved_off;
	char saved;

	if (!names || !reader)
		FAIL("setup");

	/* a flipped byte inside block 1: the content checksum catches it */
	mid = (names->block_off[1] + names->block_off[2]) / 2;
	saved = names->packed[mid];
	names->packed[mid] ^= 0x5a;
	for (size_t i = GU_SYMBOL_NAMES_PER_BLOCK; i < 2 * GU_SYMBOL_NAMES_PER_BLOCK; i++)
		if (gu_symbol_names_read(names, reader, i, &got) == 0)
			FAIL("ordinal %zu read from a corrupt block", i);
	/* the other blocks still read */
	if (gu_symbol_names_read(names, reader, 0, &got) != 0 ||
	    gu_symbol_names_read(names, reader, 2 * GU_SYMBOL_NAMES_PER_BLOCK, &got) != 0)
		FAIL("intact blocks fail next to a corrupt one");
	names->packed[mid] = saved;

	/* block 2 truncated by 3 bytes */
	saved_off = names->block_off[3];
	names->block_off[3] -= 3;
	if (gu_symbol_names_read(names, reader, 2 * GU_SYMBOL_NAMES_PER_BLOCK, &got) == 0)
		FAIL("truncated block read");
	names->block_off[3] = saved_off;

	/* a frame that decompresses but holds fewer names than the block should */
	{
		struct gu_symbol_names_builder *b = gu_symbol_names_builder_new();
		struct gu_symbol_names *few;

		gu_symbol_names_add(b, "only_one");
		few = gu_symbol_names_finish(b);
		few->name_count = 2;	/* claims a second name in the same block */
		if (gu_symbol_names_read(few, reader, 1, &got) == 0)
			FAIL("read a name the block does not hold");
		gu_symbol_names_free(few);
	}

	/* repaired data reads again with the same reader */
	if (check_all(names, reader, count) != 0)
		return 1;
	gu_symbol_names_free(names);
	gu_symbol_names_reader_free(reader);
	puts("symbol names corrupt and truncated data rejected ok");
	return 0;
}

/*
 * Build @body (assembly, or C if @c) into an executable at @dir/@name with
 * @ld_extra.
 */
static int build_src(const char *dir, const char *name, const char *body, bool c,
		     const char *ld_extra, char *elf_path, size_t len)
{
	char asm_path[PATH_MAX], cmd[PATH_MAX * 3];
	FILE *f;

	snprintf(asm_path, sizeof(asm_path), "%s/%s.%s", dir, name, c ? "c" : "s");
	snprintf(elf_path, len, "%s/%s", dir, name);
	f = fopen(asm_path, "w");
	if (!f || fputs(body, f) == EOF) {
		if (f)
			fclose(f);
		return -1;
	}
	fclose(f);
	snprintf(cmd, sizeof(cmd), "cc -O1 -nostdlib -no-pie %s -Wl,-e,f1 -o '%s' '%s'",
		 ld_extra, elf_path, asm_path);
	return system(cmd) == 0 ? 0 : -1;
}

static int build_asm(const char *dir, const char *name, const char *body,
		     const char *ld_extra, char *elf_path, size_t len)
{
	return build_src(dir, name, body, false, ld_extra, elf_path, len);
}

/* Three functions, any architecture: for what does not need CFI. */
static const char FUNCS_C[] =
	"void f1(void) {}\n"
	"void f2(volatile int *p) { *p = 2; }\n"
	"void f3(volatile int *p) { *p = 3; }\n";

/* f1 and f2: same code and CFI; f3: a different frame. */
static const char FUNCS_ASM[] =
	".text\n"
	".globl f1\n.type f1,@function\nf1:\n"
	"  .cfi_startproc\n  push %rbp\n  .cfi_def_cfa_offset 16\n  .cfi_offset %rbp, -16\n"
	"  mov %rsp, %rbp\n  .cfi_def_cfa_register %rbp\n  nop\n  pop %rbp\n"
	"  .cfi_def_cfa %rsp, 8\n  ret\n  .cfi_endproc\n.size f1, .-f1\n"
	".globl f2\n.type f2,@function\nf2:\n"
	"  .cfi_startproc\n  push %rbp\n  .cfi_def_cfa_offset 16\n  .cfi_offset %rbp, -16\n"
	"  mov %rsp, %rbp\n  .cfi_def_cfa_register %rbp\n  nop\n  pop %rbp\n"
	"  .cfi_def_cfa %rsp, 8\n  ret\n  .cfi_endproc\n.size f2, .-f2\n"
	".globl f3\n.type f3,@function\nf3:\n"
	"  .cfi_startproc\n  sub $24, %rsp\n  .cfi_def_cfa_offset 32\n  nop\n"
	"  add $24, %rsp\n  .cfi_def_cfa_offset 8\n  ret\n  .cfi_endproc\n.size f3, .-f3\n";

static struct gu_context *test_ctx(void)
{
	struct gu_init_cfg cfg = { 0 };
	struct gu_context *ctx;

	cfg.no_kernel_symbols = true;
	ctx = gu_init(&cfg);
	if (ctx)
		ctx->debug = true;
	return ctx;
}

/* The CFA rule at @pc: base register and offset. */
static int cfa_at(struct gu_cfi *cfi, uint64_t pc, uint64_t *reg, int64_t *off)
{
	Dwarf_Op *ops;
	int n;

	if (gu_cfi_parse_cfi_ex(cfi, pc, false, NULL) != 0)
		return -1;
	gu_cfi_get_ops(REG_TYPE_RSP, &ops, &n, true);
	if (n != 1 || ops[0].atom != DW_OP_bregx)
		return -1;
	*reg = ops[0].number;
	*off = (int64_t)ops[0].number2;
	return 0;
}

static int case_cfi_dedup(void)
{
	char dir[PATH_MAX] = "", elf[PATH_MAX];
	struct gu_context *ctx = NULL;
	struct per_elf_ctx *e;
	struct interval_array_item i1, i2, i3;
	uint64_t f1, f2, f3, reg;
	int64_t off;
	int ret = 1;

	if (make_work_dir(dir, sizeof(dir), "cfi") != 0 ||
	    build_asm(dir, "funcs", FUNCS_ASM, "-Wl,--build-id=sha1", elf, sizeof(elf)) != 0) {
		fprintf(stderr, "fixture\n");
		goto out;
	}
	f1 = resolve_symbol_addr(elf, "f1", 0);
	f2 = resolve_symbol_addr(elf, "f2", 0);
	f3 = resolve_symbol_addr(elf, "f3", 0);
	ctx = test_ctx();
	e = ctx ? load_elf(ctx, elf, getpid(), NULL) : NULL;
	if (!e || !e->gu_cfi || !e->gu_cfi->hdr_interval_array) {
		fprintf(stderr, "load %s\n", elf);
		goto out;
	}
	if (e->gu_cfi->hdr_interval_array->count != 3 || e->gu_cfi->body_count != 2) {
		fprintf(stderr, "%d FDEs, %lu bodies; want 3 and 2\n",
			e->gu_cfi->hdr_interval_array->count, e->gu_cfi->body_count);
		goto out;
	}
	if (gu_interval_array_search(e->gu_cfi->hdr_interval_array, f1, &i1) < 0 ||
	    gu_interval_array_search(e->gu_cfi->hdr_interval_array, f2, &i2) < 0 ||
	    gu_interval_array_search(e->gu_cfi->hdr_interval_array, f3, &i3) < 0) {
		fprintf(stderr, "FDE lookup\n");
		goto out;
	}
	/* hit: f1 and f2 share a body but keep their own ranges; miss: f3 */
	if (i1.private != i2.private || i1.private == i3.private ||
	    i1.start != f1 || i2.start != f2 || i3.start != f3) {
		fprintf(stderr, "sharing: f1 %p@%lx f2 %p@%lx f3 %p@%lx\n",
			i1.private, i1.start, i2.private, i2.start, i3.private, i3.start);
		goto out;
	}
	/* the shared body resolves against each FDE's own start */
	struct { uint64_t pc, reg; int64_t off; } want[] = {
		{ f1, 7, 8 }, { f1 + 1, 7, 16 }, { f1 + 4, 6, 16 },
		{ f2, 7, 8 }, { f2 + 1, 7, 16 }, { f2 + 4, 6, 16 },
		{ f3, 7, 8 }, { f3 + 4, 7, 32 },
	};
	for (size_t k = 0; k < sizeof(want) / sizeof(want[0]); k++) {
		if (cfa_at(e->gu_cfi, want[k].pc, &reg, &off) != 0 ||
		    reg != want[k].reg || off != want[k].off) {
			fprintf(stderr, "pc %lx: CFA reg %lu off %ld, want %lu %ld\n",
				want[k].pc, reg, off, want[k].reg, want[k].off);
			goto out;
		}
	}
	puts("cfi bodies shared by identical FDEs only ok");
	ret = 0;
out:
	gu_cleanup(ctx);
	remove_work_dir(dir);
	return ret;
}

/*
 * Without a build-id, an ELF's identity is the MD5 of its first 2 MiB and
 * its base name (gu_calculate_md5()): the same bytes under the same name
 * share one context wherever they live, another name or other bytes in the
 * first 2 MiB do not.  Bytes past 2 MiB are not hashed: two such files
 * that differ only there would share one context.
 */
static int case_buildid_fallback(void)
{
	char dir[PATH_MAX] = "", a[PATH_MAX], cmd[PATH_MAX * 6];
	char same[PATH_MAX], renamed[PATH_MAX], changed[PATH_MAX];
	struct gu_context *ctx = NULL;
	struct per_elf_ctx *ea, *es, *er, *ec;
	int ret = 1;

	if (make_work_dir(dir, sizeof(dir), "noid") != 0 ||
	    build_src(dir, "prog", FUNCS_C, true, "-Wl,--build-id=none", a, sizeof(a)) != 0) {
		fprintf(stderr, "fixture\n");
		goto out;
	}
	snprintf(same, sizeof(same), "%s/d1/prog", dir);
	snprintf(renamed, sizeof(renamed), "%s/d2/other", dir);
	snprintf(changed, sizeof(changed), "%s/d3/prog", dir);
	snprintf(cmd, sizeof(cmd),
		 "mkdir '%s/d1' '%s/d2' '%s/d3' && cp '%s' '%s' && cp '%s' '%s' && "
		 "cp '%s' '%s' && printf x >> '%s'",
		 dir, dir, dir, a, same, a, renamed, a, changed, changed);
	if (system(cmd) != 0) {
		fprintf(stderr, "copies\n");
		goto out;
	}
	ctx = test_ctx();
	ea = ctx ? load_elf(ctx, a, getpid(), NULL) : NULL;
	es = ctx ? load_elf(ctx, same, getpid(), NULL) : NULL;
	er = ctx ? load_elf(ctx, renamed, getpid(), NULL) : NULL;
	ec = ctx ? load_elf(ctx, changed, getpid(), NULL) : NULL;
	if (!ea || !es || !er || !ec) {
		fprintf(stderr, "load\n");
		goto out;
	}
	if (ea->build_id_len != MD5_DIGEST_LENGTH) {
		fprintf(stderr, "identity is %d bytes, not the MD5 fallback\n", ea->build_id_len);
		goto out;
	}
	if (es != ea || ea->refcnt != 2) {
		fprintf(stderr, "same bytes, same name, another file: %p %p refcnt %lu\n",
			(void *)ea, (void *)es, ea->refcnt);
		goto out;
	}
	if (er == ea || ec == ea || ec == er) {
		fprintf(stderr, "another name or other bytes share a context\n");
		goto out;
	}
	puts("elf without build-id keyed by its first 2 MiB and name ok");
	ret = 0;
out:
	gu_cleanup(ctx);
	remove_work_dir(dir);
	return ret;
}

static int case_symbol_name_failure(void)
{
	char dir[PATH_MAX] = "", elf[PATH_MAX];
	struct gu_context *ctx = NULL;
	struct per_elf_ctx *e;
	struct gu_statistics st;
	uint64_t f1;
	char *sym = NULL;
	size_t mid;
	char saved;
	int ret = 1;

	if (make_work_dir(dir, sizeof(dir), "fail") != 0 ||
	    build_src(dir, "funcs", FUNCS_C, true, "-Wl,--build-id=sha1", elf, sizeof(elf)) != 0) {
		fprintf(stderr, "fixture\n");
		goto out;
	}
	f1 = resolve_symbol_addr(elf, "f1", 0);
	ctx = test_ctx();
	e = ctx ? load_elf(ctx, elf, getpid(), NULL) : NULL;
	if (!e || !e->symbol_names) {
		fprintf(stderr, "load\n");
		goto out;
	}
	mid = (e->symbol_names->block_off[0] + e->symbol_names->block_off[1]) / 2;
	saved = e->symbol_names->packed[mid];
	e->symbol_names->packed[mid] ^= 0x5a;

	/* fails like a symbol without a name, counted per ELF and per context */
	for (int k = 1; k <= 2; k++) {
		if (gu_lookup_elf_symbol(e, f1, &sym, NULL) != -1 || sym) {
			fprintf(stderr, "corrupt name resolved: %s\n", sym ? sym : "?");
			goto out;
		}
		gu_copy_statistics(ctx, &st);
		if (e->symbol_name_read_failures != (uint64_t)k ||
		    st.symbol_name_read_failures != (uint64_t)k) {
			fprintf(stderr, "after %d failures: elf %lu ctx %lu\n", k,
				e->symbol_name_read_failures, st.symbol_name_read_failures);
			goto out;
		}
	}
	/* nothing was cached: once the data reads, the name comes back */
	e->symbol_names->packed[mid] = saved;
	if (gu_lookup_elf_symbol(e, f1, &sym, NULL) != 1 || !sym || strcmp(sym, "f1") != 0) {
		fprintf(stderr, "repaired lookup: %s\n", sym ? sym : "(null)");
		goto out;
	}
	puts("symbol name read failures counted ok");
	ret = 0;
out:
	gu_cleanup(ctx);
	remove_work_dir(dir);
	return ret;
}

/*
 * A return address right past the end of f1 (a call as its last
 * instruction) is f2's first byte: the caller frame is f1's, looked up one
 * byte earlier.  With f1's name unreadable the frame has no name, counted
 * once; it does not fall back to f2+0.
 */
static int case_symbol_name_failure_frame(void)
{
	char dir[PATH_MAX] = "", elf[PATH_MAX];
	struct gu_context *ctx = NULL;
	struct per_elf_ctx *e;
	uint64_t f2, off = 0;
	char *sym = NULL;
	size_t mid;
	int ret = 1;

	if (make_work_dir(dir, sizeof(dir), "failframe") != 0 ||
	    build_asm(dir, "funcs", FUNCS_ASM, "-Wl,--build-id=sha1", elf, sizeof(elf)) != 0) {
		fprintf(stderr, "fixture\n");
		goto out;
	}
	f2 = resolve_symbol_addr(elf, "f2", 0);
	ctx = test_ctx();
	e = ctx ? load_elf(ctx, elf, getpid(), NULL) : NULL;
	if (!e || !e->symbol_names ||
	    gu_lookup_elf_symbol(e, f2 - 1, &sym, NULL) != 1 || strcmp(sym, "f1") != 0) {
		fprintf(stderr, "load: f2 - 1 must be in f1\n");
		goto out;
	}
	/* the names are read once and kept: a fresh context reads them again */
	gu_cleanup(ctx);
	ctx = test_ctx();
	e = ctx ? load_elf(ctx, elf, getpid(), NULL) : NULL;
	if (!e || !e->symbol_names) {
		fprintf(stderr, "reload\n");
		goto out;
	}
	mid = (e->symbol_names->block_off[0] + e->symbol_names->block_off[1]) / 2;
	e->symbol_names->packed[mid] ^= 0x5a;
	sym = NULL;
	if (gu_lookup_frame_symbol(e, f2, f2 - 1, &sym, &off) || sym ||
	    e->symbol_name_read_failures != 1) {
		fprintf(stderr, "caller frame: %s+%lu, %lu failures; want no name, 1\n",
			sym ? sym : "(none)", off, e->symbol_name_read_failures);
		goto out;
	}
	puts("unreadable caller name not taken from the next symbol ok");
	ret = 0;
out:
	gu_cleanup(ctx);
	remove_work_dir(dir);
	return ret;
}

/*
 * A CIE whose CFA rule is an expression, in a hand-written .debug_frame
 * (the assembler's .cfi_* directives put expressions in the FDE): every
 * FDE of the CIE starts with the CIE's decoded rules, whose expression is
 * an address in the instruction pool, which moves when the load finishes.
 */
static const char CIE_EXPR_ASM[] =
	".text\n.globl f1\n.type f1,@function\nf1:\n  nop\n  ret\nf1_end:\n.size f1, .-f1\n"
	".section .debug_frame,\"\",@progbits\n"
	"cie:\n  .long cie_end - cie_start\ncie_start:\n"
	"  .long 0xffffffff\n  .byte 1\n  .string \"\"\n"
	"  .uleb128 1\n  .sleb128 -8\n  .byte 16\n"
	/* DW_CFA_def_cfa_expression { DW_OP_breg7 (rsp) 8 } */
	"  .byte 0x0f\n  .uleb128 2\n  .byte 0x77\n  .sleb128 8\n"
	/* DW_CFA_offset r16 (rip) at CFA-8 */
	"  .byte 0x90\n  .uleb128 1\n"
	"  .balign 8\ncie_end:\n"
	"fde:\n  .long fde_end - fde_start\nfde_start:\n"
	"  .long cie\n  .quad f1\n  .quad f1_end - f1\n"
	"  .balign 8\nfde_end:\n";

static int case_cfi_cie_expression(void)
{
	char dir[PATH_MAX] = "", elf[PATH_MAX];
	struct gu_context *ctx = NULL;
	struct per_elf_ctx *e;
	Dwarf_Op *ops;
	void *junk[64];
	uint64_t f1;
	int n, ret = 1;

	if (make_work_dir(dir, sizeof(dir), "cieexpr") != 0 ||
	    build_asm(dir, "cieexpr", CIE_EXPR_ASM, "-Wl,--build-id=sha1", elf, sizeof(elf)) != 0) {
		fprintf(stderr, "fixture\n");
		goto out;
	}
	f1 = resolve_symbol_addr(elf, "f1", 0);
	ctx = test_ctx();
	e = ctx ? load_elf(ctx, elf, getpid(), NULL) : NULL;
	if (!e || !e->gu_cfi) {
		fprintf(stderr, "load\n");
		goto out;
	}
	/* reuse what the load freed, so a stale pointer reads garbage */
	for (int i = 0; i < 64; i++)
		memset(junk[i] = malloc(4096), 0xa5, 4096);
	for (uint64_t pc = f1; pc < f1 + 2; pc++) {
		if (gu_cfi_parse_cfi_ex(e->gu_cfi, pc, false, NULL) != 0) {
			fprintf(stderr, "no CFI at %lx\n", pc);
			goto free_junk;
		}
		gu_cfi_get_ops(REG_TYPE_RSP, &ops, &n, true);
		if (n != 1 || ops[0].atom != DW_OP_breg7 || ops[0].number != 8) {
			fprintf(stderr, "pc %lx: CFA %d ops, atom %#x number %lu; want breg7 8\n",
				pc, n, n ? ops[0].atom : 0, n ? (unsigned long)ops[0].number : 0);
			goto free_junk;
		}
	}
	puts("cfi cie expression survives the pool move ok");
	ret = 0;
free_junk:
	for (int i = 0; i < 64; i++)
		free(junk[i]);
out:
	gu_cleanup(ctx);
	remove_work_dir(dir);
	return ret;
}

/*
 * A CIE without initial instructions takes no room in the instruction pool:
 * the body of its first FDE lands at the CIE's own address.  The FDE's
 * DW_CFA_restore must still restore the CIE's rule, in f1 and in f2, which
 * shares f1's body.  Each pushes rbp (CFA-16) after one byte and restores
 * it after two.
 */
static const char EMPTY_CIE_FDE[] =
	"  .long 0f - 1f\n1:\n  .long cie\n  .quad %s\n  .quad %s_end - %s\n"
	"  .byte 0x0c\n  .uleb128 7\n  .uleb128 8\n"	/* def_cfa rsp 8 */
	"  .byte 0x90\n  .uleb128 1\n"			/* rip at CFA-8 */
	"  .byte 0x41\n  .byte 0x86\n  .uleb128 2\n"	/* +1: rbp at CFA-16 */
	"  .byte 0x41\n  .byte 0xc6\n0:\n";		/* +1: restore rbp */

static int case_cfi_empty_cie_restore(void)
{
	char dir[PATH_MAX] = "", elf[PATH_MAX], src[2048];
	struct gu_context *ctx = NULL;
	struct per_elf_ctx *e;
	Dwarf_Op *ops;
	int n, len, ret = 1;

	len = snprintf(src, sizeof(src),
		       ".text\n"
		       ".globl f1\n.type f1,@function\nf1:\n  nop\n  nop\n  nop\n  ret\nf1_end:\n"
		       ".globl f2\n.type f2,@function\nf2:\n  nop\n  nop\n  nop\n  ret\nf2_end:\n"
		       ".section .debug_frame,\"\",@progbits\n"
		       "cie:\n  .long cie_end - cie_start\ncie_start:\n"
		       "  .long 0xffffffff\n  .byte 1\n  .string \"\"\n"
		       "  .uleb128 1\n  .sleb128 -8\n  .byte 16\ncie_end:\n");
	len += snprintf(src + len, sizeof(src) - len, EMPTY_CIE_FDE, "f1", "f1", "f1");
	snprintf(src + len, sizeof(src) - len, EMPTY_CIE_FDE, "f2", "f2", "f2");
	if (make_work_dir(dir, sizeof(dir), "emptycie") != 0 ||
	    build_asm(dir, "emptycie", src, "-Wl,--build-id=sha1", elf, sizeof(elf)) != 0) {
		fprintf(stderr, "fixture\n");
		goto out;
	}
	ctx = test_ctx();
	e = ctx ? load_elf(ctx, elf, getpid(), NULL) : NULL;
	if (!e || !e->gu_cfi || e->gu_cfi->body_count != 1) {
		fprintf(stderr, "load: want one body shared by f1 and f2\n");
		goto out;
	}
	for (int f = 0; f < 2; f++) {
		uint64_t start = resolve_symbol_addr(elf, f ? "f2" : "f1", 0);

		for (uint64_t pc = start + 1; pc <= start + 2; pc++) {
			bool want_saved = pc == start + 1;

			if (gu_cfi_parse_cfi_ex(e->gu_cfi, pc, false, NULL) != 0) {
				fprintf(stderr, "no CFI at %lx\n", pc);
				goto out;
			}
			gu_cfi_get_ops(REG_TYPE_RBP, &ops, &n, false);
			if ((n != 0) != want_saved) {
				fprintf(stderr, "f%d+%lu: rbp has %d ops, want %s\n", f + 1,
					pc - start, n, want_saved ? "the saved slot" : "the CIE's rule");
				goto out;
			}
		}
	}
	puts("cfi restore after an empty cie ok");
	ret = 0;
out:
	gu_cleanup(ctx);
	remove_work_dir(dir);
	return ret;
}

/*
 * An allocation that fails while the CFI table is built fails the whole
 * CFI: a table missing FDEs must not be cached as the ELF's CFI.  1500
 * functions with distinct frames need the body array to grow past its
 * first 1024 entries (struct gu_cfi_build_body, 24 bytes each).
 */
static int case_cfi_alloc_failure(void)
{
	char dir[PATH_MAX] = "", elf[PATH_MAX];
	struct gu_context *ctx = NULL;
	struct per_elf_ctx *e;
	size_t cap = 1 << 20, len = 0;
	char *src = malloc(cap);
	int ret = 1;

	if (!src)
		FAIL("oom");
	len += snprintf(src + len, cap - len, ".text\n");
	for (int i = 0; i < 1500; i++)
		len += snprintf(src + len, cap - len,
				".globl f%d\n.type f%d,@function\nf%d:\n  .cfi_startproc\n"
				"  sub $%d, %%rsp\n  .cfi_def_cfa_offset %d\n  add $%d, %%rsp\n"
				"  .cfi_def_cfa_offset 8\n  ret\n  .cfi_endproc\n",
				i + 1, i + 1, i + 1, 8 * (i + 1), 8 * (i + 2), 8 * (i + 1));
	if (make_work_dir(dir, sizeof(dir), "cfioom") != 0 ||
	    build_asm(dir, "many", src, "-Wl,--build-id=sha1", elf, sizeof(elf)) != 0) {
		fprintf(stderr, "fixture\n");
		goto out;
	}

	ctx = test_ctx();
	/* the growth of the body array past its first 1024 entries */
	fail_realloc_size = 2048 * sizeof(struct gu_cfi_build_body);
	e = ctx ? load_elf(ctx, elf, getpid(), NULL) : NULL;
	fail_realloc_size = 0;
	if (!e) {
		fprintf(stderr, "load\n");
		goto out;
	}
	if (fail_realloc_hits != 1) {
		fprintf(stderr, "the body array growth failed %d times, want 1\n",
			fail_realloc_hits);
		goto out;
	}
	if (e->gu_cfi) {
		fprintf(stderr, "a failed allocation left %d of 1500 FDEs as the CFI\n",
			e->gu_cfi->hdr_interval_array ? e->gu_cfi->hdr_interval_array->count : 0);
		goto out;
	}
	gu_cleanup(ctx);

	/* without the failure: the whole table */
	ctx = test_ctx();
	e = ctx ? load_elf(ctx, elf, getpid(), NULL) : NULL;
	if (!e || !e->gu_cfi || e->gu_cfi->hdr_interval_array->count != 1500 ||
	    e->gu_cfi->body_count != 1500) {
		fprintf(stderr, "full load: %d FDEs, %lu bodies\n",
			e && e->gu_cfi ? e->gu_cfi->hdr_interval_array->count : -1,
			e && e->gu_cfi ? e->gu_cfi->body_count : 0);
		goto out;
	}
	puts("cfi allocation failure fails the whole table ok");
	ret = 0;
out:
	free(src);
	gu_cleanup(ctx);
	remove_work_dir(dir);
	return ret;
}

/* ---- lookups from several threads ---- */

#define LOOKUP_THREADS 8

struct ref_sym {
	uint64_t addr;
	char *name;
};

static char self_path[PATH_MAX];
static struct ref_sym *refs;
static size_t ref_count;
static struct gu_context *shared_ctx;
static struct per_elf_ctx *shared_elf;
static int lookup_errors;

static int collect_refs(void)
{
	struct gu_context *ctx = test_ctx();
	struct per_elf_ctx *e = ctx ? load_elf(ctx, self_path, getpid(), NULL) : NULL;
	struct interval_array *s;

	if (!e || !e->symbols)
		return -1;
	s = e->symbols;
	refs = calloc(s->count, sizeof(*refs));
	for (int i = 0; refs && i < s->count; i++) {
		uint64_t addr = s->type == INTERVAL_ARRAY_TYPE_U32 ?
			s->items_u32[i].start : s->items_u64[i].start;
		char *sym = NULL;

		if (gu_lookup_elf_symbol(e, addr, &sym, NULL) == 1) {
			refs[ref_count].addr = addr;
			refs[ref_count].name = strdup(sym);
			ref_count++;
		}
	}
	gu_cleanup(ctx);
	return ref_count > 100 ? 0 : -1;
}

/* Each thread its own context: the unwind-worker model. */
static void *own_ctx_thread(void *arg)
{
	size_t seed = (size_t)arg;
	struct gu_context *ctx = test_ctx();
	struct per_elf_ctx *e = ctx ? load_elf(ctx, self_path, getpid(), NULL) : NULL;

	for (size_t k = 0; e && k < ref_count; k++) {
		size_t i = (k * 7919 + seed * 104729) % ref_count;
		char *sym = NULL;

		if (gu_lookup_elf_symbol(e, refs[i].addr, &sym, NULL) != 1 ||
		    strcmp(sym, refs[i].name) != 0)
			__atomic_add_fetch(&lookup_errors, 1, __ATOMIC_RELAXED);
	}
	if (!e)
		__atomic_add_fetch(&lookup_errors, 1, __ATOMIC_RELAXED);
	gu_cleanup(ctx);
	return NULL;
}

/* All threads on one context, under its lock: like gu_unwind(). */
static void *shared_ctx_thread(void *arg)
{
	size_t seed = (size_t)arg;

	for (size_t k = 0; k < ref_count; k++) {
		size_t i = (k * 6007 + seed * 7727) % ref_count;
		char *sym = NULL;
		int bad;

		pthread_mutex_lock(&shared_ctx->lock);
		bad = gu_lookup_elf_symbol(shared_elf, refs[i].addr, &sym, NULL) != 1 ||
		      !sym || strcmp(sym, refs[i].name) != 0;
		pthread_mutex_unlock(&shared_ctx->lock);
		if (bad)
			__atomic_add_fetch(&lookup_errors, 1, __ATOMIC_RELAXED);
	}
	return NULL;
}

static int run_threads(void *(*fn)(void *))
{
	pthread_t t[LOOKUP_THREADS];

	for (size_t i = 0; i < LOOKUP_THREADS; i++)
		if (pthread_create(&t[i], NULL, fn, (void *)(i + 1)) != 0)
			return -1;
	for (size_t i = 0; i < LOOKUP_THREADS; i++)
		pthread_join(t[i], NULL);
	return 0;
}

static const char *case_arg;

/* Optional argument: an ELF with many symbols (default: this program). */
static int case_concurrent_lookup(void)
{
	if (case_arg) {
		snprintf(self_path, sizeof(self_path), "%s", case_arg);
	} else {
		ssize_t n = readlink("/proc/self/exe", self_path, sizeof(self_path) - 1);

		if (n <= 0)
			FAIL("readlink");
		self_path[n] = '\0';
	}
	if (collect_refs() != 0)
		FAIL("reference symbols of %s", self_path);

	if (run_threads(own_ctx_thread) != 0 || lookup_errors)
		FAIL("one context per thread: %d wrong lookups", lookup_errors);

	shared_ctx = test_ctx();
	shared_elf = shared_ctx ? load_elf(shared_ctx, self_path, getpid(), NULL) : NULL;
	if (!shared_elf)
		FAIL("shared load");
	if (run_threads(shared_ctx_thread) != 0 || lookup_errors)
		FAIL("shared context: %d wrong lookups", lookup_errors);
	gu_cleanup(shared_ctx);

	printf("concurrent symbol lookups ok (%zu symbols, %d threads)\n",
	       ref_count, LOOKUP_THREADS);
	return 0;
}

int main(int argc, char **argv)
{
	static const struct {
		const char *name;
		int (*fn)(void);
	} cases[] = {
		{ "names-roundtrip", case_names_roundtrip },
		{ "names-corrupt", case_names_corrupt },
		{ "symbol-name-failure", case_symbol_name_failure },
		{ "symbol-name-failure-frame", case_symbol_name_failure_frame },
		{ "cfi-dedup", case_cfi_dedup },
		{ "cfi-cie-expression", case_cfi_cie_expression },
		{ "cfi-empty-cie-restore", case_cfi_empty_cie_restore },
		{ "cfi-alloc-failure", case_cfi_alloc_failure },
		{ "buildid-fallback", case_buildid_fallback },
		{ "concurrent-lookup", case_concurrent_lookup },
	};

	if (argc == 3)
		case_arg = argv[2];
	for (size_t i = 0; argc >= 2 && argc <= 3 && i < sizeof(cases) / sizeof(cases[0]); i++)
		if (strcmp(argv[1], cases[i].name) == 0)
			return cases[i].fn();
	fprintf(stderr, "usage: %s <", argv[0]);
	for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
		fprintf(stderr, "%s%s", i ? "|" : "", cases[i].name);
	fprintf(stderr, ">\n");
	return 2;
}
