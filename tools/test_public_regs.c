/* SPDX-License-Identifier: LGPL-3.0-or-later */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <stdlib.h>
#include <unistd.h>

#include "gunwinder/unwinder.h"
#include "../src/gu_unwinder.h"

#if defined(GUNWINDER_X86)
#define TEST_PC_REG reg_name_rip
#define TEST_SP_REG reg_name_rsp
#define TEST_BP_REG reg_name_rbp
#define TEST_CALLEE_REG reg_name_r12
#define TEST_NATIVE_ARCH GU_ARCH_X86_64
#define TEST_MISMATCH_ARCH GU_ARCH_ARM64
#elif defined(GUNWINDER_ARM64)
#define TEST_PC_REG reg_name_pc
#define TEST_SP_REG reg_name_sp
#define TEST_BP_REG reg_name_x29
#define TEST_CALLEE_REG reg_name_x19
#define TEST_NATIVE_ARCH GU_ARCH_ARM64
#define TEST_MISMATCH_ARCH GU_ARCH_X86_64
#else
#error Unsupported test architecture
#endif

static int failures;

static void expect_true(const char *name, bool ok)
{
	if (!ok) {
		fprintf(stderr, "%s: expected true\n", name);
		failures++;
	}
}

static void expect_false(const char *name, bool ok)
{
	if (ok) {
		fprintf(stderr, "%s: expected false\n", name);
		failures++;
	}
}

static void expect_int(const char *name, int actual, int expected)
{
	if (actual != expected) {
		fprintf(stderr, "%s: expected %d got %d\n", name, expected, actual);
		failures++;
	}
}

static void expect_u64(const char *name, uint64_t actual, uint64_t expected)
{
	if (actual != expected) {
		fprintf(stderr, "%s: expected 0x%llx got 0x%llx\n", name,
			(unsigned long long)expected, (unsigned long long)actual);
		failures++;
	}
}

static void test_public_helpers(void)
{
	struct gu_regs regs;
	uint64_t value = 0;

	memset(&regs, 0xa5, sizeof(regs));
	gu_regs_init(&regs, GU_ARCH_NATIVE);
	expect_u64("init size", regs.size, sizeof(regs));
	expect_u64("init version", regs.version, GU_REGS_VERSION);
	expect_u64("init arch", regs.arch, TEST_NATIVE_ARCH);
	expect_u64("init mask", regs.valid_mask, 0);

	expect_true("set pc", gu_regs_set(&regs, TEST_PC_REG, 0x1111222233334444ULL));
	expect_true("get pc", gu_regs_get(&regs, TEST_PC_REG, &value));
	expect_u64("get pc value", value, 0x1111222233334444ULL);
	expect_true("valid mask bit", (regs.valid_mask & (1ULL << TEST_PC_REG)) != 0);

	expect_false("get unset register", gu_regs_get(&regs, TEST_SP_REG, &value));
	expect_false("set out of range",
		     gu_regs_set(&regs, GU_REGS_MAX_DWARF_REGS, 1));
	expect_false("get out of range",
		     gu_regs_get(&regs, GU_REGS_MAX_DWARF_REGS, &value));
	expect_false("set null", gu_regs_set(NULL, TEST_PC_REG, 1));
	expect_false("get null regs", gu_regs_get(NULL, TEST_PC_REG, &value));
	expect_false("get null value", gu_regs_get(&regs, TEST_PC_REG, NULL));

	regs.size = sizeof(regs) - 1;
	expect_false("set invalid size", gu_regs_set(&regs, TEST_PC_REG, 1));
	regs.size = sizeof(regs);
	regs.version = GU_REGS_VERSION + 1;
	expect_false("get invalid version", gu_regs_get(&regs, TEST_PC_REG, &value));
}

static void test_native_arch_normalized(void)
{
	struct gu_regs regs;

	gu_regs_init(&regs, GU_ARCH_NATIVE);
	expect_u64("native arch normalized", regs.arch, TEST_NATIVE_ARCH);
}

static void test_stack_info_set_regs(void)
{
	struct gu_stack_info info = { 0 };
	struct gu_regs regs;

	gu_regs_init(&regs, GU_ARCH_NATIVE);
	gu_stack_info_set_regs(&info, &regs);
	expect_true("stack info regs pointer", info.regs == &regs);
	expect_u64("stack info regs size", info.regs_size, sizeof(regs));
}

static void test_normalized_internal_path(void)
{
	struct gu_stack_info info = { 0 };
	struct gu_regs regs;
	uint64_t value = 0;

	gu_regs_init(&regs, TEST_NATIVE_ARCH);
	gu_stack_info_set_regs(&info, &regs);

	expect_true("write pc", write_regs(&info, TEST_PC_REG, 0x1010));
	expect_true("write sp", write_regs(&info, TEST_SP_REG, 0x2020));
	expect_true("write bp", write_regs(&info, TEST_BP_REG, 0x3030));
	expect_true("write callee", write_regs(&info, TEST_CALLEE_REG, 0x4040));

	expect_true("read pc", get_regs(&info, TEST_PC_REG, &value));
	expect_u64("read pc value", value, 0x1010);
	expect_true("read sp", get_regs(&info, TEST_SP_REG, &value));
	expect_u64("read sp value", value, 0x2020);
	expect_true("read bp", get_regs(&info, TEST_BP_REG, &value));
	expect_u64("read bp value", value, 0x3030);
	expect_true("read callee", get_regs(&info, TEST_CALLEE_REG, &value));
	expect_u64("read callee value", value, 0x4040);
}

static void test_arch_mismatch_rejected(void)
{
	struct gu_stack_info info = { 0 };
	struct gu_regs regs;
	uint64_t value = 0;

	gu_regs_init(&regs, TEST_MISMATCH_ARCH);
	gu_stack_info_set_regs(&info, &regs);

	expect_false("mismatch write rejected",
		     write_regs(&info, TEST_PC_REG, 0x1010));
	expect_false("mismatch read rejected", get_regs(&info, TEST_PC_REG, &value));
}

static void test_legacy_bounds_checks(void)
{
	struct gu_stack_info info = { 0 };
	uint64_t legacy_regs[64] = { 0 };
	uint64_t value = 0;

	info.regs = legacy_regs;
	info.regs_size = 0;
	expect_false("legacy read zero size", get_regs(&info, TEST_PC_REG, &value));
	expect_false("legacy write zero size", write_regs(&info, TEST_PC_REG, 1));
}

static char *find_dump_path(const char *dir)
{
	DIR *dp;
	struct dirent *entry;
	char *path = NULL;

	dp = opendir(dir);
	if (!dp)
		return NULL;

	while ((entry = readdir(dp)) != NULL) {
		size_t name_len = strlen(entry->d_name);
		size_t dir_len;

		if (name_len < strlen(".dump.v2"))
			continue;
		if (strcmp(entry->d_name + name_len - strlen(".dump.v2"),
			   ".dump.v2") != 0)
			continue;

		dir_len = strlen(dir);
		path = malloc(dir_len + 1 + name_len + 1);
		if (!path)
			break;
		snprintf(path, dir_len + 1 + name_len + 1, "%s/%s", dir,
			 entry->d_name);
		break;
	}

	closedir(dp);
	return path;
}

static void free_stack_dump(struct gu_stack_info *info)
{
	if (!info)
		return;

	free(info->regs);
	free(info->stack_data);
	free(info);
}

static void test_debug_dump_preserves_public_regs(void)
{
	char template[] = "/tmp/gu-public-regs-XXXXXX";
	char *dir;
	char *dump_path;
	struct gu_stack_info info = { 0 };
	struct gu_stack_info *read_info;
	struct gu_regs regs;
	struct gu_regs *read_regs;
	uint8_t stack_data[16] = { 0x31, 0x32, 0x33, 0x34 };

	dir = mkdtemp(template);
	if (!dir) {
		perror("mkdtemp");
		failures++;
		return;
	}

	gu_regs_init(&regs, GU_ARCH_NATIVE);
	expect_true("dump set pc", gu_regs_set(&regs, TEST_PC_REG,
					       0xabcddcba11223344ULL));
	expect_true("dump set sp", gu_regs_set(&regs, TEST_SP_REG,
					       0x1020304050607080ULL));

	info.pid = getpid();
	info.stack_size = sizeof(stack_data);
	info.stack_data = stack_data;
	info.ustack_fp_level = 2;
	info.ustack_fp[0] = 0x1111;
	info.ustack_fp[1] = 0x2222;
	gu_stack_info_set_regs(&info, &regs);

	gu_debug_dump_sample(&info, dir, false);
	dump_path = find_dump_path(dir);
	expect_true("dump file created", dump_path != NULL);
	if (!dump_path)
		goto out_rmdir;

	read_info = gu_read_stack_dump(dump_path);
	expect_true("read public regs dump", read_info != NULL);
	if (!read_info)
		goto out_unlink;

	expect_u64("dump regs size", read_info->regs_size, sizeof(regs));
	read_regs = (struct gu_regs *)read_info->regs;
	if (read_info->regs_size >= sizeof(regs))
		expect_int("dump regs content",
			   memcmp(read_regs, &regs, sizeof(regs)), 0);
	else
		expect_true("dump regs content not truncated", false);
	expect_u64("dump stack size", read_info->stack_size, sizeof(stack_data));
	expect_int("dump stack content",
		   memcmp(read_info->stack_data, stack_data, sizeof(stack_data)), 0);
	expect_u64("dump fp level", read_info->ustack_fp_level, 2);
	expect_u64("dump fp 0", read_info->ustack_fp[0], 0x1111);
	expect_u64("dump fp 1", read_info->ustack_fp[1], 0x2222);

	free_stack_dump(read_info);
out_unlink:
	unlink(dump_path);
	free(dump_path);
out_rmdir:
	rmdir(dir);
}

int main(void)
{
	test_public_helpers();
	test_native_arch_normalized();
	test_stack_info_set_regs();
	test_normalized_internal_path();
	test_arch_mismatch_rejected();
	test_legacy_bounds_checks();
	test_debug_dump_preserves_public_regs();

	if (failures)
		return 1;

	puts("public register snapshot tests ok");
	return 0;
}
