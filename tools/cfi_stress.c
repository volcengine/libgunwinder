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
#include <unistd.h>

#include "../src/gu_cfi_helper.h"
#include "../src/gu_interval_array.h"
#include "../src/gu_unwinder.h"

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#define TEST_STACK_SIZE 8192
#define TEST_REGISTER_COPY_VALUE 0x123456789abcdef0ULL
#define TEST_DW_REG3 ((enum reg_name)3)
#define TEST_DW_REG12 ((enum reg_name)12)

struct eval_fixture {
	struct gu_stack_info info;
	struct pt_regs regs;
	uint8_t stack[TEST_STACK_SIZE];
	uint64_t raw_sp;
	uint64_t stack_base;
};

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

struct test_case {
	const char *name;
	int (*run)(void);
};

static void init_eval_fixture(struct eval_fixture *fx)
{
	memset(fx, 0, sizeof(*fx));
	fx->raw_sp = 0x70000120ULL;
	fx->stack_base = fx->raw_sp - (fx->raw_sp % (uint64_t)getpagesize());

	fx->info.pid = getpid();
	fx->info.unique_id = 1;
	fx->info.regs = &fx->regs;
	fx->info.regs_size = sizeof(fx->regs);
	fx->info.stack_data = fx->stack;
	fx->info.stack_size = sizeof(fx->stack);

	write_regs(&fx->info, reg_name_rsp, fx->raw_sp);
	write_regs(&fx->info, reg_name_rbp, fx->raw_sp + 0xe0);
	write_regs(&fx->info, TEST_DW_REG3, TEST_REGISTER_COPY_VALUE);
	write_regs(&fx->info, TEST_DW_REG12, 0x70000300ULL);
}

static void write_stack_u64(struct eval_fixture *fx, uint64_t addr, uint64_t value)
{
	uint64_t off = addr - fx->stack_base;

	if (off + sizeof(value) > sizeof(fx->stack)) {
		fprintf(stderr, "stack write out of range: addr=0x%" PRIx64 "\n", addr);
		exit(2);
	}
	memcpy(&fx->stack[off], &value, sizeof(value));
}

static int expect_ops_value(const char *name, const Dwarf_Op *ops, size_t nops,
			    uint64_t bias, uint64_t expected)
{
	struct eval_fixture fx;
	uint64_t actual = 0;

	init_eval_fixture(&fx);
	if (!gu_dwarf_ops_eval(NULL, ops, nops, &actual, bias, fx.raw_sp, &fx.info)) {
		fprintf(stderr, "%s: expression evaluation failed\n", name);
		return 1;
	}
	if (actual != expected) {
		fprintf(stderr, "%s: expected 0x%" PRIx64 ", got 0x%" PRIx64 "\n",
			name, expected, actual);
		return 1;
	}

	return 0;
}

static int test_expr_literal_arithmetic(void)
{
	const Dwarf_Op ops[] = {
		{ .atom = DW_OP_lit10 },
		{ .atom = DW_OP_lit3 },
		{ .atom = DW_OP_minus },
		{ .atom = DW_OP_constu, .number = 4 },
		{ .atom = DW_OP_plus },
		{ .atom = DW_OP_addr, .number = 0x20 },
		{ .atom = DW_OP_constu, .number = 0x1000 },
		{ .atom = DW_OP_minus },
		{ .atom = DW_OP_plus },
	};

	return expect_ops_value("expr_literal_arithmetic", ops, ARRAY_SIZE(ops),
				0x1000, 0x2b);
}

static int test_expr_register_base(void)
{
	struct eval_fixture fx;
	const Dwarf_Op ops[] = {
		{ .atom = DW_OP_bregx, .number = reg_name_rbp, .number2 = -0x20 },
		{ .atom = DW_OP_regx, .number = reg_name_rsp },
		{ .atom = DW_OP_minus },
		{ .atom = DW_OP_breg12, .number = 0x10 },
		{ .atom = DW_OP_constu, .number = 0x70000310ULL },
		{ .atom = DW_OP_eq },
		{ .atom = DW_OP_plus },
	};
	uint64_t actual = 0;

	init_eval_fixture(&fx);
	if (!gu_dwarf_ops_eval(NULL, ops, ARRAY_SIZE(ops), &actual, 0, fx.raw_sp,
			       &fx.info)) {
		fprintf(stderr, "expr_register_base: expression evaluation failed\n");
		return 1;
	}
	if (actual != 0xc1) {
		fprintf(stderr, "expr_register_base: expected 0xc1, got 0x%" PRIx64 "\n",
			actual);
		return 1;
	}

	return 0;
}

static int test_expr_stack_manipulation(void)
{
	const Dwarf_Op ops[] = {
		{ .atom = DW_OP_lit1 },
		{ .atom = DW_OP_lit2 },
		{ .atom = DW_OP_lit3 },
		{ .atom = DW_OP_rot },
		{ .atom = DW_OP_pick, .number = 2 },
		{ .atom = DW_OP_plus },
		{ .atom = DW_OP_lit7 },
		{ .atom = DW_OP_swap },
		{ .atom = DW_OP_over },
		{ .atom = DW_OP_plus },
		{ .atom = DW_OP_minus },
	};

	return expect_ops_value("expr_stack_manipulation", ops, ARRAY_SIZE(ops),
				0, 0xfffffffffffffffbULL);
}

static int test_expr_constants_and_direct_registers(void)
{
	struct eval_fixture fx;
	const Dwarf_Op ops[] = {
		{ .atom = DW_OP_const1u, .number = 0x12 },
		{ .atom = DW_OP_const1s, .number = (Dwarf_Word)-2 },
		{ .atom = DW_OP_plus },
		{ .atom = DW_OP_const2u, .number = 0x1234 },
		{ .atom = DW_OP_const2s, .number = (Dwarf_Word)-4 },
		{ .atom = DW_OP_plus },
		{ .atom = DW_OP_minus },
		{ .atom = DW_OP_const4u, .number = 0x10000 },
		{ .atom = DW_OP_const4s, .number = (Dwarf_Word)-0x100 },
		{ .atom = DW_OP_plus },
		{ .atom = DW_OP_plus },
		{ .atom = DW_OP_const8s, .number = (Dwarf_Word)-0x10 },
		{ .atom = DW_OP_plus },
		{ .atom = DW_OP_consts, .number = (Dwarf_Word)-0x20 },
		{ .atom = DW_OP_plus },
		{ .atom = DW_OP_reg3 },
		{ .atom = DW_OP_const8u, .number = 0x123456789abcdef0ULL },
		{ .atom = DW_OP_eq },
		{ .atom = DW_OP_plus },
	};
	uint64_t actual = 0;

	init_eval_fixture(&fx);
	if (!gu_dwarf_ops_eval(NULL, ops, ARRAY_SIZE(ops), &actual, 0, fx.raw_sp,
			       &fx.info)) {
		fprintf(stderr, "expr_constants_and_direct_registers: evaluation failed\n");
		return 1;
	}
	if (actual != 0xecb1) {
		fprintf(stderr, "expr_constants_and_direct_registers: expected 0xecb1,"
			" got 0x%" PRIx64 "\n",
			actual);
		return 1;
	}

	return 0;
}

static int test_expr_stack_dup_drop(void)
{
	const Dwarf_Op ops[] = {
		{ .atom = DW_OP_lit5 },
		{ .atom = DW_OP_dup },
		{ .atom = DW_OP_mul },
		{ .atom = DW_OP_lit9 },
		{ .atom = DW_OP_drop },
	};

	return expect_ops_value("expr_stack_dup_drop", ops, ARRAY_SIZE(ops),
				0, 25);
}

static int test_expr_arithmetic_logic(void)
{
	const Dwarf_Op ops[] = {
		{ .atom = DW_OP_const1s, .number = (Dwarf_Word)-7 },
		{ .atom = DW_OP_abs },
		{ .atom = DW_OP_lit3 },
		{ .atom = DW_OP_mul },
		{ .atom = DW_OP_lit5 },
		{ .atom = DW_OP_div },
		{ .atom = DW_OP_lit3 },
		{ .atom = DW_OP_mod },
		{ .atom = DW_OP_lit1 },
		{ .atom = DW_OP_shl },
		{ .atom = DW_OP_lit8 },
		{ .atom = DW_OP_or },
		{ .atom = DW_OP_lit3 },
		{ .atom = DW_OP_xor },
		{ .atom = DW_OP_lit7 },
		{ .atom = DW_OP_and },
		{ .atom = DW_OP_lit1 },
		{ .atom = DW_OP_shr },
		{ .atom = DW_OP_lit1 },
		{ .atom = DW_OP_plus_uconst, .number = 5 },
		{ .atom = DW_OP_plus },
	};

	return expect_ops_value("expr_arithmetic_logic", ops, ARRAY_SIZE(ops),
				0, 6);
}

static int test_expr_signed_shift_and_unary(void)
{
	const Dwarf_Op ops[] = {
		{ .atom = DW_OP_lit5 },
		{ .atom = DW_OP_neg },
		{ .atom = DW_OP_lit1 },
		{ .atom = DW_OP_shra },
		{ .atom = DW_OP_not },
	};

	return expect_ops_value("expr_signed_shift_and_unary", ops, ARRAY_SIZE(ops),
				0, 2);
}

static int test_expr_comparisons(void)
{
	const Dwarf_Op ops[] = {
		{ .atom = DW_OP_lit4 },
		{ .atom = DW_OP_lit4 },
		{ .atom = DW_OP_le },
		{ .atom = DW_OP_lit5 },
		{ .atom = DW_OP_lit4 },
		{ .atom = DW_OP_ge },
		{ .atom = DW_OP_plus },
		{ .atom = DW_OP_lit7 },
		{ .atom = DW_OP_lit7 },
		{ .atom = DW_OP_eq },
		{ .atom = DW_OP_plus },
		{ .atom = DW_OP_lit3 },
		{ .atom = DW_OP_lit8 },
		{ .atom = DW_OP_lt },
		{ .atom = DW_OP_plus },
		{ .atom = DW_OP_lit9 },
		{ .atom = DW_OP_lit2 },
		{ .atom = DW_OP_gt },
		{ .atom = DW_OP_plus },
		{ .atom = DW_OP_lit6 },
		{ .atom = DW_OP_lit1 },
		{ .atom = DW_OP_ne },
		{ .atom = DW_OP_plus },
	};

	return expect_ops_value("expr_comparisons", ops, ARRAY_SIZE(ops), 0, 6);
}

static int test_expr_stack_deref_size(void)
{
	struct eval_fixture fx;
	uint64_t actual = 0;
	uint64_t addr;
	uint64_t value = 0x1122334455667788ULL;
	const Dwarf_Op full_ops[] = {
		{ .atom = DW_OP_const8u },
		{ .atom = DW_OP_deref },
	};
	const Dwarf_Op sized_ops[] = {
		{ .atom = DW_OP_const8u },
		{ .atom = DW_OP_deref_size, .number = 2 },
	};
	Dwarf_Op ops[2];

	init_eval_fixture(&fx);
	addr = fx.stack_base + 0x180;
	write_stack_u64(&fx, addr, value);

	memcpy(ops, full_ops, sizeof(full_ops));
	ops[0].number = addr;
	if (!gu_dwarf_ops_eval(NULL, ops, ARRAY_SIZE(ops), &actual, 0, fx.raw_sp,
			       &fx.info) || actual != value) {
		fprintf(stderr, "expr_stack_deref_size: full deref got 0x%" PRIx64 "\n",
			actual);
		return 1;
	}

	memcpy(ops, sized_ops, sizeof(sized_ops));
	ops[0].number = addr;
	if (!gu_dwarf_ops_eval(NULL, ops, ARRAY_SIZE(ops), &actual, 0, fx.raw_sp,
			       &fx.info) || actual != 0x7788) {
		fprintf(stderr, "expr_stack_deref_size: sized deref got 0x%" PRIx64 "\n",
			actual);
		return 1;
	}

	return 0;
}

static int test_expr_signed_compare_branch(void)
{
	const Dwarf_Op ops[] = {
		{ .atom = DW_OP_const1s, .number = (Dwarf_Word)-1, .offset = 0 },
		{ .atom = DW_OP_const1u, .number = 2, .offset = 2 },
		{ .atom = DW_OP_lt, .offset = 4 },
		{ .atom = DW_OP_bra, .number = 4, .offset = 5 },
		{ .atom = DW_OP_lit0, .offset = 8 },
		{ .atom = DW_OP_skip, .number = 2, .offset = 9 },
		{ .atom = DW_OP_const1u, .number = 42, .offset = 12 },
		{ .atom = DW_OP_nop, .offset = 14 },
	};

	return expect_ops_value("expr_signed_compare_branch", ops, ARRAY_SIZE(ops),
				0, 42);
}

static int test_expr_branch_loop_is_bounded(void)
{
	struct eval_fixture fx;
	uint64_t actual = 0;
	const Dwarf_Op ops[] = {
		{ .atom = DW_OP_skip, .number = (Dwarf_Word)-3, .offset = 0 },
	};

	init_eval_fixture(&fx);
	if (gu_dwarf_ops_eval(NULL, ops, ARRAY_SIZE(ops), &actual, 0,
			      fx.raw_sp, &fx.info)) {
		fprintf(stderr, "expr_branch_loop_is_bounded: looping expression succeeded\n");
		return 1;
	}

	return 0;
}

static int test_expr_invalid_register_number_fails(void)
{
	struct eval_fixture fx;
	uint64_t actual = 0;
	const Dwarf_Op ops[] = {
		{ .atom = DW_OP_regx, .number = (Dwarf_Word)-1 },
	};

	init_eval_fixture(&fx);
	if (gu_dwarf_ops_eval(NULL, ops, ARRAY_SIZE(ops), &actual, 0,
			      fx.raw_sp, &fx.info)) {
		fprintf(stderr, "expr_invalid_register_number_fails: invalid register succeeded\n");
		return 1;
	}

	return 0;
}

static int test_expr_deref_size_rejects_too_wide(void)
{
	struct eval_fixture fx;
	uint64_t actual = 0;
	uint64_t addr;
	const Dwarf_Op ops[] = {
		{ .atom = DW_OP_const8u },
		{ .atom = DW_OP_deref_size, .number = 9 },
	};
	Dwarf_Op local_ops[ARRAY_SIZE(ops)];

	init_eval_fixture(&fx);
	addr = fx.stack_base + 0x180;
	write_stack_u64(&fx, addr, 0x1122334455667788ULL);
	memcpy(local_ops, ops, sizeof(local_ops));
	local_ops[0].number = addr;

	if (gu_dwarf_ops_eval(NULL, local_ops, ARRAY_SIZE(local_ops), &actual, 0,
			      fx.raw_sp, &fx.info)) {
		fprintf(stderr, "expr_deref_size_rejects_too_wide: oversized deref succeeded\n");
		return 1;
	}

	return 0;
}

static void emit_u8(struct byte_builder *b, uint8_t value)
{
	if (b->len >= sizeof(b->data)) {
		fprintf(stderr, "CFI byte buffer overflow\n");
		exit(2);
	}
	b->data[b->len++] = value;
}

static void emit_u64(struct byte_builder *b, uint64_t value)
{
	for (int i = 0; i < 8; i++)
		emit_u8(b, (uint8_t)(value >> (i * 8)));
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

static void emit_sleb(struct byte_builder *b, int64_t value)
{
	bool more = true;

	while (more) {
		uint8_t byte = value & 0x7f;
		bool sign = byte & 0x40;

		value >>= 7;
		if ((value == 0 && !sign) || (value == -1 && sign))
			more = false;
		else
			byte |= 0x80;
		emit_u8(b, byte);
	}
}

static void emit_def_cfa_rsp(struct byte_builder *b, uint64_t offset)
{
	emit_u8(b, DW_CFA_def_cfa);
	emit_uleb(b, reg_name_rsp);
	emit_uleb(b, offset);
}

static void emit_rip_val_offset_zero(struct byte_builder *b)
{
	emit_u8(b, DW_CFA_val_offset);
	emit_uleb(b, reg_name_rip);
	emit_uleb(b, 0);
}

static int init_cfi_fixture(struct cfi_fixture *cf, const uint8_t *ins,
			    size_t ins_len, uint64_t start, uint64_t end)
{
	struct interval_array_item item;

	memset(cf, 0, sizeof(*cf));
	cf->cfi_data.d_buf = (void *)ins;
	cf->cfi_data.d_size = ins_len;
	cf->cfi.cfi_data = &cf->cfi_data;

	cf->cie.code_alignment_factor = 1;
	cf->cie.data_alignment_factor = -8;
	cf->cie.return_address_register = reg_name_rip;
	cf->cie.fde_encoding = DW_EH_PE_udata8;
	cf->cie.lsda_encoding = DW_EH_PE_omit;

	cf->fde.cie = &cf->cie;
	cf->fde.start = start;
	cf->fde.end = end;
	cf->fde.instructions = ins;
	cf->fde.instructions_end = ins + ins_len;

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

static int parse_cfi_fixture(struct cfi_fixture *cf, const struct byte_builder *b,
			     uint64_t pc)
{
	int ret;

	if (init_cfi_fixture(cf, b->data, b->len, 0x1000, 0x2000) != 0) {
		fprintf(stderr, "failed to initialize synthetic CFI fixture\n");
		return -1;
	}

	ret = gu_cfi_parse_cfi(&cf->cfi, pc);
	if (ret != 0) {
		fprintf(stderr, "gu_cfi_parse_cfi failed for pc=0x%" PRIx64 "\n", pc);
		destroy_cfi_fixture(cf);
		return -1;
	}

	return 0;
}

static int expect_cfi_parse_failure(const char *name, const struct byte_builder *b,
				    uint64_t pc)
{
	struct cfi_fixture cf;
	int ret;

	if (init_cfi_fixture(&cf, b->data, b->len, 0x1000, 0x2000) != 0) {
		fprintf(stderr, "%s: failed to initialize synthetic CFI fixture\n",
			name);
		return 1;
	}

	ret = gu_cfi_parse_cfi(&cf.cfi, pc);
	destroy_cfi_fixture(&cf);
	if (ret == 0) {
		fprintf(stderr, "%s: expected CFI parse failure, got success\n", name);
		return 1;
	}

	return 0;
}

static int expect_current_cfa(const char *name, const struct byte_builder *b,
			      uint64_t pc, uint64_t expected)
{
	struct cfi_fixture cf;
	struct eval_fixture fx;
	Dwarf_Op *ops = NULL;
	int nops = 0;
	uint64_t actual = 0;
	int ret = 1;

	init_eval_fixture(&fx);
	if (parse_cfi_fixture(&cf, b, pc) != 0)
		return 1;

	if (gu_cfi_get_ops(REG_TYPE_RIP, &ops, &nops, true) != 0 || nops == 0)
		goto out;
	if (!gu_dwarf_ops_eval(NULL, ops, nops, &actual, 0, fx.raw_sp, &fx.info))
		goto out;
	if (actual != expected) {
		fprintf(stderr, "%s: expected CFA 0x%" PRIx64 ", got 0x%" PRIx64 "\n",
			name, expected, actual);
		goto out;
	}

	ret = 0;
out:
	destroy_cfi_fixture(&cf);
	return ret;
}

static int expect_cfi_reg(const char *name, const struct byte_builder *b,
			  uint64_t pc, int regno, uint64_t expected,
			  uint64_t stack_addr, uint64_t stack_value)
{
	struct cfi_fixture cf;
	struct eval_fixture fx;
	uint64_t actual = 0;
	int ret = 1;

	init_eval_fixture(&fx);
	if (stack_addr)
		write_stack_u64(&fx, stack_addr, stack_value);
	if (parse_cfi_fixture(&cf, b, pc) != 0)
		return 1;

	if (gen_reg(NULL, regno, 0, fx.raw_sp, &fx.info, &actual) !=
	    GU_UNWIND_REASON_OK)
		goto out;
	if (actual != expected) {
		fprintf(stderr, "%s: expected reg %d = 0x%" PRIx64
			", got 0x%" PRIx64 "\n",
			name, regno, expected, actual);
		goto out;
	}

	ret = 0;
out:
	destroy_cfi_fixture(&cf);
	return ret;
}

static int expect_cfi_reg_reason(const char *name, const struct byte_builder *b,
				 uint64_t pc, int regno,
				 enum gu_unwind_reason expected)
{
	struct cfi_fixture cf;
	struct eval_fixture fx;
	uint64_t actual = 0;
	enum gu_unwind_reason reason;
	int ret = 1;

	init_eval_fixture(&fx);
	if (parse_cfi_fixture(&cf, b, pc) != 0)
		return 1;

	reason = gen_reg(NULL, regno, 0, fx.raw_sp, &fx.info, &actual);
	if (reason != expected) {
		fprintf(stderr, "%s: expected reason %d, got %d\n",
			name, expected, reason);
		goto out;
	}

	ret = 0;
out:
	destroy_cfi_fixture(&cf);
	return ret;
}

static int test_cfi_def_cfa_offset(void)
{
	struct byte_builder b = { 0 };
	struct eval_fixture fx;

	init_eval_fixture(&fx);
	emit_def_cfa_rsp(&b, 16);
	emit_u8(&b, DW_CFA_def_cfa_offset);
	emit_uleb(&b, 24);
	emit_rip_val_offset_zero(&b);

	return expect_current_cfa("cfi_def_cfa_offset", &b, 0x1000,
				  fx.raw_sp + 24);
}

static int test_cfi_def_cfa_expression(void)
{
	struct byte_builder expr = { 0 };
	struct byte_builder b = { 0 };
	struct eval_fixture fx;

	init_eval_fixture(&fx);
	emit_u8(&expr, DW_OP_bregx);
	emit_uleb(&expr, reg_name_rsp);
	emit_sleb(&expr, 40);

	emit_u8(&b, DW_CFA_def_cfa_expression);
	emit_uleb(&b, expr.len);
	for (size_t i = 0; i < expr.len; i++)
		emit_u8(&b, expr.data[i]);
	emit_rip_val_offset_zero(&b);

	return expect_current_cfa("cfi_def_cfa_expression", &b, 0x1000,
				  fx.raw_sp + 40);
}

static int test_cfi_def_cfa_sf(void)
{
	struct byte_builder b = { 0 };
	struct eval_fixture fx;

	init_eval_fixture(&fx);
	emit_u8(&b, DW_CFA_def_cfa_sf);
	emit_uleb(&b, reg_name_rsp);
	emit_sleb(&b, -2);
	emit_u8(&b, DW_CFA_def_cfa_offset_sf);
	emit_sleb(&b, -4);
	emit_rip_val_offset_zero(&b);

	return expect_current_cfa("cfi_def_cfa_sf", &b, 0x1000, fx.raw_sp + 32);
}

static int test_cfi_def_cfa_register(void)
{
	struct byte_builder b = { 0 };
	struct eval_fixture fx;

	init_eval_fixture(&fx);
	emit_def_cfa_rsp(&b, 16);
	emit_u8(&b, DW_CFA_def_cfa_register);
	emit_uleb(&b, reg_name_rbp);
	emit_rip_val_offset_zero(&b);

	return expect_current_cfa("cfi_def_cfa_register", &b, 0x1000,
				  fx.raw_sp + 0xe0 + 16);
}

static int test_cfi_expression(void)
{
	struct byte_builder b = { 0 };
	struct eval_fixture fx;
	uint64_t saved_pc;
	uint64_t saved_addr;

	init_eval_fixture(&fx);
	saved_pc = 0xabcdef1234567890ULL;
	saved_addr = fx.raw_sp + 16 + 8;

	emit_def_cfa_rsp(&b, 16);
	emit_u8(&b, DW_CFA_expression);
	emit_uleb(&b, reg_name_rip);
	emit_uleb(&b, 2);
	emit_u8(&b, DW_OP_plus_uconst);
	emit_uleb(&b, 8);

	return expect_cfi_reg("cfi_expression", &b, 0x1000, reg_name_rip,
			      saved_pc, saved_addr, saved_pc);
}

static int test_cfi_val_expression(void)
{
	struct byte_builder b = { 0 };
	struct eval_fixture fx;

	init_eval_fixture(&fx);
	emit_def_cfa_rsp(&b, 16);
	emit_u8(&b, DW_CFA_val_expression);
	emit_uleb(&b, reg_name_rip);
	emit_uleb(&b, 2);
	emit_u8(&b, DW_OP_plus_uconst);
	emit_uleb(&b, 32);

	return expect_cfi_reg("cfi_val_expression", &b, 0x1000, reg_name_rip,
			      fx.raw_sp + 48, 0, 0);
}

static int test_cfi_offset_rule(void)
{
	struct byte_builder b = { 0 };
	struct eval_fixture fx;
	uint64_t saved_pc = 0x5555666677778888ULL;
	uint64_t saved_addr;

	init_eval_fixture(&fx);
	saved_addr = fx.raw_sp + 16 - 8;

	emit_def_cfa_rsp(&b, 16);
	emit_u8(&b, DW_CFA_offset + reg_name_rip);
	emit_uleb(&b, 1);

	return expect_cfi_reg("cfi_offset_rule", &b, 0x1000, reg_name_rip,
			      saved_pc, saved_addr, saved_pc);
}

static int test_cfi_remember_restore(void)
{
	struct byte_builder b = { 0 };
	struct eval_fixture fx;

	init_eval_fixture(&fx);
	emit_def_cfa_rsp(&b, 16);
	emit_u8(&b, DW_CFA_remember_state);
	emit_u8(&b, DW_CFA_def_cfa_offset);
	emit_uleb(&b, 64);
	emit_u8(&b, DW_CFA_restore_state);
	emit_rip_val_offset_zero(&b);

	return expect_current_cfa("cfi_remember_restore", &b, 0x1000,
				  fx.raw_sp + 16);
}

static int test_cfi_register_copy(void)
{
	struct byte_builder b = { 0 };

	emit_def_cfa_rsp(&b, 16);
	emit_rip_val_offset_zero(&b);
	emit_u8(&b, DW_CFA_register);
	emit_uleb(&b, reg_name_rbp);
	emit_uleb(&b, TEST_DW_REG3);

	return expect_cfi_reg("cfi_register_copy", &b, 0x1000, reg_name_rbp,
			      TEST_REGISTER_COPY_VALUE, 0, 0);
}

static int test_cfi_advance_loc(void)
{
	struct byte_builder b = { 0 };
	struct eval_fixture fx;
	int ret = 0;

	init_eval_fixture(&fx);
	emit_def_cfa_rsp(&b, 16);
	emit_rip_val_offset_zero(&b);
	emit_u8(&b, DW_CFA_advance_loc + 4);
	emit_u8(&b, DW_CFA_def_cfa_offset);
	emit_uleb(&b, 40);

	ret |= expect_current_cfa("cfi_advance_loc_before", &b, 0x1002,
				  fx.raw_sp + 16);
	ret |= expect_current_cfa("cfi_advance_loc_after", &b, 0x1004,
				  fx.raw_sp + 40);

	memset(&b, 0, sizeof(b));
	emit_def_cfa_rsp(&b, 16);
	emit_rip_val_offset_zero(&b);
	emit_u8(&b, DW_CFA_advance_loc1);
	emit_u8(&b, 4);
	emit_u8(&b, DW_CFA_def_cfa_offset);
	emit_uleb(&b, 48);
	ret |= expect_current_cfa("cfi_advance_loc1_after", &b, 0x1004,
				  fx.raw_sp + 48);

	memset(&b, 0, sizeof(b));
	emit_def_cfa_rsp(&b, 16);
	emit_rip_val_offset_zero(&b);
	emit_u8(&b, DW_CFA_advance_loc2);
	emit_u8(&b, 4);
	emit_u8(&b, 0);
	emit_u8(&b, DW_CFA_def_cfa_offset);
	emit_uleb(&b, 56);
	ret |= expect_current_cfa("cfi_advance_loc2_after", &b, 0x1004,
				  fx.raw_sp + 56);

	memset(&b, 0, sizeof(b));
	emit_def_cfa_rsp(&b, 16);
	emit_rip_val_offset_zero(&b);
	emit_u8(&b, DW_CFA_advance_loc4);
	emit_u8(&b, 4);
	emit_u8(&b, 0);
	emit_u8(&b, 0);
	emit_u8(&b, 0);
	emit_u8(&b, DW_CFA_def_cfa_offset);
	emit_uleb(&b, 64);
	ret |= expect_current_cfa("cfi_advance_loc4_after", &b, 0x1004,
				  fx.raw_sp + 64);

	return ret;
}

static int test_cfi_unrecoverable_rip_fails(void)
{
	struct byte_builder b = { 0 };
	int ret = 0;

	emit_def_cfa_rsp(&b, 16);
	emit_u8(&b, DW_CFA_undefined);
	emit_uleb(&b, reg_name_rip);
	ret |= expect_cfi_parse_failure("cfi_undefined_rip_fails", &b, 0x1000);

	memset(&b, 0, sizeof(b));
	emit_def_cfa_rsp(&b, 16);
	emit_u8(&b, DW_CFA_same_value);
	emit_uleb(&b, reg_name_rip);
	ret |= expect_cfi_parse_failure("cfi_same_value_rip_fails", &b, 0x1000);

	return ret;
}

static int test_cfi_truncated_expression_block_fails(void)
{
	struct byte_builder b = { 0 };
	int ret = 0;

	emit_def_cfa_rsp(&b, 16);
	emit_u8(&b, DW_CFA_val_expression);
	emit_uleb(&b, reg_name_rip);
	emit_uleb(&b, 1);
	emit_u8(&b, DW_OP_const8u);
	ret |= expect_cfi_parse_failure("cfi_truncated_expression_operand_fails",
					&b, 0x1000);

	memset(&b, 0, sizeof(b));
	emit_def_cfa_rsp(&b, 16);
	emit_u8(&b, DW_CFA_val_expression);
	emit_uleb(&b, reg_name_rip);
	emit_uleb(&b, 16);
	emit_u8(&b, DW_OP_lit0);
	ret |= expect_cfi_parse_failure("cfi_expression_block_past_section_fails",
					&b, 0x1000);

	return ret;
}

static int test_cfi_truncated_instruction_fails(void)
{
	struct byte_builder b = { 0 };
	int ret = 0;

	emit_def_cfa_rsp(&b, 16);
	emit_rip_val_offset_zero(&b);
	emit_u8(&b, DW_CFA_def_cfa);
	emit_uleb(&b, reg_name_rsp);
	ret |= expect_cfi_parse_failure("cfi_truncated_def_cfa_fails", &b,
					0x1000);

	memset(&b, 0, sizeof(b));
	emit_def_cfa_rsp(&b, 16);
	emit_rip_val_offset_zero(&b);
	emit_u8(&b, DW_CFA_advance_loc4);
	emit_u8(&b, 1);
	emit_u8(&b, 0);
	ret |= expect_cfi_parse_failure("cfi_truncated_advance_loc4_fails",
					&b, 0x1000);

	return ret;
}

static int test_cfi_stack_read_out_of_range(void)
{
	struct byte_builder b = { 0 };

	emit_def_cfa_rsp(&b, TEST_STACK_SIZE + 16);
	emit_u8(&b, DW_CFA_offset + reg_name_rip);
	emit_uleb(&b, 1);
	return expect_cfi_reg_reason("cfi_stack_read_out_of_range", &b, 0x1000,
				     reg_name_rip,
				     GU_UNWIND_REASON_STACK_READ_OUT_OF_RANGE);
}

static int test_cfi_set_loc(void)
{
	struct byte_builder b = { 0 };
	struct eval_fixture fx;

	init_eval_fixture(&fx);
	emit_def_cfa_rsp(&b, 16);
	emit_u8(&b, DW_CFA_set_loc);
	emit_u64(&b, 0x100b);
	emit_u8(&b, DW_CFA_def_cfa_offset);
	emit_uleb(&b, 32);
	emit_rip_val_offset_zero(&b);

	return expect_current_cfa("cfi_set_loc", &b, 0x100b, fx.raw_sp + 32);
}

static int expect_ops_fail(const char *name, const Dwarf_Op *ops, size_t nops)
{
struct eval_fixture fx;
uint64_t actual = 0xcafef00d;

init_eval_fixture(&fx);
if (gu_dwarf_ops_eval(NULL, ops, nops, &actual, 0, fx.raw_sp, &fx.info)) {
fprintf(stderr, "%s: expression evaluation must fail but succeeded\n",
name);
return 1;
}

return 0;
}

/* Signed INT64_MIN / -1 overflows and must be rejected, not wrapped. */
static int test_expr_div_int64_min_overflow_fails(void)
{
const Dwarf_Op ops[] = {
{ .atom = DW_OP_const8u, .number = 0x8000000000000000ULL },
{ .atom = DW_OP_const1s, .number = -1 },
{ .atom = DW_OP_div },
};

return expect_ops_fail("expr_div_int64_min_overflow_fails", ops,
ARRAY_SIZE(ops));
}

static int test_expr_shr_overflow_fails(void)
{
const Dwarf_Op ops[] = {
{ .atom = DW_OP_lit1 },
{ .atom = DW_OP_const1u, .number = 64 },
{ .atom = DW_OP_shr },
};

return expect_ops_fail("expr_shr_overflow_fails", ops, ARRAY_SIZE(ops));
}

static int test_expr_shl_overflow_fails(void)
{
const Dwarf_Op ops[] = {
{ .atom = DW_OP_lit1 },
{ .atom = DW_OP_const1u, .number = 64 },
{ .atom = DW_OP_shl },
};

return expect_ops_fail("expr_shl_overflow_fails", ops, ARRAY_SIZE(ops));
}

static int test_expr_shra_overflow_fails(void)
{
const Dwarf_Op ops[] = {
{ .atom = DW_OP_lit1 },
{ .atom = DW_OP_const1u, .number = 64 },
{ .atom = DW_OP_shra },
};

return expect_ops_fail("expr_shra_overflow_fails", ops, ARRAY_SIZE(ops));
}

static const struct test_case cases[] = {
	{ "expr_literal_arithmetic", test_expr_literal_arithmetic },
	{ "expr_register_base", test_expr_register_base },
	{ "expr_stack_manipulation", test_expr_stack_manipulation },
	{ "expr_constants_and_direct_registers", test_expr_constants_and_direct_registers },
	{ "expr_stack_dup_drop", test_expr_stack_dup_drop },
	{ "expr_arithmetic_logic", test_expr_arithmetic_logic },
	{ "expr_signed_shift_and_unary", test_expr_signed_shift_and_unary },
	{ "expr_comparisons", test_expr_comparisons },
	{ "expr_stack_deref_size", test_expr_stack_deref_size },
	{ "expr_signed_compare_branch", test_expr_signed_compare_branch },
	{ "expr_branch_loop_is_bounded", test_expr_branch_loop_is_bounded },
	{ "expr_invalid_register_number_fails", test_expr_invalid_register_number_fails },
	{ "expr_deref_size_rejects_too_wide", test_expr_deref_size_rejects_too_wide },
	{ "cfi_def_cfa_offset", test_cfi_def_cfa_offset },
	{ "cfi_def_cfa_expression", test_cfi_def_cfa_expression },
	{ "cfi_def_cfa_sf", test_cfi_def_cfa_sf },
	{ "cfi_def_cfa_register", test_cfi_def_cfa_register },
	{ "cfi_expression", test_cfi_expression },
	{ "cfi_val_expression", test_cfi_val_expression },
	{ "cfi_offset_rule", test_cfi_offset_rule },
	{ "cfi_remember_restore", test_cfi_remember_restore },
	{ "cfi_register_copy", test_cfi_register_copy },
	{ "cfi_advance_loc", test_cfi_advance_loc },
	{ "cfi_unrecoverable_rip_fails", test_cfi_unrecoverable_rip_fails },
	{ "cfi_truncated_expression_block_fails", test_cfi_truncated_expression_block_fails },
	{ "cfi_truncated_instruction_fails", test_cfi_truncated_instruction_fails },
	{ "cfi_stack_read_out_of_range", test_cfi_stack_read_out_of_range },
	{ "cfi_set_loc", test_cfi_set_loc },
{ "expr_div_int64_min_overflow_fails", test_expr_div_int64_min_overflow_fails },
{ "expr_shr_overflow_fails", test_expr_shr_overflow_fails },
{ "expr_shl_overflow_fails", test_expr_shl_overflow_fails },
{ "expr_shra_overflow_fails", test_expr_shra_overflow_fails },
};

int main(int argc, char **argv)
{
	int failures = 0;

	if (argc == 2 && strcmp(argv[1], "--list") == 0) {
		for (size_t i = 0; i < ARRAY_SIZE(cases); i++)
			printf("%s\n", cases[i].name);
		return 0;
	}
	if (argc > 1) {
		fprintf(stderr, "usage: %s [--list]\n", argv[0]);
		return 2;
	}

	for (size_t i = 0; i < ARRAY_SIZE(cases); i++) {
		int ret = cases[i].run();

		if (ret == 0) {
			printf("ok %zu - %s\n", i + 1, cases[i].name);
		} else {
			printf("not ok %zu - %s\n", i + 1, cases[i].name);
			failures++;
		}
	}

	if (failures) {
		fprintf(stderr, "%d libgunwinder CFI stress case(s) failed\n", failures);
		return 1;
	}

	return 0;
}
