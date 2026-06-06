/* SPDX-License-Identifier: LGPL-3.0-or-later */
/*
 * Copyright (C) 2026 ByteDance Inc.
 *
 * This file is part of libgunwinder and is distributed under the
 * GNU Lesser General Public License v3.0 or later.
 *
 * The DWARF expression safety rules implemented here were designed with
 * reference to elfutils/libdwfl frame unwinding code, including
 * libdwfl/frame_unwind.c:
 *
 *   Copyright (C) 2013, 2014, 2016, 2024 Red Hat, Inc.
 *
 * elfutils is available under LGPL-3.0-or-later or GPL-2.0-or-later.
 * libgunwinder keeps its own snapshot-oriented evaluator structure rather
 * than copying the upstream implementation.
 */

#include "gunwinder/unwinder_types.h"
#include <stddef.h>
#include <unistd.h>

#include "gu_unwinder.h"
#include "gu_cfi_helper.h"

#define REG_POS(pos, reg) [pos] = offsetof(struct pt_regs, reg)
static unsigned long regs[] = { REG_POS_LIST };
#undef REG_POS

#define THREE_TAB_STR "\t\t\t"
#define FOUR_TAB_STR "\t\t\t\t"

#define DW_EVAL_STACK_SIZE 0x100
#define DW_EVAL_STEPS_MAX 0x1000

struct dw_eval_stack {
	Dwarf_Addr addrs[DW_EVAL_STACK_SIZE];
	size_t used;
};

static __thread bool stack_read_out_of_range;
static __thread uint64_t stack_read_out_of_range_addr;
static __thread uint64_t stack_read_out_of_range_start;
static __thread uint64_t stack_read_out_of_range_end;
static __thread uint64_t stack_read_out_of_range_raw_sp;

static enum gu_arch compiled_arch(void)
{
#if defined(GUNWINDER_X86)
	return GU_ARCH_X86_64;
#elif defined(GUNWINDER_ARM64)
	return GU_ARCH_ARM64;
#else
	return GU_ARCH_NATIVE;
#endif
}

static bool arch_is_compatible(enum gu_arch arch)
{
	return arch == GU_ARCH_NATIVE || arch == compiled_arch();
}

static struct gu_regs *public_regs_from_info(struct gu_stack_info *info)
{
	struct gu_regs *regs;

	if (!info || !info->regs)
		return NULL;
	if (info->regs_size < sizeof(*regs))
		return NULL;

	regs = (struct gu_regs *)info->regs;
	if (regs->size != sizeof(*regs))
		return NULL;

	return regs;
}

static bool legacy_reg_bounds_ok(struct gu_stack_info *info, int regno,
				 unsigned long *offset)
{
	size_t byte_offset;

	if (regno >= sizeof(regs) / sizeof(regs[0]))
		return false;

	byte_offset = regs[regno];
	if (info->regs_size < byte_offset ||
	    info->regs_size - byte_offset < sizeof(unsigned long))
		return false;

	*offset = byte_offset / sizeof(unsigned long);
	return true;
}

bool gu_last_stack_read_out_of_range(uint64_t *addr, uint64_t *start,
				     uint64_t *end, uint64_t *raw_sp)
{
	if (!stack_read_out_of_range)
		return false;

	if (addr)
		*addr = stack_read_out_of_range_addr;
	if (start)
		*start = stack_read_out_of_range_start;
	if (end)
		*end = stack_read_out_of_range_end;
	if (raw_sp)
		*raw_sp = stack_read_out_of_range_raw_sp;

	return true;
}

static const char *op_name(unsigned int code)
{
	static const char *const known[] = {
#define DWARF_ONE_KNOWN_DW_OP(NAME, CODE) [CODE] = #NAME,
		DWARF_ALL_KNOWN_DW_OP
#undef DWARF_ONE_KNOWN_DW_OP
	};

	if ((code < sizeof(known) / sizeof(known[0])))
		return known[code];

	return NULL;
}

static bool dw_push(struct dw_eval_stack *stack, uint64_t val)
{
	if (stack->used >= DW_EVAL_STACK_SIZE) {
		GU_VERBOSE(THREE_TAB_STR "stack->used >= DW_EVAL_STACK_SIZE");
		return false;
	}

	stack->addrs[stack->used++] = val;
	GU_VERBOSE(THREE_TAB_STR "push 0x%lx", val);

	return true;
}

static bool dw_pop(struct dw_eval_stack *stack, uint64_t *val)
{
	if (!stack->used) {
		GU_VERBOSE(THREE_TAB_STR "stack->used == 0");
		return false;
	}

	*val = stack->addrs[--stack->used];
	GU_VERBOSE(THREE_TAB_STR "pop 0x%lx", *val);

	return true;
}

bool get_regs(struct gu_stack_info *info, int regno, uint64_t *val)
{
	struct gu_regs *public_regs;
	unsigned long offset;

	if (!info || !info->regs || !val)
		return false;
	if (regno < 0)
		return false;
	public_regs = public_regs_from_info(info);
	if (public_regs) {
		if (!arch_is_compatible(public_regs->arch))
			return false;
		return gu_regs_get(public_regs, regno, val);
	}
	struct pt_regs *reg = (struct pt_regs *)info->regs;
	if (!legacy_reg_bounds_ok(info, regno, &offset)) {
		GU_VERBOSE(THREE_TAB_STR "get_regs: %d failed", regno);
		return false;
	}

	*val = ((unsigned long *)(reg))[offset];
	GU_VERBOSE(THREE_TAB_STR "get_regs: %d offset: %ld val: 0x%lx", regno, offset, *val);

	return true;
}

bool write_regs(struct gu_stack_info *info, int regno, uint64_t val)
{
	struct gu_regs *public_regs;
	unsigned long offset;

	if (!info || !info->regs)
		return false;
	if (regno < 0)
		return false;
	public_regs = public_regs_from_info(info);
	if (public_regs) {
		if (!arch_is_compatible(public_regs->arch))
			return false;
		return gu_regs_set(public_regs, regno, val);
	}
	struct pt_regs *reg = (struct pt_regs *)info->regs;
	if (!legacy_reg_bounds_ok(info, regno, &offset))
		return false;

	((unsigned long *)(reg))[offset] = val;
	GU_VERBOSE(THREE_TAB_STR "write_regs: %d offset: %ld val: 0x%lx", regno, offset, val);

	return true;
}

static bool read_addr(uint8_t *stack, uint64_t stack_start, uint64_t stack_end,
		      uint64_t raw_sp, uint64_t read_addr, uint64_t *val)
{
	GU_VERBOSE(THREE_TAB_STR "read_addr: 0x%lx start: 0x%lx end: 0x%lx info->raw_sp: 0x%lx",
	      read_addr, stack_start, stack_end, raw_sp);
	if (read_addr < stack_start || read_addr >= stack_end ||
	    read_addr + sizeof(Dwarf_Addr) < read_addr ||
	    stack_end - read_addr < sizeof(Dwarf_Addr)) {
		stack_read_out_of_range = true;
		stack_read_out_of_range_addr = read_addr;
		stack_read_out_of_range_start = stack_start;
		stack_read_out_of_range_end = stack_end;
		stack_read_out_of_range_raw_sp = raw_sp;
		GU_VERBOSE("read_addr out of range");
		return false;
	}

	*val = *(Dwarf_Addr *)&(stack[(read_addr - stack_start)]);
	GU_VERBOSE(THREE_TAB_STR "read_addr: 0x%lx val: 0x%lx", read_addr, *val);

	return true;
}

static bool read_addr_from_info(struct gu_stack_info *info, uint64_t raw_sp,
				uint64_t addr, uint64_t *val)
{
	uint64_t stack_page_size = getpagesize();
	uint64_t stack_start = raw_sp - (raw_sp % stack_page_size);
	uint64_t stack_end = stack_start + info->stack_size;

	return read_addr(info->stack_data, stack_start, stack_end, raw_sp, addr,
			 val);
}

static bool fast_eval_reg_or_breg(const Dwarf_Op *op, struct gu_stack_info *info,
				  uint64_t *result)
{
	uint64_t base;

	switch (op->atom) {
	case DW_OP_reg0 ... DW_OP_reg31:
		return get_regs(info, op->atom - DW_OP_reg0, result);
	case DW_OP_regx:
		return get_regs(info, op->number, result);
	case DW_OP_breg0 ... DW_OP_breg31:
		if (!get_regs(info, op->atom - DW_OP_breg0, &base))
			return false;
		*result = base + op->number;
		return true;
	case DW_OP_bregx:
		if (!get_regs(info, op->number, &base))
			return false;
		*result = base + op->number2;
		return true;
	default:
		return false;
	}
}

static bool fast_eval_cfa(uint64_t bias, uint64_t raw_sp,
			  struct gu_stack_info *info, uint64_t *cfa)
{
	Dwarf_Op *cfa_ops;
	int cfa_nops;

	if (gu_cfi_get_ops(0, &cfa_ops, &cfa_nops, true) != 0 || cfa_nops <= 0)
		return false;
	if (cfa_nops == 1 && fast_eval_reg_or_breg(&cfa_ops[0], info, cfa))
		return true;

	return gu_dwarf_ops_eval(NULL, cfa_ops, cfa_nops, cfa, bias, raw_sp,
				 info);
}

static bool fast_dwarf_ops_eval(const Dwarf_Op *ops, size_t nops,
				uint64_t *result, uint64_t bias,
				uint64_t raw_sp, struct gu_stack_info *info)
{
	uint64_t cfa;
	uint64_t addr;

	if (nops == 1)
		return fast_eval_reg_or_breg(&ops[0], info, result);

	if (nops < 2 || ops[0].atom != DW_OP_call_frame_cfa)
		return false;
	if (!fast_eval_cfa(bias, raw_sp, info, &cfa))
		return false;

	if (nops == 2) {
		switch (ops[1].atom) {
		case DW_OP_stack_value:
			*result = cfa;
			return true;
		case DW_OP_plus_uconst:
			addr = cfa + ops[1].number;
			return read_addr_from_info(info, raw_sp, addr, result);
		default:
			return false;
		}
	}

	if (nops == 3 && ops[1].atom == DW_OP_plus_uconst &&
	    ops[2].atom == DW_OP_stack_value) {
		*result = cfa + ops[1].number;
		return true;
	}

	return false;
}

static int compare(const void *key, const void *val)
{
	Dwarf_Word offset = (uintptr_t)key;
	const Dwarf_Op *op = val;
	return (offset > op->offset) - (offset < op->offset);
}

bool gu_dwarf_ops_eval(Dwarf_Frame *frame, const Dwarf_Op *ops, size_t nops,
		       uint64_t *result, uint64_t bias, uint64_t raw_sp,
		       struct gu_stack_info  *info)
{
	if (nops == 0)
		return false;

	struct dw_eval_stack dw_stack;

	GU_VERBOSE(THREE_TAB_STR "Enter dw_ops_eval");

	dw_stack.used = 0;

	Dwarf_Addr val1, val2, val3;
	bool is_location = false;
	uint64_t stack_page_size = 0;
	uint64_t stack_start = 0;
	uint64_t stack_end = 0;
	size_t steps_count = 0;

	for (const Dwarf_Op *op = ops; op < ops + nops; op++) {
		if (++steps_count > DW_EVAL_STEPS_MAX)
			goto failed;
		GU_VERBOSE(THREE_TAB_STR "==> ops: %s %ld + %ld", op_name(op->atom), op->number, op->number2);
		switch (op->atom) {
		case DW_OP_lit0 ... DW_OP_lit31:
			if (!dw_push(&dw_stack, op->atom - DW_OP_lit0))
				goto failed;
			break;
		case DW_OP_addr:
			if (!dw_push(&dw_stack, op->number + bias))
				goto failed;
			break;
		case DW_OP_GNU_encoded_addr:
			goto failed;
		case DW_OP_const1u:
		case DW_OP_const1s:
		case DW_OP_const2u:
		case DW_OP_const2s:
		case DW_OP_const4u:
		case DW_OP_const4s:
		case DW_OP_const8u:
		case DW_OP_const8s:
		case DW_OP_constu:
		case DW_OP_consts:
			if (!dw_push(&dw_stack, op->number))
				goto failed;
			break;
		case DW_OP_reg0 ... DW_OP_reg31:
			if (!get_regs(info, op->atom - DW_OP_reg0,
				     &val1) ||
			    !dw_push(&dw_stack, val1))
				goto failed;
			break;
		case DW_OP_regx:
			if (!get_regs(info, op->number, &val1) ||
			    !dw_push(&dw_stack, val1))
				goto failed;
			break;
		case DW_OP_breg0 ... DW_OP_breg31:
			if (!get_regs(info, op->atom - DW_OP_breg0,
				     &val1))
				goto failed;
			val1 += op->number;
			if (!dw_push(&dw_stack, val1))
				goto failed;
			break;
		case DW_OP_bregx:
			if (!get_regs(info, op->number, &val1))
				goto failed;
			val1 += op->number2;
			if (!dw_push(&dw_stack, val1)) {
				goto failed;
			}
			break;
		case DW_OP_dup:
			if (!dw_pop(&dw_stack, &val1) ||
			    !dw_push(&dw_stack, val1) ||
			    !dw_push(&dw_stack, val1))
				goto failed;
			break;
		case DW_OP_drop:
			if (!dw_pop(&dw_stack, &val1))
				goto failed;
			break;
		case DW_OP_pick:
			if (dw_stack.used <= op->number)
				goto failed;
			size_t off = dw_stack.used - 1 - op->number;
			if (!dw_push(&dw_stack, dw_stack.addrs[off]))
				goto failed;
			break;
		case DW_OP_over:
			if (!dw_pop(&dw_stack, &val1) ||
			    !dw_pop(&dw_stack, &val2) ||
			    !dw_push(&dw_stack, val2) ||
			    !dw_push(&dw_stack, val1) ||
			    !dw_push(&dw_stack, val2))
				goto failed;

			break;
		case DW_OP_swap:
			if (!dw_pop(&dw_stack, &val1) ||
			    !dw_pop(&dw_stack, &val2) ||
			    !dw_push(&dw_stack, val1) ||
			    !dw_push(&dw_stack, val2))
				goto failed;
			break;
		case DW_OP_rot:
			if (!dw_pop(&dw_stack, &val1) ||
			    !dw_pop(&dw_stack, &val2) ||
			    !dw_pop(&dw_stack, &val3) ||
			    !dw_push(&dw_stack, val1) ||
			    !dw_push(&dw_stack, val3) ||
			    !dw_push(&dw_stack, val2))
				goto failed;
			break;
		case DW_OP_deref:
		case DW_OP_deref_size:
			if (op->atom == DW_OP_deref_size &&
			    op->number > sizeof(Dwarf_Addr))
				goto failed;
			if (!stack_page_size) {
				stack_page_size = getpagesize();
				stack_start = raw_sp - (raw_sp % stack_page_size);
				stack_end = stack_start + info->stack_size;
			}
			if (!dw_pop(&dw_stack, &val1) ||
			    !read_addr(info->stack_data, stack_start, stack_end, raw_sp, val1, &val1))
				goto failed;
			if (op->atom == DW_OP_deref_size && op->number < 8)
				val1 &= (1ULL << (op->number * 8)) - 1;
			if (!dw_push(&dw_stack, val1))
				goto failed;
			break;

		case DW_OP_abs:
			if (!dw_pop(&dw_stack, &val1) ||
			    !dw_push(&dw_stack, llabs((int64_t)val1)))
				goto failed;
			break;
		case DW_OP_neg:
			if (!dw_pop(&dw_stack, &val1) ||
			    !dw_push(&dw_stack, -(int64_t)val1))
				goto failed;
			break;
		case DW_OP_not:
			if (!dw_pop(&dw_stack, &val1) ||
			    !dw_push(&dw_stack, ~val1))
				goto failed;
			break;
		case DW_OP_plus_uconst:
			if (!dw_pop(&dw_stack, &val1) ||
			    !dw_push(&dw_stack, val1 + op->number))
				goto failed;
			break;
		case DW_OP_and:
			if (!dw_pop(&dw_stack, &val2) ||
			    !dw_pop(&dw_stack, &val1) ||
			    !dw_push(&dw_stack, val1 & val2))
				goto failed;
			break;
		case DW_OP_div:
			if (!dw_pop(&dw_stack, &val2) ||
			    !dw_pop(&dw_stack, &val1))
				goto failed;
			if (val2 == 0)
				goto failed;
			if (!dw_push(&dw_stack, (int64_t)val1 / (int64_t)val2))
				goto failed;
			break;
		case DW_OP_mod:
			if (!dw_pop(&dw_stack, &val2) ||
			    !dw_pop(&dw_stack, &val1))
				goto failed;
			if (val2 == 0)
				goto failed;
			if (!dw_push(&dw_stack, val1 % val2))
				goto failed;
			break;
		case DW_OP_minus:
			if (!dw_pop(&dw_stack, &val2) ||
			    !dw_pop(&dw_stack, &val1) ||
			    !dw_push(&dw_stack, val1 - val2))
				goto failed;
			break;
		case DW_OP_xor:
			if (!dw_pop(&dw_stack, &val2) ||
			    !dw_pop(&dw_stack, &val1) ||
			    !dw_push(&dw_stack, val1 ^ val2))
				goto failed;
			break;
		case DW_OP_shr:
			if (!dw_pop(&dw_stack, &val2) ||
			    !dw_pop(&dw_stack, &val1) ||
			    !dw_push(&dw_stack, val1 >> val2))
				goto failed;
			break;
		case DW_OP_shl:
			if (!dw_pop(&dw_stack, &val2) ||
			    !dw_pop(&dw_stack, &val1) ||
			    !dw_push(&dw_stack, val1 << val2))
				goto failed;
			break;
		case DW_OP_plus:
			if (!dw_pop(&dw_stack, &val2) ||
			    !dw_pop(&dw_stack, &val1) ||
			    !dw_push(&dw_stack, val1 + val2))
				goto failed;
			break;
		case DW_OP_or:
			if (!dw_pop(&dw_stack, &val2) ||
			    !dw_pop(&dw_stack, &val1) ||
			    !dw_push(&dw_stack, val1 | val2))
				goto failed;
			break;
		case DW_OP_mul:
			if (!dw_pop(&dw_stack, &val2) ||
			    !dw_pop(&dw_stack, &val1) ||
			    !dw_push(&dw_stack, val1 * val2))
				goto failed;
			break;
		case DW_OP_shra:
			if (!dw_pop(&dw_stack, &val2) ||
			    !dw_pop(&dw_stack, &val1) ||
			    !dw_push(&dw_stack, (int64_t)val1 >> (int64_t)val2))
				goto failed;
			break;
		case DW_OP_le:
			if (!dw_pop(&dw_stack, &val2) ||
			    !dw_pop(&dw_stack, &val1) ||
			    !dw_push(&dw_stack, (int64_t)val1 <= (int64_t)val2))
				goto failed;
			break;
		case DW_OP_ge:
			if (!dw_pop(&dw_stack, &val2) ||
			    !dw_pop(&dw_stack, &val1) ||
			    !dw_push(&dw_stack, (int64_t)val1 >= (int64_t)val2))
				goto failed;
			break;
		case DW_OP_eq:
			if (!dw_pop(&dw_stack, &val2) ||
			    !dw_pop(&dw_stack, &val1) ||
			    !dw_push(&dw_stack, (int64_t)val1 == (int64_t)val2))
				goto failed;
			break;
		case DW_OP_lt:
			if (!dw_pop(&dw_stack, &val2) ||
			    !dw_pop(&dw_stack, &val1) ||
			    !dw_push(&dw_stack, (int64_t)val1 < (int64_t)val2))
				goto failed;
			break;
		case DW_OP_gt:
			if (!dw_pop(&dw_stack, &val2) ||
			    !dw_pop(&dw_stack, &val1) ||
			    !dw_push(&dw_stack, (int64_t)val1 > (int64_t)val2))
				goto failed;
			break;
		case DW_OP_ne:
			if (!dw_pop(&dw_stack, &val2) ||
			    !dw_pop(&dw_stack, &val1) ||
			    !dw_push(&dw_stack, (int64_t)val1 != (int64_t)val2))
				goto failed;
			break;
		case DW_OP_bra:
			if (!dw_pop(&dw_stack, &val1))
				goto failed;
			if (val1 == 0)
				break;
		case DW_OP_skip:;
			Dwarf_Word offset =
				op->offset + 1 + 2 + (int16_t)op->number;
			const Dwarf_Op *found =
				bsearch((void *)(uintptr_t)offset, ops, nops,
					sizeof(*ops), compare);
			if (found == NULL)
				goto failed;
			op = found - 1;
			break;
		case DW_OP_nop:
			break;
		case DW_OP_call_frame_cfa:;
			Dwarf_Op *cfa_ops;
			int cfa_nops;
			Dwarf_Addr cfa;
			GU_VERBOSE(THREE_TAB_STR "Call CFA");
			if (gu_cfi_get_ops(0, &cfa_ops, &cfa_nops, true) != 0 ||
			    !gu_dwarf_ops_eval(NULL, cfa_ops, cfa_nops, &cfa, bias,
					       raw_sp, info) ||
			    !dw_push(&dw_stack, cfa))
				goto failed;
			is_location = true;
			break;
		case DW_OP_stack_value:
			is_location = false;
			break;
		default:
			goto failed;
		}
	}
	if (!dw_pop(&dw_stack, result))
		goto failed;
	if (is_location) {
		if (!stack_page_size) {
			stack_page_size = getpagesize();
			stack_start = raw_sp - (raw_sp % stack_page_size);
			stack_end = stack_start + info->stack_size;
		}
		if (!read_addr(info->stack_data, stack_start, stack_end, raw_sp, *result, result))
			goto failed;
	}

	return true;

failed:
	GU_VERBOSE(THREE_TAB_STR "Failed to evaluate DWARF expression");
	return false;
}

enum gu_unwind_reason gen_reg(Dwarf_Frame *frame, int regno, uint64_t bias, uint64_t raw_sp,
			  struct gu_stack_info *info, uint64_t *val)
{
	Dwarf_Op reg_ops_mem[3], *reg_ops;
	int reg_nops;
	enum gu_unwind_reason reason = GU_UNWIND_REASON_OK;

	int ret = gu_cfi_get_ops(trans_reg_type(regno), &reg_ops, &reg_nops, false);
	if (ret < 0) {
		reason = GU_UNWIND_REASON_CFI_FRAME_CFA_FAILED;
		goto failed;
	}

	GU_VERBOSE(THREE_TAB_STR "return reg %d ops dump, len %ld", regno, reg_nops);

	for (int i = 0; i < reg_nops; ++i)
		GU_VERBOSE(FOUR_TAB_STR "%s %ld + %ld", op_name(reg_ops[i].atom),
		      reg_ops[i].number, reg_ops[i].number2);

	stack_read_out_of_range = false;
	stack_read_out_of_range_addr = 0;
	stack_read_out_of_range_start = 0;
	stack_read_out_of_range_end = 0;
	stack_read_out_of_range_raw_sp = 0;
	ret = fast_dwarf_ops_eval(reg_ops, reg_nops, val, bias, raw_sp, info) ||
	      gu_dwarf_ops_eval(frame, reg_ops, reg_nops, val, bias, raw_sp, info);
	if (!ret) {
		reason = stack_read_out_of_range ?
			GU_UNWIND_REASON_STACK_READ_OUT_OF_RANGE :
			GU_UNWIND_REASON_CFI_FRAME_CFA_CALC_FAILED;
		goto failed;
	}

failed:

	return reason;
}
