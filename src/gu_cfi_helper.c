/* SPDX-License-Identifier: LGPL-3.0-or-later */
/*
 * Copyright (C) 2026 ByteDance Inc.
 *
 * This file is part of libgunwinder and is distributed under the
 * GNU Lesser General Public License v3.0 or later.
 *
 * The CFI decode and frame-rule edge cases handled here were designed with
 * conceptual guidance from elfutils/libdw CFI behavior and cross-checks,
 * including behavior covered by cfi.c, dwarf_frame_register.c,
 * dwarf_frame_cfa.c, and libdwfl/frame_unwind.c:
 *
 *   Copyright (C) 2009-2010, 2014, 2015 Red Hat, Inc.
 *   Copyright (C) 2013, 2014, 2016, 2024 Red Hat, Inc.
 *
 * elfutils is available under LGPL-3.0-or-later or GPL-2.0-or-later.
 * libgunwinder keeps its own compact CFI cache/parser layout rather than
 * copying the upstream implementation.
 */

#include "gu_cfi_helper.h"
#include "gu_stacktrace.h"
#include "uthash.h"

#define DW_CFA_ENTRY(name)                                                                                                                                                                                                                                     \
	{                                                                                                                                                                                                                                                      \
		name, #name                                                                                                                                                                                                                                    \
	}

typedef struct {
	int value;
	const char *name;
} DW_CFA_Mapping;

static const DW_CFA_Mapping dw_reg_mappings[] = {
	DW_CFA_ENTRY(reg_unspecified), DW_CFA_ENTRY(reg_undefined), DW_CFA_ENTRY(reg_same_value), DW_CFA_ENTRY(reg_offset), DW_CFA_ENTRY(reg_val_offset), DW_CFA_ENTRY(reg_register), DW_CFA_ENTRY(reg_expression), DW_CFA_ENTRY(reg_val_expression),
};

static const DW_CFA_Mapping dw_cfa_mappings[] = { DW_CFA_ENTRY(DW_CFA_advance_loc),
						  DW_CFA_ENTRY(DW_CFA_offset),
						  DW_CFA_ENTRY(DW_CFA_restore),
						  DW_CFA_ENTRY(DW_CFA_extended),
						  DW_CFA_ENTRY(DW_CFA_nop),
						  DW_CFA_ENTRY(DW_CFA_set_loc),
						  DW_CFA_ENTRY(DW_CFA_advance_loc1),
						  DW_CFA_ENTRY(DW_CFA_advance_loc2),
						  DW_CFA_ENTRY(DW_CFA_advance_loc4),
						  DW_CFA_ENTRY(DW_CFA_offset_extended),
						  DW_CFA_ENTRY(DW_CFA_restore_extended),
						  DW_CFA_ENTRY(DW_CFA_undefined),
						  DW_CFA_ENTRY(DW_CFA_same_value),
						  DW_CFA_ENTRY(DW_CFA_register),
						  DW_CFA_ENTRY(DW_CFA_remember_state),
						  DW_CFA_ENTRY(DW_CFA_restore_state),
						  DW_CFA_ENTRY(DW_CFA_def_cfa),
						  DW_CFA_ENTRY(DW_CFA_def_cfa_register),
						  DW_CFA_ENTRY(DW_CFA_def_cfa_offset),
						  DW_CFA_ENTRY(DW_CFA_def_cfa_expression),
						  DW_CFA_ENTRY(DW_CFA_expression),
						  DW_CFA_ENTRY(DW_CFA_offset_extended_sf),
						  DW_CFA_ENTRY(DW_CFA_def_cfa_sf),
						  DW_CFA_ENTRY(DW_CFA_def_cfa_offset_sf),
						  DW_CFA_ENTRY(DW_CFA_val_offset),
						  DW_CFA_ENTRY(DW_CFA_val_offset_sf),
						  DW_CFA_ENTRY(DW_CFA_val_expression),
						  DW_CFA_ENTRY(DW_CFA_low_user),
						  DW_CFA_ENTRY(DW_CFA_MIPS_advance_loc8),
						  DW_CFA_ENTRY(DW_CFA_GNU_window_save),
						  DW_CFA_ENTRY(DW_CFA_GNU_args_size),
						  DW_CFA_ENTRY(DW_CFA_GNU_negative_offset_extended),
						  DW_CFA_ENTRY(DW_CFA_high_user) };

const char *get_dw_cfa_name(int value)
{
	size_t num_mappings = sizeof(dw_cfa_mappings) / sizeof(dw_cfa_mappings[0]);
	for (size_t i = 0; i < num_mappings; i++) {
		if (dw_cfa_mappings[i].value == value) {
			return dw_cfa_mappings[i].name;
		}
	}
	return "Unknown";
}

const char *get_dw_reg_name(int value)
{
	size_t num_mappings = sizeof(dw_reg_mappings) / sizeof(dw_reg_mappings[0]);
	for (size_t i = 0; i < num_mappings; i++) {
		if (dw_reg_mappings[i].value == value) {
			return dw_reg_mappings[i].name;
		}
	}
	return "Unknown";
}

static uint64_t decode_uleb128(const uint8_t *buffer, int *size)
{
	uint64_t result = 0;
	size_t shift = 0;
	size_t count = 0;

	while (count < 8) {
		uint8_t byte = buffer[count++];
		result |= (byte & 0x7F) << shift;
		if ((byte & 0x80) == 0)
			break;
		shift += 7;
	}

	if (size)
		*size = count;

	return result;
}

static uint64_t decode_sleb128(const uint8_t *buffer, int *size)
{
	uint64_t result = 0;
	size_t shift = 0;
	size_t count = 0;
	uint8_t byte;

	while (count < 10) {
		byte = buffer[count++];
		result |= (uint64_t)(byte & 0x7F) << shift;
		if ((byte & 0x80) == 0) {
			break;
		}
		shift += 7;
	}

	if (byte & 0x40) {
		result |= (~(uint64_t)0) << (shift + 7);
	}

	if (size) {
		*size = (int)count;
	}

	return result;
}

static int get_encoding_size(unsigned int type, const unsigned char *test_buf)
{
	if (type == DW_EH_PE_omit)
		return 0;

	int size;
	switch (type & 0xf) {
	case DW_EH_PE_uleb128:
		decode_uleb128(test_buf, &size);
		return size;
	case DW_EH_PE_sleb128:
		decode_sleb128(test_buf, &size);
		return size;
	case DW_EH_PE_udata2:
	case DW_EH_PE_sdata2:
		return 2;
	case DW_EH_PE_udata4:
	case DW_EH_PE_sdata4:
		return 4;
	case DW_EH_PE_udata8:
	case DW_EH_PE_sdata8:
		return 8;
	case DW_EH_PE_absptr:
		return 8;
	}

	return 0;
}

static const unsigned char *decode_read(const unsigned char *buf, unsigned int type, unsigned long *res)
{
	int size = 0;
	switch (type & 0xf) {
	case DW_EH_PE_uleb128:
		*res = decode_uleb128(buf, &size);
		buf = buf + size;
		break;
	case DW_EH_PE_sleb128:
		*res = decode_sleb128(buf, &size);
		buf = buf + size;
		break;
	case DW_EH_PE_udata2:
		*res = *((uint16_t *)buf);
		buf = buf + 2;
		break;
	case DW_EH_PE_udata4:
		*res = *((uint32_t *)buf);
		buf = buf + 4;
		break;
	case DW_EH_PE_udata8:
		*res = *((uint64_t *)buf);
		buf = buf + 8;
		break;
	case DW_EH_PE_absptr:
		*res = *((uint64_t *)buf);
		buf = buf + 8;
		break;
	case DW_EH_PE_sdata2:
		*res = *((int16_t *)buf);
		buf = buf + 2;
		break;
	case DW_EH_PE_sdata4:
		*res = *((int32_t *)buf);
		buf = buf + 4;
		break;
	case DW_EH_PE_sdata8:
		*res = *((int64_t *)buf);
		buf = buf + 8;
		break;
	default:
		return NULL;
	}

	return buf;
}

static bool decode_read_fits(const unsigned char *buf, const unsigned char *end,
			     unsigned int type)
{
	size_t max_len;

	if (!buf || !end || buf > end)
		return false;

	switch (type & 0xf) {
	case DW_EH_PE_uleb128:
		max_len = 8;
		break;
	case DW_EH_PE_sleb128:
		max_len = 10;
		break;
	case DW_EH_PE_udata2:
	case DW_EH_PE_sdata2:
		return (size_t)(end - buf) >= 2;
	case DW_EH_PE_udata4:
	case DW_EH_PE_sdata4:
		return (size_t)(end - buf) >= 4;
	case DW_EH_PE_udata8:
	case DW_EH_PE_sdata8:
	case DW_EH_PE_absptr:
		return (size_t)(end - buf) >= 8;
	default:
		return false;
	}

	for (size_t i = 0; i < max_len && buf + i < end; i++) {
		if ((buf[i] & 0x80) == 0)
			return true;
	}

	return false;
}

static const unsigned char *decode_read_checked(const unsigned char *buf,
						const unsigned char *end,
						unsigned int type,
						unsigned long *res)
{
	const unsigned char *next;

	if (!decode_read_fits(buf, end, type))
		return NULL;
	next = decode_read(buf, type, res);
	if (!next || next > end)
		return NULL;
	return next;
}

static bool block_fits(const unsigned char *data, const unsigned char *end,
		       size_t len)
{
	return data && end && data <= end && len <= (size_t)(end - data);
}

#define CFI_PRIMARY_MAX 0x3f

enum cfi_reg_type trans_reg_type(int regno)
{
	switch (regno) {
	case reg_name_rsp:
		return REG_TYPE_RSP;
#ifdef GUNWINDER_ARM64
	case reg_name_lr:
		return REG_TYPE_RIP;
#endif
	case reg_name_rip:
		return REG_TYPE_RIP;
	case reg_name_rbp:
		return REG_TYPE_RBP;
	default:
		return REG_TYPE_MAX;
	}
}

bool _default_init = false;

/* arch */
static const uint8_t _default_init_cfi[] = {
#ifndef GUNWINDER_ARM64
	DW_CFA_def_cfa, 7, 8, DW_CFA_offset + 16, 1,
#endif
	DW_CFA_same_value, 6, DW_CFA_val_offset, 7, 0,
};

static struct gu_cfi_calc_ctx _default_calc_ctx = { 0 };

void print_bytes(const uint8_t *ins_start, const uint8_t *ins_end)
{
	const uint8_t *current = ins_start;
	int count = 0;

	while (current < ins_end) {
		printf("%02x ", *current);
		count++;
		if (count % 16 == 0) {
			printf("\n");
		}
		current++;
	}
	if (count % 16 != 0) {
		printf("\n");
	}
}

int init_calc_ctx_by_ins(struct gu_cfi *cfi, struct gu_cfi_cie *cie, struct gu_cfi_calc_ctx *calc_ctx, const uint8_t *ins_start, const uint8_t *ins_end, uint64_t loc, uint64_t find_pc)
{
	const uint8_t *ins = ins_start;

	bool in_cie = (ins_start == cie->initial_instructions);
	struct gu_cfi_calc_ctx *tmp_ctx;

#define DECODE_CFI(TYPE, OUT) do { \
	ins = decode_read_checked(ins, ins_end, (TYPE), &(OUT)); \
	if (!ins) \
		return -1; \
} while (0)

	while (ins < ins_end) {
		uint8_t op = *ins++;
		Dwarf_Word operand = op & CFI_PRIMARY_MAX;
		Dwarf_Word regno;
		Dwarf_Word offset;
		Dwarf_Word sf_offset;

		switch (op) {
		case DW_CFA_advance_loc1:
			if (ins >= ins_end)
				return -1;
			operand = *ins++;
			loc += operand * cie->code_alignment_factor;
			break;

		case DW_CFA_advance_loc + 0 ... DW_CFA_advance_loc + CFI_PRIMARY_MAX:
			loc += operand * cie->code_alignment_factor;
			break;

		case DW_CFA_advance_loc2:
			DECODE_CFI(DW_EH_PE_udata2, operand);
			loc += operand * cie->code_alignment_factor;
			break;

		case DW_CFA_advance_loc4:
			DECODE_CFI(DW_EH_PE_udata4, operand);
			loc += operand * cie->code_alignment_factor;
			break;

		case DW_CFA_MIPS_advance_loc8:
			DECODE_CFI(DW_EH_PE_udata8, operand);
			loc += operand * cie->code_alignment_factor;
			break;

		case DW_CFA_set_loc:
			DECODE_CFI(cie->fde_encoding, loc);
			break;

		case DW_CFA_def_cfa:
			DECODE_CFI(DW_EH_PE_uleb128, operand);
			DECODE_CFI(DW_EH_PE_uleb128, offset);
			// GU_OUTPUT("cfa1: cfa_offset atom %lx num1 %d num2 %d", DW_OP_bregx, operand, offset);
			calc_ctx->cfa_rule = cfa_offset;
			calc_ctx->cfa_data.offset.number = operand;
			calc_ctx->cfa_data.offset.number2 = offset;
			calc_ctx->cfa_data.offset.atom = DW_OP_bregx;
			calc_ctx->cfa_data.offset.offset = 0;
			continue;

		case DW_CFA_def_cfa_sf:
			DECODE_CFI(DW_EH_PE_uleb128, operand);
			DECODE_CFI(DW_EH_PE_sleb128, sf_offset);
			offset = sf_offset * cie->data_alignment_factor;
			// GU_OUTPUT("cfa2: cfa_offset atom %lx num1 %d num2 %d", DW_OP_bregx, operand, offset);
			calc_ctx->cfa_rule = cfa_offset;
			calc_ctx->cfa_data.offset.number = operand;
			calc_ctx->cfa_data.offset.number2 = offset;
			calc_ctx->cfa_data.offset.atom = DW_OP_bregx;
			calc_ctx->cfa_data.offset.offset = 0;
			continue;

		case DW_CFA_def_cfa_register:
			DECODE_CFI(DW_EH_PE_uleb128, operand);
			// GU_OUTPUT("cfa3: cfa_offset atom %lx num1 %d", DW_OP_bregx, operand, operand);
			calc_ctx->cfa_data.offset.number = operand;
			continue;

		case DW_CFA_def_cfa_offset:
			DECODE_CFI(DW_EH_PE_uleb128, offset);
			calc_ctx->cfa_data.offset.number2 = offset;
			// GU_OUTPUT("cfa4: cfa_offset atom %lx num2 %d", DW_OP_bregx, offset);
			continue;

		case DW_CFA_def_cfa_offset_sf:
			DECODE_CFI(DW_EH_PE_sleb128, sf_offset);
			offset = sf_offset * cie->data_alignment_factor;
			// GU_OUTPUT("cfa5: cfa_offset atom %lx num2 %d", DW_OP_bregx, offset);
			calc_ctx->cfa_data.offset.number2 = offset;
			continue;

		case DW_CFA_def_cfa_expression:
			DECODE_CFI(DW_EH_PE_uleb128, operand);
			if (!block_fits(ins, ins_end, operand))
				return -1;
			calc_ctx->cfa_rule = cfa_expr;
			calc_ctx->cfa_data.expr.data = (unsigned char *)ins;
			calc_ctx->cfa_data.expr.length = operand;
			ins += operand;
			continue;

		case DW_CFA_undefined:
			DECODE_CFI(DW_EH_PE_uleb128, regno);
			regno = trans_reg_type(regno);
			if (regno >= REG_TYPE_MAX)
				continue;
			calc_ctx->regs[regno].rule = reg_undefined;
			calc_ctx->regs[regno].value = 0;
			continue;

		case DW_CFA_same_value:
			DECODE_CFI(DW_EH_PE_uleb128, regno);
			regno = trans_reg_type(regno);
			if (regno >= REG_TYPE_MAX)
				continue;
			calc_ctx->regs[regno].rule = reg_same_value;
			calc_ctx->regs[regno].value = 0;
			continue;

		case DW_CFA_remember_state:
			tmp_ctx = malloc(sizeof(struct gu_cfi_calc_ctx));
			if (tmp_ctx == NULL)
				return -1;
			memcpy(tmp_ctx, calc_ctx, sizeof(struct gu_cfi_calc_ctx));
			calc_ctx->prev = tmp_ctx;
			continue;

		case DW_CFA_restore_state:
			tmp_ctx = calc_ctx->prev;
			if (tmp_ctx == NULL)
				return -1;

			memcpy(calc_ctx, tmp_ctx, sizeof(struct gu_cfi_calc_ctx));
			free(tmp_ctx);
			continue;

		case DW_CFA_offset_extended:
			DECODE_CFI(DW_EH_PE_uleb128, operand);
			DECODE_CFI(DW_EH_PE_uleb128, offset);
			offset *= cie->data_alignment_factor;
			operand = trans_reg_type(operand);
			if (operand >= REG_TYPE_MAX)
				continue;
			calc_ctx->regs[operand].rule = reg_offset;
			calc_ctx->regs[operand].value = offset;
			continue;

		case DW_CFA_offset + 0 ... DW_CFA_offset + CFI_PRIMARY_MAX:
			DECODE_CFI(DW_EH_PE_uleb128, offset);
			offset *= cie->data_alignment_factor;
			operand = trans_reg_type(operand);
			if (operand >= REG_TYPE_MAX)
				continue;
			calc_ctx->regs[operand].rule = reg_offset;
			calc_ctx->regs[operand].value = offset;
			continue;

		case DW_CFA_offset_extended_sf:
			DECODE_CFI(DW_EH_PE_uleb128, operand);
			DECODE_CFI(DW_EH_PE_sleb128, sf_offset);
			offset = sf_offset * cie->data_alignment_factor;
			operand = trans_reg_type(operand);
			if (operand >= REG_TYPE_MAX)
				continue;
			calc_ctx->regs[operand].rule = reg_offset;
			calc_ctx->regs[operand].value = offset;
			continue;

		case DW_CFA_GNU_negative_offset_extended:
			DECODE_CFI(DW_EH_PE_uleb128, operand);
			DECODE_CFI(DW_EH_PE_uleb128, offset);
			/* GNU extension obsoleted by DW_CFA_offset_extended_sf.  */
			sf_offset = -offset;
			offset = sf_offset * cie->data_alignment_factor;
			operand = trans_reg_type(operand);
			if (operand >= REG_TYPE_MAX)
				continue;
			calc_ctx->regs[operand].rule = reg_offset;
			calc_ctx->regs[operand].value = offset;
			continue;

		case DW_CFA_val_offset:
			DECODE_CFI(DW_EH_PE_uleb128, operand);
			DECODE_CFI(DW_EH_PE_uleb128, offset);
			offset *= cie->data_alignment_factor;
			operand = trans_reg_type(operand);
			if (operand >= REG_TYPE_MAX)
				continue;
			calc_ctx->regs[operand].rule = reg_val_offset;
			calc_ctx->regs[operand].value = offset;
			continue;

		case DW_CFA_val_offset_sf:
			DECODE_CFI(DW_EH_PE_uleb128, operand);
			DECODE_CFI(DW_EH_PE_sleb128, sf_offset);
			offset = sf_offset * cie->data_alignment_factor;
			operand = trans_reg_type(operand);
			if (operand >= REG_TYPE_MAX)
				continue;
			calc_ctx->regs[operand].rule = reg_val_offset;
			calc_ctx->regs[operand].value = offset;
			continue;

		case DW_CFA_register:
			DECODE_CFI(DW_EH_PE_uleb128, regno);
			DECODE_CFI(DW_EH_PE_uleb128, operand);
			regno = trans_reg_type(regno);
			if (regno >= REG_TYPE_MAX)
				continue;
			calc_ctx->regs[regno].rule = reg_register;
			calc_ctx->regs[regno].value = operand;
			continue;

		case DW_CFA_expression:
			DECODE_CFI(DW_EH_PE_uleb128, regno);
			offset = ins - (const uint8_t *)cfi->cfi_data->d_buf;
			DECODE_CFI(DW_EH_PE_uleb128, operand);
			if (!block_fits(ins, ins_end, operand))
				return -1;
			ins += operand;
			regno = trans_reg_type(regno);
			if (regno >= REG_TYPE_MAX)
				continue;
			calc_ctx->regs[regno].rule = reg_expression;
			calc_ctx->regs[regno].value = offset;
			continue;

		case DW_CFA_val_expression:
			DECODE_CFI(DW_EH_PE_uleb128, regno);
			offset = ins - (const uint8_t *)cfi->cfi_data->d_buf;
			DECODE_CFI(DW_EH_PE_uleb128, operand);
			if (!block_fits(ins, ins_end, operand))
				return -1;
			ins += operand;
			regno = trans_reg_type(regno);
			if (regno >= REG_TYPE_MAX)
				continue;
			calc_ctx->regs[regno].rule = reg_val_expression;
			calc_ctx->regs[regno].value = offset;
			continue;

		case DW_CFA_restore_extended:
			DECODE_CFI(DW_EH_PE_uleb128, operand);
			if (in_cie)
				continue;
			operand = trans_reg_type(operand);
			if (operand >= REG_TYPE_MAX)
				continue;
			calc_ctx->regs[operand] = cie->cie_calc_ctx.regs[operand];
			continue;

		case DW_CFA_restore + 0 ... DW_CFA_restore + CFI_PRIMARY_MAX:

			if (in_cie)
				continue;
			operand = trans_reg_type(operand);
			if (operand >= REG_TYPE_MAX)
				continue;
			calc_ctx->regs[operand] = cie->cie_calc_ctx.regs[operand];
			continue;

		case DW_CFA_nop:
			continue;

		case DW_CFA_GNU_args_size:
			DECODE_CFI(DW_EH_PE_uleb128, operand);
			continue;

		default:
			continue;
		}

		if (find_pc < loc)
			break;
	}

#undef DECODE_CFI
	return 0;
}

static struct gu_cfi_cie *init_cie_from_buf(struct gu_cfi *cfi, Dwarf_Off cie_off, Dwarf_CIE *dwarf_cie)
{
	struct gu_cfi_cie *cie = NULL;

	cie = calloc(1, sizeof(struct gu_cfi_cie));
	if (!cie)
		return NULL;

	cfi->cfi_mem_usage += sizeof(struct gu_cfi_cie);

	cie->offset = cie_off;

	cie->code_alignment_factor = dwarf_cie->code_alignment_factor;
	cie->data_alignment_factor = dwarf_cie->data_alignment_factor;
	cie->return_address_register = dwarf_cie->return_address_register;
	cie->initial_instructions = dwarf_cie->initial_instructions;
	cie->initial_instructions_end = dwarf_cie->initial_instructions_end;

	cie->fde_augmentation_data_size = 0;
	cie->sized_augmentation_data = false;
	cie->signal_frame = false;

	cie->fde_encoding = DW_EH_PE_absptr;
	cie->lsda_encoding = DW_EH_PE_omit;

	const uint8_t *data = dwarf_cie->augmentation_data;
	uint8_t tmp_encoding;
	const char *c = dwarf_cie->augmentation;
	while (*c != '\0') {
		switch (*(c++)) {
		case 'z':
			cie->sized_augmentation_data = true;
			continue;
		case 'S':
			cie->signal_frame = true;
			continue;
		case 'L':
			cie->lsda_encoding = *data++;
			if (!cie->sized_augmentation_data)
				cie->fde_augmentation_data_size += get_encoding_size(cie->lsda_encoding, data);
			continue;
		case 'R':
			cie->fde_encoding = *data++;
			continue;
		case 'P':
			tmp_encoding = *data++;
			data += get_encoding_size(tmp_encoding, data);
			continue;
		default:
			if (cie->sized_augmentation_data)
				continue;
		}
		break;
	}
	// GU_VERBOSE("");
	//GU_VERBOSE("		cie->fde_encoding = %d, cie->lsda_encoding = %d signal_frame = %d", cie->fde_encoding, cie->lsda_encoding, cie->signal_frame);

	if ((cie->fde_encoding & 0xf) == DW_EH_PE_absptr)
		cie->fde_encoding |= DW_EH_PE_udata8;

	if (_default_init == false) {
		_default_init = true;
		init_calc_ctx_by_ins(cfi, cie, &_default_calc_ctx, _default_init_cfi, _default_init_cfi + sizeof(_default_init_cfi), 0, -1);
	}

	memcpy(&cie->cie_calc_ctx, &_default_calc_ctx,
	       sizeof(cie->cie_calc_ctx));
	cie->cie_calc_ctx.prev = NULL;

	int ret = init_calc_ctx_by_ins(cfi, cie, &cie->cie_calc_ctx, cie->initial_instructions, cie->initial_instructions_end, 0, -1);
	if (ret != 0) {
		GU_OUTPUT("CIE Ins init failed.");
		free(cie);
		return NULL;
	}

	return cie;
}

// FDE
static int init_fde_from_entry(struct gu_cfi *cfi, struct gu_cfi_fde *fde, Dwarf_CFI_Entry *entry)
{
	Dwarf_FDE *fde_dwarf = &entry->fde;
	struct gu_cfi_cie *cie = NULL;
	int ret = 0;

	HASH_FIND_INT(cfi->cie_list, &fde_dwarf->CIE_pointer, cie);
	if (!cie) {
		Dwarf_Off off_cie = 0, next_off_cie = 0;
		Dwarf_CFI_Entry entry_cie;
		off_cie = fde_dwarf->CIE_pointer;
		ret = dwarf_next_cfi(cfi->e_ident, cfi->cfi_data, cfi->eh_frame, off_cie, &next_off_cie, &entry_cie);
		if (ret != 0)
			return ret;

		if (entry_cie.cie.CIE_id != 0xffffffffffffffffULL)
			return -1;

		cie = init_cie_from_buf(cfi, off_cie, &entry_cie.cie);
		HASH_ADD_INT(cfi->cie_list, offset, cie);
	}

	uint64_t pc = 0;
	uint64_t size = 0;
	const unsigned char *buf = (const unsigned char *)fde_dwarf->start;
	const unsigned char *end = fde_dwarf->end;

	buf = decode_read_checked(buf, end, cie->fde_encoding, &pc);
	if (!buf)
		return -1;
	buf = decode_read_checked(buf, end, cie->fde_encoding, &size);
	if (!buf)
		return -1;

	if (cie->sized_augmentation_data) {
		Dwarf_Word len;
		buf = decode_read_checked(buf, end, DW_EH_PE_uleb128, &len);
		if (!buf || !block_fits(buf, end, len))
			return -1;
		buf += len;
	} else {
		if (!block_fits(buf, end, cie->fde_augmentation_data_size))
			return -1;
		buf += cie->fde_augmentation_data_size;
	}

	fde->cie = cie;
	fde->instructions = buf;
	fde->instructions_end = fde_dwarf->end;

	if ((cie->fde_encoding & 0x70) == DW_EH_PE_pcrel)
		pc = (((uint64_t)cfi->sh_off + (fde_dwarf->start - (const unsigned char *)cfi->cfi_data->d_buf) + (uint64_t)pc) & (0xffffffffffffffffUL));

	if (pc + size < pc)
		return -1;
	fde->start = pc;
	fde->end = pc + size;

	// GU_VERBOSE("FDE Init: PC [ %lx - %lx ] CIE pointer %p Ins [ %p - %p ]", fde->start, fde->end, fde->cie, fde->instructions, fde->instructions_end);

	return 0;
}

#define HDR_VERSION 1
static int gu_cfi_hdr_init_by_hdr(struct gu_cfi *cfi, const unsigned char *buf, size_t size, uint64_t eh_hdr_p_offset)
{
	const unsigned char *raw = buf;
	const unsigned char *end = raw + size;
	struct ehhdr_info *encoding;

	if (size < sizeof(struct ehhdr_info) || end < raw)
		return -1;

	encoding = (struct ehhdr_info *)buf;
	if (encoding->version != HDR_VERSION)
		return -1;

	if (encoding->eh_frame_t == DW_EH_PE_omit || encoding->fde_count_t == DW_EH_PE_omit || encoding->fde_p_t == DW_EH_PE_omit)
		return -1;

	cfi->eh_frame = true;

	unsigned long eh_frame_ptr;
	unsigned long fde_count;

	buf = buf + sizeof(struct ehhdr_info);

	buf = decode_read_checked(buf, end, encoding->eh_frame_t, &eh_frame_ptr);
	if (buf == NULL)
		return -1;

	buf = decode_read_checked(buf, end, encoding->fde_count_t, &fde_count);
	if (buf == NULL)
		return -1;
	cfi->fde_count = fde_count;

	struct interval_array_item *items = calloc(fde_count, sizeof(struct interval_array_item));
	if (!items)
		return -1;

	cfi->fdes = calloc(fde_count, sizeof(struct gu_cfi_fde));
	if (!cfi->fdes) {
		free(items);
		return -1;
	}

	cfi->cfi_mem_usage += cfi->fde_count * sizeof(struct gu_cfi_fde);

	int item_index = 0;

	while (item_index < fde_count && buf < end) {
		unsigned long loc, addr, offset, next_off;
		buf = decode_read_checked(buf, end, DW_EH_PE_sdata4, &loc);
		if (!buf)
			break;
		buf = decode_read_checked(buf, end, DW_EH_PE_sdata4, &addr);
		if (!buf)
			break;
		Dwarf_CFI_Entry entry;

		offset = addr - (eh_frame_ptr + 4);
		int ret = dwarf_next_cfi(cfi->e_ident, cfi->cfi_data, cfi->eh_frame, offset, &next_off, &entry);
		if (ret != 0)
			break;

		ret = init_fde_from_entry(cfi, &cfi->fdes[item_index], &entry);
		if (ret != 0)
			break;

		struct gu_cfi_fde *fde = &cfi->fdes[item_index];

		items[item_index].start = fde->start;
		items[item_index].end = fde->end;
		items[item_index].private = (void *)mark_interval_array_pointer_no_free((uint64_t)fde);
		item_index++;
	}

	cfi->hdr_interval_array = gu_interval_array_init(items, item_index);
	if (cfi->hdr_interval_array == NULL) {
		free(items);
		free(cfi->fdes);
		return -1;
	}

	cfi->cfi_mem_usage += item_index * sizeof(struct interval_array_item);

	free(items);

	return 0;
}

static int gu_cfi_hdr_init_by_scan(struct gu_cfi *cfi, bool is_eh)
{
	Dwarf_Off off = 0, next_off = 0;
	Dwarf_CFI_Entry entry;
	int ret, cie_count = 0, fde_count = 0, item_index = 0;

	cfi->eh_frame = is_eh;

	while ((ret = dwarf_next_cfi(cfi->e_ident, cfi->cfi_data, cfi->eh_frame, off, &next_off, &entry)) == 0) {
		if (entry.cie.CIE_id == 0xffffffffffffffffULL)
			cie_count++;
		else
			fde_count++;
		off = next_off;
	}

	struct interval_array_item *items = calloc(fde_count, sizeof(struct interval_array_item));
	if (!items)
		return -1;

	cfi->fdes = calloc(fde_count, sizeof(struct gu_cfi_fde));
	if (!cfi->fdes) {
		free(items);
		return -1;
	}

	off = 0;
	next_off = 0;

	while ((ret = dwarf_next_cfi(cfi->e_ident, cfi->cfi_data, cfi->eh_frame, off, &next_off, &entry)) == 0) {
		if (entry.cie.CIE_id == 0xffffffffffffffffULL) {
			off = next_off;
			continue;
		}

		ret = init_fde_from_entry(cfi, &cfi->fdes[item_index], &entry);
		if (ret != 0)
			break;

		struct gu_cfi_fde *fde = &cfi->fdes[item_index];

		items[item_index].start = fde->start;
		items[item_index].end = fde->end;
		items[item_index].private = (void *)mark_interval_array_pointer_no_free((uint64_t)fde);
		item_index++;

		off = next_off;
	}

	cfi->hdr_interval_array = gu_interval_array_init(items, item_index);
	if (cfi->hdr_interval_array == NULL) {
		free(items);
		free(cfi->fdes);
		return -1;
	}

	free(items);

	return 0;
}

static struct gu_cfi *gu_cfi_init_with_hdr(Elf *elf, Elf_Data *hdr_scn_data, Elf_Data *scn_data, uint64_t eh_hdr_p_offset, uint64_t frame_shoff, bool is_eh)
{
	struct gu_cfi *cfi = calloc(1, sizeof(struct gu_cfi));
	if (!cfi)
		return NULL;

	size_t size = 0;

	char *ident = elf_getident(elf, &size);
	if (ident == NULL)
		goto failed;

	cfi->e_ident = malloc(size);
	if (!cfi->e_ident)
		goto failed;

	memcpy(cfi->e_ident, ident, size);
	cfi->sh_off = frame_shoff;

	cfi->cfi_data = malloc(sizeof(Elf_Data));
	void *cfi_data_buf = malloc(scn_data->d_size);

	memcpy(cfi_data_buf, scn_data->d_buf, scn_data->d_size);
	memcpy(cfi->cfi_data, scn_data, sizeof(Elf_Data));

	cfi->cfi_mem_usage += sizeof(Elf_Data);
	cfi->cfi_data_mem_usage += scn_data->d_size;

	cfi->cfi_data->d_buf = cfi_data_buf;

	if (hdr_scn_data != NULL) {
		unsigned char *hdr_buf = hdr_scn_data->d_buf;
		size_t hdr_size = hdr_scn_data->d_size;
		if (gu_cfi_hdr_init_by_hdr(cfi, hdr_buf, hdr_size, eh_hdr_p_offset) != 0)
			goto failed;
	} else {
		if (gu_cfi_hdr_init_by_scan(cfi, is_eh) != 0)
			goto failed;
	}

	return cfi;

failed:
	if (cfi) {
		if (cfi->e_ident)
			free(cfi->e_ident);
		if (cfi->cfi_data) {
			if (cfi->cfi_data->d_buf)
				free(cfi->cfi_data->d_buf);
			free(cfi->cfi_data);
		}
		free(cfi);
	}

	return NULL;
}

struct gu_cfi *gu_cfi_init(struct per_elf_ctx *info)
{
	if (info->scn[ELF_SCN_TYPE_DWARF_FRAME] == NULL && info->scn[ELF_SCN_TYPE_EH_FRAME] == NULL && info->scn[ELF_SCN_TYPE_ZDWARF_FRAME] == NULL)
		return NULL;

	int scn_type = 0;
	bool is_ehframe = 0;
	Elf_Scn *hdr_scn = NULL, *scn = NULL;
	Elf_Data *hdr_scn_data = NULL, *scn_data = NULL;

	if (info->scn[ELF_SCN_TYPE_DWARF_FRAME] != NULL)
		scn_type = ELF_SCN_TYPE_DWARF_FRAME;
	else if (info->scn[ELF_SCN_TYPE_EH_FRAME] != NULL)
		scn_type = ELF_SCN_TYPE_EH_FRAME;
	else if (info->scn[ELF_SCN_TYPE_ZDWARF_FRAME] != NULL)
		scn_type = ELF_SCN_TYPE_ZDWARF_FRAME;

	// default use dwarf_drame, only use eh_frame if dwarf_frame is smaller than eh_frame
	if (info->scn[ELF_SCN_TYPE_EH_FRAME] != NULL && info->scn[ELF_SCN_TYPE_DWARF_FRAME] != NULL) {
		GElf_Shdr eh_frame_shdr, dwarf_frame_shdr;
		gelf_getshdr(info->scn[ELF_SCN_TYPE_EH_FRAME], &eh_frame_shdr);
		gelf_getshdr(info->scn[ELF_SCN_TYPE_DWARF_FRAME], &dwarf_frame_shdr);
		if (eh_frame_shdr.sh_size > dwarf_frame_shdr.sh_size)
			scn_type = ELF_SCN_TYPE_EH_FRAME;
	}

	scn = info->scn[scn_type];
	if (scn == NULL)
		return NULL;

	// golang eh_frame is not good support, directly use debug_frame
	if (scn_type == ELF_SCN_TYPE_EH_FRAME && (info->scn[ELF_SCN_TYPE_GO_BUILD_ID] == NULL || (info->scn[ELF_SCN_TYPE_GO_BUILD_ID] != NULL && info->scn[ELF_SCN_TYPE_ZDWARF_FRAME] == NULL && info->scn[ELF_SCN_TYPE_DWARF_FRAME] == NULL))) {
		hdr_scn = info->scn[ELF_SCN_TYPE_EH_FRAME_HDR];
		hdr_scn_data = elf_getdata(hdr_scn, NULL);
		/* no need to check */
	}

	GElf_Shdr shdr;
	if (gelf_getshdr(scn, &shdr) != &shdr)
		return NULL;

	scn_data = elf_rawdata(scn, NULL);

	if (scn_type == ELF_SCN_TYPE_ZDWARF_FRAME || shdr.sh_flags & SHF_COMPRESSED)
		elf_compress(scn, 0, 0);

	scn_data = elf_getdata(scn, NULL);
	if (scn_data == NULL)
		return NULL;

	Elf *elf = info->scn_elf[scn_type];

	struct gu_cfi *cfi = gu_cfi_init_with_hdr(elf, hdr_scn_data, scn_data, info->eh_frame_hdr_off, shdr.sh_addr, scn_type == ELF_SCN_TYPE_EH_FRAME);

	info->gu_cfi = cfi;

	return cfi;
}

void gu_cfi_destroy(struct gu_cfi *cfi)
{
	if (!cfi)
		return;
	if (cfi->e_ident)
		free(cfi->e_ident);
	if (cfi->cfi_data) {
		if (cfi->cfi_data->d_buf)
			free(cfi->cfi_data->d_buf);
		free(cfi->cfi_data);
	}

	if (cfi->fdes)
		free(cfi->fdes);
	if (cfi->hdr_interval_array)
		gu_interval_array_destroy(cfi->hdr_interval_array);
	if (cfi->cie_list) {
		struct gu_cfi_cie *cie = NULL, *tmp = NULL;
		HASH_ITER (hh, cfi->cie_list, cie, tmp) {
			HASH_DEL(cfi->cie_list, cie);
			free(cie);
		}
	}
	free(cfi);
}

static Dwarf_Op static_ops[DWARF_OPS_MAX] = { 0 };

struct backtrace_ops_info {
	Dwarf_Op *ops;
	int ops_size;
};

static Dwarf_Op rip_ops[DWARF_OPS_MAX] = { 0 };
static Dwarf_Op rbp_ops[DWARF_OPS_MAX] = { 0 };
static Dwarf_Op rsp_ops[DWARF_OPS_MAX] = { 0 };
static Dwarf_Op cfa_ops[DWARF_OPS_MAX] = { 0 };

static struct backtrace_ops_info ops_arr[REG_TYPE_MAX] = {
	[REG_TYPE_RIP] = { rip_ops, 0 },
	[REG_TYPE_RBP] = { rbp_ops, 0 },
	[REG_TYPE_RSP] = { rsp_ops, 0 },
};

struct backtrace_ops_info cfa_ops_info = {
	.ops = cfa_ops,
	.ops_size = 0,
};

static size_t gu_cfi_parse_cache_index(uint64_t pc)
{
	return ((pc >> 4) ^ (pc >> 12)) & (GU_CFI_PARSE_CACHE_SIZE - 1);
}

static bool gu_cfi_ops_cacheable(int ops_size)
{
	return ops_size >= 0 && ops_size <= GU_CFI_PARSE_CACHE_OPS_MAX;
}

static void gu_cfi_cache_copy_to_scratch(const struct gu_cfi_cached_ops *cached,
					 struct backtrace_ops_info *scratch)
{
	scratch->ops_size = cached->ops_size;
	if (cached->ops_size > 0)
		memcpy(scratch->ops, cached->ops,
		       cached->ops_size * sizeof(Dwarf_Op));
}

static bool gu_cfi_parse_cache_load(struct gu_cfi *cfi, uint64_t pc,
				    bool *signal_frame)
{
	struct gu_cfi_parse_cache_entry *entry =
		&cfi->parse_cache[gu_cfi_parse_cache_index(pc)];

	if (!entry->valid || entry->pc != pc)
		return false;

	if (signal_frame)
		*signal_frame = entry->signal_frame;
	for (int i = 0; i < REG_TYPE_MAX; i++)
		gu_cfi_cache_copy_to_scratch(&entry->regs[i], &ops_arr[i]);
	gu_cfi_cache_copy_to_scratch(&entry->cfa, &cfa_ops_info);
	return true;
}

static void gu_cfi_cache_copy_from_scratch(struct gu_cfi_cached_ops *cached,
					   const struct backtrace_ops_info *scratch)
{
	cached->ops_size = scratch->ops_size;
	if (scratch->ops_size > 0)
		memcpy(cached->ops, scratch->ops,
		       scratch->ops_size * sizeof(Dwarf_Op));
}

static void gu_cfi_parse_cache_store(struct gu_cfi *cfi, uint64_t pc,
				     bool signal_frame)
{
	struct gu_cfi_parse_cache_entry *entry;

	if (!gu_cfi_ops_cacheable(cfa_ops_info.ops_size))
		return;
	for (int i = 0; i < REG_TYPE_MAX; i++)
		if (!gu_cfi_ops_cacheable(ops_arr[i].ops_size))
			return;

	entry = &cfi->parse_cache[gu_cfi_parse_cache_index(pc)];
	memset(entry, 0, sizeof(*entry));
	entry->valid = true;
	entry->pc = pc;
	entry->signal_frame = signal_frame;
	for (int i = 0; i < REG_TYPE_MAX; i++)
		gu_cfi_cache_copy_from_scratch(&entry->regs[i], &ops_arr[i]);
	gu_cfi_cache_copy_from_scratch(&entry->cfa, &cfa_ops_info);
}

static Dwarf_Op *gu_cfi_init_ops_from_block(struct gu_cfi *cfi, Dwarf_Block *block, int *ops_size, enum dwarf_frame_rule rule, bool cfa)
{
	if (block->length == 0) {
		*ops_size = 0;
		return NULL;
	}

	const unsigned char *data = block->data;
	const unsigned char *end = data + block->length;
	int size = 0;

	if (!cfa)
		static_ops[size++] = (Dwarf_Op){ .atom = DW_OP_call_frame_cfa };

	while (data < end && size < DWARF_OPS_MAX) {
		Dwarf_Op op = {
			.number = 0,
			.number2 = 0,
			.offset = data - block->data,
		};

		op.atom = *data++;

		switch (op.atom) {
		case DW_OP_addr:
			data = decode_read_checked(data, end, DW_EH_PE_udata8,
						   &op.number);
			if (!data)
				return NULL;
			break;
		case DW_OP_call_ref:
		case DW_OP_GNU_variable_value:
			data = decode_read_checked(data, end, DW_EH_PE_udata8,
						   &op.number);
			if (!data)
				return NULL;
			break;
		case DW_OP_deref:
		case DW_OP_dup:
		case DW_OP_drop:
		case DW_OP_over:
		case DW_OP_swap:
		case DW_OP_rot:
		case DW_OP_xderef:
		case DW_OP_abs:
		case DW_OP_and:
		case DW_OP_div:
		case DW_OP_minus:
		case DW_OP_mod:
		case DW_OP_mul:
		case DW_OP_neg:
		case DW_OP_not:
		case DW_OP_or:
		case DW_OP_plus:
		case DW_OP_shl:
		case DW_OP_shr:
		case DW_OP_shra:
		case DW_OP_xor:
		case DW_OP_eq:
		case DW_OP_ge:
		case DW_OP_gt:
		case DW_OP_le:
		case DW_OP_lt:
		case DW_OP_ne:
		case DW_OP_lit0 ... DW_OP_lit31:
		case DW_OP_reg0 ... DW_OP_reg31:
		case DW_OP_nop:
		case DW_OP_push_object_address:
		case DW_OP_call_frame_cfa:
		case DW_OP_form_tls_address:
		case DW_OP_GNU_push_tls_address:
		case DW_OP_stack_value:
		case DW_OP_GNU_uninit:
			break;

		case DW_OP_const1u:
		case DW_OP_pick:
		case DW_OP_deref_size:
		case DW_OP_xderef_size:
			if (data >= end)
				return NULL;
			op.number = *data++;
			break;

		case DW_OP_const1s:
			if (data >= end)
				return NULL;
			op.number = *((int8_t *)data);
			++data;
			break;

		case DW_OP_const2u:
			data = decode_read_checked(data, end, DW_EH_PE_udata2,
						   &op.number);
			if (!data)
				return NULL;
			break;

		case DW_OP_const2s:
		case DW_OP_skip:
		case DW_OP_bra:
		case DW_OP_call2:
			data = decode_read_checked(data, end, DW_EH_PE_sdata2,
						   &op.number);
			if (!data)
				return NULL;
			break;

		case DW_OP_const4u:
			data = decode_read_checked(data, end, DW_EH_PE_udata4,
						   &op.number);
			if (!data)
				return NULL;
			break;

		case DW_OP_const4s:
		case DW_OP_call4:
		case DW_OP_GNU_parameter_ref:
			data = decode_read_checked(data, end, DW_EH_PE_sdata4,
						   &op.number);
			if (!data)
				return NULL;
			break;

		case DW_OP_const8u:
			data = decode_read_checked(data, end, DW_EH_PE_udata8,
						   &op.number);
			if (!data)
				return NULL;
			break;

		case DW_OP_const8s:
			data = decode_read_checked(data, end, DW_EH_PE_sdata8,
						   &op.number);
			if (!data)
				return NULL;
			break;

		case DW_OP_constu:
		case DW_OP_plus_uconst:
		case DW_OP_regx:
		case DW_OP_piece:
		case DW_OP_convert:
		case DW_OP_GNU_convert:
		case DW_OP_reinterpret:
		case DW_OP_GNU_reinterpret:
		case DW_OP_addrx:
		case DW_OP_GNU_addr_index:
		case DW_OP_constx:
		case DW_OP_GNU_const_index:
			data = decode_read_checked(data, end, DW_EH_PE_uleb128,
						   &op.number);
			if (!data)
				return NULL;
			break;

		case DW_OP_consts:
		case DW_OP_breg0 ... DW_OP_breg31:
		case DW_OP_fbreg:
			data = decode_read_checked(data, end, DW_EH_PE_sleb128,
						   &op.number);
			if (!data)
				return NULL;
			break;

		case DW_OP_bregx:
			data = decode_read_checked(data, end, DW_EH_PE_uleb128,
						   &op.number);
			if (!data)
				return NULL;
			data = decode_read_checked(data, end, DW_EH_PE_sleb128,
						   &op.number2);
			if (!data)
				return NULL;
			break;

		case DW_OP_bit_piece:
		case DW_OP_regval_type:
		case DW_OP_GNU_regval_type:
			data = decode_read_checked(data, end, DW_EH_PE_uleb128,
						   &op.number);
			if (!data)
				return NULL;
			data = decode_read_checked(data, end, DW_EH_PE_uleb128,
						   &op.number2);
			if (!data)
				return NULL;
			break;

		case DW_OP_implicit_pointer:
		case DW_OP_GNU_implicit_pointer:
			data = decode_read_checked(data, end, DW_EH_PE_udata8,
						   &op.number);
			if (!data)
				return NULL;
			data = decode_read_checked(data, end, DW_EH_PE_udata8,
						   &op.number2);
			if (!data)
				return NULL;
			break;

		case DW_OP_deref_type:
		case DW_OP_GNU_deref_type:
		case DW_OP_xderef_type:
			if (data >= end)
				return NULL;
			op.number = *data++;
			data = decode_read_checked(data, end, DW_EH_PE_udata8,
						   &op.number2);
			if (!data)
				return NULL;
			break;

		default:
			return NULL;
		}

		static_ops[size++] = op;
	}

	if (data < end || size >= DWARF_OPS_MAX)
		return NULL;
	if (rule == reg_val_expression)
		static_ops[size++] = (Dwarf_Op){ .atom = DW_OP_stack_value, .offset = data - block->data };

	*ops_size = size;

	return static_ops;
}

Dwarf_Op *gu_cfi_get_cfa_ops(struct gu_cfi *cfi, struct gu_cfi_calc_ctx *calc_ctx, int *ops_size)
{
	int result = 0;
	*ops_size = 0;

	switch (calc_ctx->cfa_rule) {
	case cfa_undefined:
		return NULL;

	case cfa_offset:
		memcpy(static_ops, &calc_ctx->cfa_data.offset, sizeof(Dwarf_Op));
		*ops_size = 1;
		break;

	case cfa_expr:
		return gu_cfi_init_ops_from_block(cfi, &calc_ctx->cfa_data.expr, ops_size, reg_expression, true);

	case cfa_invalid:
		return NULL;

	default:
		return NULL;
	}

	return static_ops;
}

Dwarf_Op *gu_cfi_get_regs_ops(struct gu_cfi *cfi, enum cfi_reg_type type, struct gu_cfi_calc_ctx *calc_ctx, struct gu_cfi_fde *fde, int *ops_size)
{
	if (type >= REG_TYPE_MAX)
		return NULL;

	int size = 0;
	*ops_size = 0;
	const uint8_t *p = NULL;
	Dwarf_Block block;

	struct dwarf_frame_register *reg = &calc_ctx->regs[type];

	switch (reg->rule) {
	case reg_unspecified:
		return NULL;
	case reg_undefined:
		return NULL;
	case reg_same_value:
		return NULL;

	case reg_offset:
		static_ops[size++] = (Dwarf_Op){ .atom = DW_OP_call_frame_cfa };
		if (reg->value != 0)
			static_ops[size++] = (Dwarf_Op){ .atom = DW_OP_plus_uconst, .number = reg->value };
		*ops_size = size;
		return static_ops;

	case reg_val_offset:
		static_ops[size++] = (Dwarf_Op){ .atom = DW_OP_call_frame_cfa };
		if (reg->value != 0)
			static_ops[size++] = (Dwarf_Op){ .atom = DW_OP_plus_uconst, .number = reg->value };
		if (reg->rule == reg_val_offset)
			static_ops[size++] = (Dwarf_Op){ .atom = DW_OP_stack_value };
		*ops_size = size;
		return static_ops;

	case reg_register:
		static_ops[size++] = (Dwarf_Op){ .atom = DW_OP_regx, .number = reg->value };
		*ops_size = size;
		return static_ops;

	case reg_val_expression:
	case reg_expression:
		if ((uint64_t)reg->value >= cfi->cfi_data->d_size)
			return NULL;
		const uint8_t *end = (const uint8_t *)cfi->cfi_data->d_buf +
				     cfi->cfi_data->d_size;
		p = (const uint8_t *)cfi->cfi_data->d_buf + reg->value;
		p = decode_read_checked(p, end, DW_EH_PE_uleb128,
					&block.length);
		if (p == NULL || !block_fits(p, end, block.length))
			return NULL;
		block.data = (void *)p;

		return gu_cfi_init_ops_from_block(cfi, &block, ops_size, reg->rule, false);
	}

	return 0;
}

int gu_cfi_get_ops(enum cfi_reg_type type, Dwarf_Op **ops, int *ops_size, bool cfa)
{
	if (type >= REG_TYPE_MAX)
		return -1;

	if (cfa || (type == REG_TYPE_RSP && ops_arr[type].ops_size == 0)) {
		*ops = cfa_ops_info.ops;
		*ops_size = cfa_ops_info.ops_size;
		return 0;
	}

	*ops = ops_arr[type].ops;
	*ops_size = ops_arr[type].ops_size;
	return 0;
}

int gu_cfi_parse_cfi(struct gu_cfi *cfi, uint64_t pc)
{
	return gu_cfi_parse_cfi_ex(cfi, pc, NULL);
}

int gu_cfi_parse_cfi_ex(struct gu_cfi *cfi, uint64_t pc,
			bool *signal_frame)
{
	GU_VERBOSE("cfi parse cfi start, try find pc %lx", pc);

	/* The decode result is global scratch state; never reuse stale ops. */
	for (int i = 0; i < REG_TYPE_MAX; i++)
		ops_arr[i].ops_size = 0;
	cfa_ops_info.ops_size = 0;
	if (signal_frame)
		*signal_frame = false;

	if (gu_cfi_parse_cache_load(cfi, pc, signal_frame))
		return 0;

	if (cfi->hdr_interval_array == NULL)
		return -1;

	struct interval_array_item item;
	int ret = gu_interval_array_search(cfi->hdr_interval_array, pc, &item);
	if (ret < 0)
		return -1;

	struct gu_cfi_fde *fde = (struct gu_cfi_fde *)get_interval_array_pointer((uint64_t)item.private, NULL);
	if (fde == NULL || fde->cie == NULL)
		return -1;
	if (signal_frame)
		*signal_frame = fde->cie->signal_frame;

	//GU_VERBOSE("Get FDE : PC [ %lx - %lx ] CIE pointer %p Ins [ %p - %p ]", fde->start, fde->end, fde->cie, fde->instructions, fde->instructions_end);
	//GU_VERBOSE("Get FDE->CIE (%p): Ins [ %p - %p ]", fde->cie, fde->cie->initial_instructions, fde->cie->initial_instructions_end);

	struct gu_cfi_calc_ctx calc_ctx = { .prev = NULL };
	memcpy(&calc_ctx, &fde->cie->cie_calc_ctx, sizeof(calc_ctx));

	ret = init_calc_ctx_by_ins(cfi, fde->cie, &calc_ctx, fde->instructions, fde->instructions_end, fde->start, pc);
	if (ret < 0)
		return ret;

	struct gu_cfi_calc_ctx *tmp = &calc_ctx, *tmp2 = NULL;

	while (calc_ctx.prev) {
		struct gu_cfi_calc_ctx *next = calc_ctx.prev->prev;
		free(calc_ctx.prev);
		calc_ctx.prev = next;
	}

	int ops_size = 0;
	Dwarf_Op *ops = NULL;

	ops = gu_cfi_get_cfa_ops(cfi, &calc_ctx, &ops_size);
	if (ops == NULL)
		return -1;

	cfa_ops_info.ops_size = ops_size;
	memcpy(cfa_ops_info.ops, ops, ops_size * sizeof(Dwarf_Op));

	// if not have RSP, use CFA directly
	ops = gu_cfi_get_regs_ops(cfi, REG_TYPE_RSP, &calc_ctx, fde, &ops_size);
	if (ops == NULL) {
		ops_arr[REG_TYPE_RSP].ops_size = cfa_ops_info.ops_size;
		memcpy(ops_arr[REG_TYPE_RSP].ops, cfa_ops_info.ops,  cfa_ops_info.ops_size * sizeof(Dwarf_Op));
	} else {
		ops_arr[REG_TYPE_RSP].ops_size = ops_size;
		memcpy(ops_arr[REG_TYPE_RSP].ops, ops, ops_size * sizeof(Dwarf_Op));
	}

	// must, if not has RIP, direct return error.
	ops = gu_cfi_get_regs_ops(cfi, REG_TYPE_RIP, &calc_ctx, fde, &ops_size);
	if (ops == NULL)
		return -1;

	ops_arr[REG_TYPE_RIP].ops_size = ops_size;
	memcpy(ops_arr[REG_TYPE_RIP].ops, ops, ops_size * sizeof(Dwarf_Op));

	// may not need, direct give up.
	ops = gu_cfi_get_regs_ops(cfi, REG_TYPE_RBP, &calc_ctx, fde, &ops_size);
	if (ops != NULL) {
		ops_arr[REG_TYPE_RBP].ops_size = ops_size;
		memcpy(ops_arr[REG_TYPE_RBP].ops, ops, ops_size * sizeof(Dwarf_Op));
	}

	gu_cfi_parse_cache_store(cfi, pc, fde->cie->signal_frame);

	return 0;
}
