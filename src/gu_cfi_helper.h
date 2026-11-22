/* SPDX-License-Identifier: LGPL-3.0-or-later */
/*
 * Copyright (C) 2026 ByteDance Inc.
 *
 * This file is part of libgunwinder and is distributed under the
 * GNU Lesser General Public License v3.0 or later.
 *
 * The CFI frame-state semantics represented by this interface were reviewed
 * against elfutils/libdw and libdwfl behavior, including code copyrighted by
 * Red Hat, Inc. and available under LGPL-3.0-or-later or GPL-2.0-or-later.
 * The data structures here are libgunwinder-specific.
 */

#ifndef GU_CFI_HELPER_H
#define GU_CFI_HELPER_H

#include "gu_unwinder.h"
#include "uthash.h"

#define DWARF_OPS_MAX 256
#define GU_CFI_PARSE_CACHE_SIZE 64
#define GU_CFI_PARSE_CACHE_OPS_MAX 8

enum cfi_reg_type {
	REG_TYPE_RIP = 0,
	REG_TYPE_RBP,
	REG_TYPE_RSP,
	REG_TYPE_MAX,
};

struct gu_cfi_cached_ops {
	int ops_size;
	Dwarf_Op ops[GU_CFI_PARSE_CACHE_OPS_MAX];
};

struct gu_cfi_parse_cache_entry {
	bool valid;
	uint64_t pc;
	bool signal_frame;
	struct gu_cfi_cached_ops regs[REG_TYPE_MAX];
	struct gu_cfi_cached_ops cfa;
};

/*
 * The CFI of one ELF, built once at load and read-only afterwards.
 *
 * Every FDE is one item of @hdr_interval_array: the item holds the FDE's pc
 * range and points to a gu_cfi_fde_body, the FDE's CIE and instructions.
 * FDEs with the same CIE and instruction bytes share one body: a large C++
 * binary has millions of FDEs but only a few percent distinct instruction
 * sequences, and the instructions do not depend on where the FDE starts
 * (advance_loc is relative to the start the item supplies).
 *
 * @cfi_data holds only the distinct instruction bytes: the CIEs' initial
 * instructions and the bodies'.  A register rule given by an expression
 * stores the expression's offset in @cfi_data.  The section itself is not
 * kept after load.
 */
struct gu_cfi {
	struct interval_array *hdr_interval_array;

	unsigned char *e_ident;
	unsigned long sh_off;

	bool eh_frame;

	unsigned long cfi_mem_usage;
	unsigned long cfi_data_mem_usage;

	struct gu_cfi_cie *cie_list;

	unsigned long fde_count;
	unsigned long eh_frame_p;

	struct gu_cfi_fde_body *bodies;
	unsigned long body_count;

	Elf_Data *cfi_data;

	/* allocated by the first CFI lookup: most ELFs are never unwound */
	struct gu_cfi_parse_cache_entry *parse_cache;
};

enum cfi_reg_type trans_reg_type(int regno);

struct ehhdr_info {
	unsigned char version;
	unsigned char eh_frame_t;
	unsigned char fde_count_t;
	unsigned char fde_p_t;
};

enum dwarf_frame_rule {
	reg_unspecified,
	reg_undefined,
	reg_same_value,
	reg_offset,
	reg_val_offset,
	reg_register,
	reg_expression,
	reg_val_expression,
};

enum dwarf_cfa_rule { cfa_undefined, cfa_offset, cfa_expr, cfa_invalid };

struct dwarf_frame_register {
	enum dwarf_frame_rule rule : 3;
	Dwarf_Sword value : (sizeof(Dwarf_Sword) * 8 - 3);
};

struct gu_cfi_calc_ctx {
	enum dwarf_cfa_rule cfa_rule;
	union {
		Dwarf_Op offset;
		Dwarf_Block expr;
	} cfa_data;
	struct dwarf_frame_register regs[REG_TYPE_MAX];
	struct gu_cfi_calc_ctx *prev;
};

struct gu_cfi_cie {
	Dwarf_Off offset;

	Dwarf_Word code_alignment_factor;
	Dwarf_Sword data_alignment_factor;
	Dwarf_Word return_address_register;

	size_t fde_augmentation_data_size;

	const uint8_t *initial_instructions;
	const uint8_t *initial_instructions_end;

	uint8_t fde_encoding;
	uint8_t lsda_encoding;

	bool sized_augmentation_data;
	bool signal_frame;

	struct gu_cfi_calc_ctx cie_calc_ctx;

	UT_hash_handle hh;
};

/* What FDEs with the same CIE and instructions share, see struct gu_cfi. */
struct gu_cfi_fde_body {
	struct gu_cfi_cie *cie;
	const uint8_t *instructions;
	const uint8_t *instructions_end;
};

/* One FDE as a lookup sees it: its range and its shared body. */
struct gu_cfi_fde {
	struct gu_cfi_cie *cie;

	// PC Offset
	Dwarf_Addr start;
	Dwarf_Addr end;

	const uint8_t *instructions;
	const uint8_t *instructions_end;
};

struct per_elf_ctx;

struct gu_cfi *gu_cfi_init(struct per_elf_ctx *info);

void gu_cfi_destroy(struct gu_cfi *cfi);

/*
 * Bytes of @cfi: cfi_mem_usage and cfi_data_mem_usage are fixed at load
 * (the context's totals add and subtract them), the parse cache comes later.
 */
static inline unsigned long gu_cfi_runtime_mem_usage(const struct gu_cfi *cfi)
{
	return cfi->parse_cache ?
		GU_CFI_PARSE_CACHE_SIZE * sizeof(*cfi->parse_cache) : 0;
}

int gu_cfi_parse_cfi(struct gu_cfi *cfi, uint64_t pc);
int gu_cfi_parse_cfi_ex(struct gu_cfi *cfi, uint64_t pc, bool initial_frame,
			bool *signal_frame);

int gu_cfi_get_ops(enum cfi_reg_type type, Dwarf_Op **ops, int *ops_size, bool cfa);

int init_calc_ctx_by_ins(struct gu_cfi *cfi, struct gu_cfi_cie *cie,
			 struct gu_cfi_calc_ctx *calc_ctx,
			 const uint8_t *ins_start, const uint8_t *ins_end,
			 uint64_t loc, uint64_t find_pc);
Dwarf_Op *gu_cfi_get_cfa_ops(struct gu_cfi *cfi,
			     struct gu_cfi_calc_ctx *calc_ctx, int *ops_size);
Dwarf_Op *gu_cfi_get_regs_ops(struct gu_cfi *cfi, enum cfi_reg_type type,
			      struct gu_cfi_calc_ctx *calc_ctx,
			      struct gu_cfi_fde *fde, int *ops_size);

#endif
