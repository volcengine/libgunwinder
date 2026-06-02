/* SPDX-License-Identifier: LGPL-3.0-or-later */

#ifndef GU_UNWINDER_H
#define GU_UNWINDER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <elf.h>
#include <arch.h>
#include <gelf.h>
#include <elfutils/libdw.h>
#include <elfutils/known-dwarf.h>
#include <elfutils/libdwfl.h>
#include <elfutils/libdwelf.h>
#include <dwarf.h>

#include <stdint.h>
#include <sys/types.h>

#include "gu_comm.h"
#include "uthash.h"

#define REG_POS(pos, reg) reg_name_##reg = pos
enum reg_name { REG_POS_LIST };
#undef REG_POS

/**
 * gen_reg() - Generate register value from DWARF frame information.
 * @frame:    The DWARF frame.
 * @regno:    The register number.
 * @bias:     The bias to apply to the register value.
 * @raw_sp:   The raw stack pointer.
 * @info:     The stack info structure.
 * @val:      A pointer to store the generated register value.
 *
 * Return: A gu_unwind_reason value indicating success or failure.
 */
enum gu_unwind_reason gen_reg(Dwarf_Frame *frame, int regno, uint64_t bias, uint64_t raw_sp,
			  struct gu_stack_info *info, uint64_t *val);

/**
 * gu_dwarf_ops_eval() - Evaluate a decoded DWARF expression.
 * @frame:  The DWARF frame, if available.
 * @ops:    Decoded expression operations.
 * @nops:   Number of operations.
 * @result: Evaluated value.
 * @bias:   Load bias applied to DW_OP_addr.
 * @raw_sp: Raw stack pointer for stack snapshot addressing.
 * @info:   Stack/register snapshot.
 *
 * This is an internal entry point used by the unwinder and the synthetic CFI
 * stress test tool.
 *
 * Return: True on success, false on failure.
 */
bool gu_dwarf_ops_eval(Dwarf_Frame *frame, const Dwarf_Op *ops, size_t nops,
		       uint64_t *result, uint64_t bias, uint64_t raw_sp,
		       struct gu_stack_info *info);

/**
 * get_regs() - Get a register value from the stack info.
 * @info:  The stack info structure.
 * @regno: The register number.
 * @val:   A pointer to store the register value.
 *
 * Return: True on success, false on failure.
 */
bool get_regs(struct gu_stack_info *info, int regno, uint64_t *val);

/**
 * write_regs() - Write a register value to the stack info.
 * @info:  The stack info structure.
 * @regno: The register number.
 * @val:   The value to write.
 *
 * Return: True on success, false on failure.
 */
bool write_regs(struct gu_stack_info *info, int regno, uint64_t val);

bool gu_last_stack_read_out_of_range(uint64_t *addr, uint64_t *start,
				     uint64_t *end, uint64_t *raw_sp);

#endif
