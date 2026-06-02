/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (c) 2024 Zhang Yuchen */

#ifndef __STACK_UNWINDER_ARCH_H
#define __STACK_UNWINDER_ARCH_H

#include <asm/ptrace.h>

/*
 * REG_POS_LIST - x86_64 register slots used by the shared unwinder.
 *
 * The order must match the register block supplied by the sampler. Shared code
 * expands this list into enum reg_name.
 */
/* clang-format off */
#define REG_POS_LIST      \
	REG_POS(0, rax),  \
	REG_POS(1, rdx),  \
	REG_POS(2, rcx),  \
	REG_POS(3, rbx),  \
	REG_POS(4, rsi),  \
	REG_POS(5, rdi),  \
	REG_POS(6, rbp),  \
	REG_POS(7, rsp),  \
	REG_POS(8, r8),   \
	REG_POS(9, r9),   \
	REG_POS(10, r10), \
	REG_POS(11, r11), \
	REG_POS(12, r12), \
	REG_POS(13, r13), \
	REG_POS(14, r14), \
	REG_POS(15, r15), \
	REG_POS(16, rip)
/* clang-format on */

#endif /* __STACK_UNWINDER_ARCH_H */
