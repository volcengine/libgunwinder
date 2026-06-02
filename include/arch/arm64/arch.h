/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (c) 2024 Zhang Yuchen */

#ifndef __STACK_UNWINDER_ARCH_H
#define __STACK_UNWINDER_ARCH_H

#include <asm/ptrace.h>

/**
 * struct pt_regs - Minimal arm64 userspace register snapshot.
 * @x0: General-purpose register x0.
 * @x1: General-purpose register x1.
 * @x2: General-purpose register x2.
 * @x3: General-purpose register x3.
 * @x4: General-purpose register x4.
 * @x5: General-purpose register x5.
 * @x6: General-purpose register x6.
 * @x7: General-purpose register x7.
 * @x8: General-purpose register x8.
 * @x9: General-purpose register x9.
 * @x10: General-purpose register x10.
 * @x11: General-purpose register x11.
 * @x12: General-purpose register x12.
 * @x13: General-purpose register x13.
 * @x14: General-purpose register x14.
 * @x15: General-purpose register x15.
 * @x16: General-purpose register x16.
 * @x17: General-purpose register x17.
 * @x18: General-purpose register x18.
 * @x19: General-purpose register x19.
 * @x20: General-purpose register x20.
 * @x21: General-purpose register x21.
 * @x22: General-purpose register x22.
 * @x23: General-purpose register x23.
 * @x24: General-purpose register x24.
 * @x25: General-purpose register x25.
 * @x26: General-purpose register x26.
 * @x27: General-purpose register x27.
 * @x28: General-purpose register x28.
 * @x29: Frame pointer register.
 * @lr: Link register.
 * @sp: Stack pointer.
 * @pc: Program counter.
 * @pstate: Processor state.
 */
struct pt_regs {
	unsigned long long x0;
	unsigned long long x1;
	unsigned long long x2;
	unsigned long long x3;
	unsigned long long x4;
	unsigned long long x5;
	unsigned long long x6;
	unsigned long long x7;
	unsigned long long x8;
	unsigned long long x9;
	unsigned long long x10;
	unsigned long long x11;
	unsigned long long x12;
	unsigned long long x13;
	unsigned long long x14;
	unsigned long long x15;
	unsigned long long x16;
	unsigned long long x17;
	unsigned long long x18;
	unsigned long long x19;
	unsigned long long x20;
	unsigned long long x21;
	unsigned long long x22;
	unsigned long long x23;
	unsigned long long x24;
	unsigned long long x25;
	unsigned long long x26;
	unsigned long long x27;
	unsigned long long x28;
	unsigned long long x29;
	unsigned long long lr;
	unsigned long long sp;
	unsigned long long pc;
	unsigned long long pstate;
};

/*
 * REG_POS_LIST - arm64 register slots used by the shared unwinder.
 *
 * Shared code uses x29/lr/sp/pc through x86-compatible aliases below.
 */
/* clang-format off */
#define REG_POS_LIST   \
	REG_POS(0, x0),   \
	REG_POS(1, x1),   \
	REG_POS(2, x2),   \
	REG_POS(3, x3),   \
	REG_POS(4, x4),   \
	REG_POS(5, x5),   \
	REG_POS(6, x6),   \
	REG_POS(7, x7),   \
	REG_POS(8, x8),   \
	REG_POS(9, x9),   \
	REG_POS(10, x10), \
	REG_POS(11, x11), \
	REG_POS(12, x12), \
	REG_POS(13, x13), \
	REG_POS(14, x14), \
	REG_POS(15, x15), \
	REG_POS(16, x16), \
	REG_POS(17, x17), \
	REG_POS(18, x18), \
	REG_POS(19, x19), \
	REG_POS(20, x20), \
	REG_POS(21, x21), \
	REG_POS(22, x22), \
	REG_POS(23, x23), \
	REG_POS(24, x24), \
	REG_POS(25, x25), \
	REG_POS(26, x26), \
	REG_POS(27, x27), \
	REG_POS(28, x28), \
	REG_POS(29, x29), \
	REG_POS(30, lr),  \
	REG_POS(31, sp),  \
	REG_POS(32, pc)
/* clang-format on */

#define reg_name_rip reg_name_pc
#define reg_name_rsp reg_name_sp
#define reg_name_rbp reg_name_x29

#endif /* __STACK_UNWINDER_ARCH_H */
