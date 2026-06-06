/* SPDX-License-Identifier: LGPL-3.0-or-later */

#include "gunwinder/unwinder_types.h"

#include <string.h>

static bool gu_regs_header_valid(const struct gu_regs *regs)
{
	return regs && regs->size == sizeof(*regs) &&
	       regs->version == GU_REGS_VERSION;
}

static enum gu_arch gu_regs_normalize_arch(enum gu_arch arch)
{
	if (arch != GU_ARCH_NATIVE)
		return arch;

#if defined(GUNWINDER_X86)
	return GU_ARCH_X86_64;
#elif defined(GUNWINDER_ARM64)
	return GU_ARCH_ARM64;
#else
	return GU_ARCH_NATIVE;
#endif
}

void gu_regs_init(struct gu_regs *regs, enum gu_arch arch)
{
	if (!regs)
		return;

	memset(regs, 0, sizeof(*regs));
	regs->size = sizeof(*regs);
	regs->version = GU_REGS_VERSION;
	regs->arch = gu_regs_normalize_arch(arch);
}

bool gu_regs_set(struct gu_regs *regs, uint32_t dwarf_regno, uint64_t value)
{
	if (!gu_regs_header_valid(regs))
		return false;
	if (dwarf_regno >= GU_REGS_MAX_DWARF_REGS)
		return false;

	regs->dwarf[dwarf_regno] = value;
	regs->valid_mask |= (1ULL << dwarf_regno);
	return true;
}

bool gu_regs_get(const struct gu_regs *regs, uint32_t dwarf_regno,
		 uint64_t *value)
{
	if (!gu_regs_header_valid(regs) || !value)
		return false;
	if (dwarf_regno >= GU_REGS_MAX_DWARF_REGS)
		return false;
	if (!(regs->valid_mask & (1ULL << dwarf_regno)))
		return false;

	*value = regs->dwarf[dwarf_regno];
	return true;
}
