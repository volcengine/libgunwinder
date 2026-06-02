/* SPDX-License-Identifier: LGPL-3.0-or-later */

#ifndef GU_ELF_H
#define GU_ELF_H

#include <stdbool.h>
#include <stddef.h>

#include <libelf.h>

struct gu_elf_exec_range {
	unsigned long start;
	unsigned long end;
	unsigned long offset;
};

struct gu_elf_exec_ranges {
	struct gu_elf_exec_range *ranges;
	size_t count;
};

int gu_elf_exec_ranges_load_from_elf(Elf *elf,
				     struct gu_elf_exec_ranges *ranges);
int gu_elf_exec_ranges_load(const char *path,
			    struct gu_elf_exec_ranges *ranges);
void gu_elf_exec_ranges_destroy(struct gu_elf_exec_ranges *ranges);
unsigned long
gu_elf_exec_ranges_first_start(const struct gu_elf_exec_ranges *ranges);
bool gu_elf_exec_ranges_find(const struct gu_elf_exec_ranges *ranges,
			     unsigned long start, unsigned long end,
			     unsigned long *exec_virt_addr);
bool gu_elf_exec_ranges_find_by_offset(const struct gu_elf_exec_ranges *ranges,
				       unsigned long offset, unsigned long size,
				       unsigned long *exec_virt_addr);

#endif
