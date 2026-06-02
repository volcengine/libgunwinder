/* SPDX-License-Identifier: LGPL-3.0-or-later */

#define _GNU_SOURCE
#include "gu_elf.h"

#include <fcntl.h>
#include <gelf.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static unsigned long align_down(unsigned long value, unsigned long align)
{
	if (align == 0)
		return value;
	return value - value % align;
}

static unsigned long align_up(unsigned long value, unsigned long align)
{
	unsigned long rem;

	if (align == 0)
		return value;

	rem = value % align;
	if (rem == 0)
		return value;
	return value + (align - rem);
}

void gu_elf_exec_ranges_destroy(struct gu_elf_exec_ranges *ranges)
{
	if (!ranges)
		return;

	free(ranges->ranges);
	memset(ranges, 0, sizeof(*ranges));
}

int gu_elf_exec_ranges_load_from_elf(Elf *elf,
				     struct gu_elf_exec_ranges *ranges)
{
	struct gu_elf_exec_range *loaded = NULL;
	size_t phnum = 0;
	size_t count = 0;

	if (!elf || !ranges)
		return -1;

	memset(ranges, 0, sizeof(*ranges));

	if (elf_getphdrnum(elf, &phnum) != 0)
		return -1;

	loaded = calloc(phnum, sizeof(*loaded));
	if (!loaded)
		return -1;

	for (size_t i = 0; i < phnum; i++) {
		GElf_Phdr phdr;
		unsigned long start, end;

		if (gelf_getphdr(elf, i, &phdr) != &phdr)
			goto err;

		if (phdr.p_type != PT_LOAD || !(phdr.p_flags & PF_X) ||
		    phdr.p_memsz == 0)
			continue;

		/*
		 * maps files are page-aligned, while PT_LOAD virtual addresses
		 * can carry a file-offset skew. Align by p_align in the same
		 * way the old single exec_virt_addr calculation did so a maps
		 * interval can be compared directly with an ELF load range after
		 * subtracting the process load bias.
		 */
		start = align_down((unsigned long)phdr.p_vaddr,
				   (unsigned long)phdr.p_align);
		end = align_up((unsigned long)(phdr.p_vaddr + phdr.p_memsz),
			       (unsigned long)phdr.p_align);
		if (end <= start)
			continue;

		loaded[count].start = start;
		loaded[count].end = end;
		loaded[count].offset = align_down((unsigned long)phdr.p_offset,
						  (unsigned long)phdr.p_align);
		count++;
	}

	if (count == 0) {
		free(loaded);
		return 0;
	}

	ranges->ranges = loaded;
	ranges->count = count;
	return 0;

err:
	free(loaded);
	return -1;
}

int gu_elf_exec_ranges_load(const char *path,
			    struct gu_elf_exec_ranges *ranges)
{
	int fd = -1;
	Elf *elf = NULL;
	int ret = -1;

	if (!path || !ranges)
		return -1;

	memset(ranges, 0, sizeof(*ranges));

	if (elf_version(EV_CURRENT) == EV_NONE)
		return -1;

	fd = open(path, O_RDONLY, 0);
	if (fd < 0)
		return -1;

	elf = elf_begin(fd, ELF_C_READ, NULL);
	if (!elf)
		goto out;

	ret = gu_elf_exec_ranges_load_from_elf(elf, ranges);

out:
	if (elf)
		elf_end(elf);
	if (fd >= 0)
		close(fd);
	return ret;
}

unsigned long
gu_elf_exec_ranges_first_start(const struct gu_elf_exec_ranges *ranges)
{
	if (!ranges || ranges->count == 0)
		return 0;
	return ranges->ranges[0].start;
}

bool gu_elf_exec_ranges_find(const struct gu_elf_exec_ranges *ranges,
			     unsigned long start, unsigned long end,
			     unsigned long *exec_virt_addr)
{
	if (!ranges || !ranges->ranges || end <= start)
		return false;

	for (size_t i = 0; i < ranges->count; i++) {
		if (start >= ranges->ranges[i].start &&
		    end <= ranges->ranges[i].end) {
			if (exec_virt_addr)
				*exec_virt_addr = start;
			return true;
		}
	}

	return false;
}

bool gu_elf_exec_ranges_find_by_offset(const struct gu_elf_exec_ranges *ranges,
				       unsigned long offset, unsigned long size,
				       unsigned long *exec_virt_addr)
{
	unsigned long end_offset;

	if (!ranges || !ranges->ranges || size == 0)
		return false;
	if (offset > ULONG_MAX - size)
		return false;
	end_offset = offset + size;

	for (size_t i = 0; i < ranges->count; i++) {
		const struct gu_elf_exec_range *range = &ranges->ranges[i];
		unsigned long range_size;
		unsigned long range_end_offset;

		if (range->end <= range->start)
			continue;
		range_size = range->end - range->start;
		if (range->offset > ULONG_MAX - range_size)
			continue;
		range_end_offset = range->offset + range_size;

		if (offset >= range->offset && end_offset <= range_end_offset) {
			if (exec_virt_addr)
				*exec_virt_addr = range->start +
					(offset - range->offset);
			return true;
		}
	}

	return false;
}
