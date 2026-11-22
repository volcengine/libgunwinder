/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* SPDX-FileCopyrightText: 2026 ByteDance Inc. */

/*
 * Helpers shared by the test tools that include src/gu_stacktrace.c.
 */
#ifndef GU_TEST_ELF_SYMBOL_H
#define GU_TEST_ELF_SYMBOL_H

/*
 * resolve_symbol_addr() - Address of a defined symbol in an ELF file.
 * @path:     ELF file.
 * @sym_name: Symbol name, looked up in .symtab and .dynsym.
 * @base:     Load bias, added unless the ELF is ET_EXEC.
 *
 * Return: The address, or 0 if the file or the symbol is not found.
 */
static uint64_t resolve_symbol_addr(const char *path, const char *sym_name, unsigned long long base)
{
	int fd = -1;
	Elf *elf = NULL;
	Elf_Scn *scn = NULL;
	GElf_Ehdr ehdr;
	GElf_Shdr shdr;
	size_t shstrndx = 0;
	uint64_t addr = 0;

	if (!path || !sym_name)
		return 0;

	if (!gu_elf_init())
		return 0;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return 0;

	elf = elf_begin(fd, ELF_C_READ, NULL);
	if (!elf) {
		close(fd);
		return 0;
	}

	if (gelf_getehdr(elf, &ehdr) != &ehdr) {
		elf_end(elf);
		close(fd);
		return 0;
	}

	if (elf_getshdrstrndx(elf, &shstrndx) != 0) {
		elf_end(elf);
		close(fd);
		return 0;
	}

	while ((scn = elf_nextscn(elf, scn)) != NULL) {
		Elf_Data *data = NULL;
		size_t count = 0;
		if (gelf_getshdr(scn, &shdr) != &shdr)
			continue;
		if (shdr.sh_type != SHT_SYMTAB && shdr.sh_type != SHT_DYNSYM)
			continue;
		data = elf_getdata(scn, NULL);
		if (!data || shdr.sh_entsize == 0)
			continue;
		count = shdr.sh_size / shdr.sh_entsize;
		for (size_t i = 0; i < count; i++) {
			GElf_Sym sym;
			const char *name = NULL;
			if (gelf_getsym(data, (int)i, &sym) != &sym)
				continue;
			if (sym.st_shndx == SHN_UNDEF)
				continue;
			name = elf_strptr(elf, shdr.sh_link, sym.st_name);
			if (!name)
				continue;
			if (strcmp(name, sym_name) == 0) {
				addr = ehdr.e_type == ET_EXEC ? sym.st_value :
								 base + sym.st_value;
				goto out;
			}
		}
	}

out:
	elf_end(elf);
	close(fd);
	return addr;
}

#endif /* GU_TEST_ELF_SYMBOL_H */
