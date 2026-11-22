/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* SPDX-FileCopyrightText: 2026 ByteDance Inc. */

#ifndef GU_SYMBOL_NAMES_H
#define GU_SYMBOL_NAMES_H

#include <stddef.h>

/*
 * The symbol names of one ELF, compressed.
 *
 * A big binary has millions of symbols but a profile shows a few thousand
 * of them, so the names are kept the way they compress best: in the
 * symbol table's order, GU_SYMBOL_NAMES_PER_BLOCK names to a zstd block.
 * A name is addressed by its ordinal, the order it was added in.  Reading
 * one decompresses its block; the caller keeps what it reads (see
 * per_elf_ctx), so each name is decompressed about once.
 *
 * Immutable once built; the owner of the ELF context frees it with the
 * context.
 */
#define GU_SYMBOL_NAMES_PER_BLOCK 64

struct gu_symbol_names;
struct gu_symbol_names_builder;
struct gu_symbol_names_reader;

struct gu_symbol_names_builder *gu_symbol_names_builder_new(void);
void gu_symbol_names_builder_free(struct gu_symbol_names_builder *b);
/* Add @name; its ordinal, or -1 when out of memory. */
long gu_symbol_names_add(struct gu_symbol_names_builder *b, const char *name);
/* Compress what is left and free @b; NULL when out of memory. */
struct gu_symbol_names *gu_symbol_names_finish(struct gu_symbol_names_builder *b);

/*
 * What reading needs and keeps between reads: a zstd decompression context
 * and a buffer for one block, so a read allocates nothing once the buffer
 * has grown to the largest block.  Not thread safe: one reader per
 * gu_context, used under that context's lock like the ELF contexts it reads.
 */
struct gu_symbol_names_reader *gu_symbol_names_reader_new(void);
void gu_symbol_names_reader_free(struct gu_symbol_names_reader *reader);

/*
 * Decompress the block of @ordinal with @reader.  On success *@name points
 * to the name inside the reader's buffer, valid until its next read.
 * -1 if the block does not decompress to well-formed names (corrupt or
 * truncated data) or memory runs out.
 */
int gu_symbol_names_read(const struct gu_symbol_names *names,
			 struct gu_symbol_names_reader *reader, size_t ordinal,
			 const char **name);
/* Bytes held, the compressed blocks and their index. */
size_t gu_symbol_names_bytes(const struct gu_symbol_names *names);
/* Bytes the names take uncompressed. */
size_t gu_symbol_names_raw_bytes(const struct gu_symbol_names *names);
void gu_symbol_names_free(struct gu_symbol_names *names);

#endif
