/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* SPDX-FileCopyrightText: 2026 ByteDance Inc. */

#include "gu_symbol_names.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
/* ZSTD_compress_advanced(), for zstd before 1.4 (no ZSTD_compress2()) */
#define ZSTD_STATIC_LINKING_ONLY
#include <zstd.h>

/*
 * zstd level 1 on 64 mangled C++ names (~14 KiB): about 7% of the raw
 * bytes at ~550 MB/s, ~10 us to read a block back.  Higher levels gain
 * little on names and cost the load more.  Each block carries zstd's
 * content checksum (4 bytes), so corrupt data fails the read instead of
 * decompressing to wrong names.
 */
#define GU_SYMBOL_NAMES_ZSTD_LEVEL 1

struct gu_symbol_names {
	char *packed;
	/* block i is packed[block_off[i], block_off[i + 1]) */
	size_t *block_off;
	size_t block_count;
	size_t name_count;
	size_t raw_bytes;
};

struct gu_symbol_names_reader {
	ZSTD_DCtx *dctx;
	char *buf;
	size_t cap;
};

struct gu_symbol_names_builder {
	struct gu_symbol_names *names;
	ZSTD_CCtx *cctx;
	size_t packed_cap;
	size_t block_cap;
	/* the names of the block being filled */
	char *raw;
	size_t raw_len;
	size_t raw_cap;
	size_t raw_count;
};

struct gu_symbol_names_builder *gu_symbol_names_builder_new(void)
{
	struct gu_symbol_names_builder *b = calloc(1, sizeof(*b));

	if (!b)
		return NULL;
	b->names = calloc(1, sizeof(*b->names));
	b->cctx = ZSTD_createCCtx();
	if (!b->names || !b->cctx) {
		gu_symbol_names_builder_free(b);
		return NULL;
	}
#if ZSTD_VERSION_NUMBER >= 10400
	if (ZSTD_isError(ZSTD_CCtx_setParameter(b->cctx, ZSTD_c_compressionLevel,
						GU_SYMBOL_NAMES_ZSTD_LEVEL)) ||
	    ZSTD_isError(ZSTD_CCtx_setParameter(b->cctx, ZSTD_c_checksumFlag, 1))) {
		gu_symbol_names_builder_free(b);
		return NULL;
	}
#endif
	return b;
}

void gu_symbol_names_builder_free(struct gu_symbol_names_builder *b)
{
	if (!b)
		return;
	gu_symbol_names_free(b->names);
	ZSTD_freeCCtx(b->cctx);
	free(b->raw);
	free(b);
}

static int gu_symbol_names_flush(struct gu_symbol_names_builder *b)
{
	struct gu_symbol_names *names = b->names;
	size_t bound, used, len;

	if (b->raw_count == 0)
		return 0;

	if (names->block_count + 2 > b->block_cap) {
		size_t cap = b->block_cap ? b->block_cap * 2 : 64;
		size_t *off = realloc(names->block_off, cap * sizeof(*off));

		if (!off)
			return -1;
		if (!names->block_off)
			off[0] = 0;
		names->block_off = off;
		b->block_cap = cap;
	}

	used = names->block_off[names->block_count];
	bound = ZSTD_compressBound(b->raw_len);
	if (used + bound > b->packed_cap) {
		size_t cap = b->packed_cap ? b->packed_cap * 2 : 64 * 1024;
		char *packed;

		while (cap < used + bound)
			cap *= 2;
		packed = realloc(names->packed, cap);
		if (!packed)
			return -1;
		names->packed = packed;
		b->packed_cap = cap;
	}

#if ZSTD_VERSION_NUMBER >= 10400
	len = ZSTD_compress2(b->cctx, names->packed + used, bound, b->raw,
			     b->raw_len);
#else
	{
		ZSTD_parameters params = ZSTD_getParams(GU_SYMBOL_NAMES_ZSTD_LEVEL,
							b->raw_len, 0);

		params.fParams.checksumFlag = 1;
		len = ZSTD_compress_advanced(b->cctx, names->packed + used, bound,
					     b->raw, b->raw_len, NULL, 0, params);
	}
#endif
	if (ZSTD_isError(len))
		return -1;

	names->block_count++;
	names->block_off[names->block_count] = used + len;
	names->raw_bytes += b->raw_len;
	b->raw_len = 0;
	b->raw_count = 0;
	return 0;
}

long gu_symbol_names_add(struct gu_symbol_names_builder *b, const char *name)
{
	size_t len = strlen(name) + 1;

	if (len > b->raw_cap - b->raw_len) {
		size_t cap = b->raw_cap ? b->raw_cap : 16 * 1024;
		char *raw;

		while (cap - b->raw_len < len)
			cap *= 2;
		raw = realloc(b->raw, cap);
		if (!raw)
			return -1;
		b->raw = raw;
		b->raw_cap = cap;
	}
	memcpy(b->raw + b->raw_len, name, len);
	b->raw_len += len;
	b->raw_count++;

	if (b->raw_count == GU_SYMBOL_NAMES_PER_BLOCK &&
	    gu_symbol_names_flush(b) != 0)
		return -1;
	return b->names->name_count++;
}

struct gu_symbol_names *gu_symbol_names_finish(struct gu_symbol_names_builder *b)
{
	struct gu_symbol_names *names;
	char *packed;

	if (gu_symbol_names_flush(b) != 0) {
		gu_symbol_names_builder_free(b);
		return NULL;
	}

	names = b->names;
	b->names = NULL;
	gu_symbol_names_builder_free(b);

	/* the builder grew both by doubling */
	if (names->block_count) {
		size_t packed_len = names->block_off[names->block_count];
		size_t *off = realloc(names->block_off,
				      (names->block_count + 1) * sizeof(*off));

		if (off)
			names->block_off = off;
		packed = realloc(names->packed, packed_len);
		if (packed)
			names->packed = packed;
	}
	return names;
}

struct gu_symbol_names_reader *gu_symbol_names_reader_new(void)
{
	struct gu_symbol_names_reader *reader = calloc(1, sizeof(*reader));

	if (!reader)
		return NULL;
	reader->dctx = ZSTD_createDCtx();
	if (!reader->dctx) {
		free(reader);
		return NULL;
	}
	return reader;
}

void gu_symbol_names_reader_free(struct gu_symbol_names_reader *reader)
{
	if (!reader)
		return;
	ZSTD_freeDCtx(reader->dctx);
	free(reader->buf);
	free(reader);
}

int gu_symbol_names_read(const struct gu_symbol_names *names,
			 struct gu_symbol_names_reader *reader, size_t ordinal,
			 const char **name)
{
	size_t index = ordinal / GU_SYMBOL_NAMES_PER_BLOCK;
	size_t skip = ordinal % GU_SYMBOL_NAMES_PER_BLOCK;
	const char *src;
	size_t src_len, raw_len, len;
	unsigned long long size;
	char *p, *end;

	*name = NULL;
	if (!names || !reader || ordinal >= names->name_count)
		return -1;

	src = names->packed + names->block_off[index];
	src_len = names->block_off[index + 1] - names->block_off[index];
	size = ZSTD_getFrameContentSize(src, src_len);
	if (size == ZSTD_CONTENTSIZE_ERROR || size == ZSTD_CONTENTSIZE_UNKNOWN ||
	    size == 0 || size > SIZE_MAX)
		return -1;
	raw_len = (size_t)size;

	if (raw_len > reader->cap) {
		char *buf = realloc(reader->buf, raw_len);

		if (!buf)
			return -1;
		reader->buf = buf;
		reader->cap = raw_len;
	}
	len = ZSTD_decompressDCtx(reader->dctx, reader->buf, raw_len, src, src_len);
	if (ZSTD_isError(len) || len != raw_len || reader->buf[raw_len - 1] != '\0')
		return -1;

	p = reader->buf;
	end = reader->buf + raw_len;
	while (skip--) {
		p = memchr(p, '\0', end - p);
		if (!p || ++p >= end)
			return -1;
	}

	*name = p;
	return 0;
}

size_t gu_symbol_names_bytes(const struct gu_symbol_names *names)
{
	if (!names)
		return 0;
	return sizeof(*names) +
	       (names->block_count ? names->block_off[names->block_count] +
		(names->block_count + 1) * sizeof(*names->block_off) : 0);
}

size_t gu_symbol_names_raw_bytes(const struct gu_symbol_names *names)
{
	return names ? names->raw_bytes : 0;
}

void gu_symbol_names_free(struct gu_symbol_names *names)
{
	if (!names)
		return;
	free(names->packed);
	free(names->block_off);
	free(names);
}
