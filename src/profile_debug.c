/* SPDX-License-Identifier: LGPL-3.0-or-later */

#include "gu_unwinder.h"
#include "gu_stacktrace.h"
#include "gu_elf.h"

#include "unwinder_types.h"
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define DEBUG_MAPS_PATH_MAX 4096
#if defined(__GNUC__)
#define GU_DEBUG_UNUSED __attribute__((unused))
#else
#define GU_DEBUG_UNUSED
#endif

static int parse_debug_maps_line(const char *line, unsigned long *start,
				 unsigned long *end, char perm[5],
				 char *map_path, size_t map_path_size)
{
	unsigned long offset;
	int fields;

	if (!line || !start || !end || !perm || !map_path || map_path_size == 0)
		return -1;

	map_path[0] = '\0';
	fields = sscanf(line, "%lx-%lx %4s %lx %*s %*s %4095s",
			start, end, perm, &offset, map_path);
	return fields >= 4 ? 0 : -1;
}

static int write_maps_line_with_path(FILE *output_file, const char *line,
				     const char *replacement_path)
{
	const char *cursor = line;

	if (!output_file || !line || !replacement_path)
		return -1;

	for (int field = 0; field < 5; field++) {
		while (*cursor == ' ' || *cursor == '\t')
			cursor++;
		if (*cursor == '\0' || *cursor == '\n')
			return -1;
		while (*cursor != '\0' && *cursor != '\n' &&
		       *cursor != ' ' && *cursor != '\t')
			cursor++;
	}

	/*
	 * Preserve address/perms/offset/dev/inode exactly as sampled.  Only the
	 * pathname is synthetic, and offline bt_debug depends on the original
	 * address range to compute the same ELF load bias as live unwinding.
	 */
	return fprintf(output_file, "%.*s %s\n", (int)(cursor - line),
		       line, replacement_path) < 0 ? -1 : 0;
}

struct debug_hugepage_text_recovery {
	bool enabled;
	char path[DEBUG_MAPS_PATH_MAX];
	struct gu_elf_exec_ranges exec_ranges;
	unsigned long load_bias;
};

/*
 * These helpers are only for debug dump/offline bt_debug recovery.  They must
 * not be used from the normal live unwind path, which has its own
 * hugepage_text_recovery implementation in gu_stacktrace.c.
 */
static GU_DEBUG_UNUSED void debug_hugepage_text_recovery_destroy(
	struct debug_hugepage_text_recovery *recovery)
{
	if (!recovery)
		return;

	gu_elf_exec_ranges_destroy(&recovery->exec_ranges);
	memset(recovery, 0, sizeof(*recovery));
}

static GU_DEBUG_UNUSED bool debug_hugepage_text_recovery_init(
	pid_t pid, const char *proc_root, const char *dump_path,
	unsigned long first_exec_start,
	struct debug_hugepage_text_recovery *recovery)
{
	char *rooted_path = NULL;
	char *output_bin_path = NULL;
	const char *binary_name;
	unsigned long first_exec_virt_addr;
	bool ok = false;

	if (!proc_root || !dump_path || !recovery)
		return false;

	memset(recovery, 0, sizeof(*recovery));

	if (gu_get_pid_cmdline_argv0(pid, recovery->path,
				     sizeof(recovery->path)) != 0)
		return false;

	rooted_path = gu_path_join(proc_root, recovery->path);
	if (!rooted_path)
		return false;

	if (gu_elf_exec_ranges_load(rooted_path, &recovery->exec_ranges) != 0 ||
	    recovery->exec_ranges.count == 0)
		goto out;

	binary_name = strrchr(recovery->path, '/');
	binary_name = binary_name ? binary_name + 1 : recovery->path;
	output_bin_path = gu_path_join(dump_path, binary_name);
	if (!output_bin_path)
		goto out;

	if (gu_copy_file(rooted_path, output_bin_path) != 0) {
		GU_ERROR("Skip debug dump hugepage text file %s", rooted_path);
		goto out;
	}

	first_exec_virt_addr =
		gu_elf_exec_ranges_first_start(&recovery->exec_ranges);
	recovery->load_bias = first_exec_start - first_exec_virt_addr;
	recovery->enabled = true;
	ok = true;

out:
	if (!ok)
		debug_hugepage_text_recovery_destroy(recovery);
	free(output_bin_path);
	free(rooted_path);
	return ok;
}

static GU_DEBUG_UNUSED bool debug_hugepage_text_recovery_match(
	const struct debug_hugepage_text_recovery *recovery, unsigned long start,
	unsigned long end, const char *map_path)
{
	unsigned long virt_start, virt_end;

	if (!recovery || !recovery->enabled || end <= start ||
	    !gu_maps_path_is_anonymous_exec_candidate(map_path))
		return false;

	if (start < recovery->load_bias || end < recovery->load_bias)
		return false;

	virt_start = start - recovery->load_bias;
	virt_end = end - recovery->load_bias;

	return gu_elf_exec_ranges_find(&recovery->exec_ranges, virt_start,
				       virt_end, NULL);
}

static void dump_all_related_files(pid_t pid, const char *path)
{
	char maps_path[128];
	char proc_root_path[128];
	struct debug_hugepage_text_recovery hugepage_text = { 0 };
	char *line = NULL;
	size_t len = 0;
	FILE *maps_file = NULL, *output_file = NULL;
	char *output_maps_path = NULL,  *bin_path = NULL, *new_path = NULL, *token = NULL;
	char *output_bin_path = NULL;
	bool saw_first_exec = false;
	int ret;

	GU_OUTPUT("Start Dump Related info to %s", path);
	snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);

	maps_file = fopen(maps_path, "r");
	if (!maps_file)
		goto out;

	output_maps_path = gu_path_join(path, "maps");
	if (!output_maps_path)
		goto out;

	output_file = fopen(output_maps_path, "w");
	if (!output_file)
		goto out;

	snprintf(proc_root_path, sizeof(proc_root_path), "/proc/%d/root", pid);

	while (getline(&line, &len, maps_file) != -1) {
		unsigned long start = 0, end = 0;
		char perm[5] = { 0 };
		char map_path[DEBUG_MAPS_PATH_MAX] = { 0 };
		bool is_exec = false;
		bool first_exec = false;

		if (parse_debug_maps_line(line, &start, &end, perm, map_path,
					  sizeof(map_path)) == 0) {
			is_exec = perm[2] == 'x';
			first_exec = is_exec && !saw_first_exec;
			if (is_exec)
				saw_first_exec = true;
		}

		/*
		 * Private hugepage text optimization compatibility:
		 *
		 * Offline bt_debug cannot read the original process'
		 * /proc/<pid>/cmdline after the debug dump is moved away.  When
		 * the first executable mapping is anonymous, mirror the live
		 * unwinder heuristic immediately: copy cmdline[0] into the dump
		 * directory and rewrite every VMA that is anonymous executable
		 * and maps back into one of that ELF's executable PT_LOAD
		 * ranges.
		 *
		 * This range-based check is intentionally stricter than "keep
		 * rewriting adjacent VMAs".  tiexec can leave holes between Go
		 * executable loads, while unrelated JIT/anonymous executable
		 * mappings may appear later.  Only ranges that the original ELF
		 * can actually cover are rewritten.
		 *
		 * If cmdline[0] cannot be read or the ELF copy fails, leave the
		 * anonymous line untouched so the dump faithfully preserves the
		 * original failure mode.
		 */
		if (first_exec &&
		    gu_maps_path_is_anonymous_exec_candidate(map_path)) {
			debug_hugepage_text_recovery_init(pid, proc_root_path,
							  path, start,
							  &hugepage_text);
		}

		if (is_exec &&
		    debug_hugepage_text_recovery_match(&hugepage_text, start,
						       end, map_path)) {
			if (write_maps_line_with_path(output_file, line,
						      hugepage_text.path) != 0)
				goto out;
			GU_OUTPUT("hugepage optimize detected, replace anonymous executable segment [0x%lx-0x%lx] with %s\n",
				  start, end, hugepage_text.path);
			continue;
		}

		if (is_exec && gu_maps_path_is_anonymous_exec_candidate(map_path)) {
			if (fputs(line, output_file) == EOF)
				goto out;
			continue;
		}

		if ((strstr(line, " r-xp ") || strstr(line, " rwxp ")) && (token = strchr(line, '/'))) {
			if (fputs(line, output_file) == EOF)
				goto out;

			bin_path = strdup(token);
			if (!bin_path)
				goto out;

			if (strstr(bin_path, " (deleted)"))
				goto next_line;

			/*
			 * Copy through /proc/<pid>/root so container paths are
			 * resolved in the target namespace.  Deleted files are
			 * skipped above because the pathname may now name a
			 * different inode and copying it would produce misleading
			 * offline symbols.
			 */
			new_path = gu_path_join(proc_root_path, bin_path);
			if (!new_path)
				goto out;

			char *binary_name = strrchr(bin_path, '/');
			if (!binary_name)
				goto out;
			binary_name++;

			output_bin_path = gu_path_join(path, binary_name);
			if (!output_bin_path)
				goto out;

			ret = gu_copy_file(new_path, output_bin_path);
			if (ret < 0)
				GU_ERROR("Skip debug dump related file %s", new_path);

			free(output_bin_path); output_bin_path = NULL;
next_line:
			free(new_path); new_path = NULL;
			free(bin_path); bin_path = NULL;
		} else {
			if (fputs(line, output_file) == EOF)
				goto out;
		}
	}

	char *binary_name = "__vdso.so";
	output_bin_path = gu_path_join(path, binary_name);
	if (output_bin_path)
		gu_dump_vdso(output_bin_path);

	free(output_bin_path); output_bin_path = NULL;

out:
	debug_hugepage_text_recovery_destroy(&hugepage_text);
	if (line)
		free(line);
	if (maps_file)
		fclose(maps_file);
	if (output_file)
		fclose(output_file);
	if (output_maps_path)
		free(output_maps_path);
	if (bin_path)
		free(bin_path);
	if (new_path)
		free(new_path);
	if (output_bin_path)
		free(output_bin_path);
	return;
}

static __thread time_t record_timestamp;
static __thread int count;

void gu_debug_dump_sample(const struct gu_stack_info *info, const char *path, bool dump_related_files)
{
	FILE *file = NULL;
	char *file_path = NULL;
	char buffer[512];
	size_t bytes_read;
	int maps_fd = -1;

	time_t timestamp = time(NULL);
	if (record_timestamp == timestamp) {
		count ++;
	} else {
		record_timestamp = timestamp;
		count = 0;
	}
	snprintf(buffer, sizeof(buffer), "%d_%ld_%d.dump.v2", info->pid, record_timestamp, count);

	file_path = gu_path_join(path, buffer);
	if (!file_path)
		goto out;

	GU_OUTPUT("Start Dump Debug info to %s\n", file_path);

	file = fopen(file_path, "wb");
	if (!file)
		goto out_free_path;

	if (fwrite(&info->pid, sizeof(info->pid), 1, file) != 1 ||
	    fwrite(&info->stack_size, sizeof(info->stack_size), 1, file) != 1 ||
	    fwrite(&info->flags, sizeof(info->flags), 1, file) != 1)
		goto out_close_file;

	size_t regs_size = sizeof(struct pt_regs);
	if (fwrite(&regs_size, sizeof(regs_size), 1, file) != 1)
		goto out_close_file;

	if (fwrite(info->regs, regs_size, 1, file) != 1 ||
	    fwrite(info->stack_data, info->stack_size, 1, file) != 1)
		goto out_close_file;

	if (fwrite(&info->ustack_fp_level, sizeof(info->ustack_fp_level), 1, file) != 1)
		goto out_close_file;

	if (fwrite(info->ustack_fp, sizeof(uint64_t), info->ustack_fp_level, file) != info->ustack_fp_level)
		goto out_close_file;

	if (dump_related_files)
		dump_all_related_files(info->pid, path);

out_close_file:
	fclose(file);
out_free_path:
	free(file_path);
out:
	return;
}

#define GU_DEBUG_DUMP_VERSION_V1_STR ".dump"
#define GU_DEBUG_DUMP_VERSION_V2_STR ".dump.v2"

static bool str_ends_with(const char *str, const char *suffix)
{
	if (!str || !suffix)
		return false;

	size_t str_len = strlen(str);
	size_t suffix_len = strlen(suffix);

	if (suffix_len > str_len)
		return false;

	return strcmp(str + str_len - suffix_len, suffix) == 0;
}

enum gu_debug_dump_version_type gu_debug_dump_version(const char *path)
{
	if (str_ends_with(path, GU_DEBUG_DUMP_VERSION_V2_STR))
		return GU_DEBUG_DUMP_VERSION_V2;
	if (str_ends_with(path, GU_DEBUG_DUMP_VERSION_V1_STR))
		return GU_DEBUG_DUMP_VERSION_V1;
	return GU_DEBUG_DUMP_VER_ERROR;
}

#define GU_USTACK_FP_CAP(info) (sizeof((info)->ustack_fp) / sizeof((info)->ustack_fp[0]))

struct gu_stack_info *gu_read_stack_dump(const char *path)
{
	FILE *file = NULL;
	struct gu_stack_info *info = NULL;
	size_t regs_size;
	int ret = -1;

	info = (struct gu_stack_info *)malloc(sizeof(struct gu_stack_info));
	if (!info)
		goto out;
	memset(info, 0, sizeof(struct gu_stack_info));

	file = fopen(path, "rb");
	if (!file) {
		perror("Failed to open file");
		goto out;
	}

	enum gu_debug_dump_version_type version = gu_debug_dump_version(path);

	if (version == GU_DEBUG_DUMP_VER_ERROR) {
		perror("Failed to get dump version");
		goto out;
	}

	if (fread(&info->pid, sizeof(info->pid), 1, file) != 1 ||
	    fread(&info->stack_size, sizeof(info->stack_size), 1, file) != 1) {
		perror("Failed to read pid");
		goto out;
	}
#define DUMP_V1_FP_FLAGS (1 << 3)
	if (version == GU_DEBUG_DUMP_VERSION_V1) {
		int type = 0;
		if (fread(&type, sizeof(type), 1, file) != 1) {
			perror("Failed to read type");
			goto out;
		}
		if (type & DUMP_V1_FP_FLAGS) {
			info->flags = 0;
			gu_flags_set(info, GU_FLAG_HINT_SET_FP);
		}
	} else if (version == GU_DEBUG_DUMP_VERSION_V2) {
		if (fread(&info->flags, sizeof(info->flags), 1, file) != 1) {
			perror("Failed to read flags");
			goto out;
		}
	}

	if (fread(&regs_size, sizeof(regs_size), 1, file) != 1) {
		perror("Failed to read reg");
		goto out;
	}
	/* the unwinder reads a full struct pt_regs of the build arch */
	if (regs_size != sizeof(struct pt_regs)) {
		fprintf(stderr, "Bad regs size %zu in %s, expected %zu\n",
			regs_size, path, sizeof(struct pt_regs));
		goto out;
	}
	info->regs_size = regs_size;

	info->regs = (void *)malloc(regs_size);
	if (!info->regs)
		goto out;

	info->stack_data = (uint8_t *)malloc(info->stack_size);
	if (!info->stack_data)
		goto out;

	if (fread(info->regs, regs_size, 1, file) != 1 ||
	    fread(info->stack_data, info->stack_size, 1, file) != 1) {
		perror("Failed to read stack");
		goto out;
	}

	if (version == GU_DEBUG_DUMP_VERSION_V1) {
		if (gu_flags_is_set(info, GU_FLAG_HINT_SET_FP)) {
			memcpy(info->ustack_fp, info->stack_data, info->stack_size > (127 * 8) ? (127 * 8) : info->stack_size);
			info->ustack_fp_level = info->stack_size > (127 * 8) ? (127 * 8) / sizeof(uint64_t) : info->stack_size / sizeof(uint64_t);
		}

		ret = 0;
		goto out;
	}

	if (fread(&info->ustack_fp_level, sizeof(info->ustack_fp_level), 1, file) != 1) {
		perror("Failed to read ustack_fp_level");
		goto out;
	}
	if (info->ustack_fp_level > GU_USTACK_FP_CAP(info)) {
		fprintf(stderr, "Bad ustack_fp_level %llu in %s, max %zu\n",
			(unsigned long long)info->ustack_fp_level, path,
			GU_USTACK_FP_CAP(info));
		goto out;
	}

	if (info->ustack_fp_level > 0) {
		if (fread(info->ustack_fp, sizeof(uint64_t), info->ustack_fp_level, file) != info->ustack_fp_level) {
			perror("Failed to read ustack_fp");
			goto out;
		}
	}

	ret = 0;

out:
	if (file)
		fclose(file);
	if (ret) {
		gu_free_stack_dump(info);
		info = NULL;
	}
	return info;
}

void gu_free_stack_dump(struct gu_stack_info *info)
{
	if (!info)
		return;
	free(info->regs);
	free(info->stack_data);
	free(info);
}
