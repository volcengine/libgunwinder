/* SPDX-License-Identifier: LGPL-3.0-or-later */

#include "gu_unwinder.h"
#include "gu_stacktrace.h"

#include "unwinder_types.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static void dump_all_related_files(pid_t pid, const char *path)
{
	char maps_path[128];
	char proc_root_path[128];
	char *line = NULL;
	size_t len = 0;
	FILE *maps_file = NULL, *output_file = NULL;
	char *output_maps_path = NULL,  *bin_path = NULL, *new_path = NULL, *token = NULL;
	char *output_bin_path = NULL;
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
		if ((strstr(line, " r-xp ") || strstr(line, " rwxp ")) &&
		    !strchr(line, '/')) {
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

static time_t record_timestamp;
static int count = 0;

void gu_debug_dump_sample(struct gu_stack_info *info, const char *path, bool dump_related_files)
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
	if (ret && info) {
		if (info->regs)
			free(info->regs);
		if (info->stack_data)
			free(info->stack_data);
		free(info);
		info = NULL;
	}
	return info;
}
