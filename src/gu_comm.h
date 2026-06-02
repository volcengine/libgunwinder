/* SPDX-License-Identifier: LGPL-3.0-or-later */

#ifndef GU_COMM_H
#define GU_COMM_H

#include "../include/gunwinder/unwinder.h"
#include <openssl/md5.h>
#include <stdbool.h>
#include <stddef.h>

/**
 * enum GU_LOG_LEVEL - Log levels for internal use.
 * @GU_LOG_ERROR:   Error messages.
 * @GU_LOG_OUTPUT:  Regular output.
 * @GU_LOG_VERBOSE: Verbose debug output.
 */
enum GU_LOG_LEVEL {
	GU_LOG_ERROR,
	GU_LOG_OUTPUT,
	GU_LOG_VERBOSE,
};

/* Internal use only */
void __gu_log(enum GU_LOG_LEVEL level, const char *format, ...);
extern int gu_verbose_enabled;

static inline int gu_is_verbose(void)
{
	return __builtin_expect(gu_verbose_enabled, 0);
}

#define GU_ERROR(fmt, ...) __gu_log(GU_LOG_ERROR, fmt, ##__VA_ARGS__)
#define GU_OUTPUT(fmt, ...) __gu_log(GU_LOG_OUTPUT, fmt, ##__VA_ARGS__)
#define GU_VERBOSE(fmt, ...) \
	do { \
		if (gu_is_verbose()) \
			__gu_log(GU_LOG_VERBOSE, fmt, ##__VA_ARGS__); \
	} while (0)

void gu_set_verbose(int verbose);

/**
 * gu_calculate_md5() - Calculate the MD5 hash of a file descriptor.
 * @fd:   The file descriptor to hash.
 * @name: The name of the file (for error messages).
 *
 * Return: A 16-byte array containing the MD5 hash, or NULL on failure.
 */
unsigned char *gu_calculate_md5(int fd, const char *name);

/**
 * gu_dump_vdso() - Dump the vdso to a file.
 * @output_file: The path to the output file.
 */
void gu_dump_vdso(const char *output_file);

char *gu_path_join(const char *path1, const char *path2);

/* Memory permission flags for process memory mapping */
enum {
	PERMISSION_R = 1 << 0, /* Read permission */
	PERMISSION_W = 1 << 1, /* Write permission */
	PERMISSION_X = 1 << 2, /* Execute permission */
};

/**
 * struct maps_info - Represents a memory mapping segment.
 * @path:       File path of the mapped file (empty for anonymous mappings).
 * @start:      Starting virtual address of the mapping.
 * @end:        Ending virtual address of the mapping.
 * @offset:     File offset backing the mapping.
 * @permission: Memory permissions (combination of PERMISSION_* flags).
 */
struct maps_info {
	char *path;
	uint64_t start;
	uint64_t end;
	uint64_t offset;
	char permission;
};

/**
 * gu_get_maps_info() - Get memory mapping information for a process.
 * @pid:             Process ID to query.
 * @count:           Output parameter for number of mappings found.
 * @permission_flag: Filter mappings by permission (e.g., PERMISSION_R).
 * @debug_maps:      Optional path to a debug maps file.
 *
 * Return: An array of mapping information, or NULL on error.
 */
struct maps_info *gu_get_maps_info(int pid, int *count, char permission_flag, char *debug_maps);

/**
 * gu_free_maps_info() - Free memory mapping information array.
 * @maps:  Array of mapping information to free.
 * @count: Number of mappings in the array.
 */
void gu_free_maps_info(struct maps_info *maps, int count);

int gu_get_pid_comm(int pid, char *comm, size_t comm_size);

int gu_copy_file(const char *file_path, const char *target_file_path);

#endif /* GU_COMM_H */
