/* SPDX-License-Identifier: LGPL-3.0-or-later */

#define _GNU_SOURCE /* vasprintf */
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include "gu_comm.h"

static gu_print_fn_t g_print_fn = NULL;
int gu_verbose_enabled = 0;

void gu_set_print_fn(gu_print_fn_t fn)
{
	g_print_fn = fn;
}

void gu_set_verbose(int verbose)
{
	gu_verbose_enabled = verbose;
}

void __gu_log(enum GU_LOG_LEVEL level, const char *format, ...)
{
	if (level == GU_LOG_VERBOSE && !gu_verbose_enabled)
		return;

	char *buffer = NULL;
	const char *prefix = "";
	bool newline = false;

	switch (level) {
	case GU_LOG_ERROR:
		prefix = "[ERROR] ";
		newline = true;
		break;
	case GU_LOG_VERBOSE:
		prefix = "[VERBOSE] ";
		newline = true;
		break;
	case GU_LOG_OUTPUT:
	default:
		break;
	}

	va_list args;
	int len;

	va_start(args, format);
	len = vasprintf(&buffer, format, args);
	va_end(args);

	/* on failure the contents of the asprintf() result pointer are undefined */
	if (len < 0)
		return;

	/* every message is a line: OUTPUT ones end it unless they did */
	if (level == GU_LOG_OUTPUT && (len == 0 || buffer[len - 1] != '\n'))
		newline = true;

	char *output_string = NULL;
	if (newline)
		len = asprintf(&output_string, "%s%s\n", prefix, buffer);
	else
		len = asprintf(&output_string, "%s%s", prefix, buffer);

	free(buffer);

	if (len < 0)
		return;

	/*
	 * A message is out when this returns: stdout to journald is a pipe,
	 * fully buffered, and the few messages left would wait there for hours
	 * or until the process ends.
	 */
	if (g_print_fn)
		g_print_fn(output_string);
	else if (level == GU_LOG_ERROR)
		fprintf(stderr, "%s", output_string);
	else {
		printf("%s", output_string);
		fflush(stdout);
	}

	free(output_string);
}

bool gu_log_limit_allow(struct gu_log_limit *limit, uint64_t now_ns,
			uint64_t interval_ns, uint64_t *suppressed)
{
	if (limit->next_ns && now_ns < limit->next_ns) {
		limit->suppressed++;
		return false;
	}
	*suppressed = limit->suppressed;
	limit->suppressed = 0;
	limit->next_ns = now_ns + interval_ns;
	return true;
}

unsigned char *gu_calculate_md5(int fd, const char *name)
{
	MD5_CTX md5_ctx;
	unsigned char *md5_digest;
	ssize_t bytes_read;
	size_t total_read = 0;
	char gu_md5_buffer[4096];

	md5_digest = malloc(MD5_DIGEST_LENGTH);
	if (!md5_digest)
		return NULL;

	MD5_Init(&md5_ctx);

	while ((bytes_read = read(fd, gu_md5_buffer, sizeof(gu_md5_buffer))) > 0 && total_read < 2 * 1024 * 1024) {
		MD5_Update(&md5_ctx, gu_md5_buffer, bytes_read);
		total_read += bytes_read;
	}

	MD5_Update(&md5_ctx, name, strlen(name));

	MD5_Final(md5_digest, &md5_ctx);

	return md5_digest;
}

void gu_dump_vdso(const char *output_file)
{
	FILE *maps_file;
	char line[256];
	unsigned long start = 0, end = 0;
	int found_vdso = 0;
	FILE *output_fd = NULL;
	size_t size;
	char *buffer = NULL;

	maps_file = fopen("/proc/self/maps", "r");
	if (!maps_file) {
		GU_ERROR("fopen /proc/self/maps failed.");
		return;
	}

	while (fgets(line, sizeof(line), maps_file)) {
		if (strstr(line, "[vdso]")) {
			if (sscanf(line, "%lx-%lx", &start, &end) == 2) {
				found_vdso = 1;
				break;
			}
		}
	}

	fclose(maps_file);

	if (!found_vdso) {
		GU_ERROR("vdso not found in /proc/self/maps");
		return;
	}

	output_fd = fopen(output_file, "wb");
	if (!output_fd) {
		GU_ERROR("fopen output file failed.");
		return;
	}

	size = end - start;
	buffer = malloc(size);
	if (!buffer) {
		GU_ERROR("malloc vdso buffer failed.");
		fclose(output_fd);
		return;
	}

	memcpy(buffer, (void *)start, size);

	if (fwrite(buffer, 1, size, output_fd) != size)
		GU_ERROR("fwrite to %s failed", output_file);

	free(buffer);
	fclose(output_fd);
}

static char *_trim_trailing_whitespace(char *str)
{
	size_t len = strlen(str);
	while (len > 0 && (str[len - 1] == '\n' || str[len - 1] == ' ')) {
		str[len - 1] = '\0';
		len--;
	}
	return str;
}

char *gu_path_join(const char *path1, const char *path2)
{
	if (!path1 || !path2) {
		return NULL;
	}

	size_t len1 = strlen(path1);
	size_t len2 = strlen(path2);

	int need_separator = (len1 > 0 && path1[len1 - 1] != '/' && path2[0] != '/') ? 1 : 0;

	size_t total_len = len1 + len2 + need_separator + 1;

	char *result = (char *)malloc(total_len);
	if (!result) {
		GU_ERROR("Failed to allocate memory");
		return NULL;
	}

	strcpy(result, path1);

	if (need_separator) {
		result[len1] = '/';
		len1++;
	}

	strcpy(result + len1, path2);

	return _trim_trailing_whitespace(result);
}

#define MAX_MAPS_PATH 4096
/* line scratch of the maps parser; per thread, parsers run on several */
static __thread char maps_path[MAX_MAPS_PATH];
static __thread char maps_line[MAX_MAPS_PATH];

struct maps_info *gu_get_maps_info(int pid, int *count, char permission_flag, char *debug_maps)
{
	FILE *fp = NULL;
	char filename[256];
	struct maps_info *info = NULL;
	int allocated = 64;
	int index = 0;

	if (debug_maps) {
		strncpy(filename, debug_maps, sizeof(filename));
		filename[sizeof(filename) - 1] = '\0';
	} else {
		snprintf(filename, sizeof(filename), "/proc/%d/maps", pid);
	}

	fp = fopen(filename, "r");
	if (!fp) {
		if (debug_maps || errno != ENOENT)
			GU_OUTPUT("Failed to open file %s\n", filename);
		goto fail;
	}

	info = malloc(allocated * sizeof(struct maps_info));
	if (!info) {
		GU_OUTPUT("Failed to allocate memory for maps_info\n");
		goto fail;
	}

	while (fgets(maps_line, sizeof(maps_line), fp)) {
		uint64_t start, end, offset;
		char perm[5];
		int n;

		memset(maps_path, 0, MAX_MAPS_PATH);

		n = sscanf(maps_line, "%lx-%lx %4s %lx %*s %*s %4095s", &start, &end, perm, &offset, maps_path);
		if (n < 4)
			continue;

		if (!((perm[0] == 'r' ? PERMISSION_R : 0) & permission_flag) && !((perm[1] == 'w' ? PERMISSION_W : 0) & permission_flag) && !((perm[2] == 'x' ? PERMISSION_X : 0) & permission_flag))
			continue;

		if (index >= allocated) {
			allocated *= 2;
			struct maps_info *new_info = realloc(info, allocated * sizeof(struct maps_info));
			if (!new_info) {
				GU_OUTPUT("Failed to allocate memory realloc errno %d", errno);
				goto fail;
			}
			info = new_info;
		}

		/*
		 * Go binaries and tiexec-remapped text can expose one executable
		 * program header as several adjacent /proc/maps VMAs.  The unwinder
		 * computes one load bias per interval, so keep such adjacent pieces
		 * as a single logical mapping.  Do not merge equal-looking mappings
		 * across an address gap: a later anonymous/JIT mapping with the same
		 * empty path must not inherit the first ELF's bias or symbols.
		 */
		if (index >= 1) {
			uint64_t prev_size = info[index - 1].end - info[index - 1].start;
			if (info[index - 1].end == start &&
			    info[index - 1].offset <= UINT64_MAX - prev_size &&
			    info[index - 1].offset + prev_size == offset &&
			    info[index - 1].permission == (perm[0] | perm[1] | perm[2]) &&
			    strcmp(info[index - 1].path, maps_path) == 0) {
				info[index - 1].end = end;
				continue;
			}
		}

		info[index].start = start;
		info[index].end = end;
		info[index].offset = offset;
		info[index].permission = perm[0] | perm[1] | perm[2];
		info[index].path = strdup(maps_path);
		if (!info[index].path) {
			GU_OUTPUT("Failed to allocate memory path\n");
			goto fail;
		}
		/*
		 * The " (deleted)" suffix in /proc/<pid>/maps marks a file that
		 * was unlinked after being mapped.  sscanf() above stops at the
		 * space, so the suffix is not part of maps_path.  Record it here
		 * so callers can avoid opening a (possibly replaced) file at the
		 * same pathname and instead read the live mapping through
		 * /proc/<pid>/exe or /proc/<pid>/map_files/.
		 */
		info[index].deleted = strstr(maps_line, " (deleted)") != NULL;

		index++;
	}

	if (index == 0)
		goto fail;

	struct maps_info *new_info = realloc(info, index * sizeof(struct maps_info));
	if (!new_info) {
		GU_OUTPUT("Failed to allocate memory realloc, index: %d\n", index);
		goto fail;
	}
	info = new_info;
	*count = index;
	fclose(fp);
	return info;

fail:
	if (info) {
		for (int i = 0; i < index; i++) {
			free(info[i].path);
		}
		free(info);
	}
	if (fp)
		fclose(fp);
	*count = 0;
	return NULL;
}

int gu_get_pid_cmdline_argv0(int pid, char *argv0, size_t argv0_size)
{
	char path[128];
	int fd = -1;
	ssize_t n = 0;
	char *nul = NULL;
	int ret = -1;

	if (pid <= 0 || !argv0 || argv0_size == 0)
		return -1;

	argv0[0] = '\0';

	if (snprintf(path, sizeof(path), "/proc/%d/cmdline", pid) < 0)
		return -1;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		goto out;

	n = read(fd, argv0, argv0_size - 1);
	if (n <= 0)
		goto out;

	nul = memchr(argv0, '\0', n);
	if (nul) {
		*nul = '\0';
	} else {
		if ((size_t)n >= argv0_size - 1)
			goto out;
		argv0[n] = '\0';
	}

	if (argv0[0] != '/')
		goto out;

	ret = 0;

out:
	if (ret != 0 && argv0_size > 0)
		argv0[0] = '\0';
	if (fd >= 0)
		close(fd);
	return ret;
}

bool gu_maps_path_is_anonymous_exec_candidate(const char *path)
{
	if (!path || path[0] == '\0')
		return true;

	/*
	 * Newer kernels can name private anonymous VMAs. Treat only the named
	 * anonymous forms as candidates; bracketed kernel pseudo mappings such as
	 * [vdso] and [vsyscall] must stay on their existing paths.
	 */
	return strncmp(path, "[anon:", 6) == 0 ||
	       strncmp(path, "[anon_shmem:", 12) == 0;
}

void gu_free_maps_info(struct maps_info *maps, int count)
{
	for (int i = 0; i < count; i++)
		free(maps[i].path);

	free(maps);
}

int gu_get_pid_comm(int pid, char *comm, size_t comm_size)
{
	char path[128];
	int fd = -1;
	ssize_t n = 0;
	int ret = -1;

	if (!comm || comm_size == 0)
		return -1;

	comm[0] = '\0';

	if (snprintf(path, sizeof(path), "/proc/%d/comm", pid) < 0)
		return -1;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		goto out;

	n = read(fd, comm, comm_size - 1);
	if (n <= 0)
		goto out;

	comm[n] = '\0';
	if (comm[n - 1] == '\n')
		comm[n - 1] = '\0';

	ret = 0;

out:
	if (fd >= 0)
		close(fd);
	return ret;
}

#define BUFFER_SIZE 4096

int gu_copy_file(const char *file_path, const char *target_file_path)
{
	int src_fd = -1, dest_fd = -1;
	ssize_t bytes_read, bytes_written;
	char buffer[BUFFER_SIZE];
	int ret = -1;

	src_fd = open(file_path, O_RDONLY);
	if (src_fd < 0) {
		GU_ERROR("Failed to open source file");
		goto out;
	}

	dest_fd = open(target_file_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (dest_fd < 0) {
		GU_ERROR("Failed to open/create destination file");
		goto out;
	}

	while ((bytes_read = read(src_fd, buffer, BUFFER_SIZE)) > 0) {
		bytes_written = write(dest_fd, buffer, bytes_read);
		if (bytes_written != bytes_read) {
			GU_ERROR("Failed to write data to destination file");
			goto out;
		}
	}

	if (bytes_read < 0) {
		GU_ERROR("Failed to read data from source file");
		goto out;
	}

	close(src_fd);
	src_fd = -1;
	close(dest_fd);
	dest_fd = -1;

	ret = 0;

out:
	if (src_fd >= 0)
		close(src_fd);
	if (dest_fd >= 0)
		close(dest_fd);
	return ret;
}
