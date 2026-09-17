/* SPDX-License-Identifier: LGPL-3.0-or-later */

#include "gunwinder/unwinder.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <time.h>
#include <math.h>
#include <unistd.h>
#include <libiberty/demangle.h>
#include "../src/gu_comm.h"
#include "../src/gu_stacktrace.h"
#include "../src/gu_unwinder.h"

#define ANSI_COLOR_GREEN "\x1b[32m"
#define ANSI_COLOR_RESET "\x1b[0m"
#define ANSI_BOLD "\x1b[1m"

static const char *stop_reason_str[] = {
	[GU_UNWIND_REASON_OK] = "OK",
	[GU_UNWIND_REASON_NO_REGS] = "NO_REGS",
	[GU_UNWIND_REASON_NO_ELF] = "NO_ELF",
	[GU_UNWIND_REASON_NO_CFI] = "NO_CFI",
	[GU_UNWIND_REASON_CFI_FAIL] = "CFI_FAIL",
	[GU_UNWIND_REASON_ARCH_FAIL] = "ARCH_FAIL",
	[GU_UNWIND_REASON_PROCESS_EXIT] = "PROCESS_EXIT",
	[GU_UNWIND_REASON_LANG_SKIP] = "LANG_SKIP",
	[GU_UNWIND_REASON_TRUNCATED] = "TRUNCATED",
	[GU_UNWIND_REASON_NO_EXEC_PC] = "NO_EXEC_PC",
	[GU_UNWIND_REASON_CFI_FRAME_DECODE_FAILED] = "CFI_FRAME_DECODE_FAILED",
	[GU_UNWIND_REASON_CFI_FRAME_CFA_FAILED] = "CFI_FRAME_CFA_FAILED",
	[GU_UNWIND_REASON_CFI_FRAME_CFA_CALC_FAILED] = "CFI_FRAME_CFA_CALC_FAILED",
	[GU_UNWIND_REASON_END_OF_STACK] = "END_OF_STACK",
	[GU_UNWIND_REASON_STACK_READ_OUT_OF_RANGE] = "STACK_READ_OUT_OF_RANGE",
	[GU_UNWIND_REASON_NO_PROGRESS] = "NO_PROGRESS",
	[GU_UNWIND_REASON_UNKNOWN] = "UNKNOWN",
};

static const char *format_stop_reason(uint64_t flags, char *buf, size_t buf_size)
{
	enum gu_unwind_reason reason = gu_flags_reason(flags);

	if ((size_t)reason < sizeof(stop_reason_str) / sizeof(stop_reason_str[0]) &&
	    stop_reason_str[reason] != NULL)
		return stop_reason_str[reason];

	snprintf(buf, buf_size, "UNMAPPED_REASON_%u", (unsigned int)reason);
	return buf;
}

static const char *format_stop_status(uint64_t flags)
{
	enum gu_unwind_reason reason = gu_flags_reason(flags);

	switch (reason) {
	case GU_UNWIND_REASON_OK:
	case GU_UNWIND_REASON_END_OF_STACK:
		return "NORMAL";
	default:
		return "ABNORMAL";
	}
}

struct unwind_timing_stats {
	uint64_t total_ns;
	uint64_t count;
	uint64_t min_ns;
	uint64_t max_ns;
	uint64_t first_ns;
	bool first_recorded;
	uint64_t *times;
	uint64_t times_capacity;
	uint64_t hist_min_ns;
	uint64_t hist_max_ns;
	int hist_bins;
	uint64_t *hist_counts;
	uint64_t max_us;
	uint64_t max_ms;
	uint64_t max_us_count;
	uint64_t max_ms_count;
};

static struct unwind_timing_stats fp_stats = { 0 };
static struct unwind_timing_stats dwarf_stats = { 0 };

static void init_timing_stats(struct unwind_timing_stats *stats)
{
	memset(stats, 0, sizeof(*stats));
	stats->min_ns = UINT64_MAX;
	stats->times_capacity = 1000;
	stats->times = malloc(stats->times_capacity * sizeof(uint64_t));
	if (!stats->times) {
		printf("Failed to allocate memory for times array\n");
		stats->times_capacity = 0;
	}
	stats->hist_bins = 20;
	stats->hist_counts = calloc(stats->hist_bins, sizeof(uint64_t));
	if (!stats->hist_counts) {
		printf("Failed to allocate memory for histogram counts\n");
		stats->hist_bins = 0;
	}
}


static void free_timing_stats(struct unwind_timing_stats *stats)
{
	if (stats->times) {
		free(stats->times);
		stats->times = NULL;
	}
	if (stats->hist_counts) {
		free(stats->hist_counts);
		stats->hist_counts = NULL;
	}
}

static uint64_t calculate_percentile(uint64_t *sorted_times, uint64_t count, double percentile)
{
	if (count == 0)
		return 0;

	double index = (percentile / 100.0) * (count - 1);
	uint64_t lower_index = (uint64_t)index;
	uint64_t upper_index = lower_index + 1;

	if (upper_index >= count)
		return sorted_times[count - 1];

	double fraction = index - lower_index;
	return (uint64_t)(sorted_times[lower_index] * (1.0 - fraction) + sorted_times[upper_index] * fraction);
}

static uint64_t power_of_2_floor(uint64_t value)
{
	if (value == 0)
		return 1;

	uint64_t result = 1;
	while (result * 2 <= value)
		result *= 2;
	return result;
}

static uint64_t power_of_2_ceil(uint64_t value)
{
	if (value == 0)
		return 1;

	uint64_t result = 1;
	while (result < value)
		result *= 2;
	return result;
}

static void build_histogram(struct unwind_timing_stats *stats)
{
	if (stats->count == 0 || !stats->hist_counts)
		return;

	memset(stats->hist_counts, 0, stats->hist_bins * sizeof(uint64_t));

	uint64_t min_pow2 = power_of_2_floor(stats->hist_min_ns);
	uint64_t max_pow2 = power_of_2_ceil(stats->hist_max_ns);

	if (min_pow2 == max_pow2) {
		if (min_pow2 > 1)
			min_pow2 /= 2;
		else
			max_pow2 *= 2;
	}

	double log_min = log2(min_pow2);
	double log_max = log2(max_pow2);
	double bin_size = (log_max - log_min) / stats->hist_bins;

	for (uint64_t i = 0; i < stats->count; i++) {
		uint64_t time = stats->times[i];
		double log_time = log2(time);
		int bin_index = (int)((log_time - log_min) / bin_size);
		if (bin_index < 0)
			bin_index = 0;
		if (bin_index >= stats->hist_bins)
			bin_index = stats->hist_bins - 1;
		stats->hist_counts[bin_index]++;
	}
}

static int compare_uint64(const void *a, const void *b)
{
	uint64_t va = *(const uint64_t *)a;
	uint64_t vb = *(const uint64_t *)b;

	if (va < vb)
		return -1;
	if (va > vb)
		return 1;
	return 0;
}

static const char *format_time(uint64_t ns, char *buffer, size_t buffer_size)
{
	if (ns < 1000) {
		snprintf(buffer, buffer_size, "%lu ns", ns);
	} else if (ns < 1000000) {
		snprintf(buffer, buffer_size, "%.2f us", ns / 1000.0);
	} else if (ns < 1000000000) {
		snprintf(buffer, buffer_size, "%.2f ms", ns / 1000000.0);
	} else {
		snprintf(buffer, buffer_size, "%.2f s", ns / 1000000000.0);
	}
	return buffer;
}

static void update_timing_stats(struct unwind_timing_stats *stats, uint64_t elapsed_ns)
{
	if (!stats->first_recorded) {
		stats->first_ns = elapsed_ns;
		stats->first_recorded = true;
		return;
	}

	stats->total_ns += elapsed_ns;

	if (stats->times && stats->count < stats->times_capacity)
		stats->times[stats->count] = elapsed_ns;

	stats->count++;

	if (elapsed_ns < stats->min_ns)
		stats->min_ns = elapsed_ns;
	if (elapsed_ns > stats->max_ns)
		stats->max_ns = elapsed_ns;

	uint64_t elapsed_us = elapsed_ns / 1000;
	uint64_t elapsed_ms = elapsed_ns / 1000000;

	if (elapsed_ms > 0) {
		stats->max_ms_count++;
		if (elapsed_ms > stats->max_ms)
			stats->max_ms = elapsed_ms;
	} else {
		stats->max_us_count++;
		if (elapsed_us > stats->max_us)
			stats->max_us = elapsed_us;
	}

	if (stats->hist_min_ns == 0 && stats->hist_max_ns == 0) {
		stats->hist_min_ns = elapsed_ns;
		stats->hist_max_ns = elapsed_ns;
	} else {
		if (elapsed_ns < stats->hist_min_ns)
			stats->hist_min_ns = elapsed_ns;
		if (elapsed_ns > stats->hist_max_ns)
			stats->hist_max_ns = elapsed_ns;
	}
}

static void print_timing_stats(const struct unwind_timing_stats *stats, const char *method)
{
	char first_buffer[32];

	if (stats->first_recorded) {
		printf("[%s] First unwind: %s\n", method, format_time(stats->first_ns, first_buffer, sizeof(first_buffer)));
	} else {
		printf("[%s] No unwind data available\n", method);
		return;
	}

	if (stats->count == 0) {
		printf("[%s] No subsequent unwinds (excluding first)\n", method);
		return;
	}

	char avg_buffer[32], min_buffer[32], max_buffer[32];
	uint64_t avg_ns = stats->total_ns / stats->count;

	printf("[%s] Subsequent unwinds (excluding first): avg=%s, min=%s, max=%s, count=%lu\n", method, format_time(avg_ns, avg_buffer, sizeof(avg_buffer)), format_time(stats->min_ns, min_buffer, sizeof(min_buffer)),
	       format_time(stats->max_ns, max_buffer, sizeof(max_buffer)), stats->count);

	if (stats->max_us_count > 0)
		printf("[%s] Max time (us only): %.2f us (%lu values)\n", method, (double)stats->max_us, stats->max_us_count);
	if (stats->max_ms_count > 0)
		printf("[%s] Max time (ms only): %.2f ms (%lu values)\n", method, (double)stats->max_ms, stats->max_ms_count);

	if (stats->times && stats->count > 1) {
		uint64_t *sorted_times = malloc(stats->count * sizeof(uint64_t));
		if (sorted_times) {
			memcpy(sorted_times, stats->times, stats->count * sizeof(uint64_t));
			qsort(sorted_times, stats->count, sizeof(uint64_t), compare_uint64);

			uint64_t p50 = calculate_percentile(sorted_times, stats->count, 50.0);
			uint64_t p75 = calculate_percentile(sorted_times, stats->count, 75.0);
			uint64_t p90 = calculate_percentile(sorted_times, stats->count, 90.0);
			uint64_t p95 = calculate_percentile(sorted_times, stats->count, 95.0);
			uint64_t p99 = calculate_percentile(sorted_times, stats->count, 99.0);
			uint64_t p999 = calculate_percentile(sorted_times, stats->count, 99.9);

			char p50_buffer[32], p75_buffer[32], p90_buffer[32], p95_buffer[32], p99_buffer[32], p999_buffer[32];

			printf("[%s] Percentiles: P50=%s, P75=%s, P90=%s, P95=%s, P99=%s, P99.9=%s\n", method, format_time(p50, p50_buffer, sizeof(p50_buffer)), format_time(p75, p75_buffer, sizeof(p75_buffer)),
			       format_time(p90, p90_buffer, sizeof(p90_buffer)), format_time(p95, p95_buffer, sizeof(p95_buffer)), format_time(p99, p99_buffer, sizeof(p99_buffer)), format_time(p999, p999_buffer, sizeof(p999_buffer)));

			free(sorted_times);
		}
	}

	if (stats->hist_counts && stats->count > 0) {
		uint64_t *temp_counts = calloc(stats->hist_bins, sizeof(uint64_t));
		if (temp_counts) {
			if (stats->count == 0 || !stats->hist_counts) {
				free(temp_counts);
				return;
			}

			memset(temp_counts, 0, stats->hist_bins * sizeof(uint64_t));

			uint64_t min_pow2 = power_of_2_floor(stats->hist_min_ns);
			uint64_t max_pow2 = power_of_2_ceil(stats->hist_max_ns);

			if (min_pow2 == max_pow2) {
				if (min_pow2 > 1)
					min_pow2 /= 2;
				else
					max_pow2 *= 2;
			}

			double log_min = log2(min_pow2);
			double log_max = log2(max_pow2);
			double bin_size = (log_max - log_min) / stats->hist_bins;

			for (uint64_t i = 0; i < stats->count; i++) {
				uint64_t time = stats->times[i];
				double log_time = log2(time);
				int bin_index = (int)((log_time - log_min) / bin_size);
				if (bin_index < 0)
					bin_index = 0;
				if (bin_index >= stats->hist_bins)
					bin_index = stats->hist_bins - 1;
				temp_counts[bin_index]++;
			}

			uint64_t max_count = 0;
			for (int i = 0; i < stats->hist_bins; i++)
				if (temp_counts[i] > max_count)
					max_count = temp_counts[i];

			printf("[%s] Histogram (logarithmic scale):\n", method);
			for (int i = 0; i < stats->hist_bins; i++) {
				if (temp_counts[i] == 0)
					continue;

				double log_lower = log_min + i * bin_size;
				double log_upper = log_min + (i + 1) * bin_size;
				uint64_t lower = (uint64_t)pow(2, log_lower);
				uint64_t upper = (uint64_t)pow(2, log_upper);

				char lower_buffer[32], upper_buffer[32];
				format_time(lower, lower_buffer, sizeof(lower_buffer));
				format_time(upper, upper_buffer, sizeof(upper_buffer));

				int bar_length = max_count > 0 ? (int)(50.0 * temp_counts[i] / max_count) : 0;

				printf("  [%s - %s): %lu ", lower_buffer, upper_buffer, temp_counts[i]);
				for (int j = 0; j < bar_length; j++)
					printf("*");
				printf("\n");
			}

			free(temp_counts);
		}
	}
}

static void print_gu_statistics(struct gu_context *ctx)
{
	struct gu_statistics *stats = gu_get_statistics(ctx);
	if (!stats) {
		printf("[stats] gu_get_statistics returned NULL\n");
		return;
	}

	printf("\n[stats] elf_ctx_count=%lu pid_ctx_count=%lu\n", stats->elf_ctx_count, stats->pid_ctx_count);
	printf("[stats] elf_ctx_alloc_count=%lu pid_ctx_alloc_count=%lu\n", stats->elf_ctx_alloc_count, stats->pid_ctx_alloc_count);
	double symbols_mb = (double)stats->symbols_mem_size / (1024.0 * 1024.0);
	double cfi_mb = (double)stats->cfi_mem_size / (1024.0 * 1024.0);
	double cfi_data_mb = (double)stats->cfi_data_mem_size / (1024.0 * 1024.0);
	double kernel_symbols_mb = (double)stats->kernel_symbols_mem_size / (1024.0 * 1024.0);
	printf("[stats] symbols_mem_size=%.2fMB cfi_mem_size=%.2fMB cfi_data_mem_size=%.2fMB kernel_symbols_mem_size=%.2fMB\n",
	       symbols_mb,
	       cfi_mb,
	       cfi_data_mb,
	       kernel_symbols_mb);
}

void rm_template_param(char *demangled)
{
	char *write_pos = demangled;
	int depth = 0;

	if (!write_pos)
		return;

	for (char *read_pos = demangled; *read_pos != '\0'; read_pos++) {
		if (*read_pos == '<')
			depth++;
		else if (*read_pos == '>')
			depth--;
		else if (depth == 0)
			*write_pos++ = *read_pos;
	}
	*write_pos = '\0';
}

struct trace_output {
	bool print_frames;
	int frame_count;
	char last_frame[512];
};

static void format_frame(const struct gu_frame_record *frame, char *buf, size_t buf_size)
{
	const char *module = "anon exec segment";
	const char *symbol = NULL;
	char *demangle_str = NULL;

	if (frame->elf_info)
		module = frame->elf_info->base_name;

	if (frame->symbol) {
		if (strncmp(frame->symbol, "_Z", 2) == 0) {
			demangle_str = cplus_demangle(frame->symbol, DMGL_AUTO);
			rm_template_param(demangle_str);
			symbol = demangle_str;
		} else {
			symbol = frame->symbol;
		}
	}

	if (symbol)
		snprintf(buf, buf_size, "%s+0x%lx (0x%lx) [%s]",
			 symbol, frame->offset, frame->pc, module);
	else
		snprintf(buf, buf_size, "0x%lx [%s]", frame->pc, module);

	if (demangle_str)
		free(demangle_str);
}

static void process_single_frame(const struct gu_frame_record *frame, void *cb_ctx)
{
	struct trace_output *output = (struct trace_output *)cb_ctx;
	char frame_text[512];
	int frame_index = output ? output->frame_count : 0;

	format_frame(frame, frame_text, sizeof(frame_text));

	if (output) {
		snprintf(output->last_frame, sizeof(output->last_frame), "#%02d %s",
			 frame_index, frame_text);
		output->frame_count++;
	}

	if (!output || output->print_frames)
		printf("  #%02d %s\n", frame_index, frame_text);
}

static void print_dump_header(const char *file_name, enum gu_debug_dump_version_type version,
			      struct gu_stack_info *info)
{
	uint64_t raw_sp = 0;
	uint64_t stack_start = 0;
	uint64_t stack_end = 0;
	const char *version_str = version == GU_DEBUG_DUMP_VERSION_V2 ? "v2" : "v1";

	if (info->regs && get_regs(info, reg_name_rsp, &raw_sp)) {
		stack_start = raw_sp - (raw_sp % getpagesize());
		stack_end = stack_start + info->stack_size;
	}

	printf("[dump] file=%s\n", file_name);
	printf("[dump] version=%s pid=%d stack=%zuB fp_level=%llu",
	       version_str, info->pid, info->stack_size,
	       (unsigned long long)info->ustack_fp_level);
	if (raw_sp)
		printf(" raw_sp=0x%llx stack_window=[0x%llx,0x%llx)",
		       (unsigned long long)raw_sp,
		       (unsigned long long)stack_start,
		       (unsigned long long)stack_end);
	printf("\n");
}

static void print_trace_summary(const char *method, struct gu_stack_info *info,
				const struct trace_output *output, uint64_t elapsed_ns)
{
	char time_buffer[32];
	char reason_buffer[64];
	const char *reason = format_stop_reason(info->flags, reason_buffer, sizeof(reason_buffer));
	const char *status = format_stop_status(info->flags);
	int frames = output ? output->frame_count : 0;
	uint64_t read_addr = 0;
	uint64_t stack_start = 0;
	uint64_t stack_end = 0;
	uint64_t raw_sp = 0;
	bool stack_read_oob = false;
	uint64_t needed_stack = 0;
	int64_t extra_stack = 0;

	if (gu_flags_reason(info->flags) == GU_UNWIND_REASON_STACK_READ_OUT_OF_RANGE)
		stack_read_oob = gu_last_stack_read_out_of_range(&read_addr, &stack_start,
								 &stack_end, &raw_sp);

	if (stack_read_oob && read_addr >= stack_start) {
		needed_stack = read_addr - stack_start + sizeof(uint64_t);
		extra_stack = (int64_t)needed_stack - (int64_t)info->stack_size;
	}

	printf("[%s] stop: status=%s reason=%s frames=%d time=%s\n",
	       method, status, reason, frames,
	       format_time(elapsed_ns, time_buffer, sizeof(time_buffer)));
	if (stack_read_oob)
		printf("[%s] stack-read-oob: stack_read=0x%llx raw_sp=0x%llx stack_window=[0x%llx,0x%llx) needed_stack=%lluB extra=%lldB\n",
		       method,
		       (unsigned long long)read_addr,
		       (unsigned long long)raw_sp,
		       (unsigned long long)stack_start,
		       (unsigned long long)stack_end,
		       (unsigned long long)needed_stack,
		       (long long)extra_stack);
	if (output && output->last_frame[0] != '\0')
		printf("[%s] last: %s\n", method, output->last_frame);

	printf("end backtrace reason: %s, status: %s, frames: %d, time: %s\n",
	       reason, status, frames, format_time(elapsed_ns, time_buffer, sizeof(time_buffer)));
}

static char *get_parent_dir(const char *path)
{
	char *path_copy = strdup(path);
	if (!path_copy)
		return NULL;

	char *last_slash = strrchr(path_copy, '/');
	if (last_slash)
		*last_slash = '\0';
	else {
		free(path_copy);
		return NULL;
	}

	char *result = strdup(path_copy);
	free(path_copy);
	return result;
}

static bool updated = false;

static int update_maps_paths(const char *path, struct gu_stack_info *info)
{
	FILE *maps_file = NULL, *output_file = NULL;
	char *maps_path = NULL, *output_maps_path = NULL;
	char *line = NULL, *token = NULL;
	size_t len = 0;
	char *parent_dir = NULL;
	int ret = -1;

	info->unique_id = 0;

	parent_dir = get_parent_dir(path);
	if (!parent_dir)
		goto out;

	maps_path = gu_path_join(parent_dir, "maps");
	if (!maps_path)
		goto out;

	maps_file = fopen(maps_path, "r");
	if (!maps_file)
		goto out;

	output_maps_path = gu_path_join(parent_dir, "maps_updated");
	if (!output_maps_path)
		goto out;

	if (updated)
		goto update;

	updated = true;

	output_file = fopen(output_maps_path, "w");
	if (!output_file)
		goto out;

	while (getline(&line, &len, maps_file) != -1) {
		if ((token = strrchr(line, '/')) || (token = strstr(line, "[vdso]"))) {
			char *binary_name = NULL;

			if (strncmp("[vdso]", token, 6) == 0)
				binary_name = "__vdso.so";
			else
				binary_name = token + 1;

			char *new_path = gu_path_join(parent_dir, binary_name);
			if (!new_path)
				goto out;

			char *new_maps_line = malloc(len + strlen(parent_dir) + 1);
			if (!new_maps_line) {
				free(new_path);
				goto out;
			}

			char *tmp = token;
			while (*tmp != ' ' && tmp > line)
				tmp--;

			/*
			 * A debug dump stores copied ELFs beside the dump file,
			 * but the saved maps still uses the target process'
			 * original path.  Rewrite only the pathname suffix to
			 * the dump-local copy and keep the sampled VMA metadata
			 * unchanged so load-bias math remains identical.
			 */
			snprintf(new_maps_line, len + strlen(parent_dir) + 1, "%.*s%s\n", (int)(tmp - line), line, new_path);

			if (fputs(new_maps_line, output_file) == EOF) {
				free(new_path);
				free(new_maps_line);
				goto out;
			}

			free(new_path);
			free(new_maps_line);
		} else {
			if (fputs(line, output_file) == EOF)
				goto out;
		}
	}

update:
	/*
	 * gu_load_pid() treats info->unique_id as a maps filename in debug mode.
	 * This is intentionally different from live mode, where unique_id is a
	 * process-start identity used to detect pid reuse.
	 */
	info->unique_id = (uint64_t)output_maps_path;
	ret = 0;

out:
	if (line)
		free(line);
	if (maps_file)
		fclose(maps_file);
	if (output_file)
		fclose(output_file);
	if (maps_path)
		free(maps_path);
	if (parent_dir)
		free(parent_dir);
	return ret;
}

int stack_trace_from_dump(struct gu_context *ctx, const char *file_name, bool print_details)
{
	struct gu_stack_info *info = NULL;

	enum gu_debug_dump_version_type dump_version = gu_debug_dump_version(file_name);

	info = gu_read_stack_dump(file_name);
	if (!info) {
		printf("alloc stack info failed\n");
		return -1;
	}

	update_maps_paths(file_name, info);

	if (dump_version == GU_DEBUG_DUMP_VER_ERROR) {
		printf("get dump version failed\n");
		return -1;
	}

	print_dump_header(file_name, dump_version, info);

	int ret;

	gu_flags_clear(info, GU_FLAG_HINT_SET_FP);
	printf("[DWARF] %s start backtrace pid: %d, stack_size: %ld %s\n", file_name, info->pid, info->stack_size, gu_flags_is_set(info, GU_FLAG_HINT_SET_FP) ? "[FP]" : "[DWARF]");

	struct timespec start_time, end_time;
	struct trace_output dwarf_output = { .print_frames = print_details };
	clock_gettime(CLOCK_MONOTONIC, &start_time);
	gu_flags_set_reason(info, GU_UNWIND_REASON_OK);
	ret = gu_unwind(ctx, info, process_single_frame, &dwarf_output);
	clock_gettime(CLOCK_MONOTONIC, &end_time);

	uint64_t elapsed_ns;
	if (end_time.tv_nsec >= start_time.tv_nsec)
		elapsed_ns = (end_time.tv_sec - start_time.tv_sec) * 1000000000ULL + (end_time.tv_nsec - start_time.tv_nsec);
	else
		elapsed_ns = (end_time.tv_sec - start_time.tv_sec - 1) * 1000000000ULL + (1000000000ULL + end_time.tv_nsec - start_time.tv_nsec);
	update_timing_stats(&dwarf_stats, elapsed_ns);

	print_trace_summary("DWARF", info, &dwarf_output, elapsed_ns);

	if (dump_version == GU_DEBUG_DUMP_VERSION_V2) {
		gu_flags_set(info, GU_FLAG_HINT_SET_FP);
		printf("[FP   ] %s start backtrace pid: %d, stack_size: %ld %s\n", file_name, info->pid, info->stack_size, gu_flags_is_set(info, GU_FLAG_HINT_SET_FP) ? "[FP]" : "[DWARF]");

		struct trace_output fp_output = { .print_frames = print_details };
		clock_gettime(CLOCK_MONOTONIC, &start_time);
		gu_flags_set_reason(info, GU_UNWIND_REASON_OK);
		ret = gu_unwind(ctx, info, process_single_frame, &fp_output);
		clock_gettime(CLOCK_MONOTONIC, &end_time);

		if (end_time.tv_nsec >= start_time.tv_nsec)
			elapsed_ns = (end_time.tv_sec - start_time.tv_sec) * 1000000000ULL + (end_time.tv_nsec - start_time.tv_nsec);
		else
			elapsed_ns = (end_time.tv_sec - start_time.tv_sec - 1) * 1000000000ULL + (1000000000ULL + end_time.tv_nsec - start_time.tv_nsec);
		update_timing_stats(&fp_stats, elapsed_ns);

		print_trace_summary("FP   ", info, &fp_output, elapsed_ns);
	}

	free((void *)info->unique_id);
	free(info->stack_data);
	free(info->regs);
	free(info);

	return 0;
}

int main(int argc, char *argv[])
{
	struct stat path_stat;
	DIR *dir = NULL;
	struct dirent *entry = NULL;
	char *abs_path = NULL;
	int file_count = 0;
	int ret = 0;
	struct gu_context *ctx = NULL;
	int verbose = 0;
	bool print_details = true;
	const char *file_name = NULL;

	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0)
			verbose = 1;
		else if (strcmp(argv[i], "-q") == 0 || strcmp(argv[i], "--quiet") == 0)
			print_details = false;
		else
			file_name = argv[i];
	}

	if (file_name == NULL) {
		printf("Usage: %s [-v|--verbose] [-q|--quiet] <file_or_directory>\n", argv[0]);
		printf("  -v, --verbose  Enable verbose output\n");
		printf("  -q, --quiet    Print dump and stop summaries without per-frame lines\n");
		return -1;
	}

	if (stat(file_name, &path_stat) != 0) {
		ret = -1;
		goto out;
	}

	struct gu_init_cfg cfg = { .debug_print = true };
	ctx = gu_init(&cfg);
	if (!ctx) {
		printf("gu_init failed\n");
		return -1;
	}

	init_timing_stats(&dwarf_stats);
	init_timing_stats(&fp_stats);

	if (verbose)
		gu_set_verbose(1);

	if (S_ISDIR(path_stat.st_mode)) {
		dir = opendir(file_name);
		if (dir == NULL) {
			ret = -1;
			goto out;
		}

		while ((entry = readdir(dir)) != NULL && ret == 0) {
			if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
				continue;

			if (strstr(entry->d_name, ".dump") != NULL) {
				abs_path = gu_path_join(file_name, entry->d_name);

				printf("[%d]: %s\n", ++file_count, abs_path);
				ret = stack_trace_from_dump(ctx, abs_path, print_details);

				free(abs_path);
				abs_path = NULL;
			}
		}
	} else if (S_ISREG(path_stat.st_mode)) {
		if (strstr(file_name, ".dump") != NULL) {
			printf("[%d]: %s\n", ++file_count, file_name);
			ret = stack_trace_from_dump(ctx, file_name, print_details);
		}
	}

out:
	if (print_details) {
		print_timing_stats(&dwarf_stats, "DWARF");
		print_timing_stats(&fp_stats, "FP   ");

		if (ctx)
			print_gu_statistics(ctx);
	}

	free_timing_stats(&dwarf_stats);
	free_timing_stats(&fp_stats);

	if (dir != NULL)
		closedir(dir);
	if (abs_path != NULL)
		free(abs_path);
	if (ctx)
		gu_cleanup(ctx);

	return ret;
}
