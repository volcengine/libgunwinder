/* SPDX-License-Identifier: LGPL-3.0-or-later */
/*
 * End-to-end symbol resolution regression tests:
 *   1. symbols load from .gnu_debuglink separate debuginfo
 *   2. deleted/replaced executables resolve through /proc/<pid>/exe
 *   3. symbols load even when the ELF carries no .eh_frame CFI table
 *
 * The test compiles a small workload at runtime, drives it with ptrace,
 * and feeds a real register/stack snapshot into the public unwind API.
 */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#include "gunwinder/unwinder.h"

#define STACK_SNAPSHOT_SIZE (32 * 1024)
#define REGMAP_RBP 6
#define REGMAP_RSP 7
#define REGMAP_RIP 16

struct symbol_hits {
	int hot_leaf;
	int hot_mid;
};

static void frame_callback(const struct gu_frame_record *frame, void *ctx)
{
	struct symbol_hits *hits = ctx;

	if (getenv("SYMTEST_DEBUG"))
		fprintf(stderr, "frame pc=0x%llx abs=0x%llx sym=%s off=%llu flags=%u\n",
			(unsigned long long)frame->pc,
			(unsigned long long)frame->abs_pc,
			frame->symbol ? frame->symbol : "<none>",
			(unsigned long long)frame->offset, frame->flags);
	if (frame->symbol && strstr(frame->symbol, "hot_leaf"))
		hits->hot_leaf = 1;
	if (frame->symbol && strstr(frame->symbol, "hot_mid"))
		hits->hot_mid = 1;
}

static int write_workload_source(const char *path)
{
	FILE *f = fopen(path, "w");
	if (!f)
		return -1;
	fputs(
"#include <signal.h>\n"
"static volatile unsigned long spin;\n"
"__attribute__((noinline)) void hot_leaf(void){ for(;;){ spin++; "
"for (int i = 0; i < 1000; i++) __asm__ volatile(\"\" ::: \"memory\"); } }\n"
"__attribute__((noinline)) void hot_mid(void){ hot_leaf(); }\n"
"int main(void){ signal(SIGPIPE, SIG_IGN); for (;;) hot_mid(); }\n", f);
	fclose(f);
	return 0;
}

static int run_cmd(const char *cmd)
{
	int ret = system(cmd);
	if (ret == -1)
		return -1;
	return WIFEXITED(ret) ? WEXITSTATUS(ret) : -1;
}

/*
 * fork+exec the workload under ptrace. The child blocks in raise(SIGSTOP)
 * inside hot_leaf(); waitpid(WUNTRACED) returns that group stop.
 */
static pid_t spawn_workload(const char *bin)
{
	pid_t pid = fork();

	if (pid < 0) {
		perror("fork");
		return -1;
	}
	if (pid == 0) {
		execl(bin, bin, (char *)NULL);
		perror("execl workload");
		_exit(127);
	}

	/* Let the child reach the userspace spin loop, then freeze it. */
	usleep(200 * 1000);
	if (ptrace(PTRACE_SEIZE, pid, 0, NULL) < 0) {
		perror("PTRACE_SEIZE");
		return -1;
	}
	if (ptrace(PTRACE_INTERRUPT, pid, NULL, NULL) < 0) {
		perror("PTRACE_INTERRUPT");
		return -1;
	}
	return pid;
}

/* Read the stopped child's registers + stack, then unwind it live. */
static int unwind_stopped_child(pid_t pid, struct symbol_hits *hits)
{
	struct gu_init_cfg cfg = { 0 };
	struct gu_context *ctx = NULL;
	struct gu_stack_info info;
	uint64_t regs[32] = { 0 };
	unsigned char *stack = NULL;
	struct user_regs_struct user_regs;
	int status = 0;
	int ret = 1;
	long lrc;
	int fd_mem;
	unsigned long start;
	char mem_path[64];

	if (waitpid(pid, &status, WUNTRACED) < 0 || !WIFSTOPPED(status)) {
		perror("waitpid for workload stop");
		return 1;
	}

	lrc = ptrace(PTRACE_GETREGS, pid, NULL, &user_regs);
	if (lrc < 0) {
		perror("PTRACE_GETREGS");
		return 1;
	}

	regs[REGMAP_RBP] = user_regs.rbp;
	regs[REGMAP_RSP] = user_regs.rsp;
	regs[REGMAP_RIP] = user_regs.rip;

	stack = calloc(1, STACK_SNAPSHOT_SIZE);
	if (!stack)
		return 1;

	start = user_regs.rsp & ~(unsigned long)(getpagesize() - 1);
	snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", pid);
	fd_mem = open(mem_path, O_RDONLY | O_CLOEXEC);
	if (fd_mem < 0) {
		perror("open /proc/pid/mem");
		goto out;
	}
	/* Read page by page: stack above RSP can abut an unmapped guard. */
	for (size_t off = 0; off < STACK_SNAPSHOT_SIZE; off += getpagesize()) {
		if (pread(fd_mem, stack + off, getpagesize(),
			  (off_t)(start + off)) < 0) {
			if (errno != EIO && errno != EFAULT &&
			    errno != EINVAL && errno != ENOMEM) {
				perror("pread stack snapshot");
				close(fd_mem);
				goto out;
			}
		}
	}
	close(fd_mem);

	ctx = gu_init(&cfg);
	if (!ctx) {
		fprintf(stderr, "gu_init failed\n");
		goto out;
	}

	memset(&info, 0, sizeof(info));
	info.pid = pid;
	info.regs = regs;
	info.regs_size = sizeof(regs);
	info.stack_data = stack;
	info.stack_size = STACK_SNAPSHOT_SIZE;

	{
		int n = gu_unwind(ctx, &info, frame_callback, hits);
		if (getenv("SYMTEST_DEBUG"))
			fprintf(stderr, "unwind frames=%d reason=%d\n", n,
				gu_flags_reason(info.flags));
		if (n < 0)
			goto out_ctx;
	}

	/* A valid chain must never trip the no-progress loop guard. */
	if (gu_flags_reason(info.flags) == GU_UNWIND_REASON_NO_PROGRESS) {
		fprintf(stderr, "valid workload chain stopped with NO_PROGRESS\n");
		goto out_ctx;
	}

	ret = 0;
out_ctx:
	gu_cleanup(ctx);
out:
	free(stack);
	return ret;
}

static void reap_child(pid_t pid)
{
	ptrace(PTRACE_DETACH, pid, NULL, NULL);
	kill(pid, SIGKILL);
	waitpid(pid, NULL, 0);
}

static int stop_and_unwind(const char *bin)
{
	pid_t pid = spawn_workload(bin);
	struct symbol_hits hits = { 0 };
	int rc;

	if (pid < 0)
		return 1;

	rc = unwind_stopped_child(pid, &hits);
	if (rc == 0 && !hits.hot_leaf) {
		fprintf(stderr, "%s: hot_leaf frame was not symbolized\n", bin);
		rc = 1;
	}
	if (rc == 0 && !hits.hot_mid)
		fprintf(stderr, "%s: note: hot_mid frame not seen (unwind depth)\n",
			bin);
	if (rc)
		fprintf(stderr, "stop_and_unwind(%s) FAILED\n", bin);

	reap_child(pid);
	return rc;
}

static int scenario_debuglink(const char *dir)
{
	char src[PATH_MAX], bin[PATH_MAX], dbg[PATH_MAX];
	char cmd[PATH_MAX * 4];

	snprintf(src, sizeof(src), "%s/work.c", dir);
	snprintf(bin, sizeof(bin), "%s/work_dbg", dir);
	snprintf(dbg, sizeof(dbg), "%s/work_dbg.debug", dir);
	if (write_workload_source(src) != 0)
		return 1;

	snprintf(cmd, sizeof(cmd),
		 "cc -O0 -fno-omit-frame-pointer -g -o %s %s && "
		 "objcopy --only-keep-debug %s %s && "
		 "strip --strip-unneeded %s && "
		 "objcopy --add-gnu-debuglink=%s %s",
		 bin, src, bin, dbg, bin, dbg, bin);
	if (run_cmd(cmd) != 0) {
		fprintf(stderr, "debuglink workload build failed\n");
		return 1;
	}
	if (stop_and_unwind(bin) == 0) {
		printf("gnu_debuglink symbol resolution ok\n");
		return 0;
	}
	fprintf(stderr, "scenario_debuglink FAILED\n");
	return 1;
}

static int scenario_deleted(const char *dir)
{
	char src[PATH_MAX], bin[PATH_MAX], repl[PATH_MAX];
	char cmd[PATH_MAX * 3];
	pid_t pid;
	struct symbol_hits hits = { 0 };
	int rc = 1;

	snprintf(src, sizeof(src), "%s/work.c", dir);
	snprintf(bin, sizeof(bin), "%s/work_del", dir);
	snprintf(repl, sizeof(repl), "%s/replacement", dir);
	if (write_workload_source(src) != 0)
		return 1;

	snprintf(cmd, sizeof(cmd),
		 "cc -O0 -fno-omit-frame-pointer -g -o %s %s && cp /bin/true %s",
		 bin, src, repl);
	if (run_cmd(cmd) != 0) {
		fprintf(stderr, "deleted workload build failed\n");
		return 1;
	}

	pid = spawn_workload(bin);
	if (pid < 0)
		return 1;

	/* Replace the running executable's path with a different inode. */
	if (rename(repl, bin) != 0) {
		perror("rename replacement over running binary");
		reap_child(pid);
		return 1;
	}

	if (unwind_stopped_child(pid, &hits) == 0 && hits.hot_leaf) {
		printf("deleted-mapping symbol resolution ok\n");
		rc = 0;
	} else {
		fprintf(stderr, "scenario_deleted FAILED\n");
	}
	reap_child(pid);
	return rc;
}

static int scenario_no_cfi(const char *dir)
{
	char src[PATH_MAX], bin[PATH_MAX];
	char cmd[PATH_MAX * 3];

	snprintf(src, sizeof(src), "%s/work.c", dir);
	snprintf(bin, sizeof(bin), "%s/work_nocfi", dir);
	if (write_workload_source(src) != 0)
		return 1;

	snprintf(cmd, sizeof(cmd),
		 "cc -O0 -fno-omit-frame-pointer -g -o %s %s && "
		 "objcopy --remove-section .eh_frame "
		 "--remove-section .eh_frame_hdr %s",
		 bin, src, bin);
	if (run_cmd(cmd) != 0) {
		fprintf(stderr, "no-cfi workload build failed\n");
		return 1;
	}
	if (stop_and_unwind(bin) == 0) {
		printf("symbols-without-cfi resolution ok\n");
		return 0;
	}
	fprintf(stderr, "scenario_no_cfi FAILED\n");
	return 1;
}

int main(void)
{
	char dir[] = "/tmp/gunwinder-symtest-XXXXXX";
	int failures = 0;

	if (!mkdtemp(dir)) {
		perror("mkdtemp");
		return 1;
	}

	failures += scenario_debuglink(dir);
	failures += scenario_deleted(dir);
	failures += scenario_no_cfi(dir);

	if (failures)
		fprintf(stderr, "%d symbol resolution scenario(s) failed\n",
			failures);
	return failures ? 1 : 0;
}
