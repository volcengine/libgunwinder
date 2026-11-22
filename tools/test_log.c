/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* SPDX-FileCopyrightText: 2026 ByteDance Inc. */

/*
 * Tests of libgunwinder's log output: every message is one line, it is
 * flushed, and the limit on repeated messages.
 *
 * Usage: test_log <case>
 */
/* first: it defines _GNU_SOURCE for the system headers */
#include "../src/gu_stacktrace.c"

#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>

#define FAIL(...) do { fprintf(stderr, __VA_ARGS__); fputc('\n', stderr); return 1; } while (0)
#define SEC 1000000000ULL

static char *lines[64];
static int line_count;

static void capture(const char *s)
{
	if (line_count < 64)
		lines[line_count++] = strdup(s);
}

static void reset_capture(void)
{
	for (int i = 0; i < line_count; i++)
		free(lines[i]);
	line_count = 0;
}

static int case_output_newline(void)
{
	static const char *const want[] = { "a\n", "b\n", "\n", "[ERROR] c\n" };

	gu_set_print_fn(capture);
	GU_OUTPUT("a");
	GU_OUTPUT("b\n");	/* already a line: not doubled */
	GU_OUTPUT("%s", "");
	GU_ERROR("c");
	gu_set_print_fn(NULL);
	if (line_count != 4)
		FAIL("%d messages, want 4", line_count);
	for (int i = 0; i < 4; i++)
		if (strcmp(lines[i], want[i]) != 0)
			FAIL("message %d is \"%s\", want \"%s\"", i, lines[i], want[i]);
	reset_capture();
	puts("every output message is one line ok");
	return 0;
}

static int case_log_limit(void)
{
	struct gu_log_limit limit = { 0 };
	struct { uint64_t now; bool allow; uint64_t dropped; } steps[] = {
		{ 5 * SEC, true, 0 },		/* the first one */
		{ 6 * SEC, false, 0 },
		{ 300 * SEC, false, 0 },
		{ 305 * SEC, true, 2 },		/* the interval is over */
		{ 306 * SEC, false, 0 },
		{ 2000 * SEC, true, 1 },
		{ 4000 * SEC, true, 0 },	/* nothing dropped since */
	};

	for (size_t i = 0; i < sizeof(steps) / sizeof(steps[0]); i++) {
		uint64_t dropped = 99;
		bool allow = gu_log_limit_allow(&limit, steps[i].now, 300 * SEC, &dropped);

		if (allow != steps[i].allow || (allow && dropped != steps[i].dropped))
			FAIL("step %zu: allow %d dropped %lu, want %d %lu", i, allow,
			     allow ? dropped : 0, steps[i].allow, steps[i].dropped);
	}
	puts("log limit first one then one per interval ok");
	return 0;
}

/*
 * Printed to a pipe (a service's stdout to journald), a message is readable
 * while the process still runs, not when its buffer fills or it exits.
 */
static int case_output_flushed(void)
{
	int fds[2];
	char buf[64] = "";
	struct pollfd pfd;
	pid_t child;
	ssize_t n;

	if (pipe(fds) != 0)
		FAIL("pipe");
	child = fork();
	if (child < 0) {
		int err = errno;

		close(fds[0]);
		close(fds[1]);
		FAIL("fork: %s", strerror(err));
	}
	if (child == 0) {
		dup2(fds[1], STDOUT_FILENO);
		close(fds[0]);
		close(fds[1]);
		GU_OUTPUT("flushed");
		/* alive well past the wait below: only a flush can deliver */
		sleep(30);
		_exit(0);
	}
	close(fds[1]);
	pfd.fd = fds[0];
	pfd.events = POLLIN;
	/* generous for a loaded CI host; the child outlives it either way */
	n = poll(&pfd, 1, 10000) == 1 ? read(fds[0], buf, sizeof(buf) - 1) : -1;
	kill(child, SIGKILL);
	waitpid(child, NULL, 0);
	close(fds[0]);
	if (n <= 0 || strcmp(buf, "flushed\n") != 0)
		FAIL("nothing readable from the running process (read %zd \"%s\")", n, buf);
	puts("output reaches a pipe at once ok");
	return 0;
}

int main(int argc, char **argv)
{
	static const struct {
		const char *name;
		int (*fn)(void);
	} cases[] = {
		{ "output-newline", case_output_newline },
		{ "output-flushed", case_output_flushed },
		{ "log-limit", case_log_limit },
	};

	for (size_t i = 0; argc == 2 && i < sizeof(cases) / sizeof(cases[0]); i++)
		if (strcmp(argv[1], cases[i].name) == 0)
			return cases[i].fn();
	fprintf(stderr, "usage: %s <", argv[0]);
	for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
		fprintf(stderr, "%s%s", i ? "|" : "", cases[i].name);
	fprintf(stderr, ">\n");
	return 2;
}
