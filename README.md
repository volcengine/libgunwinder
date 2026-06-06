# libgunwinder

[English](README.md) | [简体中文](README.zh-CN.md)

libgunwinder is a Linux userspace stack unwinding library for long-running profilers and production diagnostics. It focuses on low-overhead unwinding from caller-provided register and stack snapshots, while reusing ELF, symbol, and CFI metadata across samples.

The project name expands to **Global Unwinder**.

## Contents

- [Features](#features)
- [Supported Platforms](#supported-platforms)
- [Dependencies](#dependencies)
- [Build](#build)
- [Install](#install)
- [Quick Start](#quick-start)
- [Architecture](#architecture)
- [Tools](#tools)
- [Validation](#validation)
- [Concurrency](#concurrency)
- [Documentation Links](#documentation-links)
- [License](#license)
- [Acknowledgements](#acknowledgements)

## Features

- Lazy ELF, DWARF, CFI, and symbol loading for repeated unwinds.
- Reusable per-process and per-ELF caches to reduce allocation churn during sampling.
- DWARF CFI unwinding with a frame-pointer fast path when `GU_FLAG_HINT_SET_FP` is provided.
- Build-ID based ELF/debug-file matching and Go symbol handling options.
- PID lifecycle events for cache cleanup on process exit or module reload.
- Debug dump read/write helpers and a replay tool for offline investigation.
- Kernel symbol lookup helpers for diagnostics that need kernel address resolution.

## Supported Platforms

- Linux
- `x86_64`
- `aarch64`

The Makefile selects architecture-specific headers from `include/arch/x86` or `include/arch/arm64`.

## Dependencies

Build-time and link-time dependencies:

- GNU make
- A C compiler such as GCC or Clang
- elfutils libraries: `libelf` and `libdw`
- binutils libraries: `libbfd` and `libiberty`
- OpenSSL libraries: `libssl` and `libcrypto`
- POSIX/Linux system headers

## Build

```bash
make
```

The build creates:

- `lib/libgunwinder.a`
- `lib/libgunwinder.so` with soname `libgunwinder.so.1`
- `bin/bt_debug`

Use `V=1` to print the full compiler and linker commands:

```bash
make V=1
```

## Install

```bash
make install DESTDIR=/path/to/stage
```

Installed files are placed under:

- `/usr/lib`
- `/usr/include/gunwinder`
- `/usr/lib/pkgconfig`

Override `PREFIX`, `LIBDIR`, `INCLUDEDIR`, or `PKGCONFIGDIR` to stage files
under different installation paths:

```bash
make install DESTDIR=/path/to/stage PREFIX=/usr
```

Downstream builds can discover the library with pkg-config:

```bash
pkg-config --cflags --libs libgunwinder
```

## Quick Start

```c
#include <gunwinder/unwinder.h>
#include <stdio.h>
#include <sys/types.h>

static void on_frame(const struct gu_frame_record *frame, void *user_ctx)
{
	(void)user_ctx;

	if (frame->symbol)
		printf("%s+0x%lx\n", frame->symbol, frame->offset);
}

void unwind_sample(pid_t pid, void *regs, uint32_t regs_size, uint8_t *stack, size_t stack_size)
{
	struct gu_init_cfg cfg = {
		.debug_print = false,
		.go_not_strip_name = false,
		.go_buildid_only = false,
	};
	struct gu_context *ctx = gu_init(&cfg);
	if (!ctx)
		return;

	uint64_t unique_id = gu_preload_pid_debug_info(ctx, pid);

	struct gu_stack_info info = {
		.pid = pid,
		.unique_id = unique_id,
		.regs = regs,
		.regs_size = regs_size,
		.stack_data = stack,
		.stack_size = stack_size,
	};

	gu_unwind(ctx, &info, on_frame, NULL);

	gu_event_occur(ctx, GU_EVENT_PROCESS_EXIT, &pid);
	gu_cleanup(ctx);
}
```

Callers own the register and stack buffers passed through `struct gu_stack_info`. libgunwinder reads them during `gu_unwind()` and does not take ownership.

## Architecture

```text
caller snapshot
  | regs + stack bytes
  v
gu_unwind()
  | per-pid executable intervals
  | per-ELF symbols, build IDs, debug files
  v
DWARF CFI / frame-pointer unwinding
  |
  v
gu_frame_callback_t
```

The main public entry points are declared in [`include/gunwinder/unwinder.h`](include/gunwinder/unwinder.h):

- `gu_init()` and `gu_cleanup()` manage the root unwinder context.
- `gu_preload_pid_debug_info()` warms per-PID ELF/debug metadata before sampling.
- `gu_unwind()` walks a stack snapshot and emits frames through a callback.
- `gu_event_occur()` notifies the unwinder about process lifecycle events.
- `gu_debug_dump_sample()` and `gu_read_stack_dump()` support offline debug dumps.

## Tools

`bin/bt_debug` replays stack dump files created by `gu_debug_dump_sample()`:

```bash
bin/bt_debug [-v|--verbose] <dump-file-or-directory>
```

For timing-oriented runs, redirect normal output to a file so terminal printing does not dominate measured unwind time.

## Validation

The repository includes self-contained validation tools. They generate synthetic
inputs or use caller-provided dump files; no private test data or internal
services are required.

```bash
make clean all
bin/cfi_stress
bin/test_stable_fp_miss_reload
bin/cfi_bench --frames 100000 --set-size 100 --warmup 1000
```

- `cfi_stress` covers DWARF expression and CFI edge cases.
- `test_stable_fp_miss_reload` checks PID map reload throttling behavior.
- `cfi_bench` is a synthetic CFI parser/evaluator microbenchmark. Treat its
  output as a local performance signal rather than a production workload model.

## Concurrency

`struct gu_context` owns mutable caches. Serialize access to a context when calling `gu_unwind()`, `gu_preload_pid_debug_info()`, `gu_event_occur()`, and cache-related accessors. Use separate contexts if independent threads need to unwind without external locking.

## Documentation Links

- [中文 README](README.zh-CN.md)
- [Acknowledgements](ACKNOWLEDGEMENTS.md)
- [Project notice](NOTICE)
- [LGPLv3 license text](LICENSE)
- [GPLv3 base license text](COPYING)
- [LGPLv3 additional permissions](COPYING.LESSER)
- [Authors](AUTHOR)

## License

Unless a file states otherwise, libgunwinder is licensed under the GNU Lesser General Public License v3.0 or later (`LGPL-3.0-or-later`). See [`LICENSE`](LICENSE), [`COPYING`](COPYING), and [`COPYING.LESSER`](COPYING.LESSER).

Some vendored third-party headers carry their own notices. See [`NOTICE`](NOTICE) and [`ACKNOWLEDGEMENTS.md`](ACKNOWLEDGEMENTS.md).

## Acknowledgements

libgunwinder acknowledges:

- [uthash](https://troydhanson.github.io/uthash/) for the vendored `uthash.h` and `utlist.h` headers.
- [elfutils](https://sourceware.org/elfutils/) and its `libelf`/`libdw`
  libraries. Parts of libgunwinder's DWARF and unwinding behavior were
  cross-checked against elfutils/libdw. libgunwinder keeps its own data
  structures, parser/cache layout, and stack-snapshot unwind flow; no
  elfutils source code is copied into this project. The project uses
  `LGPL-3.0-or-later` to align with the LGPLv3-or-later option available to
  elfutils libraries and backends.

See [`ACKNOWLEDGEMENTS.md`](ACKNOWLEDGEMENTS.md) for details.
