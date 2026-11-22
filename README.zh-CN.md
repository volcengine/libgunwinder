# libgunwinder

[English](README.md) | [简体中文](README.zh-CN.md)

libgunwinder 是一个面向 Linux 用户态的栈回溯库，适用于长时间运行的 Profiling 和线上诊断场景。它从调用方提供的寄存器和栈快照中回溯调用栈，并尽量复用 ELF、符号和 CFI 元数据，降低持续采样时的开销。

项目名含义为 **Global Unwinder**。

## 目录

- [特性](#特性)
- [支持平台](#支持平台)
- [依赖](#依赖)
- [构建](#构建)
- [安装](#安装)
- [快速开始](#快速开始)
- [架构](#架构)
- [工具](#工具)
- [验证](#验证)
- [并发约束](#并发约束)
- [文档链接](#文档链接)
- [许可证](#许可证)
- [致谢](#致谢)

## 特性

- 按需加载 ELF、DWARF、CFI 和符号信息，适合重复回溯。
- 复用进程级和 ELF 级缓存，减少采样过程中的内存分配抖动。
- 支持 DWARF CFI 回溯；调用方提供 `GU_FLAG_HINT_SET_FP` 时可走 frame pointer 快路径。
- 支持基于 Build ID 的 ELF/debug 文件匹配，并提供 Go 符号处理选项。
- 支持 PID 生命周期事件，用于进程退出或模块重载时清理缓存。
- 提供 debug dump 读写能力和离线回放工具。
- 提供内核符号查询辅助接口，便于诊断场景解析内核地址。

## 支持平台

- Linux
- `x86_64`
- `aarch64`

Makefile 会根据当前架构选择 `include/arch/x86` 或 `include/arch/arm64` 下的架构相关头文件。

## 依赖

构建和链接需要：

- GNU make
- GCC 或 Clang 等 C 编译器
- elfutils 库：`libelf`、`libdw`
- binutils 库：`libbfd`、`libiberty`
- OpenSSL 库：`libssl`、`libcrypto`
- zstd 库：`libzstd`（符号名在内存中压缩保存）
- POSIX/Linux 系统头文件
- Python 3 和 pytest，仅 `make tests` 需要

## 构建

```bash
make
```

构建产物包括：

- `lib/libgunwinder.a`
- `lib/libgunwinder.so`
- `bin/bt_debug`

如需查看完整编译和链接命令：

```bash
make V=1
```

## 安装

```bash
make install DESTDIR=/path/to/stage
```

安装路径：

- `/usr/lib`
- `/usr/include/gunwinder`

## 快速开始

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

	struct gu_process_exit_event exit_event = {
		.pid = pid,
		.start_time = unique_id,
	};
	gu_event_occur(ctx, GU_EVENT_PROCESS_EXIT, &exit_event);
	gu_cleanup(ctx);
}
```

`struct gu_stack_info` 中的寄存器和栈内存由调用方持有。libgunwinder 只会在 `gu_unwind()` 调用期间读取这些数据，不接管所有权。

`unique_id` 标识进程实例：即进程的启动时间（单位为 clock tick），
也就是 `/proc/<pid>/stat` 的第 22 个字段。如果样本的 `unique_id`
与该 pid 下当前存活的进程不一致，libgunwinder 不会用新进程的映射去回溯它。

## 架构

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

主要公开接口声明在 [`include/gunwinder/unwinder.h`](include/gunwinder/unwinder.h)：

- `gu_init()` 和 `gu_cleanup()` 管理 unwinder 根上下文。
- `gu_preload_pid_debug_info()` 在采样前预热指定 PID 的 ELF/debug 元数据。
- `gu_unwind()` 回溯一份栈快照，并通过回调输出 frame。
- `gu_event_occur()` 通知进程生命周期事件。
- `gu_debug_dump_sample()` 和 `gu_read_stack_dump()` 用于离线 debug dump。

## 工具

`bin/bt_debug` 可回放 `gu_debug_dump_sample()` 生成的栈 dump：

```bash
bin/bt_debug [-v|--verbose] [-q|--quiet] <dump-file-or-directory>
```

做耗时测试时建议将普通输出重定向到文件，避免终端打印影响回溯耗时。

`bin/bt_debug_minimize` 把随 dump 保存的 ELF 文件裁剪到回溯和符号化需要的
section，便于分享 dump 而不带上二进制的其余部分：

```bash
bin/bt_debug_minimize --dump-dir DIR --out-dir DIR
bin/bt_debug_minimize --elf FILE --out FILE
```

## 验证

仓库包含自包含的测试。它们生成合成输入，或在运行时编译小程序；不依赖私有
测试数据或外部服务。

```bash
make tests
```

`make tests` 先运行 `bin/` 下的独立测试工具，再运行 `tests/` 下按用例组织的
测试（pytest），覆盖 CFI 解码与去重、符号名压缩、进程身份与 maps 重载、ELF
缓存、调用者帧查找、大页代码段恢复、日志以及调试 dump 工具。CI 在 x86_64 和
arm64 上分别用 gcc、clang 运行，并额外用 AddressSanitizer 和
UndefinedBehaviorSanitizer 跑一遍。

`bin/cfi_bench --frames 100000 --set-size 100 --warmup 1000` 是合成的 CFI
parser/evaluator 微基准测试；它的输出适合作为本机性能信号，不应直接等同为
线上 workload 模型。

## 并发约束

每个 `struct gu_context` 有自己的互斥锁，所有以 context 为参数的调用都会持有
它，因此同一个 context 上的调用是串行的。不同 context 之间除了少数文档列出的
进程级状态（内核符号、pid context 监听器注册表、libelf 初始化和日志钩子）外不
共享可变状态，所以不同 context 可以各用一个线程并发回溯。完整模型见
[`include/gunwinder/unwinder.h`](include/gunwinder/unwinder.h) 开头的说明。

## 2.0 的变化

2.0 有以下不兼容的 API 变化，已有调用方需要相应修改：

- `GU_EVENT_PROCESS_EXIT` 的参数改为 `struct gu_process_exit_event *`（pid 和
  进程实例的启动时间），不再是 `int *`。
- 不再支持 `gu_init_cfg::go_buildid_only`：设置后 `gu_init()` 返回失败。
- `gu_stack_info` 新增 `tid`（被采样的线程），用于读取 leader 已经退出的进程。
  请把结构体整体清零后再填写。
- `gu_copy_statistics()` 在 context 锁内复制计数；`gu_get_statistics()` 只保留给
  单线程调用方。
- 链接需要 `-lzstd`。

## 文档链接

- [English README](README.md)
- [致谢](ACKNOWLEDGEMENTS.zh-CN.md)
- [项目声明](NOTICE)
- [LGPLv3 许可证文本](LICENSE)
- [GPLv3 基础许可证文本](COPYING)
- [LGPLv3 附加权限](COPYING.LESSER)
- [作者](AUTHOR)

## 许可证

除非文件中另有说明，libgunwinder 使用 GNU Lesser General Public License v3.0 or later（`LGPL-3.0-or-later`）授权。见 [`LICENSE`](LICENSE)、[`COPYING`](COPYING) 和 [`COPYING.LESSER`](COPYING.LESSER)。

部分 vendored 第三方头文件带有自己的版权和许可证声明。见 [`NOTICE`](NOTICE) 和 [`ACKNOWLEDGEMENTS.zh-CN.md`](ACKNOWLEDGEMENTS.zh-CN.md)。

## 致谢

libgunwinder 致谢：

- [uthash](https://troydhanson.github.io/uthash/)：本仓库 vendored 了 `uthash.h` 和 `utlist.h`。
- [elfutils](https://sourceware.org/elfutils/) 及其 `libelf`/`libdw` 库。
  libgunwinder 的部分 DWARF 和栈回溯行为与 elfutils/libdw 做过交叉校验。
  libgunwinder 保留自己的数据结构、parser/cache 布局和 stack-snapshot
  回溯流程；本项目没有复制 elfutils 源码。本项目选择 `LGPL-3.0-or-later`，
  以对齐 elfutils libraries/backends 可用的 LGPLv3-or-later 许可证选项。

详情见 [`ACKNOWLEDGEMENTS.zh-CN.md`](ACKNOWLEDGEMENTS.zh-CN.md)。
