# SPDX-License-Identifier: LGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 ByteDance Inc.

import subprocess
import textwrap
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
LIBGUNWINDER = REPO_ROOT
GU_COMM_C = LIBGUNWINDER / "src" / "gu_comm.c"
GU_ELF_C = LIBGUNWINDER / "src" / "gu_elf.c"
BT_DEBUG_C = LIBGUNWINDER / "tools" / "bt_debug.c"
GU_STACKTRACE_C = LIBGUNWINDER / "src" / "gu_stacktrace.c"


def test_cmdline_argv0_helper_reads_current_process_path(tmp_path: Path) -> None:
    harness = tmp_path / "cmdline_argv0_harness.c"
    binary = tmp_path / "cmdline_argv0_harness"
    harness.write_text(
        textwrap.dedent(
            r"""
            #include <stdio.h>
            #include <string.h>
            #include <unistd.h>

            #include "gu_comm.h"

            int main(int argc, char **argv)
            {
                char argv0[4096];

                if (argc < 1 || argv[0][0] != '/')
                    return 2;

                if (gu_get_pid_cmdline_argv0(getpid(), argv0, sizeof(argv0)) != 0)
                    return 3;

                if (strcmp(argv0, argv[0]) != 0) {
                    fprintf(stderr, "argv0=%s expected=%s\n", argv0, argv[0]);
                    return 4;
                }

                return 0;
            }
            """
        ),
        encoding="utf-8",
    )

    subprocess.run(
        [
            "cc",
            "-D_GNU_SOURCE",
            "-std=c11",
            "-Werror=implicit-function-declaration",
            "-I",
            str(LIBGUNWINDER / "src"),
            "-I",
            str(LIBGUNWINDER / "include"),
            str(harness),
            str(GU_COMM_C),
            "-o",
            str(binary),
            "-lcrypto",
        ],
        check=True,
        cwd=REPO_ROOT,
        text=True,
        timeout=30,
    )

    proc = subprocess.run(
        [str(binary)],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        timeout=30,
    )
    assert proc.returncode == 0, proc.stdout + "\n" + proc.stderr


def test_openat2_resolve_in_root_keeps_absolute_symlink_inside_root(
    tmp_path: Path,
) -> None:
    fake_root = tmp_path / "root"
    host_target = tmp_path / "host-target"
    fake_target = fake_root / str(host_target).lstrip("/")
    link_parent = fake_root / "bin"
    link_path = link_parent / "app"

    host_target.mkdir(parents=True)
    fake_target.mkdir(parents=True)
    link_parent.mkdir(parents=True)
    (host_target / "app").write_text("host-file", encoding="utf-8")
    (fake_target / "app").write_text("root-file", encoding="utf-8")
    link_path.symlink_to(host_target / "app")

    harness = tmp_path / "openat2_in_root_harness.c"
    binary = tmp_path / "openat2_in_root_harness"
    harness.write_text(
        textwrap.dedent(
            r"""
            #define _GNU_SOURCE
            #include <asm/unistd.h>
            #include <errno.h>
            #include <fcntl.h>
            #include <linux/openat2.h>
            #include <stdio.h>
            #include <sys/syscall.h>
            #include <unistd.h>

            #ifndef SYS_openat2
            #ifdef __NR_openat2
            #define SYS_openat2 __NR_openat2
            #endif
            #endif

            int main(int argc, char **argv)
            {
                int root_fd;
                int fd;
                int openat_error;
                char buf[64] = { 0 };
                struct open_how how = {
                    .flags = O_RDONLY | O_CLOEXEC,
                    .resolve = RESOLVE_IN_ROOT,
                };

                if (argc != 3)
                    return 2;

                root_fd = open(argv[1], O_PATH | O_DIRECTORY | O_CLOEXEC);
                if (root_fd < 0)
                    return 3;

            #ifdef SYS_openat2
                fd = syscall(SYS_openat2, root_fd, argv[2], &how, sizeof(how));
            #else
                errno = ENOSYS;
                fd = -1;
                #endif
                if (fd < 0) {
                    openat_error = errno;
                    perror("openat2");
                    if (openat_error == ENOSYS)
                        return 77;
                    return 4;
                }

                if (read(fd, buf, sizeof(buf) - 1) < 0)
                    return 5;

                printf("%s", buf);
                return 0;
            }
            """
        ),
        encoding="utf-8",
    )

    subprocess.run(
        [
            "cc",
            "-D_GNU_SOURCE",
            "-std=c11",
            "-Werror=implicit-function-declaration",
            str(harness),
            "-o",
            str(binary),
        ],
        check=True,
        cwd=REPO_ROOT,
        text=True,
        timeout=30,
    )

    proc = subprocess.run(
        [str(binary), str(fake_root), str(link_path.relative_to(fake_root))],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        timeout=30,
    )
    if proc.returncode == 77:
        pytest.skip("openat2 is not implemented by this kernel")
    assert proc.returncode == 0, proc.stdout + "\n" + proc.stderr
    assert proc.stdout == "root-file"


def test_maps_info_only_merges_adjacent_equal_mappings(tmp_path: Path) -> None:
    maps_file = tmp_path / "maps"
    maps_file.write_text(
        "\n".join(
            [
                "00001000-00002000 r-xp 00000000 00:00 0 /tmp/huge_text",
                "00003000-00004000 r-xp 00001000 00:00 0 /tmp/huge_text",
                "00004000-00005000 r-xp 00002000 00:00 0 /tmp/huge_text",
                "",
            ]
        ),
        encoding="utf-8",
    )

    harness = tmp_path / "maps_merge_harness.c"
    binary = tmp_path / "maps_merge_harness"
    harness.write_text(
        textwrap.dedent(
            r"""
            #include <stdio.h>

            #include "gu_comm.h"

            int main(int argc, char **argv)
            {
                struct maps_info *maps = NULL;
                int count = 0;

                if (argc != 2)
                    return 2;

                maps = gu_get_maps_info(0, &count, PERMISSION_X, argv[1]);
                if (!maps)
                    return 3;

                if (count != 2) {
                    fprintf(stderr, "count=%d\n", count);
                    gu_free_maps_info(maps, count);
                    return 4;
                }

                if (maps[0].start != 0x1000 || maps[0].end != 0x2000 ||
                    maps[1].start != 0x3000 || maps[1].end != 0x5000) {
                    fprintf(stderr, "maps[0]=0x%lx-0x%lx maps[1]=0x%lx-0x%lx\n",
                            maps[0].start, maps[0].end, maps[1].start, maps[1].end);
                    gu_free_maps_info(maps, count);
                    return 5;
                }

                gu_free_maps_info(maps, count);
                return 0;
            }
            """
        ),
        encoding="utf-8",
    )

    subprocess.run(
        [
            "cc",
            "-D_GNU_SOURCE",
            "-std=c11",
            "-Werror=implicit-function-declaration",
            "-I",
            str(LIBGUNWINDER / "src"),
            "-I",
            str(LIBGUNWINDER / "include"),
            str(harness),
            str(GU_COMM_C),
            "-o",
            str(binary),
            "-lcrypto",
        ],
        check=True,
        cwd=REPO_ROOT,
        text=True,
        timeout=30,
    )

    proc = subprocess.run(
        [str(binary), str(maps_file)],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        timeout=30,
    )
    assert proc.returncode == 0, proc.stdout + "\n" + proc.stderr


def test_elf_exec_range_match_accepts_noncontiguous_loads_and_rejects_holes(
    tmp_path: Path,
) -> None:
    harness = tmp_path / "exec_ranges_harness.c"
    binary = tmp_path / "exec_ranges_harness"
    harness.write_text(
        textwrap.dedent(
            r"""
            #include <stdbool.h>
            #include <stdio.h>

            #include "gu_elf.h"

            int main(void)
            {
                struct gu_elf_exec_range raw_ranges[] = {
                    { 0x400000, 0x5303000 },
                    { 0x5800000, 0x8a52000 },
                };
                struct gu_elf_exec_ranges ranges = {
                    .ranges = raw_ranges,
                    .count = 2,
                };
                unsigned long exec_virt_addr = 0;

                if (!gu_elf_exec_ranges_find(&ranges, 0x400000, 0x5303000,
                                             &exec_virt_addr) ||
                    exec_virt_addr != 0x400000)
                    return 1;

                if (!gu_elf_exec_ranges_find(&ranges, 0x5800000, 0x8a52000,
                                             &exec_virt_addr) ||
                    exec_virt_addr != 0x5800000)
                    return 2;

                if (gu_elf_exec_ranges_find(&ranges, 0x5303000, 0x5800000,
                                            &exec_virt_addr))
                    return 3;

                if (gu_elf_exec_ranges_find(&ranges, 0x5200000, 0x5810000,
                                            &exec_virt_addr))
                    return 4;

                return 0;
            }
            """
        ),
        encoding="utf-8",
    )

    subprocess.run(
        [
            "cc",
            "-D_GNU_SOURCE",
            "-std=c11",
            "-Werror=implicit-function-declaration",
            "-I",
            str(LIBGUNWINDER / "src"),
            str(harness),
            str(GU_ELF_C),
            "-o",
            str(binary),
            "-lelf",
            "-pthread",
        ],
        check=True,
        cwd=REPO_ROOT,
        text=True,
        timeout=30,
    )

    proc = subprocess.run(
        [str(binary)],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        timeout=30,
    )
    assert proc.returncode == 0, proc.stdout + "\n" + proc.stderr


def test_bt_debug_recovers_hugepage_text_from_dump_local_elf() -> None:
    source = BT_DEBUG_C.read_text()

    assert "bt_debug_hugepage_text_recovery_init" in source
    assert "bt_debug_hugepage_text_recovery_try_path" in source
    assert "bt_debug_hugepage_text_recovery_match" in source
    assert "gu_elf_exec_ranges_load(path, &ranges)" in source
    assert "gu_elf_exec_ranges_find(&recovery->exec_ranges" in source
    assert "write_bt_debug_maps_line_with_path" in source
    assert "hugepage optimize detected, replace anonymous executable segment" in source


def test_live_hugepage_text_uses_cmdline0_with_openat2_pid_root() -> None:
    source = GU_STACKTRACE_C.read_text()

    assert "RESOLVE_IN_ROOT" in source
    assert "gu_open_pid_root_path(ctx, pid, recovery->path, O_RDONLY)" in source
    assert "gu_elf_exec_ranges_load_fd(fd, &ranges)" in source
    assert "gu_open_pid_root_path(ctx, pid, file_name, O_RDONLY)" in source
    assert "if (path != recovery->path)" in source
    assert "hugepage_text_recovery_try_maps_paths" not in source
    assert "PERMISSION_R | PERMISSION_W | PERMISSION_X" not in source


def test_pid_root_open_falls_back_only_for_missing_openat2_without_path_escape() -> None:
    source = GU_STACKTRACE_C.read_text()

    assert "gu_openat2_in_root_compat" in source
    assert "fd < 0 && errno == ENOSYS" in source
    assert "O_PATH | O_NOFOLLOW | O_CLOEXEC" in source
    assert 'readlinkat(component_fd, "", link_target' in source
    assert "GU_OPEN_IN_ROOT_MAX_SYMLINKS" in source
    assert "open(\"/proc/%d/root" not in source
