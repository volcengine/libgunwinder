# SPDX-License-Identifier: LGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 ByteDance Inc.

"""libgunwinder debuginfo memory layout: packed symbol names, CFI bodies."""

import platform
import shutil
import subprocess
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
LIBGUNWINDER = REPO_ROOT
TEST_TOOL = LIBGUNWINDER / "bin" / "test_debuginfo_mem"
ARCH = platform.machine()
ARCH_DEFINE = {
    "x86_64": ("GUNWINDER_X86", "x86"),
    "aarch64": ("GUNWINDER_ARM64", "arm64"),
    "riscv64": ("GUNWINDER_RISCV64", "riscv64"),
}
# the CFI fixtures are x86-64 assembly (registers, frame layout)
x86_only = pytest.mark.skipif(ARCH != "x86_64", reason="x86-64 CFI fixture")
# a library with tens of thousands of symbols, many zstd blocks
BIG_ELFS = [
    Path("/usr/lib/x86_64-linux-gnu/libLLVM-15.so.1"),
    Path("/usr/lib/aarch64-linux-gnu/libLLVM-15.so.1"),
]


def run_case(name: str, *args: str) -> str:
    subprocess.run(
        ["make", "bin/test_debuginfo_mem"],
        cwd=LIBGUNWINDER,
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=120,
    )
    proc = subprocess.run(
        [str(TEST_TOOL), name, *args],
        cwd=LIBGUNWINDER,
        capture_output=True,
        text=True,
        timeout=600,
    )
    assert proc.returncode == 0, proc.stdout + "\n" + proc.stderr
    return proc.stdout


def test_packed_symbol_names_read_back_exactly() -> None:
    assert "symbol names round trip ok" in run_case("names-roundtrip")


def test_corrupt_or_truncated_symbol_names_fail_the_read() -> None:
    assert "corrupt and truncated data rejected ok" in run_case("names-corrupt")


def test_symbol_name_read_failures_are_counted_and_not_cached() -> None:
    assert "symbol name read failures counted ok" in run_case("symbol-name-failure")


@x86_only
def test_unreadable_caller_name_is_not_taken_from_the_next_symbol() -> None:
    assert "not taken from the next symbol ok" in run_case("symbol-name-failure-frame")


@x86_only
def test_identical_fdes_share_a_body_and_keep_their_ranges() -> None:
    assert "cfi bodies shared by identical FDEs only ok" in run_case("cfi-dedup")


@x86_only
def test_cie_cfa_expression_survives_the_instruction_pool_move() -> None:
    assert "cie expression survives the pool move ok" in run_case("cfi-cie-expression")


@x86_only
def test_fde_restore_after_a_cie_without_instructions() -> None:
    assert "cfi restore after an empty cie ok" in run_case("cfi-empty-cie-restore")


@x86_only
def test_failed_allocation_fails_the_whole_cfi_table() -> None:
    assert "fails the whole table ok" in run_case("cfi-alloc-failure")


def test_elf_without_build_id_is_keyed_by_its_head_and_name() -> None:
    assert "keyed by its first 2 MiB and name ok" in run_case("buildid-fallback")


def test_symbol_lookups_from_several_threads() -> None:
    assert "concurrent symbol lookups ok" in run_case("concurrent-lookup")


def test_symbol_lookups_from_several_threads_on_a_big_library() -> None:
    big = next((p for p in BIG_ELFS if p.exists()), None)
    if big is None:
        pytest.skip("no libLLVM-15 on this host")
    assert "concurrent symbol lookups ok" in run_case("concurrent-lookup", str(big))


def build_asan_tool(tmp_path: Path) -> Path:
    if shutil.which("gcc") is None or ARCH not in ARCH_DEFINE:
        pytest.skip("no gcc or unknown architecture")
    subprocess.run(["make", "lib/libgunwinder.a"], cwd=LIBGUNWINDER, check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=300)
    define, arch_dir = ARCH_DEFINE[ARCH]
    tool = tmp_path / "test_debuginfo_mem_asan"
    proc = subprocess.run(
        ["gcc", "-O1", "-g", "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
         "-I", str(LIBGUNWINDER / "include"),
         "-I", str(LIBGUNWINDER / "include" / "gunwinder"),
         "-I", str(LIBGUNWINDER / "include" / "arch" / arch_dir),
         f"-D{define}", str(LIBGUNWINDER / "tools" / "test_debuginfo_mem.c"),
         "-o", str(tool), str(LIBGUNWINDER / "lib" / "libgunwinder.a"),
         "-Wl,--wrap=realloc", "-lelf", "-ldw", "-lzstd", "-lssl", "-lcrypto",
         "-liberty", "-lm", "-pthread", "-ldl"],
        capture_output=True, text=True, timeout=300,
    )
    if proc.returncode != 0 and "sanitize" in proc.stderr:
        pytest.skip("compiler without AddressSanitizer")
    assert proc.returncode == 0, proc.stderr
    return tool


# Use after free only shows when the allocator moves a block, which glibc
# rarely does on shrink; AddressSanitizer always does.
ASAN_CASES = ["names-roundtrip", "names-corrupt", "symbol-name-failure", "buildid-fallback"]
if ARCH == "x86_64":
    ASAN_CASES += ["cfi-dedup", "cfi-cie-expression", "cfi-empty-cie-restore",
                   "cfi-alloc-failure", "symbol-name-failure-frame"]


def test_debuginfo_mem_cases_under_address_sanitizer(tmp_path: Path) -> None:
    tool = build_asan_tool(tmp_path)
    for case in ASAN_CASES:
        proc = subprocess.run(
            [str(tool), case], cwd=LIBGUNWINDER, capture_output=True, text=True,
            timeout=600, env={"ASAN_OPTIONS": "detect_leaks=0", "PATH": "/usr/bin:/bin"},
        )
        assert proc.returncode == 0 and "AddressSanitizer" not in proc.stderr, (
            case + "\n" + proc.stdout + proc.stderr)
