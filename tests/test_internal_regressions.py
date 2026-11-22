# SPDX-License-Identifier: LGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 ByteDance Inc.

import re
import shutil
import subprocess
import textwrap
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
LIBGUNWINDER = REPO_ROOT
TEST_TOOL = LIBGUNWINDER / "bin" / "test_internal_regressions"


def build_internal_tool() -> None:
    subprocess.run(
        ["make", "bin/test_internal_regressions"],
        cwd=LIBGUNWINDER,
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        text=True,
        timeout=60,
    )


def run_internal_case(name: str, *args: str) -> str:
    build_internal_tool()
    proc = subprocess.run(
        [str(TEST_TOOL), name, *args],
        cwd=LIBGUNWINDER,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode == 0, proc.stdout + "\n" + proc.stderr
    return proc.stdout


def test_live_vdso_uses_fresh_local_dump_without_proc_root_prefix() -> None:
    out = run_internal_case("vdso")

    assert "vdso fresh local dump ok" in out


def test_retired_elf_cache_is_reused_then_swept_after_deadline() -> None:
    out = run_internal_case("retire")

    assert "retired elf cache lifecycle ok" in out


def test_maps_reload_gate_uses_per_pid_randomized_backoff() -> None:
    out = run_internal_case("maps-reload")

    assert "maps reload jitter ok" in out


def test_reused_pid_never_loads_the_new_instance_view_for_an_old_sample() -> None:
    out = run_internal_case("identity-reuse")

    assert "instance identity on reuse ok" in out


def test_identity_check_accepts_a_live_thread_of_the_sampled_instance() -> None:
    out = run_internal_case("identity-thread")

    assert "thread of the live instance ok" in out


def test_thread_of_a_zombie_leader_loads_the_process_view() -> None:
    """A leader that called pthread_exit() has no
    mappings in its /proc; its live thread's sample loads, reloads and
    replaces the process' view through the thread's /proc."""
    out = run_internal_case("identity-zombie-leader")

    assert "thread of a zombie leader ok" in out


def test_instance_switched_during_the_maps_read_is_not_attached() -> None:
    """The pid is reused between the instance check
    and the maps read. Cold load, leaf-miss reload and identity replacement
    drop the view built and keep the old one; controls commit it."""
    subprocess.run(
        ["make", "bin/test_identity_race"],
        cwd=LIBGUNWINDER,
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        text=True,
        timeout=60,
    )
    proc = subprocess.run(
        [str(LIBGUNWINDER / "bin" / "test_identity_race")],
        cwd=LIBGUNWINDER,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode == 0, proc.stdout + "\n" + proc.stderr
    assert "failures=0" in proc.stdout, proc.stdout


def test_maps_reload_refreshes_in_place_without_exit_events() -> None:
    out = run_internal_case("reload-in-place")

    assert "maps reload in place ok" in out


def test_unchanged_elf_file_is_reused_without_parsing() -> None:
    out = run_internal_case("elf-file-cache")

    assert "elf file cache ok" in out


def test_retired_elf_sweep_needs_no_timer_thread() -> None:
    out = run_internal_case("retire-without-timer")

    assert "retire without timer ok" in out


def test_arm_mapping_symbol_names_are_rejected_before_symbol_insert() -> None:
    out = run_internal_case("mapping-symbol-names")

    assert "mapping symbol name filter ok" in out


def test_symbol_string_table_view_supports_direct_and_fallback_reads() -> None:
    out = run_internal_case("string-table-view")

    assert "symbol string table view ok" in out


def test_cfi_lookup_pc_rule_matches_elfutils_activation_semantics() -> None:
    out = run_internal_case("cfi-lookup-pc-rule")

    assert "cfi lookup pc rule ok" in out


def test_fp_stack_symbolizes_caller_frames_by_return_address_minus_one() -> None:
    """A frame-pointer stack resolves a return address that lands on the next
    function (a noreturn call as the caller's last instruction) to the
    caller, as the DWARF walk does; the sampled PC itself is not adjusted."""
    out = run_internal_case("fp-caller-return-address")

    assert "fp caller return address ok" in out


def test_fp_stack_names_the_sigreturn_trampoline_by_its_entry() -> None:
    """A signal handler returns into the sigreturn trampoline the kernel
    pushed: its entry, with an unnamed nop before it (glibc's __restore_rt,
    the arm64 vDSO's __kernel_rt_sigreturn), is named by itself."""
    out = run_internal_case("fp-sigreturn-trampoline")

    assert "fp sigreturn trampoline ok" in out


def test_symbol_lookup_ignores_arm_mapping_symbols_at_function_address(
    tmp_path: Path,
) -> None:
    if shutil.which("cc") is None or shutil.which("readelf") is None:
        raise AssertionError("missing ELF test tools: cc and readelf")

    asm = tmp_path / "mapping_symbol.S"
    elf = tmp_path / "libmapping_symbol.so"
    asm.write_text(
        textwrap.dedent(
            r"""
            .text
            .globl libgunwinder_real_func
            .type libgunwinder_real_func, @function
            libgunwinder_real_func:
            .cfi_startproc
            .local $x
            .type $x, @notype
            $x:
                ret
            .cfi_endproc
            .size libgunwinder_real_func, .-libgunwinder_real_func
            """
        ),
        encoding="utf-8",
    )
    subprocess.run(
        [
            "cc",
            "-shared",
            "-nostdlib",
            "-Wl,--build-id=sha1",
            str(asm),
            "-o",
            str(elf),
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    symbols = subprocess.run(
        ["readelf", "-W", "-s", str(elf)],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    ).stdout
    match = re.search(
        r"\s+[0-9]+:\s+([0-9a-fA-F]+)\s+\d+\s+FUNC\s+\S+\s+\S+\s+\S+\s+libgunwinder_real_func\b",
        symbols,
    )
    assert match is not None, symbols

    out = run_internal_case(
        "symbol-lookup",
        str(elf),
        "0x" + match.group(1),
        "libgunwinder_real_func",
    )

    assert "symbol lookup skip mapping symbol ok" in out


def test_symbol_lookup_works_when_elf_has_no_cfi(tmp_path: Path) -> None:
    if shutil.which("cc") is None or shutil.which("readelf") is None:
        raise AssertionError("missing ELF test tools: cc and readelf")

    asm = tmp_path / "no_cfi_symbol.S"
    elf = tmp_path / "libno_cfi_symbol.so"
    asm.write_text(
        textwrap.dedent(
            r"""
            .text
            .globl libgunwinder_no_cfi_func
            .type libgunwinder_no_cfi_func, @function
            libgunwinder_no_cfi_func:
                nop
                ret
            .size libgunwinder_no_cfi_func, .-libgunwinder_no_cfi_func
            """
        ),
        encoding="utf-8",
    )
    subprocess.run(
        [
            "cc",
            "-shared",
            "-nostdlib",
            "-Wl,--build-id=sha1",
            str(asm),
            "-o",
            str(elf),
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    sections = subprocess.run(
        ["readelf", "-W", "-S", str(elf)],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    ).stdout
    frame_sizes = [
        int(match.group(1), 16)
        for match in re.finditer(
            r"\]\s+\.(?:eh_frame|debug_frame)\s+\S+\s+"
            r"[0-9a-fA-F]+\s+[0-9a-fA-F]+\s+([0-9a-fA-F]+)\s",
            sections,
        )
    ]
    assert all(size == 0 for size in frame_sizes), sections

    symbols = subprocess.run(
        ["readelf", "-W", "-s", str(elf)],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    ).stdout
    match = re.search(
        r"\s+[0-9]+:\s+([0-9a-fA-F]+)\s+\d+\s+FUNC\s+\S+\s+\S+\s+\S+\s+libgunwinder_no_cfi_func\b",
        symbols,
    )
    assert match is not None, symbols

    out = run_internal_case(
        "symbol-lookup",
        str(elf),
        "0x" + match.group(1),
        "libgunwinder_no_cfi_func",
    )

    assert "symbol lookup skip mapping symbol ok" in out


def test_return_address_at_function_end_resolves_previous_symbol(
    tmp_path: Path,
) -> None:
    if shutil.which("cc") is None or shutil.which("readelf") is None:
        raise AssertionError("missing ELF test tools: cc and readelf")

    asm = tmp_path / "return_address_boundary.S"
    elf = tmp_path / "libreturn_address_boundary.so"
    asm.write_text(
        textwrap.dedent(
            r"""
            .text
            .globl libgunwinder_boundary_func
            .type libgunwinder_boundary_func, @function
            libgunwinder_boundary_func:
            .cfi_startproc
                nop
                ret
            .cfi_endproc
            .size libgunwinder_boundary_func, .-libgunwinder_boundary_func

            .globl libgunwinder_boundary_next
            .type libgunwinder_boundary_next, @function
            libgunwinder_boundary_next:
            .cfi_startproc
                ret
            .cfi_endproc
            .size libgunwinder_boundary_next, .-libgunwinder_boundary_next
            """
        ),
        encoding="utf-8",
    )
    subprocess.run(
        [
            "cc",
            "-shared",
            "-nostdlib",
            "-Wl,--build-id=sha1",
            str(asm),
            "-o",
            str(elf),
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    symbols = subprocess.run(
        ["readelf", "-W", "-s", str(elf)],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    ).stdout
    match = re.search(
        r"\s+[0-9]+:\s+([0-9a-fA-F]+)\s+([0-9]+)\s+FUNC\s+\S+\s+\S+\s+\S+\s+libgunwinder_boundary_func\b",
        symbols,
    )
    assert match is not None, symbols
    return_address = int(match.group(1), 16) + int(match.group(2), 10)

    out = run_internal_case(
        "frame-symbol-lookup",
        str(elf),
        hex(return_address),
        "libgunwinder_boundary_func",
    )

    assert "frame symbol lookup return-address rule ok" in out


def _readelf_symbol_address(symbols: str, name: str, sym_type: str) -> int:
    match = re.search(
        rf"\s+[0-9]+:\s+([0-9a-fA-F]+)\s+\d+\s+{sym_type}\s+\S+\s+\S+\s+\S+\s+{re.escape(name)}\b",
        symbols,
    )
    assert match is not None, f"{sym_type} symbol {name} not found in:\n{symbols}"
    return int(match.group(1), 16)


def test_notype_symbols_inside_typed_funcs_are_dropped_but_standalone_asm_kept(
    tmp_path: Path,
) -> None:
    """LTO-style function-local NOTYPE labels must resolve to the containing
    STT_FUNC (and cost nothing), while a standalone NOTYPE assembly routine
    outside any function must still be symbolized."""
    if shutil.which("cc") is None or shutil.which("readelf") is None:
        raise AssertionError("missing ELF test tools: cc and readelf")

    asm = tmp_path / "notype_mix.S"
    elf = tmp_path / "libnotype_mix.so"
    asm.write_text(
        textwrap.dedent(
            r"""
            .text

            .globl libgunwinder_typed_func
            .type libgunwinder_typed_func, @function
            libgunwinder_typed_func:
                nop
            .type libgunwinder_inner_label, @notype
            libgunwinder_inner_label:
                nop
                ret
            .size libgunwinder_typed_func, .-libgunwinder_typed_func

            .globl libgunwinder_asm_routine
            .type libgunwinder_asm_routine, @notype
            libgunwinder_asm_routine:
                nop
                ret
            .size libgunwinder_asm_routine, .-libgunwinder_asm_routine
            """
        ),
        encoding="utf-8",
    )
    subprocess.run(
        [
            "cc",
            "-shared",
            "-nostdlib",
            "-Wl,--build-id=sha1",
            str(asm),
            "-o",
            str(elf),
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    symbols = subprocess.run(
        ["readelf", "-W", "-s", str(elf)],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    ).stdout

    typed = _readelf_symbol_address(symbols, "libgunwinder_typed_func", "FUNC")
    inner = _readelf_symbol_address(symbols, "libgunwinder_inner_label", "NOTYPE")
    standalone = _readelf_symbol_address(symbols, "libgunwinder_asm_routine", "NOTYPE")
    # The inner label really is inside the typed function body.
    assert typed < inner < typed + 16

    # Standalone NOTYPE assembly routine survives and symbolizes to itself.
    out = run_internal_case(
        "symbol-lookup", str(elf), hex(standalone), "libgunwinder_asm_routine"
    )
    assert "symbol lookup skip mapping symbol ok" in out

    # Function-local NOTYPE labels resolve to the containing function, both
    # at the label start and at a PC strictly inside the label's own range.
    out = run_internal_case(
        "symbol-lookup", str(elf), hex(inner), "libgunwinder_typed_func"
    )
    assert "symbol lookup skip mapping symbol ok" in out

    # The typed function entry itself is unaffected.
    out = run_internal_case(
        "symbol-lookup", str(elf), hex(typed), "libgunwinder_typed_func"
    )
    assert "symbol lookup skip mapping symbol ok" in out


def test_sized_notype_extending_past_func_is_kept(tmp_path: Path) -> None:
    """A NOTYPE symbol with a size that starts inside a typed function but
    extends past its end must NOT be dropped: the bytes past the function are
    only symbolizable through that NOTYPE range.  Whole-range coverage (not
    start-address coverage) is the correct drop condition."""
    if shutil.which("cc") is None or shutil.which("readelf") is None:
        raise AssertionError("missing ELF test tools: cc and readelf")

    asm = tmp_path / "notype_overlap.S"
    elf = tmp_path / "libnotype_overlap.so"
    asm.write_text(
        textwrap.dedent(
            r"""
            .text

            .globl libgunwinder_overlap_func
            .type libgunwinder_overlap_func, @function
            libgunwinder_overlap_func:
                nop
            libgunwinder_overlap_label:
                nop
                ret
            .size libgunwinder_overlap_func, .-libgunwinder_overlap_func

            .type libgunwinder_overlap_label, @notype
                nop
                nop
                nop
                nop
            .size libgunwinder_overlap_label, .-libgunwinder_overlap_label
            """
        ),
        encoding="utf-8",
    )
    subprocess.run(
        ["cc", "-shared", "-nostdlib", "-Wl,--build-id=sha1", str(asm), "-o", str(elf)],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    symbols = subprocess.run(
        ["readelf", "-W", "-s", str(elf)],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    ).stdout

    func = _readelf_symbol_address(symbols, "libgunwinder_overlap_func", "FUNC")
    label = _readelf_symbol_address(symbols, "libgunwinder_overlap_label", "NOTYPE")
    size_match = re.search(
        r"\s+[0-9]+:\s+[0-9a-fA-F]+\s+([0-9a-fA-F]+)\s+NOTYPE\s+\S+\s+\S+\s+\S+\s+libgunwinder_overlap_label\b",
        symbols,
    )
    assert size_match is not None, symbols
    label_size = int(size_match.group(1), 0)  # readelf prints sizes in decimal
    func_match = re.search(
        r"\s+[0-9]+:\s+[0-9a-fA-F]+\s+([0-9a-fA-F]+)\s+FUNC\s+\S+\s+\S+\s+\S+\s+libgunwinder_overlap_func\b",
        symbols,
    )
    assert func_match is not None, symbols
    # three instructions: 3 bytes on x86_64, 12 on arm64
    func_end = func + int(func_match.group(1), 0)
    # The NOTYPE starts inside the function and extends past it.
    assert func < label < func_end
    assert label + label_size > func_end

    # Inside the shared prefix, the containing FUNC wins (interval semantics).
    out = run_internal_case(
        "symbol-lookup", str(elf), hex(func), "libgunwinder_overlap_func"
    )
    assert "symbol lookup skip mapping symbol ok" in out
    out = run_internal_case(
        "symbol-lookup", str(elf), hex(label), "libgunwinder_overlap_func"
    )
    assert "symbol lookup skip mapping symbol ok" in out

    # The NOTYPE-only tail past the function end must still symbolize.
    tail = label + label_size - 1
    out = run_internal_case(
        "symbol-lookup", str(elf), hex(tail), "libgunwinder_overlap_label"
    )
    assert "symbol lookup skip mapping symbol ok" in out
