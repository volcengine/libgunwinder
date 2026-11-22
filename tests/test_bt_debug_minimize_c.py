# SPDX-License-Identifier: LGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 ByteDance Inc.

import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
LIBGUNWINDER_DIR = REPO_ROOT
MINIMIZER_BIN = LIBGUNWINDER_DIR / "bin" / "bt_debug_minimize"


def require_elf_tools() -> None:
    missing = [name for name in ("cc", "readelf") if shutil.which(name) is None]
    if missing:
        pytest.skip("missing ELF test tools: " + ", ".join(missing))


def ensure_minimizer() -> None:
    subprocess.run(
        ["make", "bin/bt_debug_minimize"],
        cwd=LIBGUNWINDER_DIR,
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        text=True,
        timeout=60,
    )


def build_probe_elf(tmp_path: Path) -> Path:
    source = tmp_path / "probe.c"
    binary = tmp_path / "probe"
    source.write_text(
        textwrap.dedent(
            r"""
            #include <stdint.h>

            static const char payload[65536] = { 1 };

            __attribute__((noinline))
            int libgunwinder_minimize_probe(uint64_t input)
            {
                return (int)(input + payload[0]);
            }

            int main(void)
            {
                return libgunwinder_minimize_probe(41) == 42 ? 0 : 1;
            }
            """
        ),
        encoding="utf-8",
    )
    subprocess.run(
        [
            "cc",
            "-g",
            "-fno-omit-frame-pointer",
            "-Wl,--build-id=sha1",
            str(source),
            "-o",
            str(binary),
        ],
        check=True,
        text=True,
        timeout=30,
    )
    return binary


def test_c_minimizer_keeps_symbols_cfi_and_build_id(tmp_path: Path) -> None:
    require_elf_tools()
    ensure_minimizer()
    src = build_probe_elf(tmp_path)
    dst = tmp_path / "probe.min"

    subprocess.run(
        [str(MINIMIZER_BIN), "--elf", str(src), "--out", str(dst)],
        check=True,
        text=True,
        timeout=30,
    )

    sections = subprocess.run(
        ["readelf", "-W", "-S", str(dst)],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    ).stdout
    assert ".symtab" in sections
    assert ".strtab" in sections
    assert ".eh_frame" in sections
    assert ".note.gnu.build-id" in sections
    assert dst.stat().st_size < src.stat().st_size

    symbols = subprocess.run(
        ["readelf", "-W", "-s", str(dst)],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    ).stdout
    assert "libgunwinder_minimize_probe" in symbols


def test_c_minimizer_mirrors_dump_tree(tmp_path: Path) -> None:
    require_elf_tools()
    ensure_minimizer()
    dump_dir = tmp_path / "dump_case"
    out_dir = tmp_path / "out" / "dump_case"
    bin_dir = dump_dir / "bin"
    bin_dir.mkdir(parents=True)
    src = build_probe_elf(bin_dir)
    (dump_dir / "maps").write_text(
        "00400000-00401000 r-xp 00000000 08:01 1 /service/probe\n",
        encoding="utf-8",
    )

    subprocess.run(
        [str(MINIMIZER_BIN), "--dump-dir", str(dump_dir), "--out-dir", str(out_dir)],
        check=True,
        text=True,
        timeout=30,
    )

    assert (out_dir / "maps").read_text(encoding="utf-8").startswith("00400000")
    assert (out_dir / "bin" / src.name).stat().st_size < src.stat().st_size
