# SPDX-License-Identifier: LGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 ByteDance Inc.

import subprocess
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
LIBGUNWINDER_DIR = REPO_ROOT
TEST_TOOL = LIBGUNWINDER_DIR / "bin" / "test_stable_fp_miss_reload"


def test_stable_fp_miss_does_not_reload_pid_maps_every_sample() -> None:
    """A missing deeper frame never reloads, a missing leaf reloads once then
    waits for the throttle, and a library mapped after the pid was first
    seen resolves on its first leaf miss (a process dying in libc right after
    exec keeps its user frames)."""
    subprocess.run(
        ["make", "bin/test_stable_fp_miss_reload", "bin/libdeep.so"],
        cwd=LIBGUNWINDER_DIR,
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        text=True,
        timeout=60,
    )

    proc = subprocess.run(
        [str(TEST_TOOL), str(LIBGUNWINDER_DIR / "bin" / "libdeep.so")],
        cwd=LIBGUNWINDER_DIR,
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert proc.returncode == 0, proc.stdout + "\n" + proc.stderr
