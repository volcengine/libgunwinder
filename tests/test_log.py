# SPDX-License-Identifier: LGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 ByteDance Inc.

"""Every log message is one line, reaches a pipe at once and is rate limited."""

import subprocess
from pathlib import Path

import pytest


LIBGUNWINDER = Path(__file__).resolve().parents[1]


def run_log_case(name: str) -> str:
    subprocess.run(["make", "bin/test_log"], cwd=LIBGUNWINDER, check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=300)
    proc = subprocess.run([str(LIBGUNWINDER / "bin" / "test_log"), name],
                          cwd=LIBGUNWINDER, capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stdout + "\n" + proc.stderr
    return proc.stdout


@pytest.mark.parametrize("case,expect", [
    ("output-newline", "every output message is one line ok"),
    ("output-flushed", "output reaches a pipe at once ok"),
    ("log-limit", "first one then one per interval ok"),
])
def test_libgunwinder_log(case: str, expect: str) -> None:
    assert expect in run_log_case(case)
