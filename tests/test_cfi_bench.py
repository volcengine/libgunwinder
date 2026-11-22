# SPDX-License-Identifier: LGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 ByteDance Inc.

import re
import subprocess
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
LIBGUNWINDER = REPO_ROOT


def test_libgunwinder_cfi_bench_reports_throughput_and_p99() -> None:
    subprocess.run(
        ["make", "-C", str(LIBGUNWINDER), "bin/cfi_bench"],
        check=True,
        text=True,
        timeout=60,
    )

    proc = subprocess.run(
        [
            str(LIBGUNWINDER / "bin" / "cfi_bench"),
            "--frames",
            "1000",
            "--set-size",
            "10",
            "--warmup",
            "100",
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert proc.returncode == 0, proc.stdout + "\n" + proc.stderr
    assert re.search(r"frames_per_sec=[0-9]+\.[0-9]+", proc.stdout)
    assert re.search(r"avg_ns_per_frame=[0-9]+\.[0-9]+", proc.stdout)
    assert re.search(r"p99_ns_per_frame=[0-9]+\.[0-9]+", proc.stdout)
