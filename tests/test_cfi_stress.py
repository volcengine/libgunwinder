# SPDX-License-Identifier: LGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 ByteDance Inc.

import subprocess
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
LIBGUNWINDER = REPO_ROOT


def test_libgunwinder_cfi_stress_cli_runs_all_cases() -> None:
    subprocess.run(
        ["make", "-C", str(LIBGUNWINDER), "bin/cfi_stress"],
        check=True,
        text=True,
        timeout=60,
    )

    proc = subprocess.run(
        [str(LIBGUNWINDER / "bin" / "cfi_stress")],
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert proc.returncode == 0, proc.stdout + "\n" + proc.stderr
    assert "expr_signed_compare_branch" in proc.stdout
    assert "expr_branch_loop_is_bounded" in proc.stdout
    assert "expr_invalid_register_number_fails" in proc.stdout
    assert "expr_deref_size_rejects_too_wide" in proc.stdout
    assert "cfi_val_expression" in proc.stdout
    assert "cfi_def_cfa_expression" in proc.stdout
    assert "cfi_offset_extended_rule" in proc.stdout
    assert "cfi_val_offset_rule" in proc.stdout
    assert "cfi_truncated_expression_block_fails" in proc.stdout
    assert "cfi_truncated_instruction_fails" in proc.stdout
    assert "cfi_same_value_and_undefined_non_return_regs" in proc.stdout
