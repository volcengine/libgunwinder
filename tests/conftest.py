# SPDX-License-Identifier: LGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 ByteDance Inc.

"""Shared settings of the case-driven tests."""

import os

# The cases load ELF and CFI state without a context and do not free it, so
# in a sanitizer build they are checked for memory errors, not for leaks.
# Set here rather than in the Makefile so a direct pytest run behaves the
# same as `make tests`.
os.environ.setdefault("ASAN_OPTIONS", "detect_leaks=0")
