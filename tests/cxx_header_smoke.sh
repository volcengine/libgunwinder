#!/bin/sh
# SPDX-License-Identifier: LGPL-3.0-or-later

set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
tmpdir=$(mktemp -d)

cleanup()
{
	rm -rf "$tmpdir"
}
trap cleanup EXIT

cat > "$tmpdir/header_smoke.cc" <<'EOF'
#include <gunwinder/unwinder.h>

int main()
{
	gu_frame_callback_t callback = nullptr;
	pid_ctx_callback pid_callback = nullptr;
	gu_regs regs = {};
	gu_stack_info info = {};

	gu_regs_init(&regs, GU_ARCH_NATIVE);
	gu_stack_info_set_regs(&info, &regs);
	(void)callback;
	(void)pid_callback;
	(void)info;
	return 0;
}
EOF

"${CXX:-c++}" -std=c++11 -I"$repo_dir/include" \
	-c "$tmpdir/header_smoke.cc" -o "$tmpdir/header_smoke.o"
