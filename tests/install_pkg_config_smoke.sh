#!/bin/sh
# SPDX-License-Identifier: LGPL-3.0-or-later

set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
make_cmd=${MAKE:-make}
prefix=${PREFIX:-/opt/libgunwinder}
libdir=${LIBDIR:-${prefix}/lib}
includedir=${INCLUDEDIR:-${prefix}/include}
pkgconfigdir=${PKGCONFIGDIR:-${libdir}/pkgconfig}
version=${VERSION:-1.0.0}
lib_major=${LIB_MAJOR:-1}
stage=$(mktemp -d)
tmpdir=$(mktemp -d)

cleanup()
{
	rm -rf "$stage" "$tmpdir"
}
trap cleanup EXIT

require_file()
{
	if [ ! -f "$1" ]; then
		echo "missing file: $1" >&2
		exit 1
	fi
}

require_link()
{
	if [ ! -L "$1" ]; then
		echo "missing symlink: $1" >&2
		exit 1
	fi
}

require_word()
{
	case " $1 " in
	*" $2 "*) ;;
	*)
		echo "$3: $1" >&2
		exit 1
		;;
	esac
}

require_flag()
{
	case " $1 " in
	*" $2 "*) ;;
	*)
		echo "$3: $1" >&2
		exit 1
		;;
	esac
}

is_system_libdir()
{
	case "$1" in
	/usr/lib|/usr/lib64) return 0 ;;
	*) return 1 ;;
	esac
}

is_system_includedir()
{
	case "$1" in
	/usr/include) return 0 ;;
	*) return 1 ;;
	esac
}

"$make_cmd" -C "$repo_dir" install \
	DESTDIR="$stage" \
	PREFIX="$prefix" \
	LIBDIR="$libdir" \
	INCLUDEDIR="$includedir" \
	PKGCONFIGDIR="$pkgconfigdir"

require_file "$stage$libdir/libgunwinder.a"
require_file "$stage$libdir/libgunwinder.so.$version"
require_link "$stage$libdir/libgunwinder.so.$lib_major"
require_link "$stage$libdir/libgunwinder.so"
require_file "$stage$includedir/gunwinder/unwinder.h"
require_file "$stage$includedir/gunwinder/unwinder_types.h"
require_file "$stage$pkgconfigdir/libgunwinder.pc"

soname="libgunwinder.so.$lib_major"
if ! readelf -d "$stage$libdir/$soname" | grep -q "Library soname: \[$soname\]"; then
	echo "$soname does not advertise the expected soname" >&2
	exit 1
fi

cat > "$tmpdir/smoke.c" <<'EOF'
#include <gunwinder/unwinder.h>

int main(void)
{
	struct gu_init_cfg cfg = { 0 };
	struct gu_context *ctx = gu_init(&cfg);

	if (!ctx)
		return 1;

	gu_cleanup(ctx);
	return 0;
}
EOF

PKG_CONFIG_PATH="$stage$pkgconfigdir${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
PKG_CONFIG_SYSROOT_DIR="$stage"
export PKG_CONFIG_PATH
export PKG_CONFIG_SYSROOT_DIR

cflags=$(pkg-config --cflags libgunwinder)
libs=$(pkg-config --libs libgunwinder)
static_libs=$(pkg-config --static --libs libgunwinder)
compile_cflags=$cflags
link_libs=$libs

if [ "$includedir" != /usr/include ]; then
	require_flag "$cflags" "-I$stage$includedir" \
		"pkg-config cflags do not reference staged includedir"
elif is_system_includedir "$includedir"; then
	compile_cflags=$(PKG_CONFIG_ALLOW_SYSTEM_CFLAGS=1 \
		pkg-config --cflags libgunwinder)
fi

if ! is_system_libdir "$libdir"; then
	require_flag "$libs" "-L$stage$libdir" \
		"pkg-config libs do not reference staged libdir"
else
	link_libs=$(PKG_CONFIG_ALLOW_SYSTEM_LIBS=1 \
		pkg-config --libs libgunwinder)
fi
require_flag "$libs" "-lgunwinder" \
	"pkg-config libs do not link libgunwinder"

if pkg-config --exists libdw libelf openssl; then
	requires_private=$(pkg-config --print-requires-private libgunwinder | tr '\n' ' ')
	require_word "$requires_private" "libdw" \
		"pkg-config Requires.private does not include libdw"
	require_word "$requires_private" "libelf" \
		"pkg-config Requires.private does not include libelf"
	require_word "$requires_private" "openssl" \
		"pkg-config Requires.private does not include openssl"
else
	require_flag "$static_libs" "-ldw" \
		"pkg-config static libs do not include libdw"
	require_flag "$static_libs" "-lelf" \
		"pkg-config static libs do not include libelf"
	require_flag "$static_libs" "-lssl" \
		"pkg-config static libs do not include libssl"
	require_flag "$static_libs" "-lcrypto" \
		"pkg-config static libs do not include libcrypto"
fi

${CC:-cc} "$tmpdir/smoke.c" $compile_cflags $link_libs -o "$tmpdir/smoke"
