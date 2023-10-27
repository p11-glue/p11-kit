#!/bin/sh

set +x

bindir="$1"
libdir="$2"
shift 2

export PATH="$MESON_INSTALL_DESTDIR_PREFIX/$bindir:$PATH"
export LD_LIBRARY_PATH="$MESON_INSTALL_DESTDIR_PREFIX/$libdir:$LD_LIBRARY_PATH"
export PKG_CONFIG_PATH="$MESON_INSTALL_DESTDIR_PREFIX/$libdir/pkg-config:$PKG_CONFIG_PATH"
export abs_top_builddir="$MESON_BUILD_ROOT"
export abs_top_srcdir="$MESON_SOURCE_ROOT"

exec "$@"
