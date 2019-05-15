#!/bin/sh

set +x

libdir="$1"
p11_package_config_modules="$2"

# Proxy module is actually same as library, so install a link
for i in so dylib; do
  test -f "$MESON_INSTALL_DESTDIR_PREFIX/$libdir/libp11-kit.$i" &&
    ln -sf `readlink $MESON_INSTALL_DESTDIR_PREFIX/$libdir/libp11-kit.$i` \
       "$MESON_INSTALL_DESTDIR_PREFIX/$libdir/p11-kit-proxy.$i" || true;
done

mkdir -p "$MESON_INSTALL_DESTDIR_PREFIX/$p11_package_config_modules"
