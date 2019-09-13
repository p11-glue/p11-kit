#!/bin/sh

docker exec $CONTAINER su - user sh -c "cd $SRCDIR && meson $BUILDDIR -Dstrict=true -Dprefix=/installdir -Dlibdir=/installdir/lib -Dsysconfdir=/installdir/etc -Dtrust-paths=/installdir/etc/pki/ca-trust-source:/installdir/share/pki/ca-trust-source $MESON_BUILD_OPTS"
if test $? -ne 0; then
  exit 1
fi

if test -n "$SCAN_BUILD"; then
    docker exec $CONTAINER su - user sh -c "cd $SRCDIR && SCAN_BUILD='$SCAN_BUILD' ninja scan-build -C $BUILDDIR"
else
    docker exec $CONTAINER su - user sh -c "cd $SRCDIR && ninja -C $BUILDDIR"
fi
if test $? -ne 0; then
  exit 1
fi

docker exec $CONTAINER su - user sh -c "cd $SRCDIR && P11_KIT_DEBUG=all $MESON_TEST_ENV meson test -C $BUILDDIR $MESON_TEST_OPTS || cat $BUILDDIR/meson-logs/testlog.txt"
if test $? -ne 0; then
  exit 1
fi

docker exec $CONTAINER sh -c "cd $SRCDIR && ninja -C $BUILDDIR install"
if test $? -ne 0; then
  exit 1
fi
