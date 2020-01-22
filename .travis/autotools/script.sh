#!/bin/sh

docker exec $CONTAINER sh -c "cd $SRCDIR && NOCONFIGURE=1 ./autogen.sh"
if test $? -ne 0; then
  exit 1
fi

docker exec $CONTAINER su - user sh -c "cd $BUILDDIR && $SRCDIR/configure --enable-strict --prefix=/installdir --libdir=/installdir/lib --sysconfdir=/installdir/etc --with-trust-paths=/installdir/etc/pki/ca-trust-source:/installdir/share/pki/ca-trust-source --enable-doc --without-systemd --without-bash-completion $BUILD_OPTS"
if test $? -ne 0; then
  exit 1
fi

if test -n "$PRELOAD_CMD"; then
  P11_KIT_TEST_LD_PRELOAD=$(docker exec $CONTAINER su - user sh -c "$PRELOAD_CMD")
fi
docker exec $CONTAINER su - user sh -c "cd $BUILDDIR && $SCAN_BUILD make -j$(nproc) V=1"
if test $? -ne 0; then
  exit 1
fi

docker exec $CONTAINER su - user sh -c "cd $BUILDDIR && P11_KIT_DEBUG=all LSAN_OPTIONS="$LSAN_OPTIONS" P11_KIT_TEST_LD_PRELOAD=\"$P11_KIT_TEST_LD_PRELOAD\" make distcheck -j$(nproc) V=1 $CHECK_OPTS"
if test $? -ne 0; then
  exit 1
fi

docker exec $CONTAINER su - user sh -c "cd $BUILDDIR && make install"
if test $? -ne 0; then
  exit 1
fi

docker exec $CONTAINER su - user sh -c "cd $BUILDDIR && make installcheck"
if test $? -ne 0; then
  exit 1
fi

docker exec $CONTAINER su - user sh -c "cd $BUILDDIR && valgrind --error-exitcode=81 pkcs11-tool --module p11-kit-proxy.so -L; test $? != 81"
if test $? -ne 0; then
  exit 1
fi
