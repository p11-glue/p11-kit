#!/bin/sh

NOCONFIGURE=1 ./autogen.sh
./configure --prefix=/installdir --libdir=/installdir/lib --sysconfdir=/installdir/etc --with-trust-paths=/installdir/etc/pki/ca-trust-source:/installdir/share/pki/ca-trust-source
make V=1
make check V=1
