#!/bin/sh

docker cp . $CONTAINER:/srcdir
docker exec $CONTAINER cp -R /srcdir /coverage
docker exec $CONTAINER mkdir /builddir
docker exec $CONTAINER chown -R user /builddir
docker exec $CONTAINER mkdir /installdir
docker exec $CONTAINER mkdir -p /installdir/etc/pki/ca-trust-source
docker exec $CONTAINER mkdir -p /installdir/share/pki/ca-trust-source
docker exec $CONTAINER chown -R user /installdir
# FIXME: This is needed because some files are included in distribution
# and need to be generated in $srcdir rather than $builddir
docker exec $CONTAINER chown -R user /srcdir
docker exec $CONTAINER chown -R user /coverage
