#!/bin/sh

docker exec $CONTAINER su - user sh -c "cd $BUILDDIR && cat meson-logs/testlog.txt"
