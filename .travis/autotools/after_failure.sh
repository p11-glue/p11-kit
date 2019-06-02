#!/bin/sh

docker exec $CONTAINER su - user sh -c "cd $BUILDDIR && cat test-suite.log"
