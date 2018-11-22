#!/bin/sh

docker exec $CONTAINER sh -c "cd $SRCDIR && find common p11-kit trust -name '*.c' -print | cppcheck -f --platform=unix64 --relative-paths --language=c --quiet -I common -I p11-kit -I trust --file-list=- --inline-suppr --template='{file}:{line},{severity},{id},{message}' --error-exitcode=1 2> $BUILDDIR/cppcheck.log"
