#!/bin/sh

set +x

if test x"$COVERAGE" = xyes; then
  docker exec $CONTAINER su user sh -c "pip3 install --user cpp-coveralls"
  docker exec \
	 -e TRAVIS_JOB_ID="$TRAVIS_JOB_ID" \
	 -e TRAVIS_BRANCH="$TRAVIS_BRANCH" \
	 $CONTAINER su user sh -c "cd $SRCDIR && /home/user/.local/bin/cpp-coveralls -b $BUILDDIR -E '(^|.*/)(frob|mock|test)-.*|(^|.*/)(virtual-fixed-generated\.c)' --gcov-options '\-lp'"
fi
