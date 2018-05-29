#!/bin/sh

if test x"$COVERAGE" = xyes; then
  docker exec $CONTAINER pip install cpp-coveralls
  docker exec \
	 -e TRAVIS_JOB_ID="$TRAVIS_JOB_ID" \
	 -e TRAVIS_BRANCH="$TRAVIS_BRANCH" \
	 $CONTAINER sh -c "cd $BUILDDIR && coveralls -b $BUILDDIR -E '(^|.*/)(frob|mock|test)-.*|(^|.*/)(virtual-fixed\.c)' --gcov-options '\-lp'"
fi
