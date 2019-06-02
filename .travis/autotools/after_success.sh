#!/bin/sh

if test x"$COVERAGE" = xyes; then
  # docker exec $CONTAINER pip install cpp-coveralls

  # manually install cpp-coveralls until the gcov fix has been
  # incorporated in the pip version
  docker exec $CONTAINER sh -c "cd /tmp && rm -rf cpp-coveralls && git clone -q https://github.com/eddyxu/cpp-coveralls && cd cpp-coveralls && python setup.py build && python setup.py install"
  docker exec \
	 -e TRAVIS_JOB_ID="$TRAVIS_JOB_ID" \
	 -e TRAVIS_BRANCH="$TRAVIS_BRANCH" \
	 $CONTAINER sh -c "cd $BUILDDIR && cpp-coveralls -b $BUILDDIR -E '(^|.*/)(frob|mock|test)-.*|(^|.*/)(virtual-fixed-generated\.h)' --gcov-options '\-lp'"
fi
