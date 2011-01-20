#!/bin/sh -e

set -e

# Some boiler plate to get git setup as expected
if test -d .git; then
	if test -f .git/hooks/pre-commit.sample && \
	   test ! -f .git/hooks/pre-commit; then
		cp -pv .git/hooks/pre-commit.sample .git/hooks/pre-commit
	fi
fi

set -x

aclocal
libtoolize
autoheader
automake -a
autoconf
./configure "$@"

