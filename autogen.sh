#!/bin/sh -e

set -e

oldpwd=$(pwd)
topdir=$(dirname $0)
cd $topdir

# Some boiler plate to get git setup as expected
if test -d .git; then
	if test -f .git/hooks/pre-commit.sample && \
	   test ! -f .git/hooks/pre-commit; then
		cp -pv .git/hooks/pre-commit.sample .git/hooks/pre-commit
	fi
fi

set -x

autoreconf --force --install --verbose
if test x"$NOCONFIGURE" = x; then
  cd $oldpwd
  exec $topdir/configure "$@"
fi

