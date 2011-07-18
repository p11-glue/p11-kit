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

# Copied from avahi's autogen.sh to work around gettext braindamage
rm -f Makefile.am~ configure.ac~
# Evil, evil, evil, evil hack
sed 's/read dummy/\#/' `which gettextize` | sh -s -- --copy --force --no-changelog
test -f Makefile.am~ && mv Makefile.am~ Makefile.am
test -f configure.ac~ && mv configure.ac~ configure.ac

autoreconf --force --install --verbose
if test x"$NOCONFIGURE" = x; then
  exec ./configure "$@"
fi

