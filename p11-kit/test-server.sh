#!/bin/sh

testdir=$PWD/test-server-$$
test -d "$testdir" || mkdir "$testdir"

cleanup () {
  rm -rf "$testdir"
}
trap cleanup 0

cd "$testdir"

unset P11_KIT_SERVER_ADDRESS
unset P11_KIT_SERVER_PID

XDG_RUNTIME_DIR="$testdir"
export XDG_RUNTIME_DIR

"$abs_top_builddir"/p11-kit-server -s --provider "$abs_top_builddir"/.libs/mock-one.so pkcs11: > start.env 2> start.err
if test $? -ne 0; then
    cat start.err
    exit 1
fi

. ./start.env

test "${P11_KIT_SERVER_ADDRESS+set}" == set || exit 1
test "${P11_KIT_SERVER_PID+set}" == set || exit 1

"$abs_top_builddir"/p11-kit-server -s -k > stop.env 2> stop.err
if test $? -ne 0; then
    cat stop.err
    exit 1
fi

. ./stop.env

test "${P11_KIT_SERVER_ADDRESS-unset}" == unset || exit 1
test "${P11_KIT_SERVER_PID-unset}" == unset || exit 1
