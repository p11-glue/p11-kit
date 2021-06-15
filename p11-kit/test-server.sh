#!/bin/sh

set -e

: ${P11_MODULE_PATH="$abs_top_builddir"/.libs}

testdir=`mktemp -d -t test-server.XXXXXX`
if test $? -ne 0; then
	echo "cannot create temporary directory" >&2
	exit 77
fi

cleanup () {
	rm -rf "$testdir"
}
trap cleanup 0

cd "$testdir"

unset P11_KIT_SERVER_ADDRESS
unset P11_KIT_SERVER_PID

XDG_RUNTIME_DIR="$testdir"
export XDG_RUNTIME_DIR

echo 1..4

"$abs_top_builddir"/p11-kit/p11-kit-server -s --provider "$P11_MODULE_PATH"/mock-one.so pkcs11: > start.env 2> start.err
if test $? -eq 0; then
	echo "ok 1 /server/start"
else
	echo "not ok 1 /server/start"
	sed 's/^/# /' start.err
	exit 1
fi

. ./start.env

if test "${P11_KIT_SERVER_ADDRESS+set}" = "set" && test "${P11_KIT_SERVER_PID+set}" = "set"; then
	echo "ok 2 /server/start-env"
else
	echo "not ok 2 /server/start-env"
	exit 1
fi

"$abs_top_builddir"/p11-kit/p11-kit-server -s -k > stop.env 2> stop.err
if test $? -eq 0; then
	echo "ok 3 /server/stop"
else
	echo "not ok 3 /server/stop"
	sed 's/^/# /' stop.err
	exit 1
fi

. ./stop.env

if test "${P11_KIT_SERVER_ADDRESS-unset}" = "unset" && test "${P11_KIT_SERVER_PID-unset}" = "unset"; then
	echo "ok 4 /server/stop-env"
else
	echo "not ok 4 /server/stop-env"
	exit 1
fi
