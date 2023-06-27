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

export XDG_RUNTIME_DIR="$testdir"
export P11_KIT_PRIVATEDIR="${abs_top_builddir}/p11-kit"
export ASAN_OPTIONS="verify_asan_link_order=0"

echo 1..5

"$abs_top_builddir"/p11-kit/p11-kit-server-testable -s --provider "$P11_MODULE_PATH"/mock-one.so pkcs11: > start.env 2> start.err
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
	pkill -f p11-kit-server
	echo "not ok 2 /server/start-env"
	exit 1
fi

if p11tool --version > /dev/null; then
	p11tool --provider "$P11_MODULE_PATH"/p11-kit-client.so --list-tokens > /dev/null 2> p11tool.err
	if test $? -eq 0; then
		echo "ok 3 /server/client-access"
	else
		pkill -f p11-kit-server
		echo "not ok 3 /server/client-access"
		sed 's/^/# /' p11tool.err
		exit 1
	fi
else
	echo "ok 3 /server/client-access"
	echo "cannot find p11tool" >&2
fi

"$abs_top_builddir"/p11-kit/p11-kit-server-testable -s -k > stop.env 2> stop.err
if test $? -eq 0; then
	echo "ok 4 /server/stop"
else
	pkill -f p11-kit-server
	echo "not ok 4 /server/stop"
	sed 's/^/# /' stop.err
	exit 1
fi

. ./stop.env

if test "${P11_KIT_SERVER_ADDRESS-unset}" = "unset" && test "${P11_KIT_SERVER_PID-unset}" = "unset"; then
	echo "ok 5 /server/stop-env"
else
	echo "not ok 5 /server/stop-env"
	exit 1
fi
