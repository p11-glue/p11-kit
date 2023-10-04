#!/bin/sh

test "${abs_top_builddir+set}" = set || {
	echo "set abs_top_builddir" 1>&2
	exit 1
}

. "$abs_top_builddir/common/test-init.sh"

: ${P11_MODULE_PATH="$abs_top_builddir"/.libs}

setup() {
	testdir=`mktemp -d -t test-server.XXXXXX`
	if test $? -ne 0; then
		echo "cannot create temporary directory" >&2
		exit 77
	fi
	cd "$testdir"

	unset P11_KIT_SERVER_ADDRESS
	unset P11_KIT_SERVER_PID

	export XDG_RUNTIME_DIR="$testdir"
	export P11_KIT_PRIVATEDIR="${abs_top_builddir}/p11-kit"
	export ASAN_OPTIONS="verify_asan_link_order=0"
}

teardown() {
	rm -rf "$testdir"
	if test "${P11_KIT_SERVER_PID+set}" = "set"; then
		kill "$P11_KIT_SERVER_PID"
	fi
}

test_server_access() {
	"$abs_top_builddir"/p11-kit/p11-kit-server-testable -s --provider "$P11_MODULE_PATH"/mock-one.so pkcs11: > start.env 2> start.err
	if test $? -ne 0; then
		sed 's/^/# /' start.err
		assert_fail "unable to start server"
	fi

	. ./start.env

	if test "${P11_KIT_SERVER_ADDRESS-unset}" = "unset"; then
		assert_fail "P11_KIT_SERVER_ADDRESS is not set"
	fi

	if test "${P11_KIT_SERVER_PID-unset}" = "unset"; then
		assert_fail "P11_KIT_SERVER_PID is not set"
	fi

	: ${P11TOOL=p11tool}
	if "$P11TOOL" --version > /dev/null; then
		"$P11TOOL" --provider "$P11_MODULE_PATH"/p11-kit-client.so --list-tokens > /dev/null 2> p11tool.err
		if test $? -ne 0; then
			sed 's/^/# /' p11tool.err
			assert_fail "unable to access server"
		fi
	else
		skip "p11tool not found"
		return
	fi

	"$abs_top_builddir"/p11-kit/p11-kit-server-testable -s -k > stop.env 2> stop.err
	if test $? -ne 0; then
		sed 's/^/# /' stop.err
		assert_fail "unable to stop server"
	fi

	. ./stop.env

	if test "${P11_KIT_SERVER_ADDRESS+set}" = "set"; then
		assert_fail "P11_KIT_SERVER_ADDRESS is still set"
	fi

	if test "${P11_KIT_SERVER_PID+set}" = "set"; then
		assert_fail "P11_KIT_SERVER_PID is still set"
	fi
}

run test_server_access
