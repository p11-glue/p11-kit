#!/bin/sh

test "${abs_top_builddir+set}" = set || {
	echo "set abs_top_builddir" 1>&2
	exit 1
}

. "$abs_top_builddir/common/test-init.sh"

setup() {
	testdir=$PWD/test-mechanisms-$$
	test -d "$testdir" || mkdir "$testdir"
	cd "$testdir"
}

teardown() {
	rm -rf "$testdir"
}

test_list_mechanisms_multi() {  # pkcs11: matches only the first token
	cat > list.exp <<EOF
0x80000001 (unknown): encrypt decrypt key-size=512-4096
0x80000002 (unknown): sign verify key-size=2048-2048
EOF

	if ! "$abs_top_builddir"/p11-kit/p11-kit-testable list-mechanisms pkcs11: > list.out; then
		assert_fail "unable to run: p11-kit list-mechanisms"
	fi

	: ${DIFF=diff}
	if ! ${DIFF} list.exp list.out > list.diff; then
		sed 's/^/# /' list.diff
		assert_fail "output contains wrong results"
	fi
}

test_list_mechanisms_single() {  # specific existing token can be specified
	cat > list.exp <<EOF
0x80000001 (unknown): encrypt decrypt key-size=512-4096
0x80000002 (unknown): sign verify key-size=2048-2048
EOF

	if ! "$abs_top_builddir"/p11-kit/p11-kit-testable list-mechanisms pkcs11:token=PUBKEY%20LABEL > list.out; then
		assert_fail "unable to run: p11-kit list-mechanisms"
	fi

	: ${DIFF=diff}
	if ! ${DIFF} list.exp list.out > list.diff; then
		sed 's/^/# /' list.diff
		assert_fail "output contains wrong results"
	fi
}

test_list_mechanisms_nonex() {  # specific nonexisting token leads to a warning
	if "$abs_top_builddir"/p11-kit/p11-kit-testable list-mechanisms pkcs11:token=nonex 2> list.err; then
		assert_fail "p11-kit list-mechanisms returned 0 for nonexisting token"
	fi

	: ${GREP=grep}
	if ! ${GREP} -Fqx 'p11-kit: no matching token' list.err; then
		assert_fail "p11-kit list-mechanisms hasn't printed 'no matching token' error"
	fi
}

run test_list_mechanisms_multi test_list_mechanisms_single test_list_mechanisms_nonex
