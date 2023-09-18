#!/bin/sh

test "${abs_top_builddir+set}" = set || {
	echo "set abs_top_builddir" 1>&2
	exit 1
}

. "$abs_top_builddir/common/test-init.sh"

setup() {
	testdir=$PWD/test-profiles-$$
	test -d "$testdir" || mkdir "$testdir"
	cd "$testdir"
}

teardown() {
	rm -rf "$testdir"
}

test_list_profiles() {
	cat > list.exp <<EOF
public-certificates-token
EOF

	if ! "$abs_top_builddir"/p11-kit/p11-kit-testable list-profiles -q pkcs11: > list.out; then
		assert_fail "unable to run: p11-kit list-profiles"
	fi

	: ${DIFF=diff}
	if ! ${DIFF} list.exp list.out > list.diff; then
		sed 's/^/# /' list.diff
		assert_fail "output contains wrong results"
	fi
}

run test_list_profiles
