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

test_add_profile_nonexistent_token() {
	cat > list.exp <<EOF
EOF

	if "$abs_top_builddir"/p11-kit/p11-kit-testable add-profile --profile=baseline-provider "pkcs11:token=NONEXISTENT" > list.out 2> err.out; then
		assert_fail "expected to fail: p11-kit add-profile"
	fi

	: ${DIFF=diff}
	if ! ${DIFF} list.exp list.out > list.diff; then
		sed 's/^/# /' list.diff
		assert_fail "output contains wrong results"
	fi
	assert_contains err.out "no matching token"
}

run test_list_profiles \
    test_add_profile_nonexistent_token
