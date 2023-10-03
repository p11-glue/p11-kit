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
	cat > test-profiles.p11-kit <<EOF
[p11-kit-object-v1]
class: profile
token: true
profile-id: baseline-provider

[p11-kit-object-v1]
class: profile
token: true
profile-id: extended-provider

[p11-kit-object-v1]
class: profile
token: true
profile-id: authentication-token

[p11-kit-object-v1]
class: profile
token: true
profile-id: public-certificates-token

[p11-kit-object-v1]
class: profile
token: true
profile-id: vendor-defined
EOF

	cat > list.exp <<EOF
baseline-provider
extended-provider
authentication-token
public-certificates-token
vendor-defined
EOF

	if ! "$abs_top_builddir"/p11-kit/p11-kit-testable list-profiles -q "pkcs11:token=PROFILE%20LABEL%20ONE" > list.out; then
		assert_fail "unable to run: p11-kit list-profiles"
	fi

	: ${DIFF=diff}
	if ! ${DIFF} list.exp list.out > list.diff; then
		sed 's/^/# /' list.diff
		assert_fail "output contains wrong results"
	fi
}

test_list_profiles_session() {
	cat > test-profiles.p11-kit <<EOF
[p11-kit-object-v1]
class: profile
token: false
profile-id: baseline-provider
EOF

	cat > list.exp <<EOF
baseline-provider
EOF

	if ! "$abs_top_builddir"/p11-kit/p11-kit-testable list-profiles -q "pkcs11:token=PROFILE%20LABEL%20ONE" > list.out; then
		assert_fail "unable to run: p11-kit list-profiles"
	fi

	: ${DIFF=diff}
	if ! ${DIFF} list.exp list.out > list.diff; then
		sed 's/^/# /' list.diff
		assert_fail "output contains wrong results"
	fi
}

test_list_profiles_empty() {
	cat > list.exp <<EOF
EOF

	if ! "$abs_top_builddir"/p11-kit/p11-kit-testable list-profiles -q "pkcs11:token=PROFILE%20LABEL%20ONE" > list.out; then
		assert_fail "unable to run: p11-kit list-profiles"
	fi

	: ${DIFF=diff}
	if ! ${DIFF} list.exp list.out > list.diff; then
		sed 's/^/# /' list.diff
		assert_fail "output contains wrong results"
	fi
}

test_list_profiles_nonexistent_token() {
	cat > list.exp <<EOF
EOF

	if "$abs_top_builddir"/p11-kit/p11-kit-testable list-profiles "pkcs11:token=NONEXISTENT" > list.out 2> err.out; then
		assert_fail "expected to fail: p11-kit list-profiles"
	fi

	: ${DIFF=diff}
	if ! ${DIFF} list.exp list.out > list.diff; then
		sed 's/^/# /' list.diff
		assert_fail "output contains wrong results"
	fi
	assert_contains err.out "no matching token"
}

test_add_profile() {
	cat > test-profiles.p11-kit <<EOF
[p11-kit-object-v1]
class: profile
token: true
profile-id: baseline-provider
EOF

	cat > list.exp <<EOF
[p11-kit-object-v1]
class: profile
profile-id: baseline-provider

[p11-kit-object-v1]
class: profile
profile-id: public-certificates-token

EOF

	if ! "$abs_top_builddir"/p11-kit/p11-kit-testable add-profile -q --profile="public-certificates-token" "pkcs11:token=PROFILE%20LABEL%20ONE"; then
		assert_fail "unable to run: p11-kit add-profile"
	fi

	: ${DIFF=diff}
	if ! ${DIFF} list.exp test-profiles.out.p11-kit > list.diff; then
		sed 's/^/# /' list.diff
		assert_fail "output contains wrong results"
	fi
}

test_add_profile_empty() {
	cat > list.exp <<EOF
[p11-kit-object-v1]
class: profile
profile-id: public-certificates-token

EOF

	if ! "$abs_top_builddir"/p11-kit/p11-kit-testable add-profile -q --profile="public-certificates-token" "pkcs11:token=PROFILE%20LABEL%20ONE"; then
		assert_fail "unable to run: p11-kit add-profile"
	fi

	: ${DIFF=diff}
	if ! ${DIFF} list.exp test-profiles.out.p11-kit > list.diff; then
		sed 's/^/# /' list.diff
		assert_fail "output contains wrong results"
	fi
}

test_add_profile_duplicate() {
	cat > test-profiles.p11-kit <<EOF
[p11-kit-object-v1]
class: profile
token: true
profile-id: extended-provider
EOF

	cat > list.exp <<EOF
[p11-kit-object-v1]
class: profile
profile-id: extended-provider

EOF

	if "$abs_top_builddir"/p11-kit/p11-kit-testable add-profile -q --profile="extended-provider" "pkcs11:token=PROFILE%20LABEL%20ONE"; then
		assert_fail "expected to fail: p11-kit add-profile"
	fi

	: ${DIFF=diff}
	if ! ${DIFF} list.exp test-profiles.out.p11-kit > list.diff; then
		sed 's/^/# /' list.diff
		assert_fail "output contains wrong results"
	fi
}

test_add_profile_session_duplicate() {
	cat > test-profiles.p11-kit <<EOF
[p11-kit-object-v1]
class: profile
token: false
profile-id: extended-provider
EOF

	cat > list.exp <<EOF
[p11-kit-object-v1]
class: profile
profile-id: extended-provider

[p11-kit-object-v1]
class: profile
profile-id: extended-provider

EOF

	if ! "$abs_top_builddir"/p11-kit/p11-kit-testable add-profile -q --profile="extended-provider" "pkcs11:token=PROFILE%20LABEL%20ONE"; then
		assert_fail "unable to run: p11-kit add-profile"
	fi

	: ${DIFF=diff}
	if ! ${DIFF} list.exp test-profiles.out.p11-kit > list.diff; then
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

test_add_profile_no_args() {
	cat > list.exp <<EOF
EOF

	if "$abs_top_builddir"/p11-kit/p11-kit-testable add-profile "pkcs11:token=pkcs11:token=PROFILE%20LABEL%20ONE" > list.out 2> err.out; then
		assert_fail "expected to fail: p11-kit add-profile"
	fi

	: ${DIFF=diff}
	if ! ${DIFF} list.exp list.out > list.diff; then
		sed 's/^/# /' list.diff
		assert_fail "output contains wrong results"
	fi
	assert_contains err.out "no profile specified"
}

test_add_profile_duplicate_args() {
	cat > list.exp <<EOF
EOF

	if "$abs_top_builddir"/p11-kit/p11-kit-testable add-profile --profile="baseline-provider" --profile="extended-provider" "pkcs11:token=pkcs11:token=PROFILE%20LABEL%20ONE" > list.out 2> err.out; then
		assert_fail "expected to fail: p11-kit add-profile"
	fi

	: ${DIFF=diff}
	if ! ${DIFF} list.exp list.out > list.diff; then
		sed 's/^/# /' list.diff
		assert_fail "output contains wrong results"
	fi
	assert_contains err.out "multiple profiles specified"
}

test_delete_profile() {
	cat > test-profiles.p11-kit <<EOF
[p11-kit-object-v1]
class: profile
token: true
profile-id: baseline-provider

[p11-kit-object-v1]
class: profile
token: true
profile-id: extended-provider
EOF

	cat > list.exp <<EOF
[p11-kit-object-v1]
class: profile
profile-id: extended-provider

EOF

	if ! "$abs_top_builddir"/p11-kit/p11-kit-testable delete-profile -q --profile="baseline-provider" "pkcs11:token=PROFILE%20LABEL%20ONE"; then
		assert_fail "unable to run: p11-kit delete-profile"
	fi

	: ${DIFF=diff}
	if ! ${DIFF} list.exp test-profiles.out.p11-kit > list.diff; then
		sed 's/^/# /' list.diff
		assert_fail "output contains wrong results"
	fi
}

test_delete_profile_last() {
	cat > test-profiles.p11-kit <<EOF
[p11-kit-object-v1]
class: profile
token: true
profile-id: extended-provider
EOF

	cat > list.exp <<EOF
EOF

	if ! "$abs_top_builddir"/p11-kit/p11-kit-testable delete-profile -q --profile="extended-provider" "pkcs11:token=PROFILE%20LABEL%20ONE"; then
		assert_fail "unable to run: p11-kit delete-profile"
	fi

	: ${DIFF=diff}
	if ! ${DIFF} list.exp test-profiles.out.p11-kit > list.diff; then
		sed 's/^/# /' list.diff
		assert_fail "output contains wrong results"
	fi
}

test_delete_profile_empty() {
	cat > list.exp <<EOF
EOF

	if ! "$abs_top_builddir"/p11-kit/p11-kit-testable delete-profile -q --profile="extended-provider" "pkcs11:token=PROFILE%20LABEL%20ONE"; then
		assert_fail "unable to run: p11-kit delete-profile"
	fi

	: ${DIFF=diff}
	if ! ${DIFF} list.exp test-profiles.out.p11-kit > list.diff; then
		sed 's/^/# /' list.diff
		assert_fail "output contains wrong results"
	fi
}

test_delete_profile_multiple() {
	cat > test-profiles.p11-kit <<EOF
[p11-kit-object-v1]
class: profile
token: true
profile-id: extended-provider

[p11-kit-object-v1]
class: profile
token: true
profile-id: extended-provider

[p11-kit-object-v1]
class: profile
token: true
profile-id: extended-provider

[p11-kit-object-v1]
class: profile
token: true
profile-id: baseline-provider

[p11-kit-object-v1]
class: profile
token: true
profile-id: extended-provider

[p11-kit-object-v1]
class: profile
token: true
profile-id: extended-provider

[p11-kit-object-v1]
class: profile
token: true
profile-id: extended-provider
EOF

	cat > list.exp <<EOF
[p11-kit-object-v1]
class: profile
profile-id: baseline-provider

EOF

	if ! "$abs_top_builddir"/p11-kit/p11-kit-testable delete-profile -q --profile="extended-provider" "pkcs11:token=PROFILE%20LABEL%20ONE"; then
		assert_fail "unable to run: p11-kit delete-profile"
	fi

	: ${DIFF=diff}
	if ! ${DIFF} list.exp test-profiles.out.p11-kit > list.diff; then
		sed 's/^/# /' list.diff
		assert_fail "output contains wrong results"
	fi
}

test_delete_profile_session() {
	cat > test-profiles.p11-kit <<EOF
[p11-kit-object-v1]
class: profile
token: false
profile-id: extended-provider
EOF

	cat > list.exp <<EOF
EOF

	if ! "$abs_top_builddir"/p11-kit/p11-kit-testable delete-profile -q --profile="extended-provider" "pkcs11:token=PROFILE%20LABEL%20ONE"; then
		assert_fail "unable to run: p11-kit delete-profile"
	fi

	: ${DIFF=diff}
	if ! ${DIFF} list.exp test-profiles.out.p11-kit > list.diff; then
		sed 's/^/# /' list.diff
		assert_fail "output contains wrong results"
	fi
}

test_delete_profile_nonexistent_token() {
	cat > list.exp <<EOF
EOF

	if "$abs_top_builddir"/p11-kit/p11-kit-testable delete-profile --profile="baseline-provider" "pkcs11:token=NONEXISTENT" > list.out 2> err.out; then
		assert_fail "expected to fail: p11-kit delete-profile"
	fi

	: ${DIFF=diff}
	if ! ${DIFF} list.exp list.out > list.diff; then
		sed 's/^/# /' list.diff
		assert_fail "output contains wrong results"
	fi
	assert_contains err.out "no matching token"
}

test_delete_profile_no_args() {
	cat > list.exp <<EOF
EOF

	if "$abs_top_builddir"/p11-kit/p11-kit-testable delete-profile "pkcs11:token=pkcs11:token=PROFILE%20LABEL%20ONE" > list.out 2> err.out; then
		assert_fail "expected to fail: p11-kit delete-profile"
	fi

	: ${DIFF=diff}
	if ! ${DIFF} list.exp list.out > list.diff; then
		sed 's/^/# /' list.diff
		assert_fail "output contains wrong results"
	fi
	assert_contains err.out "no profile specified"
}

test_delete_profile_duplicate_args() {
	cat > list.exp <<EOF
EOF

	if "$abs_top_builddir"/p11-kit/p11-kit-testable delete-profile --profile="baseline-provider" --profile="extended-provider" "pkcs11:token=pkcs11:token=PROFILE%20LABEL%20ONE" > list.out 2> err.out; then
		assert_fail "expected to fail: p11-kit delete-profile"
	fi

	: ${DIFF=diff}
	if ! ${DIFF} list.exp list.out > list.diff; then
		sed 's/^/# /' list.diff
		assert_fail "output contains wrong results"
	fi
	assert_contains err.out "multiple profiles specified"
}

run test_list_profiles \
    test_list_profiles_session \
    test_list_profiles_empty \
    test_list_profiles_nonexistent_token \
    test_add_profile \
    test_add_profile_empty \
    test_add_profile_duplicate \
    test_add_profile_session_duplicate \
    test_add_profile_nonexistent_token \
    test_add_profile_no_args \
    test_add_profile_duplicate_args \
    test_delete_profile \
    test_delete_profile_last \
    test_delete_profile_empty \
    test_delete_profile_multiple \
    test_delete_profile_session \
    test_delete_profile_nonexistent_token \
    test_delete_profile_no_args \
    test_delete_profile_duplicate_args
