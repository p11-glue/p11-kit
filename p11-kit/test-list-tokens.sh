#!/bin/sh

# Test public key export from mock-twelve.so (mock-module-ep10.c).

test "${abs_top_builddir+set}" = set || {
	echo "set abs_top_builddir" 1>&2
	exit 1
}

. "$abs_top_builddir/common/test-init.sh"

setup() {
	testdir=$PWD/test-objects-$$
	test -d "$testdir" || mkdir "$testdir"
	cd "$testdir"
}

teardown() {
	rm -rf "$testdir"
}

test_list_tokens_without_uri() {
	cat > list.exp <<EOF
usage: p11-kit list-tokens [--only-uris] pkcs11:token

  -v, --verbose       show verbose debug output
  -q, --quiet         suppress command output
  --only-uris         only print token URIs
  --provider=<...>    specify the module to use
EOF
	if "$abs_top_builddir"/p11-kit/p11-kit-testable list-tokens -q 2>&1 > list.out; then
		assert_fail "p11-kit list-tokens succeeded without token URI"
	fi

	: ${DIFF=diff}
	if ! ${DIFF} list.exp list.out > list.diff; then
		sed 's/^/# /' list.diff
		assert_fail "output contains incorrect result"
	fi
}

test_list_tokens() {
	cat > list.exp <<EOF
token: PUBKEY LABEL
    uri: pkcs11:model=PUBKEY%20MODEL;manufacturer=PUBKEY%20MANUFACTURER;serial=PUBKEY%20SERIAL;token=PUBKEY%20LABEL
    manufacturer: PUBKEY MANUFACTURER
    model: PUBKEY MODEL
    serial-number: PUBKEY SERIAL
    hardware-version: 75.175
    firmware-version: 85.185
    flags:
          login-required
          user-pin-initialized
          clock-on-token
          token-initialized
EOF
	if ! "$abs_top_builddir"/p11-kit/p11-kit-testable list-tokens -q "pkcs11:model=PUBKEY%20MODEL" > list.out; then
		assert_fail "unable to run: p11-kit list-tokens"
	fi

	: ${DIFF=diff}
	if ! ${DIFF} list.exp list.out > list.diff; then
		sed 's/^/# /' list.diff
		assert_fail "output contains incorrect result"
	fi
}

test_list_tokens_only_uris() {
	cat > list.exp <<EOF
pkcs11:model=PUBKEY%20MODEL;manufacturer=PUBKEY%20MANUFACTURER;serial=PUBKEY%20SERIAL;token=PUBKEY%20LABEL
EOF
	if ! "$abs_top_builddir"/p11-kit/p11-kit-testable list-tokens -q --only-uris "pkcs11:model=PUBKEY%20MODEL" > list.out; then
		assert_fail "unable to run: p11-kit list-tokens --only-uris"
	fi

	: ${DIFF=diff}
	if ! ${DIFF} list.exp list.out > list.diff; then
		sed 's/^/# /' list.diff
		assert_fail "output contains incorrect result"
	fi
}

test_list_tokens_provider() {
	cat > list.exp <<EOF
token: TEST LABEL
    uri: pkcs11:model=TEST%20MODEL;manufacturer=TEST%20MANUFACTURER;serial=TEST%20SERIAL;token=TEST%20LABEL
    manufacturer: TEST MANUFACTURER
    model: TEST MODEL
    serial-number: TEST SERIAL
    hardware-version: 75.175
    firmware-version: 85.185
    flags:
          login-required
          user-pin-initialized
          clock-on-token
          token-initialized
EOF
	if ! "$abs_top_builddir"/p11-kit/p11-kit-testable list-tokens -q --provider "$P11_MODULE_PATH"/mock-one.so "pkcs11:" > list.out; then
		assert_fail "unable to run: p11-kit list-tokens --provider"
	fi

	: ${DIFF=diff}
	if ! ${DIFF} list.exp list.out > list.diff; then
		sed 's/^/# /' list.diff
		assert_fail "output contains incorrect result"
	fi
}

run test_list_tokens_without_uri test_list_tokens test_list_tokens_only_uris test_list_tokens_provider
