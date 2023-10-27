#!/bin/sh

test "${abs_top_builddir+set}" = set || {
	echo "set abs_top_builddir" 1>&2
	exit 1
}

. "$abs_top_builddir/common/test-init.sh"

: ${P11_MODULE_PATH="$abs_top_builddir"/.libs}

setup() {
	testdir=$PWD/test-genkey-$$
	test -d "$testdir" || mkdir "$testdir"
	cd "$testdir"
}

teardown() {
	rm -rf "$testdir"
}

test_generate_keypair_mock() {
	if ! "$abs_top_builddir"/p11-kit/p11-kit-testable generate-keypair --login --label=mock --type=mock "pkcs11:token=PUBKEY%20LABEL?pin-value=booo"; then
		assert_fail "unable to run p11-kit generate-keypair"
	fi
}

test_generate_keypair_rsa() {
	if "$abs_top_builddir"/p11-kit/p11-kit-testable generate-keypair --login --label=rsa --type=rsa --bits=2048 "pkcs11:token=PUBKEY%20LABEL?pin-value=booo" 2> err.out; then
		assert_fail "expected to fail: p11-kit generate-keypair"
	fi
	assert_contains err.out "key-pair generation failed: The crypto mechanism is invalid or unrecognized"

	if "$abs_top_builddir"/p11-kit/p11-kit-testable generate-keypair --login --label=rsa --type=rsa "pkcs11:token=PUBKEY%20LABEL?pin-value=booo" 2> err.out; then
		assert_fail "expected to fail: p11-kit generate-keypair"
	fi
	assert_contains err.out "no bits specified"
}

test_generate_keypair_ecdsa() {
	for curve in secp256r1 secp384r1 secp521r1; do
		if "$abs_top_builddir"/p11-kit/p11-kit-testable generate-keypair --login --label="ecdsa-$curve" --type=ecdsa --curve="$curve" "pkcs11:token=PUBKEY%20LABEL?pin-value=booo" 2> err.out; then
			assert_fail "expected to fail: p11-kit generate-keypair"
		fi
	done
	assert_contains err.out "key-pair generation failed: The crypto mechanism is invalid or unrecognized"

	if "$abs_top_builddir"/p11-kit/p11-kit-testable generate-keypair --login --label="ecdsa-unknown" --type=ecdsa --curve=unknown "pkcs11:token=PUBKEY%20LABEL?pin-value=booo" 2> err.out; then
		assert_fail "p11-kit generate-keypair succeeded for unknown ecdsa curve"
	fi
	assert_contains err.out "unknown curve name: unknown"
}

test_generate_keypair_eddsa() {
	for curve in ed25519 ed448; do
		if "$abs_top_builddir"/p11-kit/p11-kit-testable generate-keypair --login --label="eddsa-$curve" --type=eddsa --curve="$curve" "pkcs11:token=PUBKEY%20LABEL?pin-value=booo" 2> err.out; then
			assert_fail "unable to run: p11-kit generate-keypair"
		fi
	done
	assert_contains err.out "key-pair generation failed: The crypto mechanism is invalid or unrecognized"

	if "$abs_top_builddir"/p11-kit/p11-kit-testable generate-keypair --login --label="eddsa-unknown" --type=eddsa --curve=unknown "pkcs11:token=PUBKEY%20LABEL?pin-value=booo"; then
		assert_fail "p11-kit generate-keypair succeeded for unknown eddsa curve"
	fi
	assert_contains err.out "unknown curve name: unknown"
}

run test_generate_keypair_mock test_generate_keypair_rsa \
    test_generate_keypair_ecdsa test_generate_keypair_ecdsa
