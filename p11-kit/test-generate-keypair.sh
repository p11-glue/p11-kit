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

	if "$abs_top_builddir"/p11-kit/p11-kit-testable generate-keypair --login --label=rsa --type=rsa --bits=2048 --parameter-set=44 "pkcs11:token=PUBKEY%20LABEL?pin-value=booo" 2> err.out; then
		assert_fail "p11-kit generate-keypair succeeded with --parameter-set for RSA"
	fi
	assert_contains err.out "parameter-set cannot be used with this key type"
}

test_generate_keypair_ecdsa() {
	for curve in secp256r1 secp384r1 secp521r1; do
		if "$abs_top_builddir"/p11-kit/p11-kit-testable generate-keypair --login --label="ecdsa-$curve" --type=ecdsa --curve="$curve" "pkcs11:token=PUBKEY%20LABEL?pin-value=booo" 2> err.out; then
			assert_fail "expected to fail: p11-kit generate-keypair"
		fi
		assert_contains err.out "key-pair generation failed: The crypto mechanism is invalid or unrecognized"
	done

	if "$abs_top_builddir"/p11-kit/p11-kit-testable generate-keypair --login --label="ecdsa-unknown" --type=ecdsa --curve=unknown "pkcs11:token=PUBKEY%20LABEL?pin-value=booo" 2> err.out; then
		assert_fail "p11-kit generate-keypair succeeded for unknown ecdsa curve"
	fi
	assert_contains err.out "unknown curve name: unknown"
}

test_generate_keypair_eddsa() {
	for curve in ed25519 ed448; do
		if "$abs_top_builddir"/p11-kit/p11-kit-testable generate-keypair --login --label="eddsa-$curve" --type=eddsa --curve="$curve" "pkcs11:token=PUBKEY%20LABEL?pin-value=booo" 2> err.out; then
			assert_fail "expected to fail: p11-kit generate-keypair"
		fi
		assert_contains err.out "key-pair generation failed: The crypto mechanism is invalid or unrecognized"
	done

	if "$abs_top_builddir"/p11-kit/p11-kit-testable generate-keypair --login --label="eddsa-unknown" --type=eddsa --curve=unknown "pkcs11:token=PUBKEY%20LABEL?pin-value=booo" 2> err.out; then
		assert_fail "p11-kit generate-keypair succeeded for unknown eddsa curve"
	fi
	assert_contains err.out "unknown curve name: unknown"
}

test_generate_keypair_ml_dsa() {
	for ps in 44 65 87; do
		if ! "$abs_top_builddir"/p11-kit/p11-kit-testable generate-keypair --login --label="ml-dsa-$ps" --type=ml-dsa --parameter-set="$ps" "pkcs11:token=PUBKEY%20LABEL?pin-value=booo"; then
			assert_fail "unable to run: p11-kit generate-keypair (ML-DSA-$ps)"
		fi
	done

	if "$abs_top_builddir"/p11-kit/p11-kit-testable generate-keypair --login --label="ml-dsa-bad" --type=ml-dsa --parameter-set=unknown "pkcs11:token=PUBKEY%20LABEL?pin-value=booo" 2> err.out; then
		assert_fail "p11-kit generate-keypair succeeded for unknown ML-DSA parameter set"
	fi
	assert_contains err.out "unknown parameter-set: unknown"

	if "$abs_top_builddir"/p11-kit/p11-kit-testable generate-keypair --login --label="ml-dsa-nops" --type=ml-dsa "pkcs11:token=PUBKEY%20LABEL?pin-value=booo" 2> err.out; then
		assert_fail "p11-kit generate-keypair succeeded without parameter-set for ML-DSA"
	fi
	assert_contains err.out "no parameter-set specified"

	if "$abs_top_builddir"/p11-kit/p11-kit-testable generate-keypair --login --label="ml-dsa-bits" --type=ml-dsa --parameter-set=44 --bits=2048 "pkcs11:token=PUBKEY%20LABEL?pin-value=booo" 2> err.out; then
		assert_fail "p11-kit generate-keypair succeeded with --bits for ML-DSA"
	fi
	assert_contains err.out "bits cannot be used with this key type"

	if "$abs_top_builddir"/p11-kit/p11-kit-testable generate-keypair --login --label="ml-dsa-curve" --type=ml-dsa --parameter-set=44 --curve=secp256r1 "pkcs11:token=PUBKEY%20LABEL?pin-value=booo" 2> err.out; then
		assert_fail "p11-kit generate-keypair succeeded with --curve for ML-DSA"
	fi
	assert_contains err.out "curve cannot be used with this key type"
}

test_generate_keypair_ml_kem() {
	for ps in 512 768 1024; do
		if ! "$abs_top_builddir"/p11-kit/p11-kit-testable generate-keypair --login --label="ml-kem-$ps" --type=ml-kem --parameter-set="$ps" "pkcs11:token=PUBKEY%20LABEL?pin-value=booo"; then
			assert_fail "unable to run: p11-kit generate-keypair (ML-KEM-$ps)"
		fi
	done

	if "$abs_top_builddir"/p11-kit/p11-kit-testable generate-keypair --login --label="ml-kem-bad" --type=ml-kem --parameter-set=unknown "pkcs11:token=PUBKEY%20LABEL?pin-value=booo" 2> err.out; then
		assert_fail "p11-kit generate-keypair succeeded for unknown ML-KEM parameter set"
	fi
	assert_contains err.out "unknown parameter-set: unknown"
}

test_generate_keypair_slh_dsa() {
	for ps in sha2-128s sha2-128f sha2-192s sha2-192f sha2-256s sha2-256f \
	          shake-128s shake-128f shake-192s shake-192f shake-256s shake-256f; do
		if ! "$abs_top_builddir"/p11-kit/p11-kit-testable generate-keypair --login --label="slh-dsa-$ps" --type=slh-dsa --parameter-set="$ps" "pkcs11:token=PUBKEY%20LABEL?pin-value=booo"; then
			assert_fail "unable to run: p11-kit generate-keypair (SLH-DSA-$ps)"
		fi
	done

	if "$abs_top_builddir"/p11-kit/p11-kit-testable generate-keypair --login --label="slh-dsa-bad" --type=slh-dsa --parameter-set=unknown "pkcs11:token=PUBKEY%20LABEL?pin-value=booo" 2> err.out; then
		assert_fail "p11-kit generate-keypair succeeded for unknown SLH-DSA parameter set"
	fi
	assert_contains err.out "unknown parameter-set: unknown"
}

run test_generate_keypair_mock test_generate_keypair_rsa \
    test_generate_keypair_ecdsa test_generate_keypair_eddsa \
    test_generate_keypair_ml_dsa test_generate_keypair_ml_kem \
    test_generate_keypair_slh_dsa
