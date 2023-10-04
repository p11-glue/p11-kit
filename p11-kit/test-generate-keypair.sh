#!/bin/sh

test "${abs_top_builddir+set}" = set || {
	echo "set abs_top_builddir" 1>&2
	exit 1
}

. "$abs_top_builddir/common/test-init.sh"

: ${P11_MODULE_PATH="$abs_top_builddir"/.libs}

setup() {
	testdir=$PWD/test-objects-$$
	test -d "$testdir" || mkdir "$testdir"
	cd "$testdir"
	mkdir tokens
	cat > softhsm2.conf <<EOF
directories.tokendir = $PWD/tokens/
EOF
	export SOFTHSM2_CONF=$PWD/softhsm2.conf

	: ${SOFTHSM2_UTIL=softhsm2-util}
	if ! "$SOFTHSM2_UTIL" --version >/dev/null; then
		skip "softhsm2-util not found"
		return
	fi
	softhsm2-util --init-token --free --label test-genkey --so-pin 12345 --pin 12345

	: ${PKG_CONFIG=pkg-config}
	if ! "$PKG_CONFIG" p11-kit-1 --exists; then
		skip "pkgconfig(p11-kit-1) not found"
		return
	fi

	module_path=$("$PKG_CONFIG" p11-kit-1 --variable=p11_module_path)
	if ! test -e "$module_path/libsofthsm2.so"; then
		skip "unable to resolve libsofthsm2.so"
		return
	fi

	ln -sf "$module_path"/libsofthsm2.so "$P11_MODULE_PATH"
}

teardown() {
	unset SOFTHSM2_CONF
	rm -rf "$testdir"
}

test_generate_keypair_rsa() {
	if ! "$abs_top_builddir"/p11-kit/p11-kit-testable generate-keypair --label=rsa --type=rsa --bits=2048 "pkcs11:token=test-genkey?pin-value=12345"; then
		assert_fail "unable to run: p11-kit generate-keypair"
	fi
}

test_generate_keypair_ecdsa() {
	for curve in secp256r1 secp384r1 secp521r1; do
		if ! "$abs_top_builddir"/p11-kit/p11-kit-testable generate-keypair --label="ecdsa-$curve" --type=ecdsa --curve="$curve" "pkcs11:token=test-genkey?pin-value=12345"; then
			assert_fail "unable to run: p11-kit generate-keypair"
		fi
	done

	if "$abs_top_builddir"/p11-kit/p11-kit-testable generate-keypair --label="ecdsa-unknown" --type=ecdsa --curve=unknown "pkcs11:token=test-genkey?pin-value=12345"; then
		assert_fail "p11-kit generate-keypair succeeded for unknown ecdsa curve"
	fi
}

test_generate_keypair_eddsa() {
	curves=
	mech=$("$abs_top_builddir"/p11-kit/p11-kit-testable list-mechanisms "pkcs11:token=test-genkey" | sed -n '/CKM_EDDSA/p')
	if test -z "$mech"; then
		skip "no support for EdDSA"
		return
	fi
	if expr "$mech" : ".*key-size=256-" > /dev/null; then
		curve="$curve ed25519"
	fi
	if expr "$mech" : ".*key-size=.*-456" > /dev/null; then
		curve="$curve ed448"
	fi
	for curve in $curves; do
		if ! "$abs_top_builddir"/p11-kit/p11-kit-testable generate-keypair --label="eddsa-$curve" --type=eddsa --curve="$curve" "pkcs11:token=test-genkey?pin-value=12345"; then
			assert_fail "unable to run: p11-kit generate-keypair"
		fi
	done

	if "$abs_top_builddir"/p11-kit/p11-kit-testable generate-keypair --label="eddsa-unknown" --type=eddsa --curve=unknown "pkcs11:token=test-genkey?pin-value=12345"; then
		assert_fail "p11-kit generate-keypair succeeded for unknown eddsa curve"
	fi
}

run test_generate_keypair_rsa test_generate_keypair_ecdsa \
    test_generate_keypair_ecdsa
