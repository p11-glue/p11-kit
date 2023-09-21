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

test_export_public_rsa() {
	# Generated and extracted with:
	# p11-kit generate-keypair --type=rsa --bits=2048 --label=RSA 'pkcs11:model=SoftHSM%20v2'
	# p11tool --export 'pkcs11:model=SoftHSM%20v2;object=RSA;type=public'
	cat > export.exp <<EOF
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwK4hLgsRxltV0MudYWt2
yZYWgjHh1B2G5EuJDRvjkYIGiFl6nDk9akWxawgJoVmnZg3Y0a4ogk0H8++WXOZj
bVL1vYq9fxQm2KMNZPX0TM/efh0P8YM8lAyxiiCnCwGkffbUFqOa++4T/30FRfeX
D1YaNYH1ZPf2CKSlm6uUIyqFOakxLcaTVj6oXif4NWtg6Edu6I1rES1sBMnsKQQE
lLXoKLJovpzZgIeJfaxXhnQxfWFH4Ye0BAF4YtzoDXXnSfKVioiwNS06i6ZH9Ztd
P20Te0/BDjxPMmTwml/j5NW/nM0N4tldl2HxbwgEkq+m4aVFYGrp0KOihgC5kDGO
fQIDAQAB
-----END PUBLIC KEY-----
EOF
	if ! "$abs_top_builddir"/p11-kit/p11-kit-testable export-object -q "pkcs11:model=PUBKEY%20MODEL;object=RSA;type=public" > export.out; then
		assert_fail "unable to run: p11-kit export-object"
	fi

	: ${DIFF=diff}
	if ! ${DIFF} export.exp export.out > export.diff; then
		sed 's/^/# /' export.diff
		assert_fail "output contains incorrect result"
	fi
}

test_export_public_ec() {
	# Generated and extracted with:
	# p11-kit generate-keypair --type=ecdsa --curve=secp256r1 --label=EC 'pkcs11:model=SoftHSM%20v2'
	# p11tool --export 'pkcs11:model=SoftHSM%20v2;object=EC;type=public'
	cat > export.exp <<EOF
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEsaTJt0debXaW7Hpcrpn7X07SsTk9
6OKFal97R2f9wetmK/EVyZIjCsth4tvkVtvyVsawBF0A2iI7N+uZdiPshw==
-----END PUBLIC KEY-----
EOF
	if ! "$abs_top_builddir"/p11-kit/p11-kit-testable export-object -q "pkcs11:model=PUBKEY%20MODEL;object=EC;type=public" > export.out; then
		assert_fail "unable to run: p11-kit export-object"
	fi

	: ${DIFF=diff}
	if ! ${DIFF} export.exp export.out > export.diff; then
		sed 's/^/# /' export.diff
		assert_fail "output contains incorrect result"
	fi
}

test_export_public_spki() {
	# Generated and extracted with:
	# p11-kit generate-keypair --type=ecdsa --curve=secp256r1 --label=EC 'pkcs11:model=SoftHSM%20v2'
	# p11tool --export 'pkcs11:model=SoftHSM%20v2;object=EC;type=public'
	cat > export.exp <<EOF
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEsaTJt0debXaW7Hpcrpn7X07SsTk9
6OKFal97R2f9wetmK/EVyZIjCsth4tvkVtvyVsawBF0A2iI7N+uZdiPshw==
-----END PUBLIC KEY-----
EOF
	if ! "$abs_top_builddir"/p11-kit/p11-kit-testable export-object -q "pkcs11:model=PUBKEY%20MODEL;object=SPKI;type=public" > export.out; then
		assert_fail "unable to run: p11-kit export-object"
	fi

	: ${DIFF=diff}
	if ! ${DIFF} export.exp export.out > export.diff; then
		sed 's/^/# /' export.diff
		assert_fail "output contains incorrect result"
	fi
}

run test_export_public_rsa test_export_public_ec test_export_public_spki
