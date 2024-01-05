#!/bin/sh

test "${abs_top_builddir+set}" = set || {
	echo "set abs_top_builddir" 1>&2
	exit 1
}

test "${abs_top_srcdir+set}" = set || {
	echo "set abs_top_srcdir" 1>&2
	exit 1
}

. "$abs_top_builddir/common/test-init.sh"

setup() {
	testdir=$PWD/test-import-$$
	test -d "$testdir" || mkdir "$testdir"
	cd "$testdir"
}

teardown() {
	rm -rf "$testdir"
}

test_import_cert() {
	if ! "$abs_top_builddir"/p11-kit/p11-kit-testable import-object -q --login --file="$abs_top_srcdir"/trust/fixtures/cacert3.pem --label=cert --id="1a:bc:f6:9a" "pkcs11:token=PERSIST%20LABEL%20ONE?pin-value=booo"; then
		assert_fail "unable to run: p11-kit import-object"
	fi

	if ! "$abs_top_builddir"/p11-kit/p11-kit-testable export-object -q --login "pkcs11:token=PERSIST%20LABEL%20ONE;object=cert;id=%1A%BC%F6%9A?pin-value=booo" > export.out; then
		assert_fail "unable to run: p11-kit export-object"
	fi

	: ${DIFF=diff}
	if ! ${DIFF} "$abs_top_srcdir"/trust/fixtures/cacert3.pem export.out > export.diff; then
		sed 's/^/# /' export.diff
		assert_fail "output contains incorrect result"
	fi
}

test_import_pubkey_rsa() {
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

	if ! "$abs_top_builddir"/p11-kit/p11-kit-testable import-object -q --login --file="export.exp" --label=rsa --id="2a:bc:f6:9a" "pkcs11:token=PERSIST%20LABEL%20ONE?pin-value=booo"; then
		assert_fail "unable to run: p11-kit import-object"
	fi

	if ! "$abs_top_builddir"/p11-kit/p11-kit-testable export-object -q --login "pkcs11:token=PERSIST%20LABEL%20ONE;object=rsa;id=%2A%BC%F6%9A?pin-value=booo" > export.out; then
		assert_fail "unable to run: p11-kit export-object"
	fi

	: ${DIFF=diff}
	if ! ${DIFF} export.exp export.out > export.diff; then
		sed 's/^/# /' export.diff
		assert_fail "output contains incorrect result"
	fi
}

test_import_pubkey_ec() {
	# Generated and extracted with:
	# p11-kit generate-keypair --type=ecdsa --curve=secp256r1 --label=EC 'pkcs11:model=SoftHSM%20v2'
	# p11tool --export 'pkcs11:model=SoftHSM%20v2;object=EC;type=public'
	cat > export.exp <<EOF
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEsaTJt0debXaW7Hpcrpn7X07SsTk9
6OKFal97R2f9wetmK/EVyZIjCsth4tvkVtvyVsawBF0A2iI7N+uZdiPshw==
-----END PUBLIC KEY-----
EOF

	if ! "$abs_top_builddir"/p11-kit/p11-kit-testable import-object -q --login --file="export.exp" --label=ec --id="3a:bc:f6:9a" "pkcs11:token=PERSIST%20LABEL%20ONE?pin-value=booo"; then
		assert_fail "unable to run: p11-kit import-object"
	fi

	if ! "$abs_top_builddir"/p11-kit/p11-kit-testable export-object -q --login "pkcs11:token=PERSIST%20LABEL%20ONE;object=ec;id=%3A%BC%F6%9A?pin-value=booo" > export.out; then
		assert_fail "unable to run: p11-kit export-object"
	fi

	: ${DIFF=diff}
	if ! ${DIFF} export.exp export.out > export.diff; then
		sed 's/^/# /' export.diff
		assert_fail "output contains incorrect result"
	fi
}

run test_import_cert test_import_pubkey_rsa test_import_pubkey_ec
