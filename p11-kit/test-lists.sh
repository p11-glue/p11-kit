#!/bin/sh

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

test_list_modules() {
	cat > list.exp <<EOF
module: four
    uri: pkcs11:library-description=MOCK%20LIBRARY;library-manufacturer=MOCK%20MANUFACTURER
    library-description: MOCK LIBRARY
    library-manufacturer: MOCK MANUFACTURER
    library-version: 45.145
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
module: eleven
    uri: pkcs11:library-description=MOCK%20LIBRARY;library-manufacturer=MOCK%20MANUFACTURER
    library-description: MOCK LIBRARY
    library-manufacturer: MOCK MANUFACTURER
    library-version: 45.145
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
module: one
    uri: pkcs11:library-description=MOCK%20LIBRARY;library-manufacturer=MOCK%20MANUFACTURER
    library-description: MOCK LIBRARY
    library-manufacturer: MOCK MANUFACTURER
    library-version: 45.145
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
module: twelve
    uri: pkcs11:library-description=MOCK%20LIBRARY;library-manufacturer=MOCK%20MANUFACTURER
    library-description: MOCK LIBRARY
    library-manufacturer: MOCK MANUFACTURER
    library-version: 45.145
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
module: two-duplicate
    uri: pkcs11:library-description=MOCK%20LIBRARY;library-manufacturer=MOCK%20MANUFACTURER
    library-description: MOCK LIBRARY
    library-manufacturer: MOCK MANUFACTURER
    library-version: 45.145
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

	# Since the path is absolute, it may contain user's current working
	# directory; strip it before taking a diff.
	if ! "$abs_top_builddir"/p11-kit/p11-kit-testable list-modules -q | sed '/^ *path: /d' > list.out; then
		assert_fail "unable to run: p11-kit list-modules"
	fi

	: ${DIFF=diff}
	if ! ${DIFF} list.exp list.out > list.diff; then
		sed 's/^/# /' list.diff
		assert_fail "output contains incorrect result"
	fi
}

run test_list_modules
