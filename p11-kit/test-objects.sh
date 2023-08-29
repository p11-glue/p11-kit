#!/bin/sh

set -e

testdir=$PWD/test-objects-$$
test -d "$testdir" || mkdir "$testdir"

cleanup () {
	rm -rf "$testdir"
}
trap cleanup 0

cd "$testdir"

cat > list.exp <<EOF
Object: #0
    uri: pkcs11:model=TEST%20MODEL;manufacturer=TEST%20MANUFACTURER;serial=TEST%20SERIAL;token=TEST%20LABEL;object=TEST%20LABEL;type=data
    class: data
    label: TEST LABEL
Object: #1
    uri: pkcs11:model=TEST%20MODEL;manufacturer=TEST%20MANUFACTURER;serial=TEST%20SERIAL;token=TEST%20LABEL;object=Public%20Capitalize%20Key;type=public
    class: public-key
    label: Public Capitalize Key
    private: false
Object: #2
    uri: pkcs11:model=TEST%20MODEL;manufacturer=TEST%20MANUFACTURER;serial=TEST%20SERIAL;token=TEST%20LABEL;object=Public%20prefix%20key;type=public
    class: public-key
    label: Public prefix key
    private: false
Object: #3
    uri: pkcs11:model=TEST%20MODEL;manufacturer=TEST%20MANUFACTURER;serial=TEST%20SERIAL;token=TEST%20LABEL;object=TEST%20LABEL;type=data
    class: data
    label: TEST LABEL
Object: #4
    uri: pkcs11:model=TEST%20MODEL;manufacturer=TEST%20MANUFACTURER;serial=TEST%20SERIAL;token=TEST%20LABEL;object=Public%20Capitalize%20Key;type=public
    class: public-key
    label: Public Capitalize Key
    private: false
Object: #5
    uri: pkcs11:model=TEST%20MODEL;manufacturer=TEST%20MANUFACTURER;serial=TEST%20SERIAL;token=TEST%20LABEL;object=Public%20prefix%20key;type=public
    class: public-key
    label: Public prefix key
    private: false
Object: #6
    class: profile
    profile-id: public-certificates-token
Object: #7
    uri: pkcs11:model=TEST%20MODEL;manufacturer=TEST%20MANUFACTURER;serial=TEST%20SERIAL;token=TEST%20LABEL;object=TEST%20LABEL;type=data
    class: data
    label: TEST LABEL
Object: #8
    uri: pkcs11:model=TEST%20MODEL;manufacturer=TEST%20MANUFACTURER;serial=TEST%20SERIAL;token=TEST%20LABEL;object=Public%20Capitalize%20Key;type=public
    class: public-key
    label: Public Capitalize Key
    private: false
Object: #9
    uri: pkcs11:model=TEST%20MODEL;manufacturer=TEST%20MANUFACTURER;serial=TEST%20SERIAL;token=TEST%20LABEL;object=Public%20prefix%20key;type=public
    class: public-key
    label: Public prefix key
    private: false
Object: #10
    uri: pkcs11:model=TEST%20MODEL;manufacturer=TEST%20MANUFACTURER;serial=TEST%20SERIAL;token=TEST%20LABEL;object=TEST%20LABEL;type=data
    class: data
    label: TEST LABEL
Object: #11
    uri: pkcs11:model=TEST%20MODEL;manufacturer=TEST%20MANUFACTURER;serial=TEST%20SERIAL;token=TEST%20LABEL;object=Public%20Capitalize%20Key;type=public
    class: public-key
    label: Public Capitalize Key
    private: false
Object: #12
    uri: pkcs11:model=TEST%20MODEL;manufacturer=TEST%20MANUFACTURER;serial=TEST%20SERIAL;token=TEST%20LABEL;object=Public%20prefix%20key;type=public
    class: public-key
    label: Public prefix key
    private: false
EOF

"$abs_top_builddir"/p11-kit/p11-kit-testable list-objects -q "pkcs11:" > list.out

echo 1..4

: ${DIFF=diff}
if ${DIFF} list.exp list.out > list.diff; then
	echo "ok 1 /objects/list-objects-all"
else
	echo "not ok 1 /objects/list-objects-all"
	sed 's/^/# /' list.diff
	exit 1
fi

cat > list.exp <<EOF
Object: #0
    uri: pkcs11:model=TEST%20MODEL;manufacturer=TEST%20MANUFACTURER;serial=TEST%20SERIAL;token=TEST%20LABEL;object=TEST%20LABEL;type=data
    class: data
    label: TEST LABEL
Object: #1
    uri: pkcs11:model=TEST%20MODEL;manufacturer=TEST%20MANUFACTURER;serial=TEST%20SERIAL;token=TEST%20LABEL;object=TEST%20LABEL;type=data
    class: data
    label: TEST LABEL
Object: #2
    uri: pkcs11:model=TEST%20MODEL;manufacturer=TEST%20MANUFACTURER;serial=TEST%20SERIAL;token=TEST%20LABEL;object=TEST%20LABEL;type=data
    class: data
    label: TEST LABEL
Object: #3
    uri: pkcs11:model=TEST%20MODEL;manufacturer=TEST%20MANUFACTURER;serial=TEST%20SERIAL;token=TEST%20LABEL;object=TEST%20LABEL;type=data
    class: data
    label: TEST LABEL
EOF

"$abs_top_builddir"/p11-kit/p11-kit-testable list-objects -q "pkcs11:model=TEST%20MODEL;manufacturer=TEST%20MANUFACTURER;serial=TEST%20SERIAL;token=TEST%20LABEL;object=TEST%20LABEL;type=data" > list.out

echo 2..4

: ${DIFF=diff}
if ${DIFF} list.exp list.out > list.diff; then
	echo "ok 2 /objects/list-objects-specific"
else
	echo "not ok 2 /objects/list-objects-specific"
	sed 's/^/# /' list.diff
	exit 1
fi

"$abs_top_builddir"/p11-kit/p11-kit-testable list-objects -q "pkcs11:type=data" > list.out

echo 3..4

: ${DIFF=diff}
if ${DIFF} list.exp list.out > list.diff; then
	echo "ok 3 /objects/list-objects-data"
else
	echo "not ok 3 /objects/list-objects-data"
	sed 's/^/# /' list.diff
	exit 1
fi

cat > list.exp <<EOF
EOF

"$abs_top_builddir"/p11-kit/p11-kit-testable list-objects -q "pkcs11:model=NONEXISTENT" > list.out

echo 4..4

: ${DIFF=diff}
if ${DIFF} list.exp list.out > list.diff; then
	echo "ok 4 /objects/list-objects-nonexistent"
else
	echo "not ok 4 /objects/list-objects-nonexistent"
	sed 's/^/# /' list.diff
	exit 1
fi
