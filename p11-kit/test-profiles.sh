#!/bin/sh

set -e

testdir=$PWD/test-profiles-$$
test -d "$testdir" || mkdir "$testdir"

cleanup () {
	rm -rf "$testdir"
}
trap cleanup 0

cd "$testdir"

cat > list.exp <<EOF
public-certificates-token
EOF

"$abs_top_builddir"/p11-kit/p11-kit-testable list-profiles -q pkcs11: > list.out

echo 1..1

: ${DIFF=diff}
if ${DIFF} list.exp list.out > list.diff; then
	echo "ok 1 /profiles/list"
else
	echo "not ok 1 /profiles/list"
	sed 's/^/# /' list.diff
	exit 1
fi
