#!/bin/sh

test "${abs_top_builddir+set}" = set || {
	echo "set abs_top_builddir" 1>&2
	exit 1
}

. "$abs_top_builddir/common/test-init.sh"
. "$abs_top_srcdir/common/test-external-helpers.sh"

setup() {
	testdir=$PWD/test-kryoptic-$$
	test -d "$testdir" || mkdir "$testdir"
	cd "$testdir"

	# Find kryoptic module
	if test -z "${KRYOPTIC_MODULE-}"; then
		for path in \
			/usr/lib/pkcs11/libkryoptic_pkcs11.so \
			/usr/lib64/pkcs11/libkryoptic_pkcs11.so \
			/usr/lib/libkryoptic_pkcs11.so \
			/usr/lib64/libkryoptic_pkcs11.so; do
			if test -f "$path"; then
				KRYOPTIC_MODULE="$path"
				break
			fi
		done
	fi
	if test -z "${KRYOPTIC_MODULE-}" || ! test -f "$KRYOPTIC_MODULE"; then
		skip "kryoptic module not found"
		return
	fi

	: ${PKCS11_TOOL=pkcs11-tool}
	if ! command -v "$PKCS11_TOOL" >/dev/null 2>&1; then
		skip "pkcs11-tool not found"
		return
	fi

	cat > kryoptic.conf <<EOF
[[slots]]
slot = 0
dbtype = "sqlite"
dbargs = "$PWD/token-genkey.sql"

[[slots]]
slot = 1
dbtype = "sqlite"
dbargs = "$PWD/token-import.sql"
EOF
	export KRYOPTIC_CONF=$PWD/kryoptic.conf

	# Register kryoptic as a p11-kit module so p11-kit commands
	# can find it (needed when using a custom install prefix)
	mkdir -p p11-modules
	cat > p11-modules/kryoptic.module <<EOF
module: $KRYOPTIC_MODULE
EOF
	export P11_SYSTEM_CONFIG_MODULES=$PWD/p11-modules

	# In ASan/LSan builds, kryoptic (not compiled with ASan) may have
	# memory leaks that cause LSan to abort p11-kit before output is flushed.
	# Disable LSan leak detection for external module tests.
	set_sanitizer_options

	"$PKCS11_TOOL" --module "$KRYOPTIC_MODULE" --slot 0 \
		--init-token --label test-genkey --so-pin 12345 >/dev/null 2>&1
	"$PKCS11_TOOL" --module "$KRYOPTIC_MODULE" --slot 0 \
		--login --login-type so --so-pin 12345 \
		--init-pin --new-pin 12345 >/dev/null 2>&1
	"$PKCS11_TOOL" --module "$KRYOPTIC_MODULE" --slot 1 \
		--init-token --label test-import --so-pin 12345 >/dev/null 2>&1
	"$PKCS11_TOOL" --module "$KRYOPTIC_MODULE" --slot 1 \
		--login --login-type so --so-pin 12345 \
		--init-pin --new-pin 12345 >/dev/null 2>&1

	# Verify p11-kit can actually load the kryoptic module and
	# see our tokens (may fail in sanitizer builds)
	if ! p11-kit list-tokens "pkcs11:" 2>/dev/null | grep -q test-genkey; then
		skip "p11-kit cannot see kryoptic tokens"
		return
	fi

	# kryoptic is passed directly as --provider to p11-kit server
	P11_SERVER_PROVIDER="$KRYOPTIC_MODULE"
	find_p11_client_module
}

teardown_token() {
	unset KRYOPTIC_CONF
}

test_generate_keypair_ml_dsa() {
	has_mechanism "pkcs11:token=test-genkey" ml-dsa || \
		{ skip "no support for ML-DSA"; return; }
	generate_keypair_loop ml-dsa "44 65 87" "" \
		"pkcs11:token=test-genkey?pin-value=12345" --login
	if p11-kit generate-keypair --login \
		--label="ml-dsa-bad" --type=ml-dsa \
		--parameter-set=unknown \
		"pkcs11:token=test-genkey?pin-value=12345" 2>/dev/null; then
		assert_fail "p11-kit generate-keypair succeeded for unknown ML-DSA parameter set"
	fi
}

test_generate_keypair_ml_kem() {
	has_mechanism "pkcs11:token=test-genkey" ml-kem || \
		{ skip "no support for ML-KEM"; return; }
	generate_keypair_loop ml-kem "512 768 1024" "" \
		"pkcs11:token=test-genkey?pin-value=12345" --login
	if p11-kit generate-keypair --login \
		--label="ml-kem-bad" --type=ml-kem \
		--parameter-set=unknown \
		"pkcs11:token=test-genkey?pin-value=12345" 2>/dev/null; then
		assert_fail "p11-kit generate-keypair succeeded for unknown ML-KEM parameter set"
	fi
}

test_generate_keypair_slh_dsa() {
	has_mechanism "pkcs11:token=test-genkey" slh-dsa || \
		{ skip "no support for SLH-DSA"; return; }
	generate_keypair_loop slh-dsa "sha2-128s sha2-128f sha2-192s" "" \
		"pkcs11:token=test-genkey?pin-value=12345" --login
	if p11-kit generate-keypair --login \
		--label="slh-dsa-bad" --type=slh-dsa \
		--parameter-set=unknown \
		"pkcs11:token=test-genkey?pin-value=12345" 2>/dev/null; then
		assert_fail "p11-kit generate-keypair succeeded for unknown SLH-DSA parameter set"
	fi
}

test_export_pubkey_ml_dsa() {
	has_mechanism "pkcs11:token=test-import" ml-dsa || \
		{ skip "no support for ML-DSA"; return; }
	export_pubkey_check ml-dsa 65 export-mldsa \
		"pkcs11:token=test-import?pin-value=12345" --login
}

test_export_pubkey_ml_kem() {
	has_mechanism "pkcs11:token=test-import" ml-kem || \
		{ skip "no support for ML-KEM"; return; }
	export_pubkey_check ml-kem 768 export-mlkem \
		"pkcs11:token=test-import?pin-value=12345" --login
}

test_export_pubkey_slh_dsa() {
	has_mechanism "pkcs11:token=test-import" slh-dsa || \
		{ skip "no support for SLH-DSA"; return; }
	export_pubkey_check slh-dsa sha2-128s export-slhdsa \
		"pkcs11:token=test-import?pin-value=12345" --login
}

test_import_pubkey_ml_dsa() {
	has_mechanism "pkcs11:token=test-import" ml-dsa || \
		{ skip "no support for ML-DSA"; return; }
	key_roundtrip ml-dsa 65 roundtrip-mldsa \
		"pkcs11:token=test-import?pin-value=12345" --login
}

test_import_pubkey_ml_kem() {
	has_mechanism "pkcs11:token=test-import" ml-kem || \
		{ skip "no support for ML-KEM"; return; }
	key_roundtrip ml-kem 768 roundtrip-mlkem \
		"pkcs11:token=test-import?pin-value=12345" --login
}

test_import_pubkey_slh_dsa() {
	has_mechanism "pkcs11:token=test-import" slh-dsa || \
		{ skip "no support for SLH-DSA"; return; }
	key_roundtrip slh-dsa sha2-128s roundtrip-slhdsa \
		"pkcs11:token=test-import?pin-value=12345" --login
}

test_forwarding_generate_ml_dsa() {
	has_mechanism "pkcs11:token=test-genkey" ml-dsa || \
		{ skip "no support for ML-DSA"; return; }
	start_forwarding || return
	generate_keypair_loop ml-dsa "44 65 87" fwd \
		"pkcs11:token=test-genkey?pin-value=12345" --login
	stop_forwarding
}

test_forwarding_generate_ml_kem() {
	has_mechanism "pkcs11:token=test-genkey" ml-kem || \
		{ skip "no support for ML-KEM"; return; }
	start_forwarding || return
	generate_keypair_loop ml-kem "512 768 1024" fwd \
		"pkcs11:token=test-genkey?pin-value=12345" --login
	stop_forwarding
}

test_forwarding_generate_slh_dsa() {
	has_mechanism "pkcs11:token=test-genkey" slh-dsa || \
		{ skip "no support for SLH-DSA"; return; }
	start_forwarding || return
	generate_keypair_loop slh-dsa "sha2-128s sha2-128f sha2-192s" fwd \
		"pkcs11:token=test-genkey?pin-value=12345" --login
	stop_forwarding
}

test_forwarding_roundtrip_ml_dsa() {
	has_mechanism "pkcs11:token=test-import" ml-dsa || \
		{ skip "no support for ML-DSA"; return; }
	start_forwarding || return
	key_roundtrip ml-dsa 65 fwd-rt-mldsa \
		"pkcs11:token=test-import?pin-value=12345" --login
	stop_forwarding
}

test_forwarding_roundtrip_ml_kem() {
	has_mechanism "pkcs11:token=test-import" ml-kem || \
		{ skip "no support for ML-KEM"; return; }
	start_forwarding || return
	key_roundtrip ml-kem 768 fwd-rt-mlkem \
		"pkcs11:token=test-import?pin-value=12345" --login
	stop_forwarding
}

test_forwarding_roundtrip_slh_dsa() {
	has_mechanism "pkcs11:token=test-import" slh-dsa || \
		{ skip "no support for SLH-DSA"; return; }
	start_forwarding || return
	key_roundtrip slh-dsa sha2-128s fwd-rt-slhdsa \
		"pkcs11:token=test-import?pin-value=12345" --login
	stop_forwarding
}

run test_generate_keypair_ml_dsa test_generate_keypair_ml_kem \
    test_generate_keypair_slh_dsa \
    test_export_pubkey_ml_dsa test_export_pubkey_ml_kem \
    test_export_pubkey_slh_dsa \
    test_import_pubkey_ml_dsa test_import_pubkey_ml_kem \
    test_import_pubkey_slh_dsa \
    test_forwarding_generate_ml_dsa test_forwarding_generate_ml_kem \
    test_forwarding_generate_slh_dsa \
    test_forwarding_roundtrip_ml_dsa test_forwarding_roundtrip_ml_kem \
    test_forwarding_roundtrip_slh_dsa
