#!/bin/sh

test "${abs_top_builddir+set}" = set || {
	echo "set abs_top_builddir" 1>&2
	exit 1
}

. "$abs_top_builddir/common/test-init.sh"
. "$abs_top_srcdir/common/test-external-helpers.sh"

setup() {
	testdir=$PWD/test-nss-$$
	test -d "$testdir" || mkdir "$testdir"
	cd "$testdir"

	# NSS Certificate DB token name (percent-encoded for PKCS#11 URI).
	# NSS Generic Crypto Services is ephemeral/write-protected; this token
	# requires a configDir and is the one that supports persistent key storage.
	NSS_CERTDB_TOKEN="NSS%20Certificate%20DB"

	: ${CERTUTIL=certutil}
	if ! command -v "$CERTUTIL" >/dev/null 2>&1; then
		skip "certutil not found"
		return
	fi

	# Find NSS softokn module
	NSS_MODULE=
	for path in \
		/usr/lib/pkcs11/libsoftokn3.so \
		/usr/lib64/pkcs11/libsoftokn3.so \
		/usr/lib/libsoftokn3.so \
		/usr/lib64/libsoftokn3.so; do
		if test -f "$path"; then
			NSS_MODULE="$path"
			break
		fi
	done
	if test -z "$NSS_MODULE"; then
		skip "NSS softokn module not found"
		return
	fi

	# Create NSS database for key generation token.
	# Clear LD_LIBRARY_PATH for certutil: in ASan post-install builds,
	# LD_LIBRARY_PATH includes the installdir which contains an ASan-compiled
	# libp11-kit.so.0.  certutil loads it transitively (via NSS->p11-kit-proxy),
	# pulling libasan into a non-ASan process and causing an abort.
	mkdir -p nssdb-genkey
	env -u LD_LIBRARY_PATH \
		"$CERTUTIL" -d sql:$PWD/nssdb-genkey -N --empty-password

	# Register NSS softokn as p11-kit module with database path.
	# NSS Generic Crypto Services is write-protected (ephemeral only);
	# key generation requires NSS Certificate DB which needs a configDir.
	mkdir -p p11-modules
	cat > p11-modules/nss-softokn.module <<EOF
module: $NSS_MODULE
x-init-reserved: configDir=sql:$PWD/nssdb-genkey
EOF
	export P11_SYSTEM_CONFIG_MODULES=$PWD/p11-modules

	# Disable LSan leak detection: NSS softokn (non-ASan) is expected to
	# have leaks that LSan would report as errors in ASan builds.
	set_sanitizer_options

	# Verify p11-kit can actually work with the module
	if ! p11-kit list-mechanisms \
		"pkcs11:token=$NSS_CERTDB_TOKEN" \
		>/dev/null 2>&1; then
		skip "p11-kit cannot work with NSS softokn module"
		return
	fi

	# Probe which PQC algorithms NSS actually supports (not just lists).
	# Some NSS builds expose mechanism IDs as stubs that return errors on
	# actual key generation; we skip the corresponding tests in that case.
	NSS_ML_KEM=
	if p11-kit list-mechanisms "pkcs11:token=$NSS_CERTDB_TOKEN" \
			2>/dev/null | grep -q ml-kem; then
		if p11-kit generate-keypair --login \
				--label=probe-mlkem --type=ml-kem \
				--parameter-set=768 \
				"pkcs11:token=$NSS_CERTDB_TOKEN?pin-value=" \
				>/dev/null 2>&1; then
			NSS_ML_KEM=yes
		fi
	fi

	NSS_ML_DSA=
	if p11-kit list-mechanisms "pkcs11:token=$NSS_CERTDB_TOKEN" \
			2>/dev/null | grep -q ml-dsa; then
		if p11-kit generate-keypair --login \
				--label=probe-mldsa --type=ml-dsa \
				--parameter-set=65 \
				"pkcs11:token=$NSS_CERTDB_TOKEN?pin-value=" \
				>/dev/null 2>&1; then
			NSS_ML_DSA=yes
		fi
	fi

	find_p11_client_module
}

test_generate_keypair_ml_kem() {
	# ML-KEM is fully working in upstream NSS (768 and 1024)
	if test -z "$NSS_ML_KEM"; then
		skip "no support for ML-KEM"
		return
	fi
	generate_keypair_loop ml-kem "768 1024" "" \
		"pkcs11:token=$NSS_CERTDB_TOKEN?pin-value=" --login
}

test_generate_keypair_ml_dsa() {
	# ML-DSA may be disabled in distribution packages
	if test -z "$NSS_ML_DSA"; then
		skip "no support for ML-DSA (upstream NSS has stubs only)"
		return
	fi
	generate_keypair_loop ml-dsa "44 65 87" "" \
		"pkcs11:token=$NSS_CERTDB_TOKEN?pin-value=" --login
}

test_export_pubkey_ml_kem() {
	if test -z "$NSS_ML_KEM"; then
		skip "no support for ML-KEM"
		return
	fi
	export_pubkey_check ml-kem 768 export-mlkem \
		"pkcs11:token=$NSS_CERTDB_TOKEN?pin-value=" --login
}

test_export_pubkey_ml_dsa() {
	if test -z "$NSS_ML_DSA"; then
		skip "no support for ML-DSA"
		return
	fi
	export_pubkey_check ml-dsa 65 export-mldsa \
		"pkcs11:token=$NSS_CERTDB_TOKEN?pin-value=" --login
}

test_forwarding_generate_ml_kem() {
	if test -z "$NSS_ML_KEM"; then
		skip "no support for ML-KEM"
		return
	fi
	start_forwarding || return
	generate_keypair_loop ml-kem "768 1024" fwd \
		"pkcs11:token=$NSS_CERTDB_TOKEN?pin-value=" --login
	stop_forwarding
}

test_forwarding_generate_ml_dsa() {
	if test -z "$NSS_ML_DSA"; then
		skip "no support for ML-DSA"
		return
	fi
	start_forwarding || return
	generate_keypair_loop ml-dsa "44 65 87" fwd \
		"pkcs11:token=$NSS_CERTDB_TOKEN?pin-value=" --login
	stop_forwarding
}

test_forwarding_export_ml_kem() {
	if test -z "$NSS_ML_KEM"; then
		skip "no support for ML-KEM"
		return
	fi
	start_forwarding || return
	export_pubkey_check ml-kem 768 fwd-export-mlkem \
		"pkcs11:token=$NSS_CERTDB_TOKEN?pin-value=" --login
	stop_forwarding
}

run test_generate_keypair_ml_kem test_generate_keypair_ml_dsa \
    test_export_pubkey_ml_kem test_export_pubkey_ml_dsa \
    test_forwarding_generate_ml_kem test_forwarding_generate_ml_dsa \
    test_forwarding_export_ml_kem
