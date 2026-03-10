# Shared helpers for integration tests against external PKCS#11 tokens.
# Source this file from individual token test scripts after test-init.sh.
#
# Variables consumed (set in token-specific setup before calling helpers):
#   P11_SERVER_PROVIDER  - if set, passed as --provider to p11-kit server;
#                          leave unset to use the p11-kit module config instead
#
# Override per token:
#   teardown_token()     - called during teardown for token-specific cleanup
#
# Note: helper functions use _h_* variables as pseudo-locals (POSIX sh has no
# local).  Do not call one helper from inside another without renaming their
# working variables first, or the outer call's state will be clobbered.

# Discover p11-kit-client.so for RPC forwarding tests.
# Sets P11_CLIENT_MODULE.
find_p11_client_module() {
	P11_CLIENT_MODULE=
	for path in \
		"$libdir/pkcs11/p11-kit-client.so" \
		/usr/lib/pkcs11/p11-kit-client.so \
		/usr/lib64/pkcs11/p11-kit-client.so; do
		if test -f "$path"; then
			P11_CLIENT_MODULE="$path"
			break
		fi
	done
}

# Suppress sanitizer false-positives from non-ASan third-party modules.
set_sanitizer_options() {
	export LSAN_OPTIONS="detect_leaks=0"
	export ASAN_OPTIONS="${ASAN_OPTIONS:-}${ASAN_OPTIONS:+:}verify_asan_link_order=0"
}

# Per-token teardown hook; override to unset token-specific env vars.
teardown_token() { :; }

teardown() {
	if test "${FORWARDING_PID+set}" = "set"; then
		kill "$FORWARDING_PID" 2>/dev/null || true
		wait "$FORWARDING_PID" 2>/dev/null || true
		unset FORWARDING_PID
		unset P11_KIT_SERVER_ADDRESS
		unset P11_KIT_SERVER_PID
	fi
	teardown_token
	unset P11_SYSTEM_CONFIG_MODULES
	rm -rf "$testdir"
}

start_forwarding() {
	if test -z "$P11_CLIENT_MODULE"; then
		skip "p11-kit-client.so not found"
		return 1
	fi

	# p11-kit server needs XDG_RUNTIME_DIR for socket creation; the
	# post-install test environment may not have it set.
	if test -z "${XDG_RUNTIME_DIR-}"; then
		export XDG_RUNTIME_DIR="$testdir/runtime"
		mkdir -p "$XDG_RUNTIME_DIR"
	fi

	if test -n "${P11_SERVER_PROVIDER-}"; then
		p11-kit server -s --provider "$P11_SERVER_PROVIDER" \
			"pkcs11:" > server.env 2> server.err
	else
		# Start server using the module config rather than --provider,
		# so tokens that require x-init-reserved (e.g. NSS configDir)
		# are initialised correctly.
		p11-kit server -s \
			"pkcs11:" > server.env 2> server.err
	fi
	if test $? -ne 0; then
		sed 's/^/# /' server.err
		assert_fail "unable to start p11-kit server"
	fi
	. ./server.env

	if test -z "${P11_KIT_SERVER_ADDRESS-}"; then
		assert_fail "P11_KIT_SERVER_ADDRESS not set after server start"
	fi
	FORWARDING_PID="$P11_KIT_SERVER_PID"

	SAVED_P11_SYSTEM_CONFIG_MODULES="${P11_SYSTEM_CONFIG_MODULES-}"
	mkdir -p p11-forwarding
	cat > p11-forwarding/remote.module <<EOF
module: $P11_CLIENT_MODULE
EOF
	export P11_SYSTEM_CONFIG_MODULES=$PWD/p11-forwarding

	return 0
}

stop_forwarding() {
	if test "${FORWARDING_PID+set}" = "set"; then
		kill "$FORWARDING_PID" 2>/dev/null || true
		wait "$FORWARDING_PID" 2>/dev/null || true
		unset FORWARDING_PID
		unset P11_KIT_SERVER_ADDRESS
		unset P11_KIT_SERVER_PID
	fi

	if test -n "${SAVED_P11_SYSTEM_CONFIG_MODULES-}"; then
		export P11_SYSTEM_CONFIG_MODULES="$SAVED_P11_SYSTEM_CONFIG_MODULES"
	else
		unset P11_SYSTEM_CONFIG_MODULES
	fi
}

# Check whether TOKEN lists a mechanism matching PATTERN.
has_mechanism() {
	p11-kit list-mechanisms "$1" 2>/dev/null | grep -qF "$2"
}

# Generate key pairs for each parameter set in SETS.
# TYPE: key type (e.g. ml-kem); SETS: space-separated parameter sets;
# PREFIX: label prefix, empty for none ("TYPE-PS"), "fwd" gives "fwd-TYPE-PS";
# URI: full pkcs11 URI; remaining args passed to p11-kit generate-keypair.
generate_keypair_loop() {
	_h_type=$1; _h_sets=$2; _h_prefix=$3; _h_uri=$4; shift 4
	for _h_ps in $_h_sets; do
		_h_label="${_h_prefix:+${_h_prefix}-}${_h_type}-${_h_ps}"
		if ! p11-kit generate-keypair "$@" \
			--label="$_h_label" \
			--type="$_h_type" \
			--parameter-set="$_h_ps" \
			"$_h_uri"; then
			assert_fail "unable to generate ${_h_type}-${_h_ps} key pair"
		fi
	done
}

# Verify that FILE is a valid PEM public key; TYPE used in error messages.
check_pem_pubkey() {
	grep -q "BEGIN PUBLIC KEY" "$2" || \
		assert_fail "$1 export missing PEM header"
}

# Generate a single key pair and export the public key; verify PEM output.
# TYPE: key type; PS: parameter set; LABEL: key label; URI: pkcs11 URI;
# remaining args passed to both generate-keypair and export-object.
export_pubkey_check() {
	_h_type=$1; _h_ps=$2; _h_label=$3; _h_uri=$4; shift 4
	_h_base="${_h_uri%%\?*}"
	_h_query="${_h_uri#"$_h_base"}"
	if ! p11-kit generate-keypair "$@" \
		--label="$_h_label" \
		--type="$_h_type" \
		--parameter-set="$_h_ps" \
		"$_h_uri"; then
		assert_fail "unable to generate ${_h_type}-${_h_ps} key for export"
	fi
	if ! p11-kit export-object -q "$@" \
		"${_h_base};object=${_h_label};type=public${_h_query}" \
		> "${_h_label}.pem"; then
		assert_fail "unable to export ${_h_type} public key"
	fi
	check_pem_pubkey "$_h_type" "${_h_label}.pem"
}

# Generate a key pair, export, import, re-export and diff (roundtrip check).
# TYPE: key type; PS: parameter set; LABEL: base label; URI: pkcs11 URI;
# remaining args passed to all p11-kit invocations.
key_roundtrip() {
	_h_type=$1; _h_ps=$2; _h_label=$3; _h_uri=$4; shift 4
	_h_base="${_h_uri%%\?*}"
	_h_query="${_h_uri#"$_h_base"}"
	if ! p11-kit generate-keypair "$@" \
		--label="$_h_label" \
		--type="$_h_type" \
		--parameter-set="$_h_ps" \
		"$_h_uri"; then
		assert_fail "unable to generate ${_h_type}-${_h_ps} key for roundtrip"
	fi
	if ! p11-kit export-object -q "$@" \
		"${_h_base};object=${_h_label};type=public${_h_query}" \
		> "${_h_label}.exp"; then
		assert_fail "unable to export ${_h_type} key"
	fi
	check_pem_pubkey "$_h_type" "${_h_label}.exp"
	if ! p11-kit import-object -q "$@" \
		--file="${_h_label}.exp" \
		--label="imported-${_h_label}" \
		"$_h_uri"; then
		assert_fail "unable to import ${_h_type} key"
	fi
	if ! p11-kit export-object -q "$@" \
		"${_h_base};object=imported-${_h_label};type=public${_h_query}" \
		> "${_h_label}.out"; then
		assert_fail "unable to re-export imported ${_h_type} key"
	fi
	: ${DIFF=diff}
	if ! ${DIFF} "${_h_label}.exp" "${_h_label}.out" > "${_h_label}.diff"; then
		sed 's/^/# /' "${_h_label}.diff"
		assert_fail "${_h_type} import/export roundtrip: output mismatch"
	fi
}
