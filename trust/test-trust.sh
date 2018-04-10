#!/bin/sh

. "${builddir=.}/test-init.sh"

test_disable_in_proxy()
{
	: ${PKCS11_TOOL=pkcs11-tool}
	if ! (type ${PKCS11_TOOL}) > /dev/null 2>&1; then
		skip "pkcs11-tool not found"
	fi
	: ${PKG_CONFIG=pkg-config}
	if ! (type ${PKG_CONFIG}) > /dev/null 2>&1; then
		skip "pkg-config not found"
	fi
	proxy_module=$(${PKG_CONFIG} --variable=proxy_module p11-kit-1)
	if ${PKCS11_TOOL} --module="$proxy_module" -T | grep '^ *token model *: *p11-kit-trust' > /dev/null 2>&1; then
		assert_fail "p11-kit-trust is not disabled in proxy module"
	fi
}

run test_disable_in_proxy
