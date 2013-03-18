/*
 * Copyright (C) 2013, Redhat Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *     * Redistributions of source code must retain the above
 *       copyright notice, this list of conditions and the
 *       following disclaimer.
 *     * Redistributions in binary form must reproduce the
 *       above copyright notice, this list of conditions and
 *       the following disclaimer in the documentation and/or
 *       other materials provided with the distribution.
 *     * The names of contributors to this software may not be
 *       used to endorse or promote products derived from this
 *       software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
 * THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 *
 * Author: Stef Walter <stefw@redhat.com>
 */

#include "config.h"

#include "attrs.h"
#include "constants.h"
#include "debug.h"
#include "pkcs11.h"
#include "pkcs11x.h"

#include <stdlib.h>

#define ELEMS(x) (sizeof (x) / sizeof (x[0]))

/*
 * These are in numeric order of their type for easy lookup
 * After changing something make sure to run the test-attrs
 * test to verify everything is in order.
 */

#define CT(x, n) { x, #x, n },

const p11_constant p11_constant_types[] = {
	CT (CKA_CLASS, "class")
	CT (CKA_TOKEN, "token")
	CT (CKA_PRIVATE, "private")
	CT (CKA_LABEL, "label")
	CT (CKA_APPLICATION, "application")
	CT (CKA_VALUE, "value")
	CT (CKA_OBJECT_ID, "object-id")
	CT (CKA_CERTIFICATE_TYPE, "certificate-type")
	CT (CKA_ISSUER, "issuer")
	CT (CKA_SERIAL_NUMBER, "serial-number")
	CT (CKA_AC_ISSUER, "ac-issuer")
	CT (CKA_OWNER, "owner")
	CT (CKA_ATTR_TYPES, "attr-types")
	CT (CKA_TRUSTED, "trusted")
	CT (CKA_CERTIFICATE_CATEGORY, "certificate-category")
	CT (CKA_JAVA_MIDP_SECURITY_DOMAIN, "java-midp-security-domain")
	CT (CKA_URL, "url")
	CT (CKA_HASH_OF_SUBJECT_PUBLIC_KEY, "hash-of-subject-public-key")
	CT (CKA_HASH_OF_ISSUER_PUBLIC_KEY, "hash-of-issuer-public-key")
	CT (CKA_CHECK_VALUE, "check-value")
	CT (CKA_KEY_TYPE, "key-type")
	CT (CKA_SUBJECT, "subject")
	CT (CKA_ID, "id")
	CT (CKA_SENSITIVE, "sensitive")
	CT (CKA_ENCRYPT, "encrypt")
	CT (CKA_DECRYPT, "decrypt")
	CT (CKA_WRAP, "wrap")
	CT (CKA_UNWRAP, "unwrap")
	CT (CKA_SIGN, "sign")
	CT (CKA_SIGN_RECOVER, "sign-recover")
	CT (CKA_VERIFY, "verify")
	CT (CKA_VERIFY_RECOVER, "recover")
	CT (CKA_DERIVE, "derive")
	CT (CKA_START_DATE, "start-date")
	CT (CKA_END_DATE, "end-date")
	CT (CKA_MODULUS, "modulus")
	CT (CKA_MODULUS_BITS, "modulus-bits")
	CT (CKA_PUBLIC_EXPONENT, "public-exponent")
	CT (CKA_PRIVATE_EXPONENT, "private-exponent")
	CT (CKA_PRIME_1, "prime-1")
	CT (CKA_PRIME_2, "prime-2")
	CT (CKA_EXPONENT_1, "exponent-1")
	CT (CKA_EXPONENT_2, "exponent-2")
	CT (CKA_COEFFICIENT, "coefficient")
	CT (CKA_PRIME, "prime")
	CT (CKA_SUBPRIME, "subprime")
	CT (CKA_BASE, "base")
	CT (CKA_PRIME_BITS, "prime-bits")
	/* CT (CKA_SUBPRIME_BITS) */
	CT (CKA_SUB_PRIME_BITS, "subprime-bits")
	CT (CKA_VALUE_BITS, "value-bits")
	CT (CKA_VALUE_LEN, "vaule-len")
	CT (CKA_EXTRACTABLE, "extractable")
	CT (CKA_LOCAL, "local")
	CT (CKA_NEVER_EXTRACTABLE, "never-extractable")
	CT (CKA_ALWAYS_SENSITIVE, "always-sensitive")
	CT (CKA_KEY_GEN_MECHANISM, "key-gen-mechanism")
	CT (CKA_MODIFIABLE, "modifiable")
	CT (CKA_ECDSA_PARAMS, "ecdsa-params")
	/* CT (CKA_EC_PARAMS) */
	CT (CKA_EC_POINT, "ec-point")
	CT (CKA_SECONDARY_AUTH, "secondary-auth")
	CT (CKA_AUTH_PIN_FLAGS, "auth-pin-flags")
	CT (CKA_ALWAYS_AUTHENTICATE, "always-authenticate")
	CT (CKA_WRAP_WITH_TRUSTED, "wrap-with-trusted")
	CT (CKA_HW_FEATURE_TYPE, "hw-feature-type")
	CT (CKA_RESET_ON_INIT, "reset-on-init")
	CT (CKA_HAS_RESET, "has-reset")
	CT (CKA_PIXEL_X, "pixel-x")
	CT (CKA_PIXEL_Y, "pixel-y")
	CT (CKA_RESOLUTION, "resolution")
	CT (CKA_CHAR_ROWS, "char-rows")
	CT (CKA_CHAR_COLUMNS, "char-columns")
	CT (CKA_COLOR, "color")
	CT (CKA_BITS_PER_PIXEL, "bits-per-pixel")
	CT (CKA_CHAR_SETS, "char-sets")
	CT (CKA_ENCODING_METHODS, "encoding-methods")
	CT (CKA_MIME_TYPES, "mime-types")
	CT (CKA_MECHANISM_TYPE, "mechanism-type")
	CT (CKA_REQUIRED_CMS_ATTRIBUTES, "required-cms-attributes")
	CT (CKA_DEFAULT_CMS_ATTRIBUTES, "default-cms-attributes")
	CT (CKA_SUPPORTED_CMS_ATTRIBUTES, "supported-cms-attributes")
	CT (CKA_WRAP_TEMPLATE, "wrap-template")
	CT (CKA_UNWRAP_TEMPLATE, "unwrap-template")
	CT (CKA_ALLOWED_MECHANISMS, "allowed-mechanisms")
	CT (CKA_NSS_URL, "nss-url")
	CT (CKA_NSS_EMAIL, "nss-email")
	CT (CKA_NSS_SMIME_INFO, "nss-smime-constant")
	CT (CKA_NSS_SMIME_TIMESTAMP, "nss-smime-timestamp")
	CT (CKA_NSS_PKCS8_SALT, "nss-pkcs8-salt")
	CT (CKA_NSS_PASSWORD_CHECK, "nss-password-check")
	CT (CKA_NSS_EXPIRES, "nss-expires")
	CT (CKA_NSS_KRL, "nss-krl")
	CT (CKA_NSS_PQG_COUNTER, "nss-pqg-counter")
	CT (CKA_NSS_PQG_SEED, "nss-pqg-seed")
	CT (CKA_NSS_PQG_H, "nss-pqg-h")
	CT (CKA_NSS_PQG_SEED_BITS, "nss-pqg-seed-bits")
	CT (CKA_NSS_MODULE_SPEC, "nss-module-spec")
	CT (CKA_TRUST_DIGITAL_SIGNATURE, "trust-digital-signature")
	CT (CKA_TRUST_NON_REPUDIATION, "trust-non-repudiation")
	CT (CKA_TRUST_KEY_ENCIPHERMENT, "trust-key-encipherment")
	CT (CKA_TRUST_DATA_ENCIPHERMENT, "trust-data-encipherment")
	CT (CKA_TRUST_KEY_AGREEMENT, "trust-key-agreement")
	CT (CKA_TRUST_KEY_CERT_SIGN, "trust-key-cert-sign")
	CT (CKA_TRUST_CRL_SIGN, "trust-crl-sign")
	CT (CKA_TRUST_SERVER_AUTH, "trust-server-auth")
	CT (CKA_TRUST_CLIENT_AUTH, "trust-client-auth")
	CT (CKA_TRUST_CODE_SIGNING, "trust-code-signing")
	CT (CKA_TRUST_EMAIL_PROTECTION, "trust-email-protection")
	CT (CKA_TRUST_IPSEC_END_SYSTEM, "trust-ipsec-end-system")
	CT (CKA_TRUST_IPSEC_TUNNEL, "trust-ipsec-tunnel")
	CT (CKA_TRUST_IPSEC_USER, "trust-ipsec-user")
	CT (CKA_TRUST_TIME_STAMPING, "trust-time-stamping")
	CT (CKA_TRUST_STEP_UP_APPROVED, "trust-step-up-approved")
	CT (CKA_CERT_SHA1_HASH, "cert-sha1-hash")
	CT (CKA_CERT_MD5_HASH, "cert-md5-hash")
	CT (CKA_X_ASSERTION_TYPE, "x-assertion-type")
	CT (CKA_X_CERTIFICATE_VALUE, "x-cetrificate-value")
	CT (CKA_X_PURPOSE, "x-purpose")
	CT (CKA_X_PEER, "x-peer")
	CT (CKA_X_DISTRUSTED, "x-distrusted")
	CT (CKA_X_CRITICAL, "x-critical")
	{ CKA_INVALID },
};

const p11_constant p11_constant_classes[] = {
	CT (CKO_DATA, "data")
	CT (CKO_CERTIFICATE, "certificate")
	CT (CKO_PUBLIC_KEY, "public-key")
	CT (CKO_PRIVATE_KEY, "private-key")
	CT (CKO_SECRET_KEY, "secret-key")
	CT (CKO_HW_FEATURE, "hw-feature")
	CT (CKO_DOMAIN_PARAMETERS, "domain-parameters")
	CT (CKO_MECHANISM, "mechanism")
	CT (CKO_NSS_CRL, "nss-crl")
	CT (CKO_NSS_SMIME, "nss-smime")
	CT (CKO_NSS_TRUST, "nss-trust")
	CT (CKO_NSS_BUILTIN_ROOT_LIST, "nss-builtin-root-list")
	CT (CKO_NSS_NEWSLOT, "nss-newslot")
	CT (CKO_NSS_DELSLOT, "nss-delslot")
	CT (CKO_X_TRUST_ASSERTION, "x-trust-assertion")
	CT (CKO_X_CERTIFICATE_EXTENSION, "x-certificate-extension")
	{ CKA_INVALID },
};

const p11_constant p11_constant_trusts[] = {
	CT (CKT_NSS_TRUSTED, "nss-trusted")
	CT (CKT_NSS_TRUSTED_DELEGATOR, "nss-trusted-delegator")
	CT (CKT_NSS_MUST_VERIFY_TRUST, "nss-must-verify-trust")
	CT (CKT_NSS_TRUST_UNKNOWN, "nss-trust-unknown")
	CT (CKT_NSS_NOT_TRUSTED, "nss-not-trusted")
	CT (CKT_NSS_VALID_DELEGATOR, "nss-valid-delegator")
	{ CKA_INVALID },
};

const p11_constant p11_constant_certs[] = {
	CT (CKC_X_509, "x-509")
	CT (CKC_X_509_ATTR_CERT, "x-509-attr-cert")
	CT (CKC_WTLS, "wtls")
	{ CKA_INVALID },
};

const p11_constant p11_constant_keys[] = {
	CT (CKK_RSA, "rsa")
	CT (CKK_DSA, "dsa")
	CT (CKK_DH, "dh")
	/* CT (CKK_ECDSA) */
	CT (CKK_EC, "ec")
	CT (CKK_X9_42_DH, "x9-42-dh")
	CT (CKK_KEA, "kea")
	CT (CKK_GENERIC_SECRET, "generic-secret")
	CT (CKK_RC2, "rc2")
	CT (CKK_RC4, "rc4")
	CT (CKK_DES, "des")
	CT (CKK_DES2, "des2")
	CT (CKK_DES3, "des3")
	CT (CKK_CAST, "cast")
	CT (CKK_CAST3, "cast3")
	CT (CKK_CAST128, "cast128")
	CT (CKK_RC5, "rc5")
	CT (CKK_IDEA, "idea")
	CT (CKK_SKIPJACK, "skipjack")
	CT (CKK_BATON, "baton")
	CT (CKK_JUNIPER, "juniper")
	CT (CKK_CDMF, "cdmf")
	CT (CKK_AES, "aes")
	CT (CKK_BLOWFISH, "blowfish")
	CT (CKK_TWOFISH, "twofish")
	CT (CKK_NSS_PKCS8, "nss-pkcs8")
	{ CKA_INVALID },
};

const p11_constant p11_constant_asserts[] = {
	CT (CKT_X_DISTRUSTED_CERTIFICATE, "x-distrusted-certificate")
	CT (CKT_X_PINNED_CERTIFICATE, "x-pinned-certificate")
	CT (CKT_X_ANCHORED_CERTIFICATE, "x-anchored-certificate")
	{ CKA_INVALID },
};

const p11_constant p11_constant_categories[] = {
	{ 0, "unspecified", "unspecified" },
	{ 1, "token-user", "token-user" },
	{ 2, "authority", "authority" },
	{ 3, "other-entry", "other-entry" },
	{ CKA_INVALID },
};

#undef CT

struct {
	const p11_constant *table;
	int length;
} tables[] = {
	{ p11_constant_types, ELEMS (p11_constant_types) - 1 },
	{ p11_constant_classes, ELEMS (p11_constant_classes) - 1 },
	{ p11_constant_trusts, ELEMS (p11_constant_trusts) - 1 },
	{ p11_constant_certs, ELEMS (p11_constant_certs) - 1 },
	{ p11_constant_keys, ELEMS (p11_constant_keys) - 1 },
	{ p11_constant_asserts, ELEMS (p11_constant_asserts) - 1 },
	{ p11_constant_categories, ELEMS (p11_constant_categories) - 1 }
};

static int
compar_attr_info (const void *one,
                  const void *two)
{
	const p11_constant *a1 = one;
	const p11_constant *a2 = two;
	if (a1->value == a2->value)
		return 0;
	if (a1->value < a2->value)
		return -1;
	return 1;
}

static const p11_constant *
lookup_info (const p11_constant *table,
             CK_ATTRIBUTE_TYPE type)
{
	p11_constant match = { type, NULL, NULL };
	int length = -1;
	int i;

	for (i = 0; i < ELEMS (tables); i++) {
		if (table == tables[i].table) {
			length = tables[i].length;
			break;
		}
	}

	return_val_if_fail (length != -1, NULL);
	return bsearch (&match, table, length, sizeof (p11_constant), compar_attr_info);

}
const char *
p11_constant_name (const p11_constant *constants,
                   CK_ULONG type)
{
	const p11_constant *constant = lookup_info (constants, type);
	return constant ? constant->name : NULL;
}

const char *
p11_constant_nick (const p11_constant *constants,
                   CK_ULONG type)
{
	const p11_constant *constant = lookup_info (constants, type);
	return constant ? constant->nick : NULL;
}

p11_dict *
p11_constant_reverse (bool nick)
{
	const p11_constant *table;
	p11_dict *lookups;
	int length = -1;
	int i, j;

	lookups = p11_dict_new (p11_dict_str_hash, p11_dict_str_equal, NULL, NULL);
	return_val_if_fail (lookups != NULL, NULL);

	for (i = 0; i < ELEMS (tables); i++) {
		table = tables[i].table;
		length = tables[i].length;

		for (j = 0; j < length; j++) {
			if (!p11_dict_set (lookups,
			                   nick ? (void *)table[j].nick : (void *)table[j].name,
			                   (void *)&table[j].value))
				return_val_if_reached (NULL);
		}
	}

	return lookups;
}

CK_ULONG
p11_constant_resolve (p11_dict *reversed,
                     const char *string)
{
	CK_ULONG *ptr;

	return_val_if_fail (reversed != NULL, CKA_INVALID);
	return_val_if_fail (string != NULL, CKA_INVALID);

	ptr = p11_dict_get (reversed, string);
	return ptr ? *ptr : CKA_INVALID;
}
