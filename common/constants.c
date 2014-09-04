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
#include "pkcs11i.h"
#include "pkcs11x.h"

#include <stdlib.h>

#define ELEMS(x) (sizeof (x) / sizeof (x[0]))

/*
 * These are in numeric order of their type for easy lookup
 * After changing something make sure to run the test-attrs
 * test to verify everything is in order.
 */

#define CT(x, n) { x, #x, { n } },
#define CT2(x, n, n2) { x, #x, { n, n2 } },

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
	CT2 (CKA_PUBLIC_KEY_INFO, "public-key-info", "x-public-key-info")
	CT (CKA_PRIME, "prime")
	CT (CKA_SUBPRIME, "subprime")
	CT (CKA_BASE, "base")
	CT (CKA_PRIME_BITS, "prime-bits")
	/* CT (CKA_SUBPRIME_BITS) */
	CT (CKA_SUB_PRIME_BITS, "subprime-bits")
	CT (CKA_VALUE_BITS, "value-bits")
	CT (CKA_VALUE_LEN, "value-len")
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
	{ 0, "unspecified", { "unspecified" } },
	{ 1, "token-user",  { "token-user" } },
	{ 2, "authority",  { "authority" } },
	{ 3, "other-entry",  { "other-entry" } },
	{ CKA_INVALID },
};

const p11_constant p11_constant_users[] = {
	CT (CKU_SO, NULL)
	CT (CKU_USER, NULL)
	CT (CKU_CONTEXT_SPECIFIC, NULL)
	{ CKA_INVALID },
};

const p11_constant p11_constant_states[] = {
	CT (CKS_RO_PUBLIC_SESSION, NULL)
	CT (CKS_RO_USER_FUNCTIONS, NULL)
	CT (CKS_RW_PUBLIC_SESSION, NULL)
	CT (CKS_RW_USER_FUNCTIONS, NULL)
	CT (CKS_RW_SO_FUNCTIONS, NULL)
	{ CKA_INVALID },
};

const p11_constant p11_constant_returns[] = {
	CT (CKR_OK, NULL)
	CT (CKR_CANCEL, NULL)
	CT (CKR_HOST_MEMORY, NULL)
	CT (CKR_SLOT_ID_INVALID, NULL)
	CT (CKR_GENERAL_ERROR, NULL)
	CT (CKR_FUNCTION_FAILED, NULL)
	CT (CKR_ARGUMENTS_BAD, NULL)
	CT (CKR_NO_EVENT, NULL)
	CT (CKR_NEED_TO_CREATE_THREADS, NULL)
	CT (CKR_CANT_LOCK, NULL)
	CT (CKR_ATTRIBUTE_READ_ONLY, NULL)
	CT (CKR_ATTRIBUTE_SENSITIVE, NULL)
	CT (CKR_ATTRIBUTE_TYPE_INVALID, NULL)
	CT (CKR_ATTRIBUTE_VALUE_INVALID, NULL)
	CT (CKR_DATA_INVALID, NULL)
	CT (CKR_DATA_LEN_RANGE, NULL)
	CT (CKR_DEVICE_ERROR, NULL)
	CT (CKR_DEVICE_MEMORY, NULL)
	CT (CKR_DEVICE_REMOVED, NULL)
	CT (CKR_ENCRYPTED_DATA_INVALID, NULL)
	CT (CKR_ENCRYPTED_DATA_LEN_RANGE, NULL)
	CT (CKR_FUNCTION_CANCELED, NULL)
	CT (CKR_FUNCTION_NOT_PARALLEL, NULL)
	CT (CKR_FUNCTION_NOT_SUPPORTED, NULL)
	CT (CKR_KEY_HANDLE_INVALID, NULL)
	CT (CKR_KEY_SIZE_RANGE, NULL)
	CT (CKR_KEY_TYPE_INCONSISTENT, NULL)
	CT (CKR_KEY_NOT_NEEDED, NULL)
	CT (CKR_KEY_CHANGED, NULL)
	CT (CKR_KEY_NEEDED, NULL)
	CT (CKR_KEY_INDIGESTIBLE, NULL)
	CT (CKR_KEY_FUNCTION_NOT_PERMITTED, NULL)
	CT (CKR_KEY_NOT_WRAPPABLE, NULL)
	CT (CKR_KEY_UNEXTRACTABLE, NULL)
	CT (CKR_MECHANISM_INVALID, NULL)
	CT (CKR_MECHANISM_PARAM_INVALID, NULL)
	CT (CKR_OBJECT_HANDLE_INVALID, NULL)
	CT (CKR_OPERATION_ACTIVE, NULL)
	CT (CKR_OPERATION_NOT_INITIALIZED, NULL)
	CT (CKR_PIN_INCORRECT, NULL)
	CT (CKR_PIN_INVALID, NULL)
	CT (CKR_PIN_LEN_RANGE, NULL)
	CT (CKR_PIN_EXPIRED, NULL)
	CT (CKR_PIN_LOCKED, NULL)
	CT (CKR_SESSION_CLOSED, NULL)
	CT (CKR_SESSION_COUNT, NULL)
	CT (CKR_SESSION_HANDLE_INVALID, NULL)
	CT (CKR_SESSION_PARALLEL_NOT_SUPPORTED, NULL)
	CT (CKR_SESSION_READ_ONLY, NULL)
	CT (CKR_SESSION_EXISTS, NULL)
	CT (CKR_SESSION_READ_ONLY_EXISTS, NULL)
	CT (CKR_SESSION_READ_WRITE_SO_EXISTS, NULL)
	CT (CKR_SIGNATURE_INVALID, NULL)
	CT (CKR_SIGNATURE_LEN_RANGE, NULL)
	CT (CKR_TEMPLATE_INCOMPLETE, NULL)
	CT (CKR_TEMPLATE_INCONSISTENT, NULL)
	CT (CKR_TOKEN_NOT_PRESENT, NULL)
	CT (CKR_TOKEN_NOT_RECOGNIZED, NULL)
	CT (CKR_TOKEN_WRITE_PROTECTED, NULL)
	CT (CKR_UNWRAPPING_KEY_HANDLE_INVALID, NULL)
	CT (CKR_UNWRAPPING_KEY_SIZE_RANGE, NULL)
	CT (CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT, NULL)
	CT (CKR_USER_ALREADY_LOGGED_IN, NULL)
	CT (CKR_USER_NOT_LOGGED_IN, NULL)
	CT (CKR_USER_PIN_NOT_INITIALIZED, NULL)
	CT (CKR_USER_TYPE_INVALID, NULL)
	CT (CKR_USER_ANOTHER_ALREADY_LOGGED_IN, NULL)
	CT (CKR_USER_TOO_MANY_TYPES, NULL)
	CT (CKR_WRAPPED_KEY_INVALID, NULL)
	CT (CKR_WRAPPED_KEY_LEN_RANGE, NULL)
	CT (CKR_WRAPPING_KEY_HANDLE_INVALID, NULL)
	CT (CKR_WRAPPING_KEY_SIZE_RANGE, NULL)
	CT (CKR_WRAPPING_KEY_TYPE_INCONSISTENT, NULL)
	CT (CKR_RANDOM_SEED_NOT_SUPPORTED, NULL)
	CT (CKR_RANDOM_NO_RNG, NULL)
	CT (CKR_DOMAIN_PARAMS_INVALID, NULL)
	CT (CKR_BUFFER_TOO_SMALL, NULL)
	CT (CKR_SAVED_STATE_INVALID, NULL)
	CT (CKR_INFORMATION_SENSITIVE, NULL)
	CT (CKR_STATE_UNSAVEABLE, NULL)
	CT (CKR_CRYPTOKI_NOT_INITIALIZED, NULL)
	CT (CKR_CRYPTOKI_ALREADY_INITIALIZED, NULL)
	CT (CKR_MUTEX_BAD, NULL)
	CT (CKR_MUTEX_NOT_LOCKED, NULL)
	CT (CKR_FUNCTION_REJECTED, NULL)
	{ CKA_INVALID },
};

const p11_constant p11_constant_mechanisms[] = {
	CT (CKM_RSA_PKCS_KEY_PAIR_GEN, "rsa-pkcs-key-pair-gen")
	CT (CKM_RSA_PKCS, "rsa-pkcs")
	CT (CKM_RSA_9796, "rsa-9796")
	CT (CKM_RSA_X_509, "rsa-x-509")
	CT (CKM_MD2_RSA_PKCS, "md2-rsa-pkcs")
	CT (CKM_MD5_RSA_PKCS, "md5-rsa-pkcs")
	CT (CKM_SHA1_RSA_PKCS, "sha1-rsa-pkcs")
	CT (CKM_RIPEMD128_RSA_PKCS, "ripemd128-rsa-pkcs")
	CT (CKM_RIPEMD160_RSA_PKCS, "ripemd160-rsa-pkcs")
	CT (CKM_RSA_PKCS_OAEP, "rsa-pkcs-oaep")
	CT (CKM_RSA_X9_31_KEY_PAIR_GEN, "rsa-x9-31-key-pair-gen")
	CT (CKM_RSA_X9_31, "rsa-x9-31")
	CT (CKM_SHA1_RSA_X9_31, "sha1-rsa-x9-31")
	CT (CKM_RSA_PKCS_PSS, "rsa-pkcs-pss")
	CT (CKM_SHA1_RSA_PKCS_PSS, "sha1-rsa-pkcs-pss")
	CT (CKM_DSA_KEY_PAIR_GEN, "dsa-key-pair-gen")
	CT (CKM_DSA, NULL) /* "dsa" */
	CT (CKM_DSA_SHA1, "dsa-sha1")
	CT (CKM_DH_PKCS_KEY_PAIR_GEN, "dh-pkcs-key-pair-gen")
	CT (CKM_DH_PKCS_DERIVE, "dh-pkcs-derive")
	CT (CKM_X9_42_DH_KEY_PAIR_GEN, "x9-42-dh-key-pair-gen")
	CT (CKM_X9_42_DH_DERIVE, "x9-42-dh-derive")
	CT (CKM_X9_42_DH_HYBRID_DERIVE, "x9-42-dh-hybrid-derive")
	CT (CKM_X9_42_MQV_DERIVE, "x9-42-mqv-derive")
	CT (CKM_SHA256_RSA_PKCS, "sha256-rsa-pkcs")
	CT (CKM_SHA384_RSA_PKCS, "sha384-rsa-pkcs")
	CT (CKM_SHA512_RSA_PKCS, "sha512-rsa-pkcs")
	CT (CKM_SHA256_RSA_PKCS_PSS, "sha256-rsa-pkcs-pss")
	CT (CKM_SHA384_RSA_PKCS_PSS, "sha384-rsa-pkcs-pss")
	CT (CKM_SHA512_RSA_PKCS_PSS, "sha512-rsa-pkcs-pss")
	CT (CKM_RC2_KEY_GEN, "rc2-key-gen")
	CT (CKM_RC2_ECB, "rc2-ecb")
	CT (CKM_RC2_CBC, "rc2-cbc")
	CT (CKM_RC2_MAC, "rc2-mac")
	CT (CKM_RC2_MAC_GENERAL, "rc2-mac-general")
	CT (CKM_RC2_CBC_PAD, "rc2-cbc-pad")
	CT (CKM_RC4_KEY_GEN, "rc4-key-gen")
	CT (CKM_RC4, NULL) /* "rc4" */
	CT (CKM_DES_KEY_GEN, "des-key-gen")
	CT (CKM_DES_ECB, "des-ecb")
	CT (CKM_DES_CBC, "des-cbc")
	CT (CKM_DES_MAC, "des-mac")
	CT (CKM_DES_MAC_GENERAL, "des-mac-general")
	CT (CKM_DES_CBC_PAD, "des-cbc-pad")
	CT (CKM_DES2_KEY_GEN, "des2-key-gen")
	CT (CKM_DES3_KEY_GEN, "des3-key-gen")
	CT (CKM_DES3_ECB, "des3-ecb")
	CT (CKM_DES3_CBC, "des3-cbc")
	CT (CKM_DES3_MAC, "des3-mac")
	CT (CKM_DES3_MAC_GENERAL, "des3-mac-general")
	CT (CKM_DES3_CBC_PAD, "des3-cbc-pad")
	CT (CKM_CDMF_KEY_GEN, "cdmf-key-gen")
	CT (CKM_CDMF_ECB, "cdmf-ecb")
	CT (CKM_CDMF_CBC, "cdmf-cbc")
	CT (CKM_CDMF_MAC, "cdmf-mac")
	CT (CKM_CDMF_MAC_GENERAL, "cdmf-mac-general")
	CT (CKM_CDMF_CBC_PAD, "cdmf-cbc-pad")
	CT (CKM_DES_OFB64, "des-ofb64")
	CT (CKM_DES_OFB8, "des-ofb8")
	CT (CKM_DES_CFB64, "des-cfb64")
	CT (CKM_DES_CFB8, "des-cfb8")
	CT (CKM_MD2, "md2")
	CT (CKM_MD2_HMAC, "md2-hmac")
	CT (CKM_MD2_HMAC_GENERAL, "md2-hmac-general")
	CT (CKM_MD5, "md5")
	CT (CKM_MD5_HMAC, "md5-hmac")
	CT (CKM_MD5_HMAC_GENERAL, "md5-hmac-general")
	CT (CKM_SHA_1, "sha-1")
	CT (CKM_SHA_1_HMAC, "sha-1-hmac")
	CT (CKM_SHA_1_HMAC_GENERAL, "sha-1-hmac-general")
	CT (CKM_RIPEMD128, "ripemd128")
	CT (CKM_RIPEMD128_HMAC, "ripemd128-hmac")
	CT (CKM_RIPEMD128_HMAC_GENERAL, "ripemd128-hmac-general")
	CT (CKM_RIPEMD160, "ripemd160")
	CT (CKM_RIPEMD160_HMAC, "ripemd160-hmac")
	CT (CKM_RIPEMD160_HMAC_GENERAL, "ripemd160-hmac-general")
	CT (CKM_SHA256, "sha256")
	CT (CKM_SHA256_HMAC, "sha256-hmac")
	CT (CKM_SHA256_HMAC_GENERAL, "sha256-hmac-general")
	CT (CKM_SHA384, "sha384")
	CT (CKM_SHA384_HMAC, "sha384-hmac")
	CT (CKM_SHA384_HMAC_GENERAL, "sha384-hmac-general")
	CT (CKM_SHA512, "sha512")
	CT (CKM_SHA512_HMAC, "sha512-hmac")
	CT (CKM_SHA512_HMAC_GENERAL, "sha512-hmac-general")
	CT (CKM_CAST_KEY_GEN, "cast-key-gen")
	CT (CKM_CAST_ECB, "cast-ecb")
	CT (CKM_CAST_CBC, "cast-cbc")
	CT (CKM_CAST_MAC, "cast-mac")
	CT (CKM_CAST_MAC_GENERAL, "cast-mac-general")
	CT (CKM_CAST_CBC_PAD, "cast-cbc-pad")
	CT (CKM_CAST3_KEY_GEN, "cast3-key-gen")
	CT (CKM_CAST3_ECB, "cast3-ecb")
	CT (CKM_CAST3_CBC, "cast3-cbc")
	CT (CKM_CAST3_MAC, "cast3-mac")
	CT (CKM_CAST3_MAC_GENERAL, "cast3-mac-general")
	CT (CKM_CAST3_CBC_PAD, "cast3-cbc-pad")
	CT (CKM_CAST5_KEY_GEN, "cast5-key-gen")
	/* CT (CKM_CAST128_KEY_GEN) */
	CT (CKM_CAST5_ECB, "cast5-ecb")
	/* CT (CKM_CAST128_ECB) */
	CT (CKM_CAST5_CBC, "cast5-cbc")
	/* CT (CKM_CAST128_CBC) */
	CT (CKM_CAST5_MAC, "cast5-mac")
	/* CT (CKM_CAST128_MAC) */
	CT (CKM_CAST5_MAC_GENERAL, "cast5-mac-general")
	/* CT (CKM_CAST128_MAC_GENERAL) */
	CT (CKM_CAST5_CBC_PAD, "cast5-cbc-pad")
	/* CT (CKM_CAST128_CBC_PAD) */
	CT (CKM_RC5_KEY_GEN, "rc5-key-gen")
	CT (CKM_RC5_ECB, "rc5-ecb")
	CT (CKM_RC5_CBC, "rc5-cbc")
	CT (CKM_RC5_MAC, "rc5-mac")
	CT (CKM_RC5_MAC_GENERAL, "rc5-mac-general")
	CT (CKM_RC5_CBC_PAD, "rc5-cbc-pad")
	CT (CKM_IDEA_KEY_GEN, "idea-key-gen")
	CT (CKM_IDEA_ECB, "idea-ecb")
	CT (CKM_IDEA_CBC, "idea-cbc")
	CT (CKM_IDEA_MAC, "idea-mac")
	CT (CKM_IDEA_MAC_GENERAL, "idea-mac-general")
	CT (CKM_IDEA_CBC_PAD, "idea-cbc-pad")
	CT (CKM_GENERIC_SECRET_KEY_GEN, "generic-secret-key-gen")
	CT (CKM_CONCATENATE_BASE_AND_KEY, "concatenate-base-and-key")
	CT (CKM_CONCATENATE_BASE_AND_DATA, "concatenate-base-and-data")
	CT (CKM_CONCATENATE_DATA_AND_BASE, "concatenate-data-and-base")
	CT (CKM_XOR_BASE_AND_DATA, "xor-base-and-data")
	CT (CKM_EXTRACT_KEY_FROM_KEY, "extract-key-from-key")
	CT (CKM_SSL3_PRE_MASTER_KEY_GEN, "ssl3-pre-master-key-gen")
	CT (CKM_SSL3_MASTER_KEY_DERIVE, "ssl3-master-key-derive")
	CT (CKM_SSL3_KEY_AND_MAC_DERIVE, "ssl3-key-and-mac-derive")
	CT (CKM_SSL3_MASTER_KEY_DERIVE_DH, "ssl3-master-key-derive-dh")
	CT (CKM_TLS_PRE_MASTER_KEY_GEN, "tls-pre-master-key-gen")
	CT (CKM_TLS_MASTER_KEY_DERIVE, "tls-master-key-derive")
	CT (CKM_TLS_KEY_AND_MAC_DERIVE, "tls-key-and-mac-derive")
	CT (CKM_TLS_MASTER_KEY_DERIVE_DH, "tls-master-key-derive-dh")
	/* CT (CKM_TLS_PRF) */
	CT (CKM_SSL3_MD5_MAC, "ssl3-md5-mac")
	CT (CKM_SSL3_SHA1_MAC, "ssl3-sha1-mac")
	CT (CKM_MD5_KEY_DERIVATION, "md5-key-derivation")
	CT (CKM_MD2_KEY_DERIVATION, "md2-key-derivation")
	CT (CKM_SHA1_KEY_DERIVATION, "sha1-key-derivation")
	CT (CKM_SHA256_KEY_DERIVATION, "sha256-key-derivation")
	CT (CKM_SHA384_KEY_DERIVATION, "sha384-key-derivation")
	CT (CKM_SHA512_KEY_DERIVATION, "sha512-key-derivation")
	CT (CKM_PBE_MD2_DES_CBC, "pbe-md2-des-cbc")
	CT (CKM_PBE_MD5_DES_CBC, "pbe-md5-des-cbc")
	CT (CKM_PBE_MD5_CAST_CBC, "pbe-md5-cast-cbc")
	CT (CKM_PBE_MD5_CAST3_CBC, "pbe-md5-cast3-cbc")
	CT (CKM_PBE_MD5_CAST5_CBC, "pbe-md5-cast5-cbc")
	/* CT (CKM_PBE_MD5_CAST128_CBC) */
	CT (CKM_PBE_SHA1_CAST5_CBC, "pbe-sha1-cast5-cbc")
	/* CT (CKM_PBE_SHA1_CAST128_CBC) */
	CT (CKM_PBE_SHA1_RC4_128, "pbe-sha1-rc4-128")
	CT (CKM_PBE_SHA1_RC4_40, "pbe-sha1-rc4-40")
	CT (CKM_PBE_SHA1_DES3_EDE_CBC, "pbe-sha1-des3-ede-cbc")
	CT (CKM_PBE_SHA1_DES2_EDE_CBC, "pbe-sha1-des2-ede-cbc")
	CT (CKM_PBE_SHA1_RC2_128_CBC, "pbe-sha1-rc2-128-cbc")
	CT (CKM_PBE_SHA1_RC2_40_CBC, "pbe-sha1-rc2-40-cbc")
	CT (CKM_PKCS5_PBKD2, "pkcs5-pbkd2")
	CT (CKM_PBA_SHA1_WITH_SHA1_HMAC, "pba-sha1-with-sha1-hmac")
	CT (CKM_WTLS_PRE_MASTER_KEY_GEN, "wtls-pre-master-key-gen")
	CT (CKM_WTLS_MASTER_KEY_DERIVE, "wtls-master-key-derive")
	CT (CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC, "wtls-master-key-derive-dh-ecc")
	CT (CKM_WTLS_PRF, "wtls-prf")
	CT (CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE, "wtls-server-key-and-mac-derive")
	CT (CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE, "wtls-client-key-and-mac-derive")
	CT (CKM_KEY_WRAP_LYNKS, "key-wrap-lynks")
	CT (CKM_KEY_WRAP_SET_OAEP, "key-wrap-set-oaep")
	CT (CKM_CMS_SIG, "cms-sig")
	CT (CKM_SKIPJACK_KEY_GEN, "skipjack-key-gen")
	CT (CKM_SKIPJACK_ECB64, "skipjack-ecb64")
	CT (CKM_SKIPJACK_CBC64, "skipjack-cbc64")
	CT (CKM_SKIPJACK_OFB64, "skipjack-ofb64")
	CT (CKM_SKIPJACK_CFB64, "skipjack-cfb64")
	CT (CKM_SKIPJACK_CFB32, "skipjack-cfb32")
	CT (CKM_SKIPJACK_CFB16, "skipjack-cfb16")
	CT (CKM_SKIPJACK_CFB8, "skipjack-cfb8")
	CT (CKM_SKIPJACK_WRAP, "skipjack-wrap")
	CT (CKM_SKIPJACK_PRIVATE_WRAP, "skipjack-private-wrap")
	CT (CKM_SKIPJACK_RELAYX, "skipjack-relayx")
	CT (CKM_KEA_KEY_PAIR_GEN, "kea-key-pair-gen")
	CT (CKM_KEA_KEY_DERIVE, "kea-key-derive")
	CT (CKM_FORTEZZA_TIMESTAMP, "fortezza-timestamp")
	CT (CKM_BATON_KEY_GEN, "baton-key-gen")
	CT (CKM_BATON_ECB128, "baton-ecb128")
	CT (CKM_BATON_ECB96, "baton-ecb96")
	CT (CKM_BATON_CBC128, "baton-cbc128")
	CT (CKM_BATON_COUNTER, "baton-counter")
	CT (CKM_BATON_SHUFFLE, "baton-shuffle")
	CT (CKM_BATON_WRAP, "baton-wrap")
	CT (CKM_ECDSA_KEY_PAIR_GEN, "ecdsa-key-pair-gen")
	/* CT (CKM_EC_KEY_PAIR_GEN) */
	CT (CKM_ECDSA, "ecdsa")
	CT (CKM_ECDSA_SHA1, "ecdsa-sha1")
	CT (CKM_ECDH1_DERIVE, "ecdh1-derive")
	CT (CKM_ECDH1_COFACTOR_DERIVE, "ecdh1-cofactor-derive")
	CT (CKM_ECMQV_DERIVE, "ecmqv-derive")
	CT (CKM_JUNIPER_KEY_GEN, "juniper-key-gen")
	CT (CKM_JUNIPER_ECB128, "juniper-ecb128")
	CT (CKM_JUNIPER_CBC128, "juniper-cbc128")
	CT (CKM_JUNIPER_COUNTER, "juniper-counter")
	CT (CKM_JUNIPER_SHUFFLE, "juniper-shuffle")
	CT (CKM_JUNIPER_WRAP, "juniper-wrap")
	CT (CKM_FASTHASH, "fasthash")
	CT (CKM_AES_KEY_GEN, "aes-key-gen")
	CT (CKM_AES_ECB, "aes-ecb")
	CT (CKM_AES_CBC, "aes-cbc")
	CT (CKM_AES_MAC, "aes-mac")
	CT (CKM_AES_MAC_GENERAL, "aes-mac-general")
	CT (CKM_AES_CBC_PAD, "aes-cbc-pad")
	CT (CKM_BLOWFISH_KEY_GEN, "blowfish-key-gen")
	CT (CKM_BLOWFISH_CBC, "blowfish-cbc")
	CT (CKM_TWOFISH_KEY_GEN, "twofish-key-gen")
	CT (CKM_TWOFISH_CBC, "twofish-cbc")
	CT (CKM_DES_ECB_ENCRYPT_DATA, "des-ecb-encrypt-data")
	CT (CKM_DES_CBC_ENCRYPT_DATA, "des-cbc-encrypt-data")
	CT (CKM_DES3_ECB_ENCRYPT_DATA, "des3-ecb-encrypt-data")
	CT (CKM_DES3_CBC_ENCRYPT_DATA, "des3-cbc-encrypt-data")
	CT (CKM_AES_ECB_ENCRYPT_DATA, "aes-ecb-encrypt-data")
	CT (CKM_AES_CBC_ENCRYPT_DATA, "aes-cbc-encrypt-data")
	CT (CKM_DSA_PARAMETER_GEN, "dsa-parameter-gen")
	CT (CKM_DH_PKCS_PARAMETER_GEN, "dh-pkcs-parameter-gen")
	CT (CKM_X9_42_DH_PARAMETER_GEN, "x9-42-dh-parameter-gen")
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
	{ p11_constant_categories, ELEMS (p11_constant_categories) - 1 },
	{ p11_constant_mechanisms, ELEMS (p11_constant_mechanisms) - 1 },
	{ p11_constant_states, ELEMS (p11_constant_states) - 1 },
	{ p11_constant_users, ELEMS (p11_constant_users) - 1 },
	{ p11_constant_returns, ELEMS (p11_constant_returns) - 1 },
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
	p11_constant match = { type, NULL, { NULL } };
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
	return constant ? constant->nicks[0] : NULL;
}

p11_dict *
p11_constant_reverse (bool nick)
{
	const p11_constant *table;
	p11_dict *lookups;
	int length = -1;
	int i, j, k;

	lookups = p11_dict_new (p11_dict_str_hash, p11_dict_str_equal, NULL, NULL);
	return_val_if_fail (lookups != NULL, NULL);

	for (i = 0; i < ELEMS (tables); i++) {
		table = tables[i].table;
		length = tables[i].length;

		for (j = 0; j < length; j++) {
			if (nick) {
				for (k = 0; table[j].nicks[k] != NULL; k++) {
					if (!p11_dict_set (lookups, (void *)table[j].nicks[k],
					                   (void *)&table[j].value))
						return_val_if_reached (NULL);
				}
			} else {
				if (!p11_dict_set (lookups, (void *)table[j].name, (void *)&table[j].value))
					return_val_if_reached (NULL);
			}
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
