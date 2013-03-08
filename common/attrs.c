/*
 * Copyright (C) 2012, Redhat Inc.
 * Copyright (c) 2011, Collabora Ltd.
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
 * Author: Stef Walter <stefw@collabora.co.uk>
 */

#include "config.h"

#include "attrs.h"
#include "buffer.h"
#include "compat.h"
#include "debug.h"
#include "pkcs11.h"
#include "pkcs11x.h"

#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

bool
p11_attrs_is_empty (const CK_ATTRIBUTE *attrs)
{
	return (attrs == NULL || attrs->type == CKA_INVALID);
}

CK_ULONG
p11_attrs_count (const CK_ATTRIBUTE *attrs)
{
	CK_ULONG count;

	if (attrs == NULL)
		return 0UL;

	for (count = 0; !p11_attrs_is_empty (attrs); count++, attrs++);

	return count;
}

void
p11_attrs_free (void *attrs)
{
	CK_ATTRIBUTE *ats = attrs;
	int i;

	if (!attrs)
		return;

	for (i = 0; !p11_attrs_is_empty (ats + i); i++)
		free (ats[i].pValue);
	free (ats);
}

static CK_ATTRIBUTE *
attrs_build (CK_ATTRIBUTE *attrs,
             CK_ULONG count_to_add,
             bool copy,
             CK_ATTRIBUTE * (*generator) (void *),
             void *state)
{
	CK_ATTRIBUTE *attr;
	CK_ATTRIBUTE *add;
	CK_ULONG current;
	CK_ULONG at;
	CK_ULONG j;
	CK_ULONG i;

	/* How many attributes we already have */
	current = p11_attrs_count (attrs);

	/* Reallocate for how many we need */
	attrs = realloc (attrs, (current + count_to_add + 1) * sizeof (CK_ATTRIBUTE));
	return_val_if_fail (attrs != NULL, NULL);

	at = current;
	for (i = 0; i < count_to_add; i++) {
		add = (generator) (state);

		/* Skip with invalid type */
		if (!add || add->type == CKA_INVALID)
			continue;

		attr = NULL;

		/* Do we have this attribute? */
		for (j = 0; attr == NULL && j < current; j++) {
			if (attrs[j].type == add->type) {
				attr = attrs + j;
				free (attrs[j].pValue);
				break;
			}
		}

		if (attr == NULL) {
			attr = attrs + at;
			at++;
		}

		memcpy (attr, add, sizeof (CK_ATTRIBUTE));
		if (copy)
			attr->pValue = memdup (attr->pValue, attr->ulValueLen);
	}

	/* Mark this as the end */
	(attrs + at)->type = CKA_INVALID;
	assert (p11_attrs_is_empty (attrs + at));
	return attrs;
}

static CK_ATTRIBUTE *
vararg_generator (void *state)
{
	va_list *va = state;
	return va_arg (*va, CK_ATTRIBUTE *);
}

CK_ATTRIBUTE *
p11_attrs_build (CK_ATTRIBUTE *attrs,
                 ...)
{
	CK_ULONG count;
	va_list va;

	count = 0UL;
	va_start (va, attrs);
	while (va_arg (va, CK_ATTRIBUTE *))
		count++;
	va_end (va);

	va_start (va, attrs);
	attrs = attrs_build (attrs, count, true, vararg_generator, &va);
	va_end (va);

	return attrs;
}

static CK_ATTRIBUTE *
template_generator (void *state)
{
	CK_ATTRIBUTE **template = state;
	return (*template)++;
}

CK_ATTRIBUTE *
p11_attrs_buildn (CK_ATTRIBUTE *attrs,
                  const CK_ATTRIBUTE *add,
                  CK_ULONG count)
{
	return attrs_build (attrs, count, true, template_generator, &add);
}

CK_ATTRIBUTE *
p11_attrs_take (CK_ATTRIBUTE *attrs,
                CK_ATTRIBUTE_TYPE type,
                CK_VOID_PTR value,
                CK_ULONG length)
{
	CK_ATTRIBUTE attr = { type, value, length };
	CK_ATTRIBUTE *add = &attr;
	return attrs_build (attrs, 1, false, template_generator, &add);
}

CK_ATTRIBUTE *
p11_attrs_dup (const CK_ATTRIBUTE *attrs)
{
	CK_ULONG count;

	count = p11_attrs_count (attrs);
	return p11_attrs_buildn (NULL, attrs, count);
}

CK_ATTRIBUTE *
p11_attrs_find (CK_ATTRIBUTE *attrs,
                CK_ATTRIBUTE_TYPE type)
{
	CK_ULONG i;

	for (i = 0; !p11_attrs_is_empty (attrs + i); i++) {
		if (attrs[i].type == type)
			return attrs + i;
	}

	return NULL;
}

CK_ATTRIBUTE *
p11_attrs_findn (CK_ATTRIBUTE *attrs,
                 CK_ULONG count,
                 CK_ATTRIBUTE_TYPE type)
{
	CK_ULONG i;

	for (i = 0; i < count; i++) {
		if (attrs[i].type == type)
			return attrs + i;
	}

	return NULL;
}

bool
p11_attrs_find_bool (CK_ATTRIBUTE *attrs,
                     CK_ATTRIBUTE_TYPE type,
                     CK_BBOOL *value)
{
	CK_ULONG i;

	for (i = 0; !p11_attrs_is_empty (attrs + i); i++) {
		if (attrs[i].type == type &&
		    attrs[i].ulValueLen == sizeof (CK_BBOOL) &&
		    attrs[i].pValue != NULL) {
			*value = *((CK_BBOOL *)attrs[i].pValue);
			return true;
		}
	}

	return false;
}

bool
p11_attrs_findn_bool (CK_ATTRIBUTE *attrs,
                      CK_ULONG count,
                      CK_ATTRIBUTE_TYPE type,
                      CK_BBOOL *value)
{
	CK_ULONG i;

	for (i = 0; i < count; i++) {
		if (attrs[i].type == type &&
		    attrs[i].ulValueLen == sizeof (CK_BBOOL) &&
		    attrs[i].pValue != NULL) {
			*value = *((CK_BBOOL *)attrs[i].pValue);
			return true;
		}
	}

	return false;
}

bool
p11_attrs_find_ulong (CK_ATTRIBUTE *attrs,
                      CK_ATTRIBUTE_TYPE type,
                      CK_ULONG *value)
{
	CK_ULONG i;

	for (i = 0; !p11_attrs_is_empty (attrs + i); i++) {
		if (attrs[i].type == type &&
		    attrs[i].ulValueLen == sizeof (CK_ULONG) &&
		    attrs[i].pValue != NULL) {
			*value = *((CK_ULONG *)attrs[i].pValue);
			return true;
		}
	}

	return false;
}

bool
p11_attrs_findn_ulong (CK_ATTRIBUTE *attrs,
                       CK_ULONG count,
                       CK_ATTRIBUTE_TYPE type,
                       CK_ULONG *value)
{
	CK_ULONG i;

	for (i = 0; i < count; i++) {
		if (attrs[i].type == type &&
		    attrs[i].ulValueLen == sizeof (CK_ULONG) &&
		    attrs[i].pValue != NULL) {
			*value = *((CK_ULONG *)attrs[i].pValue);
			return true;
		}
	}

	return false;
}

CK_ATTRIBUTE *
p11_attrs_find_valid (CK_ATTRIBUTE *attrs,
                      CK_ATTRIBUTE_TYPE type)
{
	CK_ULONG i;

	for (i = 0; !p11_attrs_is_empty (attrs + i); i++) {
		if (attrs[i].type == type &&
		    attrs[i].ulValueLen != (CK_ULONG)-1)
			return attrs + i;
	}

	return NULL;
}

CK_ATTRIBUTE *
p11_attrs_findn_valid (CK_ATTRIBUTE *attrs,
                       CK_ULONG count,
                       CK_ATTRIBUTE_TYPE type)
{
	CK_ULONG i;

	for (i = 0; i < count; i++) {
		if (attrs[i].type == type &&
		    attrs[i].ulValueLen != (CK_ULONG)-1)
			return attrs + i;
	}

	return NULL;
}

bool
p11_attrs_remove (CK_ATTRIBUTE *attrs,
                  CK_ATTRIBUTE_TYPE type)
{
	CK_ULONG count;
	CK_ULONG i;

	count = p11_attrs_count (attrs);
	for (i = 0; i < count; i++) {
		if (attrs[i].type == type)
			break;
	}

	if (i == count)
		return false;

	if (attrs[i].pValue)
		free (attrs[i].pValue);

	memmove (attrs + i, attrs + i + 1, (count - (i + 1)) * sizeof (CK_ATTRIBUTE));
	attrs[count - 1].type = CKA_INVALID;
	return true;
}

bool
p11_attrs_match (const CK_ATTRIBUTE *attrs,
                 const CK_ATTRIBUTE *match)
{
	CK_ATTRIBUTE *attr;

	for (; !p11_attrs_is_empty (match); match++) {
		attr = p11_attrs_find ((CK_ATTRIBUTE *)attrs, match->type);
		if (!attr)
			return false;
		if (!p11_attr_equal (attr, match))
			return false;
	}

	return true;
}

bool
p11_attrs_matchn (const CK_ATTRIBUTE *attrs,
                  const CK_ATTRIBUTE *match,
                  CK_ULONG count)
{
	CK_ATTRIBUTE *attr;
	CK_ULONG i;

	for (i = 0; i < count; i++) {
		attr = p11_attrs_find ((CK_ATTRIBUTE *)attrs, match[i].type);
		if (!attr)
			return false;
		if (!p11_attr_equal (attr, match + i))
			return false;
	}

	return true;

}


bool
p11_attr_match_value (const CK_ATTRIBUTE *attr,
                      const void *value,
                      ssize_t length)
{
	if (length < 0)
		length = strlen (value);
	return (attr != NULL &&
	        attr->ulValueLen == length &&
	        (attr->pValue == value ||
	         (attr->pValue && value &&
	          memcmp (attr->pValue, value, attr->ulValueLen) == 0)));
}

bool
p11_attr_equal (const void *v1,
                const void *v2)
{
	const CK_ATTRIBUTE *one = v1;
	const CK_ATTRIBUTE *two = v2;

	return (one == two ||
		(one && two && one->type == two->type &&
		 p11_attr_match_value (one, two->pValue, two->ulValueLen)));
}

unsigned int
p11_attr_hash (const void *data)
{
	const CK_ATTRIBUTE *attr = data;
	unsigned int hash = (unsigned int)attr->type;
	const char *p, *end;

	for (p = attr->pValue, end = p + attr->ulValueLen ; p != NULL && p != end; p++)
		hash = (hash << 5) - hash + *p;

	return hash;
}

static void
buffer_append_printf (p11_buffer *buffer,
                      const char *format,
                      ...)
{
	char *string;
	va_list va;

	va_start (va, format);
	if (vasprintf (&string, format, va) < 0)
		return_if_reached ();
	va_end (va);

	p11_buffer_add (buffer, string, -1);
	free (string);
}

static bool
attribute_is_ulong_of_type (const CK_ATTRIBUTE *attr,
                            CK_ULONG type)
{
	if (attr->type != type)
		return false;
	if (attr->ulValueLen != sizeof (CK_ULONG))
		return false;
	if (!attr->pValue)
		return false;
	return true;
}

static bool
attribute_is_trust_value (const CK_ATTRIBUTE *attr)
{
	switch (attr->type) {
	case CKA_TRUST_DIGITAL_SIGNATURE:
	case CKA_TRUST_NON_REPUDIATION:
	case CKA_TRUST_KEY_ENCIPHERMENT:
	case CKA_TRUST_DATA_ENCIPHERMENT:
	case CKA_TRUST_KEY_AGREEMENT:
	case CKA_TRUST_KEY_CERT_SIGN:
	case CKA_TRUST_CRL_SIGN:
	case CKA_TRUST_SERVER_AUTH:
	case CKA_TRUST_CLIENT_AUTH:
	case CKA_TRUST_CODE_SIGNING:
	case CKA_TRUST_EMAIL_PROTECTION:
	case CKA_TRUST_IPSEC_END_SYSTEM:
	case CKA_TRUST_IPSEC_TUNNEL:
	case CKA_TRUST_IPSEC_USER:
	case CKA_TRUST_TIME_STAMPING:
		break;
	default:
		return false;
	}

	return attribute_is_ulong_of_type (attr, attr->type);
}

static bool
attribute_is_sensitive (const CK_ATTRIBUTE *attr)
{
	/*
	 * Don't print any just attribute, since they may contain
	 * sensitive data
	 */

	switch (attr->type) {
	#define X(x) case x: return false;
	X (CKA_CLASS)
	X (CKA_TOKEN)
	X (CKA_PRIVATE)
	X (CKA_LABEL)
	X (CKA_APPLICATION)
	X (CKA_OBJECT_ID)
	X (CKA_CERTIFICATE_TYPE)
	X (CKA_ISSUER)
	X (CKA_SERIAL_NUMBER)
	X (CKA_AC_ISSUER)
	X (CKA_OWNER)
	X (CKA_ATTR_TYPES)
	X (CKA_TRUSTED)
	X (CKA_CERTIFICATE_CATEGORY)
	X (CKA_JAVA_MIDP_SECURITY_DOMAIN)
	X (CKA_URL)
	X (CKA_HASH_OF_SUBJECT_PUBLIC_KEY)
	X (CKA_HASH_OF_ISSUER_PUBLIC_KEY)
	X (CKA_CHECK_VALUE)
	X (CKA_KEY_TYPE)
	X (CKA_SUBJECT)
	X (CKA_ID)
	X (CKA_SENSITIVE)
	X (CKA_ENCRYPT)
	X (CKA_DECRYPT)
	X (CKA_WRAP)
	X (CKA_UNWRAP)
	X (CKA_SIGN)
	X (CKA_SIGN_RECOVER)
	X (CKA_VERIFY)
	X (CKA_VERIFY_RECOVER)
	X (CKA_DERIVE)
	X (CKA_START_DATE)
	X (CKA_END_DATE)
	X (CKA_MODULUS_BITS)
	X (CKA_PRIME_BITS)
	/* X (CKA_SUBPRIME_BITS) */
	/* X (CKA_SUB_PRIME_BITS) */
	X (CKA_VALUE_BITS)
	X (CKA_VALUE_LEN)
	X (CKA_EXTRACTABLE)
	X (CKA_LOCAL)
	X (CKA_NEVER_EXTRACTABLE)
	X (CKA_ALWAYS_SENSITIVE)
	X (CKA_KEY_GEN_MECHANISM)
	X (CKA_MODIFIABLE)
	X (CKA_SECONDARY_AUTH)
	X (CKA_AUTH_PIN_FLAGS)
	X (CKA_ALWAYS_AUTHENTICATE)
	X (CKA_WRAP_WITH_TRUSTED)
	X (CKA_WRAP_TEMPLATE)
	X (CKA_UNWRAP_TEMPLATE)
	X (CKA_HW_FEATURE_TYPE)
	X (CKA_RESET_ON_INIT)
	X (CKA_HAS_RESET)
	X (CKA_PIXEL_X)
	X (CKA_PIXEL_Y)
	X (CKA_RESOLUTION)
	X (CKA_CHAR_ROWS)
	X (CKA_CHAR_COLUMNS)
	X (CKA_COLOR)
	X (CKA_BITS_PER_PIXEL)
	X (CKA_CHAR_SETS)
	X (CKA_ENCODING_METHODS)
	X (CKA_MIME_TYPES)
	X (CKA_MECHANISM_TYPE)
	X (CKA_REQUIRED_CMS_ATTRIBUTES)
	X (CKA_DEFAULT_CMS_ATTRIBUTES)
	X (CKA_SUPPORTED_CMS_ATTRIBUTES)
	X (CKA_ALLOWED_MECHANISMS)
	X (CKA_X_ASSERTION_TYPE)
	X (CKA_X_CERTIFICATE_VALUE)
	X (CKA_X_PURPOSE)
	X (CKA_X_PEER)
	X (CKA_X_DISTRUSTED)
	X (CKA_X_CRITICAL)
	X (CKA_NSS_URL)
	X (CKA_NSS_EMAIL)
	X (CKA_NSS_SMIME_INFO)
	X (CKA_NSS_SMIME_TIMESTAMP)
	X (CKA_NSS_PKCS8_SALT)
	X (CKA_NSS_PASSWORD_CHECK)
	X (CKA_NSS_EXPIRES)
	X (CKA_NSS_KRL)
	X (CKA_NSS_PQG_COUNTER)
	X (CKA_NSS_PQG_SEED)
	X (CKA_NSS_PQG_H)
	X (CKA_NSS_PQG_SEED_BITS)
	X (CKA_NSS_MODULE_SPEC)
	X (CKA_TRUST_DIGITAL_SIGNATURE)
	X (CKA_TRUST_NON_REPUDIATION)
	X (CKA_TRUST_KEY_ENCIPHERMENT)
	X (CKA_TRUST_DATA_ENCIPHERMENT)
	X (CKA_TRUST_KEY_AGREEMENT)
	X (CKA_TRUST_KEY_CERT_SIGN)
	X (CKA_TRUST_CRL_SIGN)
	X (CKA_TRUST_SERVER_AUTH)
	X (CKA_TRUST_CLIENT_AUTH)
	X (CKA_TRUST_CODE_SIGNING)
	X (CKA_TRUST_EMAIL_PROTECTION)
	X (CKA_TRUST_IPSEC_END_SYSTEM)
	X (CKA_TRUST_IPSEC_TUNNEL)
	X (CKA_TRUST_IPSEC_USER)
	X (CKA_TRUST_TIME_STAMPING)
	X (CKA_TRUST_STEP_UP_APPROVED)
	X (CKA_CERT_SHA1_HASH)
	X (CKA_CERT_MD5_HASH)
	#undef X
	}

	return true;
}

static void
format_class (p11_buffer *buffer,
              CK_OBJECT_CLASS klass)
{
	const char *string = NULL;

	switch (klass) {
	#define X(x) case x: string = #x; break;
	X (CKO_DATA)
	X (CKO_CERTIFICATE)
	X (CKO_PUBLIC_KEY)
	X (CKO_PRIVATE_KEY)
	X (CKO_SECRET_KEY)
	X (CKO_HW_FEATURE)
	X (CKO_DOMAIN_PARAMETERS)
	X (CKO_MECHANISM)
	X (CKO_X_TRUST_ASSERTION)
	X (CKO_X_CERTIFICATE_EXTENSION)
	X (CKO_NSS_CRL)
	X (CKO_NSS_SMIME)
	X (CKO_NSS_TRUST)
	X (CKO_NSS_BUILTIN_ROOT_LIST)
	X (CKO_NSS_NEWSLOT)
	X (CKO_NSS_DELSLOT)
	#undef X
	}

	if (string != NULL)
		p11_buffer_add (buffer, string, -1);
	else
		buffer_append_printf (buffer, "0x%08lX", klass);
}

static void
format_assertion_type (p11_buffer *buffer,
                       CK_X_ASSERTION_TYPE type)
{
	const char *string = NULL;

	switch (type) {
	#define X(x) case x: string = #x; break;
	X (CKT_X_DISTRUSTED_CERTIFICATE)
	X (CKT_X_PINNED_CERTIFICATE)
	X (CKT_X_ANCHORED_CERTIFICATE)
	#undef X
	}

	if (string != NULL)
		p11_buffer_add (buffer, string, -1);
	else
		buffer_append_printf (buffer, "0x%08lX", type);
}

static void
format_key_type (p11_buffer *buffer,
                 CK_KEY_TYPE type)
{
	const char *string = NULL;

	switch (type) {
	#define X(x) case x: string = #x; break;
	X (CKK_RSA)
	X (CKK_DSA)
	X (CKK_DH)
	/* X (CKK_ECDSA) */
	X (CKK_EC)
	X (CKK_X9_42_DH)
	X (CKK_KEA)
	X (CKK_GENERIC_SECRET)
	X (CKK_RC2)
	X (CKK_RC4)
	X (CKK_DES)
	X (CKK_DES2)
	X (CKK_DES3)
	X (CKK_CAST)
	X (CKK_CAST3)
	X (CKK_CAST128)
	X (CKK_RC5)
	X (CKK_IDEA)
	X (CKK_SKIPJACK)
	X (CKK_BATON)
	X (CKK_JUNIPER)
	X (CKK_CDMF)
	X (CKK_AES)
	X (CKK_BLOWFISH)
	X (CKK_TWOFISH)
	X (CKK_NSS_PKCS8)
	#undef X
	}

	if (string != NULL)
		p11_buffer_add (buffer, string, -1);
	else
		buffer_append_printf (buffer, "0x%08lX", type);
}

static void
format_certificate_type (p11_buffer *buffer,
                         CK_CERTIFICATE_TYPE type)
{
	const char *string = NULL;

	switch (type) {
	#define X(x) case x: string = #x; break;
	X (CKC_X_509)
	X (CKC_X_509_ATTR_CERT)
	X (CKC_WTLS)
	}

	if (string != NULL)
		p11_buffer_add (buffer, string, -1);
	else
		buffer_append_printf (buffer, "0x%08lX", type);
}

static void
format_trust_value (p11_buffer *buffer,
                    CK_TRUST trust)
{
	const char *string = NULL;

	switch (trust) {
	#define X(x) case x: string = #x; break;
	X (CKT_NSS_TRUSTED)
	X (CKT_NSS_TRUSTED_DELEGATOR)
	X (CKT_NSS_NOT_TRUSTED)
	X (CKT_NSS_MUST_VERIFY_TRUST)
	X (CKT_NSS_TRUST_UNKNOWN)
	}

	if (string != NULL)
		p11_buffer_add (buffer, string, -1);
	else
		buffer_append_printf (buffer, "0x%08lX", trust);
}

static void
format_certificate_category (p11_buffer *buffer,
                             CK_ULONG category)
{
	const char *string = NULL;

	switch (category) {
	case 0:
		string = "unspecified";
		break;
	case 1:
		string = "token-user";
		break;
	case 2:
		string = "authority";
		break;
	case 3:
		string = "other-entry";
		break;
	}

	if (string != NULL)
		buffer_append_printf (buffer, "%lu (%s)", category, string);
	else
		buffer_append_printf (buffer, "%lu", category);
}

static void
format_attribute_type (p11_buffer *buffer,
                       CK_ULONG type)
{
	const char *string = NULL;

	switch (type) {
	#define X(x) case x: string = #x; break;
	X (CKA_CLASS)
	X (CKA_TOKEN)
	X (CKA_PRIVATE)
	X (CKA_LABEL)
	X (CKA_APPLICATION)
	X (CKA_VALUE)
	X (CKA_OBJECT_ID)
	X (CKA_CERTIFICATE_TYPE)
	X (CKA_ISSUER)
	X (CKA_SERIAL_NUMBER)
	X (CKA_AC_ISSUER)
	X (CKA_OWNER)
	X (CKA_ATTR_TYPES)
	X (CKA_TRUSTED)
	X (CKA_CERTIFICATE_CATEGORY)
	X (CKA_JAVA_MIDP_SECURITY_DOMAIN)
	X (CKA_URL)
	X (CKA_HASH_OF_SUBJECT_PUBLIC_KEY)
	X (CKA_HASH_OF_ISSUER_PUBLIC_KEY)
	X (CKA_CHECK_VALUE)
	X (CKA_KEY_TYPE)
	X (CKA_SUBJECT)
	X (CKA_ID)
	X (CKA_SENSITIVE)
	X (CKA_ENCRYPT)
	X (CKA_DECRYPT)
	X (CKA_WRAP)
	X (CKA_UNWRAP)
	X (CKA_SIGN)
	X (CKA_SIGN_RECOVER)
	X (CKA_VERIFY)
	X (CKA_VERIFY_RECOVER)
	X (CKA_DERIVE)
	X (CKA_START_DATE)
	X (CKA_END_DATE)
	X (CKA_MODULUS)
	X (CKA_MODULUS_BITS)
	X (CKA_PUBLIC_EXPONENT)
	X (CKA_PRIVATE_EXPONENT)
	X (CKA_PRIME_1)
	X (CKA_PRIME_2)
	X (CKA_EXPONENT_1)
	X (CKA_EXPONENT_2)
	X (CKA_COEFFICIENT)
	X (CKA_PRIME)
	X (CKA_SUBPRIME)
	X (CKA_BASE)
	X (CKA_PRIME_BITS)
	/* X (CKA_SUBPRIME_BITS) */
	X (CKA_SUB_PRIME_BITS)
	X (CKA_VALUE_BITS)
	X (CKA_VALUE_LEN)
	X (CKA_EXTRACTABLE)
	X (CKA_LOCAL)
	X (CKA_NEVER_EXTRACTABLE)
	X (CKA_ALWAYS_SENSITIVE)
	X (CKA_KEY_GEN_MECHANISM)
	X (CKA_MODIFIABLE)
	X (CKA_ECDSA_PARAMS)
	/* X (CKA_EC_PARAMS) */
	X (CKA_EC_POINT)
	X (CKA_SECONDARY_AUTH)
	X (CKA_AUTH_PIN_FLAGS)
	X (CKA_ALWAYS_AUTHENTICATE)
	X (CKA_WRAP_WITH_TRUSTED)
	X (CKA_WRAP_TEMPLATE)
	X (CKA_UNWRAP_TEMPLATE)
	X (CKA_HW_FEATURE_TYPE)
	X (CKA_RESET_ON_INIT)
	X (CKA_HAS_RESET)
	X (CKA_PIXEL_X)
	X (CKA_PIXEL_Y)
	X (CKA_RESOLUTION)
	X (CKA_CHAR_ROWS)
	X (CKA_CHAR_COLUMNS)
	X (CKA_COLOR)
	X (CKA_BITS_PER_PIXEL)
	X (CKA_CHAR_SETS)
	X (CKA_ENCODING_METHODS)
	X (CKA_MIME_TYPES)
	X (CKA_MECHANISM_TYPE)
	X (CKA_REQUIRED_CMS_ATTRIBUTES)
	X (CKA_DEFAULT_CMS_ATTRIBUTES)
	X (CKA_SUPPORTED_CMS_ATTRIBUTES)
	X (CKA_ALLOWED_MECHANISMS)
	X (CKA_X_ASSERTION_TYPE)
	X (CKA_X_CERTIFICATE_VALUE)
	X (CKA_X_PURPOSE)
	X (CKA_X_PEER)
	X (CKA_X_DISTRUSTED)
	X (CKA_X_CRITICAL)
	X (CKA_NSS_URL)
	X (CKA_NSS_EMAIL)
	X (CKA_NSS_SMIME_INFO)
	X (CKA_NSS_SMIME_TIMESTAMP)
	X (CKA_NSS_PKCS8_SALT)
	X (CKA_NSS_PASSWORD_CHECK)
	X (CKA_NSS_EXPIRES)
	X (CKA_NSS_KRL)
	X (CKA_NSS_PQG_COUNTER)
	X (CKA_NSS_PQG_SEED)
	X (CKA_NSS_PQG_H)
	X (CKA_NSS_PQG_SEED_BITS)
	X (CKA_NSS_MODULE_SPEC)
	X (CKA_TRUST_DIGITAL_SIGNATURE)
	X (CKA_TRUST_NON_REPUDIATION)
	X (CKA_TRUST_KEY_ENCIPHERMENT)
	X (CKA_TRUST_DATA_ENCIPHERMENT)
	X (CKA_TRUST_KEY_AGREEMENT)
	X (CKA_TRUST_KEY_CERT_SIGN)
	X (CKA_TRUST_CRL_SIGN)
	X (CKA_TRUST_SERVER_AUTH)
	X (CKA_TRUST_CLIENT_AUTH)
	X (CKA_TRUST_CODE_SIGNING)
	X (CKA_TRUST_EMAIL_PROTECTION)
	X (CKA_TRUST_IPSEC_END_SYSTEM)
	X (CKA_TRUST_IPSEC_TUNNEL)
	X (CKA_TRUST_IPSEC_USER)
	X (CKA_TRUST_TIME_STAMPING)
	X (CKA_TRUST_STEP_UP_APPROVED)
	X (CKA_CERT_SHA1_HASH)
	X (CKA_CERT_MD5_HASH)
	#undef X
	}

	if (string != NULL)
		p11_buffer_add (buffer, string, -1);
	else
		buffer_append_printf (buffer, "CKA_0x%08lX", type);
}

static void
format_some_bytes (p11_buffer *buffer,
                   void *bytes,
                   CK_ULONG length)
{
	unsigned char ch;
	const unsigned char *data = bytes;
	CK_ULONG i;

	if (bytes == NULL) {
		p11_buffer_add (buffer, "NULL", -1);
		return;
	}

	p11_buffer_add (buffer, "\"", 1);
	for (i = 0; i < length && i < 128; i++) {
		ch = data[i];
		if (ch == '\t')
			p11_buffer_add (buffer, "\\t", -1);
		else if (ch == '\n')
			p11_buffer_add (buffer, "\\n", -1);
		else if (ch == '\r')
			p11_buffer_add (buffer, "\\r", -1);
		else if (ch >= 32 && ch < 127)
			p11_buffer_add (buffer, &ch, 1);
		else
			buffer_append_printf (buffer, "\\x%02x", ch);
	}

	if (i < length)
		buffer_append_printf (buffer, "...");
	p11_buffer_add (buffer, "\"", 1);
}

static void
format_attribute (p11_buffer *buffer,
                  const CK_ATTRIBUTE *attr)
{
	p11_buffer_add (buffer, "{ ", -1);
	format_attribute_type (buffer, attr->type);
	p11_buffer_add (buffer, " = ", -1);
	if (attr->ulValueLen == CKA_INVALID) {
		buffer_append_printf (buffer, "(-1) INVALID");
	} else if (attribute_is_ulong_of_type (attr, CKA_CLASS)) {
		format_class (buffer, *((CK_OBJECT_CLASS *)attr->pValue));
	} else if (attribute_is_ulong_of_type (attr, CKA_X_ASSERTION_TYPE)) {
		format_assertion_type (buffer, *((CK_X_ASSERTION_TYPE *)attr->pValue));
	} else if (attribute_is_ulong_of_type (attr, CKA_CERTIFICATE_TYPE)) {
		format_certificate_type (buffer, *((CK_CERTIFICATE_TYPE *)attr->pValue));
	} else if (attribute_is_ulong_of_type (attr, CKA_CERTIFICATE_CATEGORY)) {
		format_certificate_category (buffer, *((CK_ULONG *)attr->pValue));
	} else if (attribute_is_ulong_of_type (attr, CKA_KEY_TYPE)) {
		format_key_type (buffer, *((CK_KEY_TYPE *)attr->pValue));
	} else if (attribute_is_trust_value (attr)) {
		format_trust_value (buffer, *((CK_TRUST *)attr->pValue));
	} else if (attribute_is_sensitive (attr)) {
		buffer_append_printf (buffer, "(%lu) NOT-PRINTED", attr->ulValueLen);
	} else {
		buffer_append_printf (buffer, "(%lu) ", attr->ulValueLen);
		format_some_bytes (buffer, attr->pValue, attr->ulValueLen);
	}
	p11_buffer_add (buffer, " }", -1);
}

static void
format_attributes (p11_buffer *buffer,
                   const CK_ATTRIBUTE *attrs)
{
	CK_BBOOL first = CK_TRUE;
	int count, i;

	count = p11_attrs_count (attrs);
	buffer_append_printf (buffer, "(%d) [", count);
	for (i = 0; i < count; i++) {
		if (first)
			p11_buffer_add (buffer, " ", 1);
		else
			p11_buffer_add (buffer, ", ", 2);
		first = CK_FALSE;
		format_attribute (buffer, attrs + i);
	}
	p11_buffer_add (buffer, " ]", -1);
}

char *
p11_attrs_to_string (const CK_ATTRIBUTE *attrs)
{
	p11_buffer buffer;
	if (!p11_buffer_init_null (&buffer, 128))
		return_val_if_reached (NULL);
	format_attributes (&buffer, attrs);
	return p11_buffer_steal (&buffer, NULL);
}

char *
p11_attr_to_string (const CK_ATTRIBUTE *attr)
{
	p11_buffer buffer;
	if (!p11_buffer_init_null (&buffer, 32))
		return_val_if_reached (NULL);
	format_attribute (&buffer, attr);
	return p11_buffer_steal (&buffer, NULL);
}
