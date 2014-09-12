/*
 * Copyright (C) 2013 Red Hat Inc.
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

#include "asn1.h"
#include "attrs.h"
#include "constants.h"
#include "debug.h"
#include "lexer.h"
#include "message.h"
#include "pem.h"
#include "persist.h"
#include "pkcs11.h"
#include "pkcs11i.h"
#include "pkcs11x.h"
#include "types.h"
#include "url.h"

#include "basic.asn.h"

#include <libtasn1.h>

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#define PERSIST_HEADER "p11-kit-object-v1"

struct _p11_persist {
	p11_dict *constants;
	node_asn *asn1_defs;
};

bool
p11_persist_magic (const unsigned char *data,
                   size_t length)
{
	return (strnstr ((char *)data, "[" PERSIST_HEADER "]", length) != NULL);
}

p11_persist *
p11_persist_new (void)
{
	p11_persist *persist;

	persist = calloc (1, sizeof (p11_persist));
	return_val_if_fail (persist != NULL, NULL);

	persist->constants = p11_constant_reverse (true);
	return_val_if_fail (persist->constants != NULL, NULL);

	return persist;
}

void
p11_persist_free (p11_persist *persist)
{
	if (!persist)
		return;
	p11_dict_free (persist->constants);
	asn1_delete_structure (&persist->asn1_defs);
	free (persist);
}

struct constant {
	CK_ULONG value;
	const char *string;
};

static bool
parse_string (p11_lexer *lexer,
              CK_ATTRIBUTE *attr)
{
	const char *value;
	const char *end;
	size_t length;
	unsigned char *data;

	value = lexer->tok.field.value;
	end = value + strlen (value);

	/* Not a string/binary value */
	if (value == end || value[0] != '\"' || *(end - 1) != '\"')
		return false;

	/* Note that we don't skip whitespace when decoding, as you might in other URLs */
	data = p11_url_decode (value + 1, end - 1, "", &length);
	if (data == NULL) {
		p11_lexer_msg(lexer, "bad encoding of attribute value");
		return false;
	}

	attr->pValue = data;
	attr->ulValueLen = length;
	return true;
}

static void
format_string (CK_ATTRIBUTE *attr,
               p11_buffer *buf)
{
	const unsigned char *value;

	assert (attr->ulValueLen != CK_UNAVAILABLE_INFORMATION);

	p11_buffer_add (buf, "\"", 1);
	value = attr->pValue;
	p11_url_encode (value, value + attr->ulValueLen, P11_URL_VERBATIM, buf);
	p11_buffer_add (buf, "\"", 1);
}

static bool
parse_bool (p11_lexer *lexer,
            CK_ATTRIBUTE *attr)
{
	const char *value = lexer->tok.field.value;
	CK_BBOOL boolean;

	if (strcmp (value, "true") == 0) {
		boolean = CK_TRUE;

	} else if (strcmp (value, "false") == 0) {
		boolean = CK_FALSE;

	} else {
		/* Not a valid boolean value */
		return false;
	}

	attr->pValue = memdup (&boolean, sizeof (boolean));
	return_val_if_fail (attr != NULL, FALSE);
	attr->ulValueLen = sizeof (boolean);
	return true;
}

static bool
format_bool (CK_ATTRIBUTE *attr,
             p11_buffer *buf)
{
	const CK_BBOOL *value;

	if (attr->ulValueLen != sizeof (CK_BBOOL))
		return false;

	switch (attr->type) {
	case CKA_TOKEN:
	case CKA_PRIVATE:
	case CKA_TRUSTED:
	case CKA_SENSITIVE:
	case CKA_ENCRYPT:
	case CKA_DECRYPT:
	case CKA_WRAP:
	case CKA_UNWRAP:
	case CKA_SIGN:
	case CKA_SIGN_RECOVER:
	case CKA_VERIFY:
	case CKA_VERIFY_RECOVER:
	case CKA_DERIVE:
	case CKA_EXTRACTABLE:
	case CKA_LOCAL:
	case CKA_NEVER_EXTRACTABLE:
	case CKA_ALWAYS_SENSITIVE:
	case CKA_MODIFIABLE:
	case CKA_SECONDARY_AUTH:
	case CKA_ALWAYS_AUTHENTICATE:
	case CKA_WRAP_WITH_TRUSTED:
	case CKA_RESET_ON_INIT:
	case CKA_HAS_RESET:
	case CKA_COLOR:
	case CKA_X_DISTRUSTED:
		break;
	default:
		return false;
	}

	value = attr->pValue;
	if (*value == CK_TRUE)
		p11_buffer_add (buf, "true", -1);
	else if (*value == CK_FALSE)
		p11_buffer_add (buf, "false", -1);
	else
		return false;

	return true;
}

static bool
parse_ulong (p11_lexer *lexer,
             CK_ATTRIBUTE *attr)
{
	unsigned long value;
	char *end;

	end = NULL;
	value = strtoul (lexer->tok.field.value, &end, 10);

	/* Not a valid number value */
	if (!end || *end != '\0')
		return false;

	attr->pValue = memdup (&value, sizeof (CK_ULONG));
	return_val_if_fail (attr->pValue != NULL, false);
	attr->ulValueLen = sizeof (CK_ULONG);
	return true;
}

static bool
format_ulong (CK_ATTRIBUTE *attr,
              p11_buffer *buf)
{
	char string[sizeof (CK_ULONG) * 4];
	const CK_ULONG *value;

	if (attr->ulValueLen != sizeof (CK_ULONG))
		return false;

	switch (attr->type) {
	case CKA_CERTIFICATE_CATEGORY:
	case CKA_CERTIFICATE_TYPE:
	case CKA_CLASS:
	case CKA_JAVA_MIDP_SECURITY_DOMAIN:
	case CKA_KEY_GEN_MECHANISM:
	case CKA_KEY_TYPE:
	case CKA_MECHANISM_TYPE:
	case CKA_MODULUS_BITS:
	case CKA_PRIME_BITS:
	case CKA_SUB_PRIME_BITS:
	case CKA_VALUE_BITS:
	case CKA_VALUE_LEN:
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
	case CKA_TRUST_STEP_UP_APPROVED:
	case CKA_X_ASSERTION_TYPE:
	case CKA_AUTH_PIN_FLAGS:
	case CKA_HW_FEATURE_TYPE:
	case CKA_PIXEL_X:
	case CKA_PIXEL_Y:
	case CKA_RESOLUTION:
	case CKA_CHAR_ROWS:
	case CKA_CHAR_COLUMNS:
	case CKA_BITS_PER_PIXEL:
		break;
	default:
		return false;
	}

	value = attr->pValue;
	snprintf (string, sizeof (string), "%lu", *value);

	p11_buffer_add (buf, string, -1);
	return true;
}

static bool
parse_constant (p11_persist *persist,
                p11_lexer *lexer,
                CK_ATTRIBUTE *attr)
{
	CK_ULONG value;

	value = p11_constant_resolve (persist->constants, lexer->tok.field.value);

	/* Not a valid constant */
	if (value == CKA_INVALID)
		return false;

	attr->pValue = memdup (&value, sizeof (CK_ULONG));
	return_val_if_fail (attr->pValue != NULL, false);
	attr->ulValueLen = sizeof (CK_ULONG);
	return true;
}

static bool
format_constant (CK_ATTRIBUTE *attr,
                 p11_buffer *buf)
{
	const p11_constant *table;
	const CK_ULONG *value;
	const char *nick;

	if (attr->ulValueLen != sizeof (CK_ULONG))
		return false;

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
		table = p11_constant_trusts;
		break;
	case CKA_CLASS:
		table = p11_constant_classes;
		break;
	case CKA_CERTIFICATE_TYPE:
		table = p11_constant_certs;
		break;
	case CKA_KEY_TYPE:
		table = p11_constant_keys;
		break;
	case CKA_X_ASSERTION_TYPE:
		table = p11_constant_asserts;
		break;
	case CKA_CERTIFICATE_CATEGORY:
		table = p11_constant_categories;
		break;
	case CKA_KEY_GEN_MECHANISM:
	case CKA_MECHANISM_TYPE:
		table = p11_constant_mechanisms;
		break;
	default:
		table = NULL;
	};

	if (!table)
		return false;

	value = attr->pValue;
	nick = p11_constant_nick (table, *value);

	if (!nick)
		return false;

	p11_buffer_add (buf, nick, -1);
	return true;
}

static bool
parse_oid (p11_persist *persist,
           p11_lexer *lexer,
           CK_ATTRIBUTE *attr)
{
	char message[ASN1_MAX_ERROR_DESCRIPTION_SIZE] = { 0, };
	node_asn *asn;
	size_t length;
	char *value;
	int ret;

	value = lexer->tok.field.value;
	length = strlen (value);

	/* Not an OID value? */
	if (length < 4 ||
	    strchr (value, '.') == NULL ||
	    strspn (value, "0123456790.") != length ||
	    strstr (value, "..") != NULL ||
	    value[0] == '.' || value[0] == '0' ||
	    value[length - 1] == '.' ||
	    strchr (value, '.') == strrchr (value, '.')) {
		return false;
	}

	if (!persist->asn1_defs) {
		ret = asn1_array2tree (basic_asn1_tab, &persist->asn1_defs, message);
		if (ret != ASN1_SUCCESS) {
			p11_debug_precond ("failed to load BASIC definitions: %s: %s\n",
			                   asn1_strerror (ret), message);
			return false;
		}
	}

	ret = asn1_create_element (persist->asn1_defs, "BASIC.ObjectIdentifier", &asn);
	if (ret != ASN1_SUCCESS) {
		p11_debug_precond ("failed to create ObjectIdentifier element: %s\n",
		                   asn1_strerror (ret));
		return false;
	}

	ret = asn1_write_value (asn, "", value, 1);
	if (ret == ASN1_VALUE_NOT_VALID) {
		p11_lexer_msg (lexer, "invalid oid value");
		asn1_delete_structure (&asn);
		return false;
	}
	return_val_if_fail (ret == ASN1_SUCCESS, false);

	attr->pValue = p11_asn1_encode (asn, &length);
	return_val_if_fail (attr->pValue != NULL, false);
	attr->ulValueLen = length;

	asn1_delete_structure (&asn);
	return true;
}

static bool
format_oid (p11_persist *persist,
            CK_ATTRIBUTE *attr,
            p11_buffer *buf)
{
	char message[ASN1_MAX_ERROR_DESCRIPTION_SIZE] = { 0, };
	node_asn *asn;
	char *data;
	size_t len;
	int ret;

	if (attr->type != CKA_OBJECT_ID || attr->ulValueLen == 0)
		return false;

	if (!persist->asn1_defs) {
		ret = asn1_array2tree (basic_asn1_tab, &persist->asn1_defs, message);
		if (ret != ASN1_SUCCESS) {
			p11_debug_precond ("failed to load BASIC definitions: %s: %s\n",
			                   asn1_strerror (ret), message);
			return false;
		}
	}

	ret = asn1_create_element (persist->asn1_defs, "BASIC.ObjectIdentifier", &asn);
	if (ret != ASN1_SUCCESS) {
		p11_debug_precond ("failed to create ObjectIdentifier element: %s\n",
		                   asn1_strerror (ret));
		return false;
	}

	ret = asn1_der_decoding (&asn, attr->pValue, attr->ulValueLen, message);
	if (ret != ASN1_SUCCESS) {
		p11_message ("invalid oid value: %s", message);
		return false;
	}

	data = p11_asn1_read (asn, "", &len);
	return_val_if_fail (data != NULL, false);

	asn1_delete_structure (&asn);

	p11_buffer_add (buf, data, len - 1);
	free (data);

	return true;
}

static bool
parse_value (p11_persist *persist,
             p11_lexer *lexer,
             CK_ATTRIBUTE *attr)
{
	return parse_constant (persist, lexer, attr) ||
	       parse_string (lexer, attr) ||
	       parse_bool (lexer, attr) ||
	       parse_ulong (lexer, attr) ||
	       parse_oid (persist, lexer, attr);
}

static void
format_value (p11_persist *persist,
              CK_ATTRIBUTE *attr,
              p11_buffer *buf)
{
	assert (attr->ulValueLen != CK_UNAVAILABLE_INFORMATION);

	if (format_bool (attr, buf) ||
	    format_constant (attr, buf) ||
	    format_ulong (attr, buf) ||
	    format_oid (persist, attr, buf))
		return;

	/* Everything else as string */
	format_string (attr, buf);
}

static bool
field_to_attribute (p11_persist *persist,
                    p11_lexer *lexer,
                    CK_ATTRIBUTE **attrs)
{
	CK_ATTRIBUTE attr = { 0, };
	char *end;

	end = NULL;
	attr.type = strtoul (lexer->tok.field.name, &end, 10);

	/* Not a valid number value, probably a constant */
	if (!end || *end != '\0') {
		attr.type = p11_constant_resolve (persist->constants, lexer->tok.field.name);
		if (attr.type == CKA_INVALID || !p11_constant_name (p11_constant_types, attr.type)) {
			p11_lexer_msg (lexer, "invalid or unsupported attribute");
			return false;
		}
	}

	if (!parse_value (persist, lexer, &attr)) {
		p11_lexer_msg (lexer, "invalid value");
		return false;
	}

	*attrs = p11_attrs_take (*attrs, attr.type,
	                         attr.pValue, attr.ulValueLen);
	return true;
}

static CK_ATTRIBUTE *
certificate_to_attributes (const unsigned char *der,
                           size_t length)
{
	CK_OBJECT_CLASS klassv = CKO_CERTIFICATE;
	CK_CERTIFICATE_TYPE x509 = CKC_X_509;

	CK_ATTRIBUTE klass = { CKA_CLASS, &klassv, sizeof (klassv) };
	CK_ATTRIBUTE certificate_type = { CKA_CERTIFICATE_TYPE, &x509, sizeof (x509) };
	CK_ATTRIBUTE value = { CKA_VALUE, (void *)der, length };

	return p11_attrs_build (NULL, &klass, &certificate_type, &value, NULL);
}

static CK_ATTRIBUTE *
public_key_to_attributes (const unsigned char *der,
                          size_t length)
{
	/* Eventually we might choose to contribute a class here ... */
	CK_ATTRIBUTE public_key = { CKA_PUBLIC_KEY_INFO, (void *)der, length };
	return p11_attrs_build (NULL, &public_key, NULL);
}

typedef struct {
	p11_lexer *lexer;
	CK_ATTRIBUTE *attrs;
	bool result;
} parse_block;

static void
on_pem_block (const char *type,
              const unsigned char *contents,
              size_t length,
              void *user_data)
{
	parse_block *pb = user_data;
	CK_ATTRIBUTE *attrs;

	if (strcmp (type, "CERTIFICATE") == 0) {
		attrs = certificate_to_attributes (contents, length);
		pb->attrs = p11_attrs_merge (pb->attrs, attrs, false);
		pb->result = true;

	} else if (strcmp (type, "PUBLIC KEY") == 0) {
		attrs = public_key_to_attributes (contents, length);
		pb->attrs = p11_attrs_merge (pb->attrs, attrs, false);
		pb->result = true;

	} else {
		p11_lexer_msg (pb->lexer, "unsupported pem block in store");
		pb->result = false;
	}
}

static bool
pem_to_attributes (p11_lexer *lexer,
                   CK_ATTRIBUTE **attrs)
{
	parse_block pb = { lexer, *attrs, false };
	unsigned int count;

	count = p11_pem_parse (lexer->tok.pem.begin,
	                       lexer->tok.pem.length,
	                       on_pem_block, &pb);

	if (count == 0) {
		p11_lexer_msg (lexer, "invalid pem block");
		return false;
	}

	/* The lexer should have only matched one block */
	return_val_if_fail (count == 1, false);
	*attrs = pb.attrs;
	return pb.result;
}

bool
p11_persist_read (p11_persist *persist,
                  const char *filename,
                  const unsigned char *data,
                  size_t length,
                  p11_array *objects)
{
	p11_lexer lexer;
	CK_ATTRIBUTE *attrs;
	bool failed;
	bool skip;

	return_val_if_fail (persist != NULL, false);
	return_val_if_fail (objects != NULL, false);

	skip = false;
	attrs = NULL;
	failed = false;

	p11_lexer_init (&lexer, filename, (const char *)data, length);
	while (p11_lexer_next (&lexer, &failed)) {
		switch (lexer.tok_type) {
		case TOK_SECTION:
			if (attrs && !p11_array_push (objects, attrs))
				return_val_if_reached (false);
			attrs = NULL;
			if (strcmp (lexer.tok.section.name, PERSIST_HEADER) != 0) {
				p11_lexer_msg (&lexer, "unrecognized or invalid section header");
				skip = true;
			} else {
				attrs = p11_attrs_build (NULL, NULL);
				return_val_if_fail (attrs != NULL, false);
				skip = false;
			}
			failed = false;
			break;
		case TOK_FIELD:
			if (skip) {
				failed = false;
			} else if (!attrs) {
				p11_lexer_msg (&lexer, "attribute before p11-kit section header");
				failed = true;
			} else {
				failed = !field_to_attribute (persist, &lexer, &attrs);
			}
			break;
		case TOK_PEM:
			if (skip) {
				failed = false;
			} else if (!attrs) {
				p11_lexer_msg (&lexer, "pem block before p11-kit section header");
				failed = true;
			} else {
				failed = !pem_to_attributes (&lexer, &attrs);
			}
			break;
		}

		if (failed)
			break;
	}

	if (attrs && !p11_array_push (objects, attrs))
		return_val_if_reached (false);
	attrs = NULL;

	p11_lexer_done (&lexer);
	return !failed;
}

static CK_ATTRIBUTE *
find_certificate_value (CK_ATTRIBUTE *attrs)
{
	CK_OBJECT_CLASS klass;
	CK_CERTIFICATE_TYPE type;

	if (!p11_attrs_find_ulong (attrs, CKA_CLASS, &klass) ||
	    klass != CKO_CERTIFICATE)
		return NULL;
	if (!p11_attrs_find_ulong (attrs, CKA_CERTIFICATE_TYPE, &type) ||
	    type != CKC_X_509)
		return NULL;
	return p11_attrs_find_valid (attrs, CKA_VALUE);
}

bool
p11_persist_write (p11_persist *persist,
                   CK_ATTRIBUTE *attrs,
                   p11_buffer *buf)
{
	char string[sizeof (CK_ULONG) * 4];
	CK_ATTRIBUTE *cert_value;
	CK_ATTRIBUTE *spki_value;
	const char *nick;
	int i;

	cert_value = find_certificate_value (attrs);
	spki_value = p11_attrs_find_valid (attrs, CKA_PUBLIC_KEY_INFO);

	p11_buffer_add (buf, "[" PERSIST_HEADER "]\n", -1);

	for (i = 0; !p11_attrs_terminator (attrs + i); i++) {

		/* These are written later? */
		if (cert_value != NULL &&
		    (attrs[i].type == CKA_CLASS ||
		     attrs[i].type == CKA_CERTIFICATE_TYPE ||
		     attrs[i].type == CKA_VALUE))
			continue;

		/* These are written later? */
		if (spki_value != NULL &&
		    attrs[i].type == CKA_PUBLIC_KEY_INFO)
			continue;

		/* These are never written */
		if (attrs[i].type == CKA_TOKEN ||
		    attrs[i].type == CKA_X_ORIGIN ||
		    attrs[i].type == CKA_X_GENERATED)
			continue;

		if (attrs[i].ulValueLen == CK_UNAVAILABLE_INFORMATION)
			continue;

		nick = p11_constant_nick (p11_constant_types, attrs[i].type);
		if (nick == NULL) {
			snprintf (string, sizeof (string), "%lu", attrs[i].type);
			nick = string;
		}

		p11_buffer_add (buf, nick, -1);
		p11_buffer_add (buf, ": ", 2);
		format_value (persist, attrs + i, buf);
		p11_buffer_add (buf, "\n", 1);
	}

	if (cert_value != NULL) {
		if (!p11_pem_write (cert_value->pValue, cert_value->ulValueLen, "CERTIFICATE", buf))
			return_val_if_reached (false);
	} else if (spki_value != NULL) {
		if (!p11_pem_write (spki_value->pValue, spki_value->ulValueLen, "PUBLIC KEY", buf))
			return_val_if_reached (false);
	}

	p11_buffer_add (buf, "\n", 1);
	return p11_buffer_ok (buf);
}
