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
#include "pem.h"
#include "persist.h"
#include "url.h"

#include "basic.asn.h"

#include <libtasn1.h>

#include <stdlib.h>
#include <string.h>

#define PERSIST_HEADER "p11-kit-object-v1"

struct _p11_persist {
	p11_dict *constants;
	node_asn *asn1_defs;

	/* Used during parsing */
	p11_lexer lexer;
	CK_ATTRIBUTE *attrs;
	bool result;
	bool skip;
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

static bool
field_to_attribute (p11_persist *persist,
                    p11_lexer *lexer)
{
	CK_ATTRIBUTE attr = { 0, };

	attr.type = p11_constant_resolve (persist->constants, lexer->tok.field.name);
	if (attr.type == CKA_INVALID || !p11_constant_name (p11_constant_types, attr.type)) {
		p11_lexer_msg (lexer, "invalid or unsupported attribute");
		return false;
	}

	if (!parse_value (persist, lexer, &attr)) {
		p11_lexer_msg (lexer, "invalid value");
		return false;
	}

	persist->attrs = p11_attrs_take (persist->attrs, attr.type,
	                                 attr.pValue, attr.ulValueLen);
	return true;
}

static void
on_pem_block (const char *type,
              const unsigned char *contents,
              size_t length,
              void *user_data)
{
	CK_OBJECT_CLASS klassv = CKO_CERTIFICATE;
	CK_CERTIFICATE_TYPE x509 = CKC_X_509;
	CK_BBOOL modifiablev = CK_FALSE;

	CK_ATTRIBUTE modifiable = { CKA_MODIFIABLE, &modifiablev, sizeof (modifiablev) };
	CK_ATTRIBUTE klass = { CKA_CLASS, &klassv, sizeof (klassv) };
	CK_ATTRIBUTE certificate_type = { CKA_CERTIFICATE_TYPE, &x509, sizeof (x509) };
	CK_ATTRIBUTE value = { CKA_VALUE, };

	p11_persist *store = user_data;
	CK_ATTRIBUTE *attrs;

	if (strcmp (type, "CERTIFICATE") == 0) {
		value.pValue = (void *)contents;
		value.ulValueLen = length;
		attrs = p11_attrs_build (NULL, &klass, &modifiable, &certificate_type, &value, NULL);
		store->attrs = p11_attrs_merge (store->attrs, attrs, false);
		store->result = true;

	} else {
		p11_lexer_msg (&store->lexer, "unsupported pem block in store");
		store->result = false;
	}
}

static bool
pem_to_attributes (p11_persist *store,
                   p11_lexer *lexer)
{
	unsigned int count;

	count = p11_pem_parse (lexer->tok.pem.begin,
	                       lexer->tok.pem.length,
	                       on_pem_block, store);

	if (count == 0) {
		p11_lexer_msg (lexer, "invalid pem block");
		return false;
	}

	/* The lexer should have only matched one block */
	return_val_if_fail (count == 1, false);
	return store->result;
}

bool
p11_persist_read (p11_persist *persist,
                  const char *filename,
                  const unsigned char *data,
                  size_t length,
                  p11_array *objects)
{
	bool failed = false;

	return_val_if_fail (persist != NULL, false);
	return_val_if_fail (objects != NULL, false);

	persist->skip = false;
	persist->result = false;
	persist->attrs = NULL;

	p11_lexer_init (&persist->lexer, filename, (const char *)data, length);
	while (p11_lexer_next (&persist->lexer, &failed)) {
		switch (persist->lexer.tok_type) {
		case TOK_SECTION:
			if (persist->attrs && !p11_array_push (objects, persist->attrs))
				return_val_if_reached (false);
			persist->attrs = NULL;
			if (strcmp (persist->lexer.tok.section.name, PERSIST_HEADER) != 0) {
				p11_lexer_msg (&persist->lexer, "unrecognized or invalid section header");
				persist->skip = true;
			} else {
				persist->attrs = p11_attrs_build (NULL, NULL);
				return_val_if_fail (persist->attrs != NULL, false);
				persist->skip = false;
			}
			failed = false;
			break;
		case TOK_FIELD:
			if (persist->skip) {
				failed = false;
			} else if (!persist->attrs) {
				p11_lexer_msg (&persist->lexer, "attribute before p11-kit section header");
				failed = true;
			} else {
				failed = !field_to_attribute (persist, &persist->lexer);
			}
			break;
		case TOK_PEM:
			if (persist->skip) {
				failed = false;
			} else if (!persist->attrs) {
				p11_lexer_msg (&persist->lexer, "pem block before p11-kit section header");
				failed = true;
			} else {
				failed = !pem_to_attributes (persist, &persist->lexer);
			}
			break;
		}

		if (failed)
			break;
	}

	if (persist->attrs && !p11_array_push (objects, persist->attrs))
		return_val_if_reached (false);
	persist->attrs = NULL;

	p11_lexer_done (&persist->lexer);
	return !failed;
}
