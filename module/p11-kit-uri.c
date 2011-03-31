/*
 * Copyright (C) 2011 Collabora Ltd.
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

#include "pkcs11.h"
#include "p11-kit-uri.h"
#include "util.h"

#include <assert.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

enum {
	CLASS_IDX,
	LABEL_IDX,
	ID_IDX,
	NUM_ATTRS,
};

struct _P11KitUri {
	int unrecognized;
	CK_INFO module;
	CK_TOKEN_INFO token;
	CK_ATTRIBUTE attrs[NUM_ATTRS];
};

const static char HEX_CHARS[] = "0123456789abcdef";

static int
url_decode (const char *value, const char *end,
            unsigned char** output, size_t *length)
{
	char *a, *b;
	unsigned char *result, *p;

	assert (output);
	assert (value <= end);

	/* String can only get shorter */
	result = malloc ((end - value) + 1);
	if (!result)
		return P11_KIT_URI_NO_MEMORY;

	/* Now loop through looking for escapes */
	p = result;
	while (value != end) {
		/*
		 * A percent sign followed by two hex digits means
		 * that the digits represent an escaped character.
		 */
		if (*value == '%') {
			value++;
			if (value + 2 > end) {
				free (result);
				return P11_KIT_URI_BAD_ENCODING;
			}
			a = strchr (HEX_CHARS, tolower (value[0]));
			b = strchr (HEX_CHARS, tolower (value[1]));
			if (!a || !b) {
				free (result);
				return P11_KIT_URI_BAD_ENCODING;
			}
			*p = (a - HEX_CHARS) << 4;
			*(p++) |= (b - HEX_CHARS);
			value += 2;
		} else {
			*(p++) = *(value++);
		}
	}

	*p = 0;
	if (length)
		*length = p - result;
	*output = result;
	return P11_KIT_URI_OK;
}

static char*
url_encode (const unsigned char *value, const unsigned char *end, size_t *length)
{
	char *p;
	char *result;

	assert (value <= end);

	/* Just allocate for worst case */
	result = malloc (((end - value) * 3) + 1);
	if (!result)
		return NULL;

	/* Now loop through looking for escapes */
	p = result;
	while (value != end) {

		/* These characters we let through verbatim */
		if (*value && (isalnum (*value) || strchr ("_-.", *value) != NULL)) {
			*(p++) = *(value++);

		/* All others get encoded */
		} else {
			*(p++) = '%';
			*(p++) = HEX_CHARS[((unsigned char)*value) >> 4];
			*(p++) = HEX_CHARS[((unsigned char)*value) & 0x0F];
			++value;
		}
	}

	*p = 0;
	if (length)
		*length = p - result;
	return result;
}

static int
attribute_to_idx (CK_ATTRIBUTE_TYPE type)
{
	switch (type) {
	case CKA_CLASS:
		return CLASS_IDX;
	case CKA_LABEL:
		return LABEL_IDX;
	case CKA_ID:
		return ID_IDX;
	default:
		return -1;
	}
}

static CK_ATTRIBUTE_TYPE
idx_to_attribute (int idx)
{
	switch (idx) {
	case CLASS_IDX:
		return CKA_CLASS;
	case LABEL_IDX:
		return CKA_LABEL;
	case ID_IDX:
		return CKA_ID;
	default:
		assert (0);
	}
}

static int
match_struct_string (const unsigned char *inuri, const unsigned char *real,
                     size_t length)
{
	assert (inuri);
	assert (real);
	assert (length > 0);

	/* NULL matches anything */
	if (inuri[0] == 0)
		return 1;

	return memcmp (inuri, real, length) == 0 ? 1 : 0;
}

static int
match_struct_version (CK_VERSION_PTR inuri, CK_VERSION_PTR real)
{
	/* This matches anything */
	if (inuri->major == (CK_BYTE)-1 && inuri->minor == (CK_BYTE)-1)
		return 1;

	return memcmp (inuri, real, sizeof (CK_VERSION));
}

/**
 * p11_kit_uri_get_module_info:
 *
 * Get the %CK_INFO structure associated with this URI.
 *
 * Returns: A pointer to the %CK_INFO structure.
 */
CK_INFO_PTR
p11_kit_uri_get_module_info (P11KitUri *uri)
{
	assert (uri);
	return &uri->module;
}

/**
 * p11_kit_uri_match_module_info:
 *
 * Match a %CK_INFO structure against the library parts of this URI.
 *
 * Only the fields of the %CK_INFO structure that are valid for use in a
 * URI will be matched. A URI part that was not specified in the URI will
 * match any value in the structure. If during the URI parsing any unrecognized
 * parts were encountered then this match will fail.
 *
 * Returns: 1 if the URI matches, 0 if not.
 */
int
p11_kit_uri_match_module_info (P11KitUri *uri, CK_INFO_PTR info)
{
	assert (uri);
	assert (info);

	if (uri->unrecognized)
		return 0;

	return (match_struct_string (uri->module.libraryDescription,
	                             info->libraryDescription,
	                             sizeof (info->libraryDescription)) &&
	        match_struct_string (uri->module.manufacturerID,
	                             info->manufacturerID,
	                             sizeof (info->manufacturerID)) &&
	        match_struct_version (&uri->module.libraryVersion,
	                              &info->libraryVersion));
}

CK_TOKEN_INFO_PTR
p11_kit_uri_get_token_info (P11KitUri *uri)
{
	assert (uri);
	return &uri->token;
}

/**
 * p11_kit_uri_match_token_info:
 *
 * Match a %CK_TOKEN_INFO structure against the token parts of this URI.
 *
 * Only the fields of the %CK_TOKEN_INFO structure that are valid for use in a
 * URI will be matched. A URI part that was not specified in the URI will
 * match any value in the structure. If during the URI parsing any unrecognized
 * parts were encountered then this match will fail.
 *
 * Returns: 1 if the URI matches, 0 if not.
 */
int
p11_kit_uri_match_token_info (P11KitUri *uri, CK_TOKEN_INFO_PTR token_info)
{
	assert (uri);
	assert (token_info);

	if (uri->unrecognized)
		return 0;

	return (match_struct_string (uri->token.label,
	                             token_info->label,
	                             sizeof (token_info->label)) &&
	        match_struct_string (uri->token.manufacturerID,
	                             token_info->manufacturerID,
	                             sizeof (token_info->manufacturerID)) &&
	        match_struct_string (uri->token.model,
	                             token_info->model,
	                             sizeof (token_info->model)) &&
	        match_struct_string (uri->token.serialNumber,
	                             token_info->serialNumber,
	                             sizeof (token_info->serialNumber)));
}

CK_ATTRIBUTE_TYPE*
p11_kit_uri_get_attribute_types (P11KitUri *uri, int *n_types)
{
	CK_ATTRIBUTE_TYPE *result;
	int i, j;

	assert (uri);
	assert (n_types);

	result = calloc (NUM_ATTRS, sizeof (CK_ATTRIBUTE_TYPE));
	if (result == NULL)
		return NULL;

	for (i = 0, j = 0; i < NUM_ATTRS; ++i) {
		if (uri->attrs[i].ulValueLen != (CK_ULONG)-1)
			result[j++] = uri->attrs[i].type;
	}

	*n_types = j;
	return result;
}

CK_ATTRIBUTE_PTR
p11_kit_uri_get_attribute (P11KitUri *uri, CK_ATTRIBUTE_TYPE type)
{
	int idx;

	assert (uri);

	idx = attribute_to_idx (type);
	if (idx < 0)
		return NULL;

	assert (idx < NUM_ATTRS);
	if (uri->attrs[idx].ulValueLen == (CK_ULONG)-1)
		return NULL;
	return &uri->attrs[idx];
}

int
p11_kit_uri_set_attribute (P11KitUri *uri, CK_ATTRIBUTE_PTR attr)
{
	void *value = NULL;
	int idx;
	int ret;

	assert (uri);
	assert (attr);

	if (attr->pValue && attr->ulValueLen && attr->ulValueLen != (CK_ULONG)-1) {
		value = malloc (attr->ulValueLen);
		if (!value)
			return P11_KIT_URI_NO_MEMORY;
		memcpy (value, attr->pValue, attr->ulValueLen);
	}

	ret = p11_kit_uri_clear_attribute (uri, attr->type);
	if (ret < 0){
		free (value);
		return ret;
	}

	idx = attribute_to_idx (attr->type);
	assert (idx >= 0 && idx < NUM_ATTRS);

	memcpy (&uri->attrs[idx], attr, sizeof (CK_ATTRIBUTE));
	uri->attrs[idx].pValue = value;

	return P11_KIT_URI_OK;
}

int
p11_kit_uri_clear_attribute (P11KitUri *uri, CK_ATTRIBUTE_TYPE type)
{
	int idx;

	assert (uri);

	idx = attribute_to_idx (type);
	if (idx < 0)
		return P11_KIT_URI_NOT_FOUND;
	assert (idx < NUM_ATTRS);

	free (uri->attrs[idx].pValue);
	uri->attrs[idx].pValue = NULL;
	uri->attrs[idx].ulValueLen = (CK_ULONG)-1;
	return 0;
}

static int
match_attributes (CK_ATTRIBUTE_PTR one, CK_ATTRIBUTE_PTR two)
{
	assert (one);
	assert (two);

	if (one->type != two->type)
		return 0;
	if (one->ulValueLen != two->ulValueLen)
		return 0;
	if (one->pValue == two->pValue)
		return 1;
	if (!one->pValue || !two->pValue)
		return 0;
	return memcmp (one->pValue, two->pValue, one->ulValueLen) == 0;
}

/**
 * p11_kit_uri_match_attributes:
 *
 * Match a attributes against the object parts of this URI.
 *
 * Only the attributes that are valid for use in a URI will be matched. A URI
 * part that was not specified in the URI will match any attribute value. If
 * during the URI parsing any unrecognized parts were encountered then this
 * match will fail.
 *
 * Returns: 1 if the URI matches, 0 if not.
 */
int
p11_kit_uri_match_attributes (P11KitUri *uri, CK_ATTRIBUTE_PTR attrs,
                              CK_ULONG n_attrs)
{
	CK_ULONG j;
	int i;

	assert (uri);
	assert (attrs || !n_attrs);

	if (uri->unrecognized)
		return 0;

	for (i = 0; i < NUM_ATTRS; ++i) {
		if (uri->attrs[i].ulValueLen == (CK_ULONG)-1)
			continue;
		for (j = 0; j < n_attrs; ++j) {
			if (attrs[j].type == uri->attrs[i].type) {
				if (!match_attributes (&uri->attrs[i], &attrs[j]))
					return 0;
				break;
			}
		}
	}

	return 1;
}

void
p11_kit_uri_set_unrecognized (P11KitUri *uri, int unrecognized)
{
	assert (uri);
	uri->unrecognized = unrecognized;
}

int
p11_kit_uri_any_unrecognized (P11KitUri *uri)
{
	assert (uri);
	return uri->unrecognized;
}

P11KitUri*
p11_kit_uri_new (void)
{
	P11KitUri *uri;
	int i;

	uri = calloc (1, sizeof (P11KitUri));
	if (!uri)
		return NULL;

	/* So that it matches anything */
	uri->module.libraryVersion.major = (CK_BYTE)-1;
	uri->module.libraryVersion.minor = (CK_BYTE)-1;

	for (i = 0; i < NUM_ATTRS; ++i) {
		uri->attrs[i].type = idx_to_attribute (i);
		uri->attrs[i].ulValueLen = (CK_ULONG)-1;
	}

	return uri;
}

static size_t
space_strlen (const unsigned char *string, size_t max_length)
{
	size_t i = max_length - 1;

	assert (string);

	while (i > 0 && string[i] == ' ')
		--i;
	return i + 1;
}

static int
format_raw_string (char **string, size_t *length, int *is_first,
                   const char *name, const char *value)
{
	size_t namelen;
	size_t vallen;

	/* Not set */
	if (!value)
		return 1;

	namelen = strlen (name);
	vallen = strlen (value);

	*string = xrealloc (*string, *length + namelen + vallen + 3);
	if (!*string)
		return 0;

	if (!*is_first)
		(*string)[(*length)++] = ';';
	memcpy ((*string) + *length, name, namelen);
	*length += namelen;
	(*string)[(*length)++] = '=';
	memcpy ((*string) + *length, value, vallen);
	*length += vallen;
	(*string)[*length] = 0;
	*is_first = 0;

	return 1;
}


static int
format_struct_string (char **string, size_t *length, int *is_first,
                      const char *name, const unsigned char *value,
                      size_t value_max)
{
	char *encoded;
	size_t len;
	int ret;

	/* Not set */
	if (!value[0])
		return 1;

	len = space_strlen (value, value_max);
	encoded = url_encode (value, value + len, NULL);
	if (!encoded)
		return 0;

	ret = format_raw_string (string, length, is_first, name, encoded);
	free (encoded);

	return ret;
}

static int
format_attribute_string (char **string, size_t *length, int *is_first,
                         const char *name, CK_ATTRIBUTE_PTR attr)
{
	unsigned char *value;
	char *encoded;
	int ret;

	/* Not set */;
	if (attr->ulValueLen == (CK_ULONG)-1)
		return 1;

	value = attr->pValue;
	encoded = url_encode (value, value + attr->ulValueLen, NULL);
	if (!encoded)
		return 0;

	ret = format_raw_string (string, length, is_first, name, encoded);
	free (encoded);

	return ret;
}

static int
format_attribute_class (char **string, size_t *length, int *is_first,
                        const char *name, CK_ATTRIBUTE_PTR attr)
{
	CK_OBJECT_CLASS klass;
	const char *value;

	/* Not set */;
	if (attr->ulValueLen != sizeof (klass))
		return 1;

	klass = *((CK_OBJECT_CLASS*)attr->pValue);
	switch (klass) {
	case CKO_DATA:
		value = "data";
		break;
	case CKO_SECRET_KEY:
		value = "secretkey";
		break;
	case CKO_CERTIFICATE:
		value = "cert";
		break;
	case CKO_PUBLIC_KEY:
		value = "public";
		break;
	case CKO_PRIVATE_KEY:
		value = "private";
		break;
	}

	return format_raw_string (string, length, is_first, name, value);
}

static int
format_struct_version (char **string, size_t *length, int *is_first,
                       const char *name, CK_VERSION_PTR version)
{
	char buffer[64];

	/* Not set */
	if (version->major == (CK_BYTE)-1 && version->minor == (CK_BYTE)-1)
		return 1;

	snprintf (buffer, sizeof (buffer), "%d.%d",
	          (int)version->major, (int)version->minor);
	return format_raw_string (string, length, is_first, name, buffer);
}

int
p11_kit_uri_format (P11KitUri *uri, char **string)
{
	char *result = NULL;
	size_t length = 0;
	int is_first = 1;

	result = malloc (128);
	if (!result)
		return P11_KIT_URI_NO_MEMORY;

	length = P11_KIT_URI_PREFIX_LEN;
	memcpy (result, P11_KIT_URI_PREFIX, length);
	result[length] = 0;

	if (!format_struct_string (&result, &length, &is_first, "library-description",
	                           uri->module.libraryDescription,
	                           sizeof (uri->module.libraryDescription)) ||
	    !format_struct_string (&result, &length, &is_first, "library-manufacturer",
	                           uri->module.manufacturerID,
	                           sizeof (uri->module.manufacturerID)) ||
	    !format_struct_string (&result, &length, &is_first, "model",
	                           uri->token.model,
	                           sizeof (uri->token.model)) ||
	    !format_struct_string (&result, &length, &is_first, "manufacturer",
	                           uri->token.manufacturerID,
	                           sizeof (uri->token.manufacturerID)) ||
	    !format_struct_string (&result, &length, &is_first, "serial",
	                           uri->token.serialNumber,
	                           sizeof (uri->token.serialNumber)) ||
	    !format_struct_string (&result, &length, &is_first, "token",
	                           uri->token.label,
	                           sizeof (uri->token.label)) ||
	    !format_struct_version (&result, &length, &is_first, "library-version",
	                            &uri->module.libraryVersion)) {
		free (result);
		return P11_KIT_URI_NO_MEMORY;
	}

	if (!format_attribute_string (&result, &length, &is_first, "id",
	                              &uri->attrs[ID_IDX]) ||
	    !format_attribute_string (&result, &length, &is_first, "object",
	                              &uri->attrs[LABEL_IDX])) {
		free (result);
		return P11_KIT_URI_NO_MEMORY;
	}

	if (!format_attribute_class (&result, &length, &is_first, "objecttype",
	                             &uri->attrs[CLASS_IDX])) {
		free (result);
		return P11_KIT_URI_NO_MEMORY;
	}

	*string = result;
	return P11_KIT_URI_OK;
}

static int
parse_string_attribute (const char *name, const char *start, const char *end,
                        P11KitUri *uri)
{
	unsigned char *value;
	size_t length;
	int idx, ret;

	assert (start <= end);

	if (strcmp ("id", name) == 0)
		idx = ID_IDX;
	else if (strcmp ("object", name) == 0)
		idx = LABEL_IDX;
	else
		return 0;

	ret = url_decode (start, end, &value, &length);
	if (ret < 0)
		return ret;

	free (uri->attrs[idx].pValue);
	uri->attrs[idx].pValue = value;
	uri->attrs[idx].ulValueLen = length;
	return 1;
}

static int
equals_segment (const char *start, const char *end, const char *match)
{
	size_t len = strlen (match);
	assert (start <= end);
	return (end - start == len) && memcmp (start, match, len) == 0;
}

static int
parse_class_attribute (const char *name, const char *start, const char *end,
                       P11KitUri *uri)
{
	CK_OBJECT_CLASS klass = 0;
	void *value;

	assert (start <= end);

	if (strcmp ("objecttype", name) != 0)
		return 0;

	if (equals_segment (start, end, "cert"))
		klass = CKO_CERTIFICATE;
	else if (equals_segment (start, end, "public"))
		klass = CKO_PUBLIC_KEY;
	else if (equals_segment (start, end, "private"))
		klass = CKO_PRIVATE_KEY;
	else if (equals_segment (start, end, "secretkey"))
		klass = CKO_SECRET_KEY;
	else if (equals_segment (start, end, "data"))
		klass = CKO_DATA;
	else {
		uri->unrecognized = 1;
		return 1;
	}

	value = malloc (sizeof (klass));
	if (value == NULL)
		return P11_KIT_URI_NO_MEMORY;

	free (uri->attrs[CLASS_IDX].pValue);
	memcpy (value, &klass, sizeof (klass));
	uri->attrs[CLASS_IDX].pValue = value;
	uri->attrs[CLASS_IDX].ulValueLen = sizeof (klass);

	return 1;
}

static int
parse_struct_info (unsigned char *where, size_t length, const char *start,
                   const char *end, P11KitUri *uri)
{
	unsigned char *value;
	size_t value_length;
	int ret;

	assert (start <= end);

	ret = url_decode (start, end, &value, &value_length);
	if (ret < 0)
		return ret;

	/* Too long, shouldn't match anything */
	if (value_length > length) {
		free (value);
		uri->unrecognized = 1;
		return 1;
	}

	memset (where, ' ', length);
	memcpy (where, value, value_length);

	free (value);
	return 1;
}

static int
parse_token_info (const char *name, const char *start, const char *end,
                  P11KitUri *uri)
{
	unsigned char *where;
	size_t length;

	assert (start <= end);

	if (strcmp (name, "model") == 0) {
		where = uri->token.model;
		length = sizeof (uri->token.model);
	} else if (strcmp (name, "manufacturer") == 0) {
		where = uri->token.manufacturerID;
		length = sizeof (uri->token.manufacturerID);
	} else if (strcmp (name, "serial") == 0) {
		where = uri->token.serialNumber;
		length = sizeof (uri->token.serialNumber);
	} else if (strcmp (name, "token") == 0) {
		where = uri->token.label;
		length = sizeof (uri->token.label);
	} else {
		return 0;
	}

	return parse_struct_info (where, length, start, end, uri);
}

static int
atoin (const char *start, const char *end)
{
	int ret = 0;
	while (start != end) {
		if (*start < '0' || *start > '9')
			return -1;
		ret *= 10;
		ret += (*start - '0');
		++start;
	}
	return ret;
}

static int
parse_struct_version (const char *start, const char *end, CK_VERSION_PTR version)
{
	const char *dot;
	int val;

	assert (start <= end);

	dot = memchr (start, '.', end - start);
	if (!dot)
		dot = end;

	if (dot == start)
		return P11_KIT_URI_BAD_VERSION;
	val = atoin (start, dot);
	if (val < 0 || val >= 255)
		return P11_KIT_URI_BAD_VERSION;
	version->major = (CK_BYTE)val;
	version->minor = 0;

	if (dot != end) {
		if (dot + 1 == end)
			return P11_KIT_URI_BAD_VERSION;
		val = atoin (dot + 1, end);
		if (val < 0 || val >= 255)
			return P11_KIT_URI_BAD_VERSION;
		version->minor = (CK_BYTE)val;
	}

	return 1;
}

static int
parse_module_info (const char *name, const char *start, const char *end,
                   P11KitUri *uri)
{
	unsigned char *where;
	size_t length;

	assert (start <= end);

	if (strcmp (name, "library-description") == 0) {
		where = uri->module.libraryDescription;
		length = sizeof (uri->module.libraryDescription);
	} else if (strcmp (name, "library-manufacturer") == 0) {
		where = uri->module.manufacturerID;
		length = sizeof (uri->module.manufacturerID);
	} else if (strcmp (name, "library-version") == 0) {
		return parse_struct_version (start, end,
		                             &uri->module.libraryVersion);
	} else {
		return 0;
	}

	return parse_struct_info (where, length, start, end, uri);
}

int
p11_kit_uri_parse (const char *string, P11KitUriContext context,
                   P11KitUri *uri)
{
	const char *spos, *epos;
	char *key = NULL;
	int ret = -1;
	int i;

	assert (string);
	assert (uri);

	if (strncmp (string, P11_KIT_URI_PREFIX, P11_KIT_URI_PREFIX_LEN) != 0)
		return P11_KIT_URI_BAD_PREFIX;

	string += P11_KIT_URI_PREFIX_LEN;

	/* Clear everything out */
	memset (&uri->module, 0, sizeof (uri->module));
	memset (&uri->token, 0, sizeof (uri->module));
	for (i = 0; i < NUM_ATTRS; ++i)
		uri->attrs[i].ulValueLen = (CK_ULONG)-1;
	uri->module.libraryVersion.major = (CK_BYTE)-1;
	uri->module.libraryVersion.minor = (CK_BYTE)-1;
	uri->unrecognized = 0;

	for (;;) {
		spos = strchr (string, ';');
		if (spos == NULL) {
			spos = string + strlen (string);
			assert (*spos == '\0');
			if (spos == string)
				break;
		}

		epos = strchr (string, '=');
		if (epos == NULL || spos == string || epos == string || epos >= spos)
			return P11_KIT_URI_BAD_SYNTAX;

		key = malloc ((epos - string) + 1);
		if (key == NULL)
			return P11_KIT_URI_NO_MEMORY;
		memcpy (key, string, epos - string);
		key[epos - string] = 0;
		epos++;

		ret = 0;
		if (context & P11_KIT_URI_PARSE_OBJECT)
			ret = parse_string_attribute (key, epos, spos, uri);
		if (ret == 0 && context & P11_KIT_URI_PARSE_OBJECT)
			ret = parse_class_attribute (key, epos, spos, uri);
		if (ret == 0 && context & P11_KIT_URI_PARSE_TOKEN)
			ret = parse_token_info (key, epos, spos, uri);
		if (ret == 0 && context & P11_KIT_URI_PARSE_MODULE)
			ret = parse_module_info (key, epos, spos, uri);
		free (key);

		if (ret < 0)
			return ret;
		if (ret == 0)
			uri->unrecognized = 1;

		if (*spos == '\0')
			break;
		string = spos + 1;
	}

	return P11_KIT_URI_OK;
}

void
p11_kit_uri_free (P11KitUri *uri)
{
	int i;

	if (!uri)
		return;

	for (i = 0; i < NUM_ATTRS; ++i)
		free (uri->attrs[i].pValue);

	free (uri);
}
