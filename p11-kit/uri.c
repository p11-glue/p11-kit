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

#include "attrs.h"
#include "buffer.h"
#define P11_DEBUG_FLAG P11_DEBUG_URI
#include "debug.h"
#include "message.h"
#include "pkcs11.h"
#include "private.h"
#include "p11-kit.h"
#include "uri.h"
#include "url.h"

#include <assert.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/**
 * SECTION:p11-kit-uri
 * @title: URIs
 * @short_description: Parsing and formatting PKCS\#11 URIs
 *
 * PKCS\#11 URIs can be used in configuration files or applications to represent
 * PKCS\#11 modules, tokens or objects. An example of a URI might be:
 *
 * <code><literallayout>
 *      pkcs11:token=The\%20Software\%20PKCS\#11\%20softtoken;
 *          manufacturer=Snake\%20Oil,\%20Inc.;serial=;object=my-certificate;
 *          model=1.0;type=cert;id=\%69\%95\%3e\%5c\%f4\%bd\%ec\%91
 * </literallayout></code>
 *
 * You can use p11_kit_uri_parse() to parse such a URI, and p11_kit_uri_format()
 * to build one. URIs are represented by the #P11KitUri structure. You can match
 * a parsed URI against PKCS\#11 tokens with p11_kit_uri_match_token_info()
 * or attributes with p11_kit_uri_match_attributes().
 *
 * Since URIs can represent different sorts of things, when parsing or formatting
 * a URI a 'context' can be used to indicate which sort of URI is expected.
 *
 * URIs have an <code>unrecognized</code> flag. This flag is set during parsing
 * if any parts of the URI are not recognized. This may be because the part is
 * from a newer version of the PKCS\#11 spec or because that part was not valid
 * inside of the desired context used when parsing.
 */

/**
 * P11KitUri:
 *
 * A structure representing a PKCS\#11 URI. There are no public fields
 * visible in this structure. Use the various accessor functions.
 */

/**
 * P11KitUriType:
 * @P11_KIT_URI_FOR_OBJECT: The URI represents one or more objects
 * @P11_KIT_URI_FOR_TOKEN: The URI represents one or more tokens
 * @P11_KIT_URI_FOR_MODULE: The URI represents one or more modules
 * @P11_KIT_URI_FOR_MODULE_WITH_VERSION: The URI represents a module with
 *     a specific version.
 * @P11_KIT_URI_FOR_OBJECT_ON_TOKEN: The URI represents one or more objects
 *     that are present on a specific token.
 * @P11_KIT_URI_FOR_OBJECT_ON_TOKEN_AND_MODULE: The URI represents one or more
 *     objects that are present on a specific token, being used with a certain
 *     module.
 * @P11_KIT_URI_FOR_ANY: The URI can represent anything
 *
 * A PKCS\#11 URI can represent different kinds of things. This flag is used by
 * p11_kit_uri_parse() to denote in what context the URI will be used.
 *
 * The various types can be combined.
 */

/**
 * P11KitUriResult:
 * @P11_KIT_URI_OK: Success
 * @P11_KIT_URI_UNEXPECTED: Unexpected or internal system error
 * @P11_KIT_URI_BAD_SCHEME: The URI had a bad scheme
 * @P11_KIT_URI_BAD_ENCODING: The URI had a bad encoding
 * @P11_KIT_URI_BAD_SYNTAX: The URI had a bad syntax
 * @P11_KIT_URI_BAD_VERSION: The URI contained a bad version number
 * @P11_KIT_URI_NOT_FOUND: A requested part of the URI was not found
 *
 * Error codes returned by various functions. The functions each clearly state
 * which error codes they are capable of returning.
 */

/**
 * P11_KIT_URI_NO_MEMORY:
 *
 * Unexpected memory allocation failure result. Same as #P11_KIT_URI_UNEXPECTED.
 */

/**
 * P11_KIT_URI_SCHEME:
 *
 * String of URI scheme for PKCS\#11 URIs.
 */

/**
 * P11_KIT_URI_SCHEME_LEN:
 *
 * Length of %P11_KIT_URI_SCHEME.
 */

struct p11_kit_uri {
	bool unrecognized;
	CK_INFO module;
	CK_TOKEN_INFO token;
	CK_ATTRIBUTE *attrs;
	char *pin_source;
	char *pin_value;
};

static char *
key_decode (const char *value, const char *end)
{
	size_t length = (end - value);
	char *at, *pos;
	char *key;

	key = malloc (length + 1);
	return_val_if_fail (key != NULL, NULL);

	memcpy (key, value, length);
	key[length] = '\0';

	/* Do we have any whitespace? Strip it out. */
	if (strcspn (key, P11_URL_WHITESPACE) != length) {
		for (at = key, pos = key; pos != key + length + 1; ++pos) {
			if (!strchr (P11_URL_WHITESPACE, *pos))
				*(at++) = *pos;
		}
		*at = '\0';
	}

	return key;
}

static bool
match_struct_string (const unsigned char *inuri, const unsigned char *real,
                     size_t length)
{
	assert (inuri);
	assert (real);
	assert (length > 0);

	/* NULL matches anything */
	if (inuri[0] == 0)
		return true;

	return memcmp (inuri, real, length) == 0 ? true : false;
}

static bool
match_struct_version (CK_VERSION_PTR inuri, CK_VERSION_PTR real)
{
	/* This matches anything */
	if (inuri->major == (CK_BYTE)-1 && inuri->minor == (CK_BYTE)-1)
		return true;

	return memcmp (inuri, real, sizeof (CK_VERSION)) == 0 ? true : false;
}

/**
 * p11_kit_uri_get_module_info:
 * @uri: the URI
 *
 * Get the <code>CK_INFO</code> structure associated with this URI.
 *
 * If this is a parsed URI, then the fields corresponding to library parts of
 * the URI will be filled in. Any library URI parts that were missing will have
 * their fields filled with zeros.
 *
 * If the caller wishes to setup information for building a URI, then relevant
 * fields should be filled in. Fields that should not appear as parts in the
 * resulting URI should be filled with zeros.
 *
 * Returns: A pointer to the <code>CK_INFO</code> structure.
 */
CK_INFO_PTR
p11_kit_uri_get_module_info (P11KitUri *uri)
{
	return_val_if_fail (uri != NULL, NULL);
	return &uri->module;
}

int
p11_match_uri_module_info (CK_INFO_PTR one,
                           CK_INFO_PTR two)
{
	return (match_struct_string (one->libraryDescription,
	                             two->libraryDescription,
	                             sizeof (one->libraryDescription)) &&
	        match_struct_string (one->manufacturerID,
	                             two->manufacturerID,
	                             sizeof (one->manufacturerID)) &&
	        match_struct_version (&one->libraryVersion,
	                              &two->libraryVersion));
}

/**
 * p11_kit_uri_match_module_info:
 * @uri: the URI
 * @info: the structure to match against the URI
 *
 * Match a <code>CK_INFO</code> structure against the library parts of this URI.
 *
 * Only the fields of the <code>CK_INFO</code> structure that are valid for use
 * in a URI will be matched. A URI part that was not specified in the URI will
 * match any value in the structure. If during the URI parsing any unrecognized
 * parts were encountered then this match will fail.
 *
 * Returns: 1 if the URI matches, 0 if not.
 */
int
p11_kit_uri_match_module_info (P11KitUri *uri, CK_INFO_PTR info)
{
	return_val_if_fail (uri != NULL, 0);
	return_val_if_fail (info != NULL, 0);

	if (uri->unrecognized)
		return 0;

	return p11_match_uri_module_info (&uri->module, info);
}

/**
 * p11_kit_uri_get_token_info:
 * @uri: the URI
 *
 * Get the <code>CK_TOKEN_INFO</code> structure associated with this URI.
 *
 * If this is a parsed URI, then the fields corresponding to token parts of
 * the URI will be filled in. Any token URI parts that were missing will have
 * their fields filled with zeros.
 *
 * If the caller wishes to setup information for building a URI, then relevant
 * fields should be filled in. Fields that should not appear as parts in the
 * resulting URI should be filled with zeros.
 *
 * Returns: A pointer to the <code>CK_INFO</code> structure.
 */
CK_TOKEN_INFO_PTR
p11_kit_uri_get_token_info (P11KitUri *uri)
{
	return_val_if_fail (uri != NULL, NULL);
	return &uri->token;
}

int
p11_match_uri_token_info (CK_TOKEN_INFO_PTR one,
                          CK_TOKEN_INFO_PTR two)
{
	return (match_struct_string (one->label,
	                             two->label,
	                             sizeof (one->label)) &&
	        match_struct_string (one->manufacturerID,
	                             two->manufacturerID,
	                             sizeof (one->manufacturerID)) &&
	        match_struct_string (one->model,
	                             two->model,
	                             sizeof (one->model)) &&
	        match_struct_string (one->serialNumber,
	                             two->serialNumber,
	                             sizeof (one->serialNumber)));
}

/**
 * p11_kit_uri_match_token_info:
 * @uri: the URI
 * @token_info: the structure to match against the URI
 *
 * Match a <code>CK_TOKEN_INFO</code> structure against the token parts of this
 * URI.
 *
 * Only the fields of the <code>CK_TOKEN_INFO</code> structure that are valid
 * for use in a URI will be matched. A URI part that was not specified in the
 * URI will match any value in the structure. If during the URI parsing any
 * unrecognized parts were encountered then this match will fail.
 *
 * Returns: 1 if the URI matches, 0 if not.
 */
int
p11_kit_uri_match_token_info (P11KitUri *uri, CK_TOKEN_INFO_PTR token_info)
{
	return_val_if_fail (uri != NULL, 0);
	return_val_if_fail (token_info != NULL, 0);

	if (uri->unrecognized)
		return 0;

	return p11_match_uri_token_info (&uri->token, token_info);
}

/**
 * p11_kit_uri_get_attribute:
 * @uri: The URI
 * @attr_type: The attribute type
 *
 * Get a pointer to an attribute present in this URI.
 *
 * Returns: A pointer to the attribute, or <code>NULL</code> if not present.
 *     The attribute is owned by the URI and should not be freed.
 */
CK_ATTRIBUTE_PTR
p11_kit_uri_get_attribute (P11KitUri *uri, CK_ATTRIBUTE_TYPE attr_type)
{
	return_val_if_fail (uri != NULL, NULL);

	if (uri->attrs == NULL)
		return NULL;

	return p11_attrs_find (uri->attrs, attr_type);
}

/**
 * p11_kit_uri_set_attribute:
 * @uri: The URI
 * @attr: The attribute to set
 *
 * Set an attribute on the URI.
 *
 * Only attributes that map to parts in a PKCS\#11 URI will be accepted.
 *
 * Returns: %P11_KIT_URI_OK if the attribute was successfully set.
 *     %P11_KIT_URI_NOT_FOUND if the attribute was not valid for a URI.
 */
int
p11_kit_uri_set_attribute (P11KitUri *uri, CK_ATTRIBUTE_PTR attr)
{
	return_val_if_fail (uri != NULL, P11_KIT_URI_UNEXPECTED);

	uri->attrs = p11_attrs_buildn (uri->attrs, attr, 1);
	return_val_if_fail (uri->attrs != NULL, P11_KIT_URI_UNEXPECTED);

	return P11_KIT_URI_OK;
}

/**
 * p11_kit_uri_clear_attribute:
 * @uri: The URI
 * @attr_type: The type of the attribute to clear
 *
 * Clear an attribute on the URI.
 *
 * Only attributes that map to parts in a PKCS\#11 URI will be accepted.
 *
 * Returns: %P11_KIT_URI_OK if the attribute was successfully cleared.
 *     %P11_KIT_URI_NOT_FOUND if the attribute was not valid for a URI.
 */
int
p11_kit_uri_clear_attribute (P11KitUri *uri, CK_ATTRIBUTE_TYPE attr_type)
{
	return_val_if_fail (uri != NULL, P11_KIT_URI_UNEXPECTED);

	if (attr_type != CKA_CLASS &&
	    attr_type != CKA_LABEL &&
	    attr_type != CKA_ID)
		return P11_KIT_URI_NOT_FOUND;

	if (uri->attrs)
		p11_attrs_remove (uri->attrs, attr_type);

	return P11_KIT_URI_OK;
}

/**
 * p11_kit_uri_get_attribute_types:
 * @uri: The URI
 * @n_attrs: A location to store the number of attributes returned.
 *
 * Get the attributes present in this URI. The attributes and values are
 * owned by the URI. If the URI is modified, then the attributes that were
 * returned from this function will not remain consistent.
 *
 * Returns: The attributes for this URI. These are owned by the URI.
 */
CK_ATTRIBUTE_PTR
p11_kit_uri_get_attributes (P11KitUri *uri, CK_ULONG_PTR n_attrs)
{
	static const CK_ATTRIBUTE terminator = { CKA_INVALID, NULL, 0UL };

	return_val_if_fail (uri != NULL, NULL);

	if (!uri->attrs) {
		if (n_attrs)
			*n_attrs = 0;
		return (CK_ATTRIBUTE_PTR)&terminator;
	}

	if (n_attrs)
		*n_attrs = p11_attrs_count (uri->attrs);
	return uri->attrs;
}

int
p11_kit_uri_set_attributes (P11KitUri *uri, CK_ATTRIBUTE_PTR attrs,
                            CK_ULONG n_attrs)
{
	CK_ULONG i;
	int ret;

	return_val_if_fail (uri != NULL, P11_KIT_URI_UNEXPECTED);

	p11_kit_uri_clear_attributes (uri);

	for (i = 0; i < n_attrs; i++) {
		ret = p11_kit_uri_set_attribute (uri, &attrs[i]);
		if (ret != P11_KIT_URI_OK && ret != P11_KIT_URI_NOT_FOUND)
			return ret;
	}

	return P11_KIT_URI_OK;
}

void
p11_kit_uri_clear_attributes (P11KitUri *uri)
{
	return_if_fail (uri != NULL);

	p11_attrs_free (uri->attrs);
	uri->attrs = NULL;
}

/**
 * p11_kit_uri_match_attributes:
 * @uri: The URI
 * @attrs: The attributes to match
 * @n_attrs: The number of attributes
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
	CK_ATTRIBUTE *attr;
	CK_ULONG i;

	return_val_if_fail (uri != NULL, 0);
	return_val_if_fail (attrs != NULL || n_attrs == 0, 0);

	if (uri->unrecognized)
		return 0;

	for (i = 0; i < n_attrs; i++) {
		if (attrs[i].type != CKA_CLASS &&
		    attrs[i].type != CKA_LABEL &&
		    attrs[i].type != CKA_ID)
			continue;
		attr = NULL;
		if (uri->attrs)
			attr = p11_attrs_find (uri->attrs, attrs[i].type);
		if (!attr)
			continue;
		if (!p11_attr_equal (attr, attrs + i))
			return 0;
	}

	return 1;
}

/**
 * p11_kit_uri_set_unrecognized:
 * @uri: The URI
 * @unrecognized: The new unregognized flag value
 *
 * Set the unrecognized flag on this URI.
 *
 * The unrecognized flag is automatically set to 1 when during parsing any part
 * of the URI is unrecognized. If the unrecognized flag is set to 1, then
 * matching against this URI will always fail.
 */
void
p11_kit_uri_set_unrecognized (P11KitUri *uri, int unrecognized)
{
	return_if_fail (uri != NULL);
	uri->unrecognized = unrecognized ? true : false;
}

/**
 * p11_kit_uri_any_unrecognized:
 * @uri: The URI
 *
 * Get the unrecognized flag for this URI.
 *
 * The unrecognized flag is automatically set to 1 when during parsing any part
 * of the URI is unrecognized. If the unrecognized flag is set to 1, then
 * matching against this URI will always fail.
 *
 * Returns: 1 if unrecognized flag is set, 0 otherwise.
 */
int
p11_kit_uri_any_unrecognized (P11KitUri *uri)
{
	return_val_if_fail (uri != NULL, 1);
	return uri->unrecognized;
}

/**
 * p11_kit_uri_get_pin_value:
 * @uri: The URI
 *
 * Get the 'pin-value' part of the URI. This is used by some applications to
 * read the PIN for logging into a PKCS\#11 token.
 *
 * Returns: The pin-value or %NULL if not present.
 */
const char*
p11_kit_uri_get_pin_value (P11KitUri *uri)
{
	return_val_if_fail (uri != NULL, NULL);
	return uri->pin_value;
}

/**
 * p11_kit_uri_set_pin_value:
 * @uri: The URI
 * @pin: The new pin-value
 *
 * Set the 'pin-value' part of the URI. This is used by some applications to
 * specify the PIN for logging into a PKCS\#11 token.
 */
void
p11_kit_uri_set_pin_value (P11KitUri *uri, const char *pin)
{
	return_if_fail (uri != NULL);
	free (uri->pin_value);
	uri->pin_value = pin ? strdup (pin) : NULL;
}


/**
 * p11_kit_uri_get_pin_source:
 * @uri: The URI
 *
 * Get the 'pin-source' part of the URI. This is used by some applications to
 * lookup a PIN for logging into a PKCS\#11 token.
 *
 * Returns: The pin-source or %NULL if not present.
 */
const char*
p11_kit_uri_get_pin_source (P11KitUri *uri)
{
	return_val_if_fail (uri != NULL, NULL);
	return uri->pin_source;
}

/**
 * p11_kit_uri_get_pinfile:
 * @uri: The URI
 *
 * Deprecated: use p11_kit_uri_get_pin_source().
 */
const char*
p11_kit_uri_get_pinfile (P11KitUri *uri)
{
	return_val_if_fail (uri != NULL, NULL);
	return p11_kit_uri_get_pin_source (uri);
}

/**
 * p11_kit_uri_set_pin_source:
 * @uri: The URI
 * @pin_source: The new pin-source
 *
 * Set the 'pin-source' part of the URI. This is used by some applications to
 * lookup a PIN for logging into a PKCS\#11 token.
 */
void
p11_kit_uri_set_pin_source (P11KitUri *uri, const char *pin_source)
{
	return_if_fail (uri != NULL);
	free (uri->pin_source);
	uri->pin_source = pin_source ? strdup (pin_source) : NULL;
}

/**
 * p11_kit_uri_set_pinfile:
 * @uri: The URI
 * @pinfile: The pinfile
 *
 * Deprecated: use p11_kit_uri_set_pin_source().
 */
void
p11_kit_uri_set_pinfile (P11KitUri *uri, const char *pinfile)
{
	return_if_fail (uri != NULL);
	p11_kit_uri_set_pin_source (uri, pinfile);
}

/**
 * p11_kit_uri_new:
 *
 * Create a new blank PKCS\#11 URI.
 *
 * The new URI is in the right state to parse a string into. All relevant fields
 * are zeroed out. Formatting this URI will produce a valid but empty URI.
 *
 * Returns: A newly allocated URI. This should be freed with p11_kit_uri_free().
 */
P11KitUri*
p11_kit_uri_new (void)
{
	P11KitUri *uri;

	uri = calloc (1, sizeof (P11KitUri));
	return_val_if_fail (uri != NULL, NULL);

	/* So that it matches anything */
	uri->module.libraryVersion.major = (CK_BYTE)-1;
	uri->module.libraryVersion.minor = (CK_BYTE)-1;

	return uri;
}

static void
format_name_equals (p11_buffer *buffer,
                    bool *is_first,
                    const char *name)
{
	if (!*is_first)
		p11_buffer_add (buffer, ";", 1);
	p11_buffer_add (buffer, name, -1);
	p11_buffer_add (buffer, "=", 1);
	*is_first = false;
}

static bool
format_raw_string (p11_buffer *buffer,
                   bool *is_first,
                   const char *name,
                   const char *value)
{
	/* Not set */
	if (!value)
		return true;

	format_name_equals (buffer, is_first, name);
	p11_buffer_add (buffer, value, -1);

	return p11_buffer_ok (buffer);
}

static bool
format_encode_string (p11_buffer *buffer,
                      bool *is_first,
                      const char *name,
                      const unsigned char *value,
                      size_t n_value,
                      bool force)
{
	/* Not set */
	if (!value)
		return true;

	format_name_equals (buffer, is_first, name);
	p11_url_encode (value, value + n_value, force ? "" : P11_URL_VERBATIM, buffer);

	return p11_buffer_ok (buffer);
}


static bool
format_struct_string (p11_buffer *buffer,
                      bool *is_first,
                      const char *name,
                      const unsigned char *value,
                      size_t value_max)
{
	size_t len;

	/* Not set */
	if (!value[0])
		return true;

	len = p11_kit_space_strlen (value, value_max);
	return format_encode_string (buffer, is_first, name, value, len, false);
}

static bool
format_attribute_string (p11_buffer *buffer,
                         bool *is_first,
                         const char *name,
                         CK_ATTRIBUTE_PTR attr,
                         bool force)
{
	/* Not set */;
	if (attr == NULL)
		return true;

	return format_encode_string (buffer, is_first, name,
	                             attr->pValue, attr->ulValueLen,
	                             force);
}

static bool
format_attribute_class (p11_buffer *buffer,
                        bool *is_first,
                        const char *name,
                        CK_ATTRIBUTE_PTR attr)
{
	CK_OBJECT_CLASS klass;
	const char *value;

	/* Not set */;
	if (attr == NULL)
		return true;

	klass = *((CK_OBJECT_CLASS*)attr->pValue);
	switch (klass) {
	case CKO_DATA:
		value = "data";
		break;
	case CKO_SECRET_KEY:
		value = "secret-key";
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
	default:
		return true;
	}

	return format_raw_string (buffer, is_first, name, value);
}

static bool
format_struct_version (p11_buffer *buffer,
                       bool *is_first,
                       const char *name,
                       CK_VERSION_PTR version)
{
	char buf[64];

	/* Not set */
	if (version->major == (CK_BYTE)-1 && version->minor == (CK_BYTE)-1)
		return true;

	snprintf (buf, sizeof (buf), "%d.%d",
	          (int)version->major, (int)version->minor);
	return format_raw_string (buffer, is_first, name, buf);
}

/**
 * p11_kit_uri_format:
 * @uri: The URI.
 * @uri_type: The type of URI that should be produced.
 * @string: Location to store a newly allocated string.
 *
 * Format a PKCS\#11 URI into a string.
 *
 * Fields which are zeroed out will not be included in the resulting string.
 * Attributes which are not present will also not be included.
 *
 * The uri_type of URI specified limits the different parts of the resulting
 * URI. To format a URI containing all possible information use
 * %P11_KIT_URI_FOR_ANY
 *
 * It's up to the caller to guarantee that the attributes set in @uri are
 * those appropriate for inclusion in a URI, specifically:
 * <literal>CKA_ID</literal>, <literal>CKA_LABEL</literal>
 * and <literal>CKA_CLASS</literal>. The class must be one of
 * <literal>CKO_DATA</literal>, <literal>CKO_SECRET_KEY</literal>,
 * <literal>CKO_CERTIFICATE</literal>, <literal>CKO_PUBLIC_KEY</literal>,
 * <literal>CKO_PRIVATE_KEY</literal>.
 *
 * The resulting string should be freed with free().
 *
 * Returns: %P11_KIT_URI_OK if the URI was formatted successfully,
 *          %P11_KIT_URI_UNEXPECTED if the data in @uri is invalid for a URI.
 */
int
p11_kit_uri_format (P11KitUri *uri, P11KitUriType uri_type, char **string)
{
	p11_buffer buffer;
	bool is_first = true;

	return_val_if_fail (uri != NULL, P11_KIT_URI_UNEXPECTED);
	return_val_if_fail (string != NULL, P11_KIT_URI_UNEXPECTED);

	if (!p11_buffer_init_null (&buffer, 64))
		return_val_if_reached (P11_KIT_URI_UNEXPECTED);

	p11_buffer_add (&buffer, P11_KIT_URI_SCHEME, P11_KIT_URI_SCHEME_LEN);
	p11_buffer_add (&buffer, ":", 1);

	if ((uri_type & P11_KIT_URI_FOR_MODULE) == P11_KIT_URI_FOR_MODULE) {
		if (!format_struct_string (&buffer, &is_first, "library-description",
		                           uri->module.libraryDescription,
		                           sizeof (uri->module.libraryDescription)) ||
		    !format_struct_string (&buffer, &is_first, "library-manufacturer",
		                           uri->module.manufacturerID,
		                           sizeof (uri->module.manufacturerID))) {
			return_val_if_reached (P11_KIT_URI_UNEXPECTED);
		}
	}

	if ((uri_type & P11_KIT_URI_FOR_MODULE_WITH_VERSION) == P11_KIT_URI_FOR_MODULE_WITH_VERSION) {
		if (!format_struct_version (&buffer, &is_first, "library-version",
		                            &uri->module.libraryVersion)) {
			return_val_if_reached (P11_KIT_URI_UNEXPECTED);
		}
	}

	if ((uri_type & P11_KIT_URI_FOR_TOKEN) == P11_KIT_URI_FOR_TOKEN) {
		if (!format_struct_string (&buffer, &is_first, "model",
		                           uri->token.model,
		                           sizeof (uri->token.model)) ||
		    !format_struct_string (&buffer, &is_first, "manufacturer",
		                           uri->token.manufacturerID,
		                           sizeof (uri->token.manufacturerID)) ||
		    !format_struct_string (&buffer, &is_first, "serial",
		                           uri->token.serialNumber,
		                           sizeof (uri->token.serialNumber)) ||
		    !format_struct_string (&buffer, &is_first, "token",
		                           uri->token.label,
		                           sizeof (uri->token.label))) {
			return_val_if_reached (P11_KIT_URI_UNEXPECTED);
		}
	}

	if ((uri_type & P11_KIT_URI_FOR_OBJECT) == P11_KIT_URI_FOR_OBJECT) {
		if (!format_attribute_string (&buffer, &is_first, "id",
		                              p11_kit_uri_get_attribute (uri, CKA_ID),
		                              true) ||
		    !format_attribute_string (&buffer, &is_first, "object",
		                              p11_kit_uri_get_attribute (uri, CKA_LABEL),
		                              false)) {
			return_val_if_reached (P11_KIT_URI_UNEXPECTED);
		}

		if (!format_attribute_class (&buffer, &is_first, "type",
		                             p11_kit_uri_get_attribute (uri, CKA_CLASS))) {
			return_val_if_reached (P11_KIT_URI_UNEXPECTED);
		}
	}

	if (uri->pin_source) {
		if (!format_encode_string (&buffer, &is_first, "pin-source",
		                           (const unsigned char*)uri->pin_source,
		                           strlen (uri->pin_source), 0)) {
			return_val_if_reached (P11_KIT_URI_UNEXPECTED);
		}
	}

	if (uri->pin_value) {
		if (!format_encode_string (&buffer, &is_first, "pin-value",
		                           (const unsigned char*)uri->pin_value,
		                           strlen (uri->pin_value), 0)) {
			return_val_if_reached (P11_KIT_URI_UNEXPECTED);
		}
	}

	return_val_if_fail (p11_buffer_ok (&buffer), P11_KIT_URI_UNEXPECTED);
	*string = p11_buffer_steal (&buffer, NULL);
	return P11_KIT_URI_OK;
}

static int
parse_string_attribute (const char *name, const char *start, const char *end,
                        P11KitUri *uri)
{
	unsigned char *value;
	CK_ATTRIBUTE_TYPE type;
	size_t length;

	assert (start <= end);

	if (strcmp ("id", name) == 0)
		type = CKA_ID;
	else if (strcmp ("object", name) == 0)
		type = CKA_LABEL;
	else
		return 0;

	value = p11_url_decode (start, end, P11_URL_WHITESPACE, &length);
	if (value == NULL)
		return P11_KIT_URI_BAD_ENCODING;

	uri->attrs = p11_attrs_take (uri->attrs, type, value, length);
	return 1;
}

static int
parse_class_attribute (const char *name, const char *start, const char *end,
                       P11KitUri *uri)
{
	CK_OBJECT_CLASS klass = 0;
	CK_ATTRIBUTE attr;
	char *value;

	assert (start <= end);

	if (strcmp ("objecttype", name) != 0 &&
	    strcmp ("object-type", name) != 0 &&
	    strcmp ("type", name) != 0)
		return 0;

	value = key_decode (start, end);
	return_val_if_fail (value != NULL, P11_KIT_URI_UNEXPECTED);

	if (strcmp (value, "cert") == 0)
		klass = CKO_CERTIFICATE;
	else if (strcmp (value, "public") == 0)
		klass = CKO_PUBLIC_KEY;
	else if (strcmp (value, "private") == 0)
		klass = CKO_PRIVATE_KEY;
	else if (strcmp (value, "secretkey") == 0)
		klass = CKO_SECRET_KEY;
	else if (strcmp (value, "secret-key") == 0)
		klass = CKO_SECRET_KEY;
	else if (strcmp (value, "data") == 0)
		klass = CKO_DATA;
	else {
		free (value);
		uri->unrecognized = true;
		return 1;
	}

	free (value);

	attr.pValue = &klass;
	attr.ulValueLen = sizeof (klass);
	attr.type = CKA_CLASS;

	uri->attrs = p11_attrs_build (uri->attrs, &attr, NULL);
	return 1;
}

static int
parse_struct_info (unsigned char *where, size_t length, const char *start,
                   const char *end, P11KitUri *uri)
{
	unsigned char *value;
	size_t value_length;

	assert (start <= end);

	value = p11_url_decode (start, end, P11_URL_WHITESPACE, &value_length);
	if (value == NULL)
		return P11_KIT_URI_BAD_ENCODING;

	/* Too long, shouldn't match anything */
	if (value_length > length) {
		free (value);
		uri->unrecognized = true;
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
		if (strchr (P11_URL_WHITESPACE, *start)) {
			start++;
			continue;
		}
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
parse_module_version_info (const char *name, const char *start, const char *end,
                           P11KitUri *uri)
{
	assert (start <= end);

	if (strcmp (name, "library-version") == 0)
		return parse_struct_version (start, end,
		                             &uri->module.libraryVersion);

	return 0;
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
	} else {
		return 0;
	}

	return parse_struct_info (where, length, start, end, uri);
}

static int
parse_extra_info (const char *name, const char *start, const char *end,
                  P11KitUri *uri)
{
	unsigned char *pin_source;

	assert (start <= end);

	if (strcmp (name, "pinfile") == 0 ||
	    strcmp (name, "pin-source") == 0) {
		pin_source = p11_url_decode (start, end, P11_URL_WHITESPACE, NULL);
		if (pin_source == NULL)
			return P11_KIT_URI_BAD_ENCODING;
		free (uri->pin_source);
		uri->pin_source = (char*)pin_source;
		return 1;
	} else if (strcmp (name, "pin-value") == 0) {
		pin_source = p11_url_decode (start, end, P11_URL_WHITESPACE, NULL);
		if (pin_source == NULL)
			return P11_KIT_URI_BAD_ENCODING;
		free (uri->pin_value);
		uri->pin_value = (char*)pin_source;
		return 1;
	}

	return 0;
}

/**
 * p11_kit_uri_parse:
 * @string: The string to parse
 * @uri_type: The type of URI that is expected
 * @uri: The blank URI to parse the values into
 *
 * Parse a PKCS\#11 URI string.
 *
 * PKCS\#11 URIs can represent tokens, objects or modules. The uri_type argument
 * allows the caller to specify what type of URI is expected and the sorts of
 * things the URI should match. %P11_KIT_URI_FOR_ANY can be used to parse a URI
 * for any context. It's then up to the caller to make sense of the way that
 * it is used.
 *
 * If the PKCS\#11 URI contains unrecognized URI parts or parts not applicable
 * to the specified context, then the unrecognized flag will be set. This will
 * prevent the URI from matching using the various match functions.
 *
 * Returns: %P11_KIT_URI_OK if the URI was parsed successfully.
 *     %P11_KIT_URI_BAD_SCHEME if this was not a PKCS\#11 URI.
 *     %P11_KIT_URI_BAD_SYNTAX if the URI syntax was bad.
 *     %P11_KIT_URI_BAD_VERSION if a version number was bad.
 *     %P11_KIT_URI_BAD_ENCODING if the URI encoding was invalid.
 */
int
p11_kit_uri_parse (const char *string, P11KitUriType uri_type,
                   P11KitUri *uri)
{
	const char *spos, *epos;
	char *key = NULL;
	int ret;

	assert (string);
	assert (uri);

	epos = strchr (string, ':');
	if (epos == NULL)
		return P11_KIT_URI_BAD_SCHEME;
	key = key_decode (string, epos);
	ret = strcmp (key, P11_KIT_URI_SCHEME);
	free (key);

	if (ret != 0)
		return P11_KIT_URI_BAD_SCHEME;

	string = epos + 1;

	/* Clear everything out */
	memset (&uri->module, 0, sizeof (uri->module));
	memset (&uri->token, 0, sizeof (uri->token));
	p11_attrs_free (uri->attrs);
	uri->attrs = NULL;
	uri->module.libraryVersion.major = (CK_BYTE)-1;
	uri->module.libraryVersion.minor = (CK_BYTE)-1;
	uri->unrecognized = 0;
	free (uri->pin_source);
	uri->pin_source = NULL;
	free (uri->pin_value);
	uri->pin_value = NULL;

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

		key = key_decode (string, epos);
		return_val_if_fail (key != NULL, P11_KIT_URI_UNEXPECTED);
		epos++;

		ret = 0;
		if ((uri_type & P11_KIT_URI_FOR_OBJECT) == P11_KIT_URI_FOR_OBJECT)
			ret = parse_string_attribute (key, epos, spos, uri);
		if (ret == 0 && (uri_type & P11_KIT_URI_FOR_OBJECT) == P11_KIT_URI_FOR_OBJECT)
			ret = parse_class_attribute (key, epos, spos, uri);
		if (ret == 0 && (uri_type & P11_KIT_URI_FOR_TOKEN) == P11_KIT_URI_FOR_TOKEN)
			ret = parse_token_info (key, epos, spos, uri);
		if (ret == 0 && (uri_type & P11_KIT_URI_FOR_MODULE) == P11_KIT_URI_FOR_MODULE)
			ret = parse_module_info (key, epos, spos, uri);
		if (ret == 0 && (uri_type & P11_KIT_URI_FOR_MODULE_WITH_VERSION) == P11_KIT_URI_FOR_MODULE_WITH_VERSION)
			ret = parse_module_version_info (key, epos, spos, uri);
		if (ret == 0)
			ret = parse_extra_info (key, epos, spos, uri);
		free (key);

		if (ret < 0)
			return ret;
		if (ret == 0)
			uri->unrecognized = true;

		if (*spos == '\0')
			break;
		string = spos + 1;
	}

	return P11_KIT_URI_OK;
}

/**
 * p11_kit_uri_free:
 * @uri: The URI
 *
 * Free a PKCS\#11 URI.
 */
void
p11_kit_uri_free (P11KitUri *uri)
{
	if (!uri)
		return;

	p11_attrs_free (uri->attrs);
	free (uri->pin_source);
	free (uri->pin_value);
	free (uri);
}

/**
 * p11_kit_uri_message:
 * @code: The error code
 *
 * Lookup a message for the uri error code. These codes are the P11_KIT_URI_XXX
 * error codes that can be returned from p11_kit_uri_parse() or
 * p11_kit_uri_format(). As a special case %NULL, will be returned for
 * %P11_KIT_URI_OK.
 *
 * Returns: The message for the error code. This string is owned by the p11-kit
 *      library.
 */
const char*
p11_kit_uri_message (int code)
{
	switch (code) {
	case P11_KIT_URI_OK:
		return NULL;
	case P11_KIT_URI_UNEXPECTED:
		return "Unexpected or internal system error";
	case P11_KIT_URI_BAD_SCHEME:
		return "URI scheme must be 'pkcs11:'";
	case P11_KIT_URI_BAD_ENCODING:
		return "URI encoding invalid or corrupted";
	case P11_KIT_URI_BAD_SYNTAX:
		return "URI syntax is invalid";
	case P11_KIT_URI_BAD_VERSION:
		return "URI version component is invalid";
	case P11_KIT_URI_NOT_FOUND:
		return "The URI component was not found";
	default:
		p11_debug ("unknown error code: %d", code);
		return "Unknown error";
	}
}
