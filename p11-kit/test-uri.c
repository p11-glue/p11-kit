/*
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
#include "test.h"

#include "debug.h"
#include "message.h"

#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "p11-kit/uri.h"
#include "p11-kit/private.h"

static int
is_module_empty (P11KitUri *uri)
{
	CK_INFO_PTR info = p11_kit_uri_get_module_info (uri);
	return (info->libraryDescription[0] == 0 &&
	        info->manufacturerID[0] == 0 &&
	        info->libraryVersion.major == (CK_BYTE)-1 &&
	        info->libraryVersion.minor == (CK_BYTE)-1);
}

static int
is_token_empty (P11KitUri *uri)
{
	CK_TOKEN_INFO_PTR token = p11_kit_uri_get_token_info (uri);
	return (token->serialNumber[0] == 0 &&
	        token->manufacturerID[0] == 0 &&
	        token->label[0] == 0 &&
	        token->model[0] == 0);
}

static int
are_attributes_empty (P11KitUri *uri)
{
	return (p11_kit_uri_get_attribute (uri, CKA_LABEL) == NULL &&
	        p11_kit_uri_get_attribute (uri, CKA_ID) == NULL &&
	        p11_kit_uri_get_attribute (uri, CKA_CLASS) == NULL);
}

static void
test_uri_parse (void)
{
	P11KitUri *uri;
	int ret;

	uri = p11_kit_uri_new ();
	assert_ptr_not_null (uri);

	ret = p11_kit_uri_parse ("pkcs11:", P11_KIT_URI_FOR_MODULE, uri);
	assert_num_eq (P11_KIT_URI_OK, ret);

	assert (is_module_empty (uri));
	assert (is_token_empty (uri));
	assert (are_attributes_empty (uri));

	p11_kit_uri_free (uri);
}

static void
test_uri_parse_bad_scheme (void)
{
	P11KitUri *uri;
	int ret;

	uri = p11_kit_uri_new ();
	assert_ptr_not_null (uri);

	ret = p11_kit_uri_parse ("http:\\example.com\test", P11_KIT_URI_FOR_ANY, uri);
	assert_num_eq (P11_KIT_URI_BAD_SCHEME, ret);

	p11_kit_uri_free (uri);
}

static void
test_uri_parse_with_label (void)
{
	CK_ATTRIBUTE_PTR attr;
	P11KitUri *uri;
	int ret;

	uri = p11_kit_uri_new ();
	assert_ptr_not_null (uri);

	ret = p11_kit_uri_parse ("pkcs11:object=Test%20Label", P11_KIT_URI_FOR_ANY, uri);
	assert_num_eq (P11_KIT_URI_OK, ret);

	assert (is_module_empty (uri));
	assert (is_token_empty (uri));

	attr = p11_kit_uri_get_attribute (uri, CKA_LABEL);
	assert_ptr_not_null (attr);
	assert (attr->ulValueLen == strlen ("Test Label"));
	assert (memcmp (attr->pValue, "Test Label", attr->ulValueLen) == 0);

	p11_kit_uri_free (uri);
}

static void
test_uri_parse_with_label_and_klass (void)
{
	CK_ATTRIBUTE_PTR attr;
	P11KitUri *uri;
	int ret;

	uri = p11_kit_uri_new ();
	assert_ptr_not_null (uri);

	ret = p11_kit_uri_parse ("pkcs11:object=Test%20Label;object-type=cert", P11_KIT_URI_FOR_ANY, uri);
	assert_num_eq (P11_KIT_URI_OK, ret);

	attr = p11_kit_uri_get_attribute (uri, CKA_LABEL);
	assert_ptr_not_null (attr);
	assert (attr->ulValueLen == strlen ("Test Label"));
	assert (memcmp (attr->pValue, "Test Label", attr->ulValueLen) == 0);

	attr = p11_kit_uri_get_attribute (uri, CKA_CLASS);
	assert_ptr_not_null (attr);
	assert (attr->ulValueLen == sizeof (CK_OBJECT_CLASS));
	assert (*((CK_OBJECT_CLASS_PTR)attr->pValue) == CKO_CERTIFICATE);

	p11_kit_uri_free (uri);
}

static void
test_uri_parse_with_label_and_new_klass (void)
{
	CK_ATTRIBUTE_PTR attr;
	P11KitUri *uri;
	int ret;

	uri = p11_kit_uri_new ();
	assert_ptr_not_null (uri);

	ret = p11_kit_uri_parse ("pkcs11:object=Test%20Label;type=cert", P11_KIT_URI_FOR_ANY, uri);
	assert_num_eq (P11_KIT_URI_OK, ret);

	attr = p11_kit_uri_get_attribute (uri, CKA_LABEL);
	assert_ptr_not_null (attr);
	assert (attr->ulValueLen == strlen ("Test Label"));
	assert (memcmp (attr->pValue, "Test Label", attr->ulValueLen) == 0);

	attr = p11_kit_uri_get_attribute (uri, CKA_CLASS);
	assert_ptr_not_null (attr);
	assert (attr->ulValueLen == sizeof (CK_OBJECT_CLASS));
	assert (*((CK_OBJECT_CLASS_PTR)attr->pValue) == CKO_CERTIFICATE);

	p11_kit_uri_free (uri);
}

static void
test_uri_parse_with_empty_label (void)
{
	CK_ATTRIBUTE_PTR attr;
	P11KitUri *uri;
	int ret;

	uri = p11_kit_uri_new ();
	assert_ptr_not_null (uri);

	ret = p11_kit_uri_parse ("pkcs11:object=;type=cert", P11_KIT_URI_FOR_ANY, uri);
	assert_num_eq (P11_KIT_URI_OK, ret);

	attr = p11_kit_uri_get_attribute (uri, CKA_LABEL);
	assert_ptr_not_null (attr);

	p11_kit_uri_free (uri);

	/* really empty */

	uri = p11_kit_uri_new ();
	assert_ptr_not_null (uri);

	ret = p11_kit_uri_parse ("pkcs11:type=cert", P11_KIT_URI_FOR_ANY, uri);
	assert_num_eq (P11_KIT_URI_OK, ret);

	attr = p11_kit_uri_get_attribute (uri, CKA_LABEL);
	assert (attr == NULL);

	p11_kit_uri_free (uri);
}

static void
test_uri_parse_with_empty_id (void)
{
	CK_ATTRIBUTE_PTR attr;
	P11KitUri *uri;
	int ret;

	uri = p11_kit_uri_new ();
	assert_ptr_not_null (uri);

	ret = p11_kit_uri_parse ("pkcs11:id=;type=cert", P11_KIT_URI_FOR_ANY, uri);
	assert_num_eq (P11_KIT_URI_OK, ret);

	attr = p11_kit_uri_get_attribute (uri, CKA_ID);
	assert_ptr_not_null (attr);

	p11_kit_uri_free (uri);

	/* really empty */

	uri = p11_kit_uri_new ();
	assert_ptr_not_null (uri);

	ret = p11_kit_uri_parse ("pkcs11:type=cert", P11_KIT_URI_FOR_ANY, uri);
	assert_num_eq (P11_KIT_URI_OK, ret);

	attr = p11_kit_uri_get_attribute (uri, CKA_ID);
	assert (attr == NULL);

	p11_kit_uri_free (uri);
}

static void
test_uri_parse_with_id (void)
{
	CK_ATTRIBUTE_PTR attr;
	P11KitUri *uri;
	int ret;

	uri = p11_kit_uri_new ();
	assert_ptr_not_null (uri);

	ret = p11_kit_uri_parse ("pkcs11:id=%54%45%53%54%00", P11_KIT_URI_FOR_OBJECT, uri);
	assert_num_eq (P11_KIT_URI_OK, ret);

	/* Note that there's a NULL in the attribute (end) */
	attr = p11_kit_uri_get_attribute (uri, CKA_ID);
	assert_ptr_not_null (attr);
	assert (attr->ulValueLen == 5);
	assert (memcmp (attr->pValue, "TEST", 5) == 0);


	p11_kit_uri_free (uri);
}

static void
test_uri_parse_with_bad_string_encoding (void)
{
	P11KitUri *uri;
	int ret;

	uri = p11_kit_uri_new ();
	assert_ptr_not_null (uri);

	ret = p11_kit_uri_parse ("pkcs11:object=Test%", P11_KIT_URI_FOR_OBJECT, uri);
	assert_num_eq (P11_KIT_URI_BAD_ENCODING, ret);

	p11_kit_uri_free (uri);
}

static void
test_uri_parse_with_bad_hex_encoding (void)
{
	P11KitUri *uri;
	int ret;

	uri = p11_kit_uri_new ();
	assert_ptr_not_null (uri);

	ret = p11_kit_uri_parse ("pkcs11:object=T%xxest", P11_KIT_URI_FOR_OBJECT, uri);
	assert_num_eq (P11_KIT_URI_BAD_ENCODING, ret);

	p11_kit_uri_free (uri);
}

static bool
is_space_string (CK_UTF8CHAR_PTR string, CK_ULONG size, const char *check)
{
	size_t i, len = strlen (check);
	if (len > size)
		return false;
	if (memcmp (string, check, len) != 0)
		return false;
	for (i = len; i < size; ++i)
		if (string[i] != ' ')
			return false;
	return true;
}

static void
test_uri_parse_with_token (void)
{
	P11KitUri *uri = NULL;
	CK_TOKEN_INFO_PTR token;
	int ret;

	uri = p11_kit_uri_new ();
	assert_ptr_not_null (uri);

	ret = p11_kit_uri_parse ("pkcs11:token=Token%20Label;serial=3333;model=Deluxe;manufacturer=Me",
	                         P11_KIT_URI_FOR_TOKEN, uri);
	assert_num_eq (P11_KIT_URI_OK, ret);

	token = p11_kit_uri_get_token_info (uri);
	assert (is_space_string (token->label, sizeof (token->label), "Token Label"));
	assert (is_space_string (token->serialNumber, sizeof (token->serialNumber), "3333"));
	assert (is_space_string (token->model, sizeof (token->model), "Deluxe"));
	assert (is_space_string (token->manufacturerID, sizeof (token->manufacturerID), "Me"));

	p11_kit_uri_free (uri);
}

static void
test_uri_parse_with_token_bad_encoding (void)
{
	P11KitUri *uri;
	int ret;

	uri = p11_kit_uri_new ();
	assert_ptr_not_null (uri);

	ret = p11_kit_uri_parse ("pkcs11:token=Token%", P11_KIT_URI_FOR_TOKEN, uri);
	assert_num_eq (P11_KIT_URI_BAD_ENCODING, ret);

	p11_kit_uri_free (uri);
}

static void
test_uri_parse_with_bad_syntax (void)
{
	P11KitUri *uri;
	int ret;

	uri = p11_kit_uri_new ();
	assert_ptr_not_null (uri);

	ret = p11_kit_uri_parse ("pkcs11:token", P11_KIT_URI_FOR_ANY, uri);
	assert_num_eq (P11_KIT_URI_BAD_SYNTAX, ret);

	p11_kit_uri_free (uri);
}

static void
test_uri_parse_with_spaces (void)
{
	P11KitUri *uri = NULL;
	CK_INFO_PTR info;
	int ret;

	uri = p11_kit_uri_new ();
	assert_ptr_not_null (uri);

	ret = p11_kit_uri_parse ("pkc\ns11: lib rary-desc\rrip  \n  tion =The%20Library;\n\n\nlibrary-manufacturer=\rMe",
	                         P11_KIT_URI_FOR_MODULE, uri);
	assert_num_eq (P11_KIT_URI_OK, ret);

	info = p11_kit_uri_get_module_info (uri);

	assert (is_space_string (info->manufacturerID, sizeof (info->manufacturerID), "Me"));
	assert (is_space_string (info->libraryDescription, sizeof (info->libraryDescription), "The Library"));

	p11_kit_uri_free (uri);
}


static void
test_uri_parse_with_library (void)
{
	P11KitUri *uri = NULL;
	CK_INFO_PTR info;
	int ret;

	uri = p11_kit_uri_new ();
	assert_ptr_not_null (uri);

	ret = p11_kit_uri_parse ("pkcs11:library-description=The%20Library;library-manufacturer=Me",
	                         P11_KIT_URI_FOR_MODULE, uri);
	assert_num_eq (P11_KIT_URI_OK, ret);

	info = p11_kit_uri_get_module_info (uri);

	assert (is_space_string (info->manufacturerID, sizeof (info->manufacturerID), "Me"));
	assert (is_space_string (info->libraryDescription, sizeof (info->libraryDescription), "The Library"));

	p11_kit_uri_free (uri);
}

static void
test_uri_parse_with_library_bad_encoding (void)
{
	P11KitUri *uri;
	int ret;

	uri = p11_kit_uri_new ();
	assert_ptr_not_null (uri);

	ret = p11_kit_uri_parse ("pkcs11:library-description=Library%", P11_KIT_URI_FOR_MODULE, uri);
	assert_num_eq (P11_KIT_URI_BAD_ENCODING, ret);

	p11_kit_uri_free (uri);
}

static void
test_uri_build_empty (void)
{
	P11KitUri *uri;
	char *string;
	int ret;

	uri = p11_kit_uri_new ();
	assert_ptr_not_null (uri);

	ret = p11_kit_uri_format (uri, P11_KIT_URI_FOR_ANY, &string);
	assert_num_eq (P11_KIT_URI_OK, ret);
	assert_str_eq ("pkcs11:", string);
	free (string);

	p11_kit_uri_free (uri);
}

static void
set_space_string (CK_BYTE_PTR buffer, CK_ULONG length, const char *string)
{
	size_t len = strlen (string);
	assert (len <= length);
	memset (buffer, ' ', length);
	memcpy (buffer, string, len);
}

static void
test_uri_build_with_token_info (void)
{
	char *string = NULL;
	P11KitUri *uri;
	P11KitUri *check;
	CK_TOKEN_INFO_PTR token;
	int ret;

	uri = p11_kit_uri_new ();
	assert_ptr_not_null (uri);

	token = p11_kit_uri_get_token_info (uri);
	set_space_string (token->label, sizeof (token->label), "The Label");
	set_space_string (token->serialNumber, sizeof (token->serialNumber), "44444");
	set_space_string (token->manufacturerID, sizeof (token->manufacturerID), "Me");
	set_space_string (token->model, sizeof (token->model), "Deluxe");

	ret = p11_kit_uri_format (uri, P11_KIT_URI_FOR_ANY, &string);
	assert_num_eq (P11_KIT_URI_OK, ret);
	assert_ptr_not_null (string);

	check = p11_kit_uri_new ();
	assert_ptr_not_null (check);

	ret = p11_kit_uri_parse (string, P11_KIT_URI_FOR_TOKEN, check);
	assert_num_eq (P11_KIT_URI_OK, ret);

	p11_kit_uri_match_token_info (check, p11_kit_uri_get_token_info (uri));

	p11_kit_uri_free (uri);
	p11_kit_uri_free (check);

	assert (strstr (string, "token=The%20Label") != NULL);
	assert (strstr (string, "serial=44444") != NULL);
	assert (strstr (string, "manufacturer=Me") != NULL);
	assert (strstr (string, "model=Deluxe") != NULL);

	free (string);
}

static void
test_uri_build_with_token_null_info (void)
{
	char *string = NULL;
	P11KitUri *uri;
	CK_TOKEN_INFO_PTR token;
	int ret;

	uri = p11_kit_uri_new ();
	assert_ptr_not_null (uri);

	token = p11_kit_uri_get_token_info (uri);
	set_space_string (token->label, sizeof (token->label), "The Label");

	ret = p11_kit_uri_format (uri, P11_KIT_URI_FOR_ANY, &string);
	assert_num_eq (P11_KIT_URI_OK, ret);

	assert (strstr (string, "token=The%20Label") != NULL);
	assert (strstr (string, "serial=") == NULL);

	free (string);
	p11_kit_uri_free (uri);
}

static void
test_uri_build_with_token_empty_info (void)
{
	char *string = NULL;
	P11KitUri *uri;
	CK_TOKEN_INFO_PTR token;
	int ret;

	uri = p11_kit_uri_new ();
	assert_ptr_not_null (uri);

	token = p11_kit_uri_get_token_info (uri);
	set_space_string (token->label, sizeof (token->label), "");
	set_space_string (token->serialNumber, sizeof (token->serialNumber), "");

	ret = p11_kit_uri_format (uri, P11_KIT_URI_FOR_ANY, &string);
	assert_num_eq (P11_KIT_URI_OK, ret);

	assert (strstr (string, "token=") != NULL);
	assert (strstr (string, "serial=") != NULL);

	free (string);
	p11_kit_uri_free (uri);
}

static void
test_uri_build_with_attributes (void)
{
	char *string = NULL;
	P11KitUri *uri;
	P11KitUri *check;
	CK_OBJECT_CLASS klass;
	CK_ATTRIBUTE_PTR attr;
	CK_ATTRIBUTE at;
	int ret;

	uri = p11_kit_uri_new ();
	assert_ptr_not_null (uri);

	at.type = CKA_LABEL;
	at.pValue = "The Label";
	at.ulValueLen = 9;
	ret = p11_kit_uri_set_attribute (uri, &at);
	assert_num_eq (P11_KIT_URI_OK, ret);

	at.type = CKA_ID;
	at.pValue = "HELLO";
	at.ulValueLen = 5;
	ret = p11_kit_uri_set_attribute (uri, &at);
	assert_num_eq (P11_KIT_URI_OK, ret);

	klass = CKO_DATA;
	at.type = CKA_CLASS;
	at.pValue = &klass;
	at.ulValueLen = sizeof (klass);
	ret = p11_kit_uri_set_attribute (uri, &at);
	assert_num_eq (P11_KIT_URI_OK, ret);

	ret = p11_kit_uri_format (uri, P11_KIT_URI_FOR_ANY, &string);
	assert_num_eq (P11_KIT_URI_OK, ret);

	check = p11_kit_uri_new ();
	assert_ptr_not_null (check);

	ret = p11_kit_uri_parse (string, P11_KIT_URI_FOR_ANY, check);
	assert_num_eq (P11_KIT_URI_OK, ret);

	attr = p11_kit_uri_get_attribute (check, CKA_LABEL);
	assert_ptr_not_null (attr);
	assert (attr->ulValueLen == 9);
	assert (memcmp (attr->pValue, "The Label", attr->ulValueLen) == 0);

	attr = p11_kit_uri_get_attribute (check, CKA_CLASS);
	assert_ptr_not_null (attr);
	assert (attr->ulValueLen == sizeof (klass));
	assert (*((CK_OBJECT_CLASS_PTR)attr->pValue) == klass);

	attr = p11_kit_uri_get_attribute (check, CKA_ID);
	assert_ptr_not_null (attr);
	assert (attr->ulValueLen == 5);
	assert (memcmp (attr->pValue, "HELLO", attr->ulValueLen) == 0);

	p11_kit_uri_free (check);

	assert (strstr (string, "object=The%20Label") != NULL);
	assert (strstr (string, "type=data") != NULL);
	assert (strstr (string, "id=%48%45%4c%4c%4f") != NULL);

	free (string);
	p11_kit_uri_free (uri);
}

static void
test_uri_parse_private_key (void)
{
	P11KitUri *uri;
	CK_ATTRIBUTE_PTR attr;
	int ret;

	uri = p11_kit_uri_new ();
	assert_ptr_not_null (uri);

	ret = p11_kit_uri_parse ("pkcs11:type=private", P11_KIT_URI_FOR_OBJECT, uri);
	assert_num_eq (P11_KIT_URI_OK, ret);

	attr = p11_kit_uri_get_attribute (uri, CKA_CLASS);
	assert_ptr_not_null (attr);
	assert (attr->ulValueLen == sizeof (CK_OBJECT_CLASS));
	assert (*((CK_OBJECT_CLASS_PTR)attr->pValue) == CKO_PRIVATE_KEY);

	p11_kit_uri_free (uri);
}

static void
test_uri_parse_secret_key (void)
{
	P11KitUri *uri;
	CK_ATTRIBUTE_PTR attr;
	int ret;

	uri = p11_kit_uri_new ();
	assert_ptr_not_null (uri);

	ret = p11_kit_uri_parse ("pkcs11:type=secret-key", P11_KIT_URI_FOR_OBJECT, uri);
	assert_num_eq (P11_KIT_URI_OK, ret);

	attr = p11_kit_uri_get_attribute (uri, CKA_CLASS);
	assert_ptr_not_null (attr);
	assert (attr->ulValueLen == sizeof (CK_OBJECT_CLASS));
	assert (*((CK_OBJECT_CLASS_PTR)attr->pValue) == CKO_SECRET_KEY);

	p11_kit_uri_free (uri);
}

static void
test_uri_parse_library_version (void)
{
	P11KitUri *uri;
	CK_INFO_PTR info;
	int ret;

	uri = p11_kit_uri_new ();
	assert_ptr_not_null (uri);

	ret = p11_kit_uri_parse ("pkcs11:library-version=2.101", P11_KIT_URI_FOR_MODULE_WITH_VERSION, uri);
	assert_num_eq (P11_KIT_URI_OK, ret);

	info = p11_kit_uri_get_module_info (uri);
	assert_num_eq (2, info->libraryVersion.major);
	assert_num_eq (101, info->libraryVersion.minor);

	ret = p11_kit_uri_parse ("pkcs11:library-version=23", P11_KIT_URI_FOR_MODULE_WITH_VERSION, uri);
	assert_num_eq (P11_KIT_URI_OK, ret);

	info = p11_kit_uri_get_module_info (uri);
	assert_num_eq (23, info->libraryVersion.major);
	assert_num_eq (0, info->libraryVersion.minor);

	ret = p11_kit_uri_parse ("pkcs11:library-version=23.", P11_KIT_URI_FOR_MODULE_WITH_VERSION, uri);
	assert_num_eq (P11_KIT_URI_BAD_VERSION, ret);

	ret = p11_kit_uri_parse ("pkcs11:library-version=a.a", P11_KIT_URI_FOR_MODULE_WITH_VERSION, uri);
	assert_num_eq (P11_KIT_URI_BAD_VERSION, ret);

	ret = p11_kit_uri_parse ("pkcs11:library-version=.23", P11_KIT_URI_FOR_MODULE_WITH_VERSION, uri);
	assert_num_eq (P11_KIT_URI_BAD_VERSION, ret);

	ret = p11_kit_uri_parse ("pkcs11:library-version=1000", P11_KIT_URI_FOR_MODULE_WITH_VERSION, uri);
	assert_num_eq (P11_KIT_URI_BAD_VERSION, ret);

	ret = p11_kit_uri_parse ("pkcs11:library-version=2.1000", P11_KIT_URI_FOR_MODULE_WITH_VERSION, uri);
	assert_num_eq (P11_KIT_URI_BAD_VERSION, ret);

	p11_kit_uri_free (uri);
}

static void
test_uri_parse_parse_unknown_object_type (void)
{
	P11KitUri *uri;
	CK_ATTRIBUTE_PTR attr;
	int ret;

	uri = p11_kit_uri_new ();
	assert_ptr_not_null (uri);

	ret = p11_kit_uri_parse ("pkcs11:type=unknown", P11_KIT_URI_FOR_OBJECT, uri);
	assert_num_eq (P11_KIT_URI_OK, ret);

	attr = p11_kit_uri_get_attribute (uri, CKA_CLASS);
	assert_ptr_eq (NULL, attr);

	p11_kit_uri_free (uri);
}

static void
test_uri_parse_unrecognized (void)
{
	P11KitUri *uri;
	int ret;

	uri = p11_kit_uri_new ();
	assert_ptr_not_null (uri);

	ret = p11_kit_uri_parse ("pkcs11:x-blah=some-value", P11_KIT_URI_FOR_ANY, uri);
	assert_num_eq (P11_KIT_URI_OK, ret);

	ret = p11_kit_uri_any_unrecognized (uri);
	assert_num_eq (1, ret);

	p11_kit_uri_free (uri);
}

static void
test_uri_parse_too_long_is_unrecognized (void)
{
	P11KitUri *uri;
	int ret;

	uri = p11_kit_uri_new ();
	assert_ptr_not_null (uri);

	ret = p11_kit_uri_parse ("pkcs11:model=a-value-that-is-too-long-for-the-field-that-it-goes-with",
	                         P11_KIT_URI_FOR_ANY, uri);
	assert_num_eq (P11_KIT_URI_OK, ret);

	ret = p11_kit_uri_any_unrecognized (uri);
	assert_num_eq (1, ret);

	p11_kit_uri_free (uri);
}



static void
test_uri_build_object_type_cert (void)
{
	CK_ATTRIBUTE attr;
	CK_OBJECT_CLASS klass;
	P11KitUri *uri;
	char *string;
	int ret;

	uri = p11_kit_uri_new ();
	assert_ptr_not_null (uri);

	klass = CKO_CERTIFICATE;
	attr.type = CKA_CLASS;
	attr.pValue = &klass;
	attr.ulValueLen = sizeof (klass);
	p11_kit_uri_set_attribute (uri, &attr);

	ret = p11_kit_uri_format (uri, P11_KIT_URI_FOR_ANY, &string);
	assert_num_eq (P11_KIT_URI_OK, ret);
	assert (strstr (string, "type=cert") != NULL);

	p11_kit_uri_free (uri);
	free (string);
}

static void
test_uri_build_object_type_private (void)
{
	CK_ATTRIBUTE attr;
	CK_OBJECT_CLASS klass;
	P11KitUri *uri;
	char *string;
	int ret;

	uri = p11_kit_uri_new ();
	assert_ptr_not_null (uri);

	klass = CKO_PRIVATE_KEY;
	attr.type = CKA_CLASS;
	attr.pValue = &klass;
	attr.ulValueLen = sizeof (klass);
	p11_kit_uri_set_attribute (uri, &attr);

	ret = p11_kit_uri_format (uri, P11_KIT_URI_FOR_ANY, &string);
	assert_num_eq (P11_KIT_URI_OK, ret);
	assert (strstr (string, "type=private") != NULL);

	p11_kit_uri_free (uri);
	free (string);
}

static void
test_uri_build_object_type_public (void)
{
	CK_ATTRIBUTE attr;
	CK_OBJECT_CLASS klass;
	P11KitUri *uri;
	char *string;
	int ret;

	uri = p11_kit_uri_new ();
	assert_ptr_not_null (uri);

	klass = CKO_PUBLIC_KEY;
	attr.type = CKA_CLASS;
	attr.pValue = &klass;
	attr.ulValueLen = sizeof (klass);
	p11_kit_uri_set_attribute (uri, &attr);

	ret = p11_kit_uri_format (uri, P11_KIT_URI_FOR_ANY, &string);
	assert_num_eq (P11_KIT_URI_OK, ret);
	assert (strstr (string, "type=public") != NULL);

	p11_kit_uri_free (uri);
	free (string);
}

static void
test_uri_build_object_type_secret (void)
{
	CK_ATTRIBUTE attr;
	CK_OBJECT_CLASS klass;
	P11KitUri *uri;
	char *string;
	int ret;

	uri = p11_kit_uri_new ();
	assert_ptr_not_null (uri);

	klass = CKO_SECRET_KEY;
	attr.type = CKA_CLASS;
	attr.pValue = &klass;
	attr.ulValueLen = sizeof (klass);
	p11_kit_uri_set_attribute (uri, &attr);

	ret = p11_kit_uri_format (uri, P11_KIT_URI_FOR_ANY, &string);
	assert_num_eq (P11_KIT_URI_OK, ret);
	assert (strstr (string, "type=secret-key") != NULL);

	p11_kit_uri_free (uri);
	free (string);
}

static void
test_uri_build_with_library (void)
{
	CK_INFO_PTR info;
	P11KitUri *uri;
	char *string;
	int ret;

	uri = p11_kit_uri_new ();
	assert_ptr_not_null (uri);

	info = p11_kit_uri_get_module_info (uri);
	set_space_string (info->libraryDescription, sizeof (info->libraryDescription), "The Description");

	ret = p11_kit_uri_format (uri, P11_KIT_URI_FOR_ANY, &string);
	assert_num_eq (P11_KIT_URI_OK, ret);
	assert (strstr (string, "library-description=The%20Description") != NULL);

	p11_kit_uri_free (uri);
	free (string);
}

static void
test_uri_build_library_version (void)
{
	CK_INFO_PTR info;
	P11KitUri *uri;
	char *string;
	int ret;

	uri = p11_kit_uri_new ();
	assert_ptr_not_null (uri);

	info = p11_kit_uri_get_module_info (uri);
	info->libraryVersion.major = 2;
	info->libraryVersion.minor = 10;

	ret = p11_kit_uri_format (uri, P11_KIT_URI_FOR_ANY, &string);
	assert_num_eq (P11_KIT_URI_OK, ret);
	assert (strstr (string, "library-version=2.10") != NULL);

	p11_kit_uri_free (uri);
	free (string);
}

static void
test_uri_get_set_unrecognized (void)
{
	P11KitUri *uri;
	int ret;

	uri = p11_kit_uri_new ();
	assert_ptr_not_null (uri);

	ret = p11_kit_uri_any_unrecognized (uri);
	assert_num_eq (0, ret);

	p11_kit_uri_set_unrecognized (uri, 1);

	ret = p11_kit_uri_any_unrecognized (uri);
	assert_num_eq (1, ret);

	p11_kit_uri_set_unrecognized (uri, 0);

	ret = p11_kit_uri_any_unrecognized (uri);
	assert_num_eq (0, ret);

	p11_kit_uri_free (uri);
}

static void
test_uri_match_token (void)
{
	CK_TOKEN_INFO token;
	P11KitUri *uri;
	int ret;

	uri = p11_kit_uri_new ();
	assert_ptr_not_null (uri);

	ret = p11_kit_uri_parse ("pkcs11:model=Giselle", P11_KIT_URI_FOR_ANY, uri);
	assert_num_eq (P11_KIT_URI_OK, ret);

	set_space_string (token.label, sizeof (token.label), "A label");
	set_space_string (token.model, sizeof (token.model), "Giselle");

	ret = p11_kit_uri_match_token_info (uri, &token);
	assert_num_eq (1, ret);

	set_space_string (token.label, sizeof (token.label), "Another label");

	ret = p11_kit_uri_match_token_info (uri, &token);
	assert_num_eq (1, ret);

	set_space_string (token.model, sizeof (token.model), "Zoolander");

	ret = p11_kit_uri_match_token_info (uri, &token);
	assert_num_eq (0, ret);

	p11_kit_uri_set_unrecognized (uri, 1);

	ret = p11_kit_uri_match_token_info (uri, &token);
	assert_num_eq (0, ret);

	p11_kit_uri_free (uri);
}

static void
test_uri_match_module (void)
{
	CK_INFO info;
	P11KitUri *uri;
	int ret;

	uri = p11_kit_uri_new ();
	assert_ptr_not_null (uri);

	ret = p11_kit_uri_parse ("pkcs11:library-description=Quiet", P11_KIT_URI_FOR_ANY, uri);
	assert_num_eq (P11_KIT_URI_OK, ret);

	set_space_string (info.libraryDescription, sizeof (info.libraryDescription), "Quiet");
	set_space_string (info.manufacturerID, sizeof (info.manufacturerID), "Someone");

	ret = p11_kit_uri_match_module_info (uri, &info);
	assert_num_eq (1, ret);

	set_space_string (info.manufacturerID, sizeof (info.manufacturerID), "Someone else");

	ret = p11_kit_uri_match_module_info (uri, &info);
	assert_num_eq (1, ret);

	set_space_string (info.libraryDescription, sizeof (info.libraryDescription), "Leise");

	ret = p11_kit_uri_match_module_info (uri, &info);
	assert_num_eq (0, ret);

	p11_kit_uri_set_unrecognized (uri, 1);

	ret = p11_kit_uri_match_module_info (uri, &info);
	assert_num_eq (0, ret);

	p11_kit_uri_free (uri);
}

static void
test_uri_match_version (void)
{
	CK_INFO info;
	P11KitUri *uri;
	int ret;

	memset (&info, 0, sizeof (info));

	uri = p11_kit_uri_new ();
	assert_ptr_not_null (uri);

	ret = p11_kit_uri_parse ("pkcs11:library-version=5.8", P11_KIT_URI_FOR_ANY, uri);
	assert_num_eq (P11_KIT_URI_OK, ret);

	info.libraryVersion.major = 5;
	info.libraryVersion.minor = 8;

	ret = p11_kit_uri_match_module_info (uri, &info);
	assert_num_eq (1, ret);

	info.libraryVersion.major = 2;
	info.libraryVersion.minor = 3;

	ret = p11_kit_uri_match_module_info (uri, &info);
	assert_num_eq (0, ret);

	p11_kit_uri_free (uri);
}

static void
test_uri_match_attributes (void)
{
	CK_ATTRIBUTE attrs[4];
	CK_OBJECT_CLASS klass;
	P11KitUri *uri;
	int ret;

	attrs[0].type = CKA_ID;
	attrs[0].pValue = "Blah";
	attrs[0].ulValueLen = 4;

	attrs[1].type = CKA_LABEL;
	attrs[1].pValue = "Junk";
	attrs[1].ulValueLen = 4;

	attrs[2].type = CKA_COLOR;
	attrs[2].pValue = "blue";
	attrs[2].ulValueLen = 4;

	klass = CKO_DATA;
	attrs[3].type = CKA_CLASS;
	attrs[3].pValue = &klass;
	attrs[3].ulValueLen = sizeof (klass);

	uri = p11_kit_uri_new ();
	assert_ptr_not_null (uri);

	ret = p11_kit_uri_parse ("pkcs11:object=Fancy;id=Blah;type=data", P11_KIT_URI_FOR_ANY, uri);
	assert_num_eq (P11_KIT_URI_OK, ret);

	ret = p11_kit_uri_match_attributes (uri, attrs, 4);
	assert_num_eq (0, ret);

	attrs[1].pValue = "Fancy";
	attrs[1].ulValueLen = 5;

	ret = p11_kit_uri_match_attributes (uri, attrs, 4);
	assert_num_eq (1, ret);

	p11_kit_uri_clear_attribute (uri, CKA_CLASS);

	ret = p11_kit_uri_match_attributes (uri, attrs, 4);
	assert_num_eq (1, ret);

	attrs[2].pValue = "pink";

	ret = p11_kit_uri_match_attributes (uri, attrs, 4);
	assert_num_eq (1, ret);

	p11_kit_uri_set_unrecognized (uri, 1);

	ret = p11_kit_uri_match_attributes (uri, attrs, 4);
	assert_num_eq (0, ret);

	p11_kit_uri_free (uri);
}

static void
test_uri_get_set_attribute (void)
{
	CK_ATTRIBUTE attr;
	CK_ATTRIBUTE_PTR ptr;
	P11KitUri *uri;
	int ret;

	uri = p11_kit_uri_new ();
	assert_ptr_not_null (uri);

	ptr = p11_kit_uri_get_attribute (uri, CKA_LABEL);
	assert_ptr_eq (NULL, ptr);

	ret = p11_kit_uri_clear_attribute (uri, CKA_LABEL);
	assert_num_eq (P11_KIT_URI_OK, ret);

	ret = p11_kit_uri_clear_attribute (uri, CKA_COLOR);
	assert_num_eq (P11_KIT_URI_NOT_FOUND, ret);

	attr.type = CKA_LABEL;
	attr.pValue = "Test";
	attr.ulValueLen = 4;

	ret = p11_kit_uri_set_attribute (uri, &attr);
	assert_num_eq (P11_KIT_URI_OK, ret);

	/* We can set other attributes */
	attr.type = CKA_COLOR;
	ret = p11_kit_uri_set_attribute (uri, &attr);
	assert_num_eq (P11_KIT_URI_OK, ret);

	/* And get them too */
	ptr = p11_kit_uri_get_attribute (uri, CKA_COLOR);
	assert_ptr_not_null (ptr);

	ptr = p11_kit_uri_get_attribute (uri, CKA_LABEL);
	assert_ptr_not_null (ptr);

	assert (ptr->type == CKA_LABEL);
	assert (ptr->ulValueLen == 4);
	assert (memcmp (ptr->pValue, "Test", 4) == 0);

	ret = p11_kit_uri_clear_attribute (uri, CKA_LABEL);
	assert_num_eq (P11_KIT_URI_OK, ret);

	ptr = p11_kit_uri_get_attribute (uri, CKA_LABEL);
	assert_ptr_eq (NULL, ptr);

	p11_kit_uri_free (uri);
}

static void
test_uri_get_set_attributes (void)
{
	CK_ATTRIBUTE_PTR attrs;
	CK_OBJECT_CLASS klass;
	CK_ATTRIBUTE attr;
	CK_ULONG n_attrs;
	P11KitUri *uri;
	int ret;

	uri = p11_kit_uri_new ();
	assert_ptr_not_null (uri);

	attrs = p11_kit_uri_get_attributes (uri, &n_attrs);
	assert_ptr_not_null (attrs);
	assert_num_eq (0, n_attrs);

	attr.type = CKA_LABEL;
	attr.pValue = "Test";
	attr.ulValueLen = 4;

	ret = p11_kit_uri_set_attribute (uri, &attr);
	assert_num_eq (P11_KIT_URI_OK, ret);

	attrs = p11_kit_uri_get_attributes (uri, &n_attrs);
	assert_ptr_not_null (attrs);
	assert_num_eq (1, n_attrs);
	assert (attrs[0].type == CKA_LABEL);
	assert (attrs[0].ulValueLen == 4);
	assert (memcmp (attrs[0].pValue, "Test", 4) == 0);

	attr.type = CKA_LABEL;
	attr.pValue = "Kablooey";
	attr.ulValueLen = 8;

	ret = p11_kit_uri_set_attribute (uri, &attr);
	assert_num_eq (P11_KIT_URI_OK, ret);

	attrs = p11_kit_uri_get_attributes (uri, &n_attrs);
	assert_ptr_not_null (attrs);
	assert_num_eq (1, n_attrs);
	assert (attrs[0].type == CKA_LABEL);
	assert (attrs[0].ulValueLen == 8);
	assert (memcmp (attrs[0].pValue, "Kablooey", 8) == 0);

	klass = CKO_DATA;
	attr.type = CKA_CLASS;
	attr.pValue = &klass;
	attr.ulValueLen = sizeof (klass);

	ret = p11_kit_uri_set_attribute (uri, &attr);
	assert_num_eq (P11_KIT_URI_OK, ret);

	attrs = p11_kit_uri_get_attributes (uri, &n_attrs);
	assert_ptr_not_null (attrs);
	assert_num_eq (2, n_attrs);
	assert (attrs[0].type == CKA_LABEL);
	assert (attrs[0].ulValueLen == 8);
	assert (memcmp (attrs[0].pValue, "Kablooey", 8) == 0);
	assert (attrs[1].type == CKA_CLASS);
	assert (attrs[1].ulValueLen == sizeof (klass));
	assert (memcmp (attrs[1].pValue, &klass, sizeof (klass)) == 0);

	ret = p11_kit_uri_clear_attribute (uri, CKA_LABEL);
	assert_num_eq (P11_KIT_URI_OK, ret);

	attrs = p11_kit_uri_get_attributes (uri, &n_attrs);
	assert_ptr_not_null (attrs);
	assert_num_eq (1, n_attrs);
	assert (attrs[0].type == CKA_CLASS);
	assert (attrs[0].ulValueLen == sizeof (klass));
	assert (memcmp (attrs[0].pValue, &klass, sizeof (klass)) == 0);

	attr.type = CKA_LABEL;
	attr.pValue = "Three";
	attr.ulValueLen = 5;

	ret = p11_kit_uri_set_attributes (uri, &attr, 1);
	assert_num_eq (P11_KIT_URI_OK, ret);

	attrs = p11_kit_uri_get_attributes (uri, &n_attrs);
	assert_ptr_not_null (attrs);
	assert_num_eq (1, n_attrs);
	assert (attrs[0].type == CKA_LABEL);
	assert (attrs[0].ulValueLen == 5);
	assert (memcmp (attrs[0].pValue, "Three", 5) == 0);

	p11_kit_uri_clear_attributes (uri);

	attrs = p11_kit_uri_get_attributes (uri, &n_attrs);
	assert_ptr_not_null (attrs);
	assert_num_eq (0, n_attrs);

	p11_kit_uri_free (uri);
}

static void
test_uri_pin_source (void)
{
	P11KitUri *uri;
	const char *pin_source;
	char *string;
	int ret;

	uri = p11_kit_uri_new ();
	assert_ptr_not_null (uri);

	p11_kit_uri_set_pin_source (uri, "|my-pin-source");

	pin_source = p11_kit_uri_get_pin_source (uri);
	assert_str_eq ("|my-pin-source", pin_source);

	pin_source = p11_kit_uri_get_pinfile (uri);
	assert_str_eq ("|my-pin-source", pin_source);

	p11_kit_uri_set_pinfile (uri, "|my-pin-file");

	pin_source = p11_kit_uri_get_pin_source (uri);
	assert_str_eq ("|my-pin-file", pin_source);

	ret = p11_kit_uri_format (uri, P11_KIT_URI_FOR_ANY, &string);
	assert_num_eq (P11_KIT_URI_OK, ret);
	assert (strstr (string, "pin-source=%7cmy-pin-file") != NULL);
	free (string);

	ret = p11_kit_uri_parse ("pkcs11:pin-source=blah%2Fblah", P11_KIT_URI_FOR_ANY, uri);
	assert_num_eq (P11_KIT_URI_OK, ret);

	pin_source = p11_kit_uri_get_pin_source (uri);
	assert_str_eq ("blah/blah", pin_source);

	p11_kit_uri_free (uri);
}


static void
test_uri_pin_value (void)
{
	P11KitUri *uri;
	const char *pin_value;
	char *string;
	int ret;

	uri = p11_kit_uri_new ();
	assert_ptr_not_null (uri);

	p11_kit_uri_set_pin_value (uri, "123456");

	pin_value = p11_kit_uri_get_pin_value (uri);
	assert_str_eq ("123456", pin_value);

	p11_kit_uri_set_pin_value (uri, "1*&#%&@(");

	pin_value = p11_kit_uri_get_pin_value (uri);
	assert_str_eq ("1*&#%&@(", pin_value);

	ret = p11_kit_uri_format (uri, P11_KIT_URI_FOR_ANY, &string);
	assert_num_eq (P11_KIT_URI_OK, ret);
	assert (strstr (string, "pkcs11:pin-value=1%2a%26%23%25%26%40%28") != NULL);
	free (string);

	ret = p11_kit_uri_parse ("pkcs11:pin-value=blah%2Fblah", P11_KIT_URI_FOR_ANY, uri);
	assert_num_eq (P11_KIT_URI_OK, ret);

	pin_value = p11_kit_uri_get_pin_value (uri);
	assert_str_eq ("blah/blah", pin_value);

	p11_kit_uri_free (uri);
}

static void
test_uri_pin_value_bad (void)
{
	P11KitUri *uri;
	int ret;

	uri = p11_kit_uri_new ();
	assert_ptr_not_null (uri);

	ret = p11_kit_uri_parse ("pkcs11:pin-value=blahblah%2", P11_KIT_URI_FOR_ANY, uri);
	assert_num_eq (P11_KIT_URI_BAD_ENCODING, ret);

	p11_kit_uri_free (uri);
}

static void
test_uri_free_null (void)
{
	p11_kit_uri_free (NULL);
}

static void
test_uri_message (void)
{
	assert (p11_kit_uri_message (P11_KIT_URI_OK) == NULL);
	assert_ptr_not_null (p11_kit_uri_message (P11_KIT_URI_UNEXPECTED));
	assert_ptr_not_null (p11_kit_uri_message (-555555));
}

int
main (int argc,
      char *argv[])
{
	p11_test (test_uri_parse, "/uri/test_uri_parse");
	p11_test (test_uri_parse_bad_scheme, "/uri/test_uri_parse_bad_scheme");
	p11_test (test_uri_parse_with_label, "/uri/test_uri_parse_with_label");
	p11_test (test_uri_parse_with_empty_label, "/uri/test_uri_parse_with_empty_label");
	p11_test (test_uri_parse_with_empty_id, "/uri/test_uri_parse_with_empty_id");
	p11_test (test_uri_parse_with_label_and_klass, "/uri/test_uri_parse_with_label_and_klass");
	p11_test (test_uri_parse_with_label_and_new_klass, "/uri/parse-with-label-and-new-class");
	p11_test (test_uri_parse_with_id, "/uri/test_uri_parse_with_id");
	p11_test (test_uri_parse_with_bad_string_encoding, "/uri/test_uri_parse_with_bad_string_encoding");
	p11_test (test_uri_parse_with_bad_hex_encoding, "/uri/test_uri_parse_with_bad_hex_encoding");
	p11_test (test_uri_parse_with_token, "/uri/test_uri_parse_with_token");
	p11_test (test_uri_parse_with_token_bad_encoding, "/uri/test_uri_parse_with_token_bad_encoding");
	p11_test (test_uri_parse_with_bad_syntax, "/uri/test_uri_parse_with_bad_syntax");
	p11_test (test_uri_parse_with_spaces, "/uri/test_uri_parse_with_spaces");
	p11_test (test_uri_parse_with_library, "/uri/test_uri_parse_with_library");
	p11_test (test_uri_parse_with_library_bad_encoding, "/uri/test_uri_parse_with_library_bad_encoding");
	p11_test (test_uri_build_empty, "/uri/test_uri_build_empty");
	p11_test (test_uri_build_with_token_info, "/uri/test_uri_build_with_token_info");
	p11_test (test_uri_build_with_token_null_info, "/uri/test_uri_build_with_token_null_info");
	p11_test (test_uri_build_with_token_empty_info, "/uri/test_uri_build_with_token_empty_info");
	p11_test (test_uri_build_with_attributes, "/uri/test_uri_build_with_attributes");
	p11_test (test_uri_parse_private_key, "/uri/test_uri_parse_private_key");
	p11_test (test_uri_parse_secret_key, "/uri/test_uri_parse_secret_key");
	p11_test (test_uri_parse_library_version, "/uri/test_uri_parse_library_version");
	p11_test (test_uri_parse_parse_unknown_object_type, "/uri/test_uri_parse_parse_unknown_object_type");
	p11_test (test_uri_parse_unrecognized, "/uri/test_uri_parse_unrecognized");
	p11_test (test_uri_parse_too_long_is_unrecognized, "/uri/test_uri_parse_too_long_is_unrecognized");
	p11_test (test_uri_build_object_type_cert, "/uri/test_uri_build_object_type_cert");
	p11_test (test_uri_build_object_type_private, "/uri/test_uri_build_object_type_private");
	p11_test (test_uri_build_object_type_public, "/uri/test_uri_build_object_type_public");
	p11_test (test_uri_build_object_type_secret, "/uri/test_uri_build_object_type_secret");
	p11_test (test_uri_build_with_library, "/uri/test_uri_build_with_library");
	p11_test (test_uri_build_library_version, "/uri/test_uri_build_library_version");
	p11_test (test_uri_get_set_unrecognized, "/uri/test_uri_get_set_unrecognized");
	p11_test (test_uri_match_token, "/uri/test_uri_match_token");
	p11_test (test_uri_match_module, "/uri/test_uri_match_module");
	p11_test (test_uri_match_version, "/uri/test_uri_match_version");
	p11_test (test_uri_match_attributes, "/uri/test_uri_match_attributes");
	p11_test (test_uri_get_set_attribute, "/uri/test_uri_get_set_attribute");
	p11_test (test_uri_get_set_attributes, "/uri/test_uri_get_set_attributes");
	p11_test (test_uri_pin_source, "/uri/test_uri_pin_source");
	p11_test (test_uri_pin_value, "/uri/pin-value");
	p11_test (test_uri_pin_value_bad, "/uri/pin-value-bad");
	p11_test (test_uri_free_null, "/uri/test_uri_free_null");
	p11_test (test_uri_message, "/uri/test_uri_message");

	return p11_test_run (argc, argv);
}
