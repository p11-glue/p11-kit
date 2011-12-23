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
#include "CuTest.h"

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
test_uri_parse (CuTest *tc)
{
	P11KitUri *uri;
	int ret;

	uri = p11_kit_uri_new ();
	CuAssertPtrNotNull (tc, uri);

	ret = p11_kit_uri_parse ("pkcs11:", P11_KIT_URI_FOR_MODULE, uri);
	CuAssertIntEquals (tc, P11_KIT_URI_OK, ret);

	CuAssertTrue (tc, is_module_empty (uri));
	CuAssertTrue (tc, is_token_empty (uri));
	CuAssertTrue (tc, are_attributes_empty (uri));

	p11_kit_uri_free (uri);
}

static void
test_uri_parse_bad_scheme (CuTest *tc)
{
	P11KitUri *uri;
	int ret;

	uri = p11_kit_uri_new ();
	CuAssertPtrNotNull (tc, uri);

	ret = p11_kit_uri_parse ("http:\\example.com\test", P11_KIT_URI_FOR_ANY, uri);
	CuAssertIntEquals (tc, P11_KIT_URI_BAD_SCHEME, ret);

	p11_kit_uri_free (uri);
}

static void
test_uri_parse_with_label (CuTest *tc)
{
	CK_ATTRIBUTE_PTR attr;
	P11KitUri *uri;
	int ret;

	uri = p11_kit_uri_new ();
	CuAssertPtrNotNull (tc, uri);

	ret = p11_kit_uri_parse ("pkcs11:object=Test%20Label", P11_KIT_URI_FOR_ANY, uri);
	CuAssertIntEquals (tc, P11_KIT_URI_OK, ret);

	CuAssertTrue (tc, is_module_empty (uri));
	CuAssertTrue (tc, is_token_empty (uri));

	attr = p11_kit_uri_get_attribute (uri, CKA_LABEL);
	CuAssertPtrNotNull (tc, attr);
	CuAssertTrue (tc, attr->ulValueLen == strlen ("Test Label"));
	CuAssertTrue (tc, memcmp (attr->pValue, "Test Label", attr->ulValueLen) == 0);

	p11_kit_uri_free (uri);
}

static void
test_uri_parse_with_label_and_klass (CuTest *tc)
{
	CK_ATTRIBUTE_PTR attr;
	P11KitUri *uri;
	int ret;

	uri = p11_kit_uri_new ();
	CuAssertPtrNotNull (tc, uri);

	ret = p11_kit_uri_parse ("pkcs11:object=Test%20Label;object-type=cert", P11_KIT_URI_FOR_ANY, uri);
	CuAssertIntEquals (tc, P11_KIT_URI_OK, ret);

	attr = p11_kit_uri_get_attribute (uri, CKA_LABEL);
	CuAssertPtrNotNull (tc, attr);
	CuAssertTrue (tc, attr->ulValueLen == strlen ("Test Label"));
	CuAssertTrue (tc, memcmp (attr->pValue, "Test Label", attr->ulValueLen) == 0);

	attr = p11_kit_uri_get_attribute (uri, CKA_CLASS);
	CuAssertPtrNotNull (tc, attr);
	CuAssertTrue (tc, attr->ulValueLen == sizeof (CK_OBJECT_CLASS));
	CuAssertTrue (tc, *((CK_OBJECT_CLASS_PTR)attr->pValue) == CKO_CERTIFICATE);

	p11_kit_uri_free (uri);
}

static void
test_uri_parse_with_id (CuTest *tc)
{
	CK_ATTRIBUTE_PTR attr;
	P11KitUri *uri;
	int ret;

	uri = p11_kit_uri_new ();
	CuAssertPtrNotNull (tc, uri);

	ret = p11_kit_uri_parse ("pkcs11:id=%54%45%53%54%00", P11_KIT_URI_FOR_OBJECT, uri);
	CuAssertIntEquals (tc, P11_KIT_URI_OK, ret);

	/* Note that there's a NULL in the attribute (end) */
	attr = p11_kit_uri_get_attribute (uri, CKA_ID);
	CuAssertPtrNotNull (tc, attr);
	CuAssertTrue (tc, attr->ulValueLen == 5);
	CuAssertTrue (tc, memcmp (attr->pValue, "TEST", 5) == 0);


	p11_kit_uri_free (uri);
}

static void
test_uri_parse_with_bad_string_encoding (CuTest *tc)
{
	P11KitUri *uri;
	int ret;

	uri = p11_kit_uri_new ();
	CuAssertPtrNotNull (tc, uri);

	ret = p11_kit_uri_parse ("pkcs11:object=Test%", P11_KIT_URI_FOR_OBJECT, uri);
	CuAssertIntEquals (tc, P11_KIT_URI_BAD_ENCODING, ret);

	p11_kit_uri_free (uri);
}

static void
test_uri_parse_with_bad_hex_encoding (CuTest *tc)
{
	P11KitUri *uri;
	int ret;

	uri = p11_kit_uri_new ();
	CuAssertPtrNotNull (tc, uri);

	ret = p11_kit_uri_parse ("pkcs11:object=T%xxest", P11_KIT_URI_FOR_OBJECT, uri);
	CuAssertIntEquals (tc, P11_KIT_URI_BAD_ENCODING, ret);

	p11_kit_uri_free (uri);
}

static int
is_space_string (CK_UTF8CHAR_PTR string, CK_ULONG size, const char *check)
{
	size_t i, len = strlen (check);
	if (len > size)
		return 0;
	if (memcmp (string, check, len) != 0)
		return 0;
	for (i = len; i < size; ++i)
		if (string[i] != ' ')
			return 0;
	return 1;
}

static void
test_uri_parse_with_token (CuTest *tc)
{
	P11KitUri *uri = NULL;
	CK_TOKEN_INFO_PTR token;
	int ret;

	uri = p11_kit_uri_new ();
	CuAssertPtrNotNull (tc, uri);

	ret = p11_kit_uri_parse ("pkcs11:token=Token%20Label;serial=3333;model=Deluxe;manufacturer=Me",
	                         P11_KIT_URI_FOR_TOKEN, uri);
	CuAssertIntEquals (tc, P11_KIT_URI_OK, ret);

	token = p11_kit_uri_get_token_info (uri);
	CuAssertTrue (tc, is_space_string (token->label, sizeof (token->label), "Token Label"));
	CuAssertTrue (tc, is_space_string (token->serialNumber, sizeof (token->serialNumber), "3333"));
	CuAssertTrue (tc, is_space_string (token->model, sizeof (token->model), "Deluxe"));
	CuAssertTrue (tc, is_space_string (token->manufacturerID, sizeof (token->manufacturerID), "Me"));

	p11_kit_uri_free (uri);
}

static void
test_uri_parse_with_token_bad_encoding (CuTest *tc)
{
	P11KitUri *uri;
	int ret;

	uri = p11_kit_uri_new ();
	CuAssertPtrNotNull (tc, uri);

	ret = p11_kit_uri_parse ("pkcs11:token=Token%", P11_KIT_URI_FOR_TOKEN, uri);
	CuAssertIntEquals (tc, P11_KIT_URI_BAD_ENCODING, ret);

	p11_kit_uri_free (uri);
}

static void
test_uri_parse_with_bad_syntax (CuTest *tc)
{
	P11KitUri *uri;
	int ret;

	uri = p11_kit_uri_new ();
	CuAssertPtrNotNull (tc, uri);

	ret = p11_kit_uri_parse ("pkcs11:token", P11_KIT_URI_FOR_ANY, uri);
	CuAssertIntEquals (tc, P11_KIT_URI_BAD_SYNTAX, ret);

	p11_kit_uri_free (uri);
}

static void
test_uri_parse_with_spaces (CuTest *tc)
{
	P11KitUri *uri = NULL;
	CK_INFO_PTR info;
	int ret;

	uri = p11_kit_uri_new ();
	CuAssertPtrNotNull (tc, uri);

	ret = p11_kit_uri_parse ("pkc\ns11: lib rary-desc\rrip  \n  tion =The%20Library;\n\n\nlibrary-manufacturer=\rMe",
	                         P11_KIT_URI_FOR_MODULE, uri);
	CuAssertIntEquals (tc, P11_KIT_URI_OK, ret);

	info = p11_kit_uri_get_module_info (uri);

	CuAssertTrue (tc, is_space_string (info->manufacturerID, sizeof (info->manufacturerID), "Me"));
	CuAssertTrue (tc, is_space_string (info->libraryDescription, sizeof (info->libraryDescription), "The Library"));

	p11_kit_uri_free (uri);
}


static void
test_uri_parse_with_library (CuTest *tc)
{
	P11KitUri *uri = NULL;
	CK_INFO_PTR info;
	int ret;

	uri = p11_kit_uri_new ();
	CuAssertPtrNotNull (tc, uri);

	ret = p11_kit_uri_parse ("pkcs11:library-description=The%20Library;library-manufacturer=Me",
	                         P11_KIT_URI_FOR_MODULE, uri);
	CuAssertIntEquals (tc, P11_KIT_URI_OK, ret);

	info = p11_kit_uri_get_module_info (uri);

	CuAssertTrue (tc, is_space_string (info->manufacturerID, sizeof (info->manufacturerID), "Me"));
	CuAssertTrue (tc, is_space_string (info->libraryDescription, sizeof (info->libraryDescription), "The Library"));

	p11_kit_uri_free (uri);
}

static void
test_uri_parse_with_library_bad_encoding (CuTest *tc)
{
	P11KitUri *uri;
	int ret;

	uri = p11_kit_uri_new ();
	CuAssertPtrNotNull (tc, uri);

	ret = p11_kit_uri_parse ("pkcs11:library-description=Library%", P11_KIT_URI_FOR_MODULE, uri);
	CuAssertIntEquals (tc, P11_KIT_URI_BAD_ENCODING, ret);

	p11_kit_uri_free (uri);
}

static void
test_uri_build_empty (CuTest *tc)
{
	P11KitUri *uri;
	char *string;
	int ret;

	uri = p11_kit_uri_new ();
	CuAssertPtrNotNull (tc, uri);

	ret = p11_kit_uri_format (uri, P11_KIT_URI_FOR_ANY, &string);
	CuAssertIntEquals (tc, P11_KIT_URI_OK, ret);
	CuAssertStrEquals (tc, "pkcs11:", string);
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
test_uri_build_with_token_info (CuTest *tc)
{
	char *string = NULL;
	P11KitUri *uri;
	P11KitUri *check;
	CK_TOKEN_INFO_PTR token;
	int ret;

	uri = p11_kit_uri_new ();
	CuAssertPtrNotNull (tc, uri);

	token = p11_kit_uri_get_token_info (uri);
	set_space_string (token->label, sizeof (token->label), "The Label");
	set_space_string (token->serialNumber, sizeof (token->serialNumber), "44444");
	set_space_string (token->manufacturerID, sizeof (token->manufacturerID), "Me");
	set_space_string (token->model, sizeof (token->model), "Deluxe");

	ret = p11_kit_uri_format (uri, P11_KIT_URI_FOR_ANY, &string);
	CuAssertIntEquals (tc, P11_KIT_URI_OK, ret);
	CuAssertPtrNotNull (tc, string);

	check = p11_kit_uri_new ();
	CuAssertPtrNotNull (tc, check);

	ret = p11_kit_uri_parse (string, P11_KIT_URI_FOR_TOKEN, check);
	CuAssertIntEquals (tc, P11_KIT_URI_OK, ret);

	p11_kit_uri_match_token_info (check, p11_kit_uri_get_token_info (uri));

	p11_kit_uri_free (uri);
	p11_kit_uri_free (check);

	CuAssertTrue (tc, strstr (string, "token=The%20Label") != NULL);
	CuAssertTrue (tc, strstr (string, "serial=44444") != NULL);
	CuAssertTrue (tc, strstr (string, "manufacturer=Me") != NULL);
	CuAssertTrue (tc, strstr (string, "model=Deluxe") != NULL);

	free (string);
}

static void
test_uri_build_with_token_null_info (CuTest *tc)
{
	char *string = NULL;
	P11KitUri *uri;
	CK_TOKEN_INFO_PTR token;
	int ret;

	uri = p11_kit_uri_new ();
	CuAssertPtrNotNull (tc, uri);

	token = p11_kit_uri_get_token_info (uri);
	set_space_string (token->label, sizeof (token->label), "The Label");

	ret = p11_kit_uri_format (uri, P11_KIT_URI_FOR_ANY, &string);
	CuAssertIntEquals (tc, P11_KIT_URI_OK, ret);

	CuAssertTrue (tc, strstr (string, "token=The%20Label") != NULL);
	CuAssertTrue (tc, strstr (string, "serial=") == NULL);

	free (string);
	p11_kit_uri_free (uri);
}

static void
test_uri_build_with_token_empty_info (CuTest *tc)
{
	char *string = NULL;
	P11KitUri *uri;
	CK_TOKEN_INFO_PTR token;
	int ret;

	uri = p11_kit_uri_new ();
	CuAssertPtrNotNull (tc, uri);

	token = p11_kit_uri_get_token_info (uri);
	set_space_string (token->label, sizeof (token->label), "");
	set_space_string (token->serialNumber, sizeof (token->serialNumber), "");

	ret = p11_kit_uri_format (uri, P11_KIT_URI_FOR_ANY, &string);
	CuAssertIntEquals (tc, P11_KIT_URI_OK, ret);

	CuAssertTrue (tc, strstr (string, "token=") != NULL);
	CuAssertTrue (tc, strstr (string, "serial=") != NULL);

	free (string);
	p11_kit_uri_free (uri);
}

static void
test_uri_build_with_attributes (CuTest *tc)
{
	char *string = NULL;
	P11KitUri *uri;
	P11KitUri *check;
	CK_OBJECT_CLASS klass;
	CK_ATTRIBUTE_PTR attr;
	CK_ATTRIBUTE at;
	int ret;

	uri = p11_kit_uri_new ();
	CuAssertPtrNotNull (tc, uri);

	at.type = CKA_LABEL;
	at.pValue = "The Label";
	at.ulValueLen = 9;
	ret = p11_kit_uri_set_attribute (uri, &at);

	at.type = CKA_ID;
	at.pValue = "HELLO";
	at.ulValueLen = 5;
	ret = p11_kit_uri_set_attribute (uri, &at);

	klass = CKO_DATA;
	at.type = CKA_CLASS;
	at.pValue = &klass;
	at.ulValueLen = sizeof (klass);
	ret = p11_kit_uri_set_attribute (uri, &at);

	ret = p11_kit_uri_format (uri, P11_KIT_URI_FOR_ANY, &string);
	CuAssertIntEquals (tc, P11_KIT_URI_OK, ret);

	check = p11_kit_uri_new ();
	CuAssertPtrNotNull (tc, check);

	ret = p11_kit_uri_parse (string, P11_KIT_URI_FOR_ANY, check);
	CuAssertIntEquals (tc, P11_KIT_URI_OK, ret);

	attr = p11_kit_uri_get_attribute (check, CKA_LABEL);
	CuAssertPtrNotNull (tc, attr);
	CuAssertTrue (tc, attr->ulValueLen == 9);
	CuAssertTrue (tc, memcmp (attr->pValue, "The Label", attr->ulValueLen) == 0);

	attr = p11_kit_uri_get_attribute (check, CKA_CLASS);
	CuAssertPtrNotNull (tc, attr);
	CuAssertTrue (tc, attr->ulValueLen == sizeof (klass));
	CuAssertTrue (tc, *((CK_OBJECT_CLASS_PTR)attr->pValue) == klass);

	attr = p11_kit_uri_get_attribute (check, CKA_ID);
	CuAssertPtrNotNull (tc, attr);
	CuAssertTrue (tc, attr->ulValueLen == 5);
	CuAssertTrue (tc, memcmp (attr->pValue, "HELLO", attr->ulValueLen) == 0);

	p11_kit_uri_free (check);

	CuAssertTrue (tc, strstr (string, "object=The%20Label") != NULL);
	CuAssertTrue (tc, strstr (string, "object-type=data") != NULL);
	CuAssertTrue (tc, strstr (string, "id=HELLO") != NULL);

	free (string);
	p11_kit_uri_free (uri);
}

static void
test_uri_parse_private_key (CuTest *tc)
{
	P11KitUri *uri;
	CK_ATTRIBUTE_PTR attr;
	int ret;

	uri = p11_kit_uri_new ();
	CuAssertPtrNotNull (tc, uri);

	ret = p11_kit_uri_parse ("pkcs11:object-type=private", P11_KIT_URI_FOR_OBJECT, uri);
	CuAssertIntEquals (tc, P11_KIT_URI_OK, ret);

	attr = p11_kit_uri_get_attribute (uri, CKA_CLASS);
	CuAssertPtrNotNull (tc, attr);
	CuAssertTrue (tc, attr->ulValueLen == sizeof (CK_OBJECT_CLASS));
	CuAssertTrue (tc, *((CK_OBJECT_CLASS_PTR)attr->pValue) == CKO_PRIVATE_KEY);

	p11_kit_uri_free (uri);
}

static void
test_uri_parse_secret_key (CuTest *tc)
{
	P11KitUri *uri;
	CK_ATTRIBUTE_PTR attr;
	int ret;

	uri = p11_kit_uri_new ();
	CuAssertPtrNotNull (tc, uri);

	ret = p11_kit_uri_parse ("pkcs11:object-type=secret-key", P11_KIT_URI_FOR_OBJECT, uri);
	CuAssertIntEquals (tc, P11_KIT_URI_OK, ret);

	attr = p11_kit_uri_get_attribute (uri, CKA_CLASS);
	CuAssertPtrNotNull (tc, attr);
	CuAssertTrue (tc, attr->ulValueLen == sizeof (CK_OBJECT_CLASS));
	CuAssertTrue (tc, *((CK_OBJECT_CLASS_PTR)attr->pValue) == CKO_SECRET_KEY);

	p11_kit_uri_free (uri);
}

static void
test_uri_parse_library_version (CuTest *tc)
{
	P11KitUri *uri;
	CK_INFO_PTR info;
	int ret;

	uri = p11_kit_uri_new ();
	CuAssertPtrNotNull (tc, uri);

	ret = p11_kit_uri_parse ("pkcs11:library-version=2.101", P11_KIT_URI_FOR_MODULE_WITH_VERSION, uri);
	CuAssertIntEquals (tc, P11_KIT_URI_OK, ret);

	info = p11_kit_uri_get_module_info (uri);
	CuAssertIntEquals (tc, 2, info->libraryVersion.major);
	CuAssertIntEquals (tc, 101, info->libraryVersion.minor);

	ret = p11_kit_uri_parse ("pkcs11:library-version=23", P11_KIT_URI_FOR_MODULE_WITH_VERSION, uri);
	CuAssertIntEquals (tc, P11_KIT_URI_OK, ret);

	info = p11_kit_uri_get_module_info (uri);
	CuAssertIntEquals (tc, 23, info->libraryVersion.major);
	CuAssertIntEquals (tc, 0, info->libraryVersion.minor);

	ret = p11_kit_uri_parse ("pkcs11:library-version=23.", P11_KIT_URI_FOR_MODULE_WITH_VERSION, uri);
	CuAssertIntEquals (tc, P11_KIT_URI_BAD_VERSION, ret);

	ret = p11_kit_uri_parse ("pkcs11:library-version=a.a", P11_KIT_URI_FOR_MODULE_WITH_VERSION, uri);
	CuAssertIntEquals (tc, P11_KIT_URI_BAD_VERSION, ret);

	ret = p11_kit_uri_parse ("pkcs11:library-version=.23", P11_KIT_URI_FOR_MODULE_WITH_VERSION, uri);
	CuAssertIntEquals (tc, P11_KIT_URI_BAD_VERSION, ret);

	ret = p11_kit_uri_parse ("pkcs11:library-version=1000", P11_KIT_URI_FOR_MODULE_WITH_VERSION, uri);
	CuAssertIntEquals (tc, P11_KIT_URI_BAD_VERSION, ret);

	ret = p11_kit_uri_parse ("pkcs11:library-version=2.1000", P11_KIT_URI_FOR_MODULE_WITH_VERSION, uri);
	CuAssertIntEquals (tc, P11_KIT_URI_BAD_VERSION, ret);

	p11_kit_uri_free (uri);
}

static void
test_uri_parse_parse_unknown_object_type (CuTest *tc)
{
	P11KitUri *uri;
	CK_ATTRIBUTE_PTR attr;
	int ret;

	uri = p11_kit_uri_new ();
	CuAssertPtrNotNull (tc, uri);

	ret = p11_kit_uri_parse ("pkcs11:object-type=unknown", P11_KIT_URI_FOR_OBJECT, uri);
	CuAssertIntEquals (tc, P11_KIT_URI_OK, ret);

	attr = p11_kit_uri_get_attribute (uri, CKA_CLASS);
	CuAssertPtrEquals (tc, NULL, attr);

	p11_kit_uri_free (uri);
}

static void
test_uri_parse_unrecognized (CuTest *tc)
{
	P11KitUri *uri;
	int ret;

	uri = p11_kit_uri_new ();
	CuAssertPtrNotNull (tc, uri);

	ret = p11_kit_uri_parse ("pkcs11:x-blah=some-value", P11_KIT_URI_FOR_ANY, uri);
	CuAssertIntEquals (tc, P11_KIT_URI_OK, ret);

	ret = p11_kit_uri_any_unrecognized (uri);
	CuAssertIntEquals (tc, 1, ret);

	p11_kit_uri_free (uri);
}

static void
test_uri_parse_too_long_is_unrecognized (CuTest *tc)
{
	P11KitUri *uri;
	int ret;

	uri = p11_kit_uri_new ();
	CuAssertPtrNotNull (tc, uri);

	ret = p11_kit_uri_parse ("pkcs11:model=a-value-that-is-too-long-for-the-field-that-it-goes-with",
	                         P11_KIT_URI_FOR_ANY, uri);
	CuAssertIntEquals (tc, P11_KIT_URI_OK, ret);

	ret = p11_kit_uri_any_unrecognized (uri);
	CuAssertIntEquals (tc, 1, ret);

	p11_kit_uri_free (uri);
}



static void
test_uri_build_object_type_cert (CuTest *tc)
{
	CK_ATTRIBUTE attr;
	CK_OBJECT_CLASS klass;
	P11KitUri *uri;
	char *string;
	int ret;

	uri = p11_kit_uri_new ();
	CuAssertPtrNotNull (tc, uri);

	klass = CKO_CERTIFICATE;
	attr.type = CKA_CLASS;
	attr.pValue = &klass;
	attr.ulValueLen = sizeof (klass);
	p11_kit_uri_set_attribute (uri, &attr);

	ret = p11_kit_uri_format (uri, P11_KIT_URI_FOR_ANY, &string);
	CuAssertIntEquals (tc, P11_KIT_URI_OK, ret);
	CuAssertTrue (tc, strstr (string, "object-type=cert") != NULL);

	p11_kit_uri_free (uri);
	free (string);
}

static void
test_uri_build_object_type_private (CuTest *tc)
{
	CK_ATTRIBUTE attr;
	CK_OBJECT_CLASS klass;
	P11KitUri *uri;
	char *string;
	int ret;

	uri = p11_kit_uri_new ();
	CuAssertPtrNotNull (tc, uri);

	klass = CKO_PRIVATE_KEY;
	attr.type = CKA_CLASS;
	attr.pValue = &klass;
	attr.ulValueLen = sizeof (klass);
	p11_kit_uri_set_attribute (uri, &attr);

	ret = p11_kit_uri_format (uri, P11_KIT_URI_FOR_ANY, &string);
	CuAssertIntEquals (tc, P11_KIT_URI_OK, ret);
	CuAssertTrue (tc, strstr (string, "object-type=private") != NULL);

	p11_kit_uri_free (uri);
	free (string);
}

static void
test_uri_build_object_type_public (CuTest *tc)
{
	CK_ATTRIBUTE attr;
	CK_OBJECT_CLASS klass;
	P11KitUri *uri;
	char *string;
	int ret;

	uri = p11_kit_uri_new ();
	CuAssertPtrNotNull (tc, uri);

	klass = CKO_PUBLIC_KEY;
	attr.type = CKA_CLASS;
	attr.pValue = &klass;
	attr.ulValueLen = sizeof (klass);
	p11_kit_uri_set_attribute (uri, &attr);

	ret = p11_kit_uri_format (uri, P11_KIT_URI_FOR_ANY, &string);
	CuAssertIntEquals (tc, P11_KIT_URI_OK, ret);
	CuAssertTrue (tc, strstr (string, "object-type=public") != NULL);

	p11_kit_uri_free (uri);
	free (string);
}

static void
test_uri_build_object_type_secret (CuTest *tc)
{
	CK_ATTRIBUTE attr;
	CK_OBJECT_CLASS klass;
	P11KitUri *uri;
	char *string;
	int ret;

	uri = p11_kit_uri_new ();
	CuAssertPtrNotNull (tc, uri);

	klass = CKO_SECRET_KEY;
	attr.type = CKA_CLASS;
	attr.pValue = &klass;
	attr.ulValueLen = sizeof (klass);
	p11_kit_uri_set_attribute (uri, &attr);

	ret = p11_kit_uri_format (uri, P11_KIT_URI_FOR_ANY, &string);
	CuAssertIntEquals (tc, P11_KIT_URI_OK, ret);
	CuAssertTrue (tc, strstr (string, "object-type=secret-key") != NULL);

	p11_kit_uri_free (uri);
	free (string);
}

static void
test_uri_build_with_library (CuTest *tc)
{
	CK_INFO_PTR info;
	P11KitUri *uri;
	char *string;
	int ret;

	uri = p11_kit_uri_new ();
	CuAssertPtrNotNull (tc, uri);

	info = p11_kit_uri_get_module_info (uri);
	set_space_string (info->libraryDescription, sizeof (info->libraryDescription), "The Description");

	ret = p11_kit_uri_format (uri, P11_KIT_URI_FOR_ANY, &string);
	CuAssertIntEquals (tc, P11_KIT_URI_OK, ret);
	CuAssertTrue (tc, strstr (string, "library-description=The%20Description") != NULL);

	p11_kit_uri_free (uri);
	free (string);
}

static void
test_uri_build_library_version (CuTest *tc)
{
	CK_INFO_PTR info;
	P11KitUri *uri;
	char *string;
	int ret;

	uri = p11_kit_uri_new ();
	CuAssertPtrNotNull (tc, uri);

	info = p11_kit_uri_get_module_info (uri);
	info->libraryVersion.major = 2;
	info->libraryVersion.minor = 10;

	ret = p11_kit_uri_format (uri, P11_KIT_URI_FOR_ANY, &string);
	CuAssertIntEquals (tc, P11_KIT_URI_OK, ret);
	CuAssertTrue (tc, strstr (string, "library-version=2.10") != NULL);

	p11_kit_uri_free (uri);
	free (string);
}

static void
test_uri_get_set_unrecognized (CuTest *tc)
{
	P11KitUri *uri;
	int ret;

	uri = p11_kit_uri_new ();
	CuAssertPtrNotNull (tc, uri);

	ret = p11_kit_uri_any_unrecognized (uri);
	CuAssertIntEquals (tc, 0, ret);

	p11_kit_uri_set_unrecognized (uri, 1);

	ret = p11_kit_uri_any_unrecognized (uri);
	CuAssertIntEquals (tc, 1, ret);

	p11_kit_uri_set_unrecognized (uri, 0);

	ret = p11_kit_uri_any_unrecognized (uri);
	CuAssertIntEquals (tc, 0, ret);

	p11_kit_uri_free (uri);
}

static void
test_uri_match_token (CuTest *tc)
{
	CK_TOKEN_INFO token;
	P11KitUri *uri;
	int ret;

	uri = p11_kit_uri_new ();
	CuAssertPtrNotNull (tc, uri);

	ret = p11_kit_uri_parse ("pkcs11:model=Giselle", P11_KIT_URI_FOR_ANY, uri);
	CuAssertIntEquals (tc, P11_KIT_URI_OK, ret);

	set_space_string (token.label, sizeof (token.label), "A label");
	set_space_string (token.model, sizeof (token.model), "Giselle");

	ret = p11_kit_uri_match_token_info (uri, &token);
	CuAssertIntEquals (tc, 1, ret);

	set_space_string (token.label, sizeof (token.label), "Another label");

	ret = p11_kit_uri_match_token_info (uri, &token);
	CuAssertIntEquals (tc, 1, ret);

	set_space_string (token.model, sizeof (token.model), "Zoolander");

	ret = p11_kit_uri_match_token_info (uri, &token);
	CuAssertIntEquals (tc, 0, ret);

	p11_kit_uri_set_unrecognized (uri, 1);

	ret = p11_kit_uri_match_token_info (uri, &token);
	CuAssertIntEquals (tc, 0, ret);

	p11_kit_uri_free (uri);
}

static void
test_uri_match_module (CuTest *tc)
{
	CK_INFO info;
	P11KitUri *uri;
	int ret;

	uri = p11_kit_uri_new ();
	CuAssertPtrNotNull (tc, uri);

	ret = p11_kit_uri_parse ("pkcs11:library-description=Quiet", P11_KIT_URI_FOR_ANY, uri);
	CuAssertIntEquals (tc, P11_KIT_URI_OK, ret);

	set_space_string (info.libraryDescription, sizeof (info.libraryDescription), "Quiet");
	set_space_string (info.manufacturerID, sizeof (info.manufacturerID), "Someone");

	ret = p11_kit_uri_match_module_info (uri, &info);
	CuAssertIntEquals (tc, 1, ret);

	set_space_string (info.manufacturerID, sizeof (info.manufacturerID), "Someone else");

	ret = p11_kit_uri_match_module_info (uri, &info);
	CuAssertIntEquals (tc, 1, ret);

	set_space_string (info.libraryDescription, sizeof (info.libraryDescription), "Leise");

	ret = p11_kit_uri_match_module_info (uri, &info);
	CuAssertIntEquals (tc, 0, ret);

	p11_kit_uri_set_unrecognized (uri, 1);

	ret = p11_kit_uri_match_module_info (uri, &info);
	CuAssertIntEquals (tc, 0, ret);

	p11_kit_uri_free (uri);
}

static void
test_uri_match_attributes (CuTest *tc)
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
	CuAssertPtrNotNull (tc, uri);

	ret = p11_kit_uri_parse ("pkcs11:object=Fancy;id=Blah;object-type=data", P11_KIT_URI_FOR_ANY, uri);
	CuAssertIntEquals (tc, P11_KIT_URI_OK, ret);

	ret = p11_kit_uri_match_attributes (uri, attrs, 4);
	CuAssertIntEquals (tc, 0, ret);

	attrs[1].pValue = "Fancy";
	attrs[1].ulValueLen = 5;

	ret = p11_kit_uri_match_attributes (uri, attrs, 4);
	CuAssertIntEquals (tc, 1, ret);

	p11_kit_uri_clear_attribute (uri, CKA_CLASS);

	ret = p11_kit_uri_match_attributes (uri, attrs, 4);
	CuAssertIntEquals (tc, 1, ret);

	attrs[2].pValue = "pink";

	ret = p11_kit_uri_match_attributes (uri, attrs, 4);
	CuAssertIntEquals (tc, 1, ret);

	p11_kit_uri_set_unrecognized (uri, 1);

	ret = p11_kit_uri_match_attributes (uri, attrs, 4);
	CuAssertIntEquals (tc, 0, ret);

	p11_kit_uri_free (uri);
}

static void
test_uri_get_set_attribute (CuTest *tc)
{
	CK_ATTRIBUTE attr;
	CK_ATTRIBUTE_PTR ptr;
	P11KitUri *uri;
	int ret;

	uri = p11_kit_uri_new ();
	CuAssertPtrNotNull (tc, uri);

	ptr = p11_kit_uri_get_attribute (uri, CKA_LABEL);
	CuAssertPtrEquals (tc, NULL, ptr);

	ret = p11_kit_uri_clear_attribute (uri, CKA_LABEL);
	CuAssertIntEquals (tc, P11_KIT_URI_OK, ret);

	ret = p11_kit_uri_clear_attribute (uri, CKA_COLOR);
	CuAssertIntEquals (tc, P11_KIT_URI_NOT_FOUND, ret);

	attr.type = CKA_LABEL;
	attr.pValue = "Test";
	attr.ulValueLen = 4;

	ret = p11_kit_uri_set_attribute (uri, &attr);
	CuAssertIntEquals (tc, P11_KIT_URI_OK, ret);

	attr.type = CKA_COLOR;
	ret = p11_kit_uri_set_attribute (uri, &attr);
	CuAssertIntEquals (tc, P11_KIT_URI_NOT_FOUND, ret);

	ptr = p11_kit_uri_get_attribute (uri, CKA_COLOR);
	CuAssertPtrEquals (tc, NULL, ptr);

	ptr = p11_kit_uri_get_attribute (uri, CKA_LABEL);
	CuAssertPtrNotNull (tc, ptr);

	CuAssertTrue (tc, ptr->type == CKA_LABEL);
	CuAssertTrue (tc, ptr->ulValueLen == 4);
	CuAssertTrue (tc, memcmp (ptr->pValue, "Test", 4) == 0);

	ret = p11_kit_uri_clear_attribute (uri, CKA_LABEL);
	CuAssertIntEquals (tc, P11_KIT_URI_OK, ret);

	ptr = p11_kit_uri_get_attribute (uri, CKA_LABEL);
	CuAssertPtrEquals (tc, NULL, ptr);

	p11_kit_uri_free (uri);
}

static void
test_uri_get_set_attributes (CuTest *tc)
{
	CK_ATTRIBUTE_PTR attrs;
	CK_OBJECT_CLASS klass;
	CK_ATTRIBUTE attr;
	CK_ULONG n_attrs;
	P11KitUri *uri;
	int ret;

	uri = p11_kit_uri_new ();
	CuAssertPtrNotNull (tc, uri);

	attrs = p11_kit_uri_get_attributes (uri, &n_attrs);
	CuAssertPtrNotNull (tc, attrs);
	CuAssertIntEquals (tc, 0, n_attrs);

	attr.type = CKA_LABEL;
	attr.pValue = "Test";
	attr.ulValueLen = 4;

	ret = p11_kit_uri_set_attribute (uri, &attr);
	CuAssertIntEquals (tc, P11_KIT_URI_OK, ret);

	attrs = p11_kit_uri_get_attributes (uri, &n_attrs);
	CuAssertPtrNotNull (tc, attrs);
	CuAssertIntEquals (tc, 1, n_attrs);
	CuAssertTrue (tc, attrs[0].type == CKA_LABEL);
	CuAssertTrue (tc, attrs[0].ulValueLen == 4);
	CuAssertTrue (tc, memcmp (attrs[0].pValue, "Test", 4) == 0);

	attr.type = CKA_LABEL;
	attr.pValue = "Kablooey";
	attr.ulValueLen = 8;

	ret = p11_kit_uri_set_attribute (uri, &attr);
	CuAssertIntEquals (tc, P11_KIT_URI_OK, ret);

	attrs = p11_kit_uri_get_attributes (uri, &n_attrs);
	CuAssertPtrNotNull (tc, attrs);
	CuAssertIntEquals (tc, 1, n_attrs);
	CuAssertTrue (tc, attrs[0].type == CKA_LABEL);
	CuAssertTrue (tc, attrs[0].ulValueLen == 8);
	CuAssertTrue (tc, memcmp (attrs[0].pValue, "Kablooey", 8) == 0);

	klass = CKO_DATA;
	attr.type = CKA_CLASS;
	attr.pValue = &klass;
	attr.ulValueLen = sizeof (klass);

	ret = p11_kit_uri_set_attribute (uri, &attr);
	CuAssertIntEquals (tc, P11_KIT_URI_OK, ret);

	attrs = p11_kit_uri_get_attributes (uri, &n_attrs);
	CuAssertPtrNotNull (tc, attrs);
	CuAssertIntEquals (tc, 2, n_attrs);
	CuAssertTrue (tc, attrs[0].type == CKA_LABEL);
	CuAssertTrue (tc, attrs[0].ulValueLen == 8);
	CuAssertTrue (tc, memcmp (attrs[0].pValue, "Kablooey", 8) == 0);
	CuAssertTrue (tc, attrs[1].type == CKA_CLASS);
	CuAssertTrue (tc, attrs[1].ulValueLen == sizeof (klass));
	CuAssertTrue (tc, memcmp (attrs[1].pValue, &klass, sizeof (klass)) == 0);

	ret = p11_kit_uri_clear_attribute (uri, CKA_LABEL);
	CuAssertIntEquals (tc, P11_KIT_URI_OK, ret);

	attrs = p11_kit_uri_get_attributes (uri, &n_attrs);
	CuAssertPtrNotNull (tc, attrs);
	CuAssertIntEquals (tc, 1, n_attrs);
	CuAssertTrue (tc, attrs[0].type == CKA_CLASS);
	CuAssertTrue (tc, attrs[0].ulValueLen == sizeof (klass));
	CuAssertTrue (tc, memcmp (attrs[0].pValue, &klass, sizeof (klass)) == 0);

	attr.type = CKA_LABEL;
	attr.pValue = "Three";
	attr.ulValueLen = 5;

	ret = p11_kit_uri_set_attributes (uri, &attr, 1);
	CuAssertIntEquals (tc, P11_KIT_URI_OK, ret);

	attrs = p11_kit_uri_get_attributes (uri, &n_attrs);
	CuAssertPtrNotNull (tc, attrs);
	CuAssertIntEquals (tc, 1, n_attrs);
	CuAssertTrue (tc, attrs[0].type == CKA_LABEL);
	CuAssertTrue (tc, attrs[0].ulValueLen == 5);
	CuAssertTrue (tc, memcmp (attrs[0].pValue, "Three", 5) == 0);

	p11_kit_uri_clear_attributes (uri);

	attrs = p11_kit_uri_get_attributes (uri, &n_attrs);
	CuAssertPtrNotNull (tc, attrs);
	CuAssertIntEquals (tc, 0, n_attrs);

	p11_kit_uri_free (uri);
}
static void
test_uri_pin_source (CuTest *tc)
{
	P11KitUri *uri;
	const char *pin_source;
	char *string;
	int ret;

	uri = p11_kit_uri_new ();
	CuAssertPtrNotNull (tc, uri);

	p11_kit_uri_set_pin_source (uri, "|my-pin-file");

	pin_source = p11_kit_uri_get_pin_source (uri);
	CuAssertStrEquals (tc, "|my-pin-file", pin_source);

	ret = p11_kit_uri_format (uri, P11_KIT_URI_FOR_ANY, &string);
	CuAssertIntEquals (tc, P11_KIT_URI_OK, ret);
	CuAssertTrue (tc, strstr (string, "pin-source=%7cmy-pin-file") != NULL);
	free (string);

	ret = p11_kit_uri_parse ("pkcs11:pin-source=blah%2Fblah", P11_KIT_URI_FOR_ANY, uri);
	CuAssertIntEquals (tc, P11_KIT_URI_OK, ret);

	pin_source = p11_kit_uri_get_pin_source (uri);
	CuAssertStrEquals (tc, "blah/blah", pin_source);

	p11_kit_uri_free (uri);
}

static void
test_uri_free_null (CuTest *tc)
{
	p11_kit_uri_free (NULL);
}

static void
test_uri_message (CuTest *tc)
{
	CuAssertTrue (tc, p11_kit_uri_message (P11_KIT_URI_OK) == NULL);
	CuAssertPtrNotNull (tc, p11_kit_uri_message (P11_KIT_URI_NO_MEMORY));
	CuAssertPtrNotNull (tc, p11_kit_uri_message (-555555));
}

int
main (void)
{
	CuString *output = CuStringNew ();
	CuSuite* suite = CuSuiteNew ();
	int ret;

	_p11_library_init ();

	SUITE_ADD_TEST (suite, test_uri_parse);
	SUITE_ADD_TEST (suite, test_uri_parse_bad_scheme);
	SUITE_ADD_TEST (suite, test_uri_parse_with_label);
	SUITE_ADD_TEST (suite, test_uri_parse_with_label_and_klass);
	SUITE_ADD_TEST (suite, test_uri_parse_with_id);
	SUITE_ADD_TEST (suite, test_uri_parse_with_bad_string_encoding);
	SUITE_ADD_TEST (suite, test_uri_parse_with_bad_hex_encoding);
	SUITE_ADD_TEST (suite, test_uri_parse_with_token);
	SUITE_ADD_TEST (suite, test_uri_parse_with_token_bad_encoding);
	SUITE_ADD_TEST (suite, test_uri_parse_with_bad_syntax);
	SUITE_ADD_TEST (suite, test_uri_parse_with_spaces);
	SUITE_ADD_TEST (suite, test_uri_parse_with_library);
	SUITE_ADD_TEST (suite, test_uri_parse_with_library_bad_encoding);
	SUITE_ADD_TEST (suite, test_uri_build_empty);
	SUITE_ADD_TEST (suite, test_uri_build_with_token_info);
	SUITE_ADD_TEST (suite, test_uri_build_with_token_null_info);
	SUITE_ADD_TEST (suite, test_uri_build_with_token_empty_info);
	SUITE_ADD_TEST (suite, test_uri_build_with_attributes);
	SUITE_ADD_TEST (suite, test_uri_parse_private_key);
	SUITE_ADD_TEST (suite, test_uri_parse_secret_key);
	SUITE_ADD_TEST (suite, test_uri_parse_library_version);
	SUITE_ADD_TEST (suite, test_uri_parse_parse_unknown_object_type);
	SUITE_ADD_TEST (suite, test_uri_parse_unrecognized);
	SUITE_ADD_TEST (suite, test_uri_parse_too_long_is_unrecognized);
	SUITE_ADD_TEST (suite, test_uri_build_object_type_cert);
	SUITE_ADD_TEST (suite, test_uri_build_object_type_private);
	SUITE_ADD_TEST (suite, test_uri_build_object_type_public);
	SUITE_ADD_TEST (suite, test_uri_build_object_type_secret);
	SUITE_ADD_TEST (suite, test_uri_build_with_library);
	SUITE_ADD_TEST (suite, test_uri_build_library_version);
	SUITE_ADD_TEST (suite, test_uri_get_set_unrecognized);
	SUITE_ADD_TEST (suite, test_uri_match_token);
	SUITE_ADD_TEST (suite, test_uri_match_module);
	SUITE_ADD_TEST (suite, test_uri_match_attributes);
	SUITE_ADD_TEST (suite, test_uri_get_set_attribute);
	SUITE_ADD_TEST (suite, test_uri_get_set_attributes);
	SUITE_ADD_TEST (suite, test_uri_pin_source);
	SUITE_ADD_TEST (suite, test_uri_free_null);
	SUITE_ADD_TEST (suite, test_uri_message);

	CuSuiteRun (suite);
	CuSuiteSummary (suite, output);
	CuSuiteDetails (suite, output);
	printf ("%s\n", output->buffer);
	ret = suite->failCount;
	CuSuiteDelete (suite);
	CuStringDelete (output);
	return ret;
}
