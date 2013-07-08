/*
 * Copyright (c) 2012 Red Hat Inc.
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
 * Author: Stef Walter <stefw@gnome.org>
 */

#include "config.h"
#include "test.h"
#include "test-trust.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "array.h"
#include "attrs.h"
#include "builder.h"
#include "debug.h"
#include "message.h"
#include "oid.h"
#include "parser.h"
#include "pkcs11x.h"

struct {
	p11_parser *parser;
	p11_array *parsed;
	p11_asn1_cache *cache;
} test;

static void
setup (void *unused)
{
	test.cache = p11_asn1_cache_new ();
	test.parser = p11_parser_new (test.cache);
	assert_ptr_not_null (test.parser);

	test.parsed = p11_parser_parsed (test.parser);
	assert_ptr_not_null (test.parsed);
}

static void
teardown (void *unused)
{
	p11_parser_free (test.parser);
	p11_asn1_cache_free (test.cache);
	memset (&test, 0, sizeof (test));
}

static CK_OBJECT_CLASS certificate = CKO_CERTIFICATE;
static CK_OBJECT_CLASS certificate_extension = CKO_X_CERTIFICATE_EXTENSION;
static CK_BBOOL falsev = CK_FALSE;
static CK_BBOOL truev = CK_TRUE;
static CK_CERTIFICATE_TYPE x509 = CKC_X_509;

static CK_ATTRIBUTE certificate_match[] = {
	{ CKA_CLASS, &certificate, sizeof (certificate) },
	{ CKA_INVALID, },
};

static CK_ATTRIBUTE *
parsed_attrs (CK_ATTRIBUTE *match,
              int length)
{
	int i;

	if (length < 0)
		length = p11_attrs_count (match);
	for (i = 0; i < test.parsed->num; i++) {
		if (p11_attrs_matchn (test.parsed->elem[i], match, length))
			return test.parsed->elem[i];
	}

	return NULL;
}

static void
test_parse_der_certificate (void)
{
	CK_ATTRIBUTE *cert;
	int ret;

	CK_ATTRIBUTE expected[] = {
		{ CKA_CERTIFICATE_TYPE, &x509, sizeof (x509) },
		{ CKA_CLASS, &certificate, sizeof (certificate) },
		{ CKA_VALUE, (void *)test_cacert3_ca_der, sizeof (test_cacert3_ca_der) },
		{ CKA_MODIFIABLE, &falsev, sizeof (falsev) },
		{ CKA_TRUSTED, &falsev, sizeof (falsev) },
		{ CKA_X_DISTRUSTED, &falsev, sizeof (falsev) },
		{ CKA_INVALID },
	};

	p11_parser_formats (test.parser, p11_parser_format_x509, NULL);
	ret = p11_parse_file (test.parser, SRCDIR "/files/cacert3.der",
	                      P11_PARSE_FLAG_NONE);
	assert_num_eq (P11_PARSE_SUCCESS, ret);

	/* Should have gotten certificate */
	assert_num_eq (1, test.parsed->num);

	cert = parsed_attrs (certificate_match, -1);
	test_check_attrs (expected, cert);
}

static void
test_parse_pem_certificate (void)
{
	CK_ATTRIBUTE *cert;
	int ret;

	CK_ATTRIBUTE expected[] = {
		{ CKA_CERTIFICATE_TYPE, &x509, sizeof (x509) },
		{ CKA_CLASS, &certificate, sizeof (certificate) },
		{ CKA_VALUE, (void *)test_cacert3_ca_der, sizeof (test_cacert3_ca_der) },
		{ CKA_MODIFIABLE, &falsev, sizeof (falsev) },
		{ CKA_TRUSTED, &falsev, sizeof (falsev) },
		{ CKA_X_DISTRUSTED, &falsev, sizeof (falsev) },
		{ CKA_INVALID },
	};

	p11_parser_formats (test.parser, p11_parser_format_pem, NULL);
	ret = p11_parse_file (test.parser, SRCDIR "/files/cacert3.pem",
	                      P11_PARSE_FLAG_NONE);
	assert_num_eq (P11_PARSE_SUCCESS, ret);

	/* Should have gotten certificate  */
	assert_num_eq (1, test.parsed->num);

	cert = parsed_attrs (certificate_match, -1);
	test_check_attrs (expected, cert);
}

static void
test_parse_p11_kit_persist (void)
{
	CK_ATTRIBUTE *cert;
	int ret;

	CK_ATTRIBUTE expected[] = {
		{ CKA_CERTIFICATE_TYPE, &x509, sizeof (x509) },
		{ CKA_CLASS, &certificate, sizeof (certificate) },
		{ CKA_VALUE, (void *)verisign_v1_ca, sizeof (verisign_v1_ca) },
		{ CKA_TRUSTED, &truev, sizeof (truev) },
		{ CKA_X_DISTRUSTED, &falsev, sizeof (falsev) },
		{ CKA_INVALID },
	};

	p11_parser_formats (test.parser, p11_parser_format_persist, NULL);
	ret = p11_parse_file (test.parser, SRCDIR "/input/verisign-v1.p11-kit",
	                      P11_PARSE_FLAG_NONE);
	assert_num_eq (P11_PARSE_SUCCESS, ret);

	/* Should have gotten certificate  */
	assert_num_eq (1, test.parsed->num);

	cert = parsed_attrs (certificate_match, -1);
	test_check_attrs (expected, cert);
}

static void
test_parse_openssl_trusted (void)
{
	CK_ATTRIBUTE cacert3[] = {
		{ CKA_CERTIFICATE_TYPE, &x509, sizeof (x509) },
		{ CKA_CLASS, &certificate, sizeof (certificate) },
		{ CKA_VALUE, (void *)test_cacert3_ca_der, sizeof (test_cacert3_ca_der) },
		{ CKA_MODIFIABLE, &falsev, sizeof (falsev) },
		{ CKA_TRUSTED, &truev, sizeof (truev) },
		{ CKA_X_DISTRUSTED, &falsev, sizeof (falsev) },
		{ CKA_INVALID },
	};

	CK_ATTRIBUTE eku_extension[] = {
		{ CKA_CLASS, &certificate_extension, sizeof (certificate_extension), },
		{ CKA_OBJECT_ID, (void *)P11_OID_EXTENDED_KEY_USAGE, sizeof (P11_OID_EXTENDED_KEY_USAGE) },
		{ CKA_X_PUBLIC_KEY_INFO, (void *)test_cacert3_ca_public_key, sizeof (test_cacert3_ca_public_key) },
		{ CKA_VALUE, "\x30\x16\x06\x03\x55\x1d\x25\x01\x01\xff\x04\x0c\x30\x0a\x06\x08\x2b\x06\x01\x05\x05\x07\x03\x01", 24 },
		{ CKA_INVALID },
	};

	CK_ATTRIBUTE reject_extension[] = {
		{ CKA_CLASS, &certificate_extension, sizeof (certificate_extension), },
		{ CKA_OBJECT_ID, (void *)P11_OID_OPENSSL_REJECT, sizeof (P11_OID_OPENSSL_REJECT) },
		{ CKA_X_PUBLIC_KEY_INFO, (void *)test_cacert3_ca_public_key, sizeof (test_cacert3_ca_public_key) },
		{ CKA_VALUE, "\x30\x1a\x06\x0a\x2b\x06\x01\x04\x01\x99\x77\x06\x0a\x01\x04\x0c\x30\x0a\x06\x08\x2b\x06\x01\x05\x05\x07\x03\x04", 28 },
		{ CKA_INVALID },
	};

	CK_ATTRIBUTE *expected[] = {
		cacert3,
		eku_extension,
		reject_extension,
		NULL
	};

	CK_ATTRIBUTE *cert;
	CK_ATTRIBUTE *object;
	int ret;
	int i;

	p11_parser_formats (test.parser, p11_parser_format_pem, NULL);
	ret = p11_parse_file (test.parser, SRCDIR "/files/cacert3-trusted.pem",
	                      P11_PARSE_FLAG_ANCHOR);
	assert_num_eq (P11_PARSE_SUCCESS, ret);

	/*
	 * Should have gotten:
	 * - 1 certificate
	 * - 2 stapled extensions
	 */
	assert_num_eq (3, test.parsed->num);

	/* The certificate */
	cert = parsed_attrs (certificate_match, -1);
	test_check_attrs (expected[0], cert);

	/* The other objects */
	for (i = 1; expected[i]; i++) {
		object = parsed_attrs (expected[i], 2);
		assert_ptr_not_null (object);

		test_check_attrs (expected[i], object);
		test_check_id (cert, object);
	}
}

static void
test_parse_openssl_distrusted (void)
{
	static const char distrust_public_key[] = {
		0x30, 0x81, 0x9f, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
		0x05, 0x00, 0x03, 0x81, 0x8d, 0x00, 0x30, 0x81, 0x89, 0x02, 0x81, 0x81, 0x00, 0xdf, 0xc7, 0x0d,
		0x61, 0xa2, 0x2f, 0xc0, 0x5a, 0xad, 0x45, 0x83, 0x22, 0x33, 0x42, 0xea, 0xec, 0x42, 0x5e, 0xa6,
		0x0d, 0x42, 0x4c, 0x1c, 0x9a, 0x12, 0x0b, 0x5f, 0xe7, 0x25, 0xf9, 0x8b, 0x83, 0x0c, 0x0a, 0xc5,
		0x2f, 0x5a, 0x58, 0x56, 0xb8, 0xad, 0x87, 0x6d, 0xbc, 0x80, 0x5d, 0xdd, 0x49, 0x45, 0x39, 0x5f,
		0xb9, 0x08, 0x3a, 0x63, 0xe4, 0x92, 0x33, 0x61, 0x79, 0x19, 0x1b, 0x9d, 0xab, 0x3a, 0xd5, 0x7f,
		0xa7, 0x8b, 0x7f, 0x8a, 0x5a, 0xf6, 0xd7, 0xde, 0xaf, 0xa1, 0xe5, 0x53, 0x31, 0x29, 0x7d, 0x9c,
		0x03, 0x55, 0x3e, 0x47, 0x78, 0xcb, 0xb9, 0x7a, 0x98, 0x8c, 0x5f, 0x8d, 0xda, 0x09, 0x0f, 0xc8,
		0xfb, 0xf1, 0x7a, 0x80, 0xee, 0x12, 0x77, 0x0a, 0x00, 0x8b, 0x70, 0xfa, 0x62, 0xbf, 0xaf, 0xee,
		0x0b, 0x58, 0x16, 0xf9, 0x9c, 0x5c, 0xde, 0x93, 0xb8, 0x4f, 0xdf, 0x4d, 0x7b, 0x02, 0x03, 0x01,
		0x00, 0x01,
	};

	CK_ATTRIBUTE distrust_cert[] = {
		{ CKA_CLASS, &certificate, sizeof (certificate), },
		{ CKA_MODIFIABLE, &falsev, sizeof (falsev) },
		{ CKA_CERTIFICATE_TYPE, &x509, sizeof (x509) },
		{ CKA_TRUSTED, &falsev, sizeof (falsev) },
		{ CKA_X_DISTRUSTED, &truev, sizeof (truev) },
		{ CKA_INVALID },
	};

	CK_ATTRIBUTE eku_extension[] = {
		{ CKA_CLASS, &certificate_extension, sizeof (certificate_extension), },
		{ CKA_OBJECT_ID, (void *)P11_OID_EXTENDED_KEY_USAGE, sizeof (P11_OID_EXTENDED_KEY_USAGE) },
		{ CKA_X_PUBLIC_KEY_INFO, (void *)distrust_public_key, sizeof (distrust_public_key) },
		{ CKA_VALUE, "\x30\x18\x06\x03\x55\x1d\x25\x01\x01\xff\x04\x0e\x30\x0c\x06\x0a\x2b\x06\x01\x04\x01\x99\x77\x06\x0a\x10", 26 },
		{ CKA_INVALID },
	};

	CK_ATTRIBUTE reject_extension[] = {
		{ CKA_CLASS, &certificate_extension, sizeof (certificate_extension), },
		{ CKA_OBJECT_ID, (void *)P11_OID_OPENSSL_REJECT, sizeof (P11_OID_OPENSSL_REJECT) },
		{ CKA_X_PUBLIC_KEY_INFO, (void *)distrust_public_key, sizeof (distrust_public_key) },
		{ CKA_VALUE, "\x30\x1a\x06\x0a\x2b\x06\x01\x04\x01\x99\x77\x06\x0a\x01\x04\x0c\x30\x0a\x06\x08\x2b\x06\x01\x05\x05\x07\x03\x02", 28 },
		{ CKA_INVALID },
	};

	CK_ATTRIBUTE *expected[] = {
		distrust_cert,
		eku_extension,
		reject_extension,
		NULL
	};

	CK_ATTRIBUTE *cert;
	CK_ATTRIBUTE *object;
	int ret;
	int i;

	/*
	 * OpenSSL style is to litter the blacklist in with the anchors,
	 * so we parse this as an anchor, but expect it to be blacklisted
	 */
	p11_parser_formats (test.parser, p11_parser_format_pem, NULL);
	ret = p11_parse_file (test.parser, SRCDIR "/files/distrusted.pem",
	                      P11_PARSE_FLAG_ANCHOR);
	assert_num_eq (P11_PARSE_SUCCESS, ret);

	/*
	 * Should have gotten:
	 * - 1 certificate
	 * - 2 stapled extensions
	 */
	assert_num_eq (3, test.parsed->num);
	cert = parsed_attrs (certificate_match, -1);
	test_check_attrs (expected[0], cert);

	/* The other objects */
	for (i = 1; expected[i]; i++) {
		object = parsed_attrs (expected[i], 2);
		assert_ptr_not_null (object);

		test_check_attrs (expected[i], object);
		test_check_id (cert, object);
	}
}

static void
test_parse_anchor (void)
{
	CK_ATTRIBUTE cacert3[] = {
		{ CKA_CERTIFICATE_TYPE, &x509, sizeof (x509) },
		{ CKA_CLASS, &certificate, sizeof (certificate) },
		{ CKA_VALUE, (void *)test_cacert3_ca_der, sizeof (test_cacert3_ca_der) },
		{ CKA_MODIFIABLE, &falsev, sizeof (falsev) },
		{ CKA_TRUSTED, &truev, sizeof (truev) },
		{ CKA_X_DISTRUSTED, &falsev, sizeof (falsev) },
		{ CKA_INVALID },
	};

	CK_ATTRIBUTE *cert;
	int ret;

	p11_parser_formats (test.parser, p11_parser_format_x509, NULL);
	ret = p11_parse_file (test.parser, SRCDIR "/files/cacert3.der",
	                      P11_PARSE_FLAG_ANCHOR);
	assert_num_eq (P11_PARSE_SUCCESS, ret);

	/*
	 * Should have gotten:
	 * - 1 certificate
	 */
	assert_num_eq (1, test.parsed->num);

	cert = parsed_attrs (certificate_match, -1);
	test_check_attrs (cacert3, cert);
}

static void
test_parse_thawte (void)
{
	CK_ATTRIBUTE *cert;
	int ret;

	CK_ATTRIBUTE expected[] = {
		{ CKA_CERTIFICATE_TYPE, &x509, sizeof (x509) },
		{ CKA_CLASS, &certificate, sizeof (certificate) },
		{ CKA_MODIFIABLE, &falsev, sizeof (falsev) },
		{ CKA_TRUSTED, &falsev, sizeof (falsev) },
		{ CKA_X_DISTRUSTED, &falsev, sizeof (falsev) },
		{ CKA_INVALID },
	};

	p11_parser_formats (test.parser, p11_parser_format_pem, NULL);
	ret = p11_parse_file (test.parser, SRCDIR "/files/thawte.pem",
	                      P11_PARSE_FLAG_NONE);
	assert_num_eq (P11_PARSE_SUCCESS, ret);

	/* Should have gotten certificate  */
	assert_num_eq (1, test.parsed->num);

	cert = parsed_attrs (certificate_match, -1);
	test_check_attrs (expected, cert);
}

/* TODO: A certificate that uses generalTime needs testing */

static void
test_parse_invalid_file (void)
{
	int ret;

	p11_message_quiet ();

	p11_parser_formats (test.parser, p11_parser_format_x509, NULL);
	ret = p11_parse_file (test.parser, "/nonexistant",
	                      P11_PARSE_FLAG_NONE);
	assert_num_eq (P11_PARSE_FAILURE, ret);

	p11_message_loud ();
}

static void
test_parse_unrecognized (void)
{
	int ret;

	p11_message_quiet ();

	p11_parser_formats (test.parser, p11_parser_format_x509, NULL);
	ret = p11_parse_file (test.parser, SRCDIR "/files/unrecognized-file.txt",
	                      P11_PARSE_FLAG_NONE);
	assert_num_eq (P11_PARSE_UNRECOGNIZED, ret);

	p11_message_loud ();
}

static void
test_parse_no_asn1_cache (void)
{
	p11_parser *parser;
	int ret;

	parser = p11_parser_new (NULL);
	assert_ptr_not_null (parser);

	p11_parser_formats (parser, p11_parser_format_x509, NULL);
	ret = p11_parse_file (parser, SRCDIR "/files/cacert3.der", P11_PARSE_FLAG_NONE);
	assert_num_eq (P11_PARSE_SUCCESS, ret);

	/* Should have gotten certificate  */
	assert_num_eq (1, p11_parser_parsed (parser)->num);

	p11_parser_free (parser);
}

int
main (int argc,
      char *argv[])
{
	p11_fixture (setup, teardown);
	p11_test (test_parse_der_certificate, "/parser/parse_der_certificate");
	p11_test (test_parse_pem_certificate, "/parser/parse_pem_certificate");
	p11_test (test_parse_p11_kit_persist, "/parser/parse_p11_kit_persist");
	p11_test (test_parse_openssl_trusted, "/parser/parse_openssl_trusted");
	p11_test (test_parse_openssl_distrusted, "/parser/parse_openssl_distrusted");
	p11_test (test_parse_anchor, "/parser/parse_anchor");
	p11_test (test_parse_thawte, "/parser/parse_thawte");
	p11_test (test_parse_invalid_file, "/parser/parse_invalid_file");
	p11_test (test_parse_unrecognized, "/parser/parse_unrecognized");

	p11_fixture (NULL, NULL);
	p11_test (test_parse_no_asn1_cache, "/parser/null-asn1-cache");

	return p11_test_run (argc, argv);
}
