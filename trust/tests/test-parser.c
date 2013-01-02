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
#include "CuTest.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "array.h"
#include "attrs.h"
#include "debug.h"
#include "library.h"
#include "oid.h"
#include "parser.h"
#include "pkcs11x.h"
#include "test-data.h"

struct {
	p11_parser *parser;
	p11_array *objects;
} test;

static void
setup (CuTest *cu)
{
	test.parser = p11_parser_new ();
	CuAssertPtrNotNull (cu, test.parser);

	test.objects = p11_array_new (p11_attrs_free);
	CuAssertPtrNotNull (cu, test.objects);
}

static void
teardown (CuTest *cu)
{
	p11_parser_free (test.parser);
	p11_array_free (test.objects);
	memset (&test, 0, sizeof (test));
}

static void
on_parse_object (CK_ATTRIBUTE *attrs,
                 void *data)
{
	CuTest *cu = data;

	CuAssertPtrNotNull (cu, attrs);
	CuAssertTrue (cu, p11_attrs_count (attrs) > 0);

	p11_array_push (test.objects, attrs);
}

static void
test_parse_der_certificate (CuTest *cu)
{
	CK_ATTRIBUTE *attrs;
	CK_ATTRIBUTE *attr;
	int ret;

	setup (cu);

	ret = p11_parse_file (test.parser, SRCDIR "/files/cacert3.der",
	                      0, on_parse_object, cu);
	CuAssertIntEquals (cu, P11_PARSE_SUCCESS, ret);

	/* Should have gotten certificate and a trust object */
	CuAssertIntEquals (cu, 2, test.objects->num);

	attrs = test.objects->elem[0];
	test_check_cacert3_ca (cu, attrs, NULL);

	attr = p11_attrs_find (attrs, CKA_TRUSTED);
	CuAssertPtrEquals (cu, NULL, attr);

	teardown (cu);
}

static void
test_parse_pem_certificate (CuTest *cu)
{
	CK_ATTRIBUTE *attrs;
	CK_ATTRIBUTE *attr;
	int ret;

	setup (cu);

	ret = p11_parse_file (test.parser, SRCDIR "/files/cacert3.pem",
	                      0, on_parse_object, cu);
	CuAssertIntEquals (cu, P11_PARSE_SUCCESS, ret);

	/* Should have gotten certificate and a trust object */
	CuAssertIntEquals (cu, 2, test.objects->num);

	attrs = test.objects->elem[0];
	test_check_cacert3_ca (cu, attrs, NULL);

	attr = p11_attrs_find (attrs, CKA_TRUSTED);
	CuAssertPtrEquals (cu, NULL, attr);

	teardown (cu);
}

static void
test_parse_openssl_trusted (CuTest *cu)
{
	CK_TRUST trusted = CKT_NETSCAPE_TRUSTED;
	CK_TRUST distrusted = CKT_NETSCAPE_UNTRUSTED;
	CK_TRUST unknown = CKT_NETSCAPE_TRUST_UNKNOWN;
	CK_OBJECT_CLASS certificate_extension = CKO_X_CERTIFICATE_EXTENSION;
	CK_OBJECT_CLASS trust_object = CKO_NETSCAPE_TRUST;
	CK_BBOOL vtrue = CK_TRUE;
	CK_BBOOL vfalse = CK_FALSE;

	CK_ATTRIBUTE eku_extension[] = {
		{ CKA_LABEL, "Custom Label", 12 },
		{ CKA_CLASS, &certificate_extension, sizeof (certificate_extension), },
		{ CKA_OBJECT_ID, (void *)P11_OID_EXTENDED_KEY_USAGE, sizeof (P11_OID_EXTENDED_KEY_USAGE) },
		{ CKA_X_CRITICAL, &vtrue, sizeof (vtrue) },
		{ CKA_INVALID },
	};

	CK_ATTRIBUTE reject_extension[] = {
		{ CKA_LABEL, "Custom Label", 12 },
		{ CKA_CLASS, &certificate_extension, sizeof (certificate_extension), },
		{ CKA_OBJECT_ID, (void *)P11_OID_OPENSSL_REJECT, sizeof (P11_OID_OPENSSL_REJECT) },
		{ CKA_X_CRITICAL, &vfalse, sizeof (vfalse) },
		{ CKA_INVALID },
	};

	CK_ATTRIBUTE nss_trust[] = {
		{ CKA_LABEL, "Custom Label", 12 },
		{ CKA_CLASS, &trust_object, sizeof (trust_object), },
		{ CKA_CERT_SHA1_HASH, "\xad\x7c\x3f\x64\xfc\x44\x39\xfe\xf4\xe9\x0b\xe8\xf4\x7c\x6c\xfa\x8a\xad\xfd\xce", 20 },
		{ CKA_CERT_MD5_HASH, "\xf7\x25\x12\x82\x4e\x67\xb5\xd0\x8d\x92\xb7\x7c\x0b\x86\x7a\x42", 16 },
		{ CKA_ISSUER, (void *)test_cacert3_ca_issuer, sizeof (test_cacert3_ca_issuer) },
		{ CKA_SUBJECT, (void *)test_cacert3_ca_subject, sizeof (test_cacert3_ca_subject) },
		{ CKA_SERIAL_NUMBER, (void *)test_cacert3_ca_serial, sizeof (test_cacert3_ca_serial) },
		{ CKA_TRUST_SERVER_AUTH, &trusted, sizeof (trusted) },
		{ CKA_TRUST_CLIENT_AUTH, &trusted, sizeof (trusted) },
		{ CKA_TRUST_EMAIL_PROTECTION, &distrusted, sizeof (distrusted) },
		{ CKA_TRUST_CODE_SIGNING, &unknown, sizeof (unknown) },
		{ CKA_TRUST_IPSEC_END_SYSTEM, &unknown, sizeof (unknown) },
		{ CKA_TRUST_IPSEC_TUNNEL, &unknown, sizeof (unknown) },
		{ CKA_TRUST_IPSEC_USER, &unknown, sizeof (unknown) },
		{ CKA_TRUST_TIME_STAMPING, &unknown, sizeof (unknown) },
		{ CKA_TRUST_DIGITAL_SIGNATURE, &trusted, sizeof (trusted) },
		{ CKA_TRUST_NON_REPUDIATION, &trusted, sizeof (trusted) },
		{ CKA_TRUST_KEY_ENCIPHERMENT, &trusted, sizeof (trusted) },
		{ CKA_TRUST_DATA_ENCIPHERMENT, &trusted, sizeof (trusted) },
		{ CKA_TRUST_KEY_AGREEMENT, &trusted, sizeof (trusted) },
		{ CKA_TRUST_KEY_CERT_SIGN, &trusted, sizeof (trusted) },
		{ CKA_TRUST_CRL_SIGN, &trusted, sizeof (trusted) },
		{ CKA_INVALID, }
	};

	CK_ATTRIBUTE *attrs;
	CK_ATTRIBUTE *attr;
	int ret;

	setup (cu);

	ret = p11_parse_file (test.parser, SRCDIR "/files/cacert3-trusted.pem",
	                      0, on_parse_object, cu);
	CuAssertIntEquals (cu, P11_PARSE_SUCCESS, ret);

	/* Should have gotten certificate, two stapled extensions, and a trust object */
	CuAssertIntEquals (cu, 4, test.objects->num);

	attrs = test.objects->elem[0];
	test_check_cacert3_ca (cu, attrs, NULL);

	attr = p11_attrs_find (attrs, CKA_TRUSTED);
	CuAssertPtrEquals (cu, NULL, attr);

	attrs = test.objects->elem[1];
	test_check_attrs (cu, eku_extension, attrs);

	attrs = test.objects->elem[2];
	test_check_attrs (cu, reject_extension, attrs);

	attrs = test.objects->elem[3];
	test_check_attrs (cu, nss_trust, attrs);

	teardown (cu);
}

static void
test_parse_with_key_usage (CuTest *cu)
{
	CK_TRUST trusted = CKT_NETSCAPE_TRUSTED;
	CK_TRUST unknown = CKT_NETSCAPE_TRUST_UNKNOWN;
	CK_OBJECT_CLASS klass = CKO_CERTIFICATE;
	CK_OBJECT_CLASS trust_object = CKO_NETSCAPE_TRUST;
	CK_BBOOL vtrue = CK_TRUE;
	CK_BBOOL vfalse = CK_FALSE;
	CK_CERTIFICATE_TYPE x509 = CKC_X_509;
	CK_ULONG category = 0; /* TODO: Implement */

	CK_ATTRIBUTE certificate[] = {
		{ CKA_CLASS, &klass, sizeof (klass), },
		{ CKA_TOKEN, &vtrue, sizeof (vtrue) },
		{ CKA_PRIVATE, &vfalse, sizeof (vfalse) },
		{ CKA_MODIFIABLE, &vfalse, sizeof (vfalse) },
		{ CKA_CLASS, &klass, sizeof (klass) },
		{ CKA_LABEL, "self-signed-with-ku.der", 23 },
		{ CKA_CERTIFICATE_TYPE, &x509, sizeof (x509) },
		{ CKA_CERTIFICATE_CATEGORY, &category, sizeof (category) },
		{ CKA_CHECK_VALUE, "d/\x9c", 3 },
		{ CKA_START_DATE, "20121211", 8 },
		{ CKA_END_DATE, "20130110", 8, },
		{ CKA_ISSUER, "0*1(0&\x06\x03U\x04\x03\x13\x1f""self-signed-with-ku.example.com", 44 },
		{ CKA_SUBJECT, "0*1(0&\x06\x03U\x04\x03\x13\x1f""self-signed-with-ku.example.com", 44 },
		{ CKA_SERIAL_NUMBER, "\x02\x02\x03x", 4 },
		{ CKA_INVALID },
	};

	CK_ATTRIBUTE nss_trust[] = {
		{ CKA_LABEL, "self-signed-with-ku.der", 23 },
		{ CKA_CLASS, &trust_object, sizeof (trust_object), },
		{ CKA_CERT_SHA1_HASH, "d/\x9c=\xbc\x9a\x7f\x91\xc7wT\t`\x86\xe2\x8e\x8f\xa8J\x12", 20 },
		{ CKA_CERT_MD5_HASH, "\xb1N=\x16\x12?dz\x97\x81""By/\xcc\x97\x82", 16 },
		{ CKA_ISSUER, "0*1(0&\x06\x03U\x04\x03\x13\x1f""self-signed-with-ku.example.com", 44 },
		{ CKA_SUBJECT, "0*1(0&\x06\x03U\x04\x03\x13\x1f""self-signed-with-ku.example.com", 44 },
		{ CKA_SERIAL_NUMBER, "\x02\x02\x03x", 4 },
		{ CKA_TRUST_SERVER_AUTH, &trusted, sizeof (trusted) },
		{ CKA_TRUST_CLIENT_AUTH, &trusted, sizeof (trusted) },
		{ CKA_TRUST_EMAIL_PROTECTION, &trusted, sizeof (trusted) },
		{ CKA_TRUST_CODE_SIGNING, &trusted, sizeof (trusted) },
		{ CKA_TRUST_IPSEC_END_SYSTEM, &trusted, sizeof (trusted) },
		{ CKA_TRUST_IPSEC_TUNNEL, &trusted, sizeof (trusted) },
		{ CKA_TRUST_IPSEC_USER, &trusted, sizeof (trusted) },
		{ CKA_TRUST_TIME_STAMPING, &trusted, sizeof (trusted) },
		{ CKA_TRUST_DIGITAL_SIGNATURE, &trusted, sizeof (trusted) },
		{ CKA_TRUST_NON_REPUDIATION, &unknown, sizeof (unknown) },
		{ CKA_TRUST_KEY_ENCIPHERMENT, &unknown, sizeof (unknown) },
		{ CKA_TRUST_DATA_ENCIPHERMENT, &unknown, sizeof (unknown) },
		{ CKA_TRUST_KEY_AGREEMENT, &unknown, sizeof (unknown) },
		{ CKA_TRUST_KEY_CERT_SIGN, &trusted, sizeof (trusted) },
		{ CKA_TRUST_CRL_SIGN, &unknown, sizeof (unknown) },
		{ CKA_INVALID, }
	};

	CK_ATTRIBUTE *attrs;
	CK_ATTRIBUTE *attr;
	int ret;

	setup (cu);

	ret = p11_parse_file (test.parser, SRCDIR "/files/self-signed-with-ku.der",
	                      0, on_parse_object, cu);
	CuAssertIntEquals (cu, P11_PARSE_SUCCESS, ret);

	/* Should have gotten certificate, two stapled extensions, and a trust object */
	CuAssertIntEquals (cu, 2, test.objects->num);

	attrs = test.objects->elem[0];
	test_check_attrs (cu, certificate, attrs);

	attr = p11_attrs_find (attrs, CKA_TRUSTED);
	CuAssertPtrEquals (cu, NULL, attr);

	attrs = test.objects->elem[1];
	test_check_attrs (cu, nss_trust, attrs);

	teardown (cu);
}

static void
test_parse_distrusted (CuTest *cu)
{
	int ret;

	setup (cu);

	ret = p11_parse_file (test.parser, SRCDIR "/files/distrusted.pem",
	                      0, on_parse_object, cu);
	CuAssertIntEquals (cu, P11_PARSE_SUCCESS, ret);

	teardown (cu);
}

static void
test_parse_anchor (CuTest *cu)
{
	CK_ATTRIBUTE *attrs;
	CK_ATTRIBUTE *attr;
	CK_BBOOL vtrue = CK_TRUE;
	CK_ATTRIBUTE trusted = { CKA_TRUSTED, &vtrue, sizeof (vtrue) };
	int ret;

	setup (cu);

	ret = p11_parse_file (test.parser, SRCDIR "/files/cacert3.der",
	                      P11_PARSE_FLAG_ANCHOR, on_parse_object, cu);
	CuAssertIntEquals (cu, P11_PARSE_SUCCESS, ret);

	/* Should have gotten a certificate and a trust object */
	CuAssertIntEquals (cu, 2, test.objects->num);

	attrs = test.objects->elem[0];
	test_check_cacert3_ca (cu, attrs, NULL);

	attr = p11_attrs_find (attrs, CKA_TRUSTED);
	test_check_attr (cu, &trusted, attr);

	teardown (cu);
}

/* TODO: A certificate that uses generalTime needs testing */

static void
test_parse_no_sink (CuTest *cu)
{
	int ret;

	setup (cu);

	ret = p11_parse_file (test.parser, SRCDIR "/files/cacert3.der",
	                      0, NULL, NULL);
	CuAssertIntEquals (cu, P11_PARSE_SUCCESS, ret);

	teardown (cu);
}

static void
test_parse_invalid_file (CuTest *cu)
{
	int ret;

	setup (cu);

	ret = p11_parse_file (test.parser, "/nonexistant", 0, on_parse_object, cu);
	CuAssertIntEquals (cu, P11_PARSE_FAILURE, ret);

	teardown (cu);
}

static void
test_parse_unrecognized (CuTest *cu)
{
	int ret;

	setup (cu);

	ret = p11_parse_file (test.parser, SRCDIR "/files/unrecognized-file.txt",
	                      0, on_parse_object, cu);
	CuAssertIntEquals (cu, P11_PARSE_UNRECOGNIZED, ret);

	teardown (cu);
}

struct {
	const char *eku;
	size_t length;
	const unsigned char *expected[16];
} extended_key_usage_fixtures[] = {
	{ test_eku_server_and_client, sizeof (test_eku_server_and_client),
	  { P11_OID_CLIENT_AUTH, P11_OID_SERVER_AUTH, NULL }, },
	{ test_eku_none, sizeof (test_eku_none),
	  { NULL, }, },
	{ test_eku_client_email_and_timestamp, sizeof (test_eku_client_email_and_timestamp),
	  { P11_OID_CLIENT_AUTH, P11_OID_EMAIL_PROTECTION, P11_OID_TIME_STAMPING }, },
	{ NULL },
};

static void
test_parse_extended_key_usage (CuTest *cu)
{
	p11_dict *ekus;
	int i, j;

	setup (cu);

	for (i = 0; extended_key_usage_fixtures[i].eku != NULL; i++) {
		ekus = p11_parse_extended_key_usage (test.parser,
		                                     (const unsigned char *)extended_key_usage_fixtures[i].eku,
		                                     extended_key_usage_fixtures[i].length);
		CuAssertPtrNotNull (cu, ekus);

		for (j = 0; extended_key_usage_fixtures[i].expected[j] != NULL; j++)
			CuAssertTrue (cu, p11_dict_get (ekus, extended_key_usage_fixtures[i].expected[j]) != NULL);
		CuAssertIntEquals (cu, j, p11_dict_size (ekus));

		p11_dict_free (ekus);
	}

	teardown (cu);
}

static void
test_bad_extended_key_usage (CuTest *cu)
{
	p11_dict *ekus;

	setup (cu);

	ekus = p11_parse_extended_key_usage (test.parser, (const unsigned char *)"blah", 4);
	CuAssertPtrEquals (cu, NULL, ekus);

	teardown (cu);
}

struct {
	const char *ku;
	size_t length;
	unsigned int expected;
} key_usage_fixtures[] = {
	{ test_ku_ds_and_np, sizeof (test_ku_ds_and_np), P11_KU_DIGITAL_SIGNATURE | P11_KU_NON_REPUDIATION },
	{ test_ku_none, sizeof (test_ku_none), 0 },
	{ test_ku_cert_crl_sign, sizeof (test_ku_cert_crl_sign), P11_KU_KEY_CERT_SIGN | P11_KU_CRL_SIGN },
	{ NULL },
};

static void
test_parse_key_usage (CuTest *cu)
{
	unsigned int ku;
	int i;
	int ret;

	setup (cu);

	for (i = 0; key_usage_fixtures[i].ku != NULL; i++) {
		ku = 0;

		ret = p11_parse_key_usage (test.parser,
		                           (const unsigned char *)key_usage_fixtures[i].ku,
		                           key_usage_fixtures[i].length, &ku);
		CuAssertIntEquals (cu, P11_PARSE_SUCCESS, ret);

		CuAssertIntEquals (cu, key_usage_fixtures[i].expected, ku);
	}

	teardown (cu);
}

static void
test_bad_key_usage (CuTest *cu)
{
	unsigned int ku;
	int ret;

	setup (cu);

	ret = p11_parse_key_usage (test.parser, (const unsigned char *)"blah", 4, &ku);
	CuAssertIntEquals (cu, P11_PARSE_UNRECOGNIZED, ret);

	teardown (cu);
}

int
main (void)
{
	CuString *output = CuStringNew ();
	CuSuite* suite = CuSuiteNew ();
	int ret;

	setenv ("P11_KIT_STRICT", "1", 1);
	p11_debug_init ();
	p11_message_quiet ();

	SUITE_ADD_TEST (suite, test_bad_extended_key_usage);
	SUITE_ADD_TEST (suite, test_parse_extended_key_usage);
	SUITE_ADD_TEST (suite, test_bad_key_usage);
	SUITE_ADD_TEST (suite, test_parse_key_usage);
	SUITE_ADD_TEST (suite, test_parse_der_certificate);
	SUITE_ADD_TEST (suite, test_parse_pem_certificate);
	SUITE_ADD_TEST (suite, test_parse_openssl_trusted);
	SUITE_ADD_TEST (suite, test_parse_with_key_usage);
	SUITE_ADD_TEST (suite, test_parse_distrusted);
	SUITE_ADD_TEST (suite, test_parse_anchor);
	SUITE_ADD_TEST (suite, test_parse_no_sink);
	SUITE_ADD_TEST (suite, test_parse_invalid_file);
	SUITE_ADD_TEST (suite, test_parse_unrecognized);

	CuSuiteRun (suite);
	CuSuiteSummary (suite, output);
	CuSuiteDetails (suite, output);
	printf ("%s\n", output->buffer);
	ret = suite->failCount;
	CuSuiteDelete (suite);
	CuStringDelete (output);

	return ret;
}
