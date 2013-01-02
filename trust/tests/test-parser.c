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

	CK_ATTRIBUTE expected[] = {
		{ CKA_LABEL, "Custom Label", 12 },
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
		{ CKA_INVALID, }
	};

	CK_ATTRIBUTE *attrs;
	CK_ATTRIBUTE *attr;
	int ret;

	setup (cu);

	ret = p11_parse_file (test.parser, SRCDIR "/files/cacert3-trusted.pem",
	                      0, on_parse_object, cu);
	CuAssertIntEquals (cu, P11_PARSE_SUCCESS, ret);

	/* Should have gotten certificate and a trust object */
	CuAssertIntEquals (cu, 2, test.objects->num);

	attrs = test.objects->elem[0];
	test_check_cacert3_ca (cu, attrs, NULL);

	attr = p11_attrs_find (attrs, CKA_TRUSTED);
	CuAssertPtrEquals (cu, NULL, attr);

	attrs = test.objects->elem[1];
	test_check_attrs (cu, expected, attrs);

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
	const char *expected[16];
} extended_key_usage_fixtures[] = {
	{ test_eku_server_and_client, sizeof (test_eku_server_and_client),
	  { P11_EKU_CLIENT_AUTH, P11_EKU_SERVER_AUTH, NULL }, },
	{ test_eku_none, sizeof (test_eku_none),
	  { NULL, }, },
	{ test_eku_client_email_and_timestamp, sizeof (test_eku_client_email_and_timestamp),
	  { P11_EKU_CLIENT_AUTH, P11_EKU_EMAIL, P11_EKU_TIME_STAMPING }, },
	{ NULL },
};

static void
test_parse_extended_key_usage (CuTest *cu)
{
	p11_dict *ekus;
	int i, j;
	int ret;

	setup (cu);

	for (i = 0; extended_key_usage_fixtures[i].eku != NULL; i++) {
		ekus = p11_dict_new (p11_dict_str_hash, p11_dict_str_equal, free, NULL);

		ret = p11_parse_extended_key_usage (test.parser,
		                                    (const unsigned char *)extended_key_usage_fixtures[i].eku,
		                                    extended_key_usage_fixtures[i].length, ekus);
		CuAssertIntEquals (cu, P11_PARSE_SUCCESS, ret);

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
	int ret;

	setup (cu);

	ekus = p11_dict_new (p11_dict_str_hash, p11_dict_str_equal, free, NULL);

	ret = p11_parse_extended_key_usage (test.parser, (const unsigned char *)"blah", 4, ekus);
	CuAssertIntEquals (cu, P11_PARSE_UNRECOGNIZED, ret);

	p11_dict_free (ekus);

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

	SUITE_ADD_TEST (suite, test_parse_der_certificate);
	SUITE_ADD_TEST (suite, test_parse_pem_certificate);
	SUITE_ADD_TEST (suite, test_parse_openssl_trusted);
	SUITE_ADD_TEST (suite, test_parse_distrusted);
	SUITE_ADD_TEST (suite, test_parse_anchor);
	SUITE_ADD_TEST (suite, test_parse_no_sink);
	SUITE_ADD_TEST (suite, test_parse_invalid_file);
	SUITE_ADD_TEST (suite, test_parse_unrecognized);
	SUITE_ADD_TEST (suite, test_bad_extended_key_usage);
	SUITE_ADD_TEST (suite, test_parse_extended_key_usage);
	SUITE_ADD_TEST (suite, test_bad_key_usage);
	SUITE_ADD_TEST (suite, test_parse_key_usage);

	CuSuiteRun (suite);
	CuSuiteSummary (suite, output);
	CuSuiteDetails (suite, output);
	printf ("%s\n", output->buffer);
	ret = suite->failCount;
	CuSuiteDelete (suite);
	CuStringDelete (output);

	return ret;
}
