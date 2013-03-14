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
#include "builder.h"
#include "debug.h"
#include "library.h"
#include "oid.h"
#include "parser.h"
#include "pkcs11x.h"
#include "test-data.h"

struct {
	p11_parser *parser;
	p11_asn1_cache *cache;
	p11_index *index;
} test;

static void
setup (CuTest *cu)
{
	test.index = p11_index_new (NULL, NULL, NULL);
	test.cache = p11_asn1_cache_new ();
	test.parser = p11_parser_new (test.index, test.cache);
	CuAssertPtrNotNull (cu, test.parser);
}

static void
teardown (CuTest *cu)
{
	p11_parser_free (test.parser);
	p11_index_free (test.index);
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
parsed_attrs (CK_ATTRIBUTE *match)
{
	CK_OBJECT_HANDLE handle;
	handle = p11_index_find (test.index, certificate_match);
	return p11_index_lookup (test.index, handle);

}

static void
test_parse_der_certificate (CuTest *cu)
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

	setup (cu);

	ret = p11_parse_file (test.parser, SRCDIR "/files/cacert3.der",
	                      P11_PARSE_FLAG_NONE);
	CuAssertIntEquals (cu, P11_PARSE_SUCCESS, ret);

	/* Should have gotten certificate */
	CuAssertIntEquals (cu, 1, p11_index_size (test.index));

	cert = parsed_attrs (certificate_match);
	test_check_attrs (cu, expected, cert);

	teardown (cu);
}

static void
test_parse_pem_certificate (CuTest *cu)
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

	setup (cu);

	ret = p11_parse_file (test.parser, SRCDIR "/files/cacert3.pem",
	                      P11_PARSE_FLAG_NONE);
	CuAssertIntEquals (cu, P11_PARSE_SUCCESS, ret);

	/* Should have gotten certificate  */
	CuAssertIntEquals (cu, 1, p11_index_size (test.index));

	cert = parsed_attrs (certificate_match);
	test_check_attrs (cu, expected, cert);

	teardown (cu);
}

static void
test_parse_openssl_trusted (CuTest *cu)
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
		{ CKA_X_CRITICAL, &truev, sizeof (truev) },
		{ CKA_VALUE, "\x30\x14\x06\x08\x2b\x06\x01\x05\x05\x07\x03\x01\x06\x08\x2b\x06"
			"\x01\x05\x05\x07\x03\x02", 22 },
		{ CKA_INVALID },
	};

	CK_ATTRIBUTE reject_extension[] = {
		{ CKA_CLASS, &certificate_extension, sizeof (certificate_extension), },
		{ CKA_OBJECT_ID, (void *)P11_OID_OPENSSL_REJECT, sizeof (P11_OID_OPENSSL_REJECT) },
		{ CKA_X_CRITICAL, &falsev, sizeof (falsev) },
		{ CKA_VALUE, "\x30\x0a\x06\x08\x2b\x06\x01\x05\x05\x07\x03\x04", 12 },
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
	CK_OBJECT_HANDLE handle;
	int ret;
	int i;

	setup (cu);

	ret = p11_parse_file (test.parser, SRCDIR "/files/cacert3-trusted.pem",
	                      P11_PARSE_FLAG_ANCHOR);
	CuAssertIntEquals (cu, P11_PARSE_SUCCESS, ret);

	/*
	 * Should have gotten:
	 * - 1 certificate
	 * - 2 stapled extensions
	 */
	CuAssertIntEquals (cu, 3, p11_index_size (test.index));

	/* The certificate */
	cert = parsed_attrs (certificate_match);
	test_check_attrs (cu, expected[0], cert);

	/* The other objects */
	for (i = 1; expected[i]; i++) {
		handle = p11_index_findn (test.index, expected[i], 2);
		CuAssertTrue (cu, handle != 0);

		object = p11_index_lookup (test.index, handle);
		CuAssertPtrNotNull (cu, object);

		test_check_attrs (cu, expected[i], object);
		test_check_id (cu, cert, object);
	}

	teardown (cu);
}

static void
test_parse_openssl_distrusted (CuTest *cu)
{
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
		{ CKA_X_CRITICAL, &truev, sizeof (truev) },
		{ CKA_VALUE, "\x30\x0c\x06\x0a\x2b\x06\x01\x04\x01\x99\x77\x06\x0a\x10", 14 },
		{ CKA_INVALID },
	};

	CK_ATTRIBUTE reject_extension[] = {
		{ CKA_CLASS, &certificate_extension, sizeof (certificate_extension), },
		{ CKA_OBJECT_ID, (void *)P11_OID_OPENSSL_REJECT, sizeof (P11_OID_OPENSSL_REJECT) },
		{ CKA_X_CRITICAL, &falsev, sizeof (falsev) },
		{ CKA_VALUE, "\x30\x0a\x06\x08\x2b\x06\x01\x05\x05\x07\x03\x02", 12 },
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
	CK_OBJECT_HANDLE handle;
	int ret;
	int i;

	setup (cu);

	/*
	 * OpenSSL style is to litter the blacklist in with the anchors,
	 * so we parse this as an anchor, but expect it to be blacklisted
	 */
	ret = p11_parse_file (test.parser, SRCDIR "/files/distrusted.pem",
	                      P11_PARSE_FLAG_ANCHOR);
	CuAssertIntEquals (cu, P11_PARSE_SUCCESS, ret);

	/*
	 * Should have gotten:
	 * - 1 certificate
	 * - 2 stapled extensions
	 */
	CuAssertIntEquals (cu, 3, p11_index_size (test.index));
	cert = parsed_attrs (certificate_match);
	test_check_attrs (cu, expected[0], cert);

	/* The other objects */
	for (i = 1; expected[i]; i++) {
		handle = p11_index_findn (test.index, expected[i], 2);
		CuAssertTrue (cu, handle != 0);

		object = p11_index_lookup (test.index, handle);
		CuAssertPtrNotNull (cu, object);

		test_check_attrs (cu, expected[i], object);
		test_check_id (cu, cert, object);
	}

	teardown (cu);
}

static void
test_parse_anchor (CuTest *cu)
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

	setup (cu);

	ret = p11_parse_file (test.parser, SRCDIR "/files/cacert3.der",
	                      P11_PARSE_FLAG_ANCHOR);
	CuAssertIntEquals (cu, P11_PARSE_SUCCESS, ret);

	/*
	 * Should have gotten:
	 * - 1 certificate
	 */
	CuAssertIntEquals (cu, 1, p11_index_size (test.index));

	cert = parsed_attrs (certificate_match);
	test_check_attrs (cu, cacert3, cert);

	teardown (cu);
}

/* TODO: A certificate that uses generalTime needs testing */

static void
test_parse_invalid_file (CuTest *cu)
{
	int ret;

	setup (cu);

	p11_message_quiet ();

	ret = p11_parse_file (test.parser, "/nonexistant",
	                      P11_PARSE_FLAG_NONE);
	CuAssertIntEquals (cu, P11_PARSE_FAILURE, ret);

	p11_message_loud ();

	teardown (cu);
}

static void
test_parse_unrecognized (CuTest *cu)
{
	int ret;

	setup (cu);

	p11_message_quiet ();

	ret = p11_parse_file (test.parser, SRCDIR "/files/unrecognized-file.txt",
	                      P11_PARSE_FLAG_NONE);
	CuAssertIntEquals (cu, P11_PARSE_UNRECOGNIZED, ret);

	p11_message_loud ();

	teardown (cu);
}

int
main (void)
{
	CuString *output = CuStringNew ();
	CuSuite* suite = CuSuiteNew ();
	int ret;

	putenv ("P11_KIT_STRICT=1");
	p11_library_init ();
	p11_debug_init ();

	SUITE_ADD_TEST (suite, test_parse_der_certificate);
	SUITE_ADD_TEST (suite, test_parse_pem_certificate);
	SUITE_ADD_TEST (suite, test_parse_openssl_trusted);
	SUITE_ADD_TEST (suite, test_parse_openssl_distrusted);
	SUITE_ADD_TEST (suite, test_parse_anchor);
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
