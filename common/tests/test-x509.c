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

#include "asn1.h"
#include "debug.h"
#include "oid.h"
#include "x509.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

struct {
	p11_dict *asn1_defs;
} test;

static void
setup (CuTest *cu)
{
	test.asn1_defs = p11_asn1_defs_load ();
	CuAssertPtrNotNull (cu, test.asn1_defs);
}

static void
teardown (CuTest *cu)
{
	p11_dict_free (test.asn1_defs);
	memset (&test, 0, sizeof (test));
}

static const char test_ku_ds_and_np[] = {
	0x03, 0x03, 0x07, 0xc0, 0x00,
};

static const char test_ku_none[] = {
	0x03, 0x03, 0x07, 0x00, 0x00,
};

static const char test_ku_cert_crl_sign[] = {
	0x03, 0x03, 0x07, 0x06, 0x00,
};

static const char test_eku_server_and_client[] = {
	0x30, 0x14, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01, 0x06, 0x08, 0x2b, 0x06,
	0x01, 0x05, 0x05, 0x07, 0x03, 0x02,
};

static const char test_eku_none[] = {
	0x30, 0x00,
};

static const char test_eku_client_email_and_timestamp[] = {
	0x30, 0x1e, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02, 0x06, 0x08, 0x2b, 0x06,
	0x01, 0x05, 0x05, 0x07, 0x03, 0x04, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x08,
};

struct {
	const char *eku;
	size_t length;
	const char *expected[16];
} extended_key_usage_fixtures[] = {
	{ test_eku_server_and_client, sizeof (test_eku_server_and_client),
	  { P11_OID_CLIENT_AUTH_STR, P11_OID_SERVER_AUTH_STR, NULL }, },
	{ test_eku_none, sizeof (test_eku_none),
	  { NULL, }, },
	{ test_eku_client_email_and_timestamp, sizeof (test_eku_client_email_and_timestamp),
	  { P11_OID_CLIENT_AUTH_STR, P11_OID_EMAIL_PROTECTION_STR, P11_OID_TIME_STAMPING_STR }, },
	{ NULL },
};

static void
test_parse_extended_key_usage (CuTest *cu)
{
	p11_dict *ekus;
	int i, j;

	setup (cu);

	for (i = 0; extended_key_usage_fixtures[i].eku != NULL; i++) {
		ekus = p11_x509_parse_extended_key_usage (test.asn1_defs,
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
	bool ret;

	setup (cu);

	for (i = 0; key_usage_fixtures[i].ku != NULL; i++) {
		ku = 0;

		ret = p11_x509_parse_key_usage (test.asn1_defs,
		                                (const unsigned char *)key_usage_fixtures[i].ku,
		                                key_usage_fixtures[i].length, &ku);
		CuAssertIntEquals (cu, true, ret);

		CuAssertIntEquals (cu, key_usage_fixtures[i].expected, ku);
	}

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

	SUITE_ADD_TEST (suite, test_parse_extended_key_usage);
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
