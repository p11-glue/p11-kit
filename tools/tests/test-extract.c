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

#include "attrs.h"
#include "compat.h"
#include "debug.h"
#include "dict.h"
#include "extract.h"
#include "library.h"
#include "mock.h"
#include "pkcs11.h"
#include "pkcs11x.h"
#include "oid.h"
#include "test.h"

#include <stdlib.h>
#include <string.h>

static void
test_file_name_for_label (CuTest *tc)
{
	CK_ATTRIBUTE label = { CKA_LABEL, "The Label!", 10 };
	p11_extract_info ex;
	char *name;

	p11_extract_info_init (&ex);

	ex.attrs = p11_attrs_build (NULL, &label, NULL);

	name = p11_extract_info_filename (&ex);
	CuAssertStrEquals (tc, "The_Label_", name);
	free (name);

	p11_extract_info_cleanup (&ex);
}

static void
test_file_name_for_class (CuTest *tc)
{
	p11_extract_info ex;
	char *name;

	p11_extract_info_init (&ex);

	ex.klass = CKO_CERTIFICATE;

	name = p11_extract_info_filename (&ex);
	CuAssertStrEquals (tc, "certificate", name);
	free (name);

	ex.klass = CKO_DATA;

	name = p11_extract_info_filename (&ex);
	CuAssertStrEquals (tc, "unknown", name);
	free (name);

	p11_extract_info_cleanup (&ex);
}

struct {
	CK_FUNCTION_LIST module;
	P11KitIter *iter;
	p11_extract_info ex;
} test;

static void
setup (CuTest *tc)
{
	CK_RV rv;

	memcpy (&test.module, &mock_module, sizeof (CK_FUNCTION_LIST));

	rv = p11_kit_initialize_module (&test.module);
	CuAssertIntEquals (tc, CKR_OK, rv);

	test.iter = p11_kit_iter_new (NULL);

	p11_extract_info_init (&test.ex);
}

static void
teardown (CuTest *tc)
{
	CK_RV rv;

	p11_extract_info_cleanup (&test.ex);

	p11_kit_iter_free (test.iter);

	rv = p11_kit_finalize_module (&test.module);
	CuAssertIntEquals (tc, CKR_OK, rv);
}

static CK_OBJECT_CLASS certificate_class = CKO_CERTIFICATE;
static CK_OBJECT_CLASS extension_class = CKO_X_CERTIFICATE_EXTENSION;
static CK_CERTIFICATE_TYPE x509_type = CKC_X_509;

static CK_ATTRIBUTE cacert3_authority_attrs[] = {
	{ CKA_VALUE, (void *)test_cacert3_ca_der, sizeof (test_cacert3_ca_der) },
	{ CKA_CLASS, &certificate_class, sizeof (certificate_class) },
	{ CKA_CERTIFICATE_TYPE, &x509_type, sizeof (x509_type) },
	{ CKA_LABEL, "Cacert3 Here", 11 },
	{ CKA_SUBJECT, (void *)test_cacert3_ca_subject, sizeof (test_cacert3_ca_subject) },
	{ CKA_ID, "ID1", 3 },
	{ CKA_INVALID },
};

static CK_ATTRIBUTE certificate_filter[] = {
	{ CKA_CLASS, &certificate_class, sizeof (certificate_class) },
	{ CKA_INVALID },
};

static CK_ATTRIBUTE extension_eku_server_client[] = {
	{ CKA_CLASS, &extension_class, sizeof (extension_class) },
	{ CKA_ID, "ID1", 3 },
	{ CKA_OBJECT_ID, (void *)P11_OID_EXTENDED_KEY_USAGE, sizeof (P11_OID_EXTENDED_KEY_USAGE) },
	{ CKA_VALUE, (void *)test_eku_server_and_client, sizeof (test_eku_server_and_client) },
	{ CKA_INVALID },
};

static CK_ATTRIBUTE extension_eku_invalid[] = {
	{ CKA_CLASS, &extension_class, sizeof (extension_class) },
	{ CKA_ID, "ID1", 3 },
	{ CKA_OBJECT_ID, (void *)P11_OID_EXTENDED_KEY_USAGE, sizeof (P11_OID_EXTENDED_KEY_USAGE) },
	{ CKA_VALUE, "invalid", 7 },
	{ CKA_INVALID },
};

static void
test_info_simple_certificate (CuTest *tc)
{
	CK_ATTRIBUTE *value;
	CK_RV rv;

	setup (tc);

	CuAssertPtrNotNull (tc, test.ex.asn1_defs);

	mock_module_add_object (MOCK_SLOT_ONE_ID, cacert3_authority_attrs);
	mock_module_add_object (MOCK_SLOT_ONE_ID, extension_eku_server_client);

	p11_kit_iter_add_callback (test.iter, p11_extract_info_load_filter, &test.ex, NULL);
	p11_kit_iter_add_filter (test.iter, certificate_filter, 1);
	p11_kit_iter_begin_with (test.iter, &test.module, 0, 0);

	rv = p11_kit_iter_next (test.iter);
	CuAssertIntEquals (tc, CKR_OK, rv);

	CuAssertIntEquals (tc, CKO_CERTIFICATE, test.ex.klass);
	CuAssertPtrNotNull (tc, test.ex.attrs);
	value = p11_attrs_find_valid (test.ex.attrs, CKA_VALUE);
	CuAssertPtrNotNull (tc, value);
	CuAssertTrue (tc, memcmp (value->pValue, test_cacert3_ca_der, value->ulValueLen) == 0);
	CuAssertPtrNotNull (tc, test.ex.cert_der);
	CuAssertTrue (tc, memcmp (test.ex.cert_der, test_cacert3_ca_der, test.ex.cert_len) == 0);
	CuAssertPtrNotNull (tc, test.ex.cert_asn);

	rv = p11_kit_iter_next (test.iter);
	CuAssertIntEquals (tc, CKR_CANCEL, rv);

	teardown (tc);
}

static void
test_info_limit_purposes (CuTest *tc)
{
	CK_RV rv;

	setup (tc);

	mock_module_add_object (MOCK_SLOT_ONE_ID, cacert3_authority_attrs);
	mock_module_add_object (MOCK_SLOT_ONE_ID, extension_eku_server_client);

	/* This should not match the above, with the stapled certificat ext */
	CuAssertPtrEquals (tc, NULL, test.ex.limit_to_purposes);
	p11_extract_info_limit_purpose (&test.ex, "1.1.1");
	CuAssertPtrNotNull (tc, test.ex.limit_to_purposes);

	p11_kit_iter_add_callback (test.iter, p11_extract_info_load_filter, &test.ex, NULL);
	p11_kit_iter_add_filter (test.iter, certificate_filter, 1);
	p11_kit_iter_begin_with (test.iter, &test.module, 0, 0);

	rv = p11_kit_iter_next (test.iter);
	CuAssertIntEquals (tc, CKR_CANCEL, rv);

	teardown (tc);
}

static void
test_info_invalid_purposes (CuTest *tc)
{
	CK_RV rv;

	setup (tc);

	mock_module_add_object (MOCK_SLOT_ONE_ID, cacert3_authority_attrs);
	mock_module_add_object (MOCK_SLOT_ONE_ID, extension_eku_invalid);

	p11_kit_iter_add_callback (test.iter, p11_extract_info_load_filter, &test.ex, NULL);
	p11_kit_iter_add_filter (test.iter, certificate_filter, 1);
	p11_kit_iter_begin_with (test.iter, &test.module, 0, 0);

	p11_kit_be_quiet ();

	/* No results due to invalid purpose on certificate */
	rv = p11_kit_iter_next (test.iter);
	CuAssertIntEquals (tc, CKR_CANCEL, rv);

	p11_kit_be_loud ();

	teardown (tc);
}

static void
test_info_skip_non_certificate (CuTest *tc)
{
	CK_RV rv;

	setup (tc);

	mock_module_add_object (MOCK_SLOT_ONE_ID, cacert3_authority_attrs);

	p11_kit_iter_add_callback (test.iter, p11_extract_info_load_filter, &test.ex, NULL);
	p11_kit_iter_begin_with (test.iter, &test.module, 0, 0);

	p11_message_quiet ();

	rv = p11_kit_iter_next (test.iter);
	CuAssertIntEquals (tc, CKR_OK, rv);

	CuAssertIntEquals (tc, CKO_CERTIFICATE, test.ex.klass);

	rv = p11_kit_iter_next (test.iter);
	CuAssertIntEquals (tc, CKR_CANCEL, rv);

	p11_message_loud ();

	teardown (tc);
}

int
main (void)
{
	CuString *output = CuStringNew ();
	CuSuite* suite = CuSuiteNew ();
	int ret;

	putenv ("P11_KIT_STRICT=1");
	p11_library_init ();
	mock_module_init ();
	p11_debug_init ();

	SUITE_ADD_TEST (suite, test_file_name_for_label);
	SUITE_ADD_TEST (suite, test_file_name_for_class);
	SUITE_ADD_TEST (suite, test_info_simple_certificate);
	SUITE_ADD_TEST (suite, test_info_limit_purposes);
	SUITE_ADD_TEST (suite, test_info_invalid_purposes);
	SUITE_ADD_TEST (suite, test_info_skip_non_certificate);

	CuSuiteRun (suite);
	CuSuiteSummary (suite, output);
	CuSuiteDetails (suite, output);
	printf ("%s\n", output->buffer);
	ret = suite->failCount;
	CuSuiteDelete (suite);
	CuStringDelete (output);

	return ret;
}
