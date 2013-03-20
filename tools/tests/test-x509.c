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

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct {
	CK_FUNCTION_LIST module;
	P11KitIter *iter;
	p11_extract_info ex;
	char *directory;
} test;

static void
setup (CuTest *tc)
{
	CK_RV rv;

	memcpy (&test.module, &mock_module, sizeof (CK_FUNCTION_LIST));
	rv = p11_kit_initialize_module (&test.module);
	CuAssertIntEquals (tc, CKR_OK, rv);

	mock_module_reset_objects (MOCK_SLOT_ONE_ID);

	test.iter = p11_kit_iter_new (NULL);

	p11_extract_info_init (&test.ex);

	test.directory = strdup ("/tmp/test-extract.XXXXXX");
	if (!mkdtemp (test.directory))
		CuFail (tc, "mkdtemp() failed");
}

static void
teardown (CuTest *tc)
{
	CK_RV rv;

	if (rmdir (test.directory) < 0)
		CuFail (tc, "rmdir() failed");
	free (test.directory);

	p11_extract_info_cleanup (&test.ex);
	p11_kit_iter_free (test.iter);

	rv = p11_kit_finalize_module (&test.module);
	CuAssertIntEquals (tc, CKR_OK, rv);
}

static CK_OBJECT_CLASS certificate_class = CKO_CERTIFICATE;
static CK_CERTIFICATE_TYPE x509_type = CKC_X_509;

static CK_ATTRIBUTE cacert3_authority_attrs[] = {
	{ CKA_VALUE, (void *)test_cacert3_ca_der, sizeof (test_cacert3_ca_der) },
	{ CKA_CLASS, &certificate_class, sizeof (certificate_class) },
	{ CKA_CERTIFICATE_TYPE, &x509_type, sizeof (x509_type) },
	{ CKA_LABEL, "Cacert3 Here", 12 },
	{ CKA_SUBJECT, (void *)test_cacert3_ca_subject, sizeof (test_cacert3_ca_subject) },
	{ CKA_ID, "ID1", 3 },
	{ CKA_INVALID },
};

static CK_ATTRIBUTE certificate_filter[] = {
	{ CKA_CLASS, &certificate_class, sizeof (certificate_class) },
	{ CKA_INVALID },
};

static void
test_file (CuTest *tc)
{
	bool ret;

	setup (tc);

	mock_module_add_object (MOCK_SLOT_ONE_ID, cacert3_authority_attrs);

	p11_kit_iter_add_callback (test.iter, p11_extract_info_load_filter, &test.ex, NULL);
	p11_kit_iter_add_filter (test.iter, certificate_filter, 1);
	p11_kit_iter_begin_with (test.iter, &test.module, 0, 0);

	if (asprintf (&test.ex.destination, "%s/%s", test.directory, "extract.cer") < 0)
		assert_not_reached ();

	ret = p11_extract_x509_file (test.iter, &test.ex);
	CuAssertIntEquals (tc, true, ret);

	test_check_file (tc, test.directory, "extract.cer", SRCDIR "/files/cacert3.der");

	free (test.ex.destination);
	teardown (tc);
}

static void
test_file_multiple (CuTest *tc)
{
	bool ret;

	setup (tc);

	mock_module_add_object (MOCK_SLOT_ONE_ID, cacert3_authority_attrs);
	mock_module_add_object (MOCK_SLOT_ONE_ID, cacert3_authority_attrs);

	p11_kit_iter_add_callback (test.iter, p11_extract_info_load_filter, &test.ex, NULL);
	p11_kit_iter_add_filter (test.iter, certificate_filter, 1);
	p11_kit_iter_begin_with (test.iter, &test.module, 0, 0);

	if (asprintf (&test.ex.destination, "%s/%s", test.directory, "extract.cer") < 0)
		assert_not_reached ();

	p11_message_quiet ();

	ret = p11_extract_x509_file (test.iter, &test.ex);
	CuAssertIntEquals (tc, true, ret);

	CuAssertTrue (tc, strstr (p11_message_last (), "multiple certificates") != NULL);

	p11_message_loud ();

	test_check_file (tc, test.directory, "extract.cer", SRCDIR "/files/cacert3.der");

	free (test.ex.destination);
	teardown (tc);
}

static void
test_file_without (CuTest *tc)
{
	bool ret;

	setup (tc);

	p11_kit_iter_add_callback (test.iter, p11_extract_info_load_filter, &test.ex, NULL);
	p11_kit_iter_add_filter (test.iter, certificate_filter, 1);
	p11_kit_iter_begin_with (test.iter, &test.module, 0, 0);

	if (asprintf (&test.ex.destination, "%s/%s", test.directory, "extract.cer") < 0)
		assert_not_reached ();

	p11_message_quiet ();

	ret = p11_extract_x509_file (test.iter, &test.ex);
	CuAssertIntEquals (tc, false, ret);

	CuAssertTrue (tc, strstr (p11_message_last (), "no certificate") != NULL);

	p11_message_loud ();

	free (test.ex.destination);
	teardown (tc);
}

static void
test_directory (CuTest *tc)
{
	bool ret;

	setup (tc);

	mock_module_add_object (MOCK_SLOT_ONE_ID, cacert3_authority_attrs);
	mock_module_add_object (MOCK_SLOT_ONE_ID, cacert3_authority_attrs);

	p11_kit_iter_add_callback (test.iter, p11_extract_info_load_filter, &test.ex, NULL);
	p11_kit_iter_add_filter (test.iter, certificate_filter, 1);
	p11_kit_iter_begin_with (test.iter, &test.module, 0, 0);

	/* Yes, this is a race, and why you shouldn't build software as root */
	if (rmdir (test.directory) < 0)
		assert_not_reached ();
	test.ex.destination = test.directory;

	ret = p11_extract_x509_directory (test.iter, &test.ex);
	CuAssertIntEquals (tc, true, ret);

	test_check_directory (tc, test.directory, ("Cacert3_Here.cer", "Cacert3_Here.1.cer", NULL));
	test_check_file (tc, test.directory, "Cacert3_Here.cer", SRCDIR "/files/cacert3.der");
	test_check_file (tc, test.directory, "Cacert3_Here.1.cer", SRCDIR "/files/cacert3.der");

	teardown (tc);
}

static void
test_directory_empty (CuTest *tc)
{
	bool ret;

	setup (tc);

	p11_kit_iter_add_callback (test.iter, p11_extract_info_load_filter, &test.ex, NULL);
	p11_kit_iter_add_filter (test.iter, certificate_filter, 1);
	p11_kit_iter_begin_with (test.iter, &test.module, 0, 0);

	/* Yes, this is a race, and why you shouldn't build software as root */
	if (rmdir (test.directory) < 0)
		assert_not_reached ();
	test.ex.destination = test.directory;

	ret = p11_extract_x509_directory (test.iter, &test.ex);
	CuAssertIntEquals (tc, true, ret);

	test_check_directory (tc, test.directory, (NULL, NULL));

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

	SUITE_ADD_TEST (suite, test_file);
	SUITE_ADD_TEST (suite, test_file_multiple);
	SUITE_ADD_TEST (suite, test_file_without);
	SUITE_ADD_TEST (suite, test_directory);
	SUITE_ADD_TEST (suite, test_directory_empty);

	CuSuiteRun (suite);
	CuSuiteSummary (suite, output);
	CuSuiteDetails (suite, output);
	printf ("%s\n", output->buffer);
	ret = suite->failCount;
	CuSuiteDelete (suite);
	CuStringDelete (output);

	return ret;
}
