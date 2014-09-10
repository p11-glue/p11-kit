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

#define P11_KIT_DISABLE_DEPRECATED

#include "config.h"

#include "test-trust.h"

#include "attrs.h"
#include "compat.h"
#include "debug.h"
#include "dict.h"
#include "extract.h"
#include "message.h"
#include "mock.h"
#include "pkcs11.h"
#include "pkcs11x.h"
#include "oid.h"
#include "test.h"

#include <stdlib.h>
#include <string.h>


static void
test_file_name_for_label (void)
{
	CK_ATTRIBUTE label = { CKA_LABEL, "The Label!", 10 };
	p11_enumerate ex;
	char *name;

	p11_enumerate_init (&ex);

	ex.attrs = p11_attrs_build (NULL, &label, NULL);

	name = p11_enumerate_filename (&ex);
	assert_str_eq ("The_Label_", name);
	free (name);

	p11_enumerate_cleanup (&ex);
}

static void
test_file_name_for_class (void)
{
	p11_enumerate ex;
	char *name;

	p11_enumerate_init (&ex);

	ex.klass = CKO_CERTIFICATE;

	name = p11_enumerate_filename (&ex);
	assert_str_eq ("certificate", name);
	free (name);

	ex.klass = CKO_DATA;

	name = p11_enumerate_filename (&ex);
	assert_str_eq ("unknown", name);
	free (name);

	p11_enumerate_cleanup (&ex);
}

static void
test_comment_for_label (void)
{
	CK_ATTRIBUTE label = { CKA_LABEL, "The Label!", 10 };
	p11_enumerate ex;
	char *comment;

	p11_enumerate_init (&ex);

	ex.flags = P11_EXTRACT_COMMENT;
	ex.attrs = p11_attrs_build (NULL, &label, NULL);

	comment = p11_enumerate_comment (&ex, true);
	assert_str_eq ("# The Label!\n", comment);
	free (comment);

	comment = p11_enumerate_comment (&ex, false);
	assert_str_eq ("\n# The Label!\n", comment);
	free (comment);

	p11_enumerate_cleanup (&ex);
}

static void
test_comment_not_enabled (void)
{
	CK_ATTRIBUTE label = { CKA_LABEL, "The Label!", 10 };
	p11_enumerate ex;
	char *comment;

	p11_enumerate_init (&ex);

	ex.attrs = p11_attrs_build (NULL, &label, NULL);

	comment = p11_enumerate_comment (&ex, true);
	assert_ptr_eq (NULL, comment);

	comment = p11_enumerate_comment (&ex, false);
	assert_ptr_eq (NULL, comment);

	p11_enumerate_cleanup (&ex);
}

struct {
	CK_FUNCTION_LIST module;
	CK_FUNCTION_LIST_PTR modules[2];
	p11_enumerate ex;
} test;

static void
setup (void *unused)
{
	CK_RV rv;

	mock_module_reset ();
	memcpy (&test.module, &mock_module, sizeof (CK_FUNCTION_LIST));

	rv = test.module.C_Initialize (NULL);
	assert_num_eq (CKR_OK, rv);

	p11_enumerate_init (&test.ex);

	/* Prefill the modules */
	test.modules[0] = &test.module;
	test.modules[1] = NULL;
	test.ex.modules = test.modules;
}

static void
teardown (void *unused)
{
	CK_RV rv;

	/* Don't free the modules */
	test.ex.modules = NULL;

	p11_enumerate_cleanup (&test.ex);

	rv = test.module.C_Finalize (NULL);
	assert_num_eq (CKR_OK, rv);
}

static CK_OBJECT_CLASS certificate_class = CKO_CERTIFICATE;
static CK_OBJECT_CLASS public_key_class = CKO_PUBLIC_KEY;
static CK_OBJECT_CLASS extension_class = CKO_X_CERTIFICATE_EXTENSION;
static CK_CERTIFICATE_TYPE x509_type = CKC_X_509;
static CK_BBOOL truev = CK_TRUE;

static CK_ATTRIBUTE cacert3_trusted[] = {
	{ CKA_VALUE, (void *)test_cacert3_ca_der, sizeof (test_cacert3_ca_der) },
	{ CKA_CLASS, &certificate_class, sizeof (certificate_class) },
	{ CKA_CERTIFICATE_TYPE, &x509_type, sizeof (x509_type) },
	{ CKA_LABEL, "Cacert3 Here", 11 },
	{ CKA_SUBJECT, (void *)test_cacert3_ca_subject, sizeof (test_cacert3_ca_subject) },
	{ CKA_ISSUER, (void *)test_cacert3_ca_issuer, sizeof (test_cacert3_ca_issuer) },
	{ CKA_SERIAL_NUMBER, (void *)test_cacert3_ca_serial, sizeof (test_cacert3_ca_serial) },
	{ CKA_PUBLIC_KEY_INFO, (void *)test_cacert3_ca_public_key, sizeof (test_cacert3_ca_public_key) },
	{ CKA_TRUSTED, &truev, sizeof (truev) },
	{ CKA_ID, "ID1", 3 },
	{ CKA_INVALID },
};

static CK_ATTRIBUTE cacert3_distrusted[] = {
	{ CKA_VALUE, (void *)test_cacert3_ca_der, sizeof (test_cacert3_ca_der) },
	{ CKA_CLASS, &certificate_class, sizeof (certificate_class) },
	{ CKA_CERTIFICATE_TYPE, &x509_type, sizeof (x509_type) },
	{ CKA_LABEL, "Another CaCert", 11 },
	{ CKA_SUBJECT, (void *)test_cacert3_ca_subject, sizeof (test_cacert3_ca_subject) },
	{ CKA_ISSUER, (void *)test_cacert3_ca_issuer, sizeof (test_cacert3_ca_issuer) },
	{ CKA_SERIAL_NUMBER, (void *)test_cacert3_ca_serial, sizeof (test_cacert3_ca_serial) },
	{ CKA_X_DISTRUSTED, &truev, sizeof (truev) },
	{ CKA_INVALID },
};

static CK_ATTRIBUTE cacert3_distrusted_by_key[] = {
	{ CKA_CLASS, &public_key_class, sizeof (public_key_class) },
	{ CKA_PUBLIC_KEY_INFO, (void *)test_cacert3_ca_public_key, sizeof (test_cacert3_ca_public_key) },
	{ CKA_X_DISTRUSTED, &truev, sizeof (truev) },
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
	{ CKA_VALUE, "\x30\x1d\x06\x03\x55\x1d\x25\x04\x16\x30\x14\x06\x08\x2b\x06\x01\x05\x05\x07\x03\x01\x06\x08\x2b\x06\x01\x05\x05\x07\x03\x02", 31 },
	{ CKA_PUBLIC_KEY_INFO, (void *)test_cacert3_ca_public_key, sizeof (test_cacert3_ca_public_key) },
	{ CKA_INVALID },
};

static CK_ATTRIBUTE extension_eku_invalid[] = {
	{ CKA_CLASS, &extension_class, sizeof (extension_class) },
	{ CKA_ID, "ID1", 3 },
	{ CKA_OBJECT_ID, (void *)P11_OID_EXTENDED_KEY_USAGE, sizeof (P11_OID_EXTENDED_KEY_USAGE) },
	{ CKA_PUBLIC_KEY_INFO, (void *)test_cacert3_ca_public_key, sizeof (test_cacert3_ca_public_key) },
	{ CKA_VALUE, "\x30\x0e\x06\x03\x55\x1d\x25\x04\x07\x69\x6e\x76\x61\x6c\x69\x64", 16 },
	{ CKA_INVALID },
};

static void
test_info_simple_certificate (void)
{
	void *value;
	size_t length;
	CK_RV rv;

	assert_ptr_not_null (test.ex.asn1_defs);

	mock_module_add_object (MOCK_SLOT_ONE_ID, cacert3_trusted);
	mock_module_add_object (MOCK_SLOT_ONE_ID, extension_eku_server_client);

	p11_kit_iter_add_filter (test.ex.iter, certificate_filter, 1);
	p11_enumerate_ready (&test.ex, NULL);

	rv = p11_kit_iter_next (test.ex.iter);
	assert_num_eq (CKR_OK, rv);

	assert_num_eq (CKO_CERTIFICATE, test.ex.klass);
	assert_ptr_not_null (test.ex.attrs);
	value = p11_attrs_find_value (test.ex.attrs, CKA_VALUE, &length);
	assert_ptr_not_null (value);
	assert (memcmp (value, test_cacert3_ca_der, length) == 0);
	assert_ptr_not_null (test.ex.cert_der);
	assert (memcmp (test.ex.cert_der, test_cacert3_ca_der, test.ex.cert_len) == 0);
	assert_ptr_not_null (test.ex.cert_asn);

	rv = p11_kit_iter_next (test.ex.iter);
	assert_num_eq (CKR_CANCEL, rv);
}

static void
test_info_limit_purposes (void)
{
	CK_RV rv;

	mock_module_add_object (MOCK_SLOT_ONE_ID, cacert3_trusted);
	mock_module_add_object (MOCK_SLOT_ONE_ID, extension_eku_server_client);

	/* This should not match the above, with the attached certificat ext */
	assert_ptr_eq (NULL, test.ex.limit_to_purposes);
	p11_enumerate_opt_purpose (&test.ex, "1.1.1");
	assert_ptr_not_null (test.ex.limit_to_purposes);

	p11_kit_iter_add_filter (test.ex.iter, certificate_filter, 1);
	p11_enumerate_ready (&test.ex, NULL);

	rv = p11_kit_iter_next (test.ex.iter);
	assert_num_eq (CKR_CANCEL, rv);
}

static void
test_info_invalid_purposes (void)
{
	CK_RV rv;

	mock_module_add_object (MOCK_SLOT_ONE_ID, cacert3_trusted);
	mock_module_add_object (MOCK_SLOT_ONE_ID, extension_eku_invalid);

	p11_kit_iter_add_filter (test.ex.iter, certificate_filter, 1);
	p11_enumerate_ready (&test.ex, NULL);

	p11_kit_be_quiet ();

	/* No results due to invalid purpose on certificate */
	rv = p11_kit_iter_next (test.ex.iter);
	assert_num_eq (CKR_CANCEL, rv);

	p11_kit_be_loud ();
}

static void
test_info_skip_non_certificate (void)
{
	CK_RV rv;

	mock_module_add_object (MOCK_SLOT_ONE_ID, cacert3_trusted);

	p11_enumerate_ready (&test.ex, NULL);

	p11_message_quiet ();

	rv = p11_kit_iter_next (test.ex.iter);
	assert_num_eq (CKR_OK, rv);

	assert_num_eq (CKO_CERTIFICATE, test.ex.klass);

	rv = p11_kit_iter_next (test.ex.iter);
	assert_num_eq (CKR_CANCEL, rv);

	p11_message_loud ();
}

static void
test_limit_to_purpose_match (void)
{
	CK_RV rv;

	mock_module_add_object (MOCK_SLOT_ONE_ID, cacert3_trusted);
	mock_module_add_object (MOCK_SLOT_ONE_ID, extension_eku_server_client);

	p11_enumerate_opt_purpose (&test.ex, P11_OID_SERVER_AUTH_STR);
	p11_enumerate_ready (&test.ex, NULL);

	p11_message_quiet ();

	rv = p11_kit_iter_next (test.ex.iter);
	assert_num_eq (CKR_OK, rv);

	p11_message_loud ();
}

static void
test_limit_to_purpose_no_match (void)
{
	CK_RV rv;

	mock_module_add_object (MOCK_SLOT_ONE_ID, cacert3_trusted);
	mock_module_add_object (MOCK_SLOT_ONE_ID, extension_eku_server_client);

	p11_enumerate_opt_purpose (&test.ex, "3.3.3.3");
	p11_enumerate_ready (&test.ex, NULL);

	p11_message_quiet ();

	rv = p11_kit_iter_next (test.ex.iter);
	assert_num_eq (CKR_CANCEL, rv);

	p11_message_loud ();
}

static void
test_duplicate_extract (void)
{
	CK_ATTRIBUTE certificate = { CKA_CLASS, &certificate_class, sizeof (certificate_class) };
	CK_RV rv;

	mock_module_add_object (MOCK_SLOT_ONE_ID, cacert3_trusted);
	mock_module_add_object (MOCK_SLOT_ONE_ID, cacert3_distrusted);

	p11_kit_iter_add_filter (test.ex.iter, &certificate, 1);
	p11_enumerate_ready (&test.ex, NULL);

	rv = p11_kit_iter_next (test.ex.iter);
	assert_num_eq (CKR_OK, rv);

	rv = p11_kit_iter_next (test.ex.iter);
	assert_num_eq (CKR_OK, rv);

	rv = p11_kit_iter_next (test.ex.iter);
	assert_num_eq (CKR_CANCEL, rv);
}

static void
test_duplicate_distrusted (void)
{
	CK_ATTRIBUTE certificate = { CKA_CLASS, &certificate_class, sizeof (certificate_class) };
	CK_ATTRIBUTE attrs[] = {
		{ CKA_X_DISTRUSTED, NULL, 0 },
	};

	CK_BBOOL val;
	CK_RV rv;

	mock_module_add_object (MOCK_SLOT_ONE_ID, cacert3_distrusted);
	mock_module_add_object (MOCK_SLOT_ONE_ID, cacert3_trusted);

	test.ex.flags = P11_ENUMERATE_COLLAPSE;
	p11_kit_iter_add_filter (test.ex.iter, &certificate, 1);
	p11_enumerate_ready (&test.ex, NULL);

	rv = p11_kit_iter_next (test.ex.iter);
	assert_num_eq (CKR_OK, rv);

	rv = p11_kit_iter_load_attributes (test.ex.iter, attrs, 1);
	assert_num_eq (CKR_OK, rv);
	assert (p11_attrs_findn_bool (attrs, 1, CKA_X_DISTRUSTED, &val));
	assert_num_eq (val, CK_TRUE);
	free (attrs[0].pValue);

	rv = p11_kit_iter_next (test.ex.iter);
	assert_num_eq (CKR_CANCEL, rv);
}

static void
test_trusted_match (void)
{
	CK_ATTRIBUTE certificate = { CKA_CLASS, &certificate_class, sizeof (certificate_class) };
	CK_RV rv;

	mock_module_add_object (MOCK_SLOT_ONE_ID, cacert3_trusted);
	mock_module_add_object (MOCK_SLOT_ONE_ID, cacert3_distrusted);

	test.ex.flags = P11_ENUMERATE_ANCHORS;
	p11_kit_iter_add_filter (test.ex.iter, &certificate, 1);
	p11_enumerate_ready (&test.ex, NULL);

	rv = p11_kit_iter_next (test.ex.iter);
	assert_num_eq (CKR_CANCEL, rv);
}

static void
test_distrust_match (void)
{
	CK_ATTRIBUTE certificate = { CKA_CLASS, &certificate_class, sizeof (certificate_class) };
	CK_BBOOL boolv;
	CK_RV rv;

	mock_module_add_object (MOCK_SLOT_ONE_ID, cacert3_trusted);
	mock_module_add_object (MOCK_SLOT_ONE_ID, cacert3_distrusted);

	test.ex.flags = P11_ENUMERATE_BLACKLIST;
	p11_kit_iter_add_filter (test.ex.iter, &certificate, 1);
	p11_enumerate_ready (&test.ex, NULL);

	rv = p11_kit_iter_next (test.ex.iter);
	assert_num_eq (CKR_OK, rv);

	if (!p11_attrs_find_bool (test.ex.attrs, CKA_X_DISTRUSTED, &boolv))
		boolv = CK_FALSE;
	assert_num_eq (CK_TRUE, boolv);

	rv = p11_kit_iter_next (test.ex.iter);
	assert_num_eq (CKR_CANCEL, rv);
}

static void
test_override_by_issuer_serial (void)
{
	CK_ATTRIBUTE certificate = { CKA_CLASS, &certificate_class, sizeof (certificate_class) };
	CK_BBOOL distrusted = CK_FALSE;
	CK_RV rv;

	mock_module_add_object (MOCK_SLOT_ONE_ID, cacert3_trusted);
	mock_module_add_object (MOCK_SLOT_ONE_ID, cacert3_distrusted);

	test.ex.flags =  P11_ENUMERATE_ANCHORS | P11_ENUMERATE_BLACKLIST;
	p11_kit_iter_add_filter (test.ex.iter, &certificate, 1);
	p11_enumerate_ready (&test.ex, NULL);

	rv = p11_kit_iter_next (test.ex.iter);
	assert_num_eq (CKR_OK, rv);

	assert (p11_attrs_find_bool (test.ex.attrs, CKA_X_DISTRUSTED, &distrusted));
	assert_num_eq (CK_TRUE, distrusted);

	rv = p11_kit_iter_next (test.ex.iter);
	assert_num_eq (CKR_CANCEL, rv);
}

static void
test_override_by_public_key (void)
{
	CK_ATTRIBUTE certificate = { CKA_CLASS, &certificate_class, sizeof (certificate_class) };
	CK_RV rv;

	mock_module_add_object (MOCK_SLOT_ONE_ID, cacert3_trusted);
	mock_module_add_object (MOCK_SLOT_ONE_ID, cacert3_distrusted_by_key);

	test.ex.flags =  P11_ENUMERATE_ANCHORS | P11_ENUMERATE_BLACKLIST;
	p11_kit_iter_add_filter (test.ex.iter, &certificate, 1);
	p11_enumerate_ready (&test.ex, NULL);

	/* No results returned, because distrust is not a cert */
	rv = p11_kit_iter_next (test.ex.iter);
	assert_num_eq (CKR_CANCEL, rv);
}

int
main (int argc,
      char *argv[])
{
	mock_module_init ();

	p11_test (test_file_name_for_label, "/extract/test_file_name_for_label");
	p11_test (test_file_name_for_class, "/extract/test_file_name_for_class");
	p11_test (test_comment_for_label, "/extract/test_comment_for_label");
	p11_test (test_comment_not_enabled, "/extract/test_comment_not_enabled");

	p11_fixture (setup, teardown);
	p11_test (test_info_simple_certificate, "/extract/test_info_simple_certificate");
	p11_test (test_info_limit_purposes, "/extract/test_info_limit_purposes");
	p11_test (test_info_invalid_purposes, "/extract/test_info_invalid_purposes");
	p11_test (test_info_skip_non_certificate, "/extract/test_info_skip_non_certificate");
	p11_test (test_limit_to_purpose_match, "/extract/test_limit_to_purpose_match");
	p11_test (test_limit_to_purpose_no_match, "/extract/test_limit_to_purpose_no_match");
	p11_test (test_duplicate_extract, "/extract/test_duplicate_extract");
	p11_test (test_duplicate_distrusted, "/extract/test-duplicate-distrusted");
	p11_test (test_trusted_match, "/extract/test_trusted_match");
	p11_test (test_distrust_match, "/extract/test_distrust_match");
	p11_test (test_override_by_issuer_serial, "/extract/override-by-issuer-and-serial");
	p11_test (test_override_by_public_key, "/extract/override-by-public-key");

	return p11_test_run (argc, argv);
}

#include "enumerate.c"
