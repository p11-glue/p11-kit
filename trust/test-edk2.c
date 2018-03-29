/*
 * Copyright (c) 2011, Collabora Ltd.
 * Copyright (c) 2018, Red Hat Inc.
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
 * Authors: Stef Walter <stefw@collabora.co.uk>
 *          Laszlo Ersek <lersek@redhat.com>
 */

#define P11_KIT_DISABLE_DEPRECATED

#include "config.h"

#include "test-trust.h" /* test_cacert3_ca_der */

#include "attrs.h"      /* p11_attrs_build() */
#include "extract.h"    /* p11_extract_edk2_cacerts() */
#include "mock.h"       /* mock_module_reset() */
#include "pkcs11.h"     /* CK_FUNCTION_LIST */
#include "pkcs11x.h"    /* CKO_X_CERTIFICATE_EXTENSION */
#include "oid.h"        /* P11_OID_EXTENDED_KEY_USAGE */
#include "test.h"       /* p11_test() */

#include <stdarg.h>     /* va_list */
#include <stdio.h>      /* asprintf() */
#include <stdlib.h>     /* free() */
#include <string.h>     /* memcpy() */
#include <unistd.h>     /* rmdir() */

struct {
	CK_FUNCTION_LIST module;
	p11_enumerate ex;
	char *directory;
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
	test.ex.flags |= P11_ENUMERATE_CORRELATE;

	test.directory = p11_test_directory ("test-extract");
}

static void
teardown (void *unused)
{
	CK_RV rv;

	if (rmdir (test.directory) < 0)
		assert_not_reached ();
	free (test.directory);

	p11_enumerate_cleanup (&test.ex);
	p11_kit_iter_free (test.ex.iter);

	rv = test.module.C_Finalize (NULL);
	assert_num_eq (CKR_OK, rv);
}

static CK_OBJECT_CLASS certificate_class = CKO_CERTIFICATE;
static CK_OBJECT_CLASS extension_class = CKO_X_CERTIFICATE_EXTENSION;
static CK_CERTIFICATE_TYPE x509_type = CKC_X_509;
static CK_BBOOL vtrue = CK_TRUE;

static CK_ATTRIBUTE cacert3_authority_attrs[] = {
	{ CKA_VALUE, (void *)test_cacert3_ca_der, sizeof (test_cacert3_ca_der) },
	{ CKA_CLASS, &certificate_class, sizeof (certificate_class) },
	{ CKA_CERTIFICATE_TYPE, &x509_type, sizeof (x509_type) },
	{ CKA_LABEL, "Custom Label", 12 },
	{ CKA_SUBJECT, (void *)test_cacert3_ca_subject, sizeof (test_cacert3_ca_subject) },
	{ CKA_PUBLIC_KEY_INFO, (void *)test_cacert3_ca_public_key, sizeof (test_cacert3_ca_public_key) },
	{ CKA_TRUSTED, &vtrue, sizeof (vtrue) },
	{ CKA_INVALID },
};

static CK_ATTRIBUTE verisign_v1_attrs[] = {
	{ CKA_VALUE, (void *)verisign_v1_ca, sizeof (verisign_v1_ca) },
	{ CKA_CLASS, &certificate_class, sizeof (certificate_class) },
	{ CKA_CERTIFICATE_TYPE, &x509_type, sizeof (x509_type) },
	{ CKA_LABEL, "Custom Label", 12 },
	{ CKA_SUBJECT, (void *)verisign_v1_ca_subject, sizeof (verisign_v1_ca_subject) },
	{ CKA_PUBLIC_KEY_INFO, (void *)verisign_v1_ca_public_key, sizeof (verisign_v1_ca_public_key) },
	{ CKA_TRUSTED, &vtrue, sizeof (vtrue) },
	{ CKA_INVALID },
};

static CK_ATTRIBUTE extension_eku_server[] = {
	{ CKA_CLASS, &extension_class, sizeof (extension_class) },
	{ CKA_OBJECT_ID, (void *)P11_OID_EXTENDED_KEY_USAGE, sizeof (P11_OID_EXTENDED_KEY_USAGE) },
	{ CKA_PUBLIC_KEY_INFO, (void *)test_cacert3_ca_public_key, sizeof (test_cacert3_ca_public_key) },
	{ CKA_VALUE, "\x30\x13\x06\x03\x55\x1d\x25\x04\x0c\x30\x0a\x06\x08\x2b\x06\x01\x05\x05\x07\x03\x01", 21 },
	{ CKA_INVALID },
};

static CK_ATTRIBUTE extension_reject_email[] = {
	{ CKA_CLASS, &extension_class, sizeof (extension_class) },
	{ CKA_OBJECT_ID, (void *)P11_OID_OPENSSL_REJECT, sizeof (P11_OID_OPENSSL_REJECT) },
	{ CKA_VALUE, "\x30\x1a\x06\x0a\x2b\x06\x01\x04\x01\x99\x77\x06\x0a\x01\x04\x0c\x30\x0a\x06\x08\x2b\x06\x01\x05\x05\x07\x03\x04", 28 },
	{ CKA_PUBLIC_KEY_INFO, (void *)test_cacert3_ca_public_key, sizeof (test_cacert3_ca_public_key) },
	{ CKA_INVALID },
};

static CK_ATTRIBUTE certificate_filter[] = {
	{ CKA_CLASS, &certificate_class, sizeof (certificate_class) },
	{ CKA_INVALID },
};

static void
setup_objects (const CK_ATTRIBUTE *attrs,
               ...) GNUC_NULL_TERMINATED;

static void
setup_objects (const CK_ATTRIBUTE *attrs,
               ...)
{
	static CK_ULONG id_value = 8888;

	CK_ATTRIBUTE id = { CKA_ID, &id_value, sizeof (id_value) };
	CK_ATTRIBUTE *copy;
	va_list va;

	va_start (va, attrs);
	while (attrs != NULL) {
		copy = p11_attrs_build (p11_attrs_dup (attrs), &id, NULL);
		assert (copy != NULL);
		mock_module_take_object (MOCK_SLOT_ONE_ID, copy);
		attrs = va_arg (va, const CK_ATTRIBUTE *);
	}
	va_end (va);

	id_value++;
}

static void
test_file_multiple (void)
{
	char *destination;
	bool ret;

	setup_objects (cacert3_authority_attrs,
	               extension_eku_server,
	               extension_reject_email,
	               NULL);

	setup_objects (verisign_v1_attrs,
	               NULL);

	p11_kit_iter_add_filter (test.ex.iter, certificate_filter, 1);
	p11_kit_iter_begin_with (test.ex.iter, &test.module, 0, 0);

	if (asprintf (&destination, "%s/%s", test.directory, "extract.edk2") < 0)
		assert_not_reached ();

	ret = p11_extract_edk2_cacerts (&test.ex, destination);
	assert_num_eq (true, ret);

	test_check_file (test.directory, "extract.edk2", SRCDIR "/trust/fixtures/multiple.edk2");
	free (destination);
}

int
main (int argc,
      char *argv[])
{
	mock_module_init ();

	p11_fixture (setup, teardown);
	p11_test (test_file_multiple, "/edk2/test_file_multiple");

	return p11_test_run (argc, argv);
}

#include "enumerate.c"    /* p11_enumerate_init() */
#include "extract-edk2.c" /* p11_extract_edk2_cacerts() */
