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
#include "buffer.h"
#include "compat.h"
#include "debug.h"
#include "dict.h"
#include "extract.h"
#include "message.h"
#include "mock.h"
#include "path.h"
#include "pkcs11.h"
#include "pkcs11x.h"
#include "oid.h"
#include "test.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define ELEMS(x) (sizeof (x) / sizeof (x[0]))

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
test_file (void)
{
	char *destination;
	bool ret;

	setup_objects (cacert3_authority_attrs,
	               extension_eku_server,
	               extension_reject_email,
	               NULL);

	p11_kit_iter_add_filter (test.ex.iter, certificate_filter, 1);
	p11_kit_iter_begin_with (test.ex.iter, &test.module, 0, 0);

	if (asprintf (&destination, "%s/%s", test.directory, "extract.pem") < 0)
		assert_not_reached ();

	ret = p11_extract_openssl_bundle (&test.ex, destination);
	assert_num_eq (true, ret);

	test_check_file (test.directory, "extract.pem",
	                 SRCDIR "/trust/fixtures/cacert3-trusted-server-alias.pem");

	free (destination);
}

static void
test_plain (void)
{
	char *destination;
	bool ret;

	setup_objects (cacert3_authority_attrs, NULL);

	p11_kit_iter_add_filter (test.ex.iter, certificate_filter, 1);
	p11_kit_iter_begin_with (test.ex.iter, &test.module, 0, 0);

	if (asprintf (&destination, "%s/%s", test.directory, "extract.pem") < 0)
		assert_not_reached ();

	ret = p11_extract_openssl_bundle (&test.ex, destination);
	assert_num_eq (true, ret);

	test_check_file (test.directory, "extract.pem",
	                 SRCDIR "/trust/fixtures/cacert3-trusted-alias.pem");

	free (destination);
}

static void
test_keyid (void)
{
	char *destination;
	bool ret;

	static CK_ATTRIBUTE cacert3_plain[] = {
		{ CKA_VALUE, (void *)test_cacert3_ca_der, sizeof (test_cacert3_ca_der) },
		{ CKA_CLASS, &certificate_class, sizeof (certificate_class) },
		{ CKA_CERTIFICATE_TYPE, &x509_type, sizeof (x509_type) },
		{ CKA_SUBJECT, (void *)test_cacert3_ca_subject, sizeof (test_cacert3_ca_subject) },
		{ CKA_PUBLIC_KEY_INFO, (void *)test_cacert3_ca_public_key, sizeof (test_cacert3_ca_public_key) },
		{ CKA_TRUSTED, &vtrue, sizeof (vtrue) },
		{ CKA_INVALID },
	};

	static CK_ATTRIBUTE extension_subject_key_identifier[] = {
		{ CKA_CLASS, &extension_class, sizeof (extension_class) },
		{ CKA_OBJECT_ID, (void *)P11_OID_SUBJECT_KEY_IDENTIFIER, sizeof (P11_OID_SUBJECT_KEY_IDENTIFIER) },
		{ CKA_PUBLIC_KEY_INFO, (void *)test_cacert3_ca_public_key, sizeof (test_cacert3_ca_public_key) },
		{ CKA_VALUE, "\x30\x0e\x06\x03\x55\x1d\x0e\x04\x07\x00\x01\x02\x03\x04\x05\x06", 16 },
		{ CKA_INVALID },
	};

	setup_objects (cacert3_plain, extension_subject_key_identifier, NULL);

	p11_kit_iter_add_filter (test.ex.iter, certificate_filter, 1);
	p11_kit_iter_begin_with (test.ex.iter, &test.module, 0, 0);

	if (asprintf (&destination, "%s/%s", test.directory, "extract.pem") < 0)
		assert_not_reached ();

	ret = p11_extract_openssl_bundle (&test.ex, destination);
	assert_num_eq (true, ret);

	test_check_file (test.directory, "extract.pem",
	                 SRCDIR "/trust/fixtures/cacert3-trusted-keyid.pem");

	free (destination);
}

static void
test_not_authority (void)
{
	char *destination;
	bool ret;

	static CK_ATTRIBUTE cacert3_not_trusted[] = {
		{ CKA_VALUE, (void *)test_cacert3_ca_der, sizeof (test_cacert3_ca_der) },
		{ CKA_CLASS, &certificate_class, sizeof (certificate_class) },
		{ CKA_CERTIFICATE_TYPE, &x509_type, sizeof (x509_type) },
		{ CKA_SUBJECT, (void *)test_cacert3_ca_subject, sizeof (test_cacert3_ca_subject) },
		{ CKA_INVALID },
	};

	setup_objects (cacert3_not_trusted, NULL);

	p11_kit_iter_add_filter (test.ex.iter, certificate_filter, 1);
	p11_kit_iter_begin_with (test.ex.iter, &test.module, 0, 0);

	if (asprintf (&destination, "%s/%s", test.directory, "extract.pem") < 0)
		assert_not_reached ();

	ret = p11_extract_openssl_bundle (&test.ex, destination);
	assert_num_eq (true, ret);

	test_check_file (test.directory, "extract.pem",
	                 SRCDIR "/trust/fixtures/cacert3-not-trusted.pem");

	free (destination);
}

static void
test_distrust_all (void)
{
	char *destination;
	bool ret;

	static CK_ATTRIBUTE cacert3_blacklist[] = {
		{ CKA_VALUE, (void *)test_cacert3_ca_der, sizeof (test_cacert3_ca_der) },
		{ CKA_CLASS, &certificate_class, sizeof (certificate_class) },
		{ CKA_CERTIFICATE_TYPE, &x509_type, sizeof (x509_type) },
		{ CKA_SUBJECT, (void *)test_cacert3_ca_subject, sizeof (test_cacert3_ca_subject) },
		{ CKA_X_DISTRUSTED, &vtrue, sizeof (vtrue) },
		{ CKA_INVALID },
	};

	setup_objects (cacert3_blacklist, NULL);

	p11_kit_iter_add_filter (test.ex.iter, certificate_filter, 1);
	p11_kit_iter_begin_with (test.ex.iter, &test.module, 0, 0);

	if (asprintf (&destination, "%s/%s", test.directory, "extract.pem") < 0)
		assert_not_reached ();

	ret = p11_extract_openssl_bundle (&test.ex, destination);
	assert_num_eq (true, ret);

	test_check_file (test.directory, "extract.pem",
	                 SRCDIR "/trust/fixtures/cacert3-distrust-all.pem");

	free (destination);
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

	if (asprintf (&destination, "%s/%s", test.directory, "extract.pem") < 0)
		assert_not_reached ();

	ret = p11_extract_openssl_bundle (&test.ex, destination);
	assert_num_eq (true, ret);

	test_check_file (test.directory, "extract.pem", SRCDIR "/trust/fixtures/multiple.pem");
	free (destination);
}

static void
test_file_without (void)
{
	char *destination;
	bool ret;

	p11_kit_iter_add_filter (test.ex.iter, certificate_filter, 1);
	p11_kit_iter_begin_with (test.ex.iter, &test.module, 0, 0);

	if (asprintf (&destination, "%s/%s", test.directory, "extract.pem") < 0)
		assert_not_reached ();

	ret = p11_extract_openssl_bundle (&test.ex, destination);
	assert_num_eq (true, ret);

	test_check_data (test.directory, "extract.pem", "", 0);

	free (destination);
}

/* From extract-openssl.c */
void p11_openssl_canon_string (char *str, size_t *len);

static void
test_canon_string (void)
{
	struct {
		char *input;
		int input_len;
		char *output;
		int output_len;
	} fixtures[] = {
		{ "A test", -1, "a test", -1 },
		{ "   Strip spaces   ", -1, "strip spaces", -1 },
		{ " Collapse \n\t spaces", -1, "collapse spaces", -1 },
		{ "Ignore non-ASCII \303\204", -1, "ignore non-ascii \303\204", -1 },
		{ "no-space", -1, "no-space", -1 },
	};

	char *str;
	size_t len;
	size_t out;
	int i;

	for (i = 0; i < ELEMS (fixtures); i++) {
		if (fixtures[i].input_len < 0)
			len = strlen (fixtures[i].input);
		else
			len = fixtures[i].input_len;
		str = strndup (fixtures[i].input, len);

		p11_openssl_canon_string (str, &len);

		if (fixtures[i].output_len < 0)
			out = strlen (fixtures[i].output);
		else
			out = fixtures[i].output_len;
		assert_num_eq (out, len);
		assert_str_eq (fixtures[i].output, str);

		free (str);
	}
}

bool   p11_openssl_canon_string_der  (p11_buffer *der);

static void
test_canon_string_der (void)
{
	struct {
		unsigned char input[100];
		int input_len;
		unsigned char output[100];
		int output_len;
	} fixtures[] = {
		/* UTF8String */
		{ { 0x0c, 0x0f, 0xc3, 0x84, ' ', 'U', 'T', 'F', '8', ' ', 's', 't', 'r', 'i', 'n', 'g', ' ', }, 17,
		  { 0x0c, 0x0e, 0xc3, 0x84, ' ', 'u', 't', 'f', '8', ' ', 's', 't', 'r', 'i', 'n', 'g', }, 16,
		},

		/* NumericString */
		{ { 0x12, 0x04, '0', '1', '2', '3', }, 6,
		  { 0x0c, 0x04, '0', '1', '2', '3' }, 6,
		},

		/* IA5String */
		{ { 0x16, 0x04, ' ', 'A', 'B', ' ', }, 6,
		  { 0x0c, 0x02, 'a', 'b',  }, 4,
		},

		/* TeletexString */
		{ { 0x14, 0x07, 'A', ' ', ' ', 'n', 'i', 'c', 'e' }, 9,
		  { 0x0c, 0x06, 'a', ' ', 'n', 'i', 'c', 'e' }, 8,
		},

		/* PrintableString */
		{ { 0x13, 0x07, 'A', ' ', ' ', 'n', 'i', 'c', 'e' }, 9,
		  { 0x0c, 0x06, 'a', ' ', 'n', 'i', 'c', 'e' }, 8,
		},

		/* No change, not a known string type */
		{ { 0x05, 0x07, 'A', ' ', ' ', 'n', 'i', 'c', 'e' }, 9,
		  { 0x05, 0x07, 'A', ' ', ' ', 'n', 'i', 'c', 'e' }, 9
		},

		/* UniversalString */
		{ { 0x1c, 0x14, 0x00, 0x00, 0x00, 'F', 0x00, 0x00, 0x00, 'u',
		    0x00, 0x00, 0x00, 'n', 0x00, 0x00, 0x00, ' ', 0x00, 0x01, 0x03, 0x19, }, 22,
		  { 0x0c, 0x08, 'f', 'u', 'n', ' ', 0xf0, 0x90, 0x8c, 0x99 }, 10,
		},

		/* BMPString */
		{ { 0x1e, 0x0a, 0x00, 'V', 0x00, 0xF6, 0x00, 'g', 0x00, 'e', 0x00, 'l' }, 12,
		  { 0x0c, 0x06, 'v', 0xc3, 0xb6, 'g', 'e', 'l' }, 8,
		},
	};

	p11_buffer buf;
	bool ret;
	int i;

	for (i = 0; i < ELEMS (fixtures); i++) {
		p11_buffer_init_full (&buf, memdup (fixtures[i].input, fixtures[i].input_len),
		                      fixtures[i].input_len, 0, realloc, free);

		ret = p11_openssl_canon_string_der (&buf);
		assert_num_eq (true, ret);

		assert_num_eq (fixtures[i].output_len, buf.len);
		assert (memcmp (buf.data, fixtures[i].output, buf.len) == 0);

		p11_buffer_uninit (&buf);
	}
}

bool   p11_openssl_canon_name_der     (p11_dict *asn1_defs,
                                       p11_buffer *der);

static void
test_canon_name_der (void)
{
	struct {
		unsigned char input[100];
		int input_len;
		unsigned char output[100];
		int output_len;
	} fixtures[] = {
		{ { '0', 'T', '1', 0x14, '0', 0x12, 0x06, 0x03, 'U', 0x04, 0x0a,
		    0x13, 0x0b, 'C', 'A', 'c', 'e', 'r', 't', 0x20, 'I', 'n',
		    'c', '.', '1', 0x1e, '0', 0x1c, 0x06, 0x03, 'U', 0x04,
		    0x0b, 0x13, 0x15, 'h', 't', 't', 'p', ':', '/', '/', 'w',
		    'w', 'w', '.', 'C', 'A', 'c', 'e', 'r', 't', '.', 'o', 'r',
		    'g', '1', 0x1c, '0', 0x1a, 0x06, 0x03, 'U', 0x04, 0x03, 0x13,
		    0x13, 'C', 'A', 'c', 'e', 'r', 't', 0x20, 'C', 'l', 'a', 's',
		    's', 0x20, '3', 0x20, 'R', 'o', 'o', 't', }, 86,
		  { '1', 0x14, '0', 0x12, 0x06, 0x03, 'U', 0x04, 0x0a,
		    0x0c, 0x0b, 'c', 'a', 'c', 'e', 'r', 't', 0x20, 'i', 'n',
		    'c', '.', '1', 0x1e, '0', 0x1c, 0x06, 0x03, 'U', 0x04,
		    0x0b, 0x0c, 0x15, 'h', 't', 't', 'p', ':', '/', '/', 'w',
		    'w', 'w', '.', 'c', 'a', 'c', 'e', 'r', 't', '.', 'o', 'r',
		    'g', '1', 0x1c, '0', 0x1a, 0x06, 0x03, 'U', 0x04, 0x03, 0x0c,
		    0x13, 'c', 'a', 'c', 'e', 'r', 't', 0x20, 'c', 'l', 'a', 's',
		    's', 0x20, '3', 0x20, 'r', 'o', 'o', 't', }, 84,
		},
		{ { '0', 0x00, }, 2,
		  { }, 0,
		},
	};

	p11_buffer buf;
	p11_dict *asn1_defs;
	bool ret;
	int i;

	asn1_defs = p11_asn1_defs_load ();

	for (i = 0; i < ELEMS (fixtures); i++) {
		p11_buffer_init_full (&buf, memdup (fixtures[i].input, fixtures[i].input_len),
		                      fixtures[i].input_len, 0, realloc, free);

		ret = p11_openssl_canon_name_der (asn1_defs, &buf);
		assert_num_eq (true, ret);

		assert_num_eq (fixtures[i].output_len, buf.len);
		assert (memcmp (buf.data, fixtures[i].output, buf.len) == 0);

		p11_buffer_uninit (&buf);
	}

	p11_dict_free (asn1_defs);
}

static void
test_canon_string_der_fail (void)
{
	struct {
		unsigned char input[100];
		int input_len;
	} fixtures[] = {
		{ { 0x0c, 0x02, 0xc3, 0xc4 /* Invalid UTF-8 */ }, 4 },
		{ { 0x1e, 0x01, 0x00 /* Invalid UCS2 */ }, 3 },
		{ { 0x1c, 0x02, 0x00, 0x01 /* Invalid UCS4 */ }, 4 },
	};

	p11_buffer buf;
	bool ret;
	int i;

	for (i = 0; i < ELEMS (fixtures); i++) {
		p11_buffer_init_full (&buf, memdup (fixtures[i].input, fixtures[i].input_len),
		                      fixtures[i].input_len, 0, realloc, free);

		ret = p11_openssl_canon_string_der (&buf);
		assert_num_eq (false, ret);

		p11_buffer_uninit (&buf);
	}
}

static void
test_directory (void)
{
	bool ret;

	setup_objects (cacert3_authority_attrs,
	               extension_eku_server,
	               extension_reject_email,
	               NULL);

	/* Accesses the above objects */
	setup_objects (cacert3_authority_attrs,
	               NULL);

	p11_kit_iter_add_filter (test.ex.iter, certificate_filter, 1);
	p11_kit_iter_begin_with (test.ex.iter, &test.module, 0, 0);

	/* Yes, this is a race, and why you shouldn't build software as root */
	if (rmdir (test.directory) < 0)
		assert_not_reached ();

	ret = p11_extract_openssl_directory (&test.ex, test.directory);
	assert_num_eq (true, ret);

	test_check_directory (test.directory, ("Custom_Label.pem", "Custom_Label.1.pem",
#ifdef OS_UNIX
	                                           "e5662767.1", "e5662767.0", "590d426f.1", "590d426f.0",
#endif
	                                           NULL));
	test_check_file (test.directory, "Custom_Label.pem",
	                 SRCDIR "/trust/fixtures/cacert3-trusted-server-alias.pem");
	test_check_file (test.directory, "Custom_Label.1.pem",
	                 SRCDIR "/trust/fixtures/cacert3-trusted-server-alias.pem");
#ifdef OS_UNIX
	test_check_symlink (test.directory, "e5662767.0", "Custom_Label.pem");
	test_check_symlink (test.directory, "e5662767.1", "Custom_Label.1.pem");
	test_check_symlink (test.directory, "590d426f.0", "Custom_Label.pem");
	test_check_symlink (test.directory, "590d426f.1", "Custom_Label.1.pem");
#endif
}

static void
test_directory_empty (void)
{
	bool ret;

	p11_kit_iter_add_filter (test.ex.iter, certificate_filter, 1);
	p11_kit_iter_begin_with (test.ex.iter, &test.module, 0, 0);

	/* Yes, this is a race, and why you shouldn't build software as root */
	if (rmdir (test.directory) < 0)
		assert_not_reached ();

	ret = p11_extract_openssl_directory (&test.ex, test.directory);
	assert_num_eq (true, ret);

	test_check_directory (test.directory, (NULL, NULL));
}

int
main (int argc,
      char *argv[])
{
	mock_module_init ();

	p11_fixture (setup, teardown);
	p11_test (test_file, "/openssl/test_file");
	p11_test (test_plain, "/openssl/test_plain");
	p11_test (test_keyid, "/openssl/test_keyid");
	p11_test (test_not_authority, "/openssl/test_not_authority");
	p11_test (test_distrust_all, "/openssl/test_distrust_all");
	p11_test (test_file_multiple, "/openssl/test_file_multiple");
	p11_test (test_file_without, "/openssl/test_file_without");

	p11_fixture (NULL, NULL);
	p11_test (test_canon_string, "/openssl/test_canon_string");
	p11_test (test_canon_string_der, "/openssl/test_canon_string_der");
	p11_test (test_canon_string_der_fail, "/openssl/test_canon_string_der_fail");
	p11_test (test_canon_name_der, "/openssl/test_canon_name_der");

	p11_fixture (setup, teardown);
	p11_test (test_directory, "/openssl/test_directory");
	p11_test (test_directory_empty, "/openssl/test_directory_empty");

	return p11_test_run (argc, argv);
}

#include "enumerate.c"
#include "extract-openssl.c"
#include "save.c"
