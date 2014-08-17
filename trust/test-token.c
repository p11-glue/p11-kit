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

#include "attrs.h"
#include "debug.h"
#include "parser.h"
#include "path.h"
#include "pkcs11x.h"
#include "message.h"
#include "token.h"

static CK_OBJECT_CLASS certificate = CKO_CERTIFICATE;
static CK_OBJECT_CLASS data = CKO_DATA;
static CK_BBOOL falsev = CK_FALSE;
static CK_BBOOL truev = CK_TRUE;

struct {
	p11_token *token;
	p11_index *index;
	p11_parser *parser;
	char *directory;
} test;

static void
setup (void *path)
{
	test.token = p11_token_new (333, path, "Label");
	assert_ptr_not_null (test.token);

	test.index = p11_token_index (test.token);
	assert_ptr_not_null (test.token);

	test.parser = p11_token_parser (test.token);
	assert_ptr_not_null (test.parser);
}

static void
setup_temp (void *unused)
{
	test.directory = p11_test_directory ("test-module");
	setup (test.directory);
}

static void
teardown (void *path)
{
	p11_token_free (test.token);
	memset (&test, 0, sizeof (test));
}

static void
teardown_temp (void *unused)
{
	p11_test_directory_delete (test.directory);
	teardown (test.directory);
	free (test.directory);
}

static void
test_token_load (void *path)
{
	p11_index *index;
	int count;

	count = p11_token_load (test.token);
	assert_num_eq (6, count);

	/* A certificate and trust object for each parsed object */
	index = p11_token_index (test.token);
	assert (((count - 1) * 2) + 1 <= p11_index_size (index));
}

static void
test_token_flags (void *path)
{
	/*
	 * blacklist comes from the input/distrust.pem file. It is not in the blacklist
	 * directory, but is an OpenSSL trusted certificate file, and is marked
	 * in the blacklist style for OpenSSL.
	 */

	CK_ATTRIBUTE blacklist[] = {
		{ CKA_CLASS, &certificate, sizeof (certificate) },
		{ CKA_LABEL, "Red Hat Is the CA", 17 },
		{ CKA_SERIAL_NUMBER, "\x02\x01\x01", 3 },
		{ CKA_TRUSTED, &falsev, sizeof (falsev) },
		{ CKA_X_DISTRUSTED, &truev, sizeof (truev) },
		{ CKA_INVALID },
	};

	/*
	 * blacklist2 comes from the input/blacklist/self-server.der file. It is
	 * explicitly put on the blacklist, even though it containts no trust
	 * policy information.
	 */

	const unsigned char self_server_subject[] = {
		0x30, 0x4b, 0x31, 0x13, 0x30, 0x11, 0x06, 0x0a, 0x09, 0x92, 0x26, 0x89, 0x93, 0xf2, 0x2c, 0x64,
		0x01, 0x19, 0x16, 0x03, 0x43, 0x4f, 0x4d, 0x31, 0x17, 0x30, 0x15, 0x06, 0x0a, 0x09, 0x92, 0x26,
		0x89, 0x93, 0xf2, 0x2c, 0x64, 0x01, 0x19, 0x16, 0x07, 0x45, 0x58, 0x41, 0x4d, 0x50, 0x4c, 0x45,
		0x31, 0x1b, 0x30, 0x19, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x12, 0x73, 0x65, 0x72, 0x76, 0x65,
		0x72, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d,
	};

	CK_ATTRIBUTE blacklist2[] = {
		{ CKA_CLASS, &certificate, sizeof (certificate) },
		{ CKA_SUBJECT, (void *)self_server_subject, sizeof (self_server_subject) },
		{ CKA_TRUSTED, &falsev, sizeof (falsev) },
		{ CKA_X_DISTRUSTED, &truev, sizeof (truev) },
		{ CKA_INVALID },
	};

	/*
	 * anchor comes from the input/anchors/cacert3.der file. It is
	 * explicitly marked as an anchor, even though it containts no trust
	 * policy information.
	 */

	CK_ATTRIBUTE anchor[] = {
		{ CKA_CLASS, &certificate, sizeof (certificate) },
		{ CKA_SUBJECT, (void *)test_cacert3_ca_subject, sizeof (test_cacert3_ca_subject) },
		{ CKA_TRUSTED, &truev, sizeof (truev) },
		{ CKA_X_DISTRUSTED, &falsev, sizeof (falsev) },
		{ CKA_INVALID },
	};

	const unsigned char cacert_root_subject[] = {
		0x30, 0x79, 0x31, 0x10, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x07, 0x52, 0x6f, 0x6f,
		0x74, 0x20, 0x43, 0x41, 0x31, 0x1e, 0x30, 0x1c, 0x06, 0x03, 0x55, 0x04, 0x0b, 0x13, 0x15, 0x68,
		0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x77, 0x77, 0x77, 0x2e, 0x63, 0x61, 0x63, 0x65, 0x72, 0x74,
		0x2e, 0x6f, 0x72, 0x67, 0x31, 0x22, 0x30, 0x20, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x19, 0x43,
		0x41, 0x20, 0x43, 0x65, 0x72, 0x74, 0x20, 0x53, 0x69, 0x67, 0x6e, 0x69, 0x6e, 0x67, 0x20, 0x41,
		0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x74, 0x79, 0x31, 0x21, 0x30, 0x1f, 0x06, 0x09, 0x2a, 0x86,
		0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01, 0x16, 0x12, 0x73, 0x75, 0x70, 0x70, 0x6f, 0x72, 0x74,
		0x40, 0x63, 0x61, 0x63, 0x65, 0x72, 0x74, 0x2e, 0x6f, 0x72, 0x67,
	};

	/*
	 * notrust comes from the input/cacert-ca.der file. It contains no
	 * trust information, and is not explicitly marked as an anchor, so
	 * it's neither trusted or distrusted.
	 */

	CK_ATTRIBUTE notrust[] = {
		{ CKA_CLASS, &certificate, sizeof (certificate) },
		{ CKA_SUBJECT, (void *)cacert_root_subject, sizeof (cacert_root_subject) },
		{ CKA_TRUSTED, &falsev, sizeof (falsev) },
		{ CKA_X_DISTRUSTED, &falsev, sizeof (falsev) },
		{ CKA_INVALID },
	};

	CK_ATTRIBUTE *expected[] = {
		anchor,
		blacklist,
		blacklist2,
		notrust,
		NULL,
	};

	CK_OBJECT_HANDLE handle;
	CK_ATTRIBUTE *object;
	int i;

	if (p11_token_load (test.token) < 0)
		assert_not_reached ();

	/* The other objects */
	for (i = 0; expected[i]; i++) {
		handle = p11_index_find (p11_token_index (test.token), expected[i], 2);
		assert (handle != 0);

		object = p11_index_lookup (p11_token_index (test.token), handle);
		assert_ptr_not_null (object);

		test_check_attrs (expected[i], object);
	}
}

static void
test_token_path (void *path)
{
	assert_str_eq (path, p11_token_get_path (test.token));
}

static void
test_token_label (void *path)
{
	assert_str_eq ("Label", p11_token_get_label (test.token));
}

static void
test_token_slot (void *path)
{
	assert_num_eq (333, p11_token_get_slot (test.token));
}

static void
test_not_writable (void)
{
	p11_token *token;

#ifdef OS_UNIX
	if (getuid () != 0) {
#endif
		token = p11_token_new (333, "/", "Label");
		assert (!p11_token_is_writable (token));
		p11_token_free (token);
#ifdef OS_UNIX
	}
#endif

	token = p11_token_new (333, "", "Label");
	assert (!p11_token_is_writable (token));
	p11_token_free (token);

	token = p11_token_new (333, "/non-existant", "Label");
	assert (!p11_token_is_writable (token));
	p11_token_free (token);
}

static void
test_writable_exists (void)
{
	/* A writable directory since we created it */
	assert (p11_token_is_writable (test.token));
}

static void
test_writable_no_exist (void)
{
	char *directory;
	p11_token *token;
	char *path;

	directory = p11_test_directory ("test-module");

	path = p11_path_build (directory, "subdir", NULL);
	assert (path != NULL);

	token = p11_token_new (333, path, "Label");
	free (path);

	/* A writable directory since parent is writable */
	assert (p11_token_is_writable (token));

	p11_token_free (token);

	if (rmdir (directory) < 0)
		assert_not_reached ();

	free (directory);
}

static void
test_load_already (void)
{
	CK_ATTRIBUTE cert[] = {
		{ CKA_CLASS, &certificate, sizeof (certificate) },
		{ CKA_SUBJECT, (void *)test_cacert3_ca_subject, sizeof (test_cacert3_ca_subject) },
		{ CKA_VALUE, (void *)test_cacert3_ca_der, sizeof (test_cacert3_ca_der) },
		{ CKA_INVALID },
	};

	CK_OBJECT_HANDLE handle;
	int ret;

	p11_test_file_write (test.directory, "test.cer", test_cacert3_ca_der,
	                     sizeof (test_cacert3_ca_der));

	ret = p11_token_load (test.token);
	assert_num_eq (ret, 1);
	handle = p11_index_find (test.index, cert, -1);
	assert (handle != 0);

	/* Have to wait to make sure changes are detected */
	p11_sleep_ms (1100);

	ret = p11_token_load (test.token);
	assert_num_eq (ret, 0);
	assert_num_eq (p11_index_find (test.index, cert, -1), handle);
}

static void
test_load_unreadable (void)
{
	CK_ATTRIBUTE cert[] = {
		{ CKA_CLASS, &certificate, sizeof (certificate) },
		{ CKA_SUBJECT, (void *)test_cacert3_ca_subject, sizeof (test_cacert3_ca_subject) },
		{ CKA_VALUE, (void *)test_cacert3_ca_der, sizeof (test_cacert3_ca_der) },
		{ CKA_INVALID },
	};

	int ret;

	p11_test_file_write (test.directory, "test.cer", test_cacert3_ca_der,
	                     sizeof (test_cacert3_ca_der));

	ret = p11_token_load (test.token);
	assert_num_eq (ret, 1);
	assert (p11_index_find (test.index, cert, -1) != 0);

	p11_test_file_write (test.directory, "test.cer", "", 0);

	/* Have to wait to make sure changes are detected */
	p11_sleep_ms (1100);

	ret = p11_token_load (test.token);
	assert_num_eq (ret, 0);
	assert (p11_index_find (test.index, cert, -1) == 0);
}

static void
test_load_gone (void)
{
	CK_ATTRIBUTE cert[] = {
		{ CKA_CLASS, &certificate, sizeof (certificate) },
		{ CKA_SUBJECT, (void *)test_cacert3_ca_subject, sizeof (test_cacert3_ca_subject) },
		{ CKA_VALUE, (void *)test_cacert3_ca_der, sizeof (test_cacert3_ca_der) },
		{ CKA_INVALID },
	};

	int ret;

	p11_test_file_write (test.directory, "test.cer", test_cacert3_ca_der,
	                     sizeof (test_cacert3_ca_der));

	ret = p11_token_load (test.token);
	assert_num_eq (ret, 1);
	assert (p11_index_find (test.index, cert, -1) != 0);

	p11_test_file_delete (test.directory, "test.cer");

	/* Have to wait to make sure changes are detected */
	p11_sleep_ms (1100);

	ret = p11_token_load (test.token);
	assert_num_eq (ret, 0);
	assert (p11_index_find (test.index, cert, -1) == 0);
}

static void
test_load_found (void)
{
	CK_ATTRIBUTE cert[] = {
		{ CKA_CLASS, &certificate, sizeof (certificate) },
		{ CKA_SUBJECT, (void *)test_cacert3_ca_subject, sizeof (test_cacert3_ca_subject) },
		{ CKA_VALUE, (void *)test_cacert3_ca_der, sizeof (test_cacert3_ca_der) },
		{ CKA_INVALID },
	};

	int ret;

	ret = p11_token_load (test.token);
	assert_num_eq (ret, 0);
	assert (p11_index_find (test.index, cert, -1) == 0);

	/* Have to wait to make sure changes are detected */
	p11_sleep_ms (1100);

	p11_test_file_write (test.directory, "test.cer", test_cacert3_ca_der,
	                     sizeof (test_cacert3_ca_der));

	ret = p11_token_load (test.token);
	assert_num_eq (ret, 1);
	assert (p11_index_find (test.index, cert, -1) != 0);
}

static void
test_reload_changed (void)
{
	CK_ATTRIBUTE cacert3[] = {
		{ CKA_CLASS, &certificate, sizeof (certificate) },
		{ CKA_SUBJECT, (void *)test_cacert3_ca_subject, sizeof (test_cacert3_ca_subject) },
		{ CKA_VALUE, (void *)test_cacert3_ca_der, sizeof (test_cacert3_ca_der) },
		{ CKA_INVALID },
	};

	CK_ATTRIBUTE verisign[] = {
		{ CKA_CLASS, &certificate, sizeof (certificate) },
		{ CKA_VALUE, (void *)verisign_v1_ca, sizeof (verisign_v1_ca) },
		{ CKA_INVALID },
	};

	CK_ATTRIBUTE *attrs;
	CK_OBJECT_HANDLE handle;
	int ret;

	/* Just one file */
	p11_test_file_write (test.directory, "test.cer", test_cacert3_ca_der,
	                     sizeof (test_cacert3_ca_der));

	ret = p11_token_load (test.token);
	assert_num_eq (ret, 1);
	handle = p11_index_find (test.index, cacert3, -1);
	assert (handle != 0);

	/* Replace the file with verisign */
	p11_test_file_write (test.directory, "test.cer", verisign_v1_ca,
	                     sizeof (verisign_v1_ca));

	/* Add another file with cacert3, but not reloaded */
	p11_test_file_write (test.directory, "another.cer", test_cacert3_ca_der,
	                     sizeof (test_cacert3_ca_der));

	attrs = p11_index_lookup (test.index, handle);
	assert_ptr_not_null (attrs);
	if (!p11_token_reload (test.token, attrs))
		assert_not_reached ();

	assert (p11_index_find (test.index, cacert3, -1) == 0);
	assert (p11_index_find (test.index, verisign, -1) != 0);
}

static void
test_reload_gone (void)
{
	CK_ATTRIBUTE cacert3[] = {
		{ CKA_CLASS, &certificate, sizeof (certificate) },
		{ CKA_SUBJECT, (void *)test_cacert3_ca_subject, sizeof (test_cacert3_ca_subject) },
		{ CKA_VALUE, (void *)test_cacert3_ca_der, sizeof (test_cacert3_ca_der) },
		{ CKA_INVALID },
	};

	CK_ATTRIBUTE verisign[] = {
		{ CKA_CLASS, &certificate, sizeof (certificate) },
		{ CKA_VALUE, (void *)verisign_v1_ca, sizeof (verisign_v1_ca) },
		{ CKA_INVALID },
	};

	CK_ATTRIBUTE *attrs;
	CK_OBJECT_HANDLE handle;
	int ret;

	/* Just one file */
	p11_test_file_write (test.directory, "cacert3.cer", test_cacert3_ca_der,
	                     sizeof (test_cacert3_ca_der));
	p11_test_file_write (test.directory, "verisign.cer", verisign_v1_ca,
	                     sizeof (verisign_v1_ca));

	ret = p11_token_load (test.token);
	assert_num_eq (ret, 2);
	handle = p11_index_find (test.index, cacert3, -1);
	assert (handle != 0);
	assert (p11_index_find (test.index, verisign, -1) != 0);

	p11_test_file_delete (test.directory, "cacert3.cer");
	p11_test_file_delete (test.directory, "verisign.cer");

	attrs = p11_index_lookup (test.index, handle);
	assert_ptr_not_null (attrs);
	if (p11_token_reload (test.token, attrs))
		assert_not_reached ();

	assert (p11_index_find (test.index, cacert3, -1) == 0);
	assert (p11_index_find (test.index, verisign, -1) != 0);
}

static void
test_reload_no_origin (void)
{
	CK_ATTRIBUTE cacert3[] = {
		{ CKA_CLASS, &certificate, sizeof (certificate) },
		{ CKA_SUBJECT, (void *)test_cacert3_ca_subject, sizeof (test_cacert3_ca_subject) },
		{ CKA_VALUE, (void *)test_cacert3_ca_der, sizeof (test_cacert3_ca_der) },
		{ CKA_INVALID },
	};

	if (p11_token_reload (test.token, cacert3))
		assert_not_reached ();
}

static void
test_write_new (void)
{
	CK_ATTRIBUTE original[] = {
		{ CKA_CLASS, &data, sizeof (data) },
		{ CKA_LABEL, "Yay!", 4 },
		{ CKA_VALUE, "eight", 5 },
		{ CKA_TOKEN, &truev, sizeof (truev) },
		{ CKA_INVALID }
	};

	CK_ATTRIBUTE expected[] = {
		{ CKA_CLASS, &data, sizeof (data) },
		{ CKA_LABEL, "Yay!", 4 },
		{ CKA_VALUE, "eight", 5 },
		{ CKA_APPLICATION, "", 0 },
		{ CKA_OBJECT_ID, "", 0 },
		{ CKA_INVALID }
	};

	CK_OBJECT_HANDLE handle;
	p11_array *parsed;
	char *path;
	CK_RV rv;
	int ret;

	rv = p11_index_add (test.index, original, 4, &handle);
	assert_num_eq (rv, CKR_OK);

	/* The expected file name */
	path = p11_path_build (test.directory, "Yay_.p11-kit", NULL);
	ret = p11_parse_file (test.parser, path, NULL, 0);
	assert_num_eq (ret, P11_PARSE_SUCCESS);
	free (path);

	parsed = p11_parser_parsed (test.parser);
	assert_num_eq (parsed->num, 1);

	test_check_attrs (expected, parsed->elem[0]);
}

static void
test_write_no_label (void)
{
	CK_ATTRIBUTE original[] = {
		{ CKA_CLASS, &data, sizeof (data) },
		{ CKA_VALUE, "eight", 5 },
		{ CKA_TOKEN, &truev, sizeof (truev) },
		{ CKA_INVALID }
	};

	CK_ATTRIBUTE expected[] = {
		{ CKA_CLASS, &data, sizeof (data) },
		{ CKA_LABEL, "", 0 },
		{ CKA_VALUE, "eight", 5 },
		{ CKA_APPLICATION, "", 0 },
		{ CKA_OBJECT_ID, "", 0 },
		{ CKA_INVALID }
	};

	CK_OBJECT_HANDLE handle;
	p11_array *parsed;
	char *path;
	CK_RV rv;
	int ret;

	rv = p11_index_add (test.index, original, 4, &handle);
	assert_num_eq (rv, CKR_OK);

	/* The expected file name */
	path = p11_path_build (test.directory, "data.p11-kit", NULL);
	ret = p11_parse_file (test.parser, path, NULL, 0);
	assert_num_eq (ret, P11_PARSE_SUCCESS);
	free (path);

	parsed = p11_parser_parsed (test.parser);
	assert_num_eq (parsed->num, 1);

	test_check_attrs (expected, parsed->elem[0]);
}

static void
test_modify_multiple (void)
{
	const char *test_data =
		"[p11-kit-object-v1]\n"
		"class: data\n"
		"label: \"first\"\n"
		"value: \"1\"\n"
		"\n"
		"[p11-kit-object-v1]\n"
		"class: data\n"
		"label: \"second\"\n"
		"value: \"2\"\n"
		"\n"
		"[p11-kit-object-v1]\n"
		"class: data\n"
		"label: \"third\"\n"
		"value: \"3\"\n";

	CK_ATTRIBUTE first[] = {
		{ CKA_CLASS, &data, sizeof (data) },
		{ CKA_LABEL, "first", 5 },
		{ CKA_VALUE, "1", 1 },
		{ CKA_INVALID },
	};

	CK_ATTRIBUTE second[] = {
		{ CKA_CLASS, &data, sizeof (data) },
		{ CKA_LABEL, "zwei", 4 },
		{ CKA_VALUE, "2", 2 },
		{ CKA_INVALID },
	};

	CK_ATTRIBUTE third[] = {
		{ CKA_CLASS, &data, sizeof (data) },
		{ CKA_LABEL, "third", 5 },
		{ CKA_VALUE, "3", 1 },
		{ CKA_INVALID },
	};

	CK_ATTRIBUTE match = { CKA_LABEL, "second", 6 };

	CK_OBJECT_HANDLE handle;
	p11_array *parsed;
	char *path;
	int ret;
	CK_RV rv;

	p11_test_file_write (test.directory, "Test.p11-kit", test_data, strlen (test_data));

	/* Reload now that we have this new file */
	p11_token_load (test.token);

	handle = p11_index_find (test.index, &match, 1);

	rv = p11_index_update (test.index, handle, p11_attrs_dup (second));
	assert_num_eq (rv, CKR_OK);

	/* Now read in the file and make sure it has all the objects */
	path = p11_path_build (test.directory, "Test.p11-kit", NULL);
	ret = p11_parse_file (test.parser, path, NULL, 0);
	assert_num_eq (ret, P11_PARSE_SUCCESS);
	free (path);

	parsed = p11_parser_parsed (test.parser);
	assert_num_eq (parsed->num, 3);

	/* The modified one will be first */
	test_check_attrs (second, parsed->elem[0]);
	test_check_attrs (first, parsed->elem[1]);
	test_check_attrs (third, parsed->elem[2]);
}

static void
test_remove_one (void)
{
	const char *test_data =
		"[p11-kit-object-v1]\n"
		"class: data\n"
		"label: \"first\"\n"
		"value: \"1\"\n"
		"\n";

	CK_ATTRIBUTE match = { CKA_LABEL, "first", 5 };

	CK_OBJECT_HANDLE handle;
	CK_RV rv;

	p11_test_file_write (test.directory, "Test.p11-kit", test_data, strlen (test_data));
	test_check_directory (test.directory, ("Test.p11-kit", NULL));

	/* Reload now that we have this new file */
	p11_token_load (test.token);

	handle = p11_index_find (test.index, &match, 1);
	assert_num_cmp (handle, !=, 0);

	rv = p11_index_remove (test.index, handle);
	assert_num_eq (rv, CKR_OK);

	/* No other files in the test directory, all files gone */
	test_check_directory (test.directory, (NULL, NULL));
}

static void
test_remove_multiple (void)
{
	const char *test_data =
		"[p11-kit-object-v1]\n"
		"class: data\n"
		"label: \"first\"\n"
		"value: \"1\"\n"
		"\n"
		"[p11-kit-object-v1]\n"
		"class: data\n"
		"label: \"second\"\n"
		"value: \"2\"\n"
		"\n"
		"[p11-kit-object-v1]\n"
		"class: data\n"
		"label: \"third\"\n"
		"value: \"3\"\n";

	CK_ATTRIBUTE first[] = {
		{ CKA_CLASS, &data, sizeof (data) },
		{ CKA_LABEL, "first", 5 },
		{ CKA_VALUE, "1", 1 },
		{ CKA_INVALID },
	};

	CK_ATTRIBUTE third[] = {
		{ CKA_CLASS, &data, sizeof (data) },
		{ CKA_LABEL, "third", 5 },
		{ CKA_VALUE, "3", 1 },
		{ CKA_INVALID },
	};

	CK_ATTRIBUTE match = { CKA_LABEL, "second", 6 };

	CK_OBJECT_HANDLE handle;
	p11_array *parsed;
	char *path;
	int ret;
	CK_RV rv;

	p11_test_file_write (test.directory, "Test.p11-kit", test_data, strlen (test_data));

	/* Reload now that we have this new file */
	p11_token_load (test.token);

	handle = p11_index_find (test.index, &match, 1);
	assert_num_cmp (handle, !=, 0);

	rv = p11_index_remove (test.index, handle);
	assert_num_eq (rv, CKR_OK);

	/* Now read in the file and make sure it has all the objects */
	path = p11_path_build (test.directory, "Test.p11-kit", NULL);
	ret = p11_parse_file (test.parser, path, NULL, 0);
	assert_num_eq (ret, P11_PARSE_SUCCESS);
	free (path);

	parsed = p11_parser_parsed (test.parser);
	assert_num_eq (parsed->num, 2);

	/* The modified one will be first */
	test_check_attrs (first, parsed->elem[0]);
	test_check_attrs (third, parsed->elem[1]);
}

int
main (int argc,
      char *argv[])
{
	p11_fixture (setup, teardown);
	p11_testx (test_token_load, SRCDIR "/trust/input", "/token/load");
	p11_testx (test_token_flags, SRCDIR "/trust/input", "/token/flags");
	p11_testx (test_token_path, "/wheee", "/token/path");
	p11_testx (test_token_label, "/wheee", "/token/label");
	p11_testx (test_token_slot, "/unneeded", "/token/slot");

	p11_fixture (NULL, NULL);
	p11_test (test_not_writable, "/token/not-writable");
	p11_test (test_writable_no_exist, "/token/writable-no-exist");

	p11_fixture (setup_temp, teardown_temp);
	p11_test (test_writable_exists, "/token/writable-exists");
	p11_test (test_load_found, "/token/load-found");
	p11_test (test_load_already, "/token/load-already");
	p11_test (test_load_unreadable, "/token/load-unreadable");
	p11_test (test_load_gone, "/token/load-gone");
	p11_test (test_reload_changed, "/token/reload-changed");
	p11_test (test_reload_gone, "/token/reload-gone");
	p11_test (test_reload_no_origin, "/token/reload-no-origin");
	p11_test (test_write_new, "/token/write-new");
	p11_test (test_write_no_label, "/token/write-no-label");
	p11_test (test_modify_multiple, "/token/modify-multiple");
	p11_test (test_remove_one, "/token/remove-one");
	p11_test (test_remove_multiple, "/token/remove-multiple");

	return p11_test_run (argc, argv);
}
