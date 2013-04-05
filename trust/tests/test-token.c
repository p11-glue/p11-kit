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
#include "pkcs11x.h"
#include "message.h"
#include "token.h"

struct {
	p11_token *token;
} test;

static void
setup (void *path)
{
	test.token = p11_token_new (333, path, "Label");
	assert_ptr_not_null (test.token);
}

static void
teardown (void *path)
{
	p11_token_free (test.token);
	memset (&test, 0, sizeof (test));
}

static void
test_token_load (void *path)
{
	p11_index *index;
	int count;

	count = p11_token_load (test.token);
	assert_num_eq (7, count);

	/* A certificate and trust object for each parsed object + builtin */
	index = p11_token_index (test.token);
	assert (((count - 1) * 2) + 1 <= p11_index_size (index));
}

static void
test_token_flags (void *path)
{
	CK_OBJECT_CLASS certificate = CKO_CERTIFICATE;
	CK_BBOOL falsev = CK_FALSE;
	CK_BBOOL truev = CK_TRUE;

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

int
main (int argc,
      char *argv[])
{
	p11_fixture (setup, teardown);
	p11_testx (test_token_load, SRCDIR "/input", "/token/load");
	p11_testx (test_token_flags, SRCDIR "/input", "/token/flags");

	p11_fixture (setup, teardown);
	p11_testx (test_token_path, "/wheee", "/token/path");
	p11_testx (test_token_label, "/wheee", "/token/label");
	p11_testx (test_token_slot, "/unneeded", "/token/slot");
	return p11_test_run (argc, argv);
}
