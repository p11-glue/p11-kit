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

#include "attrs.h"
#include "debug.h"
#include "library.h"
#include "session.h"
#include "token.h"

struct {
	p11_token *token;
	p11_session *session;
} test;

static void
setup (CuTest *cu)
{
	test.token = p11_token_new ("", "");
	CuAssertPtrNotNull (cu, test.token);

	test.session = p11_session_new (test.token);
	CuAssertPtrNotNull (cu, test.session);
}

static void
teardown (CuTest *cu)
{
	p11_session_free (test.session);
	p11_token_free (test.token);
	memset (&test, 0, sizeof (test));
}

static void
test_session_add_get (CuTest *cu)
{
	CK_ATTRIBUTE original[] = {
		{ CKA_LABEL, "yay", 3 },
		{ CKA_VALUE, "eight", 5 },
		{ CKA_INVALID }
	};

	CK_ATTRIBUTE *attrs;
	CK_ATTRIBUTE *check;
	CK_OBJECT_HANDLE handle;
	CK_BBOOL token;

	setup (cu);

	attrs = p11_attrs_dup (original);
	p11_session_add_object (test.session, attrs, &handle);

	check = p11_session_get_object (test.session, handle, &token);

	CuAssertPtrEquals (cu, attrs, check);
	CuAssertTrue (cu, token == CK_FALSE);

	check = p11_session_get_object (test.session, 1UL, &token);
	CuAssertPtrEquals (cu, NULL, check);

	teardown (cu);
}

static void
test_session_del (CuTest *cu)
{
	CK_ATTRIBUTE original[] = {
		{ CKA_LABEL, "yay", 3 },
		{ CKA_VALUE, "eight", 5 },
		{ CKA_INVALID }
	};

	CK_ATTRIBUTE *attrs;
	CK_ATTRIBUTE *check;
	CK_OBJECT_HANDLE handle;
	CK_BBOOL token;
	CK_RV rv;

	setup (cu);

	attrs = p11_attrs_dup (original);
	p11_session_add_object (test.session, attrs, &handle);

	check = p11_session_get_object (test.session, handle, &token);
	CuAssertPtrEquals (cu, attrs, check);
	CuAssertTrue (cu, token == CK_FALSE);

	rv = p11_session_del_object (test.session, 1UL);
	CuAssertTrue (cu, rv == CKR_OBJECT_HANDLE_INVALID);

	rv = p11_session_del_object (test.session, handle);
	CuAssertTrue (cu, rv == CKR_OK);

	check = p11_session_get_object (test.session, handle, &token);
	CuAssertPtrEquals (cu, NULL, check);

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

	SUITE_ADD_TEST (suite, test_session_add_get);
	SUITE_ADD_TEST (suite, test_session_del);

	CuSuiteRun (suite);
	CuSuiteSummary (suite, output);
	CuSuiteDetails (suite, output);
	printf ("%s\n", output->buffer);
	ret = suite->failCount;
	CuSuiteDelete (suite);
	CuStringDelete (output);

	return ret;
}
