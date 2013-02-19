/*
 * Copyright (c) 2013 Red Hat Inc
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
 * Author: Stef Walter <stefw@redhat.com>
 */

#include "config.h"
#include "CuTest.h"

#include "dict.h"
#include "library.h"
#include "log.h"
#include "mock.h"
#include "modules.h"
#include "p11-kit.h"
#include "virtual.h"

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

static CK_FUNCTION_LIST_PTR
setup_mock_module (CuTest *tc,
                   CK_SESSION_HANDLE *session)
{
	CK_FUNCTION_LIST_PTR module;
	CK_RV rv;

	p11_lock ();
	p11_log_force = true;

	rv = p11_module_load_inlock_reentrant (&mock_module, 0, &module);
	CuAssertTrue (tc, rv == CKR_OK);
	CuAssertPtrNotNull (tc, module);
	CuAssertTrue (tc, p11_virtual_is_wrapper (module));

	p11_unlock ();

	rv = p11_kit_module_initialize (module);
	CuAssertTrue (tc, rv == CKR_OK);

	if (session) {
		rv = (module->C_OpenSession) (MOCK_SLOT_ONE_ID,
		                              CKF_RW_SESSION | CKF_SERIAL_SESSION,
		                              NULL, NULL, session);
		CuAssertTrue (tc, rv == CKR_OK);
	}

	return module;
}

static void
teardown_mock_module (CuTest *tc,
                      CK_FUNCTION_LIST_PTR module)
{
	CK_RV rv;

	rv = p11_kit_module_finalize (module);
	CuAssertTrue (tc, rv == CKR_OK);

	p11_lock ();

	rv = p11_module_release_inlock_reentrant (module);
	CuAssertTrue (tc, rv == CKR_OK);

	p11_unlock ();
}

/* Bring in all the mock module tests */
#include "test-mock.c"

int
main (void)
{
	CuString *output = CuStringNew ();
	CuSuite* suite = CuSuiteNew ();
	int ret;

	putenv ("P11_KIT_STRICT=1");
	p11_library_init ();
	mock_module_init ();

	test_mock_add_tests (suite);

	p11_kit_be_quiet ();
	p11_log_output = false;

	CuSuiteRun (suite);
	CuSuiteSummary (suite, output);
	CuSuiteDetails (suite, output);
	printf ("%s\n", output->buffer);
	ret = suite->failCount;
	CuSuiteDelete (suite);
	CuStringDelete (output);
	return ret;
}
