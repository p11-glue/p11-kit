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

#include <sys/types.h>
#include <sys/wait.h>

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "p11-kit/p11-kit.h"

#include "mock-module.h"

static CK_RV
mock_C_Initialize__with_fork (CK_VOID_PTR init_args)
{
	CK_RV rv;
	pid_t child;
	pid_t ret;
	int status;

	rv = mock_C_Initialize (init_args);
	assert (rv == CKR_OK);

	/* Fork during the initialization */
	child = fork ();
	if (child == 0) {
		sleep (1);
		exit (66);
	}

	ret = waitpid (child, &status, 0);
	assert (ret == child);
	assert (WIFEXITED (status));
	assert (WEXITSTATUS (status) == 66);

	return CKR_OK;
}

static void
test_fork_initialization (CuTest *tc)
{
	CK_FUNCTION_LIST module;
	CK_RV rv;

	/* Build up our own function list */
	memcpy (&module, &mock_module_no_slots, sizeof (CK_FUNCTION_LIST));
	module.C_Initialize = mock_C_Initialize__with_fork;

	rv = p11_kit_initialize_module (&module);
	CuAssertTrue (tc, rv == CKR_OK);

	rv = p11_kit_finalize_module (&module);
	CuAssertTrue (tc, rv == CKR_OK);
}

int
main (void)
{
	CuString *output = CuStringNew ();
	CuSuite* suite = CuSuiteNew ();
	int ret;

	SUITE_ADD_TEST (suite, test_fork_initialization);

	CuSuiteRun (suite);
	CuSuiteSummary (suite, output);
	CuSuiteDetails (suite, output);
	printf ("%s\n", output->buffer);
	ret = suite->failCount;
	CuSuiteDelete (suite);
	CuStringDelete (output);

	return ret;
}

#include "CuTest.c"
