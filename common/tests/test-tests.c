/*
 * Copyright (c) 2013 Red Hat Inc.
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

#include <stdlib.h>
#include <stdio.h>

static void
test_success (CuTest *tc)
{
	/* Yup, nothing */
}


static void
test_failure (CuTest *tc)
{
	if (getenv ("TEST_FAIL"))
		CuFail (tc, "Unconditional test failure due to TEST_FAIL environment variable");
}

static void
test_memory (CuTest *tc)
{
	char *mem;

	if (getenv ("TEST_FAIL")) {
		mem = malloc (1);
		free (mem);
		*mem = 1;
	}
}


static void
test_leak (CuTest *tc)
{
	char *mem;

	if (getenv ("TEST_FAIL")) {
		mem = malloc (1);
		*mem = 1;
	}
}

int
main (void)
{
	CuString *output = CuStringNew ();
	CuSuite* suite = CuSuiteNew ();
	int ret;

	SUITE_ADD_TEST (suite, test_success);

	if (getenv ("TEST_FAIL")) {
		SUITE_ADD_TEST (suite, test_failure);
		SUITE_ADD_TEST (suite, test_memory);
		SUITE_ADD_TEST (suite, test_leak);
	}

	CuSuiteRun (suite);
	CuSuiteSummary (suite, output);
	CuSuiteDetails (suite, output);
	printf ("%s\n", output->buffer);
	ret = suite->failCount;
	CuSuiteDelete (suite);
	CuStringDelete (output);

	return ret;
}
