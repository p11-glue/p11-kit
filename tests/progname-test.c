/*
 * Copyright (c) 2012 Stefan Walter
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
 * Author: Stef Walter <stef@thewalter.net>
 */

#include "config.h"
#include "CuTest.h"

#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "p11-kit/uri.h"
#include "p11-kit/p11-kit.h"
#include "p11-kit/private.h"

static void
test_progname_default (CuTest *tc)
{
	const char *progname;

	progname = _p11_get_progname_unlocked ();
	CuAssertStrEquals (tc, "progname-test", progname);
}

static void
test_progname_set (CuTest *tc)
{
	const char *progname;

	p11_kit_set_progname ("love-generation");

	progname = _p11_get_progname_unlocked ();
	CuAssertStrEquals (tc, "love-generation", progname);

	_p11_set_progname_unlocked (NULL);

	progname = _p11_get_progname_unlocked ();
	CuAssertStrEquals (tc, "progname-test", progname);
}

/* Defined in util.c */
extern char *_p11_my_progname;

static void
test_progname_uninit_clears (CuTest *tc)
{
	_p11_set_progname_unlocked ("love-generation");
	CuAssertStrEquals (tc, "love-generation", _p11_my_progname);

	/* Inititialize should clear above variable */
	_p11_library_uninit ();

	CuAssertPtrEquals (tc, NULL, _p11_my_progname);
}

int
main (void)
{
	CuString *output = CuStringNew ();
	CuSuite* suite = CuSuiteNew ();
	int ret;

	_p11_library_init ();

	SUITE_ADD_TEST (suite, test_progname_default);
	SUITE_ADD_TEST (suite, test_progname_set);

	/* This test should be last, as it uninitializes the library */
	SUITE_ADD_TEST (suite, test_progname_uninit_clears);

	CuSuiteRun (suite);
	CuSuiteSummary (suite, output);
	CuSuiteDetails (suite, output);
	printf ("%s\n", output->buffer);
	ret = suite->failCount;
	CuSuiteDelete (suite);
	CuStringDelete (output);
	return ret;
}
