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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "conf.h"

static int n_errors = 0;

static void
error_func (const char *buffer)
{
	++n_errors;
}

static void
test_parse_conf_1 (CuTest *tc)
{
	hash_t *ht;
	const char *value;

	ht = conf_parse_file (SRCDIR "/files/test-1.conf", 0, error_func);
	CuAssertPtrNotNull (tc, ht);

	value = hash_get (ht, "key1");
	CuAssertStrEquals (tc, "value1", value);

	value = hash_get (ht, "with-colon");
	CuAssertStrEquals (tc, "value-of-colon", value);

	value = hash_get (ht, "with-whitespace");
	CuAssertStrEquals (tc, "value-with-whitespace", value);

	value = hash_get (ht, "embedded-comment");
	CuAssertStrEquals (tc, "this is # not a comment", value);

	hash_free (ht);
}

static void
test_parse_ignore_missing (CuTest *tc)
{
	hash_t *ht;

	n_errors = 0;
	ht = conf_parse_file (SRCDIR "/files/non-existant.conf", CONF_IGNORE_MISSING, error_func);
	CuAssertPtrNotNull (tc, ht);

	CuAssertIntEquals (tc, 0, hash_count (ht));
	CuAssertIntEquals (tc, 0, n_errors);
	hash_free (ht);
}

static void
test_parse_fail_missing (CuTest *tc)
{
	hash_t *ht;

	n_errors = 0;
	ht = conf_parse_file (SRCDIR "/files/non-existant.conf", 0, error_func);
	CuAssertPtrEquals (tc, ht, NULL);
	CuAssertIntEquals (tc, 1, n_errors);
}

int
main (void)
{
	CuString *output = CuStringNew ();
	CuSuite* suite = CuSuiteNew ();
	int ret;

	SUITE_ADD_TEST (suite, test_parse_conf_1);
	SUITE_ADD_TEST (suite, test_parse_ignore_missing);
	SUITE_ADD_TEST (suite, test_parse_fail_missing);

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
