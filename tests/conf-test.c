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
#include "p11-kit.h"

static void
test_parse_conf_1 (CuTest *tc)
{
	hash_t *ht;
	const char *value;

	ht = _p11_conf_parse_file (SRCDIR "/files/test-1.conf", 0);
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

	ht = _p11_conf_parse_file (SRCDIR "/files/non-existant.conf", CONF_IGNORE_MISSING);
	CuAssertPtrNotNull (tc, ht);

	CuAssertIntEquals (tc, 0, hash_count (ht));
	CuAssertPtrEquals (tc, NULL, (void*)p11_kit_message ());
	hash_free (ht);
}

static void
test_parse_fail_missing (CuTest *tc)
{
	hash_t *ht;

	ht = _p11_conf_parse_file (SRCDIR "/files/non-existant.conf", 0);
	CuAssertPtrEquals (tc, ht, NULL);
	CuAssertPtrNotNull (tc, p11_kit_message ());
}

static void
test_merge_defaults (CuTest *tc)
{
	hash_t *values;
	hash_t *defaults;

	values = hash_create (hash_string_hash, hash_string_equal, free, free);
	defaults = hash_create (hash_string_hash, hash_string_equal, free, free);

	hash_set (values, strdup ("one"), strdup ("real1"));
	hash_set (values, strdup ("two"), strdup ("real2"));

	hash_set (defaults, strdup ("two"), strdup ("default2"));
	hash_set (defaults, strdup ("three"), strdup ("default3"));

	if (_p11_conf_merge_defaults (values, defaults) < 0)
		CuFail (tc, "should not be reached");

	hash_free (defaults);

	CuAssertStrEquals (tc, hash_get (values, "one"), "real1");
	CuAssertStrEquals (tc, hash_get (values, "two"), "real2");
	CuAssertStrEquals (tc, hash_get (values, "three"), "default3");

	hash_free (values);
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
	SUITE_ADD_TEST (suite, test_merge_defaults);

	p11_kit_be_quiet ();

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
