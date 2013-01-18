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

#include "array.h"

static void
test_p11_array_create (CuTest *tc)
{
	p11_array *array;

	array = p11_array_new (NULL);
	CuAssertPtrNotNull (tc, array);
	p11_array_free (array);
}

static void
test_p11_array_free_null (CuTest *tc)
{
	p11_array_free (NULL);
}

static void
destroy_value (void *data)
{
	int *value = data;
	*value = 2;
}

static void
test_p11_array_free_destroys (CuTest *tc)
{
	p11_array *array;
	int value = 0;

	array = p11_array_new (destroy_value);
	CuAssertPtrNotNull (tc, array);
	if (!p11_array_push (array, &value))
		CuFail (tc, "should not be reached");
	p11_array_free (array);

	CuAssertIntEquals (tc, 2, value);
}

static void
test_p11_array_add (CuTest *tc)
{
	char *value = "VALUE";
	p11_array *array;

	array = p11_array_new (NULL);
	if (!p11_array_push (array, value))
		CuFail (tc, "should not be reached");

	CuAssertIntEquals (tc, 1, array->num);
	CuAssertPtrEquals (tc, array->elem[0], value);

	p11_array_free (array);
}

static void
test_p11_array_add_remove (CuTest *tc)
{
	char *value = "VALUE";
	p11_array *array;

	array = p11_array_new (NULL);
	if (!p11_array_push (array, value))
		CuFail (tc, "should not be reached");

	CuAssertIntEquals (tc, 1, array->num);

	CuAssertPtrEquals (tc, array->elem[0], value);

	p11_array_remove (array, 0);

	CuAssertIntEquals (tc, 0, array->num);

	p11_array_free (array);
}

static void
test_p11_array_remove_destroys (CuTest *tc)
{
	p11_array *array;
	int value = 0;

	array = p11_array_new (destroy_value);
	if (!p11_array_push (array, &value))
		CuFail (tc, "should not be reached");

	p11_array_remove (array, 0);

	CuAssertIntEquals (tc, 2, value);

	/* should not be destroyed again */
	value = 0;

	p11_array_free (array);

	CuAssertIntEquals (tc, 0, value);
}

static void
test_p11_array_remove_and_count (CuTest *tc)
{
	p11_array *array;
	int *value;
	int i;

	array = p11_array_new (free);

	CuAssertIntEquals (tc, 0, array->num);

	for (i = 0; i < 20000; ++i) {
		value = malloc (sizeof (int));
		*value = i;
		if (!p11_array_push (array, value))
			CuFail (tc, "should not be reached");
		CuAssertIntEquals (tc, i + 1, array->num);
	}

	for (i = 10; i < 20000; ++i) {
		p11_array_remove (array, 10);
		CuAssertIntEquals (tc, 20010 - (i + 1), array->num);
	}

	CuAssertIntEquals (tc, 10, array->num);

	p11_array_free (array);
}

static void
test_p11_array_clear_destroys (CuTest *tc)
{
	p11_array *array;
	int value = 0;

	array = p11_array_new (destroy_value);
	if (!p11_array_push (array, &value))
		CuFail (tc, "should not be reached");

	CuAssertIntEquals (tc, 1, array->num);

	p11_array_clear (array);

	CuAssertIntEquals (tc, 2, value);
	CuAssertIntEquals (tc, 0, array->num);

	/* should not be destroyed again */
	value = 0;

	p11_array_free (array);

	CuAssertIntEquals (tc, 0, value);
}


int
main (void)
{
	CuString *output = CuStringNew ();
	CuSuite* suite = CuSuiteNew ();
	int ret;

	SUITE_ADD_TEST (suite, test_p11_array_create);
	SUITE_ADD_TEST (suite, test_p11_array_add);
	SUITE_ADD_TEST (suite, test_p11_array_add_remove);
	SUITE_ADD_TEST (suite, test_p11_array_remove_destroys);
	SUITE_ADD_TEST (suite, test_p11_array_remove_and_count);
	SUITE_ADD_TEST (suite, test_p11_array_free_null);
	SUITE_ADD_TEST (suite, test_p11_array_free_destroys);
	SUITE_ADD_TEST (suite, test_p11_array_clear_destroys);

	CuSuiteRun (suite);
	CuSuiteSummary (suite, output);
	CuSuiteDetails (suite, output);
	printf ("%s\n", output->buffer);
	ret = suite->failCount;
	CuSuiteDelete (suite);
	CuStringDelete (output);

	return ret;
}
