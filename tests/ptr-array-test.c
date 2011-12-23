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

#include "ptr-array.h"

static void
test__p11_ptr_array_create (CuTest *tc)
{
	ptr_array_t *array;

	array = _p11_ptr_array_create (NULL);
	CuAssertPtrNotNull (tc, array);
	_p11_ptr_array_free (array);
}

static void
test__p11_ptr_array_free_null (CuTest *tc)
{
	_p11_ptr_array_free (NULL);
}

static void
destroy_value (void *data)
{
	int *value = data;
	*value = 2;
}

static void
test__p11_ptr_array_free_destroys (CuTest *tc)
{
	ptr_array_t *array;
	int value = 0;

	array = _p11_ptr_array_create (destroy_value);
	CuAssertPtrNotNull (tc, array);
	if (!_p11_ptr_array_add (array, &value))
		CuFail (tc, "should not be reached");
	_p11_ptr_array_free (array);

	CuAssertIntEquals (tc, 2, value);
}

#if 0
static void
test__p11_hash_iterate (CuTest *tc)
{
	hash_t *ht;
	hash_iter_t hi;
	int key = 1;
	int value = 2;
	void *pkey;
	void *pvalue;
	int ret;

	ht = _p11_hash_create (_p11_hash_direct_hash, _p11_hash_direct_equal, NULL, NULL);
	CuAssertPtrNotNull (tc, ht);
	if (!_p11_hash_set (ht, &key, &value))
		CuFail (tc, "should not be reached");

	_p11_hash_iterate (ht, &hi);

	ret = _p11_hash_next (&hi, &pkey, &pvalue);
	CuAssertIntEquals (tc, 1, ret);
	CuAssertPtrEquals (tc, pkey, &key);
	CuAssertPtrEquals (tc, pvalue, &value);

	ret = _p11_hash_next (&hi, &pkey, &pvalue);
	CuAssertIntEquals (tc, 0, ret);

	_p11_hash_free (ht);
}

#endif

static void
test__p11_ptr_array_add (CuTest *tc)
{
	char *value = "VALUE";
	char *check;
	ptr_array_t *array;

	array = _p11_ptr_array_create (NULL);
	if (!_p11_ptr_array_add (array, value))
		CuFail (tc, "should not be reached");

	CuAssertIntEquals (tc, 1, _p11_ptr_array_count (array));

	check = _p11_ptr_array_at (array, 0);
	CuAssertPtrEquals (tc, check, value);

	_p11_ptr_array_free (array);
}

static void
test__p11_ptr_array_add_remove (CuTest *tc)
{
	char *value = "VALUE";
	char *check;
	ptr_array_t *array;

	array = _p11_ptr_array_create (NULL);
	if (!_p11_ptr_array_add (array, value))
		CuFail (tc, "should not be reached");

	CuAssertIntEquals (tc, 1, _p11_ptr_array_count (array));

	check = _p11_ptr_array_at (array, 0);
	CuAssertPtrEquals (tc, check, value);

	_p11_ptr_array_remove (array, 0);

	CuAssertIntEquals (tc, 0, _p11_ptr_array_count (array));

	_p11_ptr_array_free (array);
}

static void
test__p11_ptr_array_remove_destroys (CuTest *tc)
{
	ptr_array_t *array;
	int value = 0;

	array = _p11_ptr_array_create (destroy_value);
	if (!_p11_ptr_array_add (array, &value))
		CuFail (tc, "should not be reached");

	_p11_ptr_array_remove (array, 0);

	CuAssertIntEquals (tc, 2, value);

	/* should not be destroyed again */
	value = 0;

	_p11_ptr_array_free (array);

	CuAssertIntEquals (tc, 0, value);
}

static void
test__p11_ptr_array_remove_and_count (CuTest *tc)
{
	ptr_array_t *array;
	int *value;
	int i;

	array = _p11_ptr_array_create (free);

	CuAssertIntEquals (tc, 0, _p11_ptr_array_count (array));

	for (i = 0; i < 20000; ++i) {
		value = malloc (sizeof (int));
		*value = i;
		if (!_p11_ptr_array_add (array, value))
			CuFail (tc, "should not be reached");
		CuAssertIntEquals (tc, i + 1, _p11_ptr_array_count (array));
	}

	for (i = 10; i < 20000; ++i) {
		_p11_ptr_array_remove (array, 10);
		CuAssertIntEquals (tc, 20010 - (i + 1), _p11_ptr_array_count (array));
	}

	CuAssertIntEquals (tc, 10, _p11_ptr_array_count (array));

	_p11_ptr_array_free (array);
}

static void
test__p11_ptr_array_snapshot (CuTest *tc)
{
	ptr_array_t *array;
	void **snapshot;

	array = _p11_ptr_array_create (NULL);

	_p11_ptr_array_add (array, "1");
	_p11_ptr_array_add (array, "2");
	_p11_ptr_array_add (array, "3");
	_p11_ptr_array_add (array, "4");
	CuAssertIntEquals (tc, 4, _p11_ptr_array_count (array));

	snapshot = _p11_ptr_array_snapshot (array);

	CuAssertStrEquals (tc, "1", snapshot[0]);
	CuAssertStrEquals (tc, "2", snapshot[1]);
	CuAssertStrEquals (tc, "3", snapshot[2]);
	CuAssertStrEquals (tc, "4", snapshot[3]);

	free (snapshot);
	_p11_ptr_array_free (array);
}

int
main (void)
{
	CuString *output = CuStringNew ();
	CuSuite* suite = CuSuiteNew ();
	int ret;

	SUITE_ADD_TEST (suite, test__p11_ptr_array_create);
	SUITE_ADD_TEST (suite, test__p11_ptr_array_add);
	SUITE_ADD_TEST (suite, test__p11_ptr_array_add_remove);
	SUITE_ADD_TEST (suite, test__p11_ptr_array_remove_destroys);
	SUITE_ADD_TEST (suite, test__p11_ptr_array_remove_and_count);
	SUITE_ADD_TEST (suite, test__p11_ptr_array_free_null);
	SUITE_ADD_TEST (suite, test__p11_ptr_array_free_destroys);
	SUITE_ADD_TEST (suite, test__p11_ptr_array_snapshot);

	CuSuiteRun (suite);
	CuSuiteSummary (suite, output);
	CuSuiteDetails (suite, output);
	printf ("%s\n", output->buffer);
	ret = suite->failCount;
	CuSuiteDelete (suite);
	CuStringDelete (output);

	return ret;
}
