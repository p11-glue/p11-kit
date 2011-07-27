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

#include "hashmap.h"

static void
test_hash_create (CuTest *tc)
{
	hashmap *map;

	map = hash_create (hash_direct_hash, hash_direct_equal, NULL, NULL);
	CuAssertPtrNotNull (tc, map);
	hash_free (map);
}

static void
test_hash_free_null (CuTest *tc)
{
	hash_free (NULL);
}

static void
destroy_key (void *data)
{
	int *key = data;
	*key = 1;
}

static void
destroy_value (void *data)
{
	int *value = data;
	*value = 2;
}

static void
test_hash_free_destroys (CuTest *tc)
{
	hashmap *map;
	int key = 0;
	int value = 0;

	map = hash_create (hash_direct_hash, hash_direct_equal, destroy_key, destroy_value);
	CuAssertPtrNotNull (tc, map);
	if (!hash_set (map, &key, &value))
		CuFail (tc, "should not be reached");
	hash_free (map);

	CuAssertIntEquals (tc, 1, key);
	CuAssertIntEquals (tc, 2, value);
}

static void
test_hash_iterate (CuTest *tc)
{
	hashmap *map;
	hashiter iter;
	int key = 1;
	int value = 2;
	void *pkey;
	void *pvalue;
	int ret;

	map = hash_create (hash_direct_hash, hash_direct_equal, NULL, NULL);
	CuAssertPtrNotNull (tc, map);
	if (!hash_set (map, &key, &value))
		CuFail (tc, "should not be reached");

	hash_iterate (map, &iter);

	ret = hash_next (&iter, &pkey, &pvalue);
	CuAssertIntEquals (tc, 1, ret);
	CuAssertPtrEquals (tc, pkey, &key);
	CuAssertPtrEquals (tc, pvalue, &value);

	ret = hash_next (&iter, &pkey, &pvalue);
	CuAssertIntEquals (tc, 0, ret);

	hash_free (map);
}

static void
test_hash_set_get (CuTest *tc)
{
	char *key = "KEY";
	char *value = "VALUE";
	char *check;
	hashmap *map;

	map = hash_create (hash_string_hash, hash_string_equal, NULL, NULL);
	hash_set (map, key, value);
	check = hash_get (map, key);
	CuAssertPtrEquals (tc, check, value);

	hash_free (map);
}

static void
test_hash_set_get_remove (CuTest *tc)
{
	char *key = "KEY";
	char *value = "VALUE";
	char *check;
	hashmap *map;
	int ret;

	map = hash_create (hash_string_hash, hash_string_equal, NULL, NULL);

	if (!hash_set (map, key, value))
		CuFail (tc, "should not be reached");

	check = hash_get (map, key);
	CuAssertPtrEquals (tc, check, value);

	ret = hash_remove (map, key);
	CuAssertIntEquals (tc, ret, 1);
	ret = hash_remove (map, key);
	CuAssertIntEquals (tc, ret, 0);

	check = hash_get (map, key);
	CuAssert (tc, "should be null", check == NULL);

	hash_free (map);
}

static void
test_hash_set_get_clear (CuTest *tc)
{
	char *key = "KEY";
	char *value = "VALUE";
	char *check;
	hashmap *map;

	map = hash_create (hash_direct_hash, hash_direct_equal, NULL, NULL);

	if (!hash_set (map, key, value))
		CuFail (tc, "should not be reached");

	check = hash_get (map, key);
	CuAssertPtrEquals (tc, check, value);

	hash_clear (map);

	check = hash_get (map, key);
	CuAssert (tc, "should be null", check == NULL);

	hash_free (map);
}

static void
test_hash_remove_destroys (CuTest *tc)
{
	hashmap *map;
	int key = 0;
	int value = 0;
	int ret;

	map = hash_create (hash_direct_hash, hash_direct_equal, destroy_key, destroy_value);
	CuAssertPtrNotNull (tc, map);
	if (!hash_set (map, &key, &value))
		CuFail (tc, "should not be reached");

	ret = hash_remove (map, &key);
	CuAssertIntEquals (tc, ret, 1);
	CuAssertIntEquals (tc, 1, key);
	CuAssertIntEquals (tc, 2, value);

	/* should not be destroyed again */
	key = 0;
	value = 0;

	ret = hash_remove (map, &key);
	CuAssertIntEquals (tc, ret, 0);
	CuAssertIntEquals (tc, 0, key);
	CuAssertIntEquals (tc, 0, value);

	/* should not be destroyed again */
	key = 0;
	value = 0;

	hash_free (map);

	CuAssertIntEquals (tc, 0, key);
	CuAssertIntEquals (tc, 0, value);
}

static void
test_hash_set_destroys (CuTest *tc)
{
	hashmap *map;
	int key = 0;
	int value = 0;
	int value2 = 0;
	int ret;

	map = hash_create (hash_direct_hash, hash_direct_equal, destroy_key, destroy_value);
	CuAssertPtrNotNull (tc, map);
	if (!hash_set (map, &key, &value))
		CuFail (tc, "should not be reached");

	ret = hash_set (map, &key, &value2);
	CuAssertIntEquals (tc, ret, 1);
	CuAssertIntEquals (tc, 0, key);
	CuAssertIntEquals (tc, 2, value);
	CuAssertIntEquals (tc, 0, value2);

	key = 0;
	value = 0;
	value2 = 0;

	hash_free (map);

	CuAssertIntEquals (tc, 1, key);
	CuAssertIntEquals (tc, 0, value);
	CuAssertIntEquals (tc, 2, value2);
}


static void
test_hash_clear_destroys (CuTest *tc)
{
	hashmap *map;
	int key = 0;
	int value = 0;

	map = hash_create (hash_direct_hash, hash_direct_equal, destroy_key, destroy_value);
	CuAssertPtrNotNull (tc, map);
	if (!hash_set (map, &key, &value))
		CuFail (tc, "should not be reached");

	hash_clear (map);
	CuAssertIntEquals (tc, 1, key);
	CuAssertIntEquals (tc, 2, value);

	/* should not be destroyed again */
	key = 0;
	value = 0;

	hash_clear (map);
	CuAssertIntEquals (tc, 0, key);
	CuAssertIntEquals (tc, 0, value);

	/* should not be destroyed again */
	key = 0;
	value = 0;

	hash_free (map);

	CuAssertIntEquals (tc, 0, key);
	CuAssertIntEquals (tc, 0, value);
}

static unsigned int
test_hash_intptr_with_collisions (const void *data)
{
	/* lots and lots of collisions, only returns 100 values */
	return (unsigned int)(*((int*)data) % 100);
}

static void
test_hash_add_check_lots_and_collisions (CuTest *tc)
{
	hashmap *map;
	int *value;
	int i;

	map = hash_create (test_hash_intptr_with_collisions,
	                  hash_intptr_equal, NULL, free);

	for (i = 0; i < 20000; ++i) {
		value = malloc (sizeof (int));
		*value = i;
		if (!hash_set (map, value, value))
			CuFail (tc, "should not be reached");
	}

	for (i = 0; i < 20000; ++i) {
		value = hash_get (map, &i);
		CuAssertPtrNotNull (tc, value);
		CuAssertIntEquals (tc, i, *value);
	}

	hash_free (map);
}

static void
test_hash_count (CuTest *tc)
{
	hashmap *map;
	int *value;
	int i, ret;

	map = hash_create (hash_intptr_hash, hash_intptr_equal, NULL, free);

	CuAssertIntEquals (tc, 0, hash_size (map));

	for (i = 0; i < 20000; ++i) {
		value = malloc (sizeof (int));
		*value = i;
		if (!hash_set (map, value, value))
			CuFail (tc, "should not be reached");
		CuAssertIntEquals (tc, i + 1, hash_size (map));
	}

	for (i = 0; i < 20000; ++i) {
		ret = hash_remove (map, &i);
		CuAssertIntEquals (tc, 1, ret);
		CuAssertIntEquals (tc, 20000 - (i + 1), hash_size (map));
	}

	hash_clear (map);
	CuAssertIntEquals (tc, 0, hash_size (map));

	hash_free (map);
}

static void
test_hash_ulongptr (CuTest *tc)
{
	hashmap *map;
	unsigned long *value;
	unsigned long i;

	map = hash_create (hash_ulongptr_hash, hash_ulongptr_equal, NULL, free);

	for (i = 0; i < 20000; ++i) {
		value = malloc (sizeof (unsigned long));
		*value = i;
		if (!hash_set (map, value, value))
			CuFail (tc, "should not be reached");
	}

	for (i = 0; i < 20000; ++i) {
		value = hash_get (map, &i);
		CuAssertPtrNotNull (tc, value);
		CuAssertIntEquals (tc, i, *value);
	}

	hash_free (map);
}

int
main (void)
{
	CuString *output = CuStringNew ();
	CuSuite* suite = CuSuiteNew ();
	int ret;

	SUITE_ADD_TEST (suite, test_hash_create);
	SUITE_ADD_TEST (suite, test_hash_set_get);
	SUITE_ADD_TEST (suite, test_hash_set_get_remove);
	SUITE_ADD_TEST (suite, test_hash_remove_destroys);
	SUITE_ADD_TEST (suite, test_hash_set_get_clear);
	SUITE_ADD_TEST (suite, test_hash_set_destroys);
	SUITE_ADD_TEST (suite, test_hash_clear_destroys);
	SUITE_ADD_TEST (suite, test_hash_free_null);
	SUITE_ADD_TEST (suite, test_hash_free_destroys);
	SUITE_ADD_TEST (suite, test_hash_iterate);
	SUITE_ADD_TEST (suite, test_hash_add_check_lots_and_collisions);
	SUITE_ADD_TEST (suite, test_hash_count);
	SUITE_ADD_TEST (suite, test_hash_ulongptr);

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
