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

#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "dict.h"

static void
test_create (CuTest *tc)
{
	p11_dict *map;

	map = p11_dict_new (p11_dict_direct_hash, p11_dict_direct_equal, NULL, NULL);
	CuAssertPtrNotNull (tc, map);
	p11_dict_free (map);
}

static void
test_free_null (CuTest *tc)
{
	p11_dict_free (NULL);
}

typedef struct {
	int value;
	int freed;
} Key;

static unsigned int
key_hash (const void *ptr)
{
	const Key *k = ptr;
	assert (!k->freed);
	return p11_dict_intptr_hash (&k->value);
}

static int
key_equal (const void *one,
           const void *two)
{
	const Key *k1 = one;
	const Key *k2 = two;
	assert (!k1->freed);
	assert (!k2->freed);
	return p11_dict_intptr_equal (&k1->value, &k2->value);
}

static void
key_destroy (void *data)
{
	Key *k = data;
	assert (!k->freed);
	k->freed = 1;
}

static void
value_destroy (void *data)
{
	int *value = data;
	*value = 2;
}

static void
test_free_destroys (CuTest *tc)
{
	p11_dict *map;
	Key key = { 8, 0 };
	int value = 0;

	map = p11_dict_new (key_hash, key_equal, key_destroy, value_destroy);
	CuAssertPtrNotNull (tc, map);
	if (!p11_dict_set (map, &key, &value))
		CuFail (tc, "should not be reached");
	p11_dict_free (map);

	CuAssertIntEquals (tc, 1, key.freed);
	CuAssertIntEquals (tc, 2, value);
}

static void
test_iterate (CuTest *tc)
{
	p11_dict *map;
	p11_dictiter iter;
	int key = 1;
	int value = 2;
	void *pkey;
	void *pvalue;
	int ret;

	map = p11_dict_new (p11_dict_direct_hash, p11_dict_direct_equal, NULL, NULL);
	CuAssertPtrNotNull (tc, map);
	if (!p11_dict_set (map, &key, &value))
		CuFail (tc, "should not be reached");

	p11_dict_iterate (map, &iter);

	ret = p11_dict_next (&iter, &pkey, &pvalue);
	CuAssertIntEquals (tc, 1, ret);
	CuAssertPtrEquals (tc, pkey, &key);
	CuAssertPtrEquals (tc, pvalue, &value);

	ret = p11_dict_next (&iter, &pkey, &pvalue);
	CuAssertIntEquals (tc, 0, ret);

	p11_dict_free (map);
}

static void
test_set_get (CuTest *tc)
{
	char *key = "KEY";
	char *value = "VALUE";
	char *check;
	p11_dict *map;

	map = p11_dict_new (p11_dict_str_hash, p11_dict_str_equal, NULL, NULL);
	p11_dict_set (map, key, value);
	check = p11_dict_get (map, key);
	CuAssertPtrEquals (tc, check, value);

	p11_dict_free (map);
}

static void
test_set_get_remove (CuTest *tc)
{
	char *key = "KEY";
	char *value = "VALUE";
	char *check;
	p11_dict *map;
	int ret;

	map = p11_dict_new (p11_dict_str_hash, p11_dict_str_equal, NULL, NULL);

	if (!p11_dict_set (map, key, value))
		CuFail (tc, "should not be reached");

	check = p11_dict_get (map, key);
	CuAssertPtrEquals (tc, check, value);

	ret = p11_dict_remove (map, key);
	CuAssertIntEquals (tc, ret, 1);
	ret = p11_dict_remove (map, key);
	CuAssertIntEquals (tc, ret, 0);

	check = p11_dict_get (map, key);
	CuAssert (tc, "should be null", check == NULL);

	p11_dict_free (map);
}

static void
test_set_clear (CuTest *tc)
{
	char *key = "KEY";
	char *value = "VALUE";
	char *check;
	p11_dict *map;

	map = p11_dict_new (p11_dict_direct_hash, p11_dict_direct_equal, NULL, NULL);

	if (!p11_dict_set (map, key, value))
		CuFail (tc, "should not be reached");

	p11_dict_clear (map);

	check = p11_dict_get (map, key);
	CuAssert (tc, "should be null", check == NULL);

	p11_dict_free (map);
}

static void
test_remove_destroys (CuTest *tc)
{
	p11_dict *map;
	Key key = { 8, 0 };
	int value = 0;
	int ret;

	map = p11_dict_new (key_hash, key_equal, key_destroy, value_destroy);
	CuAssertPtrNotNull (tc, map);
	if (!p11_dict_set (map, &key, &value))
		CuFail (tc, "should not be reached");

	ret = p11_dict_remove (map, &key);
	CuAssertIntEquals (tc, ret, 1);
	CuAssertIntEquals (tc, 1, key.freed);
	CuAssertIntEquals (tc, 2, value);

	/* should not be destroyed again */
	key.freed = 0;
	value = 0;

	ret = p11_dict_remove (map, &key);
	CuAssertIntEquals (tc, ret, 0);
	CuAssertIntEquals (tc, 0, key.freed);
	CuAssertIntEquals (tc, 0, value);

	/* should not be destroyed again */
	key.freed = 0;
	value = 0;

	p11_dict_free (map);

	CuAssertIntEquals (tc, 0, key.freed);
	CuAssertIntEquals (tc, 0, value);
}

static void
test_set_destroys (CuTest *tc)
{
	p11_dict *map;
	Key key = { 8, 0 };
	Key key2 = { 8, 0 };
	int value, value2;
	int ret;

	map = p11_dict_new (key_hash, key_equal, key_destroy, value_destroy);
	CuAssertPtrNotNull (tc, map);
	if (!p11_dict_set (map, &key, &value))
		CuFail (tc, "should not be reached");

	key.freed = key2.freed = value = value2 = 0;

	/* Setting same key and value, should not be destroyed */
	ret = p11_dict_set (map, &key, &value);
	CuAssertIntEquals (tc, ret, 1);
	CuAssertIntEquals (tc, 0, key.freed);
	CuAssertIntEquals (tc, 0, key2.freed);
	CuAssertIntEquals (tc, 0, value);
	CuAssertIntEquals (tc, 0, value2);

	key.freed = key2.freed = value = value2 = 0;

	/* Setting a new key same value, key should be destroyed */
	ret = p11_dict_set (map, &key2, &value);
	CuAssertIntEquals (tc, ret, 1);
	CuAssertIntEquals (tc, 1, key.freed);
	CuAssertIntEquals (tc, 0, key2.freed);
	CuAssertIntEquals (tc, 0, value);
	CuAssertIntEquals (tc, 0, value2);

	key.freed = key2.freed = value = value2 = 0;

	/* Setting same key, new value, value should be destroyed */
	ret = p11_dict_set (map, &key2, &value2);
	CuAssertIntEquals (tc, ret, 1);
	CuAssertIntEquals (tc, 0, key.freed);
	CuAssertIntEquals (tc, 0, key2.freed);
	CuAssertIntEquals (tc, 2, value);
	CuAssertIntEquals (tc, 0, value2);

	key.freed = key2.freed = value = value2 = 0;

	/* Setting new key new value, both should be destroyed */
	ret = p11_dict_set (map, &key, &value);
	CuAssertIntEquals (tc, ret, 1);
	CuAssertIntEquals (tc, 0, key.freed);
	CuAssertIntEquals (tc, 1, key2.freed);
	CuAssertIntEquals (tc, 0, value);
	CuAssertIntEquals (tc, 2, value2);

	key.freed = key2.freed = value = value2 = 0;

	p11_dict_free (map);
	CuAssertIntEquals (tc, 1, key.freed);
	CuAssertIntEquals (tc, 2, value);
	CuAssertIntEquals (tc, 0, key2.freed);
	CuAssertIntEquals (tc, 0, value2);
}


static void
test_clear_destroys (CuTest *tc)
{
	p11_dict *map;
	Key key = { 18, 0 };
	int value = 0;

	map = p11_dict_new (key_hash, key_equal, key_destroy, value_destroy);
	CuAssertPtrNotNull (tc, map);
	if (!p11_dict_set (map, &key, &value))
		CuFail (tc, "should not be reached");

	p11_dict_clear (map);
	CuAssertIntEquals (tc, 1, key.freed);
	CuAssertIntEquals (tc, 2, value);

	/* should not be destroyed again */
	key.freed = 0;
	value = 0;

	p11_dict_clear (map);
	CuAssertIntEquals (tc, 0, key.freed);
	CuAssertIntEquals (tc, 0, value);

	/* should not be destroyed again */
	key.freed = 0;
	value = 0;

	p11_dict_free (map);

	CuAssertIntEquals (tc, 0, key.freed);
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
	p11_dict *map;
	int *value;
	int i;

	map = p11_dict_new (test_hash_intptr_with_collisions,
	                    p11_dict_intptr_equal, NULL, free);

	for (i = 0; i < 20000; ++i) {
		value = malloc (sizeof (int));
		*value = i;
		if (!p11_dict_set (map, value, value))
			CuFail (tc, "should not be reached");
	}

	for (i = 0; i < 20000; ++i) {
		value = p11_dict_get (map, &i);
		CuAssertPtrNotNull (tc, value);
		CuAssertIntEquals (tc, i, *value);
	}

	p11_dict_free (map);
}

static void
test_hash_count (CuTest *tc)
{
	p11_dict *map;
	int *value;
	int i, ret;

	map = p11_dict_new (p11_dict_intptr_hash, p11_dict_intptr_equal, NULL, free);

	CuAssertIntEquals (tc, 0, p11_dict_size (map));

	for (i = 0; i < 20000; ++i) {
		value = malloc (sizeof (int));
		*value = i;
		if (!p11_dict_set (map, value, value))
			CuFail (tc, "should not be reached");
		CuAssertIntEquals (tc, i + 1, p11_dict_size (map));
	}

	for (i = 0; i < 20000; ++i) {
		ret = p11_dict_remove (map, &i);
		CuAssertIntEquals (tc, 1, ret);
		CuAssertIntEquals (tc, 20000 - (i + 1), p11_dict_size (map));
	}

	p11_dict_clear (map);
	CuAssertIntEquals (tc, 0, p11_dict_size (map));

	p11_dict_free (map);
}

static void
test_hash_ulongptr (CuTest *tc)
{
	p11_dict *map;
	unsigned long *value;
	unsigned long i;

	map = p11_dict_new (p11_dict_ulongptr_hash, p11_dict_ulongptr_equal, NULL, free);

	for (i = 0; i < 20000; ++i) {
		value = malloc (sizeof (unsigned long));
		*value = i;
		if (!p11_dict_set (map, value, value))
			CuFail (tc, "should not be reached");
	}

	for (i = 0; i < 20000; ++i) {
		value = p11_dict_get (map, &i);
		CuAssertPtrNotNull (tc, value);
		CuAssertIntEquals (tc, i, *value);
	}

	p11_dict_free (map);
}

int
main (void)
{
	CuString *output = CuStringNew ();
	CuSuite* suite = CuSuiteNew ();
	int ret;

	SUITE_ADD_TEST (suite, test_create);
	SUITE_ADD_TEST (suite, test_set_get);
	SUITE_ADD_TEST (suite, test_set_get_remove);
	SUITE_ADD_TEST (suite, test_remove_destroys);
	SUITE_ADD_TEST (suite, test_set_clear);
	SUITE_ADD_TEST (suite, test_set_destroys);
	SUITE_ADD_TEST (suite, test_clear_destroys);
	SUITE_ADD_TEST (suite, test_free_null);
	SUITE_ADD_TEST (suite, test_free_destroys);
	SUITE_ADD_TEST (suite, test_iterate);
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
