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

#include "hash.h"

static void
test_hash_create (CuTest *tc)
{
	hash_t *ht;

	ht = hash_create (hash_direct_hash, hash_direct_equal, NULL, NULL);
	CuAssertPtrNotNull (tc, ht);
	hash_free (ht);
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
	hash_t *ht;
	int key = 0;
	int value = 0;

	ht = hash_create (hash_direct_hash, hash_direct_equal, destroy_key, destroy_value);
	CuAssertPtrNotNull (tc, ht);
	if (!hash_set (ht, &key, &value))
		CuFail (tc, "should not be reached");
	hash_free (ht);

	CuAssertIntEquals (tc, 1, key);
	CuAssertIntEquals (tc, 2, value);
}

static void
test_hash_iterate (CuTest *tc)
{
	hash_t *ht;
	hash_iter_t hi;
	int key = 1;
	int value = 2;
	void *pkey;
	void *pvalue;
	int ret;

	ht = hash_create (hash_direct_hash, hash_direct_equal, NULL, NULL);
	CuAssertPtrNotNull (tc, ht);
	if (!hash_set (ht, &key, &value))
		CuFail (tc, "should not be reached");

	hash_iterate (ht, &hi);

	ret = hash_next (&hi, &pkey, &pvalue);
	CuAssertIntEquals (tc, 1, ret);
	CuAssertPtrEquals (tc, pkey, &key);
	CuAssertPtrEquals (tc, pvalue, &value);

	ret = hash_next (&hi, &pkey, &pvalue);
	CuAssertIntEquals (tc, 0, ret);

	hash_free (ht);
}

static void
test_hash_set_get (CuTest *tc)
{
	char *key = "KEY";
	char *value = "VALUE";
	char *check;
	hash_t *ht;

	ht = hash_create (hash_string_hash, hash_string_equal, NULL, NULL);
	hash_set (ht, key, value);
	check = hash_get (ht, key);
	CuAssertPtrEquals (tc, check, value);

	hash_free (ht);
}

static void
test_hash_set_get_remove (CuTest *tc)
{
	char *key = "KEY";
	char *value = "VALUE";
	char *check;
	hash_t *ht;
	int ret;

	ht = hash_create (hash_string_hash, hash_string_equal, NULL, NULL);

	if (!hash_set (ht, key, value))
		CuFail (tc, "should not be reached");

	check = hash_get (ht, key);
	CuAssertPtrEquals (tc, check, value);

	ret = hash_remove (ht, key);
	CuAssertIntEquals (tc, ret, 1);
	ret = hash_remove (ht, key);
	CuAssertIntEquals (tc, ret, 0);

	check = hash_get (ht, key);
	CuAssert (tc, "should be null", check == NULL);

	hash_free (ht);
}

static void
test_hash_set_get_clear (CuTest *tc)
{
	char *key = "KEY";
	char *value = "VALUE";
	char *check;
	hash_t *ht;

	ht = hash_create (hash_direct_hash, hash_direct_equal, NULL, NULL);

	if (!hash_set (ht, key, value))
		CuFail (tc, "should not be reached");

	check = hash_get (ht, key);
	CuAssertPtrEquals (tc, check, value);

	hash_clear (ht);

	check = hash_get (ht, key);
	CuAssert (tc, "should be null", check == NULL);

	hash_free (ht);
}

static void
test_hash_remove_destroys (CuTest *tc)
{
	hash_t *ht;
	int key = 0;
	int value = 0;
	int ret;

	ht = hash_create (hash_direct_hash, hash_direct_equal, destroy_key, destroy_value);
	CuAssertPtrNotNull (tc, ht);
	if (!hash_set (ht, &key, &value))
		CuFail (tc, "should not be reached");

	ret = hash_remove (ht, &key);
	CuAssertIntEquals (tc, ret, 1);
	CuAssertIntEquals (tc, 1, key);
	CuAssertIntEquals (tc, 2, value);

	/* should not be destroyed again */
	key = 0;
	value = 0;

	ret = hash_remove (ht, &key);
	CuAssertIntEquals (tc, ret, 0);
	CuAssertIntEquals (tc, 0, key);
	CuAssertIntEquals (tc, 0, value);

	/* should not be destroyed again */
	key = 0;
	value = 0;

	hash_free (ht);

	CuAssertIntEquals (tc, 0, key);
	CuAssertIntEquals (tc, 0, value);
}

static void
test_hash_clear_destroys (CuTest *tc)
{
	hash_t *ht;
	int key = 0;
	int value = 0;

	ht = hash_create (hash_direct_hash, hash_direct_equal, destroy_key, destroy_value);
	CuAssertPtrNotNull (tc, ht);
	if (!hash_set (ht, &key, &value))
		CuFail (tc, "should not be reached");

	hash_clear (ht);
	CuAssertIntEquals (tc, 1, key);
	CuAssertIntEquals (tc, 2, value);

	/* should not be destroyed again */
	key = 0;
	value = 0;

	hash_clear (ht);
	CuAssertIntEquals (tc, 0, key);
	CuAssertIntEquals (tc, 0, value);

	/* should not be destroyed again */
	key = 0;
	value = 0;

	hash_free (ht);

	CuAssertIntEquals (tc, 0, key);
	CuAssertIntEquals (tc, 0, value);
}

static unsigned int
test_hash_intptr_with_collisions (const void *data)
{
	/* lots and lots of collisions, only returns 100 values */
	return (unsigned int)(*((unsigned long*)data) % 100);
}

static void
test_hash_add_check_lots_and_collisions (CuTest *tc)
{
	hash_t *ht;
	int *value;
	int i;

	ht = hash_create (test_hash_intptr_with_collisions,
	                  hash_intptr_equal, NULL, free);

	for (i = 0; i < 20000; ++i) {
		value = malloc (sizeof (int));
		*value = i;
		if (!hash_set (ht, value, value))
			CuFail (tc, "should not be reached");
	}

	for (i = 0; i < 20000; ++i) {
		value = hash_get (ht, &i);
		CuAssertPtrNotNull (tc, value);
		CuAssertIntEquals (tc, i, *value);
	}

	hash_free (ht);
}

static void
test_hash_count (CuTest *tc)
{
	hash_t *ht;
	int *value;
	int i, ret;

	ht = hash_create (hash_intptr_hash, hash_intptr_equal, NULL, free);

	CuAssertIntEquals (tc, 0, hash_count (ht));

	for (i = 0; i < 20000; ++i) {
		value = malloc (sizeof (int));
		*value = i;
		if (!hash_set (ht, value, value))
			CuFail (tc, "should not be reached");
		CuAssertIntEquals (tc, i + 1, hash_count (ht));
	}

	for (i = 0; i < 20000; ++i) {
		ret = hash_remove (ht, &i);
		CuAssertIntEquals (tc, 1, ret);
		CuAssertIntEquals (tc, 20000 - (i + 1), hash_count (ht));
	}

	hash_clear (ht);
	CuAssertIntEquals (tc, 0, hash_count (ht));

	hash_free (ht);
}

static void
test_hash_ulongptr (CuTest *tc)
{
	hash_t *ht;
	unsigned long *value;
	unsigned long i;

	ht = hash_create (hash_ulongptr_hash, hash_ulongptr_equal, NULL, free);

	for (i = 0; i < 20000; ++i) {
		value = malloc (sizeof (int));
		*value = i;
		if (!hash_set (ht, value, value))
			CuFail (tc, "should not be reached");
	}

	for (i = 0; i < 20000; ++i) {
		value = hash_get (ht, &i);
		CuAssertPtrNotNull (tc, value);
		CuAssertIntEquals (tc, i, *value);
	}

	hash_free (ht);
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
	return ret;
}

#include "CuTest.c"
