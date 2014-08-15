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
#include "test.h"

#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "dict.h"

static void
test_create (void)
{
	p11_dict *map;

	map = p11_dict_new (p11_dict_direct_hash, p11_dict_direct_equal, NULL, NULL);
	assert_ptr_not_null (map);
	p11_dict_free (map);
}

static void
test_free_null (void)
{
	p11_dict_free (NULL);
}

typedef struct {
	int value;
	bool freed;
} Key;

static unsigned int
key_hash (const void *ptr)
{
	const Key *k = ptr;
	assert (!k->freed);
	return p11_dict_intptr_hash (&k->value);
}

static bool
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
	k->freed = true;
}

static void
value_destroy (void *data)
{
	int *value = data;
	*value = 2;
}

static void
test_free_destroys (void)
{
	p11_dict *map;
	Key key = { 8, 0 };
	int value = 0;

	map = p11_dict_new (key_hash, key_equal, key_destroy, value_destroy);
	assert_ptr_not_null (map);
	if (!p11_dict_set (map, &key, &value))
		assert_not_reached ();
	p11_dict_free (map);

	assert_num_eq (true, key.freed);
	assert_num_eq (2, value);
}

static void
test_iterate (void)
{
	p11_dict *map;
	p11_dictiter iter;
	int key = 1;
	int value = 2;
	void *pkey;
	void *pvalue;
	int ret;

	map = p11_dict_new (p11_dict_direct_hash, p11_dict_direct_equal, NULL, NULL);
	assert_ptr_not_null (map);
	if (!p11_dict_set (map, &key, &value))
		assert_not_reached ();

	p11_dict_iterate (map, &iter);

	ret = p11_dict_next (&iter, &pkey, &pvalue);
	assert_num_eq (1, ret);
	assert_ptr_eq (pkey, &key);
	assert_ptr_eq (pvalue, &value);

	ret = p11_dict_next (&iter, &pkey, &pvalue);
	assert_num_eq (0, ret);

	p11_dict_free (map);
}

static int
compar_strings (const void *one,
                const void *two)
{
	char **p1 = (char **)one;
	char **p2 = (char **)two;
	return strcmp (*p1, *p2);
}

static void
test_iterate_remove (void)
{
	p11_dict *map;
	p11_dictiter iter;
	char *keys[] = { "111", "222", "333" };
	char *values[] = { "444", "555", "666" };
	void *okeys[3];
	void *ovalues[3];
	bool ret;
	int i;

	map = p11_dict_new (p11_dict_str_hash, p11_dict_str_equal, NULL, NULL);
	assert_ptr_not_null (map);

	for (i = 0; i < 3; i++) {
		if (!p11_dict_set (map, keys[i], values[i]))
			assert_not_reached ();
	}

	p11_dict_iterate (map, &iter);

	ret = p11_dict_next (&iter, &okeys[0], &ovalues[0]);
	assert_num_eq (true, ret);

	ret = p11_dict_next (&iter, &okeys[1], &ovalues[1]);
	assert_num_eq (true, ret);
	if (!p11_dict_remove (map, okeys[1]))
		assert_not_reached ();

	ret = p11_dict_next (&iter, &okeys[2], &ovalues[2]);
	assert_num_eq (true, ret);

	ret = p11_dict_next (&iter, NULL, NULL);
	assert_num_eq (false, ret);

	assert_num_eq (2, p11_dict_size (map));
	p11_dict_free (map);

	qsort (okeys, 3, sizeof (void *), compar_strings);
	qsort (ovalues, 3, sizeof (void *), compar_strings);

	for (i = 0; i < 3; i++) {
		assert_str_eq (keys[i], okeys[i]);
		assert_ptr_eq (keys[i], okeys[i]);
		assert_str_eq (values[i], ovalues[i]);
		assert_ptr_eq (values[i], ovalues[i]);
	}
}

static void
test_set_get (void)
{
	char *key = "KEY";
	char *value = "VALUE";
	char *check;
	p11_dict *map;

	map = p11_dict_new (p11_dict_str_hash, p11_dict_str_equal, NULL, NULL);
	p11_dict_set (map, key, value);
	check = p11_dict_get (map, key);
	assert_ptr_eq (check, value);

	p11_dict_free (map);
}

static void
test_set_get_remove (void)
{
	char *key = "KEY";
	char *value = "VALUE";
	char *check;
	p11_dict *map;
	bool ret;

	map = p11_dict_new (p11_dict_str_hash, p11_dict_str_equal, NULL, NULL);

	if (!p11_dict_set (map, key, value))
		assert_not_reached ();

	check = p11_dict_get (map, key);
	assert_ptr_eq (check, value);

	ret = p11_dict_remove (map, key);
	assert_num_eq (true, ret);
	ret = p11_dict_remove (map, key);
	assert_num_eq (false, ret);

	check = p11_dict_get (map, key);
	assert (check == NULL);

	p11_dict_free (map);
}

static void
test_set_clear (void)
{
	char *key = "KEY";
	char *value = "VALUE";
	char *check;
	p11_dict *map;

	map = p11_dict_new (p11_dict_direct_hash, p11_dict_direct_equal, NULL, NULL);

	if (!p11_dict_set (map, key, value))
		assert_not_reached ();

	p11_dict_clear (map);

	check = p11_dict_get (map, key);
	assert (check == NULL);

	p11_dict_free (map);
}

static void
test_remove_destroys (void)
{
	p11_dict *map;
	Key key = { 8, 0 };
	int value = 0;
	bool ret;

	map = p11_dict_new (key_hash, key_equal, key_destroy, value_destroy);
	assert_ptr_not_null (map);
	if (!p11_dict_set (map, &key, &value))
		assert_not_reached ();

	ret = p11_dict_remove (map, &key);
	assert_num_eq (true, ret);
	assert_num_eq (true, key.freed);
	assert_num_eq (2, value);

	/* should not be destroyed again */
	key.freed = false;
	value = 0;

	ret = p11_dict_remove (map, &key);
	assert_num_eq (false, ret);
	assert_num_eq (false, key.freed);
	assert_num_eq (0, value);

	/* should not be destroyed again */
	key.freed = false;
	value = 0;

	p11_dict_free (map);

	assert_num_eq (false, key.freed);
	assert_num_eq (0, value);
}

static void
test_set_destroys (void)
{
	p11_dict *map;
	Key key = { 8, 0 };
	Key key2 = { 8, 0 };
	int value, value2;
	bool ret;

	map = p11_dict_new (key_hash, key_equal, key_destroy, value_destroy);
	assert_ptr_not_null (map);
	if (!p11_dict_set (map, &key, &value))
		assert_not_reached ();

	key.freed = key2.freed = false;
	value = value2 = 0;

	/* Setting same key and value, should not be destroyed */
	ret = p11_dict_set (map, &key, &value);
	assert_num_eq (true, ret);
	assert_num_eq (false, key.freed);
	assert_num_eq (false, key2.freed);
	assert_num_eq (0, value);
	assert_num_eq (0, value2);

	key.freed = key2.freed = false;
	value = value2 = 0;

	/* Setting a new key same value, key should be destroyed */
	ret = p11_dict_set (map, &key2, &value);
	assert_num_eq (true, ret);
	assert_num_eq (true, key.freed);
	assert_num_eq (false, key2.freed);
	assert_num_eq (0, value);
	assert_num_eq (0, value2);

	key.freed = key2.freed = false;
	value = value2 = 0;

	/* Setting same key, new value, value should be destroyed */
	ret = p11_dict_set (map, &key2, &value2);
	assert_num_eq (true, ret);
	assert_num_eq (false, key.freed);
	assert_num_eq (false, key2.freed);
	assert_num_eq (2, value);
	assert_num_eq (0, value2);

	key.freed = key2.freed = false;
	value = value2 = 0;

	/* Setting new key new value, both should be destroyed */
	ret = p11_dict_set (map, &key, &value);
	assert_num_eq (true, ret);
	assert_num_eq (false, key.freed);
	assert_num_eq (true, key2.freed);
	assert_num_eq (0, value);
	assert_num_eq (2, value2);

	key.freed = key2.freed = false;
	value = value2 = 0;

	p11_dict_free (map);
	assert_num_eq (true, key.freed);
	assert_num_eq (2, value);
	assert_num_eq (false, key2.freed);
	assert_num_eq (0, value2);
}


static void
test_clear_destroys (void)
{
	p11_dict *map;
	Key key = { 18, 0 };
	int value = 0;

	map = p11_dict_new (key_hash, key_equal, key_destroy, value_destroy);
	assert_ptr_not_null (map);
	if (!p11_dict_set (map, &key, &value))
		assert_not_reached ();

	p11_dict_clear (map);
	assert_num_eq (true, key.freed);
	assert_num_eq (2, value);

	/* should not be destroyed again */
	key.freed = false;
	value = 0;

	p11_dict_clear (map);
	assert_num_eq (false, key.freed);
	assert_num_eq (0, value);

	/* should not be destroyed again */
	key.freed = false;
	value = 0;

	p11_dict_free (map);

	assert_num_eq (false, key.freed);
	assert_num_eq (0, value);
}

static unsigned int
test_hash_intptr_with_collisions (const void *data)
{
	/* lots and lots of collisions, only returns 100 values */
	return (unsigned int)(*((int*)data) % 100);
}

static void
test_hash_add_check_lots_and_collisions (void)
{
	p11_dict *map;
	int *value;
	int i;

	map = p11_dict_new (test_hash_intptr_with_collisions,
	                    p11_dict_intptr_equal, NULL, free);

	for (i = 0; i < 20000; ++i) {
		value = malloc (sizeof (int));
		assert (value != NULL);
		*value = i;
		if (!p11_dict_set (map, value, value))
			assert_not_reached ();
	}

	for (i = 0; i < 20000; ++i) {
		value = p11_dict_get (map, &i);
		assert_ptr_not_null (value);
		assert_num_eq (i, *value);
	}

	p11_dict_free (map);
}

static void
test_hash_count (void)
{
	p11_dict *map;
	int *value;
	int i;
	bool ret;

	map = p11_dict_new (p11_dict_intptr_hash, p11_dict_intptr_equal, NULL, free);

	assert_num_eq (0, p11_dict_size (map));

	for (i = 0; i < 20000; ++i) {
		value = malloc (sizeof (int));
		assert (value != NULL);
		*value = i;
		if (!p11_dict_set (map, value, value))
			assert_not_reached ();
		assert_num_eq (i + 1, p11_dict_size (map));
	}

	for (i = 0; i < 20000; ++i) {
		ret = p11_dict_remove (map, &i);
		assert_num_eq (true, ret);
		assert_num_eq (20000 - (i + 1), p11_dict_size (map));
	}

	p11_dict_clear (map);
	assert_num_eq (0, p11_dict_size (map));

	p11_dict_free (map);
}

static void
test_hash_ulongptr (void)
{
	p11_dict *map;
	unsigned long *value;
	unsigned long i;

	map = p11_dict_new (p11_dict_ulongptr_hash, p11_dict_ulongptr_equal, NULL, free);

	for (i = 0; i < 20000; ++i) {
		value = malloc (sizeof (unsigned long));
		assert (value != NULL);
		*value = i;
		if (!p11_dict_set (map, value, value))
			assert_not_reached ();
	}

	for (i = 0; i < 20000; ++i) {
		value = p11_dict_get (map, &i);
		assert_ptr_not_null (value);
		assert_num_eq (i, *value);
	}

	p11_dict_free (map);
}

int
main (int argc,
      char *argv[])
{
	p11_test (test_create, "/dict/create");
	p11_test (test_set_get, "/dict/set-get");
	p11_test (test_set_get_remove, "/dict/set-get-remove");
	p11_test (test_remove_destroys, "/dict/remove-destroys");
	p11_test (test_set_clear, "/dict/set-clear");
	p11_test (test_set_destroys, "/dict/set-destroys");
	p11_test (test_clear_destroys, "/dict/clear-destroys");
	p11_test (test_free_null, "/dict/free-null");
	p11_test (test_free_destroys, "/dict/free-destroys");
	p11_test (test_iterate, "/dict/iterate");
	p11_test (test_iterate_remove, "/dict/iterate-remove");
	p11_test (test_hash_add_check_lots_and_collisions, "/dict/add-check-lots-and-collisions");
	p11_test (test_hash_count, "/dict/count");
	p11_test (test_hash_ulongptr, "/dict/ulongptr");
	return p11_test_run (argc, argv);
}
