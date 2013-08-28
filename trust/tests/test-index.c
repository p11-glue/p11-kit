/*
 * Copyright (c) 2012 Red Hat Inc.
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
 * Author: Stef Walter <stefw@gnome.org>
 */

#include "config.h"
#include "test.h"
#include "test-trust.h"

#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "attrs.h"
#include "debug.h"
#include "index.h"
#include "message.h"

struct {
	p11_index *index;
} test;

static void
setup (void *unused)
{
	test.index = p11_index_new (NULL, NULL, NULL, NULL, NULL);
	assert_ptr_not_null (test.index);
}

static void
teardown (void *unused)
{
	p11_index_free (test.index);
	memset (&test, 0, sizeof (test));
}

static void
test_take_lookup (void)
{
	CK_ATTRIBUTE original[] = {
		{ CKA_LABEL, "yay", 3 },
		{ CKA_VALUE, "eight", 5 },
		{ CKA_INVALID }
	};

	CK_ATTRIBUTE *attrs;
	CK_ATTRIBUTE *check;
	CK_OBJECT_HANDLE handle;
	CK_RV rv;

	attrs = p11_attrs_dup (original);
	rv = p11_index_take (test.index, attrs, &handle);
	assert (rv == CKR_OK);

	check = p11_index_lookup (test.index, handle);
	test_check_attrs (original, check);

	check = p11_index_lookup (test.index, 1UL);
	assert_ptr_eq (NULL, check);

	check = p11_index_lookup (test.index, 0UL);
	assert_ptr_eq (NULL, check);
}

static void
test_add_lookup (void)
{
	CK_ATTRIBUTE original[] = {
		{ CKA_LABEL, "yay", 3 },
		{ CKA_VALUE, "eight", 5 },
		{ CKA_INVALID }
	};

	CK_ATTRIBUTE *check;
	CK_OBJECT_HANDLE handle;
	CK_RV rv;

	rv = p11_index_add (test.index, original, 2, &handle);
	assert (rv == CKR_OK);

	check = p11_index_lookup (test.index, handle);
	test_check_attrs (original, check);
}

static void
test_size (void)
{
	static CK_ATTRIBUTE original[] = {
		{ CKA_LABEL, "yay", 3 },
		{ CKA_VALUE, "eight", 5 },
		{ CKA_INVALID }
	};

	CK_RV rv;

	rv = p11_index_add (test.index, original, 2, NULL);
	assert (rv == CKR_OK);

	rv = p11_index_add (test.index, original, 2, NULL);
	assert (rv == CKR_OK);

	rv = p11_index_add (test.index, original, 2, NULL);
	assert (rv == CKR_OK);

	assert_num_eq (3, p11_index_size (test.index));
}

static int
compar_ulong (const void *one,
              const void *two)
{
	const CK_ULONG *u1 = one;
	const CK_ULONG *u2 = two;

	if (*u1 == *u2)
		return 0;
	if (*u1 < *u2)
		return -1;
	return 1;
}

static void
test_snapshot (void)
{
	CK_ATTRIBUTE original[] = {
		{ CKA_LABEL, "yay", 3 },
		{ CKA_VALUE, "eight", 5 },
		{ CKA_INVALID }
	};

	static const int NUM = 16;
	CK_OBJECT_HANDLE expected[NUM];
	CK_OBJECT_HANDLE *snapshot;
	int i;

	for (i = 0; i < NUM; i++)
		p11_index_add (test.index, original, 2, expected + i);

	snapshot = p11_index_snapshot (test.index, NULL, NULL, 0);
	assert_ptr_not_null (snapshot);

	for (i = 0; i < NUM; i++)
		assert (snapshot[i] != 0);
	assert (snapshot[NUM] == 0);

	qsort (snapshot, NUM, sizeof (CK_OBJECT_HANDLE), compar_ulong);

	for (i = 0; i < NUM; i++)
		assert_num_eq (expected[i], snapshot[i]);

	free (snapshot);
}

static void
test_snapshot_base (void)
{
	CK_ATTRIBUTE original[] = {
		{ CKA_LABEL, "yay", 3 },
		{ CKA_VALUE, "eight", 5 },
		{ CKA_INVALID }
	};

	static const int NUM = 16;
	CK_OBJECT_HANDLE expected[NUM];
	CK_OBJECT_HANDLE *snapshot;
	CK_RV rv;
	int i;

	for (i = 0; i < NUM; i++) {
		rv = p11_index_add (test.index, original, 2, expected + i);
		assert (rv == CKR_OK);
	}

	snapshot = p11_index_snapshot (test.index, test.index, NULL, 0);
	assert_ptr_not_null (snapshot);

	for (i = 0; i < NUM * 2; i++)
		assert (snapshot[i] != 0);
	assert (snapshot[NUM * 2] == 0);

	qsort (snapshot, NUM * 2, sizeof (CK_OBJECT_HANDLE), compar_ulong);

	for (i = 0; i < NUM * 2; i++)
		assert_num_eq (expected[i / 2], snapshot[i]);

	free (snapshot);
}

static void
test_remove (void)
{
	CK_ATTRIBUTE original[] = {
		{ CKA_LABEL, "yay", 3 },
		{ CKA_VALUE, "eight", 5 },
		{ CKA_INVALID }
	};

	CK_ATTRIBUTE *attrs;
	CK_ATTRIBUTE *check;
	CK_OBJECT_HANDLE handle;
	CK_RV rv;

	attrs = p11_attrs_dup (original);
	rv = p11_index_take (test.index, attrs, &handle);
	assert (rv == CKR_OK);

	check = p11_index_lookup (test.index, handle);
	assert_ptr_eq (attrs, check);

	rv = p11_index_remove (test.index, 1UL);
	assert (rv == CKR_OBJECT_HANDLE_INVALID);

	rv = p11_index_remove (test.index, handle);
	assert (rv == CKR_OK);

	check = p11_index_lookup (test.index, handle);
	assert_ptr_eq (NULL, check);
}

static void
test_set (void)
{
	CK_ATTRIBUTE original[] = {
		{ CKA_LABEL, "yay", 3 },
		{ CKA_VALUE, "eight", 5 },
		{ CKA_INVALID }
	};

	CK_ATTRIBUTE change = { CKA_LABEL, "naay", 4 };

	CK_ATTRIBUTE changed[] = {
		{ CKA_LABEL, "naay", 4 },
		{ CKA_VALUE, "eight", 5 },
		{ CKA_INVALID }
	};

	CK_ATTRIBUTE *attrs;
	CK_ATTRIBUTE *check;
	CK_OBJECT_HANDLE handle;
	CK_RV rv;

	attrs = p11_attrs_dup (original);
	rv = p11_index_take (test.index, attrs, &handle);
	assert (rv == CKR_OK);

	check = p11_index_lookup (test.index, handle);
	test_check_attrs (original, check);

	rv = p11_index_set (test.index, handle, &change, 1);
	assert (rv == CKR_OK);

	check = p11_index_lookup (test.index, handle);
	test_check_attrs (changed, check);

	rv = p11_index_set (test.index, 1UL, &change, 1);
	assert (rv == CKR_OBJECT_HANDLE_INVALID);
}

static void
test_update (void)
{
	CK_ATTRIBUTE original[] = {
		{ CKA_LABEL, "yay", 3 },
		{ CKA_VALUE, "eight", 5 },
		{ CKA_INVALID }
	};

	CK_ATTRIBUTE change = { CKA_LABEL, "naay", 4 };

	CK_ATTRIBUTE changed[] = {
		{ CKA_LABEL, "naay", 4 },
		{ CKA_VALUE, "eight", 5 },
		{ CKA_INVALID }
	};

	CK_ATTRIBUTE *attrs;
	CK_ATTRIBUTE *check;
	CK_OBJECT_HANDLE handle;
	CK_RV rv;

	attrs = p11_attrs_dup (original);
	rv = p11_index_take (test.index, attrs, &handle);
	assert (rv == CKR_OK);

	check = p11_index_lookup (test.index, handle);
	test_check_attrs (original, check);

	attrs = p11_attrs_build (NULL, &change, NULL);
	rv = p11_index_update (test.index, handle, attrs);
	assert (rv == CKR_OK);

	check = p11_index_lookup (test.index, handle);
	test_check_attrs (changed, check);

	attrs = p11_attrs_build (NULL, &change, NULL);
	rv = p11_index_update (test.index, 1L, attrs);
	assert (rv == CKR_OBJECT_HANDLE_INVALID);
}

static void
test_find (void)
{
	CK_ATTRIBUTE first[] = {
		{ CKA_LABEL, "yay", 3 },
		{ CKA_VALUE, "one", 3 },
		{ CKA_INVALID }
	};

	CK_ATTRIBUTE second[] = {
		{ CKA_LABEL, "yay", 3 },
		{ CKA_VALUE, "two", 3 },
		{ CKA_INVALID }
	};

	CK_ATTRIBUTE third[] = {
		{ CKA_LABEL, "yay", 3 },
		{ CKA_VALUE, "three", 5 },
		{ CKA_INVALID }
	};

	CK_ATTRIBUTE match3[] = {
		{ CKA_VALUE, "three", 5 },
		{ CKA_INVALID }
	};

	CK_ATTRIBUTE match_any[] = {
		{ CKA_LABEL, "yay", 3 },
		{ CKA_INVALID }
	};

	CK_ATTRIBUTE match_none[] = {
		{ CKA_VALUE, "blonononon", 10 },
		{ CKA_LABEL, "yay", 3 },
		{ CKA_INVALID }
	};

	CK_OBJECT_HANDLE check;
	CK_OBJECT_HANDLE one;
	CK_OBJECT_HANDLE two;
	CK_OBJECT_HANDLE three;

	p11_index_add (test.index, first, 2, &one);
	p11_index_add (test.index, second, 2, &two);
	p11_index_add (test.index, third, 2, &three);

	check = p11_index_find (test.index, match3, -1);
	assert_num_eq (three, check);

	check = p11_index_find (test.index, match3, 1);
	assert_num_eq (three, check);

	check = p11_index_find (test.index, match_any, -1);
	assert (check == one || check == two || check == three);

	check = p11_index_find (test.index, match_any, 1);
	assert (check == one || check == two || check == three);

	check = p11_index_find (test.index, match_none, -1);
	assert_num_eq (0, check);

	check = p11_index_find (test.index, match_none, 2);
	assert_num_eq (0, check);
}

static bool
handles_are (CK_OBJECT_HANDLE *handles,
             ...)
{
	CK_OBJECT_HANDLE handle;
	bool matched = true;
	int count;
	int num;
	va_list va;
	int i;

	if (!handles)
		return false;

	/* Count number of handles */
	for (num = 0; handles[num]; num++);

	va_start (va, handles);

	for (count = 0; matched; count++) {
		handle = va_arg (va, CK_OBJECT_HANDLE);
		if (handle == 0)
			break;

		for (i = 0; handles[i]; i++) {
			if (handle == handles[i])
				break;
		}

		if (handles[i] != handle)
			matched = false;
	}

	va_end (va);

	return matched && (count == num);
}

static void
test_find_all (void)
{
	CK_ATTRIBUTE first[] = {
		{ CKA_LABEL, "odd", 3 },
		{ CKA_VALUE, "one", 3 },
		{ CKA_APPLICATION, "test", 4 },
		{ CKA_INVALID }
	};

	CK_ATTRIBUTE second[] = {
		{ CKA_LABEL, "even", 4 },
		{ CKA_VALUE, "two", 3 },
		{ CKA_APPLICATION, "test", 4 },
		{ CKA_INVALID }
	};

	CK_ATTRIBUTE third[] = {
		{ CKA_LABEL, "odd", 3 },
		{ CKA_VALUE, "three", 5 },
		{ CKA_APPLICATION, "test", 4 },
		{ CKA_INVALID }
	};

	CK_ATTRIBUTE match_odd[] = {
		{ CKA_LABEL, "odd", 3 },
		{ CKA_APPLICATION, "test", 4 },
		{ CKA_INVALID }
	};

	CK_ATTRIBUTE match_3[] = {
		{ CKA_VALUE, "three", 5 },
		{ CKA_INVALID }
	};

	CK_ATTRIBUTE match_any[] = {
		{ CKA_INVALID }
	};

	CK_ATTRIBUTE match_none[] = {
		{ CKA_VALUE, "blonononon", 10 },
		{ CKA_LABEL, "yay", 3 },
		{ CKA_INVALID }
	};

	CK_OBJECT_HANDLE *check;
	CK_OBJECT_HANDLE one;
	CK_OBJECT_HANDLE two;
	CK_OBJECT_HANDLE three;

	p11_index_add (test.index, first, 3, &one);
	p11_index_add (test.index, second, 3, &two);
	p11_index_add (test.index, third, 3, &three);

	check = p11_index_find_all (test.index, match_3, -1);
	assert (handles_are (check, three, 0UL));
	free (check);

	check = p11_index_find_all (test.index, match_none, -1);
	assert (handles_are (check, 0UL));
	free (check);

	check = p11_index_find_all (test.index, match_odd, -1);
	assert (handles_are (check, one, three, 0UL));
	free (check);

	check = p11_index_find_all (test.index, match_any, -1);
	assert (handles_are (check, one, two, three, 0UL));
	free (check);

	check = p11_index_find_all (test.index, match_none, -1);
	assert_ptr_not_null (check);
	assert_num_eq (0, check[0]);
	free (check);

	/* A double check of this method */
	one = 0UL;
	check = &one;
	assert (!handles_are (check, 29292929, 0UL));
	assert (!handles_are (NULL, 0UL));
}

static void
test_find_realloc (void)
{
	CK_ATTRIBUTE attrs[] = {
		{ CKA_LABEL, "odd", 3 },
		{ CKA_VALUE, "one", 3 },
		{ CKA_APPLICATION, "test", 4 },
		{ CKA_INVALID }
	};

	CK_ATTRIBUTE match[] = {
		{ CKA_INVALID }
	};

	CK_OBJECT_HANDLE *check;
	int i;

	for (i = 0; i < 1000; i++)
		p11_index_add (test.index, attrs, 3, NULL);

	check = p11_index_find_all (test.index, match, -1);
	assert_ptr_not_null (check);

	for (i = 0; i < 1000; i++)
		assert (check[i] != 0);
	assert_num_eq (0, check[1000]);

	free (check);
}

static void
test_replace_all (void)
{
	CK_ATTRIBUTE first[] = {
		{ CKA_LABEL, "odd", 3 },
		{ CKA_VALUE, "one", 3 },
		{ CKA_APPLICATION, "test", 4 },
		{ CKA_INVALID }
	};

	CK_ATTRIBUTE second[] = {
		{ CKA_LABEL, "even", 4 },
		{ CKA_VALUE, "two", 3 },
		{ CKA_APPLICATION, "test", 4 },
		{ CKA_INVALID }
	};

	CK_ATTRIBUTE third[] = {
		{ CKA_LABEL, "odd", 3 },
		{ CKA_VALUE, "three", 5 },
		{ CKA_APPLICATION, "test", 4 },
		{ CKA_INVALID }
	};

	CK_ATTRIBUTE fifth[] = {
		{ CKA_LABEL, "odd", 3 },
		{ CKA_VALUE, "five", 4 },
		{ CKA_APPLICATION, "test", 4 },
		{ CKA_INVALID }
	};

	CK_ATTRIBUTE match[] = {
		{ CKA_LABEL, "odd", 3 },
		{ CKA_INVALID }
	};

	CK_ATTRIBUTE eins[] = {
		{ CKA_LABEL, "odd", 3 },
		{ CKA_VALUE, "one", 3 },
		{ CKA_APPLICATION, "replace", 7 },
		{ CKA_INVALID }
	};

	CK_ATTRIBUTE sieben[] = {
		{ CKA_LABEL, "odd", 3 },
		{ CKA_VALUE, "seven", 5 },
		{ CKA_APPLICATION, "replace", 7 },
		{ CKA_INVALID }
	};

	CK_ATTRIBUTE neun[] = {
		{ CKA_LABEL, "odd", 3 },
		{ CKA_VALUE, "nine", 4 },
		{ CKA_APPLICATION, "replace", 7 },
		{ CKA_INVALID }
	};

	CK_OBJECT_HANDLE check;
	CK_OBJECT_HANDLE one;
	CK_OBJECT_HANDLE two;
	CK_OBJECT_HANDLE three;
	CK_OBJECT_HANDLE five;
	p11_array *array;
	CK_RV rv;

	p11_index_add (test.index, first, 3, &one);
	assert (one != 0);
	p11_index_add (test.index, second, 3, &two);
	assert (two != 0);
	p11_index_add (test.index, third, 3, &three);
	assert (three != 0);
	p11_index_add (test.index, fifth, 3, &five);
	assert (five != 0);

	array = p11_array_new (p11_attrs_free);
	p11_array_push (array, p11_attrs_buildn (NULL, eins, 3));
	p11_array_push (array, p11_attrs_buildn (NULL, sieben, 3));
	p11_array_push (array, p11_attrs_buildn (NULL, neun, 3));

	rv = p11_index_replace_all (test.index, match, CKA_VALUE, array);
	assert (rv == CKR_OK);

	assert_num_eq (0, array->num);
	p11_array_free (array);

	/* eins should have replaced one */
	check = p11_index_find (test.index, eins, -1);
	assert_num_eq (one, check);

	/* two should still be around */
	check = p11_index_find (test.index, second, -1);
	assert_num_eq (two, check);

	/* three should have been removed */
	check = p11_index_find (test.index, third, -1);
	assert_num_eq (0, check);

	/* five should have been removed */
	check = p11_index_find (test.index, fifth, -1);
	assert_num_eq (0, check);

	/* sieben should have been added */
	check = p11_index_find (test.index, sieben, -1);
	assert (check != one && check != two && check != three && check != five);

	/* neun should have been added */
	check = p11_index_find (test.index, neun, -1);
	assert (check != one && check != two && check != three && check != five);

	assert_num_eq (4, p11_index_size (test.index));
}

static CK_RV
on_index_build_fail (void *data,
                     p11_index *index,
                     CK_ATTRIBUTE *attrs,
                     CK_ATTRIBUTE *merge,
                     CK_ATTRIBUTE **populate)
{
	CK_ATTRIBUTE *match = data;

	if (p11_attrs_match (merge, match))
		return CKR_FUNCTION_FAILED;

	return CKR_OK;
}

static void
test_replace_all_build_fails (void)
{
	CK_ATTRIBUTE replace[] = {
		{ CKA_LABEL, "odd", 3 },
		{ CKA_VALUE, "one", 3 },
		{ CKA_APPLICATION, "test", 4 },
		{ CKA_INVALID }
	};

	CK_ATTRIBUTE match[] = {
		{ CKA_LABEL, "odd", 3 },
		{ CKA_INVALID }
	};

	p11_array *array;
	p11_index *index;
	CK_RV rv;

	index = p11_index_new (on_index_build_fail, NULL, NULL, NULL, &match);
	assert_ptr_not_null (index);

	array = p11_array_new (p11_attrs_free);
	if (!p11_array_push (array, p11_attrs_dup (replace)))
		assert_not_reached ();

	rv = p11_index_replace_all (index, NULL, CKA_INVALID, array);
	assert_num_eq (rv, CKR_FUNCTION_FAILED);

	p11_array_free (array);
	p11_index_free (index);
}


static CK_RV
on_build_populate (void *data,
                   p11_index *index,
                   CK_ATTRIBUTE *attrs,
                   CK_ATTRIBUTE *merge,
                   CK_ATTRIBUTE **populate)
{
	CK_ATTRIBUTE more[] = {
		{ CKA_APPLICATION, "vigorous", 8 },
		{ CKA_LABEL, "naay", 4 },
	};

	assert_str_eq (data, "blah");
	assert_ptr_not_null (index);
	assert_ptr_not_null (merge);

	*populate = p11_attrs_buildn (*populate, more, 2);
	return CKR_OK;
}

static void
test_build_populate (void)
{
	CK_ATTRIBUTE original[] = {
		{ CKA_LABEL, "yay", 3 },
		{ CKA_VALUE, "eight", 5 },
		{ CKA_INVALID }

	};

	CK_ATTRIBUTE after[] = {
		{ CKA_LABEL, "yay", 3 },
		{ CKA_VALUE, "eight", 5 },
		{ CKA_APPLICATION, "vigorous", 8 },
		{ CKA_INVALID }
	};

	CK_OBJECT_HANDLE handle;
	CK_ATTRIBUTE *check;
	p11_index *index;
	CK_RV rv;

	index = p11_index_new (on_build_populate, NULL, NULL, NULL, "blah");
	assert_ptr_not_null (index);

	rv = p11_index_add (index, original, 2, &handle);
	assert (rv == CKR_OK);

	check = p11_index_lookup (index, handle);
	assert_ptr_not_null (check);

	test_check_attrs (after, check);

	rv = p11_index_set (index, handle, original, 2);
	assert (rv == CKR_OK);

	check = p11_index_lookup (index, handle);
	assert_ptr_not_null (check);

	test_check_attrs (after, check);

	p11_index_free (index);
}

static CK_RV
on_build_fail (void *data,
               p11_index *index,
               CK_ATTRIBUTE *attrs,
               CK_ATTRIBUTE *merge,
               CK_ATTRIBUTE **populate)
{
	CK_ATTRIBUTE check[] = {
		{ CKA_LABEL, "nay", 3 },
		{ CKA_INVALID }
	};

	assert_str_eq (data, "testo");
	assert_ptr_not_null (merge);

	if (p11_attrs_match (merge, check))
		return CKR_DEVICE_ERROR;

	return CKR_OK;
}


static void
test_build_fail (void)
{
	CK_ATTRIBUTE okay[] = {
		{ CKA_LABEL, "yay", 3 },
		{ CKA_VALUE, "eight", 5 },
		{ CKA_INVALID }
	};

	CK_ATTRIBUTE fails[] = {
		{ CKA_LABEL, "nay", 3 },
		{ CKA_VALUE, "eight", 5 },
		{ CKA_INVALID }
	};

	CK_OBJECT_HANDLE handle;
	p11_index *index;
	CK_RV rv;

	index = p11_index_new (on_build_fail, NULL, NULL, NULL, "testo");
	assert_ptr_not_null (index);

	rv = p11_index_add (index, okay, 2, &handle);
	assert (rv == CKR_OK);

	rv = p11_index_add (index, fails, 2, NULL);
	assert (rv == CKR_DEVICE_ERROR);

	rv = p11_index_set (index, handle, fails, 2);
	assert (rv == CKR_DEVICE_ERROR);

	rv = p11_index_set (index, handle, okay, 2);
	assert (rv == CKR_OK);

	p11_index_free (index);
}

static int on_change_called = 0;
static bool on_change_removing = false;
static bool on_change_batching = false;

static void
on_change_check (void *data,
                 p11_index *index,
                 CK_OBJECT_HANDLE handle,
                 CK_ATTRIBUTE *attrs)
{
	CK_ATTRIBUTE check[] = {
		{ CKA_LABEL, "yay", 3 },
		{ CKA_VALUE, "eight", 5 },
		{ CKA_INVALID }

	};

	assert_str_eq (data, "change-check");
	assert_ptr_not_null (index);
	assert_ptr_not_null (attrs);

	if (!on_change_batching) {
		if (on_change_removing)
			assert_num_eq (0, handle);
		else
			assert (handle != 0);
	}

	test_check_attrs (check, attrs);
	on_change_called++;
}

static void
test_change_called (void)
{
	CK_ATTRIBUTE original[] = {
		{ CKA_LABEL, "yay", 3 },
		{ CKA_VALUE, "eight", 5 },
		{ CKA_INVALID }

	};

	CK_OBJECT_HANDLE handle;
	p11_index *index;
	CK_RV rv;

	index = p11_index_new (NULL, NULL, NULL, on_change_check, "change-check");
	assert_ptr_not_null (index);

	on_change_removing = false;
	on_change_called = 0;

	rv = p11_index_add (index, original, 2, NULL);
	assert (rv == CKR_OK);

	assert_num_eq (1, on_change_called);

	rv = p11_index_add (index, original, 2, NULL);
	assert (rv == CKR_OK);

	assert_num_eq (2, on_change_called);

	rv = p11_index_add (index, original, 2, &handle);
	assert (rv == CKR_OK);

	assert_num_eq (3, on_change_called);

	on_change_removing = true;

	rv = p11_index_remove (index, handle);
	assert (rv == CKR_OK);

	assert_num_eq (4, on_change_called);

	p11_index_free (index);
}

static void
test_change_batch (void)
{
	CK_ATTRIBUTE original[] = {
		{ CKA_LABEL, "yay", 3 },
		{ CKA_VALUE, "eight", 5 },
		{ CKA_INVALID }

	};

	CK_OBJECT_HANDLE handle;
	p11_index *index;
	CK_RV rv;

	index = p11_index_new (NULL, NULL, NULL, on_change_check, "change-check");
	assert_ptr_not_null (index);

	on_change_batching = true;
	on_change_called = 0;

	p11_index_load (index);

	assert (p11_index_loading (index));

	rv = p11_index_add (index, original, 2, NULL);
	assert (rv == CKR_OK);

	assert_num_eq (0, on_change_called);

	rv = p11_index_add (index, original, 2, NULL);
	assert (rv == CKR_OK);

	assert_num_eq (0, on_change_called);

	rv = p11_index_add (index, original, 2, &handle);
	assert (rv == CKR_OK);

	assert_num_eq (0, on_change_called);

	/* Nested batch is a noop */
	p11_index_load (index);

	rv = p11_index_remove (index, handle);
	assert (rv == CKR_OK);

	assert_num_eq (0, on_change_called);

	/*
	 * Batch finishes when first finish call is called,
	 * even when batches are nested
	 */
	p11_index_finish (index);

	assert (!p11_index_loading (index));

	/*
	 * Only three calls, because later operations on the
	 * same handle override the earlier one.
	 */
	assert_num_eq (3, on_change_called);

	/* This is a noop */
	p11_index_finish (index);

	assert (!p11_index_loading (index));

	p11_index_free (index);
}

static void
on_change_nested (void *data,
                  p11_index *index,
                  CK_OBJECT_HANDLE handle,
                  CK_ATTRIBUTE *attrs)
{
	CK_RV rv;

	CK_ATTRIBUTE second[] = {
		{ CKA_LABEL, "yay", 3 },
		{ CKA_VALUE, "eight", 5 },
		{ CKA_INVALID }

	};

	assert_str_eq (data, "change-nested");
	on_change_called++;

	/* A nested call */
	rv = p11_index_add (index, second, 2, NULL);
	assert (rv == CKR_OK);
}

static void
test_change_nested (void)
{
	CK_ATTRIBUTE original[] = {
		{ CKA_LABEL, "yay", 3 },
		{ CKA_VALUE, "eight", 5 },
		{ CKA_INVALID }

	};

	p11_index *index;
	CK_RV rv;

	index = p11_index_new (NULL, NULL, NULL, on_change_nested, "change-nested");
	assert_ptr_not_null (index);

	on_change_called = 0;
	rv = p11_index_add (index, original, 2, NULL);
	assert (rv == CKR_OK);
	assert_num_eq (1, on_change_called);


	on_change_called = 0;
	p11_index_load (index);
	rv = p11_index_add (index, original, 2, NULL);
	assert (rv == CKR_OK);
	p11_index_finish (index);
	assert_num_eq (1, on_change_called);

	p11_index_free (index);
}

static CK_RV
on_remove_callback (void *data,
                    p11_index *index,
                    CK_ATTRIBUTE *attrs)
{
	int *removed = data;
	assert_ptr_not_null (removed);
	assert_num_eq (*removed, 0);
	*removed = 1;
	return CKR_OK;
}

static void
test_remove_callback (void)
{
	CK_ATTRIBUTE original[] = {
		{ CKA_LABEL, "yay", 3 },
		{ CKA_VALUE, "eight", 5 },
		{ CKA_INVALID }

	};

	CK_OBJECT_HANDLE handle;
	p11_index *index;
	int removed = 0;
	CK_RV rv;

	index = p11_index_new (NULL, NULL, on_remove_callback, NULL, &removed);
	assert_ptr_not_null (index);

	rv = p11_index_add (index, original, 2, &handle);
	assert_num_eq (rv, CKR_OK);

	assert_ptr_not_null (p11_index_lookup (index, handle));

	rv = p11_index_remove (index, handle);
	assert_num_eq (rv, CKR_OK);

	assert_num_eq (removed, 1);
	assert_ptr_eq (p11_index_lookup (index, handle), NULL);

	p11_index_free (index);
}

static CK_RV
on_remove_fail (void *data,
                p11_index *index,
                CK_ATTRIBUTE *attrs)
{
	assert_str_eq (data, "remove-fail");
	return CKR_DEVICE_REMOVED;
}

static void
test_remove_fail (void)
{
	CK_ATTRIBUTE original[] = {
		{ CKA_LABEL, "yay", 3 },
		{ CKA_VALUE, "eight", 5 },
		{ CKA_INVALID }

	};

	CK_OBJECT_HANDLE handle;
	p11_index *index;
	CK_RV rv;

	index = p11_index_new (NULL, NULL, on_remove_fail, NULL, "remove-fail");
	assert_ptr_not_null (index);

	rv = p11_index_add (index, original, 2, &handle);
	assert (rv == CKR_OK);

	assert_ptr_not_null (p11_index_lookup (index, handle));

	rv = p11_index_remove (index, handle);
	assert_num_eq (rv, CKR_DEVICE_REMOVED);

	assert_ptr_not_null (p11_index_lookup (index, handle));

	p11_index_free (index);
}

int
main (int argc,
      char *argv[])
{
	p11_message_quiet ();

	p11_fixture (setup, teardown);
	p11_test (test_add_lookup, "/index/add_lookup");
	p11_test (test_take_lookup, "/index/take_lookup");
	p11_test (test_size, "/index/size");
	p11_test (test_remove, "/index/remove");
	p11_test (test_snapshot, "/index/snapshot");
	p11_test (test_snapshot_base, "/index/snapshot_base");
	p11_test (test_set, "/index/set");
	p11_test (test_update, "/index/update");
	p11_test (test_find, "/index/find");
	p11_test (test_find_all, "/index/find_all");
	p11_test (test_find_realloc, "/index/find_realloc");
	p11_test (test_replace_all, "/index/replace_all");

	p11_fixture (NULL, NULL);
	p11_test (test_build_populate, "/index/build_populate");
	p11_test (test_build_fail, "/index/build_fail");
	p11_test (test_change_called, "/index/change_called");
	p11_test (test_change_batch, "/index/change_batch");
	p11_test (test_change_nested, "/index/change_nested");
	p11_test (test_replace_all_build_fails, "/index/replace-all-build-fails");
	p11_test (test_remove_callback, "/index/remove-callback");
	p11_test (test_remove_fail, "/index/remove-fail");

	return p11_test_run (argc, argv);
}
