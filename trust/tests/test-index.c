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
#include "CuTest.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "attrs.h"
#include "debug.h"
#include "library.h"
#include "index.h"

#include "test-data.h"

struct {
	p11_index *index;
} test;

static void
setup (CuTest *cu)
{
	test.index = p11_index_new (NULL, NULL, NULL);
	CuAssertPtrNotNull (cu, test.index);
}

static void
teardown (CuTest *cu)
{
	p11_index_free (test.index);
	memset (&test, 0, sizeof (test));
}

static void
test_take_lookup (CuTest *cu)
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

	setup (cu);

	attrs = p11_attrs_dup (original);
	rv = p11_index_take (test.index, attrs, &handle);
	CuAssertTrue (cu, rv == CKR_OK);

	check = p11_index_lookup (test.index, handle);
	test_check_attrs (cu, original, check);

	check = p11_index_lookup (test.index, 1UL);
	CuAssertPtrEquals (cu, NULL, check);

	check = p11_index_lookup (test.index, 0UL);
	CuAssertPtrEquals (cu, NULL, check);

	teardown (cu);
}

static void
test_add_lookup (CuTest *cu)
{
	CK_ATTRIBUTE original[] = {
		{ CKA_LABEL, "yay", 3 },
		{ CKA_VALUE, "eight", 5 },
		{ CKA_INVALID }
	};

	CK_ATTRIBUTE *check;
	CK_OBJECT_HANDLE handle;
	CK_RV rv;

	setup (cu);

	rv = p11_index_add (test.index, original, 2, &handle);
	CuAssertTrue (cu, rv == CKR_OK);

	check = p11_index_lookup (test.index, handle);
	test_check_attrs (cu, original, check);

	teardown (cu);
}

static void
test_size (CuTest *cu)
{
	static CK_ATTRIBUTE original[] = {
		{ CKA_LABEL, "yay", 3 },
		{ CKA_VALUE, "eight", 5 },
		{ CKA_INVALID }
	};

	CK_RV rv;

	setup (cu);

	rv = p11_index_add (test.index, original, 2, NULL);
	CuAssertTrue (cu, rv == CKR_OK);

	rv = p11_index_add (test.index, original, 2, NULL);
	CuAssertTrue (cu, rv == CKR_OK);

	rv = p11_index_add (test.index, original, 2, NULL);
	CuAssertTrue (cu, rv == CKR_OK);

	CuAssertIntEquals (cu, 3, p11_index_size (test.index));

	teardown (cu);
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
test_snapshot (CuTest *cu)
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

	setup (cu);

	for (i = 0; i < NUM; i++)
		p11_index_add (test.index, original, 2, expected + i);

	snapshot = p11_index_snapshot (test.index, NULL, NULL, 0);
	CuAssertPtrNotNull (cu, snapshot);

	for (i = 0; i < NUM; i++)
		CuAssertTrue (cu, snapshot[i] != 0);
	CuAssertTrue (cu, snapshot[NUM] == 0);

	qsort (snapshot, NUM, sizeof (CK_OBJECT_HANDLE), compar_ulong);

	for (i = 0; i < NUM; i++)
		CuAssertIntEquals (cu, expected[i], snapshot[i]);

	teardown (cu);
}

static void
test_snapshot_base (CuTest *cu)
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

	setup (cu);

	for (i = 0; i < NUM; i++) {
		rv = p11_index_add (test.index, original, 2, expected + i);
		CuAssertTrue (cu, rv == CKR_OK);
	}

	snapshot = p11_index_snapshot (test.index, test.index, NULL, 0);
	CuAssertPtrNotNull (cu, snapshot);

	for (i = 0; i < NUM * 2; i++)
		CuAssertTrue (cu, snapshot[i] != 0);
	CuAssertTrue (cu, snapshot[NUM * 2] == 0);

	qsort (snapshot, NUM * 2, sizeof (CK_OBJECT_HANDLE), compar_ulong);

	for (i = 0; i < NUM * 2; i++)
		CuAssertIntEquals (cu, expected[i / 2], snapshot[i]);

	teardown (cu);
}

static void
test_remove (CuTest *cu)
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

	setup (cu);

	attrs = p11_attrs_dup (original);
	rv = p11_index_take (test.index, attrs, &handle);
	CuAssertTrue (cu, rv == CKR_OK);

	check = p11_index_lookup (test.index, handle);
	CuAssertPtrEquals (cu, attrs, check);

	rv = p11_index_remove (test.index, 1UL);
	CuAssertTrue (cu, rv == CKR_OBJECT_HANDLE_INVALID);

	rv = p11_index_remove (test.index, handle);
	CuAssertTrue (cu, rv == CKR_OK);

	check = p11_index_lookup (test.index, handle);
	CuAssertPtrEquals (cu, NULL, check);

	teardown (cu);
}

static void
test_set (CuTest *cu)
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

	setup (cu);

	attrs = p11_attrs_dup (original);
	rv = p11_index_take (test.index, attrs, &handle);
	CuAssertTrue (cu, rv == CKR_OK);

	check = p11_index_lookup (test.index, handle);
	test_check_attrs (cu, original, check);

	rv = p11_index_set (test.index, handle, &change, 1);
	CuAssertTrue (cu, rv == CKR_OK);

	check = p11_index_lookup (test.index, handle);
	test_check_attrs (cu, changed, check);

	rv = p11_index_set (test.index, 1UL, &change, 1);
	CuAssertTrue (cu, rv == CKR_OBJECT_HANDLE_INVALID);

	teardown (cu);
}

static void
test_update (CuTest *cu)
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

	setup (cu);

	attrs = p11_attrs_dup (original);
	rv = p11_index_take (test.index, attrs, &handle);
	CuAssertTrue (cu, rv == CKR_OK);

	check = p11_index_lookup (test.index, handle);
	test_check_attrs (cu, original, check);

	attrs = p11_attrs_build (NULL, &change, NULL);
	rv = p11_index_update (test.index, handle, attrs);
	CuAssertTrue (cu, rv == CKR_OK);

	check = p11_index_lookup (test.index, handle);
	test_check_attrs (cu, changed, check);

	attrs = p11_attrs_build (NULL, &change, NULL);
	rv = p11_index_update (test.index, 1L, attrs);
	CuAssertTrue (cu, rv == CKR_OBJECT_HANDLE_INVALID);

	teardown (cu);
}

static void
test_find (CuTest *tc)
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

	setup (tc);

	p11_index_add (test.index, first, 2, &one);
	p11_index_add (test.index, second, 2, &two);
	p11_index_add (test.index, third, 2, &three);

	check = p11_index_find (test.index, match3, -1);
	CuAssertIntEquals (tc, three, check);

	check = p11_index_find (test.index, match3, 1);
	CuAssertIntEquals (tc, three, check);

	check = p11_index_find (test.index, match_any, -1);
	CuAssertTrue (tc, check == one || check == two || check == three);

	check = p11_index_find (test.index, match_any, 1);
	CuAssertTrue (tc, check == one || check == two || check == three);

	check = p11_index_find (test.index, match_none, -1);
	CuAssertIntEquals (tc, 0, check);

	check = p11_index_find (test.index, match_none, 2);
	CuAssertIntEquals (tc, 0, check);

	teardown (tc);
}

static bool
handles_are (CK_OBJECT_HANDLE *handles,
             ...)
{
	CK_OBJECT_HANDLE handle;
	int count;
	int num;
	va_list va;
	int i;

	if (!handles)
		return false;

	/* Count number of handles */
	for (num = 0; handles[num]; num++);

	va_start (va, handles);

	for (count = 0; true; count++) {
		handle = va_arg (va, CK_OBJECT_HANDLE);
		if (handle == 0)
			break;

		for (i = 0; handles[i]; i++) {
			if (handle == handles[i])
				break;
		}

		if (handles[i] != handle)
			return false;
	}

	va_end (va);

	return (count == num);
}

static void
test_find_all (CuTest *tc)
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

	setup (tc);

	p11_index_add (test.index, first, 3, &one);
	p11_index_add (test.index, second, 3, &two);
	p11_index_add (test.index, third, 3, &three);

	check = p11_index_find_all (test.index, match_3, -1);
	CuAssertTrue (tc, handles_are (check, three, 0UL));
	free (check);

	check = p11_index_find_all (test.index, match_none, -1);
	CuAssertTrue (tc, handles_are (check, 0UL));
	free (check);

	check = p11_index_find_all (test.index, match_odd, -1);
	CuAssertTrue (tc, handles_are (check, one, three, 0UL));
	free (check);

	check = p11_index_find_all (test.index, match_any, -1);
	CuAssertTrue (tc, handles_are (check, one, two, three, 0UL));
	free (check);

	check = p11_index_find_all (test.index, match_none, -1);
	CuAssertPtrNotNull (tc, check);
	CuAssertIntEquals (tc, 0, check[0]);
	free (check);

	/* A double check of this method */
	one = 0UL;
	check = &one;
	CuAssertTrue (tc, !handles_are (check, 29292929, 0UL));
	CuAssertTrue (tc, !handles_are (NULL, 0UL));

	teardown (tc);
}

static void
test_find_realloc (CuTest *tc)
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

	setup (tc);

	for (i = 0; i < 1000; i++)
		p11_index_add (test.index, attrs, 3, NULL);

	check = p11_index_find_all (test.index, match, -1);
	CuAssertPtrNotNull (tc, check);

	for (i = 0; i < 1000; i++)
		CuAssertTrue (tc, check[i] != 0);
	CuAssertIntEquals (tc, 0, check[1000]);

	free (check);
	teardown (tc);
}

static void
test_replace_all (CuTest *tc)
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

	setup (tc);

	p11_index_add (test.index, first, 3, &one);
	CuAssertTrue (tc, one != 0);
	p11_index_add (test.index, second, 3, &two);
	CuAssertTrue (tc, two != 0);
	p11_index_add (test.index, third, 3, &three);
	CuAssertTrue (tc, three != 0);
	p11_index_add (test.index, fifth, 3, &five);
	CuAssertTrue (tc, five != 0);

	array = p11_array_new (p11_attrs_free);
	p11_array_push (array, p11_attrs_buildn (NULL, eins, 3));
	p11_array_push (array, p11_attrs_buildn (NULL, sieben, 3));
	p11_array_push (array, p11_attrs_buildn (NULL, neun, 3));

	rv = p11_index_replace_all (test.index, match, CKA_VALUE, array);
	CuAssertTrue (tc, rv == CKR_OK);

	CuAssertIntEquals (tc, 0, array->num);

	/* eins should have replaced one */
	check = p11_index_find (test.index, eins, -1);
	CuAssertIntEquals (tc, one, check);

	/* two should still be around */
	check = p11_index_find (test.index, second, -1);
	CuAssertIntEquals (tc, two, check);

	/* three should have been removed */
	check = p11_index_find (test.index, third, -1);
	CuAssertIntEquals (tc, 0, check);

	/* five should have been removed */
	check = p11_index_find (test.index, fifth, -1);
	CuAssertIntEquals (tc, 0, check);

	/* sieben should have been added */
	check = p11_index_find (test.index, sieben, -1);
	CuAssertTrue (tc, check != one && check != two && check != three && check != five);

	/* neun should have been added */
	check = p11_index_find (test.index, neun, -1);
	CuAssertTrue (tc, check != one && check != two && check != three && check != five);

	CuAssertIntEquals (tc, 4, p11_index_size (test.index));

	teardown (tc);
}


static CK_RV
on_build_populate (void *data,
                   p11_index *index,
                   CK_ATTRIBUTE **attrs,
                   CK_ATTRIBUTE *merge)
{
	CuTest *cu = data;

	CK_ATTRIBUTE override[] = {
		{ CKA_APPLICATION, "vigorous", 8 },
		{ CKA_LABEL, "naay", 4 },
		{ CKA_INVALID },
	};

	CuAssertPtrNotNull (cu, index);
	CuAssertPtrNotNull (cu, attrs);
	CuAssertPtrNotNull (cu, merge);

	*attrs = p11_attrs_merge (*attrs, merge, true);
	*attrs = p11_attrs_merge (*attrs, p11_attrs_dup (override), true);
	return CKR_OK;
}

static void
test_build_populate (CuTest *cu)
{
	CK_ATTRIBUTE original[] = {
		{ CKA_LABEL, "yay", 3 },
		{ CKA_VALUE, "eight", 5 },
		{ CKA_INVALID }

	};

	CK_ATTRIBUTE after[] = {
		{ CKA_LABEL, "naay", 4 },
		{ CKA_VALUE, "eight", 5 },
		{ CKA_APPLICATION, "vigorous", 8 },
		{ CKA_INVALID }
	};

	CK_OBJECT_HANDLE handle;
	CK_ATTRIBUTE *check;
	p11_index *index;
	CK_RV rv;

	index = p11_index_new (on_build_populate, NULL, cu);
	CuAssertPtrNotNull (cu, index);

	rv = p11_index_add (index, original, 2, &handle);
	CuAssertTrue (cu, rv == CKR_OK);

	check = p11_index_lookup (index, handle);
	CuAssertPtrNotNull (cu, check);

	test_check_attrs (cu, after, check);

	rv = p11_index_set (index, handle, original, 2);
	CuAssertTrue (cu, rv == CKR_OK);

	check = p11_index_lookup (index, handle);
	CuAssertPtrNotNull (cu, check);

	test_check_attrs (cu, after, check);

	p11_index_free (index);
}

static CK_RV
on_build_fail (void *data,
               p11_index *index,
               CK_ATTRIBUTE **attrs,
               CK_ATTRIBUTE *merge)
{
	CuTest *cu = data;

	CK_ATTRIBUTE check[] = {
		{ CKA_LABEL, "nay", 3 },
		{ CKA_INVALID }
	};

	CuAssertPtrNotNull (cu, merge);

	if (p11_attrs_match (merge, check))
		return CKR_DEVICE_ERROR;

	*attrs = p11_attrs_merge (*attrs, merge, true);
	return CKR_OK;
}


static void
test_build_fail (CuTest *cu)
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

	index = p11_index_new (on_build_fail, NULL, cu);
	CuAssertPtrNotNull (cu, index);

	rv = p11_index_add (index, okay, 2, &handle);
	CuAssertTrue (cu, rv == CKR_OK);

	rv = p11_index_add (index, fails, 2, NULL);
	CuAssertTrue (cu, rv == CKR_DEVICE_ERROR);

	rv = p11_index_set (index, handle, fails, 2);
	CuAssertTrue (cu, rv == CKR_DEVICE_ERROR);

	rv = p11_index_set (index, handle, okay, 2);
	CuAssertTrue (cu, rv == CKR_OK);

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
	CuTest *cu = data;

	CK_ATTRIBUTE check[] = {
		{ CKA_LABEL, "yay", 3 },
		{ CKA_VALUE, "eight", 5 },
		{ CKA_INVALID }

	};

	CuAssertPtrNotNull (cu, index);
	CuAssertPtrNotNull (cu, attrs);

	if (!on_change_batching) {
		if (on_change_removing)
			CuAssertIntEquals (cu, 0, handle);
		else
			CuAssertTrue (cu, handle != 0);
	}

	test_check_attrs (cu, check, attrs);
	on_change_called++;
}

static void
test_change_called (CuTest *cu)
{
	CK_ATTRIBUTE original[] = {
		{ CKA_LABEL, "yay", 3 },
		{ CKA_VALUE, "eight", 5 },
		{ CKA_INVALID }

	};

	CK_OBJECT_HANDLE handle;
	p11_index *index;
	CK_RV rv;

	index = p11_index_new (NULL, on_change_check, cu);
	CuAssertPtrNotNull (cu, index);

	on_change_removing = false;
	on_change_called = 0;

	rv = p11_index_add (index, original, 2, NULL);
	CuAssertTrue (cu, rv == CKR_OK);

	CuAssertIntEquals (cu, 1, on_change_called);

	rv = p11_index_add (index, original, 2, NULL);
	CuAssertTrue (cu, rv == CKR_OK);

	CuAssertIntEquals (cu, 2, on_change_called);

	rv = p11_index_add (index, original, 2, &handle);
	CuAssertTrue (cu, rv == CKR_OK);

	CuAssertIntEquals (cu, 3, on_change_called);

	on_change_removing = true;

	rv = p11_index_remove (index, handle);
	CuAssertTrue (cu, rv == CKR_OK);

	CuAssertIntEquals (cu, 4, on_change_called);

	p11_index_free (index);
}

static void
test_change_batch (CuTest *cu)
{
	CK_ATTRIBUTE original[] = {
		{ CKA_LABEL, "yay", 3 },
		{ CKA_VALUE, "eight", 5 },
		{ CKA_INVALID }

	};

	CK_OBJECT_HANDLE handle;
	p11_index *index;
	CK_RV rv;

	index = p11_index_new (NULL, on_change_check, cu);
	CuAssertPtrNotNull (cu, index);

	on_change_batching = true;
	on_change_called = 0;

	p11_index_batch (index);

	CuAssertTrue (cu, p11_index_in_batch (index));

	rv = p11_index_add (index, original, 2, NULL);
	CuAssertTrue (cu, rv == CKR_OK);

	CuAssertIntEquals (cu, 0, on_change_called);

	rv = p11_index_add (index, original, 2, NULL);
	CuAssertTrue (cu, rv == CKR_OK);

	CuAssertIntEquals (cu, 0, on_change_called);

	rv = p11_index_add (index, original, 2, &handle);
	CuAssertTrue (cu, rv == CKR_OK);

	CuAssertIntEquals (cu, 0, on_change_called);

	/* Nested batch is a noop */
	p11_index_batch (index);

	rv = p11_index_remove (index, handle);
	CuAssertTrue (cu, rv == CKR_OK);

	CuAssertIntEquals (cu, 0, on_change_called);

	/*
	 * Batch finishes when first finish call is called,
	 * even when batches are nested
	 */
	p11_index_finish (index);

	CuAssertTrue (cu, !p11_index_in_batch (index));

	/*
	 * Only three calls, because later operations on the
	 * same handle override the earlier one.
	 */
	CuAssertIntEquals (cu, 3, on_change_called);

	/* This is a noop */
	p11_index_finish (index);

	CuAssertTrue (cu, !p11_index_in_batch (index));

	p11_index_free (index);
}

static void
on_change_nested (void *data,
                  p11_index *index,
                  CK_OBJECT_HANDLE handle,
                  CK_ATTRIBUTE *attrs)
{
	CuTest *cu = data;
	CK_RV rv;

	CK_ATTRIBUTE second[] = {
		{ CKA_LABEL, "yay", 3 },
		{ CKA_VALUE, "eight", 5 },
		{ CKA_INVALID }

	};

	on_change_called++;

	/* A nested call */
	rv = p11_index_add (index, second, 2, NULL);
	CuAssertTrue (cu, rv == CKR_OK);
}

static void
test_change_nested (CuTest *cu)
{
	CK_ATTRIBUTE original[] = {
		{ CKA_LABEL, "yay", 3 },
		{ CKA_VALUE, "eight", 5 },
		{ CKA_INVALID }

	};

	p11_index *index;
	CK_RV rv;

	index = p11_index_new (NULL, on_change_nested, cu);
	CuAssertPtrNotNull (cu, index);

	on_change_called = 0;
	rv = p11_index_add (index, original, 2, NULL);
	CuAssertTrue (cu, rv == CKR_OK);
	CuAssertIntEquals (cu, 1, on_change_called);


	on_change_called = 0;
	p11_index_batch (index);
	rv = p11_index_add (index, original, 2, NULL);
	CuAssertTrue (cu, rv == CKR_OK);
	p11_index_finish (index);
	CuAssertIntEquals (cu, 1, on_change_called);
}

int
main (void)
{
	CuString *output = CuStringNew ();
	CuSuite* suite = CuSuiteNew ();
	int ret;

	putenv ("P11_KIT_STRICT=1");
	p11_library_init ();
	p11_debug_init ();
	p11_message_quiet ();

	SUITE_ADD_TEST (suite, test_add_lookup);
	SUITE_ADD_TEST (suite, test_take_lookup);
	SUITE_ADD_TEST (suite, test_size);
	SUITE_ADD_TEST (suite, test_remove);
	SUITE_ADD_TEST (suite, test_snapshot);
	SUITE_ADD_TEST (suite, test_snapshot_base);
	SUITE_ADD_TEST (suite, test_set);
	SUITE_ADD_TEST (suite, test_update);
	SUITE_ADD_TEST (suite, test_find);
	SUITE_ADD_TEST (suite, test_find_all);
	SUITE_ADD_TEST (suite, test_find_realloc);
	SUITE_ADD_TEST (suite, test_replace_all);
	SUITE_ADD_TEST (suite, test_build_populate);
	SUITE_ADD_TEST (suite, test_build_fail);
	SUITE_ADD_TEST (suite, test_change_called);
	SUITE_ADD_TEST (suite, test_change_batch);
	SUITE_ADD_TEST (suite, test_change_nested);

	CuSuiteRun (suite);
	CuSuiteSummary (suite, output);
	CuSuiteDetails (suite, output);
	printf ("%s\n", output->buffer);
	ret = suite->failCount;
	CuSuiteDelete (suite);
	CuStringDelete (output);

	return ret;
}
