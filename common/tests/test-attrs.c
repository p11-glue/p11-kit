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

static void
test_count (CuTest *tc)
{
	CK_BBOOL vtrue = CK_TRUE;

	CK_ATTRIBUTE attrs[] = {
		{ CKA_LABEL, "label", 5 },
		{ CKA_TOKEN, &vtrue, sizeof (vtrue) },
		{ CKA_INVALID },
	};

	CK_ATTRIBUTE empty[] = {
		{ CKA_INVALID },
	};

	CuAssertIntEquals (tc, 2, p11_attrs_count (attrs));
	CuAssertIntEquals (tc, 0, p11_attrs_count (NULL));
	CuAssertIntEquals (tc, 0, p11_attrs_count (empty));
}

static void
test_build_one (CuTest *tc)
{
	CK_ATTRIBUTE *attrs;
	CK_ATTRIBUTE add = { CKA_LABEL, "yay", 3 };

	attrs = p11_attrs_build (NULL, &add, NULL);

	/* Test the first attribute */
	CuAssertPtrNotNull (tc, attrs);
	CuAssertTrue (tc, attrs->type == CKA_LABEL);
	CuAssertIntEquals (tc, 3, attrs->ulValueLen);
	CuAssertTrue (tc, memcmp (attrs->pValue, "yay", 3) == 0);

	CuAssertTrue (tc, attrs[1].type == CKA_INVALID);

	p11_attrs_free (attrs);
}

static void
test_build_two (CuTest *tc)
{
	CK_ATTRIBUTE *attrs;
	CK_ATTRIBUTE one = { CKA_LABEL, "yay", 3 };
	CK_ATTRIBUTE two = { CKA_VALUE, "eight", 5 };

	attrs = p11_attrs_build (NULL, &one, &two, NULL);

	CuAssertPtrNotNull (tc, attrs);
	CuAssertTrue (tc, attrs[0].type == CKA_LABEL);
	CuAssertIntEquals (tc, 3, attrs[0].ulValueLen);
	CuAssertTrue (tc, memcmp (attrs[0].pValue, "yay", 3) == 0);

	CuAssertPtrNotNull (tc, attrs);
	CuAssertTrue (tc, attrs[1].type == CKA_VALUE);
	CuAssertIntEquals (tc, 5, attrs[1].ulValueLen);
	CuAssertTrue (tc, memcmp (attrs[1].pValue, "eight", 5) == 0);

	CuAssertTrue (tc, attrs[2].type == CKA_INVALID);

	p11_attrs_free (attrs);
}

static void
test_build_invalid (CuTest *tc)
{
	CK_ATTRIBUTE *attrs;
	CK_ATTRIBUTE one = { CKA_LABEL, "yay", 3 };
	CK_ATTRIBUTE invalid = { CKA_INVALID };
	CK_ATTRIBUTE two = { CKA_VALUE, "eight", 5 };

	attrs = p11_attrs_build (NULL, &one, &invalid, &two, NULL);

	CuAssertPtrNotNull (tc, attrs);
	CuAssertTrue (tc, attrs[0].type == CKA_LABEL);
	CuAssertIntEquals (tc, 3, attrs[0].ulValueLen);
	CuAssertTrue (tc, memcmp (attrs[0].pValue, "yay", 3) == 0);

	CuAssertPtrNotNull (tc, attrs);
	CuAssertTrue (tc, attrs[1].type == CKA_VALUE);
	CuAssertIntEquals (tc, 5, attrs[1].ulValueLen);
	CuAssertTrue (tc, memcmp (attrs[1].pValue, "eight", 5) == 0);

	CuAssertTrue (tc, attrs[2].type == CKA_INVALID);

	p11_attrs_free (attrs);
}

static void
test_buildn_two (CuTest *tc)
{
	CK_ATTRIBUTE *attrs;
	CK_ATTRIBUTE add[] = {
		{ CKA_LABEL, "yay", 3 },
		{ CKA_VALUE, "eight", 5 }
	};

	attrs = p11_attrs_buildn (NULL, add, 2);

	/* Test the first attribute */
	CuAssertPtrNotNull (tc, attrs);
	CuAssertTrue (tc, attrs->type == CKA_LABEL);
	CuAssertIntEquals (tc, 3, attrs->ulValueLen);
	CuAssertTrue (tc, memcmp (attrs->pValue, "yay", 3) == 0);

	CuAssertPtrNotNull (tc, attrs);
	CuAssertTrue (tc, attrs[1].type == CKA_VALUE);
	CuAssertIntEquals (tc, 5, attrs[1].ulValueLen);
	CuAssertTrue (tc, memcmp (attrs[1].pValue, "eight", 5) == 0);

	CuAssertTrue (tc, attrs[2].type == CKA_INVALID);

	p11_attrs_free (attrs);
}

static void
test_buildn_one (CuTest *tc)
{
	CK_ATTRIBUTE *attrs;
	CK_ATTRIBUTE add = { CKA_LABEL, "yay", 3 };

	attrs = p11_attrs_buildn (NULL, &add, 1);

	/* Test the first attribute */
	CuAssertPtrNotNull (tc, attrs);
	CuAssertTrue (tc, attrs->type == CKA_LABEL);
	CuAssertIntEquals (tc, 3, attrs->ulValueLen);
	CuAssertTrue (tc, memcmp (attrs->pValue, "yay", 3) == 0);

	CuAssertTrue (tc, attrs[1].type == CKA_INVALID);

	p11_attrs_free (attrs);
}

static void
test_build_add (CuTest *tc)
{
	CK_ATTRIBUTE initial[] = {
		{ CKA_LABEL, "label", 5 },
		{ CKA_VALUE, "nine", 4 },
	};

	CK_ATTRIBUTE *attrs;
	CK_ATTRIBUTE one = { CKA_LABEL, "yay", 3 };
	CK_ATTRIBUTE two = { CKA_TOKEN, "\x01", 1 };

	attrs = p11_attrs_buildn (NULL, initial, 2);
	attrs = p11_attrs_build (attrs, &one, &two, NULL);

	CuAssertPtrNotNull (tc, attrs);
	CuAssertTrue (tc, attrs[0].type == CKA_LABEL);
	CuAssertIntEquals (tc, 3, attrs[0].ulValueLen);
	CuAssertTrue (tc, memcmp (attrs[0].pValue, "yay", 3) == 0);

	CuAssertPtrNotNull (tc, attrs);
	CuAssertTrue (tc, attrs[1].type == CKA_VALUE);
	CuAssertIntEquals (tc, 4, attrs[1].ulValueLen);
	CuAssertTrue (tc, memcmp (attrs[1].pValue, "nine", 4) == 0);

	CuAssertPtrNotNull (tc, attrs);
	CuAssertTrue (tc, attrs[2].type == CKA_TOKEN);
	CuAssertIntEquals (tc, 1, attrs[2].ulValueLen);
	CuAssertTrue (tc, memcmp (attrs[2].pValue, "\x01", 1) == 0);

	CuAssertTrue (tc, attrs[3].type == CKA_INVALID);

	p11_attrs_free (attrs);
}

static void
test_build_null (CuTest *tc)
{
	CK_ATTRIBUTE *attrs;
	CK_ATTRIBUTE add = { CKA_LABEL, NULL, (CK_ULONG)-1 };

	attrs = p11_attrs_build (NULL, &add, NULL);

	/* Test the first attribute */
	CuAssertPtrNotNull (tc, attrs);
	CuAssertTrue (tc, attrs->type == CKA_LABEL);
	CuAssertTrue (tc, attrs->ulValueLen == (CK_ULONG)-1);
	CuAssertPtrEquals (tc, NULL, attrs->pValue);

	p11_attrs_free (attrs);
}

static void
test_dup (CuTest *tc)
{
	CK_ATTRIBUTE *attrs;
	CK_ATTRIBUTE original[] = {
		{ CKA_LABEL, "yay", 3 },
		{ CKA_VALUE, "eight", 5 },
		{ CKA_INVALID }
	};

	attrs = p11_attrs_dup (original);

	/* Test the first attribute */
	CuAssertPtrNotNull (tc, attrs);
	CuAssertTrue (tc, attrs->type == CKA_LABEL);
	CuAssertIntEquals (tc, 3, attrs->ulValueLen);
	CuAssertTrue (tc, memcmp (attrs->pValue, "yay", 3) == 0);

	CuAssertPtrNotNull (tc, attrs);
	CuAssertTrue (tc, attrs[1].type == CKA_VALUE);
	CuAssertIntEquals (tc, 5, attrs[1].ulValueLen);
	CuAssertTrue (tc, memcmp (attrs[1].pValue, "eight", 5) == 0);

	CuAssertTrue (tc, attrs[2].type == CKA_INVALID);

	p11_attrs_free (attrs);
}

static void
test_take (CuTest *tc)
{
	CK_ATTRIBUTE initial[] = {
		{ CKA_LABEL, "label", 5 },
		{ CKA_VALUE, "nine", 4 },
	};

	CK_ATTRIBUTE *attrs;

	attrs = p11_attrs_buildn (NULL, initial, 2);
	attrs = p11_attrs_take (attrs, CKA_LABEL, strdup ("boooyah"), 7);
	attrs = p11_attrs_take (attrs, CKA_TOKEN, strdup ("\x01"), 1);
	CuAssertPtrNotNull (tc, attrs);

	CuAssertTrue (tc, attrs[0].type == CKA_LABEL);
	CuAssertIntEquals (tc, 7, attrs[0].ulValueLen);
	CuAssertTrue (tc, memcmp (attrs[0].pValue, "boooyah", 7) == 0);

	CuAssertPtrNotNull (tc, attrs);
	CuAssertTrue (tc, attrs[1].type == CKA_VALUE);
	CuAssertIntEquals (tc, 4, attrs[1].ulValueLen);
	CuAssertTrue (tc, memcmp (attrs[1].pValue, "nine", 4) == 0);

	CuAssertPtrNotNull (tc, attrs);
	CuAssertTrue (tc, attrs[2].type == CKA_TOKEN);
	CuAssertIntEquals (tc, 1, attrs[2].ulValueLen);
	CuAssertTrue (tc, memcmp (attrs[2].pValue, "\x01", 1) == 0);

	CuAssertTrue (tc, attrs[3].type == CKA_INVALID);

	p11_attrs_free (attrs);
}

static void
test_free_null (CuTest *tc)
{
	p11_attrs_free (NULL);
}

static void
test_equal (CuTest *tc)
{
	char *data = "extra attribute";
	CK_ATTRIBUTE one = { CKA_LABEL, "yay", 3 };
	CK_ATTRIBUTE null = { CKA_LABEL, NULL, 3 };
	CK_ATTRIBUTE two = { CKA_VALUE, "yay", 3 };
	CK_ATTRIBUTE other = { CKA_VALUE, data, 5 };
	CK_ATTRIBUTE overflow = { CKA_VALUE, data, 5 };
	CK_ATTRIBUTE content = { CKA_VALUE, "conte", 5 };

	CuAssertTrue (tc, p11_attr_equal (&one, &one));
	CuAssertTrue (tc, !p11_attr_equal (&one, NULL));
	CuAssertTrue (tc, !p11_attr_equal (NULL, &one));
	CuAssertTrue (tc, !p11_attr_equal (&one, &two));
	CuAssertTrue (tc, !p11_attr_equal (&two, &other));
	CuAssertTrue (tc, p11_attr_equal (&other, &overflow));
	CuAssertTrue (tc, !p11_attr_equal (&one, &null));
	CuAssertTrue (tc, !p11_attr_equal (&one, &null));
	CuAssertTrue (tc, !p11_attr_equal (&other, &content));
}

static void
test_hash (CuTest *tc)
{
	char *data = "extra attribute";
	CK_ATTRIBUTE one = { CKA_LABEL, "yay", 3 };
	CK_ATTRIBUTE null = { CKA_LABEL, NULL, 3 };
	CK_ATTRIBUTE two = { CKA_VALUE, "yay", 3 };
	CK_ATTRIBUTE other = { CKA_VALUE, data, 5 };
	CK_ATTRIBUTE overflow = { CKA_VALUE, data, 5 };
	CK_ATTRIBUTE content = { CKA_VALUE, "conte", 5 };
	unsigned int hash;

	hash = p11_attr_hash (&one);
	CuAssertTrue (tc, hash != 0);

	CuAssertTrue (tc, p11_attr_hash (&one) == hash);
	CuAssertTrue (tc, p11_attr_hash (&two) != hash);
	CuAssertTrue (tc, p11_attr_hash (&other) != hash);
	CuAssertTrue (tc, p11_attr_hash (&overflow) != hash);
	CuAssertTrue (tc, p11_attr_hash (&null) != hash);
	CuAssertTrue (tc, p11_attr_hash (&content) != hash);
}

static void
test_to_string (CuTest *tc)
{
	char *data = "extra attribute";
	CK_ATTRIBUTE one = { CKA_LABEL, "yay", 3 };
	CK_ATTRIBUTE attrs[] = {
		{ CKA_LABEL, "yay", 3 },
		{ CKA_VALUE, data, 5 },
		{ CKA_INVALID },
	};

	char *string;


	string = p11_attr_to_string (&one);
	CuAssertStrEquals (tc, "{ CKA_LABEL = (3) \"yay\" }", string);
	free (string);

	string = p11_attrs_to_string (attrs);
	CuAssertStrEquals (tc, "(2) [ { CKA_LABEL = (3) \"yay\" }, { CKA_VALUE = (5) NOT-PRINTED } ]", string);
	free (string);
}

static void
test_find (CuTest *tc)
{
	CK_BBOOL vtrue = CK_TRUE;
	CK_ATTRIBUTE *attr;

	CK_ATTRIBUTE attrs[] = {
		{ CKA_LABEL, "label", 5 },
		{ CKA_TOKEN, &vtrue, sizeof (vtrue) },
		{ CKA_INVALID },
	};

	attr = p11_attrs_find (attrs, CKA_LABEL);
	CuAssertPtrEquals (tc, attrs + 0, attr);

	attr = p11_attrs_find (attrs, CKA_TOKEN);
	CuAssertPtrEquals (tc, attrs + 1, attr);

	attr = p11_attrs_find (attrs, CKA_VALUE);
	CuAssertPtrEquals (tc, NULL, attr);
}

static void
test_findn (CuTest *tc)
{
	CK_BBOOL vtrue = CK_TRUE;
	CK_ATTRIBUTE *attr;

	CK_ATTRIBUTE attrs[] = {
		{ CKA_LABEL, "label", 5 },
		{ CKA_TOKEN, &vtrue, sizeof (vtrue) },
	};

	attr = p11_attrs_findn (attrs, 2, CKA_LABEL);
	CuAssertPtrEquals (tc, attrs + 0, attr);

	attr = p11_attrs_findn (attrs, 2, CKA_TOKEN);
	CuAssertPtrEquals (tc, attrs + 1, attr);

	attr = p11_attrs_findn (attrs, 2, CKA_VALUE);
	CuAssertPtrEquals (tc, NULL, attr);

	attr = p11_attrs_findn (attrs, 1, CKA_TOKEN);
	CuAssertPtrEquals (tc, NULL, attr);
}

static void
test_remove (CuTest *tc)
{
	CK_BBOOL vtrue = CK_TRUE;
	CK_ATTRIBUTE *attr;
	CK_ATTRIBUTE *attrs;
	CK_BBOOL ret;

	CK_ATTRIBUTE initial[] = {
		{ CKA_LABEL, "label", 5 },
		{ CKA_TOKEN, &vtrue, sizeof (vtrue) },
	};

	attrs = p11_attrs_buildn (NULL, initial, 2);
	CuAssertPtrNotNull (tc, attrs);

	attr = p11_attrs_find (attrs, CKA_LABEL);
	CuAssertPtrEquals (tc, attrs + 0, attr);

	ret = p11_attrs_remove (attrs, CKA_LABEL);
	CuAssertIntEquals (tc, CK_TRUE, ret);

	attr = p11_attrs_find (attrs, CKA_LABEL);
	CuAssertPtrEquals (tc, NULL, attr);

	ret = p11_attrs_remove (attrs, CKA_LABEL);
	CuAssertIntEquals (tc, CK_FALSE, ret);

	p11_attrs_free (attrs);
}

static void
test_match (CuTest *tc)
{
	CK_BBOOL vtrue = CK_TRUE;

	CK_ATTRIBUTE attrs[] = {
		{ CKA_LABEL, "label", 5 },
		{ CKA_TOKEN, &vtrue, sizeof (vtrue) },
		{ CKA_INVALID },
	};

	CK_ATTRIBUTE subset[] = {
		{ CKA_LABEL, "label", 5 },
		{ CKA_INVALID },
	};

	CK_ATTRIBUTE different[] = {
		{ CKA_LABEL, "other", 5 },
		{ CKA_INVALID },
	};

	CK_ATTRIBUTE extra[] = {
		{ CKA_VALUE, "the value", 9 },
		{ CKA_LABEL, "other", 5 },
		{ CKA_TOKEN, &vtrue, sizeof (vtrue) },
		{ CKA_INVALID },
	};

	CuAssertTrue (tc, p11_attrs_match (attrs, attrs));
	CuAssertTrue (tc, p11_attrs_match (attrs, subset));
	CuAssertTrue (tc, !p11_attrs_match (attrs, different));
	CuAssertTrue (tc, !p11_attrs_match (attrs, extra));
}

static void
test_matchn (CuTest *tc)
{
	CK_BBOOL vtrue = CK_TRUE;

	CK_ATTRIBUTE attrs[] = {
		{ CKA_LABEL, "label", 5 },
		{ CKA_TOKEN, &vtrue, sizeof (vtrue) },
		{ CKA_INVALID },
	};

	CK_ATTRIBUTE subset[] = {
		{ CKA_LABEL, "label", 5 },
	};

	CK_ATTRIBUTE different[] = {
		{ CKA_TOKEN, &vtrue, sizeof (vtrue) },
		{ CKA_LABEL, "other", 5 },
	};

	CK_ATTRIBUTE extra[] = {
		{ CKA_VALUE, "the value", 9 },
		{ CKA_LABEL, "other", 5 },
		{ CKA_TOKEN, &vtrue, sizeof (vtrue) },
	};

	CuAssertTrue (tc, p11_attrs_matchn (attrs, subset, 1));
	CuAssertTrue (tc, !p11_attrs_matchn (attrs, different, 2));
	CuAssertTrue (tc, !p11_attrs_matchn (attrs, extra, 3));
}

static void
test_find_bool (CuTest *tc)
{
	CK_BBOOL vtrue = CK_TRUE;
	CK_BBOOL vfalse = CK_FALSE;
	CK_BBOOL value;

	CK_ATTRIBUTE attrs[] = {
		{ CKA_LABEL, "\x01yy", 3 },
		{ CKA_VALUE, &vtrue, (CK_ULONG)-1 },
		{ CKA_TOKEN, &vtrue, sizeof (CK_BBOOL) },
		{ CKA_TOKEN, &vfalse, sizeof (CK_BBOOL) },
		{ CKA_INVALID },
	};

	CuAssertTrue (tc, p11_attrs_find_bool (attrs, CKA_TOKEN, &value) && value == CK_TRUE);
	CuAssertTrue (tc, !p11_attrs_find_bool (attrs, CKA_LABEL, &value));
	CuAssertTrue (tc, !p11_attrs_find_bool (attrs, CKA_VALUE, &value));
}

static void
test_find_ulong (CuTest *tc)
{
	CK_ULONG v33 = 33UL;
	CK_ULONG v45 = 45UL;
	CK_ULONG value;

	CK_ATTRIBUTE attrs[] = {
		{ CKA_LABEL, &v33, 2 },
		{ CKA_VALUE, &v45, (CK_ULONG)-1 },
		{ CKA_BITS_PER_PIXEL, &v33, sizeof (CK_ULONG) },
		{ CKA_BITS_PER_PIXEL, &v45, sizeof (CK_ULONG) },
		{ CKA_INVALID },
	};

	CuAssertTrue (tc, p11_attrs_find_ulong (attrs, CKA_BITS_PER_PIXEL, &value) && value == v33);
	CuAssertTrue (tc, !p11_attrs_find_ulong (attrs, CKA_LABEL, &value));
	CuAssertTrue (tc, !p11_attrs_find_ulong (attrs, CKA_VALUE, &value));
}

static void
test_find_valid (CuTest *tc)
{
	CK_ATTRIBUTE *attr;

	CK_ATTRIBUTE attrs[] = {
		{ CKA_LABEL, "", (CK_ULONG)-1 },
		{ CKA_LABEL, "test", 4 },
		{ CKA_VALUE, NULL, 0 },
		{ CKA_INVALID },
	};

	attr = p11_attrs_find_valid (attrs, CKA_LABEL);
	CuAssertPtrEquals (tc, attrs + 1, attr);

	attr = p11_attrs_find_valid (attrs, CKA_VALUE);
	CuAssertPtrEquals (tc, attrs + 2, attr);

	attr = p11_attrs_find_valid (attrs, CKA_TOKEN);
	CuAssertPtrEquals (tc, NULL, attr);
}

int
main (void)
{
	CuString *output = CuStringNew ();
	CuSuite* suite = CuSuiteNew ();
	int ret;

	setenv ("P11_KIT_STRICT", "1", 1);
	p11_debug_init ();

	SUITE_ADD_TEST (suite, test_equal);
	SUITE_ADD_TEST (suite, test_hash);
	SUITE_ADD_TEST (suite, test_to_string);

	SUITE_ADD_TEST (suite, test_count);
	SUITE_ADD_TEST (suite, test_build_one);
	SUITE_ADD_TEST (suite, test_build_two);
	SUITE_ADD_TEST (suite, test_build_invalid);
	SUITE_ADD_TEST (suite, test_buildn_one);
	SUITE_ADD_TEST (suite, test_buildn_two);
	SUITE_ADD_TEST (suite, test_build_add);
	SUITE_ADD_TEST (suite, test_build_null);
	SUITE_ADD_TEST (suite, test_dup);
	SUITE_ADD_TEST (suite, test_take);
	SUITE_ADD_TEST (suite, test_free_null);
	SUITE_ADD_TEST (suite, test_match);
	SUITE_ADD_TEST (suite, test_matchn);
	SUITE_ADD_TEST (suite, test_find);
	SUITE_ADD_TEST (suite, test_findn);
	SUITE_ADD_TEST (suite, test_find_bool);
	SUITE_ADD_TEST (suite, test_find_ulong);
	SUITE_ADD_TEST (suite, test_find_valid);
	SUITE_ADD_TEST (suite, test_remove);

	CuSuiteRun (suite);
	CuSuiteSummary (suite, output);
	CuSuiteDetails (suite, output);
	printf ("%s\n", output->buffer);
	ret = suite->failCount;
	CuSuiteDelete (suite);
	CuStringDelete (output);

	return ret;
}
