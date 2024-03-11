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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "attrs.h"
#include "debug.h"

static void
test_terminator (void)
{
	CK_ATTRIBUTE attrs[] = {
		{ CKA_LABEL, "label", 5 },
		{ CKA_LABEL, NULL, 0 },
		{ CKA_INVALID },
	};

	assert_num_eq (true, p11_attrs_terminator (attrs + 2));
	assert_num_eq (true, p11_attrs_terminator (NULL));
	assert_num_eq (false, p11_attrs_terminator (attrs));
	assert_num_eq (false, p11_attrs_terminator (attrs + 1));
}

static void
test_count (void)
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

	CK_ATTRIBUTE temp[] = {
		{ CKA_LABEL, "label", 5 },
		{ CKA_ENCRYPT, &vtrue, sizeof (vtrue) },
	};

	CK_ATTRIBUTE wrapped_attrs[] = {
		{ CKA_WRAP_TEMPLATE, &temp, sizeof (temp) },
		{ CKA_INVALID },
        };

	assert_num_eq (2, p11_attrs_count (attrs));
	assert_num_eq (1, p11_attrs_count (wrapped_attrs));
	assert_num_eq (0, p11_attrs_count (NULL));
	assert_num_eq (0, p11_attrs_count (empty));
}

static void
test_build_one (void)
{
	CK_ATTRIBUTE *attrs;
	CK_ATTRIBUTE add = { CKA_LABEL, "yay", 3 };

	attrs = p11_attrs_build (NULL, &add, NULL);

	/* Test the first attribute */
	assert_ptr_not_null (attrs);
	assert (attrs->type == CKA_LABEL);
	assert_num_eq (3, attrs->ulValueLen);
	assert (memcmp (attrs->pValue, "yay", 3) == 0);

	assert (attrs[1].type == CKA_INVALID);

	p11_attrs_free (attrs);
}

static void
test_build_two (void)
{
	CK_ATTRIBUTE *attrs;
	CK_ATTRIBUTE one = { CKA_LABEL, "yay", 3 };
	CK_ATTRIBUTE two = { CKA_VALUE, "eight", 5 };

	attrs = p11_attrs_build (NULL, &one, &two, NULL);

	assert_ptr_not_null (attrs);
	assert (attrs[0].type == CKA_LABEL);
	assert_num_eq (3, attrs[0].ulValueLen);
	assert (memcmp (attrs[0].pValue, "yay", 3) == 0);

	assert_ptr_not_null (attrs);
	assert (attrs[1].type == CKA_VALUE);
	assert_num_eq (5, attrs[1].ulValueLen);
	assert (memcmp (attrs[1].pValue, "eight", 5) == 0);

	assert (attrs[2].type == CKA_INVALID);

	p11_attrs_free (attrs);
}

static void
test_build_invalid (void)
{
	CK_ATTRIBUTE *attrs;
	CK_ATTRIBUTE one = { CKA_LABEL, "yay", 3 };
	CK_ATTRIBUTE invalid = { CKA_INVALID };
	CK_ATTRIBUTE two = { CKA_VALUE, "eight", 5 };

	attrs = p11_attrs_build (NULL, &one, &invalid, &two, NULL);

	assert_ptr_not_null (attrs);
	assert (attrs[0].type == CKA_LABEL);
	assert_num_eq (3, attrs[0].ulValueLen);
	assert (memcmp (attrs[0].pValue, "yay", 3) == 0);

	assert_ptr_not_null (attrs);
	assert (attrs[1].type == CKA_VALUE);
	assert_num_eq (5, attrs[1].ulValueLen);
	assert (memcmp (attrs[1].pValue, "eight", 5) == 0);

	assert (attrs[2].type == CKA_INVALID);

	p11_attrs_free (attrs);
}

static void
test_buildn_two (void)
{
	CK_ATTRIBUTE *attrs;
	CK_ATTRIBUTE add[] = {
		{ CKA_LABEL, "yay", 3 },
		{ CKA_VALUE, "eight", 5 }
	};

	attrs = p11_attrs_buildn (NULL, add, 2);

	/* Test the first attribute */
	assert_ptr_not_null (attrs);
	assert (attrs->type == CKA_LABEL);
	assert_num_eq (3, attrs->ulValueLen);
	assert (memcmp (attrs->pValue, "yay", 3) == 0);

	assert_ptr_not_null (attrs);
	assert (attrs[1].type == CKA_VALUE);
	assert_num_eq (5, attrs[1].ulValueLen);
	assert (memcmp (attrs[1].pValue, "eight", 5) == 0);

	assert (attrs[2].type == CKA_INVALID);

	p11_attrs_free (attrs);
}

static void
test_buildn_one (void)
{
	CK_ATTRIBUTE *attrs;
	CK_ATTRIBUTE add = { CKA_LABEL, "yay", 3 };

	attrs = p11_attrs_buildn (NULL, &add, 1);

	/* Test the first attribute */
	assert_ptr_not_null (attrs);
	assert (attrs->type == CKA_LABEL);
	assert_num_eq (3, attrs->ulValueLen);
	assert (memcmp (attrs->pValue, "yay", 3) == 0);

	assert (attrs[1].type == CKA_INVALID);

	p11_attrs_free (attrs);
}

static void
test_build_add (void)
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

	assert_ptr_not_null (attrs);
	assert (attrs[0].type == CKA_LABEL);
	assert_num_eq (3, attrs[0].ulValueLen);
	assert (memcmp (attrs[0].pValue, "yay", 3) == 0);

	assert_ptr_not_null (attrs);
	assert (attrs[1].type == CKA_VALUE);
	assert_num_eq (4, attrs[1].ulValueLen);
	assert (memcmp (attrs[1].pValue, "nine", 4) == 0);

	assert_ptr_not_null (attrs);
	assert (attrs[2].type == CKA_TOKEN);
	assert_num_eq (1, attrs[2].ulValueLen);
	assert (memcmp (attrs[2].pValue, "\x01", 1) == 0);

	assert (attrs[3].type == CKA_INVALID);

	p11_attrs_free (attrs);
}

static void
test_build_null (void)
{
	CK_ATTRIBUTE *attrs;
	CK_ATTRIBUTE add = { CKA_LABEL, NULL, (CK_ULONG)-1 };

	attrs = p11_attrs_build (NULL, &add, NULL);

	/* Test the first attribute */
	assert_ptr_not_null (attrs);
	assert (attrs->type == CKA_LABEL);
	assert (attrs->ulValueLen == (CK_ULONG)-1);
	assert_ptr_eq (NULL, attrs->pValue);

	p11_attrs_free (attrs);
}

static void
test_build_recursive (void)
{
	CK_BBOOL vtrue = CK_TRUE;
	CK_BYTE vpoint[1];
	CK_ATTRIBUTE template[] = {
		{ CKA_LOCAL, &vtrue, sizeof (vtrue) },
		{ CKA_EC_POINT, vpoint, 0 },
	};
	CK_ATTRIBUTE add = { CKA_WRAP_TEMPLATE, template, sizeof (template) };
	CK_ATTRIBUTE *attrs;
	CK_ATTRIBUTE *array;

	attrs = p11_attrs_build (NULL, &add, NULL);

	/* Test the first attribute */
	assert_ptr_not_null (attrs);
	assert_num_eq (attrs->type, CKA_WRAP_TEMPLATE);
	assert_num_eq (attrs->ulValueLen, sizeof (template));
	assert_ptr_cmp (attrs->pValue, !=, template);
	array = attrs->pValue;
	/* Check that the CKA_LOCAL attribute has been copied, but
	 * still has the same value */
	assert_num_eq (array[0].type, CKA_LOCAL);
	assert_num_eq (array[0].ulValueLen, sizeof (vtrue));
	assert_ptr_cmp (array[0].pValue, !=, &vtrue);
	assert_num_eq (*(CK_BBOOL *)array[0].pValue, vtrue);
	/* Check that the CKA_EC_POINT attribute has been allocated,
	 * even if the length is zero */
	assert_num_eq (array[1].type, CKA_EC_POINT);
	assert_num_eq (array[1].ulValueLen, 0);
	assert_ptr_not_null (array[1].pValue);
	assert_ptr_cmp (array[1].pValue, !=, vpoint);
	p11_attrs_free (attrs);
}

static void
test_build_recursive_null (void)
{
	CK_BBOOL vtrue = CK_TRUE;
	CK_ATTRIBUTE template[] = {
		{ CKA_LABEL, NULL, (CK_ULONG)-1 },
		{ CKA_LOCAL, &vtrue, sizeof (vtrue) },
	};
	CK_ATTRIBUTE add = { CKA_WRAP_TEMPLATE, template, sizeof (template) };
	CK_ATTRIBUTE *attrs;
	CK_ATTRIBUTE *array;

	attrs = p11_attrs_build (NULL, &add, NULL);

	/* Test the first attribute */
	assert_ptr_not_null (attrs);
	assert_num_eq (attrs->type, CKA_WRAP_TEMPLATE);
	assert_num_eq (attrs->ulValueLen, sizeof (template));
	assert_ptr_cmp (attrs->pValue, !=, template);

	array = attrs->pValue;

	/* Check that the CKA_LABEL attribute has been copied */
	assert_num_eq (array[0].type, CKA_LABEL);
	assert_num_eq (array[0].ulValueLen, (CK_ULONG)-1);
	assert_ptr_eq (array[0].pValue, NULL);

	/* Check that the CKA_LOCAL attribute has been copied, but
	 * still has the same value */
	assert_num_eq (array[1].type, CKA_LOCAL);
	assert_num_eq (array[1].ulValueLen, sizeof (vtrue));
	assert_ptr_cmp (array[1].pValue, !=, &vtrue);
	assert_num_eq (*(CK_BBOOL *)array[1].pValue, vtrue);

	p11_attrs_free (attrs);
}

static void
test_dup (void)
{
	CK_ATTRIBUTE *attrs;
	CK_ATTRIBUTE original[] = {
		{ CKA_LABEL, "yay", 3 },
		{ CKA_VALUE, "eight", 5 },
		{ CKA_INVALID }
	};

	attrs = p11_attrs_dup (original);

	/* Test the first attribute */
	assert_ptr_not_null (attrs);
	assert (attrs->type == CKA_LABEL);
	assert_num_eq (3, attrs->ulValueLen);
	assert (memcmp (attrs->pValue, "yay", 3) == 0);

	assert_ptr_not_null (attrs);
	assert (attrs[1].type == CKA_VALUE);
	assert_num_eq (5, attrs[1].ulValueLen);
	assert (memcmp (attrs[1].pValue, "eight", 5) == 0);

	assert (attrs[2].type == CKA_INVALID);

	p11_attrs_free (attrs);
}

static void
test_dup_recursive (void)
{
	CK_BBOOL vtrue = CK_TRUE;
	CK_ATTRIBUTE *attrs, *array;
	CK_ATTRIBUTE template[] = {
		{ CKA_LOCAL, &vtrue, sizeof (vtrue) },
		{ CKA_LABEL, "label", 5 },
	};
	CK_ATTRIBUTE original[] = {
		{ CKA_WRAP_TEMPLATE, template, sizeof (template) },
		{ CKA_LABEL, "yay", 3 },
		{ CKA_INVALID },
	};

	attrs = p11_attrs_dup (original);
	assert_ptr_not_null (attrs);

	/* Test the first attribute */
	assert (attrs[0].type == CKA_WRAP_TEMPLATE);
	assert_num_eq (attrs[0].ulValueLen, sizeof (template));
	assert_ptr_cmp (attrs[0].pValue, !=, template);

	array = attrs[0].pValue;

	/* Test the first template attribute */
	assert (array[0].type == CKA_LOCAL);
	assert_num_eq (array[0].ulValueLen, sizeof (vtrue));
	assert_ptr_cmp (array[0].pValue, !=, &vtrue);
	assert_num_eq (*(CK_BBOOL *)array[0].pValue, vtrue);

	/* Test the second template attribute */
	assert (array[1].type == CKA_LABEL);
	assert_num_eq (array[1].ulValueLen, 5);
	assert (memcmp (array[1].pValue, "label", 5) == 0);

	/* Test the second attribute */
	assert (attrs[1].type == CKA_LABEL);
	assert_num_eq (attrs[1].ulValueLen, 3);
	assert (memcmp (attrs[1].pValue, "yay", 3) == 0);

	assert (attrs[2].type == CKA_INVALID);

	p11_attrs_free (attrs);
}

static void
test_take (void)
{
	CK_ATTRIBUTE initial[] = {
		{ CKA_LABEL, "label", 5 },
		{ CKA_VALUE, "nine", 4 },
	};

	CK_ATTRIBUTE *attrs;

	attrs = p11_attrs_buildn (NULL, initial, 2);
	attrs = p11_attrs_take (attrs, CKA_LABEL, strdup ("boooyah"), 7);
	attrs = p11_attrs_take (attrs, CKA_TOKEN, strdup ("\x01"), 1);
	assert_ptr_not_null (attrs);

	assert (attrs[0].type == CKA_LABEL);
	assert_num_eq (7, attrs[0].ulValueLen);
	assert (memcmp (attrs[0].pValue, "boooyah", 7) == 0);

	assert_ptr_not_null (attrs);
	assert (attrs[1].type == CKA_VALUE);
	assert_num_eq (4, attrs[1].ulValueLen);
	assert (memcmp (attrs[1].pValue, "nine", 4) == 0);

	assert_ptr_not_null (attrs);
	assert (attrs[2].type == CKA_TOKEN);
	assert_num_eq (1, attrs[2].ulValueLen);
	assert (memcmp (attrs[2].pValue, "\x01", 1) == 0);

	assert (attrs[3].type == CKA_INVALID);

	p11_attrs_free (attrs);
}

static void
test_take_recursive (void)
{
	CK_ATTRIBUTE *attrs, *array, *template;
	CK_ATTRIBUTE initial_template[] = {
		{ CKA_LABEL, "yay", 3 },
	};
	CK_ATTRIBUTE initial[] = {
		{ CKA_WRAP_TEMPLATE, initial_template, sizeof (initial_template) },
		{ CKA_VALUE, "nine", 4 },
	};

	template = malloc (2 * sizeof (CK_ATTRIBUTE));
	assert_ptr_not_null (template);
	template[0].type = CKA_LOCAL;
	template[0].ulValueLen = sizeof (CK_BBOOL);
	template[0].pValue = malloc (template[0].ulValueLen);
	assert_ptr_not_null (template[0].pValue);
	*(CK_BBOOL *)(template[0].pValue) = CK_TRUE;
	template[1].type = CKA_LABEL;
	template[1].ulValueLen = 5;
	template[1].pValue = malloc (template[1].ulValueLen);
	assert_ptr_not_null (template[1].pValue);
	memcpy (template[1].pValue, "label", 5);

	attrs = p11_attrs_buildn (NULL, initial, 2);
	attrs = p11_attrs_take (attrs, CKA_WRAP_TEMPLATE, template, 2 * sizeof (CK_ATTRIBUTE));
	attrs = p11_attrs_take (attrs, CKA_TOKEN, strdup ("\x01"), 1);
	assert_ptr_not_null (attrs);

	assert (attrs[0].type == CKA_WRAP_TEMPLATE);
	assert_num_eq (attrs[0].ulValueLen, 2 * sizeof (CK_ATTRIBUTE));
	assert_ptr_not_null (attrs[0].pValue);

	array = attrs[0].pValue;

	assert (array[0].type == CKA_LOCAL);
	assert_num_eq (array[0].ulValueLen, sizeof (CK_BBOOL));
	assert (*(CK_BBOOL *)(array[0].pValue) == CK_TRUE);

	assert (array[1].type == CKA_LABEL);
	assert_num_eq (array[1].ulValueLen, 5);
	assert (memcmp (array[1].pValue, "label", 5) == 0);

	assert (attrs[1].type == CKA_VALUE);
	assert_num_eq (4, attrs[1].ulValueLen);
	assert (memcmp (attrs[1].pValue, "nine", 4) == 0);

	assert (attrs[2].type == CKA_TOKEN);
	assert_num_eq (1, attrs[2].ulValueLen);
	assert (memcmp (attrs[2].pValue, "\x01", 1) == 0);

	assert (attrs[3].type == CKA_INVALID);

	p11_attrs_free (attrs);
}

static void
test_merge_replace (void)
{
	CK_ATTRIBUTE initial[] = {
		{ CKA_LABEL, "label", 5 },
		{ CKA_VALUE, "nine", 4 },
	};

	CK_ATTRIBUTE extra[] = {
		{ CKA_LABEL, "boooyah", 7 },
		{ CKA_APPLICATION, "disco", 5 },
	};

	CK_ATTRIBUTE *attrs;
	CK_ATTRIBUTE *merge;

	attrs = p11_attrs_buildn (NULL, initial, 2);
	merge = p11_attrs_buildn (NULL, extra, 2);
	attrs = p11_attrs_merge (attrs, merge, true);
	assert_ptr_not_null (attrs);

	assert (attrs[0].type == CKA_LABEL);
	assert_num_eq (7, attrs[0].ulValueLen);
	assert (memcmp (attrs[0].pValue, "boooyah", 7) == 0);

	assert_ptr_not_null (attrs);
	assert (attrs[1].type == CKA_VALUE);
	assert_num_eq (4, attrs[1].ulValueLen);
	assert (memcmp (attrs[1].pValue, "nine", 4) == 0);

	assert_ptr_not_null (attrs);
	assert (attrs[2].type == CKA_APPLICATION);
	assert_num_eq (5, attrs[2].ulValueLen);
	assert (memcmp (attrs[2].pValue, "disco", 5) == 0);

	assert (attrs[3].type == CKA_INVALID);

	p11_attrs_free (attrs);
}

static void
test_merge_empty (void)
{
	CK_ATTRIBUTE extra[] = {
		{ CKA_LABEL, "boooyah", 7 },
		{ CKA_APPLICATION, "disco", 5 },
	};

	CK_ATTRIBUTE *attrs = NULL;
	CK_ATTRIBUTE *merge;

	merge = p11_attrs_buildn (NULL, extra, 2);
	attrs = p11_attrs_merge (attrs, merge, true);
	assert_ptr_not_null (attrs);
	assert_ptr_eq (merge, attrs);

	p11_attrs_free (attrs);
}

static void
test_merge_augment (void)
{
	CK_ATTRIBUTE initial[] = {
		{ CKA_LABEL, "label", 5 },
		{ CKA_VALUE, "nine", 4 },
	};

	CK_ATTRIBUTE extra[] = {
		{ CKA_LABEL, "boooyah", 7 },
		{ CKA_APPLICATION, "disco", 5 },
	};

	CK_ATTRIBUTE *attrs;
	CK_ATTRIBUTE *merge;

	attrs = p11_attrs_buildn (NULL, initial, 2);
	merge = p11_attrs_buildn (NULL, extra, 2);
	attrs = p11_attrs_merge (attrs, merge, false);
	assert_ptr_not_null (attrs);

	assert (attrs[0].type == CKA_LABEL);
	assert_num_eq (5, attrs[0].ulValueLen);
	assert (memcmp (attrs[0].pValue, "label", 5) == 0);

	assert_ptr_not_null (attrs);
	assert (attrs[1].type == CKA_VALUE);
	assert_num_eq (4, attrs[1].ulValueLen);
	assert (memcmp (attrs[1].pValue, "nine", 4) == 0);

	assert_ptr_not_null (attrs);
	assert (attrs[2].type == CKA_APPLICATION);
	assert_num_eq (5, attrs[2].ulValueLen);
	assert (memcmp (attrs[2].pValue, "disco", 5) == 0);

	assert (attrs[3].type == CKA_INVALID);

	p11_attrs_free (attrs);
}

static void
test_merge_replace_recursive (void)
{
	CK_ATTRIBUTE temp1[] = {
		{ CKA_VALUE, "nine", 4 },
	};
	CK_ATTRIBUTE initial[] = {
		{ CKA_WRAP_TEMPLATE, temp1, sizeof (temp1) },
		{ CKA_VALUE, "nine", 4 },
	};

	CK_ATTRIBUTE temp2[] = {
		{ CKA_VALUE, "seven", 5 },
		{ CKA_LABEL, "yay", 3 },
	};
	CK_ATTRIBUTE extra[] = {
		{ CKA_WRAP_TEMPLATE, temp2, sizeof (temp2) },
		{ CKA_APPLICATION, "disco", 5 },
	};

	CK_ATTRIBUTE *array;
	CK_ATTRIBUTE *attrs;
	CK_ATTRIBUTE *merge;

	attrs = p11_attrs_buildn (NULL, initial, 2);
	merge = p11_attrs_buildn (NULL, extra, 2);
	attrs = p11_attrs_merge (attrs, merge, true);
	assert_ptr_not_null (attrs);

	assert (attrs[0].type == CKA_WRAP_TEMPLATE);
	assert_num_eq (attrs[0].ulValueLen, sizeof (temp2));
	assert_ptr_not_null (attrs[0].pValue);

	array = attrs[0].pValue;

	assert (array[0].type == CKA_VALUE);
	assert_num_eq (array[0].ulValueLen, 5);
	assert (memcmp (array[0].pValue, "seven", 5) == 0);

	assert (array[1].type == CKA_LABEL);
	assert_num_eq (array[1].ulValueLen, 3);
	assert (memcmp (array[1].pValue, "yay", 3) == 0);

	assert_ptr_not_null (attrs);
	assert (attrs[1].type == CKA_VALUE);
	assert_num_eq (4, attrs[1].ulValueLen);
	assert (memcmp (attrs[1].pValue, "nine", 4) == 0);

	assert_ptr_not_null (attrs);
	assert (attrs[2].type == CKA_APPLICATION);
	assert_num_eq (5, attrs[2].ulValueLen);
	assert (memcmp (attrs[2].pValue, "disco", 5) == 0);

	assert (attrs[3].type == CKA_INVALID);

	p11_attrs_free (attrs);
}

static void
test_merge_augment_recursive (void)
{
	CK_ATTRIBUTE temp1[] = {
		{ CKA_VALUE, "nine", 4 },
	};
	CK_ATTRIBUTE initial[] = {
		{ CKA_WRAP_TEMPLATE, temp1, sizeof (temp1) },
		{ CKA_VALUE, "nine", 4 },
	};

	CK_ATTRIBUTE temp2[] = {
		{ CKA_VALUE, "seven", 5 },
		{ CKA_LABEL, "yay", 3 },
	};
	CK_ATTRIBUTE extra[] = {
		{ CKA_WRAP_TEMPLATE, temp2, sizeof (temp2) },
		{ CKA_APPLICATION, "disco", 5 },
	};

	CK_ATTRIBUTE *array;
	CK_ATTRIBUTE *attrs;
	CK_ATTRIBUTE *merge;

	attrs = p11_attrs_buildn (NULL, initial, 2);
	merge = p11_attrs_buildn (NULL, extra, 2);
	attrs = p11_attrs_merge (attrs, merge, false);
	assert_ptr_not_null (attrs);

	assert (attrs[0].type == CKA_WRAP_TEMPLATE);
	assert_num_eq (attrs[0].ulValueLen, sizeof (temp1));
	assert_ptr_not_null (attrs[0].pValue);

	array = attrs[0].pValue;

	assert (array[0].type == CKA_VALUE);
	assert_num_eq (array[0].ulValueLen, 4);
	assert (memcmp (array[0].pValue, "nine", 4) == 0);

	assert_ptr_not_null (attrs);
	assert (attrs[1].type == CKA_VALUE);
	assert_num_eq (4, attrs[1].ulValueLen);
	assert (memcmp (attrs[1].pValue, "nine", 4) == 0);

	assert_ptr_not_null (attrs);
	assert (attrs[2].type == CKA_APPLICATION);
	assert_num_eq (5, attrs[2].ulValueLen);
	assert (memcmp (attrs[2].pValue, "disco", 5) == 0);

	assert (attrs[3].type == CKA_INVALID);

	p11_attrs_free (attrs);
}

static void
test_free_null (void)
{
	p11_attrs_free (NULL);
}

static void
test_equal (void)
{
	char *data = "extra attribute";
	CK_ATTRIBUTE one = { CKA_LABEL, "yay", 3 };
	CK_ATTRIBUTE null = { CKA_LABEL, NULL, 3 };
	CK_ATTRIBUTE two = { CKA_VALUE, "yay", 3 };
	CK_ATTRIBUTE other = { CKA_VALUE, data, 5 };
	CK_ATTRIBUTE overflow = { CKA_VALUE, data, 5 };
	CK_ATTRIBUTE content = { CKA_VALUE, "conte", 5 };

	assert (p11_attr_equal (&one, &one));
	assert (!p11_attr_equal (&one, NULL));
	assert (!p11_attr_equal (NULL, &one));
	assert (!p11_attr_equal (&one, &two));
	assert (!p11_attr_equal (&two, &other));
	assert (p11_attr_equal (&other, &overflow));
	assert (!p11_attr_equal (&one, &null));
	assert (!p11_attr_equal (&one, &null));
	assert (!p11_attr_equal (&other, &content));
}

static void
test_equal_recursive (void)
{
	CK_ATTRIBUTE temp1[] = {
		{ CKA_LABEL, "yay", 3 },
	};
	CK_ATTRIBUTE temp2[] = {
		{ CKA_LABEL, "yay", 3 },
		{ CKA_VALUE, "conte", 5 },
	};
	CK_ATTRIBUTE temp3[] = {
		{ CKA_VALUE, "conte", 5 },
		{ CKA_LABEL, "yay", 3 },
	};
	CK_ATTRIBUTE temp4[] = {
		{ CKA_LABEL, "conte", 5 },
		{ CKA_VALUE, "yay", 3 },
	};
	CK_ATTRIBUTE temp_one = { CKA_WRAP_TEMPLATE, temp1, sizeof (temp1) };
	CK_ATTRIBUTE temp_two = { CKA_WRAP_TEMPLATE, temp2, sizeof (temp2) };
	CK_ATTRIBUTE temp_three = { CKA_WRAP_TEMPLATE, temp3, sizeof (temp3) };
	CK_ATTRIBUTE temp_four = { CKA_WRAP_TEMPLATE, temp4, sizeof (temp4) };

	assert (p11_attr_equal (&temp_one, &temp_one));
	assert (p11_attr_equal (&temp_two, &temp_two));
	assert (!p11_attr_equal (&temp_one, &temp_two));
	assert (!p11_attr_equal (&temp_two, &temp_three));
	assert (!p11_attr_equal (&temp_three, &temp_four));
}

static void
test_hash (void)
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
	assert (hash != 0);

	assert (p11_attr_hash (&one) == hash);
	assert (p11_attr_hash (&two) != hash);
	assert (p11_attr_hash (&other) != hash);
	assert (p11_attr_hash (&overflow) != hash);
	assert (p11_attr_hash (&null) != hash);
	assert (p11_attr_hash (&content) != hash);

	hash = p11_attr_hash (NULL);
	assert (hash == 0);
}

static void
test_to_string (void)
{
	char *data = "extra attribute";
	CK_ATTRIBUTE one = { CKA_LABEL, "yay", 3 };
	CK_ATTRIBUTE attrs[] = {
		{ CKA_LABEL, "yay", 3 },
		{ CKA_VALUE, data, 5 },
		{ CKA_INVALID },
	};

	char *string;


	string = p11_attr_to_string (&one, CKA_INVALID);
	assert_str_eq ("{ CKA_LABEL = (3) \"yay\" }", string);
	free (string);

	string = p11_attrs_to_string (attrs, -1);
	assert_str_eq ("(2) [ { CKA_LABEL = (3) \"yay\" }, { CKA_VALUE = (5) NOT-PRINTED } ]", string);
	free (string);

	string = p11_attrs_to_string (attrs, 1);
	assert_str_eq ("(1) [ { CKA_LABEL = (3) \"yay\" } ]", string);
	free (string);
}

static void
test_find (void)
{
	CK_BBOOL vtrue = CK_TRUE;
	CK_ATTRIBUTE *attr;

	CK_ATTRIBUTE template[] = {
		{ CKA_VALUE, "value", 5 },
	};
	CK_ATTRIBUTE attrs[] = {
		{ CKA_LABEL, "label", 5 },
		{ CKA_TOKEN, &vtrue, sizeof (vtrue) },
		{ CKA_WRAP_TEMPLATE, template, sizeof (template) },
		{ CKA_INVALID },
	};

	attr = p11_attrs_find (attrs, CKA_LABEL);
	assert_ptr_eq (attrs + 0, attr);

	attr = p11_attrs_find (attrs, CKA_TOKEN);
	assert_ptr_eq (attrs + 1, attr);

	attr = p11_attrs_find (attrs, CKA_WRAP_TEMPLATE);
	assert_ptr_eq (attrs + 2, attr);

	attr = p11_attrs_find (attrs, CKA_VALUE);
	assert_ptr_eq (NULL, attr);
}

static void
test_findn (void)
{
	CK_BBOOL vtrue = CK_TRUE;
	CK_ATTRIBUTE *attr;

	CK_ATTRIBUTE template[] = {
		{ CKA_VALUE, "value", 5 },
	};
	CK_ATTRIBUTE attrs[] = {
		{ CKA_WRAP_TEMPLATE, template, sizeof (template) },
		{ CKA_LABEL, "label", 5 },
		{ CKA_TOKEN, &vtrue, sizeof (vtrue) },
	};

	attr = p11_attrs_findn (attrs, 3, CKA_WRAP_TEMPLATE);
	assert_ptr_eq (attrs + 0, attr);

	attr = p11_attrs_findn (attrs, 3, CKA_LABEL);
	assert_ptr_eq (attrs + 1, attr);

	attr = p11_attrs_findn (attrs, 3, CKA_TOKEN);
	assert_ptr_eq (attrs + 2, attr);

	attr = p11_attrs_findn (attrs, 3, CKA_VALUE);
	assert_ptr_eq (NULL, attr);

	attr = p11_attrs_findn (attrs, 2, CKA_TOKEN);
	assert_ptr_eq (NULL, attr);
}

static void
test_remove (void)
{
	CK_BBOOL vtrue = CK_TRUE;
	CK_ATTRIBUTE *attr;
	CK_ATTRIBUTE *attrs;
	CK_BBOOL ret;

	CK_ATTRIBUTE template[] = {
		{ CKA_VALUE, "value", 5 },
	};
	CK_ATTRIBUTE initial[] = {
		{ CKA_LABEL, "label", 5 },
		{ CKA_TOKEN, &vtrue, sizeof (vtrue) },
		{ CKA_WRAP_TEMPLATE, template, sizeof (template) },
	};

	attrs = p11_attrs_buildn (NULL, initial, 3);
	assert_ptr_not_null (attrs);

	attr = p11_attrs_find (attrs, CKA_LABEL);
	assert_ptr_eq (attrs + 0, attr);

	ret = p11_attrs_remove (attrs, CKA_LABEL);
	assert_num_eq (CK_TRUE, ret);

	attr = p11_attrs_find (attrs, CKA_LABEL);
	assert_ptr_eq (NULL, attr);

	ret = p11_attrs_remove (attrs, CKA_LABEL);
	assert_num_eq (CK_FALSE, ret);

	ret = p11_attrs_remove (attrs, CKA_VALUE);
	assert_num_eq (CK_FALSE, ret);

	ret = p11_attrs_remove (attrs, CKA_WRAP_TEMPLATE);
	assert_num_eq (CK_TRUE, ret);

	p11_attrs_free (attrs);
}

static void
test_purge (void)
{
	CK_BBOOL vtrue = CK_TRUE;
	CK_ATTRIBUTE *attr;
	CK_ATTRIBUTE *attrs;

	/* We can't release child attributes without knowing ulValueLen */
	CK_ATTRIBUTE template[] = {
		{ CKA_VALUE, NULL, 0 },
	};
	CK_ATTRIBUTE initial[] = {
		{ CKA_LABEL, "label", 5 },
		{ CKA_TOKEN, &vtrue, sizeof (vtrue) },
		{ CKA_WRAP_TEMPLATE, template, sizeof (template) },
	};

	attrs = p11_attrs_buildn (NULL, initial, 3);
	assert_ptr_not_null (attrs);

	attr = p11_attrs_find (attrs, CKA_LABEL);
	assert_ptr_eq (attrs + 0, attr);

	attr = p11_attrs_find (attrs, CKA_WRAP_TEMPLATE);
	assert_ptr_eq (attrs + 2, attr);

	attrs[0].ulValueLen = (CK_ULONG) -1;
	attrs[2].ulValueLen = (CK_ULONG) -1;

	p11_attrs_purge (attrs);

	attr = p11_attrs_find (attrs, CKA_LABEL);
	assert_ptr_eq (NULL, attr);

	attr = p11_attrs_find (attrs, CKA_WRAP_TEMPLATE);
	assert_ptr_eq (NULL, attr);

	p11_attrs_free (attrs);
}

static void
test_match (void)
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

	CK_ATTRIBUTE temp1[] = {
		{ CKA_LABEL, "yay", 3 },
		{ CKA_VALUE, "val", 3 },
	};
	CK_ATTRIBUTE one_recursive[] = {
		{ CKA_WRAP_TEMPLATE, temp1, sizeof (temp1) },
		{ CKA_INVALID },
	};

	CK_ATTRIBUTE temp2[] = {
		{ CKA_LABEL, "yay", 3 },
		{ CKA_VALUE, "nil", 3 },
	};
	CK_ATTRIBUTE two_recursive[] = {
		{ CKA_WRAP_TEMPLATE, temp2, sizeof (temp2) },
		{ CKA_INVALID },
	};

	assert (p11_attrs_match (attrs, attrs));
	assert (p11_attrs_match (attrs, subset));
	assert (!p11_attrs_match (attrs, different));
	assert (!p11_attrs_match (attrs, extra));
	assert (p11_attrs_match (one_recursive, one_recursive));
	assert (!p11_attrs_match (one_recursive, two_recursive));
}

static void
test_matchn (void)
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

	CK_ATTRIBUTE temp1[] = {
		{ CKA_LABEL, "yay", 3 },
		{ CKA_VALUE, "val", 3 },
	};
	CK_ATTRIBUTE one_recursive[] = {
		{ CKA_WRAP_TEMPLATE, temp1, sizeof (temp1) },
		{ CKA_INVALID },
	};

	CK_ATTRIBUTE temp2[] = {
		{ CKA_LABEL, "nay", 3 },
		{ CKA_VALUE, "val", 3 },
	};
	CK_ATTRIBUTE two_recursive[] = {
		{ CKA_WRAP_TEMPLATE, temp2, sizeof (temp2) },
		{ CKA_INVALID },
	};

	assert (p11_attrs_matchn (attrs, subset, 1));
	assert (!p11_attrs_matchn (attrs, different, 2));
	assert (!p11_attrs_matchn (attrs, extra, 3));
	assert (p11_attrs_matchn (one_recursive, one_recursive, 1));
	assert (!p11_attrs_matchn (one_recursive, two_recursive, 1));
}

static void
test_find_bool (void)
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

	assert (p11_attrs_find_bool (attrs, CKA_TOKEN, &value) && value == CK_TRUE);
	assert (!p11_attrs_find_bool (attrs, CKA_LABEL, &value));
	assert (!p11_attrs_find_bool (attrs, CKA_VALUE, &value));
}

static void
test_find_ulong (void)
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

	assert (p11_attrs_find_ulong (attrs, CKA_BITS_PER_PIXEL, &value) && value == v33);
	assert (!p11_attrs_find_ulong (attrs, CKA_LABEL, &value));
	assert (!p11_attrs_find_ulong (attrs, CKA_VALUE, &value));
}

static void
test_find_value (void)
{
	void *value;
	size_t length;

	CK_ATTRIBUTE attrs[] = {
		{ CKA_LABEL, "", (CK_ULONG)-1 },
		{ CKA_LABEL, NULL, 5 },
		{ CKA_LABEL, "", 0 },
		{ CKA_LABEL, "test", 4 },
		{ CKA_VALUE, NULL, 0 },
		{ CKA_INVALID },
	};

	value = p11_attrs_find_value (attrs, CKA_LABEL, &length);
	assert_ptr_eq (attrs[3].pValue, value);
	assert_num_eq (4, length);

	value = p11_attrs_find_value (attrs, CKA_LABEL, NULL);
	assert_ptr_eq (attrs[3].pValue, value);

	value = p11_attrs_find_value (attrs, CKA_VALUE, &length);
	assert_ptr_eq (NULL, value);

	value = p11_attrs_find_value (attrs, CKA_TOKEN, &length);
	assert_ptr_eq (NULL, value);
}

static void
test_find_valid (void)
{
	CK_ATTRIBUTE *attr;

	CK_ATTRIBUTE attrs[] = {
		{ CKA_LABEL, "", (CK_ULONG)-1 },
		{ CKA_LABEL, NULL, 5 },
		{ CKA_LABEL, "", 0 },
		{ CKA_LABEL, "test", 4 },
		{ CKA_VALUE, "value", 5 },
		{ CKA_INVALID },
	};

	attr = p11_attrs_find_valid (attrs, CKA_LABEL);
	assert_ptr_eq (attrs + 3, attr);

	attr = p11_attrs_find_valid (attrs, CKA_VALUE);
	assert_ptr_eq (attrs + 4, attr);

	attr = p11_attrs_find_valid (attrs, CKA_TOKEN);
	assert_ptr_eq (NULL, attr);
}

int
main (int argc,
      char *argv[])
{
	p11_test (test_equal, "/attrs/equal");
	p11_test (test_equal_recursive, "/attrs/equal-recursive");
	p11_test (test_hash, "/attrs/hash");
	p11_test (test_to_string, "/attrs/to-string");

	p11_test (test_terminator, "/attrs/terminator");
	p11_test (test_count, "/attrs/count");
	p11_test (test_build_one, "/attrs/build-one");
	p11_test (test_build_two, "/attrs/build-two");
	p11_test (test_build_invalid, "/attrs/build-invalid");
	p11_test (test_buildn_one, "/attrs/buildn-one");
	p11_test (test_buildn_two, "/attrs/buildn-two");
	p11_test (test_build_add, "/attrs/build-add");
	p11_test (test_build_null, "/attrs/build-null");
	p11_test (test_build_recursive, "/attrs/build-recursive");
	p11_test (test_build_recursive_null, "/attrs/build-recursive-null");
	p11_test (test_dup, "/attrs/dup");
	p11_test (test_dup_recursive, "/attrs/dup-recursive");
	p11_test (test_take, "/attrs/take");
	p11_test (test_take_recursive, "/attrs/take-recursive");
	p11_test (test_merge_replace, "/attrs/merge-replace");
	p11_test (test_merge_augment, "/attrs/merge-augment");
	p11_test (test_merge_empty, "/attrs/merge-empty");
	p11_test (test_merge_replace_recursive, "/attrs/merge-replace-recursive");
	p11_test (test_merge_augment_recursive, "/attrs/merge-augment-recursive");
	p11_test (test_free_null, "/attrs/free-null");
	p11_test (test_match, "/attrs/match");
	p11_test (test_matchn, "/attrs/matchn");
	p11_test (test_find, "/attrs/find");
	p11_test (test_findn, "/attrs/findn");
	p11_test (test_find_bool, "/attrs/find-bool");
	p11_test (test_find_ulong, "/attrs/find-ulong");
	p11_test (test_find_value, "/attrs/find-value");
	p11_test (test_find_valid, "/attrs/find-valid");
	p11_test (test_remove, "/attrs/remove");
	p11_test (test_purge, "/attrs/purge");
	return p11_test_run (argc, argv);
}
