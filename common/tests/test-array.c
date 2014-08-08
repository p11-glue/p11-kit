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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "array.h"
#include "test.h"

static void
test_create (void)
{
	p11_array *array;

	array = p11_array_new (NULL);
	assert_ptr_not_null (array);
	p11_array_free (array);
}

static void
test_free_null (void)
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
test_free_destroys (void)
{
	p11_array *array;
	int value = 0;

	array = p11_array_new (destroy_value);
	assert_ptr_not_null (array);
	if (!p11_array_push (array, &value))
		assert_not_reached ();
	p11_array_free (array);

	assert_num_eq (2, value);
}

static void
test_add (void)
{
	char *value = "VALUE";
	p11_array *array;

	array = p11_array_new (NULL);
	if (!p11_array_push (array, value))
		assert_not_reached ();

	assert_num_eq (1, array->num);
	assert_ptr_eq (array->elem[0], value);

	p11_array_free (array);
}

static void
test_add_remove (void)
{
	char *value = "VALUE";
	p11_array *array;

	array = p11_array_new (NULL);
	if (!p11_array_push (array, value))
		assert_not_reached ();

	assert_num_eq (1, array->num);

	assert_ptr_eq (array->elem[0], value);

	p11_array_remove (array, 0);

	assert_num_eq (0, array->num);

	p11_array_free (array);
}

static void
test_remove_destroys (void)
{
	p11_array *array;
	int value = 0;

	array = p11_array_new (destroy_value);
	if (!p11_array_push (array, &value))
		assert_not_reached ();

	p11_array_remove (array, 0);

	assert_num_eq (2, value);

	/* should not be destroyed again */
	value = 0;

	p11_array_free (array);

	assert_num_eq (0, value);
}

static void
test_remove_and_count (void)
{
	p11_array *array;
	int *value;
	int i;

	array = p11_array_new (free);

	assert_num_eq (0, array->num);

	for (i = 0; i < 20000; ++i) {
		value = malloc (sizeof (int));
		assert (value != NULL);
		*value = i;
		if (!p11_array_push (array, value))
			assert_not_reached ();
		assert_num_eq (i + 1, array->num);
	}

	for (i = 10; i < 20000; ++i) {
		p11_array_remove (array, 10);
		assert_num_eq (20010 - (i + 1), array->num);
	}

	assert_num_eq (10, array->num);

	p11_array_free (array);
}

static void
test_clear_destroys (void)
{
	p11_array *array;
	int value = 0;

	array = p11_array_new (destroy_value);
	if (!p11_array_push (array, &value))
		assert_not_reached ();

	assert_num_eq (1, array->num);

	p11_array_clear (array);

	assert_num_eq (2, value);
	assert_num_eq (0, array->num);

	/* should not be destroyed again */
	value = 0;

	p11_array_free (array);

	assert_num_eq (0, value);
}

int
main (int argc,
      char *argv[])
{
	p11_test (test_create, "/array/create");
	p11_test (test_add, "/array/add");
	p11_test (test_add_remove, "/array/add-remove");
	p11_test (test_remove_destroys, "/array/remove-destroys");
	p11_test (test_remove_and_count, "/array/remove-and-count");
	p11_test (test_free_null, "/array/free-null");
	p11_test (test_free_destroys, "/array/free-destroys");
	p11_test (test_clear_destroys, "/array/clear-destroys");
	return p11_test_run (argc, argv);
}
