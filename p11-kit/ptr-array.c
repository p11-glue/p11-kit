/*
 * Copyright (c) 2011 Collabora Ltd.
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
 */

#include "config.h"

#include "ptr-array.h"

#include <stdlib.h>
#include <string.h>

struct ptr_array {
	void **memory;
	unsigned int length;
	unsigned int allocated;
	ptr_array_destroy_func destroy;
};

static int
maybe_expand_array (ptr_array_t *array,
                    unsigned int length)
{
	unsigned int new_allocated;
	void **new_memory;

	if (length <= array->allocated)
		return 1;

	new_allocated = array->allocated + 16;
	if (new_allocated < length)
		new_allocated = length;

	new_memory = realloc (array->memory, new_allocated * sizeof (void*));
	if (new_memory == NULL)
		return 0;

	array->memory = new_memory;
	array->allocated = new_allocated;
	return 1;
}

ptr_array_t *
_p11_ptr_array_create (ptr_array_destroy_func destroy_func)
{
	ptr_array_t *array;

	array = calloc (1, sizeof (ptr_array_t));
	if (array == NULL)
		return NULL;

	if (!maybe_expand_array (array, 2)) {
		_p11_ptr_array_free (array);
		return NULL;
	}

	array->destroy = destroy_func;
	return array;
}

void
_p11_ptr_array_free (ptr_array_t *array)
{
	unsigned int i;

	if (array == NULL)
		return;

	if (array->destroy) {
		for (i = 0; i < array->length; i++)
			(array->destroy) (array->memory[i]);
	}

	free (array->memory);
	free (array);
}

unsigned int
_p11_ptr_array_count (ptr_array_t *array)
{
	return array->length;
}

int
_p11_ptr_array_add (ptr_array_t *array,
                    void *value)
{
	if (!maybe_expand_array (array, array->length + 1))
		return 0;

	array->memory[array->length] = value;
	array->length++;
	return 1;
}

void
_p11_ptr_array_remove (ptr_array_t *array,
                       unsigned int index)
{
	if (array->destroy)
		(array->destroy) (array->memory[index]);
	memmove (array->memory + index, array->memory + index + 1,
	         (array->length - (index + 1)) * sizeof (void*));
	array->length--;
}

void *
_p11_ptr_array_at (ptr_array_t *array,
                   unsigned int index)
{
	return array->memory[index];
}

void **
_p11_ptr_array_snapshot (ptr_array_t *array)
{
	void **snapshot;
	size_t bytes;

	bytes = array->length * sizeof (void*);
	snapshot = malloc (bytes);
	if (!snapshot)
		return NULL;

	memcpy (snapshot, array->memory, bytes);
	return snapshot;
}
