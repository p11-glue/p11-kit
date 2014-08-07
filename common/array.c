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

#include "array.h"
#include "debug.h"

#include <stdlib.h>
#include <string.h>

static bool
maybe_expand_array (p11_array *array,
                    unsigned int length)
{
	unsigned int new_allocated;
	void **new_memory;

	if (length <= array->allocated)
		return true;


	new_allocated = array->allocated * 2;
	if (new_allocated == 0)
		new_allocated = 16;
	if (new_allocated < length)
		new_allocated = length;

	new_memory = realloc (array->elem, new_allocated * sizeof (void*));
	return_val_if_fail (new_memory != NULL, false);

	array->elem = new_memory;
	array->allocated = new_allocated;
	return true;
}

p11_array *
p11_array_new (p11_destroyer destroyer)
{
	p11_array *array;

	array = calloc (1, sizeof (p11_array));
	if (array == NULL)
		return NULL;

	if (!maybe_expand_array (array, 2)) {
		p11_array_free (array);
		return NULL;
	}

	array->destroyer = destroyer;
	return array;
}

void
p11_array_free (p11_array *array)
{
	if (array == NULL)
		return;

	p11_array_clear (array);
	free (array->elem);
	free (array);
}

bool
p11_array_push (p11_array *array,
                void *value)
{
	if (!maybe_expand_array (array, array->num + 1))
		return_val_if_reached (false);

	array->elem[array->num] = value;
	array->num++;
	return true;
}

void
p11_array_remove (p11_array *array,
                  unsigned int index)
{
	if (array->destroyer)
		(array->destroyer) (array->elem[index]);
	memmove (array->elem + index, array->elem + index + 1,
	         (array->num - (index + 1)) * sizeof (void*));
	array->num--;
}

void
p11_array_clear (p11_array *array)
{
	int i;

	if (array->destroyer) {
		for (i = 0; i < array->num; i++)
			(array->destroyer) (array->elem[i]);
	}

	array->num = 0;
}
