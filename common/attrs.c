/*
 * Copyright (C) 2012, Redhat Inc.
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

#include "attrs.h"
#include "compat.h"
#include "debug.h"

#include <assert.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

CK_BBOOL
p11_attrs_is_empty (CK_ATTRIBUTE *attrs)
{
	return (attrs == NULL || attrs->type == CKA_INVALID);
}

CK_ULONG
p11_attrs_count (CK_ATTRIBUTE *attrs)
{
	CK_ULONG count;

	if (attrs == NULL)
		return 0UL;

	for (count = 0; !p11_attrs_is_empty (attrs); count++, attrs++);

	return count;
}

void
p11_attrs_free (void *attrs)
{
	CK_ATTRIBUTE *ats = attrs;
	int i;

	if (!attrs)
		return;

	for (i = 0; !p11_attrs_is_empty (ats + i); i++)
		free (ats[i].pValue);
	free (ats);
}

static CK_ATTRIBUTE *
attrs_build (CK_ATTRIBUTE *attrs,
             CK_ULONG count_to_add,
             bool copy,
             CK_ATTRIBUTE * (*generator) (void *),
             void *state)
{
	CK_ATTRIBUTE *attr;
	CK_ATTRIBUTE *add;
	CK_ULONG current;
	CK_ULONG at;
	CK_ULONG j;
	CK_ULONG i;

	/* How many attributes we already have */
	current = p11_attrs_count (attrs);

	/* Reallocate for how many we need */
	attrs = realloc (attrs, (current + count_to_add + 1) * sizeof (CK_ATTRIBUTE));
	return_val_if_fail (attrs != NULL, NULL);

	at = current;
	for (i = 0; i < count_to_add; i++) {
		add = (generator) (state);

		/* Skip with invalid type */
		if (!add || add->type == CKA_INVALID)
			continue;

		attr = NULL;

		/* Do we have this attribute? */
		for (j = 0; attr == NULL && j < current; j++) {
			if (attrs[j].type == add->type) {
				attr = attrs + j;
				free (attrs[j].pValue);
				break;
			}
		}

		if (attr == NULL) {
			attr = attrs + at;
			at++;
		}

		memcpy (attr, add, sizeof (CK_ATTRIBUTE));
		if (copy)
			attr->pValue = memdup (attr->pValue, attr->ulValueLen);
	}

	/* Mark this as the end */
	(attrs + at)->type = CKA_INVALID;
	assert (p11_attrs_is_empty (attrs + at));
	return attrs;
}

static CK_ATTRIBUTE *
vararg_generator (void *state)
{
	va_list *va = state;
	return va_arg (*va, CK_ATTRIBUTE *);
}

CK_ATTRIBUTE *
p11_attrs_build (CK_ATTRIBUTE *attrs,
                 ...)
{
	CK_ULONG count;
	va_list va;

	count = 0UL;
	va_start (va, attrs);
	while (va_arg (va, CK_ATTRIBUTE *))
		count++;
	va_end (va);

	va_start (va, attrs);
	attrs = attrs_build (attrs, count, true, vararg_generator, va);
	va_end (va);

	return attrs;
}

static CK_ATTRIBUTE *
template_generator (void *state)
{
	CK_ATTRIBUTE **template = state;
	return (*template)++;
}

CK_ATTRIBUTE *
p11_attrs_buildn (CK_ATTRIBUTE *attrs,
                  CK_ATTRIBUTE *add,
                  CK_ULONG count)
{
	return attrs_build (attrs, count, true, template_generator, &add);
}

CK_ATTRIBUTE *
p11_attrs_take (CK_ATTRIBUTE *attrs,
                CK_ATTRIBUTE_TYPE type,
                CK_VOID_PTR value,
                CK_ULONG length)
{
	CK_ATTRIBUTE attr = { type, value, length };
	CK_ATTRIBUTE *add = &attr;
	return attrs_build (attrs, 1, false, template_generator, &add);
}

CK_ATTRIBUTE *
p11_attrs_dup (CK_ATTRIBUTE *attrs)
{
	CK_ULONG count;

	count = p11_attrs_count (attrs);
	return p11_attrs_buildn (NULL, attrs, count);
}

CK_ATTRIBUTE *
p11_attrs_find (CK_ATTRIBUTE *attrs,
                CK_ATTRIBUTE_TYPE type)
{
	CK_ULONG i;

	for (i = 0; !p11_attrs_is_empty (attrs + i); i++) {
		if (attrs[i].type == type)
			return attrs + i;
	}

	return NULL;
}

CK_ATTRIBUTE *
p11_attrs_findn (CK_ATTRIBUTE *attrs,
                 CK_ULONG count,
                 CK_ATTRIBUTE_TYPE type)
{
	CK_ULONG i;

	for (i = 0; i < count; i++) {
		if (attrs[i].type == type)
			return attrs + i;
	}

	return NULL;
}

CK_BBOOL
p11_attrs_remove (CK_ATTRIBUTE *attrs,
                  CK_ATTRIBUTE_TYPE type)
{
	CK_ULONG count;
	CK_ULONG i;

	count = p11_attrs_count (attrs);
	for (i = 0; i < count; i++) {
		if (attrs[i].type == type)
			break;
	}

	if (i == count)
		return CK_FALSE;

	if (attrs[i].pValue)
		free (attrs[i].pValue);

	memmove (attrs + i, attrs + i + 1, (count - (i + 1)) * sizeof (CK_ATTRIBUTE));
	attrs[count - 1].type = CKA_INVALID;
	return CK_TRUE;
}

CK_BBOOL
p11_attrs_match (CK_ATTRIBUTE *attrs,
                 CK_ATTRIBUTE *match)
{
	CK_ATTRIBUTE *attr;

	for (; !p11_attrs_is_empty (match); match++) {
		attr = p11_attrs_find (attrs, match->type);
		if (!attr)
			return CK_FALSE;
		if (!p11_attr_equal (attr, match))
			return CK_FALSE;
	}

	return CK_TRUE;
}

CK_BBOOL
p11_attrs_matchn (CK_ATTRIBUTE *attrs,
                  CK_ATTRIBUTE *match,
                  CK_ULONG count)
{
	CK_ATTRIBUTE *attr;
	CK_ULONG i;

	for (i = 0; i < count; i++) {
		attr = p11_attrs_find (attrs, match[i].type);
		if (!attr)
			return CK_FALSE;
		if (!p11_attr_equal (attr, match + i))
			return CK_FALSE;
	}

	return CK_TRUE;

}

CK_BBOOL
p11_attr_match_boolean (CK_ATTRIBUTE *attr,
                        CK_BBOOL value)
{
	return (attr->ulValueLen == sizeof (value) &&
	        attr->pValue != NULL &&
	        memcmp (attr->pValue, &value, sizeof (value)) == 0);
}

CK_BBOOL
p11_attr_equal (CK_ATTRIBUTE *one,
                CK_ATTRIBUTE *two)
{
	if (one == two)
		return CK_TRUE;
	if (!one || !two || one->type != two->type || one->ulValueLen != two->ulValueLen)
		return CK_FALSE;
	if (one->pValue == two->pValue)
		return TRUE;
	if (!one->pValue || !two->pValue)
		return FALSE;
	return memcmp (one->pValue, two->pValue, one->ulValueLen) == 0;
}
