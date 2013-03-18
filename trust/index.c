/*
 * Copyright (C) 2013 Red Hat Inc.
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
 * Author: Stef Walter <stefw@redhat.com>
 */

#include "compat.h"

#define P11_DEBUG_FLAG P11_DEBUG_TRUST

#include "attrs.h"
#include "debug.h"
#include "dict.h"
#include "index.h"
#include "module.h"

#include <assert.h>
#include <stdlib.h>

/*
 * TODO: Eventually we want to be using a bloom filter to optimize and
 * actually implement the index.
 */

struct _p11_index {
	/* The list of objects */
	p11_dict *objects;

	/* Data passed to callbacks */
	void *data;

	/* Called to build an new/modified object */
	p11_index_build_cb build;

	/* Called after objects change */
	p11_index_changed_cb changed;

	/* Used for queueing changes, when in a batch */
	p11_dict *changes;
	bool changing;
};

struct object {
	CK_OBJECT_HANDLE handle;
	CK_ATTRIBUTE *attrs;
};

static void
free_object (void *data)
{
	struct object *obj = data;
	p11_attrs_free (obj->attrs);
	free (obj);
}

p11_index *
p11_index_new (p11_index_build_cb build,
               p11_index_changed_cb changed,
               void *data)
{
	p11_index *index;

	index = calloc (1, sizeof (p11_index));
	return_val_if_fail (index != NULL, NULL);

	index->build = build;
	index->changed = changed;
	index->data = data;

	index->objects = p11_dict_new (p11_dict_ulongptr_hash,
	                               p11_dict_ulongptr_equal,
	                               NULL, free_object);
	return_val_if_fail (index->objects != NULL, NULL);

	return index;
}

void
p11_index_free (p11_index *index)
{
	return_if_fail (index != NULL);

	p11_dict_free (index->objects);
	p11_dict_free (index->changes);
	free (index);
}

int
p11_index_size (p11_index *index)
{
	return_val_if_fail (index != NULL, -1);
	return p11_dict_size (index->objects);
}

static CK_RV
index_build (p11_index *index,
             CK_ATTRIBUTE **attrs,
             CK_ATTRIBUTE *merge)
{
	if (index->build) {
		return index->build (index->data, index, attrs, merge);
	} else {
		*attrs = p11_attrs_merge (*attrs, merge, true);
		return CKR_OK;
	}
}

static void
call_change (p11_index *index,
             CK_OBJECT_HANDLE handle,
             CK_ATTRIBUTE *attrs)
{
	assert (index->changed);

	/* When attrs is NULL, means this is a modify */
	if (attrs == NULL) {
		attrs = p11_index_lookup (index, handle);
		if (attrs == NULL)
			return;

	/* Otherwise a remove operation, handle not valid anymore */
	} else {
		handle = 0;
	}

	index->changing = true;
	index->changed (index->data, index, handle, attrs);
	index->changing = false;
}

static void
index_change (p11_index *index,
              CK_OBJECT_HANDLE handle,
              CK_ATTRIBUTE *removed)
{
	struct object *obj;

	if (!index->changed || index->changing)
		return;

	if (!index->changes) {
		call_change (index, handle, removed);
		p11_attrs_free (removed);

	} else {
		obj = calloc (1, sizeof (struct object));
		return_if_fail (obj != NULL);

		obj->handle = handle;
		obj->attrs = removed;
		if (!p11_dict_set (index->changes, &obj->handle, obj))
			return_if_reached ();
	}
}

void
p11_index_batch (p11_index *index)
{
	return_if_fail (index != NULL);

	if (index->changes)
		return;

	index->changes = p11_dict_new (p11_dict_ulongptr_hash,
	                               p11_dict_ulongptr_equal,
	                               NULL, free_object);
	return_if_fail (index->changes != NULL);
}

void
p11_index_finish (p11_index *index)
{
	p11_dict *changes;
	struct object *obj;
	p11_dictiter iter;

	return_if_fail (index != NULL);

	if (!index->changes)
		return;

	changes = index->changes;
	index->changes = NULL;

	p11_dict_iterate (changes, &iter);
	while (p11_dict_next (&iter, NULL, (void **)&obj))
		call_change (index, obj->handle, obj->attrs);

	p11_dict_free (changes);
}

bool
p11_index_in_batch (p11_index *index)
{
	return_val_if_fail (index != NULL, false);
	return index->changes ? true : false;
}

CK_RV
p11_index_take (p11_index *index,
                CK_ATTRIBUTE *attrs,
                CK_OBJECT_HANDLE *handle)
{
	struct object *obj;
	CK_RV rv;

	return_val_if_fail (index != NULL, CKR_GENERAL_ERROR);
	return_val_if_fail (attrs != NULL, CKR_GENERAL_ERROR);

	obj = calloc (1, sizeof (struct object));
	return_val_if_fail (obj != NULL, CKR_HOST_MEMORY);

	rv = index_build (index, &obj->attrs, attrs);
	if (rv != CKR_OK) {
		p11_attrs_free (attrs);
		return rv;
	}

	return_val_if_fail (obj->attrs != NULL, CKR_GENERAL_ERROR);
	obj->handle = p11_module_next_id ();

	if (!p11_dict_set (index->objects, &obj->handle, obj))
		return_val_if_reached (CKR_HOST_MEMORY);

	if (handle)
		*handle = obj->handle;

	index_change (index, obj->handle, NULL);
	return CKR_OK;
}

CK_RV
p11_index_add (p11_index *index,
               CK_ATTRIBUTE *attrs,
               CK_ULONG count,
               CK_OBJECT_HANDLE *handle)
{
	CK_ATTRIBUTE *copy;

	return_val_if_fail (index != NULL, CKR_GENERAL_ERROR);
	return_val_if_fail (attrs == NULL || count > 0, CKR_ARGUMENTS_BAD);

	copy = p11_attrs_buildn (NULL, attrs, count);
	return_val_if_fail (copy != NULL, CKR_HOST_MEMORY);

	return p11_index_take (index, copy, handle);
}

CK_RV
p11_index_update (p11_index *index,
                  CK_OBJECT_HANDLE handle,
                  CK_ATTRIBUTE *update)
{
	struct object *obj;
	CK_RV rv;

	return_val_if_fail (index != NULL, CKR_GENERAL_ERROR);
	return_val_if_fail (update != NULL, CKR_GENERAL_ERROR);

	obj = p11_dict_get (index->objects, &handle);
	if (obj == NULL) {
		p11_attrs_free (update);
		return CKR_OBJECT_HANDLE_INVALID;
	}

	rv = index_build (index, &obj->attrs, update);
	if (rv != CKR_OK) {
		p11_attrs_free (update);
		return rv;
	}

	index_change (index, obj->handle, NULL);
	return CKR_OK;
}

CK_RV
p11_index_set (p11_index *index,
               CK_OBJECT_HANDLE handle,
               CK_ATTRIBUTE *attrs,
               CK_ULONG count)
{
	CK_ATTRIBUTE *update;
	struct object *obj;

	return_val_if_fail (index != NULL, CKR_GENERAL_ERROR);

	obj = p11_dict_get (index->objects, &handle);
	if (obj == NULL)
		return CKR_OBJECT_HANDLE_INVALID;

	update = p11_attrs_buildn (NULL, attrs, count);
	return_val_if_fail (update != NULL, CKR_HOST_MEMORY);

	return p11_index_update (index, handle, update);
}

CK_RV
p11_index_remove (p11_index *index,
                  CK_OBJECT_HANDLE handle)
{
	struct object *obj;

	return_val_if_fail (index != NULL, CKR_GENERAL_ERROR);

	if (!p11_dict_steal (index->objects, &handle, NULL, (void **)&obj))
		return CKR_OBJECT_HANDLE_INVALID;

	/* This takes ownership of the attributes */
	index_change (index, handle, obj->attrs);
	obj->attrs = NULL;
	free_object (obj);

	return CKR_OK;
}

static CK_RV
index_replacev (p11_index *index,
                CK_ATTRIBUTE *match,
                CK_ATTRIBUTE_TYPE key,
                CK_ATTRIBUTE **replace,
                CK_ULONG replacen)
{
	CK_OBJECT_HANDLE *handles;
	struct object *obj;
	CK_ATTRIBUTE *attrs;
	CK_ATTRIBUTE *attr;
	bool handled = false;
	CK_RV rv;
	int i, j;

	handles = p11_index_find_all (index, match);

	for (i = 0; handles && handles[i] != 0; i++) {
		obj = p11_dict_get (index->objects, handles + i);
		if (obj == NULL)
			continue;

		handled = false;
		attr = p11_attrs_find (obj->attrs, key);

		/* The match doesn't have the key, so remove it */
		if (attr != NULL) {
			for (j = 0; j < replacen; j++) {
				if (!replace[j])
					continue;
				if (p11_attrs_matchn (replace[j], attr, 1)) {
					attrs = NULL;
					rv = index_build (index, &attrs, replace[j]);
					if (rv != CKR_OK)
						return rv;
					p11_attrs_free (obj->attrs);
					obj->attrs = attrs;
					replace[j] = NULL;
					handled = true;
					break;
				}
			}
		}

		if (!handled) {
			rv = p11_index_remove (index, handles[i]);
			if (rv != CKR_OK)
				return rv;
		}
	}

	for (j = 0; j < replacen; j++) {
		if (!replace[j])
			continue;
		rv = p11_index_take (index, replace[j], NULL);
		if (rv != CKR_OK)
			return rv;
		replace[j] = NULL;
	}

	free (handles);
	return CKR_OK;
}

CK_RV
p11_index_replace (p11_index *index,
                   CK_ATTRIBUTE *match,
                   CK_ATTRIBUTE_TYPE key,
                   CK_ATTRIBUTE *replace)
{
	return_val_if_fail (index != NULL, CKR_GENERAL_ERROR);
	return index_replacev (index, match, key, &replace, 1);
}

CK_RV
p11_index_replace_all (p11_index *index,
                       CK_ATTRIBUTE *match,
                       CK_ATTRIBUTE_TYPE key,
                       p11_array *replace)
{
	CK_RV rv;
	int i;

	return_val_if_fail (index != NULL, CKR_GENERAL_ERROR);

	rv = index_replacev (index, match, key,
	                     (CK_ATTRIBUTE **)replace->elem,
	                     replace->num);

	for (i = 0; i < replace->num; i++) {
		if (!replace->elem[i]) {
			p11_array_remove (replace, i);
			i--;
		}
	}

	return rv;
}

CK_ATTRIBUTE *
p11_index_lookup (p11_index *index,
                  CK_OBJECT_HANDLE handle)
{
	struct object *obj;

	return_val_if_fail (index != NULL, NULL);

	if (handle == CK_INVALID_HANDLE)
		return NULL;

	obj = p11_dict_get (index->objects, &handle);
	return obj ? obj->attrs : NULL;
}

CK_OBJECT_HANDLE
p11_index_find (p11_index *index,
                CK_ATTRIBUTE *match)
{
	struct object *obj;
	p11_dictiter iter;

	p11_dict_iterate (index->objects, &iter);
	while (p11_dict_next (&iter, NULL, (void *)&obj)) {
		if (p11_attrs_match (obj->attrs, match))
			return obj->handle;
	}

	return 0;
}

CK_OBJECT_HANDLE
p11_index_findn (p11_index *index,
                 CK_ATTRIBUTE *match,
                 CK_ULONG count)
{
	struct object *obj;
	p11_dictiter iter;

	p11_dict_iterate (index->objects, &iter);
	while (p11_dict_next (&iter, NULL, (void *)&obj)) {
		if (p11_attrs_matchn (obj->attrs, match, count))
			return obj->handle;
	}

	return 0;
}

CK_OBJECT_HANDLE *
p11_index_find_all (p11_index *index,
                    CK_ATTRIBUTE *match)
{
	CK_OBJECT_HANDLE *handles = NULL;
	struct object *obj;
	p11_dictiter iter;
	int nhandles;
	int at = 0;

	nhandles = 16;
	handles = malloc (nhandles * sizeof (CK_OBJECT_HANDLE));
	return_val_if_fail (handles != NULL, NULL);

	p11_dict_iterate (index->objects, &iter);
	while (p11_dict_next (&iter, NULL, (void *)&obj)) {
		if (p11_attrs_match (obj->attrs, match)) {
			if (at + 2 > nhandles) {
				nhandles += 16;
				handles = realloc (handles, nhandles * sizeof (CK_OBJECT_HANDLE));
				return_val_if_fail (handles != NULL, NULL);
			}
			handles[at++] = obj->handle;
		}
	}

	handles[at++] = 0UL;
	return handles;
}

CK_OBJECT_HANDLE *
p11_index_snapshot (p11_index *index,
                    p11_index *base,
                    CK_ATTRIBUTE *attrs,
                    CK_ULONG count)
{
	CK_OBJECT_HANDLE *snapshot;
	CK_OBJECT_HANDLE *handle;
	p11_dictiter iter;
	int num;
	int i;

	/*
	 * TODO: The concept is that we use our bloom filter to provide
	 * an initial rough snapshot here of which objects match, but for
	 * now just include everything in the snapshot.
	 */

	return_val_if_fail (index != NULL, NULL);

	num = p11_index_size (index) + 1;
	if (base)
		num += p11_index_size (base);

	snapshot = calloc (num, sizeof (CK_OBJECT_HANDLE));
	return_val_if_fail (snapshot != NULL, NULL);

	p11_dict_iterate (index->objects, &iter);
	for (i = 0 ; p11_dict_next (&iter, (void *)&handle, NULL); i++) {
		assert (i < num);
		snapshot[i] = *handle;
	}

	if (base) {
		p11_dict_iterate (base->objects, &iter);
		for ( ; p11_dict_next (&iter, (void *)&handle, NULL); i++) {
			assert (i < num);
			snapshot[i] = *handle;
		}
	}

	assert (i < num);
	assert (snapshot[i] == 0UL);

	return snapshot;
}
