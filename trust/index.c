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
#include <string.h>

/*
 * The number of buckets we use for indexing, should end up as roughly
 * equal to the expected number of unique attribute values * 0.75,
 * prime if possible. Currently we don't expand the index, so this is
 * just a good guess for general usage.
 */
#define NUM_BUCKETS 7919

/*
 * The number of indexes to use when trying to find a matching object.
 */
#define MAX_SELECT 3

typedef struct {
	CK_OBJECT_HANDLE *elem;
	int num;
} index_bucket;

struct _p11_index {
	/* The list of objects by handle */
	p11_dict *objects;

	/* Used for indexing */
	index_bucket *buckets;

	/* Data passed to callbacks */
	void *data;

	/* Called to build an new/modified object */
	p11_index_build_cb build;

	/* Called after each object ready to be stored */
	p11_index_store_cb store;

	/* Called after an object has been removed */
	p11_index_remove_cb remove;

	/* Called after objects change */
	p11_index_notify_cb notify;

	/* Used for queueing changes, when in a batch */
	p11_dict *changes;
	bool notifying;
};

typedef struct {
	CK_OBJECT_HANDLE handle;
	CK_ATTRIBUTE *attrs;
} index_object;

static void
free_object (void *data)
{
	index_object *obj = data;
	p11_attrs_free (obj->attrs);
	free (obj);
}

static CK_RV
default_build (void *data,
               p11_index *index,
               CK_ATTRIBUTE *attrs,
               CK_ATTRIBUTE *merge,
               CK_ATTRIBUTE **populate)
{
	return CKR_OK;
}

static CK_RV
default_store (void *data,
               p11_index *index,
               CK_OBJECT_HANDLE handle,
               CK_ATTRIBUTE **attrs)
{
	return CKR_OK;
}

static void
default_notify (void *data,
                p11_index *index,
                CK_OBJECT_HANDLE handle,
                CK_ATTRIBUTE *attrs)
{

}

static CK_RV
default_remove (void *data,
                p11_index *index,
                CK_ATTRIBUTE *attrs)
{
	return CKR_OK;
}

p11_index *
p11_index_new (p11_index_build_cb build,
               p11_index_store_cb store,
               p11_index_remove_cb remove,
               p11_index_notify_cb notify,
               void *data)
{
	p11_index *index;

	index = calloc (1, sizeof (p11_index));
	return_val_if_fail (index != NULL, NULL);

	if (build == NULL)
		build = default_build;
	if (store == NULL)
		store = default_store;
	if (notify == NULL)
		notify = default_notify;
	if (remove == NULL)
		remove = default_remove;

	index->build = build;
	index->store = store;
	index->notify = notify;
	index->remove = remove;
	index->data = data;

	index->objects = p11_dict_new (p11_dict_ulongptr_hash,
	                               p11_dict_ulongptr_equal,
	                               NULL, free_object);
	return_val_if_fail (index->objects != NULL, NULL);

	index->buckets = calloc (NUM_BUCKETS, sizeof (index_bucket));
	return_val_if_fail (index->buckets != NULL, NULL);

	return index;
}

void
p11_index_free (p11_index *index)
{
	int i;

	return_if_fail (index != NULL);

	p11_dict_free (index->objects);
	p11_dict_free (index->changes);
	for (i = 0; i < NUM_BUCKETS; i++)
		free (index->buckets[i].elem);
	free (index->buckets);
	free (index);
}

int
p11_index_size (p11_index *index)
{
	return_val_if_fail (index != NULL, -1);
	return p11_dict_size (index->objects);
}

static bool
is_indexable (p11_index *index,
              CK_ATTRIBUTE_TYPE type)
{
	switch (type) {
	case CKA_CLASS:
	case CKA_VALUE:
	case CKA_OBJECT_ID:
	case CKA_ID:
	case CKA_X_ORIGIN:
		return true;
	}

	return false;
}

static unsigned int
alloc_size (int num)
{
	unsigned int n = num ? 1 : 0;
	while (n < num && n > 0)
		n <<= 1;
	return n;
}

static int
binary_search (CK_OBJECT_HANDLE *elem,
               int low,
               int high,
               CK_OBJECT_HANDLE handle)
{
	int mid;

	if (low == high)
		return low;

	mid = low + ((high - low) / 2);
	if (handle > elem[mid])
		return binary_search (elem, mid + 1, high, handle);
	else if (handle < elem[mid])
		return binary_search (elem, low, mid, handle);

	return mid;
}


static void
bucket_insert (index_bucket *bucket,
               CK_OBJECT_HANDLE handle)
{
	unsigned int alloc;
	int at = 0;

	if (bucket->elem) {
		at = binary_search (bucket->elem, 0, bucket->num, handle);
		if (at < bucket->num && bucket->elem[at] == handle)
			return;
	}

	alloc = alloc_size (bucket->num);
	if (bucket->num + 1 > alloc) {
		alloc = alloc ? alloc * 2 : 1;
		return_if_fail (alloc != 0);
		bucket->elem = realloc (bucket->elem, alloc * sizeof (CK_OBJECT_HANDLE));
	}

	return_if_fail (bucket->elem != NULL);
	memmove (bucket->elem + at + 1, bucket->elem + at,
	         (bucket->num - at) * sizeof (CK_OBJECT_HANDLE));
	bucket->elem[at] = handle;
	bucket->num++;
}

static bool
bucket_push (index_bucket *bucket,
             CK_OBJECT_HANDLE handle)
{
	unsigned int alloc;

	alloc = alloc_size (bucket->num);
	if (bucket->num + 1 > alloc) {
		alloc = alloc ? alloc * 2 : 1;
		return_val_if_fail (alloc != 0, false);
		bucket->elem = realloc (bucket->elem, alloc * sizeof (CK_OBJECT_HANDLE));
	}

	return_val_if_fail (bucket->elem != NULL, false);
	bucket->elem[bucket->num++] = handle;
	return true;
}

static void
index_hash (p11_index *index,
            index_object *obj)
{
	unsigned int hash;
	int i;

	for (i = 0; !p11_attrs_terminator (obj->attrs + i); i++) {
		if (is_indexable (index, obj->attrs[i].type)) {
			hash = p11_attr_hash (obj->attrs + i);
			bucket_insert (index->buckets + (hash % NUM_BUCKETS), obj->handle);
		}
	}
}

static void
merge_attrs (CK_ATTRIBUTE *output,
             CK_ULONG *noutput,
             CK_ATTRIBUTE *merge,
             CK_ULONG nmerge,
             p11_array *to_free)
{
	CK_ULONG i;

	for (i = 0; i < nmerge; i++) {
		/* Already have this attribute? */
		if (p11_attrs_findn (output, *noutput, merge[i].type)) {
			p11_array_push (to_free, merge[i].pValue);

		} else {
			memcpy (output + *noutput, merge + i, sizeof (CK_ATTRIBUTE));
			(*noutput)++;
		}
	}

	/* Freeing the array itself */
	p11_array_push (to_free, merge);
}

static CK_RV
index_build (p11_index *index,
             CK_OBJECT_HANDLE handle,
             CK_ATTRIBUTE **attrs,
             CK_ATTRIBUTE *merge)
{
	CK_ATTRIBUTE *extra = NULL;
	CK_ATTRIBUTE *built;
	p11_array *stack = NULL;
	CK_ULONG count;
	CK_ULONG nattrs;
	CK_ULONG nmerge;
	CK_ULONG nextra;
	CK_RV rv;
	int i;

	rv = index->build (index->data, index, *attrs, merge, &extra);
	if (rv != CKR_OK)
		return rv;

	/* Short circuit when nothing to merge */
	if (*attrs == NULL && extra == NULL) {
		built = merge;
		stack = NULL;

	} else {
		stack = p11_array_new (NULL);
		nattrs = p11_attrs_count (*attrs);
		nmerge = p11_attrs_count (merge);
		nextra = p11_attrs_count (extra);

		/* Make a shallow copy of the combined attributes for validation */
		built = calloc (nmerge + nattrs + nextra + 1, sizeof (CK_ATTRIBUTE));
		return_val_if_fail (built != NULL, CKR_GENERAL_ERROR);

		count = nmerge;
		memcpy (built, merge, sizeof (CK_ATTRIBUTE) * nmerge);
		p11_array_push (stack, merge);
		merge_attrs (built, &count, *attrs, nattrs, stack);
		merge_attrs (built, &count, extra, nextra, stack);

		/* The terminator attribute */
		built[count].type = CKA_INVALID;
		assert (p11_attrs_terminator (built + count));
	}

	rv = index->store (index->data, index, handle, &built);

	if (rv == CKR_OK) {
		for (i = 0; stack && i < stack->num; i++)
			free (stack->elem[i]);
		*attrs = built;
	} else {
		p11_attrs_free (extra);
		free (built);
	}

	p11_array_free (stack);
	return rv;
}

static void
call_notify (p11_index *index,
             CK_OBJECT_HANDLE handle,
             CK_ATTRIBUTE *attrs)
{
	assert (index->notify);

	/* When attrs is NULL, means this is a modify */
	if (attrs == NULL) {
		attrs = p11_index_lookup (index, handle);
		if (attrs == NULL)
			return;

	/* Otherwise a remove operation, handle not valid anymore */
	} else {
		handle = 0;
	}

	index->notifying = true;
	index->notify (index->data, index, handle, attrs);
	index->notifying = false;
}

static void
index_notify (p11_index *index,
              CK_OBJECT_HANDLE handle,
              CK_ATTRIBUTE *removed)
{
	index_object *obj;

	if (!index->notify || index->notifying) {
		p11_attrs_free (removed);

	} else if (!index->changes) {
		call_notify (index, handle, removed);
		p11_attrs_free (removed);

	} else {
		obj = calloc (1, sizeof (index_object));
		return_if_fail (obj != NULL);

		obj->handle = handle;
		obj->attrs = removed;
		if (!p11_dict_set (index->changes, &obj->handle, obj))
			return_if_reached ();
	}
}

void
p11_index_load (p11_index *index)
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
	index_object *obj;
	p11_dictiter iter;

	return_if_fail (index != NULL);

	if (!index->changes)
		return;

	changes = index->changes;
	index->changes = NULL;

	p11_dict_iterate (changes, &iter);
	while (p11_dict_next (&iter, NULL, (void **)&obj)) {
		index_notify (index, obj->handle, obj->attrs);
		obj->attrs = NULL;
	}

	p11_dict_free (changes);
}

bool
p11_index_loading (p11_index *index)
{
	return_val_if_fail (index != NULL, false);
	return index->changes ? true : false;
}

CK_RV
p11_index_take (p11_index *index,
                CK_ATTRIBUTE *attrs,
                CK_OBJECT_HANDLE *handle)
{
	index_object *obj;
	CK_RV rv;

	return_val_if_fail (index != NULL, CKR_GENERAL_ERROR);
	return_val_if_fail (attrs != NULL, CKR_GENERAL_ERROR);

	obj = calloc (1, sizeof (index_object));
	return_val_if_fail (obj != NULL, CKR_HOST_MEMORY);

	obj->handle = p11_module_next_id ();

	rv = index_build (index, obj->handle, &obj->attrs, attrs);
	if (rv != CKR_OK) {
		p11_attrs_free (attrs);
		free (obj);
		return rv;
	}

	return_val_if_fail (obj->attrs != NULL, CKR_GENERAL_ERROR);

	if (!p11_dict_set (index->objects, &obj->handle, obj))
		return_val_if_reached (CKR_HOST_MEMORY);

	index_hash (index, obj);

	if (handle)
		*handle = obj->handle;

	index_notify (index, obj->handle, NULL);
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
	index_object *obj;
	CK_RV rv;

	return_val_if_fail (index != NULL, CKR_GENERAL_ERROR);
	return_val_if_fail (update != NULL, CKR_GENERAL_ERROR);

	obj = p11_dict_get (index->objects, &handle);
	if (obj == NULL) {
		p11_attrs_free (update);
		return CKR_OBJECT_HANDLE_INVALID;
	}

	rv = index_build (index, obj->handle, &obj->attrs, update);
	if (rv != CKR_OK) {
		p11_attrs_free (update);
		return rv;
	}

	index_hash (index, obj);
	index_notify (index, obj->handle, NULL);

	return CKR_OK;
}

CK_RV
p11_index_set (p11_index *index,
               CK_OBJECT_HANDLE handle,
               CK_ATTRIBUTE *attrs,
               CK_ULONG count)
{
	CK_ATTRIBUTE *update;
	index_object *obj;

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
	index_object *obj;
	CK_RV rv;

	return_val_if_fail (index != NULL, CKR_GENERAL_ERROR);

	if (!p11_dict_steal (index->objects, &handle, NULL, (void **)&obj))
		return CKR_OBJECT_HANDLE_INVALID;

	rv = (index->remove) (index->data, index, obj->attrs);

	/* If the writer failed the remove, then add it back */
	if (rv != CKR_OK) {
		if (!p11_dict_set (index->objects, &obj->handle, obj))
			return_val_if_reached (CKR_HOST_MEMORY);
		return rv;
	}

	/* This takes ownership of the attributes */
	index_notify (index, handle, obj->attrs);
	obj->attrs = NULL;
	free_object (obj);

	return CKR_OK;
}

static CK_RV
index_replacev (p11_index *index,
                CK_OBJECT_HANDLE *handles,
                CK_ATTRIBUTE_TYPE key,
                CK_ATTRIBUTE **replace,
                CK_ULONG replacen)
{
	index_object *obj;
	CK_ATTRIBUTE *attrs;
	CK_ATTRIBUTE *attr;
	bool handled = false;
	CK_RV rv;
	int i, j;

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
					rv = index_build (index, obj->handle, &attrs, replace[j]);
					if (rv != CKR_OK)
						return rv;
					p11_attrs_free (obj->attrs);
					obj->attrs = attrs;
					replace[j] = NULL;
					handled = true;
					index_hash (index, obj);
					index_notify (index, obj->handle, NULL);
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
		attrs = replace[j];
		replace[j] = NULL;
		rv = p11_index_take (index, attrs, NULL);
		if (rv != CKR_OK)
			return rv;
	}

	return CKR_OK;
}

CK_RV
p11_index_replace (p11_index *index,
                   CK_OBJECT_HANDLE handle,
                   CK_ATTRIBUTE *replace)
{
	CK_OBJECT_HANDLE handles[] = { handle, 0 };
	return_val_if_fail (index != NULL, CKR_GENERAL_ERROR);
	return index_replacev (index, handles, CKA_INVALID,
	                       &replace, replace ? 1 : 0);
}

CK_RV
p11_index_replace_all (p11_index *index,
                       CK_ATTRIBUTE *match,
                       CK_ATTRIBUTE_TYPE key,
                       p11_array *replace)
{
	CK_OBJECT_HANDLE *handles;
	CK_RV rv;
	int i;

	return_val_if_fail (index != NULL, CKR_GENERAL_ERROR);

	handles = p11_index_find_all (index, match, -1);

	rv = index_replacev (index, handles, key,
	                     replace ? (CK_ATTRIBUTE **)replace->elem : NULL,
	                     replace ? replace->num : 0);

	if (rv == CKR_OK) {
		if (replace)
			p11_array_clear (replace);
	} else {
		for (i = 0; replace && i < replace->num; i++) {
			if (!replace->elem[i]) {
				p11_array_remove (replace, i);
				i--;
			}
		}
	}

	free (handles);
	return rv;
}

CK_ATTRIBUTE *
p11_index_lookup (p11_index *index,
                  CK_OBJECT_HANDLE handle)
{
	index_object *obj;

	return_val_if_fail (index != NULL, NULL);

	if (handle == CK_INVALID_HANDLE)
		return NULL;

	obj = p11_dict_get (index->objects, &handle);
	return obj ? obj->attrs : NULL;
}

typedef bool (* index_sink) (p11_index *index,
                             index_object *obj,
                             CK_ATTRIBUTE *match,
                             CK_ULONG count,
                             void *data);

static void
index_select (p11_index *index,
              CK_ATTRIBUTE *match,
              CK_ULONG count,
              index_sink sink,
              void *data)
{
	index_bucket *selected[MAX_SELECT];
	CK_OBJECT_HANDLE handle;
	index_object *obj;
	unsigned int hash;
	p11_dictiter iter;
	CK_ULONG n;
	int num, at;
	int i, j;

	/* First look for any matching buckets */
	for (n = 0, num = 0; n < count && num < MAX_SELECT; n++) {
		if (is_indexable (index, match[n].type)) {
			hash = p11_attr_hash (match + n);
			selected[num] = index->buckets + (hash % NUM_BUCKETS);

			/* If any index is empty, then obviously no match */
			if (!selected[num]->num)
				return;

			num++;
		}
	}

	/* Fall back on selecting all the items, if no index */
	if (num == 0) {
		p11_dict_iterate (index->objects, &iter);
		while (p11_dict_next (&iter, NULL, (void *)&obj)) {
			if (!sink (index, obj, match, count, data))
				return;
		}
		return;
	}

	for (i = 0; i < selected[0]->num; i++) {
		/* A candidate match from first bucket */
		handle = selected[0]->elem[i];

		/* Check if the candidate is in other buckets */
		for (j = 1; j < num; j++) {
			assert (selected[j]->elem); /* checked above */
			at = binary_search (selected[j]->elem, 0, selected[j]->num, handle);
			if (at >= selected[j]->num || selected[j]->elem[at] != handle) {
				handle = 0;
				break;
			}
		}

		/* Matched all the buckets, now actually match attrs */
		if (handle != 0) {
			obj = p11_dict_get (index->objects, &handle);
			if (obj != NULL) {
				if (!sink (index, obj, match, count, data))
					return;
			}
		}
	}
}

static bool
sink_one_match (p11_index *index,
                index_object *obj,
                CK_ATTRIBUTE *match,
                CK_ULONG count,
                void *data)
{
	CK_OBJECT_HANDLE *result = data;

	if (p11_attrs_matchn (obj->attrs, match, count)) {
		*result = obj->handle;
		return false;
	}

	return true;
}

CK_OBJECT_HANDLE
p11_index_find (p11_index *index,
                CK_ATTRIBUTE *match,
                int count)
{
	CK_OBJECT_HANDLE handle = 0UL;

	return_val_if_fail (index != NULL, 0UL);

	if (count < 0)
		count = p11_attrs_count (match);

	index_select (index, match, count, sink_one_match, &handle);
	return handle;
}

static bool
sink_if_match (p11_index *index,
               index_object *obj,
               CK_ATTRIBUTE *match,
               CK_ULONG count,
               void *data)
{
	index_bucket *handles = data;

	if (p11_attrs_matchn (obj->attrs, match, count))
		bucket_push (handles, obj->handle);
	return true;
}

CK_OBJECT_HANDLE *
p11_index_find_all (p11_index *index,
                    CK_ATTRIBUTE *match,
                    int count)
{
	index_bucket handles = { NULL, 0 };

	return_val_if_fail (index != NULL, NULL);

	if (count < 0)
		count = p11_attrs_count (match);

	index_select (index, match, count, sink_if_match, &handles);

	/* Null terminate */
	bucket_push (&handles, 0UL);
	return handles.elem;
}

static bool
sink_any (p11_index *index,
          index_object *obj,
          CK_ATTRIBUTE *match,
          CK_ULONG count,
          void *data)
{
	index_bucket *handles = data;
	bucket_push (handles, obj->handle);
	return true;
}

CK_OBJECT_HANDLE *
p11_index_snapshot (p11_index *index,
                    p11_index *base,
                    CK_ATTRIBUTE *attrs,
                    CK_ULONG count)
{
	index_bucket handles = { NULL, 0 };

	return_val_if_fail (index != NULL, NULL);

	if (count < (CK_ULONG)0UL)
		count = p11_attrs_count (attrs);

	index_select (index, attrs, count, sink_any, &handles);
	if (base)
		index_select (base, attrs, count, sink_any, &handles);

	/* Null terminate */
	bucket_push (&handles, 0UL);
	return handles.elem;
}
