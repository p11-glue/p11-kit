/*
 * Copyright (c) 2004 Stefan Walter
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

#include "debug.h"
#include "dict.h"
#include "hash.h"

#include <sys/types.h>

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

struct _p11_dict {
	p11_dict_hasher hash_func;
	p11_dict_equals equal_func;
	p11_destroyer key_destroy_func;
	p11_destroyer value_destroy_func;

	struct _p11_dictbucket **buckets;
	unsigned int num_items;
	unsigned int num_buckets;
};

typedef struct _p11_dictbucket {
	void *key;
	unsigned int hashed;
	void *value;
	struct _p11_dictbucket *next;
} dictbucket;

static dictbucket *
next_entry (p11_dictiter *iter)
{
	dictbucket *bucket = iter->next;
	while (!bucket) {
		if (iter->index >= iter->dict->num_buckets)
			return NULL;
		bucket = iter->dict->buckets[iter->index++];
	}
	iter->next = bucket->next;
	return bucket;
}


bool
p11_dict_next (p11_dictiter *iter,
               void **key,
               void **value)
{
	dictbucket *bucket = next_entry (iter);
	if (bucket == NULL)
		return false;
	if (key)
		*key = bucket->key;
	if (value)
		*value = bucket->value;
	return true;
}

void
p11_dict_iterate (p11_dict *dict,
                  p11_dictiter *iter)
{
	iter->dict = dict;
	iter->index = 0;
	iter->next = NULL;
}

static dictbucket **
lookup_or_create_bucket (p11_dict *dict,
                         const void *key,
                         bool create)
{
	dictbucket **bucketp;
	unsigned int hash;

	/* Perform the hashing */
	hash = dict->hash_func (key);

	/* scan linked list */
	for (bucketp = &dict->buckets[hash % dict->num_buckets];
	     *bucketp != NULL; bucketp = &(*bucketp)->next) {
		if((*bucketp)->hashed == hash && dict->equal_func ((*bucketp)->key, key))
			break;
	}

	if ((*bucketp) != NULL || !create)
		return bucketp;

	/* add a new entry for non-NULL val */
	(*bucketp) = calloc (sizeof (dictbucket), 1);

	if (*bucketp != NULL) {
		(*bucketp)->key = (void*)key;
		(*bucketp)->hashed = hash;
		dict->num_items++;
	}

	return bucketp;
}

void *
p11_dict_get (p11_dict *dict,
              const void *key)
{
	dictbucket **bucketp;

	bucketp = lookup_or_create_bucket (dict, key, false);
	if (bucketp && *bucketp)
		return (void*)((*bucketp)->value);
	else
		return NULL;
}

bool
p11_dict_set (p11_dict *dict,
              void *key,
              void *val)
{
	dictbucket **bucketp;
	p11_dictiter iter;
	dictbucket *bucket;
	dictbucket **new_buckets;
	unsigned int num_buckets;

	bucketp = lookup_or_create_bucket (dict, key, true);
	if(bucketp && *bucketp) {

		/* Destroy the previous key */
		if ((*bucketp)->key && (*bucketp)->key != key && dict->key_destroy_func)
			dict->key_destroy_func ((*bucketp)->key);

		/* Destroy the previous value */
		if ((*bucketp)->value && (*bucketp)->value != val && dict->value_destroy_func)
			dict->value_destroy_func ((*bucketp)->value);

		/* replace entry */
		(*bucketp)->key = key;
		(*bucketp)->value = val;

		/* check that the collision rate isn't too high */
		if (dict->num_items > dict->num_buckets) {
			num_buckets = dict->num_buckets * 2 + 1;
			new_buckets = (dictbucket **)calloc (sizeof (dictbucket *), num_buckets);

			/* Ignore failures, maybe we can expand later */
			if(new_buckets) {
				p11_dict_iterate (dict, &iter);
				while ((bucket = next_entry (&iter)) != NULL) {
					unsigned int i = bucket->hashed % num_buckets;
					bucket->next = new_buckets[i];
					new_buckets[i] = bucket;
				}

				free (dict->buckets);
				dict->buckets = new_buckets;
				dict->num_buckets = num_buckets;
			}
		}

		return true;
	}

	return_val_if_reached (false);
}

bool
p11_dict_steal (p11_dict *dict,
                const void *key,
                void **stolen_key,
                void **stolen_value)
{
	dictbucket **bucketp;

	bucketp = lookup_or_create_bucket (dict, key, false);
	if (bucketp && *bucketp) {
		dictbucket *old = *bucketp;
		*bucketp = (*bucketp)->next;
		--dict->num_items;
		if (stolen_key)
			*stolen_key = old->key;
		if (stolen_value)
			*stolen_value = old->value;
		free (old);
		return true;
	}

	return false;

}

bool
p11_dict_remove (p11_dict *dict,
                 const void *key)
{
	void *old_key;
	void *old_value;

	if (!p11_dict_steal (dict, key, &old_key, &old_value))
		return false;

	if (dict->key_destroy_func)
		dict->key_destroy_func (old_key);
	if (dict->value_destroy_func)
		dict->value_destroy_func (old_value);
	return true;
}

void
p11_dict_clear (p11_dict *dict)
{
	dictbucket *bucket, *next;
	int i;

	/* Free all entries in the array */
	for (i = 0; i < dict->num_buckets; ++i) {
		bucket = dict->buckets[i];
		while (bucket != NULL) {
			next = bucket->next;
			if (dict->key_destroy_func)
				dict->key_destroy_func (bucket->key);
			if (dict->value_destroy_func)
				dict->value_destroy_func (bucket->value);
			free (bucket);
			bucket = next;
		}
	}

	memset (dict->buckets, 0, dict->num_buckets * sizeof (dictbucket *));
	dict->num_items = 0;
}

p11_dict *
p11_dict_new (p11_dict_hasher hash_func,
              p11_dict_equals equal_func,
              p11_destroyer key_destroy_func,
              p11_destroyer value_destroy_func)
{
	p11_dict *dict;

	assert (hash_func);
	assert (equal_func);

	dict = malloc (sizeof (p11_dict));
	if (dict) {
		dict->hash_func = hash_func;
		dict->equal_func = equal_func;
		dict->key_destroy_func = key_destroy_func;
		dict->value_destroy_func = value_destroy_func;

		dict->num_buckets = 9;
		dict->buckets = (dictbucket **)calloc (sizeof (dictbucket *), dict->num_buckets);
		if (!dict->buckets) {
			free (dict);
			return NULL;
		}

		dict->num_items = 0;
	}

	return dict;
}

void
p11_dict_free (p11_dict *dict)
{
	dictbucket *bucket;
	p11_dictiter iter;

	if (!dict)
		return;

	p11_dict_iterate (dict, &iter);
	while ((bucket = next_entry (&iter)) != NULL) {
		if (dict->key_destroy_func)
			dict->key_destroy_func (bucket->key);
		if (dict->value_destroy_func)
			dict->value_destroy_func (bucket->value);
		free (bucket);
	}

	if (dict->buckets)
		free (dict->buckets);

	free (dict);
}

unsigned int
p11_dict_size (p11_dict *dict)
{
	return dict->num_items;
}

unsigned int
p11_dict_str_hash (const void *string)
{
	uint32_t hash;
	p11_hash_murmur3 (&hash, string, strlen (string), NULL);
	return hash;
}

bool
p11_dict_str_equal (const void *string_one,
                    const void *string_two)
{
	assert (string_one);
	assert (string_two);

	return strcmp (string_one, string_two) == 0;
}

unsigned int
p11_dict_ulongptr_hash (const void *to_ulong)
{
	assert (to_ulong);
	return (unsigned int)*((unsigned long*)to_ulong);
}

bool
p11_dict_ulongptr_equal (const void *ulong_one,
                         const void *ulong_two)
{
	assert (ulong_one);
	assert (ulong_two);
	return *((unsigned long*)ulong_one) == *((unsigned long*)ulong_two);
}

unsigned int
p11_dict_intptr_hash (const void *to_int)
{
	assert (to_int);
	return (unsigned int)*((int*)to_int);
}

bool
p11_dict_intptr_equal (const void *int_one,
                        const void *int_two)
{
	assert (int_one);
	assert (int_two);
	return *((int*)int_one) == *((int*)int_two);
}

unsigned int
p11_dict_direct_hash (const void *ptr)
{
	return (unsigned int)(size_t)ptr;
}

bool
p11_dict_direct_equal (const void *ptr_one,
                       const void *ptr_two)
{
	return ptr_one == ptr_two;
}
