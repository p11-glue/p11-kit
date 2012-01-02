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

#include "hashmap.h"

#include <sys/types.h>

#include <assert.h>
#include <stdlib.h>
#include <string.h>

struct _hashmap {
	hash_hash_func hash_func;
	hash_equal_func equal_func;
	hash_destroy_func key_destroy_func;
	hash_destroy_func value_destroy_func;

	struct _hashbucket **buckets;
	unsigned int num_items;
	unsigned int num_buckets;
};

typedef struct _hashbucket {
	void *key;
	unsigned int hashed;
	void *value;
	struct _hashbucket *next;
} hashbucket;

static hashbucket *
next_entry (hashiter *iter)
{
	hashbucket *bucket = iter->next;
	while (!bucket) {
		if (iter->index > iter->map->num_buckets)
			return NULL;
		bucket = iter->map->buckets[iter->index++];
	}
	iter->next = bucket->next;
	return bucket;
}


int
_p11_hash_next (hashiter *iter,
                void **key,
                void **value)
{
	hashbucket *bucket = next_entry (iter);
	if (bucket == NULL)
		return 0;
	if (key)
		*key = bucket->key;
	if (value)
		*value = bucket->value;
	return 1;
}

void
_p11_hash_iterate (hashmap *map,
                   hashiter *iter)
{
	iter->map = map;
	iter->index = 0;
	iter->next = NULL;
}

static hashbucket **
lookup_or_create_bucket (hashmap *map,
                         const void *key,
                         int create)
{
	hashbucket **bucketp;
	unsigned int hash;

	/* Perform the hashing */
	hash = map->hash_func (key);

	/* scan linked list */
	for (bucketp = &map->buckets[map->num_buckets & hash];
	     *bucketp != NULL; bucketp = &(*bucketp)->next) {
		if((*bucketp)->hashed == hash && map->equal_func ((*bucketp)->key, key))
			break;
	}

	if ((*bucketp) != NULL || !create)
		return bucketp;

	/* add a new entry for non-NULL val */
	(*bucketp) = calloc (sizeof (hashbucket), 1);

	if (*bucketp != NULL) {
		(*bucketp)->key = (void*)key;
		(*bucketp)->hashed = hash;
		map->num_items++;
	}

	return bucketp;
}

void *
_p11_hash_get (hashmap *map,
               const void *key)
{
	hashbucket **bucketp;

	bucketp = lookup_or_create_bucket (map, key, 0);
	if (bucketp && *bucketp)
		return (void*)((*bucketp)->value);
	else
		return NULL;
}

int
_p11_hash_set (hashmap *map,
               void *key,
               void *val)
{
	hashbucket **bucketp;
	hashiter iter;
	hashbucket *bucket;
	hashbucket **new_buckets;
	unsigned int num_buckets;

	bucketp = lookup_or_create_bucket (map, key, 1);
	if(bucketp && *bucketp) {

		/* Destroy the previous value */
		if ((*bucketp)->value && map->value_destroy_func)
			map->value_destroy_func ((*bucketp)->value);

		/* replace entry */
		(*bucketp)->value = val;

		/* check that the collision rate isn't too high */
		if (map->num_items > map->num_buckets) {
			num_buckets = map->num_buckets * 2 + 1;
			new_buckets = (hashbucket **)calloc (sizeof (hashbucket *),
			                                     num_buckets + 1);

			/* Ignore failures, maybe we can expand later */
			if(new_buckets) {
				_p11_hash_iterate (map, &iter);
				while ((bucket = next_entry (&iter)) != NULL) {
					unsigned int i = bucket->hashed & num_buckets;
					bucket->next = new_buckets[i];
					new_buckets[i] = bucket;
				}

				free (map->buckets);
				map->buckets = new_buckets;
				map->num_buckets = num_buckets;
			}
		}

		return 1;
	}

	return 0;
}

int
_p11_hash_steal (hashmap *map,
                 const void *key,
                 void **stolen_key,
                 void **stolen_value)
{
	hashbucket **bucketp;

	bucketp = lookup_or_create_bucket (map, key, 0);
	if (bucketp && *bucketp) {
		hashbucket *old = *bucketp;
		*bucketp = (*bucketp)->next;
		--map->num_items;
		if (stolen_key)
			*stolen_key = old->key;
		if (stolen_value)
			*stolen_value = old->value;
		free (old);
		return 1;
	}

	return 0;

}

int
_p11_hash_remove (hashmap *map,
                  const void *key)
{
	void *old_key;
	void *old_value;

	if (!_p11_hash_steal (map, key, &old_key, &old_value))
		return 0;

	if (map->key_destroy_func)
		map->key_destroy_func (old_key);
	if (map->value_destroy_func)
		map->value_destroy_func (old_value);
	return 1;
}

void
_p11_hash_clear (hashmap *map)
{
	hashbucket *bucket, *next;
	int i;

	/* Free all entries in the array */
	for (i = 0; i < map->num_buckets; ++i) {
		bucket = map->buckets[i];
		while (bucket != NULL) {
			next = bucket->next;
			if (map->key_destroy_func)
				map->key_destroy_func (bucket->key);
			if (map->value_destroy_func)
				map->value_destroy_func (bucket->value);
			free (bucket);
			bucket = next;
		}
	}

	memset (map->buckets, 0, map->num_buckets * sizeof (hashbucket *));
	map->num_items = 0;
}

hashmap *
_p11_hash_create (hash_hash_func hash_func,
                  hash_equal_func equal_func,
                  hash_destroy_func key_destroy_func,
                  hash_destroy_func value_destroy_func)
{
	hashmap *map;

	assert (hash_func);
	assert (equal_func);

	map = malloc (sizeof (hashmap));
	if (map) {
		map->hash_func = hash_func;
		map->equal_func = equal_func;
		map->key_destroy_func = key_destroy_func;
		map->value_destroy_func = value_destroy_func;

		map->num_buckets = 9;
		map->buckets = (hashbucket **)calloc (sizeof (hashbucket *),
		                                       map->num_buckets + 1);
		if (!map->buckets) {
			free (map);
			return NULL;
		}

		map->num_items = 0;
	}

	return map;
}

void
_p11_hash_free (hashmap *map)
{
	hashbucket *bucket;
	hashiter iter;

	if (!map)
		return;

	_p11_hash_iterate (map, &iter);
	while ((bucket = next_entry (&iter)) != NULL) {
		if (map->key_destroy_func)
			map->key_destroy_func (bucket->key);
		if (map->value_destroy_func)
			map->value_destroy_func (bucket->value);
		free (bucket);
	}

	if (map->buckets)
		free (map->buckets);

	free (map);
}

unsigned int
_p11_hash_size (hashmap *map)
{
	return map->num_items;
}

unsigned int
_p11_hash_string_hash (const void *string)
{
	const char *p = string;
	unsigned int hash = *p;

	if (hash)
		for (p += 1; *p != '\0'; p++)
			hash = (hash << 5) - hash + *p;

	return hash;
}

int
_p11_hash_string_equal (const void *string_one,
                        const void *string_two)
{
	assert (string_one);
	assert (string_two);

	return strcmp (string_one, string_two) == 0;
}

unsigned int
_p11_hash_ulongptr_hash (const void *to_ulong)
{
	assert (to_ulong);
	return (unsigned int)*((unsigned long*)to_ulong);
}

int
_p11_hash_ulongptr_equal (const void *ulong_one,
                          const void *ulong_two)
{
	assert (ulong_one);
	assert (ulong_two);
	return *((unsigned long*)ulong_one) == *((unsigned long*)ulong_two);
}

unsigned int
_p11_hash_intptr_hash (const void *to_int)
{
	assert (to_int);
	return (unsigned int)*((int*)to_int);
}

int
_p11_hash_intptr_equal (const void *int_one,
                        const void *int_two)
{
	assert (int_one);
	assert (int_two);
	return *((int*)int_one) == *((int*)int_two);
}

unsigned int
_p11_hash_direct_hash (const void *ptr)
{
	return (unsigned int)(size_t)ptr;
}

int
_p11_hash_direct_equal (const void *ptr_one,
                        const void *ptr_two)
{
	return ptr_one == ptr_two;
}
