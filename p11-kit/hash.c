/*
 * Copyright (c) 2004, Stefan Walter
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
 */

/*
 * Originally from apache 2.0
 * Modifications for general use by <stef@memberwebs.com>
 */

/* Copyright 2000-2004 The Apache Software Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <sys/types.h>

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "hash.h"

/*
 * The internal form of a hash table.
 *
 * The table is an array indexed by the hash of the key; collisions
 * are resolved by hanging a linked list of hash entries off each
 * element of the array. Although this is a really simple design it
 * isn't too bad given that pools have a low allocation overhead.
 */

typedef struct hash_entry hash_entry_t;

struct hash_entry
{
	hash_entry_t* next;
	unsigned int hash;
	void* key;
	void* val;
};

/*
 * The size of the array is always a power of two. We use the maximum
 * index rather than the size so that we can use bitwise-AND for
 * modular arithmetic.
 * The count of hash entries may be greater depending on the chosen
 * collision rate.
 */
struct hash {
	hash_entry_t** array;
	unsigned int count;
	unsigned int max;
	hash_hash_func hash_func;
	hash_equal_func equal_func;
	hash_destroy_func key_destroy_func;
	hash_destroy_func value_destroy_func;
};

#define INITIAL_MAX 15 /* tunable == 2^n - 1 */
#define int_malloc malloc
#define int_calloc calloc
#define int_free free

/*
 * Hash creation functions.
 */

static hash_entry_t**
alloc_array(hash_t* ht, unsigned int max)
{
	return (hash_entry_t**)int_calloc (sizeof (*(ht->array)), (max + 1));
}

hash_t*
hash_create (hash_hash_func hash_func,
             hash_equal_func equal_func,
             hash_destroy_func key_destroy_func,
             hash_destroy_func value_destroy_func)
{
	hash_t* ht;

	assert (hash_func);
	assert (equal_func);

	ht = int_malloc (sizeof (hash_t));
	if (ht) {
		ht->count = 0;
		ht->max = INITIAL_MAX;
		ht->hash_func = hash_func;
		ht->equal_func = equal_func;
		ht->key_destroy_func = key_destroy_func;
		ht->value_destroy_func = value_destroy_func;
		ht->array = alloc_array (ht, ht->max);
		if (!ht->array) {
			int_free (ht);
			return NULL;
		}
	}
	return ht;
}

void
hash_free (hash_t* ht)
{
	hash_iter_t hi;

	if (!ht)
		return;

	hash_iterate (ht, &hi);
	while (hash_next (&hi, NULL, NULL)) {
		if (ht->key_destroy_func)
			ht->key_destroy_func (hi.ths->key);
		if (ht->value_destroy_func)
			ht->value_destroy_func (hi.ths->val);
	}

	if (ht->array)
		int_free (ht->array);

	int_free (ht);
}

/*
 * Hash iteration functions.
 */
int
hash_next (hash_iter_t* hi, void **key, void **value)
{
	hi->ths = hi->next;
	while (!hi->ths) {
		if (hi->index > hi->ht->max)
			return 0;
		hi->ths = hi->ht->array[hi->index++];
	}
	hi->next = hi->ths->next;
	if (key)
		*key = hi->ths->key;
	if (value)
		*value = hi->ths->val;
	return 1;
}

void
hash_iterate (hash_t* ht, hash_iter_t *hi)
{
	hi->ht = ht;
	hi->index = 0;
	hi->ths = NULL;
	hi->next = NULL;
}

/*
 * Expanding a hash table
 */

static int
expand_array (hash_t* ht)
{
	hash_iter_t hi;
	hash_entry_t** new_array;
	unsigned int new_max;

	new_max = ht->max * 2 + 1;
	new_array = alloc_array (ht, new_max);

	if(!new_array)
		return 0;

	hash_iterate (ht, &hi);
	while (hash_next (&hi, NULL, NULL)) {
		unsigned int i = hi.ths->hash & new_max;
		hi.ths->next = new_array[i];
		new_array[i] = hi.ths;
	}

	if(ht->array)
		int_free (ht->array);

	ht->array = new_array;
	ht->max = new_max;
	return 1;
}

/*
 * This is where we keep the details of the hash function and control
 * the maximum collision rate.
 *
 * If val is non-NULL it creates and initializes a new hash entry if
 * there isn't already one there; it returns an updatable pointer so
 * that hash entries can be removed.
 */

static hash_entry_t**
find_entry (hash_t* ht, const void* key, void* val)
{
	hash_entry_t** hep;
	hash_entry_t* he;
	unsigned int hash;

	/* Perform the hashing */
	hash = ht->hash_func (key);

	/* scan linked list */
	for (hep = &ht->array[hash & ht->max], he = *hep;
	     he; hep = &he->next, he = *hep) {
		if(he->hash == hash && ht->equal_func (he->key, key))
			break;
	}

	if(he || !val)
		return hep;

	/* add a new entry for non-NULL val */
	he = int_malloc (sizeof (*he));

	if(he) {
		he->key = (void*)key;
		he->next = NULL;
		he->hash = hash;
		he->val = val;

		*hep = he;
		ht->count++;
	}

	return hep;
}

void*
hash_get (hash_t* ht, const void *key)
{
	hash_entry_t** he = find_entry (ht, key, NULL);
	if (he && *he)
		return (void*)((*he)->val);
	else
		return NULL;
}

int
hash_set (hash_t* ht, void* key, void* val)
{
	hash_entry_t** hep = find_entry (ht, key, val);
	if(hep && *hep) {
		/* replace entry */
		(*hep)->val = val;

		/* check that the collision rate isn't too high */
		if (ht->count > ht->max) {
			if (!expand_array (ht))
				return 0;
		}

		return 1;
	}

	return 0;
}

int
hash_remove (hash_t* ht, const void* key)
{
	hash_entry_t** hep = find_entry (ht, key, NULL);

	if (hep && *hep) {
		hash_entry_t* old = *hep;
		*hep = (*hep)->next;
		--ht->count;
		if (ht->key_destroy_func)
			ht->key_destroy_func (old->key);
		if (ht->value_destroy_func)
			ht->value_destroy_func (old->val);
		free (old);
		return 1;
	}

	return 0;
}

void
hash_clear (hash_t* ht)
{
	hash_entry_t *he, *next;
	int i;

	/* Free all entries in the array */
	for (i = 0; i < ht->max; ++i) {
		he = ht->array[i];
		while (he) {
			next = he->next;
			if (ht->key_destroy_func)
				ht->key_destroy_func (he->key);
			if (ht->value_destroy_func)
				ht->value_destroy_func (he->val);
			free (he);
			he = next;
		}
	}

	memset (ht->array, 0, ht->max * sizeof (hash_entry_t*));
	ht->count = 0;
}

unsigned int
hash_count (hash_t* ht)
{
	return ht->count;
}

unsigned int
hash_string_hash (const void *string)
{
	unsigned int hash;
	const unsigned char *p;

	assert (string);

	/*
	 * This is the popular `times 33' hash algorithm which is used by
	 * perl and also appears in Berkeley DB. This is one of the best
	 * known hash functions for strings because it is both computed
	 * very fast and distributes very well.
	 *
	 * The originator may be Dan Bernstein but the code in Berkeley DB
	 * cites Chris Torek as the source. The best citation I have found
	 * is "Chris Torek, Hash function for text in C, Usenet message
	 * <27038@mimsy.umd.edu> in comp.lang.c , October, 1990." in Rich
	 * Salz's USENIX 1992 paper about INN which can be found at
	 * <http://citeseer.nj.nec.com/salz92internetnews.html>.
	 *
	 * The magic of number 33, i.e. why it works better than many other
	 * constants, prime or not, has never been adequately explained by
	 * anyone. So I try an explanation: if one experimentally tests all
	 * multipliers between 1 and 256 (as I did while writing a low-level
	 * data structure library some time ago) one detects that even
	 * numbers are not useable at all. The remaining 128 odd numbers
	 * (except for the number 1) work more or less all equally well.
	 * They all distribute in an acceptable way and this way fill a hash
	 * table with an average percent of approx. 86%.
	 *
	 * If one compares the chi^2 values of the variants (see
	 * Bob Jenkins ``Hashing Frequently Asked Questions'' at
	 * http://burtleburtle.net/bob/hash/hashfaq.html for a description
	 * of chi^2), the number 33 not even has the best value. But the
	 * number 33 and a few other equally good numbers like 17, 31, 63,
	 * 127 and 129 have nevertheless a great advantage to the remaining
	 * numbers in the large set of possible multipliers: their multiply
	 * operation can be replaced by a faster operation based on just one
	 * shift plus either a single addition or subtraction operation. And
	 * because a hash function has to both distribute good _and_ has to
	 * be very fast to compute, those few numbers should be preferred.
	 *
	 *                        -- Ralf S. Engelschall <rse@engelschall.com>
	 */

	hash = 0;

	for(p = string; *p; p++)
		hash = hash * 33 + *p;

	return hash;
}

int
hash_string_equal (const void *string_one, const void *string_two)
{
	assert (string_one);
	assert (string_two);

	return strcmp (string_one, string_two) == 0;
}

unsigned int
hash_ulongptr_hash (const void *to_ulong)
{
	assert (to_ulong);
	return (unsigned int)*((unsigned long*)to_ulong);
}

int
hash_ulongptr_equal (const void *ulong_one, const void *ulong_two)
{
	assert (ulong_one);
	assert (ulong_two);
	return *((unsigned long*)ulong_one) == *((unsigned long*)ulong_two);
}

unsigned int
hash_intptr_hash (const void *to_int)
{
	assert (to_int);
	return (unsigned int)*((unsigned long*)to_int);
}

int
hash_intptr_equal (const void *int_one, const void *int_two)
{
	assert (int_one);
	assert (int_two);
	return *((unsigned long*)int_one) == *((unsigned long*)int_two);
}

unsigned int
hash_direct_hash (const void *ptr)
{
	return (unsigned int)ptr;
}

int
hash_direct_equal (const void *ptr_one, const void *ptr_two)
{
	return ptr_one == ptr_two;
}
