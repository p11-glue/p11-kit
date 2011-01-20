/*
 * Copyright (c) 2004, Stefan Walter
 * All rights reserved.
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
#include <stdlib.h>
#include <string.h>
#include "hash.h"

#define KEY_DATA(he)    ((he)->key)

/*
 * The internal form of a hash table.
 *
 * The table is an array indexed by the hash of the key; collisions
 * are resolved by hanging a linked list of hash entries off each
 * element of the array. Although this is a really simple design it
 * isn't too bad given that pools have a low allocation overhead.
 */

typedef struct hsh_entry_t hsh_entry_t;

struct hsh_entry_t
{
    hsh_entry_t* next;
    unsigned int hash;
    const void* key;
    size_t klen;
    const void* val;
};

/*
 * Data structure for iterating through a hash table.
 *
 * We keep a pointer to the next hash entry here to allow the current
 * hash entry to be freed or otherwise mangled between calls to
 * hsh_next().
 */
struct hsh_index_t
{
    hsh_t* ht;
    hsh_entry_t* ths;
    hsh_entry_t* next;
    unsigned int index;
};

/*
 * The size of the array is always a power of two. We use the maximum
 * index rather than the size so that we can use bitwise-AND for
 * modular arithmetic.
 * The count of hash entries may be greater depending on the chosen
 * collision rate.
 */
struct hsh_t
{
    hsh_entry_t** array;
    hsh_index_t iterator;    /* For hsh_first(...) */
    unsigned int count;
    unsigned int max;
};


#define INITIAL_MAX 15 /* tunable == 2^n - 1 */
#define int_malloc malloc
#define int_calloc calloc
#define int_free free

/*
 * Hash creation functions.
 */

static hsh_entry_t** alloc_array(hsh_t* ht, unsigned int max)
{
    return (hsh_entry_t**)int_calloc(sizeof(*(ht->array)), (max + 1));
}

hsh_t* hsh_create()
{
    hsh_t* ht = int_malloc(sizeof(hsh_t));
    if(ht)
    {
        ht->count = 0;
        ht->max = INITIAL_MAX;
        ht->array = alloc_array(ht, ht->max);
        if(!ht->array)
        {
            int_free(ht);
            return NULL;
        }
    }
    return ht;
}

void hsh_free(hsh_t* ht)
{
    hsh_index_t* hi;

    for(hi = hsh_first(ht); hi; hi = hsh_next(hi))
        int_free(hi->ths);

    if(ht->array)
        int_free(ht->array);

    int_free(ht);
}

/*
 * Hash iteration functions.
 */

hsh_index_t* hsh_next(hsh_index_t* hi)
{
    hi->ths = hi->next;
    while(!hi->ths)
    {
        if(hi->index > hi->ht->max)
            return NULL;

        hi->ths = hi->ht->array[hi->index++];
    }
    hi->next = hi->ths->next;
    return hi;
}

hsh_index_t* hsh_first(hsh_t* ht)
{
    hsh_index_t* hi = &ht->iterator;

    hi->ht = ht;
    hi->index = 0;
    hi->ths = NULL;
    hi->next = NULL;
    return hsh_next(hi);
}

void* hsh_this(hsh_index_t* hi, const void** key, size_t* klen)
{
    if(key)
        *key = KEY_DATA(hi->ths);
    if(klen)
        *klen = hi->ths->klen;
    return (void*)hi->ths->val;
}


/*
 * Expanding a hash table
 */

static int expand_array(hsh_t* ht)
{
    hsh_index_t* hi;
    hsh_entry_t** new_array;
    unsigned int new_max;

    new_max = ht->max * 2 + 1;
    new_array = alloc_array(ht, new_max);

    if(!new_array)
        return 0;

    for(hi = hsh_first(ht); hi; hi = hsh_next(hi))
    {
        unsigned int i = hi->ths->hash & new_max;
        hi->ths->next = new_array[i];
        new_array[i] = hi->ths;
    }

    if(ht->array)
        free(ht->array);

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

static hsh_entry_t** find_entry(hsh_t* ht, const void* key, size_t klen, const void* val)
{
    hsh_entry_t** hep;
    hsh_entry_t* he;
    const unsigned char* p;
    unsigned int hash;
    size_t i;

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

    if(klen == HSH_KEY_STRING)
    {
        for(p = key; *p; p++)
            hash = hash * 33 + *p;

        klen = p - (const unsigned char *)key;
    }
    else
    {
        for(p = key, i = klen; i; i--, p++)
            hash = hash * 33 + *p;
    }

    /* scan linked list */
    for(hep = &ht->array[hash & ht->max], he = *hep;
            he; hep = &he->next, he = *hep)
    {
     if(he->hash == hash &&
        he->klen == klen &&
        memcmp(KEY_DATA(he), key, klen) == 0)
         break;
    }

    if(he || !val)
        return hep;

    /* add a new entry for non-NULL val */
    he = int_malloc(sizeof(*he));

    if(he)
    {
        /* Key points to external data */
        he->key = key;
        he->klen = klen;

        he->next = NULL;
        he->hash = hash;
        he->val    = val;

        *hep = he;
        ht->count++;
    }

    return hep;
}

void* hsh_get(hsh_t* ht, const void *key, size_t klen)
{
        hsh_entry_t** he = find_entry(ht, key, klen, NULL);

        if(he && *he)
            return (void*)((*he)->val);
        else
            return NULL;
}

int hsh_set(hsh_t* ht, const void* key, size_t klen, void* val)
{
    hsh_entry_t** hep = find_entry(ht, key, klen, val);

    if(hep && *hep)
    {
        /* replace entry */
        (*hep)->val = val;

        /* check that the collision rate isn't too high */
        if(ht->count > ht->max)
        {
            if(!expand_array(ht))
                return 0;
        }

        return 1;
    }

    return 0;
}

void* hsh_rem(hsh_t* ht, const void* key, size_t klen)
{
    hsh_entry_t** hep = find_entry(ht, key, klen, NULL);
    void* val = NULL;

    if(hep && *hep)
    {
        hsh_entry_t* old = *hep;
        *hep = (*hep)->next;
        --ht->count;
        val = (void*)old->val;
        free(old);
    }

    return val;
}

void hsh_clear(hsh_t* ht)
{
	hsh_entry_t *he, *next;
	int i;

	/* Free all entries in the array */
	for (i = 0; i < ht->max; ++i) {
		he = ht->array[i];
		while (he) {
			next = he->next;
			free (he);
			he = next;
		}
	}

	memset (ht->array, 0, ht->max * sizeof (hsh_entry_t*));
	ht->count = 0;
}

unsigned int hsh_count(hsh_t* ht)
{
    return ht->count;
}

