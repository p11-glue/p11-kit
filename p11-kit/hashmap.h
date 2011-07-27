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
 *
 * Author: Stef Waler <stefw@collabora.co.uk>
 */

#ifndef HASHMAP_H_
#define HASHMAP_H_

#include <sys/types.h>

/*
 * ARGUMENT DOCUMENTATION
 *
 * map: The hashmap
 * key: Pointer to the key value
 * val: Pointer to the value
 * iter: A hashmap iterator
 */


/* ----------------------------------------------------------------------------------
 * TYPES
 */

/* Abstract type for hash maps. */
typedef struct _hashmap hashmap;

/* Type for scanning hash tables.  */
typedef struct _hashiter {
	hashmap *map;
	struct _hashbucket *next;
	unsigned int index;
} hashiter;

typedef unsigned int (*hash_hash_func)            (const void *data);

typedef int          (*hash_equal_func)           (const void *one,
                                                   const void *two);

typedef void         (*hash_destroy_func)         (void *data);

/* -----------------------------------------------------------------------------
 * MAIN
 */

/*
 * hash_create : Create a hash table
 * - returns an allocated hashtable
 */
hashmap*           hash_create                 (hash_hash_func hash_func,
                                                hash_equal_func equal_func,
                                                hash_destroy_func key_destroy_func,
                                                hash_destroy_func value_destroy_func);

/*
 * hash_free : Free a hash table
 */
void               hash_free                   (hashmap *map);

/*
 * hash_size: Number of values in hash table
 * - returns the number of entries in hash table
 */
unsigned int       hash_size                   (hashmap *map);

/*
 * hash_get: Retrieves a value from the hash table
 * - returns the value of the entry
 */
void*              hash_get                    (hashmap *map,
                                                const void *key);

/*
 * hash_set: Set a value in the hash table
 * - returns 1 if the entry was added properly
 */
int                hash_set                    (hashmap *map,
                                                void *key,
                                                void *value);

/*
 * hash_remove: Remove a value from the hash table
 * - returns 1 if the entry was found
 */
int                hash_remove                 (hashmap *map,
                                                const void *key);

/*
 * hash_steal: Remove a value from the hash table without calling destroy funcs
 * - returns 1 if the entry was found
 */
int                hash_steal                  (hashmap *map,
                                                const void *key,
                                                void **stolen_key,
                                                void **stolen_value);

/*
 * hash_first: Start enumerating through the hash table
 * - returns a hash iterator
 */
void               hash_iterate                (hashmap *map,
                                                hashiter *iter);

/*
 * hash_next: Enumerate through hash table
 * - sets key and value to key and/or value
 * - returns whether there was another entry
 */
int                hash_next                   (hashiter *iter,
                                                void **key,
                                                void **value);

/*
 * hash_clear: Clear all values from has htable.
 */
void               hash_clear                  (hashmap *map);

/* -----------------------------------------------------------------------------
 * HASH FUNCTIONS
 */

unsigned int       hash_string_hash            (const void *string);

int                hash_string_equal           (const void *string_one,
                                                const void *string_two);

unsigned int       hash_ulongptr_hash          (const void *to_ulong);

int                hash_ulongptr_equal         (const void *ulong_one,
                                                const void *ulong_two);

unsigned int       hash_intptr_hash            (const void *to_int);

int                hash_intptr_equal           (const void *int_one,
                                                const void *int_two);

unsigned int       hash_direct_hash            (const void *ptr);

int                hash_direct_equal           (const void *ptr_one,
                                                const void *ptr_two);

#endif  /* __HASHMAP_H__ */
