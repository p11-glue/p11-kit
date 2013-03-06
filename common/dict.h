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

#ifndef P11_DICT_H_
#define P11_DICT_H_

#include "compat.h"

/*
 * ARGUMENT DOCUMENTATION
 *
 * dict: The dict
 * key: Pointer to the key value
 * val: Pointer to the value
 * iter: A dict iterator
 */


/* ----------------------------------------------------------------------------------
 * TYPES
 */

/* Abstract type for dicts. */
typedef struct _p11_dict p11_dict;

/* Type for scanning hash tables.  */
typedef struct _p11_dictiter {
	p11_dict *dict;
	struct _p11_dictbucket *next;
	unsigned int index;
} p11_dictiter;

typedef unsigned int (*p11_dict_hasher)        (const void *data);

typedef bool         (*p11_dict_equals)        (const void *one,
                                                const void *two);

#ifndef P11_DESTROYER_DEFINED
#define P11_DESTROYER_DEFINED

typedef void         (*p11_destroyer)          (void *data);

#endif

/* -----------------------------------------------------------------------------
 * MAIN
 */

/*
 * p11_dict_create : Create a hash table
 * - returns an allocated hashtable
 */
p11_dict *          p11_dict_new               (p11_dict_hasher hasher,
                                                p11_dict_equals equals,
                                                p11_destroyer key_destroyer,
                                                p11_destroyer value_destroyer);

/*
 * p11_dict_free : Free a hash table
 */
void                p11_dict_free              (p11_dict *dict);

/*
 *  p11_dict_size: Number of values in hash table
 * - returns the number of entries in hash table
 */
unsigned int        p11_dict_size              (p11_dict *dict);

/*
 *  p11_dict_get: Retrieves a value from the hash table
 * - returns the value of the entry
 */
void*               p11_dict_get               (p11_dict *dict,
                                                const void *key);

/*
 *  p11_dict_set: Set a value in the hash table
 * - returns true if the entry was added properly
 */
bool                p11_dict_set               (p11_dict *dict,
                                                void *key,
                                                void *value);

/*
 *  p11_dict_remove: Remove a value from the hash table
 * - returns true if the entry was found
 */
bool                p11_dict_remove            (p11_dict *dict,
                                                const void *key);

/*
 *  p11_dict_steal: Remove a value from the hash table without calling
 * destroy funcs
 * - returns true if the entry was found
 */
bool                p11_dict_steal             (p11_dict *dict,
                                                const void *key,
                                                void **stolen_key,
                                                void **stolen_value);

/*
 *  p11_dict_iterate: Start enumerating through the hash table
 * - returns a hash iterator
 */
void                p11_dict_iterate           (p11_dict *dict,
                                                p11_dictiter *iter);

/*
 *  p11_dict_next: Enumerate through hash table
 * - sets key and value to key and/or value
 * - returns whether there was another entry
 * - p11_dict_remove or p11_dict_steal is safe to use on
 *   the current key.
 */
bool                p11_dict_next              (p11_dictiter *iter,
                                                void **key,
                                                void **value);

/*
 *  p11_dict_clear: Clear all values from has htable.
 */
void                p11_dict_clear             (p11_dict *dict);

/* -----------------------------------------------------------------------------
 * KEY FUNCTIONS
 */

unsigned int        p11_dict_str_hash          (const void *string);

bool                p11_dict_str_equal         (const void *string_one,
                                                const void *string_two);

unsigned int        p11_dict_ulongptr_hash     (const void *to_ulong);

bool                p11_dict_ulongptr_equal    (const void *ulong_one,
                                                const void *ulong_two);

unsigned int        p11_dict_intptr_hash       (const void *to_int);

bool                p11_dict_intptr_equal      (const void *int_one,
                                                const void *int_two);

unsigned int        p11_dict_direct_hash       (const void *ptr);

bool                p11_dict_direct_equal      (const void *ptr_one,
                                                const void *ptr_two);

#endif  /* __P11_DICT_H__ */
