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
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __HSH_H__
#define __HSH_H__

#include <sys/types.h>

/*
 * OPTIONAL FEATURES
 *
 * Features to define. You need to build both this file and
 * the corresponding hash.c file with whatever options you set here.
 * These affect the method signatures, so see the sections below
 * for the actual options
 */

/*
 * ARGUMENT DOCUMENTATION
 *
 * ht: The hashtable
 * key: Pointer to the key value
 * klen: The length of the key
 * val: Pointer to the value
 * hi: A hashtable iterator
 * stamp: A unix timestamp
 */


/* ----------------------------------------------------------------------------------
 * TYPES
 */

/* Abstract type for hash tables. */
typedef struct hsh_t hsh_t;

/* Abstract type for scanning hash tables.  */
typedef struct hsh_index_t hsh_index_t;

/* -----------------------------------------------------------------------------
 * MAIN
 */

/*
 * hsh_create : Create a hash table
 * - returns an allocated hashtable
 */
hsh_t* hsh_create(void);

/*
 * hsh_free : Free a hash table
 */
void hsh_free(hsh_t* ht);

/*
 * hsh_count: Number of values in hash table
 * - returns the number of entries in hash table
 */
unsigned int hsh_count(hsh_t* ht);

/*
 * hsh_get: Retrieves a value from the hash table
 * - returns the value of the entry
 */
void* hsh_get(hsh_t* ht, const void* key, size_t klen);

/*
 * hsh_set: Set a value in the hash table
 * - returns 1 if the entry was added properly
 */
int hsh_set(hsh_t* ht, const void* key, size_t klen, void* val);

/*
 * hsh_rem: Remove a value from the hash table
 * - returns the value of the removed entry
 */
void* hsh_rem(hsh_t* ht, const void* key, size_t klen);

/*
 * hsh_first: Start enumerating through the hash table
 * - returns a hash iterator
 */
hsh_index_t* hsh_first(hsh_t* ht);

/*
 * hsh_next: Enumerate through hash table
 * - returns the hash iterator or null when no more entries
 */
hsh_index_t* hsh_next(hsh_index_t* hi);

/*
 * hsh_this: While enumerating get current value
 * - returns the value that the iterator currently points to
 */
void* hsh_this(hsh_index_t* hi, const void** key, size_t* klen);

/*
 * hsh_clear: Clear all values from has htable.
 */
void hsh_clear(hsh_t* ht);

/*
 * This can be passed as 'klen' in any of the above functions to indicate
 * a string-valued key, and have hash compute the length automatically.
 */
#define HSH_KEY_STRING     (-1)

#endif  /* __HSH_H__ */
