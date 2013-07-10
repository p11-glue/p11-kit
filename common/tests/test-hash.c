/*
 * Copyright (c) 2012 Red Hat Inc.
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
 * Author: Stef Walter <stefw@gnome.org>
 */

#include "config.h"
#include "test.h"

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "hash.h"

static void
test_murmur3 (void)
{
	uint32_t one, two, four, seven, eleven, split;

	assert (sizeof (one) == P11_HASH_MURMUR3_LEN);

	p11_hash_murmur3 ((unsigned char *)&one, "one", 3, NULL);
	p11_hash_murmur3 ((unsigned char *)&two, "two", 3, NULL);
	p11_hash_murmur3 ((unsigned char *)&four, "four", 4, NULL);
	p11_hash_murmur3 ((unsigned char *)&seven, "seven", 5, NULL);
	p11_hash_murmur3 ((unsigned char *)&eleven, "eleven", 6, NULL);
	p11_hash_murmur3 ((unsigned char *)&split, "ele", 3, "ven", 3, NULL);

	assert (one != two);
	assert (one != four);
	assert (one != seven);
	assert (one != eleven);

	assert (two != four);
	assert (two != seven);
	assert (two != eleven);

	assert (four != seven);
	assert (four != eleven);

	assert (split == eleven);
}

static void
test_murmur3_incr (void)
{
	uint32_t first, second;

	p11_hash_murmur3 ((unsigned char *)&first,
	                  "this is the long input!", (size_t)23,
	                  NULL);

	p11_hash_murmur3 ((unsigned char *)&second,
	                  "this", (size_t)4,
	                  " ", (size_t)1,
	                  "is ", (size_t)3,
	                  "the long ", (size_t)9,
	                  "in", (size_t)2,
	                  "p", (size_t)1,
	                  "u", (size_t)1,
	                  "t", (size_t)1,
	                  "!", (size_t)1,
	                  NULL);

	assert_num_eq (first, second);
}

int
main (int argc,
      char *argv[])
{
	p11_test (test_murmur3, "/hash/murmur3");
	p11_test (test_murmur3_incr, "/hash/murmur3-incr");
	return p11_test_run (argc, argv);
}
