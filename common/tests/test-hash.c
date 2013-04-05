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

const char *sha1_input[] = {
	"abc",
	"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
	NULL
};

const char *sha1_checksum[] = {
	"\xA9\x99\x3E\x36\x47\x06\x81\x6A\xBA\x3E\x25\x71\x78\x50\xC2\x6C\x9C\xD0\xD8\x9D",
	"\x84\x98\x3E\x44\x1C\x3B\xD2\x6E\xBA\xAE\x4A\xA1\xF9\x51\x29\xE5\xE5\x46\x70\xF1",
	NULL
};

static void
test_sha1 (void)
{
	unsigned char checksum[P11_HASH_SHA1_LEN];
	size_t len;
	int i;

	for (i = 0; sha1_input[i] != NULL; i++) {
		memset (checksum, 0, sizeof (checksum));
		len = strlen (sha1_input[i]);

		p11_hash_sha1 (checksum, sha1_input[i], len, NULL);
		assert (memcmp (sha1_checksum[i], checksum, P11_HASH_SHA1_LEN) == 0);

		if (len > 6) {
			p11_hash_sha1 (checksum, sha1_input[i], 6, sha1_input[i] + 6, len - 6, NULL);
			assert (memcmp (sha1_checksum[i], checksum, P11_HASH_SHA1_LEN) == 0);
		}
	}
}

static void
test_sha1_long (void)
{
	unsigned char checksum[P11_HASH_SHA1_LEN];
	char *expected = "\x34\xAA\x97\x3C\xD4\xC4\xDA\xA4\xF6\x1E\xEB\x2B\xDB\xAD\x27\x31\x65\x34\x01\x6F";
	char *input;

	input = malloc (1000000);
	assert (input != NULL);
	memset (input, 'a', 1000000);

	p11_hash_sha1 (checksum, input, 1000000, NULL);
	assert (memcmp (expected, checksum, P11_HASH_SHA1_LEN) == 0);

	free (input);
}

const char *md5_input[] = {
	"",
	"a",
	"abc",
	"message digest",
	"abcdefghijklmnopqrstuvwxyz",
	NULL
};

const char *md5_checksum[] = {
	"\xd4\x1d\x8c\xd9\x8f\x00\xb2\x04\xe9\x80\x09\x98\xec\xf8\x42\x7e",
	"\x0c\xc1\x75\xb9\xc0\xf1\xb6\xa8\x31\xc3\x99\xe2\x69\x77\x26\x61",
	"\x90\x01\x50\x98\x3c\xd2\x4f\xb0\xd6\x96\x3f\x7d\x28\xe1\x7f\x72",
	"\xf9\x6b\x69\x7d\x7c\xb7\x93\x8d\x52\x5a\x2f\x31\xaa\xf1\x61\xd0",
	"\xc3\xfc\xd3\xd7\x61\x92\xe4\x00\x7d\xfb\x49\x6c\xca\x67\xe1\x3b",
	NULL
};

static void
test_md5 (void)
{
	unsigned char checksum[P11_HASH_MD5_LEN];
	size_t len;
	int i;

	for (i = 0; md5_input[i] != NULL; i++) {
		memset (checksum, 0, sizeof (checksum));
		len = strlen (md5_input[i]);

		p11_hash_md5 (checksum, md5_input[i], len, NULL);
		assert (memcmp (md5_checksum[i], checksum, P11_HASH_MD5_LEN) == 0);

		if (len > 5) {
			p11_hash_md5 (checksum, md5_input[i], 5, md5_input[i] + 5, len - 5, NULL);
			assert (memcmp (md5_checksum[i], checksum, P11_HASH_MD5_LEN) == 0);
		}
	}
}

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
	p11_test (test_sha1, "/hash/sha1");
	p11_test (test_sha1_long, "/hash/sha1-long");
	p11_test (test_md5, "/hash/md5");
	p11_test (test_murmur3, "/hash/murmur3");
	p11_test (test_murmur3_incr, "/hash/murmur3-incr");
	return p11_test_run (argc, argv);
}
