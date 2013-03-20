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
#include "CuTest.h"

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
test_sha1 (CuTest *cu)
{
	unsigned char checksum[P11_HASH_SHA1_LEN];
	size_t len;
	int i;

	for (i = 0; sha1_input[i] != NULL; i++) {
		memset (checksum, 0, sizeof (checksum));
		len = strlen (sha1_input[i]);

		p11_hash_sha1 (checksum, sha1_input[i], len, NULL);
		CuAssertTrue (cu, memcmp (sha1_checksum[i], checksum, P11_HASH_SHA1_LEN) == 0);

		if (len > 6) {
			p11_hash_sha1 (checksum, sha1_input[i], 6, sha1_input[i] + 6, len - 6, NULL);
			CuAssertTrue (cu, memcmp (sha1_checksum[i], checksum, P11_HASH_SHA1_LEN) == 0);
		}
	}
}

static void
test_sha1_long (CuTest *cu)
{
	unsigned char checksum[P11_HASH_SHA1_LEN];
	char *expected = "\x34\xAA\x97\x3C\xD4\xC4\xDA\xA4\xF6\x1E\xEB\x2B\xDB\xAD\x27\x31\x65\x34\x01\x6F";
	char *input;

	input = malloc (1000000);
	CuAssertTrue (cu, input != NULL);
	memset (input, 'a', 1000000);

	p11_hash_sha1 (checksum, input, strlen (input), NULL);
	CuAssertTrue (cu, memcmp (expected, checksum, P11_HASH_SHA1_LEN) == 0);
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
test_md5 (CuTest *cu)
{
	unsigned char checksum[P11_HASH_MD5_LEN];
	size_t len;
	int i;

	for (i = 0; md5_input[i] != NULL; i++) {
		memset (checksum, 0, sizeof (checksum));
		len = strlen (md5_input[i]);

		p11_hash_md5 (checksum, md5_input[i], len, NULL);
		CuAssertTrue (cu, memcmp (md5_checksum[i], checksum, P11_HASH_MD5_LEN) == 0);

		if (len > 5) {
			p11_hash_md5 (checksum, md5_input[i], 5, md5_input[i] + 5, len - 5, NULL);
			CuAssertTrue (cu, memcmp (md5_checksum[i], checksum, P11_HASH_MD5_LEN) == 0);
		}
	}
}

static void
test_murmur2 (CuTest *cu)
{
	struct {
		const char *input;
		const char *input2;
		int hash;
	} fixtures[] = {
		{ "one", NULL, 1910179066 },
		{ "two", NULL, 396151652 },
		{ "four", NULL, -2034170174 },
		{ "seven", NULL, -588341181 },
		/* Note that these are identical output */
		{ "eleven", NULL, -37856894 },
		{ "ele", "ven", -37856894 },
		{ NULL },
	};

	uint32_t first;
	uint32_t second;
	int i;

	assert (sizeof (first) == P11_HASH_MURMUR2_LEN);
	for (i = 0; fixtures[i].input != NULL; i++) {
		p11_hash_murmur2 ((unsigned char *)&first,
		                  fixtures[i].input,
		                  strlen (fixtures[i].input),
		                  fixtures[i].input2,
		                  fixtures[i].input2 ? strlen (fixtures[i].input2) : 0,
		                  NULL);

		p11_hash_murmur2 ((unsigned char *)&second,
		                  fixtures[i].input,
		                  strlen (fixtures[i].input),
		                  fixtures[i].input2,
		                  fixtures[i].input2 ? strlen (fixtures[i].input2) : 0,
		                  NULL);

		CuAssertIntEquals (cu, fixtures[i].hash, first);
		CuAssertIntEquals (cu, fixtures[i].hash, second);
	}
}

static void
test_murmur2_incr (CuTest *cu)
{
	uint32_t first, second;

	p11_hash_murmur2 ((unsigned char *)&first,
	                  "this is the long input!", 23,
	                  NULL);

	p11_hash_murmur2 ((unsigned char *)&second,
	                  "this", 4,
	                  " ", 1,
	                  "is ", 3,
	                  "the long ", 9,
	                  "in", 2,
	                  "p", 1,
	                  "u", 1,
	                  "t", 1,
	                  "!", 1,
	                  NULL);

	CuAssertIntEquals (cu, first, second);
}

int
main (void)
{
	CuString *output = CuStringNew ();
	CuSuite* suite = CuSuiteNew ();
	int ret;

	SUITE_ADD_TEST (suite, test_sha1);
	SUITE_ADD_TEST (suite, test_sha1_long);
	SUITE_ADD_TEST (suite, test_md5);
	SUITE_ADD_TEST (suite, test_murmur2);
	SUITE_ADD_TEST (suite, test_murmur2_incr);

	CuSuiteRun (suite);
	CuSuiteSummary (suite, output);
	CuSuiteDetails (suite, output);
	printf ("%s\n", output->buffer);
	ret = suite->failCount;
	CuSuiteDelete (suite);
	CuStringDelete (output);

	return ret;
}
