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

#include "asn1.h"
#include "debug.h"
#include "oid.h"
#include "x509.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

struct {
	p11_dict *asn1_defs;
} test;

static void
setup (void *unused)
{
	test.asn1_defs = p11_asn1_defs_load ();
	assert_ptr_not_null (test.asn1_defs);
}

static void
teardown (void *unused)
{
	p11_dict_free (test.asn1_defs);
	memset (&test, 0, sizeof (test));
}

static void
test_tlv_length (void)
{
	struct {
		const char *der;
		size_t der_len;
		int expected;
	} tlv_lengths[] = {
		{ "\x01\x01\x00", 3, 3 },
		{ "\x01\x01\x00\x01\x02", 5, 3 },
		{ "\x01\x05\x00", 3, -1 },
		{ NULL }
	};

	int length;
	int i;

	for (i = 0; tlv_lengths[i].der != NULL; i++) {
		length = p11_asn1_tlv_length ((const unsigned char *)tlv_lengths[i].der, tlv_lengths[i].der_len);
		assert_num_eq (tlv_lengths[i].expected, length);
	}
}

static const unsigned char test_eku_server_and_client[] = {
	0x30, 0x14, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01, 0x06, 0x08, 0x2b, 0x06,
	0x01, 0x05, 0x05, 0x07, 0x03, 0x02,
};

static void
test_asn1_cache (void)
{
	p11_asn1_cache *cache;
	p11_dict *defs;
	node_asn *asn;
	node_asn *check;

	cache = p11_asn1_cache_new ();
	assert_ptr_not_null (cache);

	defs = p11_asn1_cache_defs (cache);
	assert_ptr_not_null (defs);

	asn = p11_asn1_decode (defs, "PKIX1.ExtKeyUsageSyntax",
	                       test_eku_server_and_client,
	                       sizeof (test_eku_server_and_client), NULL);
	assert_ptr_not_null (defs);

	/* Place the parsed data in the cache */
	p11_asn1_cache_take (cache, asn, "PKIX1.ExtKeyUsageSyntax",
	                     test_eku_server_and_client,
	                     sizeof (test_eku_server_and_client));

	/* Get it back out */
	check = p11_asn1_cache_get (cache, "PKIX1.ExtKeyUsageSyntax",
	                            test_eku_server_and_client,
	                            sizeof (test_eku_server_and_client));
	assert_ptr_eq (asn, check);

	/* Flush should remove it */
	p11_asn1_cache_flush (cache);
	check = p11_asn1_cache_get (cache, "PKIX1.ExtKeyUsageSyntax",
	                            test_eku_server_and_client,
	                            sizeof (test_eku_server_and_client));
	assert_ptr_eq (NULL, check);

	p11_asn1_cache_free (cache);
}

static void
test_asn1_free (void)
{
	p11_dict *defs;
	node_asn *asn;

	defs = p11_asn1_defs_load ();
	assert_ptr_not_null (defs);

	asn = p11_asn1_decode (defs, "PKIX1.ExtKeyUsageSyntax",
	                       test_eku_server_and_client,
	                       sizeof (test_eku_server_and_client), NULL);
	assert_ptr_not_null (asn);

	p11_asn1_free (asn);
	p11_asn1_free (NULL);
	p11_dict_free (defs);
}

int
main (int argc,
      char *argv[])
{
	p11_fixture (setup, teardown);
	p11_test (test_tlv_length, "/asn1/tlv_length");

	p11_fixture (NULL, NULL);
	p11_test (test_asn1_cache, "/asn1/asn1_cache");
	p11_test (test_asn1_free, "/asn1/free");

	return p11_test_run (argc, argv);
}
