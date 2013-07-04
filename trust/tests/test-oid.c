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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "debug.h"
#include "oid.h"

#include <libtasn1.h>

#include "pkix.asn.h"

static void
test_known_oids (void)
{
	char buffer[128];
	node_asn *definitions = NULL;
	node_asn *node;
	int ret;
	int len;
	int i;

	struct {
		const unsigned char *oid;
		size_t length;
		const char *string;
	} known_oids[] = {
		{ P11_OID_SUBJECT_KEY_IDENTIFIER, sizeof (P11_OID_SUBJECT_KEY_IDENTIFIER), P11_OID_SUBJECT_KEY_IDENTIFIER_STR, },
		{ P11_OID_KEY_USAGE, sizeof (P11_OID_KEY_USAGE), P11_OID_KEY_USAGE_STR, },
		{ P11_OID_BASIC_CONSTRAINTS, sizeof (P11_OID_BASIC_CONSTRAINTS), P11_OID_BASIC_CONSTRAINTS_STR },
		{ P11_OID_EXTENDED_KEY_USAGE, sizeof (P11_OID_EXTENDED_KEY_USAGE), P11_OID_EXTENDED_KEY_USAGE_STR },
		{ P11_OID_OPENSSL_REJECT, sizeof (P11_OID_OPENSSL_REJECT), P11_OID_OPENSSL_REJECT_STR },
		{ P11_OID_SERVER_AUTH, sizeof (P11_OID_SERVER_AUTH), P11_OID_SERVER_AUTH_STR },
		{ P11_OID_CLIENT_AUTH, sizeof (P11_OID_CLIENT_AUTH), P11_OID_CLIENT_AUTH_STR },
		{ P11_OID_CODE_SIGNING, sizeof (P11_OID_CODE_SIGNING), P11_OID_CODE_SIGNING_STR },
		{ P11_OID_EMAIL_PROTECTION, sizeof (P11_OID_EMAIL_PROTECTION), P11_OID_EMAIL_PROTECTION_STR },
		{ P11_OID_IPSEC_END_SYSTEM, sizeof (P11_OID_IPSEC_END_SYSTEM), P11_OID_IPSEC_END_SYSTEM_STR },
		{ P11_OID_IPSEC_TUNNEL, sizeof (P11_OID_IPSEC_TUNNEL), P11_OID_IPSEC_TUNNEL_STR },
		{ P11_OID_IPSEC_USER, sizeof (P11_OID_IPSEC_USER), P11_OID_IPSEC_USER_STR },
		{ P11_OID_TIME_STAMPING, sizeof (P11_OID_TIME_STAMPING), P11_OID_TIME_STAMPING_STR },
		{ P11_OID_RESERVED_PURPOSE, sizeof (P11_OID_RESERVED_PURPOSE), P11_OID_RESERVED_PURPOSE_STR },
		{ NULL },
	};

	ret = asn1_array2tree (pkix_asn1_tab, &definitions, NULL);
	assert (ret == ASN1_SUCCESS);

	for (i = 0; known_oids[i].oid != NULL; i++) {

		assert (p11_oid_simple (known_oids[i].oid, known_oids[i].length));
		assert_num_eq (known_oids[i].length, p11_oid_length (known_oids[i].oid));
		assert (p11_oid_equal (known_oids[i].oid, known_oids[i].oid));

		if (i > 0)
			assert (!p11_oid_equal (known_oids[i].oid, known_oids[i - 1].oid));

		/* AttributeType is a OBJECT IDENTIFIER */
		ret = asn1_create_element (definitions, "PKIX1.AttributeType", &node);
		assert (ret == ASN1_SUCCESS);

		ret = asn1_der_decoding (&node, known_oids[i].oid, known_oids[i].length, NULL);
		assert (ret == ASN1_SUCCESS);

		len = sizeof (buffer);
		ret = asn1_read_value (node, "", buffer, &len);
		assert (ret == ASN1_SUCCESS);

		assert_str_eq (known_oids[i].string, buffer);

		asn1_delete_structure (&node);
	}

	asn1_delete_structure (&definitions);
}

static void
test_hash (void)
{
	assert_num_cmp (p11_oid_hash (P11_OID_CN), !=, 0);
	assert_num_cmp (p11_oid_hash (P11_OID_CN), ==, p11_oid_hash (P11_OID_CN));
	assert_num_cmp (p11_oid_hash (P11_OID_CN), !=, p11_oid_hash (P11_OID_BASIC_CONSTRAINTS));
}

int
main (int argc,
      char *argv[])
{
	p11_test (test_known_oids, "/oids/known");
	p11_test (test_hash, "/oids/hash");
	return p11_test_run (argc, argv);
}
