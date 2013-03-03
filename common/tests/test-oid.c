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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "debug.h"
#include "oid.h"

#include <libtasn1.h>

#include "pkix.asn.h"

static void
test_known_oids (CuTest *cu)
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
		{ P11_OID_SUBJECT_KEY_IDENTIFIER, sizeof (P11_OID_SUBJECT_KEY_IDENTIFIER), "2.5.29.14", },
		{ P11_OID_KEY_USAGE, sizeof (P11_OID_KEY_USAGE), "2.5.29.15", },
		{ P11_OID_BASIC_CONSTRAINTS, sizeof (P11_OID_BASIC_CONSTRAINTS), "2.5.29.19" },
		{ P11_OID_EXTENDED_KEY_USAGE, sizeof (P11_OID_EXTENDED_KEY_USAGE), "2.5.29.37" },
		{ P11_OID_OPENSSL_REJECT, sizeof (P11_OID_OPENSSL_REJECT), "1.3.6.1.4.1.3319.6.10.1" },
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
	CuAssertTrue (cu, ret == ASN1_SUCCESS);

	for (i = 0; known_oids[i].oid != NULL; i++) {

		CuAssertTrue (cu, p11_oid_simple (known_oids[i].oid, known_oids[i].length));
		CuAssertIntEquals (cu, known_oids[i].length, p11_oid_length (known_oids[i].oid));
		CuAssertTrue (cu, p11_oid_equal (known_oids[i].oid, known_oids[i].oid));

		if (i > 0)
			CuAssertTrue (cu, !p11_oid_equal (known_oids[i].oid, known_oids[i - 1].oid));

		/* AttributeType is a OBJECT IDENTIFIER */
		ret = asn1_create_element (definitions, "PKIX1.AttributeType", &node);
		CuAssertTrue (cu, ret == ASN1_SUCCESS);

		ret = asn1_der_decoding (&node, known_oids[i].oid, known_oids[i].length, NULL);
		CuAssertTrue (cu, ret == ASN1_SUCCESS);

		len = sizeof (buffer);
		ret = asn1_read_value (node, "", buffer, &len);
		CuAssertTrue (cu, ret == ASN1_SUCCESS);

		CuAssertStrEquals (cu, known_oids[i].string, buffer);

		asn1_delete_structure (&node);
	}

	asn1_delete_structure (&definitions);
}

int
main (void)
{
	CuString *output = CuStringNew ();
	CuSuite* suite = CuSuiteNew ();
	int ret;

	putenv ("P11_KIT_STRICT=1");
	p11_debug_init ();

	SUITE_ADD_TEST (suite, test_known_oids);

	CuSuiteRun (suite);
	CuSuiteSummary (suite, output);
	CuSuiteDetails (suite, output);
	printf ("%s\n", output->buffer);
	ret = suite->failCount;
	CuSuiteDelete (suite);
	CuStringDelete (output);

	return ret;
}
