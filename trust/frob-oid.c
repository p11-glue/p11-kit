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
#include "compat.h"

#include <libtasn1.h>

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pkix.asn.h"

#define err_if_fail(ret, msg) \
	do { if ((ret) != ASN1_SUCCESS) { \
		fprintf (stderr, "%s: %s\n", msg, asn1_strerror (ret)); \
		exit (1); \
	} } while (0)
int
main (int argc,
      char *argv[])
{
	char message[ASN1_MAX_ERROR_DESCRIPTION_SIZE] = { 0, };
	node_asn *definitions = NULL;
	node_asn *oid = NULL;
	char *buf;
	int len;
	int ret;

	if (argc != 2) {
		fprintf (stderr, "usage: frob-oid 1.1.1\n");
		return 2;
	}

	ret = asn1_array2tree (pkix_asn1_tab, &definitions, message);
	if (ret != ASN1_SUCCESS) {
		fprintf (stderr, "definitions: %s\n", message);
		return 1;
	}

	/* AttributeType is a OBJECT IDENTIFIER */
	ret = asn1_create_element (definitions, "PKIX1.AttributeType", &oid);
	err_if_fail (ret, "AttributeType");

	ret = asn1_write_value (oid, "", argv[1], strlen (argv[1]));
	err_if_fail (ret, "asn1_write_value");

	len = 0;
	ret = asn1_der_coding (oid, "", NULL, &len, message);
	assert (ret == ASN1_MEM_ERROR);

	buf = malloc (len);
	assert (buf != NULL);
	ret = asn1_der_coding (oid, "", buf, &len, message);
	if (ret != ASN1_SUCCESS) {
		fprintf (stderr, "asn1_der_coding: %s\n", message);
		free (buf);
		return 1;
	}

	fwrite (buf, 1, len, stdout);
	fflush (stdout);
	free (buf);

	asn1_delete_structure (&oid);
	asn1_delete_structure (&definitions);

	return 0;
}
