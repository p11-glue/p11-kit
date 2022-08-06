/*
 * Copyright (c) 2013 Red Hat Inc.
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
	asn1_node definitions = NULL;
	asn1_node ext = NULL;
	unsigned char input[1024];
	char *buf;
	size_t size;
	int len;
	int ret;

	if (argc == 1 || argc > 3) {
		fprintf (stderr, "usage: frob-ext 1.2.3 TRUE\n");
		return 2;
	}

	size = fread (input, 1, sizeof (input), stdin);
	if (ferror (stdin) || !feof (stdin)) {
		fprintf (stderr, "bad input\n");
		return 1;
	}

	ret = asn1_array2tree (pkix_asn1_tab, &definitions, message);
	if (ret != ASN1_SUCCESS) {
		fprintf (stderr, "definitions: %s\n", message);
		return 1;
	}


	ret = asn1_create_element (definitions, "PKIX1.Extension", &ext);
	err_if_fail (ret, "Extension");

	ret = asn1_write_value (ext, "extnID", argv[1], 1);
	err_if_fail (ret, "extnID");

	if (argc == 3) {
		ret = asn1_write_value (ext, "critical", argv[2], 1);
		err_if_fail (ret, "critical");
	}

	ret = asn1_write_value (ext, "extnValue", input, size);
	err_if_fail (ret, "extnValue");

	len = 0;
	ret = asn1_der_coding (ext, "", NULL, &len, message);
	assert (ret == ASN1_MEM_ERROR);

	buf = malloc (len);
	assert (buf != NULL);
	ret = asn1_der_coding (ext, "", buf, &len, message);
	if (ret != ASN1_SUCCESS) {
		fprintf (stderr, "asn1_der_coding: %s\n", message);
		free (buf);
		return 1;
	}

	fwrite (buf, 1, len, stdout);
	fflush (stdout);

	free (buf);
	asn1_delete_structure (&ext);
	asn1_delete_structure (&definitions);

	return 0;
}
