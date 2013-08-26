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

#include <sys/stat.h>
#include <sys/types.h>

#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "pkix.asn.h"

#define err_if_fail(ret, msg) \
	do { if ((ret) != ASN1_SUCCESS) { \
		fprintf (stderr, "%s: %s\n", msg, asn1_strerror (ret)); \
		exit (1); \
	} } while (0)

static ssize_t
tlv_length (const unsigned char *data,
            size_t length)
{
	unsigned char cls;
	int counter = 0;
	int cb, len;
	unsigned long tag;

	if (asn1_get_tag_der (data, length, &cls, &cb, &tag) == ASN1_SUCCESS) {
		counter += cb;
		len = asn1_get_length_der (data + cb, length - cb, &cb);
		counter += cb;
		if (len >= 0) {
			len += counter;
			if (length >= len)
				return len;
		}
	}

	return -1;
}

int
main (int argc,
      char *argv[])
{
	char message[ASN1_MAX_ERROR_DESCRIPTION_SIZE] = { 0, };
	node_asn *definitions = NULL;
	node_asn *cert = NULL;
	p11_mmap *map;
	void *data;
	size_t size;
	int start, end;
	ssize_t len;
	int ret;

	if (argc != 4) {
		fprintf (stderr, "usage: frob-cert struct field filename\n");
		return 2;
	}

	ret = asn1_array2tree (pkix_asn1_tab, &definitions, message);
	if (ret != ASN1_SUCCESS) {
		fprintf (stderr, "definitions: %s\n", message);
		return 1;
	}

	ret = asn1_create_element (definitions, argv[1], &cert);
	err_if_fail (ret, "Certificate");

	map = p11_mmap_open (argv[3], NULL, &data, &size);
	if (map == NULL) {
		fprintf (stderr, "couldn't open file: %s\n", argv[3]);
		return 1;
	}

	ret = asn1_der_decoding (&cert, data, size, message);
	err_if_fail (ret, message);

	ret = asn1_der_decoding_startEnd (cert, data, size, argv[2], &start, &end);
	err_if_fail (ret, "asn1_der_decoding_startEnd");

	len = tlv_length ((unsigned char *)data + start, size - start);
	assert (len >= 0);

	fprintf (stderr, "%lu %d %d %ld\n", (unsigned long)size, start, end, (long)len);
	fwrite ((unsigned char *)data + start, 1, len, stdout);
	fflush (stdout);

	p11_mmap_close (map);

	asn1_delete_structure (&cert);
	asn1_delete_structure (&definitions);

	return 0;
}
