/*
 * Copyright (C) 2012 Red Hat Inc.
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
 * Author: Stef Walter <stefw@redhat.com>
 */

#include "config.h"

#include "asn1.h"
#define P11_DEBUG_FLAG P11_DEBUG_TRUST
#include "debug.h"
#include "oid.h"
#include "x509.h"

#include <stdlib.h>
#include <string.h>

bool
p11_x509_parse_basic_constraints (p11_dict *asn1_defs,
                                  const unsigned char *ext_der,
                                  size_t ext_len,
                                  bool *is_ca)
{
	char buffer[8];
	node_asn *ext;
	int ret;
	int len;

	return_val_if_fail (is_ca != NULL, false);

	ext = p11_asn1_decode (asn1_defs, "PKIX1.BasicConstraints", ext_der, ext_len, NULL);
	if (ext == NULL)
		return false;

	len = sizeof (buffer);
	ret = asn1_read_value (ext, "cA", buffer, &len);
	return_val_if_fail (ret == ASN1_SUCCESS, false);

	*is_ca = (strcmp (buffer, "TRUE") == 0);
	asn1_delete_structure (&ext);

	return true;
}

bool
p11_x509_parse_key_usage (p11_dict *asn1_defs,
                          const unsigned char *ext_der,
                          size_t ext_len,
                          unsigned int *ku)
{
	char message[ASN1_MAX_ERROR_DESCRIPTION_SIZE] = { 0, };
	unsigned char buf[2];
	node_asn *ext;
	int len;
	int ret;

	ext = p11_asn1_decode (asn1_defs, "PKIX1.KeyUsage", ext_der, ext_len, message);
	if (ext == NULL)
		return false;

	len = sizeof (buf);
	ret = asn1_read_value (ext, "", buf, &len);
	return_val_if_fail (ret == ASN1_SUCCESS, false);

	/* A bit string, so combine into one set of flags */
	*ku = buf[0] | (buf[1] << 8);

	asn1_delete_structure (&ext);

	return true;
}

p11_dict *
p11_x509_parse_extended_key_usage (p11_dict *asn1_defs,
                                   const unsigned char *ext_der,
                                   size_t ext_len)
{
	node_asn *asn;
	char field[128];
	p11_dict *ekus;
	char *eku;
	int ret;
	int len;
	int i;

	asn = p11_asn1_decode (asn1_defs, "PKIX1.ExtKeyUsageSyntax", ext_der, ext_len, NULL);
	if (asn == NULL)
		return NULL;

	ekus = p11_dict_new (p11_dict_str_hash, p11_dict_str_equal, free, NULL);

	for (i = 1; ; i++) {
		if (snprintf (field, sizeof (field), "?%u", i) < 0)
			return_val_if_reached (NULL);

		len = 0;
		ret = asn1_read_value (asn, field, NULL, &len);
		if (ret == ASN1_ELEMENT_NOT_FOUND)
			break;

		return_val_if_fail (ret == ASN1_MEM_ERROR, NULL);

		eku = malloc (len + 1);
		return_val_if_fail (eku != NULL, NULL);

		ret = asn1_read_value (asn, field, eku, &len);
		return_val_if_fail (ret == ASN1_SUCCESS, NULL);

		eku[len] = 0;

		/* If it's our reserved OID, then skip */
		if (strcmp (eku, P11_OID_RESERVED_PURPOSE_STR) == 0) {
			free (eku);
			continue;
		}

		if (!p11_dict_set (ekus, eku, eku))
			return_val_if_reached (NULL);
	}

	asn1_delete_structure (&asn);

	return ekus;
}
