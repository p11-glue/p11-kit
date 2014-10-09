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
#include "digest.h"
#include "oid.h"
#include "utf8.h"
#include "x509.h"

#include <stdlib.h>
#include <string.h>

unsigned char *
p11_x509_find_extension (node_asn *cert,
                         const unsigned char *oid,
                         const unsigned char *der,
                         size_t der_len,
                         size_t *ext_len)
{
	char field[128];
	int start;
	int end;
	int ret;
	int i;

	return_val_if_fail (cert != NULL, NULL);
	return_val_if_fail (oid != NULL, NULL);
	return_val_if_fail (ext_len != NULL, NULL);

	for (i = 1; ; i++) {
		if (snprintf (field, sizeof (field), "tbsCertificate.extensions.?%u.extnID", i) < 0)
			return_val_if_reached (NULL);

		ret = asn1_der_decoding_startEnd (cert, der, der_len, field, &start, &end);

		/* No more extensions */
		if (ret == ASN1_ELEMENT_NOT_FOUND)
			break;

		return_val_if_fail (ret == ASN1_SUCCESS, NULL);

		/* Make sure it's a straightforward oid with certain assumptions */
		if (!p11_oid_simple (der + start, (end - start) + 1))
			continue;

		/* The one we're lookin for? */
		if (!p11_oid_equal (der + start, oid))
			continue;

		if (snprintf (field, sizeof (field), "tbsCertificate.extensions.?%u.extnValue", i) < 0)
			return_val_if_reached (NULL);

		return p11_asn1_read (cert, field, ext_len);
	}

	return NULL;
}

bool
p11_x509_hash_subject_public_key (node_asn *cert,
                                  const unsigned char *der,
                                  size_t der_len,
                                  unsigned char *keyid)
{
	int start, end;
	size_t len;
	int ret;

	return_val_if_fail (cert != NULL, NULL);
	return_val_if_fail (der != NULL, NULL);

	ret = asn1_der_decoding_startEnd (cert, der, der_len, "tbsCertificate.subjectPublicKeyInfo", &start, &end);
	return_val_if_fail (ret == ASN1_SUCCESS, false);
	return_val_if_fail (end >= start, false);

	len = (end - start) + 1;
	p11_digest_sha1 (keyid, (der + start), len, NULL);
	return true;
}

unsigned char *
p11_x509_parse_subject_key_identifier  (p11_dict *asn1_defs,
                                        const unsigned char *ext_der,
                                        size_t ext_len,
                                        size_t *keyid_len)
{
	unsigned char *keyid;
	node_asn *ext;

	return_val_if_fail (keyid_len != NULL, false);

	ext = p11_asn1_decode (asn1_defs, "PKIX1.SubjectKeyIdentifier", ext_der, ext_len, NULL);
	if (ext == NULL)
		return NULL;

	keyid = p11_asn1_read (ext, "", keyid_len);
	return_val_if_fail (keyid != NULL, NULL);

	asn1_delete_structure (&ext);

	return keyid;
}

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

	/* Default value for cA is FALSE */
	if (ret == ASN1_ELEMENT_NOT_FOUND) {
		*is_ca = false;

	} else {
		return_val_if_fail (ret == ASN1_SUCCESS, false);
		*is_ca = (strcmp (buffer, "TRUE") == 0);
	}

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

p11_array *
p11_x509_parse_extended_key_usage (p11_dict *asn1_defs,
                                   const unsigned char *ext_der,
                                   size_t ext_len)
{
	node_asn *asn;
	char field[128];
	p11_array *ekus;
	size_t len;
	char *eku;
	int i;

	asn = p11_asn1_decode (asn1_defs, "PKIX1.ExtKeyUsageSyntax", ext_der, ext_len, NULL);
	if (asn == NULL)
		return NULL;

	ekus = p11_array_new (free);

	for (i = 1; ; i++) {
		if (snprintf (field, sizeof (field), "?%u", i) < 0)
			return_val_if_reached (NULL);

		eku = p11_asn1_read (asn, field, &len);
		if (eku == NULL)
			break;

		eku[len] = 0;

		/* If it's our reserved OID, then skip */
		if (strcmp (eku, P11_OID_RESERVED_PURPOSE_STR) == 0) {
			free (eku);
			continue;
		}

		if (!p11_array_push (ekus, eku))
			return_val_if_reached (NULL);
	}

	asn1_delete_structure (&asn);

	return ekus;
}

char *
p11_x509_parse_directory_string (const unsigned char *input,
                                 size_t input_len,
                                 bool *unknown_string,
                                 size_t *string_len)
{
	unsigned long tag;
	unsigned char cls;
	int tag_len;
	int len_len;
	const void *octets;
	long octet_len;
	int ret;

	ret = asn1_get_tag_der (input, input_len, &cls, &tag_len, &tag);
	return_val_if_fail (ret == ASN1_SUCCESS, NULL);

	octet_len = asn1_get_length_der (input + tag_len, input_len - tag_len, &len_len);
	return_val_if_fail (octet_len >= 0, false);
	return_val_if_fail (tag_len + len_len + octet_len == input_len, NULL);

	octets = input + tag_len + len_len;

	if (unknown_string)
		*unknown_string = false;

	/* The following strings are the ones we normalize */
	switch (tag) {
	case 12: /* UTF8String */
	case 18: /* NumericString */
	case 22: /* IA5String */
	case 20: /* TeletexString */
	case 19: /* PrintableString */
		if (!p11_utf8_validate (octets, octet_len))
			return NULL;
		if (string_len)
			*string_len = octet_len;
		return strndup (octets, octet_len);

	case 28: /* UniversalString */
		return p11_utf8_for_ucs4be (octets, octet_len, string_len);

	case 30: /* BMPString */
		return p11_utf8_for_ucs2be (octets, octet_len, string_len);

	/* Just pass through all the non-string types */
	default:
		if (unknown_string)
			*unknown_string = true;
		return NULL;
	}

}

char *
p11_x509_parse_dn_name (p11_dict *asn_defs,
                        const unsigned char *der,
                        size_t der_len,
                        const unsigned char *oid)
{
	node_asn *asn;
	char *part;

	asn = p11_asn1_decode (asn_defs, "PKIX1.Name", der, der_len, NULL);
	if (asn == NULL)
		return NULL;

	part = p11_x509_lookup_dn_name (asn, NULL, der, der_len, oid);
	asn1_delete_structure (&asn);
	return part;
}

char *
p11_x509_lookup_dn_name (node_asn *asn,
                         const char *dn_field,
                         const unsigned char *der,
                         size_t der_len,
                         const unsigned char *oid)
{
	unsigned char *value;
	char field[128];
	size_t value_len;
	char *part;
	int i, j;
	int start;
	int end;
	int ret;

	for (i = 1; true; i++) {
		for (j = 1; true; j++) {
			snprintf (field, sizeof (field), "%s%srdnSequence.?%d.?%d.type",
			          dn_field, dn_field ? "." : "", i, j);

			ret = asn1_der_decoding_startEnd (asn, der, der_len, field, &start, &end);

			/* No more dns */
			if (ret == ASN1_ELEMENT_NOT_FOUND)
				break;

			return_val_if_fail (ret == ASN1_SUCCESS, NULL);

			/* Make sure it's a straightforward oid with certain assumptions */
			if (!p11_oid_simple (der + start, (end - start) + 1))
				continue;

			/* The one we're lookin for? */
			if (!p11_oid_equal (der + start, oid))
				continue;

			snprintf (field, sizeof (field), "%s%srdnSequence.?%d.?%d.value",
			          dn_field, dn_field ? "." : "", i, j);

			value = p11_asn1_read (asn, field, &value_len);
			return_val_if_fail (value != NULL, NULL);

			part = p11_x509_parse_directory_string (value, value_len, NULL, NULL);
			free (value);

			return part;
		}

		if (j == 1)
			break;
	}

	return NULL;
}
