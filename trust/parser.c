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

#include "adapter.h"
#include "array.h"
#include "asn1.h"
#include "attrs.h"
#include "checksum.h"
#define P11_DEBUG_FLAG P11_DEBUG_TRUST
#include "debug.h"
#include "dict.h"
#include "library.h"
#include "module.h"
#include "oid.h"
#include "parser.h"
#include "pem.h"
#include "pkcs11x.h"
#include "x509.h"

#include <libtasn1.h>

#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct _p11_parser {
	p11_dict *asn1_defs;

	/* Set during a parse */
	p11_parser_sink sink;
	void *sink_data;
	const char *probable_label;
	int flags;

	/* Parsing state */
	p11_array *parsing;
	node_asn *cert_asn;
	const unsigned char *cert_der;
	size_t cert_len;
};

typedef int (* parser_func)   (p11_parser *parser,
                               const unsigned char *data,
                               size_t length);

static void
begin_parsing (p11_parser *parser,
               node_asn *cert_asn,
               const unsigned char *cert_der,
               size_t cert_len)
{
	return_if_fail (parser->parsing == NULL);
	return_if_fail (parser->cert_asn == NULL);
	return_if_fail (parser->cert_der == NULL);

	parser->parsing = p11_array_new (NULL);

	/*
	 * We make note of these for later looking up certificate
	 * extensions. See p11_parsed_find_extension().
	 */
	parser->cert_asn = cert_asn;
	parser->cert_der = cert_der;
	parser->cert_len = cert_len;
}

static void
finish_parsing (p11_parser *parser,
                node_asn *cert_asn)
{
	CK_ATTRIBUTE *attrs;
	int i;

	return_if_fail (parser->parsing != NULL);

	/* This is a double check */
	return_if_fail (parser->cert_asn == cert_asn);

	/* Update the certificate state */
	p11_parsing_update_certificate (parser, parser->parsing);

	/* Call all the hooks for generating further objects */
	p11_adapter_build_objects (parser, parser->parsing);

	for (i = 0; i < parser->parsing->num; i++) {
		attrs = parser->parsing->elem[i];
		if (parser->sink)
			(parser->sink) (attrs, parser->sink_data);
		else
			p11_attrs_free (attrs);
	}

	p11_array_free (parser->parsing);

	parser->parsing = NULL;
	parser->cert_asn = NULL;
	parser->cert_der = NULL;
	parser->cert_len = 0;
}

#define ID_LENGTH P11_CHECKSUM_SHA1_LENGTH

static void
id_generate (p11_parser *parser,
             CK_BYTE *vid)
{
	CK_ULONG val = p11_module_next_id ();
	p11_checksum_sha1 (vid, &val, sizeof (val), NULL);
}

static CK_ATTRIBUTE *
build_object (p11_parser *parser,
              CK_OBJECT_CLASS vclass,
              CK_BYTE *vid,
              const char *explicit_label)
{
	CK_ATTRIBUTE *attrs = NULL;
	CK_BBOOL vtrue = CK_TRUE;
	CK_BBOOL vfalse = CK_FALSE;
	const char *vlabel;

	CK_ATTRIBUTE klass = { CKA_CLASS, &vclass, sizeof (vclass) };
	CK_ATTRIBUTE token = { CKA_TOKEN, &vtrue, sizeof (vtrue) };
	CK_ATTRIBUTE private = { CKA_PRIVATE, &vfalse, sizeof (vfalse) };
	CK_ATTRIBUTE modifiable = { CKA_MODIFIABLE, &vfalse, sizeof (vfalse) };
	CK_ATTRIBUTE id = { CKA_ID, vid, ID_LENGTH };
	CK_ATTRIBUTE label = { CKA_LABEL, };

	vlabel = explicit_label ? (char *)explicit_label : parser->probable_label;
	if (vlabel) {
		label.pValue = (void *)vlabel;
		label.ulValueLen = strlen (vlabel);
	} else {
		label.type = CKA_INVALID;
	}

	if (!vid)
		id.type = CKA_INVALID;

	return p11_attrs_build (attrs, &klass, &token, &private, &modifiable,
	                        &id, &label, NULL);
}

static void
calc_check_value (const unsigned char *data,
                  size_t length,
                  CK_BYTE *check_value)
{
	unsigned char checksum[P11_CHECKSUM_SHA1_LENGTH];
	p11_checksum_sha1 (checksum, data, length, NULL);
	memcpy (check_value, checksum, 3);
}

static bool
calc_date (node_asn *cert,
           const char *field,
           CK_DATE *date)
{
	node_asn *choice;
	struct tm when;
	char buf[64];
	time_t timet;
	char *sub;
	int len;
	int ret;

	choice = asn1_find_node (cert, field);
	return_val_if_fail (choice != NULL, false);

	len = sizeof (buf) - 1;
	ret = asn1_read_value (cert, field, buf, &len);
	return_val_if_fail (ret == ASN1_SUCCESS, false);

	sub = strconcat (field, ".", buf, NULL);

	if (strcmp (buf, "generalTime") == 0) {
		len = sizeof (buf) - 1;
		ret = asn1_read_value (cert, sub, buf, &len);
		return_val_if_fail (ret == ASN1_SUCCESS, false);
		timet = p11_asn1_parse_general (buf, &when);
		return_val_if_fail (timet >= 0, false);

	} else if (strcmp (buf, "utcTime") == 0) {
		len = sizeof (buf) - 1;
		ret = asn1_read_value (cert, sub, buf, &len);
		return_val_if_fail (ret == ASN1_SUCCESS, false);
		timet = p11_asn1_parse_utc (buf, &when);
		return_val_if_fail (timet >= 0, false);

	} else {
		return_val_if_reached (false);
	}

	free (sub);

	assert (sizeof (date->year) == 4);
	snprintf ((char *)buf, 5, "%04d", 1900 + when.tm_year);
	memcpy (date->year, buf, 4);

	assert (sizeof (date->month) == 2);
	snprintf ((char *)buf, 3, "%02d", when.tm_mon + 1);
	memcpy (date->month, buf, 2);

	assert (sizeof (date->day) == 2);
	snprintf ((char *)buf, 3, "%02d", when.tm_mday);
	memcpy (date->day, buf, 2);

	return true;
}

static bool
calc_element (node_asn *el,
              const unsigned char *data,
              size_t length,
              const char *field,
              CK_ATTRIBUTE *attr)
{
	int ret;
	int start, end;

	ret = asn1_der_decoding_startEnd (el, data, length, field, &start, &end);
	return_val_if_fail (ret == ASN1_SUCCESS, false);
	return_val_if_fail (end >= start, false);

	attr->pValue = (void *)(data + start);
	attr->ulValueLen = (end - start) + 1;
	return true;
}

static CK_ATTRIBUTE *
build_x509_certificate (p11_parser *parser,
                        CK_BYTE *vid,
                        node_asn *cert,
                        const unsigned char *data,
                        size_t length)
{
	CK_ATTRIBUTE *attrs;
	CK_CERTIFICATE_TYPE vx509 = CKC_X_509;
	CK_BYTE vchecksum[3];

	CK_DATE vstart;
	CK_DATE vend;

	/* Filled in later */
	CK_ULONG vcategory = 0;
	CK_BBOOL vtrusted = CK_FALSE;
	CK_BBOOL vdistrusted = CK_FALSE;

	CK_ATTRIBUTE certificate_type = { CKA_CERTIFICATE_TYPE, &vx509, sizeof (vx509) };
	CK_ATTRIBUTE certificate_category = { CKA_CERTIFICATE_CATEGORY, &vcategory, sizeof (vcategory) };
	CK_ATTRIBUTE value = { CKA_VALUE, (void *)data, length };

	CK_ATTRIBUTE check_value = { CKA_CHECK_VALUE, &vchecksum, sizeof (vchecksum) };
	CK_ATTRIBUTE trusted = { CKA_TRUSTED, &vtrusted, sizeof (vtrusted) };
	CK_ATTRIBUTE distrusted = { CKA_X_DISTRUSTED, &vdistrusted, sizeof (vdistrusted) };
	CK_ATTRIBUTE start_date = { CKA_START_DATE, &vstart, sizeof (vstart) };
	CK_ATTRIBUTE end_date = { CKA_END_DATE, &vend, sizeof (vend) };
	CK_ATTRIBUTE subject = { CKA_SUBJECT, };
	CK_ATTRIBUTE issuer = { CKA_ISSUER, };
	CK_ATTRIBUTE serial_number = { CKA_SERIAL_NUMBER, };

	/*
	 * The following are not present:
	 *  CKA_URL
	 * CKA_HASH_OF_SUBJECT_PUBLIC_KEY
	 * CKA_HASH_OF_ISSUER_PUBLIC_KEY
	 * CKA_JAVA_MIDP_SECURITY_DOMAIN
	 */

	calc_check_value (data, length, vchecksum);

	if (!calc_date (cert, "tbsCertificate.validity.notBefore", &vstart))
		start_date.type = CKA_INVALID;
	if (!calc_date (cert, "tbsCertificate.validity.notAfter", &vend))
		end_date.type = CKA_INVALID;

	if (!calc_element (cert, data, length, "tbsCertificate.issuer.rdnSequence", &issuer))
		issuer.type = CKA_INVALID;
	if (!calc_element (cert, data, length, "tbsCertificate.subject.rdnSequence", &subject))
		subject.type = CKA_INVALID;
	if (!calc_element (cert, data, length, "tbsCertificate.serialNumber", &serial_number))
		serial_number.type = CKA_INVALID;

	attrs = build_object (parser, CKO_CERTIFICATE, vid, NULL);
	return_val_if_fail (attrs != NULL, NULL);

	attrs = p11_attrs_build (attrs, &certificate_type, &certificate_category,
	                         &check_value, &trusted, &distrusted, &start_date, &end_date,
	                         &subject, &issuer, &serial_number, &value,
	                         NULL);
	return_val_if_fail (attrs != NULL, NULL);

	if (!p11_array_push (parser->parsing, attrs))
		return_val_if_reached (NULL);

	return attrs;
}

static CK_ATTRIBUTE *
match_parsing_object (p11_parser *parser,
                      CK_ATTRIBUTE *match)
{
	CK_ATTRIBUTE *attrs;
	int i;

	for (i = 0; i < parser->parsing->num; i++) {
		attrs = parser->parsing->elem[i];
		if (p11_attrs_match (attrs, match))
			return attrs;
	}

	return NULL;
}

unsigned char *
p11_parsing_get_extension (p11_parser *parser,
                           p11_array *parsing,
                           const unsigned char *oid,
                           size_t *length)
{
	CK_OBJECT_CLASS klass = CKO_X_CERTIFICATE_EXTENSION;
	CK_ATTRIBUTE *attrs;
	CK_ATTRIBUTE *attr;

	CK_ATTRIBUTE match[] = {
	                        { CKA_OBJECT_ID, (void *)oid, p11_oid_length (oid) },
	                        { CKA_CLASS, &klass, sizeof (klass) },
	                        { CKA_INVALID },
	};

	return_val_if_fail (parser != NULL, NULL);
	return_val_if_fail (parser->parsing == parsing, NULL);
	return_val_if_fail (length != NULL, NULL);
	return_val_if_fail (oid != NULL, NULL);

	attrs = match_parsing_object (parser, match);
	if (attrs != NULL) {
		attr = p11_attrs_find (attrs, CKA_VALUE);
		return_val_if_fail (attr != NULL, NULL);

		*length = attr->ulValueLen;
		return memdup (attr->pValue, attr->ulValueLen);

	/* Couldn't find a parsed extension, so look in the current certificate */
	} else if (parser->cert_asn) {
		return p11_x509_find_extension (parser->cert_asn, oid,
		                                parser->cert_der, parser->cert_len,
		                                length);
	}

	return NULL;
}

CK_ATTRIBUTE *
p11_parsing_get_certificate (p11_parser *parser,
                             p11_array *parsing)
{
	CK_OBJECT_CLASS klass = CKO_CERTIFICATE;

	CK_ATTRIBUTE match[] = {
	                        { CKA_CLASS, &klass, sizeof (klass) },
	                        { CKA_INVALID },
	};

	return_val_if_fail (parser != NULL, NULL);
	return_val_if_fail (parser->parsing == parsing, NULL);

	return match_parsing_object (parser, match);
}

static int
parse_der_x509_certificate (p11_parser *parser,
                            const unsigned char *data,
                            size_t length)
{
	CK_BYTE vid[ID_LENGTH];
	CK_ATTRIBUTE *attrs;
	node_asn *cert;

	cert = p11_asn1_decode (parser->asn1_defs, "PKIX1.Certificate", data, length, NULL);
	if (cert == NULL)
		return P11_PARSE_UNRECOGNIZED;

	begin_parsing (parser, cert, data, length);

	/* The CKA_ID links related objects */
	id_generate (parser, vid);

	attrs = build_x509_certificate (parser, vid, cert, data, length);
	return_val_if_fail (attrs != NULL, P11_PARSE_FAILURE);

	finish_parsing (parser, cert);
	asn1_delete_structure (&cert);
	return P11_PARSE_SUCCESS;
}

static int
build_der_extension (p11_parser *parser,
                     CK_ATTRIBUTE *cert,
                     const unsigned char *oid_der,
                     CK_BBOOL vcritical,
                     const unsigned char *ext_der,
                     int ext_len)
{
	CK_ATTRIBUTE critical = { CKA_X_CRITICAL, &vcritical, sizeof (vcritical) };
	CK_ATTRIBUTE oid = { CKA_OBJECT_ID, (void *)oid_der, p11_oid_length (oid_der) };
	CK_ATTRIBUTE value = { CKA_VALUE, (void *)ext_der, ext_len };
	CK_ATTRIBUTE invalid = { CKA_INVALID, };

	CK_ATTRIBUTE *attrs;
	CK_ATTRIBUTE *id;
	CK_ATTRIBUTE *label;

	attrs = build_object (parser, CKO_X_CERTIFICATE_EXTENSION, NULL, NULL);
	return_val_if_fail (attrs != NULL, P11_PARSE_FAILURE);

	id = p11_attrs_find (cert, CKA_ID);
	if (id == NULL)
		id = &invalid;
	label = p11_attrs_find (cert, CKA_LABEL);
	if (id == NULL)
		label = &invalid;

	attrs = p11_attrs_build (attrs, id, label, &oid, &critical, &value, NULL);
	return_val_if_fail (attrs != NULL, P11_PARSE_FAILURE);

	if (!p11_array_push (parser->parsing, attrs))
		return_val_if_reached (P11_PARSE_FAILURE);

	return P11_PARSE_SUCCESS;
}

static int
build_stapled_extension (p11_parser *parser,
                         CK_ATTRIBUTE *cert,
                         const unsigned char *oid,
                         CK_BBOOL critical,
                         node_asn *ext)
{
	unsigned char *der;
	size_t len;
	int ret;

	der = p11_asn1_encode (ext, &len);
	return_val_if_fail (der != NULL, P11_PARSE_FAILURE);

	ret = build_der_extension (parser, cert, oid, critical, (unsigned char *)der, len);
	free (der);

	return ret;
}

static p11_dict *
load_seq_of_oid_str (node_asn *node,
                     const char *seqof)
{
	p11_dict *oids;
	char field[128];
	char *oid;
	int len;
	int ret;
	int i;

	oids = p11_dict_new (p11_dict_str_hash, p11_dict_str_equal, free, NULL);

	for (i = 1; ; i++) {
		if (snprintf (field, sizeof (field), "%s.?%u", seqof, i) < 0)
			return_val_if_reached (NULL);

		len = 0;
		ret = asn1_read_value (node, field, NULL, &len);
		if (ret == ASN1_ELEMENT_NOT_FOUND)
			break;

		return_val_if_fail (ret == ASN1_MEM_ERROR, NULL);

		oid = malloc (len + 1);
		return_val_if_fail (oid != NULL, NULL);

		ret = asn1_read_value (node, field, oid, &len);
		return_val_if_fail (ret == ASN1_SUCCESS, NULL);

		if (!p11_dict_set (oids, oid, oid))
			return_val_if_reached (NULL);
	}

	return oids;
}

static int
build_eku_extension (p11_parser *parser,
                     CK_ATTRIBUTE *cert,
                     const unsigned char *oid,
                     CK_BBOOL critical,
                     p11_dict *oid_strs)
{
	p11_dictiter iter;
	node_asn *dest;
	int count = 0;
	void *value;
	int ret;

	dest = p11_asn1_create (parser->asn1_defs, "PKIX1.ExtKeyUsageSyntax");
	return_val_if_fail (dest != NULL, P11_PARSE_FAILURE);

	p11_dict_iterate (oid_strs, &iter);
	while (p11_dict_next (&iter, NULL, &value)) {
		ret = asn1_write_value (dest, "", "NEW", 1);
		return_val_if_fail (ret == ASN1_SUCCESS, P11_PARSE_FAILURE);

		ret = asn1_write_value (dest, "?LAST", value, -1);
		return_val_if_fail (ret == ASN1_SUCCESS, P11_PARSE_FAILURE);

		count++;
	}

	/*
	 * If no oids have been written, then we have to put in a reserved
	 * value, due to the way that ExtendedKeyUsage is defined in RFC 5280.
	 * There must be at least one purpose. This is important since *not*
	 * having an ExtendedKeyUsage is very different than having one without
	 * certain usages.
	 *
	 * We account for this in p11_parse_extended_key_usage(). However for
	 * most callers this should not matter, as they only check whether a
	 * given purpose is present, and don't make assumptions about ones
	 * that they don't know about.
	 */

	if (count == 0) {
		ret = asn1_write_value (dest, "", "NEW", 1);
		return_val_if_fail (ret == ASN1_SUCCESS, P11_PARSE_FAILURE);

		ret = asn1_write_value (dest, "?LAST", P11_OID_RESERVED_PURPOSE_STR, -1);
		return_val_if_fail (ret == ASN1_SUCCESS, P11_PARSE_FAILURE);
	}


	ret = build_stapled_extension (parser, cert, oid, critical, dest);
	asn1_delete_structure (&dest);

	return ret;
}

static int
build_bc_extension (p11_parser *parser,
                    CK_ATTRIBUTE *cert,
                    CK_BBOOL critical,
                    int is_ca)
{
	node_asn *ext;
	int ret;

	ext = p11_asn1_create (parser->asn1_defs, "PKIX1.BasicConstraints");
	return_val_if_fail (ext != NULL, P11_PARSE_FAILURE);

	/* FALSE is the default, so clear if not CA */
	ret = asn1_write_value (ext, "cA", is_ca ? "TRUE" : NULL, is_ca ? -1 : 0);
	return_val_if_fail (ret == ASN1_SUCCESS, P11_PARSE_FAILURE);

	/* Clear this optional value */
	ret = asn1_write_value (ext, "pathLenConstraint", NULL, 0);
	return_val_if_fail (ret == ASN1_SUCCESS, P11_PARSE_FAILURE);

	ret = build_stapled_extension (parser, cert, P11_OID_BASIC_CONSTRAINTS, critical, ext);
	asn1_delete_structure (&ext);

	return ret;
}

static bool
is_v1_x509_authority (CK_ATTRIBUTE *cert,
                      node_asn *node)
{
	CK_ATTRIBUTE *subject;
	CK_ATTRIBUTE *issuer;
	char buffer[16];
	int len;
	int ret;

	len = sizeof (buffer);
	ret = asn1_read_value (node, "tbsCertificate.version", buffer, &len);

	/* The default value */
	if (ret == ASN1_ELEMENT_NOT_FOUND) {
		ret = ASN1_SUCCESS;
		buffer[0] = 0;
		len = 1;
	}

	return_val_if_fail (ret == ASN1_SUCCESS, false);

	/*
	 * In X.509 version v1 is the integer zero. Two's complement
	 * integer, but zero is easy to read.
	 */
	if (len != 1 || buffer[0] != 0)
		return false;

	/* Must be self-signed, ie: same subject and issuer */
	subject = p11_attrs_find (cert, CKA_SUBJECT);
	issuer = p11_attrs_find (cert, CKA_ISSUER);
	return (subject != NULL && issuer != NULL &&
	        p11_attr_match_value (subject, issuer->pValue, issuer->ulValueLen));
}

static void
update_category (p11_parser *parser,
                 CK_ATTRIBUTE *cert)
{
	CK_ATTRIBUTE *category;
	bool is_ca = 0;
	unsigned char *data;
	size_t length;
	int ret;

	/* See if we have a basic constraints extension */
	data = p11_parsing_get_extension (parser, parser->parsing, P11_OID_BASIC_CONSTRAINTS, &length);
	if (data) {
		if (!p11_x509_parse_basic_constraints (parser->asn1_defs, data, length, &is_ca))
			p11_message ("invalid basic constraints certificate extension");
		free (data);

	} else if (is_v1_x509_authority (cert, parser->cert_asn)) {
		/*
		 * If there is no basic constraints extension, and the CA version is
		 * v1, and is self-signed, then we assume this is a certificate authority.
		 * So we add a BasicConstraints stapled certificate extension
		 */
		is_ca = 1;
		ret = build_bc_extension (parser, cert, CK_FALSE, is_ca);
		return_if_fail (ret == P11_PARSE_SUCCESS);
	}

	category = p11_attrs_find (cert, CKA_CERTIFICATE_CATEGORY);
	assert (category != NULL);
	assert (category->pValue != NULL);
	assert (category->ulValueLen == sizeof (CK_ULONG));

	/*
	 * In the PKCS#11 spec:
	 *   0 = unspecified (default value)
	 *   1 = token user
	 *   2 = authority
	 *   3 = other entity
	 */
	*((CK_ULONG *)category->pValue) = is_ca ? 2 : 3;
}

static void
update_trust_and_distrust (p11_parser *parser,
                           CK_ATTRIBUTE *cert)
{
	CK_ATTRIBUTE *attr;
	CK_BBOOL trusted;
	CK_BBOOL distrusted;
	unsigned char *data;
	size_t length;
	p11_array *ekus;

	/*
	 * This function is called to update the CKA_TRUSTED and CKA_X_DISTRUSTED
	 * fields (anchor and blacklist). Some other code may have updated the
	 * related extensions, so this may be called more than once.
	 *
	 * Since some input like OpenSSL model blacklists as anchors with all
	 * purposes being removed/rejected, we account for that here. If there
	 * is an ExtendedKeyUsage without any useful purposes, then treat
	 * like a blacklist.
	 *
	 * The certificate is an anchor if the parser is in anchor mode.
	 */

	trusted = (parser->flags & P11_PARSE_FLAG_ANCHOR) ? CK_TRUE : CK_FALSE;
	distrusted = (parser->flags & P11_PARSE_FLAG_BLACKLIST) ? CK_TRUE : CK_FALSE;

	data = p11_parsing_get_extension (parser, parser->parsing, P11_OID_EXTENDED_KEY_USAGE, &length);
	if (data) {
		ekus = p11_x509_parse_extended_key_usage (parser->asn1_defs, data, length);
		if (ekus == NULL)
			p11_message ("invalid extendend key usage certificate extension");
		else if (ekus->num == 0) {
			distrusted = CK_TRUE;
			trusted = CK_FALSE;
		}

		p11_array_free (ekus);
		free (data);
	}

	attr = p11_attrs_find (cert, CKA_TRUSTED);
	assert (attr != NULL);
	assert (attr->pValue != NULL);
	assert (attr->ulValueLen == sizeof (CK_BBOOL));
	*((CK_BBOOL *)attr->pValue) = trusted;

	attr = p11_attrs_find (cert, CKA_X_DISTRUSTED);
	assert (attr != NULL);
	assert (attr->pValue != NULL);
	assert (attr->ulValueLen == sizeof (CK_BBOOL));
	*((CK_BBOOL *)attr->pValue) = distrusted;
}

void
p11_parsing_update_certificate (p11_parser *parser,
                                p11_array *parsing)
{
	CK_ATTRIBUTE *cert;

	/* Find the certificate to update */
	cert = p11_parsing_get_certificate (parser, parsing);
	if (cert == NULL)
		return;

	/* This should match the above cert */
	assert (parser->cert_asn != NULL);

	update_category (parser, cert);
	update_trust_and_distrust (parser, cert);
}


static int
build_openssl_extensions (p11_parser *parser,
                          CK_ATTRIBUTE *cert,
                          node_asn *aux,
                          const unsigned char *aux_der,
                          size_t aux_len)
{
	p11_dict *trust = NULL;
	p11_dict *reject = NULL;
	p11_dictiter iter;
	void *key;
	int start;
	int end;
	int ret;
	int num;

	/*
	 * This will load an empty list if there is no OPTIONAL trust field.
	 * OpenSSL assumes that for a TRUSTED CERTIFICATE a missing trust field
	 * is identical to untrusted for all purposes.
	 *
	 * This is different from ExtendedKeyUsage, where a missing certificate
	 * extension means that it is trusted for all purposes.
	 */
	trust = load_seq_of_oid_str (aux, "trust");

	ret = asn1_number_of_elements (aux, "reject", &num);
	return_val_if_fail (ret == ASN1_SUCCESS || ret == ASN1_ELEMENT_NOT_FOUND, P11_PARSE_FAILURE);
	if (ret == ASN1_SUCCESS)
		reject = load_seq_of_oid_str (aux, "reject");

	/* Remove all rejected oids from the trust set */
	if (trust && reject) {
		p11_dict_iterate (reject, &iter);
		while (p11_dict_next (&iter, &key, NULL))
			p11_dict_remove (trust, key);
	}

	/*
	 * The trust field (or lack of it) becomes a standard ExtKeyUsageSyntax.
	 *
	 * critical: require that this is enforced
	 */

	if (trust) {
		ret = build_eku_extension (parser, cert, P11_OID_EXTENDED_KEY_USAGE, CK_TRUE, trust);
		return_val_if_fail (ret == P11_PARSE_SUCCESS, ret);
	}

	/*
	 * For the reject field we use a custom defined extension. We track this
	 * for completeness, although the above ExtendedKeyUsage extension handles
	 * this data fine. See oid.h for more details. It uses ExtKeyUsageSyntax structure.
	 *
	 * non-critical: non-standard, and also covered by trusts
	 */

	if (reject && p11_dict_size (reject) > 0) {
		ret = build_eku_extension (parser, cert, P11_OID_OPENSSL_REJECT, CK_FALSE, reject);
		return_val_if_fail (ret == P11_PARSE_SUCCESS, ret);
	}

	p11_dict_free (trust);
	p11_dict_free (reject);

	/*
	 * For the keyid field we use the SubjectKeyIdentifier extension. It
	 * is already in the correct form, an OCTET STRING.
	 *
	 * non-critical: as recommended in RFC 5280
	 */

	ret = asn1_der_decoding_startEnd (aux, aux_der, aux_len, "keyid", &start, &end);
	return_val_if_fail (ret == ASN1_SUCCESS || ret == ASN1_ELEMENT_NOT_FOUND, P11_PARSE_FAILURE);

	if (ret == ASN1_SUCCESS) {
		ret = build_der_extension (parser, cert, P11_OID_SUBJECT_KEY_IDENTIFIER, CK_FALSE,
		                           aux_der + start, (end - start) + 1);
		return_val_if_fail (ret == P11_PARSE_SUCCESS, ret);
	}


	return P11_PARSE_SUCCESS;
}

static int
parse_openssl_trusted_certificate (p11_parser *parser,
                                   const unsigned char *data,
                                   size_t length)
{
	CK_ATTRIBUTE *attrs;
	CK_BYTE vid[ID_LENGTH];
	const char *old_label = NULL;
	char *label = NULL;
	node_asn *cert;
	node_asn *aux;
	ssize_t cert_len;
	int len;
	int ret;

	/*
	 * This OpenSSL format is a wierd. It's just two DER structures
	 * placed end to end without any wrapping SEQ. So calculate the
	 * length of the first DER TLV we see and try to parse that as
	 * the X.509 certificate.
	 */

	cert_len = p11_asn1_tlv_length (data, length);
	if (cert_len <= 0)
		return P11_PARSE_UNRECOGNIZED;

	cert = p11_asn1_decode (parser->asn1_defs, "PKIX1.Certificate", data, cert_len, NULL);
	if (cert == NULL)
		return P11_PARSE_UNRECOGNIZED;

	aux = p11_asn1_decode (parser->asn1_defs, "OPENSSL.CertAux", data + cert_len, length - cert_len, NULL);
	if (aux == NULL) {
		asn1_delete_structure (&cert);
		return P11_PARSE_UNRECOGNIZED;
	}

	begin_parsing (parser, cert, data, cert_len);

	/* Pull the label out of the CertAux */
	len = 0;
	ret = asn1_read_value (aux, "alias", NULL, &len);
	if (ret != ASN1_ELEMENT_NOT_FOUND) {
		return_val_if_fail (ret == ASN1_MEM_ERROR, P11_PARSE_FAILURE);
		label = calloc (len + 1, 1);
		return_val_if_fail (label != NULL, P11_PARSE_FAILURE);
		ret = asn1_read_value (aux, "alias", label, &len);
		return_val_if_fail (ret == ASN1_SUCCESS, P11_PARSE_FAILURE);

		old_label = parser->probable_label;
		parser->probable_label = label;
	}

	/* The CKA_ID links related objects */
	id_generate (parser, vid);

	attrs = build_x509_certificate (parser, vid, cert, data, cert_len);
	return_val_if_fail (attrs != NULL, P11_PARSE_FAILURE);

	ret = build_openssl_extensions (parser, attrs, aux, data + cert_len, length - cert_len);
	return_val_if_fail (ret == P11_PARSE_SUCCESS, ret);

	finish_parsing (parser, cert);

	asn1_delete_structure (&cert);
	asn1_delete_structure (&aux);

	if (label) {
		parser->probable_label = old_label;
		free (label);
	}

	return P11_PARSE_SUCCESS;
}

static void
on_pem_block (const char *type,
              const unsigned char *contents,
              size_t length,
              void *user_data)
{
	p11_parser *parser = user_data;
	int ret;

	if (strcmp (type, "CERTIFICATE") == 0) {
		ret = parse_der_x509_certificate (parser, contents, length);

	} else if (strcmp (type, "TRUSTED CERTIFICATE") == 0) {
		ret = parse_openssl_trusted_certificate (parser, contents, length);

	} else {
		p11_debug ("Saw unsupported or unrecognized PEM block of type %s", type);
		ret = P11_PARSE_SUCCESS;
	}

	if (ret != P11_PARSE_SUCCESS)
		p11_message ("Couldn't parse PEM block of type %s", type);
}

static int
parse_pem_certificates (p11_parser *parser,
                        const unsigned char *data,
                        size_t length)
{
	int num;

	num = p11_pem_parse ((const char *)data, length, on_pem_block, parser);

	if (num == 0)
		return P11_PARSE_UNRECOGNIZED;

	return P11_PARSE_SUCCESS;
}

static parser_func all_parsers[] = {
	parse_pem_certificates,
	parse_der_x509_certificate,
	NULL,
};

p11_parser *
p11_parser_new (void)
{
	p11_parser parser = { 0, };

	parser.asn1_defs = p11_asn1_defs_load ();
	return_val_if_fail (parser.asn1_defs != NULL, NULL);

	return memdup (&parser, sizeof (parser));
}

void
p11_parser_free (p11_parser *parser)
{
	if (!parser)
		return;

	p11_dict_free (parser->asn1_defs);
	free (parser);
}

int
p11_parse_memory (p11_parser *parser,
                  const char *filename,
                  int flags,
                  const unsigned char *data,
                  size_t length,
                  p11_parser_sink sink,
                  void *sink_data)
{
	int ret = P11_PARSE_UNRECOGNIZED;
	char *base;
	int i;

	return_val_if_fail (parser != NULL, P11_PARSE_FAILURE);
	return_val_if_fail (parser->sink == NULL, P11_PARSE_FAILURE);

	base = basename (filename);
	parser->probable_label = base;
	parser->sink = sink;
	parser->sink_data = sink_data;
	parser->flags = flags;

	/* Expected that state is cleaned via finish_parsing () */
	parser->parsing = NULL;
	parser->cert_asn = NULL;
	parser->cert_der = NULL;
	parser->cert_len = 0;

	for (i = 0; all_parsers[i] != NULL; i++) {
		ret = (all_parsers[i]) (parser, data, length);
		if (ret != P11_PARSE_UNRECOGNIZED)
			break;
	}

	parser->probable_label = NULL;
	parser->sink = NULL;
	parser->sink_data = NULL;
	parser->flags = 0;

	return ret;
}

int
p11_parse_file (p11_parser *parser,
                const char *filename,
                int flags,
                p11_parser_sink sink,
                void *sink_data)
{
	void *data;
	struct stat sb;
	int fd;
	int ret;

	fd = open (filename, O_RDONLY);
	if (fd == -1) {
		p11_message ("couldn't open file: %s: %s", filename, strerror (errno));
		return P11_PARSE_FAILURE;
	}

	if (fstat (fd, &sb) < 0) {
		p11_message ("couldn't stat file: %s: %s", filename, strerror (errno));
		return P11_PARSE_FAILURE;
	}

	data = mmap (NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (data == NULL) {
		p11_message ("couldn't map file: %s: %s", filename, strerror (errno));
		return P11_PARSE_FAILURE;
	}

	ret = p11_parse_memory (parser, filename, flags, data, sb.st_size, sink, sink_data);

	munmap (data, sb.st_size);
	close (fd);

	return ret;
}

p11_dict *
p11_parser_get_asn1_defs (p11_parser *parser)
{
	return_val_if_fail (parser != NULL, NULL);
	return parser->asn1_defs;
}
