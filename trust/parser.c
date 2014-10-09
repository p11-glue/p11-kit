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

#include "array.h"
#include "asn1.h"
#include "attrs.h"
#define P11_DEBUG_FLAG P11_DEBUG_TRUST
#include "debug.h"
#include "dict.h"
#include "digest.h"
#include "message.h"
#include "module.h"
#include "oid.h"
#include "parser.h"
#include "path.h"
#include "pem.h"
#include "pkcs11x.h"
#include "persist.h"
#include "x509.h"

#include <libtasn1.h>

#include <sys/types.h>
#include <sys/stat.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct _p11_parser {
	p11_asn1_cache *asn1_cache;
	p11_dict *asn1_defs;
	bool asn1_owned;
	p11_persist *persist;
	char *basename;
	p11_array *parsed;
	p11_array *formats;
	int flags;
};

#define ID_LENGTH P11_DIGEST_SHA1_LEN

typedef int (* parser_func)   (p11_parser *parser,
                               const unsigned char *data,
                               size_t length);

static CK_ATTRIBUTE *
populate_trust (p11_parser *parser,
                CK_ATTRIBUTE *attrs)
{
	CK_BBOOL trustedv;
	CK_BBOOL distrustv;

	CK_ATTRIBUTE trusted = { CKA_TRUSTED, &trustedv, sizeof (trustedv) };
	CK_ATTRIBUTE distrust = { CKA_X_DISTRUSTED, &distrustv, sizeof (distrustv) };

	/*
	 * If we're are parsing an anchor location, then warn about any ditsrusted
	 * certificates there, but don't go ahead and automatically make them
	 * trusted anchors.
	 */
	if (parser->flags & P11_PARSE_FLAG_ANCHOR) {
		if (p11_attrs_find_bool (attrs, CKA_X_DISTRUSTED, &distrustv) && distrustv) {
			p11_message ("certificate with distrust in location for anchors: %s", parser->basename);
			return attrs;

		}

		trustedv = CK_TRUE;
		distrustv = CK_FALSE;

	/*
	 * If we're parsing a blacklist location, then force all certificates to
	 * be blacklisted, regardless of whether they contain anchor information.
	 */
	} else if (parser->flags & P11_PARSE_FLAG_BLACKLIST) {
		if (p11_attrs_find_bool (attrs, CKA_TRUSTED, &trustedv) && trustedv)
			p11_message ("overriding trust for anchor in blacklist: %s", parser->basename);

		trustedv = CK_FALSE;
		distrustv = CK_TRUE;

	/*
	 * If the location doesn't have a flag, then fill in trust attributes
	 * if they are missing: neither an anchor or blacklist.
	 */
	} else {
		trustedv = CK_FALSE;
		distrustv = CK_FALSE;

		if (p11_attrs_find_valid (attrs, CKA_TRUSTED))
			trusted.type = CKA_INVALID;
		if (p11_attrs_find_valid (attrs, CKA_X_DISTRUSTED))
			distrust.type = CKA_INVALID;
	}

	return p11_attrs_build (attrs, &trusted, &distrust, NULL);
}

static void
sink_object (p11_parser *parser,
             CK_ATTRIBUTE *attrs)
{
	CK_OBJECT_CLASS klass;

	if (p11_attrs_find_ulong (attrs, CKA_CLASS, &klass) &&
	    klass == CKO_CERTIFICATE) {
		attrs = populate_trust (parser, attrs);
		return_if_fail (attrs != NULL);
	}

	if (!p11_array_push (parser->parsed, attrs))
		return_if_reached ();
}

static CK_ATTRIBUTE *
certificate_attrs (p11_parser *parser,
                   const unsigned char *der,
                   size_t der_len)
{
	CK_OBJECT_CLASS klassv = CKO_CERTIFICATE;
	CK_CERTIFICATE_TYPE x509 = CKC_X_509;
	CK_BBOOL modifiablev = CK_FALSE;

	CK_ATTRIBUTE modifiable = { CKA_MODIFIABLE, &modifiablev, sizeof (modifiablev) };
	CK_ATTRIBUTE klass = { CKA_CLASS, &klassv, sizeof (klassv) };
	CK_ATTRIBUTE certificate_type = { CKA_CERTIFICATE_TYPE, &x509, sizeof (x509) };
	CK_ATTRIBUTE value = { CKA_VALUE, (void *)der, der_len };

	return p11_attrs_build (NULL, &klass, &modifiable, &certificate_type, &value, NULL);
}

int
p11_parser_format_x509 (p11_parser *parser,
                        const unsigned char *data,
                        size_t length)
{
	char message[ASN1_MAX_ERROR_DESCRIPTION_SIZE];
	CK_ATTRIBUTE *attrs;
	CK_ATTRIBUTE *value;
	node_asn *cert;

	cert = p11_asn1_decode (parser->asn1_defs, "PKIX1.Certificate", data, length, message);
	if (cert == NULL)
		return P11_PARSE_UNRECOGNIZED;

	attrs = certificate_attrs (parser, data, length);
	return_val_if_fail (attrs != NULL, P11_PARSE_FAILURE);

	value = p11_attrs_find_valid (attrs, CKA_VALUE);
	return_val_if_fail (value != NULL, P11_PARSE_FAILURE);
	p11_asn1_cache_take (parser->asn1_cache, cert, "PKIX1.Certificate",
	                     value->pValue, value->ulValueLen);

	sink_object (parser, attrs);
	return P11_PARSE_SUCCESS;
}

static CK_ATTRIBUTE *
extension_attrs (p11_parser *parser,
                 CK_ATTRIBUTE *public_key_info,
                 const char *oid_str,
                 const unsigned char *oid_der,
                 bool critical,
                 const unsigned char *value,
                 int length)
{
	CK_OBJECT_CLASS klassv = CKO_X_CERTIFICATE_EXTENSION;
	CK_BBOOL modifiablev = CK_FALSE;

	CK_ATTRIBUTE klass = { CKA_CLASS, &klassv, sizeof (klassv) };
	CK_ATTRIBUTE modifiable = { CKA_MODIFIABLE, &modifiablev, sizeof (modifiablev) };
	CK_ATTRIBUTE oid = { CKA_OBJECT_ID, (void *)oid_der, p11_oid_length (oid_der) };

	CK_ATTRIBUTE *attrs;
	node_asn *dest;
	unsigned char *der;
	size_t len;
	int ret;

	attrs = p11_attrs_build (NULL, public_key_info, &klass, &modifiable, &oid, NULL);
	return_val_if_fail (attrs != NULL, NULL);

	dest = p11_asn1_create (parser->asn1_defs, "PKIX1.Extension");
	return_val_if_fail (dest != NULL, NULL);

	ret = asn1_write_value (dest, "extnID", oid_str, 1);
	return_val_if_fail (ret == ASN1_SUCCESS, NULL);

	if (critical)
		ret = asn1_write_value (dest, "critical", "TRUE", 1);
	return_val_if_fail (ret == ASN1_SUCCESS, NULL);

	ret = asn1_write_value (dest, "extnValue", value, length);
	return_val_if_fail (ret == ASN1_SUCCESS, NULL);

	der = p11_asn1_encode (dest, &len);
	return_val_if_fail (der != NULL, NULL);

	attrs = p11_attrs_take (attrs, CKA_VALUE, der, len);
	return_val_if_fail (attrs != NULL, NULL);

	/* An opmitization so that the builder can get at this without parsing */
	p11_asn1_cache_take (parser->asn1_cache, dest, "PKIX1.Extension", der, len);
	return attrs;
}

static CK_ATTRIBUTE *
attached_attrs (p11_parser *parser,
                CK_ATTRIBUTE *public_key_info,
                const char *oid_str,
                const unsigned char *oid_der,
                bool critical,
                node_asn *ext)
{
	CK_ATTRIBUTE *attrs;
	unsigned char *der;
	size_t len;

	der = p11_asn1_encode (ext, &len);
	return_val_if_fail (der != NULL, NULL);

	attrs = extension_attrs (parser, public_key_info, oid_str, oid_der,
	                         critical, der, len);
	return_val_if_fail (attrs != NULL, NULL);

	free (der);
	return attrs;
}

static p11_dict *
load_seq_of_oid_str (node_asn *node,
                     const char *seqof)
{
	p11_dict *oids;
	char field[128];
	char *oid;
	size_t len;
	int i;

	oids = p11_dict_new (p11_dict_str_hash, p11_dict_str_equal, free, NULL);

	for (i = 1; ; i++) {
		if (snprintf (field, sizeof (field), "%s.?%u", seqof, i) < 0)
			return_val_if_reached (NULL);

		oid = p11_asn1_read (node, field, &len);
		if (oid == NULL)
			break;

		if (!p11_dict_set (oids, oid, oid))
			return_val_if_reached (NULL);
	}

	return oids;
}

static CK_ATTRIBUTE *
attached_eku_attrs (p11_parser *parser,
                    CK_ATTRIBUTE *public_key_info,
                    const char *oid_str,
                    const unsigned char *oid_der,
                    bool critical,
                    p11_dict *oid_strs)
{
	CK_ATTRIBUTE *attrs;
	p11_dictiter iter;
	node_asn *dest;
	int count = 0;
	void *value;
	int ret;

	dest = p11_asn1_create (parser->asn1_defs, "PKIX1.ExtKeyUsageSyntax");
	return_val_if_fail (dest != NULL, NULL);

	p11_dict_iterate (oid_strs, &iter);
	while (p11_dict_next (&iter, NULL, &value)) {
		ret = asn1_write_value (dest, "", "NEW", 1);
		return_val_if_fail (ret == ASN1_SUCCESS, NULL);

		ret = asn1_write_value (dest, "?LAST", value, -1);
		return_val_if_fail (ret == ASN1_SUCCESS, NULL);

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
		return_val_if_fail (ret == ASN1_SUCCESS, NULL);

		ret = asn1_write_value (dest, "?LAST", P11_OID_RESERVED_PURPOSE_STR, -1);
		return_val_if_fail (ret == ASN1_SUCCESS, NULL);
	}


	attrs = attached_attrs (parser, public_key_info, oid_str, oid_der, critical, dest);
	asn1_delete_structure (&dest);

	return attrs;
}

static CK_ATTRIBUTE *
build_openssl_extensions (p11_parser *parser,
                          CK_ATTRIBUTE *cert,
                          CK_ATTRIBUTE *public_key_info,
                          node_asn *aux,
                          const unsigned char *aux_der,
                          size_t aux_len)
{
	CK_BBOOL trusted = CK_FALSE;
	CK_BBOOL distrust = CK_FALSE;

	CK_ATTRIBUTE trust_attrs[] = {
		{ CKA_TRUSTED, &trusted, sizeof (trusted) },
		{ CKA_X_DISTRUSTED, &distrust, sizeof (distrust) },
		{ CKA_INVALID },
	};

	CK_ATTRIBUTE *attrs;
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
	return_val_if_fail (ret == ASN1_SUCCESS || ret == ASN1_ELEMENT_NOT_FOUND, NULL);
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
		attrs = attached_eku_attrs (parser, public_key_info,
		                            P11_OID_EXTENDED_KEY_USAGE_STR,
		                            P11_OID_EXTENDED_KEY_USAGE,
		                            true, trust);
		return_val_if_fail (attrs != NULL, NULL);
		sink_object (parser, attrs);
	}

	/*
	 * For the reject field we use a custom defined extension. We track this
	 * for completeness, although the above ExtendedKeyUsage extension handles
	 * this data fine. See oid.h for more details. It uses ExtKeyUsageSyntax structure.
	 *
	 * non-critical: non-standard, and also covered by trusts
	 */

	if (reject && p11_dict_size (reject) > 0) {
		attrs = attached_eku_attrs (parser, public_key_info,
		                            P11_OID_OPENSSL_REJECT_STR,
		                            P11_OID_OPENSSL_REJECT,
		                            false, reject);
		return_val_if_fail (attrs != NULL, NULL);
		sink_object (parser, attrs);
	}

	/*
	 * OpenSSL model blacklists as anchors with all purposes being removed/rejected,
	 * we account for that here. If there is an ExtendedKeyUsage without any
	 * useful purposes, then treat like a blacklist.
	 */
	if (trust && p11_dict_size (trust) == 0) {
		trusted = CK_FALSE;
		distrust = CK_TRUE;

	/*
	 * Otherwise a 'TRUSTED CERTIFICATE' in an input directory is enough to
	 * mark this as a trusted certificate.
	 */
	} else if (trust && p11_dict_size (trust) > 0) {
		trusted = CK_TRUE;
		distrust = CK_FALSE;
	}

	/*
	 * OpenSSL model blacklists as anchors with all purposes being removed/rejected,
	 * we account for that here. If there is an ExtendedKeyUsage without any
	 * useful purposes, then treat like a blacklist.
	 */

	cert = p11_attrs_merge (cert, p11_attrs_dup (trust_attrs), true);
	return_val_if_fail (cert != NULL, NULL);

	p11_dict_free (trust);
	p11_dict_free (reject);

	/*
	 * For the keyid field we use the SubjectKeyIdentifier extension. It
	 * is already in the correct form, an OCTET STRING.
	 *
	 * non-critical: as recommended in RFC 5280
	 */

	ret = asn1_der_decoding_startEnd (aux, aux_der, aux_len, "keyid", &start, &end);
	return_val_if_fail (ret == ASN1_SUCCESS || ret == ASN1_ELEMENT_NOT_FOUND, NULL);

	if (ret == ASN1_SUCCESS) {
		attrs = extension_attrs (parser, public_key_info,
		                         P11_OID_SUBJECT_KEY_IDENTIFIER_STR,
		                         P11_OID_SUBJECT_KEY_IDENTIFIER,
		                         false, aux_der + start, (end - start) + 1);
		return_val_if_fail (attrs != NULL, NULL);
		sink_object (parser, attrs);
	}


	return cert;
}

static int
parse_openssl_trusted_certificate (p11_parser *parser,
                                   const unsigned char *data,
                                   size_t length)
{
	char message[ASN1_MAX_ERROR_DESCRIPTION_SIZE];
	CK_ATTRIBUTE *attrs;
	CK_ATTRIBUTE public_key_info = { CKA_PUBLIC_KEY_INFO };
	CK_ATTRIBUTE *value;
	char *label = NULL;
	node_asn *cert;
	node_asn *aux = NULL;
	ssize_t cert_len;
	size_t len;
	int start;
	int end;
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

	cert = p11_asn1_decode (parser->asn1_defs, "PKIX1.Certificate", data, cert_len, message);
	if (cert == NULL)
		return P11_PARSE_UNRECOGNIZED;

	/* OpenSSL sometimes outputs TRUSTED CERTIFICATE format without the CertAux supplement */
	if (cert_len < length) {
		aux = p11_asn1_decode (parser->asn1_defs, "OPENSSL.CertAux", data + cert_len,
		                       length - cert_len, message);
		if (aux == NULL) {
			asn1_delete_structure (&cert);
			return P11_PARSE_UNRECOGNIZED;
		}
	}

	attrs = certificate_attrs (parser, data, cert_len);
	return_val_if_fail (attrs != NULL, P11_PARSE_FAILURE);

	/* Cache the parsed certificate ASN.1 for later use by the builder */
	value = p11_attrs_find_valid (attrs, CKA_VALUE);
	return_val_if_fail (value != NULL, P11_PARSE_FAILURE);

	/* Pull out the subject public key info */
	ret = asn1_der_decoding_startEnd (cert, data, cert_len,
	                                  "tbsCertificate.subjectPublicKeyInfo", &start, &end);
	return_val_if_fail (ret == ASN1_SUCCESS, P11_PARSE_FAILURE);

	public_key_info.pValue = (char *)data + start;
	public_key_info.ulValueLen = (end - start) + 1;

	p11_asn1_cache_take (parser->asn1_cache, cert, "PKIX1.Certificate",
	                     value->pValue, value->ulValueLen);

	/* Pull the label out of the CertAux */
	if (aux) {
		len = 0;
		label = p11_asn1_read (aux, "alias", &len);
		if (label != NULL) {
			attrs = p11_attrs_take (attrs, CKA_LABEL, label, strlen (label));
			return_val_if_fail (attrs != NULL, P11_PARSE_FAILURE);
		}

		attrs = build_openssl_extensions (parser, attrs, &public_key_info, aux,
		                                  data + cert_len, length - cert_len);
		return_val_if_fail (attrs != NULL, P11_PARSE_FAILURE);
	}

	sink_object (parser, attrs);
	asn1_delete_structure (&aux);

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
		ret = p11_parser_format_x509 (parser, contents, length);

	} else if (strcmp (type, "TRUSTED CERTIFICATE") == 0) {
		ret = parse_openssl_trusted_certificate (parser, contents, length);

	} else {
		p11_debug ("Saw unsupported or unrecognized PEM block of type %s", type);
		ret = P11_PARSE_SUCCESS;
	}

	if (ret != P11_PARSE_SUCCESS)
		p11_message ("Couldn't parse PEM block of type %s", type);
}

int
p11_parser_format_pem (p11_parser *parser,
                       const unsigned char *data,
                       size_t length)
{
	int num;

	num = p11_pem_parse ((const char *)data, length, on_pem_block, parser);

	if (num == 0)
		return P11_PARSE_UNRECOGNIZED;

	return P11_PARSE_SUCCESS;
}

int
p11_parser_format_persist (p11_parser *parser,
                           const unsigned char *data,
                           size_t length)
{
	CK_BBOOL modifiablev = CK_TRUE;
	CK_ATTRIBUTE *attrs;
	p11_array *objects;
	bool ret;
	int i;

	CK_ATTRIBUTE modifiable = { CKA_MODIFIABLE, &modifiablev, sizeof (modifiablev) };

	if (!p11_persist_magic (data, length))
		return P11_PARSE_UNRECOGNIZED;

	if (!parser->persist) {
		parser->persist = p11_persist_new ();
		return_val_if_fail (parser->persist != NULL, P11_PARSE_UNRECOGNIZED);
	}

	objects = p11_array_new (NULL);
	return_val_if_fail (objects != NULL, P11_PARSE_FAILURE);

	ret = p11_persist_read (parser->persist, parser->basename, data, length, objects);
	if (ret) {
		for (i = 0; i < objects->num; i++) {
			attrs = p11_attrs_build (objects->elem[i], &modifiable, NULL);
			sink_object (parser, attrs);
		}
	}

	p11_array_free (objects);
	return ret ? P11_PARSE_SUCCESS : P11_PARSE_FAILURE;
}

p11_parser *
p11_parser_new (p11_asn1_cache *asn1_cache)
{
	p11_parser parser = { 0, };

	if (asn1_cache == NULL) {
		parser.asn1_owned = true;
		parser.asn1_defs = p11_asn1_defs_load ();
	} else {
		parser.asn1_defs = p11_asn1_cache_defs (asn1_cache);
		parser.asn1_cache = asn1_cache;
		parser.asn1_owned = false;
	}

	parser.parsed = p11_array_new (p11_attrs_free);
	return_val_if_fail (parser.parsed != NULL, NULL);

	return memdup (&parser, sizeof (parser));
}

void
p11_parser_free (p11_parser *parser)
{
	return_if_fail (parser != NULL);
	p11_persist_free (parser->persist);
	p11_array_free (parser->parsed);
	p11_array_free (parser->formats);
	if (parser->asn1_owned)
		p11_dict_free (parser->asn1_defs);
	free (parser);
}

p11_array *
p11_parser_parsed (p11_parser *parser)
{
	return_val_if_fail (parser != NULL, NULL);
	return parser->parsed;
}

void
p11_parser_formats (p11_parser *parser,
                    ...)
{
	p11_array *formats;
	parser_func func;
	va_list va;

	formats = p11_array_new (NULL);
	return_if_fail (formats != NULL);

	va_start (va, parser);
	for (;;) {
		func = va_arg (va, parser_func);
		if (func == NULL)
			break;
		if (!p11_array_push (formats, func))
			return_if_reached ();
	}
	va_end (va);

	p11_array_free (parser->formats);
	parser->formats = formats;
}

int
p11_parse_memory (p11_parser *parser,
                  const char *filename,
                  int flags,
                  const unsigned char *data,
                  size_t length)
{
	int ret = P11_PARSE_UNRECOGNIZED;
	char *base;
	int i;

	return_val_if_fail (parser != NULL, P11_PARSE_FAILURE);
	return_val_if_fail (filename != NULL, P11_PARSE_FAILURE);
	return_val_if_fail (parser->formats != NULL, P11_PARSE_FAILURE);

	p11_array_clear (parser->parsed);
	base = p11_path_base (filename);
	parser->basename = base;
	parser->flags = flags;

	for (i = 0; ret == P11_PARSE_UNRECOGNIZED && i < parser->formats->num; i++)
		ret = ((parser_func)parser->formats->elem[i]) (parser, data, length);

	p11_asn1_cache_flush (parser->asn1_cache);

	free (base);
	parser->basename = NULL;
	parser->flags = 0;

	return ret;
}

int
p11_parse_file (p11_parser *parser,
                const char *filename,
                struct stat *sb,
                int flags)
{
	p11_mmap *map;
	void *data;
	size_t size;
	int ret;

	return_val_if_fail (parser != NULL, P11_PARSE_FAILURE);
	return_val_if_fail (filename != NULL, P11_PARSE_FAILURE);

	map = p11_mmap_open (filename, sb, &data, &size);
	if (map == NULL) {
		p11_message_err (errno, "couldn't open and map file: %s", filename);
		return P11_PARSE_FAILURE;
	}

	ret = p11_parse_memory (parser, filename, flags, data, size);

	p11_mmap_close (map);
	return ret;
}
