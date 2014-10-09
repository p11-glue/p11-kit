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

#define P11_DEBUG_FLAG P11_DEBUG_TRUST

#include "array.h"
#include "asn1.h"
#include "attrs.h"
#include "builder.h"
#include "constants.h"
#include "debug.h"
#include "digest.h"
#include "index.h"
#include "message.h"
#include "oid.h"
#include "pkcs11i.h"
#include "pkcs11x.h"
#include "utf8.h"
#include "x509.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

struct _p11_builder {
	p11_asn1_cache *asn1_cache;
	p11_dict *asn1_defs;
	int flags;
};

enum {
	NONE = 0,
	CREATE = 1 << 0,
	MODIFY = 1 << 1,
	REQUIRE = 1 << 2,
	WANT = 1 << 3,
};

enum {
	NORMAL_BUILD = 0,
	GENERATED_CLASS = 1 << 0,
};

typedef struct {
	int build_flags;
	struct {
		CK_ATTRIBUTE_TYPE type;
		int flags;
		bool (*validate) (p11_builder *, CK_ATTRIBUTE *);
	} attrs[32];
	CK_ATTRIBUTE * (*populate) (p11_builder *, p11_index *, CK_ATTRIBUTE *);
	CK_RV (*validate) (p11_builder *, CK_ATTRIBUTE *, CK_ATTRIBUTE *);
} builder_schema;

static node_asn *
decode_or_get_asn1 (p11_builder *builder,
                    const char *struct_name,
                    const unsigned char *der,
                    size_t length)
{
	node_asn *node;

	node = p11_asn1_cache_get (builder->asn1_cache, struct_name, der, length);
	if (node != NULL)
		return node;

	node = p11_asn1_decode (builder->asn1_defs, struct_name, der, length, NULL);
	if (node != NULL)
		p11_asn1_cache_take (builder->asn1_cache, node, struct_name, der, length);

	return node;
}

static unsigned char *
lookup_extension (p11_builder *builder,
                  p11_index *index,
                  CK_ATTRIBUTE *cert,
                  CK_ATTRIBUTE *public_key,
                  const unsigned char *oid,
                  size_t *ext_len)
{
	CK_OBJECT_CLASS klass = CKO_X_CERTIFICATE_EXTENSION;
	CK_OBJECT_HANDLE obj;
	CK_ATTRIBUTE *attrs;
	CK_ATTRIBUTE *label;
	void *value;
	size_t length;
	node_asn *node;

	CK_ATTRIBUTE match[] = {
		{ CKA_PUBLIC_KEY_INFO, },
		{ CKA_OBJECT_ID, (void *)oid, p11_oid_length (oid) },
		{ CKA_CLASS, &klass, sizeof (klass) },
		{ CKA_INVALID },
	};

	if (public_key == NULL || public_key->type == CKA_INVALID)
		public_key = p11_attrs_find_valid (cert, CKA_PUBLIC_KEY_INFO);

	/* Look for an attached certificate extension */
	if (public_key != NULL) {
		memcpy (match, public_key, sizeof (CK_ATTRIBUTE));
		obj = p11_index_find (index, match, -1);
		attrs = p11_index_lookup (index, obj);
		if (attrs != NULL) {
			value = p11_attrs_find_value (attrs, CKA_VALUE, &length);
			if (value != NULL) {
				node = decode_or_get_asn1 (builder, "PKIX1.Extension", value, length);
				if (node == NULL) {
					label = p11_attrs_find_valid (attrs, CKA_LABEL);
					if (label == NULL)
						label = p11_attrs_find_valid (cert, CKA_LABEL);
					p11_message ("%.*s: invalid certificate extension",
							label ? (int)label->ulValueLen : 7,
							label ? (char *)label->pValue : "unknown");
					return NULL;
				}
				return p11_asn1_read (node, "extnValue", ext_len);
			}
		}
	}

	/* Couldn't find a parsed extension, so look in the current certificate */
	value = p11_attrs_find_value (cert, CKA_VALUE, &length);
	if (value != NULL) {
		node = decode_or_get_asn1 (builder, "PKIX1.Certificate", value, length);
		return_val_if_fail (node != NULL, NULL);
		return p11_x509_find_extension (node, oid, value, length, ext_len);
	}

	return NULL;
}

static CK_OBJECT_HANDLE *
lookup_related  (p11_index *index,
                 CK_OBJECT_CLASS klass,
                 CK_ATTRIBUTE *attr)
{
	CK_ATTRIBUTE match[] = {
		{ attr->type, attr->pValue, attr->ulValueLen },
		{ CKA_CLASS, &klass, sizeof (klass) },
		{ CKA_INVALID }
	};

	return p11_index_find_all (index, match, -1);
}

p11_builder *
p11_builder_new (int flags)
{
	p11_builder *builder;

	builder = calloc (1, sizeof (p11_builder));
	return_val_if_fail (builder != NULL, NULL);

	builder->asn1_cache = p11_asn1_cache_new ();
	return_val_if_fail (builder->asn1_cache, NULL);
	builder->asn1_defs = p11_asn1_cache_defs (builder->asn1_cache);

	builder->flags = flags;
	return builder;
}

static int
atoin (const char *p,
       int digits)
{
	int ret = 0, base = 1;
	while(--digits >= 0) {
		if (p[digits] < '0' || p[digits] > '9')
			return -1;
		ret += (p[digits] - '0') * base;
		base *= 10;
	}
	return ret;
}

static bool
type_bool (p11_builder *builder,
           CK_ATTRIBUTE *attr)
{
	return (attr->pValue != NULL &&
	        sizeof (CK_BBOOL) == attr->ulValueLen);
}

static bool
type_ulong (p11_builder *builder,
            CK_ATTRIBUTE *attr)
{
	return (attr->pValue != NULL &&
	        sizeof (CK_ULONG) == attr->ulValueLen);
}

static bool
type_utf8 (p11_builder *builder,
           CK_ATTRIBUTE *attr)
{
	if (attr->ulValueLen == 0)
		return true;
	if (attr->pValue == NULL)
		return false;
	return p11_utf8_validate (attr->pValue, attr->ulValueLen);
}

static bool
type_date (p11_builder *builder,
           CK_ATTRIBUTE *attr)
{
	CK_DATE *date;
	struct tm tm;
	struct tm two;

	if (attr->ulValueLen == 0)
		return true;
	if (attr->pValue == NULL || attr->ulValueLen != sizeof (CK_DATE))
		return false;

	date = attr->pValue;
	memset (&tm, 0, sizeof (tm));
	tm.tm_year = atoin ((char *)date->year, 4) - 1900;
	tm.tm_mon = atoin ((char *)date->month, 2);
	tm.tm_mday = atoin ((char *)date->day, 2);

	if (tm.tm_year < 0 || tm.tm_mon <= 0 || tm.tm_mday <= 0)
		return false;

	memcpy (&two, &tm, sizeof (tm));
	if (mktime (&two) < 0)
		return false;

	/* If mktime changed anything, then bad date */
	if (tm.tm_year != two.tm_year ||
	    tm.tm_mon != two.tm_mon ||
	    tm.tm_mday != two.tm_mday)
		return false;

	return true;
}

static bool
check_der_struct (p11_builder *builder,
                  const char *struct_name,
                  CK_ATTRIBUTE *attr)
{
	node_asn *asn;

	if (attr->ulValueLen == 0)
		return true;
	if (attr->pValue == NULL)
		return false;

	asn = p11_asn1_decode (builder->asn1_defs, struct_name,
	                       attr->pValue, attr->ulValueLen, NULL);

	if (asn == NULL)
		return false;

	asn1_delete_structure (&asn);
	return true;
}

static bool
type_der_name (p11_builder *builder,
               CK_ATTRIBUTE *attr)
{
	return check_der_struct (builder, "PKIX1.Name", attr);
}

static bool
type_der_serial (p11_builder *builder,
                 CK_ATTRIBUTE *attr)
{
	return check_der_struct (builder, "PKIX1.CertificateSerialNumber", attr);
}

static bool
type_der_oid (p11_builder *builder,
              CK_ATTRIBUTE *attr)
{
	/* AttributeType is an OBJECT ID */
	return check_der_struct (builder, "PKIX1.AttributeType", attr);
}

static bool
type_der_cert (p11_builder *builder,
               CK_ATTRIBUTE *attr)
{
	return check_der_struct (builder, "PKIX1.Certificate", attr);
}

static bool
type_der_key (p11_builder *builder,
              CK_ATTRIBUTE *attr)
{
	return check_der_struct (builder, "PKIX1.SubjectPublicKeyInfo", attr);
}

static bool
type_der_ext (p11_builder *builder,
              CK_ATTRIBUTE *attr)
{
	return check_der_struct (builder, "PKIX1.Extension", attr);
}

#define COMMON_ATTRS \
	{ CKA_CLASS, REQUIRE | CREATE, type_ulong }, \
	{ CKA_TOKEN, CREATE | WANT, type_bool }, \
	{ CKA_MODIFIABLE, CREATE | WANT, type_bool }, \
	{ CKA_PRIVATE, CREATE, type_bool }, \
	{ CKA_LABEL, CREATE | MODIFY | WANT, type_utf8 }, \
	{ CKA_X_GENERATED, CREATE }, \
	{ CKA_X_ORIGIN, NONE } \

static CK_ATTRIBUTE *
common_populate (p11_builder *builder,
                 p11_index *index,
                 CK_ATTRIBUTE *unused)
{
	CK_BBOOL tokenv = CK_FALSE;
	CK_BBOOL modifiablev = CK_TRUE;
	CK_BBOOL privatev = CK_FALSE;
	CK_BBOOL generatedv = CK_FALSE;

	CK_ATTRIBUTE token = { CKA_TOKEN, &tokenv, sizeof (tokenv), };
	CK_ATTRIBUTE privat = { CKA_PRIVATE, &privatev, sizeof (privatev) };
	CK_ATTRIBUTE modifiable = { CKA_MODIFIABLE, &modifiablev, sizeof (modifiablev) };
	CK_ATTRIBUTE generated = { CKA_X_GENERATED, &generatedv, sizeof (generatedv) };
	CK_ATTRIBUTE label = { CKA_LABEL, "", 0 };

	if (builder->flags & P11_BUILDER_FLAG_TOKEN) {
		tokenv = CK_TRUE;
		modifiablev = CK_FALSE;
	}

	return p11_attrs_build (NULL, &token, &privat, &modifiable, &label, &generated, NULL);
}

static void
calc_check_value (const unsigned char *data,
		  size_t length,
		  CK_BYTE *check_value)
{
	unsigned char checksum[P11_DIGEST_SHA1_LEN];
	p11_digest_sha1 (checksum, data, length, NULL);
	memcpy (check_value, checksum, 3);
}

static int
century_for_two_digit_year (int year)
{
	time_t now;
	struct tm tm;
	int century, current;

	return_val_if_fail (year >= 0 && year <= 99, -1);

	/* Get the current year */
	now = time (NULL);
	return_val_if_fail (now >= 0, -1);
	if (!gmtime_r (&now, &tm))
		return_val_if_reached (-1);

	current = (tm.tm_year % 100);
	century = (tm.tm_year + 1900) - current;

	/*
	 * Check if it's within 40 years before the
	 * current date.
	 */
	if (current < 40) {
		if (year < current)
			return century;
		if (year > 100 - (40 - current))
			return century - 100;
	} else {
		if (year < current && year > (current - 40))
			return century;
	}

	/*
	 * If it's after then adjust for overflows to
	 * the next century.
	 */
	if (year < current)
		return century + 100;
	else
		return century;
}

static bool
calc_date (node_asn *node,
           const char *field,
           CK_DATE *date)
{
	node_asn *choice;
	char buf[64];
	int century;
	char *sub;
	int year;
	int len;
	int ret;

	if (!node)
		return false;

	choice = asn1_find_node (node, field);
	return_val_if_fail (choice != NULL, false);

	len = sizeof (buf) - 1;
	ret = asn1_read_value (node, field, buf, &len);
	return_val_if_fail (ret == ASN1_SUCCESS, false);

	sub = strconcat (field, ".", buf, NULL);

	/*
	 * So here we take a shortcut and just copy the date from the
	 * certificate into the CK_DATE. This doesn't take into account
	 * time zones. However the PKCS#11 spec does not say what timezone
	 * the dates are in. In the PKCS#11 value have a day resolution,
	 * and time zones aren't that critical.
	 */

	if (strcmp (buf, "generalTime") == 0) {
		len = sizeof (buf) - 1;
		ret = asn1_read_value (node, sub, buf, &len);
		return_val_if_fail (ret == ASN1_SUCCESS, false);
		return_val_if_fail (len >= 8, false);

		/* Same as first 8 characters of date */
		memcpy (date, buf, 8);

	} else if (strcmp (buf, "utcTime") == 0) {
		len = sizeof (buf) - 1;
		ret = asn1_read_value (node, sub, buf, &len);
		return_val_if_fail (ret == ASN1_SUCCESS, false);
		return_val_if_fail (len >= 6, false);

		year = atoin (buf, 2);
		return_val_if_fail (year >= 0, false);

		century = century_for_two_digit_year (year);
		return_val_if_fail (century >= 0, false);

		snprintf ((char *)date->year, 3, "%02d", century);
		memcpy (((char *)date) + 2, buf, 6);

	} else {
		return_val_if_reached (false);
	}

	free (sub);
	return true;
}

static bool
calc_element (node_asn *node,
	      const unsigned char *data,
	      size_t length,
	      const char *field,
	      CK_ATTRIBUTE *attr)
{
	int ret;
	int start, end;

	if (!node)
		return false;

	ret = asn1_der_decoding_startEnd (node, data, length, field, &start, &end);
	return_val_if_fail (ret == ASN1_SUCCESS, false);
	return_val_if_fail (end >= start, false);

	attr->pValue = (void *)(data + start);
	attr->ulValueLen = (end - start) + 1;
	return true;
}

static bool
is_v1_x509_authority (p11_builder *builder,
                      CK_ATTRIBUTE *cert)
{
	CK_ATTRIBUTE subject;
	CK_ATTRIBUTE issuer;
	CK_ATTRIBUTE *value;
	char buffer[16];
	node_asn *node;
	int len;
	int ret;

	value = p11_attrs_find_valid (cert, CKA_VALUE);
	if (value == NULL)
		return false;

	node = decode_or_get_asn1 (builder, "PKIX1.Certificate",
	                           value->pValue, value->ulValueLen);
	return_val_if_fail (node != NULL, false);

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
	if (!calc_element (node, value->pValue, value->ulValueLen, "tbsCertificate.subject", &subject))
		return_val_if_reached (false);
	if (!calc_element (node, value->pValue, value->ulValueLen, "tbsCertificate.issuer", &issuer))
		return_val_if_reached (false);
	return p11_attr_match_value (&subject, issuer.pValue, issuer.ulValueLen);
}

static bool
calc_certificate_category (p11_builder *builder,
                           p11_index *index,
                           CK_ATTRIBUTE *cert,
                           CK_ATTRIBUTE *public_key,
                           CK_ULONG *category)
{
	CK_ATTRIBUTE *label;
	unsigned char *ext;
	size_t ext_len;
	bool is_ca = 0;
	bool ret;

	/*
	 * In the PKCS#11 spec:
	 *   0 = unspecified (default value)
	 *   1 = token user
	 *   2 = authority
	 *   3 = other entity
	 */

	/* See if we have a basic constraints extension */
	ext = lookup_extension (builder, index, cert, public_key, P11_OID_BASIC_CONSTRAINTS, &ext_len);
	if (ext != NULL) {
		ret = p11_x509_parse_basic_constraints (builder->asn1_defs, ext, ext_len, &is_ca);
		free (ext);
		if (!ret) {
			label = p11_attrs_find_valid (cert, CKA_LABEL);
			p11_message ("%.*s: invalid basic constraints certificate extension",
				     label ? (int)label->ulValueLen : 7,
				     label ? (char *)label->pValue : "unknown");
			return false;
		}

	} else if (is_v1_x509_authority (builder, cert)) {
		/*
		 * If there is no basic constraints extension, and the CA version is
		 * v1, and is self-signed, then we assume this is a certificate authority.
		 * So we add a BasicConstraints attached certificate extension
		 */
		is_ca = 1;

	} else if (!p11_attrs_find_valid (cert, CKA_VALUE)) {
		/*
		 * If we have no certificate value, then this is unknown
		 */
		*category = 0;
		return true;

	}

	*category = is_ca ? 2 : 3;
	return true;
}

static CK_ATTRIBUTE *
certificate_value_attrs (p11_builder *builder,
                         CK_ATTRIBUTE *attrs,
                         node_asn *node,
                         const unsigned char *der,
                         size_t der_len,
                         CK_ATTRIBUTE *public_key)
{
	unsigned char checksum[P11_DIGEST_SHA1_LEN];
	unsigned char *keyid = NULL;
	size_t keyid_len;
	unsigned char *ext = NULL;
	size_t ext_len;
	CK_BBOOL falsev = CK_FALSE;
	CK_ULONG zero = 0UL;
	CK_BYTE checkv[3];
	CK_DATE startv;
	CK_DATE endv;
	char *labelv = NULL;

	CK_ATTRIBUTE trusted = { CKA_TRUSTED, &falsev, sizeof (falsev) };
	CK_ATTRIBUTE distrusted = { CKA_X_DISTRUSTED, &falsev, sizeof (falsev) };
	CK_ATTRIBUTE url = { CKA_URL, "", 0 };
	CK_ATTRIBUTE hash_of_subject_public_key = { CKA_HASH_OF_SUBJECT_PUBLIC_KEY, checksum, sizeof (checksum) };
	CK_ATTRIBUTE hash_of_issuer_public_key = { CKA_HASH_OF_ISSUER_PUBLIC_KEY, "", 0 };
	CK_ATTRIBUTE java_midp_security_domain = { CKA_JAVA_MIDP_SECURITY_DOMAIN, &zero, sizeof (zero) };
	CK_ATTRIBUTE check_value = { CKA_CHECK_VALUE, &checkv, sizeof (checkv) };
	CK_ATTRIBUTE start_date = { CKA_START_DATE, &startv, sizeof (startv) };
	CK_ATTRIBUTE end_date = { CKA_END_DATE, &endv, sizeof (endv) };
	CK_ATTRIBUTE subject = { CKA_SUBJECT, };
	CK_ATTRIBUTE issuer = { CKA_ISSUER, "", 0 };
	CK_ATTRIBUTE serial_number = { CKA_SERIAL_NUMBER, "", 0 };
	CK_ATTRIBUTE label = { CKA_LABEL };
	CK_ATTRIBUTE id = { CKA_ID, NULL, 0 };

	return_val_if_fail (attrs != NULL, NULL);

	if (der == NULL)
		check_value.type = CKA_INVALID;
	else
		calc_check_value (der, der_len, checkv);

	if (!calc_date (node, "tbsCertificate.validity.notBefore", &startv))
		start_date.ulValueLen = 0;
	if (!calc_date (node, "tbsCertificate.validity.notAfter", &endv))
		end_date.ulValueLen = 0;

	if (calc_element (node, der, der_len, "tbsCertificate.subjectPublicKeyInfo", public_key))
		public_key->type = CKA_PUBLIC_KEY_INFO;
	else
		public_key->type = CKA_INVALID;
	calc_element (node, der, der_len, "tbsCertificate.issuer.rdnSequence", &issuer);
	if (!calc_element (node, der, der_len, "tbsCertificate.subject.rdnSequence", &subject))
		subject.type = CKA_INVALID;
	calc_element (node, der, der_len, "tbsCertificate.serialNumber", &serial_number);

	/* Try to build a keyid from an extension */
	if (node) {
		ext = p11_x509_find_extension (node, P11_OID_SUBJECT_KEY_IDENTIFIER, der, der_len, &ext_len);
		if (ext) {
			keyid = p11_x509_parse_subject_key_identifier (builder->asn1_defs, ext,
			                                               ext_len, &keyid_len);
			id.pValue = keyid;
			id.ulValueLen = keyid_len;
		}
	}

	if (!node || !p11_x509_hash_subject_public_key (node, der, der_len, checksum))
		hash_of_subject_public_key.ulValueLen = 0;

	if (id.pValue == NULL) {
		id.pValue = hash_of_subject_public_key.pValue;
		id.ulValueLen = hash_of_subject_public_key.ulValueLen;
	}

	if (node) {
		labelv = p11_x509_lookup_dn_name (node, "tbsCertificate.subject",
		                                  der, der_len, P11_OID_CN);
		if (!labelv)
			labelv = p11_x509_lookup_dn_name (node, "tbsCertificate.subject",
			                                  der, der_len, P11_OID_OU);
		if (!labelv)
			labelv = p11_x509_lookup_dn_name (node, "tbsCertificate.subject",
			                                  der, der_len, P11_OID_O);
	}

	if (labelv) {
		label.pValue = labelv;
		label.ulValueLen = strlen (labelv);
	} else {
		label.type = CKA_INVALID;
	}

	attrs = p11_attrs_build (attrs, &trusted, &distrusted, &url, &hash_of_issuer_public_key,
	                         &hash_of_subject_public_key, &java_midp_security_domain,
	                         &check_value, &start_date, &end_date, &id,
	                         &subject, &issuer, &serial_number, &label, public_key,
				 NULL);
	return_val_if_fail (attrs != NULL, NULL);

	free (ext);
	free (keyid);
	free (labelv);
	return attrs;
}

static CK_ATTRIBUTE *
certificate_populate (p11_builder *builder,
                      p11_index *index,
                      CK_ATTRIBUTE *cert)
{
	CK_ULONG categoryv = 0UL;
	CK_ATTRIBUTE *attrs = NULL;
	CK_ATTRIBUTE public_key;
	node_asn *node = NULL;
	unsigned char *der = NULL;
	size_t der_len = 0;

	CK_ATTRIBUTE category = { CKA_CERTIFICATE_CATEGORY, &categoryv, sizeof (categoryv) };
	CK_ATTRIBUTE empty_value = { CKA_VALUE, "", 0 };

	attrs = common_populate (builder, index, cert);
	return_val_if_fail (attrs != NULL, NULL);

	der = p11_attrs_find_value (cert, CKA_VALUE, &der_len);
	if (der != NULL)
		node = decode_or_get_asn1 (builder, "PKIX1.Certificate", der, der_len);

	attrs = certificate_value_attrs (builder, attrs, node, der, der_len, &public_key);
	return_val_if_fail (attrs != NULL, NULL);

	if (!calc_certificate_category (builder, index, cert, &public_key, &categoryv))
		categoryv = 0;

	return p11_attrs_build (attrs, &category, &empty_value, NULL);
}

static bool
have_attribute (CK_ATTRIBUTE *attrs1,
                CK_ATTRIBUTE *attrs2,
                CK_ATTRIBUTE_TYPE type)
{
	CK_ATTRIBUTE *attr;

	attr = p11_attrs_find (attrs1, type);
	if (attr == NULL)
		attr = p11_attrs_find (attrs2, type);
	return attr != NULL && attr->ulValueLen > 0;
}

static CK_RV
certificate_validate (p11_builder *builder,
                      CK_ATTRIBUTE *attrs,
                      CK_ATTRIBUTE *merge)
{
	/*
	 * In theory we should be validating that in the absence of CKA_VALUE
	 * various other fields must be set. However we do not enforce this
	 * because we want to be able to have certificates without a value
	 * but issuer and serial number, for blacklisting purposes.
	 */

	if (have_attribute (attrs, merge, CKA_URL)) {
		if (!have_attribute (attrs, merge, CKA_HASH_OF_SUBJECT_PUBLIC_KEY)) {
			p11_message ("missing the CKA_HASH_OF_SUBJECT_PUBLIC_KEY attribute");
			return CKR_TEMPLATE_INCONSISTENT;
		}

		if (!have_attribute (attrs, merge, CKA_HASH_OF_SUBJECT_PUBLIC_KEY)) {
			p11_message ("missing the CKA_HASH_OF_ISSUER_PUBLIC_KEY attribute");
			return CKR_TEMPLATE_INCONSISTENT;
		}
	}

	return CKR_OK;
}

const static builder_schema certificate_schema = {
	NORMAL_BUILD,
	{ COMMON_ATTRS,
	  { CKA_CERTIFICATE_TYPE, REQUIRE | CREATE, type_ulong },
	  { CKA_TRUSTED, CREATE | WANT, type_bool },
	  { CKA_X_DISTRUSTED, CREATE | WANT, type_bool },
	  { CKA_CERTIFICATE_CATEGORY, CREATE | WANT, type_ulong },
	  { CKA_CHECK_VALUE, CREATE | WANT, },
	  { CKA_START_DATE, CREATE | MODIFY | WANT, type_date },
	  { CKA_END_DATE, CREATE | MODIFY | WANT, type_date },
	  { CKA_SUBJECT, CREATE | WANT, type_der_name },
	  { CKA_ID, CREATE | MODIFY | WANT },
	  { CKA_ISSUER, CREATE | MODIFY | WANT, type_der_name },
	  { CKA_SERIAL_NUMBER, CREATE | MODIFY | WANT, type_der_serial },
	  { CKA_VALUE, CREATE, type_der_cert },
	  { CKA_URL, CREATE, type_utf8 },
	  { CKA_HASH_OF_SUBJECT_PUBLIC_KEY, CREATE },
	  { CKA_HASH_OF_ISSUER_PUBLIC_KEY, CREATE },
	  { CKA_JAVA_MIDP_SECURITY_DOMAIN, CREATE, type_ulong },
	  { CKA_PUBLIC_KEY_INFO, WANT, type_der_key },
	  { CKA_INVALID },
	}, certificate_populate, certificate_validate,
};

static CK_ATTRIBUTE *
extension_populate (p11_builder *builder,
                    p11_index *index,
                    CK_ATTRIBUTE *extension)
{
	unsigned char checksum[P11_DIGEST_SHA1_LEN];
	CK_ATTRIBUTE object_id = { CKA_INVALID };
	CK_ATTRIBUTE id = { CKA_INVALID };
	CK_ATTRIBUTE *attrs = NULL;

	void *der;
	size_t len;
	node_asn *asn;

	attrs = common_populate (builder, index, extension);
	return_val_if_fail (attrs != NULL, NULL);

	if (!p11_attrs_find_valid (attrs, CKA_ID)) {
		der = p11_attrs_find_value (extension, CKA_PUBLIC_KEY_INFO, &len);
		return_val_if_fail (der != NULL, NULL);

		p11_digest_sha1 (checksum, der, len, NULL);
		id.pValue = checksum;
		id.ulValueLen = sizeof (checksum);
		id.type = CKA_ID;
	}

	/* Pull the object id out of the extension if not present */
	if (!p11_attrs_find_valid (attrs, CKA_OBJECT_ID)) {
		der = p11_attrs_find_value (extension, CKA_VALUE, &len);
		return_val_if_fail (der != NULL, NULL);

		asn = decode_or_get_asn1 (builder, "PKIX1.Extension", der, len);
		return_val_if_fail (asn != NULL, NULL);

		if (calc_element (asn, der, len, "extnID", &object_id))
			object_id.type = CKA_OBJECT_ID;
	}

	attrs = p11_attrs_build (attrs, &object_id, &id, NULL);
	return_val_if_fail (attrs != NULL, NULL);

	return attrs;
}

const static builder_schema extension_schema = {
	NORMAL_BUILD,
	{ COMMON_ATTRS,
	  { CKA_VALUE, REQUIRE | CREATE, type_der_ext },
	  { CKA_PUBLIC_KEY_INFO, REQUIRE | CREATE, type_der_key },
	  { CKA_OBJECT_ID, CREATE | WANT, type_der_oid },
	  { CKA_ID, CREATE | MODIFY },
	  { CKA_INVALID },
	}, extension_populate,
};

static CK_ATTRIBUTE *
data_populate (p11_builder *builder,
               p11_index *index,
               CK_ATTRIBUTE *data)
{
	static const CK_ATTRIBUTE value = { CKA_VALUE, "", 0 };
	static const CK_ATTRIBUTE application = { CKA_APPLICATION, "", 0 };
	static const CK_ATTRIBUTE object_id = { CKA_OBJECT_ID, "", 0 };
	CK_ATTRIBUTE *attrs;

	attrs = common_populate (builder, index, data);
	return_val_if_fail (attrs != NULL, NULL);

	return p11_attrs_build (attrs, &value, &application, &object_id, NULL);
}

const static builder_schema data_schema = {
	NORMAL_BUILD,
	{ COMMON_ATTRS,
	  { CKA_VALUE, CREATE | MODIFY | WANT },
	  { CKA_APPLICATION, CREATE | MODIFY | WANT, type_utf8 },
	  { CKA_OBJECT_ID, CREATE | MODIFY | WANT, type_der_oid },
	  { CKA_INVALID },
	}, data_populate,
};

const static builder_schema trust_schema = {
	GENERATED_CLASS,
	{ COMMON_ATTRS,
	  { CKA_CERT_SHA1_HASH, CREATE },
	  { CKA_CERT_MD5_HASH, CREATE },
	  { CKA_ISSUER, CREATE },
	  { CKA_SUBJECT, CREATE },
	  { CKA_SERIAL_NUMBER, CREATE },
	  { CKA_TRUST_SERVER_AUTH, CREATE },
	  { CKA_TRUST_CLIENT_AUTH, CREATE },
	  { CKA_TRUST_EMAIL_PROTECTION, CREATE },
	  { CKA_TRUST_CODE_SIGNING, CREATE },
	  { CKA_TRUST_IPSEC_END_SYSTEM, CREATE },
	  { CKA_TRUST_IPSEC_TUNNEL, CREATE },
	  { CKA_TRUST_IPSEC_USER, CREATE },
	  { CKA_TRUST_TIME_STAMPING, CREATE },
	  { CKA_TRUST_DIGITAL_SIGNATURE, CREATE },
	  { CKA_TRUST_NON_REPUDIATION, CREATE },
	  { CKA_TRUST_KEY_ENCIPHERMENT, CREATE },
	  { CKA_TRUST_DATA_ENCIPHERMENT, CREATE },
	  { CKA_TRUST_KEY_AGREEMENT, CREATE },
	  { CKA_TRUST_KEY_CERT_SIGN, CREATE },
	  { CKA_TRUST_CRL_SIGN, CREATE },
	  { CKA_TRUST_STEP_UP_APPROVED, CREATE },
	  { CKA_ID, CREATE },
	  { CKA_INVALID },
	}, common_populate
};

const static builder_schema assertion_schema = {
	GENERATED_CLASS,
	{ COMMON_ATTRS,
	  { CKA_X_PURPOSE, REQUIRE | CREATE },
	  { CKA_X_CERTIFICATE_VALUE, CREATE },
	  { CKA_X_ASSERTION_TYPE, REQUIRE | CREATE },
	  { CKA_ISSUER, CREATE },
	  { CKA_SERIAL_NUMBER, CREATE },
	  { CKA_X_PEER, CREATE },
	  { CKA_ID, CREATE },
	  { CKA_INVALID },
	}, common_populate
};

const static builder_schema builtin_schema = {
	GENERATED_CLASS,
	{ COMMON_ATTRS,
	  { CKA_INVALID },
	}, common_populate
};

static const char *
value_name (const p11_constant *info,
            CK_ATTRIBUTE_TYPE type)
{
	const char *name = p11_constant_name (info, type);
	return name ? name : "unknown";
}

static const char *
type_name (CK_ATTRIBUTE_TYPE type)
{
	return value_name (p11_constant_types, type);
}

static CK_RV
build_for_schema (p11_builder *builder,
                  p11_index *index,
                  const builder_schema *schema,
                  CK_ATTRIBUTE *attrs,
                  CK_ATTRIBUTE *merge,
                  CK_ATTRIBUTE **extra)
{
	CK_BBOOL modifiable;
	CK_ATTRIBUTE *attr;
	bool modifying;
	bool creating;
	bool populate;
	bool loading;
	bool found;
	int flags;
	int i, j;
	CK_RV rv;

	populate = false;

	/* Signifies that data is being loaded */
	loading = p11_index_loading (index);

	/* Signifies that this is being created by a caller, instead of loaded */
	creating = (attrs == NULL && !loading);

	/* Item is being modified by a caller */
	modifying = (attrs != NULL && !loading);

	/* This item may not be modifiable */
	if (modifying) {
		if (!p11_attrs_find_bool (attrs, CKA_MODIFIABLE, &modifiable) || !modifiable) {
			p11_message ("the object is not modifiable");
			return CKR_ATTRIBUTE_READ_ONLY;
		}
	}

	if (creating && (builder->flags & P11_BUILDER_FLAG_TOKEN)) {
		if (schema->build_flags & GENERATED_CLASS) {
			p11_message ("objects of this type cannot be created");
			return CKR_TEMPLATE_INCONSISTENT;
		}
	}

	for (i = 0; merge[i].type != CKA_INVALID; i++) {

		/* Don't validate attribute if not changed */
		attr = p11_attrs_find (attrs, merge[i].type);
		if (attr && p11_attr_equal (attr, merge + i))
			continue;

		found = false;
		for (j = 0; schema->attrs[j].type != CKA_INVALID; j++) {
			if (schema->attrs[j].type != merge[i].type)
				continue;

			flags = schema->attrs[j].flags;
			if (creating && !(flags & CREATE)) {
				p11_message ("the %s attribute cannot be set",
				             type_name (schema->attrs[j].type));
				return CKR_ATTRIBUTE_READ_ONLY;
			}
			if (modifying && !(flags & MODIFY)) {
				p11_message ("the %s attribute cannot be changed",
				             type_name (schema->attrs[j].type));
				return CKR_ATTRIBUTE_READ_ONLY;
			}
			if (!loading && schema->attrs[j].validate != NULL &&
			    !schema->attrs[j].validate (builder, merge + i)) {
				p11_message ("the %s attribute has an invalid value",
				             type_name (schema->attrs[j].type));
				return CKR_ATTRIBUTE_VALUE_INVALID;
			}
			found = true;
			break;
		}

		if (!found) {
			p11_message ("the %s attribute is not valid for the object",
			             type_name (merge[i].type));
			return CKR_TEMPLATE_INCONSISTENT;
		}
	}

	if (attrs == NULL) {
		for (j = 0; schema->attrs[j].type != CKA_INVALID; j++) {
			flags = schema->attrs[j].flags;
			found = false;

			if ((flags & REQUIRE) || (flags & WANT)) {
				for (i = 0; merge[i].type != CKA_INVALID; i++) {
					if (schema->attrs[j].type == merge[i].type) {
						found = true;
						break;
					}
				}
			}

			if (!found) {
				if (flags & REQUIRE) {
					p11_message ("missing the %s attribute",
					             type_name (schema->attrs[j].type));
					return CKR_TEMPLATE_INCOMPLETE;
				} else if (flags & WANT) {
					populate = true;
				}
			}
		}
	}

	/* Validate the result, before committing to the change. */
	if (!loading && schema->validate) {
		rv = (schema->validate) (builder, attrs, merge);
		if (rv != CKR_OK)
			return rv;
	}

	if (populate && schema->populate)
		*extra = schema->populate (builder, index, merge);

	return CKR_OK;
}

CK_RV
p11_builder_build (void *bilder,
                   p11_index *index,
                   CK_ATTRIBUTE *attrs,
                   CK_ATTRIBUTE *merge,
                   CK_ATTRIBUTE **populate)
{
	p11_builder *builder = bilder;
	CK_OBJECT_CLASS klass;
	CK_CERTIFICATE_TYPE type;
	CK_BBOOL token;

	return_val_if_fail (builder != NULL, CKR_GENERAL_ERROR);
	return_val_if_fail (index != NULL, CKR_GENERAL_ERROR);
	return_val_if_fail (merge != NULL, CKR_GENERAL_ERROR);

	if (!p11_attrs_find_ulong (attrs ? attrs : merge, CKA_CLASS, &klass)) {
		p11_message ("no CKA_CLASS attribute found");
		return CKR_TEMPLATE_INCOMPLETE;
	}

	if (!attrs && p11_attrs_find_bool (merge, CKA_TOKEN, &token)) {
		if (token != ((builder->flags & P11_BUILDER_FLAG_TOKEN) ? CK_TRUE : CK_FALSE)) {
			p11_message ("cannot create a %s object", token ? "token" : "non-token");
			return CKR_TEMPLATE_INCONSISTENT;
		}
	}

	switch (klass) {
	case CKO_CERTIFICATE:
		if (!p11_attrs_find_ulong (attrs ? attrs : merge, CKA_CERTIFICATE_TYPE, &type)) {
			p11_message ("missing %s on object", type_name (CKA_CERTIFICATE_TYPE));
			return CKR_TEMPLATE_INCOMPLETE;
		} else if (type == CKC_X_509) {
			return build_for_schema (builder, index, &certificate_schema, attrs, merge, populate);
		} else {
			p11_message ("%s unsupported %s", value_name (p11_constant_certs, type),
			             type_name (CKA_CERTIFICATE_TYPE));
			return CKR_TEMPLATE_INCONSISTENT;
		}

	case CKO_X_CERTIFICATE_EXTENSION:
		return build_for_schema (builder, index, &extension_schema, attrs, merge, populate);

	case CKO_DATA:
		return build_for_schema (builder, index, &data_schema, attrs, merge, populate);

	case CKO_NSS_TRUST:
		return build_for_schema (builder, index, &trust_schema, attrs, merge, populate);

	case CKO_NSS_BUILTIN_ROOT_LIST:
		return build_for_schema (builder, index, &builtin_schema, attrs, merge, populate);

	case CKO_X_TRUST_ASSERTION:
		return build_for_schema (builder, index, &assertion_schema, attrs, merge, populate);

	default:
		p11_message ("%s unsupported object class",
		             value_name (p11_constant_classes, klass));
		return CKR_TEMPLATE_INCONSISTENT;
	}
}

void
p11_builder_free (p11_builder *builder)
{
	return_if_fail (builder != NULL);

	p11_asn1_cache_free (builder->asn1_cache);
	free (builder);
}

p11_asn1_cache *
p11_builder_get_cache (p11_builder *builder)
{
	return_val_if_fail (builder != NULL, NULL);
	return builder->asn1_cache;
}

static CK_ATTRIBUTE *
build_trust_object_ku (p11_builder *builder,
                       p11_index *index,
                       CK_ATTRIBUTE *cert,
                       CK_ATTRIBUTE *object,
                       CK_TRUST present)
{
	unsigned char *data = NULL;
	unsigned int ku = 0;
	size_t length;
	CK_TRUST defawlt;
	CK_ULONG i;

	struct {
		CK_ATTRIBUTE_TYPE type;
		unsigned int ku;
	} ku_attribute_map[] = {
		{ CKA_TRUST_DIGITAL_SIGNATURE, P11_KU_DIGITAL_SIGNATURE },
		{ CKA_TRUST_NON_REPUDIATION, P11_KU_NON_REPUDIATION },
		{ CKA_TRUST_KEY_ENCIPHERMENT, P11_KU_KEY_ENCIPHERMENT },
		{ CKA_TRUST_DATA_ENCIPHERMENT, P11_KU_DATA_ENCIPHERMENT },
		{ CKA_TRUST_KEY_AGREEMENT, P11_KU_KEY_AGREEMENT },
		{ CKA_TRUST_KEY_CERT_SIGN, P11_KU_KEY_CERT_SIGN },
		{ CKA_TRUST_CRL_SIGN, P11_KU_CRL_SIGN },
		{ CKA_INVALID },
	};

	CK_ATTRIBUTE attrs[sizeof (ku_attribute_map)];

	defawlt = present;

	/* If blacklisted, don't even bother looking at extensions */
	if (present != CKT_NSS_NOT_TRUSTED)
		data = lookup_extension (builder, index, cert, NULL, P11_OID_KEY_USAGE, &length);

	if (data) {
		/*
		 * If the certificate extension was missing, then *all* key
		 * usages are to be set. If the extension was invalid, then
		 * fail safe to none of the key usages.
		 */
		defawlt = CKT_NSS_TRUST_UNKNOWN;

		if (!p11_x509_parse_key_usage (builder->asn1_defs, data, length, &ku))
			p11_message ("invalid key usage certificate extension");
		free (data);
	}

	for (i = 0; ku_attribute_map[i].type != CKA_INVALID; i++) {
		attrs[i].type = ku_attribute_map[i].type;
		if (data && (ku & ku_attribute_map[i].ku) == ku_attribute_map[i].ku) {
			attrs[i].pValue = &present;
			attrs[i].ulValueLen = sizeof (present);
		} else {
			attrs[i].pValue = &defawlt;
			attrs[i].ulValueLen = sizeof (defawlt);
		}
	}

	return p11_attrs_buildn (object, attrs, i);
}

static bool
strv_to_dict (const char **array,
              p11_dict **dict)
{
	int i;

	if (!array) {
		*dict = NULL;
		return true;
	}

	*dict = p11_dict_new (p11_dict_str_hash, p11_dict_str_equal, NULL, NULL);
	return_val_if_fail (*dict != NULL, false);

	for (i = 0; array[i] != NULL; i++) {
		if (!p11_dict_set (*dict, (void *)array[i], (void *)array[i]))
			return_val_if_reached (false);
	}

	return true;
}

static CK_ATTRIBUTE *
build_trust_object_eku (CK_ATTRIBUTE *object,
                        CK_TRUST allow,
                        const char **purposes,
                        const char **rejects)
{
	p11_dict *dict_purp;
	p11_dict *dict_rej;
	CK_TRUST neutral;
	CK_TRUST disallow;
	CK_ULONG i;

	struct {
		CK_ATTRIBUTE_TYPE type;
		const char *oid;
	} eku_attribute_map[] = {
		{ CKA_TRUST_SERVER_AUTH, P11_OID_SERVER_AUTH_STR },
		{ CKA_TRUST_CLIENT_AUTH, P11_OID_CLIENT_AUTH_STR },
		{ CKA_TRUST_CODE_SIGNING, P11_OID_CODE_SIGNING_STR },
		{ CKA_TRUST_EMAIL_PROTECTION, P11_OID_EMAIL_PROTECTION_STR },
		{ CKA_TRUST_IPSEC_END_SYSTEM, P11_OID_IPSEC_END_SYSTEM_STR },
		{ CKA_TRUST_IPSEC_TUNNEL, P11_OID_IPSEC_TUNNEL_STR },
		{ CKA_TRUST_IPSEC_USER, P11_OID_IPSEC_USER_STR },
		{ CKA_TRUST_TIME_STAMPING, P11_OID_TIME_STAMPING_STR },
		{ CKA_INVALID },
	};

	CK_ATTRIBUTE attrs[sizeof (eku_attribute_map)];

	if (!strv_to_dict (purposes, &dict_purp) ||
	    !strv_to_dict (rejects, &dict_rej))
		return_val_if_reached (NULL);

	/* The neutral value is set if an purpose is not present */
	if (allow == CKT_NSS_NOT_TRUSTED)
		neutral = CKT_NSS_NOT_TRUSTED;

	/* If anything explicitly set, then neutral is unknown */
	else if (purposes || rejects)
		neutral = CKT_NSS_TRUST_UNKNOWN;

	/* Otherwise neutral will allow any purpose */
	else
		neutral = allow;

	/* The value set if a purpose is explictly rejected */
	disallow = CKT_NSS_NOT_TRUSTED;

	for (i = 0; eku_attribute_map[i].type != CKA_INVALID; i++) {
		attrs[i].type = eku_attribute_map[i].type;
		if (dict_rej && p11_dict_get (dict_rej, eku_attribute_map[i].oid)) {
			attrs[i].pValue = &disallow;
			attrs[i].ulValueLen = sizeof (disallow);
		} else if (dict_purp && p11_dict_get (dict_purp, eku_attribute_map[i].oid)) {
			attrs[i].pValue = &allow;
			attrs[i].ulValueLen = sizeof (allow);
		} else {
			attrs[i].pValue = &neutral;
			attrs[i].ulValueLen = sizeof (neutral);
		}
	}

	p11_dict_free (dict_purp);
	p11_dict_free (dict_rej);

	return p11_attrs_buildn (object, attrs, i);
}

static void
replace_nss_trust_object (p11_builder *builder,
                          p11_index *index,
                          CK_ATTRIBUTE *cert,
                          CK_BBOOL trust,
                          CK_BBOOL distrust,
                          CK_BBOOL authority,
                          const char **purposes,
                          const char **rejects)
{
	CK_ATTRIBUTE *attrs = NULL;
	CK_ATTRIBUTE *match = NULL;
	CK_TRUST allow;
	CK_RV rv;

	CK_OBJECT_CLASS klassv = CKO_NSS_TRUST;
	CK_BYTE sha1v[P11_DIGEST_SHA1_LEN];
	CK_BYTE md5v[P11_DIGEST_MD5_LEN];
	CK_BBOOL generatedv = CK_FALSE;
	CK_BBOOL falsev = CK_FALSE;

	CK_ATTRIBUTE klass = { CKA_CLASS, &klassv, sizeof (klassv) };
	CK_ATTRIBUTE modifiable = { CKA_MODIFIABLE, &falsev, sizeof (falsev) };
	CK_ATTRIBUTE generated = { CKA_X_GENERATED, &generatedv, sizeof (generatedv) };
	CK_ATTRIBUTE invalid = { CKA_INVALID, };

	CK_ATTRIBUTE md5_hash = { CKA_CERT_MD5_HASH, md5v, sizeof (md5v) };
	CK_ATTRIBUTE sha1_hash = { CKA_CERT_SHA1_HASH, sha1v, sizeof (sha1v) };

	CK_ATTRIBUTE step_up_approved = { CKA_TRUST_STEP_UP_APPROVED, &falsev, sizeof (falsev) };

	CK_ATTRIBUTE_PTR label;
	CK_ATTRIBUTE_PTR id;
	CK_ATTRIBUTE_PTR subject;
	CK_ATTRIBUTE_PTR issuer;
	CK_ATTRIBUTE_PTR serial_number;

	p11_array *array;
	void *value;
	size_t length;

	issuer = p11_attrs_find_valid (cert, CKA_ISSUER);
	serial_number = p11_attrs_find_valid (cert, CKA_SERIAL_NUMBER);
	value = p11_attrs_find_value (cert, CKA_VALUE, &length);

	if (!issuer && !serial_number && !value) {
		p11_debug ("can't generate nss trust object for certificate without issuer+serial or value");
		return;
	}

	if (value == NULL) {
		md5_hash.type = CKA_INVALID;
		sha1_hash.type = CKA_INVALID;
	} else {
		p11_digest_md5 (md5v, value, length, NULL);
		p11_digest_sha1 (sha1v, value, length, NULL);
	}
	if (!issuer)
		issuer = &invalid;
	if (!serial_number)
		serial_number = &invalid;

	match = p11_attrs_build (NULL, issuer, serial_number, &sha1_hash,
	                         &generated, &klass, NULL);
	return_if_fail (match != NULL);

	/* If we find a non-generated object, then don't generate */
	if (p11_index_find (index, match, -1)) {
		p11_debug ("not generating nss trust object because one already exists");
		attrs = NULL;

	} else {
		generatedv = CK_TRUE;
		match = p11_attrs_build (match, &generated, NULL);
		return_if_fail (match != NULL);

		/* Copy all of the following attributes from certificate */
		id = p11_attrs_find_valid (cert, CKA_ID);
		if (id == NULL)
			id = &invalid;
		subject = p11_attrs_find_valid (cert, CKA_SUBJECT);
		if (subject == NULL)
			subject = &invalid;
		label = p11_attrs_find_valid (cert, CKA_LABEL);
		if (label == NULL)
			label = &invalid;

		attrs = p11_attrs_dup (match);
		return_if_fail (attrs != NULL);

		attrs = p11_attrs_build (attrs, &klass, &modifiable, id, label,
		                         subject, issuer, serial_number,
		                         &md5_hash, &sha1_hash, &step_up_approved, NULL);
		return_if_fail (attrs != NULL);

		/* Calculate the default allow trust */
		if (distrust)
			allow = CKT_NSS_NOT_TRUSTED;
		else if (trust && authority)
			allow = CKT_NSS_TRUSTED_DELEGATOR;
		else if (trust)
			allow = CKT_NSS_TRUSTED;
		else
			allow = CKT_NSS_TRUST_UNKNOWN;

		attrs = build_trust_object_ku (builder, index, cert, attrs, allow);
		return_if_fail (attrs != NULL);

		attrs = build_trust_object_eku (attrs, allow, purposes, rejects);
		return_if_fail (attrs != NULL);
	}

	/* Replace related generated object with this new one */
	array = p11_array_new (NULL);
	p11_array_push (array, attrs);
	rv = p11_index_replace_all (index, match, CKA_INVALID, array);
	return_if_fail (rv == CKR_OK);
	p11_array_free (array);

	p11_attrs_free (match);
}

static void
build_assertions (p11_array *array,
                  CK_ATTRIBUTE *cert,
                  CK_X_ASSERTION_TYPE type,
                  const char **oids)
{
	CK_OBJECT_CLASS assertion = CKO_X_TRUST_ASSERTION;
	CK_BBOOL truev = CK_TRUE;
	CK_BBOOL falsev = CK_FALSE;

	CK_ATTRIBUTE klass = { CKA_CLASS, &assertion, sizeof (assertion) };
	CK_ATTRIBUTE private = { CKA_PRIVATE, &falsev, sizeof (falsev) };
	CK_ATTRIBUTE modifiable = { CKA_MODIFIABLE, &falsev, sizeof (falsev) };
	CK_ATTRIBUTE assertion_type = { CKA_X_ASSERTION_TYPE, &type, sizeof (type) };
	CK_ATTRIBUTE autogen = { CKA_X_GENERATED, &truev, sizeof (truev) };
	CK_ATTRIBUTE purpose = { CKA_X_PURPOSE, };
	CK_ATTRIBUTE invalid = { CKA_INVALID, };
	CK_ATTRIBUTE certificate_value = { CKA_X_CERTIFICATE_VALUE, };

	CK_ATTRIBUTE *issuer;
	CK_ATTRIBUTE *serial;
	CK_ATTRIBUTE *value;
	CK_ATTRIBUTE *label;
	CK_ATTRIBUTE *id;
	CK_ATTRIBUTE *attrs;
	int i;

	if (type == CKT_X_DISTRUSTED_CERTIFICATE) {
		certificate_value.type = CKA_INVALID;
		issuer = p11_attrs_find_valid (cert, CKA_ISSUER);
		serial = p11_attrs_find_valid (cert, CKA_SERIAL_NUMBER);

		if (!issuer || !serial) {
			p11_debug ("not building negative trust assertion for certificate without serial or issuer");
			return;
		}

	} else {
		issuer = &invalid;
		serial = &invalid;
		value = p11_attrs_find_valid (cert, CKA_VALUE);

		if (value == NULL) {
			p11_debug ("not building positive trust assertion for certificate without value");
			return;
		}

		certificate_value.pValue = value->pValue;
		certificate_value.ulValueLen = value->ulValueLen;
	}

	label = p11_attrs_find (cert, CKA_LABEL);
	if (label == NULL)
		label = &invalid;
	id = p11_attrs_find (cert, CKA_ID);
	if (id == NULL)
		id = &invalid;

	for (i = 0; oids[i] != NULL; i++) {
		purpose.pValue = (void *)oids[i];
		purpose.ulValueLen = strlen (oids[i]);

		attrs = p11_attrs_build (NULL, &klass, &private, &modifiable,
		                         id, label, &assertion_type, &purpose,
		                         issuer, serial, &certificate_value, &autogen, NULL);
		return_if_fail (attrs != NULL);

		if (!p11_array_push (array, attrs))
			return_if_reached ();
	}
}

static void
build_trust_assertions (p11_array *positives,
                        p11_array *negatives,
                        CK_ATTRIBUTE *cert,
                        CK_BBOOL trust,
                        CK_BBOOL distrust,
                        CK_BBOOL authority,
                        const char **purposes,
                        const char **rejects)
{
	const char *all_purposes[] = {
		P11_OID_SERVER_AUTH_STR,
		P11_OID_CLIENT_AUTH_STR,
		P11_OID_CODE_SIGNING_STR,
		P11_OID_EMAIL_PROTECTION_STR,
		P11_OID_IPSEC_END_SYSTEM_STR,
		P11_OID_IPSEC_TUNNEL_STR,
		P11_OID_IPSEC_USER_STR,
		P11_OID_TIME_STAMPING_STR,
		NULL,
	};

	/* Build assertions for anything that's explicitly rejected */
	if (rejects && negatives) {
		build_assertions (negatives, cert, CKT_X_DISTRUSTED_CERTIFICATE, rejects);
	}

	if (distrust && negatives) {
		/*
		 * Trust assertions are defficient in that they don't blacklist a certificate
		 * for any purposes. So we just have to go wild and write out a bunch of
		 * assertions for all our known purposes.
		 */
		build_assertions (negatives, cert, CKT_X_DISTRUSTED_CERTIFICATE, all_purposes);
	}

	/*
	 * TODO: Build pinned certificate assertions. That is, trusted
	 * certificates where not an authority.
	 */

	if (trust && authority && positives) {
		if (purposes) {
			/* If purposes explicitly set, then anchor for those purposes */
			build_assertions (positives, cert, CKT_X_ANCHORED_CERTIFICATE, purposes);
		} else {
			/* If purposes not-explicitly set, then anchor for all known */
			build_assertions (positives, cert, CKT_X_ANCHORED_CERTIFICATE, all_purposes);
		}
	}
}

static void
replace_trust_assertions (p11_builder *builder,
                          p11_index *index,
                          CK_ATTRIBUTE *cert,
                          CK_BBOOL trust,
                          CK_BBOOL distrust,
                          CK_BBOOL authority,
                          const char **purposes,
                          const char **rejects)
{
	CK_OBJECT_CLASS assertion = CKO_X_TRUST_ASSERTION;
	CK_BBOOL generated = CK_TRUE;
	p11_array *positives = NULL;
	p11_array *negatives = NULL;
	CK_ATTRIBUTE *value;
	CK_ATTRIBUTE *issuer;
	CK_ATTRIBUTE *serial;
	CK_RV rv;

	CK_ATTRIBUTE match_positive[] = {
		{ CKA_X_CERTIFICATE_VALUE, },
		{ CKA_CLASS, &assertion, sizeof (assertion) },
		{ CKA_X_GENERATED, &generated, sizeof (generated) },
		{ CKA_INVALID }
	};

	CK_ATTRIBUTE match_negative[] = {
		{ CKA_ISSUER, },
		{ CKA_SERIAL_NUMBER, },
		{ CKA_CLASS, &assertion, sizeof (assertion) },
		{ CKA_X_GENERATED, &generated, sizeof (generated) },
		{ CKA_INVALID }
	};

	value = p11_attrs_find_valid (cert, CKA_VALUE);
	if (value) {
		positives = p11_array_new (NULL);
		match_positive[0].pValue = value->pValue;
		match_positive[0].ulValueLen = value->ulValueLen;
	}

	issuer = p11_attrs_find_valid (cert, CKA_ISSUER);
	serial = p11_attrs_find_valid (cert, CKA_SERIAL_NUMBER);
	if (issuer && serial) {
		negatives = p11_array_new (NULL);
		memcpy (match_negative + 0, issuer, sizeof (CK_ATTRIBUTE));
		memcpy (match_negative + 1, serial, sizeof (CK_ATTRIBUTE));
	}

	build_trust_assertions (positives, negatives, cert, trust, distrust,
	                        authority, purposes, rejects);

	if (positives) {
		rv = p11_index_replace_all (index, match_positive, CKA_X_PURPOSE, positives);
		return_if_fail (rv == CKR_OK);
		p11_array_free (positives);
	}

	if (negatives) {
		rv = p11_index_replace_all (index, match_negative, CKA_X_PURPOSE, negatives);
		return_if_fail (rv == CKR_OK);
		p11_array_free (negatives);
	}
}

static void
remove_trust_and_assertions (p11_builder *builder,
                             p11_index *index,
                             CK_ATTRIBUTE *attrs)
{
	replace_nss_trust_object (builder, index, attrs,
	                          CK_FALSE, CK_FALSE, CK_FALSE,
	                          NULL, NULL);
	replace_trust_assertions (builder, index, attrs,
	                          CK_FALSE, CK_FALSE, CK_FALSE,
	                          NULL, NULL);
}

static void
replace_trust_and_assertions (p11_builder *builder,
                              p11_index *index,
                              CK_ATTRIBUTE *cert)
{
	CK_BBOOL trust = CK_FALSE;
	CK_BBOOL distrust = CK_FALSE;
	CK_BBOOL authority = CK_FALSE;
	p11_array *purposes = NULL;
	p11_array *rejects = NULL;
	const char **purposev;
	const char **rejectv;
	CK_ULONG category;
	unsigned char *ext;
	size_t ext_len;

	/*
	 * We look up all this information in advance, since it's used
	 * by the various adapter objects, and we don't have to parse
	 * it multiple times.
	 */

	if (!p11_attrs_find_bool (cert, CKA_TRUSTED, &trust))
		trust = CK_FALSE;
	if (!p11_attrs_find_bool (cert, CKA_X_DISTRUSTED, &distrust))
		distrust = CK_FALSE;
	if (p11_attrs_find_ulong (cert, CKA_CERTIFICATE_CATEGORY, &category) && category == 2)
		authority = CK_TRUE;

	if (!distrust) {
		ext = lookup_extension (builder, index, cert, NULL, P11_OID_EXTENDED_KEY_USAGE, &ext_len);
		if (ext != NULL) {
			purposes = p11_x509_parse_extended_key_usage (builder->asn1_defs, ext, ext_len);
			if (purposes == NULL)
				p11_message ("invalid extended key usage certificate extension");
			free (ext);
		}

		ext = lookup_extension (builder, index, cert, NULL, P11_OID_OPENSSL_REJECT, &ext_len);
		if (ext != NULL) {
			rejects = p11_x509_parse_extended_key_usage (builder->asn1_defs, ext, ext_len);
			if (rejects == NULL)
				p11_message ("invalid reject key usage certificate extension");
			free (ext);
		}
	}

	/* null-terminate these arrays and use as strv's */
	purposev = rejectv = NULL;
	if (rejects) {
		if (!p11_array_push (rejects, NULL))
			return_if_reached ();
		rejectv = (const char **)rejects->elem;
	}
	if (purposes) {
		if (!p11_array_push (purposes, NULL))
			return_if_reached ();
		purposev = (const char **)purposes->elem;
	}

	replace_nss_trust_object (builder, index, cert, trust, distrust,
	                          authority, purposev, rejectv);
	replace_trust_assertions (builder, index, cert, trust, distrust,
	                          authority, purposev, rejectv);

	p11_array_free (purposes);
	p11_array_free (rejects);
}

static void
replace_compat_for_cert (p11_builder *builder,
                         p11_index *index,
                         CK_OBJECT_HANDLE handle,
                         CK_ATTRIBUTE *attrs)
{
	static const CK_OBJECT_CLASS certificate = CKO_CERTIFICATE;
	static const CK_CERTIFICATE_TYPE x509 = CKC_X_509;
	CK_ATTRIBUTE *value;

	CK_ATTRIBUTE match[] = {
		{ CKA_VALUE, },
		{ CKA_CLASS, (void *)&certificate, sizeof (certificate) },
		{ CKA_CERTIFICATE_TYPE, (void *)&x509, sizeof (x509) },
		{ CKA_INVALID }
	};

	/*
	 * If this certificate is going away, then find duplicate. In this
	 * case all the trust assertions are recalculated with this new
	 * certificate in mind.
	 */
	if (handle == 0) {
		value = p11_attrs_find_valid (attrs, CKA_VALUE);
		if (value != NULL) {
			match[0].pValue = value->pValue;
			match[0].ulValueLen = value->ulValueLen;
			handle = p11_index_find (index, match, -1);
		}
		if (handle != 0)
			attrs = p11_index_lookup (index, handle);
	}

	if (handle == 0)
		remove_trust_and_assertions (builder, index, attrs);
	else
		replace_trust_and_assertions (builder, index, attrs);
}

static void
replace_compat_for_ext (p11_builder *builder,
                        p11_index *index,
                        CK_OBJECT_HANDLE handle,
                        CK_ATTRIBUTE *attrs)
{

	CK_OBJECT_HANDLE *handles;
	CK_ATTRIBUTE *public_key;
	int i;

	public_key = p11_attrs_find_valid (attrs, CKA_PUBLIC_KEY_INFO);
	if (public_key == NULL)
		return;

	handles = lookup_related (index, CKO_CERTIFICATE, public_key);
	for (i = 0; handles && handles[i] != 0; i++) {
		attrs = p11_index_lookup (index, handles[i]);
		replace_trust_and_assertions (builder, index, attrs);
	}
	free (handles);
}

static void
update_related_category (p11_builder *builder,
                         p11_index *index,
                         CK_OBJECT_HANDLE handle,
                         CK_ATTRIBUTE *attrs)
{
	CK_OBJECT_HANDLE *handles;
	CK_ULONG categoryv = 0UL;
	CK_ATTRIBUTE *update;
	CK_ATTRIBUTE *cert;
	CK_ATTRIBUTE *public_key;
	CK_RV rv;
	int i;

	CK_ATTRIBUTE category[] = {
		{ CKA_CERTIFICATE_CATEGORY, &categoryv, sizeof (categoryv) },
		{ CKA_INVALID, },
	};

	public_key = p11_attrs_find_valid (attrs, CKA_PUBLIC_KEY_INFO);
	if (public_key == NULL)
		return;

	/* Find all other objects with this handle */
	handles = lookup_related (index, CKO_CERTIFICATE, public_key);

	for (i = 0; handles && handles[i] != 0; i++) {
		cert = p11_index_lookup (index, handle);

		if (calc_certificate_category (builder, index, cert, public_key, &categoryv)) {
			update = p11_attrs_build (NULL, &category, NULL);
			rv = p11_index_update (index, handles[i], update);
			return_if_fail (rv == CKR_OK);
		}
	}

	free (handles);
}

void
p11_builder_changed (void *bilder,
                     p11_index *index,
                     CK_OBJECT_HANDLE handle,
                     CK_ATTRIBUTE *attrs)
{
	static const CK_OBJECT_CLASS certificate = CKO_CERTIFICATE;
	static const CK_OBJECT_CLASS extension = CKO_X_CERTIFICATE_EXTENSION;
	static const CK_CERTIFICATE_TYPE x509 = CKC_X_509;

	static const CK_ATTRIBUTE match_cert[] = {
		{ CKA_CLASS, (void *)&certificate, sizeof (certificate) },
		{ CKA_CERTIFICATE_TYPE, (void *)&x509, sizeof (x509) },
		{ CKA_INVALID }
	};

	static const CK_ATTRIBUTE match_eku[] = {
		{ CKA_CLASS, (void *)&extension, sizeof (extension) },
		{ CKA_OBJECT_ID, (void *)P11_OID_EXTENDED_KEY_USAGE,
		  sizeof (P11_OID_EXTENDED_KEY_USAGE) },
		{ CKA_INVALID }
	};

	static const CK_ATTRIBUTE match_ku[] = {
		{ CKA_CLASS, (void *)&extension, sizeof (extension) },
		{ CKA_OBJECT_ID, (void *)P11_OID_KEY_USAGE,
		  sizeof (P11_OID_KEY_USAGE) },
		{ CKA_INVALID }
	};

	static const CK_ATTRIBUTE match_bc[] = {
		{ CKA_CLASS, (void *)&extension, sizeof (extension) },
		{ CKA_OBJECT_ID, (void *)P11_OID_BASIC_CONSTRAINTS,
		  sizeof (P11_OID_BASIC_CONSTRAINTS) },
		{ CKA_INVALID }
	};

	p11_builder *builder = bilder;

	return_if_fail (builder != NULL);
	return_if_fail (index != NULL);
	return_if_fail (attrs != NULL);

	/*
	 * Treat these operations as loading, not modifying/creating, so we get
	 * around many of the rules that govern object creation
	 */
	p11_index_load (index);

	/* A certificate */
	if (p11_attrs_match (attrs, match_cert)) {
		replace_compat_for_cert (builder, index, handle, attrs);

	/* An ExtendedKeyUsage extension */
	} else if (p11_attrs_match (attrs, match_eku) ||
	           p11_attrs_match (attrs, match_ku)) {
		replace_compat_for_ext (builder, index, handle, attrs);

	/* A BasicConstraints extension */
	} else if (p11_attrs_match (attrs, match_bc)) {
		update_related_category (builder, index, handle, attrs);
	}

	p11_index_finish (index);
}
