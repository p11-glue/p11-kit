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

#include "attrs.h"
#include "checksum.h"
#define P11_DEBUG_FLAG P11_DEBUG_TRUST
#include "debug.h"
#include "dict.h"
#include "library.h"
#include "module.h"
#include "parser.h"
#include "pkcs11x.h"

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

#include "pkix.asn.h"

struct _p11_parser {
	node_asn *pkix_definitions;
	p11_parser_sink sink;
	void *sink_data;
	const char *probable_label;
	int flags;
};

typedef int (* parser_func)   (p11_parser *parser,
                               const unsigned char *data,
                               size_t length);

static node_asn *
decode_asn1 (p11_parser *parser,
             const char *struct_name,
             const unsigned char *data,
             size_t length,
             char *message)
{
	char msg[ASN1_MAX_ERROR_DESCRIPTION_SIZE];
	node_asn *definitions;
	node_asn *el = NULL;
	int ret;

	if (message == NULL)
		message = msg;

	if (strncmp (struct_name, "PKIX1.", 6) == 0) {
		definitions = parser->pkix_definitions;

	} else {
		p11_debug_precond ("unknown prefix for element: %s", struct_name);
		return NULL;
	}

	ret = asn1_create_element (definitions, struct_name, &el);
	if (ret != ASN1_SUCCESS) {
		p11_debug_precond ("failed to create element %s at %s: %d",
		                   struct_name, __func__, ret);
		return NULL;
	}

	return_val_if_fail (ret == ASN1_SUCCESS, NULL);

	/* asn1_der_decoding destroys the element if fails */
	ret = asn1_der_decoding (&el, data, length, message);

	if (ret != ASN1_SUCCESS) {
		p11_debug ("couldn't parse %s: %s: %s",
		           struct_name, asn1_strerror (ret), message);
		return NULL;
	}

	return el;
}

static void
sink_object (p11_parser *parser,
             CK_ATTRIBUTE *attrs)
{
	if (parser->sink)
		(parser->sink) (attrs, parser->sink_data);
	else
		p11_attrs_free (attrs);
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
              CK_ATTRIBUTE *attrs,
              CK_OBJECT_CLASS vclass,
              CK_BYTE *vid,
              const char *explicit_label)
{
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

static int
two_to_four_digit_year (int year)
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
			return century + year;
		if (year > 100 - (40 - current))
			return (century - 100) + year;
	} else {
		if (year < current && year > (current - 40))
			return century + year;
	}

	/*
	 * If it's after then adjust for overflows to
	 * the next century.
	 */
	if (year < current)
		return century + 100 + year;
	else
		return century + year;
}

static bool
parse_utc_time (const char *time,
                size_t n_time,
                struct tm *when,
                int *offset)
{
	const char *p, *e;
	int year;

	assert (when != NULL);
	assert (time != NULL);
	assert (offset != NULL);

	/* YYMMDDhhmmss.ffff Z | +0000 */
	if (n_time < 6 || n_time >= 28)
		return false;

	/* Reset everything to default legal values */
	memset (when, 0, sizeof (*when));
	*offset = 0;
	when->tm_mday = 1;

	/* Select the digits part of it */
	p = time;
	for (e = p; *e >= '0' && *e <= '9'; ++e);

	if (p + 2 <= e) {
		year = atoin (p, 2);
		p += 2;

		/*
		 * 40 years in the past is our century. 60 years
		 * in the future is the next century.
		 */
		when->tm_year = two_to_four_digit_year (year) - 1900;
	}
	if (p + 2 <= e) {
		when->tm_mon = atoin (p, 2) - 1;
		p += 2;
	}
	if (p + 2 <= e) {
		when->tm_mday = atoin (p, 2);
		p += 2;
	}
	if (p + 2 <= e) {
		when->tm_hour = atoin (p, 2);
		p += 2;
	}
	if (p + 2 <= e) {
		when->tm_min = atoin (p, 2);
		p += 2;
	}
	if (p + 2 <= e) {
		when->tm_sec = atoin (p, 2);
		p += 2;
	}

	if (when->tm_year < 0 || when->tm_year > 9999 ||
	    when->tm_mon < 0 || when->tm_mon > 11 ||
	    when->tm_mday < 1 || when->tm_mday > 31 ||
	    when->tm_hour < 0 || when->tm_hour > 23 ||
	    when->tm_min < 0 || when->tm_min > 59 ||
	    when->tm_sec < 0 || when->tm_sec > 59)
		return false;

	/* Make sure all that got parsed */
	if (p != e)
		return false;

	/* Now the remaining optional stuff */
	e = time + n_time;

	/* See if there's a fraction, and discard it if so */
	if (p < e && *p == '.' && p + 5 <= e)
		p += 5;

	/* See if it's UTC */
	if (p < e && *p == 'Z') {
		p += 1;

	/* See if it has a timezone */
	} else if ((*p == '-' || *p == '+') && p + 3 <= e) {
		int off, neg;

		neg = *p == '-';
		++p;

		off = atoin (p, 2) * 3600;
		if (off < 0 || off > 86400)
			return false;
		p += 2;

		if (p + 2 <= e) {
			off += atoin (p, 2) * 60;
			p += 2;
		}

		/* Use TZ offset */
		if (neg)
			*offset = 0 - off;
		else
			*offset = off;
	}

	/* Make sure everything got parsed */
	if (p != e)
		return false;

	return true;
}

static bool
parse_general_time (const char *time,
                    size_t n_time,
                    struct tm *when,
                    int *offset)
{
	const char *p, *e;

	assert (time != NULL);
	assert (when != NULL);
	assert (offset != NULL);

	/* YYYYMMDDhhmmss.ffff Z | +0000 */
	if (n_time < 8 || n_time >= 30)
		return false;

	/* Reset everything to default legal values */
	memset (when, 0, sizeof (*when));
	*offset = 0;
	when->tm_mday = 1;

	/* Select the digits part of it */
	p = time;
	for (e = p; *e >= '0' && *e <= '9'; ++e);

	if (p + 4 <= e) {
		when->tm_year = atoin (p, 4) - 1900;
		p += 4;
	}
	if (p + 2 <= e) {
		when->tm_mon = atoin (p, 2) - 1;
		p += 2;
	}
	if (p + 2 <= e) {
		when->tm_mday = atoin (p, 2);
		p += 2;
	}
	if (p + 2 <= e) {
		when->tm_hour = atoin (p, 2);
		p += 2;
	}
	if (p + 2 <= e) {
		when->tm_min = atoin (p, 2);
		p += 2;
	}
	if (p + 2 <= e) {
		when->tm_sec = atoin (p, 2);
		p += 2;
	}

	if (when->tm_year < 0 || when->tm_year > 9999 ||
	    when->tm_mon < 0 || when->tm_mon > 11 ||
	    when->tm_mday < 1 || when->tm_mday > 31 ||
	    when->tm_hour < 0 || when->tm_hour > 23 ||
	    when->tm_min < 0 || when->tm_min > 59 ||
	    when->tm_sec < 0 || when->tm_sec > 59)
		return false;

	/* Make sure all that got parsed */
	if (p != e)
		return false;

	/* Now the remaining optional stuff */
	e = time + n_time;

	/* See if there's a fraction, and discard it if so */
	if (p < e && *p == '.' && p + 5 <= e)
		p += 5;

	/* See if it's UTC */
	if (p < e && *p == 'Z') {
		p += 1;

	/* See if it has a timezone */
	} else if ((*p == '-' || *p == '+') && p + 3 <= e) {
		int off, neg;

		neg = *p == '-';
		++p;

		off = atoin (p, 2) * 3600;
		if (off < 0 || off > 86400)
			return false;
		p += 2;

		if (p + 2 <= e) {
			off += atoin (p, 2) * 60;
			p += 2;
		}

		/* Use TZ offset */
		if (neg)
			*offset = 0 - off;
		else
			*offset = off;
	}

	/* Make sure everything got parsed */
	if (p != e)
		return false;

	return true;
}

static bool
calc_date (node_asn *cert,
           const char *field,
           CK_DATE *date)
{
	node_asn *choice;
	struct tm when;
	int tz_offset;
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
		if (!parse_general_time (buf, len, &when, &tz_offset))
			return_val_if_reached (false);

	} else if (strcmp (buf, "utcTime") == 0) {
		len = sizeof (buf) - 1;
		ret = asn1_read_value (cert, sub, buf, &len);
		return_val_if_fail (ret == ASN1_SUCCESS, false);
		if (!parse_utc_time (buf, len - 1, &when, &tz_offset))
			return_val_if_reached (false);

	} else {
		return_val_if_reached (false);
	}

	free (sub);

	/* In order to work with 32 bit time_t. */
	if (sizeof (time_t) <= 4 && when.tm_year >= 2038) {
		timet = (time_t)2145914603;  /* 2037-12-31 23:23:23 */

	/* Convert to seconds since epoch */
	} else {
		timet = timegm (&when);
		return_val_if_fail (timet >= 0, false);
		timet += tz_offset;
	}

	if (!gmtime_r (&timet, &when))
		return_val_if_reached (false);

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
calc_trusted (p11_parser *parser,
              node_asn *cert,
              CK_BBOOL *vtrusted)
{
	assert (parser != NULL);
	assert (vtrusted != NULL);

	/*
	 * This calculates CKA_TRUSTED, which is a silly attribute, don't
	 * read too much into this. The real trust mechinisms are elsewhere.
	 */

	*vtrusted = CK_FALSE;
	if (parser->flags & P11_PARSE_FLAG_ANCHOR) {
		*vtrusted = CK_TRUE;
		return true;
	}

	/* Don't add this attribute unless anchor */
	return false;
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
                        CK_ATTRIBUTE *attrs,
                        node_asn *cert,
                        const unsigned char *data,
                        size_t length)
{
	CK_CERTIFICATE_TYPE vx509 = CKC_X_509;
	CK_BYTE vchecksum[3];

	/* TODO: Implement */
	CK_ULONG vcategory = 0;
	CK_BBOOL vtrusted = CK_FALSE;
	CK_DATE vstart;
	CK_DATE vend;

	CK_ATTRIBUTE certificate_type = { CKA_CERTIFICATE_TYPE, &vx509, sizeof (vx509) };
	CK_ATTRIBUTE certificate_category = { CKA_CERTIFICATE_CATEGORY, &vcategory, sizeof (vcategory) };
	CK_ATTRIBUTE value = { CKA_VALUE, (void *)data, length };

	CK_ATTRIBUTE check_value = { CKA_CHECK_VALUE, &vchecksum, sizeof (vchecksum) };
	CK_ATTRIBUTE trusted = { CKA_TRUSTED, &vtrusted, sizeof (vtrusted) };
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

	/* This is a silly trust flag, we set it if the cert is an anchor */
	if (!calc_trusted (parser, cert, &vtrusted))
		trusted.type = CKA_INVALID;

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

	return p11_attrs_build (attrs, &certificate_type, &certificate_category,
	                        &check_value, &trusted, &start_date, &end_date,
	                        &subject, &issuer, &serial_number, &value,
	                        NULL);
}

static unsigned char *
find_extension (node_asn *cert,
                const char *extension_oid,
                size_t *length)
{
	unsigned char *data = NULL;
	char field[128];
	char oid[128];
	int len;
	int ret;
	int i;

	assert (extension_oid != NULL);
	assert (strlen (extension_oid) < sizeof (oid));

	for (i = 1; ; i++) {
		if (snprintf (field, sizeof (field), "tbsCertificate.extensions.?%u.extnID", i) < 0)
			return_val_if_reached (NULL);

		len = sizeof (oid) - 1;
		ret = asn1_read_value (cert, field, oid, &len);

		/* No more extensions */
		if (ret == ASN1_ELEMENT_NOT_FOUND)
			break;

		/* A really, really long extension oid, not looking for it */
		else if (ret == ASN1_MEM_ERROR)
			continue;

		return_val_if_fail (ret == ASN1_SUCCESS, NULL);

		/* The one we're lookin for? */
		if (strcmp (oid, extension_oid) != 0)
			continue;

		if (snprintf (field, sizeof (field), "tbsCertificate.extensions.?%u.extnValue", i) < 0)
			return_val_if_reached (NULL);

		len = 0;
		ret = asn1_read_value (cert, field, NULL, &len);
		return_val_if_fail (ret == ASN1_MEM_ERROR, NULL);

		data = malloc (len);
		return_val_if_fail (data != NULL, NULL);

		ret = asn1_read_value (cert, field, data, &len);
		return_val_if_fail (ret == ASN1_SUCCESS, NULL);

		*length = len;
		break;
	}

	return data;
}

int
p11_parse_key_usage (p11_parser *parser,
                     const unsigned char *data,
                     size_t length,
                     unsigned int *ku)
{
	char message[ASN1_MAX_ERROR_DESCRIPTION_SIZE] = { 0, };
	unsigned char buf[2];
	node_asn *ext;
	int len;
	int ret;

	ext = decode_asn1 (parser, "PKIX1.KeyUsage", data, length, message);
	if (ext == NULL)
		return P11_PARSE_UNRECOGNIZED;

	len = sizeof (buf);
	ret = asn1_read_value (ext, "", buf, &len);
	return_val_if_fail (ret == ASN1_SUCCESS, P11_PARSE_FAILURE);

	/* A bit string, so combine into one set of flags */
	*ku = buf[0] | (buf[1] << 8);

	asn1_delete_structure (&ext);

	return P11_PARSE_SUCCESS;
}

static unsigned int
decode_ku (p11_parser *parser,
           node_asn *cert)
{
	unsigned char *data;
	size_t length;
	unsigned int ku;

	/*
	 * If the certificate extension was missing, then *all* key
	 * usages are to be set. If the extension was invalid, then
	 * fail safe to none of the key usages.
	 */

	data = find_extension (cert, "2.5.29.15", &length);

	if (!data)
		return ~0U;

	if (p11_parse_key_usage (parser, data, length, &ku) != P11_PARSE_SUCCESS) {
		p11_message ("invalid key usage certificate extension");
		ku = 0U;
	}

	free (data);

	return ku;
}

int
p11_parse_extended_key_usage (p11_parser *parser,
                              const unsigned char *data,
                              size_t length,
                              p11_dict *ekus)
{
	node_asn *ext;
	char field[128];
	char *eku;
	int len;
	int ret;
	int i;

	ext = decode_asn1 (parser, "PKIX1.ExtKeyUsageSyntax", data, length, NULL);
	if (ext == NULL)
		return P11_PARSE_UNRECOGNIZED;

	for (i = 1; ; i++) {
		if (snprintf (field, sizeof (field), "?%u", i) < 0)
			return_val_if_reached (P11_PARSE_FAILURE);

		len = 0;
		ret = asn1_read_value (ext, field, NULL, &len);
		if (ret == ASN1_ELEMENT_NOT_FOUND)
			break;

		return_val_if_fail (ret == ASN1_MEM_ERROR, P11_PARSE_FAILURE);

		eku = malloc (len + 1);
		return_val_if_fail (eku != NULL, P11_PARSE_FAILURE);

		ret = asn1_read_value (ext, field, eku, &len);
		return_val_if_fail (ret == ASN1_SUCCESS, P11_PARSE_FAILURE);

		if (!p11_dict_set (ekus, eku, eku))
			return_val_if_reached (P11_PARSE_FAILURE);
	}

	asn1_delete_structure (&ext);

	return P11_PARSE_SUCCESS;

}

static p11_dict *
decode_eku (p11_parser *parser,
            node_asn *cert)
{
	unsigned char *data;
	p11_dict *ekus;
	char *eku;
	size_t length;

	ekus = p11_dict_new (p11_dict_str_hash, p11_dict_str_equal, free, NULL);
	return_val_if_fail (ekus != NULL, NULL);

	/*
	 * If the certificate extension was missing, then *all* extended key
	 * usages are to be set. If the extension was invalid, then
	 * fail safe to none of the extended key usages.
	 */

	data = find_extension (cert, "2.5.29.37", &length);
	if (data) {
		if (p11_parse_extended_key_usage (parser, data, length, ekus) != P11_PARSE_SUCCESS) {
			p11_message ("invalid extended key usage certificate extension");
			p11_dict_free (ekus);
			ekus = NULL;
		}
	} else {
		/* A star means anything to has_eku() */
		eku = strdup ("*");
		if (!eku || !p11_dict_set (ekus, eku, eku))
			return_val_if_reached (NULL);
	}

	free (data);

	return ekus;
}

static int
has_eku (p11_dict *ekus,
         const char *eku)
{
	return ekus != NULL && /* If a "*" present, then any thing allowed */
	       (p11_dict_get (ekus, eku) || p11_dict_get (ekus, "*"));
}

static CK_ATTRIBUTE *
build_nss_trust_object (p11_parser *parser,
                        CK_ATTRIBUTE *attrs,
                        node_asn *cert,
                        const unsigned char *data,
                        size_t length)
{
	CK_BYTE vsha1_hash[P11_CHECKSUM_SHA1_LENGTH];
	CK_BYTE vmd5_hash[P11_CHECKSUM_MD5_LENGTH];
	CK_BBOOL vfalse = CK_FALSE;

	CK_TRUST vdigital_signature;
	CK_TRUST vnon_repudiation;
	CK_TRUST vkey_encipherment;
	CK_TRUST vdata_encipherment;
	CK_TRUST vkey_agreement;
	CK_TRUST vkey_cert_sign;
	CK_TRUST vcrl_sign;

	CK_TRUST vserver_auth;
	CK_TRUST vclient_auth;
	CK_TRUST vcode_signing;
	CK_TRUST vemail_protection;
	CK_TRUST vipsec_end_system;
	CK_TRUST vipsec_tunnel;
	CK_TRUST vipsec_user;
	CK_TRUST vtime_stamping;

	CK_ATTRIBUTE subject = { CKA_SUBJECT, };
	CK_ATTRIBUTE issuer = { CKA_ISSUER, };
	CK_ATTRIBUTE serial_number = { CKA_SERIAL_NUMBER, };

	CK_ATTRIBUTE md5_hash = { CKA_CERT_MD5_HASH, vmd5_hash, sizeof (vmd5_hash) };
	CK_ATTRIBUTE sha1_hash = { CKA_CERT_SHA1_HASH, vsha1_hash, sizeof (vsha1_hash) };

	CK_ATTRIBUTE digital_signature = { CKA_TRUST_DIGITAL_SIGNATURE, &vdigital_signature, sizeof (vdigital_signature) };
	CK_ATTRIBUTE non_repudiation = { CKA_TRUST_NON_REPUDIATION, &vnon_repudiation, sizeof (vnon_repudiation) };
	CK_ATTRIBUTE key_encipherment = { CKA_TRUST_KEY_ENCIPHERMENT, &vkey_encipherment, sizeof (vkey_encipherment) };
	CK_ATTRIBUTE data_encipherment = { CKA_TRUST_DATA_ENCIPHERMENT, &vdata_encipherment, sizeof (vdata_encipherment) };
	CK_ATTRIBUTE key_agreement = { CKA_TRUST_KEY_AGREEMENT, &vkey_agreement, sizeof (vkey_agreement) };
	CK_ATTRIBUTE key_cert_sign = { CKA_TRUST_KEY_CERT_SIGN, &vkey_cert_sign, sizeof (vkey_cert_sign) };
	CK_ATTRIBUTE crl_sign = { CKA_TRUST_CRL_SIGN, &vcrl_sign, sizeof (vcrl_sign) };

	CK_ATTRIBUTE server_auth = { CKA_TRUST_SERVER_AUTH, &vserver_auth, sizeof (vserver_auth) };
	CK_ATTRIBUTE client_auth = { CKA_TRUST_CLIENT_AUTH, &vclient_auth, sizeof (vclient_auth) };
	CK_ATTRIBUTE code_signing = { CKA_TRUST_CODE_SIGNING, &vcode_signing, sizeof (vcode_signing) };
	CK_ATTRIBUTE email_protection = { CKA_TRUST_EMAIL_PROTECTION, &vemail_protection, sizeof (vemail_protection) };
	CK_ATTRIBUTE ipsec_end_system = { CKA_TRUST_IPSEC_END_SYSTEM, &vipsec_end_system, sizeof (vipsec_end_system) };
	CK_ATTRIBUTE ipsec_tunnel = { CKA_TRUST_IPSEC_TUNNEL, &vipsec_tunnel, sizeof (vipsec_tunnel) };
	CK_ATTRIBUTE ipsec_user = { CKA_TRUST_IPSEC_USER, &vipsec_user, sizeof (vipsec_user) };
	CK_ATTRIBUTE time_stamping = { CKA_TRUST_TIME_STAMPING, &vtime_stamping, sizeof (vtime_stamping) };

	CK_ATTRIBUTE step_up_approved = { CKA_TRUST_STEP_UP_APPROVED, &vfalse, sizeof (vfalse) };

	p11_dict *ekus;
	unsigned int ku;
	CK_TRUST value;
	CK_TRUST unknown;

	if (!calc_element (cert, data, length, "tbsCertificate.issuer.rdnSequence", &issuer))
		issuer.type = CKA_INVALID;
	if (!calc_element (cert, data, length, "tbsCertificate.subject.rdnSequence", &subject))
		subject.type = CKA_INVALID;
	if (!calc_element (cert, data, length, "tbsCertificate.serialNumber", &serial_number))
		serial_number.type = CKA_INVALID;

	p11_checksum_md5 (vmd5_hash, data, length, NULL);
	p11_checksum_sha1 (vsha1_hash, data, length, NULL);

	unknown = CKT_NETSCAPE_TRUST_UNKNOWN;
	if (parser->flags & P11_PARSE_FLAG_ANCHOR)
		value = CKT_NETSCAPE_TRUSTED_DELEGATOR;
	else
		value = CKT_NETSCAPE_TRUSTED;

	ku = decode_ku (parser, cert);
	vdigital_signature = (ku & P11_KU_DIGITAL_SIGNATURE) ? value : unknown;
	vnon_repudiation = (ku & P11_KU_NON_REPUDIATION) ? value : unknown;
	vkey_encipherment = (ku & P11_KU_KEY_ENCIPHERMENT) ? value : unknown;
	vkey_agreement = (ku & P11_KU_KEY_AGREEMENT) ? value : unknown;
	vkey_cert_sign = (ku & P11_KU_KEY_CERT_SIGN) ? value : unknown;
	vcrl_sign = (ku & P11_KU_CRL_SIGN) ? value : unknown;

	ekus = decode_eku (parser, cert);
	vserver_auth = has_eku (ekus, P11_EKU_SERVER_AUTH) ? value : unknown;
	vclient_auth = has_eku (ekus, P11_EKU_CLIENT_AUTH) ? value : unknown;
	vcode_signing = has_eku (ekus, P11_EKU_CODE_SIGNING) ? value : unknown;
	vemail_protection = has_eku (ekus, P11_EKU_EMAIL) ? value : unknown;
	vipsec_end_system = has_eku (ekus, P11_EKU_IPSEC_END_SYSTEM) ? value : unknown;
	vipsec_tunnel = has_eku (ekus, P11_EKU_IPSEC_TUNNEL) ? value : unknown;
	vipsec_user = has_eku (ekus, P11_EKU_IPSEC_USER) ? value : unknown;
	vtime_stamping = has_eku (ekus, P11_EKU_TIME_STAMPING) ? value : unknown;
	p11_dict_free (ekus);

	return p11_attrs_build (attrs, &subject, &issuer, &serial_number, &md5_hash, &sha1_hash,
	                        &digital_signature, &non_repudiation, &key_encipherment,
	                        &data_encipherment, &key_agreement, &key_cert_sign, &crl_sign,
	                        &server_auth, &client_auth, &code_signing, &email_protection,
	                        &ipsec_end_system, &ipsec_tunnel, &ipsec_user, &time_stamping,
	                        &step_up_approved, NULL);

}

static int
sink_nss_trust_object (p11_parser *parser,
                       CK_BYTE *vid,
                       node_asn *cert,
                       const unsigned char *data,
                       size_t length)
{
	CK_ATTRIBUTE *attrs = NULL;

	attrs = build_object (parser, attrs, CKO_NETSCAPE_TRUST, vid, NULL);
	return_val_if_fail (attrs != NULL, P11_PARSE_FAILURE);

	attrs = build_nss_trust_object (parser, attrs, cert, data, length);
	return_val_if_fail (attrs != NULL, P11_PARSE_FAILURE);

	sink_object (parser, attrs);
	return P11_PARSE_SUCCESS;
}

static int
sink_x509_certificate (p11_parser *parser,
                       CK_BYTE *vid,
                       node_asn *cert,
                       const unsigned char *data,
                       size_t length)
{
	CK_ATTRIBUTE *attrs = NULL;

	attrs = build_object (parser, attrs, CKO_CERTIFICATE, vid, NULL);
	return_val_if_fail (attrs != NULL, P11_PARSE_FAILURE);

	attrs = build_x509_certificate (parser, attrs, cert, data, length);
	return_val_if_fail (attrs != NULL, P11_PARSE_FAILURE);

	sink_object (parser, attrs);
	return P11_PARSE_SUCCESS;
}

static int
parse_der_x509_certificate (p11_parser *parser,
                            const unsigned char *data,
                            size_t length)
{
	CK_BYTE vid[ID_LENGTH];
	node_asn *cert;
	int ret;

	cert = decode_asn1 (parser, "PKIX1.Certificate", data, length, NULL);
	if (cert == NULL)
		return P11_PARSE_UNRECOGNIZED;

	/* The CKA_ID links related objects */
	id_generate (parser, vid);

	ret = sink_x509_certificate (parser, vid, cert, data, length);
	return_val_if_fail (ret == P11_PARSE_SUCCESS, ret);

	ret = sink_nss_trust_object (parser, vid, cert, data, length);
	return_val_if_fail (ret == P11_PARSE_SUCCESS, ret);

	asn1_delete_structure (&cert);
	return P11_PARSE_SUCCESS;
}

static parser_func all_parsers[] = {
	parse_der_x509_certificate,
	NULL,
};

p11_parser *
p11_parser_new (void)
{
	char message[ASN1_MAX_ERROR_DESCRIPTION_SIZE] = { 0, };
	node_asn *definitions = NULL;
	p11_parser *parser;
	int ret;

	ret = asn1_array2tree (pkix_asn1_tab, &definitions, message);
	if (ret != ASN1_SUCCESS) {
		p11_debug_precond ("failed to load pkix_asn1_tab in %s: %d %s",
		                   __func__, ret, message);
		return NULL;
	}

	parser = calloc (1, sizeof (p11_parser));
	return_val_if_fail (parser != NULL, NULL);

	parser->pkix_definitions = definitions;
	return parser;
}

void
p11_parser_free (p11_parser *parser)
{
	if (!parser)
		return;

	asn1_delete_structure (&parser->pkix_definitions);
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
