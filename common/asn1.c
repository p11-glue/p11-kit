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

#include "openssl.asn.h"
#include "pkix.asn.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

static void
free_asn1_def (void *data)
{
	node_asn *def = data;
	asn1_delete_structure (&def);
}

struct {
	const ASN1_ARRAY_TYPE* tab;
	const char *prefix;
	int prefix_len;
} asn1_tabs[] = {
	{ pkix_asn1_tab, "PKIX1.", 6 },
	{ openssl_asn1_tab, "OPENSSL.", 8 },
	{ NULL, },
};

p11_dict *
p11_asn1_defs_load (void)
{
	char message[ASN1_MAX_ERROR_DESCRIPTION_SIZE] = { 0, };
	node_asn *def;
	p11_dict *defs;
	int ret;
	int i;

	defs = p11_dict_new (p11_dict_str_hash, p11_dict_str_equal, NULL, free_asn1_def);

	for (i = 0; asn1_tabs[i].tab != NULL; i++) {

		def = NULL;
		ret = asn1_array2tree (asn1_tabs[i].tab, &def, message);
		if (ret != ASN1_SUCCESS) {
			p11_debug_precond ("failed to load %s* definitions: %s: %s\n",
			                   asn1_tabs[i].prefix, asn1_strerror (ret), message);
			return NULL;
		}

		if (!p11_dict_set (defs, (void *)asn1_tabs[i].prefix, def))
			return_val_if_reached (NULL);
	}

	return defs;
}

static node_asn *
lookup_def (p11_dict *asn1_defs,
            const char *struct_name)
{
	int i;

	for (i = 0; asn1_tabs[i].tab != NULL; i++) {
		if (strncmp (struct_name, asn1_tabs[i].prefix, asn1_tabs[i].prefix_len) == 0)
			return p11_dict_get (asn1_defs, asn1_tabs[i].prefix);
	}

	p11_debug_precond ("unknown prefix for element: %s\n", struct_name);
	return NULL;
}

node_asn *
p11_asn1_create (p11_dict *asn1_defs,
                 const char *struct_name)
{
	node_asn *def;
	node_asn *asn;
	int ret;

	return_val_if_fail (asn1_defs != NULL, NULL);

	def = lookup_def (asn1_defs, struct_name);
	return_val_if_fail (def != NULL, NULL);

	ret = asn1_create_element (def, struct_name, &asn);
	if (ret != ASN1_SUCCESS) {
		p11_debug_precond ("failed to create element %s: %s\n",
		                   struct_name, asn1_strerror (ret));
		return NULL;
	}

	return asn;
}

node_asn *
p11_asn1_decode (p11_dict *asn1_defs,
                 const char *struct_name,
                 const unsigned char *der,
                 size_t der_len,
                 char *message)
{
	char msg[ASN1_MAX_ERROR_DESCRIPTION_SIZE];
	node_asn *asn = NULL;
	int ret;

	return_val_if_fail (asn1_defs != NULL, NULL);

	if (message == NULL)
		message = msg;

	asn = p11_asn1_create (asn1_defs, struct_name);
	return_val_if_fail (asn != NULL, NULL);

	/* asn1_der_decoding destroys the element if fails */
	ret = asn1_der_decoding (&asn, der, der_len, message);

	if (ret != ASN1_SUCCESS) {
		p11_debug ("couldn't parse %s: %s: %s",
		           struct_name, asn1_strerror (ret), message);
		return NULL;
	}

	return asn;
}

unsigned char *
p11_asn1_encode (node_asn *asn,
                 size_t *der_len)
{
	char message[ASN1_MAX_ERROR_DESCRIPTION_SIZE];
	unsigned char *der;
	int len;
	int ret;

	return_val_if_fail (der_len != NULL, NULL);

	len = 0;
	ret = asn1_der_coding (asn, "", NULL, &len, message);
	return_val_if_fail (ret != ASN1_SUCCESS, NULL);

	if (ret == ASN1_MEM_ERROR) {
		der = malloc (len);
		return_val_if_fail (der != NULL, NULL);

		ret = asn1_der_coding (asn, "", der, &len, message);
	}

	if (ret != ASN1_SUCCESS) {
		p11_debug_precond ("failed to encode: %s\n", message);
		return NULL;
	}

	if (der_len)
		*der_len = len;
	return der;
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

static int
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
		return 0;

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
		return 0;

	/* Make sure all that got parsed */
	if (p != e)
		return 0;

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
			return 0;
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
		return 0;

	return 1;
}

static int
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
		return 0;

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
		return 0;

	/* Make sure all that got parsed */
	if (p != e)
		return 0;

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
			return 0;
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
		return 0;

	return 1;
}

static time_t
when_and_offset_to_time_t (struct tm *when,
                           int tz_offset)
{
	time_t timet;

	/* In order to work with 32 bit time_t. */
	if (sizeof (time_t) <= 4 && when->tm_year >= 2038) {
		timet = (time_t)2145914603;  /* 2037-12-31 23:23:23 */

	/* Convert to seconds since epoch */
	} else {
		timet = timegm (when);
		return_val_if_fail (timet >= 0, -1);
		timet += tz_offset;
	}

	if (!gmtime_r (&timet, when))
		return_val_if_reached (-1);

	return timet;
}

time_t
p11_asn1_parse_utc (const char *time_str,
                    struct tm *when)
{
	struct tm dummy;
	int tz_offset;
	int ret;

	if (!when)
		when = &dummy;

	ret = parse_utc_time (time_str, strlen (time_str),
	                      when, &tz_offset);
	if (!ret)
		return -1;

	return when_and_offset_to_time_t (when, tz_offset);
}

time_t
p11_asn1_parse_general (const char *time_str,
                        struct tm *when)
{
	struct tm dummy;
	int tz_offset;
	int ret;

	if (!when)
		when = &dummy;

	ret = parse_general_time (time_str, strlen (time_str),
	                          when, &tz_offset);
	if (!ret)
		return -1;

	return when_and_offset_to_time_t (when, tz_offset);
}

ssize_t
p11_asn1_tlv_length (const unsigned char *data,
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
