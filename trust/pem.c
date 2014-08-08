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

#include "compat.h"
#include "base64.h"
#include "buffer.h"
#include "debug.h"
#include "pem.h"

#include <assert.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#define ARMOR_SUFF          "-----"
#define ARMOR_SUFF_L        5
#define ARMOR_PREF_BEGIN    "-----BEGIN "
#define ARMOR_PREF_BEGIN_L  11
#define ARMOR_PREF_END      "-----END "
#define ARMOR_PREF_END_L    9

enum {
	NONE = 0,
	TRUSTED_CERTIFICATE,
	CERTIFICATE
};

static const char *
pem_find_begin (const char *data,
                size_t n_data,
                char **type)
{
	const char *pref, *suff;

	/* Look for a prefix */
	pref = strnstr ((char *)data, ARMOR_PREF_BEGIN, n_data);
	if (!pref)
		return NULL;

	n_data -= (pref - data) + ARMOR_PREF_BEGIN_L;
	data = pref + ARMOR_PREF_BEGIN_L;

	/* Look for the end of that begin */
	suff = strnstr ((char *)data, ARMOR_SUFF, n_data);
	if (!suff)
		return NULL;

	/* Make sure on the same line */
	if (memchr (pref, '\n', suff - pref))
		return NULL;

	if (type) {
		pref += ARMOR_PREF_BEGIN_L;
		assert (suff > pref);
		*type = strndup (pref, suff - pref);
		return_val_if_fail (*type != NULL, NULL);
	}

	/* The byte after this ---BEGIN--- */
	return suff + ARMOR_SUFF_L;
}

static const char *
pem_find_end (const char *data,
              size_t n_data,
              const char *type)
{
	const char *pref;
	size_t n_type;

	/* Look for a prefix */
	pref = strnstr (data, ARMOR_PREF_END, n_data);
	if (!pref)
		return NULL;

	n_data -= (pref - data) + ARMOR_PREF_END_L;
	data = pref + ARMOR_PREF_END_L;

	/* Next comes the type string */
	n_type = strlen (type);
	if (n_type > n_data || strncmp ((char *)data, type, n_type) != 0)
		return NULL;

	n_data -= n_type;
	data += n_type;

	/* Next comes the suffix */
	if (ARMOR_SUFF_L > n_data || strncmp ((char *)data, ARMOR_SUFF, ARMOR_SUFF_L) != 0)
		return NULL;

	/* The end of the data */
	return pref;
}

static unsigned char *
pem_parse_block (const char *data,
                 size_t n_data,
                 size_t *n_decoded)
{
	const char *x, *hbeg, *hend;
	const char *p, *end;
	unsigned char *decoded;
	size_t length;
	int ret;

	assert (data != NULL);
	assert (n_data != 0);
	assert (n_decoded != NULL);

	p = data;
	end = p + n_data;

	hbeg = hend = NULL;

	/* Try and find a pair of blank lines with only white space between */
	while (hend == NULL) {
		x = memchr (p, '\n', end - p);
		if (!x)
			break;
		++x;
		while (isspace (*x)) {
			/* Found a second line, with only spaces between */
			if (*x == '\n') {
				hbeg = data;
				hend = x;
				break;
			/* Found a space between two lines */
			} else {
				++x;
			}
		}

		/* Try next line */
		p = x;
	}

	/* Headers found? */
	if (hbeg && hend) {
		data = hend;
		n_data = end - data;
	}

	length = (n_data * 3) / 4 + 1;
	decoded = malloc (length);
	return_val_if_fail (decoded != NULL, 0);

	ret = p11_b64_pton (data, n_data, decoded, length);
	if (ret < 0) {
		free (decoded);
		return NULL;
	}

	/* No need to parse headers for our use cases */

	*n_decoded = ret;
	return decoded;
}

unsigned int
p11_pem_parse (const char *data,
               size_t n_data,
               p11_pem_sink sink,
               void *user_data)
{
	const char *beg, *end;
	unsigned int nfound = 0;
	unsigned char *decoded = NULL;
	size_t n_decoded = 0;
	char *type;

	assert (data != NULL);

	while (n_data > 0) {

		/* This returns the first character after the PEM BEGIN header */
		beg = pem_find_begin (data, n_data, &type);
		if (beg == NULL)
			break;

		assert (type != NULL);

		/* This returns the character position before the PEM END header */
		end = pem_find_end (beg, n_data - (beg - data), type);
		if (end == NULL) {
			free (type);
			break;
		}

		if (beg != end) {
			decoded = pem_parse_block (beg, end - beg, &n_decoded);
			if (decoded) {
				if (sink != NULL)
					(sink) (type, decoded, n_decoded, user_data);
				++nfound;
				free (decoded);
			}
		}

		free (type);

		/* Try for another block */
		end += ARMOR_SUFF_L;
		n_data -= (const char *)end - (const char *)data;
		data = end;
	}

	return nfound;
}

bool
p11_pem_write (const unsigned char *contents,
               size_t length,
               const char *type,
               p11_buffer *buf)
{
	size_t estimate;
	size_t prefix;
	char *target;
	int len;

	return_val_if_fail (contents || !length, false);
	return_val_if_fail (type, false);
	return_val_if_fail (buf, false);

	/* Estimate from base64 data. Algorithm from Glib reference */
	estimate = length * 4 / 3 + 7;
	estimate += estimate / 64 + 1;

	p11_buffer_add (buf, ARMOR_PREF_BEGIN, ARMOR_PREF_BEGIN_L);
	p11_buffer_add (buf, type, -1);
	p11_buffer_add (buf, ARMOR_SUFF, ARMOR_SUFF_L);

	prefix = buf->len;
	target = p11_buffer_append (buf, estimate);
	return_val_if_fail (target != NULL, NULL);

	/*
	 * OpenSSL is absolutely certain that it wants its PEM base64
	 * lines to be 64 characters in len.
	 */

	len = p11_b64_ntop (contents, length, target, estimate, 64);

	assert (len > 0);
	assert (len <= estimate);
	buf->len = prefix + len;

	p11_buffer_add (buf, "\n", 1);
	p11_buffer_add (buf, ARMOR_PREF_END, ARMOR_PREF_END_L);
	p11_buffer_add (buf, type, -1);
	p11_buffer_add (buf, ARMOR_SUFF, ARMOR_SUFF_L);
	p11_buffer_add (buf, "\n", 1);

	return p11_buffer_ok (buf);
}
