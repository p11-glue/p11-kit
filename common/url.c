/*
 * Copyright (C) 2011 Collabora Ltd.
 * Copyright (C) 2013 Red Hat Inc.
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
 * Author: Stef Walter <stefw@collabora.co.uk>
 */

#include "config.h"

#include "debug.h"
#include "url.h"

#include <assert.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

const static char HEX_CHARS[] = "0123456789abcdef";

unsigned char *
p11_url_decode (const char *value,
                const char *end,
                const char *skip,
                size_t *length)
{
	char *a, *b;
	unsigned char *result, *p;

	assert (value <= end);
	assert (skip != NULL);

	/* String can only get shorter */
	result = malloc ((end - value) + 1);
	return_val_if_fail (result != NULL, NULL);

	/* Now loop through looking for escapes */
	p = result;
	while (value != end) {
		/*
		 * A percent sign followed by two hex digits means
		 * that the digits represent an escaped character.
		 */
		if (*value == '%') {
			value++;
			if (value + 2 > end) {
				free (result);
				return NULL;
			}
			a = strchr (HEX_CHARS, tolower (value[0]));
			b = strchr (HEX_CHARS, tolower (value[1]));
			if (!a || !b) {
				free (result);
				return NULL;
			}
			*p = (a - HEX_CHARS) << 4;
			*(p++) |= (b - HEX_CHARS);
			value += 2;

		/* Ignore whitespace characters */
		} else if (strchr (skip, *value)) {
			value++;

		/* A different character */
		} else {
			*(p++) = *(value++);
		}
	}

	/* Null terminate string, in case its a string */
	*p = 0;

	if (length)
		*length = p - result;
	return result;
}

void
p11_url_encode (const unsigned char *value,
                const unsigned char *end,
                const char *verbatim,
                p11_buffer *buf)
{
	char hex[3];

	assert (value <= end);

	/* Now loop through looking for escapes */
	while (value != end) {

		/* These characters we let through verbatim */
		if (*value && strchr (verbatim, *value) != NULL) {
			p11_buffer_add (buf, value, 1);

		/* All others get encoded */
		} else {
			hex[0] = '%';
			hex[1] = HEX_CHARS[((unsigned char)*value) >> 4];
			hex[2] = HEX_CHARS[((unsigned char)*value) & 0x0F];
			p11_buffer_add (buf, hex, 3);
		}

		++value;
	}
}
