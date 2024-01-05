/*
 * Copyright (c) 2011, Collabora Ltd.
 * Copyright (C) 2023 Red Hat Inc.
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
 * Authors: Stef Walter <stefw@collabora.co.uk>,
 *          Daiki Ueno,
 *          Zoltan Fridrich <zfridric@redhat.com>
 */

#include "config.h"

#include "debug.h"
#include "hex.h"

#include <stdlib.h>
#include <string.h>

static const char HEXC_LOWER[] = "0123456789abcdef";

char *
hex_encode (const unsigned char *data,
            size_t n_data)
{
	char *result;
	size_t i;
	size_t o;

	return_val_if_fail (data != NULL, NULL);

	if ((SIZE_MAX - 1) / 3 < n_data)
		return NULL;
	result = malloc (n_data * 3 + 1);
	if (result == NULL)
		return NULL;

	for (i = 0, o = 0; i < n_data; i++) {
		if (i > 0)
			result[o++] = ':';
		result[o++] = HEXC_LOWER[data[i] >> 4 & 0xf];
		result[o++] = HEXC_LOWER[data[i] & 0xf];
	}

	result[o] = 0;
	return result;
}

unsigned char *
hex_decode (const char *hex,
            size_t *bin_len)
{
	int i, j;
	size_t bin_len_, hex_len;
	unsigned char *bin, c;
	bool with_separator;

	return_val_if_fail (hex != NULL, NULL);
	return_val_if_fail (bin_len != NULL, NULL);

	hex_len = strlen (hex);
	if (hex_len == 0)
		return NULL;

	with_separator = hex_len > 2 && hex[2] == ':';
	if (with_separator)
		for (i = 5; i < hex_len; i += 3)
			if (hex[i] != ':')
				return NULL;

	if (SIZE_MAX - 1 < hex_len ||
	    (with_separator && (hex_len + 1) % 3 != 0) ||
	    (!with_separator && hex_len % 2 != 0))
		return NULL;

	bin_len_ = with_separator ? (hex_len + 1) / 3 : hex_len / 2;
	bin = calloc (bin_len_, 1);
	if (bin == NULL)
		return NULL;

	for (i = 0; i < bin_len_; ++i) {
		for (j = 0; j < 2; ++j) {
			c = with_separator ? hex[i * 3 + j] : hex[i * 2 + j];
			if ('0' <= c && c <= '9')
				bin[i] |= c - '0';
			else if ('a' <= c && c <= 'f')
				bin[i] |= c - 'a' + 10;
			else if ('A' <= c && c <= 'F')
				bin[i] |= c - 'A' + 10;
			else {
				free (bin);
				return NULL;
			}
			if (j == 0)
				bin[i] <<= 4;
		}
	}

	*bin_len = bin_len_;
	return bin;
}
