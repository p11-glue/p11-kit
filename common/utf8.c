/*
 * Copyright (c) 2013, Red Hat Inc.
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

#include "buffer.h"
#include "debug.h"
#include "utf8.h"

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/*
 * Some parts come from FreeBSD utf8.c
 *
 * Copyright (c) 2002-2004 Tim J. Robbins
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

static ssize_t
utf8_to_uchar (const char *str,
               size_t len,
               uint32_t *uc)
{
	int ch, i, mask, want;
	uint32_t lbound, uch;

	assert (str != NULL);
	assert (len > 0);
	assert (uc != NULL);

	if (((ch = (unsigned char)*str) & ~0x7f) == 0) {
		/* Fast path for plain ASCII characters. */
		*uc = ch;
		return 1;
	}

	/*
	 * Determine the number of octets that make up this character
	 * from the first octet, and a mask that extracts the
	 * interesting bits of the first octet. We already know
	 * the character is at least two bytes long.
	 *
	 * We also specify a lower bound for the character code to
	 * detect redundant, non-"shortest form" encodings. For
	 * example, the sequence C0 80 is _not_ a legal representation
	 * of the null character. This enforces a 1-to-1 mapping
	 * between character codes and their multibyte representations.
	 */
	ch = (unsigned char)*str;
	if ((ch & 0xe0) == 0xc0) {
		mask = 0x1f;
		want = 2;
		lbound = 0x80;
	} else if ((ch & 0xf0) == 0xe0) {
		mask = 0x0f;
		want = 3;
		lbound = 0x800;
	} else if ((ch & 0xf8) == 0xf0) {
		mask = 0x07;
		want = 4;
		lbound = 0x10000;
	} else if ((ch & 0xfc) == 0xf8) {
		mask = 0x03;
		want = 5;
		lbound = 0x200000;
	} else if ((ch & 0xfe) == 0xfc) {
		mask = 0x01;
		want = 6;
		lbound = 0x4000000;
	} else {
		/*
		 * Malformed input; input is not UTF-8.
		 */
		return -1;
	}

	if (want > len) {
		/* Incomplete multibyte sequence. */
		return -1;
	}

	/*
	 * Decode the octet sequence representing the character in chunks
	 * of 6 bits, most significant first.
	 */
	uch = (unsigned char)*str++ & mask;
	for (i = 1; i < want; i++) {
		if ((*str & 0xc0) != 0x80) {
			/*
			 * Malformed input; bad characters in the middle
			 * of a character.
			 */
			return -1;
		}
		uch <<= 6;
		uch |= *str++ & 0x3f;
	}
	if (uch < lbound) {
		/*
		 * Malformed input; redundant encoding.
		 */
		return -1;
	}

	*uc = uch;
	return want;
}

static size_t
utf8_for_uchar (uint32_t uc,
                char *str,
                size_t len)
{
	unsigned char lead;
	int i, want;

	assert (str != NULL);
	assert (len >= 6);

	if ((uc & ~0x7f) == 0) {
		/* Fast path for plain ASCII characters. */
		*str = (char)uc;
		return 1;
	}

	/*
	 * Determine the number of octets needed to represent this character.
	 * We always output the shortest sequence possible. Also specify the
	 * first few bits of the first octet, which contains the information
	 * about the sequence length.
	 */
	if ((uc & ~0x7ff) == 0) {
		lead = 0xc0;
		want = 2;
	} else if ((uc & ~0xffff) == 0) {
		lead = 0xe0;
		want = 3;
	} else if ((uc & ~0x1fffff) == 0) {
		lead = 0xf0;
		want = 4;
	} else if ((uc & ~0x3ffffff) == 0) {
		lead = 0xf8;
		want = 5;
	} else if ((uc & ~0x7fffffff) == 0) {
		lead = 0xfc;
		want = 6;
	} else {
		return -1;
	}

	assert (want <= len);

	/*
	 * Output the octets representing the character in chunks
	 * of 6 bits, least significant last. The first octet is
	 * a special case because it contains the sequence length
	 * information.
	 */
	for (i = want - 1; i > 0; i--) {
		str[i] = (uc & 0x3f) | 0x80;
		uc >>= 6;
	}
	*str = (uc & 0xff) | lead;
	return want;
}

static ssize_t
ucs2be_to_uchar (const unsigned char *str,
                 size_t len,
                 uint32_t *wc)
{
	assert (str != NULL);
	assert (len != 0);
	assert (wc != NULL);

	if (len < 2)
		return -1;

	*wc = (str[0] << 8 | str[1]);
	return 2;
}

static ssize_t
ucs4be_to_uchar (const unsigned char *str,
                 size_t len,
                 uint32_t *uc)
{
	assert (str != NULL);
	assert (len != 0);
	assert (uc != NULL);

	if (len < 4)
		return -1;

	*uc = (str[0] << 24 | str[1] << 16 | str[2] << 8 | str[3]);
	return 4;
}

bool
p11_utf8_validate (const char *str,
                   ssize_t len)
{
	uint32_t dummy;
	ssize_t ret;

	if (len < 0)
		len = strlen (str);

	while (len > 0) {
		ret = utf8_to_uchar (str, len, &dummy);
		if (ret < 0)
			return false;
		str += ret;
		len -= ret;
	}

	return true;
}

static char *
utf8_for_convert (ssize_t (* convert) (const unsigned char *, size_t, uint32_t *),
                  const unsigned char *str,
                  size_t num_bytes,
                  size_t *ret_len)
{
	p11_buffer buf;
	char block[6];
	uint32_t uc;
	ssize_t ret;

	assert (convert);

	if (!p11_buffer_init_null (&buf, num_bytes))
		return_val_if_reached (NULL);

	while (num_bytes != 0) {
		ret = (convert) (str, num_bytes, &uc);
		if (ret < 0) {
			p11_buffer_uninit (&buf);
			return NULL;
		}

		str += ret;
		num_bytes -= ret;

		ret = utf8_for_uchar (uc, block, 6);
		if (ret < 0) {
			p11_buffer_uninit (&buf);
			return NULL;
		}
		p11_buffer_add (&buf, block, ret);
	}

	return_val_if_fail (p11_buffer_ok (&buf), NULL);
	return p11_buffer_steal (&buf, ret_len);
}

char *
p11_utf8_for_ucs2be (const unsigned char *str,
                     size_t num_bytes,
                     size_t *ret_len)
{
	assert (str != NULL);
	return utf8_for_convert (ucs2be_to_uchar, str, num_bytes, ret_len);
}

char *
p11_utf8_for_ucs4be (const unsigned char *str,
                     size_t num_bytes,
                     size_t *ret_len)
{
	assert (str != NULL);
	return utf8_for_convert (ucs4be_to_uchar, str, num_bytes, ret_len);
}
