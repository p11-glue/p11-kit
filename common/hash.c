/*
 * Copyright (C) 2004, 2005, 2007, 2011  Internet Systems Consortium, Inc. ("ISC")
 * Copyright (C) 2000, 2001, 2003  Internet Software Consortium.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
 * OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

/*! \file
 * SHA-1 in C
 * \author By Steve Reid <steve@edmweb.com>
 * 100% Public Domain
 * \verbatim
 * Test Vectors
 * "abc"
 *   A9993E36 4706816A BA3E2571 7850C26C 9CD0D89D
 * "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
 *   84983E44 1C3BD26E BAAE4AA1 F95129E5 E54670F1
 * A million repetitions of "a"
 *   34AA973C D4C4DAA4 F61EEB2B DBAD2731 6534016F
 * \endverbatim
 */

#include "config.h"

#include "hash.h"

#include <assert.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>

/* This code is based on the public domain MurmurHash3 from Austin Appleby:
 * http://code.google.com/p/smhasher/source/browse/trunk/MurmurHash3.cpp
 *
 * We use only the 32 bit variant, and slow it down a bit to support unaligned
 * reads.
 */

#if !defined(__cplusplus) && (__GNUC__ > 2)
#define GNUC_INLINE __attribute__((always_inline))
#else
#define GNUC_INLINE
#endif

GNUC_INLINE static inline uint32_t
rotl (uint32_t x,
      int8_t r)
{
	return (x << r) | (x >> (32 - r));
}

/*
 * Finalization mix - force all bits of a hash block to avalanche
 */

GNUC_INLINE static inline uint32_t
fmix (uint32_t h)
{
	h ^= h >> 16;
	h *= 0x85ebca6b;
	h ^= h >> 13;
	h *= 0xc2b2ae35;
	h ^= h >> 16;

	return h;
}


void
p11_hash_murmur3 (void *hash,
                  const void *input,
                  size_t len,
                  ...)
{
	uint8_t overflow[4];
	const uint8_t *data;
	va_list va;
	uint32_t h1;
	uint32_t k1;
	uint32_t c1;
	uint32_t c2;

	h1 = 42; /* arbitrary choice of seed */
	c1 = 0xcc9e2d51;
	c2 = 0x1b873593;
	data = input;

	/* body */

	/* Mix 4 bytes at a time into the hash */
	va_start (va, len);
	for (;;) {
		if (len >= 4) {
			memcpy (&k1, data, 4);
			data += 4;
			len -= 4;

		} else {
			size_t num = len;
			memcpy (overflow, data, len);

			while (num < 4) {
				size_t part;

				data = va_arg (va, const void *);
				if (!data)
					break;

				/* Combine uint32 from old and new */
				len = va_arg (va, size_t);
				part = 4 - num;
				if (part > len)
					part = len;
				memcpy (overflow + num, data, part);
				data += part;
				len -= part;
				num += part;
			}

			if (num < 4) {
				len = num;
				break;
			}

			memcpy (&k1, overflow, 4);
		}

		k1 *= c1;
		k1 = rotl (k1, 15);
		k1 *= c2;

		h1 ^= k1;
		h1 = rotl (h1, 13);
		h1 = h1 * 5 + 0xe6546b64;
	}
	va_end (va);

	/* tail */

	k1 = 0;

	switch (len) {
	case 3:
		k1 ^= overflow[2] << 16;
	case 2:
		k1 ^= overflow[1] << 8;
	case 1:
		k1 ^= overflow[0];
		k1 *= c1;
		k1 = rotl (k1, 15);
		k1 *= c2;
		h1 ^= k1;
	default:
		break;
	}

	/* finalization */

	h1 ^= len;
	h1 = fmix(h1);

	assert (sizeof (h1) == P11_HASH_MURMUR3_LEN);
	memcpy (hash, &h1, sizeof (h1));
}
