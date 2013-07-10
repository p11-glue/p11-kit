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

#include "digest.h"

#include <assert.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>

#ifdef WITH_FREEBL

/*
 * NSS freebl3 has awkward headers not provided by appropriate packages
 * in many cases. So put these defines here inline. freebl3 seems completely
 * undocumented anyway. If you think this is a hack, then you guessed right.
 *
 * If you want a stable p11-kit without worries, use the builtin SHA1 and MD5
 * implementations. They're not used for crypto anyway. If you need p11-kit to
 * tick the "doesn't implement own crypto" checkbox, then the you're signing
 * up for this hack.
 */

typedef enum {
	HASH_AlgMD5    = 2,
	HASH_AlgSHA1   = 3,
} HASH_HashType;

typedef struct NSSLOWInitContextStr NSSLOWInitContext;
typedef struct NSSLOWHASHContextStr NSSLOWHASHContext;

NSSLOWInitContext *NSSLOW_Init(void);
NSSLOWHASHContext *NSSLOWHASH_NewContext(
			NSSLOWInitContext *initContext,
			HASH_HashType hashType);
void NSSLOWHASH_Begin(NSSLOWHASHContext *context);
void NSSLOWHASH_Update(NSSLOWHASHContext *context,
			const unsigned char *buf,
			unsigned int len);
void NSSLOWHASH_End(NSSLOWHASHContext *context,
			unsigned char *buf,
			unsigned int *ret, unsigned int len);
void NSSLOWHASH_Destroy(NSSLOWHASHContext *context);

#endif /* WITH_FREEBL3 */

#define SHA1_BLOCK_LENGTH 64U

typedef struct {
	uint32_t state[5];
	uint32_t count[2];
	unsigned char buffer[SHA1_BLOCK_LENGTH];
} sha1_t;

#define rol(value, bits) (((value) << (bits)) | ((value) >> (32 - (bits))))

/*@{*/
/*!
 * blk0() and blk() perform the initial expand.
 * I got the idea of expanding during the round function from SSLeay
 */
#if !defined(WORDS_BIGENDIAN)
# define blk0(i) \
	(block->l[i] = (rol(block->l[i], 24) & 0xFF00FF00) \
	 | (rol(block->l[i], 8) & 0x00FF00FF))
#else
# define blk0(i) block->l[i]
#endif
#define blk(i) \
	(block->l[i & 15] = rol(block->l[(i + 13) & 15] \
				^ block->l[(i + 8) & 15] \
				^ block->l[(i + 2) & 15] \
				^ block->l[i & 15], 1))

/*@}*/
/*@{*/
/*!
 * (R0+R1), R2, R3, R4 are the different operations (rounds) used in SHA1
 */
#define R0(v,w,x,y,z,i) \
	z += ((w & (x ^ y)) ^ y) + blk0(i) + 0x5A827999 + rol(v, 5); \
	w = rol(w, 30);
#define R1(v,w,x,y,z,i) \
	z += ((w & (x ^ y)) ^ y) + blk(i) + 0x5A827999 + rol(v, 5); \
	w = rol(w, 30);
#define R2(v,w,x,y,z,i) \
	z += (w ^ x ^ y) + blk(i) + 0x6ED9EBA1 + rol(v, 5); \
	w = rol(w, 30);
#define R3(v,w,x,y,z,i) \
	z += (((w | x) & y) | (w & x)) + blk(i) + 0x8F1BBCDC + rol(v, 5); \
	w = rol(w, 30);
#define R4(v,w,x,y,z,i) \
	z += (w ^ x ^ y) + blk(i) + 0xCA62C1D6 + rol(v, 5); \
	w = rol(w, 30);

/*@}*/

typedef union {
	unsigned char c[64];
	unsigned int l[16];
} CHAR64LONG16;

/*!
 * Hash a single 512-bit block. This is the core of the algorithm.
 */
static void
transform_sha1 (uint32_t state[5],
                const unsigned char buffer[64])
{
	uint32_t a, b, c, d, e;
	CHAR64LONG16 *block;
	CHAR64LONG16 workspace;

	assert (buffer != NULL);
	assert (state != NULL);

	block = &workspace;
	(void)memcpy(block, buffer, 64);

	/* Copy context->state[] to working vars */
	a = state[0];
	b = state[1];
	c = state[2];
	d = state[3];
	e = state[4];

	/* 4 rounds of 20 operations each. Loop unrolled. */
	R0(a,b,c,d,e, 0); R0(e,a,b,c,d, 1); R0(d,e,a,b,c, 2); R0(c,d,e,a,b, 3);
	R0(b,c,d,e,a, 4); R0(a,b,c,d,e, 5); R0(e,a,b,c,d, 6); R0(d,e,a,b,c, 7);
	R0(c,d,e,a,b, 8); R0(b,c,d,e,a, 9); R0(a,b,c,d,e,10); R0(e,a,b,c,d,11);
	R0(d,e,a,b,c,12); R0(c,d,e,a,b,13); R0(b,c,d,e,a,14); R0(a,b,c,d,e,15);
	R1(e,a,b,c,d,16); R1(d,e,a,b,c,17); R1(c,d,e,a,b,18); R1(b,c,d,e,a,19);
	R2(a,b,c,d,e,20); R2(e,a,b,c,d,21); R2(d,e,a,b,c,22); R2(c,d,e,a,b,23);
	R2(b,c,d,e,a,24); R2(a,b,c,d,e,25); R2(e,a,b,c,d,26); R2(d,e,a,b,c,27);
	R2(c,d,e,a,b,28); R2(b,c,d,e,a,29); R2(a,b,c,d,e,30); R2(e,a,b,c,d,31);
	R2(d,e,a,b,c,32); R2(c,d,e,a,b,33); R2(b,c,d,e,a,34); R2(a,b,c,d,e,35);
	R2(e,a,b,c,d,36); R2(d,e,a,b,c,37); R2(c,d,e,a,b,38); R2(b,c,d,e,a,39);
	R3(a,b,c,d,e,40); R3(e,a,b,c,d,41); R3(d,e,a,b,c,42); R3(c,d,e,a,b,43);
	R3(b,c,d,e,a,44); R3(a,b,c,d,e,45); R3(e,a,b,c,d,46); R3(d,e,a,b,c,47);
	R3(c,d,e,a,b,48); R3(b,c,d,e,a,49); R3(a,b,c,d,e,50); R3(e,a,b,c,d,51);
	R3(d,e,a,b,c,52); R3(c,d,e,a,b,53); R3(b,c,d,e,a,54); R3(a,b,c,d,e,55);
	R3(e,a,b,c,d,56); R3(d,e,a,b,c,57); R3(c,d,e,a,b,58); R3(b,c,d,e,a,59);
	R4(a,b,c,d,e,60); R4(e,a,b,c,d,61); R4(d,e,a,b,c,62); R4(c,d,e,a,b,63);
	R4(b,c,d,e,a,64); R4(a,b,c,d,e,65); R4(e,a,b,c,d,66); R4(d,e,a,b,c,67);
	R4(c,d,e,a,b,68); R4(b,c,d,e,a,69); R4(a,b,c,d,e,70); R4(e,a,b,c,d,71);
	R4(d,e,a,b,c,72); R4(c,d,e,a,b,73); R4(b,c,d,e,a,74); R4(a,b,c,d,e,75);
	R4(e,a,b,c,d,76); R4(d,e,a,b,c,77); R4(c,d,e,a,b,78); R4(b,c,d,e,a,79);

	/* Add the working vars back into context.state[] */
	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;
	state[4] += e;

	/* Wipe variables */
	a = b = c = d = e = 0;
	/* Avoid compiler warnings
	POST(a); POST(b); POST(c); POST(d); POST(e);
	*/
}


/*!
 * isc_sha1_init - Initialize new context
 */
static void
sha1_init (sha1_t *context)
{
	assert (context != NULL);

	/* SHA1 initialization constants */
	context->state[0] = 0x67452301;
	context->state[1] = 0xEFCDAB89;
	context->state[2] = 0x98BADCFE;
	context->state[3] = 0x10325476;
	context->state[4] = 0xC3D2E1F0;
	context->count[0] = 0;
	context->count[1] = 0;
}

static void
sha1_invalidate (sha1_t *context)
{
	memset (context, 0, sizeof (sha1_t));
}

/*!
 * Run your data through this.
 */
static void
sha1_update(sha1_t *context,
            const unsigned char *data,
            unsigned int len)
{
	unsigned int i, j;

	assert (context != 0);
	assert (data != 0);

	j = context->count[0];
	if ((context->count[0] += len << 3) < j)
		context->count[1] += (len >> 29) + 1;
	j = (j >> 3) & 63;
	if ((j + len) > 63) {
		(void)memcpy(&context->buffer[j], data, (i = 64 - j));
		transform_sha1 (context->state, context->buffer);
		for (; i + 63 < len; i += 64)
			transform_sha1 (context->state, &data[i]);
		j = 0;
	} else {
		i = 0;
	}

	(void)memcpy(&context->buffer[j], &data[i], len - i);
}


/*!
 * Add padding and return the message digest.
 */

static const unsigned char final_200 = 128;
static const unsigned char final_0 = 0;

static void
sha1_final (sha1_t *context,
            unsigned char *digest)
{
	unsigned int i;
	unsigned char finalcount[8];

	assert (digest != 0);
	assert (context != 0);

	for (i = 0; i < 8; i++) {
		/* Endian independent */
		finalcount[i] = (unsigned char)
			((context->count[(i >= 4 ? 0 : 1)]
			  >> ((3 - (i & 3)) * 8)) & 255);
	}

	sha1_update(context, &final_200, 1);
	while ((context->count[0] & 504) != 448)
		sha1_update(context, &final_0, 1);
	/* The next Update should cause a transform_sha1() */
	sha1_update(context, finalcount, 8);

	if (digest) {
		for (i = 0; i < 20; i++)
			digest[i] = (unsigned char)
				((context->state[i >> 2]
				  >> ((3 - (i & 3)) * 8)) & 255);
	}

	memset (context, 0, sizeof (sha1_t));
}

#ifdef WITH_FREEBL

static bool
nss_slow_hash (HASH_HashType type,
               unsigned char *hash,
               unsigned int hash_len,
               const void *input,
               size_t length,
               va_list va)
{
	NSSLOWHASHContext *ctx;
	unsigned int len;

	ctx = NSSLOWHASH_NewContext(NSSLOW_Init (), type);
	if (ctx == NULL)
		return false;

	NSSLOWHASH_Begin (ctx);
	while (input != NULL) {
		NSSLOWHASH_Update (ctx, input, length);
		input = va_arg (va, const void *);
		if (input)
			length = va_arg (va, size_t);
	}
	NSSLOWHASH_End (ctx, hash, &len, hash_len);
	assert (len == hash_len);
	NSSLOWHASH_Destroy (ctx);
	return true;
}

#endif /* WITH_FREEBL */

void
p11_digest_sha1 (unsigned char *hash,
                 const void *input,
                 size_t length,
                 ...)
{
	va_list va;
	sha1_t sha1;

#ifdef WITH_FREEBL
	bool ret;

	va_start (va, length);
	ret = nss_slow_hash (HASH_AlgSHA1, hash, P11_DIGEST_SHA1_LEN, input, length, va);
	va_end (va);

	if (ret)
		return;
#endif

	sha1_init (&sha1);

	va_start (va, length);
	while (input != NULL) {
		sha1_update (&sha1, input, length);
		input = va_arg (va, const void *);
		if (input)
			length = va_arg (va, size_t);
	}
	va_end (va);

	sha1_final (&sha1, hash);
	sha1_invalidate (&sha1);
}


/*! \file
 * This code implements the MD5 message-digest algorithm.
 * The algorithm is due to Ron Rivest.  This code was
 * written by Colin Plumb in 1993, no copyright is claimed.
 * This code is in the public domain; do with it what you wish.
 *
 * Equivalent code is available from RSA Data Security, Inc.
 * This code has been tested against that, and is equivalent,
 * except that you don't need to include two pages of legalese
 * with every copy.
 *
 * To compute the message digest of a chunk of bytes, declare an
 * MD5Context structure, pass it to MD5Init, call MD5Update as
 * needed on buffers full of bytes, and then call MD5Final, which
 * will fill a supplied 16-byte array with the digest.
 */

typedef struct {
	uint32_t buf[4];
	uint32_t bytes[2];
	uint32_t in[16];
} md5_t;

static void
byteSwap (uint32_t *buf,
          unsigned words)
{
	unsigned char *p = (unsigned char *)buf;

	do {
		*buf++ = (uint32_t)((unsigned)p[3] << 8 | p[2]) << 16 |
			((unsigned)p[1] << 8 | p[0]);
		p += 4;
	} while (--words);
}

/*!
 * Start MD5 accumulation.  Set bit count to 0 and buffer to mysterious
 * initialization constants.
 */
static void
md5_init(md5_t *ctx)
{
	ctx->buf[0] = 0x67452301;
	ctx->buf[1] = 0xefcdab89;
	ctx->buf[2] = 0x98badcfe;
	ctx->buf[3] = 0x10325476;

	ctx->bytes[0] = 0;
	ctx->bytes[1] = 0;
}

static void
md5_invalidate(md5_t *ctx)
{
	memset(ctx, 0, sizeof(md5_t));
}

/*@{*/
/*! The four core functions - F1 is optimized somewhat */

/* #define F1(x, y, z) (x & y | ~x & z) */
#define F1(x, y, z) (z ^ (x & (y ^ z)))
#define F2(x, y, z) F1(z, x, y)
#define F3(x, y, z) (x ^ y ^ z)
#define F4(x, y, z) (y ^ (x | ~z))
/*@}*/

/*! This is the central step in the MD5 algorithm. */
#define MD5STEP(f,w,x,y,z,in,s) \
	 (w += f(x,y,z) + in, w = (w<<s | w>>(32-s)) + x)

/*!
 * The core of the MD5 algorithm, this alters an existing MD5 hash to
 * reflect the addition of 16 longwords of new data.  MD5Update blocks
 * the data and converts bytes into longwords for this routine.
 */
static void
transform_md5 (uint32_t buf[4],
               uint32_t const in[16])
{
	register uint32_t a, b, c, d;

	a = buf[0];
	b = buf[1];
	c = buf[2];
	d = buf[3];

	MD5STEP(F1, a, b, c, d, in[0] + 0xd76aa478, 7);
	MD5STEP(F1, d, a, b, c, in[1] + 0xe8c7b756, 12);
	MD5STEP(F1, c, d, a, b, in[2] + 0x242070db, 17);
	MD5STEP(F1, b, c, d, a, in[3] + 0xc1bdceee, 22);
	MD5STEP(F1, a, b, c, d, in[4] + 0xf57c0faf, 7);
	MD5STEP(F1, d, a, b, c, in[5] + 0x4787c62a, 12);
	MD5STEP(F1, c, d, a, b, in[6] + 0xa8304613, 17);
	MD5STEP(F1, b, c, d, a, in[7] + 0xfd469501, 22);
	MD5STEP(F1, a, b, c, d, in[8] + 0x698098d8, 7);
	MD5STEP(F1, d, a, b, c, in[9] + 0x8b44f7af, 12);
	MD5STEP(F1, c, d, a, b, in[10] + 0xffff5bb1, 17);
	MD5STEP(F1, b, c, d, a, in[11] + 0x895cd7be, 22);
	MD5STEP(F1, a, b, c, d, in[12] + 0x6b901122, 7);
	MD5STEP(F1, d, a, b, c, in[13] + 0xfd987193, 12);
	MD5STEP(F1, c, d, a, b, in[14] + 0xa679438e, 17);
	MD5STEP(F1, b, c, d, a, in[15] + 0x49b40821, 22);

	MD5STEP(F2, a, b, c, d, in[1] + 0xf61e2562, 5);
	MD5STEP(F2, d, a, b, c, in[6] + 0xc040b340, 9);
	MD5STEP(F2, c, d, a, b, in[11] + 0x265e5a51, 14);
	MD5STEP(F2, b, c, d, a, in[0] + 0xe9b6c7aa, 20);
	MD5STEP(F2, a, b, c, d, in[5] + 0xd62f105d, 5);
	MD5STEP(F2, d, a, b, c, in[10] + 0x02441453, 9);
	MD5STEP(F2, c, d, a, b, in[15] + 0xd8a1e681, 14);
	MD5STEP(F2, b, c, d, a, in[4] + 0xe7d3fbc8, 20);
	MD5STEP(F2, a, b, c, d, in[9] + 0x21e1cde6, 5);
	MD5STEP(F2, d, a, b, c, in[14] + 0xc33707d6, 9);
	MD5STEP(F2, c, d, a, b, in[3] + 0xf4d50d87, 14);
	MD5STEP(F2, b, c, d, a, in[8] + 0x455a14ed, 20);
	MD5STEP(F2, a, b, c, d, in[13] + 0xa9e3e905, 5);
	MD5STEP(F2, d, a, b, c, in[2] + 0xfcefa3f8, 9);
	MD5STEP(F2, c, d, a, b, in[7] + 0x676f02d9, 14);
	MD5STEP(F2, b, c, d, a, in[12] + 0x8d2a4c8a, 20);

	MD5STEP(F3, a, b, c, d, in[5] + 0xfffa3942, 4);
	MD5STEP(F3, d, a, b, c, in[8] + 0x8771f681, 11);
	MD5STEP(F3, c, d, a, b, in[11] + 0x6d9d6122, 16);
	MD5STEP(F3, b, c, d, a, in[14] + 0xfde5380c, 23);
	MD5STEP(F3, a, b, c, d, in[1] + 0xa4beea44, 4);
	MD5STEP(F3, d, a, b, c, in[4] + 0x4bdecfa9, 11);
	MD5STEP(F3, c, d, a, b, in[7] + 0xf6bb4b60, 16);
	MD5STEP(F3, b, c, d, a, in[10] + 0xbebfbc70, 23);
	MD5STEP(F3, a, b, c, d, in[13] + 0x289b7ec6, 4);
	MD5STEP(F3, d, a, b, c, in[0] + 0xeaa127fa, 11);
	MD5STEP(F3, c, d, a, b, in[3] + 0xd4ef3085, 16);
	MD5STEP(F3, b, c, d, a, in[6] + 0x04881d05, 23);
	MD5STEP(F3, a, b, c, d, in[9] + 0xd9d4d039, 4);
	MD5STEP(F3, d, a, b, c, in[12] + 0xe6db99e5, 11);
	MD5STEP(F3, c, d, a, b, in[15] + 0x1fa27cf8, 16);
	MD5STEP(F3, b, c, d, a, in[2] + 0xc4ac5665, 23);

	MD5STEP(F4, a, b, c, d, in[0] + 0xf4292244, 6);
	MD5STEP(F4, d, a, b, c, in[7] + 0x432aff97, 10);
	MD5STEP(F4, c, d, a, b, in[14] + 0xab9423a7, 15);
	MD5STEP(F4, b, c, d, a, in[5] + 0xfc93a039, 21);
	MD5STEP(F4, a, b, c, d, in[12] + 0x655b59c3, 6);
	MD5STEP(F4, d, a, b, c, in[3] + 0x8f0ccc92, 10);
	MD5STEP(F4, c, d, a, b, in[10] + 0xffeff47d, 15);
	MD5STEP(F4, b, c, d, a, in[1] + 0x85845dd1, 21);
	MD5STEP(F4, a, b, c, d, in[8] + 0x6fa87e4f, 6);
	MD5STEP(F4, d, a, b, c, in[15] + 0xfe2ce6e0, 10);
	MD5STEP(F4, c, d, a, b, in[6] + 0xa3014314, 15);
	MD5STEP(F4, b, c, d, a, in[13] + 0x4e0811a1, 21);
	MD5STEP(F4, a, b, c, d, in[4] + 0xf7537e82, 6);
	MD5STEP(F4, d, a, b, c, in[11] + 0xbd3af235, 10);
	MD5STEP(F4, c, d, a, b, in[2] + 0x2ad7d2bb, 15);
	MD5STEP(F4, b, c, d, a, in[9] + 0xeb86d391, 21);

	buf[0] += a;
	buf[1] += b;
	buf[2] += c;
	buf[3] += d;
}

/*!
 * Update context to reflect the concatenation of another buffer full
 * of bytes.
 */
static void
md5_update (md5_t *ctx,
            const unsigned char *buf,
            unsigned int len)
{
	uint32_t t;

	/* Update byte count */

	t = ctx->bytes[0];
	if ((ctx->bytes[0] = t + len) < t)
		ctx->bytes[1]++;	/* Carry from low to high */

	t = 64 - (t & 0x3f);	/* Space available in ctx->in (at least 1) */
	if (t > len) {
		memcpy((unsigned char *)ctx->in + 64 - t, buf, len);
		return;
	}
	/* First chunk is an odd size */
	memcpy((unsigned char *)ctx->in + 64 - t, buf, t);
	byteSwap(ctx->in, 16);
	transform_md5 (ctx->buf, ctx->in);
	buf += t;
	len -= t;

	/* Process data in 64-byte chunks */
	while (len >= 64) {
		memcpy(ctx->in, buf, 64);
		byteSwap(ctx->in, 16);
		transform_md5(ctx->buf, ctx->in);
		buf += 64;
		len -= 64;
	}

	/* Handle any remaining bytes of data. */
	memcpy(ctx->in, buf, len);
}

/*!
 * Final wrapup - pad to 64-byte boundary with the bit pattern
 * 1 0* (64-bit count of bits processed, MSB-first)
 */
static void
md5_final(md5_t *ctx,
          unsigned char *digest)
{
	int count = ctx->bytes[0] & 0x3f;    /* Number of bytes in ctx->in */
	unsigned char *p = (unsigned char *)ctx->in + count;

	/* Set the first char of padding to 0x80.  There is always room. */
	*p++ = 0x80;

	/* Bytes of padding needed to make 56 bytes (-8..55) */
	count = 56 - 1 - count;

	if (count < 0) {	/* Padding forces an extra block */
		memset(p, 0, count + 8);
		byteSwap(ctx->in, 16);
		transform_md5(ctx->buf, ctx->in);
		p = (unsigned char *)ctx->in;
		count = 56;
	}
	memset(p, 0, count);
	byteSwap(ctx->in, 14);

	/* Append length in bits and transform */
	ctx->in[14] = ctx->bytes[0] << 3;
	ctx->in[15] = ctx->bytes[1] << 3 | ctx->bytes[0] >> 29;
	transform_md5(ctx->buf, ctx->in);

	byteSwap(ctx->buf, 4);
	memcpy(digest, ctx->buf, 16);
	memset(ctx, 0, sizeof(md5_t));	/* In case it's sensitive */
}

void
p11_digest_md5 (unsigned char *hash,
                const void *input,
                size_t length,
                ...)
{
	va_list va;
	md5_t md5;

#ifdef WITH_FREEBL
	bool ret;

	va_start (va, length);
	ret = nss_slow_hash (HASH_AlgMD5, hash, P11_DIGEST_MD5_LEN, input, length, va);
	va_end (va);

	if (ret)
		return;
#endif

	md5_init (&md5);

	va_start (va, length);
	while (input) {
		md5_update (&md5, input, length);
		input = va_arg (va, const void *);
		if (input)
			length = va_arg (va, size_t);
	}
	va_end (va);

	md5_final (&md5, hash);
	md5_invalidate (&md5);
}
