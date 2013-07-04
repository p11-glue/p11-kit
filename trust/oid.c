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

#include "hash.h"
#include "oid.h"

#include <assert.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

/*
 * We deal with OIDs a lot in their DER form. These have the
 * advantage of having the length encoded in their second byte,
 * at least for all the OIDs we're interested in.
 *
 * The goal here is to avoid carrying around extra length
 * information about DER encoded OIDs.
 */

bool
p11_oid_simple (const unsigned char *oid,
                int len)
{
	return (oid != NULL &&
	        len > 3 &&                   /* minimum length */
	        oid[0] == 0x06 &&            /* simple encoding */
	        (oid[1] & 128) == 0 &&       /* short form length */
	        (size_t)oid[1] == len - 2);  /* matches length */
}

unsigned int
p11_oid_hash (const void *oid)
{
	uint32_t hash;
	int len;

	len = p11_oid_length (oid);
	p11_hash_murmur3 (&hash, oid, len, NULL);
	return hash;
}

bool
p11_oid_equal (const void *oid_one,
               const void *oid_two)
{
	int len_one;
	int len_two;

	len_one = p11_oid_length (oid_one);
	len_two = p11_oid_length (oid_two);

	return (len_one == len_two &&
	        memcmp (oid_one, oid_two, len_one) == 0);
}

int
p11_oid_length (const unsigned char *oid)
{
	assert (oid[0] == 0x06);
	assert ((oid[1] & 128) == 0);
	return (int)oid[1] + 2;
}
