/*
 * Copyright (c) 2024, Red Hat Inc.
 *
 * All rights reserved.
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
 * Author: Zoltan Fridrich <zfridric@redhat.com>
 */

#include "config.h"

#include <stdlib.h>

#include "hex.h"
#include "test.h"

static void
assert_encode_eq (const char *out,
		  const char *in,
		  size_t in_len)
{
	char *hex = hex_encode ((const unsigned char *)in, in_len);
	assert_str_eq (out, hex);
	free (hex);
}

static void
assert_decode_eq (const char *out,
		  size_t out_len,
		  const char *in)
{
	size_t bin_len = 0;
	char *bin = (char *)hex_decode (in, &bin_len);
	assert_mem_eq (out, out_len, bin, bin_len);
	free (bin);
}

static void
assert_decode_fail (const char *in)
{
	size_t i;
	assert_ptr_eq (NULL, hex_decode (in, &i));
}

static void
test_encode (void)
{
	assert_encode_eq ("", "", 0);
	assert_encode_eq ("3a", "\x3a", 1);
	assert_encode_eq ("3a:bc:f6:9a", "\x3a\xbc\xf6\x9a", 4);
}

static void
test_decode (void)
{
	assert_decode_eq ("\x3a", 1, "3a");
	assert_decode_eq ("\x3a\xbc\xf6\x9a", 4, "3abcf69a");
	assert_decode_eq ("\x3a\xbc\xf6\x9a", 4, "3AbCf69a");
	assert_decode_eq ("\x3a\xbc\xf6\x9a", 4, "3ABCF69A");
	assert_decode_eq ("\x3a\xbc\xf6\x9a", 4, "3a:bc:f6:9a");
	assert_decode_eq ("\x3a\xbc\xf6\x9a", 4, "3a:Bc:F6:9A");
	assert_decode_eq ("\x3a\xbc\xf6\x9a", 4, "3a:bc:f6:9a");
	assert_decode_fail ("");
	assert_decode_fail ("3");
	assert_decode_fail (":a");
	assert_decode_fail ("a:");
	assert_decode_fail ("3ab");
	assert_decode_fail ("3a:");
	assert_decode_fail (":3a");
	assert_decode_fail ("3a:b");
	assert_decode_fail ("3:ab");
	assert_decode_fail ("3a:bc:f6::9a");
	assert_decode_fail ("3a:bc:f69a");
	assert_decode_fail ("3a:bc:f6::9");
	assert_decode_fail ("3a:bc:f69aa");
	assert_decode_fail ("3a$bc:f6:9a");
	assert_decode_fail ("3a:bc:f6$9a");
}

int
main (int argc,
      char *argv[])
{
	p11_test (test_encode, "/hex/encode");
	p11_test (test_decode, "/hex/decode");
	return p11_test_run (argc, argv);
}
