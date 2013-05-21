/*
 * Copyright (c) 2013 Red Hat Inc.
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
#include "test.h"

#include "debug.h"
#include "message.h"

#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "url.h"

static void
check_decode_msg (const char *file,
                  int line,
                  const char *function,
                  const char *input,
                  ssize_t input_len,
                  const char *expected,
                  size_t expected_len)
{
	unsigned char *decoded;
	size_t length;

	if (input_len < 0)
		input_len = strlen (input);
	decoded = p11_url_decode (input, input + input_len, "", &length);

	if (expected == NULL) {
		if (decoded != NULL)
			p11_test_fail (file, line, function, "decoding should have failed");

	} else {
		if (decoded == NULL)
			p11_test_fail (file, line, function, "decoding failed");
		if (expected_len != length)
			p11_test_fail (file, line, function, "wrong length: (%lu != %lu)",
			               (unsigned long)expected_len, (unsigned long)length);
		if (memcmp (decoded, expected, length) != 0)
			p11_test_fail (file, line, function, "decoding wrong");
		free (decoded);
	}
}

#define check_decode_success(input, input_len, expected, expected_len) \
	check_decode_msg (__FILE__, __LINE__, __FUNCTION__, input, input_len, expected, expected_len)

#define check_decode_failure(input, input_len) \
	check_decode_msg (__FILE__, __LINE__, __FUNCTION__, input, input_len, NULL, 0)

static void
test_decode_success (void)
{
	check_decode_success ("%54%45%53%54%00", -1, "TEST", 5);
	check_decode_success ("%54%45%53%54%00", 6, "TE", 2);
	check_decode_success ("%54est%00", -1, "Test", 5);
}

static void
test_decode_skip (void)
{
	const char *input = "%54 %45 %53 %54 %00";
	unsigned char *decoded;
	size_t length;

	decoded = p11_url_decode (input, input + strlen (input), P11_URL_WHITESPACE, &length);
	assert_str_eq ("TEST", (char *)decoded);
	assert_num_eq (5, length);

	free (decoded);
}

static void
test_decode_failure (void)
{
	/* Early termination */
	check_decode_failure ("%54%45%53%5", -1);
	check_decode_failure ("%54%45%53%", -1);

	/* Not hex characters */
	check_decode_failure ("%54%XX%53%54%00", -1);
}

static void
test_encode (void)
{
	const unsigned char *input = (unsigned char *)"TEST";
	p11_buffer buf;

	if (!p11_buffer_init_null (&buf, 5))
		assert_not_reached ();

	p11_url_encode (input, input + 5, "", &buf);
	assert (p11_buffer_ok (&buf));
	assert_str_eq ("%54%45%53%54%00", (char *)buf.data);
	assert_num_eq (15, buf.len);

	p11_buffer_uninit (&buf);
}

static void
test_encode_verbatim (void)
{
	const unsigned char *input = (unsigned char *)"TEST";
	p11_buffer buf;

	if (!p11_buffer_init_null (&buf, 5))
		assert_not_reached ();

	p11_url_encode (input, input + 5, "ES", &buf);
	assert (p11_buffer_ok (&buf));
	assert_str_eq ("%54ES%54%00", (char *)buf.data);
	assert_num_eq (11, buf.len);

	p11_buffer_uninit (&buf);
}

int
main (int argc,
      char *argv[])
{
	p11_test (test_decode_success, "/url/decode-success");
	p11_test (test_decode_skip, "/url/decode-skip");
	p11_test (test_decode_failure, "/url/decode-failure");

	p11_test (test_encode, "/url/encode");
	p11_test (test_encode_verbatim, "/url/encode-verbatim");
	return p11_test_run (argc, argv);
}
