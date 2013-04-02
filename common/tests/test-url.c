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
#include "CuTest.h"

#include "debug.h"
#include "message.h"

#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "url.h"

static void
check_decode_msg (CuTest *tc,
                  const char *file,
                  int line,
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
		CuAssert_Line (tc, file, line, "decoding should have failed", decoded == NULL);

	} else {
		CuAssert_Line (tc, file, line, "decoding failed", decoded != NULL);
		CuAssertIntEquals_LineMsg (tc, file, line, "wrong length", expected_len, length);
		CuAssert_Line (tc, file, line, "decoded wrong", memcmp (decoded, expected, length) == 0);
		free (decoded);
	}
}

#define check_decode_success(tc, input, input_len, expected, expected_len) \
	check_decode_msg (tc, __FILE__, __LINE__, input, input_len, expected, expected_len)

#define check_decode_failure(tc, input, input_len) \
	check_decode_msg (tc, __FILE__, __LINE__, input, input_len, NULL, 0)

static void
test_decode_success (CuTest *tc)
{
	check_decode_success (tc, "%54%45%53%54%00", -1, "TEST", 5);
	check_decode_success (tc, "%54%45%53%54%00", 6, "TE", 2);
	check_decode_success (tc, "%54est%00", -1, "Test", 5);
}

static void
test_decode_skip (CuTest *tc)
{
	const char *input = "%54 %45 %53 %54 %00";
	unsigned char *decoded;
	size_t length;

	decoded = p11_url_decode (input, input + strlen (input), P11_URL_WHITESPACE, &length);
	CuAssertStrEquals (tc, "TEST", (char *)decoded);
	CuAssertIntEquals (tc, 5, length);

	free (decoded);
}

static void
test_decode_failure (CuTest *tc)
{
	/* Early termination */
	check_decode_failure (tc, "%54%45%53%5", -1);
	check_decode_failure (tc, "%54%45%53%", -1);

	/* Not hex characters */
	check_decode_failure (tc, "%54%XX%53%54%00", -1);
}

static void
test_encode (CuTest *tc)
{
	const unsigned char *input = (unsigned char *)"TEST";
	char *encoded;
	size_t length;

	encoded = p11_url_encode (input, input + 5, "", &length);
	CuAssertStrEquals (tc, "%54%45%53%54%00", (char *)encoded);
	CuAssertIntEquals (tc, 15, length);

	free (encoded);
}

static void
test_encode_verbatim (CuTest *tc)
{
	const unsigned char *input = (unsigned char *)"TEST";
	char *encoded;
	size_t length;

	encoded = p11_url_encode (input, input + 5, "ES", &length);
	CuAssertStrEquals (tc, "%54ES%54%00", (char *)encoded);
	CuAssertIntEquals (tc, 11, length);

	free (encoded);
}

int
main (void)
{
	CuString *output = CuStringNew ();
	CuSuite* suite = CuSuiteNew ();
	int ret;

	putenv ("P11_KIT_STRICT=1");
	p11_debug_init ();

	SUITE_ADD_TEST (suite, test_decode_success);
	SUITE_ADD_TEST (suite, test_decode_skip);
	SUITE_ADD_TEST (suite, test_decode_failure);

	SUITE_ADD_TEST (suite, test_encode);
	SUITE_ADD_TEST (suite, test_encode_verbatim);

	CuSuiteRun (suite);
	CuSuiteSummary (suite, output);
	CuSuiteDetails (suite, output);
	printf ("%s\n", output->buffer);
	ret = suite->failCount;
	CuSuiteDelete (suite);
	CuStringDelete (output);
	return ret;
}
