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
 * Author: Stef Walter <stefw@collabora.co.uk>
 */

#include "config.h"
#include "test.h"

#include "utf8.h"

#include <stdio.h>
#include <stdlib.h>

#define ELEMS(x) (sizeof (x) / sizeof (x[0]))

static void
test_ucs2be (void)
{
	char *output;
	size_t length;
	int i;

	struct {
		const char *output;
		size_t output_len;
		const unsigned char input[100];
		size_t input_len;
	} fixtures[] = {
		{ "This is a test", 14,
		  { 0x00, 'T', 0x00, 'h', 0x00, 'i', 0x00, 's', 0x00, ' ', 0x00, 'i', 0x00, 's', 0x00, ' ',
		    0x00, 'a', 0x00, ' ', 0x00, 't', 0x00, 'e', 0x00, 's', 0x00, 't' }, 28,
		},
		{ "V\303\266gel", 6,
		  { 0x00, 'V', 0x00, 0xF6, 0x00, 'g', 0x00, 'e', 0x00, 'l' }, 10,
		},
		{ "M\303\244nwich \340\264\205", 12,
		  { 0x00, 'M', 0x00, 0xE4, 0x00, 'n', 0x00, 'w', 0x00, 'i', 0x00, 'c', 0x00, 'h',
		    0x00, ' ', 0x0D, 0x05 }, 18,
		}
	};

	for (i = 0; i < ELEMS (fixtures); i++) {
		output = p11_utf8_for_ucs2be (fixtures[i].input,
		                              fixtures[i].input_len,
		                              &length);

		assert_num_eq (fixtures[i].output_len, length);
		assert_str_eq (fixtures[i].output, output);
		free (output);
	}
}

static void
test_ucs2be_fail (void)
{
	char *output;
	size_t length;
	int i;

	struct {
		const unsigned char input[100];
		size_t input_len;
	} fixtures[] = {
		{ { 0x00, 'T', 0x00, 'h', 0x00, 'i', 0x00, }, 7 /* truncated */ }
	};

	for (i = 0; i < ELEMS (fixtures); i++) {
		output = p11_utf8_for_ucs2be (fixtures[i].input,
		                              fixtures[i].input_len,
		                              &length);
		assert_ptr_eq (NULL, output);
	}
}

static void
test_ucs4be (void)
{
	char *output;
	size_t length;
	int i;

	struct {
		const char *output;
		size_t output_len;
		const unsigned char input[100];
		size_t input_len;
	} fixtures[] = {
		{ "This is a test", 14,
		  { 0x00, 0x00, 0x00, 'T',
		    0x00, 0x00, 0x00, 'h',
		    0x00, 0x00, 0x00, 'i',
		    0x00, 0x00, 0x00, 's',
		    0x00, 0x00, 0x00, ' ',
		    0x00, 0x00, 0x00, 'i',
		    0x00, 0x00, 0x00, 's',
		    0x00, 0x00, 0x00, ' ',
		    0x00, 0x00, 0x00, 'a',
		    0x00, 0x00, 0x00, ' ',
		    0x00, 0x00, 0x00, 't',
		    0x00, 0x00, 0x00, 'e',
		    0x00, 0x00, 0x00, 's',
		    0x00, 0x00, 0x00, 't',
		  }, 56,
		},
		{ "Fun \360\220\214\231", 8,
		  { 0x00, 0x00, 0x00, 'F',
		    0x00, 0x00, 0x00, 'u',
		    0x00, 0x00, 0x00, 'n',
		    0x00, 0x00, 0x00, ' ',
		    0x00, 0x01, 0x03, 0x19, /* U+10319: looks like an antenna */
		  }, 20,
		}
	};

	for (i = 0; i < ELEMS (fixtures); i++) {
		output = p11_utf8_for_ucs4be (fixtures[i].input,
		                              fixtures[i].input_len,
		                              &length);

		assert_num_eq (fixtures[i].output_len, length);
		assert_str_eq (fixtures[i].output, output);

		free (output);
	}
}

static void
test_ucs4be_fail (void)
{
	char *output;
	size_t length;
	int i;

	struct {
		const unsigned char input[100];
		size_t input_len;
	} fixtures[] = {
		{ { 0x00, 0x00, 'T',
		  }, 7 /* truncated */ },
		{ { 0x00, 0x00, 0x00, 'F',
		    0x00, 0x00, 0x00, 'u',
		    0x00, 0x00, 0x00, 'n',
		    0x00, 0x00, 0x00, ' ',
		    0xD8, 0x00, 0xDF, 0x19,
		  }, 20,
		}
	};

	for (i = 0; i < ELEMS (fixtures); i++) {
		output = p11_utf8_for_ucs4be (fixtures[i].input,
		                              fixtures[i].input_len,
		                              &length);
		assert_ptr_eq (NULL, output);
	}
}

static void
test_utf8 (void)
{
	bool ret;
	int i;

	struct {
		const char *input;
		size_t input_len;
	} fixtures[] = {
		{ "This is a test", 14 },
		{ "Good news everyone", -1 },
		{ "Fun \360\220\214\231", -1 },
		{ "Fun invalid here: \xfe", 4 }, /* but limited length */
		{ "V\303\266gel", 6, },
	};

	for (i = 0; i < ELEMS (fixtures); i++) {
		ret = p11_utf8_validate (fixtures[i].input,
		                         fixtures[i].input_len);
		assert_num_eq (true, ret);
	}
}

static void
test_utf8_fail (void)
{
	bool ret;
	int i;

	struct {
		const char *input;
		size_t input_len;
	} fixtures[] = {
		{ "This is a test\x80", 15 },
		{ "Good news everyone\x88", -1 },
		{ "Bad \xe0v following chars should be |0x80", -1 },
		{ "Truncated \xe0", -1 },
	};

	for (i = 0; i < ELEMS (fixtures); i++) {
		ret = p11_utf8_validate (fixtures[i].input,
		                         fixtures[i].input_len);
		assert_num_eq (false, ret);
	}
}

int
main (int argc,
      char *argv[])
{
	p11_test (test_ucs2be, "/utf8/ucs2be");
	p11_test (test_ucs2be_fail, "/utf8/ucs2be_fail");
	p11_test (test_ucs4be, "/utf8/ucs4be");
	p11_test (test_ucs4be_fail, "/utf8/ucs4be_fail");
	p11_test (test_utf8, "/utf8/utf8");
	p11_test (test_utf8_fail, "/utf8/utf8_fail");
	return p11_test_run (argc, argv);
}
