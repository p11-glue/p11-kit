/*
 * Copyright (c) 2012 Red Hat Inc.
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
 * Author: Stef Walter <stefw@gnome.org>
 */

#include "config.h"
#include "test.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "compat.h"
#include "pem.h"

struct {
	const char *input;
	struct {
		const char *type;
		const char *data;
		unsigned int length;
	} output[8];
} success_fixtures[] = {
	{
	  /* one block */
	  "-----BEGIN BLOCK1-----\n"
	  "aYNNXqshlVxCdo8QfKeXh3GUzd/yn4LYIVgQrx4a\n"
	  "-----END BLOCK1-----",
	  {
	    {
	      "BLOCK1",
	      "\x69\x83\x4d\x5e\xab\x21\x95\x5c\x42\x76\x8f\x10\x7c\xa7\x97\x87"
	      "\x71\x94\xcd\xdf\xf2\x9f\x82\xd8\x21\x58\x10\xaf\x1e\x1a",
	      30,
	    },
	    {
	      NULL,
	    }
	  }
	},

	{
	  /* one block, with header */
	  "-----BEGIN BLOCK1-----\n"
	  "Header1: value1 \n"
	  " Header2: value2\n"
	  "\n"
	  "aYNNXqshlVxCdo8QfKeXh3GUzd/yn4LYIVgQrx4a\n"
	  "-----END BLOCK1-----",
	  {
	    {
	      "BLOCK1",
	      "\x69\x83\x4d\x5e\xab\x21\x95\x5c\x42\x76\x8f\x10\x7c\xa7\x97\x87"
	      "\x71\x94\xcd\xdf\xf2\x9f\x82\xd8\x21\x58\x10\xaf\x1e\x1a",
	      30,
	    },
	    {
	      NULL,
	    }
	  }
	},

	{
	  /* two blocks, junk data */
	  "-----BEGIN BLOCK1-----\n"
	  "aYNNXqshlVxCdo8QfKeXh3GUzd/yn4LYIVgQrx4a\n"
	  "-----END BLOCK1-----\n"
	  "blah blah\n"
	  "-----BEGIN TWO-----\n"
	  "oy5L157C671HyJMCf9FiK9prvPZfSch6V4EoUfylFoI1Bq6SbL53kg==\n"
	  "-----END TWO-----\n"
	  "trailing data",
	  {
	    {
	      "BLOCK1",
	      "\x69\x83\x4d\x5e\xab\x21\x95\x5c\x42\x76\x8f\x10\x7c\xa7\x97\x87"
	      "\x71\x94\xcd\xdf\xf2\x9f\x82\xd8\x21\x58\x10\xaf\x1e\x1a",
	      30,
	    },
	    {
	      "TWO",
	      "\xa3\x2e\x4b\xd7\x9e\xc2\xeb\xbd\x47\xc8\x93\x02\x7f\xd1\x62\x2b"
	      "\xda\x6b\xbc\xf6\x5f\x49\xc8\x7a\x57\x81\x28\x51\xfc\xa5\x16\x82"
	      "\x35\x06\xae\x92\x6c\xbe\x77\x92",
	      40
	    },
	    {
	      NULL,
	    }
	  }
	},

	{
	  NULL,
	}
};

typedef struct {
	int input_index;
	int output_index;
	int parsed;
} Closure;

static void
on_parse_pem_success (const char *type,
                      const unsigned char *contents,
                      size_t length,
                      void *user_data)
{
	Closure *cl = user_data;

	assert_num_eq (success_fixtures[cl->input_index].output[cl->output_index].length, length);
	assert (memcmp (success_fixtures[cl->input_index].output[cl->output_index].data, contents,
	                              success_fixtures[cl->input_index].output[cl->output_index].length) == 0);

	cl->output_index++;
	cl->parsed++;
}

static void
test_pem_success (void)
{
	Closure cl;
	int ret;
	int i;
	int j;

	for (i = 0; success_fixtures[i].input != NULL; i++) {
		cl.input_index = i;
		cl.output_index = 0;
		cl.parsed = 0;

		ret = p11_pem_parse (success_fixtures[i].input, strlen (success_fixtures[i].input),
		                     on_parse_pem_success, &cl);

		assert (success_fixtures[i].output[cl.output_index].type == NULL);

		/* Count number of outputs, return from p11_pem_parse() should match */
		for (j = 0; success_fixtures[i].output[j].type != NULL; j++);
		assert_num_eq (j, ret);
		assert_num_eq (ret, cl.parsed);
	}
}

const char *failure_fixtures[] = {
	/* too short at end of opening line */
	"-----BEGIN BLOCK1---\n"
	"aYNNXqshlVxCdo8QfKeXh3GUzd/yn4LYIVgQrx4a\n"
	"-----END BLOCK1-----",

	/* truncated */
	"-----BEGIN BLOCK1---",

	/* no ending */
	"-----BEGIN BLOCK1-----\n"
	"aYNNXqshlVxCdo8QfKeXh3GUzd/yn4LYIVgQrx4a\n",

	/* wrong ending */
	"-----BEGIN BLOCK1-----\n"
	"aYNNXqshlVxCdo8QfKeXh3GUzd/yn4LYIVgQrx4a\n"
	"-----END BLOCK2-----",

	/* wrong ending */
	"-----BEGIN BLOCK1-----\n"
	"aYNNXqshlVxCdo8QfKeXh3GUzd/yn4LYIVgQrx4a\n"
	"-----END INVALID-----",

	/* too short at end of ending line */
	"-----BEGIN BLOCK1-----\n"
	"aYNNXqshlVxCdo8QfKeXh3GUzd/yn4LYIVgQrx4a\n"
	"-----END BLOCK1---",

	/* invalid base64 data */
	"-----BEGIN BLOCK1-----\n"
	"!!!!NNXqshlVxCdo8QfKeXh3GUzd/yn4LYIVgQrx4a\n"
	"-----END BLOCK1-----",

	NULL,
};

static void
on_parse_pem_failure (const char *type,
                      const unsigned char *contents,
                      size_t length,
                      void *user_data)
{
	assert (false && "not reached");
}

static void
test_pem_failure (void)
{
	int ret;
	int i;

	for (i = 0; failure_fixtures[i] != NULL; i++) {
		ret = p11_pem_parse (failure_fixtures[i], strlen (failure_fixtures[i]),
		                     on_parse_pem_failure, NULL);
		assert_num_eq (0, ret);
	}
}

typedef struct {
	const char *input;
	size_t length;
	const char *type;
	const char *output;
} WriteFixture;

static WriteFixture write_fixtures[] = {
	{
	  "\x69\x83\x4d\x5e\xab\x21\x95\x5c\x42\x76\x8f\x10\x7c\xa7\x97\x87"
	  "\x71\x94\xcd\xdf\xf2\x9f\x82\xd8\x21\x58\x10\xaf\x1e\x1a",
	  30, "BLOCK1",
	  "-----BEGIN BLOCK1-----\n"
	  "aYNNXqshlVxCdo8QfKeXh3GUzd/yn4LYIVgQrx4a\n"
	  "-----END BLOCK1-----\n",
	},
	{
	  "\x50\x31\x31\x2d\x4b\x49\x54\x0a\x0a\x50\x72\x6f\x76\x69\x64\x65"
	  "\x73\x20\x61\x20\x77\x61\x79\x20\x74\x6f\x20\x6c\x6f\x61\x64\x20"
	  "\x61\x6e\x64\x20\x65\x6e\x75\x6d\x65\x72\x61\x74\x65\x20\x50\x4b"
	  "\x43\x53\x23\x31\x31\x20\x6d\x6f\x64\x75\x6c\x65\x73\x2e\x20\x50"
	  "\x72\x6f\x76\x69\x64\x65\x73\x20\x61\x20\x73\x74\x61\x6e\x64\x61"
	  "\x72\x64\x0a\x63\x6f\x6e\x66\x69\x67\x75\x72\x61\x74\x69\x6f\x6e"
	  "\x20\x73\x65\x74\x75\x70\x20\x66\x6f\x72\x20\x69\x6e\x73\x74\x61"
	  "\x6c\x6c\x69\x6e\x67\x20\x50\x4b\x43\x53\x23\x31\x31\x20\x6d\x6f"
	  "\x64\x75\x6c\x65\x73\x20\x69\x6e\x20\x73\x75\x63\x68\x20\x61\x20"
	  "\x77\x61\x79\x20\x74\x68\x61\x74\x20\x74\x68\x65\x79\x27\x72\x65"
	  "\x0a\x64\x69\x73\x63\x6f\x76\x65\x72\x61\x62\x6c\x65\x2e\x0a\x0a"
	  "\x41\x6c\x73\x6f\x20\x73\x6f\x6c\x76\x65\x73\x20\x70\x72\x6f\x62"
	  "\x6c\x65\x6d\x73\x20\x77\x69\x74\x68\x20\x63\x6f\x6f\x72\x64\x69"
	  "\x6e\x61\x74\x69\x6e\x67\x20\x74\x68\x65\x20\x75\x73\x65\x20\x6f"
	  "\x66\x20\x50\x4b\x43\x53\x23\x31\x31\x20\x62\x79\x20\x64\x69\x66"
	  "\x66\x65\x72\x65\x6e\x74\x0a\x63\x6f\x6d\x70\x6f\x6e\x65\x6e\x74"
	  "\x73\x20\x6f\x72\x20\x6c\x69\x62\x72\x61\x72\x69\x65\x73\x20\x6c"
	  "\x69\x76\x69\x6e\x67\x20\x69\x6e\x20\x74\x68\x65\x20\x73\x61\x6d"
	  "\x65\x20\x70\x72\x6f\x63\x65\x73\x73\x2e\x0a",
	  299, "LONG TYPE WITH SPACES",
	  "-----BEGIN LONG TYPE WITH SPACES-----\n"
	  "UDExLUtJVAoKUHJvdmlkZXMgYSB3YXkgdG8gbG9hZCBhbmQgZW51bWVyYXRlIFBL\n"
	  "Q1MjMTEgbW9kdWxlcy4gUHJvdmlkZXMgYSBzdGFuZGFyZApjb25maWd1cmF0aW9u\n"
	  "IHNldHVwIGZvciBpbnN0YWxsaW5nIFBLQ1MjMTEgbW9kdWxlcyBpbiBzdWNoIGEg\n"
	  "d2F5IHRoYXQgdGhleSdyZQpkaXNjb3ZlcmFibGUuCgpBbHNvIHNvbHZlcyBwcm9i\n"
	  "bGVtcyB3aXRoIGNvb3JkaW5hdGluZyB0aGUgdXNlIG9mIFBLQ1MjMTEgYnkgZGlm\n"
	  "ZmVyZW50CmNvbXBvbmVudHMgb3IgbGlicmFyaWVzIGxpdmluZyBpbiB0aGUgc2Ft\n"
	  "ZSBwcm9jZXNzLgo=\n"
	  "-----END LONG TYPE WITH SPACES-----\n"
	},
	{
	  "\x69\x83\x4d\x5e\xab\x21\x95\x5c\x42\x76\x8f\x10\x7c\xa7\x97\x87"
	  "\x71\x94\xcd\xdf\xf2\x9f\x82\xd8\x21\x58\x10\xaf",
	  28, "BLOCK1",
	  "-----BEGIN BLOCK1-----\n"
	  "aYNNXqshlVxCdo8QfKeXh3GUzd/yn4LYIVgQrw==\n"
	  "-----END BLOCK1-----\n",
	},
	{
	  NULL,
	}
};

static void
on_parse_written (const char *type,
                  const unsigned char *contents,
                  size_t length,
                  void *user_data)
{
	WriteFixture *fixture = user_data;

	assert_str_eq (fixture->type, type);
	assert_num_eq (fixture->length, length);
	assert (memcmp (contents, fixture->input, length) == 0);
}

static void
test_pem_write (void)
{
	WriteFixture *fixture;
	p11_buffer buf;
	unsigned int count;
	int i;

	for (i = 0; write_fixtures[i].input != NULL; i++) {
		fixture = write_fixtures + i;

		if (!p11_buffer_init_null (&buf, 0))
			assert_not_reached ();

		if (!p11_pem_write ((unsigned char *)fixture->input,
		                    fixture->length,
		                    fixture->type, &buf))
			assert_not_reached ();
		assert_str_eq (fixture->output, buf.data);
		assert_num_eq (strlen (fixture->output), buf.len);

		count = p11_pem_parse (buf.data, buf.len, on_parse_written, fixture);
		assert_num_eq (1, count);

		p11_buffer_uninit (&buf);
	}
}

int
main (int argc,
      char *argv[])
{
	p11_test (test_pem_success, "/pem/success");
	p11_test (test_pem_failure, "/pem/failure");
	p11_test (test_pem_write, "/pem/write");
	return p11_test_run (argc, argv);
}
