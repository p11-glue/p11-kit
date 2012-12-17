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
#include "CuTest.h"

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
	CuTest *cu;
	int input_index;
	int output_index;
	int parsed;
} SuccessClosure;

static void
on_parse_pem_success (const char *type,
                      const unsigned char *contents,
                      size_t length,
                      void *user_data)
{
	SuccessClosure *cl = user_data;

	CuAssertIntEquals (cl->cu, success_fixtures[cl->input_index].output[cl->output_index].length, length);
	CuAssertTrue (cl->cu, memcmp (success_fixtures[cl->input_index].output[cl->output_index].data, contents,
	                              success_fixtures[cl->input_index].output[cl->output_index].length) == 0);

	cl->output_index++;
	cl->parsed++;
}

static void
test_pem_success (CuTest *cu)
{
	SuccessClosure cl;
	int ret;
	int i;
	int j;

	for (i = 0; success_fixtures[i].input != NULL; i++) {
		cl.cu = cu;
		cl.input_index = i;
		cl.output_index = 0;
		cl.parsed = 0;

		ret = p11_pem_parse (success_fixtures[i].input, strlen (success_fixtures[i].input),
		                     on_parse_pem_success, &cl);

		CuAssertTrue (cu, success_fixtures[i].output[cl.output_index].type == NULL);

		/* Count number of outputs, return from p11_pem_parse() should match */
		for (j = 0; success_fixtures[i].output[j].type != NULL; j++);
		CuAssertIntEquals (cu, j, ret);
		CuAssertIntEquals (cu, ret, cl.parsed);
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
	CuTest *cu = user_data;
	CuAssertTrue (cu, false && "not reached");
}

static void
test_pem_failure (CuTest *cu)
{
	int ret;
	int i;

	for (i = 0; failure_fixtures[i] != NULL; i++) {
		ret = p11_pem_parse (failure_fixtures[i], strlen (failure_fixtures[i]),
		                     on_parse_pem_failure, cu);
		CuAssertIntEquals (cu, 0, ret);
	}
}

int
main (void)
{
	CuString *output = CuStringNew ();
	CuSuite* suite = CuSuiteNew ();
	int ret;

	SUITE_ADD_TEST (suite, test_pem_success);
	SUITE_ADD_TEST (suite, test_pem_failure);

	CuSuiteRun (suite);
	CuSuiteSummary (suite, output);
	CuSuiteDetails (suite, output);
	printf ("%s\n", output->buffer);
	ret = suite->failCount;
	CuSuiteDelete (suite);
	CuStringDelete (output);

	return ret;
}
