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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "compat.h"
#include "debug.h"
#include "lexer.h"
#include "message.h"
#include "pem.h"

typedef struct {
	int tok_type;
	const char *name;
	const char *value;
} expected_tok;

static void
on_pem_get_type (const char *type,
                 const unsigned char *contents,
                 size_t length,
                 void *user_data)
{
	char **result = (char **)user_data;
	*result = strdup (type);
}

static void
check_lex_msg (CuTest *tc,
               const char *file,
               int line,
               const expected_tok *expected,
               const char *input,
               bool failure)
{
	unsigned int count;
	p11_lexer lexer;
	char *type;
	bool failed;
	int i;

	p11_lexer_init (&lexer, "test", input, strlen (input));
	for (i = 0; p11_lexer_next (&lexer, &failed); i++) {
		CuAssertIntEquals_LineMsg (tc, file, line,
		                           "lexer token type does not match",
		                           expected[i].tok_type, lexer.tok_type);
		switch (lexer.tok_type) {
		case TOK_FIELD:
			CuAssertStrEquals_LineMsg (tc, file, line,
			                           "field name doesn't match",
			                           expected[i].name, lexer.tok.field.name);
			CuAssertStrEquals_LineMsg (tc, file, line,
			                           "field value doesn't match",
			                           expected[i].value, lexer.tok.field.value);
			break;
		case TOK_SECTION:
			CuAssertStrEquals_LineMsg (tc, file, line,
			                           "section name doesn't match",
			                           expected[i].name, lexer.tok.field.name);
			break;
		case TOK_PEM:
			type = NULL;
			count = p11_pem_parse (lexer.tok.pem.begin, lexer.tok.pem.length,
			                       on_pem_get_type, &type);
			CuAssertIntEquals_LineMsg (tc, file, line,
			                           "wrong number of PEM blocks",
			                           1, count);
			CuAssertStrEquals_LineMsg (tc, file, line,
			                           "wrong type of PEM block",
			                           expected[i].name, type);
			free (type);
			break;
		case TOK_EOF:
			CuFail_Line (tc, file, line, NULL, "eof should not be recieved");
			break;
		}
	}

	if (failure)
		CuAssert_Line (tc, file, line, "lexing didn't fail", failed);
	else
		CuAssert_Line (tc, file, line, "lexing failed", !failed);
	CuAssertIntEquals_LineMsg (tc, file, line,
	                           "premature end of lexing",
	                           TOK_EOF, expected[i].tok_type);

	p11_lexer_done (&lexer);
}

#define check_lex_success(tc, expected, input) \
	check_lex_msg (tc, __FILE__, __LINE__, expected, input, false)

#define check_lex_failure(tc, expected, input) \
	check_lex_msg (tc, __FILE__, __LINE__, expected, input, true)

static void
test_basic (CuTest *tc)
{
	const char *input = "[the header]\n"
	                    "field: value\n"
	                    "-----BEGIN BLOCK1-----\n"
	                    "aYNNXqshlVxCdo8QfKeXh3GUzd/yn4LYIVgQrx4a\n"
	                    "-----END BLOCK1-----\n";

	const expected_tok expected[] = {
		{ TOK_SECTION, "the header" },
		{ TOK_FIELD, "field", "value" },
		{ TOK_PEM, "BLOCK1", },
		{ TOK_EOF }
	};

	check_lex_success (tc, expected, input);
}

static void
test_corners (CuTest *tc)
{
	const char *input = "\r\n"                 /* blankline */
	                    " [the header]\r\n"    /* bad line endings */
	                    "  field: value  \r\n" /* whitespace */
	                    "number:    2\n"       /* extra space*/
	                    "number    :3\n"       /* extra space*/
	                    "number  :  4\n"       /* extra space*/
	                    "\n"
	                    " # A comment \n"
	                    "not-a-comment: # value\n"
	                    "-----BEGIN BLOCK1-----\r\n"
	                    "aYNNXqshlVxCdo8QfKeXh3GUzd/yn4LYIVgQrx4a\r\n"
	                    "-----END BLOCK1-----"; /* no new line */

	const expected_tok expected[] = {
		{ TOK_SECTION, "the header" },
		{ TOK_FIELD, "field", "value" },
		{ TOK_FIELD, "number", "2" },
		{ TOK_FIELD, "number", "3" },
		{ TOK_FIELD, "number", "4" },
		{ TOK_FIELD, "not-a-comment", "# value" },
		{ TOK_PEM, "BLOCK1", },
		{ TOK_EOF }
	};

	check_lex_success (tc, expected, input);
}

static void
test_following (CuTest *tc)
{
	const char *input = "-----BEGIN BLOCK1-----\n"
	                    "aYNNXqshlVxCdo8QfKeXh3GUzd/yn4LYIVgQrx4a\n"
	                    "-----END BLOCK1-----\n"
	                    "field: value";

	const expected_tok expected[] = {
		{ TOK_PEM, "BLOCK1", },
		{ TOK_FIELD, "field", "value" },
		{ TOK_EOF }
	};

	check_lex_success (tc, expected, input);
}

static void
test_bad_pem (CuTest *tc)
{
	const char *input = "field: value\n"
	                    "-----BEGIN BLOCK1-----\n"
	                    "aYNNXqshlVxCdo8QfKeXh3GUzd/yn4LYIVgQrx4a\n";

	const expected_tok expected[] = {
		{ TOK_FIELD, "field", "value" },
		{ TOK_EOF }
	};

	p11_message_quiet ();

	check_lex_failure (tc, expected, input);

	p11_message_loud ();
}

static void
test_bad_section (CuTest *tc)
{
	const char *input = "field: value\n"
	                    "[section\n"
	                    "bad]\n";

	const expected_tok expected[] = {
		{ TOK_FIELD, "field", "value" },
		{ TOK_EOF }
	};

	p11_message_quiet ();

	check_lex_failure (tc, expected, input);

	p11_message_loud ();
}

static void
test_bad_value (CuTest *tc)
{
	const char *input = "field_value\n"
	                    "[section\n"
	                    "bad]\n";

	const expected_tok expected[] = {
		{ TOK_EOF }
	};

	p11_message_quiet ();

	check_lex_failure (tc, expected, input);

	p11_message_loud ();
}

int
main (void)
{
	CuString *output = CuStringNew ();
	CuSuite* suite = CuSuiteNew ();
	int ret;

	putenv ("P11_KIT_STRICT=1");
	p11_debug_init ();

	SUITE_ADD_TEST (suite, test_basic);
	SUITE_ADD_TEST (suite, test_corners);
	SUITE_ADD_TEST (suite, test_following);
	SUITE_ADD_TEST (suite, test_bad_pem);
	SUITE_ADD_TEST (suite, test_bad_section);
	SUITE_ADD_TEST (suite, test_bad_value);

	CuSuiteRun (suite);
	CuSuiteSummary (suite, output);
	CuSuiteDetails (suite, output);
	printf ("%s\n", output->buffer);
	ret = suite->failCount;
	CuSuiteDelete (suite);
	CuStringDelete (output);

	return ret;
}
