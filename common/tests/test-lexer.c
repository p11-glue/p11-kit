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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "compat.h"
#include "debug.h"
#include "lexer.h"
#include "message.h"

typedef struct {
	int tok_type;
	const char *name;
	const char *value;
} expected_tok;

static void
check_lex_msg (const char *file,
               int line,
               const char *function,
               const expected_tok *expected,
               const char *input,
               bool failure)
{
	p11_lexer lexer;
	size_t len;
	bool failed;
	int i;

	p11_lexer_init (&lexer, "test", input, strlen (input));
	for (i = 0; p11_lexer_next (&lexer, &failed); i++) {
		if (expected[i].tok_type != lexer.tok_type)
			p11_test_fail (file, line, function,
			               "lexer token type does not match: (%d != %d)",
			               expected[i].tok_type, lexer.tok_type);
		switch (lexer.tok_type) {
		case TOK_FIELD:
			if (strcmp (expected[i].name, lexer.tok.field.name) != 0)
				p11_test_fail (file, line, function,
				               "field name doesn't match: (%s != %s)",
				               expected[i].name, lexer.tok.field.name);
			if (strcmp (expected[i].value, lexer.tok.field.value) != 0)
				p11_test_fail (file, line, function,
				               "field value doesn't match: (%s != %s)",
				               expected[i].value, lexer.tok.field.value);
			break;
		case TOK_SECTION:
			if (strcmp (expected[i].name, lexer.tok.field.name) != 0)
				p11_test_fail (file, line, function,
				               "section name doesn't match: (%s != %s)",
				               expected[i].name, lexer.tok.field.name);
			break;
		case TOK_PEM:
			len = strlen (expected[i].name);
			if (lexer.tok.pem.length < len ||
			    strncmp (lexer.tok.pem.begin, expected[i].name, len) != 0) {
				p11_test_fail (file, line, function,
				               "wrong type of PEM block: %s",
				               expected[i].name);
			}
			break;
		case TOK_EOF:
			p11_test_fail (file, line, function, "eof should not be recieved");
			break;
		}
	}

	if (failure && !failed)
		p11_test_fail (file, line, function, "lexing didn't fail");
	else if (!failure && failed)
		p11_test_fail (file, line, function, "lexing failed");
	if (TOK_EOF != expected[i].tok_type)
		p11_test_fail (file, line, function, "premature end of lexing");

	p11_lexer_done (&lexer);
}

#define check_lex_success(expected, input) \
	check_lex_msg (__FILE__, __LINE__, __FUNCTION__, expected, input, false)

#define check_lex_failure(expected, input) \
	check_lex_msg (__FILE__, __LINE__, __FUNCTION__, expected, input, true)

static void
test_basic (void)
{
	const char *input = "[the header]\n"
	                    "field: value\n"
	                    "-----BEGIN BLOCK1-----\n"
	                    "aYNNXqshlVxCdo8QfKeXh3GUzd/yn4LYIVgQrx4a\n"
	                    "-----END BLOCK1-----\n";

	const expected_tok expected[] = {
		{ TOK_SECTION, "the header" },
		{ TOK_FIELD, "field", "value" },
		{ TOK_PEM, "-----BEGIN BLOCK1-----\n", },
		{ TOK_EOF }
	};

	check_lex_success (expected, input);
}

static void
test_corners (void)
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
		{ TOK_PEM, "-----BEGIN BLOCK1-----\r\n", },
		{ TOK_EOF }
	};

	check_lex_success (expected, input);
}

static void
test_following (void)
{
	const char *input = "-----BEGIN BLOCK1-----\n"
	                    "aYNNXqshlVxCdo8QfKeXh3GUzd/yn4LYIVgQrx4a\n"
	                    "-----END BLOCK1-----\n"
	                    "field: value";

	const expected_tok expected[] = {
		{ TOK_PEM, "-----BEGIN BLOCK1-----\n", },
		{ TOK_FIELD, "field", "value" },
		{ TOK_EOF }
	};

	check_lex_success (expected, input);
}

static void
test_bad_pem (void)
{
	const char *input = "field: value\n"
	                    "-----BEGIN BLOCK1-----\n"
	                    "aYNNXqshlVxCdo8QfKeXh3GUzd/yn4LYIVgQrx4a\n";

	const expected_tok expected[] = {
		{ TOK_FIELD, "field", "value" },
		{ TOK_EOF }
	};

	p11_message_quiet ();

	check_lex_failure (expected, input);

	p11_message_loud ();
}

static void
test_bad_section (void)
{
	const char *input = "field: value\n"
	                    "[section\n"
	                    "bad]\n";

	const expected_tok expected[] = {
		{ TOK_FIELD, "field", "value" },
		{ TOK_EOF }
	};

	p11_message_quiet ();

	check_lex_failure (expected, input);

	p11_message_loud ();
}

static void
test_bad_value (void)
{
	const char *input = "field_value\n"
	                    "[section\n"
	                    "bad]\n";

	const expected_tok expected[] = {
		{ TOK_EOF }
	};

	p11_message_quiet ();

	check_lex_failure (expected, input);

	p11_message_loud ();
}

int
main (int argc,
      char *argv[])
{
	p11_test (test_basic, "/lexer/basic");
	p11_test (test_corners, "/lexer/corners");
	p11_test (test_following, "/lexer/following");
	p11_test (test_bad_pem, "/lexer/bad-pem");
	p11_test (test_bad_section, "/lexer/bad-section");
	p11_test (test_bad_value, "/lexer/bad-value");
	return p11_test_run (argc, argv);
}
