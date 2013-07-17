/*
 * Copyright (c) 2005 Stefan Walter
 * Copyright (c) 2011 Collabora Ltd.
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
 *
 * CONTRIBUTORS
 *  Stef Walter <stefw@redhat.com>
 */

#include "config.h"

#define P11_DEBUG_FLAG P11_DEBUG_CONF
#include "debug.h"
#include "lexer.h"
#include "message.h"

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void
p11_lexer_init (p11_lexer *lexer,
                const char *filename,
                const char *data,
                size_t length)
{
	return_if_fail (lexer != NULL);

	memset (lexer, 0, sizeof (p11_lexer));
	lexer->at = data;
	lexer->remaining = length;

	return_if_fail (filename != NULL);
	lexer->filename = strdup (filename);
	return_if_fail (lexer->filename != NULL);
}

static void
clear_state (p11_lexer *lexer)
{
	switch (lexer->tok_type) {
	case TOK_FIELD:
		free (lexer->tok.field.name);
		free (lexer->tok.field.value);
		break;
	case TOK_SECTION:
		free (lexer->tok.section.name);
		break;
	case TOK_PEM:
	case TOK_EOF:
		break;
	}

	memset (&lexer->tok, 0, sizeof (lexer->tok));
	lexer->tok_type = TOK_EOF;
	lexer->complained = false;
}

bool
p11_lexer_next (p11_lexer *lexer,
                bool *failed)
{
	const char *colon;
	const char *value;
	const char *line;
	const char *end;
	const char *pos;
	char *part;

	return_val_if_fail (lexer != NULL, false);

	clear_state (lexer);
	if (failed)
		*failed = false;

	/* Go through lines and process them */
	while (lexer->remaining != 0) {
		assert (lexer->remaining > 0);

		/* Is this line the start of a PEM block? */
		if (strncmp (lexer->at, "-----BEGIN ", 11) == 0) {
			pos = strnstr (lexer->at, "\n-----END ", lexer->remaining);
			if (pos != NULL) {
				end = memchr (pos + 1, '\n', lexer->remaining - (pos - lexer->at) - 1);
				if (end)
					end += 1;
				else
					end = lexer->at + lexer->remaining;
				lexer->tok_type = TOK_PEM;
				lexer->tok.pem.begin = lexer->at;
				lexer->tok.pem.length = end - lexer->at;
				assert (end - lexer->at <= lexer->remaining);
				lexer->remaining -= (end - lexer->at);
				lexer->at = end;
				return true;
			}

			p11_lexer_msg (lexer, "invalid pem block: no ending line");
			if (failed)
				*failed = true;
			return false;
		}

		line = lexer->at;
		end = memchr (lexer->at, '\n', lexer->remaining);
		if (end == NULL) {
			end = lexer->at + lexer->remaining;
			lexer->remaining = 0;
			lexer->at = end;
		} else {
			assert ((end - lexer->at) + 1 <= lexer->remaining);
			lexer->remaining -= (end - lexer->at) + 1;
			lexer->at = end + 1;
		}

		/* Strip whitespace from line */
		while (line != end && isspace (line[0]))
			++line;
		while (line != end && isspace (*(end - 1)))
			--end;

		/* Empty lines / comments at start */
		if (line == end || line[0] == '#')
			continue;

		/* Is the the a section ? */
		if (line[0] == '[') {
			if (*(end - 1) != ']') {
				part = strndup (line, end - line);
				p11_lexer_msg (lexer, "invalid section header: missing braces");
				free (part);
				if (failed)
					*failed = true;
				return false;
			}

			lexer->tok_type = TOK_SECTION;
			lexer->tok.section.name = strndup (line + 1, (end - line) - 2);
			return_val_if_fail (lexer->tok.section.name != NULL, false);
			return true;
		}

		/* Look for the break between name: value on the same line */
		colon = memchr (line, ':', end - line);
		if (!colon) {
			part = strndup (line, end - line);
			p11_lexer_msg (lexer, "invalid field line: no colon");
			free (part);
			if (failed)
				*failed = true;
			return false;
		}

		/* Strip whitespace from name and value */
		value = colon + 1;
		while (value != end && isspace (value[0]))
			++value;
		while (line != colon && isspace (*(colon - 1)))
			--colon;

		lexer->tok_type = TOK_FIELD;
		lexer->tok.field.name = strndup (line, colon - line);
		lexer->tok.field.value = strndup (value, end - value);
		return_val_if_fail (lexer->tok.field.name && lexer->tok.field.value, false);
		return true;
	}

	return false;
}

void
p11_lexer_done (p11_lexer *lexer)
{
	return_if_fail (lexer != NULL);
	clear_state (lexer);
	free (lexer->filename);
	memset (lexer, 0, sizeof (p11_lexer));
}

void
p11_lexer_msg (p11_lexer *lexer,
               const char *msg)
{
	return_if_fail (lexer != NULL);

	if (lexer->complained)
		return;

	switch (lexer->tok_type) {
	case TOK_FIELD:
		p11_message ("%s: %s: %s", lexer->filename,
		             lexer->tok.field.name, msg);
		break;
	case TOK_SECTION:
		p11_message ("%s: [%s]: %s", lexer->filename,
		             lexer->tok.section.name, msg);
		break;
	case TOK_PEM:
		p11_message ("%s: BEGIN ...: %s", lexer->filename, msg);
		break;
	default:
		p11_message ("%s: %s", lexer->filename, msg);
		break;
	}

	lexer->complained = true;
}
