/*
 * Copyright (c) 2023 Red Hat Inc
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

#define P11_DEBUG_FLAG P11_DEBUG_TOOL

#include "check-format.h"
#include "debug.h"
#include "message.h"
#include "tool.h"

#include <assert.h>
#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef ENABLE_NLS
#include <libintl.h>
#define _(x) dgettext(PACKAGE_NAME, x)
#else
#define _(x) (x)
#endif

#define IS_BASE64(C) (isalnum ((int)(C)) || (C) == '+' || (C) == '/')
#define PEM_LABEL_MAX 256

enum format_result {
	FORMAT_OK,
	FORMAT_FAIL,
	FORMAT_ERROR
};

static char pem_label[PEM_LABEL_MAX];
static int pem_label_length;
static int inside_pem;
static int inside_section;
static size_t line_num;
static bool color_out;
static bool color_err;

static inline void
print_result (enum format_result result,
	      const char *filename)
{
	printf (color_out ? "\033[1m%s:\033[0m " : "%s: ", filename);
	switch (result) {
	case FORMAT_OK:
		printf (color_out ? "\033[1;32mOK\033[0m\n" : "OK\n");
		break;
	case FORMAT_FAIL:
		printf (color_out ? "\033[1;31mFAIL\033[0m\n" : "FAIL\n");
		break;
	case FORMAT_ERROR:
		printf (color_out ? "\033[1;31mERROR\033[0m\n" : "ERROR\n");
		break;
	default:
	    assert_not_reached ();
	    break;
	}
}

static inline void
fail (const char *msg)
{
	fprintf (stderr, color_err ? "\033[31mFailed\033[0m at line %lu: %s\n" :
				     "Failed at line %lu: %s\n", line_num, msg);
}

static bool
get_line (FILE *stream,
	  char **line)
{
	char *buffer, *tmp;
	int c, count, alloc_size;

	count = 0;
	alloc_size = 50;

	buffer = malloc (alloc_size);
	if (buffer == NULL) {
		p11_message (_("failed to allocate memory"));
		*line = NULL;
		return false;
	}

	while ((c = getc (stream)) != EOF && c != '\n') {
		if (count + 1 >= alloc_size) {
			alloc_size *= 2;
			tmp = realloc (buffer, alloc_size);
			if (tmp == NULL) {
				free (buffer);
				p11_message (_("failed to allocate memory"));
				*line = NULL;
				return false;
			}
			buffer = tmp;
		}
		buffer[count++] = (char)c;
	}

	if (c == EOF) {
		free (buffer);
		*line = NULL;
		return true;
	}

	buffer[count] = '\0';
	*line = buffer;
	return true;
}

/* Format is based on https://www.rfc-editor.org/rfc/rfc7468#section-3
 *
 * stricttextualmsg = preeb eol
 *                    strictbase64text
 *                    posteb eol
 * preeb            = "-----BEGIN " label "-----"
 * posteb           = "-----END " label "-----"
 * strictbase64text = *base64fullline strictbase64finl
 * base64fullline   = 64base64char eol
 * strictbase64finl = *15(4base64char) (4base64char / 3base64char base64pad / 2base64char 2base64pad) eol
 */
static bool
parse_pem (const char *line)
{
	const char *end;
	size_t line_len;
	int i;

	switch (inside_pem) {
	case 0: {
		/* check whether line starts a new PEM block */
		if (strncmp (line, "-----BEGIN ", 11) != 0)
			return false;
		line += 11;

		/* start a new PEM block */
		inside_pem = 1;

		/* check the end of the BEGIN block */
		end = line + strlen (line) - 5;
		if (strncmp (end, "-----", 5) != 0) {
			fail (_("couldn't find \"-----\" at the end of the BEGIN block"));
			return false;
		}

		/* if label is not empty, it cannot start with '-' */
		if (line != end && *line == '-') {
			fail (_("label cannot start with \'-\'"));
			return false;
		}

		/* check the label */
		pem_label_length = end - line;
		if (pem_label_length >= PEM_LABEL_MAX) {
			fail (_("label is too long"));
			return false;
		}

		for (i = 0; i < pem_label_length; ++i, ++line) {
			if (!isprint (*line)) {
				fail (_("label contains non-printable characters"));
				return false;
			}
			pem_label[i] = *line;
		}
		pem_label[pem_label_length] = '\0';
		break;
	}
	case 1:
		/* there has to be at least one base64 line */
		if (*line == '-') {
			fail (_("base64 text is empty"));
			return false;
		}
		inside_pem = 2;
		/* fall-through */
	case 2: {
		/* if we reached the end of base64 text, parse the END block */
		if (*line == '-')
			goto end_pem;

		line_len = strlen (line);

		if (line_len == 0 || line_len > 64 || line_len % 4 != 0) {
			fail (_("base64 line length must be multiple of 4 and within <4, 64> characters"));
			return false;
		}

		/* check for the padding */
		if (line[line_len - 1] == '=')
			line_len = line[line_len - 2] == '=' ? line_len - 2 : line_len - 1;

		/* check the base64 text */
		for (i = 0; i < line_len; ++i) {
			if (!IS_BASE64 (line[i])) {
				fail (_("base64 line must contain only alpha-numeric, '+' and '/' characters"));
				return false;
			}
		}

		/* if there were less then 64 characters then its the final base64 line */
		if (line_len < 64)
			inside_pem = 3;

		break;
	}
	case 3: {
	end_pem:
		/* check whether line starts with the END block */
		if (strncmp (line, "-----END ", 9) != 0) {
			fail (_("start of the END block expected but not found"));
			return false;
		}
		line += 9;

		/* label must match with the label in the BEGIN block */
		if (strncmp (line, pem_label, pem_label_length) != 0) {
			fail (_("label in the END block does not match the label in the BEGIN block"));
			return false;
		}
		line += pem_label_length;

		/* check the end of the END block */
		if (strncmp (line, "-----", 5) != 0) {
			fail (_("couldn't find \"-----\" at the end of the END block"));
			return false;
		}
		line += 5;

		/* only EOL is allowed */
		if (*line != '\0') {
			fail (_("characters found after the END block"));
			return false;
		}

		/* end of the PEM block */
		inside_pem = 0;
		break;
	}
	default:
		assert_not_reached ();
		return false;
	}

	return true;
}

static bool
parse_section_header (const char *line)
{
	size_t i, line_len;

	/* check the opening bracket */
	if (line[0] != '[') {
		fail (_("section header does not start with '['"));
		return false;
	}

	line_len = strlen (line);

	/* check the closing bracket */
	if (line[line_len - 1] != ']') {
		fail (_("section header does not end with ']'"));
		return false;
	}

	/* check the section label */
	for (i = 1; i < line_len - 1; ++i) {
		if (!isprint (line[i])) {
			fail (_("label contains non-printable characters"));
			return false;
		}
	}

	return true;
}

static bool
parse_key_value_pair (const char *line)
{
	const char *colon;
	size_t i, value_len;

	/* find the key-value separator */
	colon = strchr (line, ':');
	if (colon == NULL) {
		fail (_("key-value pair is missing a separator ':'"));
		return false;
	}

	if (line == colon) {
		fail (_("missing key in key-value pair"));
		return false;
	}

	/* check the key */
	while (line < colon) {
		if (!isprint (*line)) {
			fail (_("key contains non-printable characters"));
			return false;
		}
		++line;
	}
	++line;

	/* skip whitespace after colon */
	while (isspace (*line))
		++line;

	if (*line == '\0') {
		fail (_("missing value in key-value pair"));
		return false;
	}

	/* check if value is a string */
	value_len = strlen (line);
	if ((line[0] == '"' && line[value_len - 1] != '"') ||
	    (line[0] != '"' && line[value_len - 1] == '"')) {
		fail (_("value string is missing '\"'"));
		return false;
	}

	/* check the value */
	for (i = 0; i < value_len; ++i) {
		if (!isprint (line[i])) {
			fail (_("value contains non-printable characters"));
			return false;
		}
	}

	return true;
}

static bool
parse_line (char *line)
{
	bool ok;
	char *end;

	/* check for PEM block */
	ok = parse_pem (line);
	if (ok)
		return true;
	if (inside_pem)
		return false;

	/* trim whitespace from both ends */
	while (isspace (*line))
		++line;
	end = line + strlen (line) - 1;
	while (line < end && isspace (*end))
		--end;
	end[1] = '\0';

	/* ignore empty lines and comments */
	if (*line == '\0' || *line == '#')
		return true;

	/* check for section header */
	if (*line == '[') {
		ok = parse_section_header (line);
		if (ok)
			inside_section = 1;
		return ok;
	}

	/* check for key-value pair */
	ok = parse_key_value_pair (line);
	if (ok && !inside_section) {
		fail (_("key-value pair outside of section"));
		return false;
	}

	return ok;
}

static enum format_result
check_format (const char *filename)
{
	bool ok;
	FILE *stream;
	char *line;

	stream = fopen (filename, "r");
	if (stream == NULL) {
		p11_message (_("%s: failed to open file for reading"), filename);
		return FORMAT_ERROR;
	}

	/* reset context */
	inside_pem = 0;
	inside_section = 0;

	for (line_num = 1; (ok = get_line (stream, &line)) && line != NULL; ++line_num) {
		ok = parse_line (line);
		free (line);
		if (!ok) {
			fclose (stream);
			return FORMAT_FAIL;
		}
	}

	fclose (stream);

	/* Fail if we received a reading error */
	if (!ok)
		return FORMAT_ERROR;

	/* Fail if PEM block was left open after reaching EOF */
	if (inside_pem) {
		fail (_("PEM block not closed at EOF"));
		return FORMAT_FAIL;
	}

	return FORMAT_OK;
}

int
p11_trust_check_format (int argc,
			char **argv)
{
	int i, opt;
	enum format_result result;

	enum {
		opt_verbose = 'v',
		opt_quiet = 'q',
		opt_help = 'h',
	};

	struct option options[] = {
		{ "verbose", no_argument, NULL, opt_verbose },
		{ "quiet", no_argument, NULL, opt_quiet },
		{ "help", no_argument, NULL, opt_help },
		{ 0 },
	};

	p11_tool_desc usages[] = {
		{ 0, "usage: trust check-format <file>..." },
		{ opt_verbose, "show verbose debug output", },
		{ opt_quiet, "suppress command output", },
		{ 0 },
	};

	while ((opt = p11_tool_getopt (argc, argv, options)) != -1) {
		switch (opt) {
		case opt_verbose:
		case opt_quiet:
			break;
		case opt_help:
			p11_tool_usage (usages, options);
			return 0;
		case '?':
			p11_tool_usage (usages, options);
			return 2;
		default:
			assert_not_reached ();
			break;
		}
	}

	argc -= optind;
	argv += optind;

	color_out = isatty (fileno (stdout));
	color_err = isatty (fileno (stderr));

	for (i = 0; i < argc; ++i) {
		result = check_format (argv[i]);
		print_result (result, argv[i]);
		if (result == FORMAT_ERROR)
			return 2;
	}

	return 0;
}
