/*
 * Copyright (C) 2017 Red Hat Inc.
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
 * Author: Daiki Ueno
 */

#include "config.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "argv.h"
#include "test.h"

struct {
	char *foo;
	char *bar;
} test;

static void
on_argv_parsed (char *argument, void *data)
{
	char *value;

	value = argument + strcspn (argument, ":=");
	if (!*value)
		value = NULL;
	else
		*(value++) = 0;

	if (strcmp (argument, "foo") == 0) {
		test.foo = value ? strdup (value) : NULL;
	} else if (strcmp (argument, "bar") == 0) {
		test.bar = value ? strdup (value) : NULL;
	}
}

static void
setup (void *data)
{
	memset (&test, 0, sizeof (test));
}

static void
teardown (void *data)
{
	free (test.foo);
	free (test.bar);
}

static void
test_parse (void)
{
	p11_argv_parse ("foo=foo bar=bar", on_argv_parsed, NULL);
	assert_str_eq ("foo", test.foo);
	assert_str_eq ("bar", test.bar);
}

static void
test_parse_quote (void)
{
	p11_argv_parse ("foo='foo bar' bar=\"bar baz\"", on_argv_parsed, NULL);
	assert_str_eq ("foo bar", test.foo);
	assert_str_eq ("bar baz", test.bar);
}

static void
test_parse_backslash (void)
{
	p11_argv_parse ("foo='\\this\\isn\\'t\\a\\path' bar=bar",
			on_argv_parsed, NULL);
	assert_str_eq ("\\this\\isn't\\a\\path", test.foo);
	assert_str_eq ("bar", test.bar);
}

int
main (int argc,
      char *argv[])
{
	p11_fixture (setup, teardown);
	p11_test (test_parse, "/argv/parse");
	p11_test (test_parse_quote, "/argv/parse_quote");
	p11_test (test_parse_backslash, "/argv/parse_backslash");
	return p11_test_run (argc, argv);
}
