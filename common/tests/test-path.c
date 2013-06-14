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
#include "path.h"

static void
test_base (void)
{
	struct {
		const char *in;
		const char *out;
	} fixtures[] = {
		{ "/this/is/a/path", "path" },
		{ "/this/is/a/folder/", "folder" },
		{ "folder/", "folder" },
		{ "/", "" },
		{ "this", "this" },
#ifdef OS_WIN32
		{ "\\this\\is\\a\\path", "path" },
		{ "\\this\\is\\a\\folder\\", "folder" },
		{ "C:\\this\\is\\a\\path", "path" },
		{ "D:\\this\\is\\a\\folder\\", "folder" },
		{ "folder\\", "folder" },
		{ "\\", "" },
#endif
		{ NULL },
	};

	char *out;
	int i;

	for (i = 0; fixtures[i].in != NULL; i++) {
		out = p11_path_base (fixtures[i].in);
		assert_str_eq (fixtures[i].out, out);
		free (out);
	}
}

#define check_equals_and_free(ex, ac) \
	do { assert_str_eq (ex, ac); free (ac); } while (0)

static void
test_build (void)
{
#ifdef OS_UNIX
	check_equals_and_free ("/root/second",
	                       p11_path_build ("/root", "second", NULL));
	check_equals_and_free ("/root/second",
	                       p11_path_build ("/root", "/second", NULL));
	check_equals_and_free ("/root/second",
	                       p11_path_build ("/root/", "second", NULL));
	check_equals_and_free ("/root/second/third",
	                       p11_path_build ("/root", "second", "third", NULL));
	check_equals_and_free ("/root/second/third",
	                       p11_path_build ("/root", "/second/third", NULL));
#else /* OS_WIN32 */
	check_equals_and_free ("C:\\root\\second",
	                       p11_path_build ("C:\\root", "second", NULL));
	check_equals_and_free ("C:\\root\\second",
	                       p11_path_build ("C:\\root", "\\second", NULL));
	check_equals_and_free ("C:\\root\\second",
	                       p11_path_build ("C:\\root\\", "second", NULL));
	check_equals_and_free ("C:\\root\\second\\third",
	                       p11_path_build ("C:\\root", "second", "third", NULL));
	check_equals_and_free ("C:\\root\\second/third",
	                       p11_path_build ("C:\\root", "second/third", NULL));
#endif
}

static void
test_expand (void)
{
	char *path;

#ifdef OS_UNIX
	putenv ("HOME=/home/blah");
	check_equals_and_free ("/home/blah/my/path",
	                       p11_path_expand ("$HOME/my/path"));
	check_equals_and_free ("/home/blah/my/path",
	                       p11_path_expand ("~/my/path"));
	check_equals_and_free ("/home/blah",
	                       p11_path_expand ("$HOME"));
	check_equals_and_free ("/home/blah",
	                       p11_path_expand ("~"));
	putenv ("TEMP=/tmpdir");
	check_equals_and_free ("/tmpdir/my/path",
	                       p11_path_expand ("$TEMP/my/path"));
	check_equals_and_free ("/tmpdir",
	                       p11_path_expand ("$TEMP"));
#else /* OS_WIN32 */
	putenv ("HOME=C:\\Users\\blah");
	check_equals_and_free ("C:\\Users\\blah\\path",
	                       p11_path_expand ("$HOME/path"));
	check_equals_and_free ("C:\\Users\\blah\\path",
	                       p11_path_expand ("$HOME\\path"));
	check_equals_and_free ("C:\\Users\\blah\\path",
	                       p11_path_expand ("~/path"));
	check_equals_and_free ("C:\\Users\\blah\\path",
	                       p11_path_expand ("~\\path"));

	putenv ("TEMP=C:\\Temp Directory");
	check_equals_and_free ("C:\\Temp Directory\\path",
	                       p11_path_expand ("$TEMP/path"));
	check_equals_and_free ("C:\\Temp Directory\\path",
	                       p11_path_expand ("$TEMP\\path"));
#endif

	putenv("HOME=");
	path = p11_path_expand ("$HOME/this/is/my/path");
	assert (strstr (path, "this/is/my/path") != NULL);
	free (path);

	putenv("HOME=");
	path = p11_path_expand ("~/this/is/my/path");
	assert (strstr (path, "this/is/my/path") != NULL);
	free (path);

	putenv("TEMP=");
	path = p11_path_expand ("$TEMP/this/is/my/path");
	assert (strstr (path, "this/is/my/path") != NULL);
	free (path);
}

static void
test_absolute (void)
{
#ifdef OS_UNIX
	assert (p11_path_absolute ("/home"));
	assert (!p11_path_absolute ("home"));
#else /* OS_WIN32 */
	assert (p11_path_absolute ("C:\\home"));
	assert (!p11_path_absolute ("home"));
	assert (p11_path_absolute ("/home"));
#endif
}

int
main (int argc,
      char *argv[])
{
	p11_test (test_base, "/path/base");
	p11_test (test_build, "/path/build");
	p11_test (test_expand, "/path/expand");
	p11_test (test_absolute, "/path/absolute");

	return p11_test_run (argc, argv);
}
