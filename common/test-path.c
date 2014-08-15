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

#define assert_str_eq_free(ex, ac) \
	do { const char *__s1 = (ex); \
	     char *__s2 = (ac); \
	     if (__s1 && __s2 && strcmp (__s1, __s2) == 0) ; else \
	         p11_test_fail (__FILE__, __LINE__, __FUNCTION__, "assertion failed (%s == %s): (%s == %s)", \
	                        #ex, #ac, __s1 ? __s1 : "(null)", __s2 ? __s2 : "(null)"); \
	     free (__s2); \
	} while (0)

static void
test_build (void)
{
#ifdef OS_UNIX
	assert_str_eq_free ("/root/second",
	                    p11_path_build ("/root", "second", NULL));
	assert_str_eq_free ("/root/second",
	                    p11_path_build ("/root", "/second", NULL));
	assert_str_eq_free ("/root/second",
	                    p11_path_build ("/root/", "second", NULL));
	assert_str_eq_free ("/root/second/third",
	                    p11_path_build ("/root", "second", "third", NULL));
	assert_str_eq_free ("/root/second/third",
	                    p11_path_build ("/root", "/second/third", NULL));
#else /* OS_WIN32 */
	assert_str_eq_free ("C:\\root\\second",
	                    p11_path_build ("C:\\root", "second", NULL));
	assert_str_eq_free ("C:\\root\\second",
	                    p11_path_build ("C:\\root", "\\second", NULL));
	assert_str_eq_free ("C:\\root\\second",
	                    p11_path_build ("C:\\root\\", "second", NULL));
	assert_str_eq_free ("C:\\root\\second\\third",
	                    p11_path_build ("C:\\root", "second", "third", NULL));
	assert_str_eq_free ("C:\\root\\second/third",
	                    p11_path_build ("C:\\root", "second/third", NULL));
#endif
}

static void
test_expand (void)
{
	char *path;

#ifdef OS_UNIX
	putenv ("HOME=/home/blah");
	assert_str_eq_free ("/home/blah/my/path",
	                    p11_path_expand ("~/my/path"));
	assert_str_eq_free ("/home/blah",
	                    p11_path_expand ("~"));
	putenv ("XDG_CONFIG_HOME=/my");
	assert_str_eq_free ("/my/path",
	                    p11_path_expand ("~/.config/path"));
	putenv ("XDG_CONFIG_HOME=");
	assert_str_eq_free ("/home/blah/.config/path",
	                    p11_path_expand ("~/.config/path"));
#else /* OS_WIN32 */
	putenv ("HOME=C:\\Users\\blah");
	assert_str_eq_free ("C:\\Users\\blah\\path",
	                    p11_path_expand ("~/my/path"));
	assert_str_eq_free ("C:\\Users\\blah\\path",
	                    p11_path_expand ("~\\path"));
#endif

	putenv("HOME=");
	path = p11_path_expand ("~/this/is/my/path");
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

static void
test_parent (void)
{
	assert_str_eq_free ("/", p11_path_parent ("/root"));
	assert_str_eq_free ("/", p11_path_parent ("/root/"));
	assert_str_eq_free ("/", p11_path_parent ("/root//"));
	assert_str_eq_free ("/root", p11_path_parent ("/root/second"));
	assert_str_eq_free ("/root", p11_path_parent ("/root//second"));
	assert_str_eq_free ("/root", p11_path_parent ("/root//second//"));
	assert_str_eq_free ("/root", p11_path_parent ("/root///second"));
	assert_str_eq_free ("/root/second", p11_path_parent ("/root/second/test.file"));
	assert_ptr_eq (NULL, p11_path_parent ("/"));
	assert_ptr_eq (NULL, p11_path_parent ("//"));
	assert_ptr_eq (NULL, p11_path_parent (""));
}

static void
test_prefix (void)
{
	assert (p11_path_prefix ("/test/second", "/test"));
	assert (!p11_path_prefix ("/test", "/test"));
	assert (!p11_path_prefix ("/different/prefix", "/test"));
	assert (!p11_path_prefix ("/te", "/test"));
	assert (!p11_path_prefix ("/test", "/test/blah"));
	assert (p11_path_prefix ("/test/other/second", "/test"));
	assert (p11_path_prefix ("/test//other//second", "/test"));
}

static void
test_canon (void)
{
	char *test;

	test = strdup ("2309haonutb;AOE@#$O ");
	p11_path_canon (test);
	assert_str_eq (test, "2309haonutb_AOE___O_");
	free (test);

	test = strdup ("22@# %ATI@#$onot");
	p11_path_canon (test);
	assert_str_eq (test, "22____ATI___onot");
	free (test);
}

int
main (int argc,
      char *argv[])
{
	p11_test (test_base, "/path/base");
	p11_test (test_build, "/path/build");
	p11_test (test_expand, "/path/expand");
	p11_test (test_absolute, "/path/absolute");
	p11_test (test_parent, "/path/parent");
	p11_test (test_prefix, "/path/prefix");
	p11_test (test_canon, "/path/canon");

	return p11_test_run (argc, argv);
}
