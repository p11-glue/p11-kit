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

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "compat.h"

static void
test_strndup (void)
{
	char unterminated[] = { 't', 'e', 's', 't', 'e', 'r', 'o', 'n', 'i', 'o' };
	char *res;

	res = strndup (unterminated, 6);
	assert_str_eq (res, "tester");
	free (res);

	res = strndup ("test", 6);
	assert_str_eq (res, "test");
	free (res);
}

#ifdef OS_UNIX

static void
test_getauxval (void)
{
	/* 23 is AT_SECURE */
	const char *args[] = { BUILDDIR "/frob-getauxval", "23", NULL };
	char *path;
	int ret;

	ret = p11_test_run_child (args, true);
	assert_num_eq (ret, 0);

	path = p11_test_copy_setgid (args[0]);
	if (path == NULL)
		return;

	args[0] = path;
	ret = p11_test_run_child (args, true);
	assert_num_cmp (ret, !=, 0);

	if (unlink (path) < 0)
		assert_fail ("unlink failed", strerror (errno));
	free (path);
}

static void
test_secure_getenv (void)
{
	const char *args[] = { BUILDDIR "/frob-getenv", "BLAH", NULL };
	char *path;
	int ret;

	setenv ("BLAH", "5", 1);

	ret = p11_test_run_child (args, true);
	assert_num_eq (ret, 5);

	path = p11_test_copy_setgid (args[0]);
	if (path == NULL)
		return;

	args[0] = path;
	ret = p11_test_run_child (args, true);
	assert_num_cmp (ret, ==, 0);

/*	if (unlink (path) < 0)
		assert_fail ("unlink failed", strerror (errno));
		*/
	free (path);
}

static void
test_mmap (void)
{
	p11_mmap *map;
	void *data;
	size_t size;
	char file[] = "emptyfileXXXXXX";
	int fd = mkstemp (file);
	close (fd);
	/* mmap on empty file should work */
	map = p11_mmap_open (file, NULL, &data, &size);
	unlink (file);
	assert_ptr_not_null (map);
	p11_mmap_close (map);
}

#endif /* OS_UNIX */

int
main (int argc,
      char *argv[])
{
	p11_test (test_strndup, "/compat/strndup");
#ifdef OS_UNIX
	/* Don't run this test when under fakeroot */
	if (!getenv ("FAKED_MODE")) {
		p11_test (test_getauxval, "/compat/getauxval");
		p11_test (test_secure_getenv, "/compat/secure_getenv");
	}
	p11_test (test_mmap, "/compat/mmap");
#endif
	return p11_test_run (argc, argv);
}
