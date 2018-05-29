/*
 * Copyright (c) 2018 Red Hat Inc
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
#include "test.h"

#include "runtime.h"
#include "compat.h"

#include <stdio.h>
#include <stdlib.h>

#ifdef OS_UNIX
#include <unistd.h>
#include <sys/types.h>
#endif

static struct {
	char *directory;
} test;

extern const char * const *_p11_runtime_bases;

static void
setup (void *unused)
{
	test.directory = p11_test_directory ("p11-test-runtime");
}

static void
teardown (void *unused)
{
	p11_test_directory_delete (test.directory);
	free (test.directory);
}

static void
test_xdg_runtime_dir (void)
{
	char *directory;

	setenv ("XDG_RUNTIME_DIR", "/nowhere", 1);
	p11_get_runtime_directory (&directory);
	assert_str_eq ("/nowhere", directory);
	free (directory);
}

#ifdef OS_UNIX
static void
test_bases (void)
{
	char *directory;
	const char * bases[] = {
		NULL,
		NULL
	};
	char *user, *path;
	CK_RV rv;

	if (asprintf (&user, "%s/user", test.directory) < 0)
		assert_not_reached ();
	if (mkdir (user, 0700) < 0)
		assert_not_reached ();
	if (asprintf (&path, "%s/%d", user, getuid ()) < 0)
		assert_not_reached ();
	free (user);
	if (mkdir (path, 0700) < 0)
		assert_not_reached ();

	bases[0] = test.directory;
	_p11_runtime_bases = bases;

	unsetenv ("XDG_RUNTIME_DIR");
	rv = p11_get_runtime_directory (&directory);
	assert_num_eq (CKR_OK, rv);
	assert_str_eq (path, directory);
	free (path);
	free (directory);
}
#endif

static void
test_xdg_cache_home (void)
{
	char *directory;
#ifdef OS_UNIX
	const char * bases[] = {
		NULL
	};
	_p11_runtime_bases = bases;
#endif

	/* MinGW doesn't have unsetenv */
	setenv ("XDG_RUNTIME_DIR", "", 1);
	setenv ("XDG_CACHE_HOME", "/cache", 1);
	p11_get_runtime_directory (&directory);
	assert_str_eq ("/cache", directory);
	free (directory);
}

int
main (int argc,
      char *argv[])
{
	p11_fixture (setup, teardown);
	p11_test (test_xdg_runtime_dir, "/runtime/xdg-runtime-dir");
#ifdef OS_UNIX
	p11_test (test_bases, "/runtime/bases");
#endif
	p11_test (test_xdg_cache_home, "/runtime/xdg-cache-home");
	p11_test_run (argc, argv);
}
