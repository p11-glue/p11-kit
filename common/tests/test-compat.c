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

#ifdef OS_UNIX
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

static void
test_strndup (CuTest *tc)
{
	char unterminated[] = { 't', 'e', 's', 't', 'e', 'r', 'o', 'n', 'i', 'o' };
	char *res;

	res = strndup (unterminated, 6);
	CuAssertStrEquals (tc, res, "tester");
	free (res);

	res = strndup ("test", 6);
	CuAssertStrEquals (tc, res, "test");
	free (res);
}

#ifdef OS_UNIX

static void
copy_file (CuTest *tc,
           const char *input,
           int fd)
{
	p11_mmap *mmap;
	const char *data;
	ssize_t written;
	size_t size;

	mmap = p11_mmap_open (input, (void **)&data, &size);
	CuAssertPtrNotNull (tc, mmap);

	while (size > 0) {
		written = write (fd, data, size);
		CuAssertTrue (tc, written >= 0);

		data += written;
		size -= written;
	}

	p11_mmap_close (mmap);
}

static int
run_process_with_arg (CuTest *tc,
                      char *path,
                      char *arg)
{
	char *argv[] = { path, arg, NULL };
	pid_t child;
	int status;

	child = fork ();
	CuAssertTrue (tc, child >= 0);

	/* In the child process? */
	if (child == 0) {
		close (1); /* stdout */
		execve (path, argv, NULL);
		abort ();
	}

	if (waitpid (child, &status, 0) < 0) {
		CuFail (tc, "not reached");
	}

	CuAssertTrue (tc, !WIFSIGNALED (status));
	CuAssertTrue (tc, WIFEXITED (status));

	return WEXITSTATUS (status);
}

static void
test_getauxval (CuTest *tc)
{
	gid_t groups[128];
	char *path;
	gid_t group = 0;
	int ret;
	int fd;
	int i;

	/* 23 is AT_SECURE */
	ret = run_process_with_arg (tc, BUILDDIR "/frob-getauxval", "23");
	CuAssertIntEquals (tc, ret, 0);

	ret = getgroups (128, groups);
	CuAssertTrue (tc, ret >= 0);
	for (i = 0; i < ret; ++i) {
		if (groups[i] != getgid ()) {
			group = groups[i];
			break;
		}
	}
	if (i == ret) {
		fprintf (stderr, "no suitable group, skipping test");
		return;
	}

	path = strdup ("/tmp/frob-getauxval.XXXXXX");
	CuAssertPtrNotNull (tc, path);

	fd = mkstemp (path);
	CuAssertTrue (tc, fd >= 0);
	copy_file (tc, BUILDDIR "/frob-getauxval", fd);
	if (fchown (fd, getuid (), group) < 0)
		CuFail (tc, "fchown failed");
	if (fchmod (fd, 02750) < 0)
		CuFail (tc, "fchmod failed");
	if (close (fd) < 0)
		CuFail (tc, "close failed");

	ret = run_process_with_arg (tc, path, "23");
	CuAssertTrue (tc, ret != 0);

	if (unlink (path) < 0)
		CuFail (tc, "unlink failed");
	free (path);
}

#endif /* OS_UNIX */

int
main (void)
{
	CuString *output = CuStringNew ();
	CuSuite* suite = CuSuiteNew ();
	int ret;

	SUITE_ADD_TEST (suite, test_strndup);
#ifdef OS_UNIX
	/* Don't run this test when under fakeroot */
	if (!getenv ("FAKED_MODE")) {
		SUITE_ADD_TEST (suite, test_getauxval);
	}
#endif

	CuSuiteRun (suite);
	CuSuiteSummary (suite, output);
	CuSuiteDetails (suite, output);
	printf ("%s\n", output->buffer);
	ret = suite->failCount;
	CuSuiteDelete (suite);
	CuStringDelete (output);

	return ret;
}
