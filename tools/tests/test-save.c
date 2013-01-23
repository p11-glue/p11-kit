/*
 * Copyright (c) 2013, Red Hat Inc.
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
 * Author: Stef Walter <stefw@collabora.co.uk>
 */

#include "config.h"
#include "CuTest.h"

#include "attrs.h"
#include "compat.h"
#include "debug.h"
#include "dict.h"
#include "library.h"
#include "save.h"
#include "test.h"

#include <sys/stat.h>
#include <sys/types.h>

#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

struct {
	char *directory;
} test;

static void
setup (CuTest *tc)
{
	test.directory = strdup ("/tmp/test-extract.XXXXXX");
	if (!mkdtemp (test.directory))
		CuFail (tc, "mkdtemp() failed");
}

static void
teardown (CuTest *tc)
{
	if (rmdir (test.directory) < 0)
		CuFail (tc, "rmdir() failed");
	free (test.directory);
}

static void
write_zero_file (CuTest *tc,
                 const char *directory,
                 const char *name)
{
	char *filename;
	int res;
	int fd;

	if (asprintf (&filename, "%s/%s", directory, name) < 0)
		CuFail (tc, "asprintf() failed");

	fd = open (filename, O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR);
	CuAssertTrue (tc, fd != -1);
	res = close (fd);
	CuAssertTrue (tc, res >= 0);
}

static void
test_file_write (CuTest *tc)
{
	p11_save_file *file;
	char *filename;
	bool ret;

	setup (tc);

	if (asprintf (&filename, "%s/%s", test.directory, "extract-file") < 0)
		CuFail (tc, "asprintf() failed");

	file = p11_save_open_file (filename, 0);
	CuAssertPtrNotNull (tc, file);

	ret = p11_save_write_and_finish (file, test_cacert3_ca_der, sizeof (test_cacert3_ca_der));
	CuAssertIntEquals (tc, true, ret);
	free (filename);

	test_check_file (tc, test.directory, "extract-file", SRCDIR "/files/cacert3.der");

	teardown (tc);
}

static void
test_file_exists (CuTest *tc)
{
	p11_save_file *file;
	char *filename;

	setup (tc);

	if (asprintf (&filename, "%s/%s", test.directory, "extract-file") < 0)
		CuFail (tc, "asprintf() failed");

	write_zero_file (tc, test.directory, "extract-file");

	p11_message_quiet ();

	file = p11_save_open_file (filename, 0);
	CuAssertTrue (tc, file == NULL);

	p11_message_loud ();

	unlink (filename);
	free (filename);
	teardown (tc);
}

static void
test_file_bad_directory (CuTest *tc)
{
	p11_save_file *file;
	char *filename;

	setup (tc);

	if (asprintf (&filename, "/non-existent/%s/%s", test.directory, "extract-file") < 0)
		CuFail (tc, "asprintf() failed");

	p11_message_quiet ();

	file = p11_save_open_file (filename, 0);
	CuAssertTrue (tc, file == NULL);

	p11_message_loud ();

	free (filename);
	teardown (tc);
}

static void
test_file_overwrite (CuTest *tc)
{
	p11_save_file *file;
	char *filename;
	bool ret;

	setup (tc);

	if (asprintf (&filename, "%s/%s", test.directory, "extract-file") < 0)
		CuFail (tc, "asprintf() failed");

	write_zero_file (tc, test.directory, "extract-file");

	file = p11_save_open_file (filename, P11_SAVE_OVERWRITE);
	CuAssertPtrNotNull (tc, file);

	ret = p11_save_write_and_finish (file, test_cacert3_ca_der, sizeof (test_cacert3_ca_der));
	CuAssertIntEquals (tc, true, ret);
	free (filename);

	test_check_file (tc, test.directory, "extract-file", SRCDIR "/files/cacert3.der");

	teardown (tc);
}

static void
test_write_with_null (CuTest *tc)
{
	bool ret;

	ret = p11_save_write (NULL, "test", 4);
	CuAssertIntEquals (tc, false, ret);
}

static void
test_write_and_finish_with_null (CuTest *tc)
{
	bool ret;

	ret = p11_save_write_and_finish (NULL, "test", 4);
	CuAssertIntEquals (tc, false, ret);
}

static void
test_file_abort (CuTest *tc)
{
	struct stat st;
	p11_save_file *file;
	char *filename;
	bool ret;

	setup (tc);

	if (asprintf (&filename, "%s/%s", test.directory, "extract-file") < 0)
		CuFail (tc, "asprintf() failed");

	file = p11_save_open_file (filename, 0);
	CuAssertPtrNotNull (tc, file);

	ret = p11_save_finish_file (file, false);
	CuAssertIntEquals (tc, true, ret);

	if (stat (filename, &st) >= 0 || errno != ENOENT)
		CuFail (tc, "file should not exist");

	free (filename);

	teardown (tc);
}


static void
test_directory_empty (CuTest *tc)
{
	p11_save_dir *dir;
	char *subdir;
	bool ret;

	setup (tc);

	if (asprintf (&subdir, "%s/%s", test.directory, "extract-dir") < 0)
		CuFail (tc, "asprintf() failed");

	dir = p11_save_open_directory (subdir, 0);
	CuAssertPtrNotNull (tc, dir);

	ret = p11_save_finish_directory (dir, true);
	CuAssertIntEquals (tc, true, ret);

	test_check_directory (tc, subdir, (NULL, NULL));

	rmdir (subdir);
	free (subdir);

	teardown (tc);
}

static void
test_directory_files (CuTest *tc)
{
	const char *filename;
	p11_save_dir *dir;
	char *subdir;
	bool ret;

	setup (tc);

	if (asprintf (&subdir, "%s/%s", test.directory, "extract-dir") < 0)
		CuFail (tc, "asprintf() failed");

	dir = p11_save_open_directory (subdir, 0);
	CuAssertPtrNotNull (tc, dir);

	ret = p11_save_write_and_finish (p11_save_open_file_in (dir, "blah", ".cer", &filename),
	                                 test_cacert3_ca_der, sizeof (test_cacert3_ca_der));
	CuAssertIntEquals (tc, true, ret);
	CuAssertStrEquals (tc, "blah.cer", filename);

	ret = p11_save_write_and_finish (p11_save_open_file_in (dir, "file", ".txt", &filename),
	                                 test_text, strlen (test_text));
	CuAssertIntEquals (tc, true, ret);
	CuAssertStrEquals (tc, "file.txt", filename);

	ret = p11_save_symlink_in (dir, "link", ".ext", "/the/destination");
	CuAssertIntEquals (tc, true, ret);

	ret = p11_save_finish_directory (dir, true);
	CuAssertIntEquals (tc, true, ret);

	test_check_directory (tc, subdir, ("blah.cer", "file.txt", "link.ext", NULL));
	test_check_file (tc, subdir, "blah.cer", SRCDIR "/files/cacert3.der");
	test_check_data (tc, subdir, "file.txt", test_text, strlen (test_text));
	test_check_symlink (tc, subdir, "link.ext", "/the/destination");

	rmdir (subdir);
	free (subdir);

	teardown (tc);
}

static void
test_directory_dups (CuTest *tc)
{
	const char *filename;
	p11_save_dir *dir;
	char *subdir;
	bool ret;

	setup (tc);

	if (asprintf (&subdir, "%s/%s", test.directory, "extract-dir") < 0)
		CuFail (tc, "asprintf() failed");

	dir = p11_save_open_directory (subdir, 0);
	CuAssertPtrNotNull (tc, dir);

	ret = p11_save_write_and_finish (p11_save_open_file_in (dir, "file", ".txt", &filename),
	                                 test_text, 5);
	CuAssertIntEquals (tc, true, ret);
	CuAssertStrEquals (tc, "file.txt", filename);

	ret = p11_save_write_and_finish (p11_save_open_file_in (dir, "file", ".txt", &filename),
	                                 test_text, 10);
	CuAssertIntEquals (tc, true, ret);
	CuAssertStrEquals (tc, "file.1.txt", filename);

	ret = p11_save_write_and_finish (p11_save_open_file_in (dir, "file", ".txt", NULL),
	                                 test_text, 15);
	CuAssertIntEquals (tc, true, ret);

	ret = p11_save_write_and_finish (p11_save_open_file_in (dir, "no-ext", NULL, NULL),
	                                 test_text, 8);
	CuAssertIntEquals (tc, true, ret);

	ret = p11_save_write_and_finish (p11_save_open_file_in (dir, "no-ext", NULL, NULL),
	                                 test_text, 16);
	CuAssertIntEquals (tc, true, ret);

	ret = p11_save_write_and_finish (p11_save_open_file_in (dir, "with-num", ".0", NULL),
	                                 test_text, 14);
	CuAssertIntEquals (tc, true, ret);

	ret = p11_save_write_and_finish (p11_save_open_file_in (dir, "with-num", ".0", NULL),
	                                 test_text, 15);
	CuAssertIntEquals (tc, true, ret);

	ret = p11_save_symlink_in (dir, "link", ".0", "/destination1");
	CuAssertIntEquals (tc, true, ret);

	ret = p11_save_symlink_in (dir, "link", ".0", "/destination2");
	CuAssertIntEquals (tc, true, ret);

	ret = p11_save_finish_directory (dir, true);
	CuAssertIntEquals (tc, true, ret);

	test_check_directory (tc, subdir, ("file.txt", "file.1.txt", "file.2.txt",
	                                   "no-ext", "no-ext.1",
	                                   "with-num.0", "with-num.1",
	                                   "link.0", "link.1",
	                                   NULL));
	test_check_data (tc, subdir, "file.txt", test_text, 5);
	test_check_data (tc, subdir, "file.1.txt", test_text, 10);
	test_check_data (tc, subdir, "file.2.txt", test_text, 15);
	test_check_data (tc, subdir, "no-ext", test_text, 8);
	test_check_data (tc, subdir, "no-ext.1", test_text, 16);
	test_check_data (tc, subdir, "with-num.0", test_text, 14);
	test_check_data (tc, subdir, "with-num.1", test_text, 15);
	test_check_symlink (tc, subdir, "link.0", "/destination1");
	test_check_symlink (tc, subdir, "link.1", "/destination2");

	rmdir (subdir);
	free (subdir);

	teardown (tc);
}

static void
test_directory_exists (CuTest *tc)
{
	p11_save_dir *dir;
	char *subdir;

	setup (tc);

	if (asprintf (&subdir, "%s/%s", test.directory, "extract-dir") < 0)
		CuFail (tc, "asprintf() failed");

	if (mkdir (subdir, S_IRWXU) < 0)
		CuFail (tc, "mkdir() failed");

	p11_message_quiet ();

	dir = p11_save_open_directory (subdir, 0);
	CuAssertPtrEquals (tc, NULL, dir);

	p11_message_loud ();

	rmdir (subdir);
	free (subdir);

	teardown (tc);
}

static void
test_directory_overwrite (CuTest *tc)
{
	const char *filename;
	p11_save_dir *dir;
	char *subdir;
	bool ret;

	setup (tc);

	if (asprintf (&subdir, "%s/%s", test.directory, "extract-dir") < 0)
		CuFail (tc, "asprintf() failed");

	if (mkdir (subdir, S_IRWXU) < 0)
		CuFail (tc, "mkdir() failed");

	/* Some initial files into this directory, which get overwritten */
	write_zero_file (tc, subdir, "file.txt");
	write_zero_file (tc, subdir, "another-file");
	write_zero_file (tc, subdir, "third-file");

	dir = p11_save_open_directory (subdir, P11_SAVE_OVERWRITE);
	CuAssertPtrNotNull (tc, dir);

	ret = p11_save_write_and_finish (p11_save_open_file_in (dir, "blah", ".cer", &filename),
	                                 test_cacert3_ca_der, sizeof (test_cacert3_ca_der));
	CuAssertIntEquals (tc, true, ret);
	CuAssertStrEquals (tc, "blah.cer", filename);

	ret = p11_save_write_and_finish (p11_save_open_file_in (dir, "file", ".txt", &filename),
	                                 test_text, strlen (test_text));
	CuAssertIntEquals (tc, true, ret);
	CuAssertStrEquals (tc, "file.txt", filename);

	ret = p11_save_write_and_finish (p11_save_open_file_in (dir, "file", ".txt", &filename),
	                                 test_text, 10);
	CuAssertIntEquals (tc, true, ret);
	CuAssertStrEquals (tc, "file.1.txt", filename);

	ret = p11_save_finish_directory (dir, true);
	CuAssertIntEquals (tc, true, ret);

	test_check_directory (tc, subdir, ("blah.cer", "file.txt", "file.1.txt", NULL));
	test_check_data (tc, subdir, "blah.cer", test_cacert3_ca_der, sizeof (test_cacert3_ca_der));
	test_check_data (tc, subdir, "file.txt", test_text, strlen (test_text));
	test_check_data (tc, subdir, "file.1.txt", test_text, 10);

	rmdir (subdir);
	free (subdir);

	teardown (tc);
}

int
main (void)
{
	CuString *output = CuStringNew ();
	CuSuite* suite = CuSuiteNew ();
	int ret;

	SUITE_ADD_TEST (suite, test_file_write);
	SUITE_ADD_TEST (suite, test_file_exists);
	SUITE_ADD_TEST (suite, test_file_bad_directory);
	SUITE_ADD_TEST (suite, test_file_overwrite);
	SUITE_ADD_TEST (suite, test_write_with_null);
	SUITE_ADD_TEST (suite, test_write_and_finish_with_null);
	SUITE_ADD_TEST (suite, test_file_abort);

	SUITE_ADD_TEST (suite, test_directory_empty);
	SUITE_ADD_TEST (suite, test_directory_files);
	SUITE_ADD_TEST (suite, test_directory_dups);
	SUITE_ADD_TEST (suite, test_directory_exists);
	SUITE_ADD_TEST (suite, test_directory_overwrite);

	CuSuiteRun (suite);
	CuSuiteSummary (suite, output);
	CuSuiteDetails (suite, output);
	printf ("%s\n", output->buffer);
	ret = suite->failCount;
	CuSuiteDelete (suite);
	CuStringDelete (output);

	return ret;
}
