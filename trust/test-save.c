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

#include "test-trust.h"

#include "attrs.h"
#include "compat.h"
#include "debug.h"
#include "dict.h"
#include "message.h"
#include "path.h"
#include "save.h"
#include "test.h"

#include <sys/stat.h>
#include <sys/types.h>

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
setup (void *unused)
{
	test.directory = p11_test_directory ("test-extract");
}

static void
teardown (void *unused)
{
	if (rmdir (test.directory) < 0)
		assert_fail ("rmdir() failed", strerror (errno));
	free (test.directory);
}

static void
write_zero_file (const char *directory,
                 const char *name)
{
	char *filename;
	int res;
	int fd;

	if (asprintf (&filename, "%s/%s", directory, name) < 0)
		assert_not_reached ();

	fd = open (filename, O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR);
	assert (fd != -1);
	res = close (fd);
	assert (res >= 0);

	free (filename);
}

static void
test_file_write (void)
{
	p11_save_file *file;
	char *filename;
	bool ret;

	if (asprintf (&filename, "%s/%s", test.directory, "extract-file") < 0)
		assert_not_reached ();

	file = p11_save_open_file (filename, NULL, 0);
	assert_ptr_not_null (file);

	ret = p11_save_write_and_finish (file, test_cacert3_ca_der, sizeof (test_cacert3_ca_der));
	assert_num_eq (true, ret);
	free (filename);

	test_check_file (test.directory, "extract-file", SRCDIR "/trust/fixtures/cacert3.der");
}

static void
test_file_exists (void)
{
	p11_save_file *file;
	char *filename;

	if (asprintf (&filename, "%s/%s", test.directory, "extract-file") < 0)
		assert_not_reached ();

	write_zero_file (test.directory, "extract-file");

	p11_message_quiet ();

	file = p11_save_open_file (filename, NULL, 0);
	assert (file != NULL);

	if (p11_save_finish_file (file, NULL, true))
		assert_not_reached ();

	p11_message_loud ();

	unlink (filename);
	free (filename);
}

static void
test_file_bad_directory (void)
{
	p11_save_file *file;
	char *filename;

	if (asprintf (&filename, "/non-existent/%s/%s", test.directory, "extract-file") < 0)
		assert_not_reached ();

	p11_message_quiet ();

	file = p11_save_open_file (filename, NULL, 0);
	assert (file == NULL);

	p11_message_loud ();

	free (filename);
}

static void
test_file_overwrite (void)
{
	p11_save_file *file;
	char *filename;
	bool ret;

	if (asprintf (&filename, "%s/%s", test.directory, "extract-file") < 0)
		assert_not_reached ();

	write_zero_file (test.directory, "extract-file");

	file = p11_save_open_file (filename, NULL, P11_SAVE_OVERWRITE);
	assert_ptr_not_null (file);

	ret = p11_save_write_and_finish (file, test_cacert3_ca_der, sizeof (test_cacert3_ca_der));
	assert_num_eq (true, ret);
	free (filename);

	test_check_file (test.directory, "extract-file", SRCDIR "/trust/fixtures/cacert3.der");
}

static void
test_file_unique (void)
{
	p11_save_file *file;
	char *filename;
	bool ret;

	if (asprintf (&filename, "%s/%s", test.directory, "extract-file") < 0)
		assert_not_reached ();

	write_zero_file (test.directory, "extract-file");

	file = p11_save_open_file (filename, NULL, P11_SAVE_UNIQUE);
	assert_ptr_not_null (file);

	ret = p11_save_write_and_finish (file, test_cacert3_ca_der, sizeof (test_cacert3_ca_der));
	assert_num_eq (true, ret);
	free (filename);

	test_check_file (test.directory, "extract-file", SRCDIR "/trust/fixtures/empty-file");
	test_check_file (test.directory, "extract-file.1", SRCDIR "/trust/fixtures/cacert3.der");
}

static void
test_file_auto_empty (void)
{
	p11_save_file *file;
	char *filename;
	bool ret;

	if (asprintf (&filename, "%s/%s", test.directory, "extract-file") < 0)
		assert_not_reached ();

	file = p11_save_open_file (filename, NULL, 0);
	assert_ptr_not_null (file);

	ret = p11_save_write_and_finish (file, NULL, -1);
	assert_num_eq (true, ret);
	free (filename);

	test_check_file (test.directory, "extract-file", SRCDIR "/trust/fixtures/empty-file");
}

static void
test_file_auto_length (void)
{
	p11_save_file *file;
	char *filename;
	bool ret;

	if (asprintf (&filename, "%s/%s", test.directory, "extract-file") < 0)
		assert_not_reached ();

	file = p11_save_open_file (filename, NULL, 0);
	assert_ptr_not_null (file);

	ret = p11_save_write_and_finish (file, "The simple string is hairy", -1);
	assert_num_eq (true, ret);
	free (filename);

	test_check_file (test.directory, "extract-file", SRCDIR "/trust/fixtures/simple-string");
}

static void
test_write_with_null (void)
{
	bool ret;

	ret = p11_save_write (NULL, "test", 4);
	assert_num_eq (false, ret);
}

static void
test_write_and_finish_with_null (void)
{
	bool ret;

	ret = p11_save_write_and_finish (NULL, "test", 4);
	assert_num_eq (false, ret);
}

static void
test_file_abort (void)
{
	struct stat st;
	p11_save_file *file;
	char *filename;
	char *path;
	bool ret;

	if (asprintf (&filename, "%s/%s", test.directory, "extract-file") < 0)
		assert_not_reached ();

	file = p11_save_open_file (filename, NULL, 0);
	assert_ptr_not_null (file);

	path = NULL;
	ret = p11_save_finish_file (file, &path, false);
	assert_num_eq (true, ret);
	assert (path == NULL);

	if (stat (filename, &st) >= 0 || errno != ENOENT)
		assert_fail ("file should not exist", filename);

	free (filename);
}


static void
test_directory_empty (void)
{
	p11_save_dir *dir;
	char *subdir;
	bool ret;

	if (asprintf (&subdir, "%s/%s", test.directory, "extract-dir") < 0)
		assert_not_reached ();

	dir = p11_save_open_directory (subdir, 0);
	assert_ptr_not_null (dir);

	ret = p11_save_finish_directory (dir, true);
	assert_num_eq (true, ret);

	test_check_directory (subdir, (NULL, NULL));

	assert (rmdir (subdir) >= 0);
	free (subdir);
}

static void
test_directory_files (void)
{
	char *path;
	char *check;
	p11_save_file *file;
	p11_save_dir *dir;
	char *subdir;
	bool ret;

	if (asprintf (&subdir, "%s/%s", test.directory, "extract-dir") < 0)
		assert_not_reached ();

	dir = p11_save_open_directory (subdir, 0);
	assert_ptr_not_null (dir);

	file = p11_save_open_file_in (dir, "blah", ".cer");
	assert_ptr_not_null (file);
	ret = p11_save_write (file, test_cacert3_ca_der, sizeof (test_cacert3_ca_der));
	assert_num_eq (true, ret);
	ret = p11_save_finish_file (file, &path, true);
	assert_num_eq (true, ret);
	if (asprintf (&check, "%s/%s", subdir, "blah.cer") < 0)
		assert_not_reached ();
	assert_str_eq (check, path);
	free (check);
	free (path);

	file = p11_save_open_file_in (dir, "file", ".txt");
	assert_ptr_not_null (file);
	ret = p11_save_write (file, test_text, strlen (test_text));
	assert_num_eq (true, ret);
	ret = p11_save_finish_file (file, &path, true);
	assert_num_eq (true, ret);
	if (asprintf (&check, "%s/%s", subdir, "file.txt") < 0)
		assert_not_reached ();
	assert_str_eq (check, path);
	free (check);
	free (path);

#ifdef OS_UNIX
	ret = p11_save_symlink_in (dir, "link", ".ext", "/the/destination");
	assert_num_eq (true, ret);
#endif

	ret = p11_save_finish_directory (dir, true);
	assert_num_eq (true, ret);

	test_check_directory (subdir, ("blah.cer", "file.txt",
#ifdef OS_UNIX
	                      "link.ext",
#endif
	                      NULL));
	test_check_file (subdir, "blah.cer", SRCDIR "/trust/fixtures/cacert3.der");
	test_check_data (subdir, "file.txt", test_text, strlen (test_text));
#ifdef OS_UNIX
	test_check_symlink (subdir, "link.ext", "/the/destination");
#endif

	assert (rmdir (subdir) >= 0);
	free (subdir);
}

static void
test_directory_dups (void)
{
	char *path;
	char *check;
	p11_save_file *file;
	p11_save_dir *dir;
	char *subdir;
	bool ret;

	if (asprintf (&subdir, "%s/%s", test.directory, "extract-dir") < 0)
		assert_not_reached ();

	dir = p11_save_open_directory (subdir, 0);
	assert_ptr_not_null (dir);

	file = p11_save_open_file_in (dir, "file", ".txt");
	assert_ptr_not_null (file);
	ret = p11_save_write (file, test_text, 5);
	assert_num_eq (true, ret);
	ret = p11_save_finish_file (file, &path, true);
	assert_num_eq (true, ret);
	if (asprintf (&check, "%s/%s", subdir, "file.txt") < 0)
		assert_not_reached ();
	assert_str_eq (check, path);
	free (check);
	free (path);

	file = p11_save_open_file_in (dir, "file", ".txt");
	assert_ptr_not_null (file);
	ret = p11_save_write (file, test_text, 10);
	assert_num_eq (true, ret);
	ret = p11_save_finish_file (file, &path, true);
	assert_num_eq (true, ret);
	if (asprintf (&check, "%s/%s", subdir, "file.1.txt") < 0)
		assert_not_reached ();
	assert_str_eq (check, path);
	free (check);
	free (path);

	ret = p11_save_write_and_finish (p11_save_open_file_in (dir, "file", ".txt"),
	                                 test_text, 15);
	assert_num_eq (true, ret);

	ret = p11_save_write_and_finish (p11_save_open_file_in (dir, "no-ext", NULL),
	                                 test_text, 8);
	assert_num_eq (true, ret);

	ret = p11_save_write_and_finish (p11_save_open_file_in (dir, "no-ext", NULL),
	                                 test_text, 16);
	assert_num_eq (true, ret);

	ret = p11_save_write_and_finish (p11_save_open_file_in (dir, "with-num", ".0"),
	                                 test_text, 14);
	assert_num_eq (true, ret);

	ret = p11_save_write_and_finish (p11_save_open_file_in (dir, "with-num", ".0"),
	                                 test_text, 15);
	assert_num_eq (true, ret);

#ifdef OS_UNIX
	ret = p11_save_symlink_in (dir, "link", ".0", "/destination1");
	assert_num_eq (true, ret);

	ret = p11_save_symlink_in (dir, "link", ".0", "/destination2");
	assert_num_eq (true, ret);
#endif

	ret = p11_save_finish_directory (dir, true);
	assert_num_eq (true, ret);

	test_check_directory (subdir, ("file.txt", "file.1.txt", "file.2.txt",
	                                   "no-ext", "no-ext.1",
	                                   "with-num.0", "with-num.1",
#ifdef OS_UNIX
	                                   "link.0", "link.1",
#endif
	                                   NULL));
	test_check_data (subdir, "file.txt", test_text, 5);
	test_check_data (subdir, "file.1.txt", test_text, 10);
	test_check_data (subdir, "file.2.txt", test_text, 15);
	test_check_data (subdir, "no-ext", test_text, 8);
	test_check_data (subdir, "no-ext.1", test_text, 16);
	test_check_data (subdir, "with-num.0", test_text, 14);
	test_check_data (subdir, "with-num.1", test_text, 15);
#ifdef OS_UNIX
	test_check_symlink (subdir, "link.0", "/destination1");
	test_check_symlink (subdir, "link.1", "/destination2");
#endif

	assert (rmdir (subdir) >= 0);
	free (subdir);
}

static void
test_directory_exists (void)
{
	p11_save_dir *dir;
	char *subdir;

	if (asprintf (&subdir, "%s/%s", test.directory, "extract-dir") < 0)
		assert_not_reached ();

#ifdef OS_UNIX
	if (mkdir (subdir, S_IRWXU) < 0)
#else
	if (mkdir (subdir) < 0)
#endif
		assert_fail ("mkdir() failed", subdir);

	p11_message_quiet ();

	dir = p11_save_open_directory (subdir, 0);
	assert_ptr_eq (NULL, dir);

	p11_message_loud ();

	rmdir (subdir);
	free (subdir);
}

static void
test_directory_overwrite (void)
{
	char *path;
	char *check;
	p11_save_file *file;
	p11_save_dir *dir;
	char *subdir;
	bool ret;

	if (asprintf (&subdir, "%s/%s", test.directory, "extract-dir") < 0)
		assert_not_reached ();

	/* Some initial files into this directory, which get overwritten */
	dir = p11_save_open_directory (subdir, 0);
	ret = p11_save_write_and_finish (p11_save_open_file_in (dir, "file", ".txt"), "", 0) &&
	      p11_save_write_and_finish (p11_save_open_file_in (dir, "another-file", NULL), "", 0) &&
	      p11_save_write_and_finish (p11_save_open_file_in (dir, "third-file", NULL), "", 0) &&
	      p11_save_finish_directory (dir, true);
	assert (ret && dir);

	/* Now the actual test, using the same directory */
	dir = p11_save_open_directory (subdir, P11_SAVE_OVERWRITE);
	assert_ptr_not_null (dir);

	file = p11_save_open_file_in (dir, "blah", ".cer");
	assert_ptr_not_null (file);
	ret = p11_save_write (file, test_cacert3_ca_der, sizeof (test_cacert3_ca_der));
	assert_num_eq (true, ret);
	ret = p11_save_finish_file (file, &path, true);
	assert_num_eq (true, ret);
	if (asprintf (&check, "%s/%s", subdir, "blah.cer") < 0)
		assert_not_reached ();
	assert_str_eq (check, path);
	free (check);
	free (path);

	file = p11_save_open_file_in (dir, "file", ".txt");
	assert_ptr_not_null (file);
	ret = p11_save_write (file, test_text, strlen (test_text));
	assert_num_eq (true, ret);
	ret = p11_save_finish_file (file, &path, true);
	assert_num_eq (true, ret);
	if (asprintf (&check, "%s/%s", subdir, "file.txt") < 0)
		assert_not_reached ();
	assert_str_eq (check, path);
	free (check);
	free (path);

	file = p11_save_open_file_in (dir, "file", ".txt");
	assert_ptr_not_null (file);
	ret = p11_save_write (file, test_text, 10);
	assert_num_eq (true, ret);
	ret = p11_save_finish_file (file, &path, true);
	assert_num_eq (true, ret);
	if (asprintf (&check, "%s/%s", subdir, "file.1.txt") < 0)
		assert_not_reached ();
	assert_str_eq (check, path);
	free (check);
	free (path);

	ret = p11_save_finish_directory (dir, true);
	assert_num_eq (true, ret);

	test_check_directory (subdir, ("blah.cer", "file.txt", "file.1.txt", NULL));
	test_check_data (subdir, "blah.cer", test_cacert3_ca_der, sizeof (test_cacert3_ca_der));
	test_check_data (subdir, "file.txt", test_text, strlen (test_text));
	test_check_data (subdir, "file.1.txt", test_text, 10);

	assert (rmdir (subdir) >= 0);
	free (subdir);
}

int
main (int argc,
      char *argv[])
{
	p11_fixture (setup, teardown);
	p11_test (test_file_write, "/save/test_file_write");
	p11_test (test_file_exists, "/save/test_file_exists");
	p11_test (test_file_bad_directory, "/save/test_file_bad_directory");
	p11_test (test_file_overwrite, "/save/test_file_overwrite");
	p11_test (test_file_unique, "/save/file-unique");
	p11_test (test_file_auto_empty, "/save/test_file_auto_empty");
	p11_test (test_file_auto_length, "/save/test_file_auto_length");

	p11_fixture (NULL, NULL);
	p11_test (test_write_with_null, "/save/test_write_with_null");
	p11_test (test_write_and_finish_with_null, "/save/test_write_and_finish_with_null");

	p11_fixture (setup, teardown);
	p11_test (test_file_abort, "/save/test_file_abort");

	p11_test (test_directory_empty, "/save/test_directory_empty");
	p11_test (test_directory_files, "/save/test_directory_files");
	p11_test (test_directory_dups, "/save/test_directory_dups");
	p11_test (test_directory_exists, "/save/test_directory_exists");
	p11_test (test_directory_overwrite, "/save/test_directory_overwrite");
	return p11_test_run (argc, argv);
}
