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
 * Author: Stef Walter <stefw@redhat.com>
 */

#include "config.h"

#define P11_TEST_SOURCE 1

#include "compat.h"
#include "test.h"
#include "debug.h"
#include "path.h"

#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef OS_UNIX
#include <sys/stat.h>
#include <sys/wait.h>
#endif

enum {
	FIXTURE,
	TEST,
};

typedef void (*func_with_arg) (void *);

typedef struct _test_item {
	int type;

	union {
		struct {
			char name[1024];
			func_with_arg func;
			void *argument;
			int failed;
		} test;
		struct {
			func_with_arg setup;
			func_with_arg teardown;
		} fix;
	} x;

	struct _test_item *next;
} test_item;

struct {
	test_item *suite;
	test_item *last;
	int number;
	jmp_buf jump;
} gl = { NULL, NULL, 0, };

void
p11_test_fail (const char *filename,
               int line,
               const char *function,
               const char *message,
               ...)
{
	const char *pos;
	char *output;
	char *from;
	char *next;
	va_list va;

	assert (gl.last != NULL);
	assert (gl.last->type == TEST);
	gl.last->x.test.failed = 1;

	printf ("not ok %d %s\n", gl.number, gl.last->x.test.name);

	va_start (va, message);
	if (vasprintf (&output, message, va) < 0)
		assert (0 && "vasprintf() failed");
	va_end (va);

	for (from = output; from != NULL; ) {
		next = strchr (from, '\n');
		if (next) {
			next[0] = '\0';
			next += 1;
		}

		printf ("# %s\n", from);
		from = next;
	}

	pos = strrchr (filename, '/');
	if (pos != NULL && pos[1] != '\0')
		filename = pos + 1;

	printf ("# in %s() at %s:%d\n", function, filename, line);

	free (output);

	/* Let coverity know we're not supposed to return from here */
#ifdef __COVERITY__
	abort();
#endif

	longjmp (gl.jump, 1);
}

static void
test_push (test_item *it)
{
	test_item *item;

	item = calloc (1, sizeof (test_item));
	assert (item != NULL);
	memcpy (item, it, sizeof (test_item));

	if (!gl.suite)
		gl.suite = item;
	if (gl.last)
		gl.last->next = item;
	gl.last = item;
}

void
p11_test (void (* function) (void),
          const char *name,
          ...)
{
	test_item item = { TEST, };
	va_list va;

	item.x.test.func = (func_with_arg)function;

	va_start (va, name);
	vsnprintf (item.x.test.name, sizeof (item.x.test.name), name, va);
	va_end (va);

	test_push (&item);
}

void
p11_testx (void (* function) (void *),
           void *argument,
           const char *name,
           ...)
{
	test_item item = { TEST, };
	va_list va;

	item.type = TEST;
	item.x.test.func = function;
	item.x.test.argument = argument;

	va_start (va, name);
	vsnprintf (item.x.test.name, sizeof (item.x.test.name), name, va);
	va_end (va);

	test_push (&item);
}

void
p11_fixture (void (* setup) (void *),
             void (* teardown) (void *))
{
	test_item item;

	item.type = FIXTURE;
	item.x.fix.setup = setup;
	item.x.fix.teardown = teardown;

	test_push (&item);
}

static int
should_run_test (int argc,
                 char **argv,
                 test_item *item)
{
	int i;
	if (argc == 0)
		return 1;
	for (i = 0; i < argc; i++) {
		if (strcmp (argv[i], item->x.test.name) == 0)
			return 1;
	}

	return 0;
}

int
p11_test_run (int argc,
              char **argv)
{
	test_item *fixture = NULL;
	test_item *item;
	test_item *next;
	int count;
	int ret = 0;
	int setup;
	int opt;

	/* p11-kit specific stuff */
	putenv ("P11_KIT_STRICT=1");
	p11_debug_init ();

	while ((opt = getopt (argc, argv, "")) != -1) {
		switch (opt) {
		default:
			fprintf (stderr, "specify only test names on the command line\n");
			return 2;
		}
	}

	argc -= optind;
	argv += optind;

	assert (gl.number == 0);
	gl.last = NULL;

	for (item = gl.suite, count = 0; item != NULL; item = item->next) {
		if (item->type == TEST && should_run_test (argc, argv, item))
			count++;
	}

	if (count == 0) {
		printf ("1..0 # No tests\n");
		return 0;
	}

	printf ("1..%d\n", count);

	for (item = gl.suite, gl.number = 0; item != NULL; item = item->next) {
		if (item->type == FIXTURE) {
			fixture = item;
			continue;
		}

		assert (item->type == TEST);

		if (!should_run_test (argc, argv, item))
			continue;

		gl.last = item;
		gl.number++;
		setup = 0;

		if (setjmp (gl.jump) == 0) {
			if (fixture && fixture->x.fix.setup)
				(fixture->x.fix.setup) (item->x.test.argument);

			setup = 1;

			assert (item->x.test.func);
			(item->x.test.func)(item->x.test.argument);

			printf ("ok %d %s\n", gl.number, item->x.test.name);
		}

		if (setup) {
			if (setjmp (gl.jump) == 0) {
				if (fixture && fixture->x.fix.teardown)
					(fixture->x.fix.teardown) (item->x.test.argument);
			}
		}

		gl.last = NULL;
	}

	for (item = gl.suite; item != NULL; item = next) {
		if (item->type == TEST) {
			if (item->x.test.failed)
				ret++;
		}

		next = item->next;
		free (item);
	}

	gl.suite = NULL;
	gl.last = 0;
	gl.number = 0;
	return ret;
}

static char *
expand_tempdir (const char *name)
{
	const char *env;

	env = secure_getenv ("TMPDIR");
	if (env && env[0]) {
		return p11_path_build (env, name, NULL);

	} else {
#ifdef OS_UNIX
#ifdef _PATH_TMP
		return p11_path_build (_PATH_TMP, name, NULL);
#else
		return p11_path_build ("/tmp", name, NULL);
#endif

#else /* OS_WIN32 */
		char directory[MAX_PATH + 1];

		if (!GetTempPathA (MAX_PATH + 1, directory)) {
			printf ("# couldn't lookup temp directory\n");
			errno = ENOTDIR;
			return NULL;
		}

		return p11_path_build (directory, name, NULL);

#endif /* OS_WIN32 */
	}
}

char *
p11_test_directory (const char *prefix)
{
	char *templ;
	char *directory;

	if (asprintf (&templ, "%s.XXXXXX", prefix) < 0)
		assert_not_reached ();

	directory = expand_tempdir (templ);
	assert (directory != NULL);

	if (!mkdtemp (directory)) {
		printf ("# couldn't create temp directory: %s: %s\n",
		        directory, strerror (errno));
		free (directory);
		assert_not_reached ();
	}

	free (templ);
	return directory;
}

void
p11_test_file_write (const char *base,
                     const char *name,
                     const void *contents,
                     size_t length)
{
	char *path = NULL;
	FILE *f;

	if (base) {
		if (asprintf (&path, "%s/%s", base, name) < 0)
			assert_not_reached ();
		name = path;
	}

	f = fopen (name, "wb");
	if (f == NULL) {
		printf ("# couldn't open file for writing: %s: %s\n", name, strerror (errno));
		free (path);
		assert_not_reached ();
	}

	if (fwrite (contents, 1, length, f) != length ||
	    fclose (f) != 0) {
		printf ("# couldn't write to file: %s: %s\n", name, strerror (errno));
		free (path);
		assert_not_reached ();
	}

	free (path);
}

void
p11_test_file_delete (const char *base,
                      const char *name)
{
	char *path = NULL;

	if (base) {
		if (asprintf (&path, "%s/%s", base, name) < 0)
			assert_not_reached ();
		name = path;
	}

	if (unlink (name) < 0) {
		printf ("# Couldn't delete file: %s\n", name);
		free (path);
		assert_not_reached ();
	}

	free (path);
}

void
p11_test_directory_delete (const char *directory)
{
	struct dirent *dp;
	DIR *dir;

	dir = opendir (directory);
	if (dir == NULL) {
		printf ("# Couldn't open directory: %s\n", directory);
		assert_not_reached ();
	}

	while ((dp = readdir (dir)) != NULL) {
		if (strcmp (dp->d_name, ".") == 0 ||
		    strcmp (dp->d_name, "..") == 0)
			continue;

		p11_test_file_delete (directory, dp->d_name);
	}

	closedir (dir);

	if (rmdir (directory) < 0) {
		printf ("# Couldn't remove directory: %s\n", directory);
		assert_not_reached ();
	}
}


#ifdef OS_UNIX

static void
copy_file (const char *input,
           int fd)
{
	p11_mmap *mmap;
	const char *data;
	ssize_t written;
	size_t size;

	mmap = p11_mmap_open (input, NULL, (void **)&data, &size);
	assert (mmap != NULL);

	while (size > 0) {
		written = write (fd, data, size);
		assert (written >= 0);

		data += written;
		size -= written;
	}

	p11_mmap_close (mmap);
}

char *
p11_test_copy_setgid (const char *input)
{
	gid_t groups[128];
		char *path;
		gid_t group = 0;
		int ret;
		int fd;
		int i;

	ret = getgroups (128, groups);
	for (i = 0; i < ret; ++i) {
		if (groups[i] != getgid ()) {
			group = groups[i];
			break;
		}
	}
	if (i == ret) {
		fprintf (stderr, "# no suitable group, skipping test\n");
		return NULL;
	}

	path = strdup ("/tmp/test-setgid.XXXXXX");
	assert (path != NULL);

	fd = mkstemp (path);
	assert (fd >= 0);

	copy_file (input, fd);
	if (fchown (fd, getuid (), group) < 0)
		assert_not_reached ();
	if (fchmod (fd, 02750) < 0)
		assert_not_reached ();
	if (close (fd) < 0)
		assert_not_reached ();

	return path;
}

int
p11_test_run_child (const char **argv,
                    bool quiet_out)
{
	pid_t child;
	int status;

	child = fork ();
	assert (child >= 0);

	/* In the child process? */
	if (child == 0) {
		if (quiet_out)
			close (1); /* stdout */
		execv (argv[0], (char **)argv);
		assert_not_reached ();
	}

	if (waitpid (child, &status, 0) < 0)
		assert_not_reached ();

	assert (!WIFSIGNALED (status));
	assert (WIFEXITED (status));

	return WEXITSTATUS (status);
}

#endif /* OS_UNIX */
