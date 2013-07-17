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

#include "test.h"
#include "debug.h"
#include "path.h"

#include <assert.h>
#include <errno.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

	/* p11-kit specific stuff */
	putenv ("P11_KIT_STRICT=1");
	p11_debug_init ();

	assert (gl.number == 0);
	gl.last = NULL;

	for (item = gl.suite, count = 0; item != NULL; item = item->next) {
		if (item->type == TEST)
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

	env = getenv ("TMPDIR");
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
