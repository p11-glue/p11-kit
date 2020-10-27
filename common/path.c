/*
 * Copyright (c) 2005 Stefan Walter
 * Copyright (c) 2011 Collabora Ltd.
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
 *
 * CONTRIBUTORS
 *  Stef Walter <stefw@redhat.com>
 */

#include "config.h"

#include "buffer.h"
#include "debug.h"
#include "message.h"
#include "path.h"
#include "url.h"

#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#ifdef OS_UNIX
#include <pwd.h>
#include <unistd.h>
#endif

#ifdef OS_WIN32
#include <shlobj.h>
#endif


char *
p11_path_base (const char *path)
{
#ifdef OS_WIN32
	const char *delims = "/\\";
#else
	const char *delims = "/";
#endif

	const char *end;
	const char *beg;

	return_val_if_fail (path != NULL, NULL);

	/* Any trailing slashes */
	end = path + strlen (path);
	while (end != path) {
		if (!strchr (delims, *(end - 1)))
			break;
		end--;
	}

	/* Find the last slash after those */
	beg = end;
	while (beg != path) {
		if (strchr (delims, *(beg - 1)))
			break;
		beg--;
	}

	return strndup (beg, end - beg);
}

static inline bool
is_path_separator (char ch)
{
	return (ch == '/'
#ifdef OS_WIN32
			|| ch == '\\'
#endif
		);
}

static inline bool
is_path_separator_or_null (char ch)
{
	return is_path_separator (ch) || ch == '\0';
}

static char *
expand_homedir (const char *remainder)
{
	const char *env;

	if (getauxval (AT_SECURE)) {
		errno = EPERM;
		return NULL;
	}

	while (is_path_separator (remainder[0]))
		remainder++;
	if (remainder[0] == '\0')
		remainder = NULL;

	/* Expand $XDG_CONFIG_HOME */
	if (remainder != NULL &&
	    strncmp (remainder, ".config", 7) == 0 &&
	    is_path_separator_or_null (remainder[7])) {
		env = getenv ("XDG_CONFIG_HOME");
		if (env && env[0])
			return p11_path_build (env, remainder + 8, NULL);
	}

	env = getenv ("HOME");
	if (env && env[0]) {
		return p11_path_build (env, remainder, NULL);

	} else {
#ifdef OS_UNIX
		char buf[1024];
		struct passwd pws;
		struct passwd *pwd = NULL;
		int error;
		int ret;

		errno = 0;
		ret = getpwuid_r (getuid (), &pws, buf, sizeof (buf), &pwd);
		if (pwd == NULL) {
			if (ret == 0)
				error = ESRCH;
			else
				error = errno;
			p11_message_err (error, "couldn't lookup home directory for user %d", getuid ());
			errno = error;
			return NULL;
		}

		return p11_path_build (pwd->pw_dir, remainder, NULL);

#else /* OS_WIN32 */
		char directory[MAX_PATH + 1];

		if (!SHGetSpecialFolderPathA (NULL, directory, CSIDL_PROFILE, TRUE)) {
			p11_message ("couldn't lookup home directory for user");
			errno = ENOTDIR;
			return NULL;
		}

		return p11_path_build (directory, remainder, NULL);

#endif /* OS_WIN32 */
	}
}

char *
p11_path_expand (const char *path)
{
	return_val_if_fail (path != NULL, NULL);

	if (strncmp (path, "~", 1) == 0 &&
	    is_path_separator_or_null (path[1])) {
		return expand_homedir (path + 1);

	} else {
		return strdup (path);
	}
}

bool
p11_path_absolute (const char *path)
{
	return_val_if_fail (path != NULL, false);

	return (path[0] == '/')
#ifdef OS_WIN32
	|| (path[0] != '\0' && path[1] == ':' && path[2] == '\\')
#endif
	;
}

char *
p11_path_build (const char *path,
                ...)
{
#ifdef OS_WIN32
	const char delim = '\\';
#else
	const char delim = '/';
#endif
	const char *first = path;
	char *built;
	size_t len;
	size_t at;
	size_t num;
	size_t until;
	va_list va;

	return_val_if_fail (path != NULL, NULL);

	len = 1;
	va_start (va, path);
	while (path != NULL) {
		size_t old_len = len;
		len += strlen (path) + 1;
		if (len < old_len) {
			va_end (va);
			return_val_if_reached (NULL);
		}
		path = va_arg (va, const char *);
	}
	va_end (va);

	built = malloc (len + 1);
	return_val_if_fail (built != NULL, NULL);

	at = 0;
	path = first;
	va_start (va, path);
	while (path != NULL) {
		num = strlen (path);

		/* Trim beginning of path */
		while (is_path_separator (path[0])) {
			/* But preserve the leading path component */
			if (!at && !is_path_separator (path[1]))
				break;
			path++;
			num--;
		}

		/* Trim end of the path */
		until = (at > 0) ? 0 : 1;
		while (num > until && is_path_separator_or_null (path[num - 1]))
			num--;

		if (at != 0) {
			if (num == 0) {
				path = va_arg (va, const char *);
				continue;
			}
			if (built[at - 1] != delim)
				built[at++] = delim;
		}

		assert (at + num < len);
		memcpy (built + at, path, num);
		at += num;

		path = va_arg (va, const char *);
	}
	va_end (va);

	assert (at < len);
	built[at] = '\0';
	return built;
}

char *
p11_path_parent (const char *path)
{
	const char *e;
	char *parent;
	bool had = false;

	return_val_if_fail (path != NULL, NULL);

	/* Find the end of the last component */
	e = path + strlen (path);
	while (e != path && is_path_separator_or_null (*e))
		e--;

	/* Find the beginning of the last component */
	while (e != path && !is_path_separator_or_null (*e)) {
		had = true;
		e--;
	}

	/* Find the end of the last component */
	while (e != path && is_path_separator_or_null (*e))
		e--;

	if (e == path) {
		if (!had)
			return NULL;
		parent = strdup ("/");
	} else {
		parent = strndup (path, (e - path) + 1);
	}

	return_val_if_fail (parent != NULL, NULL);
	return parent;
}

bool
p11_path_prefix (const char *string,
                 const char *prefix)
{
	int a, b;

	return_val_if_fail (string != NULL, false);
	return_val_if_fail (prefix != NULL, false);

	a = strlen (string);
	b = strlen (prefix);

	return a > b &&
	       strncmp (string, prefix, b) == 0 &&
	       is_path_separator_or_null (string[b]);
}

void
p11_path_canon (char *name)
{
	static const char *VALID =
		"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_";
	int i;

	return_if_fail (name != NULL);

	for (i = 0; name[i] != '\0'; i++) {
		if (strchr (VALID, name[i]) == NULL)
			name[i] = '_';
	}
}

char *
p11_path_encode (const char *path)
{
	static const char *VALID =
		"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_/\\";
	p11_buffer buf;
	char *result;

	return_val_if_fail (path != NULL, NULL);

	if (!p11_buffer_init_null (&buf, strlen (path)))
		return_val_if_reached (NULL);

	p11_url_encode ((unsigned char *)path,
			(unsigned char *)path + strlen (path),
			VALID,
			&buf);
	return_val_if_fail (p11_buffer_ok (&buf), NULL);

	result = p11_buffer_steal (&buf, NULL);
	p11_buffer_uninit (&buf);

	return result;
}

char *
p11_path_decode (const char *path)
{
	return (char *) p11_url_decode (path, path + strlen (path), "", NULL);
}
