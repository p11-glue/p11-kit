/*
 * Copyright (c) 2011 Collabora Ltd.
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

#include "compat.h"

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#ifndef HAVE_GETPROGNAME

#ifdef OS_UNIX

#if defined (HAVE_PROGRAM_INVOCATION_SHORT_NAME) && !HAVE_DECL_PROGRAM_INVOCATION_SHORT_NAME
extern char *program_invocation_short_name;
#endif

#if defined (HAVE___PROGNAME) && !HAVE_DECL___PROGNAME
extern char *__progname;
#endif

const char *
getprogname (void)
{
	const char *name;

#if defined (HAVE_GETEXECNAME)
	const char *p;
	name = getexecname();
	p = strrchr (name ? name : "", '/');
	if (p != NULL)
		name = p + 1;
#elif defined (HAVE_PROGRAM_INVOCATION_SHORT_NAME)
	name = program_invocation_short_name;
#elif defined (HAVE___PROGNAME)
	name = __progname;
#else
	#error No way to retrieve short program name
#endif

	return name;
}

#else /* OS_WIN32 */

extern char **__argv;
static char prognamebuf[256];

const char *
getprogname (void)
{
	const char *name;
	const char *p, *p2;
	size_t length;

	name = __argv[0];
	if (name == NULL)
		return NULL;

	p = strrchr (name, '\\');
	p2 = strrchr (name, '/');
	if (p2 > p)
		p = p2;
	if (p != NULL)
		name = p + 1;

	length = sizeof (prognamebuf) - 1;
	strncpy (prognamebuf, name, length);
	prognamebuf[length] = 0;
	length = strlen (prognamebuf);
	if (length > 4 && _stricmp (prognamebuf + (length - 4), ".exe") == 0)
		prognamebuf[length - 4] = '\0';

	return prognamebuf;
}

#endif /* OS_WIN32 */

#endif /* HAVE_GETPROGNAME */

#ifdef OS_UNIX

void
p11_mutex_init (p11_mutex_t *mutex)
{
	pthread_mutexattr_t attr;
	int ret;

	pthread_mutexattr_init (&attr);
	pthread_mutexattr_settype (&attr, PTHREAD_MUTEX_RECURSIVE);
	ret = pthread_mutex_init (mutex, &attr);
	assert (ret == 0);
	pthread_mutexattr_destroy (&attr);
}

#endif /* OS_UNIX */

#ifdef OS_WIN32

const char *
p11_module_error (void)
{
	DWORD code = GetLastError();
	p11_local *local;
	LPVOID msg_buf;

	local = p11_library_get_thread_local ();

	FormatMessageA (FORMAT_MESSAGE_ALLOCATE_BUFFER |
	                FORMAT_MESSAGE_FROM_SYSTEM |
	                FORMAT_MESSAGE_IGNORE_INSERTS,
	                NULL, code,
	                MAKELANGID (LANG_NEUTRAL, SUBLANG_DEFAULT),
	                (LPSTR)&msg_buf, 0, NULL);

	if (local->last_error)
		LocalFree (local->last_error);
	local->last_error = msg_buf;

	return msg_buf;
}

int
p11_thread_create (p11_thread_t *thread,
                   p11_thread_routine routine,
                   void *arg)
{
	assert (thread);

	*thread = CreateThread (NULL, 0,
	                        (LPTHREAD_START_ROUTINE)routine,
	                        arg, 0, NULL);

	if (*thread == NULL)
		return GetLastError ();

	return 0;
}

int
p11_thread_join (p11_thread_t thread)
{
	DWORD res;

	res = WaitForSingleObject (thread, INFINITE);
	if (res == WAIT_FAILED)
		return GetLastError ();

	CloseHandle (thread);
	return 0;
}

#endif /* OS_WIN32 */

#ifndef HAVE_STRNSTR

/*-
 * Copyright (c) 2001 Mike Barcroft <mike@FreeBSD.org>
 * Copyright (c) 1990, 1993
 *      The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Chris Torek.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <string.h>

/*
 * Find the first occurrence of find in s, where the search is limited to the
 * first slen characters of s.
 */
char *
strnstr (const char *s,
         const char *find,
         size_t slen)
{
	char c, sc;
	size_t len;

	if ((c = *find++) != '\0') {
		len = strlen (find);
		do {
			do {
				if (slen-- < 1 || (sc = *s++) == '\0')
					return (NULL);
			} while (sc != c);
			if (len > slen)
				return (NULL);
		} while (strncmp(s, find, len) != 0);
		s--;
	}
	return ((char *)s);
}

#endif /* HAVE_STRNSTR */

#ifndef HAVE_MEMDUP

void *
memdup (void *data,
        size_t length)
{
	void *dup;

	if (!data)
		return NULL;

	dup = malloc (length);
	if (dup != NULL)
		memcpy (dup, data, length);

	return dup;
}

#endif /* HAVE_MEMDUP */

#ifndef HAVE_STRCONCAT

#include <stdarg.h>

char *
strconcat (const char *first,
           ...)
{
	size_t length = 0;
	const char *arg;
	char *result, *at;
	va_list va;

	va_start (va, first);

	for (arg = first; arg; arg = va_arg (va, const char*))
	       length += strlen (arg);

	va_end (va);

	at = result = malloc (length + 1);
	if (result == NULL)
	       return NULL;

	va_start (va, first);

	for (arg = first; arg; arg = va_arg (va, const char*)) {
	       length = strlen (arg);
	       memcpy (at, arg, length);
	       at += length;
	}

	va_end (va);

	*at = 0;
	return result;
}

#endif /* HAVE_STRCONCAT */
