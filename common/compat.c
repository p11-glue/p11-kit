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

/*
 * This is needed to expose pthread_mutexattr_settype and PTHREAD_MUTEX_DEFAULT
 * on older pthreads implementations
 */
#define _XOPEN_SOURCE 700

#include "compat.h"

#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

/*-
 * Portions of this file are covered by the following copyright:
 *
 * Copyright (c) 2001 Mike Barcroft <mike@FreeBSD.org>
 * Copyright (c) 1990, 1993
 * Copyright (c) 1987, 1993
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

#ifndef HAVE_GETPROGNAME

#ifdef OS_UNIX

#include <unistd.h>

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
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>

void
p11_mutex_init (p11_mutex_t *mutex)
{
	pthread_mutexattr_t attr;
	int ret;

	pthread_mutexattr_init (&attr);
	pthread_mutexattr_settype (&attr, PTHREAD_MUTEX_DEFAULT);
	ret = pthread_mutex_init (mutex, &attr);
	assert (ret == 0);
	pthread_mutexattr_destroy (&attr);
}

char *
p11_dl_error (void)
{
	const char *msg = dlerror ();
	return msg ? strdup (msg) : NULL;
}

struct _p11_mmap {
	int fd;
	void *data;
	size_t size;
};

p11_mmap *
p11_mmap_open (const char *path,
               struct stat *sb,
               void **data,
               size_t *size)
{
	struct stat stb;
	p11_mmap *map;

	map = calloc (1, sizeof (p11_mmap));
	if (map == NULL)
		return NULL;

	map->fd = open (path, O_RDONLY | O_CLOEXEC);
	if (map->fd == -1) {
		free (map);
		return NULL;
	}

	if (sb == NULL) {
		sb = &stb;
		if (fstat (map->fd, &stb) < 0) {
			close (map->fd);
			free (map);
			return NULL;
		}
	}

	/* Workaround for broken ZFS on Linux */
	if (S_ISDIR (sb->st_mode)) {
		errno = EISDIR;
		close (map->fd);
		free (map);
		return NULL;
	}

	if (sb->st_size == 0) {
		*data = "";
		*size = 0;
		return map;
	}

	map->size = sb->st_size;
	map->data = mmap (NULL, map->size, PROT_READ, MAP_PRIVATE, map->fd, 0);
	if (map->data == MAP_FAILED) {
		close (map->fd);
		free (map);
		return NULL;
	}

	*data = map->data;
	*size = map->size;
	return map;
}

void
p11_mmap_close (p11_mmap *map)
{
	if (map->size)
		munmap (map->data, map->size);
	close (map->fd);
	free (map);
}

#endif /* OS_UNIX */

#ifdef OS_WIN32

char *
p11_dl_error (void)
{
	DWORD code = GetLastError();
	LPVOID msg_buf;

	FormatMessageA (FORMAT_MESSAGE_ALLOCATE_BUFFER |
	                FORMAT_MESSAGE_FROM_SYSTEM |
	                FORMAT_MESSAGE_IGNORE_INSERTS,
	                NULL, code,
	                MAKELANGID (LANG_NEUTRAL, SUBLANG_DEFAULT),
	                (LPSTR)&msg_buf, 0, NULL);

	return msg_buf;
}

void
p11_dl_close (void *dl)
{
	FreeLibrary (dl);
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

struct _p11_mmap {
	HANDLE file;
	HANDLE mapping;
	void *data;
};

p11_mmap *
p11_mmap_open (const char *path,
               struct stat *sb,
               void **data,
               size_t *size)
{
	HANDLE mapping;
	LARGE_INTEGER large;
	DWORD errn;
	p11_mmap *map;

	map = calloc (1, sizeof (p11_mmap));
	if (map == NULL) {
		errno = ENOMEM;
		return NULL;
	}

	map->file  = CreateFile (path, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_FLAG_RANDOM_ACCESS, NULL);
	if (map->file == INVALID_HANDLE_VALUE) {
		errn = GetLastError ();
		free (map);
		SetLastError (errn);
		if (errn == ERROR_PATH_NOT_FOUND || errn == ERROR_FILE_NOT_FOUND)
			errno = ENOENT;
		else if (errn == ERROR_ACCESS_DENIED)
			errno = EPERM;
		return NULL;
	}

	if (sb == NULL) {
		if (!GetFileSizeEx (map->file, &large)) {
			errn = GetLastError ();
			CloseHandle (map->file);
			free (map);
			SetLastError (errn);
			if (errn == ERROR_ACCESS_DENIED)
				errno = EPERM;
			return NULL;
		}
	} else {
		large.QuadPart = sb->st_size;
	}

	mapping = CreateFileMapping (map->file, NULL, PAGE_READONLY, 0, 0, NULL);
	if (!mapping) {
		errn = GetLastError ();
		CloseHandle (map->file);
		free (map);
		SetLastError (errn);
		if (errn == ERROR_ACCESS_DENIED)
			errno = EPERM;
		return NULL;
	}

	map->data = MapViewOfFile (mapping, FILE_MAP_READ, 0, 0, large.QuadPart);
	CloseHandle (mapping);

	if (map->data == NULL) {
		errn = GetLastError ();
		CloseHandle (map->file);
		free (map);
		SetLastError (errn);
		if (errn == ERROR_ACCESS_DENIED)
			errno = EPERM;
		return NULL;
	}

	*data = map->data;
	*size = large.QuadPart;
	return map;
}

void
p11_mmap_close (p11_mmap *map)
{
	UnmapViewOfFile (map->data);
	CloseHandle (map->file);
	free (map);
}

#endif /* OS_WIN32 */

#ifndef HAVE_STRNSTR
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
memdup (const void *data,
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

/*
 * WORKAROUND: So in lots of released builds of firefox a completely broken strndup()
 * is present. It does not NULL terminate its string output. It is unconditionally
 * defined, and overrides the libc strndup() function on platforms where it
 * exists as a function. For this reason we (for now) unconditionally define
 * strndup().
 */

#if 1 /* #ifndef HAVE_STRNDUP */

/*
 * HAVE_STRNDUP may be undefined if strndup() isn't working. So it may be
 * present, and yet strndup may still be a defined header macro.
 */
#ifdef strndup
#undef strndup
#endif

char *
strndup (const char *data,
         size_t length);

char *
strndup (const char *data,
         size_t length)
{
	char *ret;

	ret = malloc (length + 1);
	if (ret != NULL) {
		strncpy (ret, data, length);
		ret[length] = 0;
	}

	return ret;
}

#endif /* HAVE_STRNDUP */

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

#ifndef HAVE_VASPRINTF
#include <stdio.h>

int vasprintf(char **strp, const char *fmt, va_list ap);

int
vasprintf (char **strp,
           const char *fmt,
           va_list ap)
{
	char *buf = NULL;
	char *nbuf;
	int guess = 128;
	int length = 0;
	int ret;

	if (fmt == NULL) {
		errno = EINVAL;
		return -1;
	}

	for (;;) {
		nbuf = realloc (buf, guess);
		if (!nbuf) {
			free (buf);
			return -1;
		}

		buf = nbuf;
		length = guess;

		ret = vsnprintf (buf, length, fmt, ap);

		if (ret < 0)
			guess *= 2;

		else if (ret >= length)
			guess = ret + 1;

		else
			break;
	}

	*strp = buf;
	return ret;
}

#endif /* HAVE_VASPRINTF */

#ifndef HAVE_ASPRINTF

int asprintf(char **strp, const char *fmt, ...);

int
asprintf (char **strp,
          const char *fmt,
          ...)
{
	va_list va;
	int ret;

	va_start (va, fmt);
	ret = vasprintf (strp, fmt, va);
	va_end (va);

	return ret;
}

#endif /* HAVE_ASPRINTF */

#ifndef HAVE_GMTIME_R

struct tm *
gmtime_r (const time_t *timep,
          struct tm *result)
{
#ifdef OS_WIN32
	/*
	 * On win32 gmtime() returns thread local storage, so we can
	 * just copy it out into the buffer without worrying about races.
	 */
	struct tm *tg;
	tg = gmtime (timep);
	if (!tg)
		return NULL;
	memcpy (result, tg, sizeof (struct tm));
	return result;
#else
	#error Need either gmtime_r() function on Unix
#endif
}

#endif /* HAVE_GMTIME_R */

#ifndef HAVE_TIMEGM

time_t
timegm (struct tm *tm)
{
	time_t tl, tb;
	struct tm tg;

	tl = mktime (tm);
	if (tl == -1) {
		tm->tm_hour--;
		tl = mktime (tm);
		if (tl == -1)
			return -1;
		tl += 3600;
	}
	gmtime_r (&tl, &tg);
	tg.tm_isdst = 0;
	tb = mktime (&tg);
	if (tb == -1) {
		tg.tm_hour--;
		tb = mktime (&tg);
		if (tb == -1)
			return -1;
		tb += 3600;
	}
	return (tl - (tb - tl));
}

#endif /* HAVE_TIMEGM */

#if !defined(HAVE_MKDTEMP) || !defined(HAVE_MKSTEMP)
#include <sys/stat.h>
#include <fcntl.h>

static int
_gettemp (char *path,
          int *doopen,
          int domkdir,
          int slen)
{
	static const char padchar[] =
		"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
	static const int maxpathlen = 1024;

	char *start, *trv, *suffp, *carryp;
	char *pad;
	struct stat sbuf;
	int rval;
	int rnd;
	char carrybuf[maxpathlen];

	if ((doopen != NULL && domkdir) || slen < 0) {
		errno = EINVAL;
		return (0);
	}

	for (trv = path; *trv != '\0'; ++trv)
		;
	if (trv - path >= maxpathlen) {
		errno = ENAMETOOLONG;
		return (0);
	}
	trv -= slen;
	suffp = trv;
	--trv;
	if (trv < path || NULL != strchr (suffp, '/')) {
		errno = EINVAL;
		return (0);
	}

	/* Fill space with random characters */
	while (trv >= path && *trv == 'X') {
		rnd = rand () % sizeof (padchar) - 1;
		*trv-- = padchar[rnd];
	}
	start = trv + 1;

	/* save first combination of random characters */
	memcpy (carrybuf, start, suffp - start);

	/*
	 * check the target directory.
	 */
	if (doopen != NULL || domkdir) {
		for (; trv > path; --trv) {
			if (*trv == '/') {
				*trv = '\0';
				rval = stat(path, &sbuf);
				*trv = '/';
				if (rval != 0)
					return (0);
				if (!S_ISDIR(sbuf.st_mode)) {
					errno = ENOTDIR;
					return (0);
				}
				break;
			}
		}
	}

	for (;;) {
		if (doopen) {
			if ((*doopen = open (path, O_BINARY | O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0600)) >= 0)
				return (1);
			if (errno != EEXIST)
				return (0);
		} else if (domkdir) {
#ifdef OS_UNIX
			if (mkdir (path, 0700) == 0)
#else
			if (mkdir (path) == 0)
#endif
				return (1);
			if (errno != EEXIST)
				return (0);
#ifdef OS_UNIX
		} else if (lstat (path, &sbuf))
#else
		} else if (stat (path, &sbuf))
#endif
			return (errno == ENOENT);

		/* If we have a collision, cycle through the space of filenames */
		for (trv = start, carryp = carrybuf;;) {
			/* have we tried all possible permutations? */
			if (trv == suffp)
				return (0); /* yes - exit with EEXIST */
			pad = strchr(padchar, *trv);
			if (pad == NULL) {
				/* this should never happen */
				errno = EIO;
				return (0);
			}
			/* increment character */
			*trv = (*++pad == '\0') ? padchar[0] : *pad;
			/* carry to next position? */
			if (*trv == *carryp) {
				/* increment position and loop */
				++trv;
				++carryp;
			} else {
				/* try with new name */
				break;
			}
		}
	}

	/*NOTREACHED*/
}

#endif /* !HAVE_MKDTEMP || !HAVE_MKSTEMP */

#ifndef HAVE_MKSTEMP

int
mkstemp (char *template)
{
	int fd;

	return (_gettemp (template, &fd, 0, 0) ? fd : -1);
}

#endif /* HAVE_MKSTEMP */

#ifndef HAVE_MKDTEMP

char *
mkdtemp (char *template)
{
	return (_gettemp (template, (int *)NULL, 1, 0) ? template : (char *)NULL);
}

#endif /* HAVE_MKDTEMP */

#ifndef HAVE_GETAUXVAL

unsigned long
getauxval (unsigned long type)
{
	static unsigned long secure = 0UL;
	static bool check_secure_initialized = false;

	/*
	 * This is the only one our stand-in impl supports and is
	 * also the only type we define in compat.h header
	 */
	assert (type == AT_SECURE);

	if (!check_secure_initialized) {
#if defined(HAVE___LIBC_ENABLE_SECURE)
		extern int __libc_enable_secure;
		secure = __libc_enable_secure;

#elif defined(HAVE_ISSETUGID)
		secure = issetugid ();

#elif defined(OS_UNIX)
		uid_t ruid, euid, suid; /* Real, effective and saved user ID's */
		gid_t rgid, egid, sgid; /* Real, effective and saved group ID's */

#ifdef HAVE_GETRESUID
		if (getresuid (&ruid, &euid, &suid) != 0 ||
		    getresgid (&rgid, &egid, &sgid) != 0)
#endif /* HAVE_GETRESUID */
		{
			suid = ruid = getuid ();
			sgid = rgid = getgid ();
			euid = geteuid ();
			egid = getegid ();
		}

		secure = (ruid != euid || ruid != suid ||
		          rgid != egid || rgid != sgid);
#endif /* OS_UNIX */
		check_secure_initialized = true;
	}

	return secure;
}

#endif /* HAVE_GETAUXVAL */

char *
secure_getenv (const char *name)
{
	if (getauxval (AT_SECURE))
		return NULL;
	return getenv (name);
}

#ifndef HAVE_STRERROR_R

int
strerror_r (int errnum,
            char *buf,
            size_t buflen)
{
#ifdef OS_WIN32
#if _WIN32_WINNT < 0x502 /* WinXP or older */
	int n = sys_nerr;
	const char *p;
	if (errnum < 0 || errnum >= n)
		p = sys_errlist[n];
	else
		p = sys_errlist[errnum];
	if (buf == NULL || buflen == 0)
		return EINVAL;
	strncpy(buf, p, buflen);
	buf[buflen-1] = 0;
	return 0;
#else /* Server 2003 or newer */
	return strerror_s (buf, buflen, errnum);
#endif /*_WIN32_WINNT*/

#else
	#error no strerror_r implementation
#endif
}

#endif /* HAVE_STRERROR_R */

#ifdef OS_UNIX

#include <unistd.h>

#ifndef HAVE_FDWALK

#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif

int
fdwalk (int (* cb) (void *data, int fd),
        void *data)
{
	struct dirent *de;
	char *end;
	DIR *dir;
	int open_max;
	long num;
	int res = 0;
	int fd;

#ifdef HAVE_SYS_RESOURCE_H
	struct rlimit rl;
#endif

	dir = opendir ("/proc/self/fd");
	if (dir != NULL) {
		while ((de = readdir (dir)) != NULL) {
			end = NULL;
			num = (int) strtol (de->d_name, &end, 10);

			/* didn't parse or is the opendir() fd */
			if (!end || *end != '\0' ||
			    (int)num == dirfd (dir))
				continue;

			fd = num;

			/* call the callback */
			res = cb (data, fd);
			if (res != 0)
				break;
		}

		closedir (dir);
		return res;
	}

	/* No /proc, brute force */
#ifdef HAVE_SYS_RESOURCE_H
	if (getrlimit (RLIMIT_NOFILE, &rl) == 0 && rl.rlim_max != RLIM_INFINITY)
		open_max = rl.rlim_max;
	else
#endif
		open_max = sysconf (_SC_OPEN_MAX);

	for (fd = 0; fd < open_max; fd++) {
		res = cb (data, fd);
		if (res != 0)
			break;
	}

	return res;
}

#endif /* HAVE_FDWALK */

#endif /* OS_UNIX */
