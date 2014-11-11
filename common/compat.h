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

#ifndef __COMPAT_H__
#define __COMPAT_H__

#include "config.h"

#include <sys/types.h>
#include <sys/stat.h>

#ifdef _GNU_SOURCE
#error Make the crap stop. _GNU_SOURCE is completely unportable and breaks all sorts of behavior
#endif

#if !defined(__cplusplus) && (__GNUC__ > 2)
#define GNUC_PRINTF(x, y) __attribute__((__format__(__printf__, x, y)))
#else
#define GNUC_PRINTF(x, y)
#endif

#if __GNUC__ >= 4
#define GNUC_NULL_TERMINATED __attribute__((__sentinel__))
#else
#define GNUC_NULL_TERMINATED
#endif

/* For detecting clang features */
#ifndef __has_feature
#define __has_feature(x) 0
#endif

#ifndef CLANG_ANALYZER_NORETURN
#if __has_feature(attribute_analyzer_noreturn)
#define CLANG_ANALYZER_NORETURN __attribute__((analyzer_noreturn))
#else
#define CLANG_ANALYZER_NORETURN
#endif
#endif

#ifndef O_BINARY
#define O_BINARY 0
#endif

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

#ifndef HAVE_GETPROGNAME
const char * getprogname (void);
#endif

#ifndef HAVE_MKSTEMP

int          mkstemp     (char *template);

#endif /* HAVE_MKSTEMP */

#ifndef HAVE_MKDTEMP

char *       mkdtemp     (char *template);

#endif /* HAVE_MKDTEMP */

char *       strdup_path_mangle (const char *template);

/* -----------------------------------------------------------------------------
 * WIN32
 */

#ifdef OS_WIN32

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x500
#endif

#ifndef _WIN32_IE
#define _WIN32_IE 0x500
#endif

#define WIN32_LEAN_AND_MEAN 1
#include <windows.h>

#include <io.h>

/* Oh ... my ... god */
#undef CreateMutex

typedef CRITICAL_SECTION p11_mutex_t;

typedef HANDLE p11_thread_t;

typedef DWORD p11_thread_id_t;

#define p11_mutex_init(m) \
	(InitializeCriticalSection (m))
#define p11_mutex_lock(m) \
	(EnterCriticalSection (m))
#define p11_mutex_unlock(m) \
	(LeaveCriticalSection (m))
#define p11_mutex_uninit(m) \
	(DeleteCriticalSection (m))

typedef void * (*p11_thread_routine) (void *arg);

int p11_thread_create (p11_thread_t *thread, p11_thread_routine, void *arg);

int p11_thread_join (p11_thread_t thread);

/* Returns a thread_id_t */
#define p11_thread_id_self() \
	(GetCurrentThreadId ())

typedef HMODULE dl_module_t;

#define p11_dl_open(f) \
	(LoadLibrary (f))
#define p11_dl_symbol(d, s) \
	((void *)GetProcAddress ((d), (s)))

char *    p11_dl_error       (void);

void      p11_dl_close       (void * dl);

#define p11_sleep_ms(ms) \
	(Sleep (ms))

typedef struct _p11_mmap p11_mmap;

p11_mmap *  p11_mmap_open   (const char *path,
                             struct stat *sb,
                             void **data,
                             size_t *size);

void        p11_mmap_close  (p11_mmap *map);

#ifndef HAVE_SETENV
#define setenv(n, v, z) _putenv_s(n, v)
#endif /* HAVE_SETENV */

#endif /* OS_WIN32 */

/* ----------------------------------------------------------------------------
 * UNIX
 */

#ifdef OS_UNIX

#include <pthread.h>
#include <dlfcn.h>
#include <time.h>
#include <unistd.h>

typedef pthread_mutex_t p11_mutex_t;

void        p11_mutex_init          (p11_mutex_t *mutex);

#define p11_mutex_lock(m) \
	(pthread_mutex_lock (m))
#define p11_mutex_unlock(m) \
	(pthread_mutex_unlock (m))
#define p11_mutex_uninit(m) \
	(pthread_mutex_destroy(m))

typedef pthread_t p11_thread_t;

typedef pthread_t p11_thread_id_t;

typedef void * (*p11_thread_routine) (void *arg);

#define p11_thread_create(t, r, a) \
	(pthread_create ((t), NULL, (r), (a)))
#define p11_thread_join(t) \
	(pthread_join ((t), NULL))
#define p11_thread_id_self(m) \
	(pthread_self ())

typedef void * dl_module_t;

#define p11_dl_open(f) \
	(dlopen ((f), RTLD_LOCAL | RTLD_NOW))
#define p11_dl_close \
	dlclose
#define p11_dl_symbol(d, s) \
	(dlsym ((d), (s)))

char * p11_dl_error (void);

#define p11_sleep_ms(ms) \
	do { int _ms = (ms); \
	struct timespec _ts = { _ms / 1000, (_ms % 1000) * 1000 * 1000 }; \
	nanosleep (&_ts, NULL); \
	} while(0)

typedef struct _p11_mmap p11_mmap;

p11_mmap *  p11_mmap_open   (const char *path,
                             struct stat *sb,
                             void **data,
                             size_t *size);

void        p11_mmap_close  (p11_mmap *map);

#endif /* OS_UNIX */

/* ----------------------------------------------------------------------------
 * MORE COMPAT
 */

#ifdef	HAVE_ERRNO_H
#include <errno.h>
#endif	/* HAVE_ERRNO_H */

#ifndef HAVE_STRNSTR

char *     strnstr          (const char *s,
                             const char *find,
                             size_t slen);

#endif /* HAVE_STRNSTR */

#ifndef HAVE_MEMDUP

void *     memdup           (const void *data,
                             size_t length);

#endif /* HAVE_MEMDUP */

#ifndef HAVE_STRNDUP

char *     strndup          (const char *data,
                             size_t length);

#endif /* HAVE_STRDUP */

#ifdef HAVE_STDBOOL_H
#include <stdbool.h>
#else
typedef enum { false, true } bool;
#endif

#ifndef HAVE_STRCONCAT

char *     strconcat        (const char *first,
                             ...) GNUC_NULL_TERMINATED;

#endif /* HAVE_STRCONCAT */

#if defined HAVE_DECL_ASPRINTF && !HAVE_DECL_ASPRINTF

int        asprintf         (char **strp,
                             const char *fmt,
                             ...);

#endif /* HAVE_ASPRINTF */

#if defined HAVE_DECL_VASPRINTF && !HAVE_DECL_VASPRINTF
#include <stdarg.h>

int        vasprintf        (char **strp,
                             const char *fmt,
                             va_list ap);

#endif /* HAVE_DECL_VASPRINTF */

#ifndef HAVE_GMTIME_R
#include <time.h>

struct tm * gmtime_r        (const time_t *timep,
                             struct tm *result);

#endif /* HAVE_GMTIME_R */

#ifndef HAVE_TIMEGM
#include <time.h>

time_t      timegm          (struct tm *tm);

#endif /* HAVE_TIMEGM */

#ifdef HAVE_GETAUXVAL

#include <sys/auxv.h>

#else /* !HAVE_GETAUXVAL */

unsigned long     getauxval (unsigned long type);

#define AT_SECURE 23

#endif /* !HAVE_GETAUXVAL */

char *            secure_getenv (const char *name);

#ifndef HAVE_STRERROR_R

int         strerror_r      (int errnum,
                             char *buf,
                             size_t buflen);

#endif /* HAVE_STRERROR_R */

#ifndef HAVE_FDWALK

int        fdwalk           (int (* cb) (void *data, int fd),
                             void *data);

#endif

#endif /* __COMPAT_H__ */
