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

typedef enum { false, true } bool;

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

#ifndef HAVE_GETPROGNAME
const char * getprogname (void);
#endif

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

int p11_thread_create (thread_t *thread, thread_routine, void *arg);

int p11_thread_join (thread_t thread);

/* Returns a thread_id_t */
#define p11_thread_id_self() \
	(GetCurrentThreadId ())

typedef HMODULE dl_module_t;

#define p11_module_open(f) \
	(LoadLibrary (f))
#define p11_module_close(d) \
	(FreeLibrary (d))
#define p11_module_symbol(d, s) \
	((void *)GetProcAddress ((d), (s)))

const char *    p11_module_error       (void);

#define p11_sleep_ms(ms) \
	(Sleep (ms))

#endif /* OS_WIN32 */

/* ----------------------------------------------------------------------------
 * UNIX
 */

#ifdef OS_UNIX

#include <pthread.h>
#include <dlfcn.h>
#include <time.h>

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

#define p11_module_open(f) \
	(dlopen ((f), RTLD_LOCAL | RTLD_NOW))
#define p11_module_close(d) \
	(dlclose(d))
#define p11_module_error() \
	(dlerror ())
#define p11_module_symbol(d, s) \
	(dlsym ((d), (s)))

#define p11_sleep_ms(ms) \
	do { int _ms = (ms); \
	struct timespec _ts = { _ms / 1000, (_ms % 1000) * 1000 * 1000 }; \
	nanosleep (&_ts, NULL); \
	} while(0)

#endif /* OS_UNIX */

#ifdef	HAVE_ERRNO_H
#include <errno.h>
#endif	/* HAVE_ERRNO_H */

#ifndef HAVE_MEMDUP

void *     memdup           (void *data,
                             size_t length);

#endif /* HAVE_MEMDUP */

#ifdef HAVE_STDBOOL_H
#include <stdbool.h>
#else
typedef enum { false, true } bool;
#endif

#endif /* __COMPAT_H__ */
