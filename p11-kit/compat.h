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

typedef CRITICAL_SECTION mutex_t;

typedef HANDLE thread_t;

#define _p11_mutex_init(m) \
	(InitializeCriticalSection (m))
#define _p11_mutex_lock(m) \
	(EnterCriticalSection (m))
#define _p11_mutex_unlock(m) \
	(LeaveCriticalSection (m))
#define _p11_mutex_uninit(m) \
	(DeleteCriticalSection (m))

typedef void * (*thread_routine) (void *arg);

int _p11_thread_create (thread_t *thread, thread_routine, void *arg);

int _p11_thread_join (thread_t thread);

#define _p11_thread_self() \
	(GetCurrentThread ())

typedef HMODULE dl_module_t;

#define _p11_module_open(f) \
	(LoadLibrary (f))
#define _p11_module_close(d) \
	(FreeLibrary (d))
#define _p11_module_symbol(d, s) \
	((void *)GetProcAddress ((d), (s)))

const char *    _p11_module_error       (void);

#define _p11_sleep_ms(ms) \
	(Sleep (ms))

#endif /* OS_WIN32 */

/* ----------------------------------------------------------------------------
 * UNIX
 */

#ifdef OS_UNIX

#include <pthread.h>
#include <dlfcn.h>
#include <time.h>

typedef pthread_mutex_t mutex_t;

void        _p11_mutex_init          (mutex_t *mutex);

#define _p11_mutex_lock(m) \
	(pthread_mutex_lock (m))
#define _p11_mutex_unlock(m) \
	(pthread_mutex_unlock (m))
#define _p11_mutex_uninit(m) \
	(pthread_mutex_destroy(m))

typedef pthread_t thread_t;

typedef void * (*thread_routine) (void *arg);

#define _p11_thread_create(t, r, a) \
	(pthread_create ((t), NULL, (r), (a)))
#define _p11_thread_join(t) \
	(pthread_join ((t), NULL))
#define _p11_thread_self(m) \
	(pthread_self ())

typedef void * dl_module_t;

#define _p11_module_open(f) \
	(dlopen ((f), RTLD_LOCAL | RTLD_NOW))
#define _p11_module_close(d) \
	(dlclose(d))
#define _p11_module_error() \
	(dlerror ())
#define _p11_module_symbol(d, s) \
	(dlsym ((d), (s)))

#define _p11_sleep_ms(ms) \
	do { int _ms = (ms); \
	struct timespec _ts = { _ms / 1000, (_ms % 1000) * 1000 * 1000 }; \
	nanosleep (&_ts, NULL); \
	} while(0)

#endif /* OS_UNIX */

#endif /* __COMPAT_H__ */
