/*
 * Copyright (c) 2011 Collabora Ltd
 * Copyright (c) 2012 Stef Walter
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
 *  Stef Walter <stef@thewalter.net>
 */

#include "config.h"

#include "compat.h"
#define P11_DEBUG_FLAG P11_DEBUG_LIB
#include "debug.h"
#include "library.h"
#include "message.h"

#include <assert.h>
#ifdef HAVE_LOCALE_H
#include <locale.h>
#endif
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define P11_MESSAGE_MAX 512

typedef struct {
	char message[P11_MESSAGE_MAX];
} p11_local;

static p11_local * _p11_library_get_thread_local (void);

#ifdef PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP
p11_mutex_t p11_library_mutex = PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;

p11_mutex_t p11_virtual_mutex = PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;
#else
p11_mutex_t p11_library_mutex;

p11_mutex_t p11_virtual_mutex;
#endif

#ifdef OS_UNIX
#ifndef __GNUC__
pthread_once_t p11_library_once = PTHREAD_ONCE_INIT;
#endif
#endif

unsigned int p11_forkid = 1;

#ifdef HAVE_STRERROR_L
extern locale_t p11_message_locale;
#endif

#ifdef __linux__
/* used only under __linux__ in the getprogname() emulation in compat.c. */
char *p11_program_realpath;
#endif

static char *
thread_local_message (void)
{
	p11_local *local;
	local = _p11_library_get_thread_local ();
	return local ? local->message : NULL;
}

static char *
dont_store_message (void)
{
	return NULL;
}

static void
uninit_common (void)
{
	p11_debug ("uninitializing library");
}

#ifdef OS_UNIX

#ifdef P11_TLS_KEYWORD
static p11_local *
_p11_library_get_thread_local (void)
{
	static P11_TLS_KEYWORD p11_local local;
	static P11_TLS_KEYWORD bool local_initialized = false;

	if (!local_initialized) {
		memset (&local, 0, sizeof (p11_local));
		local_initialized = true;
	}

	return &local;
}
#else
static pthread_key_t thread_local = 0;

static p11_local *
_p11_library_get_thread_local (void)
{
	p11_local *local;

	p11_library_init_once ();

	local = pthread_getspecific (thread_local);
	if (local == NULL) {
		local = calloc (1, sizeof (p11_local));
		pthread_setspecific (thread_local, local);
	}

	return local;
}
#endif

static void
count_forks (void)
{
	/* Thread safe, executed in child, one thread exists */
	p11_forkid++;
}

void
p11_library_init_impl (void)
{
	p11_debug_init ();
	p11_debug ("initializing library");
	P11_RECURSIVE_MUTEX_INIT (p11_library_mutex);
	P11_RECURSIVE_MUTEX_INIT (p11_virtual_mutex);
#ifndef P11_TLS_KEYWORD
	pthread_key_create (&thread_local, free);
#endif
	p11_message_storage = thread_local_message;
#ifdef HAVE_STRERROR_L
	p11_message_locale = newlocale (LC_ALL_MASK, "POSIX", (locale_t) 0);
#endif

	pthread_atfork (NULL, NULL, count_forks);
}

void
p11_library_init (void)
{
	p11_library_init_impl ();
}

void
p11_library_uninit (void)
{
	uninit_common ();

#ifndef P11_TLS_KEYWORD
	/* Some cleanup to pacify valgrind */
	free (pthread_getspecific (thread_local));
	pthread_setspecific (thread_local, NULL);
#endif

#ifdef HAVE_STRERROR_L
	if (p11_message_locale != (locale_t) 0)
		freelocale (p11_message_locale);
#endif
	p11_message_storage = dont_store_message;
#ifndef P11_TLS_KEYWORD
	pthread_key_delete (thread_local);
#endif
	p11_mutex_uninit (&p11_virtual_mutex);
	p11_mutex_uninit (&p11_library_mutex);

#ifdef __linux__
	free (p11_program_realpath);
#endif
}

#endif /* OS_UNIX */

#ifdef OS_WIN32

static DWORD thread_local = TLS_OUT_OF_INDEXES;

BOOL WINAPI DllMain (HINSTANCE, DWORD, LPVOID);

static p11_local *
_p11_library_get_thread_local (void)
{
	LPVOID data;

	if (thread_local == TLS_OUT_OF_INDEXES)
		return NULL;

	data = TlsGetValue (thread_local);
	if (data == NULL) {
		data = LocalAlloc (LPTR, sizeof (p11_local));
		TlsSetValue (thread_local, data);
	}

	return (p11_local *)data;
}

void
p11_library_init (void)
{
	p11_debug_init ();
	p11_debug ("initializing library");
	P11_RECURSIVE_MUTEX_INIT (p11_library_mutex);
	P11_RECURSIVE_MUTEX_INIT (p11_virtual_mutex);
	thread_local = TlsAlloc ();
	if (thread_local == TLS_OUT_OF_INDEXES)
		p11_debug ("couldn't setup tls");
	else
		p11_message_storage = thread_local_message;
}

void
p11_library_thread_cleanup (void)
{
	p11_local *local;
	if (thread_local != TLS_OUT_OF_INDEXES) {
		p11_debug ("thread stopped, freeing tls");
		local = TlsGetValue (thread_local);
		LocalFree (local);
	}
}

void
p11_library_uninit (void)
{
	LPVOID data;

	uninit_common ();

	if (thread_local != TLS_OUT_OF_INDEXES) {
		p11_message_storage = dont_store_message;
		data = TlsGetValue (thread_local);
		LocalFree (data);
		TlsFree (thread_local);
	}
	p11_mutex_uninit (&p11_virtual_mutex);
	p11_mutex_uninit (&p11_library_mutex);
}

#endif /* OS_WIN32 */
