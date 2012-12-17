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

#include <assert.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define P11_MAX_MESSAGE 512

typedef struct {
	char message[P11_MAX_MESSAGE];
#ifdef OS_WIN32
	void *last_error;
#endif
} p11_local;

static p11_local * _p11_library_get_thread_local (void);

p11_mutex_t p11_library_mutex;

#ifdef OS_UNIX
pthread_once_t p11_library_once;
#endif

static int print_messages = 1;

void
p11_message_store (const char* msg,
                   size_t length)
{
	p11_local *local;

	if (length > P11_MAX_MESSAGE - 1)
		length = P11_MAX_MESSAGE - 1;

	local = _p11_library_get_thread_local ();
	if (local != NULL) {
		memcpy (local->message, msg, length);
		local->message[length] = 0;
	}
}

void
p11_message (const char* msg,
             ...)
{
	char buffer[P11_MAX_MESSAGE];
	va_list va;
	size_t length;

	va_start (va, msg);
	length = vsnprintf (buffer, P11_MAX_MESSAGE - 1, msg, va);
	va_end (va);

	/* Was it truncated? */
	if (length > P11_MAX_MESSAGE - 1)
		length = P11_MAX_MESSAGE - 1;
	buffer[length] = 0;

	/* If printing is not disabled, just print out */
	if (print_messages)
		fprintf (stderr, "p11-kit: %s\n", buffer);

	p11_debug_message (P11_DEBUG_LIB, "message: %s", buffer);
	p11_message_store (buffer, length);
}

void
p11_message_quiet (void)
{
	p11_lock ();
	print_messages = 0;
	p11_unlock ();
}

const char*
p11_message_last (void)
{
	p11_local *local;
	local = _p11_library_get_thread_local ();
	return local && local->message[0] ? local->message : NULL;
}

void
p11_message_clear (void)
{
	p11_local *local;
	local = _p11_library_get_thread_local ();
	if (local != NULL)
		local->message[0] = 0;
}

static void
uninit_common (void)
{
	p11_debug ("uninitializing library");
}

#ifdef OS_UNIX

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

void
p11_library_init_impl (void)
{
	p11_debug_init ();
	p11_debug ("initializing library");
	p11_mutex_init (&p11_library_mutex);
	pthread_key_create (&thread_local, free);
}

#ifdef __GNUC__
__attribute__((constructor))
#endif
void
p11_library_init (void)
{
	p11_library_init_once ();
}

#ifdef __GNUC__
__attribute__((destructor))
#endif
void
p11_library_uninit (void)
{
	uninit_common ();

	/* Some cleanup to pacify valgrind */
	free (pthread_getspecific (thread_local));
	pthread_setspecific (thread_local, NULL);

	pthread_key_delete (thread_local);
	p11_mutex_uninit (&p11_library_mutex);
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
	p11_mutex_init (&p11_library_mutex);
	thread_local = TlsAlloc ();
}

static void
free_tls_value (LPVOID data)
{
	p11_local *local = data;
	if (local == NULL)
		return;
	if (local->last_error)
		LocalFree (local->last_error);
	LocalFree (data);
}

void
p11_library_uninit (void)
{
	LPVOID data;

	uninit_common ();

	if (thread_local != TLS_OUT_OF_INDEXES) {
		data = TlsGetValue (thread_local);
		free_tls_value (data);
		TlsFree (thread_local);
	}
	_p11_mutex_uninit (&p11_library_mutex);
}


BOOL WINAPI
DllMain (HINSTANCE instance,
         DWORD reason,
         LPVOID reserved)
{
	LPVOID data;

	switch (reason) {
	case DLL_PROCESS_ATTACH:
		p11_library_init ();
		if (thread_local == TLS_OUT_OF_INDEXES) {
			p11_debug ("couldn't setup tls");
			return FALSE;
		}
		break;

	case DLL_THREAD_DETACH:
		if (thread_local != TLS_OUT_OF_INDEXES) {
			p11_debug ("thread stopped, freeing tls");
			data = TlsGetValue (thread_local);
			free_tls_value (data);
		}
		break;

	case DLL_PROCESS_DETACH:
		p11_library_uninit ();
		break;

	default:
		break;
	}

	return TRUE;
}

#endif /* OS_WIN32 */
