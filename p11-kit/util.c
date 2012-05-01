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
#define DEBUG_FLAG DEBUG_LIB
#include "debug.h"
#include "p11-kit.h"
#include "private.h"
#include "util.h"

#include <assert.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/*
 * This is the mutex that protects the global data of this library
 * and the pkcs11 proxy module. Note that we *never* call into our
 * underlying pkcs11 modules while holding this mutex. Therefore it
 * doesn't have to be recursive and we can keep things simple.
 */
mutex_t _p11_mutex;

#ifdef OS_UNIX
pthread_once_t _p11_once;
#endif

/**
 * SECTION:p11-kit-future
 * @title: Future
 * @short_description: Future Unstable API
 *
 * API that is not yet stable enough to be enabled by default. In all likelyhood
 * this will be included in the next release. To use this API you must define a
 * MACRO. See the p11-kit.h header for more details.
 */

static int print_messages = 1;

void*
_p11_realloc (void *memory, size_t length)
{
	void *allocated = realloc (memory, length);
	if (!allocated)
		free (memory);
	return allocated;
}

/**
 * p11_kit_space_strlen:
 * @string: Pointer to string block
 * @max_length: Maximum length of string block
 *
 * In PKCS\#11 structures many strings are encoded in a strange way. The string
 * is placed in a fixed length buffer and then padded with spaces.
 *
 * This function determines the actual length of the string. Since the string
 * is not null-terminated you need to pass in the size of buffer as max_length.
 * The string will never be longer than this buffer.
 *
 * <informalexample><programlisting>
 * CK_INFO info;
 * size_t length;
 *    ...
 * length = p11_kit_space_strlen (info->libraryDescription, sizeof (info->libraryDescription));
 * </programlisting></informalexample>
 *
 * Returns: The length of the space padded string.
 */
size_t
p11_kit_space_strlen (const unsigned char *string, size_t max_length)
{
	size_t i = max_length - 1;

	assert (string);

	while (i > 0 && string[i] == ' ')
		--i;
	return i + 1;
}

/**
 * p11_kit_space_strdup:
 * @string: Pointer to string block
 * @max_length: Maximum length of string block
 *
 * In PKCS\#11 structures many strings are encoded in a strange way. The string
 * is placed in a fixed length buffer and then padded with spaces.
 *
 * This function copies the space padded string into a normal null-terminated
 * string. The result is owned by the caller.
 *
 * <informalexample><programlisting>
 * CK_INFO info;
 * char *description;
 *    ...
 * description = p11_kit_space_strdup (info->libraryDescription, sizeof (info->libraryDescription));
 * </programlisting></informalexample>
 *
 * Returns: The newly allocated string, or %NULL if memory could not be allocated.
 */
char*
p11_kit_space_strdup (const unsigned char *string, size_t max_length)
{
	size_t length;
	char *result;

	assert (string);

	length = p11_kit_space_strlen (string, max_length);

	result = malloc (length + 1);
	if (!result)
		return NULL;

	memcpy (result, string, length);
	result[length] = 0;
	return result;
}

static void
store_message_buffer (const char* msg, size_t length)
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
_p11_message (const char* msg, ...)
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

	store_message_buffer (buffer, length);
}

/**
 * p11_kit_be_quiet:
 *
 * Once this function is called, the p11-kit library will no longer print
 * failure or warning messages to stderr.
 */
void
p11_kit_be_quiet (void)
{
	_p11_lock ();
	print_messages = 0;
	_p11_unlock ();
}

/**
 * p11_kit_message:
 *
 * Gets the failure message for a recently called p11-kit function, which
 * returned a failure code on this thread. Not all functions set this message.
 * Each function that does so, will note it in its documentation.
 *
 * If the most recent p11-kit function did not fail, then this will return NULL.
 * The string is owned by the p11-kit library and is only valid on the same
 * thread that the failed function executed on.
 *
 * Returns: The last failure message, or %NULL.
 */
const char*
p11_kit_message (void)
{
	p11_local *local;
	local = _p11_library_get_thread_local ();
	return local && local->message[0] ? local->message : NULL;
}

void
_p11_kit_clear_message (void)
{
	p11_local *local;
	local = _p11_library_get_thread_local ();
	if (local != NULL)
		local->message[0] = 0;
}

void
_p11_kit_default_message (CK_RV rv)
{
	const char *msg;

	if (rv != CKR_OK) {
		msg = p11_kit_strerror (rv);
		store_message_buffer (msg, strlen (msg));
	}
}

static void
uninit_common (void)
{
	_p11_debug ("uninitializing library");

	_p11_set_progname_unlocked (NULL);
}

#ifdef OS_UNIX

static pthread_key_t thread_local = 0;

p11_local *
_p11_library_get_thread_local (void)
{
	p11_local *local;

	_p11_library_init_once ();

	local = pthread_getspecific (thread_local);
	if (local == NULL) {
		local = calloc (1, sizeof (p11_local));
		pthread_setspecific (thread_local, local);
	}

	return local;
}

#ifdef __GNUC__
__attribute__((constructor))
#endif
void
_p11_library_init (void)
{
	_p11_debug_init ();
	_p11_debug ("initializing library");
	_p11_mutex_init (&_p11_mutex);
	pthread_key_create (&thread_local, free);
}

#ifdef __GNUC__
__attribute__((destructor))
#endif
void
_p11_library_uninit (void)
{
	uninit_common ();

	/* Some cleanup to pacify valgrind */
	free (pthread_getspecific (thread_local));
	pthread_setspecific (thread_local, NULL);

	pthread_key_delete (thread_local);
	_p11_mutex_uninit (&_p11_mutex);
}

void
_p11_mutex_init (mutex_t *mutex)
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

static DWORD thread_local = TLS_OUT_OF_INDEXES;

BOOL WINAPI DllMain (HINSTANCE, DWORD, LPVOID);

p11_local *
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
_p11_library_init (void)
{
	_p11_debug_init ();
	_p11_debug ("initializing library");
	_p11_mutex_init (&_p11_mutex);
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
_p11_library_uninit (void)
{
	LPVOID data;

	uninit_common ();

	if (thread_local != TLS_OUT_OF_INDEXES) {
		data = TlsGetValue (thread_local);
		free_tls_value (data);
		TlsFree (thread_local);
	}
	_p11_mutex_uninit (&_p11_mutex);
}

const char *
_p11_module_error (void)
{
	DWORD code = GetLastError();
	p11_local *local;
	LPVOID msg_buf;

	local = _p11_library_get_thread_local ();

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
_p11_thread_create (thread_t *thread,
               thread_routine routine,
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
_p11_thread_join (thread_t thread)
{
	DWORD res;

	res = WaitForSingleObject (thread, INFINITE);
	if (res == WAIT_FAILED)
		return GetLastError ();

	CloseHandle (thread);
	return 0;
}

BOOL WINAPI
DllMain (HINSTANCE instance,
         DWORD reason,
         LPVOID reserved)
{
	LPVOID data;

	switch (reason) {
	case DLL_PROCESS_ATTACH:
		_p11_library_init ();
		if (thread_local == TLS_OUT_OF_INDEXES) {
			_p11_debug ("couldn't setup tls");
			return FALSE;
		}
		break;

	case DLL_THREAD_DETACH:
		if (thread_local != TLS_OUT_OF_INDEXES) {
			_p11_debug ("thread stopped, freeing tls");
			data = TlsGetValue (thread_local);
			free_tls_value (data);
		}
		break;

	case DLL_PROCESS_DETACH:
		_p11_library_uninit ();
		break;

	default:
		break;
	}

	return TRUE;
}

extern char **__argv;

static char *
get_default_progname (void)
{
	const char *name;
	const char *p;
	char *progname;
	size_t length;

	name = __argv[0];
	if (name == NULL)
		return NULL;

	p = strrchr (name, '\\');
	if (p != NULL)
		name = p + 1;

	progname = strdup (name);
	length = strlen (progname);
	if (length > 4 && _stricmp(progname + (length - 4), ".exe"))
		progname[length - 4] = '\0';

	return progname;
}

#endif /* OS_WIN32 */

/* This is the progname that we think of this process as. */
char *_p11_my_progname = NULL;

/**
 * p11_kit_set_progname:
 * @progname: the program base name
 *
 * Set the program base name that is used by the <literal>enable-in</literal>
 * and <literal>disable-in</literal> module configuration options.
 *
 * Normally this is automatically calculated from the program's argument list.
 * You would usually call this before initializing p11-kit modules.
 */
void
p11_kit_set_progname (const char *progname)
{
	_p11_library_init_once ();

	_p11_lock ();
	_p11_set_progname_unlocked (progname);
	_p11_unlock ();
}

void
_p11_set_progname_unlocked (const char *progname)
{
	/* We can be called with NULL, to cleanup memory usage */
	free (_p11_my_progname);
	_p11_my_progname = progname ? strdup (progname) : NULL;
}

const char *
_p11_get_progname_unlocked (void)
{
	if (_p11_my_progname == NULL)
		_p11_set_progname_unlocked (getprogname ());
	return _p11_my_progname;
}
