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
#include "p11-kit.h"
#include "private.h"
#include "proxy.h"

#include <assert.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/**
 * SECTION:p11-kit-future
 * @title: Future
 * @short_description: Future Unstable API
 *
 * API that is not yet stable enough to be enabled by default. In all likelyhood
 * this will be included in the next release. To use this API you must define a
 * MACRO. See the p11-kit.h header for more details.
 */

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
	size_t i = max_length;

	assert (string);

	while (i > 0 && string[i - 1] == ' ')
		--i;
	return i;
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

/**
 * p11_kit_be_quiet:
 *
 * Once this function is called, the p11-kit library will no longer print
 * failure or warning messages to stderr.
 */
void
p11_kit_be_quiet (void)
{
	p11_lock ();
	p11_message_quiet ();
	p11_debug_init ();
	p11_unlock ();
}

/**
 * p11_kit_be_loud:
 *
 * Tell the p11-kit library will print failure or warning messages to stderr.
 * This is the default behavior, but can be changed using p11_kit_be_quiet().
 */
void
p11_kit_be_loud (void)
{
	p11_lock ();
	p11_message_loud ();
	p11_debug_init ();
	p11_unlock ();
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
	return p11_message_last ();
}

void
_p11_kit_default_message (CK_RV rv)
{
	const char *msg;

	if (rv != CKR_OK) {
		msg = p11_kit_strerror (rv);
		p11_message_store (msg, strlen (msg));
	}
}

/* This is the progname that we think of this process as. */
char p11_my_progname[256] = { 0, };

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
	p11_library_init_once ();

	p11_lock ();
	_p11_set_progname_unlocked (progname);
	p11_unlock ();
}

void
_p11_set_progname_unlocked (const char *progname)
{
	/* We can be called with NULL */
	if (progname == NULL)
		progname = "";

	strncpy (p11_my_progname, progname, sizeof (p11_my_progname));
	p11_my_progname[sizeof (p11_my_progname) - 1] = 0;
}

const char *
_p11_get_progname_unlocked (void)
{
	if (p11_my_progname[0] == '\0')
		_p11_set_progname_unlocked (getprogname ());
	if (p11_my_progname[0] == '\0')
		return NULL;
	return p11_my_progname;
}

#ifdef OS_UNIX

void _p11_kit_init (void);

void _p11_kit_fini (void);

#ifdef __GNUC__
__attribute__((constructor))
#endif
void
_p11_kit_init (void)
{
	p11_library_init_once ();
}

#ifdef __GNUC__
__attribute__((destructor))
#endif
void
_p11_kit_fini (void)
{
	p11_proxy_module_cleanup ();
	p11_library_uninit ();
}

#endif /* OS_UNIX */

#ifdef OS_WIN32

BOOL WINAPI DllMain (HINSTANCE, DWORD, LPVOID);

BOOL WINAPI
DllMain (HINSTANCE instance,
         DWORD reason,
         LPVOID reserved)
{
	switch (reason) {
	case DLL_PROCESS_ATTACH:
		p11_library_init ();
		break;
	case DLL_THREAD_DETACH:
		p11_library_thread_cleanup ();
		break;
	case DLL_PROCESS_DETACH:
		p11_proxy_module_cleanup ();
		p11_library_uninit ();
		break;
	default:
		break;
	}

	return TRUE;
}

#endif /* OS_WIN32 */
