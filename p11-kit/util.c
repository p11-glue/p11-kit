/*
 * Copyright (c) 2011 Collabora Ltd
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
 *  Stef Walter <stef@memberwebs.com>
 */

#include "config.h"

#include "p11-kit.h"
#include "private.h"
#include "util.h"

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

#define MAX_MESSAGE 512
static pthread_once_t key_once = PTHREAD_ONCE_INIT;
static pthread_key_t message_buffer_key = 0;
static int print_messages = 1;

void*
xrealloc (void *memory, size_t length)
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
create_message_buffer_key (void)
{
	pthread_key_create (&message_buffer_key, free);
}

static void
store_message_buffer (const char* msg, size_t length)
{
	char *thread_buf;

	if (length > MAX_MESSAGE - 1)
		length = MAX_MESSAGE - 1;

	pthread_once (&key_once, create_message_buffer_key);
	thread_buf = pthread_getspecific (message_buffer_key);
	if (!thread_buf) {
		thread_buf = malloc (MAX_MESSAGE);
		pthread_setspecific (message_buffer_key, thread_buf);
	}

	memcpy (thread_buf, msg, length);
	thread_buf[length] = 0;
}

void
_p11_message (const char* msg, ...)
{
	char buffer[MAX_MESSAGE];
	va_list va;
	size_t length;

	va_start (va, msg);
	length = vsnprintf (buffer, MAX_MESSAGE - 1, msg, va);
	va_end (va);

	/* Was it truncated? */
	if (length > MAX_MESSAGE - 1)
		length = MAX_MESSAGE - 1;
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
	char *thread_buf;
	pthread_once (&key_once, create_message_buffer_key);
	thread_buf = pthread_getspecific (message_buffer_key);
	return thread_buf && thread_buf[0] ? thread_buf : NULL;
}

void
_p11_kit_clear_message (void)
{
	char *thread_buf;
	pthread_once (&key_once, create_message_buffer_key);
	thread_buf = pthread_getspecific (message_buffer_key);
	if (thread_buf != NULL)
		thread_buf[0] = 0;
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
