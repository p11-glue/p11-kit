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

/*
 * Oh god. glibc is nasty. Changes behavior and definitions of POSIX
 * functions to completely different signatures depending on defines
 */
#define _POSIX_C_SOURCE 200112L

#include "compat.h"
#define P11_DEBUG_FLAG P11_DEBUG_LIB
#include "debug.h"
#include "message.h"

#include <assert.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

static bool print_messages = true;

static char *
default_message_storage (void)
{
	static char message[P11_MESSAGE_MAX] = { 0, };
	return message;
}

/* Function pointer declared in message.h as extern */
char * (* p11_message_storage) (void) = default_message_storage;

void
p11_message_store (const char* msg,
                   size_t length)
{
	char *buffer;

	/*
	 * p11_message_storage() is called to get a storage location for
	 * the last message. It defaults to a globally allocated buffer
	 * but is overridden in library.c with a function that returns
	 * per thread buffers.
	 *
	 * The returned value is P11_MESSAGE_MAX bytes long
	 */
	buffer = p11_message_storage ();

	if (length > P11_MESSAGE_MAX - 1)
		length = P11_MESSAGE_MAX - 1;

	if (buffer != NULL) {
		memcpy (buffer, msg, length);
		buffer[length] = 0;
	}
}

void
p11_message_err (int errnum,
                 const char* msg,
                 ...)
{
	char buffer[P11_MESSAGE_MAX];
	char strerr[P11_MESSAGE_MAX];
	va_list va;
	size_t length;

	va_start (va, msg);
	length = vsnprintf (buffer, P11_MESSAGE_MAX - 1, msg, va);
	va_end (va);

	/* Was it truncated? */
	if (length > P11_MESSAGE_MAX - 1)
		length = P11_MESSAGE_MAX - 1;
	buffer[length] = 0;

	strncpy (strerr, "Unknown error", sizeof (strerr));
	strerror_r (errnum, strerr, sizeof (strerr));
	strerr[P11_MESSAGE_MAX - 1] = 0;

	p11_message ("%s: %s", buffer, strerr);
}

void
p11_message (const char* msg,
             ...)
{
	char buffer[P11_MESSAGE_MAX];
	va_list va;
	size_t length;

	va_start (va, msg);
	length = vsnprintf (buffer, P11_MESSAGE_MAX - 1, msg, va);
	va_end (va);

	/* Was it truncated? */
	if (length > P11_MESSAGE_MAX - 1)
		length = P11_MESSAGE_MAX - 1;
	buffer[length] = 0;

	/* If printing is not disabled, just print out */
	if (print_messages)
		fprintf (stderr, "p11-kit: %s\n", buffer);
	else
		p11_debug_message (P11_DEBUG_LIB, "message: %s", buffer);
	p11_message_store (buffer, length);
}

void
p11_message_quiet (void)
{
	print_messages = false;
}

void
p11_message_loud (void)
{
	print_messages = true;
}

const char *
p11_message_last (void)
{
	char *buffer;
	buffer = p11_message_storage ();
	return buffer && buffer[0] ? buffer : NULL;
}

void
p11_message_clear (void)
{
	char *buffer;
	buffer = p11_message_storage ();
	if (buffer != NULL)
		buffer[0] = 0;
}
