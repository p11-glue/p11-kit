/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* buffer.c - Generic data buffer, used by openssh, gnome-keyring

   Copyright (C) 2007, 2012 Stefan Walter
   Copyright (C) 2013 Red Hat Inc.

   The Gnome Keyring Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   The Gnome Keyring Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with the Gnome Library; see the file COPYING.LIB.  If not,
   write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.

   Author: Stef Walter <stef@thewalter.net>
*/

#include "config.h"

#include "buffer.h"
#include "debug.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

static bool
buffer_realloc (p11_buffer *buffer,
                size_t size)
{
	void *data;

	/* Memory owned elsewhere can't be reallocated */
	return_val_if_fail (buffer->frealloc != NULL, false);

	/* Reallocate built in buffer using allocator */
	data = (buffer->frealloc) (buffer->data, size);
	if (!data && size > 0) {
		p11_buffer_fail (buffer);
		return_val_if_reached (false);
	}

	buffer->data = data;
	buffer->size = size;
	return true;
}

bool
p11_buffer_init (p11_buffer *buffer,
                 size_t reserve)
{
	p11_buffer_init_full (buffer, NULL, 0, 0, realloc, free);
	return buffer_realloc (buffer, reserve);
}

bool
p11_buffer_init_null (p11_buffer *buffer,
                      size_t reserve)
{
	p11_buffer_init_full (buffer, NULL, 0, P11_BUFFER_NULL, realloc, free);
	return buffer_realloc (buffer, reserve);
}

void
p11_buffer_init_full (p11_buffer *buffer,
                      void *data,
                      size_t len,
                      int flags,
                      void * (* frealloc) (void *, size_t),
                      void (* ffree) (void *))
{
	memset (buffer, 0, sizeof (*buffer));

	buffer->data = data;
	buffer->len = len;
	buffer->size = len;
	buffer->flags = flags;
	buffer->frealloc = frealloc;
	buffer->ffree = ffree;

	return_if_fail (!(flags & P11_BUFFER_FAILED));
}

void
p11_buffer_uninit (p11_buffer *buffer)
{
	return_if_fail (buffer != NULL);

	if (buffer->ffree && buffer->data)
		(buffer->ffree) (buffer->data);
	memset (buffer, 0, sizeof (*buffer));
}

void *
p11_buffer_steal (p11_buffer *buffer,
                  size_t *length)
{
	void *data;

	return_val_if_fail (p11_buffer_ok (buffer), NULL);

	if (length)
		*length = buffer->len;
	data = buffer->data;

	buffer->data = NULL;
	buffer->size = 0;
	buffer->len = 0;
	return data;
}

bool
p11_buffer_reset (p11_buffer *buffer,
                  size_t reserve)
{
	buffer->flags &= ~P11_BUFFER_FAILED;
	buffer->len = 0;

	if (reserve < buffer->size)
		return true;
	return buffer_realloc (buffer, reserve);
}

void *
p11_buffer_append (p11_buffer *buffer,
                   size_t length)
{
	unsigned char *data;
	size_t terminator;
	size_t newlen;
	size_t reserve;

	return_val_if_fail (p11_buffer_ok (buffer), NULL);

	terminator = (buffer->flags & P11_BUFFER_NULL) ? 1 : 0;
	reserve = terminator + length + buffer->len;

	if (reserve > buffer->size) {

		/* Calculate a new length, minimize number of buffer allocations */
		newlen = buffer->size * 2;
		if (!newlen)
			newlen = 16;
		if (reserve > newlen)
			newlen = reserve;

		if (!buffer_realloc (buffer, newlen))
			return_val_if_reached (NULL);
	}

	data = buffer->data;
	data += buffer->len;
	buffer->len += length;
	if (terminator)
		data[length] = '\0';
	return data;
}

void
p11_buffer_add (p11_buffer *buffer,
                const void *data,
                ssize_t length)
{
	void *at;

	if (length < 0)
		length = strlen (data);

	at = p11_buffer_append (buffer, length);
	return_if_fail (at != NULL);
	memcpy (at, data, length);
}
