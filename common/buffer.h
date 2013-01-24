/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* buffer.h - Generic data buffer, used by openssh, gnome-keyring

   Copyright (C) 2007, 2012 Stefan Walter
   Copyright (C) 2012 Red Hat Inc.

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

#ifndef P11_BUFFER_H_
#define P11_BUFFER_H_

#include "compat.h"

enum {
	P11_BUFFER_FAILED = 1 << 0,
	P11_BUFFER_NULL = 1 << 1,
};

typedef struct {
	void *data;
	size_t len;

	int flags;
	size_t size;
	void * (* frealloc) (void *, size_t);
	void (* ffree) (void *);
} p11_buffer;

bool             p11_buffer_init             (p11_buffer *buffer,
                                              size_t size);

bool             p11_buffer_init_null        (p11_buffer *buffer,
                                              size_t size);

void             p11_buffer_init_full        (p11_buffer *buffer,
                                              void *data,
                                              size_t len,
                                              int flags,
                                              void * (* frealloc) (void *, size_t),
                                              void (* ffree) (void *));

void             p11_buffer_uninit           (p11_buffer *buffer);

void *           p11_buffer_steal            (p11_buffer *buffer,
                                              size_t *length);

bool             p11_buffer_reset            (p11_buffer *buffer,
                                              size_t size);

void *           p11_buffer_append           (p11_buffer *buffer,
                                              size_t length);

void             p11_buffer_add              (p11_buffer *buffer,
                                              const void *data,
                                              ssize_t length);

#define          p11_buffer_fail(buf) \
	((buf)->flags |= P11_BUFFER_FAILED)

#define          p11_buffer_ok(buf) \
	(((buf)->flags & P11_BUFFER_FAILED) ? false : true)

#define          p11_buffer_failed(buf) \
	(((buf)->flags & P11_BUFFER_FAILED) ? true : false)

#endif /* BUFFER_H */
