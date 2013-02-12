/*
 * Copyright (C) 2007, 2012 Stefan Walter
 * Copyright (C) 2012 Red Hat Inc.
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
 * Author: Stef Walter <stef@thewalter.net>
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
