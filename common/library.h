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

#ifndef P11_LIBRARY_H_
#define P11_LIBRARY_H_

#include "config.h"
#include "compat.h"

#include <sys/types.h>

extern p11_mutex_t p11_library_mutex;

extern unsigned int p11_forkid;

#define       p11_lock()                   p11_mutex_lock (&p11_library_mutex);

#define       p11_unlock()                 p11_mutex_unlock (&p11_library_mutex);

#ifdef OS_WIN32

/* No implementation, because done by DllMain */
#define       p11_library_init_once()

#else /* !OS_WIN32 */
extern        pthread_once_t               p11_library_once;

#define       p11_library_init_once() \
	pthread_once (&p11_library_once, p11_library_init_impl);

void          p11_library_init_impl        (void);

#endif /* !OS_WIN32 */

void          p11_library_init             (void);

void          p11_library_thread_cleanup   (void);

void          p11_library_uninit           (void);

#endif /* P11_LIBRARY_H_ */
