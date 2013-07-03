/*
 * Copyright (c) 2013 Red Hat Inc.
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
 * Author: Stef Walter <stefw@redhat.com>
 */

#ifndef P11_PATH_H__
#define P11_PATH_H__

#include "compat.h"

#ifdef OS_WIN32
#define P11_PATH_SEP   ";"
#define P11_PATH_SEP_C ';'
#else
#define P11_PATH_SEP   ":"
#define P11_PATH_SEP_C ':'
#endif

/*
 * The semantics of both POSIX basename() and GNU asename() are so crappy that
 * we just don't even bother. And what's worse is how it completely changes
 * behavior if _GNU_SOURCE is defined. Nasty stuff.
 */
char *       p11_path_base      (const char *name);

char *       p11_path_expand    (const char *path);

char *       p11_path_build     (const char *path,
                                 ...) GNUC_NULL_TERMINATED;

bool         p11_path_absolute  (const char *path);

char *       p11_path_parent    (const char *path);

bool         p11_path_prefix    (const char *string,
                                 const char *prefix);

void         p11_path_canon     (char *name);

#endif /* P11_PATH_H__ */
