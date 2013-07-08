/*
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
 * Author: Stef Walter <stefw@redhat.com>
 */

#ifndef P11_BUILDER_H_
#define P11_BUILDER_H_

#include "asn1.h"
#include "dict.h"
#include "index.h"
#include "pkcs11.h"

enum {
	P11_BUILDER_FLAG_NONE = 0,
	P11_BUILDER_FLAG_TOKEN = 1 << 1,
};

typedef struct _p11_builder p11_builder;

p11_builder *         p11_builder_new         (int flags);

void                  p11_builder_free        (p11_builder *builder);

CK_RV                 p11_builder_build       (void *builder,
                                               p11_index *index,
                                               CK_ATTRIBUTE *attrs,
                                               CK_ATTRIBUTE *merge,
                                               CK_ATTRIBUTE **populate);

void                  p11_builder_changed     (void *builder,
                                               p11_index *index,
                                               CK_OBJECT_HANDLE handle,
                                               CK_ATTRIBUTE *attrs);

p11_asn1_cache *      p11_builder_get_cache   (p11_builder *builder);

#endif /* P11_BUILDER_H_ */
