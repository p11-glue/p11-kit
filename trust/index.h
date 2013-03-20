/*
 * Copyright (C) 2013 Red Hat Inc.
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

#ifndef P11_INDEX_H_
#define P11_INDEX_H_

#include "array.h"
#include "compat.h"
#include "pkcs11.h"

/*
 * A boolean value which denotes whether we auto generated
 * this object, as opposed to coming from outside the builder.
 *
 * We set this on all objects. It will always be either CK_TRUE
 * or CK_FALSE for all objects built by this builder.
 */
#define CKA_X_GENERATED (CKA_X_VENDOR + 8000)

typedef struct _p11_index p11_index;

typedef CK_RV   (* p11_index_build_cb)   (void *data,
                                          p11_index *index,
                                          CK_ATTRIBUTE **attrs,
                                          CK_ATTRIBUTE *merge);

typedef void    (* p11_index_notify_cb)  (void *data,
                                          p11_index *index,
                                          CK_OBJECT_HANDLE handle,
                                          CK_ATTRIBUTE *attrs);

p11_index *        p11_index_new         (p11_index_build_cb build,
                                          p11_index_notify_cb notify,
                                          void *data);

void               p11_index_free        (p11_index *index);

int                p11_index_size        (p11_index *index);

void               p11_index_batch       (p11_index *index);

void               p11_index_finish      (p11_index *index);

bool               p11_index_in_batch    (p11_index *index);

CK_RV              p11_index_take        (p11_index *index,
                                          CK_ATTRIBUTE *attrs,
                                          CK_OBJECT_HANDLE *handle);

CK_RV              p11_index_add         (p11_index *index,
                                          CK_ATTRIBUTE *attrs,
                                          CK_ULONG count,
                                          CK_OBJECT_HANDLE *handle);

CK_RV              p11_index_set         (p11_index *index,
                                          CK_OBJECT_HANDLE handle,
                                          CK_ATTRIBUTE *attrs,
                                          CK_ULONG count);

CK_RV              p11_index_update      (p11_index *index,
                                          CK_OBJECT_HANDLE handle,
                                          CK_ATTRIBUTE *attrs);

CK_RV              p11_index_replace     (p11_index *index,
                                          CK_OBJECT_HANDLE handle,
                                          CK_ATTRIBUTE *replace);

CK_RV              p11_index_replace_all (p11_index *index,
                                          CK_ATTRIBUTE *match,
                                          CK_ATTRIBUTE_TYPE key,
                                          p11_array *replace);

CK_RV              p11_index_remove      (p11_index *index,
                                          CK_OBJECT_HANDLE handle);

CK_ATTRIBUTE *     p11_index_lookup      (p11_index *index,
                                          CK_OBJECT_HANDLE handle);

CK_OBJECT_HANDLE   p11_index_find        (p11_index *index,
                                          CK_ATTRIBUTE *match,
                                          int count);

CK_OBJECT_HANDLE * p11_index_find_all    (p11_index *index,
                                          CK_ATTRIBUTE *match,
                                          int count);

CK_OBJECT_HANDLE * p11_index_snapshot    (p11_index *index,
                                          p11_index *base,
                                          CK_ATTRIBUTE *attrs,
                                          CK_ULONG count);

#endif /* P11_INDEX_H_ */
