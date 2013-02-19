/*
 * Copyright (C) 2012, Redhat Inc.
 * Copyright (c) 2011, Collabora Ltd.
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
 * Author: Stef Walter <stefw@collabora.co.uk>
 */

#ifndef P11_ATTRS_H_
#define P11_ATTRS_H_

#include "buffer.h"
#include "compat.h"
#include "pkcs11.h"

#define CKA_INVALID ((CK_ULONG)-1)

CK_ATTRIBUTE *      p11_attrs_dup           (const CK_ATTRIBUTE *attrs);

CK_ATTRIBUTE *      p11_attrs_build         (CK_ATTRIBUTE *attrs,
                                             ...);

CK_ATTRIBUTE *      p11_attrs_buildn        (CK_ATTRIBUTE *attrs,
                                             const CK_ATTRIBUTE *add,
                                             CK_ULONG count);

CK_ATTRIBUTE *      p11_attrs_take          (CK_ATTRIBUTE *attrs,
                                             CK_ATTRIBUTE_TYPE type,
                                             CK_VOID_PTR value,
                                             CK_ULONG length);

CK_ATTRIBUTE *      p11_attrs_merge         (CK_ATTRIBUTE *attrs,
                                             CK_ATTRIBUTE *merge,
                                             bool replace);

void                p11_attrs_purge         (CK_ATTRIBUTE *attrs);

bool                p11_attrs_terminator    (const CK_ATTRIBUTE *attrs);

CK_ULONG            p11_attrs_count         (const CK_ATTRIBUTE *attrs);

void                p11_attrs_free          (void *attrs);

CK_ATTRIBUTE *      p11_attrs_find          (CK_ATTRIBUTE *attrs,
                                             CK_ATTRIBUTE_TYPE type);

CK_ATTRIBUTE *      p11_attrs_findn         (CK_ATTRIBUTE *attrs,
                                             CK_ULONG count,
                                             CK_ATTRIBUTE_TYPE type);

bool                p11_attrs_find_bool     (const CK_ATTRIBUTE *attrs,
                                             CK_ATTRIBUTE_TYPE type,
                                             CK_BBOOL *value);

bool                p11_attrs_findn_bool    (const CK_ATTRIBUTE *attrs,
                                             CK_ULONG count,
                                             CK_ATTRIBUTE_TYPE type,
                                             CK_BBOOL *value);

bool                p11_attrs_find_ulong    (const CK_ATTRIBUTE *attrs,
                                             CK_ATTRIBUTE_TYPE type,
                                             CK_ULONG *value);

bool                p11_attrs_findn_ulong   (const CK_ATTRIBUTE *attrs,
                                             CK_ULONG count,
                                             CK_ATTRIBUTE_TYPE type,
                                             CK_ULONG *value);

void *              p11_attrs_find_value    (CK_ATTRIBUTE *attrs,
                                             CK_ATTRIBUTE_TYPE type,
                                             size_t *length);

CK_ATTRIBUTE *      p11_attrs_find_valid    (CK_ATTRIBUTE *attrs,
                                             CK_ATTRIBUTE_TYPE type);

bool                p11_attrs_remove        (CK_ATTRIBUTE *attrs,
                                             CK_ATTRIBUTE_TYPE type);

bool                p11_attrs_match         (const CK_ATTRIBUTE *attrs,
                                             const CK_ATTRIBUTE *match);

bool                p11_attrs_matchn        (const CK_ATTRIBUTE *attrs,
                                             const CK_ATTRIBUTE *match,
                                             CK_ULONG count);

char *              p11_attrs_to_string     (const CK_ATTRIBUTE *attrs,
                                             int count);

void                p11_attrs_format        (p11_buffer *buffer,
                                             const CK_ATTRIBUTE *attrs,
                                             int count);

char *              p11_attr_to_string      (const CK_ATTRIBUTE *attr,
                                             CK_OBJECT_CLASS klass);

void                p11_attr_format         (p11_buffer *buffer,
                                             const CK_ATTRIBUTE *attr,
                                             CK_OBJECT_CLASS klass);

bool                p11_attr_equal          (const void *one,
                                             const void *two);

unsigned int        p11_attr_hash           (const void *data);

bool                p11_attr_match_value    (const CK_ATTRIBUTE *attr,
                                             const void *value,
                                             ssize_t length);

#endif /* P11_ATTRS_H_ */
