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

#include "pkcs11.h"

#define CKA_INVALID ((CK_ULONG)-1)

CK_ATTRIBUTE *      p11_attrs_dup           (CK_ATTRIBUTE *attrs);

CK_ATTRIBUTE *      p11_attrs_build         (CK_ATTRIBUTE *attrs,
                                             ...);

CK_ATTRIBUTE *      p11_attrs_buildn        (CK_ATTRIBUTE *attrs,
                                             CK_ATTRIBUTE *add,
                                             CK_ULONG count);

CK_ATTRIBUTE *      p11_attrs_take          (CK_ATTRIBUTE *attrs,
                                             CK_ATTRIBUTE_TYPE type,
                                             CK_VOID_PTR value,
                                             CK_ULONG length);

CK_BBOOL            p11_attrs_is_empty      (CK_ATTRIBUTE *attrs);

CK_ULONG            p11_attrs_count         (CK_ATTRIBUTE *attrs);

void                p11_attrs_free          (void *attrs);

CK_ATTRIBUTE *      p11_attrs_find          (CK_ATTRIBUTE *attrs,
                                             CK_ATTRIBUTE_TYPE type);

CK_ATTRIBUTE *      p11_attrs_findn         (CK_ATTRIBUTE *attrs,
                                             CK_ULONG count,
                                             CK_ATTRIBUTE_TYPE type);

CK_BBOOL            p11_attrs_remove        (CK_ATTRIBUTE *attrs,
                                             CK_ATTRIBUTE_TYPE type);

CK_BBOOL            p11_attrs_match         (CK_ATTRIBUTE *attrs,
                                             CK_ATTRIBUTE *match);

CK_BBOOL            p11_attrs_matchn        (CK_ATTRIBUTE *attrs,
                                             CK_ATTRIBUTE *match,
                                             CK_ULONG count);

CK_BBOOL            p11_attr_equal          (CK_ATTRIBUTE *one,
                                             CK_ATTRIBUTE *two);

CK_BBOOL            p11_attr_match_boolean  (CK_ATTRIBUTE *attr,
                                             CK_BBOOL value);

#endif /* P11_ATTRS_H_ */
