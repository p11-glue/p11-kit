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

#ifndef P11_CONSTANTS_H_
#define P11_CONSTANTS_H_

#include "compat.h"
#include "dict.h"
#include "pkcs11.h"

typedef struct {
	CK_ULONG value;
	const char *name;
	const char *nicks[4];
} p11_constant;

const char *        p11_constant_name      (const p11_constant *constants,
                                            CK_ULONG value);

const char *        p11_constant_nick      (const p11_constant *constants,
                                            CK_ULONG type);

p11_dict *          p11_constant_reverse   (bool nick);

CK_ULONG            p11_constant_resolve   (p11_dict *table,
                                            const char *string);

extern const p11_constant    p11_constant_types[];

extern const p11_constant    p11_constant_classes[];

extern const p11_constant    p11_constant_trusts[];

extern const p11_constant    p11_constant_certs[];

extern const p11_constant    p11_constant_keys[];

extern const p11_constant    p11_constant_asserts[];

extern const p11_constant    p11_constant_categories[];

extern const p11_constant    p11_constant_mechanisms[];

extern const p11_constant    p11_constant_states[];

extern const p11_constant    p11_constant_users[];

extern const p11_constant    p11_constant_returns[];

#endif /* P11_CONSTANTS_H_ */
