/*
 * Copyright (c) 2023, Red Hat Inc.
 *
 * All rights reserved.
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
 * Author: Daiki Ueno
 */

#ifndef P11_KIT_TOOL_H
#define P11_KIT_TOOL_H

#include "compat.h"
#include "iter.h"
#include "pkcs11.h"
#include "uri.h"

typedef struct p11_tool p11_tool;

p11_tool       *p11_tool_new        (void);
void            p11_tool_free       (p11_tool *tool);
P11KitUriResult p11_tool_set_uri    (p11_tool *tool,
				     const char *string,
				     P11KitUriType type);
void            p11_tool_set_login  (p11_tool *tool,
				     bool login);
P11KitIter     *p11_tool_begin_iter (p11_tool *tool,
				     P11KitIterBehavior behavior);
void            p11_tool_end_iter   (p11_tool *tool,
				     P11KitIter *iter);

#endif /* P11_KIT_TOOL_H */
