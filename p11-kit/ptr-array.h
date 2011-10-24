/*
 * Copyright (c) 2011 Collabora Ltd.
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
 * Author: Stef Waler <stefw@collabora.co.uk>
 */

#ifndef __PTR_ARRAY_H__
#define __PTR_ARRAY_H__

#include <sys/types.h>

typedef struct ptr_array ptr_array_t;

typedef void         (*ptr_array_destroy_func)         (void *data);

ptr_array_t*         _p11_ptr_array_create             (ptr_array_destroy_func destroy_func);

void                 _p11_ptr_array_free               (ptr_array_t *array);

unsigned int         _p11_ptr_array_count              (ptr_array_t *array);

int                  _p11_ptr_array_add                (ptr_array_t *array,
                                                        void *value);

void                 _p11_ptr_array_remove             (ptr_array_t *array,
                                                        unsigned int index);

void*                _p11_ptr_array_at                 (ptr_array_t *array,
                                                        unsigned int index);

void**               _p11_ptr_array_snapshot           (ptr_array_t *array);

#endif  /* __PTR_ARRAY_H__ */
