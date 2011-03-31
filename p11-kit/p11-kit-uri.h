/*
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

#include "pkcs11.h"

#ifndef __P11_KIT_URI_H__
#define __P11_KIT_URI_H__

#define P11_KIT_URI_SCHEME "pkcs11:"
#define P11_KIT_URI_SCHEME_LEN 7

typedef enum {
	P11_KIT_URI_OK = 0,
	P11_KIT_URI_NO_MEMORY = -1,
	P11_KIT_URI_BAD_SCHEME = -2,
	P11_KIT_URI_BAD_ENCODING = -3,
	P11_KIT_URI_BAD_SYNTAX = -4,
	P11_KIT_URI_BAD_VERSION = -5,
	P11_KIT_URI_NOT_FOUND = -6,
} P11KitUriResult;

typedef enum {
	P11_KIT_URI_IS_MODULE = (1 << 1),
	P11_KIT_URI_IS_TOKEN =   (1 << 2) | P11_KIT_URI_IS_MODULE,
	P11_KIT_URI_IS_OBJECT =  (1 << 3) | P11_KIT_URI_IS_TOKEN,
	P11_KIT_URI_IS_ANY =     0x0000FFFF,
} P11KitUriType;

typedef struct _P11KitUri P11KitUri;

CK_INFO_PTR         p11_kit_uri_get_module_info             (P11KitUri *uri);

int                 p11_kit_uri_match_module_info           (P11KitUri *uri,
                                                             CK_INFO_PTR info);

CK_TOKEN_INFO_PTR   p11_kit_uri_get_token_info              (P11KitUri *uri);

int                 p11_kit_uri_match_token_info            (P11KitUri *uri,
                                                             CK_TOKEN_INFO_PTR token_info);

CK_ATTRIBUTE_TYPE*  p11_kit_uri_get_attribute_types         (P11KitUri *uri,
                                                             int *n_types);

CK_ATTRIBUTE_PTR    p11_kit_uri_get_attribute               (P11KitUri *uri,
                                                             CK_ATTRIBUTE_TYPE attr_type);

int                 p11_kit_uri_set_attribute               (P11KitUri *uri,
                                                             CK_ATTRIBUTE_PTR attr);

int                 p11_kit_uri_clear_attribute             (P11KitUri *uri,
                                                             CK_ATTRIBUTE_TYPE attr_type);

int                 p11_kit_uri_match_attributes            (P11KitUri *uri,
                                                             CK_ATTRIBUTE_PTR attrs,
                                                             CK_ULONG n_attrs);

void                p11_kit_uri_set_unrecognized            (P11KitUri *uri,
                                                             int unrecognized);

int                 p11_kit_uri_any_unrecognized            (P11KitUri *uri);

P11KitUri*          p11_kit_uri_new                         (void);

int                 p11_kit_uri_format                      (P11KitUri *uri,
                                                             P11KitUriType uri_type,
                                                             char **string);

int                 p11_kit_uri_parse                       (const char *string,
                                                             P11KitUriType uri_type,
                                                             P11KitUri *uri);

void                p11_kit_uri_free                        (P11KitUri *uri);

#endif /* __P11_KIT_URI_H__ */
