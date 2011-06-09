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
 * Author: Stef Walter <stefw@collabora.co.uk>
 */

#ifndef __P11_KIT_H__
#define __P11_KIT_H__

#include "p11-kit/pkcs11.h"

/*
 * If the caller is using the PKCS#11 GNU calling convention, then we cater
 * to that here.
 */
#ifdef CRYPTOKI_GNU
typedef ck_rv_t CK_RV;
typedef struct ck_function_list* CK_FUNCTION_LIST_PTR;
#endif

#ifdef __cplusplus
extern "C" {
#endif

CK_RV                    p11_kit_initialize_registered     (void);

CK_RV                    p11_kit_finalize_registered       (void);

CK_FUNCTION_LIST_PTR*    p11_kit_registered_modules        (void);

char*                    p11_kit_registered_module_to_name (CK_FUNCTION_LIST_PTR module);

CK_FUNCTION_LIST_PTR     p11_kit_registered_name_to_module (const char *name);

char*                    p11_kit_registered_option         (CK_FUNCTION_LIST_PTR module,
                                                            const char *field);

CK_RV                    p11_kit_initialize_module         (CK_FUNCTION_LIST_PTR module);

CK_RV                    p11_kit_finalize_module           (CK_FUNCTION_LIST_PTR module);

CK_RV                    p11_kit_load_initialize_module    (const char *module_path,
                                                            CK_FUNCTION_LIST_PTR *module);

const char*              p11_kit_strerror                  (CK_RV rv);

size_t                   p11_kit_space_strlen              (const unsigned char *string,
                                                            size_t max_length);

char*                    p11_kit_space_strdup              (const unsigned char *string,
                                                            size_t max_length);

#ifdef P11_KIT_FUTURE_UNSTABLE_API

void                     p11_kit_be_quiet                  (void);

const char*              p11_kit_message                   (void);

#endif

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* __P11_KIT_H__ */
