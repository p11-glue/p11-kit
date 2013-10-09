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

#ifndef __P11_KIT_PRIVATE_H__
#define __P11_KIT_PRIVATE_H__

#include "compat.h"
#include "pkcs11.h"

/* These are global variables to be overridden in tests */
extern const char *p11_config_system_file;
extern const char *p11_config_user_file;
extern const char *p11_config_package_modules;
extern const char *p11_config_system_modules;
extern const char *p11_config_user_modules;

CK_RV       _p11_load_config_files_unlocked                     (const char *system_conf,
                                                                 const char *user_conf,
                                                                 int *user_mode);

void        _p11_kit_default_message                            (CK_RV rv);

const char * _p11_get_progname_unlocked                         (void);

void        _p11_set_progname_unlocked                          (const char *progname);

int          p11_match_uri_module_info                          (CK_INFO_PTR one,
                                                                 CK_INFO_PTR two);

int          p11_match_uri_token_info                           (CK_TOKEN_INFO_PTR one,
                                                                 CK_TOKEN_INFO_PTR two);

#endif /* __P11_KIT_PRIVATE_H__ */
