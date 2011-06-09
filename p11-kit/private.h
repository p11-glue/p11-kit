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

#include "pkcs11.h"
#include "pthread.h"

extern pthread_mutex_t _p11_mutex;

#define     _p11_lock()    pthread_mutex_lock (&_p11_mutex);

#define     _p11_unlock()  pthread_mutex_unlock (&_p11_mutex);

void        _p11_message                                        (const char* msg, ...);

CK_FUNCTION_LIST_PTR_PTR   _p11_kit_registered_modules_unlocked (void);

CK_RV       _p11_kit_initialize_registered_unlocked_reentrant   (void);

CK_RV       _p11_kit_finalize_registered_unlocked_reentrant     (void);

void        _p11_kit_proxy_after_fork                           (void);

CK_RV       _p11_load_config_files_unlocked                     (const char *system_conf,
                                                                 const char *user_conf,
                                                                 int *user_mode);

void        _p11_kit_clear_message                              (void);

void        _p11_kit_default_message                            (CK_RV rv);

#endif /* __P11_KIT_PRIVATE_H__ */
