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

#ifndef P11_KIT_PIN_H
#define P11_KIT_PIN_H

#include <p11-kit/uri.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
	P11_KIT_PIN_FLAGS_USER_LOGIN = 1,
	P11_KIT_PIN_FLAGS_SO_LOGIN = 2,
	P11_KIT_PIN_FLAGS_CONTEXT_LOGIN = 4,
	P11_KIT_PIN_FLAGS_RETRY = 10,
	P11_KIT_PIN_FLAGS_MANY_TRIES = 20,
	P11_KIT_PIN_FLAGS_FINAL_TRY = 40
} P11KitPinFlags;

#define P11_KIT_PIN_FALLBACK ""

typedef int         (*p11_kit_pin_callback)                 (const char *pinfile,
                                                             P11KitUri *pin_uri,
                                                             const char *pin_description,
                                                             P11KitPinFlags pin_flags,
                                                             void *callback_data,
                                                             char *pin,
                                                             size_t pin_length);

typedef void        (*p11_kit_pin_callback_destroy)         (void *callback_data);

int                 p11_kit_pin_register_callback           (const char *pinfile,
                                                             p11_kit_pin_callback callback,
                                                             void *callback_data,
                                                             p11_kit_pin_callback_destroy callback_destroy);

void                p11_kit_pin_unregister_callback         (const char *pinfile,
                                                             p11_kit_pin_callback callback,
                                                             void *callback_data);

int                 p11_kit_pin_retrieve                    (const char *pinfile,
                                                             P11KitUri *pin_uri,
                                                             const char *pin_description,
                                                             P11KitPinFlags pin_flags,
                                                             char *pin,
                                                             size_t pin_max);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* P11_KIT_URI_H */
