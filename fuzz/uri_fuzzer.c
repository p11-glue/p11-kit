/*
 * Copyright (c) 2026, Red Hat Inc.
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
 */

#include "config.h"
#include "test.h"

#include "fuzz/fuzz.h"
#include "p11-kit/uri.h"

#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C"
#endif
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    P11KitUri *uri;
    char *string;
    char *nul_terminated;
    int ret;

    /* p11_kit_uri_parse expects a NUL-terminated string */
    nul_terminated = malloc(size + 1);
    if (!nul_terminated)
        return 0;
    memcpy(nul_terminated, data, size);
    nul_terminated[size] = '\0';

    uri = p11_kit_uri_new();
    if (!uri) {
        free(nul_terminated);
        return 0;
    }

    /* Parse with P11_KIT_URI_FOR_ANY to exercise all attribute paths */
    ret = p11_kit_uri_parse(nul_terminated, P11_KIT_URI_FOR_ANY, uri);

    if (ret == P11_KIT_URI_OK) {
        /* Exercise the format (serialization) round-trip */
        if (p11_kit_uri_format(uri, P11_KIT_URI_FOR_ANY, &string) == P11_KIT_URI_OK)
            free(string);

        /* Exercise attribute accessors */
        p11_kit_uri_get_module_info(uri);
        p11_kit_uri_get_slot_info(uri);
        p11_kit_uri_get_token_info(uri);
        p11_kit_uri_get_pin_value(uri);
        p11_kit_uri_get_pin_source(uri);
        p11_kit_uri_get_module_name(uri);
        p11_kit_uri_get_module_path(uri);
        p11_kit_uri_any_unrecognized(uri);
    }

    /* Exercise the message function for all result codes */
    p11_kit_uri_message(ret);

    p11_kit_uri_free(uri);
    free(nul_terminated);

    return 0;
}
