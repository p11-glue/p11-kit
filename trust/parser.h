/*
 * Copyright (C) 2012 Red Hat Inc.
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
 * Author: Stef Walter <stefw@redhat.com>
 */

#include "dict.h"
#include "pkcs11.h"

#ifndef P11_PARSER_H_
#define P11_PARSER_H_

enum {
	P11_PARSE_FAILURE = -1,
	P11_PARSE_UNRECOGNIZED = 0,
	P11_PARSE_SUCCESS = 1,
};

enum {
	P11_PARSE_FLAG_NONE = 0,
	P11_PARSE_FLAG_ANCHOR = 1 << 0,
};

#define       P11_PARSER_FIRST_HANDLE    0xA0000000UL

#define P11_EKU_SERVER_AUTH "1.3.6.1.5.5.7.3.1"
#define P11_EKU_CLIENT_AUTH "1.3.6.1.5.5.7.3.2"
#define P11_EKU_CODE_SIGNING "1.3.6.1.5.5.7.3.3"
#define P11_EKU_EMAIL "1.3.6.1.5.5.7.3.4"
#define P11_EKU_IPSEC_END_SYSTEM "1.3.6.1.5.5.7.3.5"
#define P11_EKU_IPSEC_TUNNEL "1.3.6.1.5.5.7.3.6"
#define P11_EKU_IPSEC_USER "1.3.6.1.5.5.7.3.7"
#define P11_EKU_TIME_STAMPING "1.3.6.1.5.5.7.3.8"

enum {
	P11_KU_DIGITAL_SIGNATURE = 128,
	P11_KU_NON_REPUDIATION = 64,
	P11_KU_KEY_ENCIPHERMENT = 32,
	P11_KU_DATA_ENCIPHERMENT = 16,
	P11_KU_KEY_AGREEMENT = 8,
	P11_KU_KEY_CERT_SIGN = 4,
	P11_KU_CRL_SIGN = 2,
	P11_KU_ENCIPHER_ONLY = 1,
	P11_KU_DECIPHER_ONLY = 32768,
};

typedef struct _p11_parser p11_parser;

p11_parser *  p11_parser_new       (void);

void          p11_parser_free      (p11_parser *parser);

typedef void  (* p11_parser_sink)  (CK_ATTRIBUTE *attrs,
                                    void *user_data);

int           p11_parse_memory     (p11_parser *parser,
                                    const char *filename,
                                    int flags,
                                    const unsigned char *data,
                                    size_t length,
                                    p11_parser_sink sink,
                                    void *sink_data);

int           p11_parse_file       (p11_parser *parser,
                                    const char *filename,
                                    int flags,
                                    p11_parser_sink sink,
                                    void *sink_data);

int           p11_parse_key_usage            (p11_parser *parser,
                                              const unsigned char *data,
                                              size_t length,
                                              unsigned int *ku);

int           p11_parse_extended_key_usage   (p11_parser *parser,
                                              const unsigned char *data,
                                              size_t length,
                                              p11_dict *ekus);

#endif
