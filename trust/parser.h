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

#include "array.h"
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

p11_dict *    p11_parse_extended_key_usage   (p11_parser *parser,
                                              const unsigned char *data,
                                              size_t length);

/* Functions used for retrieving parsing information */

int                     p11_parsing_get_flags        (p11_parser *parser);

CK_ATTRIBUTE *          p11_parsing_get_certificate  (p11_parser *parser,
                                                      p11_array *parsing);

unsigned char *         p11_parsing_get_extension    (p11_parser *parser,
                                                      p11_array *parsing,
                                                      const unsigned char *oid,
                                                      size_t *length);

#endif
