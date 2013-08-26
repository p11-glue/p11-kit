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

#include "asn1.h"
#include "array.h"
#include "compat.h"
#include "dict.h"

#ifndef P11_PARSER_H_
#define P11_PARSER_H_

enum {
	P11_PARSE_FLAG_NONE = 0,
	P11_PARSE_FLAG_ANCHOR = 1 << 0,
	P11_PARSE_FLAG_BLACKLIST = 1 << 1,
};

enum {
	P11_PARSE_FAILURE = -1,
	P11_PARSE_UNRECOGNIZED = 0,
	P11_PARSE_SUCCESS = 1,
};

typedef struct _p11_parser p11_parser;

p11_parser *  p11_parser_new       (p11_asn1_cache *asn1_cache);

void          p11_parser_free      (p11_parser *parser);

int           p11_parse_memory     (p11_parser *parser,
                                    const char *filename,
                                    int flags,
                                    const unsigned char *data,
                                    size_t length);

int           p11_parse_file       (p11_parser *parser,
                                    const char *filename,
                                    struct stat *sb,
                                    int flags);

p11_array *   p11_parser_parsed    (p11_parser *parser);

void          p11_parser_formats   (p11_parser *parser,
                                    ...) GNUC_NULL_TERMINATED;

int           p11_parser_format_persist      (p11_parser *parser,
                                              const unsigned char *data,
                                              size_t length);

int           p11_parser_format_pem          (p11_parser *parser,
                                              const unsigned char *data,
                                              size_t length);

int           p11_parser_format_x509         (p11_parser *parser,
                                              const unsigned char *data,
                                              size_t length);

#endif /* P11_PARSER_H_ */
