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

#include <libtasn1.h>

#include "dict.h"

#ifndef P11_ASN1_H_
#define P11_ASN1_H_

typedef struct _p11_asn1_cache p11_asn1_cache;

p11_dict *       p11_asn1_defs_load                 (void);

node_asn *       p11_asn1_decode                    (p11_dict *asn1_defs,
                                                     const char *struct_name,
                                                     const unsigned char *der,
                                                     size_t der_len,
                                                     char *message);

node_asn *       p11_asn1_create                    (p11_dict *asn1_defs,
                                                     const char *struct_name);

unsigned char *  p11_asn1_encode                    (node_asn *asn,
                                                     size_t *der_len);

void *           p11_asn1_read                      (node_asn *asn,
                                                     const char *field,
                                                     size_t *length);

void             p11_asn1_free                      (void *asn);

ssize_t          p11_asn1_tlv_length                (const unsigned char *data,
                                                     size_t length);

p11_asn1_cache * p11_asn1_cache_new                 (void);

p11_dict *       p11_asn1_cache_defs                (p11_asn1_cache *cache);

node_asn *       p11_asn1_cache_get                 (p11_asn1_cache *cache,
                                                     const char *struct_name,
                                                     const unsigned char *der,
                                                     size_t der_len);

void             p11_asn1_cache_take                (p11_asn1_cache *cache,
                                                     node_asn *node,
                                                     const char *struct_name,
                                                     const unsigned char *der,
                                                     size_t der_len);

void             p11_asn1_cache_flush               (p11_asn1_cache *cache);

void             p11_asn1_cache_free                (p11_asn1_cache *cache);

#endif /* P11_ASN1_H_ */
