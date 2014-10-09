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

#include "array.h"
#include "dict.h"

#ifndef P11_X509_H_
#define P11_X509_H_

unsigned char *  p11_x509_find_extension            (node_asn *cert,
                                                     const unsigned char *oid,
                                                     const unsigned char *der,
                                                     size_t der_len,
                                                     size_t *ext_len);

bool             p11_x509_hash_subject_public_key   (node_asn *cert,
                                                     const unsigned char *der,
                                                     size_t der_len,
                                                     unsigned char *keyid);

bool             p11_x509_parse_basic_constraints   (p11_dict *asn1_defs,
                                                     const unsigned char *ext_der,
                                                     size_t ext_len,
                                                     bool *is_ca);

bool             p11_x509_parse_key_usage           (p11_dict *asn1_defs,
                                                     const unsigned char *data,
                                                     size_t length,
                                                     unsigned int *ku);

p11_array *      p11_x509_parse_extended_key_usage  (p11_dict *asn1_defs,
                                                     const unsigned char *ext_der,
                                                     size_t ext_len);

unsigned char *  p11_x509_parse_subject_key_identifier  (p11_dict *asn1_defs,
                                                         const unsigned char *ext_der,
                                                         size_t ext_len,
                                                         size_t *keyid_len);

char *           p11_x509_parse_dn_name             (p11_dict *asn_defs,
                                                     const unsigned char *der,
                                                     size_t der_len,
                                                     const unsigned char *oid);

char *           p11_x509_lookup_dn_name            (node_asn *asn,
                                                     const char *dn_field,
                                                     const unsigned char *der,
                                                     size_t der_len,
                                                     const unsigned char *oid);

char *           p11_x509_parse_directory_string    (const unsigned char *input,
                                                     size_t input_len,
                                                     bool *unknown_string,
                                                     size_t *string_len);

#endif /* P11_X509_H_ */
