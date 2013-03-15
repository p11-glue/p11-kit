/*
 * Copyright (c) 2013, Red Hat Inc.
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

#include "config.h"

#ifndef P11_EXTRACT_H_
#define P11_EXTRACT_H_

#include "array.h"
#include "asn1.h"
#include "dict.h"
#include "iter.h"
#include "pkcs11.h"

enum {
	/* These overlap with the flags in save.h, so start higher */
	P11_EXTRACT_COMMENT = 1 << 10,
	P11_EXTRACT_ANCHORS = 1 << 11,
	P11_EXTRACT_BLACKLIST = 1 << 12,
	P11_EXTRACT_COLLAPSE = 1 << 13,
};

typedef struct {
	p11_dict *asn1_defs;
	p11_dict *limit_to_purposes;
	p11_dict *already_seen;
	char *destination;
	int flags;

	/*
	 * Stuff below is parsed info for the current iteration.
	 * Currently this information is generally all relevant
	 * just for certificates.
	 */

	CK_OBJECT_CLASS klass;
	CK_ATTRIBUTE *attrs;

	/* Pre-parsed data for certificates */
	node_asn *cert_asn;
	const unsigned char *cert_der;
	size_t cert_len;

	/* DER OID -> CK_ATTRIBUTE list */
	p11_dict *stapled;

	/* Set of OID purposes as strings */
	p11_array *purposes;
} p11_extract_info;

void            p11_extract_info_init          (p11_extract_info *ex);

CK_RV           p11_extract_info_load_filter   (P11KitIter *iter,
                                                CK_BBOOL *matches,
                                                void *data);

void            p11_extract_info_limit_purpose (p11_extract_info *ex,
                                                const char *purpose);

void            p11_extract_info_cleanup       (p11_extract_info *ex);

char *          p11_extract_info_filename      (p11_extract_info *ex);

char *          p11_extract_info_comment       (p11_extract_info *ex,
                                                bool first);

typedef bool (* p11_extract_func)              (P11KitIter *iter,
                                                p11_extract_info *ex);

bool            p11_extract_x509_file          (P11KitIter *iter,
                                                p11_extract_info *ex);

bool            p11_extract_x509_directory     (P11KitIter *iter,
                                                p11_extract_info *ex);

bool            p11_extract_pem_bundle         (P11KitIter *iter,
                                                p11_extract_info *ex);

bool            p11_extract_pem_directory      (P11KitIter *iter,
                                                p11_extract_info *ex);

bool            p11_extract_jks_cacerts        (P11KitIter *iter,
                                                p11_extract_info *ex);

bool            p11_extract_openssl_bundle     (P11KitIter *iter,
                                                p11_extract_info *ex);

bool            p11_extract_openssl_directory  (P11KitIter *iter,
                                                p11_extract_info *ex);

#endif /* P11_EXTRACT_H_ */
