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

#ifndef P11_ENUMERATE_H_
#define P11_ENUMERATE_H_

#include "array.h"
#include "asn1.h"
#include "dict.h"

#include "p11-kit/iter.h"
#include "p11-kit/pkcs11.h"

enum {
	/* These overlap with the flags in save.h, so start higher */
	P11_ENUMERATE_ANCHORS = 1 << 21,
	P11_ENUMERATE_BLACKLIST = 1 << 22,
	P11_ENUMERATE_COLLAPSE = 1 << 23,
};

typedef struct {
	CK_FUNCTION_LIST **modules;
	p11_kit_iter *iter;
	p11_kit_uri *uri;

	p11_dict *asn1_defs;
	p11_dict *limit_to_purposes;
	p11_dict *already_seen;
	int num_filters;
	int flags;

	p11_dict *blacklist_issuer_serial;
	p11_dict *blacklist_public_key;

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
	p11_dict *attached;

	/* Set of OID purposes as strings */
	p11_array *purposes;
} p11_enumerate;

char *          p11_enumerate_filename      (p11_enumerate *ex);

char *          p11_enumerate_comment       (p11_enumerate *ex,
                                             bool first);

void            p11_enumerate_init          (p11_enumerate *ex);

bool            p11_enumerate_opt_filter    (p11_enumerate *ex,
                                             const char *option);

bool            p11_enumerate_opt_purpose   (p11_enumerate *ex,
                                             const char *option);

bool            p11_enumerate_ready         (p11_enumerate *ex,
                                             const char *def_filter);

void            p11_enumerate_cleanup       (p11_enumerate *ex);

#endif /* P11_ENUMERATE_H_ */
