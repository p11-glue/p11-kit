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

#include "enumerate.h"
#include "pkcs11.h"
#include "save.h"

enum {
	/* These overlap with the flags in save.h, so start higher */
	P11_EXTRACT_COMMENT = 1 << 10,
};

typedef bool (* p11_extract_func)              (p11_enumerate *ex,
                                                const char *destination);

bool            p11_extract_x509_file          (p11_enumerate *ex,
                                                const char *destination);

bool            p11_extract_x509_directory     (p11_enumerate *ex,
                                                const char *destination);

bool            p11_extract_pem_bundle         (p11_enumerate *ex,
                                                const char *destination);

bool            p11_extract_pem_directory      (p11_enumerate *ex,
                                                const char *destination);

bool            p11_extract_pem_directory_hash (p11_enumerate *ex,
                                                const char *destination);

bool            p11_extract_jks_cacerts        (p11_enumerate *ex,
                                                const char *destination);

bool            p11_extract_openssl_bundle     (p11_enumerate *ex,
                                                const char *destination);

bool            p11_extract_openssl_directory  (p11_enumerate *ex,
                                                const char *destination);

int             p11_trust_extract              (int argc,
                                                char **argv);

int             p11_trust_extract_compat       (int argc,
                                                char *argv[]);

/* from extract-openssl.c but also used in extract-pem.c */
bool            p11_openssl_symlink            (p11_enumerate *ex,
                                                p11_save_dir *dir,
                                                const char *filename);
#endif /* P11_EXTRACT_H_ */
