/*
 * Copyright (c) 2023, Red Hat Inc.
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
 * Author: Zoltan Fridrich <zfridric@redhat.com>
 */

#include "config.h"

#include "buffer.h"
#include "constants.h"
#include "debug.h"
#include "iter.h"
#include "message.h"
#include "pem.h"
#include "tool.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef ENABLE_NLS
#include <libintl.h>
#define _(x) dgettext(PACKAGE_NAME, x)
#else
#define _(x) (x)
#endif

int
p11_kit_export_object (int argc,
		       char *argv[]);

static void
export_x509_certificate (P11KitIter *iter)
{
	p11_buffer buf;
	CK_ATTRIBUTE attr = { CKA_VALUE, NULL_PTR, 0 };

	if (!p11_buffer_init_null (&buf, 0)) {
		p11_message (_("failed to initialize buffer"));
		return;
	}

	if (p11_kit_iter_get_attributes (iter, &attr, 1) != CKR_OK) {
		p11_message (_("failed to retrieve attribute length of an object"));
		goto cleanup;
	}

	attr.pValue = malloc (attr.ulValueLen);
	if (attr.pValue == NULL) {
		p11_message (_("failed to allocate memory"));
		goto cleanup;
	}

	if (p11_kit_iter_get_attributes (iter, &attr, 1) != CKR_OK) {
		p11_message (_("failed to retrieve attribute of an object"));
		goto cleanup;
	}

	if (!p11_pem_write (attr.pValue, attr.ulValueLen, "CERTIFICATE", &buf)) {
		p11_message (_("failed to write X.509 certificate"));
		goto cleanup;
	}

	if (fwrite (buf.data, 1, buf.len, stdout) != buf.len) {
		p11_message (_("failed to write the data to stdout"));
		goto cleanup;
	}

cleanup:
	p11_buffer_uninit (&buf);
	free (attr.pValue);
}

static void
export_certificate (P11KitIter *iter)
{
	const char *type_str;
	CK_CERTIFICATE_TYPE cert_type;
	CK_ATTRIBUTE attr = { CKA_CERTIFICATE_TYPE, &cert_type, sizeof (cert_type) };

	if (p11_kit_iter_get_attributes (iter, &attr, 1) != CKR_OK) {
		p11_message (_("failed to retrieve attribute of an object"));
		return;
	}

	switch (cert_type) {
	case CKC_X_509:
		export_x509_certificate (iter);
		break;
	case CKC_WTLS:
	case CKC_X_509_ATTR_CERT:
	default:
		type_str = p11_constant_nick (p11_constant_certs, cert_type);
		if (type_str == NULL)
			type_str = "(unknown)";
		p11_message (_("unsupported certificate type: %s"), type_str);
		break;
	}
}

static int
export_object (const char *token_str)
{
	int ret = 1;
	CK_RV rv;
	CK_FUNCTION_LIST **modules = NULL;
	P11KitUri *uri = NULL;
	P11KitIter *iter = NULL;
	CK_OBJECT_CLASS klass;
	CK_ATTRIBUTE attr = { CKA_CLASS, &klass, sizeof (klass) };

	uri = p11_kit_uri_new ();
	if (uri == NULL) {
		p11_message (_("failed to allocate memory for URI"));
		goto cleanup;
	}

	if (p11_kit_uri_parse (token_str, P11_KIT_URI_FOR_OBJECT_ON_TOKEN, uri) != P11_KIT_URI_OK) {
		p11_message (_("failed to parse the token URI"));
		goto cleanup;
	}

	modules = p11_kit_modules_load_and_initialize (0);
	if (modules == NULL) {
		p11_message (_("failed to load and initialize modules"));
		goto cleanup;
	}

	iter = p11_kit_iter_new (uri, P11_KIT_ITER_WITH_LOGIN);
	if (iter == NULL) {
		p11_message (_("failed to initialize iterator"));
		goto cleanup;
	}

	p11_kit_iter_begin (iter, modules);
	while (p11_kit_iter_next (iter) == CKR_OK) {
		rv = p11_kit_iter_get_attributes (iter, &attr, 1);
		if (rv != CKR_OK) {
			p11_message (_("failed to retrieve attribute of an object"));
			goto cleanup;
		}

		if (klass == CKO_CERTIFICATE) {
			export_certificate (iter);
			break;
		}
	}

	ret = 0;

cleanup:
	p11_kit_iter_free (iter);
	p11_kit_uri_free (uri);
	if (modules != NULL)
		p11_kit_modules_finalize_and_release (modules);

	return ret;
}

int
p11_kit_export_object (int argc,
		       char *argv[])
{
	int opt;

	enum {
		opt_verbose = 'v',
		opt_quiet = 'q',
		opt_help = 'h',
	};

	struct option options[] = {
		{ "verbose", no_argument, NULL, opt_verbose },
		{ "quiet", no_argument, NULL, opt_quiet },
		{ "help", no_argument, NULL, opt_help },
		{ 0 },
	};

	p11_tool_desc usages[] = {
		{ 0, "usage: p11-kit export-object pkcs11:token" },
		{ 0 },
	};

	while ((opt = p11_tool_getopt (argc, argv, options)) != -1) {
		switch (opt) {
		case opt_verbose:
			p11_kit_be_loud ();
			break;
		case opt_quiet:
			p11_kit_be_quiet ();
			break;
		case opt_help:
			p11_tool_usage (usages, options);
			return 0;
		case '?':
			return 2;
		default:
			assert_not_reached ();
			break;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 1) {
		p11_tool_usage (usages, options);
		return 2;
	}

	return export_object (*argv);
}
