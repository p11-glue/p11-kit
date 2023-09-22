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
 * Author: Alexander Sosedkin <asosedkin@redhat.com>
 */

#include "config.h"

#include "constants.h"
#define P11_DEBUG_FLAG P11_DEBUG_TOOL
#include "debug.h"
#include "iter.h"
#include "message.h"
#include "pkcs11.h"
#include "print.h"
#include "tool.h"
#include "uri.h"

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
p11_kit_list_mechanisms (int argc,
		         char *argv[]);

static void
print_mechanism_with_info (CK_MECHANISM_TYPE mechanism,
		           CK_MECHANISM_INFO info)
{
	const char *mechanism_nick = NULL;

	mechanism_nick = p11_constant_nick (p11_constant_mechanisms, mechanism);
	if (mechanism_nick == NULL)
		printf ("0x%lX (unknown):", mechanism);
	else
		printf ("%s:", mechanism_nick);

	if (info.flags & CKF_HW)
		printf (" hw");
	if (info.flags & CKF_MESSAGE_ENCRYPT)
		printf (" message-encrypt");
	if (info.flags & CKF_MESSAGE_DECRYPT)
		printf (" message-decrypt");
	if (info.flags & CKF_MESSAGE_SIGN)
		printf (" message-sign");
	if (info.flags & CKF_MESSAGE_VERIFY)
		printf (" message-verify");
	if (info.flags & CKF_MULTI_MESSAGE)
		printf (" multi-message");
	if (info.flags & CKF_FIND_OBJECTS)
		printf (" find-objects");
	if (info.flags & CKF_ENCRYPT)
		printf (" encrypt");
	if (info.flags & CKF_DECRYPT)
		printf (" decrypt");
	if (info.flags & CKF_DIGEST)
		printf (" digest");
	if (info.flags & CKF_SIGN)
		printf (" sign");
	if (info.flags & CKF_SIGN_RECOVER)
		printf (" sign-recover");
	if (info.flags & CKF_VERIFY)
		printf (" verify");
	if (info.flags & CKF_SIGN_RECOVER)
		printf (" verify-recover");
	if (info.flags & CKF_GENERATE)
		printf (" generate");
	if (info.flags & CKF_GENERATE_KEY_PAIR)
		printf (" generate-key-pair");
	if (info.flags & CKF_WRAP)
		printf (" wrap");
	if (info.flags & CKF_UNWRAP)
		printf (" unwrap");
	if (info.flags & CKF_DERIVE)
		printf (" derive");
	if (info.flags & CKF_EXTENSION)
		printf (" extension");

	if (info.ulMaxKeySize)
		printf (" key-size=%lu-%lu", info.ulMinKeySize, info.ulMaxKeySize);
	printf ("\n");
}

static int
list_mechanisms (const char *token_str)
{
	int ret = 1;
	CK_FUNCTION_LIST **modules = NULL;
	CK_FUNCTION_LIST *module = NULL;
	P11KitUri *uri = NULL;
	P11KitIter *iter = NULL;
	CK_SESSION_HANDLE session = 0;
	CK_SLOT_ID slot = 0;
	CK_TOKEN_INFO token_info;
	CK_MECHANISM_INFO mechanism_info;
	CK_MECHANISM_TYPE_PTR mechanisms = NULL;
	CK_MECHANISM_TYPE_PTR mechanisms_new = NULL;
	unsigned long mechanisms_count = 0;
	unsigned long i;
	p11_list_printer printer;
	CK_RV rv;

	uri = p11_kit_uri_new ();
	if (uri == NULL) {
		p11_message (_("failed to allocate memory"));
		goto cleanup;
	}

	if (p11_kit_uri_parse (token_str, P11_KIT_URI_FOR_TOKEN, uri) != P11_KIT_URI_OK) {
		p11_message (_("failed to parse URI"));
		goto cleanup;
	}

	modules = p11_kit_modules_load_and_initialize (0);
	if (modules == NULL) {
		p11_message (_("failed to load and initialize modules"));
		goto cleanup;
	}

	iter = p11_kit_iter_new (uri, P11_KIT_ITER_WITH_LOGIN | P11_KIT_ITER_WITH_TOKENS | P11_KIT_ITER_WITHOUT_OBJECTS);
	if (iter == NULL) {
		p11_debug ("failed to initialize iterator");
		goto cleanup;
	}

	p11_list_printer_init (&printer, stdout, 0);
	p11_kit_iter_begin (iter, modules);
	rv = p11_kit_iter_next (iter);
	if (rv != CKR_OK) {
		if (rv == CKR_CANCEL)
			p11_message (_("no matching token"));
		else
			p11_message (_("failed to find token: %s"), p11_kit_strerror (rv));
		goto cleanup;
	}

	module = p11_kit_iter_get_module (iter);
	if (module == NULL) {
		p11_message (_("failed to obtain module"));
		goto cleanup;
	}

	slot = p11_kit_iter_get_slot (iter);

	rv = module->C_GetTokenInfo (slot, &token_info);
	if (rv != CKR_OK) {
		p11_message (_("couldn't load token info: %s"), p11_kit_strerror (rv));
		goto cleanup;
	}

	rv = module->C_GetMechanismList (slot, NULL, &mechanisms_count);
	if (rv != CKR_OK) {
		p11_message (_("querying amount of mechanisms failed: %s"), p11_kit_strerror (rv));
		goto cleanup;
	}

	mechanisms_new = reallocarray (mechanisms, mechanisms_count, sizeof (CK_MECHANISM_TYPE));
	if (mechanisms_new == NULL) {
		p11_message (_("failed to allocate memory"));
		goto cleanup;
	}
	mechanisms = mechanisms_new;

	rv = module->C_GetMechanismList (slot, mechanisms, &mechanisms_count);
	if (rv != CKR_OK) {
		p11_message (_("querying mechanisms failed: %s"), p11_kit_strerror (rv));
		goto cleanup;
	}

	for (i = 0; i < mechanisms_count; i++) {
		rv = module->C_GetMechanismInfo (slot, mechanisms[i], &mechanism_info);
		if (rv != CKR_OK) {
			p11_message (_("querying mechanism info failed: %s"), p11_kit_strerror (rv));
			goto cleanup;
		}

		print_mechanism_with_info (mechanisms[i], mechanism_info);
	}
	ret = 0;

cleanup:
	if (session)
		module->C_CloseSession (session);
	if (mechanisms)
		free (mechanisms);
	p11_kit_iter_free (iter);
	p11_kit_uri_free (uri);
	if (modules != NULL)
		p11_kit_modules_finalize_and_release (modules);

	return ret;
}

int
p11_kit_list_mechanisms (int argc,
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
		{ 0, "usage: p11-kit list-mechanisms pkcs11:token" },
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

	return list_mechanisms (*argv);
}
