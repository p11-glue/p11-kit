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

#include "attrs.h"
#include "constants.h"
#include "debug.h"
#include "iter.h"
#include "message.h"
#include "tool.h"

#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>

#ifdef ENABLE_NLS
#include <libintl.h>
#define _(x) dgettext(PACKAGE_NAME, x)
#else
#define _(x) (x)
#endif

int
p11_kit_add_profile (int argc,
		     char *argv[]);

static bool
profile_exists (CK_FUNCTION_LIST *module,
		CK_PROFILE_ID profile)
{
	CK_RV rv;
	P11KitIter *iter = NULL;
	CK_OBJECT_CLASS klass = CKO_PROFILE;
	CK_PROFILE_ID profile_id = CKP_INVALID_ID;
	CK_ATTRIBUTE matching = { CKA_CLASS, &klass, sizeof (klass) };
	CK_ATTRIBUTE attr = { CKA_PROFILE_ID, &profile_id, sizeof (profile_id) };
	CK_FUNCTION_LIST *modules[] = { module, NULL };

	iter = p11_kit_iter_new (NULL, 0);
	if (iter == NULL) {
		p11_message (_("failed to initialize iterator"));
		return false;
	}

	p11_kit_iter_add_filter (iter, &matching, 1);
	p11_kit_iter_begin (iter, modules);
	while ((rv = p11_kit_iter_next (iter)) == CKR_OK) {
		rv = p11_kit_iter_get_attributes (iter, &attr, 1);
		if (rv != CKR_OK) {
			p11_message (_("failed to retrieve attribute of an object"));
			p11_kit_iter_free (iter);
			return false;
		}

		if (profile_id == profile) {
			p11_kit_iter_free (iter);
			return true;
		}
	}
	p11_kit_iter_free (iter);

	return false;
}

static int
add_profile (const char *token_str,
	     CK_PROFILE_ID profile)
{
	int ret = 1;
	CK_RV rv;
	CK_OBJECT_HANDLE object = 0;
	CK_SESSION_HANDLE session = 0;
	CK_FUNCTION_LIST *prev_module = NULL;
	CK_FUNCTION_LIST *module = NULL;
	CK_FUNCTION_LIST **modules = NULL;
	P11KitUri *uri = NULL;
	P11KitIter *iter = NULL;
	CK_OBJECT_CLASS klass = CKO_PROFILE;
	CK_ATTRIBUTE template[] = {
	    { CKA_CLASS, &klass, sizeof (klass) },
	    { CKA_PROFILE_ID, &profile, sizeof (profile) }
	};
	CK_ULONG template_len = sizeof (template) / sizeof (template[0]);

	uri = p11_kit_uri_new ();
	if (uri == NULL) {
		p11_message (_("failed to allocate memory for URI"));
		goto cleanup;
	}

	if (p11_kit_uri_parse (token_str, P11_KIT_URI_FOR_TOKEN, uri) != P11_KIT_URI_OK) {
		p11_message (_("failed to parse the token URI"));
		goto cleanup;
	}

	modules = p11_kit_modules_load_and_initialize (0);
	if (modules == NULL) {
		p11_message (_("failed to load and initialize modules"));
		goto cleanup;
	}

	iter = p11_kit_iter_new (uri, P11_KIT_ITER_WANT_WRITABLE);
	if (iter == NULL) {
		p11_message (_("failed to initialize iterator"));
		goto cleanup;
	}

	p11_kit_iter_begin (iter, modules);
	while ((rv = p11_kit_iter_next (iter)) == CKR_OK) {
		module = p11_kit_iter_get_module (iter);
		if (module == prev_module || profile_exists (module, profile)) {
			prev_module = module;
			continue;
		}

		session = p11_kit_iter_get_session (iter);
		rv = module->C_CreateObject (session, template, template_len, &object);
		if (rv != CKR_OK) {
			p11_message (_("failed to create the profile object: %s"), p11_kit_strerror (rv));
			goto cleanup;
		}

		prev_module = module;
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
p11_kit_add_profile (int argc,
		     char *argv[])
{
	int opt, ret = 2;
	CK_ULONG profile = CKA_INVALID;
	p11_dict *profile_nicks = NULL;

	enum {
		opt_verbose = 'v',
		opt_quiet = 'q',
		opt_help = 'h',
		opt_profile = 'p',
	};

	struct option options[] = {
		{ "verbose", no_argument, NULL, opt_verbose },
		{ "quiet", no_argument, NULL, opt_quiet },
		{ "help", no_argument, NULL, opt_help },
		{ "profile", required_argument, NULL, opt_profile },
		{ 0 },
	};

	p11_tool_desc usages[] = {
		{ 0, "usage: p11-kit add-profile --profile profile pkcs11:token" },
		{ opt_profile, "specify the profile to add" },
		{ 0 },
	};

	profile_nicks = p11_constant_reverse (true);
	if (profile_nicks == NULL) {
		p11_message (_("failed to allocate memory"));
		goto cleanup;
	}

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
			ret = 0;
			goto cleanup;
		case opt_profile:
			if (profile != CKA_INVALID) {
				p11_message (_("multiple profiles specified"));
				goto cleanup;
			}

			profile = p11_constant_resolve (profile_nicks, optarg);
			if (profile == CKA_INVALID)
				profile = strtol (optarg, NULL, 0);
			if (profile == 0) {
				p11_message (_("failed to convert profile argument: %s"), optarg);
				goto cleanup;
			}
			break;
		case '?':
			goto cleanup;
		default:
			assert_not_reached ();
			break;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 1) {
		p11_tool_usage (usages, options);
		goto cleanup;
	}

	if (profile == CKA_INVALID) {
		p11_message (_("no profile specified"));
		goto cleanup;
	}

	ret = add_profile (*argv, profile);

cleanup:
	p11_dict_free (profile_nicks);

	return ret;
}
