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
#include "options.h"
#include "tool.h"

#include <assert.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#ifdef ENABLE_NLS
#include <libintl.h>
#define _(x) dgettext(PACKAGE_NAME, x)
#else
#define _(x) (x)
#endif

#define MAX_OBJECTS 4

int
p11_kit_delete_profile (int argc,
			char *argv[]);

static int
delete_profile (p11_tool *tool,
		CK_PROFILE_ID profile)
{
	int ret = 1;
	CK_RV rv;
	CK_OBJECT_HANDLE objects[MAX_OBJECTS];
	CK_ULONG i, count = 0;
	CK_SESSION_HANDLE session = 0;
	CK_FUNCTION_LIST *module = NULL;
	P11KitIter *iter = NULL;
	CK_OBJECT_CLASS klass = CKO_PROFILE;
	CK_ATTRIBUTE template[] = {
		{ CKA_CLASS, &klass, sizeof (klass) },
		{ CKA_PROFILE_ID, &profile, sizeof (profile) }
	};
	CK_ULONG template_len = sizeof (template) / sizeof (template[0]);

	iter = p11_tool_begin_iter (tool, P11_KIT_ITER_WANT_WRITABLE | P11_KIT_ITER_WITH_SESSIONS | P11_KIT_ITER_WITHOUT_OBJECTS);
	if (iter == NULL) {
		p11_message (_("failed to initialize iterator"));
		return 1;
	}

	rv = p11_kit_iter_next (iter);
	if (rv != CKR_OK) {
		if (rv == CKR_CANCEL)
			p11_message (_("no matching token"));
		else
			p11_message (_("failed to find token: %s"), p11_kit_strerror (rv));
		goto cleanup;
	}

	/* Module and session should always be set at this point.  */
	module = p11_kit_iter_get_module (iter);
	return_val_if_fail (module != NULL, 1);
	session = p11_kit_iter_get_session (iter);
	return_val_if_fail (session != CK_INVALID_HANDLE, 1);

	rv = module->C_FindObjectsInit (session, template, template_len);
	if (rv != CKR_OK) {
		p11_message (_("failed to initialize search for objects: %s"), p11_kit_strerror (rv));
		goto cleanup;
	}

	do {
		rv = module->C_FindObjects (session, objects, MAX_OBJECTS, &count);
		if (rv != CKR_OK) {
			module->C_FindObjectsFinal (session);
			p11_message (_("failed to search for objects: %s"), p11_kit_strerror (rv));
			goto cleanup;
		}

		for (i = 0; i < count; ++i) {
			rv = module->C_DestroyObject (session, objects[i]);
			if (rv != CKR_OK) {
				module->C_FindObjectsFinal (session);
				p11_message (_("failed to destroy an object: %s"), p11_kit_strerror (rv));
				goto cleanup;
			}
		}
	} while (count > 0);

	rv = module->C_FindObjectsFinal (session);
	if (rv != CKR_OK) {
		p11_message (_("failed to finalize search for objects: %s"), p11_kit_strerror (rv));
		goto cleanup;
	}

	ret = 0;

cleanup:
	p11_tool_end_iter (tool, iter);

	return ret;
}

int
p11_kit_delete_profile (int argc,
			char *argv[])
{
	int opt, ret = 2;
	CK_ULONG profile = CKA_INVALID;
	p11_dict *profile_nicks = NULL;
	bool login = false;
	p11_tool *tool = NULL;
	const char *provider = NULL;

	enum {
		opt_verbose = 'v',
		opt_quiet = 'q',
		opt_help = 'h',
		opt_profile = 'p',
		opt_login = 'l',
		opt_provider = CHAR_MAX + 2,
	};

	struct option options[] = {
		{ "verbose", no_argument, NULL, opt_verbose },
		{ "quiet", no_argument, NULL, opt_quiet },
		{ "help", no_argument, NULL, opt_help },
		{ "profile", required_argument, NULL, opt_profile },
		{ "login", no_argument, NULL, opt_login },
		{ "provider", required_argument, NULL, opt_provider },
		{ 0 },
	};

	p11_tool_desc usages[] = {
		{ 0, "usage: p11-kit delete-profile --profile profile pkcs11:token" },
		{ opt_profile, "specify the profile to delete" },
		{ opt_login, "login to the token" },
		{ opt_provider, "specify the module to use" },
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
		case opt_login:
			login = true;
			break;
		case opt_provider:
			provider = optarg;
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

	tool = p11_tool_new ();
	if (!tool) {
		p11_message (_("failed to allocate memory"));
		goto cleanup;
	}

	if (p11_tool_set_uri (tool, *argv, P11_KIT_URI_FOR_TOKEN) != P11_KIT_URI_OK) {
		p11_message (_("failed to parse URI"));
		goto cleanup;
	}

	if (!p11_tool_set_provider (tool, provider)) {
		p11_message (_("failed to allocate memory"));
		goto cleanup;
	}

	p11_tool_set_login (tool, login);

	ret = delete_profile (tool, profile);

cleanup:
	p11_tool_free (tool);
	p11_dict_free (profile_nicks);

	return ret;
}
