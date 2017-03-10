/*
 * Copyright (C) 2014,2016 Red Hat Inc.
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

#include "compat.h"
#include "debug.h"
#include "iter.h"
#include "message.h"
#include "p11-kit.h"
#include "remote.h"
#include "tool.h"

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int
serve_module_from_uri (const char *uri_string)
{
	CK_FUNCTION_LIST **modules;
	CK_FUNCTION_LIST *module;
	P11KitIter *iter = NULL;
	P11KitUri *uri;
	CK_TOKEN_INFO *token;
	int ret = 1;
	CK_RV rv;

	modules = p11_kit_modules_load_and_initialize (0);
	if (modules == NULL)
		return 1;

	uri = p11_kit_uri_new ();
	if (uri == NULL)
		goto out;
	ret = p11_kit_uri_parse (uri_string, P11_KIT_URI_FOR_TOKEN, uri);
	if (ret != P11_KIT_URI_OK) {
		p11_kit_uri_free (uri);
		goto out;
	}

	iter = p11_kit_iter_new (uri, P11_KIT_ITER_WITH_TOKENS | P11_KIT_ITER_WITHOUT_OBJECTS);
	p11_kit_uri_free (uri);
	if (iter == NULL)
		goto out;

	p11_kit_iter_begin (iter, modules);
	rv = p11_kit_iter_next (iter);
	if (rv != CKR_OK)
		goto out;

	module = p11_kit_iter_get_module (iter);
	token = p11_kit_iter_get_token (iter);
	p11_kit_modules_finalize (modules);

	ret = p11_kit_remote_serve_token (module, token, 0, 1);

 out:
	p11_kit_iter_free (iter);
	p11_kit_modules_release (modules);

	return ret;
}

static int
serve_module_from_file (const char *file)
{
	CK_FUNCTION_LIST *module;
	int ret;

	module = p11_kit_module_load (file, 0);
	if (module == NULL)
		return 1;

	ret = p11_kit_remote_serve_module (module, 0, 1);
	p11_kit_module_release (module);

	return ret;
}

int
main (int argc,
      char *argv[])
{
	int opt;
	int ret;

	enum {
		opt_verbose = 'v',
		opt_help = 'h',
	};

	struct option options[] = {
		{ "verbose", no_argument, NULL, opt_verbose },
		{ "help", no_argument, NULL, opt_help },
		{ 0 },
	};

	p11_tool_desc usages[] = {
		{ 0, "usage: p11-kit remote <module-or-token>" },
		{ 0 },
	};

	while ((opt = p11_tool_getopt (argc, argv, options)) != -1) {
		switch (opt) {
		case opt_verbose:
			p11_kit_be_loud ();
			break;
		case opt_help:
		case '?':
			p11_tool_usage (usages, options);
			return 0;
		default:
			assert_not_reached ();
			break;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 1) {
		p11_message ("specify the module or token URI to remote");
		return 2;
	}

	if (isatty (0)) {
		p11_message ("the 'remote' tool is not meant to be run from a terminal");
		return 2;
	}

	if (strncmp (argv[0], "pkcs11:", 7) == 0)
		ret = serve_module_from_uri (argv[0]);
	else
		ret = serve_module_from_file (argv[0]);

	return ret;
}
