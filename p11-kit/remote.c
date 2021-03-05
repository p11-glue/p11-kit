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

#ifdef ENABLE_NLS
#include <libintl.h>
#define _(x) dgettext(PACKAGE_NAME, x)
#else
#define _(x) (x)
#endif

int
main (int argc,
      char *argv[])
{
	int opt;
	char *provider = NULL;

	enum {
		opt_verbose = 'v',
		opt_help = 'h',
		opt_provider = 'p'
	};

	struct option options[] = {
		{ "verbose", no_argument, NULL, opt_verbose },
		{ "help", no_argument, NULL, opt_help },
		{ "provider", required_argument, NULL, opt_provider },
		{ 0 },
	};

	p11_tool_desc usages[] = {
		{ 0, "usage: p11-kit remote <module>\n"
		     "       p11-kit remote [-p <provider>] <token> ..." },
		{ opt_provider, "specify the module to use" },
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
		case opt_provider:
			provider = optarg;
			break;
		default:
			assert_not_reached ();
			break;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc < 1) {
		p11_message (_("specify a module or tokens to remote"));
		return 2;
	}

	if (isatty (0)) {
		p11_message (_("the 'remote' tool is not meant to be run from a terminal"));
		return 2;
	}

	if (strncmp (argv[0], "pkcs11:", 7) == 0) {
		CK_FUNCTION_LIST *module = NULL;
		int ret;

		if (provider) {
			module = p11_kit_module_load (provider, 0);
			if (module == NULL)
				return 1;
		}

		ret = p11_kit_remote_serve_tokens ((const char **)argv, argc,
						   module,
						   STDIN_FILENO, STDOUT_FILENO);
		if (module)
			p11_kit_module_release (module);

		return ret;
	} else {
		CK_FUNCTION_LIST *module;
		int ret;

		if (argc != 1) {
			p11_message (_("only one module can be specified"));
			return 2;
		}

		module = p11_kit_module_load (argv[0], 0);
		if (module == NULL)
			return 1;

		ret = p11_kit_remote_serve_module (module,
						   STDIN_FILENO, STDOUT_FILENO);
		p11_kit_module_release (module);

		return ret;
	}
}
