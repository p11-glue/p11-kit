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

#include "anchor.h"
#include "attrs.h"
#include "debug.h"
#include "message.h"
#include "parser.h"
#include "p11-kit.h"
#include "tool.h"

#include <assert.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>

static CK_SESSION_HANDLE
session_for_store_on_module (const char *name,
                             CK_FUNCTION_LIST *module,
                             bool *found_read_only)
{
	CK_SESSION_HANDLE session = 0;
	CK_SLOT_ID *slots = NULL;
	CK_TOKEN_INFO info;
	CK_ULONG count;
	CK_ULONG i;
	CK_RV rv;

	rv = p11_kit_module_initialize (module);
	if (rv != CKR_OK) {
		p11_message ("%s: couldn't initialize: %s", name, p11_kit_message ());
		return 0UL;
	}

	rv = (module->C_GetSlotList) (CK_TRUE, NULL, &count);
	if (rv == CKR_OK) {
		slots = calloc (count, sizeof (CK_ULONG));
		return_val_if_fail (slots != NULL, 0UL);
		rv = (module->C_GetSlotList) (CK_TRUE, slots, &count);
	}
	if (rv != CKR_OK) {
		p11_message ("%s: couldn't enumerate slots: %s", name, p11_kit_strerror (rv));
		free (slots);
		return 0UL;
	}

	for (i = 0; session == 0 && i < count; i++) {
		rv = (module->C_GetTokenInfo) (slots[i], &info);
		if (rv != CKR_OK) {
			p11_message ("%s: couldn't get token info: %s", name, p11_kit_strerror (rv));
			continue;
		}

		if (info.flags & CKF_WRITE_PROTECTED) {
			*found_read_only = true;
			continue;
		}

		rv = (module->C_OpenSession) (slots[i], CKF_SERIAL_SESSION | CKF_RW_SESSION,
		                              NULL, NULL, &session);
		if (rv != CKR_OK) {
			p11_message ("%s: couldn't open session: %s", name, p11_kit_strerror (rv));
			session = 0;
		}
	}

	free (slots);

	if (session == 0UL)
		p11_kit_module_finalize (module);

	return session;
}

static CK_SESSION_HANDLE
session_for_store (CK_FUNCTION_LIST **module)
{
	CK_SESSION_HANDLE session = 0UL;
	CK_FUNCTION_LIST **modules;
	bool found_read_only = false;
	char *name;
	int i;

	modules = p11_kit_modules_load (NULL, P11_KIT_MODULE_TRUSTED);
	if (modules == NULL)
		return 0;

	for (i = 0; modules[i] != NULL; i++) {
		if (session == 0UL) {
			name = p11_kit_module_get_name (modules[i]);
			session = session_for_store_on_module (name, modules[i],
			                                       &found_read_only);

			if (session != 0UL) {
				*module = modules[i];
				modules[i] = NULL;
			}

			free (name);
		}

		if (modules[i])
			p11_kit_module_release (modules[i]);
	}

	if (session == 0UL) {
		if (found_read_only)
			p11_message ("no configured writable location to store anchors");
		else
			p11_message ("no configured location to store anchors");
	}

	free (modules);
	return session;
}

static int
anchor_store (char **files,
              int nfiles)
{
	CK_BBOOL truev = CK_TRUE;

	CK_ATTRIBUTE basics[] = {
		{ CKA_TOKEN, &truev, sizeof (truev) },
		{ CKA_INVALID, },
	};

	CK_ATTRIBUTE *attrs;
	CK_FUNCTION_LIST *module = NULL;
	CK_SESSION_HANDLE session;
	CK_OBJECT_HANDLE object;
	p11_parser *parser;
	p11_array *parsed;
	CK_RV rv = CKR_OK;
	int ret;
	int i, j;

	if (nfiles == 0) {
		p11_message ("specify at least one anchor input file");
		return 2;
	}

	session = session_for_store (&module);
	if (session == 0UL)
		return 1;

	parser = p11_parser_new (NULL);
	p11_parser_formats (parser,
	                    p11_parser_format_x509,
	                    p11_parser_format_pem,
	                    NULL);

	for (i = 0; i < nfiles; i++) {
		ret = p11_parse_file (parser, files[i], NULL, P11_PARSE_FLAG_ANCHOR);
		switch (ret) {
		case P11_PARSE_SUCCESS:
			break;
		case P11_PARSE_UNRECOGNIZED:
			p11_message ("unrecognized file format: %s", files[i]);
			break;
		default:
			p11_message ("failed to parse file: %s", files[i]);
			break;
		}

		if (ret != P11_PARSE_SUCCESS)
			break;

		parsed = p11_parser_parsed (parser);
		rv = CKR_OK;

		for (j = 0; j < parsed->num; j++) {
			attrs = p11_attrs_merge (parsed->elem[j], p11_attrs_dup (basics), true);
			parsed->elem[j] = NULL;

			rv = (module->C_CreateObject) (session, attrs,
			                               p11_attrs_count (attrs), &object);

			p11_attrs_free (attrs);

			if (rv != CKR_OK) {
				p11_message ("couldn't create object: %s", p11_kit_strerror (rv));
				break;
			}
		}

		if (rv != CKR_OK)
			break;
	}

	p11_kit_module_finalize (module);
	p11_kit_module_release (module);

	p11_parser_free (parser);
	return (ret == P11_PARSE_SUCCESS && rv == CKR_OK) ? 0 : 1;
}

int
p11_trust_anchor (int argc,
                  char **argv)
{
	int action = 0;
	int opt;

	enum {
		opt_verbose = 'v',
		opt_quiet = 'q',
		opt_help = 'h',

		opt_store = 's',
	};

	struct option options[] = {
		{ "store", no_argument, NULL, opt_store },
		{ "verbose", no_argument, NULL, opt_verbose },
		{ "quiet", no_argument, NULL, opt_quiet },
		{ "help", no_argument, NULL, opt_help },
		{ 0 },
	};

	p11_tool_desc usages[] = {
		{ 0, "usage: trust anchor --store <file> ..." },
		{ opt_verbose, "show verbose debug output", },
		{ opt_quiet, "supress command output", },
		{ 0 },
	};

	while ((opt = p11_tool_getopt (argc, argv, options)) != -1) {
		switch (opt) {
		case opt_store:
			if (action == 0) {
				action = opt;
			} else {
				p11_message ("an action was already specified");
				return 2;
			}
			break;
		case opt_verbose:
		case opt_quiet:
			break;
		case opt_help:
			p11_tool_usage (usages, options);
			return 0;
		case '?':
			p11_tool_usage (usages, options);
			return 2;
		default:
			assert_not_reached ();
			break;
		}
	} while (opt != -1);

	argc -= optind;
	argv += optind;

	/* TODO: This should only be the default if a file is specified */
	if (action == 0)
		action = opt_store;

	switch (action) {
	case opt_store:
		return anchor_store (argv, argc);
	default:
		assert_not_reached();
		return -1;
	}
}
