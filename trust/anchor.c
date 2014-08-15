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

#define P11_DEBUG_FLAG P11_DEBUG_TOOL

#include "anchor.h"
#include "attrs.h"
#include "debug.h"
#include "constants.h"
#include "extract.h"
#include "message.h"
#include "parser.h"
#include "tool.h"

#include "p11-kit/iter.h"
#include "p11-kit/p11-kit.h"

#include <assert.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static p11_parser *
create_arg_file_parser (void)
{
	p11_parser *parser;

	parser = p11_parser_new (NULL);
	return_val_if_fail (parser != NULL, NULL);

	p11_parser_formats (parser,
	                    p11_parser_format_x509,
	                    p11_parser_format_pem,
	                    NULL);

	return parser;
}

static bool
iter_match_anchor (p11_kit_iter *iter,
                   CK_ATTRIBUTE *attrs)
{
	CK_ATTRIBUTE *attr;

	attr = p11_attrs_find_valid (attrs, CKA_CLASS);
	if (attr == NULL)
		return false;

	p11_kit_iter_add_filter (iter, attr, 1);

	attr = p11_attrs_find_valid (attrs, CKA_VALUE);
	if (attr == NULL)
		return false;

	p11_kit_iter_add_filter (iter, attr, 1);
	return true;
}

static p11_array *
uris_or_files_to_iters (int argc,
                        char *argv[],
                        int behavior)
{
	int flags = P11_KIT_URI_FOR_OBJECT_ON_TOKEN_AND_MODULE;
	p11_parser *parser = NULL;
	p11_array *iters;
	p11_array *parsed;
	p11_kit_uri *uri;
	p11_kit_iter *iter;
	int ret;
	int i, j;

	iters = p11_array_new ((p11_destroyer)p11_kit_iter_free);
	return_val_if_fail (iters != NULL, NULL);

	for (i = 0; i < argc; i++) {

		/* A PKCS#11 URI */
		if (strncmp (argv[i], "pkcs11:", 7) == 0) {
			uri = p11_kit_uri_new ();
			if (p11_kit_uri_parse (argv[i], flags, uri) != P11_KIT_URI_OK) {
				p11_message ("invalid PKCS#11 uri: %s", argv[i]);
				p11_kit_uri_free (uri);
				break;
			}

			iter = p11_kit_iter_new (uri, behavior);
			return_val_if_fail (iter != NULL, NULL);
			p11_kit_uri_free (uri);

			if (!p11_array_push (iters, iter))
				return_val_if_reached (NULL);

		} else {
			if (parser == NULL)
				parser = create_arg_file_parser ();

			ret = p11_parse_file (parser, argv[i], NULL, P11_PARSE_FLAG_ANCHOR);
			switch (ret) {
			case P11_PARSE_SUCCESS:
				p11_debug ("parsed file: %s", argv[i]);
				break;
			case P11_PARSE_UNRECOGNIZED:
				p11_message ("unrecognized file format: %s", argv[i]);
				break;
			default:
				p11_message ("failed to parse file: %s", argv[i]);
				break;
			}

			if (ret != P11_PARSE_SUCCESS)
				break;

			parsed = p11_parser_parsed (parser);
			for (j = 0; j < parsed->num; j++) {
				iter = p11_kit_iter_new (NULL, behavior);
				return_val_if_fail (iter != NULL, NULL);

				iter_match_anchor (iter, parsed->elem[j]);
				if (!p11_array_push (iters, iter))
					return_val_if_reached (NULL);
			}
		}
	}

	if (parser)
		p11_parser_free (parser);

	if (argc != i) {
		p11_array_free (iters);
		return NULL;
	}

	return iters;
}

static p11_array *
files_to_attrs (int argc,
                char *argv[])
{
	p11_parser *parser;
	p11_array *parsed;
	p11_array *array;
	int ret = P11_PARSE_SUCCESS;
	int i, j;

	array = p11_array_new (p11_attrs_free);
	return_val_if_fail (array != NULL, NULL);

	parser = create_arg_file_parser ();
	return_val_if_fail (parser != NULL, NULL);

	for (i = 0; i < argc; i++) {
		ret = p11_parse_file (parser, argv[i], NULL, P11_PARSE_FLAG_ANCHOR);
		switch (ret) {
		case P11_PARSE_SUCCESS:
			p11_debug ("parsed file: %s", argv[i]);
			break;
		case P11_PARSE_UNRECOGNIZED:
			p11_message ("unrecognized file format: %s", argv[i]);
			break;
		default:
			p11_message ("failed to parse file: %s", argv[i]);
			break;
		}

		if (ret != P11_PARSE_SUCCESS)
			break;

		parsed = p11_parser_parsed (parser);
		for (j = 0; j < parsed->num; j++) {
			if (!p11_array_push (array, parsed->elem[j]))
				return_val_if_reached (NULL);
			parsed->elem[j] = NULL;
		}
	}

	p11_parser_free (parser);

	if (ret == P11_PARSE_SUCCESS)
		return array;

	p11_array_free (array);
	return NULL;

}

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

		p11_debug ("opened writable session on: %s", name);
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

static bool
create_anchor (CK_FUNCTION_LIST *module,
               CK_SESSION_HANDLE session,
               CK_ATTRIBUTE *attrs)
{
	CK_BBOOL truev = CK_TRUE;
	CK_OBJECT_HANDLE object;
	char *string;
	CK_RV rv;

	CK_ATTRIBUTE basics[] = {
		{ CKA_TOKEN, &truev, sizeof (truev) },
		{ CKA_TRUSTED, &truev, sizeof (truev) },
		{ CKA_INVALID, },
	};

	attrs = p11_attrs_merge (attrs, p11_attrs_dup (basics), true);
	p11_attrs_remove (attrs, CKA_MODIFIABLE);

	if (p11_debugging) {
		string = p11_attrs_to_string (attrs, -1);
		p11_debug ("storing: %s", string);
		free (string);
	}

	rv = (module->C_CreateObject) (session, attrs,
	                               p11_attrs_count (attrs), &object);

	p11_attrs_free (attrs);

	if (rv != CKR_OK) {
		p11_message ("couldn't create object: %s", p11_kit_strerror (rv));
		return false;
	}

	return true;
}

static bool
modify_anchor (CK_FUNCTION_LIST *module,
               CK_SESSION_HANDLE session,
               CK_OBJECT_HANDLE object,
               CK_ATTRIBUTE *attrs)
{
	CK_BBOOL truev = CK_TRUE;
	CK_ATTRIBUTE *changes;
	CK_ATTRIBUTE *label;
	char *string;
	CK_RV rv;

	CK_ATTRIBUTE trusted = { CKA_TRUSTED, &truev, sizeof (truev) };

	label = p11_attrs_find_valid (attrs, CKA_LABEL);
	changes = p11_attrs_build (NULL, &trusted, label, NULL);
	return_val_if_fail (attrs != NULL, FALSE);

	/* Don't need the attributes anymore */
	p11_attrs_free (attrs);

	if (p11_debugging) {
		string = p11_attrs_to_string (changes, -1);
		p11_debug ("setting: %s", string);
		free (string);
	}

	rv = (module->C_SetAttributeValue) (session, object, changes,
	                                    p11_attrs_count (changes));

	p11_attrs_free (changes);

	if (rv != CKR_OK) {
		p11_message ("couldn't create object: %s", p11_kit_strerror (rv));
		return false;
	}

	return true;
}

static CK_OBJECT_HANDLE
find_anchor (CK_FUNCTION_LIST *module,
             CK_SESSION_HANDLE session,
             CK_ATTRIBUTE *attrs)
{
	CK_OBJECT_HANDLE object = 0UL;
	CK_ATTRIBUTE *attr;
	p11_kit_iter *iter;

	attr = p11_attrs_find_valid (attrs, CKA_CLASS);
	return_val_if_fail (attr != NULL, 0);

	iter = p11_kit_iter_new (NULL, 0);
	return_val_if_fail (iter != NULL, 0);

	if (iter_match_anchor (iter, attrs)) {
		p11_kit_iter_begin_with (iter, module, 0, session);
		if (p11_kit_iter_next (iter) == CKR_OK)
			object = p11_kit_iter_get_object (iter);
	}

	p11_kit_iter_free (iter);

	return object;
}

static int
anchor_store (int argc,
              char *argv[],
              bool *changed)
{
	CK_ATTRIBUTE *attrs;
	CK_FUNCTION_LIST *module = NULL;
	CK_SESSION_HANDLE session;
	CK_OBJECT_HANDLE object;
	p11_array *anchors;
	int ret;
	int i;

	anchors = files_to_attrs (argc, argv);
	if (anchors == NULL)
		return 1;

	if (anchors->num == 0) {
		p11_message ("specify at least one anchor input file");
		p11_array_free (anchors);
		return 2;
	}

	session = session_for_store (&module);
	if (session == 0UL) {
		p11_array_free (anchors);
		return 1;
	}

	for (i = 0, ret = 0; i < anchors->num; i++) {
		attrs = anchors->elem[i];
		anchors->elem[i] = NULL;

		object = find_anchor (module, session, attrs);
		if (object == 0) {
			p11_debug ("don't yet have this anchor");
			if (create_anchor (module, session, attrs)) {
				*changed = true;
			} else {
				ret = 1;
				break;
			}
		} else {
			p11_debug ("already have this anchor");
			if (modify_anchor (module, session, object, attrs)) {
				*changed = true;
			} else {
				ret = 1;
				break;
			}
		}
	}

	p11_array_free (anchors);
	p11_kit_module_finalize (module);
	p11_kit_module_release (module);

	return ret;
}

static const char *
description_for_object_at_iter (p11_kit_iter *iter)
{
	CK_OBJECT_CLASS klass;
	CK_ATTRIBUTE attrs[] = {
		{ CKA_CLASS, &klass, sizeof (klass) },
		{ CKA_INVALID },
	};

	const char *desc = "object";
	CK_RV rv;

	rv = p11_kit_iter_load_attributes (iter, attrs, 1);
	if (rv == CKR_OK)
		desc = p11_constant_nick (p11_constant_classes, klass);

	return desc;
}

static bool
remove_all (p11_kit_iter *iter,
            bool *changed)
{
	const char *desc;
	CK_RV rv;

	while ((rv = p11_kit_iter_next (iter)) == CKR_OK) {
		desc = description_for_object_at_iter (iter);
		p11_debug ("removing %s: %lu", desc, p11_kit_iter_get_object (iter));
		rv = p11_kit_iter_destroy_object (iter);
		switch (rv) {
		case CKR_OK:
			*changed = true;
			/* fall through */
		case CKR_OBJECT_HANDLE_INVALID:
			continue;
		case CKR_TOKEN_WRITE_PROTECTED:
		case CKR_SESSION_READ_ONLY:
		case CKR_ATTRIBUTE_READ_ONLY:
			p11_message ("couldn't remove read-only %s", desc);
			continue;
		default:
			p11_message ("couldn't remove %s: %s", desc,
			             p11_kit_strerror (rv));
			break;
		}
	}

	return (rv == CKR_CANCEL);
}

static int
anchor_remove (int argc,
               char *argv[],
               bool *changed)
{
	CK_FUNCTION_LIST **modules;
	p11_array *iters;
	p11_kit_iter *iter;
	int ret = 0;
	int i;

	iters = uris_or_files_to_iters (argc, argv, P11_KIT_ITER_WANT_WRITABLE);
	return_val_if_fail (iters != NULL, 1);

	if (iters->num == 0) {
		p11_message ("at least one file or uri must be specified");
		p11_array_free (iters);
		return 2;
	}

	modules = p11_kit_modules_load_and_initialize (P11_KIT_MODULE_TRUSTED);
	if (modules == NULL)
		ret = 1;

	for (i = 0; ret == 0 && i < iters->num; i++) {
		iter = iters->elem[i];

		p11_kit_iter_begin (iter, modules);
		if (!remove_all (iter, changed))
			ret = 1;
	}

	p11_array_free (iters);
	p11_kit_modules_finalize_and_release (modules);

	return ret;
}

int
p11_trust_anchor (int argc,
                  char **argv)
{
	bool changed = false;
	int action = 0;
	int opt;
	int ret;

	enum {
		opt_verbose = 'v',
		opt_quiet = 'q',
		opt_help = 'h',

		opt_store = 's',
		opt_remove = 'r',
	};

	struct option options[] = {
		{ "store", no_argument, NULL, opt_store },
		{ "remove", no_argument, NULL, opt_remove },
		{ "verbose", no_argument, NULL, opt_verbose },
		{ "quiet", no_argument, NULL, opt_quiet },
		{ "help", no_argument, NULL, opt_help },
		{ 0 },
	};

	p11_tool_desc usages[] = {
		{ 0, "usage: trust anchor --store <file> ..." },
		{ opt_verbose, "show verbose debug output", },
		{ opt_quiet, "suppress command output", },
		{ 0 },
	};

	while ((opt = p11_tool_getopt (argc, argv, options)) != -1) {
		switch (opt) {
		case opt_store:
		case opt_remove:
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
	};

	argc -= optind;
	argv += optind;

	if (action == 0)
		action = opt_store;

	/* Store is different, and only accepts files */
	if (action == opt_store)
		ret = anchor_store (argc, argv, &changed);

	else if (action == opt_remove)
		ret = anchor_remove (argc, argv, &changed);

	else
		assert_not_reached ();

	/* Extract the compat bundles after modification */
	if (ret == 0 && changed) {
		char *args[] = { argv[0], NULL };
		ret = p11_trust_extract_compat (1, args);
	}

	return ret;
}
