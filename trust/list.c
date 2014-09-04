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

#include "attrs.h"
#include "constants.h"
#include "debug.h"
#include "enumerate.h"
#include "list.h"
#include "message.h"
#include "pkcs11x.h"
#include "tool.h"
#include "url.h"

#include "p11-kit/iter.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

static char *
format_uri (p11_enumerate *ex,
            int flags)
{
	CK_ATTRIBUTE *attr;
	p11_kit_uri *uri;
	char *string;

	uri = p11_kit_uri_new ();

	memcpy (p11_kit_uri_get_token_info (uri),
	        p11_kit_iter_get_token (ex->iter),
	        sizeof (CK_TOKEN_INFO));

	attr = p11_attrs_find (ex->attrs, CKA_CLASS);
	if (attr != NULL)
		p11_kit_uri_set_attribute (uri, attr);
	attr = p11_attrs_find (ex->attrs, CKA_ID);
	if (attr != NULL)
		p11_kit_uri_set_attribute (uri, attr);

	if (p11_kit_uri_format (uri, flags, &string) != P11_KIT_URI_OK)
		string = NULL;

	p11_kit_uri_free (uri);
	return string;
}

static bool
list_iterate (p11_enumerate *ex,
              bool details)
{
	unsigned char *bytes;
	CK_OBJECT_HANDLE object;
	CK_ATTRIBUTE *attr;
	CK_ULONG klass;
	CK_ULONG category;
	CK_BBOOL val;
	p11_buffer buf;
	CK_RV rv;
	const char *nick;
	char *string;
	int flags;

	flags = P11_KIT_URI_FOR_OBJECT;
	if (details)
		flags |= P11_KIT_URI_FOR_OBJECT_ON_TOKEN;

	while ((rv = p11_kit_iter_next (ex->iter)) == CKR_OK) {
		if (p11_debugging) {
			object = p11_kit_iter_get_object (ex->iter);
			p11_debug ("handle: %lu", object);

			string = p11_attrs_to_string (ex->attrs, -1);
			p11_debug ("attrs: %s", string);
			free (string);
		}

		string = format_uri (ex, flags);
		if (string == NULL) {
			p11_message ("skipping object, couldn't build uri");
			continue;
		}

		printf ("%s\n", string);
		free (string);

		if (p11_attrs_find_ulong (ex->attrs, CKA_CLASS, &klass)) {
			nick = p11_constant_nick (p11_constant_classes, klass);
			if (nick != NULL)
				printf ("    type: %s\n", nick);
		}

		attr = p11_attrs_find_valid (ex->attrs, CKA_LABEL);
		if (attr && attr->pValue && attr->ulValueLen) {
			string = strndup (attr->pValue, attr->ulValueLen);
			printf ("    label: %s\n", string);
			free (string);
		}

		if (p11_attrs_find_bool (ex->attrs, CKA_X_DISTRUSTED, &val) && val)
			printf ("    trust: blacklisted\n");
		else if (p11_attrs_find_bool (ex->attrs, CKA_TRUSTED, &val) && val)
			printf ("    trust: anchor\n");
		else
			printf ("    trust: unspecified\n");

		if (p11_attrs_find_ulong (ex->attrs, CKA_CERTIFICATE_CATEGORY, &category)) {
			nick = p11_constant_nick (p11_constant_categories, category);
			if (nick != NULL)
				printf ("    category: %s\n", nick);
		}

		if (details) {
			attr = p11_attrs_find_valid (ex->attrs, CKA_PUBLIC_KEY_INFO);
			if (attr) {
				p11_buffer_init (&buf, 1024);
				bytes = attr->pValue;
				p11_url_encode (bytes, bytes + attr->ulValueLen, "", &buf);
				printf ("    public-key-info: %.*s\n", (int)buf.len, (char *)buf.data);
				p11_buffer_uninit (&buf);
			}
		}

		printf ("\n");
	}

	return (rv == CKR_CANCEL);
}

int
p11_trust_list (int argc,
                char **argv)
{
	p11_enumerate ex;
	bool details = false;
	int opt = 0;
	int ret;

	enum {
		opt_verbose = 'v',
		opt_quiet = 'q',
		opt_help = 'h',
		opt_filter = 1000,
		opt_purpose,
		opt_details,
	};

	struct option options[] = {
		{ "filter", required_argument, NULL, opt_filter },
		{ "purpose", required_argument, NULL, opt_purpose },
		{ "details", no_argument, NULL, opt_details },
		{ "verbose", no_argument, NULL, opt_verbose },
		{ "quiet", no_argument, NULL, opt_quiet },
		{ "help", no_argument, NULL, opt_help },
		{ 0 },
	};

	p11_tool_desc usages[] = {
		{ 0, "usage: trust list --filter=<what>" },
		{ opt_filter,
		  "filter of what to export\n"
		  "  ca-anchors        certificate anchors\n"
		  "  blacklist         blacklisted certificates\n"
		  "  trust-policy      anchors and blacklist (default)\n"
		  "  certificates      all certificates\n"
		  "  pkcs11:object=xx  a PKCS#11 URI",
		  "what",
		},
		{ opt_purpose,
		  "limit to certificates usable for the purpose\n"
		  "  server-auth       for authenticating servers\n"
		  "  client-auth       for authenticating clients\n"
		  "  email             for email protection\n"
		  "  code-signing      for authenticating signed code\n"
		  "  1.2.3.4.5...      an arbitrary object id",
		  "usage"
		},
		{ opt_verbose, "show verbose debug output", },
		{ opt_quiet, "suppress command output", },
		{ 0 },
	};

	p11_enumerate_init (&ex);

	while ((opt = p11_tool_getopt (argc, argv, options)) != -1) {
		switch (opt) {
		case opt_verbose:
		case opt_quiet:
			break;

		case opt_filter:
			if (!p11_enumerate_opt_filter (&ex, optarg))
				exit (2);
			break;
		case opt_purpose:
			if (!p11_enumerate_opt_purpose (&ex, optarg))
				exit (2);
			break;
		case opt_details:
			details = true;
			break;
		case 'h':
			p11_tool_usage (usages, options);
			exit (0);
		case '?':
			exit (2);
		default:
			assert_not_reached ();
			break;
		}
	}

	if (argc - optind != 0) {
		p11_message ("extra arguments passed to command");
		exit (2);
	}

	if (!p11_enumerate_ready (&ex, "trust-policy"))
		exit (1);

	ret = list_iterate (&ex, details) ? 0 : 1;

	p11_enumerate_cleanup (&ex);
	return ret;
}
