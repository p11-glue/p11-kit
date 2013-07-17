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

#include "attrs.h"
#include "compat.h"
#include "debug.h"
#include "extract.h"
#include "iter.h"
#include "message.h"
#include "oid.h"
#include "pkcs11.h"
#include "pkcs11x.h"
#include "save.h"
#include "tool.h"

#include <assert.h>
#include <ctype.h>
#include <getopt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static bool
filter_argument (const char *optarg,
                 P11KitUri **uri,
                 CK_ATTRIBUTE **match,
                 int *flags)
{
	CK_ATTRIBUTE *attrs;
	int ret;

	CK_OBJECT_CLASS vcertificate = CKO_CERTIFICATE;
	CK_ULONG vauthority = 2;
	CK_CERTIFICATE_TYPE vx509 = CKC_X_509;

	CK_ATTRIBUTE certificate = { CKA_CLASS, &vcertificate, sizeof (vcertificate) };
	CK_ATTRIBUTE authority = { CKA_CERTIFICATE_CATEGORY, &vauthority, sizeof (vauthority) };
	CK_ATTRIBUTE x509 = { CKA_CERTIFICATE_TYPE, &vx509, sizeof (vx509) };

	if (strncmp (optarg, "pkcs11:", 7) == 0) {
		if (*uri != NULL) {
			p11_message ("only one pkcs11 uri filter may be specified");
			return false;
		}
		*uri = p11_kit_uri_new ();
		ret = p11_kit_uri_parse (optarg, P11_KIT_URI_FOR_OBJECT_ON_TOKEN_AND_MODULE, *uri);
		if (ret != P11_KIT_URI_OK) {
			p11_message ("couldn't parse pkcs11 uri filter: %s", optarg);
			return false;
		}
		return true;
	}

	if (strcmp (optarg, "ca-anchors") == 0) {
		attrs = p11_attrs_build (NULL, &certificate, &authority, &x509, NULL);
		*flags |= P11_EXTRACT_ANCHORS | P11_EXTRACT_COLLAPSE;

	} else if (strcmp (optarg, "trust-policy") == 0) {
		attrs = p11_attrs_build (NULL, &certificate, &x509, NULL);
		*flags |= P11_EXTRACT_ANCHORS | P11_EXTRACT_BLACKLIST | P11_EXTRACT_COLLAPSE;

	} else if (strcmp (optarg, "blacklist") == 0) {
		attrs = p11_attrs_build (NULL, &certificate, &x509, NULL);
		*flags |= P11_EXTRACT_BLACKLIST | P11_EXTRACT_COLLAPSE;

	} else if (strcmp (optarg, "certificates") == 0) {
		attrs = p11_attrs_build (NULL, &certificate, &x509, NULL);
		*flags |= P11_EXTRACT_COLLAPSE;

	} else {
		p11_message ("unsupported or unrecognized filter: %s", optarg);
		return false;
	}

	if (*match != NULL) {
		p11_message ("a conflicting filter has already been specified");
		p11_attrs_free (attrs);
		return false;
	}

	*match = attrs;
	return true;
}

static int
is_valid_oid_rough (const char *string)
{
	size_t len;

	len = strlen (string);

	/* Rough check if a valid OID */
	return (strspn (string, "0123456789.") == len &&
	        !strstr (string, "..") && string[0] != '\0' && string[0] != '.' &&
	        string[len - 1] != '.');
}

static bool
purpose_argument (const char *optarg,
                  p11_extract_info *ex)
{
	const char *oid;

	if (strcmp (optarg, "server-auth") == 0) {
		oid = P11_OID_SERVER_AUTH_STR;
	} else if (strcmp (optarg, "client-auth") == 0) {
		oid = P11_OID_CLIENT_AUTH_STR;
	} else if (strcmp (optarg, "email-protection") == 0 || strcmp (optarg, "email") == 0) {
		oid = P11_OID_EMAIL_PROTECTION_STR;
	} else if (strcmp (optarg, "code-signing") == 0) {
		oid = P11_OID_CODE_SIGNING_STR;
	} else if (strcmp (optarg, "ipsec-end-system") == 0) {
		oid = P11_OID_IPSEC_END_SYSTEM_STR;
	} else if (strcmp (optarg, "ipsec-tunnel") == 0) {
		oid = P11_OID_IPSEC_TUNNEL_STR;
	} else if (strcmp (optarg, "ipsec-user") == 0) {
		oid = P11_OID_IPSEC_USER_STR;
	} else if (strcmp (optarg, "time-stamping") == 0) {
		oid = P11_OID_TIME_STAMPING_STR;
	} else if (is_valid_oid_rough (optarg)) {
		oid = optarg;
	} else {
		p11_message ("unsupported or unregonized purpose: %s", optarg);
		return false;
	}

	p11_extract_info_limit_purpose (ex, oid);
	return true;
}

static bool
format_argument (const char *optarg,
                 p11_extract_func *func)
{
	int i;

	/*
	 * Certain formats do not support expressive trust information.
	 * So the caller should limit the supported purposes when asking
	 * for trust information.
	 */

	static const struct {
		const char *format;
		p11_extract_func func;
	} formats[] = {
		{ "x509-file", p11_extract_x509_file, },
		{ "x509-directory", p11_extract_x509_directory, },
		{ "pem-bundle", p11_extract_pem_bundle, },
		{ "pem-directory", p11_extract_pem_directory },
		{ "java-cacerts", p11_extract_jks_cacerts },
		{ "openssl-bundle", p11_extract_openssl_bundle },
		{ "openssl-directory", p11_extract_openssl_directory },
		{ NULL },
	};

	if (*func != NULL) {
		p11_message ("a format was already specified");
		return false;
	}

	for (i = 0; formats[i].format != NULL; i++) {
		if (strcmp (optarg, formats[i].format) == 0) {
			*func = formats[i].func;
			break;
		}
	}

	if (*func == NULL) {
		p11_message ("unsupported or unrecognized format: %s", optarg);
		return false;
	}

	return true;
}

static bool
validate_filter_and_format (p11_extract_info *ex,
                            p11_extract_func func,
                            CK_ATTRIBUTE *match)
{
	int i;

	/*
	 * These are the extract functions that contain purpose information.
	 * If we're being asked to export anchors, and the extract function does
	 * not support, and the caller has not specified a purpose, then add a
	 * default purpose to limit to.
	 */

	static p11_extract_func supports_trust_policy[] = {
		p11_extract_openssl_bundle,
		p11_extract_openssl_directory,
		NULL
	};

	for (i = 0; supports_trust_policy[i] != NULL; i++) {
		if (func == supports_trust_policy[i])
			return true;
	}

	if ((ex->flags & P11_EXTRACT_ANCHORS) &&
	    (ex->flags & P11_EXTRACT_BLACKLIST)) {
		/*
		 * If we're extracting *both* anchors and blacklist, then we must have
		 * a format that can represent the different types of information.
		 */

		p11_message ("format does not support trust policy");
		return false;

	} else if (ex->flags & P11_EXTRACT_ANCHORS) {

		/*
		 * If we're extracting anchors, then we must have either limited the
		 * purposes, or have a format that can represent multiple purposes.
		 */

		if (!ex->limit_to_purposes) {
			p11_message ("format does not support multiple purposes, defaulting to 'server-auth'");
			p11_extract_info_limit_purpose (ex, P11_OID_SERVER_AUTH_STR);
		}
	}

	return true;
}

int
p11_trust_extract (int argc,
                   char **argv)
{
	p11_extract_func format = NULL;
	CK_FUNCTION_LIST_PTR *modules;
	P11KitIter *iter;
	p11_extract_info ex;
	CK_ATTRIBUTE *match;
	P11KitUri *uri;
	int flags;
	int opt = 0;
	int ret;

	enum {
		opt_overwrite = 'f',
		opt_verbose = 'v',
		opt_quiet = 'q',
		opt_help = 'h',
		opt_filter = 1000,
		opt_purpose,
		opt_format,
		opt_comment,
	};

	struct option options[] = {
		{ "filter", required_argument, NULL, opt_filter },
		{ "format", required_argument, NULL, opt_format },
		{ "purpose", required_argument, NULL, opt_purpose },
		{ "overwrite", no_argument, NULL, opt_overwrite },
		{ "comment", no_argument, NULL, opt_comment },
		{ "verbose", no_argument, NULL, opt_verbose },
		{ "quiet", no_argument, NULL, opt_quiet },
		{ "help", no_argument, NULL, opt_help },
		{ 0 },
	};

	p11_tool_desc usages[] = {
		{ 0, "usage: trust extract --format=<output> <destination>" },
		{ opt_filter,
		  "filter of what to export\n"
		  "  ca-anchors        certificate anchors (default)\n"
		  "  blacklist         blacklisted certificates\n"
		  "  trust-policy      anchors and blacklist\n"
		  "  certificates      all certificates\n"
		  "  pkcs11:object=xx  a PKCS#11 URI",
		  "what",
		},
		{ opt_format,
		  "format to extract to\n"
		  "  x509-file         DER X.509 certificate file\n"
		  "  x509-directory    directory of X.509 certificates\n"
		  "  pem-bundle        file containing multiple PEM blocks\n"
		  "  pem-directory     directory of PEM files\n"
		  "  openssl-bundle    OpenSSL specific PEM bundle\n"
		  "  openssl-directory directory of OpenSSL specific files\n"
		  "  java-cacerts      java keystore cacerts file",
		  "type"
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
		{ opt_overwrite, "overwrite output file or directory" },
		{ opt_comment, "add comments to bundles if possible" },
		{ opt_verbose, "show verbose debug output", },
		{ opt_quiet, "supress command output", },
		{ 0 },
	};

	match = NULL;
	uri = NULL;

	p11_extract_info_init (&ex);

	while ((opt = p11_tool_getopt (argc, argv, options)) != -1) {
		switch (opt) {
		case opt_verbose:
		case opt_quiet:
			break;

		case opt_overwrite:
			ex.flags |= P11_SAVE_OVERWRITE;
			break;
		case opt_comment:
			ex.flags |= P11_EXTRACT_COMMENT;
			break;
		case opt_filter:
			if (!filter_argument (optarg, &uri, &match, &ex.flags))
				exit (2);
			break;
		case opt_purpose:
			if (!purpose_argument (optarg, &ex))
				exit (2);
			break;
		case opt_format:
			if (!format_argument (optarg, &format))
				exit (2);
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

	argc -= optind;
	argv += optind;

	if (argc != 1) {
		p11_message ("specify one destination file or directory");
		exit (2);
	}
	ex.destination = argv[0];

	if (!format) {
		p11_message ("no output format specified");
		exit (2);
	}

	/* If nothing that was useful to enumerate was specified, then bail */
	if (uri == NULL && match == NULL) {
		p11_message ("no filter specified, defaulting to 'ca-anchors'");
		filter_argument ("ca-anchors", &uri, &match, &ex.flags);
	}

	if (!validate_filter_and_format (&ex, format, match))
		exit (1);

	if (uri && p11_kit_uri_any_unrecognized (uri))
		p11_message ("uri contained unrecognized components, nothing will be extracted");

	/*
	 * We only "believe" the CKA_TRUSTED and CKA_X_DISTRUSTED attributes
	 * we get from modules explicitly marked as containing trust-policy.
	 */
	flags = 0;
	if (ex.flags & (P11_EXTRACT_ANCHORS | P11_EXTRACT_BLACKLIST))
		flags |= P11_KIT_MODULE_TRUSTED;

	modules = p11_kit_modules_load_and_initialize (flags);
	if (!modules)
		exit (1);

	if (modules[0] == NULL)
		p11_message ("no modules containing trust policy are registered");

	iter = p11_kit_iter_new (uri, 0);

	p11_kit_iter_add_callback (iter, p11_extract_info_load_filter, &ex, NULL);
	p11_kit_iter_add_filter (iter, match, p11_attrs_count (match));

	p11_kit_iter_begin (iter, modules);

	ret = (format) (iter, &ex) ? 0 : 1;

	p11_extract_info_cleanup (&ex);
	p11_kit_iter_free (iter);
	p11_kit_uri_free (uri);

	p11_kit_modules_finalize (modules);
	p11_kit_modules_release (modules);

	return ret;
}
