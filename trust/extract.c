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
#include "message.h"
#include "oid.h"
#include "path.h"
#include "pkcs11x.h"
#include "save.h"
#include "tool.h"
#include "digest.h"

#include "p11-kit/iter.h"
#include "p11-kit/pkcs11.h"

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
		{ "pem-directory-hash", p11_extract_pem_directory_hash },
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
validate_filter_and_format (p11_enumerate *ex,
                            p11_extract_func func)
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

	if ((ex->flags & P11_ENUMERATE_ANCHORS) &&
	    (ex->flags & P11_ENUMERATE_BLACKLIST)) {
		/*
		 * If we're extracting *both* anchors and blacklist, then we must have
		 * a format that can represent the different types of information.
		 */

		p11_message ("format does not support trust policy");
		return false;

	} else if (ex->flags & P11_ENUMERATE_ANCHORS) {

		/*
		 * If we're extracting anchors, then we must have either limited the
		 * purposes, or have a format that can represent multiple purposes.
		 */

		if (!ex->limit_to_purposes) {
			p11_message ("format does not support multiple purposes, defaulting to 'server-auth'");
			p11_enumerate_opt_purpose (ex, "server-auth");
		}
	}

	return true;
}

int
p11_trust_extract (int argc,
                   char **argv)
{
	p11_extract_func format = NULL;
	p11_enumerate ex;
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
		  "  x509-file           DER X.509 certificate file\n"
		  "  x509-directory      directory of X.509 certificates\n"
		  "  pem-bundle          file containing multiple PEM blocks\n"
		  "  pem-directory       directory of PEM files\n"
		  "  pem-directory-hash  directory of PEM files with hash links\n"
		  "  openssl-bundle      OpenSSL specific PEM bundle\n"
		  "  openssl-directory   directory of OpenSSL specific files\n"
		  "  java-cacerts        java keystore cacerts file",
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
		{ opt_quiet, "suppress command output", },
		{ 0 },
	};

	p11_enumerate_init (&ex);

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
			if (!p11_enumerate_opt_filter (&ex, optarg))
				exit (2);
			break;
		case opt_purpose:
			if (!p11_enumerate_opt_purpose (&ex, optarg))
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

	if (!format) {
		p11_message ("no output format specified");
		exit (2);
	}

	if (!validate_filter_and_format (&ex, format))
		exit (1);

	if (!p11_enumerate_ready (&ex, "ca-anchors"))
		exit (1);

	ret = (format) (&ex, argv[0]) ? 0 : 1;

	p11_enumerate_cleanup (&ex);
	return ret;
}

int
p11_trust_extract_compat (int argc,
                          char *argv[])
{
	char *path = NULL;
	int error;

	argv[argc] = NULL;

	/*
	 * For compatibility with people who deployed p11-kit 0.18.x
	 * before trust stuff was put into its own branch.
	 */
	path = p11_path_build (PRIVATEDIR, "p11-kit-extract-trust", NULL);
	return_val_if_fail (path != NULL, 1);
	execv (path, argv);
	error = errno;

	if (error == ENOENT) {
		free (path);
		path = p11_path_build (PRIVATEDIR, "trust-extract-compat", NULL);
		return_val_if_fail (path != NULL, 1);
		execv (path, argv);
		error = errno;
	}

	/* At this point we have no command */
	p11_message_err (error, "could not run %s command", path);

	free (path);
	return 2;
}
