/*
 * Copyright (c) 2023 Red Hat Inc
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

#define P11_DEBUG_FLAG P11_DEBUG_TOOL

#include "check-format.h"
#include "debug.h"
#include "message.h"
#include "persist.h"
#include "tool.h"

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef ENABLE_NLS
#include <libintl.h>
#define _(x) dgettext(PACKAGE_NAME, x)
#else
#define _(x) (x)
#endif

enum format_result {
	FORMAT_OK,
	FORMAT_FAIL,
	FORMAT_ERROR
};

static bool color_out;
static bool color_err;

static inline void
print_result (enum format_result result,
	      const char *filename)
{
	printf (color_out ? "\033[1m%s:\033[0m " : "%s: ", filename);
	switch (result) {
	case FORMAT_OK:
		printf (color_out ? "\033[1;32mOK\033[0m\n" : "OK\n");
		break;
	case FORMAT_FAIL:
		printf (color_out ? "\033[1;31mFAIL\033[0m\n" : "FAIL\n");
		break;
	case FORMAT_ERROR:
		printf (color_out ? "\033[1;31mERROR\033[0m\n" : "ERROR\n");
		break;
	default:
		assert_not_reached ();
		break;
	}
}

static enum format_result
check_format (const char *filename)
{
	p11_mmap *map;
	void *data;
	size_t size;
	p11_persist *persist = NULL;
	enum format_result result;

	map = p11_mmap_open (filename, NULL, &data, &size);
	if (map == NULL) {
		p11_message_err (errno, _("couldn't open and map file: %s"), filename);
		return FORMAT_ERROR;
	}

	if (!p11_persist_magic (data, size)) {
		p11_message (_("file is not recognized as .p11-kit format: %s"), filename);
		result = FORMAT_FAIL;
		goto error;
	}

	persist = p11_persist_new ();
	if (!persist) {
		result = FORMAT_ERROR;
		goto error;
	}

	result = p11_persist_check (persist, filename, data, size) ?
		FORMAT_OK : FORMAT_FAIL;

 error:
	p11_persist_free (persist);
	p11_mmap_close (map);
	return result;
}

int
p11_trust_check_format (int argc,
			char **argv)
{
	int i, opt;
	enum format_result result;

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
		{ 0, "usage: trust check-format <file>..." },
		{ opt_verbose, "show verbose debug output", },
		{ opt_quiet, "suppress command output", },
		{ 0 },
	};

	while ((opt = p11_tool_getopt (argc, argv, options)) != -1) {
		switch (opt) {
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
	}

	argc -= optind;
	argv += optind;

	if (argc < 1) {
		p11_message (_("specify a .p11-kit file"));
		return 2;
	}

	color_out = isatty (fileno (stdout));
	color_err = isatty (fileno (stderr));

	for (i = 0; i < argc; ++i) {
		result = check_format (argv[i]);
		print_result (result, argv[i]);
		if (result == FORMAT_ERROR)
			return 2;
	}

	return 0;
}
