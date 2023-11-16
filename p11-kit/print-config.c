/*
 * Copyright (c) 2022, Red Hat Inc.
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

#include "conf.h"
#include "debug.h"
#include "message.h"
#include "tool.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef ENABLE_NLS
#include <libintl.h>
#define _(x) dgettext(PACKAGE_NAME, x)
#else
#define _(x) (x)
#endif

int
p11_kit_print_config (int argc,
		      char *argv[]);

static int
print_config (void)
{
	p11_dict *global_conf, *modules_conf;
	p11_dictiter i, j;
	void *key, *value;
	int mode;

	global_conf = _p11_conf_load_globals (P11_SYSTEM_CONFIG_FILE,
					      P11_USER_CONFIG_FILE,
					      &mode);
	if (global_conf == NULL)
		return 1;

	modules_conf = _p11_conf_load_modules (mode,
					       P11_PACKAGE_CONFIG_MODULES,
					       P11_SYSTEM_CONFIG_MODULES,
					       P11_USER_CONFIG_MODULES);
	if (modules_conf == NULL) {
		p11_dict_free (global_conf);
		return 1;
	}

	printf ("[global]\n");
	p11_dict_iterate (global_conf, &i);
	while (p11_dict_next (&i, &key, &value))
		printf ("%s = %s\n", (char *)key, (char *)value);

	p11_dict_iterate (modules_conf, &i);
	while (p11_dict_next (&i, &key, &value)) {
		printf ("[%s]\n", (char *)key);
		p11_dict_iterate ((p11_dict *)value, &j);
		while (p11_dict_next (&j, &key, &value))
			printf ("%s = %s\n", (char *)key, (char *)value);
	}

	p11_dict_free (global_conf);
	p11_dict_free (modules_conf);
        return 0;
}

int
p11_kit_print_config (int argc,
		      char *argv[])
{
	int opt;

	enum {
		opt_help = 'h',
	};

	struct option options[] = {
		{ "help", no_argument, NULL, opt_help },
		{ 0 },
	};

	p11_tool_desc usages[] = {
		{ 0, "usage: p11-kit print-config" },
		{ 0 },
	};

	while ((opt = p11_tool_getopt (argc, argv, options)) != -1) {
		switch (opt) {
		case opt_help:
			p11_tool_usage (usages, options);
			return 0;
		case '?':
			return 2;
		default:
			assert_not_reached ();
			break;
		}
	}

	if (argc - optind != 0) {
		p11_message (_("extra arguments specified"));
		return 2;
	}

	return print_config ();
}
