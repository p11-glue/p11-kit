/*
 * Copyright (c) 2011, Collabora Ltd.
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
 * Author: Stef Walter <stefw@collabora.co.uk>
 */

#include "config.h"

#include "compat.h"
#include "debug.h"
#include "message.h"
#include "path.h"

#include <assert.h>
#include <ctype.h>
#include <getopt.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "tool.h"

int       p11_kit_list_modules    (int argc,
                                   char *argv[]);

int       p11_kit_extract         (int argc,
                                   char *argv[]);

int       p11_kit_external        (int argc,
                                   char *argv[]);

static const p11_tool_command commands[] = {
	{ "list-modules", p11_kit_list_modules, "List modules and tokens" },
	{ "extract", p11_kit_extract, "Extract certificates and trust" },
	{ P11_TOOL_FALLBACK, p11_kit_external, "List modules and tokens" },
	{ 0, }
};

int
p11_kit_external (int argc,
                  char *argv[])
{
	char *filename;
	char *path;

	if (!asprintf (&filename, "p11-kit-%s", argv[0]) < 0)
		return_val_if_reached (1);

	/* Add our libexec directory to the path */
	path = p11_path_build (PRIVATEDIR, filename, NULL);
	return_val_if_fail (path != NULL, 1);

	argv[argc] = NULL;
	execvp (path, argv);

	/* At this point we have no command */
	p11_message ("'%s' is not a valid command. See 'p11-kit --help'", argv[0]);
	return 2;
}

int
p11_kit_extract (int argc,
                 char *argv[])
{
	return p11_kit_external (argc, argv);
}

int
main (int argc,
      char *argv[])
{
	return p11_tool_main (argc, argv, commands);
}
