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
#include "p11-kit.h"

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "tool.h"

int       p11_kit_list_modules    (int argc,
                                   char *argv[]);

int       p11_kit_trust           (int argc,
                                   char *argv[]);

int       p11_kit_external        (int argc,
                                   char *argv[]);

static const p11_tool_command commands[] = {
	{ "list-modules", p11_kit_list_modules, "List modules and tokens" },
	{ "remote", p11_kit_external, "Run a specific PKCS#11 module remotely" },
	{ P11_TOOL_FALLBACK, p11_kit_external, NULL },
	{ 0, }
};

int
p11_kit_trust (int argc,
               char *argv[])
{
	char **args;

	args = calloc (argc + 2, sizeof (char *));
	return_val_if_fail (args != NULL, 1);

	args[0] = BINDIR "/trust";
	memcpy (args + 1, argv, sizeof (char *) * argc);
	args[argc + 1] = NULL;

	execv (args[0], args);

	/* At this point we have no command */
	p11_message_err (errno, "couldn't run trust tool");

	free (args);
	return 2;
}

int
p11_kit_external (int argc,
                  char *argv[])
{
	const char *private_dir;
	char *filename;
	char *path;

	/* These are trust commands, send them to that tool */
	if (strcmp (argv[0], "extract") == 0) {
		return p11_kit_trust (argc, argv);
	} else if (strcmp (argv[0], "extract-trust") == 0) {
		argv[0] = "extract-compat";
		return p11_kit_trust (argc, argv);
	}

	if (asprintf (&filename, "p11-kit-%s", argv[0]) < 0)
		return_val_if_reached (1);

	private_dir = secure_getenv ("P11_KIT_PRIVATEDIR");
	if (!private_dir || !private_dir[0])
		private_dir = PRIVATEDIR;

	/* Add our libexec directory to the path */
	path = p11_path_build (private_dir, filename, NULL);
	return_val_if_fail (path != NULL, 1);

	argv[argc] = NULL;
	execv (path, argv);

	/* At this point we have no command */
	p11_message ("'%s' is not a valid command. See 'p11-kit --help'", argv[0]);

	free (filename);
	free (path);
	return 2;
}

int
main (int argc,
      char *argv[])
{
	return p11_tool_main (argc, argv, commands);
}
