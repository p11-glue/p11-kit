/*
 * Copyright (c) 2020 Red Hat Inc.
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
 * Author: Daiki Ueno
 */

#include "config.h"
#include "compat.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

int
main (int argc,
      char *argv[])
{
	if (argc == 1) {
		pid_t pid;
		int pfds[2];

		if (pipe (pfds) < 0) {
			perror ("pipe");
			exit (EXIT_FAILURE);
		}

		pid = fork ();
		if (pid < 0) {
			perror ("fork");
			exit (EXIT_FAILURE);
		}

		if (pid == 0) {
			char * const args[] = {
				BUILDDIR "/common/frob-getprogname" EXEEXT " foo bar",
				"foo",
				"bar",
				NULL,
			};

			dup2 (pfds[1], STDOUT_FILENO);
			close (pfds[0]);
			close (pfds[1]);
			execv (BUILDDIR "/common/frob-getprogname" EXEEXT, args);
		} else {
			int status;
			char buffer[1024];
			size_t offset = 0;
			ssize_t nread;
			char *p;

			close (pfds[1]);
			while (1) {
				nread = read (pfds[0], buffer + offset, sizeof(buffer) - offset);
				if (nread < 0) {
					perror ("read");
					exit (EXIT_FAILURE);
				}
				if (nread == 0)
					break;
				offset += nread;
			}

			if (waitpid (pid, &status, 0) < 0) {
				perror ("waitpid");
				exit (EXIT_FAILURE);
			}

			assert (!WIFSIGNALED (status));
			assert (WIFEXITED (status));
			assert (WEXITSTATUS (status) == 0);

			p = memchr (buffer, '\n', sizeof(buffer));
			if (!p) {
				fprintf (stderr, "missing newline: %s\n", buffer);
				exit (EXIT_FAILURE);
			}
			*p = '\0';

			return strcmp ("frob-getprogname", buffer) == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
		}
	} else {
		printf ("%s\n", getprogname ());
		exit (EXIT_SUCCESS);
	}

	return EXIT_SUCCESS;
}
