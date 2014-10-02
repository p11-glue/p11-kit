/*
 * Copyright (c) 2011 Collabora Ltd.
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
 *
 * CONTRIBUTORS
 *  Stef Walter <stef@memberwebs.com>
 */

#include "config.h"

#include "compat.h"
#include "debug.h"

#include <assert.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct DebugKey {
	const char *name;
	int value;
};

static struct DebugKey debug_keys[] = {
	{ "lib", P11_DEBUG_LIB },
	{ "conf", P11_DEBUG_CONF },
	{ "uri", P11_DEBUG_URI },
	{ "proxy", P11_DEBUG_PROXY },
	{ "trust", P11_DEBUG_TRUST },
	{ "tool", P11_DEBUG_TOOL },
	{ "rpc", P11_DEBUG_RPC },
	{ 0, }
};

static bool debug_inited = false;
static bool debug_strict = false;

/* global variable exported in debug.h */
int p11_debug_current_flags = ~0;

static int
parse_environ_flags (void)
{
	const char *env;
	int result = 0;
	const char *p;
	const char *q;
	int i;

	env = secure_getenv ("P11_KIT_STRICT");
	if (env && env[0] != '\0')
		debug_strict = true;

	env = getenv ("P11_KIT_DEBUG");
	if (!env)
		return 0;

	if (strcmp (env, "all") == 0) {
		for (i = 0; debug_keys[i].name; i++)
			result |= debug_keys[i].value;

	} else if (strcmp (env, "help") == 0) {
		fprintf (stderr, "Supported debug values:");
		for (i = 0; debug_keys[i].name; i++)
			fprintf (stderr, " %s", debug_keys[i].name);
		fprintf (stderr, "\n");

	} else {
		p = env;
		while (*p) {
			q = strpbrk (p, ":;, \t");
			if (!q)
				q = p + strlen (p);

			for (i = 0; debug_keys[i].name; i++) {
				if (q - p == strlen (debug_keys[i].name) &&
				    strncmp (debug_keys[i].name, p, q - p) == 0)
					result |= debug_keys[i].value;
			}

			p = q;
			if (*p)
				p++;
		}
	}

	return result;
}

void
p11_debug_init (void)
{
	p11_debug_current_flags = parse_environ_flags ();
	debug_inited = true;
}

void
p11_debug_message (int flag,
                    const char *format, ...)
{
	va_list args;

	if (flag & p11_debug_current_flags) {
		fprintf (stderr, "(p11-kit:%d) ", getpid());
		va_start (args, format);
		vfprintf (stderr, format, args);
		va_end (args);
		fprintf (stderr, "\n");
	}
}

void
p11_debug_precond (const char *format,
                    ...)
{
	va_list va;

	va_start (va, format);
	vfprintf (stderr, format, va);
	va_end (va);

#ifdef __COVERITY__
	fprintf (stderr, "ignoring P11_KIT_STRICT under coverity: %d", (int)debug_strict);
#else
	if (debug_strict)
#endif
		abort ();
}
