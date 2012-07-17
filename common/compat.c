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
 * Author: Stef Walter <stefw@collabora.co.uk>
 */

#include "config.h"

#include "compat.h"

#include <stdlib.h>
#include <string.h>

#ifndef HAVE_GETPROGNAME

#ifdef OS_UNIX

#if defined (HAVE_PROGRAM_INVOCATION_SHORT_NAME) && !HAVE_DECL_PROGRAM_INVOCATION_SHORT_NAME
extern char *program_invocation_short_name;
#endif

#if defined (HAVE___PROGNAME) && !HAVE_DECL___PROGNAME
extern char *__progname;
#endif

const char *
getprogname (void)
{
	const char *name;

#if defined (HAVE_GETEXECNAME)
	const char *p;
	name = getexecname();
	p = strrchr (name ? name : "", '/');
	if (p != NULL)
		name = p + 1;
#elif defined (HAVE_PROGRAM_INVOCATION_SHORT_NAME)
	name = program_invocation_short_name;
#elif defined (HAVE___PROGNAME)
	name = __progname;
#else
	#error No way to retrieve short program name
#endif

	return name;
}

#else /* OS_WIN32 */

extern char **__argv;
static char prognamebuf[256];

const char *
getprogname (void)
{
	const char *name;
	const char *p, *p2;
	size_t length;

	name = __argv[0];
	if (name == NULL)
		return NULL;

	p = strrchr (name, '\\');
	p2 = strrchr (name, '/');
	if (p2 > p)
		p = p2;
	if (p != NULL)
		name = p + 1;

	length = sizeof (prognamebuf) - 1;
	strncpy (prognamebuf, name, length);
	prognamebuf[length] = 0;
	length = strlen (prognamebuf);
	if (length > 4 && _stricmp (prognamebuf + (length - 4), ".exe") == 0)
		prognamebuf[length - 4] = '\0';

	return prognamebuf;
}

#endif /* OS_WIN32 */

#endif /* HAVE_GETPROGNAME */

#ifndef HAVE_ERR_H

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>

static FILE *err_file; /* file to use for error output */

/*
 * This is declared to take a `void *' so that the caller is not required
 * to include <stdio.h> first.  However, it is really a `FILE *', and the
 * manual page documents it as such.
 */
void
err_set_file (void *fp)
{
	if (fp)
		err_file = fp;
	else
		err_file = stderr;
}

void
err (int eval,
     const char *fmt,
     ...)
{
	va_list ap;
	va_start(ap, fmt);
	verrc(eval, errno, fmt, ap);
	va_end(ap);
}

void
verr (int eval,
      const char *fmt,
      va_list ap)
{
	verrc(eval, errno, fmt, ap);
}

void
errc (int eval,
      int code,
      const char *fmt,
      ...)
{
	va_list ap;
	va_start(ap, fmt);
	verrc(eval, code, fmt, ap);
	va_end(ap);
}

void
verrc (int eval,
       int code,
       const char *fmt,
       va_list ap)
{
	if (err_file == 0)
		err_set_file((FILE *)0);
	fprintf(err_file, "%s: ", getprogname ());
	if (fmt != NULL) {
		vfprintf(err_file, fmt, ap);
		fprintf(err_file, ": ");
	}
	fprintf(err_file, "%s\n", strerror(code));
	exit(eval);
}

void
errx (int eval,
      const char *fmt,
      ...)
{
	va_list ap;
	va_start(ap, fmt);
	verrx(eval, fmt, ap);
	va_end(ap);
}

void
verrx (int eval,
       const char *fmt,
       va_list ap)
{
	if (err_file == 0)
		err_set_file((FILE *)0);
	fprintf(err_file, "%s: ", getprogname ());
	if (fmt != NULL)
		vfprintf(err_file, fmt, ap);
	fprintf(err_file, "\n");
	exit(eval);
}

void
warn (const char *fmt,
      ...)
{
	va_list ap;
	va_start(ap, fmt);
	vwarnc(errno, fmt, ap);
	va_end(ap);
}

void
vwarn (const char *fmt,
       va_list ap)
{
	vwarnc(errno, fmt, ap);
}

void
warnc (int code,
       const char *fmt,
       ...)
{
	va_list ap;
	va_start(ap, fmt);
	vwarnc(code, fmt, ap);
	va_end(ap);
}

void
vwarnc (int code,
        const char *fmt,
        va_list ap)
{
	if (err_file == 0)
		err_set_file((FILE *)0);
	fprintf(err_file, "%s: ", getprogname ());
	if (fmt != NULL)
	{
		vfprintf(err_file, fmt, ap);
		fprintf(err_file, ": ");
	}
	fprintf(err_file, "%s\n", strerror(code));
}

void
warnx (const char *fmt,
       ...)
{
	va_list ap;
	va_start(ap, fmt);
	vwarnx(fmt, ap);
	va_end(ap);
}

void
vwarnx (const char *fmt,
        va_list ap)
{
	if(err_file == 0)
		err_set_file((FILE*)0);
	fprintf(err_file, "%s: ", getprogname ());
	if(fmt != NULL)
		vfprintf(err_file, fmt, ap);
	fprintf(err_file, "\n");
}

#endif /* HAVE_ERR_H */
