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

#ifndef HAVE_ERR_H

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>

static const char *
calc_prog_name (void)
{
	static char prognamebuf[256];
	static int prepared = 0;

	if(!prepared)
	{
		const char* beg = strrchr(__argv[0], '\\');
		const char* temp = strrchr(__argv[0], '/');
		beg = (beg > temp) ? beg : temp;
		beg = (beg) ? beg + 1 : __argv[0];

		temp = strrchr(__argv[0], '.');
		temp = (temp > beg) ? temp : __argv[0] + strlen(__argv[0]);

		if((temp - beg) > 255)
			temp = beg + 255;

		strncpy(prognamebuf, beg, temp - beg);
		prognamebuf[temp - beg] = 0;
		prepared = 1;
	}

	return prognamebuf;
}

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
	fprintf(err_file, "%s: ", calc_prog_name());
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
	fprintf(err_file, "%s: ", calc_prog_name());
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
	fprintf(err_file, "%s: ", calc_prog_name());
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
	fprintf(err_file, "%s: ", calc_prog_name());
	if(fmt != NULL)
		vfprintf(err_file, fmt, ap);
	fprintf(err_file, "\n");
}

#endif /* HAVE_ERR_H */
