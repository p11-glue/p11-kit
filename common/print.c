/*
 * Copyright (c) 2023 Red Hat Inc.
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

#include "print.h"

#include <stdarg.h>
#include <unistd.h>

static const char *
color_to_sgr (p11_color color)
{
	switch (color) {
	case P11_COLOR_BLACK:   return "30";
	case P11_COLOR_RED:     return "31";
	case P11_COLOR_GREEN:   return "32";
	case P11_COLOR_YELLOW:  return "33";
	case P11_COLOR_BLUE:    return "34";
	case P11_COLOR_MAGENTA: return "35";
	case P11_COLOR_CYAN:    return "36";
	case P11_COLOR_WHITE:   return "37";
	default:                return "0";
	}
}

void
p11_highlight_word (FILE *fp,
		    const char *string)
{
	if (isatty (fileno (fp)))
		fprintf (fp, "\e]8;;%s\e\\\033[36m%s\033[0m\e]8;;\e\\\n", string, string);
	else
		fprintf (fp, "%s\n", string);
}

void
p11_print_word (FILE *fp,
		const char *string,
		p11_color color,
		p11_font font)
{
	if (!isatty (fileno (fp))) {
		fputs (string, fp);
		return;
	}

	fprintf (fp, "\033[%s", color_to_sgr (color));
	if (font & P11_FONT_BOLD)
		fprintf (fp, ";1");
	if (font & P11_FONT_UNDERLINE)
		fprintf (fp, ";4");
	fprintf (fp, "m%s\033[0m", string);
}

void
p11_print_value (FILE *fp,
		 size_t indent,
		 const char *key,
		 p11_color color,
		 p11_font font,
		 const char *value_fmt,
		 ...)
{
	size_t i;
	va_list args;

	for (i = 0; i < indent; ++i)
		fputc (' ', fp);

	p11_print_word (fp, key, color, font);
	p11_print_word (fp, ": ", color, font);

	va_start (args, value_fmt);
	vfprintf (fp, value_fmt, args);
	va_end (args);
	fputc ('\n', fp);
}
