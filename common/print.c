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

#include "compat.h"
#include "debug.h"
#include <stdarg.h>

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

/* List of colors used for nested section headers */
static p11_color header_colors[] = {
	P11_COLOR_BLUE,
	P11_COLOR_GREEN
};

void
p11_list_printer_init (p11_list_printer *printer, FILE *fp, size_t depth)
{
	printer->fp = fp;
	printer->use_color = isatty (fileno (fp));
	printer->depth = depth;
}

static inline void
print_indent (FILE *fp, size_t depth)
{
	size_t i;

	for (i = 0; i < depth; ++i)
		fputs ("    ", fp);
}

void
p11_list_printer_start_section (p11_list_printer *printer,
			   const char *header,
			   const char *value_fmt,
			   ...)
{
	va_list args;

	return_if_fail (printer->depth < sizeof(header_colors) / sizeof(*header_colors));

	print_indent (printer->fp, printer->depth);

	if (printer->use_color) {
		fprintf (printer->fp, "\033[%s;1m%s\033[0m: ",
			 color_to_sgr (header_colors[printer->depth]),
			 header);
	} else {
		fprintf (printer->fp, "%s: ", header);
	}

	va_start (args, value_fmt);
	vfprintf (printer->fp, value_fmt, args);
	va_end (args);

	fputc ('\n', printer->fp);

	printer->depth++;
}

void
p11_list_printer_end_section (p11_list_printer *printer)
{
	printer->depth--;
}

void
p11_list_printer_write_value (p11_list_printer *printer,
			 const char *name,
			 const char *value_fmt,
			 ...)
{
	va_list args;

	print_indent (printer->fp, printer->depth);

	if (printer->use_color) {
		fprintf (printer->fp, "\033[0;1m%s\033[0m: ", name);
	} else {
		fprintf (printer->fp, "%s: ", name);
	}

	va_start (args, value_fmt);
	vfprintf (printer->fp, value_fmt, args);
	va_end (args);

	fputc ('\n', printer->fp);
}

void
p11_list_printer_write_array (p11_list_printer *printer,
			 const char *name,
			 const p11_array *array)
{
	size_t i;

	print_indent (printer->fp, printer->depth);

	if (printer->use_color) {
		fprintf (printer->fp, "\033[0;1m%s\033[0m: \n", name);
	} else {
		fprintf (printer->fp, "%s: \n", name);
	}

	for (i = 0; i < array->num; i++) {
		print_indent (printer->fp, printer->depth + 1);

		/* List elements are preceded by a couple of additional spaces */
		fprintf (printer->fp, "  %s\n", (const char *)array->elem[i]);
	}
}
