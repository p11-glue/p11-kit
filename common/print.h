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

#ifndef P11_PRINT_H_
#define P11_PRINT_H_

#include <stdio.h>
#include "array.h"

typedef enum {
	P11_COLOR_DEFAULT,
	P11_COLOR_BLACK,
	P11_COLOR_RED,
	P11_COLOR_GREEN,
	P11_COLOR_YELLOW,
	P11_COLOR_BLUE,
	P11_COLOR_MAGENTA,
	P11_COLOR_CYAN,
	P11_COLOR_WHITE
} p11_color;

typedef enum {
	P11_FONT_DEFAULT   = 0,
	P11_FONT_BOLD      = 1<<0,
	P11_FONT_UNDERLINE = 1<<1
} p11_font;

typedef struct {
	FILE *fp;
	bool use_color;
	size_t depth;
} p11_list_printer;

void p11_list_printer_init          (p11_list_printer *printer,
                                     FILE *fp,
                                     size_t depth);

void p11_list_printer_start_section (p11_list_printer *printer,
                                     const char *header,
                                     const char *value_fmt,
                                     ...);
void p11_list_printer_end_section   (p11_list_printer *printer);

void p11_list_printer_write_value   (p11_list_printer *printer,
                                     const char *name,
                                     const char *value_fmt,
                                     ...);

void p11_list_printer_write_array   (p11_list_printer *printer,
                                     const char *name,
                                     const p11_array *array);

void p11_highlight_word             (FILE *fp,
                                     const char *string);

void p11_print_word                 (FILE *fp,
                                     const char *string,
                                     p11_color color,
                                     p11_font font);

#endif /* P11_PRINT_H_ */
