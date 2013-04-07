/*
 * Copyright (C) 2012 Red Hat Inc.
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
 * Author: Stef Walter <stefw@redhat.com>
 */

#include "config.h"

#include "argv.h"
#include "debug.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

bool
p11_argv_parse (const char *string,
                void (*sink) (char *, void *),
                void *argument)
{
	char quote = '\0';
	char *src, *dup, *at, *arg;
	bool ret = true;

	return_val_if_fail (string != NULL, false);
	return_val_if_fail (sink != NULL, false);

	src = dup = strdup (string);
	return_val_if_fail (dup != NULL, false);

	arg = at = src;
	for (src = dup; *src; src++) {

		/* Matching quote */
		if (quote == *src) {
			quote = '\0';

		/* Inside of quotes */
		} else if (quote != '\0') {
			if (*src == '\\') {
				*at++ = *src++;
				if (!*src) {
					ret = false;
					goto done;
				}
				if (*src != quote)
					*at++ = '\\';
			}
			*at++ = *src;

		/* Space, not inside of quotes */
		} else if (isspace (*src)) {
			*at = 0;
			sink (arg, argument);
			arg = at;

		/* Other character outside of quotes */
		} else {
			switch (*src) {
			case '\'':
			case '"':
				quote = *src;
				break;
			case '\\':
				*at++ = *src++;
				if (!*src) {
					ret = false;
					goto done;
				}
			/* fall through */
			default:
				*at++ = *src;
				break;
			}
		}
	}


	if (at != arg) {
		*at = 0;
		sink (arg, argument);
	}

done:
	free (dup);
	return ret;
}
