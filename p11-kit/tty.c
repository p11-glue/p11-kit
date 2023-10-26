/*
 * Copyright (c) 2023, Red Hat Inc.
 *
 * All rights reserved.
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

#include "tty.h"
#include "compat.h"
#include "debug.h"
#include "message.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_PIN_LEN 256

P11KitPin *
p11_pin_tty_callback (const char *pin_source,
		      P11KitUri *pin_uri,
		      const char *pin_description,
		      P11KitPinFlags pin_flags,
		      void *callback_data)
{
	char buf[MAX_PIN_LEN], *prompt = NULL;
	P11KitPin *pin = NULL;

	return_val_if_fail (pin_description != NULL, NULL);

	/* We don't support retries */
	if (pin_flags & P11_KIT_PIN_FLAGS_RETRY)
		return NULL;

	if (asprintf (&prompt, "%s: ", pin_description) < 0)
		return NULL;

	if (readpassphrase (prompt, buf, sizeof(buf), 0) == NULL)
		goto cleanup;

	pin = p11_kit_pin_new_for_string (buf);

 cleanup:
	free (prompt);
	memset (buf, 0, sizeof(buf));
	return pin;
}
