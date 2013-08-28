/*
 * Copyright (c) 2013, Red Hat Inc.
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

#include "compat.h"
#include "debug.h"
#include "extract.h"
#include "message.h"
#include "save.h"

#include <stdlib.h>

bool
p11_extract_x509_file (p11_enumerate *ex,
                       const char *destination)
{
	bool found = false;
	p11_save_file *file;
	CK_RV rv;

	while ((rv = p11_kit_iter_next (ex->iter)) == CKR_OK) {
		if (found) {
			p11_message ("multiple certificates found but could only write one to file");
			break;
		}

		file = p11_save_open_file (destination, NULL, ex->flags);
		if (!p11_save_write_and_finish (file, ex->cert_der, ex->cert_len))
			return false;

		/* Wrote something */
		found = true;
	}

	if (rv != CKR_OK && rv != CKR_CANCEL) {
		p11_message ("failed to find certificates: %s", p11_kit_strerror (rv));
		return false;

	/* Remember that an empty DER file is not a valid file, so complain if nothing */
	} else if (!found) {
		p11_message ("no certificate found");
		return false;
	}

	return true;
}

bool
p11_extract_x509_directory (p11_enumerate *ex,
                            const char *destination)
{
	p11_save_file *file;
	p11_save_dir *dir;
	char *filename;
	CK_RV rv;
	bool ret;

	dir = p11_save_open_directory (destination, ex->flags);
	if (dir == NULL)
		return false;

	while ((rv = p11_kit_iter_next (ex->iter)) == CKR_OK) {
		filename = p11_enumerate_filename (ex);
		return_val_if_fail (filename != NULL, -1);

		file = p11_save_open_file_in (dir, filename, ".cer");
		free (filename);

		if (!p11_save_write_and_finish (file, ex->cert_der, ex->cert_len)) {
			p11_save_finish_directory (dir, false);
			return false;
		}
	}

	if (rv != CKR_OK && rv != CKR_CANCEL) {
		p11_message ("failed to find certificates: %s", p11_kit_strerror (rv));
		ret = false;
	} else {
		ret = true;
	}

	p11_save_finish_directory (dir, ret);
	return ret;
}
