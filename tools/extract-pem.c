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
#include "library.h"
#include "pem.h"
#include "save.h"

#include <stdlib.h>

bool
p11_extract_pem_bundle (P11KitIter *iter,
                        p11_extract_info *ex)
{
	p11_save_file *file;
	bool ret = true;
	size_t length;
	CK_RV rv;
	char *pem;

	file = p11_save_open_file (ex->destination, ex->flags);
	if (!file)
		return false;

	while ((rv = p11_kit_iter_next (iter)) == CKR_OK) {
		pem = p11_pem_write (ex->cert_der, ex->cert_len, "CERTIFICATE", &length);
		return_val_if_fail (pem != NULL, false);

		ret = p11_save_write (file, pem, length);
		free (pem);

		if (!ret)
			break;
	}

	if (rv != CKR_OK && rv != CKR_CANCEL) {
		p11_message ("failed to find certificates: %s", p11_kit_strerror (rv));
		ret = false;
	}

	/*
	 * This will produce an empty file (which is a valid PEM bundle) if no
	 * certificates were found.
	 */

	p11_save_finish_file (file, ret);
	return ret;
}

bool
p11_extract_pem_directory (P11KitIter *iter,
                           p11_extract_info *ex)
{
	p11_save_file *file;
	p11_save_dir *dir;
	bool ret = true;
	char *filename;
	size_t length;
	char *pem;
	CK_RV rv;

	dir = p11_save_open_directory (ex->destination, ex->flags);
	if (dir == NULL)
		return false;

	while ((rv = p11_kit_iter_next (iter)) == CKR_OK) {
		pem = p11_pem_write (ex->cert_der, ex->cert_len, "CERTIFICATE", &length);
		return_val_if_fail (pem != NULL, false);

		filename = p11_extract_info_filename (ex);
		return_val_if_fail (filename != NULL, false);

		file = p11_save_open_file_in (dir, filename, ".pem", NULL);
		free (filename);

		ret = p11_save_write_and_finish (file, pem, length);
		free (pem);

		if (!ret)
			break;
	}

	if (rv != CKR_OK && rv != CKR_CANCEL) {
		p11_message ("failed to find certificates: %s", p11_kit_strerror (rv));
		ret = false;
	}

	p11_save_finish_directory (dir, ret);
	return ret;
}
