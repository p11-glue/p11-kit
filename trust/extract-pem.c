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

#define P11_DEBUG_FLAG P11_DEBUG_TOOL

#include "compat.h"
#include "debug.h"
#include "extract.h"
#include "message.h"
#include "path.h"
#include "pem.h"
#include "save.h"

#include <stdlib.h>

bool
p11_extract_pem_bundle (p11_enumerate *ex,
                        const char *destination)
{
	char *comment;
	p11_buffer buf;
	p11_save_file *file;
	bool ret = true;
	bool first = true;
	CK_RV rv;

	file = p11_save_open_file (destination, NULL, ex->flags);
	if (!file)
		return false;

	p11_buffer_init (&buf, 0);
	while ((rv = p11_kit_iter_next (ex->iter)) == CKR_OK) {
		if (!p11_buffer_reset (&buf, 2048))
			return_val_if_reached (false);

		if (!p11_pem_write (ex->cert_der, ex->cert_len, "CERTIFICATE", &buf))
			return_val_if_reached (false);

		comment = p11_enumerate_comment (ex, first);
		first = false;

		ret = p11_save_write (file, comment, -1) &&
		      p11_save_write (file, buf.data, buf.len);

		free (comment);

		if (!ret)
			break;
	}

	p11_buffer_uninit (&buf);

	if (rv != CKR_OK && rv != CKR_CANCEL) {
		p11_message ("failed to find certificates: %s", p11_kit_strerror (rv));
		ret = false;
	}

	/*
	 * This will produce an empty file (which is a valid PEM bundle) if no
	 * certificates were found.
	 */

	if (!p11_save_finish_file (file, NULL, ret))
		ret = false;

	return ret;
}

static bool
extract_pem_directory (p11_enumerate *ex,
                       const char *destination,
                       bool hash)
{
	p11_save_file *file;
	p11_save_dir *dir;
	p11_buffer buf;
	bool ret = true;
	char *filename;
	char *path;
	char *name;
	CK_RV rv;

	dir = p11_save_open_directory (destination, ex->flags);
	if (dir == NULL)
		return false;

	p11_buffer_init (&buf, 0);
	while ((rv = p11_kit_iter_next (ex->iter)) == CKR_OK) {
		if (!p11_buffer_reset (&buf, 2048))
			return_val_if_reached (false);

		if (!p11_pem_write (ex->cert_der, ex->cert_len, "CERTIFICATE", &buf))
			return_val_if_reached (false);

		name = p11_enumerate_filename (ex);
		return_val_if_fail (name != NULL, false);

		path = NULL;

		file = p11_save_open_file_in (dir, name, ".pem");
		ret = p11_save_write (file, buf.data, buf.len);

		if (!p11_save_finish_file (file, &path, ret))
			ret = false;

		if (ret && hash) {
			filename = p11_path_base (path);
			ret = p11_openssl_symlink(ex, dir, filename);
			free (filename);
		}

		free (path);
		free (name);
		if (!ret)
			break;
	}

	p11_buffer_uninit (&buf);

	if (rv != CKR_OK && rv != CKR_CANCEL) {
		p11_message ("failed to find certificates: %s", p11_kit_strerror (rv));
		ret = false;
	}

	p11_save_finish_directory (dir, ret);
	return ret;
}

bool
p11_extract_pem_directory (p11_enumerate *ex,
                           const char *destination)
{
	bool ret = true;
	ret = extract_pem_directory (ex, destination, false);
	return ret;
}

bool
p11_extract_pem_directory_hash (p11_enumerate *ex,
                           const char *destination)
{
	bool ret = true;
	ret = extract_pem_directory (ex, destination, true);
	return ret;
}
