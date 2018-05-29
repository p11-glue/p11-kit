/*
 * Copyright (c) 2018 Red Hat Inc
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

#include "runtime.h"

#include "compat.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef OS_UNIX
#include <pwd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static const char * const _p11_runtime_bases_default[] = { "/run", "/var/run", NULL };
const char * const *_p11_runtime_bases = _p11_runtime_bases_default;
#endif

CK_RV
p11_get_runtime_directory (char **directoryp)
{
	const char *envvar;
	char *directory;
#ifdef OS_UNIX
	const char * const *bases = _p11_runtime_bases;
	char *prefix;
	uid_t uid;
	struct stat sb;
	struct passwd pwbuf, *pw;
	char buf[1024];
	int i;
#endif

	/* We can't always assume the XDG_RUNTIME_DIR envvar here,
	 * because the PKCS#11 module can be loaded by a program that
	 * calls setuid().  */
	envvar = secure_getenv ("XDG_RUNTIME_DIR");

	if (envvar != NULL && envvar[0] != '\0') {
		directory = strdup (envvar);
		if (!directory)
			return CKR_HOST_MEMORY;

		*directoryp = directory;
		return CKR_OK;
	}

#ifdef OS_UNIX
	uid = getuid ();

	for (i = 0; bases[i] != NULL; i++) {
		if (asprintf (&prefix, "%s/user/%u",
			      bases[i], (unsigned int) uid) < 0)
			return CKR_HOST_MEMORY;
		if (stat (prefix, &sb) != -1 && S_ISDIR (sb.st_mode)) {
			*directoryp = prefix;
			return CKR_OK;
		}
		free (prefix);
	}
#endif

	/* We can't use /run/user/<UID>, fallback to ~/.cache.  */
	envvar = secure_getenv ("XDG_CACHE_HOME");

	if (envvar != NULL && envvar[0] != '\0') {
		directory = strdup (envvar);
		if (!directory)
			return CKR_HOST_MEMORY;

		*directoryp = directory;
		return CKR_OK;
	}

#ifdef OS_UNIX
	if (getpwuid_r (uid, &pwbuf, buf, sizeof buf, &pw) == 0 &&
	    pw != NULL && pw->pw_dir != NULL && *pw->pw_dir == '/') {
		if (asprintf (&directory, "%s/.cache", pw->pw_dir) < 0)
			return CKR_HOST_MEMORY;
		*directoryp = directory;
		return CKR_OK;
	}
#endif

	return CKR_GENERAL_ERROR;
}
