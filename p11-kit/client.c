/*
 * Copyright (C) 2016 Red Hat Inc.
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

#include "client.h"
#include "compat.h"
#include "library.h"
#include "path.h"
#include "rpc.h"

#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct _State {
	p11_virtual virt;
	p11_rpc_transport *rpc;
	CK_FUNCTION_LIST *wrapped;
	struct _State *next;
} State;

static State *all_instances = NULL;

static CK_RV
get_runtime_directory (char **directoryp)
{
	const char *envvar;
	static const char * const bases[] = { "/run", "/var/run", NULL };
	char prefix[13 + 1 + 20 + 6 + 1];
	char *directory;
	uid_t uid;
	struct stat sb;
	struct passwd pwbuf, *pw;
	char buf[1024];
	int i;

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

	uid = getuid ();

	for (i = 0; bases[i] != NULL; i++) {
		snprintf (prefix, sizeof prefix, "%s/user/%u",
			  bases[i], (unsigned int) uid);
		if (stat (prefix, &sb) != -1 && S_ISDIR (sb.st_mode)) {
			directory = strdup (prefix);
			if (!directory)
				return CKR_HOST_MEMORY;
			*directoryp = directory;
			return CKR_OK;
		}
	}

	/* We can't use /run/user/<UID>, fallback to ~/.cache.  */
	envvar = secure_getenv ("XDG_CACHE_HOME");

	if (envvar != NULL && envvar[0] != '\0') {
		directory = strdup (envvar);
		if (!directory)
			return CKR_HOST_MEMORY;

		*directoryp = directory;
		return CKR_OK;
	}

	if (getpwuid_r (uid, &pwbuf, buf, sizeof buf, &pw) < 0 ||
	    pw == NULL || pw->pw_dir == NULL || *pw->pw_dir != '/')
		return CKR_GENERAL_ERROR;

	if (asprintf (&directory, "%s/.cache", pw->pw_dir) < 0)
		return CKR_HOST_MEMORY;
	*directoryp = directory;
	return CKR_OK;
}

static CK_RV
get_server_address (char **addressp)
{
	const char *envvar;
	char *path;
	char *encoded;
	char *address;
	char *directory;
	int ret;
	CK_RV rv;

	envvar = secure_getenv ("P11_KIT_SERVER_ADDRESS");
	if (envvar != NULL && envvar[0] != '\0') {
		address = strdup (envvar);
		if (!address)
			return CKR_HOST_MEMORY;
		*addressp = address;
		return CKR_OK;
	}

	rv = get_runtime_directory (&directory);
	if (rv != CKR_OK)
		return rv;

	ret = asprintf (&path, "%s/p11-kit/pkcs11", directory);
	free (directory);
	if (ret < 0)
		return CKR_HOST_MEMORY;

	encoded = p11_path_encode (path);
	free (path);
	if (!encoded)
		return CKR_HOST_MEMORY;

	ret = asprintf (&address, "unix:path=%s", encoded);
	free (encoded);
	if (ret < 0)
		return CKR_HOST_MEMORY;

	*addressp = address;
	return CKR_OK;
}

#ifdef OS_WIN32
__declspec(dllexport)
#endif
CK_RV
C_GetFunctionList (CK_FUNCTION_LIST_PTR_PTR list)
{
	char *address = NULL;
	State *state;
	CK_FUNCTION_LIST_PTR module = NULL;
	CK_RV rv = CKR_OK;

	p11_library_init_once ();
	p11_lock ();

	rv = get_server_address (&address);

	if (rv == CKR_OK) {
		state = calloc (1, sizeof (State));
		if (!state)
			rv = CKR_HOST_MEMORY;
	}

	if (rv == CKR_OK) {
		state->rpc = p11_rpc_transport_new (&state->virt,
						    address,
						    "client");
		if (!state->rpc)
			rv = CKR_GENERAL_ERROR;
	}

	if (rv == CKR_OK) {
		module = p11_virtual_wrap (&state->virt, free);
		if (!module)
			rv = CKR_GENERAL_ERROR;
	}

	if (rv == CKR_OK) {
		*list = module;
		state->wrapped = module;
		state->next = all_instances;
		all_instances = state;
	}

	p11_unlock ();

	free (address);

	return rv;
}

void
p11_client_module_cleanup (void)
{
	State *state, *next;

	state = all_instances;
	all_instances = NULL;

	for (; state != NULL; state = next) {
		next = state->next;
		p11_virtual_unwrap (state->wrapped);
		p11_rpc_transport_free (state->rpc);
	}
}
