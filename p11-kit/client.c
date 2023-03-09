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
#include "runtime.h"
#include "path.h"
#include "rpc.h"

#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct _State {
	p11_virtual virt;
	p11_rpc_transport *rpc;
	CK_FUNCTION_LIST_3_0 *wrapped;
	struct _State *next;
} State;

static State *all_instances = NULL;
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

	rv = p11_get_runtime_directory (&directory);
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
		if (!state->rpc) {
			free (state);
			rv = CKR_GENERAL_ERROR;
		}
	}

	if (rv == CKR_OK) {
		module = p11_virtual_wrap (&state->virt, (p11_destroyer)p11_virtual_uninit);
		if (!module) {
			p11_rpc_transport_free (state->rpc);
			free (state);
			rv = CKR_GENERAL_ERROR;
		}
	}

	if (rv == CKR_OK) {
		*list = module;
		state->wrapped = (CK_FUNCTION_LIST_3_0 *)module;
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
		p11_rpc_transport_free (state->rpc);
		p11_virtual_unwrap ((CK_FUNCTION_LIST *)state->wrapped);
		free (state);
	}
}
