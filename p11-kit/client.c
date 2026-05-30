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
#include "debug.h"
#include "library.h"
#include "runtime.h"
#include "path.h"
#include "rpc.h"

#ifndef OS_WIN32
#include <pwd.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct _State {
	p11_virtual virt;
	p11_rpc_transport *rpc;
	CK_INTERFACE wrapped;
	struct _State *next;
} State;

static State *all_instances = NULL;

static char *server_address_from_interface = NULL;

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

		free (server_address_from_interface);
		server_address_from_interface = NULL;

		return CKR_OK;
	}

	if (server_address_from_interface) {
		*addressp = server_address_from_interface;
		server_address_from_interface = NULL;
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

/*
 * A hidden vendor interface to externally set server socket address.
 */
static const char p11_client_interface_name[] = P11_CLIENT_INTERFACE_NAME;

static void set_server_address (const char *server_address) {
	server_address_from_interface = strdup (server_address);
}

static const struct p11_client_function_list p11_client_function_list = {
	{ 0, 0 },
	set_server_address,
};

static const CK_INTERFACE p11_client_interface = {
	(char *)p11_client_interface_name,
	(void *)&p11_client_function_list,
	0,
};

static const char p11_interface_name[] = "PKCS 11";

static const CK_VERSION version_two = {
	CRYPTOKI_LEGACY_VERSION_MAJOR,
	CRYPTOKI_LEGACY_VERSION_MINOR
};

static const CK_VERSION version_three = {
	CRYPTOKI_VERSION_MAJOR,
	CRYPTOKI_VERSION_MINOR
};

/* We are not going to support any special interfaces */
#define NUM_INTERFACES 2

static CK_RV
get_interface_inlock(CK_INTERFACE **interface, const CK_VERSION *version, CK_FLAGS flags)
{
	char *address = NULL;
	State *state = NULL;
	CK_FUNCTION_LIST_PTR module = NULL;
	CK_RV rv;

	return_val_if_fail (interface, CKR_ARGUMENTS_BAD);
	return_val_if_fail (version, CKR_ARGUMENTS_BAD);

	if (memcmp (version, &version_three, sizeof(*version)) != 0 &&
	    memcmp (version, &version_two, sizeof(*version)) != 0)
		return CKR_ARGUMENTS_BAD;

	rv = get_server_address (&address);
	if (rv != CKR_OK)
		goto cleanup;

	state = calloc (1, sizeof (State));
	if (!state) {
		rv = CKR_HOST_MEMORY;
		goto cleanup;
	}

	state->rpc = p11_rpc_transport_new (&state->virt, address, "client");
	if (!state->rpc) {
		rv = CKR_GENERAL_ERROR;
		goto cleanup;
	}

	/* Version must be set before calling p11_virtual_wrap, as it
	 * is used to determine which functions are wrapped with
	 * libffi closures.
	 */
	state->virt.funcs.version = *version;

	module = p11_virtual_wrap (&state->virt,
				   (p11_destroyer)p11_virtual_uninit);
	if (!module) {
		rv = CKR_GENERAL_ERROR;
		goto cleanup;
	}

	module->version = *version;

	state->wrapped.pInterfaceName = (char *)p11_interface_name;

	state->wrapped.pFunctionList = (CK_FUNCTION_LIST_3_2 *)module;
	module = NULL;

	state->wrapped.flags = flags;

	*interface = &state->wrapped;

	state->next = all_instances;
	all_instances = state;
	state = NULL;

 cleanup:
	if (module)
		p11_virtual_unwrap (module);
	if (state) {
		if (state->wrapped.pFunctionList)
			p11_virtual_unwrap (state->wrapped.pFunctionList);
		p11_rpc_transport_free (state->rpc);
		free (state);
	}
	free (address);
	return rv;
}

#ifdef OS_WIN32
__declspec(dllexport)
#endif
CK_RV
C_GetFunctionList (CK_FUNCTION_LIST_PTR_PTR list)
{
	CK_RV rv = CKR_OK;
	CK_INTERFACE *res = NULL;

	p11_library_init_once ();
	p11_lock ();

	rv = get_interface_inlock (&res, &version_two, 0);
	if (rv == CKR_OK)
		*list = res->pFunctionList;

	p11_unlock ();

	return rv;
}

#ifdef OS_WIN32
__declspec(dllexport)
#endif
CK_RV
C_GetInterfaceList (CK_INTERFACE_PTR pInterfacesList, CK_ULONG_PTR pulCount)
{
	CK_RV rv = CKR_OK;
	CK_INTERFACE *interfaces[NUM_INTERFACES];
	CK_ULONG count = 0;
	CK_ULONG i;

	if (pulCount == NULL_PTR)
		return CKR_ARGUMENTS_BAD;

	if (pInterfacesList == NULL_PTR) {
		*pulCount = NUM_INTERFACES;
		return CKR_OK;
	}

	if (*pulCount < NUM_INTERFACES) {
		*pulCount = NUM_INTERFACES;
		return CKR_BUFFER_TOO_SMALL;
	}

	p11_library_init_once ();
	p11_lock ();

	rv = get_interface_inlock (&interfaces[count++], &version_three, 0);
	if (rv != CKR_OK)
		goto cleanup;

	rv = get_interface_inlock (&interfaces[count++], &version_two, 0);
	if (rv != CKR_OK)
		goto cleanup;

	for (i = 0; i < count; i++)
		pInterfacesList[i] = *interfaces[i];
	*pulCount = count;

 cleanup:
	p11_unlock ();

	return rv;
}

#ifdef OS_WIN32
__declspec(dllexport)
#endif
CK_RV
C_GetInterface (CK_UTF8CHAR_PTR pInterfaceName, CK_VERSION_PTR pVersion,
                CK_INTERFACE_PTR_PTR ppInterface, CK_FLAGS flags)
{
	int rv;

	if (ppInterface == NULL) {
		return CKR_ARGUMENTS_BAD;
	}

	if (pInterfaceName) {
		if (strcmp ((const char *)pInterfaceName, p11_client_interface_name) == 0) {
			*ppInterface = (CK_INTERFACE_PTR)&p11_client_interface;
			return CKR_OK;
		} else if (strcmp ((const char *)pInterfaceName, p11_interface_name) == 0) {
			/* fall through */
		} else {
			return CKR_ARGUMENTS_BAD;
		}
	}

	p11_library_init_once ();
	p11_lock ();

	rv = get_interface_inlock (ppInterface,
				   pVersion ? pVersion : &version_three,
				   flags);

	p11_unlock ();

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
		p11_virtual_unwrap (state->wrapped.pFunctionList);
		free (state);
	}
}
