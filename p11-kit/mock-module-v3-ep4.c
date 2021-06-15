/*
 * Copyright (c) 2012 Stefan Walter
 * Copyright (c) 2021-2022 Red Hat, Inc.
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
 * Authors: Stef Walter <stef@thewalter.net>
 *          Jakub Jelen <jjelen@redhat.com>
 */

#include "config.h"

#define CRYPTOKI_EXPORTS 1
#include "pkcs11.h"

#include "mock.h"

#include <unistd.h>
#include <string.h>

static pid_t init_pid;

static CK_RV
override_initialize (CK_VOID_PTR init_args)
{
	if (init_pid != getpid ())
		return CKR_GENERAL_ERROR;
	return mock_C_Initialize (init_args);
}

/* Present for backward compatibibility */
#ifdef OS_WIN32
__declspec(dllexport)
#endif
CK_RV
C_GetFunctionList (CK_FUNCTION_LIST_PTR_PTR list)
{
	mock_module_init ();
	mock_module.C_GetFunctionList = C_GetFunctionList;
	if (list == NULL)
		return CKR_ARGUMENTS_BAD;
	init_pid = getpid ();
	mock_module.C_Initialize = override_initialize;
	*list = &mock_module;
	return CKR_OK;
}

static void mock_initialize_interface (void)
{
	mock_module_init ();
	mock_module_v3.C_Initialize = override_initialize;
	mock_module_v3.C_GetFunctionList = C_GetFunctionList;
	mock_module_v3.C_GetInterfaceList = C_GetInterfaceList;
	mock_module_v3.C_GetInterface = C_GetInterface;
}

#ifdef OS_WIN32
__declspec(dllexport)
#endif
CK_RV
C_GetInterfaceList (CK_INTERFACE_PTR pInterfacesList, CK_ULONG_PTR pulCount)
{
	mock_initialize_interface ();

	if (pulCount == NULL_PTR)
		return CKR_ARGUMENTS_BAD;

	if (pInterfacesList == NULL_PTR) {
		*pulCount = MOCK_INTERFACES;
		return CKR_OK;
	}

	if (*pulCount < MOCK_INTERFACES) {
		*pulCount = MOCK_INTERFACES;
		return CKR_BUFFER_TOO_SMALL;
	}

	memcpy (pInterfacesList, mock_interfaces, MOCK_INTERFACES * sizeof(CK_INTERFACE));
	*pulCount = MOCK_INTERFACES;

	return CKR_OK;
}

#ifdef OS_WIN32
__declspec(dllexport)
#endif
CK_RV
C_GetInterface (CK_UTF8CHAR_PTR pInterfaceName, CK_VERSION_PTR pVersion,
                CK_INTERFACE_PTR_PTR ppInterface, CK_FLAGS flags)
{
	int i;

	mock_initialize_interface ();

	if (ppInterface == NULL) {
		return CKR_ARGUMENTS_BAD;
	}

	if (pInterfaceName == NULL_PTR) {
		/* return default interface */
		*ppInterface = &mock_interfaces[0];
		return CKR_OK;
	}

	for (i = 0; i < MOCK_INTERFACES; i++) {
		/* Version is the first member of CK_FUNCTION_LIST */
		CK_VERSION_PTR interface_version = (CK_VERSION_PTR)mock_interfaces[i].pFunctionList;

		/* The interface name is not null here */
		if (strcmp ((char *)pInterfaceName, mock_interfaces[i].pInterfaceName) != 0) {
			continue;
		}
		/* If version is not null, it must match */
		if (pVersion != NULL_PTR && (pVersion->major != interface_version->major ||
		    pVersion->minor != interface_version->minor)) {
			continue;
		}
		/* If any flags specified, it must be supported by the interface */
		if ((flags & mock_interfaces[i].flags) != flags) {
			continue;
		}
		*ppInterface = &mock_interfaces[i];
		return CKR_OK;
	}

	return CKR_ARGUMENTS_BAD;
}
