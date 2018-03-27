/*
 * Copyright (c) 2012 Stefan Walter
 * Copyright (c) 2018 Red Hat, Inc.
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
 * Author: Stef Walter <stef@thewalter.net>, Daiki Ueno
 */

#include "config.h"

#define CRYPTOKI_EXPORTS 1
#include "pkcs11.h"

#include "mock.h"
#include "test.h"

static bool initialized = false;

static CK_RV
override_initialize (CK_VOID_PTR init_args)
{
	CK_RV rv;

	if (initialized)
		return CKR_CRYPTOKI_ALREADY_INITIALIZED;
	rv = mock_C_Initialize (init_args);
	if (rv == CKR_OK)
		initialized = true;
	return rv;
}

static CK_RV
override_finalize (CK_VOID_PTR reserved)
{
	initialized = false;
	return mock_C_Finalize (reserved);
}

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
	mock_module.C_Initialize = override_initialize;
	mock_module.C_Finalize = override_finalize;
	*list = &mock_module;
	return CKR_OK;
}
