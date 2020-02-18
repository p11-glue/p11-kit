/*
 * Copyright (c) 2012 Stefan Walter
 * Copyright (c) 2020 Red Hat, Inc.
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
 * Author: Stef Walter <stef@thewalter.net>, Daiki Ueno, Anderson Sasaki
 */

#include "config.h"

#define CRYPTOKI_EXPORTS 1
#include "pkcs11.h"

#include "mock.h"
#include "test.h"

#define MOCK_SLOT_THREE_ID 792

/* Update mock-module.h URIs when updating this */

static int called = 0;
static CK_SLOT_ID last_id = 1;

static CK_RV
override_get_slot_list (CK_BBOOL token_present,
                    CK_SLOT_ID_PTR slot_list,
                    CK_ULONG_PTR count)
{
	if (count == NULL)
		return CKR_ARGUMENTS_BAD;

	/* For odd numbered calls, the module will return 1 slot with a slot ID
	 * returned previously.
	 *
	 * For even numbered calls, the module will return 2 slots, being the new
	 * slot put first in the list */
	if (called % 2) {
		if (slot_list == NULL) {
			*count = 1;
			return CKR_OK;
		}
		if (*count < 1) {
			return CKR_BUFFER_TOO_SMALL;
		}

		slot_list[0] = last_id;
		*count = 1;
	} else {
		if (slot_list == NULL) {
			*count = 2;
			return CKR_OK;
		}

		if (*count < 2) {
			return CKR_BUFFER_TOO_SMALL;
		}

		slot_list[1] = last_id;
		slot_list[0] = ++last_id;

		*count = 2;
	}

	++called;

	return CKR_OK;
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
	mock_module.C_GetSlotList= override_get_slot_list;
	*list = &mock_module;
	return CKR_OK;
}

