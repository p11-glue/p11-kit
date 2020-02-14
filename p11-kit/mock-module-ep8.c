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

static const CK_SLOT_INFO MOCK_INFO_ONE = {
	"TEST SLOT                                                       ",
	"TEST MANUFACTURER               ",
	CKF_TOKEN_PRESENT | CKF_REMOVABLE_DEVICE,
	{ 55, 155 },
	{ 65, 165 },
};

/* Update mock-module.h URIs when updating this */

static const CK_SLOT_INFO MOCK_INFO_TWO = {
	"TEST SLOT                                                       ",
	"TEST MANUFACTURER               ",
	CKF_REMOVABLE_DEVICE,
	{ 55, 155 },
	{ 65, 165 },
};

static const CK_SLOT_INFO MOCK_INFO_THREE = {
	"TEST SLOT                                                       ",
	"TEST MANUFACTURER               ",
	CKF_TOKEN_PRESENT,
	{ 55, 155 },
	{ 65, 165 },
};

static const CK_TOKEN_INFO MOCK_TOKEN_ONE = {
	"TEST LABEL                      ",
	"TEST MANUFACTURER               ",
	"TEST MODEL      ",
	"TEST SERIAL     ",
	CKF_LOGIN_REQUIRED | CKF_USER_PIN_INITIALIZED | CKF_CLOCK_ON_TOKEN | CKF_TOKEN_INITIALIZED,
	1,
	2,
	3,
	4,
	5,
	6,
	7,
	8,
	9,
	10,
	{ 75, 175 },
	{ 85, 185 },
	{ '1', '9', '9', '9', '0', '5', '2', '5', '0', '9', '1', '9', '5', '9', '0', '0' }
};

static const CK_TOKEN_INFO MOCK_TOKEN_THREE = {
	"TEST LABEL                      ", // label[32]
	"TEST MANUFACTURER               ", // manufacturer_id[32]
	"TEST MODEL      ",                 // model[16]
	"1234567812345678",                 // serial[16]
	CKF_LOGIN_REQUIRED | CKF_USER_PIN_INITIALIZED | CKF_CLOCK_ON_TOKEN | CKF_TOKEN_INITIALIZED,
	1,                                  // max_session_count
	0,                                  // session_count
	1,                                  // max_rw_session_count
	0,                                  // rw_session_count
	16,                                  // max_pin_len
	4,                                  // min_pin_len
	4096,                               // total_public_memory
	0,                                  // free_public_memory
	4096,                               // total_private_memory
	0,                                  // free_private_memory
	{ 55, 155 },                        // hardware_version
	{ 65, 165 },                        // firmware_version
	{'1', '9', '9', '1', '0', '8', '2', '5', '2', '2', '5', '7', '0', '8', '0', '0'}
};

static CK_RV
override_get_slot_list (CK_BBOOL token_present,
                    CK_SLOT_ID_PTR slot_list,
                    CK_ULONG_PTR count)
{
	CK_ULONG num;

	if (count == NULL)
		return CKR_ARGUMENTS_BAD;

	num = token_present ? 2 : 3;

	/* Application only wants to know the number of slots. */
	if (slot_list == NULL) {
		*count = num;
		return CKR_OK;
	}

	if (*count < num)
		return CKR_BUFFER_TOO_SMALL;

	*count = num;
	slot_list[0] = MOCK_SLOT_ONE_ID;
	if (token_present) {
		slot_list[1] = MOCK_SLOT_THREE_ID;
	} else {
		slot_list[1] = MOCK_SLOT_TWO_ID;
		slot_list[2] = MOCK_SLOT_THREE_ID;
	}

	return CKR_OK;

}

static CK_RV
override_get_slot_info (CK_SLOT_ID slot_id,
                    CK_SLOT_INFO_PTR info)
{
	if (info == NULL)
		return CKR_ARGUMENTS_BAD;

	if (slot_id == MOCK_SLOT_ONE_ID) {
		memcpy (info, &MOCK_INFO_ONE, sizeof (*info));
		return CKR_OK;
	} else if (slot_id == MOCK_SLOT_TWO_ID) {
		memcpy (info, &MOCK_INFO_TWO, sizeof (*info));
		return CKR_OK;
	} else if (slot_id == MOCK_SLOT_THREE_ID) {
		memcpy (info, &MOCK_INFO_THREE, sizeof (*info));
		return CKR_OK;
	} else {
		return CKR_SLOT_ID_INVALID;
	}
}

static CK_RV
override_get_token_info (CK_SLOT_ID slot_id,
                     CK_TOKEN_INFO_PTR info)
{
	if (info == NULL)
		return CKR_ARGUMENTS_BAD;

	if (slot_id == MOCK_SLOT_ONE_ID) {
		memcpy (info, &MOCK_TOKEN_ONE, sizeof (*info));
		return CKR_OK;
	} else if (slot_id == MOCK_SLOT_TWO_ID) {
		return CKR_TOKEN_NOT_PRESENT;
	} else if (slot_id == MOCK_SLOT_THREE_ID) {
		memcpy (info, &MOCK_TOKEN_THREE, sizeof (*info));
		return CKR_OK;
	} else {
		return CKR_SLOT_ID_INVALID;
	}
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
	mock_module.C_GetSlotInfo= override_get_slot_info;
	mock_module.C_GetTokenInfo= override_get_token_info;
	*list = &mock_module;
	return CKR_OK;
}

