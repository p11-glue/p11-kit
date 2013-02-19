/*
 * Copyright (c) 2012 Stefan Walter
 * Copyright (c) 2012-2013 Red Hat Inc.
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
 * Author: Stef Walter <stef@thewalter.net>
 */

#include "CuTest.h"

#include "library.h"
#include "mock.h"
#include "p11-kit.h"

#include <sys/types.h>
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

static void
test_get_info (CuTest *tc)
{
	CK_FUNCTION_LIST_PTR module;
	CK_INFO info;
	CK_RV rv;

	module = setup_mock_module (tc, NULL);

	rv = (module->C_GetInfo) (&info);
	CuAssertTrue (tc, rv == CKR_OK);
	CuAssertTrue (tc, memcmp (&info, &MOCK_INFO, sizeof (CK_INFO)) == 0);

	teardown_mock_module (tc, module);
}

static void
test_get_slot_list (CuTest *tc)
{
	CK_FUNCTION_LIST_PTR module;
	CK_SLOT_ID slot_list[8];
	CK_ULONG count = 0;
	CK_RV rv;

	module = setup_mock_module (tc, NULL);

	/* Normal module has 2 slots, one with token present */
	rv = (module->C_GetSlotList) (CK_TRUE, NULL, &count);
	CuAssertTrue (tc, rv == CKR_OK);
	CuAssertIntEquals (tc, MOCK_SLOTS_PRESENT, count);
	rv = (module->C_GetSlotList) (CK_FALSE, NULL, &count);
	CuAssertTrue (tc, rv == CKR_OK);
	CuAssertIntEquals (tc, MOCK_SLOTS_ALL, count);

	count = 8;
	rv = (module->C_GetSlotList) (CK_TRUE, slot_list, &count);
	CuAssertTrue (tc, rv == CKR_OK);
	CuAssertIntEquals (tc, MOCK_SLOTS_PRESENT, count);
	CuAssertIntEquals (tc, MOCK_SLOT_ONE_ID, slot_list[0]);

	count = 8;
	rv = (module->C_GetSlotList) (CK_FALSE, slot_list, &count);
	CuAssertTrue (tc, rv == CKR_OK);
	CuAssertIntEquals (tc, MOCK_SLOTS_ALL, count);
	CuAssertIntEquals (tc, MOCK_SLOT_ONE_ID, slot_list[0]);
	CuAssertIntEquals (tc, MOCK_SLOT_TWO_ID, slot_list[1]);

	teardown_mock_module (tc, module);
}

static void
test_get_slot_info (CuTest *tc)
{
	CK_FUNCTION_LIST_PTR module;
	CK_SLOT_INFO info;
	char *string;
	CK_RV rv;

	module = setup_mock_module (tc, NULL);

	rv = (module->C_GetSlotInfo) (MOCK_SLOT_ONE_ID, &info);
	CuAssertTrue (tc, rv == CKR_OK);
	string = p11_kit_space_strdup (info.slotDescription, sizeof (info.slotDescription));
	CuAssertStrEquals (tc, "TEST SLOT", string);
	free (string);
	string = p11_kit_space_strdup (info.manufacturerID, sizeof (info.manufacturerID));
	CuAssertStrEquals (tc, "TEST MANUFACTURER", string);
	free (string);
	CuAssertIntEquals (tc, CKF_TOKEN_PRESENT | CKF_REMOVABLE_DEVICE, info.flags);
	CuAssertIntEquals (tc, 55, info.hardwareVersion.major);
	CuAssertIntEquals (tc, 155, info.hardwareVersion.minor);
	CuAssertIntEquals (tc, 65, info.firmwareVersion.major);
	CuAssertIntEquals (tc, 165, info.firmwareVersion.minor);

	rv = (module->C_GetSlotInfo) (MOCK_SLOT_TWO_ID, &info);
	CuAssertTrue (tc, rv == CKR_OK);
	CuAssertIntEquals (tc, CKF_REMOVABLE_DEVICE, info.flags);

	rv = (module->C_GetSlotInfo) (0, &info);
	CuAssertTrue (tc, rv == CKR_SLOT_ID_INVALID);

	teardown_mock_module (tc, module);
}

static void
test_get_token_info (CuTest *tc)
{
	CK_FUNCTION_LIST_PTR module;
	CK_TOKEN_INFO info;
	char *string;
	CK_RV rv;

	module = setup_mock_module (tc, NULL);

	rv = (module->C_GetTokenInfo) (MOCK_SLOT_ONE_ID, &info);
	CuAssertTrue (tc, rv == CKR_OK);

	string = p11_kit_space_strdup (info.label, sizeof (info.label));
	CuAssertStrEquals (tc, "TEST LABEL", string);
	free (string);
	string = p11_kit_space_strdup (info.manufacturerID, sizeof (info.manufacturerID));
	CuAssertStrEquals (tc, "TEST MANUFACTURER", string);
	free (string);
	string = p11_kit_space_strdup (info.model, sizeof (info.model));
	CuAssertStrEquals (tc, "TEST MODEL", string);
	free (string);
	string = p11_kit_space_strdup (info.serialNumber, sizeof (info.serialNumber));
	CuAssertStrEquals (tc, "TEST SERIAL", string);
	free (string);
	CuAssertIntEquals (tc, CKF_LOGIN_REQUIRED | CKF_USER_PIN_INITIALIZED | CKF_CLOCK_ON_TOKEN | CKF_TOKEN_INITIALIZED, info.flags);
	CuAssertIntEquals (tc, 1, info.ulMaxSessionCount);
	CuAssertIntEquals (tc, 2, info.ulSessionCount);
	CuAssertIntEquals (tc, 3, info.ulMaxRwSessionCount);
	CuAssertIntEquals (tc, 4, info.ulRwSessionCount);
	CuAssertIntEquals (tc, 5, info.ulMaxPinLen);
	CuAssertIntEquals (tc, 6, info.ulMinPinLen);
	CuAssertIntEquals (tc, 7, info.ulTotalPublicMemory);
	CuAssertIntEquals (tc, 8, info.ulFreePublicMemory);
	CuAssertIntEquals (tc, 9, info.ulTotalPrivateMemory);
	CuAssertIntEquals (tc, 10, info.ulFreePrivateMemory);
	CuAssertIntEquals (tc, 75, info.hardwareVersion.major);
	CuAssertIntEquals (tc, 175, info.hardwareVersion.minor);
	CuAssertIntEquals (tc, 85, info.firmwareVersion.major);
	CuAssertIntEquals (tc, 185, info.firmwareVersion.minor);
	CuAssertTrue (tc, memcmp (info.utcTime, "1999052509195900", sizeof (info.utcTime)) == 0);

	rv = (module->C_GetTokenInfo) (MOCK_SLOT_TWO_ID, &info);
	CuAssertTrue (tc, rv == CKR_TOKEN_NOT_PRESENT);

	rv = (module->C_GetTokenInfo) (0, &info);
	CuAssertTrue (tc, rv == CKR_SLOT_ID_INVALID);

	teardown_mock_module (tc, module);
}

static void
test_get_mechanism_list (CuTest *tc)
{
	CK_FUNCTION_LIST_PTR module;
	CK_MECHANISM_TYPE mechs[8];
	CK_ULONG count = 0;
	CK_RV rv;

	module = setup_mock_module (tc, NULL);

	rv = (module->C_GetMechanismList) (MOCK_SLOT_ONE_ID, NULL, &count);
	CuAssertTrue (tc, rv == CKR_OK);
	CuAssertIntEquals (tc, 2, count);
	rv = (module->C_GetMechanismList) (MOCK_SLOT_TWO_ID, NULL, &count);
	CuAssertTrue (tc, rv == CKR_TOKEN_NOT_PRESENT);
	rv = (module->C_GetMechanismList) (0, NULL, &count);
	CuAssertTrue (tc, rv == CKR_SLOT_ID_INVALID);

	count = 8;
	rv = (module->C_GetMechanismList) (MOCK_SLOT_ONE_ID, mechs, &count);
	CuAssertTrue (tc, rv == CKR_OK);
	CuAssertIntEquals (tc, 2, count);
	CuAssertIntEquals (tc, mechs[0], CKM_MOCK_CAPITALIZE);
	CuAssertIntEquals (tc, mechs[1], CKM_MOCK_PREFIX);

	teardown_mock_module (tc, module);
}

static void
test_get_mechanism_info (CuTest *tc)
{
	CK_FUNCTION_LIST_PTR module;
	CK_MECHANISM_INFO info;
	CK_RV rv;

	module = setup_mock_module (tc, NULL);

	rv = (module->C_GetMechanismInfo) (MOCK_SLOT_ONE_ID, CKM_MOCK_CAPITALIZE, &info);
	CuAssertTrue (tc, rv == CKR_OK);
	CuAssertIntEquals (tc, 512, info.ulMinKeySize);
	CuAssertIntEquals (tc, 4096, info.ulMaxKeySize);
	CuAssertIntEquals (tc, CKF_ENCRYPT | CKF_DECRYPT, info.flags);

	rv = (module->C_GetMechanismInfo) (MOCK_SLOT_ONE_ID, CKM_MOCK_PREFIX, &info);
	CuAssertTrue (tc, rv == CKR_OK);
	CuAssertIntEquals (tc, 2048, info.ulMinKeySize);
	CuAssertIntEquals (tc, 2048, info.ulMaxKeySize);
	CuAssertIntEquals (tc, CKF_SIGN | CKF_VERIFY, info.flags);

	rv = (module->C_GetMechanismInfo) (MOCK_SLOT_TWO_ID, CKM_MOCK_PREFIX, &info);
	CuAssertTrue (tc, rv == CKR_TOKEN_NOT_PRESENT);
	rv = (module->C_GetMechanismInfo) (MOCK_SLOT_ONE_ID, 0, &info);
	CuAssertTrue (tc, rv == CKR_MECHANISM_INVALID);
	rv = (module->C_GetMechanismInfo) (0, CKM_MOCK_PREFIX, &info);
	CuAssertTrue (tc, rv == CKR_SLOT_ID_INVALID);

	teardown_mock_module (tc, module);
}

static void
test_init_token (CuTest *tc)
{
	CK_FUNCTION_LIST_PTR module;
	CK_RV rv;

	module = setup_mock_module (tc, NULL);

	rv = (module->C_InitToken) (MOCK_SLOT_ONE_ID, (CK_UTF8CHAR_PTR)"TEST PIN", 8, (CK_UTF8CHAR_PTR)"TEST LABEL");
	CuAssertTrue (tc, rv == CKR_OK);

	rv = (module->C_InitToken) (MOCK_SLOT_ONE_ID, (CK_UTF8CHAR_PTR)"OTHER", 5, (CK_UTF8CHAR_PTR)"TEST LABEL");
	CuAssertTrue (tc, rv == CKR_PIN_INVALID);
	rv = (module->C_InitToken) (MOCK_SLOT_TWO_ID, (CK_UTF8CHAR_PTR)"TEST PIN", 8, (CK_UTF8CHAR_PTR)"TEST LABEL");
	CuAssertTrue (tc, rv == CKR_TOKEN_NOT_PRESENT);
	rv = (module->C_InitToken) (0, (CK_UTF8CHAR_PTR)"TEST PIN", 8, (CK_UTF8CHAR_PTR)"TEST LABEL");
	CuAssertTrue (tc, rv == CKR_SLOT_ID_INVALID);

	teardown_mock_module (tc, module);
}

static void
test_wait_for_slot_event (CuTest *tc)
{
	CK_FUNCTION_LIST_PTR module;
	CK_SLOT_ID slot;
	CK_RV rv;

#ifdef MOCK_SKIP_WAIT_TEST
	return;
#endif

	module = setup_mock_module (tc, NULL);

	rv = (module->C_WaitForSlotEvent) (0, &slot, NULL);
	CuAssertTrue (tc, rv == CKR_OK);
	CuAssertIntEquals (tc, slot, MOCK_SLOT_TWO_ID);

	rv = (module->C_WaitForSlotEvent) (CKF_DONT_BLOCK, &slot, NULL);
	CuAssertTrue (tc, rv == CKR_NO_EVENT);

	teardown_mock_module (tc, module);
}

static void
test_open_close_session (CuTest *tc)
{
	CK_FUNCTION_LIST_PTR module;
	CK_SESSION_HANDLE session = 0;
	CK_RV rv;

	module = setup_mock_module (tc, NULL);

	rv = (module->C_OpenSession) (MOCK_SLOT_TWO_ID, CKF_SERIAL_SESSION, NULL, NULL, &session);
	CuAssertTrue (tc, rv == CKR_TOKEN_NOT_PRESENT);
	rv = (module->C_OpenSession) (0, CKF_SERIAL_SESSION, NULL, NULL, &session);
	CuAssertTrue (tc, rv == CKR_SLOT_ID_INVALID);

	rv = (module->C_OpenSession) (MOCK_SLOT_ONE_ID, CKF_SERIAL_SESSION, NULL, NULL, &session);
	CuAssertTrue (tc, rv == CKR_OK);
	CuAssertTrue (tc, session != 0);

	rv = (module->C_CloseSession) (session);
	CuAssertTrue (tc, rv == CKR_OK);

	rv = (module->C_CloseSession) (session);
	CuAssertTrue (tc, rv == CKR_SESSION_HANDLE_INVALID);

	teardown_mock_module (tc, module);
}

static void
test_close_all_sessions (CuTest *tc)
{
	CK_FUNCTION_LIST_PTR module;
	CK_SESSION_HANDLE session = 0;
	CK_RV rv;

	module = setup_mock_module (tc, NULL);

	rv = (module->C_OpenSession) (MOCK_SLOT_ONE_ID, CKF_SERIAL_SESSION, NULL, NULL, &session);
	CuAssertTrue (tc, rv == CKR_OK);
	CuAssertTrue (tc, session != 0);

	rv = (module->C_CloseAllSessions) (MOCK_SLOT_ONE_ID);
	CuAssertTrue (tc, rv == CKR_OK);

	rv = (module->C_CloseSession) (session);
	CuAssertTrue (tc, rv == CKR_SESSION_HANDLE_INVALID);

	teardown_mock_module (tc, module);
}

static void
test_get_function_status (CuTest *tc)
{
	CK_FUNCTION_LIST_PTR module;
	CK_SESSION_HANDLE session = 0;
	CK_RV rv;

	module = setup_mock_module (tc, &session);

	rv = (module->C_GetFunctionStatus) (session);
	CuAssertTrue (tc, rv == CKR_FUNCTION_NOT_PARALLEL);

	teardown_mock_module (tc, module);
}

static void
test_cancel_function (CuTest *tc)
{
	CK_FUNCTION_LIST_PTR module;
	CK_SESSION_HANDLE session = 0;
	CK_RV rv;

	module = setup_mock_module (tc, &session);

	rv = (module->C_CancelFunction) (session);
	CuAssertTrue (tc, rv == CKR_FUNCTION_NOT_PARALLEL);

	teardown_mock_module (tc, module);
}

static void
test_get_session_info (CuTest *tc)
{
	CK_FUNCTION_LIST_PTR module;
	CK_SESSION_HANDLE session = 0;
	CK_SESSION_INFO info;
	CK_RV rv;

	module = setup_mock_module (tc, NULL);

	rv = (module->C_GetSessionInfo) (0, &info);
	CuAssertTrue (tc, rv == CKR_SESSION_HANDLE_INVALID);

	rv = (module->C_OpenSession) (MOCK_SLOT_ONE_ID, CKF_SERIAL_SESSION, NULL, NULL, &session);
	CuAssertTrue (tc, rv == CKR_OK);
	CuAssertTrue (tc, session != 0);

	rv = (module->C_GetSessionInfo) (session, &info);
	CuAssertTrue (tc, rv == CKR_OK);
	CuAssertIntEquals (tc, MOCK_SLOT_ONE_ID, info.slotID);
	CuAssertIntEquals (tc, CKS_RO_PUBLIC_SESSION, info.state);
	CuAssertIntEquals (tc, CKF_SERIAL_SESSION, info.flags);
	CuAssertIntEquals (tc, 1414, info.ulDeviceError);

	rv = (module->C_OpenSession) (MOCK_SLOT_ONE_ID, CKF_RW_SESSION | CKF_SERIAL_SESSION, NULL, NULL, &session);
	CuAssertTrue (tc, rv == CKR_OK);
	CuAssertTrue (tc, session != 0);

	rv = (module->C_GetSessionInfo) (session, &info);
	CuAssertTrue (tc, rv == CKR_OK);
	CuAssertIntEquals (tc, MOCK_SLOT_ONE_ID, info.slotID);
	CuAssertIntEquals (tc, CKS_RW_PUBLIC_SESSION, info.state);
	CuAssertIntEquals (tc, CKF_SERIAL_SESSION | CKF_RW_SESSION, info.flags);
	CuAssertIntEquals (tc, 1414, info.ulDeviceError);

	teardown_mock_module (tc, module);
}

static void
test_init_pin (CuTest *tc)
{
	CK_FUNCTION_LIST_PTR module;
	CK_SESSION_HANDLE session = 0;
	CK_RV rv;

	module = setup_mock_module (tc, &session);

	rv = (module->C_InitPIN) (0, (CK_UTF8CHAR_PTR)"TEST PIN", 8);
	CuAssertTrue (tc, rv == CKR_SESSION_HANDLE_INVALID);

	rv = (module->C_InitPIN) (session, (CK_UTF8CHAR_PTR)"TEST PIN", 8);
	CuAssertTrue (tc, rv == CKR_OK);

	rv = (module->C_InitPIN) (session, (CK_UTF8CHAR_PTR)"OTHER", 5);
	CuAssertTrue (tc, rv == CKR_PIN_INVALID);

	teardown_mock_module (tc, module);
}

static void
test_set_pin (CuTest *tc)
{
	CK_FUNCTION_LIST_PTR module;
	CK_SESSION_HANDLE session = 0;
	CK_RV rv;

	module = setup_mock_module (tc, &session);

	rv = (module->C_SetPIN) (0, (CK_UTF8CHAR_PTR)"booo", 4, (CK_UTF8CHAR_PTR)"TEST PIN", 8);
	CuAssertTrue (tc, rv == CKR_SESSION_HANDLE_INVALID);

	rv = (module->C_SetPIN) (session, (CK_UTF8CHAR_PTR)"booo", 4, (CK_UTF8CHAR_PTR)"TEST PIN", 8);
	CuAssertTrue (tc, rv == CKR_OK);

	rv = (module->C_SetPIN) (session, (CK_UTF8CHAR_PTR)"other", 5, (CK_UTF8CHAR_PTR)"OTHER", 5);
	CuAssertTrue (tc, rv == CKR_PIN_INCORRECT);

	teardown_mock_module (tc, module);
}

static void
test_operation_state (CuTest *tc)
{
	CK_FUNCTION_LIST_PTR module;
	CK_BYTE state[128];
	CK_ULONG state_len;
	CK_SESSION_HANDLE session = 0;
	CK_RV rv;

	module = setup_mock_module (tc, &session);

	state_len = sizeof (state);
	rv = (module->C_GetOperationState) (0, state, &state_len);
	CuAssertTrue (tc, rv == CKR_SESSION_HANDLE_INVALID);

	state_len = sizeof (state);
	rv = (module->C_GetOperationState) (session, state, &state_len);
	CuAssertTrue (tc, rv == CKR_OK);

	rv = (module->C_SetOperationState) (session, state, state_len, 355, 455);
	CuAssertTrue (tc, rv == CKR_OK);

	rv = (module->C_SetOperationState) (0, state, state_len, 355, 455);
	CuAssertTrue (tc, rv == CKR_SESSION_HANDLE_INVALID);

	teardown_mock_module (tc, module);
}

static void
test_login_logout (CuTest *tc)
{
	CK_FUNCTION_LIST_PTR module;
	CK_SESSION_HANDLE session = 0;
	CK_RV rv;

	module = setup_mock_module (tc, &session);

	rv = (module->C_Login) (0, CKU_USER, (CK_UTF8CHAR_PTR)"booo", 4);
	CuAssertTrue (tc, rv == CKR_SESSION_HANDLE_INVALID);

	rv = (module->C_Login) (session, CKU_USER, (CK_UTF8CHAR_PTR)"bo", 2);
	CuAssertTrue (tc, rv == CKR_PIN_INCORRECT);

	rv = (module->C_Login) (session, CKU_USER, (CK_UTF8CHAR_PTR)"booo", 4);
	CuAssertTrue (tc, rv == CKR_OK);

	rv = (module->C_Logout) (session);
	CuAssertTrue (tc, rv == CKR_OK);

	rv = (module->C_Logout) (session);
	CuAssertTrue (tc, rv == CKR_USER_NOT_LOGGED_IN);

	teardown_mock_module (tc, module);
}

static void
test_get_attribute_value (CuTest *tc)
{
	CK_FUNCTION_LIST_PTR module;
	CK_SESSION_HANDLE session = 0;
	CK_ATTRIBUTE attrs[8];
	char label[32];
	CK_OBJECT_CLASS klass;
	CK_RV rv;

	module = setup_mock_module (tc, &session);

	attrs[0].type = CKA_CLASS;
	attrs[0].pValue = &klass;
	attrs[0].ulValueLen = sizeof (klass);
	attrs[1].type = CKA_LABEL;
	attrs[1].pValue = label;
	attrs[1].ulValueLen = 2; /* too small */
	attrs[2].type = CKA_BITS_PER_PIXEL;
	attrs[2].pValue = NULL;
	attrs[2].ulValueLen = 0;

	rv = (module->C_GetAttributeValue) (session, MOCK_PRIVATE_KEY_CAPITALIZE, attrs, 3);
	CuAssertTrue (tc, rv == CKR_USER_NOT_LOGGED_IN);

	rv = (module->C_GetAttributeValue) (session, MOCK_PUBLIC_KEY_CAPITALIZE, attrs, 2);
	CuAssertTrue (tc, rv == CKR_BUFFER_TOO_SMALL);

	/* Get right size */
	attrs[1].pValue = NULL;
	attrs[1].ulValueLen = 0;

	rv = (module->C_GetAttributeValue) (session, MOCK_PUBLIC_KEY_CAPITALIZE, attrs, 2);
	CuAssertTrue (tc, rv == CKR_OK);

	rv = (module->C_GetAttributeValue) (session, MOCK_PUBLIC_KEY_CAPITALIZE, attrs, 3);
	CuAssertTrue (tc, rv == CKR_ATTRIBUTE_TYPE_INVALID);

	CuAssertIntEquals (tc, CKO_PUBLIC_KEY, klass);
	CuAssertIntEquals (tc, 21, attrs[1].ulValueLen);
	CuAssertPtrEquals (tc, NULL, attrs[1].pValue);
	attrs[1].pValue = label;
	attrs[1].ulValueLen = sizeof (label);
	CuAssertTrue (tc, (CK_ULONG)-1 == attrs[2].ulValueLen);
	CuAssertPtrEquals (tc, NULL, attrs[2].pValue);

	rv = (module->C_GetAttributeValue) (session, MOCK_PUBLIC_KEY_CAPITALIZE, attrs, 3);
	CuAssertTrue (tc, rv == CKR_ATTRIBUTE_TYPE_INVALID);

	CuAssertIntEquals (tc, CKO_PUBLIC_KEY, klass);
	CuAssertIntEquals (tc, 21, attrs[1].ulValueLen);
	CuAssertPtrEquals (tc, label, attrs[1].pValue);
	CuAssertTrue (tc, memcmp (label, "Public Capitalize Key", attrs[1].ulValueLen) == 0);
	CuAssertTrue (tc, (CK_ULONG)-1 == attrs[2].ulValueLen);
	CuAssertPtrEquals (tc, NULL, attrs[2].pValue);

	teardown_mock_module (tc, module);
}

static void
test_set_attribute_value (CuTest *tc)
{
	CK_FUNCTION_LIST_PTR module;
	CK_SESSION_HANDLE session = 0;
	CK_ATTRIBUTE attrs[8];
	char label[32];
	CK_ULONG bits;
	CK_RV rv;

	module = setup_mock_module (tc, &session);

	strcpy (label, "Blahooo");
	bits = 1555;

	attrs[0].type = CKA_LABEL;
	attrs[0].pValue = label;
	attrs[0].ulValueLen = strlen (label);
	attrs[1].type = CKA_BITS_PER_PIXEL;
	attrs[1].pValue = &bits;
	attrs[1].ulValueLen = sizeof (bits);

	rv = (module->C_SetAttributeValue) (session, MOCK_PRIVATE_KEY_CAPITALIZE, attrs, 2);
	CuAssertTrue (tc, rv == CKR_USER_NOT_LOGGED_IN);

	rv = (module->C_SetAttributeValue) (session, MOCK_PUBLIC_KEY_CAPITALIZE, attrs, 2);
	CuAssertTrue (tc, rv == CKR_OK);

	memset (label, 0, sizeof (label));
	bits = 0;

	rv = (module->C_GetAttributeValue) (session, MOCK_PUBLIC_KEY_CAPITALIZE, attrs, 2);
	CuAssertTrue (tc, rv == CKR_OK);

	CuAssertIntEquals (tc, bits, 1555);
	CuAssertIntEquals (tc, 7, attrs[0].ulValueLen);
	CuAssertTrue (tc, memcmp (label, "Blahooo", attrs[0].ulValueLen) == 0);

	teardown_mock_module (tc, module);
}

static void
test_create_object (CuTest *tc)
{
	CK_FUNCTION_LIST_PTR module;
	CK_SESSION_HANDLE session = 0;
	CK_OBJECT_HANDLE object;
	CK_ATTRIBUTE attrs[8];
	char label[32];
	CK_ULONG bits;
	CK_RV rv;

	module = setup_mock_module (tc, &session);

	strcpy (label, "Blahooo");
	bits = 1555;

	attrs[0].type = CKA_LABEL;
	attrs[0].pValue = label;
	attrs[0].ulValueLen = strlen (label);
	attrs[1].type = CKA_BITS_PER_PIXEL;
	attrs[1].pValue = &bits;
	attrs[1].ulValueLen = sizeof (bits);

	rv = (module->C_CreateObject) (0, attrs, 2, &object);
	CuAssertTrue (tc, rv == CKR_SESSION_HANDLE_INVALID);

	rv = (module->C_CreateObject) (session, attrs, 2, &object);
	CuAssertTrue (tc, rv == CKR_OK);

	attrs[0].ulValueLen = sizeof (label);
	memset (label, 0, sizeof (label));
	bits = 0;

	rv = (module->C_GetAttributeValue) (session, object, attrs, 2);
	CuAssertTrue (tc, rv == CKR_OK);

	CuAssertIntEquals (tc, bits, 1555);
	CuAssertIntEquals (tc, 7, attrs[0].ulValueLen);
	CuAssertTrue (tc, memcmp (label, "Blahooo", attrs[0].ulValueLen) == 0);

	teardown_mock_module (tc, module);
}

static void
test_copy_object (CuTest *tc)
{
	CK_FUNCTION_LIST_PTR module;
	CK_SESSION_HANDLE session = 0;
	CK_OBJECT_HANDLE object;
	CK_ATTRIBUTE attrs[8];
	char label[32];
	CK_ULONG bits;
	CK_RV rv;

	module = setup_mock_module (tc, &session);

	bits = 1555;

	attrs[0].type = CKA_BITS_PER_PIXEL;
	attrs[0].pValue = &bits;
	attrs[0].ulValueLen = sizeof (bits);

	rv = (module->C_CopyObject) (session, 1333, attrs, 1, &object);
	CuAssertTrue (tc, rv == CKR_OBJECT_HANDLE_INVALID);

	rv = (module->C_CopyObject) (session, MOCK_PUBLIC_KEY_CAPITALIZE, attrs, 1, &object);
	CuAssertTrue (tc, rv == CKR_OK);

	attrs[1].type = CKA_LABEL;
	attrs[1].pValue = label;
	attrs[1].ulValueLen = sizeof (label);
	bits = 0;

	rv = (module->C_GetAttributeValue) (session, object, attrs, 2);
	CuAssertTrue (tc, rv == CKR_OK);

	CuAssertIntEquals (tc, bits, 1555);
	CuAssertIntEquals (tc, 21, attrs[1].ulValueLen);
	CuAssertTrue (tc, memcmp (label, "Public Capitalize Key", attrs[1].ulValueLen) == 0);

	teardown_mock_module (tc, module);
}

static void
test_destroy_object (CuTest *tc)
{
	CK_FUNCTION_LIST_PTR module;
	CK_SESSION_HANDLE session = 0;
	CK_ATTRIBUTE attrs[8];
	char label[32];
	CK_RV rv;

	module = setup_mock_module (tc, &session);

	attrs[0].type = CKA_LABEL;
	attrs[0].pValue = label;
	attrs[0].ulValueLen = sizeof (label);

	rv = (module->C_GetAttributeValue) (session, MOCK_PUBLIC_KEY_CAPITALIZE, attrs, 1);
	CuAssertTrue (tc, rv == CKR_OK);

	rv = (module->C_DestroyObject) (0, MOCK_PUBLIC_KEY_CAPITALIZE);
	CuAssertTrue (tc, rv == CKR_SESSION_HANDLE_INVALID);

	rv = (module->C_DestroyObject) (session, MOCK_PUBLIC_KEY_CAPITALIZE);
	CuAssertTrue (tc, rv == CKR_OK);

	rv = (module->C_GetAttributeValue) (session, MOCK_PUBLIC_KEY_CAPITALIZE, attrs, 1);
	CuAssertTrue (tc, rv == CKR_OBJECT_HANDLE_INVALID);

	teardown_mock_module (tc, module);
}

static void
test_get_object_size (CuTest *tc)
{
	CK_FUNCTION_LIST_PTR module;
	CK_SESSION_HANDLE session = 0;
	CK_ULONG size;
	CK_RV rv;

	module = setup_mock_module (tc, &session);

	rv = (module->C_GetObjectSize) (session, 1333, &size);
	CuAssertTrue (tc, rv == CKR_OBJECT_HANDLE_INVALID);

	rv = (module->C_GetObjectSize) (session, MOCK_PUBLIC_KEY_CAPITALIZE, &size);
	CuAssertTrue (tc, rv == CKR_OK);

	/* The number here is the length of all attributes added up */
	CuAssertIntEquals (tc, sizeof (CK_ULONG) == 8 ? 44 : 36, size);

	teardown_mock_module (tc, module);
}

static void
test_find_objects (CuTest *tc)
{
	CK_FUNCTION_LIST_PTR module;
	CK_SESSION_HANDLE session = 0;
	CK_OBJECT_CLASS klass = CKO_PUBLIC_KEY;
	CK_ATTRIBUTE attr = { CKA_CLASS, &klass, sizeof (klass) };
	CK_OBJECT_HANDLE objects[16];
	CK_ULONG count;
	CK_ULONG i;
	CK_RV rv;

	module = setup_mock_module (tc, &session);

	rv = (module->C_FindObjectsInit) (0, &attr, 1);
	CuAssertTrue (tc, rv == CKR_SESSION_HANDLE_INVALID);

	rv = (module->C_FindObjectsInit) (session, &attr, 1);
	CuAssertTrue (tc, rv == CKR_OK);

	rv = (module->C_FindObjects) (0, objects, 16, &count);
	CuAssertTrue (tc, rv == CKR_SESSION_HANDLE_INVALID);

	rv = (module->C_FindObjects) (session, objects, 16, &count);
	CuAssertTrue (tc, rv == CKR_OK);

	CuAssertTrue (tc, count < 16);

	/* Make sure we get the capitalize public key */
	for (i = 0; i < count; i++) {
		if (objects[i] == MOCK_PUBLIC_KEY_CAPITALIZE)
			break;
	}
	CuAssertTrue (tc, i != count);

	/* Make sure we get the prefix public key */
	for (i = 0; i < count; i++) {
		if (objects[i] == MOCK_PUBLIC_KEY_PREFIX)
			break;
	}
	CuAssertTrue (tc, i != count);

	/* Make sure all public keys */
	for (i = 0; i < count; i++) {
		klass = (CK_ULONG)-1;
		rv = (module->C_GetAttributeValue) (session, objects[i], &attr, 1);
		CuAssertTrue (tc, rv == CKR_OK);
		CuAssertIntEquals (tc, CKO_PUBLIC_KEY, klass);
	}

	rv = (module->C_FindObjectsFinal) (session);
	CuAssertTrue (tc, rv == CKR_OK);

	rv = (module->C_FindObjectsFinal) (session);
	CuAssertTrue (tc, rv == CKR_OPERATION_NOT_INITIALIZED);

	teardown_mock_module (tc, module);
}

static void
test_encrypt (CuTest *tc)
{
	CK_FUNCTION_LIST_PTR module;
	CK_SESSION_HANDLE session = 0;
	CK_MECHANISM mech = { CKM_MOCK_CAPITALIZE, NULL, 0 };
	CK_BYTE data[128];
	CK_ULONG length;
	CK_RV rv;

	module = setup_mock_module (tc, &session);

	rv = (module->C_EncryptInit) (session, &mech, MOCK_PUBLIC_KEY_PREFIX);
	CuAssertTrue (tc, rv == CKR_KEY_HANDLE_INVALID);

	rv = (module->C_EncryptInit) (session, &mech, MOCK_PUBLIC_KEY_CAPITALIZE);
	CuAssertTrue (tc, rv == CKR_OK);

	length = sizeof (data);
	rv = (module->C_Encrypt) (0, (CK_BYTE_PTR)"blah", 4, data, &length);
	CuAssertTrue (tc, rv == CKR_SESSION_HANDLE_INVALID);

	length = sizeof (data);
	rv = (module->C_Encrypt) (session, (CK_BYTE_PTR)"blah", 4, data, &length);
	CuAssertTrue (tc, rv == CKR_OK);

	CuAssertIntEquals (tc, 4, length);
	CuAssertTrue (tc, memcmp (data, "BLAH", 4) == 0);

	rv = (module->C_EncryptInit) (session, &mech, MOCK_PUBLIC_KEY_CAPITALIZE);
	CuAssertTrue (tc, rv == CKR_OK);

	length = sizeof (data);
	rv = (module->C_EncryptUpdate) (0, (CK_BYTE_PTR)"blah", 4, data, &length);
	CuAssertTrue (tc, rv == CKR_SESSION_HANDLE_INVALID);

	length = sizeof (data);
	rv = (module->C_EncryptUpdate) (session, (CK_BYTE_PTR)"sLurm", 5, data, &length);
	CuAssertTrue (tc, rv == CKR_OK);

	CuAssertIntEquals (tc, 5, length);
	CuAssertTrue (tc, memcmp (data, "SLURM", 5) == 0);

	length = sizeof (data);
	rv = (module->C_EncryptFinal) (0, data, &length);
	CuAssertTrue (tc, rv == CKR_SESSION_HANDLE_INVALID);

	length = sizeof (data);
	rv = (module->C_EncryptFinal) (session, data, &length);
	CuAssertTrue (tc, rv == CKR_OK);

	teardown_mock_module (tc, module);
}

static void
test_decrypt (CuTest *tc)
{
	CK_FUNCTION_LIST_PTR module;
	CK_SESSION_HANDLE session = 0;
	CK_MECHANISM mech = { CKM_MOCK_CAPITALIZE, NULL, 0 };
	CK_BYTE data[128];
	CK_ULONG length;
	CK_RV rv;

	module = setup_mock_module (tc, &session);

	rv = (module->C_Login) (session, CKU_USER, (CK_BYTE_PTR)"booo", 4);
	CuAssertTrue (tc, rv == CKR_OK);

	rv = (module->C_DecryptInit) (session, &mech, MOCK_PRIVATE_KEY_PREFIX);
	CuAssertTrue (tc, rv == CKR_KEY_HANDLE_INVALID);

	rv = (module->C_DecryptInit) (session, &mech, MOCK_PRIVATE_KEY_CAPITALIZE);
	CuAssertTrue (tc, rv == CKR_OK);

	length = sizeof (data);
	rv = (module->C_Decrypt) (0, (CK_BYTE_PTR)"bLAH", 4, data, &length);
	CuAssertTrue (tc, rv == CKR_SESSION_HANDLE_INVALID);

	length = sizeof (data);
	rv = (module->C_Decrypt) (session, (CK_BYTE_PTR)"BLAh", 4, data, &length);
	CuAssertTrue (tc, rv == CKR_OK);

	CuAssertIntEquals (tc, 4, length);
	CuAssertTrue (tc, memcmp (data, "blah", 4) == 0);

	rv = (module->C_DecryptInit) (session, &mech, MOCK_PRIVATE_KEY_CAPITALIZE);
	CuAssertTrue (tc, rv == CKR_OK);

	length = sizeof (data);
	rv = (module->C_DecryptUpdate) (0, (CK_BYTE_PTR)"blah", 4, data, &length);
	CuAssertTrue (tc, rv == CKR_SESSION_HANDLE_INVALID);

	length = sizeof (data);
	rv = (module->C_DecryptUpdate) (session, (CK_BYTE_PTR)"sLuRM", 5, data, &length);
	CuAssertTrue (tc, rv == CKR_OK);

	CuAssertIntEquals (tc, 5, length);
	CuAssertTrue (tc, memcmp (data, "slurm", 5) == 0);

	length = sizeof (data);
	rv = (module->C_DecryptFinal) (0, data, &length);
	CuAssertTrue (tc, rv == CKR_SESSION_HANDLE_INVALID);

	length = sizeof (data);
	rv = (module->C_DecryptFinal) (session, data, &length);
	CuAssertTrue (tc, rv == CKR_OK);

	teardown_mock_module (tc, module);
}

static void
test_digest (CuTest *tc)
{
	CK_FUNCTION_LIST_PTR module;
	CK_SESSION_HANDLE session = 0;
	CK_MECHANISM mech = { CKM_MOCK_COUNT, NULL, 0 };
	CK_BYTE digest[128];
	CK_ULONG length;
	CK_RV rv;

	module = setup_mock_module (tc, &session);

	rv = (module->C_DigestInit) (0, &mech);
	CuAssertTrue (tc, rv == CKR_SESSION_HANDLE_INVALID);

	rv = (module->C_DigestInit) (session, &mech);
	CuAssertTrue (tc, rv == CKR_OK);

	length = sizeof (digest);
	rv = (module->C_Digest) (0, (CK_BYTE_PTR)"bLAH", 4, digest, &length);
	CuAssertTrue (tc, rv == CKR_SESSION_HANDLE_INVALID);

	length = sizeof (digest);
	rv = (module->C_Digest) (session, (CK_BYTE_PTR)"BLAh", 4, digest, &length);
	CuAssertTrue (tc, rv == CKR_OK);

	CuAssertIntEquals (tc, 1, length);
	CuAssertTrue (tc, memcmp (digest, "4", 1) == 0);

	rv = (module->C_DigestInit) (session, &mech);
	CuAssertTrue (tc, rv == CKR_OK);

	rv = (module->C_DigestUpdate) (0, (CK_BYTE_PTR)"blah", 4);
	CuAssertTrue (tc, rv == CKR_SESSION_HANDLE_INVALID);

	rv = (module->C_DigestUpdate) (session, (CK_BYTE_PTR)"sLuRM", 5);
	CuAssertTrue (tc, rv == CKR_OK);

	/* Adds the the value of object handle to hash: 6 */
	CuAssertIntEquals (tc, 6, MOCK_PUBLIC_KEY_PREFIX);
	rv = (module->C_DigestKey) (session, MOCK_PUBLIC_KEY_PREFIX);
	CuAssertTrue (tc, rv == CKR_OK);

	rv = (module->C_DigestUpdate) (session, (CK_BYTE_PTR)"Other", 5);
	CuAssertTrue (tc, rv == CKR_OK);

	length = sizeof (digest);
	rv = (module->C_DigestFinal) (0, digest, &length);
	CuAssertTrue (tc, rv == CKR_SESSION_HANDLE_INVALID);

	length = sizeof (digest);
	rv = (module->C_DigestFinal) (session, digest, &length);
	CuAssertTrue (tc, rv == CKR_OK);

	CuAssertIntEquals (tc, 2, length);
	CuAssertTrue (tc, memcmp (digest, "16", 2) == 0);

	teardown_mock_module (tc, module);
}

static void
test_sign (CuTest *tc)
{
	CK_FUNCTION_LIST_PTR module;
	CK_SESSION_HANDLE session = 0;
	CK_MECHANISM mech = { CKM_MOCK_PREFIX, "prefix:", 7 };
	CK_BYTE signature[128];
	CK_ULONG length;
	CK_RV rv;

	module = setup_mock_module (tc, &session);

	rv = (module->C_Login) (session, CKU_USER, (CK_BYTE_PTR)"booo", 4);
	CuAssertTrue (tc, rv == CKR_OK);

	rv = (module->C_SignInit) (0, &mech, MOCK_PRIVATE_KEY_PREFIX);
	CuAssertTrue (tc, rv == CKR_SESSION_HANDLE_INVALID);

	rv = (module->C_SignInit) (session, &mech, MOCK_PRIVATE_KEY_PREFIX);
	CuAssertTrue (tc, rv == CKR_OK);

	rv = (module->C_Login) (session, CKU_CONTEXT_SPECIFIC, (CK_BYTE_PTR)"booo", 4);
	CuAssertTrue (tc, rv == CKR_OK);

	length = sizeof (signature);
	rv = (module->C_Sign) (0, (CK_BYTE_PTR)"bLAH", 4, signature, &length);
	CuAssertTrue (tc, rv == CKR_SESSION_HANDLE_INVALID);

	length = sizeof (signature);
	rv = (module->C_Sign) (session, (CK_BYTE_PTR)"BLAh", 4, signature, &length);
	CuAssertTrue (tc, rv == CKR_OK);

	CuAssertIntEquals (tc, 13, length);
	CuAssertTrue (tc, memcmp (signature, "prefix:value4", 13) == 0);

	rv = (module->C_SignInit) (session, &mech, MOCK_PRIVATE_KEY_PREFIX);
	CuAssertTrue (tc, rv == CKR_OK);

	rv = (module->C_Login) (session, CKU_CONTEXT_SPECIFIC, (CK_BYTE_PTR)"booo", 4);
	CuAssertTrue (tc, rv == CKR_OK);

	rv = (module->C_SignUpdate) (0, (CK_BYTE_PTR)"blah", 4);
	CuAssertTrue (tc, rv == CKR_SESSION_HANDLE_INVALID);

	rv = (module->C_SignUpdate) (session, (CK_BYTE_PTR)"sLuRM", 5);
	CuAssertTrue (tc, rv == CKR_OK);

	rv = (module->C_SignUpdate) (session, (CK_BYTE_PTR)"Other", 5);
	CuAssertTrue (tc, rv == CKR_OK);

	length = sizeof (signature);
	rv = (module->C_SignFinal) (0, signature, &length);
	CuAssertTrue (tc, rv == CKR_SESSION_HANDLE_INVALID);

	length = sizeof (signature);
	rv = (module->C_SignFinal) (session, signature, &length);
	CuAssertTrue (tc, rv == CKR_OK);

	CuAssertIntEquals (tc, 14, length);
	CuAssertTrue (tc, memcmp (signature, "prefix:value10", 2) == 0);

	teardown_mock_module (tc, module);
}

static void
test_sign_recover (CuTest *tc)
{
	CK_FUNCTION_LIST_PTR module;
	CK_SESSION_HANDLE session = 0;
	CK_MECHANISM mech = { CKM_MOCK_PREFIX, "prefix:", 7 };
	CK_BYTE signature[128];
	CK_ULONG length;
	CK_RV rv;

	module = setup_mock_module (tc, &session);

	rv = (module->C_Login) (session, CKU_USER, (CK_BYTE_PTR)"booo", 4);
	CuAssertTrue (tc, rv == CKR_OK);

	rv = (module->C_SignRecoverInit) (0, &mech, MOCK_PRIVATE_KEY_PREFIX);
	CuAssertTrue (tc, rv == CKR_SESSION_HANDLE_INVALID);

	rv = (module->C_SignRecoverInit) (session, &mech, MOCK_PRIVATE_KEY_PREFIX);
	CuAssertTrue (tc, rv == CKR_OK);

	rv = (module->C_Login) (session, CKU_CONTEXT_SPECIFIC, (CK_BYTE_PTR)"booo", 4);
	CuAssertTrue (tc, rv == CKR_OK);

	length = sizeof (signature);
	rv = (module->C_SignRecover) (0, (CK_BYTE_PTR)"bLAH", 4, signature, &length);
	CuAssertTrue (tc, rv == CKR_SESSION_HANDLE_INVALID);

	length = sizeof (signature);
	rv = (module->C_SignRecover) (session, (CK_BYTE_PTR)"BLAh", 4, signature, &length);
	CuAssertTrue (tc, rv == CKR_OK);

	CuAssertIntEquals (tc, 16, length);
	CuAssertTrue (tc, memcmp (signature, "prefix:valueBLAh", 16) == 0);

	teardown_mock_module (tc, module);
}

static void
test_verify (CuTest *tc)
{
	CK_FUNCTION_LIST_PTR module;
	CK_SESSION_HANDLE session = 0;
	CK_MECHANISM mech = { CKM_MOCK_PREFIX, "prefix:", 7 };
	CK_BYTE signature[128];
	CK_ULONG length;
	CK_RV rv;

	module = setup_mock_module (tc, &session);

	rv = (module->C_VerifyInit) (0, &mech, MOCK_PUBLIC_KEY_PREFIX);
	CuAssertTrue (tc, rv == CKR_SESSION_HANDLE_INVALID);

	rv = (module->C_VerifyInit) (session, &mech, MOCK_PUBLIC_KEY_PREFIX);
	CuAssertTrue (tc, rv == CKR_OK);

	length = 13;
	memcpy (signature, "prefix:value4", length);
	rv = (module->C_Verify) (0, (CK_BYTE_PTR)"bLAH", 4, signature, 5);
	CuAssertTrue (tc, rv == CKR_SESSION_HANDLE_INVALID);

	rv = (module->C_Verify) (session, (CK_BYTE_PTR)"BLAh", 4, signature, length);
	CuAssertTrue (tc, rv == CKR_OK);

	rv = (module->C_VerifyInit) (session, &mech, MOCK_PUBLIC_KEY_PREFIX);
	CuAssertTrue (tc, rv == CKR_OK);

	rv = (module->C_VerifyUpdate) (0, (CK_BYTE_PTR)"blah", 4);
	CuAssertTrue (tc, rv == CKR_SESSION_HANDLE_INVALID);

	rv = (module->C_VerifyUpdate) (session, (CK_BYTE_PTR)"sLuRM", 5);
	CuAssertTrue (tc, rv == CKR_OK);

	rv = (module->C_VerifyUpdate) (session, (CK_BYTE_PTR)"Other", 5);
	CuAssertTrue (tc, rv == CKR_OK);

	length = 14;
	memcpy (signature, "prefix:value10", length);

	rv = (module->C_VerifyFinal) (session, signature, 5);
	CuAssertTrue (tc, rv == CKR_SIGNATURE_LEN_RANGE);

	rv = (module->C_VerifyFinal) (session, signature, length);
	CuAssertTrue (tc, rv == CKR_OK);

	teardown_mock_module (tc, module);
}

static void
test_verify_recover (CuTest *tc)
{
	CK_FUNCTION_LIST_PTR module;
	CK_SESSION_HANDLE session = 0;
	CK_MECHANISM mech = { CKM_MOCK_PREFIX, "prefix:", 7 };
	CK_BYTE data[128];
	CK_ULONG length;
	CK_RV rv;

	module = setup_mock_module (tc, &session);

	rv = (module->C_VerifyRecoverInit) (0, &mech, MOCK_PUBLIC_KEY_PREFIX);
	CuAssertTrue (tc, rv == CKR_SESSION_HANDLE_INVALID);

	rv = (module->C_VerifyRecoverInit) (session, &mech, MOCK_PUBLIC_KEY_PREFIX);
	CuAssertTrue (tc, rv == CKR_OK);

	length = sizeof (data);
	rv = (module->C_VerifyRecover) (0, (CK_BYTE_PTR)"prefix:valueBLah", 16, data, &length);
	CuAssertTrue (tc, rv == CKR_SESSION_HANDLE_INVALID);

	length = sizeof (data);
	rv = (module->C_VerifyRecover) (session, (CK_BYTE_PTR)"prefix:valueBLah", 16, data, &length);
	CuAssertTrue (tc, rv == CKR_OK);

	CuAssertIntEquals (tc, 4, length);
	CuAssertTrue (tc, memcmp (data, "BLah", 4) == 0);

	teardown_mock_module (tc, module);
}

static void
test_digest_encrypt (CuTest *tc)
{
	CK_FUNCTION_LIST_PTR module;
	CK_SESSION_HANDLE session = 0;
	CK_MECHANISM mech = { CKM_MOCK_CAPITALIZE, NULL, 0 };
	CK_MECHANISM dmech = { CKM_MOCK_COUNT, NULL, 0 };
	CK_BYTE data[128];
	CK_ULONG length;
	CK_RV rv;

	module = setup_mock_module (tc, &session);

	rv = (module->C_EncryptInit) (session, &mech, MOCK_PUBLIC_KEY_CAPITALIZE);
	CuAssertTrue (tc, rv == CKR_OK);

	rv = (module->C_DigestInit) (session, &dmech);
	CuAssertTrue (tc, rv == CKR_OK);

	length = sizeof (data);
	rv = (module->C_DigestEncryptUpdate) (0, (CK_BYTE_PTR)"blah", 4, data, &length);
	CuAssertTrue (tc, rv == CKR_SESSION_HANDLE_INVALID);

	length = sizeof (data);
	rv = (module->C_DigestEncryptUpdate) (session, (CK_BYTE_PTR)"blah", 4, data, &length);
	CuAssertTrue (tc, rv == CKR_OK);

	CuAssertIntEquals (tc, 4, length);
	CuAssertTrue (tc, memcmp (data, "BLAH", 4) == 0);

	length = sizeof (data);
	rv = (module->C_EncryptFinal) (session, data, &length);
	CuAssertTrue (tc, rv == CKR_OK);

	length = sizeof (data);
	rv = (module->C_DigestFinal) (session, data, &length);
	CuAssertTrue (tc, rv == CKR_OK);

	CuAssertIntEquals (tc, 1, length);
	CuAssertTrue (tc, memcmp (data, "4", 1) == 0);

	teardown_mock_module (tc, module);
}

static void
test_decrypt_digest (CuTest *tc)
{
	CK_FUNCTION_LIST_PTR module;
	CK_SESSION_HANDLE session = 0;
	CK_MECHANISM mech = { CKM_MOCK_CAPITALIZE, NULL, 0 };
	CK_MECHANISM dmech = { CKM_MOCK_COUNT, NULL, 0 };
	CK_BYTE data[128];
	CK_ULONG length;
	CK_RV rv;

	module = setup_mock_module (tc, &session);

	rv = (module->C_Login) (session, CKU_USER, (CK_BYTE_PTR)"booo", 4);
	CuAssertTrue (tc, rv == CKR_OK);

	rv = (module->C_DecryptInit) (session, &mech, MOCK_PRIVATE_KEY_CAPITALIZE);
	CuAssertTrue (tc, rv == CKR_OK);

	rv = (module->C_DigestInit) (session, &dmech);
	CuAssertTrue (tc, rv == CKR_OK);

	length = sizeof (data);
	rv = (module->C_DecryptDigestUpdate) (0, (CK_BYTE_PTR)"BLAH", 4, data, &length);
	CuAssertTrue (tc, rv == CKR_SESSION_HANDLE_INVALID);

	length = sizeof (data);
	rv = (module->C_DecryptDigestUpdate) (session, (CK_BYTE_PTR)"BLAH", 4, data, &length);
	CuAssertTrue (tc, rv == CKR_OK);

	CuAssertIntEquals (tc, 4, length);
	CuAssertTrue (tc, memcmp (data, "blah", 4) == 0);

	length = sizeof (data);
	rv = (module->C_DecryptFinal) (session, data, &length);
	CuAssertTrue (tc, rv == CKR_OK);

	length = sizeof (data);
	rv = (module->C_DigestFinal) (session, data, &length);
	CuAssertTrue (tc, rv == CKR_OK);

	CuAssertIntEquals (tc, 1, length);
	CuAssertTrue (tc, memcmp (data, "4", 1) == 0);

	teardown_mock_module (tc, module);
}

static void
test_sign_encrypt (CuTest *tc)
{
	CK_FUNCTION_LIST_PTR module;
	CK_SESSION_HANDLE session = 0;
	CK_MECHANISM mech = { CKM_MOCK_CAPITALIZE, NULL, 0 };
	CK_MECHANISM smech = { CKM_MOCK_PREFIX, "p:", 2 };
	CK_BYTE data[128];
	CK_ULONG length;
	CK_RV rv;

	module = setup_mock_module (tc, &session);

	rv = (module->C_Login) (session, CKU_USER, (CK_BYTE_PTR)"booo", 4);
	CuAssertTrue (tc, rv == CKR_OK);

	rv = (module->C_EncryptInit) (session, &mech, MOCK_PUBLIC_KEY_CAPITALIZE);
	CuAssertTrue (tc, rv == CKR_OK);

	rv = (module->C_SignInit) (session, &smech, MOCK_PRIVATE_KEY_PREFIX);
	CuAssertTrue (tc, rv == CKR_OK);

	rv = (module->C_Login) (session, CKU_CONTEXT_SPECIFIC, (CK_BYTE_PTR)"booo", 4);
	CuAssertTrue (tc, rv == CKR_OK);

	length = sizeof (data);
	rv = (module->C_SignEncryptUpdate) (0, (CK_BYTE_PTR)"blah", 4, data, &length);
	CuAssertTrue (tc, rv == CKR_SESSION_HANDLE_INVALID);

	length = sizeof (data);
	rv = (module->C_SignEncryptUpdate) (session, (CK_BYTE_PTR)"blah", 4, data, &length);
	CuAssertTrue (tc, rv == CKR_OK);

	CuAssertIntEquals (tc, 4, length);
	CuAssertTrue (tc, memcmp (data, "BLAH", 4) == 0);

	length = sizeof (data);
	rv = (module->C_EncryptFinal) (session, data, &length);
	CuAssertTrue (tc, rv == CKR_OK);

	length = sizeof (data);
	rv = (module->C_SignFinal) (session, data, &length);
	CuAssertTrue (tc, rv == CKR_OK);

	CuAssertIntEquals (tc, 8, length);
	CuAssertTrue (tc, memcmp (data, "p:value4", 1) == 0);

	teardown_mock_module (tc, module);
}

static void
test_decrypt_verify (CuTest *tc)
{
	CK_FUNCTION_LIST_PTR module;
	CK_SESSION_HANDLE session = 0;
	CK_MECHANISM mech = { CKM_MOCK_CAPITALIZE, NULL, 0 };
	CK_MECHANISM vmech = { CKM_MOCK_PREFIX, "p:", 2 };
	CK_BYTE data[128];
	CK_ULONG length;
	CK_RV rv;

	module = setup_mock_module (tc, &session);

	rv = (module->C_Login) (session, CKU_USER, (CK_BYTE_PTR)"booo", 4);
	CuAssertTrue (tc, rv == CKR_OK);

	rv = (module->C_DecryptInit) (session, &mech, MOCK_PRIVATE_KEY_CAPITALIZE);
	CuAssertTrue (tc, rv == CKR_OK);

	rv = (module->C_VerifyInit) (session, &vmech, MOCK_PUBLIC_KEY_PREFIX);
	CuAssertTrue (tc, rv == CKR_OK);

	length = sizeof (data);
	rv = (module->C_DecryptVerifyUpdate) (0, (CK_BYTE_PTR)"BLAH", 4, data, &length);
	CuAssertTrue (tc, rv == CKR_SESSION_HANDLE_INVALID);

	length = sizeof (data);
	rv = (module->C_DecryptVerifyUpdate) (session, (CK_BYTE_PTR)"BLAH", 4, data, &length);
	CuAssertTrue (tc, rv == CKR_OK);

	CuAssertIntEquals (tc, 4, length);
	CuAssertTrue (tc, memcmp (data, "blah", 4) == 0);

	length = sizeof (data);
	rv = (module->C_DecryptFinal) (session, data, &length);
	CuAssertTrue (tc, rv == CKR_OK);

	rv = (module->C_VerifyFinal) (session, (CK_BYTE_PTR)"p:value4", 8);
	CuAssertTrue (tc, rv == CKR_OK);

	teardown_mock_module (tc, module);
}

static void
test_generate_key (CuTest *tc)
{
	CK_FUNCTION_LIST_PTR module;
	CK_SESSION_HANDLE session = 0;
	CK_OBJECT_HANDLE object;
	CK_MECHANISM mech = { CKM_MOCK_GENERATE, NULL, 0 };
	CK_ATTRIBUTE attrs[8];
	char label[32];
	char value[64];
	CK_ULONG bits;
	CK_RV rv;

	module = setup_mock_module (tc, &session);

	strcpy (label, "Blahooo");
	bits = 1555;

	attrs[0].type = CKA_LABEL;
	attrs[0].pValue = label;
	attrs[0].ulValueLen = strlen (label);
	attrs[1].type = CKA_BITS_PER_PIXEL;
	attrs[1].pValue = &bits;
	attrs[1].ulValueLen = sizeof (bits);

	rv = (module->C_GenerateKey) (session, &mech, attrs, 2, &object);
	CuAssertTrue (tc, rv == CKR_MECHANISM_PARAM_INVALID);

	mech.pParameter = "generate";
	mech.ulParameterLen = 9;

	rv = (module->C_GenerateKey) (session, &mech, attrs, 2, &object);
	CuAssertTrue (tc, rv == CKR_OK);

	attrs[0].ulValueLen = sizeof (label);
	memset (label, 0, sizeof (label));
	bits = 0;
	attrs[2].type = CKA_VALUE;
	attrs[2].pValue = value;
	attrs[2].ulValueLen = sizeof (value);

	rv = (module->C_GetAttributeValue) (session, object, attrs, 3);
	CuAssertTrue (tc, rv == CKR_OK);

	CuAssertIntEquals (tc, bits, 1555);
	CuAssertIntEquals (tc, 7, attrs[0].ulValueLen);
	CuAssertTrue (tc, memcmp (label, "Blahooo", attrs[0].ulValueLen) == 0);
	CuAssertIntEquals (tc, 9, attrs[2].ulValueLen);
	CuAssertTrue (tc, memcmp (value, "generated", attrs[2].ulValueLen) == 0);

	teardown_mock_module (tc, module);
}

static void
test_generate_key_pair (CuTest *tc)
{
	CK_FUNCTION_LIST_PTR module;
	CK_SESSION_HANDLE session = 0;
	CK_OBJECT_HANDLE pub_object;
	CK_OBJECT_HANDLE priv_object;
	CK_MECHANISM mech = { CKM_MOCK_GENERATE, "generated", 9 };
	CK_ATTRIBUTE pub_attrs[8];
	CK_ATTRIBUTE priv_attrs[8];
	char pub_label[32];
	char pub_value[64];
	char priv_label[32];
	char priv_value[64];
	CK_ULONG pub_bits;
	CK_ULONG priv_bits;
	CK_RV rv;

	module = setup_mock_module (tc, &session);

	strcpy (pub_label, "Blahooo");
	pub_bits = 1555;
	pub_attrs[0].type = CKA_LABEL;
	pub_attrs[0].pValue = pub_label;
	pub_attrs[0].ulValueLen = strlen (pub_label);
	pub_attrs[1].type = CKA_BITS_PER_PIXEL;
	pub_attrs[1].pValue = &pub_bits;
	pub_attrs[1].ulValueLen = sizeof (pub_bits);

	strcpy (priv_label, "Private");
	priv_bits = 1666;
	priv_attrs[0].type = CKA_LABEL;
	priv_attrs[0].pValue = priv_label;
	priv_attrs[0].ulValueLen = strlen (priv_label);
	priv_attrs[1].type = CKA_BITS_PER_PIXEL;
	priv_attrs[1].pValue = &priv_bits;
	priv_attrs[1].ulValueLen = sizeof (priv_bits);

	rv = (module->C_GenerateKeyPair) (0, &mech, pub_attrs, 2, priv_attrs, 2,
	                                  &pub_object, &priv_object);
	CuAssertTrue (tc, rv == CKR_SESSION_HANDLE_INVALID);

	mech.pParameter = "generate";
	mech.ulParameterLen = 9;

	rv = (module->C_GenerateKeyPair) (session, &mech, pub_attrs, 2, priv_attrs, 2,
	                                  &pub_object, &priv_object);
	CuAssertTrue (tc, rv == CKR_OK);

	pub_bits = 0;
	pub_attrs[0].ulValueLen = sizeof (pub_label);
	memset (pub_label, 0, sizeof (pub_label));
	pub_attrs[2].type = CKA_VALUE;
	pub_attrs[2].pValue = pub_value;
	pub_attrs[2].ulValueLen = sizeof (pub_value);

	rv = (module->C_GetAttributeValue) (session, pub_object, pub_attrs, 3);
	CuAssertTrue (tc, rv == CKR_OK);

	CuAssertIntEquals (tc, 1555, pub_bits);
	CuAssertIntEquals (tc, 7, pub_attrs[0].ulValueLen);
	CuAssertTrue (tc, memcmp (pub_label, "Blahooo", pub_attrs[0].ulValueLen) == 0);
	CuAssertIntEquals (tc, 9, pub_attrs[2].ulValueLen);
	CuAssertTrue (tc, memcmp (pub_value, "generated", pub_attrs[2].ulValueLen) == 0);

	priv_bits = 0;
	priv_attrs[0].ulValueLen = sizeof (priv_label);
	memset (priv_label, 0, sizeof (priv_label));
	priv_attrs[2].type = CKA_VALUE;
	priv_attrs[2].pValue = priv_value;
	priv_attrs[2].ulValueLen = sizeof (priv_value);

	rv = (module->C_GetAttributeValue) (session, priv_object, priv_attrs, 3);
	CuAssertTrue (tc, rv == CKR_OK);

	CuAssertIntEquals (tc, 1666, priv_bits);
	CuAssertIntEquals (tc, 7, priv_attrs[0].ulValueLen);
	CuAssertTrue (tc, memcmp (priv_label, "Private", priv_attrs[0].ulValueLen) == 0);
	CuAssertIntEquals (tc, 9, priv_attrs[2].ulValueLen);
	CuAssertTrue (tc, memcmp (priv_value, "generated", priv_attrs[2].ulValueLen) == 0);

	teardown_mock_module (tc, module);
}

static void
test_wrap_key (CuTest *tc)
{
	CK_FUNCTION_LIST_PTR module;
	CK_SESSION_HANDLE session = 0;
	CK_MECHANISM mech = { CKM_MOCK_WRAP, NULL, 0 };
	CK_BYTE data[128];
	CK_ULONG length;
	CK_RV rv;

	module = setup_mock_module (tc, &session);

	length = sizeof (data);
	rv = (module->C_WrapKey) (session, &mech, MOCK_PUBLIC_KEY_PREFIX, MOCK_PUBLIC_KEY_PREFIX, data, &length);
	CuAssertTrue (tc, rv == CKR_MECHANISM_PARAM_INVALID);

	mech.pParameter = "wrap";
	mech.ulParameterLen = 4;

	rv = (module->C_WrapKey) (session, &mech, MOCK_PUBLIC_KEY_PREFIX, MOCK_PUBLIC_KEY_PREFIX, data, &length);
	CuAssertTrue (tc, rv == CKR_OK);

	CuAssertIntEquals (tc, 5, length);
	CuAssertTrue (tc, memcmp (data, "value", 5) == 0);

	teardown_mock_module (tc, module);
}

static void
test_unwrap_key (CuTest *tc)
{
	CK_FUNCTION_LIST_PTR module;
	CK_SESSION_HANDLE session = 0;
	CK_OBJECT_HANDLE object;
	CK_MECHANISM mech = { CKM_MOCK_WRAP, NULL, 0 };
	CK_ATTRIBUTE attrs[8];
	char label[32];
	char value[64];
	CK_ULONG bits;
	CK_RV rv;

	module = setup_mock_module (tc, &session);

	strcpy (label, "Blahooo");
	bits = 1555;

	attrs[0].type = CKA_LABEL;
	attrs[0].pValue = label;
	attrs[0].ulValueLen = strlen (label);
	attrs[1].type = CKA_BITS_PER_PIXEL;
	attrs[1].pValue = &bits;
	attrs[1].ulValueLen = sizeof (bits);

	rv = (module->C_UnwrapKey) (session, &mech, MOCK_PUBLIC_KEY_PREFIX,
	                            (CK_BYTE_PTR)"wheee", 5, attrs, 2, &object);
	CuAssertTrue (tc, rv == CKR_MECHANISM_PARAM_INVALID);

	mech.pParameter = "wrap";
	mech.ulParameterLen = 4;

	rv = (module->C_UnwrapKey) (session, &mech, MOCK_PUBLIC_KEY_PREFIX,
	                            (CK_BYTE_PTR)"wheee", 5, attrs, 2, &object);
	CuAssertTrue (tc, rv == CKR_OK);

	attrs[0].ulValueLen = sizeof (label);
	memset (label, 0, sizeof (label));
	bits = 0;
	attrs[2].type = CKA_VALUE;
	attrs[2].pValue = value;
	attrs[2].ulValueLen = sizeof (value);

	rv = (module->C_GetAttributeValue) (session, object, attrs, 3);
	CuAssertTrue (tc, rv == CKR_OK);

	CuAssertIntEquals (tc, bits, 1555);
	CuAssertIntEquals (tc, 7, attrs[0].ulValueLen);
	CuAssertTrue (tc, memcmp (label, "Blahooo", attrs[0].ulValueLen) == 0);
	CuAssertIntEquals (tc, 5, attrs[2].ulValueLen);
	CuAssertTrue (tc, memcmp (value, "wheee", attrs[2].ulValueLen) == 0);

	teardown_mock_module (tc, module);
}

static void
test_derive_key (CuTest *tc)
{
	CK_FUNCTION_LIST_PTR module;
	CK_SESSION_HANDLE session = 0;
	CK_OBJECT_HANDLE object;
	CK_MECHANISM mech = { CKM_MOCK_DERIVE, NULL, 0 };
	CK_ATTRIBUTE attrs[8];
	char label[32];
	char value[64];
	CK_ULONG bits;
	CK_RV rv;

	module = setup_mock_module (tc, &session);

	strcpy (label, "Blahooo");
	bits = 1555;

	attrs[0].type = CKA_LABEL;
	attrs[0].pValue = label;
	attrs[0].ulValueLen = strlen (label);
	attrs[1].type = CKA_BITS_PER_PIXEL;
	attrs[1].pValue = &bits;
	attrs[1].ulValueLen = sizeof (bits);

	rv = (module->C_DeriveKey) (session, &mech, MOCK_PUBLIC_KEY_PREFIX,
	                                attrs, 2, &object);
	CuAssertTrue (tc, rv == CKR_MECHANISM_PARAM_INVALID);

	mech.pParameter = "derive";
	mech.ulParameterLen = 6;

	rv = (module->C_DeriveKey) (session, &mech, MOCK_PUBLIC_KEY_PREFIX,
	                            attrs, 2, &object);
	CuAssertTrue (tc, rv == CKR_OK);

	attrs[0].ulValueLen = sizeof (label);
	memset (label, 0, sizeof (label));
	bits = 0;
	attrs[2].type = CKA_VALUE;
	attrs[2].pValue = value;
	attrs[2].ulValueLen = sizeof (value);

	rv = (module->C_GetAttributeValue) (session, object, attrs, 3);
	CuAssertTrue (tc, rv == CKR_OK);

	CuAssertIntEquals (tc, bits, 1555);
	CuAssertIntEquals (tc, 7, attrs[0].ulValueLen);
	CuAssertTrue (tc, memcmp (label, "Blahooo", attrs[0].ulValueLen) == 0);
	CuAssertIntEquals (tc, 7, attrs[2].ulValueLen);
	CuAssertTrue (tc, memcmp (value, "derived", attrs[2].ulValueLen) == 0);

	teardown_mock_module (tc, module);
}

static void
test_random (CuTest *tc)
{
	CK_FUNCTION_LIST_PTR module;
	CK_SESSION_HANDLE session = 0;
	CK_BYTE data[10];
	CK_RV rv;

	module = setup_mock_module (tc, &session);

	rv = (module->C_SeedRandom) (0, (CK_BYTE_PTR)"seed", 4);
	CuAssertTrue (tc, rv == CKR_SESSION_HANDLE_INVALID);

	rv = (module->C_SeedRandom) (session, (CK_BYTE_PTR)"seed", 4);
	CuAssertTrue (tc, rv == CKR_OK);

	rv = (module->C_GenerateRandom) (0, data, sizeof (data));
	CuAssertTrue (tc, rv == CKR_SESSION_HANDLE_INVALID);

	rv = (module->C_GenerateRandom) (session, data, sizeof (data));
	CuAssertTrue (tc, rv == CKR_OK);

	CuAssertTrue (tc, memcmp (data, "seedseedse", sizeof (data)) == 0);

	teardown_mock_module (tc, module);
}

static void
test_mock_add_tests (CuSuite *suite)
{
	SUITE_ADD_TEST (suite, test_get_info);
	SUITE_ADD_TEST (suite, test_get_slot_list);
	SUITE_ADD_TEST (suite, test_get_slot_info);
	SUITE_ADD_TEST (suite, test_get_token_info);
	SUITE_ADD_TEST (suite, test_get_mechanism_list);
	SUITE_ADD_TEST (suite, test_get_mechanism_info);
	SUITE_ADD_TEST (suite, test_init_token);
	SUITE_ADD_TEST (suite, test_wait_for_slot_event);
	SUITE_ADD_TEST (suite, test_open_close_session);
	SUITE_ADD_TEST (suite, test_close_all_sessions);
	SUITE_ADD_TEST (suite, test_get_function_status);
	SUITE_ADD_TEST (suite, test_cancel_function);
	SUITE_ADD_TEST (suite, test_get_session_info);
	SUITE_ADD_TEST (suite, test_init_pin);
	SUITE_ADD_TEST (suite, test_set_pin);
	SUITE_ADD_TEST (suite, test_operation_state);
	SUITE_ADD_TEST (suite, test_login_logout);
	SUITE_ADD_TEST (suite, test_get_attribute_value);
	SUITE_ADD_TEST (suite, test_set_attribute_value);
	SUITE_ADD_TEST (suite, test_create_object);
	SUITE_ADD_TEST (suite, test_copy_object);
	SUITE_ADD_TEST (suite, test_destroy_object);
	SUITE_ADD_TEST (suite, test_get_object_size);
	SUITE_ADD_TEST (suite, test_find_objects);
	SUITE_ADD_TEST (suite, test_encrypt);
	SUITE_ADD_TEST (suite, test_decrypt);
	SUITE_ADD_TEST (suite, test_digest);
	SUITE_ADD_TEST (suite, test_sign);
	SUITE_ADD_TEST (suite, test_sign_recover);
	SUITE_ADD_TEST (suite, test_verify);
	SUITE_ADD_TEST (suite, test_verify_recover);
	SUITE_ADD_TEST (suite, test_digest_encrypt);
	SUITE_ADD_TEST (suite, test_decrypt_digest);
	SUITE_ADD_TEST (suite, test_sign_encrypt);
	SUITE_ADD_TEST (suite, test_decrypt_verify);
	SUITE_ADD_TEST (suite, test_generate_key);
	SUITE_ADD_TEST (suite, test_generate_key_pair);
	SUITE_ADD_TEST (suite, test_wrap_key);
	SUITE_ADD_TEST (suite, test_unwrap_key);
	SUITE_ADD_TEST (suite, test_derive_key);
	SUITE_ADD_TEST (suite, test_random);
}
