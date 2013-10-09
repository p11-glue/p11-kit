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

#include "test.h"

#include "library.h"
#include "mock.h"
#include "p11-kit.h"

#include <sys/types.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

static void
test_get_info (void)
{
	CK_FUNCTION_LIST_PTR module;
	CK_INFO info;
	CK_RV rv;

	module = setup_mock_module (NULL);

	rv = (module->C_GetInfo) (&info);
	assert_num_eq (rv, CKR_OK);
	assert_num_eq (MOCK_INFO.cryptokiVersion.major, info.cryptokiVersion.major);
	assert_num_eq (MOCK_INFO.cryptokiVersion.minor, info.cryptokiVersion.minor);
	assert (memcmp (MOCK_INFO.manufacturerID, info.manufacturerID, sizeof (info.manufacturerID)) == 0);
	assert_num_eq (MOCK_INFO.flags, info.flags);
	assert (memcmp (MOCK_INFO.libraryDescription, info.libraryDescription, sizeof (info.libraryDescription)) == 0);
	assert_num_eq (MOCK_INFO.libraryVersion.major, info.libraryVersion.major);
	assert_num_eq (MOCK_INFO.libraryVersion.minor, info.libraryVersion.minor);

	teardown_mock_module (module);
}

static void
test_get_slot_list (void)
{
	CK_FUNCTION_LIST_PTR module;
	CK_SLOT_ID slot_list[8];
	CK_ULONG count = 0;
	CK_RV rv;

	module = setup_mock_module (NULL);

	/* Normal module has 2 slots, one with token present */
	rv = (module->C_GetSlotList) (CK_TRUE, NULL, &count);
	assert (rv == CKR_OK);
	assert_num_eq (MOCK_SLOTS_PRESENT, count);
	rv = (module->C_GetSlotList) (CK_FALSE, NULL, &count);
	assert (rv == CKR_OK);
	assert_num_eq (MOCK_SLOTS_ALL, count);

	count = 8;
	rv = (module->C_GetSlotList) (CK_TRUE, slot_list, &count);
	assert (rv == CKR_OK);
	assert_num_eq (MOCK_SLOTS_PRESENT, count);
	assert_num_eq (MOCK_SLOT_ONE_ID, slot_list[0]);

	count = 8;
	rv = (module->C_GetSlotList) (CK_FALSE, slot_list, &count);
	assert (rv == CKR_OK);
	assert_num_eq (MOCK_SLOTS_ALL, count);
	assert_num_eq (MOCK_SLOT_ONE_ID, slot_list[0]);
	assert_num_eq (MOCK_SLOT_TWO_ID, slot_list[1]);

	teardown_mock_module (module);
}

static void
test_get_slot_info (void)
{
	CK_FUNCTION_LIST_PTR module;
	CK_SLOT_INFO info;
	char *string;
	CK_RV rv;

	module = setup_mock_module (NULL);

	rv = (module->C_GetSlotInfo) (MOCK_SLOT_ONE_ID, &info);
	assert (rv == CKR_OK);
	string = p11_kit_space_strdup (info.slotDescription, sizeof (info.slotDescription));
	assert_str_eq ("TEST SLOT", string);
	free (string);
	string = p11_kit_space_strdup (info.manufacturerID, sizeof (info.manufacturerID));
	assert_str_eq ("TEST MANUFACTURER", string);
	free (string);
	assert_num_eq (CKF_TOKEN_PRESENT | CKF_REMOVABLE_DEVICE, info.flags);
	assert_num_eq (55, info.hardwareVersion.major);
	assert_num_eq (155, info.hardwareVersion.minor);
	assert_num_eq (65, info.firmwareVersion.major);
	assert_num_eq (165, info.firmwareVersion.minor);

	rv = (module->C_GetSlotInfo) (MOCK_SLOT_TWO_ID, &info);
	assert (rv == CKR_OK);
	assert_num_eq (CKF_REMOVABLE_DEVICE, info.flags);

	rv = (module->C_GetSlotInfo) (0, &info);
	assert (rv == CKR_SLOT_ID_INVALID);

	teardown_mock_module (module);
}

static void
test_get_token_info (void)
{
	CK_FUNCTION_LIST_PTR module;
	CK_TOKEN_INFO info;
	char *string;
	CK_RV rv;

	module = setup_mock_module (NULL);

	rv = (module->C_GetTokenInfo) (MOCK_SLOT_ONE_ID, &info);
	assert (rv == CKR_OK);

	string = p11_kit_space_strdup (info.label, sizeof (info.label));
	assert_str_eq ("TEST LABEL", string);
	free (string);
	string = p11_kit_space_strdup (info.manufacturerID, sizeof (info.manufacturerID));
	assert_str_eq ("TEST MANUFACTURER", string);
	free (string);
	string = p11_kit_space_strdup (info.model, sizeof (info.model));
	assert_str_eq ("TEST MODEL", string);
	free (string);
	string = p11_kit_space_strdup (info.serialNumber, sizeof (info.serialNumber));
	assert_str_eq ("TEST SERIAL", string);
	free (string);
	assert_num_eq (CKF_LOGIN_REQUIRED | CKF_USER_PIN_INITIALIZED | CKF_CLOCK_ON_TOKEN | CKF_TOKEN_INITIALIZED, info.flags);
	assert_num_eq (1, info.ulMaxSessionCount);
	assert_num_eq (2, info.ulSessionCount);
	assert_num_eq (3, info.ulMaxRwSessionCount);
	assert_num_eq (4, info.ulRwSessionCount);
	assert_num_eq (5, info.ulMaxPinLen);
	assert_num_eq (6, info.ulMinPinLen);
	assert_num_eq (7, info.ulTotalPublicMemory);
	assert_num_eq (8, info.ulFreePublicMemory);
	assert_num_eq (9, info.ulTotalPrivateMemory);
	assert_num_eq (10, info.ulFreePrivateMemory);
	assert_num_eq (75, info.hardwareVersion.major);
	assert_num_eq (175, info.hardwareVersion.minor);
	assert_num_eq (85, info.firmwareVersion.major);
	assert_num_eq (185, info.firmwareVersion.minor);
	assert (memcmp (info.utcTime, "1999052509195900", sizeof (info.utcTime)) == 0);

	rv = (module->C_GetTokenInfo) (MOCK_SLOT_TWO_ID, &info);
	assert (rv == CKR_TOKEN_NOT_PRESENT);

	rv = (module->C_GetTokenInfo) (0, &info);
	assert (rv == CKR_SLOT_ID_INVALID);

	teardown_mock_module (module);
}

static void
test_get_mechanism_list (void)
{
	CK_FUNCTION_LIST_PTR module;
	CK_MECHANISM_TYPE mechs[8];
	CK_ULONG count = 0;
	CK_RV rv;

	module = setup_mock_module (NULL);

	rv = (module->C_GetMechanismList) (MOCK_SLOT_ONE_ID, NULL, &count);
	assert (rv == CKR_OK);
	assert_num_eq (2, count);
	rv = (module->C_GetMechanismList) (MOCK_SLOT_TWO_ID, NULL, &count);
	assert (rv == CKR_TOKEN_NOT_PRESENT);
	rv = (module->C_GetMechanismList) (0, NULL, &count);
	assert (rv == CKR_SLOT_ID_INVALID);

	count = 8;
	rv = (module->C_GetMechanismList) (MOCK_SLOT_ONE_ID, mechs, &count);
	assert (rv == CKR_OK);
	assert_num_eq (2, count);
	assert_num_eq (mechs[0], CKM_MOCK_CAPITALIZE);
	assert_num_eq (mechs[1], CKM_MOCK_PREFIX);

	teardown_mock_module (module);
}

static void
test_get_mechanism_info (void)
{
	CK_FUNCTION_LIST_PTR module;
	CK_MECHANISM_INFO info;
	CK_RV rv;

	module = setup_mock_module (NULL);

	rv = (module->C_GetMechanismInfo) (MOCK_SLOT_ONE_ID, CKM_MOCK_CAPITALIZE, &info);
	assert_num_eq (rv, CKR_OK);
	assert_num_eq (512, info.ulMinKeySize);
	assert_num_eq (4096, info.ulMaxKeySize);
	assert_num_eq (CKF_ENCRYPT | CKF_DECRYPT, info.flags);

	rv = (module->C_GetMechanismInfo) (MOCK_SLOT_ONE_ID, CKM_MOCK_PREFIX, &info);
	assert (rv == CKR_OK);
	assert_num_eq (2048, info.ulMinKeySize);
	assert_num_eq (2048, info.ulMaxKeySize);
	assert_num_eq (CKF_SIGN | CKF_VERIFY, info.flags);

	rv = (module->C_GetMechanismInfo) (MOCK_SLOT_TWO_ID, CKM_MOCK_PREFIX, &info);
	assert (rv == CKR_TOKEN_NOT_PRESENT);
	rv = (module->C_GetMechanismInfo) (MOCK_SLOT_ONE_ID, 0, &info);
	assert (rv == CKR_MECHANISM_INVALID);
	rv = (module->C_GetMechanismInfo) (0, CKM_MOCK_PREFIX, &info);
	assert (rv == CKR_SLOT_ID_INVALID);

	teardown_mock_module (module);
}

static void
test_init_token (void)
{
	CK_FUNCTION_LIST_PTR module;
	CK_RV rv;

	module = setup_mock_module (NULL);

	rv = (module->C_InitToken) (MOCK_SLOT_ONE_ID, (CK_UTF8CHAR_PTR)"TEST PIN", 8, (CK_UTF8CHAR_PTR)"TEST LABEL");
	assert (rv == CKR_OK);

	rv = (module->C_InitToken) (MOCK_SLOT_ONE_ID, (CK_UTF8CHAR_PTR)"OTHER", 5, (CK_UTF8CHAR_PTR)"TEST LABEL");
	assert (rv == CKR_PIN_INVALID);
	rv = (module->C_InitToken) (MOCK_SLOT_TWO_ID, (CK_UTF8CHAR_PTR)"TEST PIN", 8, (CK_UTF8CHAR_PTR)"TEST LABEL");
	assert (rv == CKR_TOKEN_NOT_PRESENT);
	rv = (module->C_InitToken) (0, (CK_UTF8CHAR_PTR)"TEST PIN", 8, (CK_UTF8CHAR_PTR)"TEST LABEL");
	assert (rv == CKR_SLOT_ID_INVALID);

	teardown_mock_module (module);
}

static void
test_wait_for_slot_event (void)
{
	CK_FUNCTION_LIST_PTR module;
	CK_SLOT_ID slot;
	CK_RV rv;

#ifdef MOCK_SKIP_WAIT_TEST
	return;
#endif

	module = setup_mock_module (NULL);

	rv = (module->C_WaitForSlotEvent) (0, &slot, NULL);
	assert (rv == CKR_OK);
	assert_num_eq (slot, MOCK_SLOT_TWO_ID);

	rv = (module->C_WaitForSlotEvent) (CKF_DONT_BLOCK, &slot, NULL);
	assert (rv == CKR_NO_EVENT);

	teardown_mock_module (module);
}

static void
test_open_close_session (void)
{
	CK_FUNCTION_LIST_PTR module;
	CK_SESSION_HANDLE session = 0;
	CK_RV rv;

	module = setup_mock_module (NULL);

	rv = (module->C_OpenSession) (MOCK_SLOT_TWO_ID, CKF_SERIAL_SESSION, NULL, NULL, &session);
	assert (rv == CKR_TOKEN_NOT_PRESENT);
	rv = (module->C_OpenSession) (0, CKF_SERIAL_SESSION, NULL, NULL, &session);
	assert (rv == CKR_SLOT_ID_INVALID);

	rv = (module->C_OpenSession) (MOCK_SLOT_ONE_ID, CKF_SERIAL_SESSION, NULL, NULL, &session);
	assert (rv == CKR_OK);
	assert (session != 0);

	rv = (module->C_CloseSession) (session);
	assert (rv == CKR_OK);

	rv = (module->C_CloseSession) (session);
	assert (rv == CKR_SESSION_HANDLE_INVALID);

	teardown_mock_module (module);
}

static void
test_close_all_sessions (void)
{
	CK_FUNCTION_LIST_PTR module;
	CK_SESSION_HANDLE session = 0;
	CK_RV rv;

	module = setup_mock_module (NULL);

	rv = (module->C_OpenSession) (MOCK_SLOT_ONE_ID, CKF_SERIAL_SESSION, NULL, NULL, &session);
	assert (rv == CKR_OK);
	assert (session != 0);

	rv = (module->C_CloseAllSessions) (MOCK_SLOT_ONE_ID);
	assert (rv == CKR_OK);

	rv = (module->C_CloseSession) (session);
	assert (rv == CKR_SESSION_HANDLE_INVALID);

	teardown_mock_module (module);
}

static void
test_get_function_status (void)
{
	CK_FUNCTION_LIST_PTR module;
	CK_SESSION_HANDLE session = 0;
	CK_RV rv;

	module = setup_mock_module (&session);

	rv = (module->C_GetFunctionStatus) (session);
	assert (rv == CKR_FUNCTION_NOT_PARALLEL);

	teardown_mock_module (module);
}

static void
test_cancel_function (void)
{
	CK_FUNCTION_LIST_PTR module;
	CK_SESSION_HANDLE session = 0;
	CK_RV rv;

	module = setup_mock_module (&session);

	rv = (module->C_CancelFunction) (session);
	assert (rv == CKR_FUNCTION_NOT_PARALLEL);

	teardown_mock_module (module);
}

static void
test_get_session_info (void)
{
	CK_FUNCTION_LIST_PTR module;
	CK_SESSION_HANDLE session = 0;
	CK_SESSION_INFO info;
	CK_RV rv;

	module = setup_mock_module (NULL);

	rv = (module->C_GetSessionInfo) (0, &info);
	assert (rv == CKR_SESSION_HANDLE_INVALID);

	rv = (module->C_OpenSession) (MOCK_SLOT_ONE_ID, CKF_SERIAL_SESSION, NULL, NULL, &session);
	assert (rv == CKR_OK);
	assert (session != 0);

	rv = (module->C_GetSessionInfo) (session, &info);
	assert (rv == CKR_OK);
	assert_num_eq (MOCK_SLOT_ONE_ID, info.slotID);
	assert_num_eq (CKS_RO_PUBLIC_SESSION, info.state);
	assert_num_eq (CKF_SERIAL_SESSION, info.flags);
	assert_num_eq (1414, info.ulDeviceError);

	rv = (module->C_OpenSession) (MOCK_SLOT_ONE_ID, CKF_RW_SESSION | CKF_SERIAL_SESSION, NULL, NULL, &session);
	assert (rv == CKR_OK);
	assert (session != 0);

	rv = (module->C_GetSessionInfo) (session, &info);
	assert (rv == CKR_OK);
	assert_num_eq (MOCK_SLOT_ONE_ID, info.slotID);
	assert_num_eq (CKS_RW_PUBLIC_SESSION, info.state);
	assert_num_eq (CKF_SERIAL_SESSION | CKF_RW_SESSION, info.flags);
	assert_num_eq (1414, info.ulDeviceError);

	teardown_mock_module (module);
}

static void
test_init_pin (void)
{
	CK_FUNCTION_LIST_PTR module;
	CK_SESSION_HANDLE session = 0;
	CK_RV rv;

	module = setup_mock_module (&session);

	rv = (module->C_InitPIN) (0, (CK_UTF8CHAR_PTR)"TEST PIN", 8);
	assert (rv == CKR_SESSION_HANDLE_INVALID);

	rv = (module->C_InitPIN) (session, (CK_UTF8CHAR_PTR)"TEST PIN", 8);
	assert (rv == CKR_OK);

	rv = (module->C_InitPIN) (session, (CK_UTF8CHAR_PTR)"OTHER", 5);
	assert (rv == CKR_PIN_INVALID);

	teardown_mock_module (module);
}

static void
test_set_pin (void)
{
	CK_FUNCTION_LIST_PTR module;
	CK_SESSION_HANDLE session = 0;
	CK_RV rv;

	module = setup_mock_module (&session);

	rv = (module->C_SetPIN) (0, (CK_UTF8CHAR_PTR)"booo", 4, (CK_UTF8CHAR_PTR)"TEST PIN", 8);
	assert (rv == CKR_SESSION_HANDLE_INVALID);

	rv = (module->C_SetPIN) (session, (CK_UTF8CHAR_PTR)"booo", 4, (CK_UTF8CHAR_PTR)"TEST PIN", 8);
	assert (rv == CKR_OK);

	rv = (module->C_SetPIN) (session, (CK_UTF8CHAR_PTR)"other", 5, (CK_UTF8CHAR_PTR)"OTHER", 5);
	assert (rv == CKR_PIN_INCORRECT);

	teardown_mock_module (module);
}

static void
test_operation_state (void)
{
	CK_FUNCTION_LIST_PTR module;
	CK_BYTE state[128];
	CK_ULONG state_len;
	CK_SESSION_HANDLE session = 0;
	CK_RV rv;

	module = setup_mock_module (&session);

	state_len = sizeof (state);
	rv = (module->C_GetOperationState) (0, state, &state_len);
	assert (rv == CKR_SESSION_HANDLE_INVALID);

	state_len = sizeof (state);
	rv = (module->C_GetOperationState) (session, state, &state_len);
	assert (rv == CKR_OK);

	rv = (module->C_SetOperationState) (session, state, state_len, 355, 455);
	assert (rv == CKR_OK);

	rv = (module->C_SetOperationState) (0, state, state_len, 355, 455);
	assert (rv == CKR_SESSION_HANDLE_INVALID);

	teardown_mock_module (module);
}

static void
test_login_logout (void)
{
	CK_FUNCTION_LIST_PTR module;
	CK_SESSION_HANDLE session = 0;
	CK_RV rv;

	module = setup_mock_module (&session);

	rv = (module->C_Login) (0, CKU_USER, (CK_UTF8CHAR_PTR)"booo", 4);
	assert (rv == CKR_SESSION_HANDLE_INVALID);

	rv = (module->C_Login) (session, CKU_USER, (CK_UTF8CHAR_PTR)"bo", 2);
	assert (rv == CKR_PIN_INCORRECT);

	rv = (module->C_Login) (session, CKU_USER, (CK_UTF8CHAR_PTR)"booo", 4);
	assert (rv == CKR_OK);

	rv = (module->C_Logout) (session);
	assert (rv == CKR_OK);

	rv = (module->C_Logout) (session);
	assert (rv == CKR_USER_NOT_LOGGED_IN);

	teardown_mock_module (module);
}

static void
test_get_attribute_value (void)
{
	CK_FUNCTION_LIST_PTR module;
	CK_SESSION_HANDLE session = 0;
	CK_ATTRIBUTE attrs[8];
	char label[32];
	CK_OBJECT_CLASS klass;
	CK_RV rv;

	module = setup_mock_module (&session);

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
	assert (rv == CKR_USER_NOT_LOGGED_IN);

	rv = (module->C_GetAttributeValue) (session, MOCK_PUBLIC_KEY_CAPITALIZE, attrs, 2);
	assert (rv == CKR_BUFFER_TOO_SMALL);

	/* Get right size */
	attrs[1].pValue = NULL;
	attrs[1].ulValueLen = 0;

	rv = (module->C_GetAttributeValue) (session, MOCK_PUBLIC_KEY_CAPITALIZE, attrs, 2);
	assert (rv == CKR_OK);

	rv = (module->C_GetAttributeValue) (session, MOCK_PUBLIC_KEY_CAPITALIZE, attrs, 3);
	assert (rv == CKR_ATTRIBUTE_TYPE_INVALID);

	assert_num_eq (CKO_PUBLIC_KEY, klass);
	assert_num_eq (21, attrs[1].ulValueLen);
	assert_ptr_eq (NULL, attrs[1].pValue);
	attrs[1].pValue = label;
	attrs[1].ulValueLen = sizeof (label);
	assert ((CK_ULONG)-1 == attrs[2].ulValueLen);
	assert_ptr_eq (NULL, attrs[2].pValue);

	rv = (module->C_GetAttributeValue) (session, MOCK_PUBLIC_KEY_CAPITALIZE, attrs, 3);
	assert (rv == CKR_ATTRIBUTE_TYPE_INVALID);

	assert_num_eq (CKO_PUBLIC_KEY, klass);
	assert_num_eq (21, attrs[1].ulValueLen);
	assert_ptr_eq (label, attrs[1].pValue);
	assert (memcmp (label, "Public Capitalize Key", attrs[1].ulValueLen) == 0);
	assert ((CK_ULONG)-1 == attrs[2].ulValueLen);
	assert_ptr_eq (NULL, attrs[2].pValue);

	teardown_mock_module (module);
}

static void
test_set_attribute_value (void)
{
	CK_FUNCTION_LIST_PTR module;
	CK_SESSION_HANDLE session = 0;
	CK_ATTRIBUTE attrs[8];
	char label[32];
	CK_ULONG bits;
	CK_RV rv;

	module = setup_mock_module (&session);

	strcpy (label, "Blahooo");
	bits = 1555;

	attrs[0].type = CKA_LABEL;
	attrs[0].pValue = label;
	attrs[0].ulValueLen = strlen (label);
	attrs[1].type = CKA_BITS_PER_PIXEL;
	attrs[1].pValue = &bits;
	attrs[1].ulValueLen = sizeof (bits);

	rv = (module->C_SetAttributeValue) (session, MOCK_PRIVATE_KEY_CAPITALIZE, attrs, 2);
	assert (rv == CKR_USER_NOT_LOGGED_IN);

	rv = (module->C_SetAttributeValue) (session, MOCK_PUBLIC_KEY_CAPITALIZE, attrs, 2);
	assert (rv == CKR_OK);

	memset (label, 0, sizeof (label));
	bits = 0;

	rv = (module->C_GetAttributeValue) (session, MOCK_PUBLIC_KEY_CAPITALIZE, attrs, 2);
	assert (rv == CKR_OK);

	assert_num_eq (bits, 1555);
	assert_num_eq (7, attrs[0].ulValueLen);
	assert (memcmp (label, "Blahooo", attrs[0].ulValueLen) == 0);

	teardown_mock_module (module);
}

static void
test_create_object (void)
{
	CK_FUNCTION_LIST_PTR module;
	CK_SESSION_HANDLE session = 0;
	CK_OBJECT_HANDLE object;
	CK_ATTRIBUTE attrs[8];
	char label[32];
	CK_ULONG bits;
	CK_RV rv;

	module = setup_mock_module (&session);

	strcpy (label, "Blahooo");
	bits = 1555;

	attrs[0].type = CKA_LABEL;
	attrs[0].pValue = label;
	attrs[0].ulValueLen = strlen (label);
	attrs[1].type = CKA_BITS_PER_PIXEL;
	attrs[1].pValue = &bits;
	attrs[1].ulValueLen = sizeof (bits);

	rv = (module->C_CreateObject) (0, attrs, 2, &object);
	assert (rv == CKR_SESSION_HANDLE_INVALID);

	rv = (module->C_CreateObject) (session, attrs, 2, &object);
	assert (rv == CKR_OK);

	attrs[0].ulValueLen = sizeof (label);
	memset (label, 0, sizeof (label));
	bits = 0;

	rv = (module->C_GetAttributeValue) (session, object, attrs, 2);
	assert (rv == CKR_OK);

	assert_num_eq (bits, 1555);
	assert_num_eq (7, attrs[0].ulValueLen);
	assert (memcmp (label, "Blahooo", attrs[0].ulValueLen) == 0);

	teardown_mock_module (module);
}

static void
test_copy_object (void)
{
	CK_FUNCTION_LIST_PTR module;
	CK_SESSION_HANDLE session = 0;
	CK_OBJECT_HANDLE object;
	CK_ATTRIBUTE attrs[8];
	char label[32];
	CK_ULONG bits;
	CK_RV rv;

	module = setup_mock_module (&session);

	bits = 1555;

	attrs[0].type = CKA_BITS_PER_PIXEL;
	attrs[0].pValue = &bits;
	attrs[0].ulValueLen = sizeof (bits);

	rv = (module->C_CopyObject) (session, 1333, attrs, 1, &object);
	assert (rv == CKR_OBJECT_HANDLE_INVALID);

	rv = (module->C_CopyObject) (session, MOCK_PUBLIC_KEY_CAPITALIZE, attrs, 1, &object);
	assert (rv == CKR_OK);

	attrs[1].type = CKA_LABEL;
	attrs[1].pValue = label;
	attrs[1].ulValueLen = sizeof (label);
	bits = 0;

	rv = (module->C_GetAttributeValue) (session, object, attrs, 2);
	assert (rv == CKR_OK);

	assert_num_eq (bits, 1555);
	assert_num_eq (21, attrs[1].ulValueLen);
	assert (memcmp (label, "Public Capitalize Key", attrs[1].ulValueLen) == 0);

	teardown_mock_module (module);
}

static void
test_destroy_object (void)
{
	CK_FUNCTION_LIST_PTR module;
	CK_SESSION_HANDLE session = 0;
	CK_ATTRIBUTE attrs[8];
	char label[32];
	CK_RV rv;

	module = setup_mock_module (&session);

	attrs[0].type = CKA_LABEL;
	attrs[0].pValue = label;
	attrs[0].ulValueLen = sizeof (label);

	rv = (module->C_GetAttributeValue) (session, MOCK_PUBLIC_KEY_CAPITALIZE, attrs, 1);
	assert (rv == CKR_OK);

	rv = (module->C_DestroyObject) (0, MOCK_PUBLIC_KEY_CAPITALIZE);
	assert (rv == CKR_SESSION_HANDLE_INVALID);

	rv = (module->C_DestroyObject) (session, MOCK_PUBLIC_KEY_CAPITALIZE);
	assert (rv == CKR_OK);

	rv = (module->C_GetAttributeValue) (session, MOCK_PUBLIC_KEY_CAPITALIZE, attrs, 1);
	assert (rv == CKR_OBJECT_HANDLE_INVALID);

	teardown_mock_module (module);
}

static void
test_get_object_size (void)
{
	CK_FUNCTION_LIST_PTR module;
	CK_SESSION_HANDLE session = 0;
	CK_ULONG size;
	CK_RV rv;

	module = setup_mock_module (&session);

	rv = (module->C_GetObjectSize) (session, 1333, &size);
	assert (rv == CKR_OBJECT_HANDLE_INVALID);

	rv = (module->C_GetObjectSize) (session, MOCK_PUBLIC_KEY_CAPITALIZE, &size);
	assert (rv == CKR_OK);

	/* The number here is the length of all attributes added up */
	assert_num_eq (sizeof (CK_ULONG) == 8 ? 44 : 36, size);

	teardown_mock_module (module);
}

static void
test_find_objects (void)
{
	CK_FUNCTION_LIST_PTR module;
	CK_SESSION_HANDLE session = 0;
	CK_OBJECT_CLASS klass = CKO_PUBLIC_KEY;
	CK_ATTRIBUTE attr = { CKA_CLASS, &klass, sizeof (klass) };
	CK_OBJECT_HANDLE objects[16];
	CK_ULONG count;
	CK_ULONG i;
	CK_RV rv;

	module = setup_mock_module (&session);

	rv = (module->C_FindObjectsInit) (0, &attr, 1);
	assert (rv == CKR_SESSION_HANDLE_INVALID);

	rv = (module->C_FindObjectsInit) (session, &attr, 1);
	assert (rv == CKR_OK);

	rv = (module->C_FindObjects) (0, objects, 16, &count);
	assert (rv == CKR_SESSION_HANDLE_INVALID);

	rv = (module->C_FindObjects) (session, objects, 16, &count);
	assert (rv == CKR_OK);

	assert (count < 16);

	/* Make sure we get the capitalize public key */
	for (i = 0; i < count; i++) {
		if (objects[i] == MOCK_PUBLIC_KEY_CAPITALIZE)
			break;
	}
	assert (i != count);

	/* Make sure we get the prefix public key */
	for (i = 0; i < count; i++) {
		if (objects[i] == MOCK_PUBLIC_KEY_PREFIX)
			break;
	}
	assert (i != count);

	/* Make sure all public keys */
	for (i = 0; i < count; i++) {
		klass = (CK_ULONG)-1;
		rv = (module->C_GetAttributeValue) (session, objects[i], &attr, 1);
		assert (rv == CKR_OK);
		assert_num_eq (CKO_PUBLIC_KEY, klass);
	}

	rv = (module->C_FindObjectsFinal) (session);
	assert (rv == CKR_OK);

	rv = (module->C_FindObjectsFinal) (session);
	assert (rv == CKR_OPERATION_NOT_INITIALIZED);

	teardown_mock_module (module);
}

static void
test_encrypt (void)
{
	CK_FUNCTION_LIST_PTR module;
	CK_SESSION_HANDLE session = 0;
	CK_MECHANISM mech = { CKM_MOCK_CAPITALIZE, NULL, 0 };
	CK_BYTE data[128];
	CK_ULONG length;
	CK_RV rv;

	module = setup_mock_module (&session);

	rv = (module->C_EncryptInit) (session, &mech, MOCK_PUBLIC_KEY_PREFIX);
	assert (rv == CKR_KEY_HANDLE_INVALID);

	rv = (module->C_EncryptInit) (session, &mech, MOCK_PUBLIC_KEY_CAPITALIZE);
	assert (rv == CKR_OK);

	length = sizeof (data);
	rv = (module->C_Encrypt) (0, (CK_BYTE_PTR)"blah", 4, data, &length);
	assert (rv == CKR_SESSION_HANDLE_INVALID);

	length = sizeof (data);
	rv = (module->C_Encrypt) (session, (CK_BYTE_PTR)"blah", 4, data, &length);
	assert (rv == CKR_OK);

	assert_num_eq (4, length);
	assert (memcmp (data, "BLAH", 4) == 0);

	rv = (module->C_EncryptInit) (session, &mech, MOCK_PUBLIC_KEY_CAPITALIZE);
	assert (rv == CKR_OK);

	length = sizeof (data);
	rv = (module->C_EncryptUpdate) (0, (CK_BYTE_PTR)"blah", 4, data, &length);
	assert (rv == CKR_SESSION_HANDLE_INVALID);

	length = sizeof (data);
	rv = (module->C_EncryptUpdate) (session, (CK_BYTE_PTR)"sLurm", 5, data, &length);
	assert (rv == CKR_OK);

	assert_num_eq (5, length);
	assert (memcmp (data, "SLURM", 5) == 0);

	length = sizeof (data);
	rv = (module->C_EncryptFinal) (0, data, &length);
	assert (rv == CKR_SESSION_HANDLE_INVALID);

	length = sizeof (data);
	rv = (module->C_EncryptFinal) (session, data, &length);
	assert (rv == CKR_OK);

	teardown_mock_module (module);
}

static void
test_decrypt (void)
{
	CK_FUNCTION_LIST_PTR module;
	CK_SESSION_HANDLE session = 0;
	CK_MECHANISM mech = { CKM_MOCK_CAPITALIZE, NULL, 0 };
	CK_BYTE data[128];
	CK_ULONG length;
	CK_RV rv;

	module = setup_mock_module (&session);

	rv = (module->C_Login) (session, CKU_USER, (CK_BYTE_PTR)"booo", 4);
	assert (rv == CKR_OK);

	rv = (module->C_DecryptInit) (session, &mech, MOCK_PRIVATE_KEY_PREFIX);
	assert (rv == CKR_KEY_HANDLE_INVALID);

	rv = (module->C_DecryptInit) (session, &mech, MOCK_PRIVATE_KEY_CAPITALIZE);
	assert (rv == CKR_OK);

	length = sizeof (data);
	rv = (module->C_Decrypt) (0, (CK_BYTE_PTR)"bLAH", 4, data, &length);
	assert (rv == CKR_SESSION_HANDLE_INVALID);

	length = sizeof (data);
	rv = (module->C_Decrypt) (session, (CK_BYTE_PTR)"BLAh", 4, data, &length);
	assert (rv == CKR_OK);

	assert_num_eq (4, length);
	assert (memcmp (data, "blah", 4) == 0);

	rv = (module->C_DecryptInit) (session, &mech, MOCK_PRIVATE_KEY_CAPITALIZE);
	assert (rv == CKR_OK);

	length = sizeof (data);
	rv = (module->C_DecryptUpdate) (0, (CK_BYTE_PTR)"blah", 4, data, &length);
	assert (rv == CKR_SESSION_HANDLE_INVALID);

	length = sizeof (data);
	rv = (module->C_DecryptUpdate) (session, (CK_BYTE_PTR)"sLuRM", 5, data, &length);
	assert (rv == CKR_OK);

	assert_num_eq (5, length);
	assert (memcmp (data, "slurm", 5) == 0);

	length = sizeof (data);
	rv = (module->C_DecryptFinal) (0, data, &length);
	assert (rv == CKR_SESSION_HANDLE_INVALID);

	length = sizeof (data);
	rv = (module->C_DecryptFinal) (session, data, &length);
	assert (rv == CKR_OK);

	teardown_mock_module (module);
}

static void
test_digest (void)
{
	CK_FUNCTION_LIST_PTR module;
	CK_SESSION_HANDLE session = 0;
	CK_MECHANISM mech = { CKM_MOCK_COUNT, NULL, 0 };
	CK_BYTE digest[128];
	CK_ULONG length;
	CK_RV rv;

	module = setup_mock_module (&session);

	rv = (module->C_DigestInit) (0, &mech);
	assert (rv == CKR_SESSION_HANDLE_INVALID);

	rv = (module->C_DigestInit) (session, &mech);
	assert (rv == CKR_OK);

	length = sizeof (digest);
	rv = (module->C_Digest) (0, (CK_BYTE_PTR)"bLAH", 4, digest, &length);
	assert (rv == CKR_SESSION_HANDLE_INVALID);

	length = sizeof (digest);
	rv = (module->C_Digest) (session, (CK_BYTE_PTR)"BLAh", 4, digest, &length);
	assert (rv == CKR_OK);

	assert_num_eq (1, length);
	assert (memcmp (digest, "4", 1) == 0);

	rv = (module->C_DigestInit) (session, &mech);
	assert (rv == CKR_OK);

	rv = (module->C_DigestUpdate) (0, (CK_BYTE_PTR)"blah", 4);
	assert (rv == CKR_SESSION_HANDLE_INVALID);

	rv = (module->C_DigestUpdate) (session, (CK_BYTE_PTR)"sLuRM", 5);
	assert (rv == CKR_OK);

	/* Adds the the value of object handle to hash: 6 */
	assert_num_eq (6, MOCK_PUBLIC_KEY_PREFIX);
	rv = (module->C_DigestKey) (session, MOCK_PUBLIC_KEY_PREFIX);
	assert (rv == CKR_OK);

	rv = (module->C_DigestUpdate) (session, (CK_BYTE_PTR)"Other", 5);
	assert (rv == CKR_OK);

	length = sizeof (digest);
	rv = (module->C_DigestFinal) (0, digest, &length);
	assert (rv == CKR_SESSION_HANDLE_INVALID);

	length = sizeof (digest);
	rv = (module->C_DigestFinal) (session, digest, &length);
	assert (rv == CKR_OK);

	assert_num_eq (2, length);
	assert (memcmp (digest, "16", 2) == 0);

	teardown_mock_module (module);
}

static void
test_sign (void)
{
	CK_FUNCTION_LIST_PTR module;
	CK_SESSION_HANDLE session = 0;
	CK_MECHANISM mech = { CKM_MOCK_PREFIX, "prefix:", 7 };
	CK_BYTE signature[128];
	CK_ULONG length;
	CK_RV rv;

	module = setup_mock_module (&session);

	rv = (module->C_Login) (session, CKU_USER, (CK_BYTE_PTR)"booo", 4);
	assert (rv == CKR_OK);

	rv = (module->C_SignInit) (0, &mech, MOCK_PRIVATE_KEY_PREFIX);
	assert (rv == CKR_SESSION_HANDLE_INVALID);

	rv = (module->C_SignInit) (session, &mech, MOCK_PRIVATE_KEY_PREFIX);
	assert (rv == CKR_OK);

	rv = (module->C_Login) (session, CKU_CONTEXT_SPECIFIC, (CK_BYTE_PTR)"booo", 4);
	assert (rv == CKR_OK);

	length = sizeof (signature);
	rv = (module->C_Sign) (0, (CK_BYTE_PTR)"bLAH", 4, signature, &length);
	assert (rv == CKR_SESSION_HANDLE_INVALID);

	length = sizeof (signature);
	rv = (module->C_Sign) (session, (CK_BYTE_PTR)"BLAh", 4, signature, &length);
	assert (rv == CKR_OK);

	assert_num_eq (13, length);
	assert (memcmp (signature, "prefix:value4", 13) == 0);

	rv = (module->C_SignInit) (session, &mech, MOCK_PRIVATE_KEY_PREFIX);
	assert (rv == CKR_OK);

	rv = (module->C_Login) (session, CKU_CONTEXT_SPECIFIC, (CK_BYTE_PTR)"booo", 4);
	assert (rv == CKR_OK);

	rv = (module->C_SignUpdate) (0, (CK_BYTE_PTR)"blah", 4);
	assert (rv == CKR_SESSION_HANDLE_INVALID);

	rv = (module->C_SignUpdate) (session, (CK_BYTE_PTR)"sLuRM", 5);
	assert (rv == CKR_OK);

	rv = (module->C_SignUpdate) (session, (CK_BYTE_PTR)"Other", 5);
	assert (rv == CKR_OK);

	length = sizeof (signature);
	rv = (module->C_SignFinal) (0, signature, &length);
	assert (rv == CKR_SESSION_HANDLE_INVALID);

	length = sizeof (signature);
	rv = (module->C_SignFinal) (session, signature, &length);
	assert (rv == CKR_OK);

	assert_num_eq (14, length);
	assert (memcmp (signature, "prefix:value10", 2) == 0);

	teardown_mock_module (module);
}

static void
test_sign_recover (void)
{
	CK_FUNCTION_LIST_PTR module;
	CK_SESSION_HANDLE session = 0;
	CK_MECHANISM mech = { CKM_MOCK_PREFIX, "prefix:", 7 };
	CK_BYTE signature[128];
	CK_ULONG length;
	CK_RV rv;

	module = setup_mock_module (&session);

	rv = (module->C_Login) (session, CKU_USER, (CK_BYTE_PTR)"booo", 4);
	assert (rv == CKR_OK);

	rv = (module->C_SignRecoverInit) (0, &mech, MOCK_PRIVATE_KEY_PREFIX);
	assert (rv == CKR_SESSION_HANDLE_INVALID);

	rv = (module->C_SignRecoverInit) (session, &mech, MOCK_PRIVATE_KEY_PREFIX);
	assert (rv == CKR_OK);

	rv = (module->C_Login) (session, CKU_CONTEXT_SPECIFIC, (CK_BYTE_PTR)"booo", 4);
	assert (rv == CKR_OK);

	length = sizeof (signature);
	rv = (module->C_SignRecover) (0, (CK_BYTE_PTR)"bLAH", 4, signature, &length);
	assert (rv == CKR_SESSION_HANDLE_INVALID);

	length = sizeof (signature);
	rv = (module->C_SignRecover) (session, (CK_BYTE_PTR)"BLAh", 4, signature, &length);
	assert (rv == CKR_OK);

	assert_num_eq (16, length);
	assert (memcmp (signature, "prefix:valueBLAh", 16) == 0);

	teardown_mock_module (module);
}

static void
test_verify (void)
{
	CK_FUNCTION_LIST_PTR module;
	CK_SESSION_HANDLE session = 0;
	CK_MECHANISM mech = { CKM_MOCK_PREFIX, "prefix:", 7 };
	CK_BYTE signature[128];
	CK_ULONG length;
	CK_RV rv;

	module = setup_mock_module (&session);

	rv = (module->C_VerifyInit) (0, &mech, MOCK_PUBLIC_KEY_PREFIX);
	assert (rv == CKR_SESSION_HANDLE_INVALID);

	rv = (module->C_VerifyInit) (session, &mech, MOCK_PUBLIC_KEY_PREFIX);
	assert (rv == CKR_OK);

	length = 13;
	memcpy (signature, "prefix:value4", length);
	rv = (module->C_Verify) (0, (CK_BYTE_PTR)"bLAH", 4, signature, 5);
	assert (rv == CKR_SESSION_HANDLE_INVALID);

	rv = (module->C_Verify) (session, (CK_BYTE_PTR)"BLAh", 4, signature, length);
	assert (rv == CKR_OK);

	rv = (module->C_VerifyInit) (session, &mech, MOCK_PUBLIC_KEY_PREFIX);
	assert (rv == CKR_OK);

	rv = (module->C_VerifyUpdate) (0, (CK_BYTE_PTR)"blah", 4);
	assert (rv == CKR_SESSION_HANDLE_INVALID);

	rv = (module->C_VerifyUpdate) (session, (CK_BYTE_PTR)"sLuRM", 5);
	assert (rv == CKR_OK);

	rv = (module->C_VerifyUpdate) (session, (CK_BYTE_PTR)"Other", 5);
	assert (rv == CKR_OK);

	length = 14;
	memcpy (signature, "prefix:value10", length);

	rv = (module->C_VerifyFinal) (session, signature, 5);
	assert (rv == CKR_SIGNATURE_LEN_RANGE);

	rv = (module->C_VerifyFinal) (session, signature, length);
	assert (rv == CKR_OK);

	teardown_mock_module (module);
}

static void
test_verify_recover (void)
{
	CK_FUNCTION_LIST_PTR module;
	CK_SESSION_HANDLE session = 0;
	CK_MECHANISM mech = { CKM_MOCK_PREFIX, "prefix:", 7 };
	CK_BYTE data[128];
	CK_ULONG length;
	CK_RV rv;

	module = setup_mock_module (&session);

	rv = (module->C_VerifyRecoverInit) (0, &mech, MOCK_PUBLIC_KEY_PREFIX);
	assert (rv == CKR_SESSION_HANDLE_INVALID);

	rv = (module->C_VerifyRecoverInit) (session, &mech, MOCK_PUBLIC_KEY_PREFIX);
	assert (rv == CKR_OK);

	length = sizeof (data);
	rv = (module->C_VerifyRecover) (0, (CK_BYTE_PTR)"prefix:valueBLah", 16, data, &length);
	assert (rv == CKR_SESSION_HANDLE_INVALID);

	length = sizeof (data);
	rv = (module->C_VerifyRecover) (session, (CK_BYTE_PTR)"prefix:valueBLah", 16, data, &length);
	assert (rv == CKR_OK);

	assert_num_eq (4, length);
	assert (memcmp (data, "BLah", 4) == 0);

	teardown_mock_module (module);
}

static void
test_digest_encrypt (void)
{
	CK_FUNCTION_LIST_PTR module;
	CK_SESSION_HANDLE session = 0;
	CK_MECHANISM mech = { CKM_MOCK_CAPITALIZE, NULL, 0 };
	CK_MECHANISM dmech = { CKM_MOCK_COUNT, NULL, 0 };
	CK_BYTE data[128];
	CK_ULONG length;
	CK_RV rv;

	module = setup_mock_module (&session);

	rv = (module->C_EncryptInit) (session, &mech, MOCK_PUBLIC_KEY_CAPITALIZE);
	assert (rv == CKR_OK);

	rv = (module->C_DigestInit) (session, &dmech);
	assert (rv == CKR_OK);

	length = sizeof (data);
	rv = (module->C_DigestEncryptUpdate) (0, (CK_BYTE_PTR)"blah", 4, data, &length);
	assert (rv == CKR_SESSION_HANDLE_INVALID);

	length = sizeof (data);
	rv = (module->C_DigestEncryptUpdate) (session, (CK_BYTE_PTR)"blah", 4, data, &length);
	assert (rv == CKR_OK);

	assert_num_eq (4, length);
	assert (memcmp (data, "BLAH", 4) == 0);

	length = sizeof (data);
	rv = (module->C_EncryptFinal) (session, data, &length);
	assert (rv == CKR_OK);

	length = sizeof (data);
	rv = (module->C_DigestFinal) (session, data, &length);
	assert (rv == CKR_OK);

	assert_num_eq (1, length);
	assert (memcmp (data, "4", 1) == 0);

	teardown_mock_module (module);
}

static void
test_decrypt_digest (void)
{
	CK_FUNCTION_LIST_PTR module;
	CK_SESSION_HANDLE session = 0;
	CK_MECHANISM mech = { CKM_MOCK_CAPITALIZE, NULL, 0 };
	CK_MECHANISM dmech = { CKM_MOCK_COUNT, NULL, 0 };
	CK_BYTE data[128];
	CK_ULONG length;
	CK_RV rv;

	module = setup_mock_module (&session);

	rv = (module->C_Login) (session, CKU_USER, (CK_BYTE_PTR)"booo", 4);
	assert (rv == CKR_OK);

	rv = (module->C_DecryptInit) (session, &mech, MOCK_PRIVATE_KEY_CAPITALIZE);
	assert (rv == CKR_OK);

	rv = (module->C_DigestInit) (session, &dmech);
	assert (rv == CKR_OK);

	length = sizeof (data);
	rv = (module->C_DecryptDigestUpdate) (0, (CK_BYTE_PTR)"BLAH", 4, data, &length);
	assert (rv == CKR_SESSION_HANDLE_INVALID);

	length = sizeof (data);
	rv = (module->C_DecryptDigestUpdate) (session, (CK_BYTE_PTR)"BLAH", 4, data, &length);
	assert (rv == CKR_OK);

	assert_num_eq (4, length);
	assert (memcmp (data, "blah", 4) == 0);

	length = sizeof (data);
	rv = (module->C_DecryptFinal) (session, data, &length);
	assert (rv == CKR_OK);

	length = sizeof (data);
	rv = (module->C_DigestFinal) (session, data, &length);
	assert (rv == CKR_OK);

	assert_num_eq (1, length);
	assert (memcmp (data, "4", 1) == 0);

	teardown_mock_module (module);
}

static void
test_sign_encrypt (void)
{
	CK_FUNCTION_LIST_PTR module;
	CK_SESSION_HANDLE session = 0;
	CK_MECHANISM mech = { CKM_MOCK_CAPITALIZE, NULL, 0 };
	CK_MECHANISM smech = { CKM_MOCK_PREFIX, "p:", 2 };
	CK_BYTE data[128];
	CK_ULONG length;
	CK_RV rv;

	module = setup_mock_module (&session);

	rv = (module->C_Login) (session, CKU_USER, (CK_BYTE_PTR)"booo", 4);
	assert (rv == CKR_OK);

	rv = (module->C_EncryptInit) (session, &mech, MOCK_PUBLIC_KEY_CAPITALIZE);
	assert (rv == CKR_OK);

	rv = (module->C_SignInit) (session, &smech, MOCK_PRIVATE_KEY_PREFIX);
	assert (rv == CKR_OK);

	rv = (module->C_Login) (session, CKU_CONTEXT_SPECIFIC, (CK_BYTE_PTR)"booo", 4);
	assert (rv == CKR_OK);

	length = sizeof (data);
	rv = (module->C_SignEncryptUpdate) (0, (CK_BYTE_PTR)"blah", 4, data, &length);
	assert (rv == CKR_SESSION_HANDLE_INVALID);

	length = sizeof (data);
	rv = (module->C_SignEncryptUpdate) (session, (CK_BYTE_PTR)"blah", 4, data, &length);
	assert (rv == CKR_OK);

	assert_num_eq (4, length);
	assert (memcmp (data, "BLAH", 4) == 0);

	length = sizeof (data);
	rv = (module->C_EncryptFinal) (session, data, &length);
	assert (rv == CKR_OK);

	length = sizeof (data);
	rv = (module->C_SignFinal) (session, data, &length);
	assert (rv == CKR_OK);

	assert_num_eq (8, length);
	assert (memcmp (data, "p:value4", 1) == 0);

	teardown_mock_module (module);
}

static void
test_decrypt_verify (void)
{
	CK_FUNCTION_LIST_PTR module;
	CK_SESSION_HANDLE session = 0;
	CK_MECHANISM mech = { CKM_MOCK_CAPITALIZE, NULL, 0 };
	CK_MECHANISM vmech = { CKM_MOCK_PREFIX, "p:", 2 };
	CK_BYTE data[128];
	CK_ULONG length;
	CK_RV rv;

	module = setup_mock_module (&session);

	rv = (module->C_Login) (session, CKU_USER, (CK_BYTE_PTR)"booo", 4);
	assert (rv == CKR_OK);

	rv = (module->C_DecryptInit) (session, &mech, MOCK_PRIVATE_KEY_CAPITALIZE);
	assert (rv == CKR_OK);

	rv = (module->C_VerifyInit) (session, &vmech, MOCK_PUBLIC_KEY_PREFIX);
	assert (rv == CKR_OK);

	length = sizeof (data);
	rv = (module->C_DecryptVerifyUpdate) (0, (CK_BYTE_PTR)"BLAH", 4, data, &length);
	assert (rv == CKR_SESSION_HANDLE_INVALID);

	length = sizeof (data);
	rv = (module->C_DecryptVerifyUpdate) (session, (CK_BYTE_PTR)"BLAH", 4, data, &length);
	assert (rv == CKR_OK);

	assert_num_eq (4, length);
	assert (memcmp (data, "blah", 4) == 0);

	length = sizeof (data);
	rv = (module->C_DecryptFinal) (session, data, &length);
	assert (rv == CKR_OK);

	rv = (module->C_VerifyFinal) (session, (CK_BYTE_PTR)"p:value4", 8);
	assert (rv == CKR_OK);

	teardown_mock_module (module);
}

static void
test_generate_key (void)
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

	module = setup_mock_module (&session);

	strcpy (label, "Blahooo");
	bits = 1555;

	attrs[0].type = CKA_LABEL;
	attrs[0].pValue = label;
	attrs[0].ulValueLen = strlen (label);
	attrs[1].type = CKA_BITS_PER_PIXEL;
	attrs[1].pValue = &bits;
	attrs[1].ulValueLen = sizeof (bits);

	rv = (module->C_GenerateKey) (session, &mech, attrs, 2, &object);
	assert (rv == CKR_MECHANISM_PARAM_INVALID);

	mech.pParameter = "generate";
	mech.ulParameterLen = 9;

	rv = (module->C_GenerateKey) (session, &mech, attrs, 2, &object);
	assert (rv == CKR_OK);

	attrs[0].ulValueLen = sizeof (label);
	memset (label, 0, sizeof (label));
	bits = 0;
	attrs[2].type = CKA_VALUE;
	attrs[2].pValue = value;
	attrs[2].ulValueLen = sizeof (value);

	rv = (module->C_GetAttributeValue) (session, object, attrs, 3);
	assert (rv == CKR_OK);

	assert_num_eq (bits, 1555);
	assert_num_eq (7, attrs[0].ulValueLen);
	assert (memcmp (label, "Blahooo", attrs[0].ulValueLen) == 0);
	assert_num_eq (9, attrs[2].ulValueLen);
	assert (memcmp (value, "generated", attrs[2].ulValueLen) == 0);

	teardown_mock_module (module);
}

static void
test_generate_key_pair (void)
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

	module = setup_mock_module (&session);

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
	assert (rv == CKR_SESSION_HANDLE_INVALID);

	mech.pParameter = "generate";
	mech.ulParameterLen = 9;

	rv = (module->C_GenerateKeyPair) (session, &mech, pub_attrs, 2, priv_attrs, 2,
	                                  &pub_object, &priv_object);
	assert (rv == CKR_OK);

	pub_bits = 0;
	pub_attrs[0].ulValueLen = sizeof (pub_label);
	memset (pub_label, 0, sizeof (pub_label));
	pub_attrs[2].type = CKA_VALUE;
	pub_attrs[2].pValue = pub_value;
	pub_attrs[2].ulValueLen = sizeof (pub_value);

	rv = (module->C_GetAttributeValue) (session, pub_object, pub_attrs, 3);
	assert (rv == CKR_OK);

	assert_num_eq (1555, pub_bits);
	assert_num_eq (7, pub_attrs[0].ulValueLen);
	assert (memcmp (pub_label, "Blahooo", pub_attrs[0].ulValueLen) == 0);
	assert_num_eq (9, pub_attrs[2].ulValueLen);
	assert (memcmp (pub_value, "generated", pub_attrs[2].ulValueLen) == 0);

	priv_bits = 0;
	priv_attrs[0].ulValueLen = sizeof (priv_label);
	memset (priv_label, 0, sizeof (priv_label));
	priv_attrs[2].type = CKA_VALUE;
	priv_attrs[2].pValue = priv_value;
	priv_attrs[2].ulValueLen = sizeof (priv_value);

	rv = (module->C_GetAttributeValue) (session, priv_object, priv_attrs, 3);
	assert (rv == CKR_OK);

	assert_num_eq (1666, priv_bits);
	assert_num_eq (7, priv_attrs[0].ulValueLen);
	assert (memcmp (priv_label, "Private", priv_attrs[0].ulValueLen) == 0);
	assert_num_eq (9, priv_attrs[2].ulValueLen);
	assert (memcmp (priv_value, "generated", priv_attrs[2].ulValueLen) == 0);

	teardown_mock_module (module);
}

static void
test_wrap_key (void)
{
	CK_FUNCTION_LIST_PTR module;
	CK_SESSION_HANDLE session = 0;
	CK_MECHANISM mech = { CKM_MOCK_WRAP, NULL, 0 };
	CK_BYTE data[128];
	CK_ULONG length;
	CK_RV rv;

	module = setup_mock_module (&session);

	length = sizeof (data);
	rv = (module->C_WrapKey) (session, &mech, MOCK_PUBLIC_KEY_PREFIX, MOCK_PUBLIC_KEY_PREFIX, data, &length);
	assert (rv == CKR_MECHANISM_PARAM_INVALID);

	mech.pParameter = "wrap";
	mech.ulParameterLen = 4;

	rv = (module->C_WrapKey) (session, &mech, MOCK_PUBLIC_KEY_PREFIX, MOCK_PUBLIC_KEY_PREFIX, data, &length);
	assert (rv == CKR_OK);

	assert_num_eq (5, length);
	assert (memcmp (data, "value", 5) == 0);

	teardown_mock_module (module);
}

static void
test_unwrap_key (void)
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

	module = setup_mock_module (&session);

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
	assert (rv == CKR_MECHANISM_PARAM_INVALID);

	mech.pParameter = "wrap";
	mech.ulParameterLen = 4;

	rv = (module->C_UnwrapKey) (session, &mech, MOCK_PUBLIC_KEY_PREFIX,
	                            (CK_BYTE_PTR)"wheee", 5, attrs, 2, &object);
	assert (rv == CKR_OK);

	attrs[0].ulValueLen = sizeof (label);
	memset (label, 0, sizeof (label));
	bits = 0;
	attrs[2].type = CKA_VALUE;
	attrs[2].pValue = value;
	attrs[2].ulValueLen = sizeof (value);

	rv = (module->C_GetAttributeValue) (session, object, attrs, 3);
	assert (rv == CKR_OK);

	assert_num_eq (bits, 1555);
	assert_num_eq (7, attrs[0].ulValueLen);
	assert (memcmp (label, "Blahooo", attrs[0].ulValueLen) == 0);
	assert_num_eq (5, attrs[2].ulValueLen);
	assert (memcmp (value, "wheee", attrs[2].ulValueLen) == 0);

	teardown_mock_module (module);
}

static void
test_derive_key (void)
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

	module = setup_mock_module (&session);

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
	assert (rv == CKR_MECHANISM_PARAM_INVALID);

	mech.pParameter = "derive";
	mech.ulParameterLen = 6;

	rv = (module->C_DeriveKey) (session, &mech, MOCK_PUBLIC_KEY_PREFIX,
	                            attrs, 2, &object);
	assert (rv == CKR_OK);

	attrs[0].ulValueLen = sizeof (label);
	memset (label, 0, sizeof (label));
	bits = 0;
	attrs[2].type = CKA_VALUE;
	attrs[2].pValue = value;
	attrs[2].ulValueLen = sizeof (value);

	rv = (module->C_GetAttributeValue) (session, object, attrs, 3);
	assert (rv == CKR_OK);

	assert_num_eq (bits, 1555);
	assert_num_eq (7, attrs[0].ulValueLen);
	assert (memcmp (label, "Blahooo", attrs[0].ulValueLen) == 0);
	assert_num_eq (7, attrs[2].ulValueLen);
	assert (memcmp (value, "derived", attrs[2].ulValueLen) == 0);

	teardown_mock_module (module);
}

static void
test_random (void)
{
	CK_FUNCTION_LIST_PTR module;
	CK_SESSION_HANDLE session = 0;
	CK_BYTE data[10];
	CK_RV rv;

	module = setup_mock_module (&session);

	rv = (module->C_SeedRandom) (0, (CK_BYTE_PTR)"seed", 4);
	assert (rv == CKR_SESSION_HANDLE_INVALID);

	rv = (module->C_SeedRandom) (session, (CK_BYTE_PTR)"seed", 4);
	assert (rv == CKR_OK);

	rv = (module->C_GenerateRandom) (0, data, sizeof (data));
	assert (rv == CKR_SESSION_HANDLE_INVALID);

	rv = (module->C_GenerateRandom) (session, data, sizeof (data));
	assert (rv == CKR_OK);

	assert (memcmp (data, "seedseedse", sizeof (data)) == 0);

	teardown_mock_module (module);
}

static void
test_mock_add_tests (const char *prefix)
{
	p11_fixture (NULL, NULL);
	p11_test (test_get_info, "%s/test_get_info", prefix);
	p11_test (test_get_slot_list, "%s/test_get_slot_list", prefix);
	p11_test (test_get_slot_info, "%s/test_get_slot_info", prefix);
	p11_test (test_get_token_info, "%s/test_get_token_info", prefix);
	p11_test (test_get_mechanism_list, "%s/test_get_mechanism_list", prefix);
	p11_test (test_get_mechanism_info, "%s/test_get_mechanism_info", prefix);
	p11_test (test_init_token, "%s/test_init_token", prefix);
	p11_test (test_wait_for_slot_event, "%s/test_wait_for_slot_event", prefix);
	p11_test (test_open_close_session, "%s/test_open_close_session", prefix);
	p11_test (test_close_all_sessions, "%s/test_close_all_sessions", prefix);
	p11_test (test_get_function_status, "%s/test_get_function_status", prefix);
	p11_test (test_cancel_function, "%s/test_cancel_function", prefix);
	p11_test (test_get_session_info, "%s/test_get_session_info", prefix);
	p11_test (test_init_pin, "%s/test_init_pin", prefix);
	p11_test (test_set_pin, "%s/test_set_pin", prefix);
	p11_test (test_operation_state, "%s/test_operation_state", prefix);
	p11_test (test_login_logout, "%s/test_login_logout", prefix);
	p11_test (test_get_attribute_value, "%s/test_get_attribute_value", prefix);
	p11_test (test_set_attribute_value, "%s/test_set_attribute_value", prefix);
	p11_test (test_create_object, "%s/test_create_object", prefix);
	p11_test (test_copy_object, "%s/test_copy_object", prefix);
	p11_test (test_destroy_object, "%s/test_destroy_object", prefix);
	p11_test (test_get_object_size, "%s/test_get_object_size", prefix);
	p11_test (test_find_objects, "%s/test_find_objects", prefix);
	p11_test (test_encrypt, "%s/test_encrypt", prefix);
	p11_test (test_decrypt, "%s/test_decrypt", prefix);
	p11_test (test_digest, "%s/test_digest", prefix);
	p11_test (test_sign, "%s/test_sign", prefix);
	p11_test (test_sign_recover, "%s/test_sign_recover", prefix);
	p11_test (test_verify, "%s/test_verify", prefix);
	p11_test (test_verify_recover, "%s/test_verify_recover", prefix);
	p11_test (test_digest_encrypt, "%s/test_digest_encrypt", prefix);
	p11_test (test_decrypt_digest, "%s/test_decrypt_digest", prefix);
	p11_test (test_sign_encrypt, "%s/test_sign_encrypt", prefix);
	p11_test (test_decrypt_verify, "%s/test_decrypt_verify", prefix);
	p11_test (test_generate_key, "%s/test_generate_key", prefix);
	p11_test (test_generate_key_pair, "%s/test_generate_key_pair", prefix);
	p11_test (test_wrap_key, "%s/test_wrap_key", prefix);
	p11_test (test_unwrap_key, "%s/test_unwrap_key", prefix);
	p11_test (test_derive_key, "%s/test_derive_key", prefix);
	p11_test (test_random, "%s/test_random", prefix);
}
