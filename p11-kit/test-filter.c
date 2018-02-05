/*
 * Copyright (c) 2016 Red Hat Inc
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
#include "test.h"

#include "dict.h"
#include "library.h"
#include "filter.h"
#include "mock.h"
#include "modules.h"
#include "p11-kit.h"
#include "virtual.h"

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

static CK_TOKEN_INFO TOKEN_ONE = {
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

static void
test_allowed (void)
{
	CK_FUNCTION_LIST_PTR module;
	CK_SLOT_ID slots[1], slot;
	CK_SLOT_INFO slot_info;
	CK_TOKEN_INFO token_info;
	CK_MECHANISM_TYPE mechs[8];
	CK_MECHANISM_INFO mech;
	CK_SESSION_HANDLE session = 0;
	p11_virtual virt;
	p11_virtual *filter;
	CK_ULONG count;
	CK_RV rv;

	p11_virtual_init (&virt, &p11_virtual_base, &mock_module, NULL);
	filter = p11_filter_subclass (&virt, NULL);
	module = p11_virtual_wrap (filter, (p11_destroyer)p11_virtual_uninit);
	assert_ptr_not_null (module);

	p11_filter_allow_token (filter, &TOKEN_ONE);

	rv = (module->C_Initialize) (NULL);
	assert_num_eq (CKR_OK, rv);

	rv = (module->C_GetSlotList) (CK_TRUE, NULL, NULL);
	assert_num_eq (CKR_ARGUMENTS_BAD, rv);

	rv = (module->C_GetSlotList) (CK_TRUE, NULL, &count);
	assert_num_eq (CKR_OK, rv);
	assert_num_eq (count, 1);

	count = 0;
	rv = (module->C_GetSlotList) (CK_TRUE, slots, &count);
	assert_num_eq (CKR_BUFFER_TOO_SMALL, rv);

	count = 1;
	rv = (module->C_GetSlotList) (CK_TRUE, slots, &count);
	assert_num_eq (CKR_OK, rv);
	assert_num_eq (count, 1);

	rv = (module->C_GetSlotInfo) (99, &slot_info);
	assert_num_eq (CKR_SLOT_ID_INVALID, rv);

	rv = (module->C_GetSlotInfo) (slots[0], &slot_info);
	assert_num_eq (CKR_OK, rv);

	rv = (module->C_GetTokenInfo) (99, &token_info);
	assert_num_eq (CKR_SLOT_ID_INVALID, rv);

	rv = (module->C_GetTokenInfo) (slots[0], &token_info);
	assert_num_eq (CKR_OK, rv);

	rv = (module->C_GetMechanismList) (99, NULL, &count);
	assert_num_eq (CKR_SLOT_ID_INVALID, rv);

	rv = (module->C_GetMechanismList) (slots[0], NULL, &count);
	assert_num_eq (CKR_OK, rv);

	rv = (module->C_GetMechanismList) (slots[0], mechs, &count);
	assert_num_eq (CKR_OK, rv);
	assert_num_eq (2, count);

	rv = (module->C_GetMechanismInfo) (99, mechs[0], &mech);
	assert_num_eq (CKR_SLOT_ID_INVALID, rv);

	rv = (module->C_GetMechanismInfo) (slots[0], mechs[0], &mech);
	assert_num_eq (CKR_OK, rv);

	rv = (module->C_InitToken) (99, (CK_UTF8CHAR_PTR)"TEST PIN", 8, (CK_UTF8CHAR_PTR)"TEST LABEL");
	assert_num_eq (CKR_SLOT_ID_INVALID, rv);

	rv = (module->C_InitToken) (slots[0], (CK_UTF8CHAR_PTR)"TEST PIN", 8, (CK_UTF8CHAR_PTR)"TEST LABEL");
	assert_num_eq (CKR_OK, rv);

	rv = (module->C_WaitForSlotEvent) (0, &slot, NULL);
	assert_num_eq (CKR_FUNCTION_NOT_SUPPORTED, rv);

	rv = (module->C_OpenSession) (99, CKF_SERIAL_SESSION, NULL, NULL, &session);
	assert_num_eq (CKR_SLOT_ID_INVALID, rv);

	rv = (module->C_OpenSession) (slots[0], CKF_SERIAL_SESSION, NULL, NULL, &session);
	assert_num_eq (CKR_OK, rv);

	rv = (module->C_CloseAllSessions) (99);
	assert_num_eq (CKR_SLOT_ID_INVALID, rv);

	rv = (module->C_CloseAllSessions) (slots[0]);
	assert_num_eq (CKR_OK, rv);

	rv = (module->C_Finalize) (NULL);
	assert_num_eq (CKR_OK, rv);

	p11_virtual_unwrap (module);
	p11_filter_release (filter);
}

static void
test_denied (void)
{
	CK_FUNCTION_LIST_PTR module;
	p11_virtual virt;
	p11_virtual *filter;
	CK_ULONG count;
	CK_RV rv;

	p11_virtual_init (&virt, &p11_virtual_base, &mock_module, NULL);
	filter = p11_filter_subclass (&virt, NULL);
	module = p11_virtual_wrap (filter, (p11_destroyer)p11_virtual_uninit);
	assert_ptr_not_null (module);

	p11_filter_deny_token (filter, &TOKEN_ONE);

	rv = (module->C_Initialize) (NULL);
	assert_num_eq (CKR_OK, rv);

	rv = (module->C_GetSlotList) (CK_TRUE, NULL, &count);
	assert_num_eq (CKR_OK, rv);
	assert_num_eq (count, 0);

	rv = (module->C_Finalize) (NULL);
	assert_num_eq (CKR_OK, rv);

	p11_virtual_unwrap (module);
	p11_filter_release (filter);
}

static void
test_write_protected (void)
{
	CK_FUNCTION_LIST_PTR module;
	CK_SLOT_ID slots[1], slot;
	CK_SLOT_INFO slot_info;
	CK_TOKEN_INFO token_info;
	CK_TOKEN_INFO token_one;
	CK_MECHANISM_TYPE mechs[8];
	CK_MECHANISM_INFO mech;
	CK_SESSION_HANDLE session = 0;
	p11_virtual virt;
	p11_virtual *filter;
	CK_ULONG count;
	CK_RV rv;

	p11_virtual_init (&virt, &p11_virtual_base, &mock_module, NULL);
	filter = p11_filter_subclass (&virt, NULL);
	module = p11_virtual_wrap (filter, (p11_destroyer)p11_virtual_uninit);
	assert_ptr_not_null (module);

	memcpy (&token_one, &TOKEN_ONE, sizeof (CK_TOKEN_INFO));
	token_one.flags |= CKF_WRITE_PROTECTED;

	p11_filter_allow_token (filter, &token_one);

	rv = (module->C_Initialize) (NULL);
	assert_num_eq (CKR_OK, rv);

	rv = (module->C_GetSlotList) (CK_TRUE, NULL, NULL);
	assert_num_eq (CKR_ARGUMENTS_BAD, rv);

	rv = (module->C_GetSlotList) (CK_TRUE, NULL, &count);
	assert_num_eq (CKR_OK, rv);
	assert_num_eq (count, 1);

	count = 0;
	rv = (module->C_GetSlotList) (CK_TRUE, slots, &count);
	assert_num_eq (CKR_BUFFER_TOO_SMALL, rv);

	count = 1;
	rv = (module->C_GetSlotList) (CK_TRUE, slots, &count);
	assert_num_eq (CKR_OK, rv);
	assert_num_eq (count, 1);

	rv = (module->C_GetSlotInfo) (99, &slot_info);
	assert_num_eq (CKR_SLOT_ID_INVALID, rv);

	rv = (module->C_GetSlotInfo) (slots[0], &slot_info);
	assert_num_eq (CKR_OK, rv);

	rv = (module->C_GetTokenInfo) (99, &token_info);
	assert_num_eq (CKR_SLOT_ID_INVALID, rv);

	rv = (module->C_GetTokenInfo) (slots[0], &token_info);
	assert_num_eq (CKR_OK, rv);

	rv = (module->C_GetMechanismList) (99, NULL, &count);
	assert_num_eq (CKR_SLOT_ID_INVALID, rv);

	rv = (module->C_GetMechanismList) (slots[0], NULL, &count);
	assert_num_eq (CKR_OK, rv);

	rv = (module->C_GetMechanismList) (slots[0], mechs, &count);
	assert_num_eq (CKR_OK, rv);
	assert_num_eq (2, count);

	rv = (module->C_GetMechanismInfo) (99, mechs[0], &mech);
	assert_num_eq (CKR_SLOT_ID_INVALID, rv);

	rv = (module->C_GetMechanismInfo) (slots[0], mechs[0], &mech);
	assert_num_eq (CKR_OK, rv);

	rv = (module->C_InitToken) (99, (CK_UTF8CHAR_PTR)"TEST PIN", 8, (CK_UTF8CHAR_PTR)"TEST LABEL");
	assert_num_eq (CKR_SLOT_ID_INVALID, rv);

	rv = (module->C_InitToken) (slots[0], (CK_UTF8CHAR_PTR)"TEST PIN", 8, (CK_UTF8CHAR_PTR)"TEST LABEL");
	assert_num_eq (CKR_TOKEN_WRITE_PROTECTED, rv);

	rv = (module->C_WaitForSlotEvent) (0, &slot, NULL);
	assert_num_eq (CKR_FUNCTION_NOT_SUPPORTED, rv);

	rv = (module->C_OpenSession) (99, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &session);
	assert_num_eq (CKR_SLOT_ID_INVALID, rv);

	rv = (module->C_OpenSession) (slots[0], CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &session);
	assert_num_eq (CKR_TOKEN_WRITE_PROTECTED, rv);

	rv = (module->C_CloseAllSessions) (99);
	assert_num_eq (CKR_SLOT_ID_INVALID, rv);

	rv = (module->C_CloseAllSessions) (slots[0]);
	assert_num_eq (CKR_OK, rv);

	rv = (module->C_Finalize) (NULL);
	assert_num_eq (CKR_OK, rv);

	p11_virtual_unwrap (module);
	p11_filter_release (filter);
}

int
main (int argc,
      char *argv[])
{
	p11_library_init ();
	mock_module_init ();

	p11_test (test_allowed, "/filter/test_allowed");
	p11_test (test_denied, "/filter/test_denied");
	p11_test (test_write_protected, "/filter/test_write_protected");

	return p11_test_run (argc, argv);
}
