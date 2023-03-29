/*
 * Copyright (c) 2013-2023, Red Hat Inc.
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
 * Author: Stef Walter <stefw@redhat.com>
 */

#ifndef __MOCK_H__
#define __MOCK_H__

#include "compat.h"
#include "pkcs11.h"
#include "pkcs11i.h"

enum {
	MOCK_DATA_OBJECT = 2,
	MOCK_PRIVATE_KEY_CAPITALIZE = 3,
	MOCK_PUBLIC_KEY_CAPITALIZE = 4,
	MOCK_PRIVATE_KEY_PREFIX = 5,
	MOCK_PUBLIC_KEY_PREFIX = 6,
	MOCK_PROFILE_OBJECT = 7,

	/*
	 * CKM_MOCK_CAPITALIZE (encrypt/decrypt)
	 * - Capitalizes to encrypt
	 * - Lowercase to decrypt
	 */
	CKM_MOCK_CAPITALIZE = (CKM_VENDOR_DEFINED | 1),

	/*
	 * CKM_MOCK_PREFIX (sign/verify)
	 * - Sign prefixes the data with a key label
	 * - Verify unprefixes data using key label
	 */
	CKM_MOCK_PREFIX = (CKM_VENDOR_DEFINED | 2),

	/*
	 * CKM_MOCK_GENERATE (generate-pair)
	 * - Generates a pair of keys, mechanism parameter should be 'generate'
	 */
	CKM_MOCK_GENERATE = (CKM_VENDOR_DEFINED | 3),

	/*
	 * CKM_MOCK_WRAP (wrap key)
	 * - Wraps key by returning value, mechanism parameter should be 'wrap'
	 */
	CKM_MOCK_WRAP = (CKM_VENDOR_DEFINED | 4),

	/*
	 * CKM_MOCK_DERIVE (derive-key)
	 * - Derives key by setting value to 'derived'
	 * - Mechanism param should be 'derive'
	 */
	CKM_MOCK_DERIVE = (CKM_VENDOR_DEFINED | 5),

	/*
	 * CKM_MOCK_COUNT (digest)
	 * - Counts the number of bytes, and returns a CK_ULONG 'hash' value
	 */
	CKM_MOCK_COUNT = (CKM_VENDOR_DEFINED | 6),

	MOCK_SLOT_ONE_ID = 52,
	MOCK_SLOT_TWO_ID = 134,

	MOCK_SLOTS_PRESENT = 1,
	MOCK_SLOTS_ALL = 2,
};

static const CK_INFO MOCK_INFO = {
	{ CRYPTOKI_LEGACY_VERSION_MAJOR, CRYPTOKI_LEGACY_VERSION_MINOR },
	"MOCK MANUFACTURER               ",
	0,
	"MOCK LIBRARY                    ",
	{ 45, 145 }
};

extern       CK_FUNCTION_LIST                            mock_module;
extern       CK_FUNCTION_LIST_3_0                        mock_module_v3;

extern       CK_FUNCTION_LIST                            mock_module_no_slots;
extern       CK_FUNCTION_LIST_3_0                        mock_module_v3_no_slots;

extern       CK_X_FUNCTION_LIST                          mock_x_module_no_slots;

#define MOCK_INTERFACES 1
extern       CK_INTERFACE                                mock_interfaces[MOCK_INTERFACES];


void         mock_module_init                            (void);

typedef bool (* mock_enumerator)                         (CK_OBJECT_HANDLE handle,
                                                          CK_ATTRIBUTE *attrs,
                                                          void *user_data);

void         mock_module_enumerate_objects               (CK_SESSION_HANDLE session,
                                                          mock_enumerator func,
                                                          void *user_data);

void         mock_module_add_object                      (CK_SLOT_ID slot_id,
                                                          const CK_ATTRIBUTE *attrs);
void         mock_module_add_profile                     (CK_SLOT_ID slot_id,
                                                          CK_PROFILE_ID profile_id);

void         mock_module_reset                           (void);

bool         mock_module_initialized                     (void);

void         mock_module_take_object                     (CK_SLOT_ID slot_id,
                                                          CK_ATTRIBUTE *attrs);

CK_RV        mock_C_Initialize                           (CK_VOID_PTR init_args);

CK_RV        mock_C_Initialize__fails                    (CK_VOID_PTR init_args);

CK_RV        mock_X_Initialize                           (CK_X_FUNCTION_LIST *self,
                                                          CK_VOID_PTR init_args);

CK_RV        mock_X_Initialize__fails                    (CK_X_FUNCTION_LIST *self,
                                                          CK_VOID_PTR init_args);

CK_RV        mock_C_Finalize                             (CK_VOID_PTR reserved);

CK_RV        mock_X_Finalize                             (CK_X_FUNCTION_LIST *self,
                                                          CK_VOID_PTR reserved);

CK_RV        mock_C_GetInfo                              (CK_INFO_PTR info);

CK_RV        mock_X_GetInfo                              (CK_X_FUNCTION_LIST *self,
                                                          CK_INFO_PTR info);

CK_RV        mock_C_GetFunctionList_not_supported        (CK_FUNCTION_LIST_PTR_PTR list);

CK_RV        mock_C_GetSlotList                          (CK_BBOOL token_present,
                                                          CK_SLOT_ID_PTR slot_list,
                                                          CK_ULONG_PTR count);

CK_RV        mock_C_GetSlotList__no_tokens               (CK_BBOOL token_present,
                                                          CK_SLOT_ID_PTR slot_list,
                                                          CK_ULONG_PTR count);

CK_RV        mock_C_GetSlotList__fail_first              (CK_BBOOL token_present,
                                                          CK_SLOT_ID_PTR slot_list,
                                                          CK_ULONG_PTR count);

CK_RV        mock_C_GetSlotList__fail_late               (CK_BBOOL token_present,
                                                          CK_SLOT_ID_PTR slot_list,
                                                          CK_ULONG_PTR count);

CK_RV        mock_C_GetSlotInfo                          (CK_SLOT_ID slot_id,
                                                          CK_SLOT_INFO_PTR info);

CK_RV        mock_X_GetSlotList__no_tokens               (CK_X_FUNCTION_LIST *self,
                                                          CK_BBOOL token_present,
                                                          CK_SLOT_ID_PTR slot_list,
                                                          CK_ULONG_PTR count);

CK_RV        mock_C_GetSlotInfo__invalid_slotid          (CK_SLOT_ID slot_id,
                                                          CK_SLOT_INFO_PTR info);

CK_RV        mock_X_GetSlotInfo__invalid_slotid          (CK_X_FUNCTION_LIST *self,
                                                          CK_SLOT_ID slot_id,
                                                          CK_SLOT_INFO_PTR info);

CK_RV        mock_C_GetTokenInfo                         (CK_SLOT_ID slot_id,
                                                          CK_TOKEN_INFO_PTR info);

CK_RV        mock_C_GetTokenInfo__invalid_slotid         (CK_SLOT_ID slot_id,
                                                          CK_TOKEN_INFO_PTR info);

CK_RV        mock_X_GetTokenInfo__invalid_slotid         (CK_X_FUNCTION_LIST *self,
                                                          CK_SLOT_ID slot_id,
                                                          CK_TOKEN_INFO_PTR info);

CK_RV        mock_C_GetTokenInfo__not_initialized        (CK_SLOT_ID slot_id,
                                                          CK_TOKEN_INFO_PTR info);

CK_RV        mock_C_GetMechanismList                     (CK_SLOT_ID slot_id,
                                                          CK_MECHANISM_TYPE_PTR mechanism_list,
                                                          CK_ULONG_PTR count);

CK_RV        mock_C_GetMechanismList__invalid_slotid     (CK_SLOT_ID slot_id,
                                                          CK_MECHANISM_TYPE_PTR mechanism_list,
                                                          CK_ULONG_PTR count);

CK_RV        mock_X_GetMechanismList__invalid_slotid     (CK_X_FUNCTION_LIST *self,
                                                          CK_SLOT_ID slot_id,
                                                          CK_MECHANISM_TYPE_PTR mechanism_list,
                                                          CK_ULONG_PTR count);

CK_RV        mock_C_GetMechanismInfo                     (CK_SLOT_ID slot_id,
                                                          CK_MECHANISM_TYPE type,
                                                          CK_MECHANISM_INFO_PTR info);

CK_RV        mock_C_GetMechanismInfo__invalid_slotid     (CK_SLOT_ID slot_id,
                                                          CK_MECHANISM_TYPE type,
                                                          CK_MECHANISM_INFO_PTR info);

CK_RV        mock_X_GetMechanismInfo__invalid_slotid     (CK_X_FUNCTION_LIST *self,
                                                          CK_SLOT_ID slot_id,
                                                          CK_MECHANISM_TYPE type,
                                                          CK_MECHANISM_INFO_PTR info);

CK_RV        mock_C_InitToken__specific_args             (CK_SLOT_ID slot_id,
                                                          CK_UTF8CHAR_PTR pin,
                                                          CK_ULONG pin_len,
                                                          CK_UTF8CHAR_PTR label);

CK_RV        mock_C_InitToken__invalid_slotid            (CK_SLOT_ID slot_id,
                                                          CK_UTF8CHAR_PTR pin,
                                                          CK_ULONG pin_len,
                                                          CK_UTF8CHAR_PTR label);

CK_RV        mock_X_InitToken__invalid_slotid            (CK_X_FUNCTION_LIST *self,
                                                          CK_SLOT_ID slot_id,
                                                          CK_UTF8CHAR_PTR pin,
                                                          CK_ULONG pin_len,
                                                          CK_UTF8CHAR_PTR label);


CK_RV        mock_C_WaitForSlotEvent                     (CK_FLAGS flags,
                                                          CK_SLOT_ID_PTR slot,
                                                          CK_VOID_PTR reserved);

CK_RV        mock_C_WaitForSlotEvent__no_event           (CK_FLAGS flags,
                                                          CK_SLOT_ID_PTR slot,
                                                          CK_VOID_PTR reserved);

CK_RV        mock_X_WaitForSlotEvent__no_event           (CK_X_FUNCTION_LIST *self,
                                                          CK_FLAGS flags,
                                                          CK_SLOT_ID_PTR slot,
                                                          CK_VOID_PTR reserved);

CK_RV        mock_C_OpenSession__invalid_slotid          (CK_SLOT_ID slot_id,
                                                          CK_FLAGS flags,
                                                          CK_VOID_PTR user_data,
                                                          CK_NOTIFY callback,
                                                          CK_SESSION_HANDLE_PTR session);

CK_RV        mock_X_OpenSession__invalid_slotid          (CK_X_FUNCTION_LIST *self,
                                                          CK_SLOT_ID slot_id,
                                                          CK_FLAGS flags,
                                                          CK_VOID_PTR user_data,
                                                          CK_NOTIFY callback,
                                                          CK_SESSION_HANDLE_PTR session);

CK_RV        mock_C_OpenSession__fails                   (CK_SLOT_ID slot_id,
                                                          CK_FLAGS flags,
                                                          CK_VOID_PTR user_data,
                                                          CK_NOTIFY callback,
                                                          CK_SESSION_HANDLE_PTR session);

CK_RV        mock_C_OpenSession                          (CK_SLOT_ID slot_id,
                                                          CK_FLAGS flags,
                                                          CK_VOID_PTR user_data,
                                                          CK_NOTIFY callback,
                                                          CK_SESSION_HANDLE_PTR session);

CK_RV        mock_C_CloseSession                         (CK_SESSION_HANDLE session);

CK_RV        mock_C_CloseSession__invalid_handle         (CK_SESSION_HANDLE session);

CK_RV        mock_X_CloseSession__invalid_handle         (CK_X_FUNCTION_LIST *self,
                                                          CK_SESSION_HANDLE session);

CK_RV        mock_C_CloseAllSessions                     (CK_SLOT_ID slot_id);

CK_RV        mock_C_CloseAllSessions__invalid_slotid     (CK_SLOT_ID slot_id);

CK_RV        mock_X_CloseAllSessions__invalid_slotid     (CK_X_FUNCTION_LIST *self,
                                                         CK_SLOT_ID slot_id);

CK_RV        mock_C_GetFunctionStatus                    (CK_SESSION_HANDLE session);

CK_RV        mock_C_GetFunctionStatus__not_parallel      (CK_SESSION_HANDLE session);

CK_RV        mock_C_CancelFunction                       (CK_SESSION_HANDLE session);

CK_RV        mock_C_CancelFunction__not_parallel         (CK_SESSION_HANDLE session);

CK_RV        mock_C_GetSessionInfo                       (CK_SESSION_HANDLE session,
                                                          CK_SESSION_INFO_PTR info);

CK_RV        mock_C_GetSessionInfo__invalid_handle       (CK_SESSION_HANDLE session,
                                                          CK_SESSION_INFO_PTR info);

CK_RV        mock_X_GetSessionInfo__invalid_handle       (CK_X_FUNCTION_LIST *self,
                                                          CK_SESSION_HANDLE session,
                                                          CK_SESSION_INFO_PTR info);

CK_RV        mock_C_InitPIN__specific_args               (CK_SESSION_HANDLE session,
                                                          CK_UTF8CHAR_PTR pin,
                                                          CK_ULONG pin_len);

CK_RV        mock_C_InitPIN__invalid_handle              (CK_SESSION_HANDLE session,
                                                          CK_UTF8CHAR_PTR pin,
                                                          CK_ULONG pin_len);

CK_RV        mock_X_InitPIN__invalid_handle              (CK_X_FUNCTION_LIST *self,
                                                          CK_SESSION_HANDLE session,
                                                          CK_UTF8CHAR_PTR pin,
                                                          CK_ULONG pin_len);

CK_RV        mock_C_SetPIN__specific_args                (CK_SESSION_HANDLE session,
                                                          CK_UTF8CHAR_PTR old_pin,
                                                          CK_ULONG old_pin_len,
                                                          CK_UTF8CHAR_PTR new_pin,
                                                          CK_ULONG new_pin_len);

CK_RV        mock_C_SetPIN__invalid_handle               (CK_SESSION_HANDLE session,
                                                          CK_UTF8CHAR_PTR old_pin,
                                                          CK_ULONG old_pin_len,
                                                          CK_UTF8CHAR_PTR new_pin,
                                                          CK_ULONG new_pin_len);

CK_RV        mock_X_SetPIN__invalid_handle               (CK_X_FUNCTION_LIST *self,
                                                          CK_SESSION_HANDLE session,
                                                          CK_UTF8CHAR_PTR old_pin,
                                                          CK_ULONG old_pin_len,
                                                          CK_UTF8CHAR_PTR new_pin,
                                                          CK_ULONG new_pin_len);

CK_RV        mock_C_GetOperationState                    (CK_SESSION_HANDLE session,
                                                          CK_BYTE_PTR operation_state,
                                                          CK_ULONG_PTR operation_state_len);

CK_RV        mock_C_GetOperationState__invalid_handle    (CK_SESSION_HANDLE session,
                                                          CK_BYTE_PTR operation_state,
                                                          CK_ULONG_PTR operation_state_len);

CK_RV        mock_X_GetOperationState__invalid_handle    (CK_X_FUNCTION_LIST *self,
                                                          CK_SESSION_HANDLE session,
                                                          CK_BYTE_PTR operation_state,
                                                          CK_ULONG_PTR operation_state_len);

CK_RV        mock_C_SetOperationState                    (CK_SESSION_HANDLE session,
                                                          CK_BYTE_PTR operation_state,
                                                          CK_ULONG operation_state_len,
                                                          CK_OBJECT_HANDLE encryption_key,
                                                          CK_OBJECT_HANDLE authentication_key);

CK_RV        mock_C_SetOperationState__invalid_handle    (CK_SESSION_HANDLE session,
                                                          CK_BYTE_PTR operation_state,
                                                          CK_ULONG operation_state_len,
                                                          CK_OBJECT_HANDLE encryption_key,
                                                          CK_OBJECT_HANDLE authentication_key);

CK_RV        mock_X_SetOperationState__invalid_handle    (CK_X_FUNCTION_LIST *self,
                                                          CK_SESSION_HANDLE session,
                                                          CK_BYTE_PTR operation_state,
                                                          CK_ULONG operation_state_len,
                                                          CK_OBJECT_HANDLE encryption_key,
                                                          CK_OBJECT_HANDLE authentication_key);

CK_RV        mock_C_Login                                (CK_SESSION_HANDLE session,
                                                          CK_USER_TYPE user_type,
                                                          CK_UTF8CHAR_PTR pin,
                                                          CK_ULONG pin_len);

CK_RV        mock_C_Login__invalid_handle                (CK_SESSION_HANDLE session,
                                                          CK_USER_TYPE user_type,
                                                          CK_UTF8CHAR_PTR pin,
                                                          CK_ULONG pin_len);

CK_RV        mock_X_Login__invalid_handle                (CK_X_FUNCTION_LIST *self,
                                                          CK_SESSION_HANDLE session,
                                                          CK_USER_TYPE user_type,
                                                          CK_UTF8CHAR_PTR pin,
                                                          CK_ULONG pin_len);

CK_RV        mock_C_Logout                               (CK_SESSION_HANDLE session);

CK_RV        mock_C_Logout__invalid_handle               (CK_SESSION_HANDLE session);

CK_RV        mock_X_Logout__invalid_handle               (CK_X_FUNCTION_LIST *self,
                                                          CK_SESSION_HANDLE session);

CK_RV        mock_C_CreateObject                         (CK_SESSION_HANDLE session,
                                                          CK_ATTRIBUTE_PTR template,
                                                          CK_ULONG count,
                                                          CK_OBJECT_HANDLE_PTR object);

CK_RV        mock_C_CreateObject__invalid_handle         (CK_SESSION_HANDLE session,
                                                          CK_ATTRIBUTE_PTR template,
                                                          CK_ULONG count,
                                                          CK_OBJECT_HANDLE_PTR new_object);

CK_RV        mock_X_CreateObject__invalid_handle         (CK_X_FUNCTION_LIST *self,
                                                          CK_SESSION_HANDLE session,
                                                          CK_ATTRIBUTE_PTR template,
                                                          CK_ULONG count,
                                                          CK_OBJECT_HANDLE_PTR new_object);

CK_RV        mock_C_CopyObject                           (CK_SESSION_HANDLE session,
                                                          CK_OBJECT_HANDLE object,
                                                          CK_ATTRIBUTE_PTR template,
                                                          CK_ULONG count,
                                                          CK_OBJECT_HANDLE_PTR new_object);

CK_RV        mock_C_CopyObject__invalid_handle           (CK_SESSION_HANDLE session,
                                                          CK_OBJECT_HANDLE object,
                                                          CK_ATTRIBUTE_PTR template,
                                                          CK_ULONG count,
                                                          CK_OBJECT_HANDLE_PTR new_object);

CK_RV        mock_X_CopyObject__invalid_handle           (CK_X_FUNCTION_LIST *self,
                                                          CK_SESSION_HANDLE session,
                                                          CK_OBJECT_HANDLE object,
                                                          CK_ATTRIBUTE_PTR template,
                                                          CK_ULONG count,
                                                          CK_OBJECT_HANDLE_PTR new_object);

CK_RV        mock_C_DestroyObject                        (CK_SESSION_HANDLE session,
                                                          CK_OBJECT_HANDLE object);

CK_RV        mock_C_DestroyObject__invalid_handle        (CK_SESSION_HANDLE session,
                                                          CK_OBJECT_HANDLE object);

CK_RV        mock_X_DestroyObject__invalid_handle        (CK_X_FUNCTION_LIST *self,
                                                          CK_SESSION_HANDLE session,
                                                          CK_OBJECT_HANDLE object);

CK_RV        mock_C_GetObjectSize                        (CK_SESSION_HANDLE session,
                                                          CK_OBJECT_HANDLE object,
                                                          CK_ULONG_PTR size);

CK_RV        mock_C_GetObjectSize__invalid_handle        (CK_SESSION_HANDLE session,
                                                          CK_OBJECT_HANDLE object,
                                                          CK_ULONG_PTR size);

CK_RV        mock_X_GetObjectSize__invalid_handle        (CK_X_FUNCTION_LIST *self,
                                                          CK_SESSION_HANDLE session,
                                                          CK_OBJECT_HANDLE object,
                                                          CK_ULONG_PTR size);

CK_RV        mock_C_GetAttributeValue                    (CK_SESSION_HANDLE session,
                                                          CK_OBJECT_HANDLE object,
                                                          CK_ATTRIBUTE_PTR template,
                                                          CK_ULONG count);

CK_RV        mock_C_GetAttributeValue__invalid_handle    (CK_SESSION_HANDLE session,
                                                          CK_OBJECT_HANDLE object,
                                                          CK_ATTRIBUTE_PTR template,
                                                          CK_ULONG count);

CK_RV        mock_X_GetAttributeValue__invalid_handle    (CK_X_FUNCTION_LIST *self,
                                                          CK_SESSION_HANDLE session,
                                                          CK_OBJECT_HANDLE object,
                                                          CK_ATTRIBUTE_PTR template,
                                                          CK_ULONG count);

CK_RV        mock_C_GetAttributeValue__fail_first        (CK_SESSION_HANDLE session,
                                                          CK_OBJECT_HANDLE object,
                                                          CK_ATTRIBUTE_PTR template,
                                                          CK_ULONG count);

CK_RV        mock_C_GetAttributeValue__fail_late         (CK_SESSION_HANDLE session,
                                                          CK_OBJECT_HANDLE object,
                                                          CK_ATTRIBUTE_PTR template,
                                                          CK_ULONG count);

CK_RV        mock_C_SetAttributeValue                    (CK_SESSION_HANDLE session,
                                                          CK_OBJECT_HANDLE object,
                                                          CK_ATTRIBUTE_PTR template,
                                                          CK_ULONG count);

CK_RV        mock_C_SetAttributeValue__invalid_handle    (CK_SESSION_HANDLE session,
                                                          CK_OBJECT_HANDLE object,
                                                          CK_ATTRIBUTE_PTR template,
                                                          CK_ULONG count);

CK_RV        mock_X_SetAttributeValue__invalid_handle    (CK_X_FUNCTION_LIST *self,
                                                          CK_SESSION_HANDLE session,
                                                          CK_OBJECT_HANDLE object,
                                                          CK_ATTRIBUTE_PTR template,
                                                          CK_ULONG count);

CK_RV        mock_C_FindObjectsInit                      (CK_SESSION_HANDLE session,
                                                          CK_ATTRIBUTE_PTR template,
                                                          CK_ULONG count);

CK_RV        mock_C_FindObjectsInit__invalid_handle      (CK_SESSION_HANDLE session,
                                                          CK_ATTRIBUTE_PTR template,
                                                          CK_ULONG count);

CK_RV        mock_X_FindObjectsInit__invalid_handle      (CK_X_FUNCTION_LIST *self,
                                                          CK_SESSION_HANDLE session,
                                                          CK_ATTRIBUTE_PTR template,
                                                          CK_ULONG count);

CK_RV        mock_C_FindObjectsInit__fails               (CK_SESSION_HANDLE session,
                                                          CK_ATTRIBUTE_PTR template,
                                                          CK_ULONG count);

CK_RV        mock_C_FindObjects                          (CK_SESSION_HANDLE session,
                                                          CK_OBJECT_HANDLE_PTR objects,
                                                          CK_ULONG max_object_count,
                                                          CK_ULONG_PTR object_count);

CK_RV        mock_C_FindObjects__invalid_handle          (CK_SESSION_HANDLE session,
                                                          CK_OBJECT_HANDLE_PTR objects,
                                                          CK_ULONG max_count,
                                                          CK_ULONG_PTR count);

CK_RV        mock_X_FindObjects__invalid_handle          (CK_X_FUNCTION_LIST *self,
                                                          CK_SESSION_HANDLE session,
                                                          CK_OBJECT_HANDLE_PTR objects,
                                                          CK_ULONG max_count,
                                                          CK_ULONG_PTR count);

CK_RV        mock_C_FindObjects__fails                   (CK_SESSION_HANDLE session,
                                                          CK_OBJECT_HANDLE_PTR objects,
                                                          CK_ULONG max_count,
                                                          CK_ULONG_PTR count);

CK_RV        mock_C_FindObjectsFinal                     (CK_SESSION_HANDLE session);

CK_RV        mock_C_FindObjectsFinal__invalid_handle     (CK_SESSION_HANDLE session);

CK_RV        mock_X_FindObjectsFinal__invalid_handle     (CK_X_FUNCTION_LIST *self,
                                                          CK_SESSION_HANDLE session);

CK_RV        mock_C_EncryptInit                          (CK_SESSION_HANDLE session,
                                                          CK_MECHANISM_PTR mechanism,
                                                          CK_OBJECT_HANDLE key);

CK_RV        mock_C_EncryptInit__invalid_handle          (CK_SESSION_HANDLE session,
                                                          CK_MECHANISM_PTR mechanism,
                                                          CK_OBJECT_HANDLE key);

CK_RV        mock_X_EncryptInit__invalid_handle          (CK_X_FUNCTION_LIST *self,
                                                          CK_SESSION_HANDLE session,
                                                          CK_MECHANISM_PTR mechanism,
                                                          CK_OBJECT_HANDLE key);

CK_RV        mock_C_Encrypt                              (CK_SESSION_HANDLE session,
                                                          CK_BYTE_PTR data,
                                                          CK_ULONG data_len,
                                                          CK_BYTE_PTR encrypted_data,
                                                          CK_ULONG_PTR encrypted_data_len);

CK_RV        mock_C_Encrypt__invalid_handle              (CK_SESSION_HANDLE session,
                                                          CK_BYTE_PTR data,
                                                          CK_ULONG data_len,
                                                          CK_BYTE_PTR encrypted_data,
                                                          CK_ULONG_PTR encrypted_data_len);

CK_RV        mock_X_Encrypt__invalid_handle              (CK_X_FUNCTION_LIST *self,
                                                          CK_SESSION_HANDLE session,
                                                          CK_BYTE_PTR data,
                                                          CK_ULONG data_len,
                                                          CK_BYTE_PTR encrypted_data,
                                                          CK_ULONG_PTR encrypted_data_len);

CK_RV        mock_C_EncryptUpdate                        (CK_SESSION_HANDLE session,
                                                          CK_BYTE_PTR part,
                                                          CK_ULONG part_len,
                                                          CK_BYTE_PTR encrypted_part,
                                                          CK_ULONG_PTR encrypted_part_len);

CK_RV        mock_C_EncryptUpdate__invalid_handle        (CK_SESSION_HANDLE session,
                                                          CK_BYTE_PTR part,
                                                          CK_ULONG part_len,
                                                          CK_BYTE_PTR encrypted_part,
                                                          CK_ULONG_PTR encrypted_part_len);

CK_RV        mock_X_EncryptUpdate__invalid_handle        (CK_X_FUNCTION_LIST *self,
                                                          CK_SESSION_HANDLE session,
                                                          CK_BYTE_PTR part,
                                                          CK_ULONG part_len,
                                                          CK_BYTE_PTR encrypted_part,
                                                          CK_ULONG_PTR encrypted_part_len);

CK_RV        mock_C_EncryptFinal                         (CK_SESSION_HANDLE session,
                                                          CK_BYTE_PTR last_encrypted_part,
                                                          CK_ULONG_PTR last_encrypted_part_len);

CK_RV        mock_C_EncryptFinal__invalid_handle         (CK_SESSION_HANDLE session,
                                                          CK_BYTE_PTR last_part,
                                                          CK_ULONG_PTR last_part_len);

CK_RV        mock_X_EncryptFinal__invalid_handle         (CK_X_FUNCTION_LIST *self,
                                                          CK_SESSION_HANDLE session,
                                                          CK_BYTE_PTR last_part,
                                                          CK_ULONG_PTR last_part_len);

CK_RV        mock_C_DecryptInit                          (CK_SESSION_HANDLE session,
                                                          CK_MECHANISM_PTR mechanism,
                                                          CK_OBJECT_HANDLE key);

CK_RV        mock_C_DecryptInit__invalid_handle          (CK_SESSION_HANDLE session,
                                                          CK_MECHANISM_PTR mechanism,
                                                          CK_OBJECT_HANDLE key);

CK_RV        mock_X_DecryptInit__invalid_handle          (CK_X_FUNCTION_LIST *self,
                                                          CK_SESSION_HANDLE session,
                                                          CK_MECHANISM_PTR mechanism,
                                                          CK_OBJECT_HANDLE key);

CK_RV        mock_C_Decrypt                              (CK_SESSION_HANDLE session,
                                                          CK_BYTE_PTR encrypted_data,
                                                          CK_ULONG encrypted_data_len,
                                                          CK_BYTE_PTR data,
                                                          CK_ULONG_PTR data_len);

CK_RV        mock_C_Decrypt__invalid_handle              (CK_SESSION_HANDLE session,
                                                          CK_BYTE_PTR enc_data,
                                                          CK_ULONG enc_data_len,
                                                          CK_BYTE_PTR data,
                                                          CK_ULONG_PTR data_len);

CK_RV        mock_X_Decrypt__invalid_handle              (CK_X_FUNCTION_LIST *self,
                                                          CK_SESSION_HANDLE session,
                                                          CK_BYTE_PTR enc_data,
                                                          CK_ULONG enc_data_len,
                                                          CK_BYTE_PTR data,
                                                          CK_ULONG_PTR data_len);

CK_RV        mock_C_DecryptUpdate                        (CK_SESSION_HANDLE session,
                                                          CK_BYTE_PTR encrypted_part,
                                                          CK_ULONG encrypted_part_len,
                                                          CK_BYTE_PTR part,
                                                          CK_ULONG_PTR part_len);

CK_RV        mock_C_DecryptUpdate__invalid_handle        (CK_SESSION_HANDLE session,
                                                          CK_BYTE_PTR enc_part,
                                                          CK_ULONG enc_part_len,
                                                          CK_BYTE_PTR part,
                                                          CK_ULONG_PTR part_len);

CK_RV        mock_X_DecryptUpdate__invalid_handle        (CK_X_FUNCTION_LIST *self,
                                                          CK_SESSION_HANDLE session,
                                                          CK_BYTE_PTR enc_part,
                                                          CK_ULONG enc_part_len,
                                                          CK_BYTE_PTR part,
                                                          CK_ULONG_PTR part_len);

CK_RV        mock_C_DecryptFinal                         (CK_SESSION_HANDLE session,
                                                          CK_BYTE_PTR last_part,
                                                          CK_ULONG_PTR last_part_len);

CK_RV        mock_C_DecryptFinal__invalid_handle         (CK_SESSION_HANDLE session,
                                                          CK_BYTE_PTR last_part,
                                                          CK_ULONG_PTR last_part_len);

CK_RV        mock_X_DecryptFinal__invalid_handle         (CK_X_FUNCTION_LIST *self,
                                                          CK_SESSION_HANDLE session,
                                                          CK_BYTE_PTR last_part,
                                                          CK_ULONG_PTR last_part_len);

CK_RV        mock_C_DigestInit                           (CK_SESSION_HANDLE session,
                                                          CK_MECHANISM_PTR mechanism);

CK_RV        mock_C_DigestInit__invalid_handle           (CK_SESSION_HANDLE session,
                                                          CK_MECHANISM_PTR mechanism);

CK_RV        mock_X_DigestInit__invalid_handle           (CK_X_FUNCTION_LIST *self,
                                                          CK_SESSION_HANDLE session,
                                                          CK_MECHANISM_PTR mechanism);

CK_RV        mock_C_Digest                               (CK_SESSION_HANDLE session,
                                                          CK_BYTE_PTR data,
                                                          CK_ULONG data_len,
                                                          CK_BYTE_PTR digest,
                                                          CK_ULONG_PTR digest_len);

CK_RV        mock_C_Digest__invalid_handle               (CK_SESSION_HANDLE session,
                                                          CK_BYTE_PTR data,
                                                          CK_ULONG data_len,
                                                          CK_BYTE_PTR digest,
                                                          CK_ULONG_PTR digest_len);

CK_RV        mock_X_Digest__invalid_handle               (CK_X_FUNCTION_LIST *self,
                                                          CK_SESSION_HANDLE session,
                                                          CK_BYTE_PTR data,
                                                          CK_ULONG data_len,
                                                          CK_BYTE_PTR digest,
                                                          CK_ULONG_PTR digest_len);

CK_RV        mock_C_DigestUpdate                         (CK_SESSION_HANDLE session,
                                                          CK_BYTE_PTR part,
                                                          CK_ULONG part_len);

CK_RV        mock_C_DigestUpdate__invalid_handle         (CK_SESSION_HANDLE session,
                                                          CK_BYTE_PTR part,
                                                          CK_ULONG part_len);

CK_RV        mock_X_DigestUpdate__invalid_handle         (CK_X_FUNCTION_LIST *self,
                                                          CK_SESSION_HANDLE session,
                                                          CK_BYTE_PTR part,
                                                          CK_ULONG part_len);

CK_RV        mock_C_DigestKey                            (CK_SESSION_HANDLE session,
                                                          CK_OBJECT_HANDLE key);

CK_RV        mock_C_DigestKey__invalid_handle            (CK_SESSION_HANDLE session,
                                                          CK_OBJECT_HANDLE key);

CK_RV        mock_X_DigestKey__invalid_handle            (CK_X_FUNCTION_LIST *self,
                                                          CK_SESSION_HANDLE session,
                                                          CK_OBJECT_HANDLE key);

CK_RV        mock_C_DigestFinal                          (CK_SESSION_HANDLE session,
                                                          CK_BYTE_PTR digest,
                                                          CK_ULONG_PTR digest_len);

CK_RV        mock_C_DigestFinal__invalid_handle          (CK_SESSION_HANDLE session,
                                                          CK_BYTE_PTR digest,
                                                          CK_ULONG_PTR digest_len);

CK_RV        mock_X_DigestFinal__invalid_handle          (CK_X_FUNCTION_LIST *self,
                                                          CK_SESSION_HANDLE session,
                                                          CK_BYTE_PTR digest,
                                                          CK_ULONG_PTR digest_len);

CK_RV        mock_C_SignInit                             (CK_SESSION_HANDLE session,
                                                          CK_MECHANISM_PTR mechanism,
                                                          CK_OBJECT_HANDLE key);

CK_RV        mock_C_SignInit__invalid_handle             (CK_SESSION_HANDLE session,
                                                          CK_MECHANISM_PTR mechanism,
                                                          CK_OBJECT_HANDLE key);

CK_RV        mock_X_SignInit__invalid_handle             (CK_X_FUNCTION_LIST *self,
                                                          CK_SESSION_HANDLE session,
                                                          CK_MECHANISM_PTR mechanism,
                                                          CK_OBJECT_HANDLE key);

CK_RV        mock_C_Sign                                 (CK_SESSION_HANDLE session,
                                                          CK_BYTE_PTR data,
                                                          CK_ULONG data_len,
                                                          CK_BYTE_PTR signature,
                                                          CK_ULONG_PTR signature_len);

CK_RV        mock_C_Sign__invalid_handle                 (CK_SESSION_HANDLE session,
                                                          CK_BYTE_PTR data,
                                                          CK_ULONG data_len,
                                                          CK_BYTE_PTR signature,
                                                          CK_ULONG_PTR signature_len);

CK_RV        mock_X_Sign__invalid_handle                 (CK_X_FUNCTION_LIST *self,
                                                          CK_SESSION_HANDLE session,
                                                          CK_BYTE_PTR data,
                                                          CK_ULONG data_len,
                                                          CK_BYTE_PTR signature,
                                                          CK_ULONG_PTR signature_len);

CK_RV        mock_C_SignUpdate                           (CK_SESSION_HANDLE session,
                                                          CK_BYTE_PTR part,
                                                          CK_ULONG part_len);

CK_RV        mock_C_SignUpdate__invalid_handle           (CK_SESSION_HANDLE session,
                                                          CK_BYTE_PTR part,
                                                          CK_ULONG part_len);

CK_RV        mock_X_SignUpdate__invalid_handle           (CK_X_FUNCTION_LIST *self,
                                                          CK_SESSION_HANDLE session,
                                                          CK_BYTE_PTR part,
                                                          CK_ULONG part_len);

CK_RV        mock_C_SignFinal                            (CK_SESSION_HANDLE session,
                                                          CK_BYTE_PTR signature,
                                                          CK_ULONG_PTR signature_len);

CK_RV        mock_C_SignFinal__invalid_handle            (CK_SESSION_HANDLE session,
                                                          CK_BYTE_PTR signature,
                                                          CK_ULONG_PTR signature_len);

CK_RV        mock_X_SignFinal__invalid_handle            (CK_X_FUNCTION_LIST *self,
                                                          CK_SESSION_HANDLE session,
                                                          CK_BYTE_PTR signature,
                                                          CK_ULONG_PTR signature_len);

CK_RV        mock_C_SignRecoverInit                      (CK_SESSION_HANDLE session,
                                                          CK_MECHANISM_PTR mechanism,
                                                          CK_OBJECT_HANDLE key);

CK_RV        mock_C_SignRecoverInit__invalid_handle      (CK_SESSION_HANDLE session,
                                                          CK_MECHANISM_PTR mechanism,
                                                          CK_OBJECT_HANDLE key);

CK_RV        mock_X_SignRecoverInit__invalid_handle      (CK_X_FUNCTION_LIST *self,
                                                          CK_SESSION_HANDLE session,
                                                          CK_MECHANISM_PTR mechanism,
                                                          CK_OBJECT_HANDLE key);

CK_RV        mock_C_SignRecover                          (CK_SESSION_HANDLE session,
                                                          CK_BYTE_PTR data,
                                                          CK_ULONG data_len,
                                                          CK_BYTE_PTR signature,
                                                          CK_ULONG_PTR signature_len);

CK_RV        mock_C_SignRecover__invalid_handle          (CK_SESSION_HANDLE session,
                                                          CK_BYTE_PTR data,
                                                          CK_ULONG data_len,
                                                          CK_BYTE_PTR signature,
                                                          CK_ULONG_PTR signature_len);

CK_RV        mock_X_SignRecover__invalid_handle          (CK_X_FUNCTION_LIST *self,
                                                          CK_SESSION_HANDLE session,
                                                          CK_BYTE_PTR data,
                                                          CK_ULONG data_len,
                                                          CK_BYTE_PTR signature,
                                                          CK_ULONG_PTR signature_len);

CK_RV        mock_C_VerifyInit                           (CK_SESSION_HANDLE session,
                                                          CK_MECHANISM_PTR mechanism,
                                                          CK_OBJECT_HANDLE key);

CK_RV        mock_C_VerifyInit__invalid_handle           (CK_SESSION_HANDLE session,
                                                          CK_MECHANISM_PTR mechanism,
                                                          CK_OBJECT_HANDLE key);

CK_RV        mock_X_VerifyInit__invalid_handle           (CK_X_FUNCTION_LIST *self,
                                                          CK_SESSION_HANDLE session,
                                                          CK_MECHANISM_PTR mechanism,
                                                          CK_OBJECT_HANDLE key);

CK_RV        mock_C_Verify                               (CK_SESSION_HANDLE session,
                                                          CK_BYTE_PTR data,
                                                          CK_ULONG data_len,
                                                          CK_BYTE_PTR signature,
                                                          CK_ULONG signature_len);

CK_RV        mock_C_Verify__invalid_handle               (CK_SESSION_HANDLE session,
                                                          CK_BYTE_PTR data,
                                                          CK_ULONG data_len,
                                                          CK_BYTE_PTR signature,
                                                          CK_ULONG signature_len);

CK_RV        mock_X_Verify__invalid_handle               (CK_X_FUNCTION_LIST *self,
                                                          CK_SESSION_HANDLE session,
                                                          CK_BYTE_PTR data,
                                                          CK_ULONG data_len,
                                                          CK_BYTE_PTR signature,
                                                          CK_ULONG signature_len);

CK_RV        mock_C_VerifyUpdate                         (CK_SESSION_HANDLE session,
                                                          CK_BYTE_PTR part,
                                                          CK_ULONG part_len);

CK_RV        mock_C_VerifyUpdate__invalid_handle         (CK_SESSION_HANDLE session,
                                                          CK_BYTE_PTR part,
                                                          CK_ULONG part_len);

CK_RV        mock_X_VerifyUpdate__invalid_handle         (CK_X_FUNCTION_LIST *self,
                                                          CK_SESSION_HANDLE session,
                                                          CK_BYTE_PTR part,
                                                          CK_ULONG part_len);

CK_RV        mock_C_VerifyFinal                          (CK_SESSION_HANDLE session,
                                                          CK_BYTE_PTR signature,
                                                          CK_ULONG signature_len);

CK_RV        mock_C_VerifyFinal__invalid_handle          (CK_SESSION_HANDLE session,
                                                          CK_BYTE_PTR signature,
                                                          CK_ULONG signature_len);

CK_RV        mock_X_VerifyFinal__invalid_handle          (CK_X_FUNCTION_LIST *self,
                                                          CK_SESSION_HANDLE session,
                                                          CK_BYTE_PTR signature,
                                                          CK_ULONG signature_len);

CK_RV        mock_C_VerifyRecoverInit                    (CK_SESSION_HANDLE session,
                                                          CK_MECHANISM_PTR mechanism,
                                                          CK_OBJECT_HANDLE key);

CK_RV        mock_C_VerifyRecoverInit__invalid_handle    (CK_SESSION_HANDLE session,
                                                          CK_MECHANISM_PTR mechanism,
                                                          CK_OBJECT_HANDLE key);

CK_RV        mock_X_VerifyRecoverInit__invalid_handle    (CK_X_FUNCTION_LIST *self,
                                                          CK_SESSION_HANDLE session,
                                                          CK_MECHANISM_PTR mechanism,
                                                          CK_OBJECT_HANDLE key);

CK_RV        mock_C_VerifyRecover                        (CK_SESSION_HANDLE session,
                                                          CK_BYTE_PTR signature,
                                                          CK_ULONG signature_len,
                                                          CK_BYTE_PTR data,
                                                          CK_ULONG_PTR data_len);

CK_RV        mock_C_VerifyRecover__invalid_handle        (CK_SESSION_HANDLE session,
                                                          CK_BYTE_PTR signature,
                                                          CK_ULONG signature_len,
                                                          CK_BYTE_PTR data,
                                                          CK_ULONG_PTR data_len);

CK_RV        mock_X_VerifyRecover__invalid_handle        (CK_X_FUNCTION_LIST *self,
                                                          CK_SESSION_HANDLE session,
                                                          CK_BYTE_PTR signature,
                                                          CK_ULONG signature_len,
                                                          CK_BYTE_PTR data,
                                                          CK_ULONG_PTR data_len);

CK_RV        mock_C_DigestEncryptUpdate                  (CK_SESSION_HANDLE session,
                                                          CK_BYTE_PTR part,
                                                          CK_ULONG part_len,
                                                          CK_BYTE_PTR encrypted_part,
                                                          CK_ULONG_PTR encrypted_part_len);

CK_RV        mock_C_DigestEncryptUpdate__invalid_handle  (CK_SESSION_HANDLE session,
                                                          CK_BYTE_PTR part,
                                                          CK_ULONG part_len,
                                                          CK_BYTE_PTR enc_part,
                                                          CK_ULONG_PTR enc_part_len);

CK_RV        mock_X_DigestEncryptUpdate__invalid_handle  (CK_X_FUNCTION_LIST *self,
                                                          CK_SESSION_HANDLE session,
                                                          CK_BYTE_PTR part,
                                                          CK_ULONG part_len,
                                                          CK_BYTE_PTR enc_part,
                                                          CK_ULONG_PTR enc_part_len);

CK_RV        mock_C_DecryptDigestUpdate                  (CK_SESSION_HANDLE session,
                                                          CK_BYTE_PTR encrypted_part,
                                                          CK_ULONG encrypted_part_len,
                                                          CK_BYTE_PTR part,
                                                          CK_ULONG_PTR part_len);

CK_RV        mock_C_DecryptDigestUpdate__invalid_handle  (CK_SESSION_HANDLE session,
                                                          CK_BYTE_PTR enc_part,
                                                          CK_ULONG enc_part_len,
                                                          CK_BYTE_PTR part,
                                                          CK_ULONG_PTR part_len);

CK_RV        mock_X_DecryptDigestUpdate__invalid_handle  (CK_X_FUNCTION_LIST *self,
                                                          CK_SESSION_HANDLE session,
                                                          CK_BYTE_PTR enc_part,
                                                          CK_ULONG enc_part_len,
                                                          CK_BYTE_PTR part,
                                                          CK_ULONG_PTR part_len);

CK_RV        mock_C_SignEncryptUpdate                    (CK_SESSION_HANDLE session,
                                                          CK_BYTE_PTR part,
                                                          CK_ULONG part_len,
                                                          CK_BYTE_PTR encrypted_part,
                                                          CK_ULONG_PTR encrypted_part_len);

CK_RV        mock_C_SignEncryptUpdate__invalid_handle    (CK_SESSION_HANDLE session,
                                                          CK_BYTE_PTR part,
                                                          CK_ULONG part_len,
                                                          CK_BYTE_PTR enc_part,
                                                          CK_ULONG_PTR enc_part_len);

CK_RV        mock_X_SignEncryptUpdate__invalid_handle    (CK_X_FUNCTION_LIST *self,
                                                          CK_SESSION_HANDLE session,
                                                          CK_BYTE_PTR part,
                                                          CK_ULONG part_len,
                                                          CK_BYTE_PTR enc_part,
                                                          CK_ULONG_PTR enc_part_len);

CK_RV        mock_C_DecryptVerifyUpdate                  (CK_SESSION_HANDLE session,
                                                          CK_BYTE_PTR encrypted_part,
                                                          CK_ULONG encrypted_part_len,
                                                          CK_BYTE_PTR part,
                                                          CK_ULONG_PTR part_len);

CK_RV        mock_C_DecryptVerifyUpdate__invalid_handle  (CK_SESSION_HANDLE session,
                                                          CK_BYTE_PTR enc_part,
                                                          CK_ULONG enc_part_len,
                                                          CK_BYTE_PTR part,
                                                          CK_ULONG_PTR part_len);

CK_RV        mock_X_DecryptVerifyUpdate__invalid_handle  (CK_X_FUNCTION_LIST *self,
                                                          CK_SESSION_HANDLE session,
                                                          CK_BYTE_PTR enc_part,
                                                          CK_ULONG enc_part_len,
                                                          CK_BYTE_PTR part,
                                                          CK_ULONG_PTR part_len);

CK_RV        mock_C_GenerateKey                          (CK_SESSION_HANDLE session,
                                                          CK_MECHANISM_PTR mechanism,
                                                          CK_ATTRIBUTE_PTR template,
                                                          CK_ULONG count,
                                                          CK_OBJECT_HANDLE_PTR key);

CK_RV        mock_C_GenerateKey__invalid_handle          (CK_SESSION_HANDLE session,
                                                          CK_MECHANISM_PTR mechanism,
                                                          CK_ATTRIBUTE_PTR template,
                                                          CK_ULONG count,
                                                          CK_OBJECT_HANDLE_PTR key);

CK_RV        mock_X_GenerateKey__invalid_handle          (CK_X_FUNCTION_LIST *self,
                                                          CK_SESSION_HANDLE session,
                                                          CK_MECHANISM_PTR mechanism,
                                                          CK_ATTRIBUTE_PTR template,
                                                          CK_ULONG count,
                                                          CK_OBJECT_HANDLE_PTR key);

CK_RV        mock_C_GenerateKeyPair                      (CK_SESSION_HANDLE session,
                                                          CK_MECHANISM_PTR mechanism,
                                                          CK_ATTRIBUTE_PTR public_key_template,
                                                          CK_ULONG public_key_count,
                                                          CK_ATTRIBUTE_PTR private_key_template,
                                                          CK_ULONG private_key_count,
                                                          CK_OBJECT_HANDLE_PTR public_key,
                                                          CK_OBJECT_HANDLE_PTR private_key);

CK_RV        mock_C_GenerateKeyPair__invalid_handle      (CK_SESSION_HANDLE session,
                                                          CK_MECHANISM_PTR mechanism,
                                                          CK_ATTRIBUTE_PTR pub_template,
                                                          CK_ULONG pub_count,
                                                          CK_ATTRIBUTE_PTR priv_template,
                                                          CK_ULONG priv_count,
                                                          CK_OBJECT_HANDLE_PTR pub_key,
                                                          CK_OBJECT_HANDLE_PTR priv_key);

CK_RV        mock_X_GenerateKeyPair__invalid_handle      (CK_X_FUNCTION_LIST *self,
                                                          CK_SESSION_HANDLE session,
                                                          CK_MECHANISM_PTR mechanism,
                                                          CK_ATTRIBUTE_PTR pub_template,
                                                          CK_ULONG pub_count,
                                                          CK_ATTRIBUTE_PTR priv_template,
                                                          CK_ULONG priv_count,
                                                          CK_OBJECT_HANDLE_PTR pub_key,
                                                          CK_OBJECT_HANDLE_PTR priv_key);

CK_RV        mock_C_WrapKey                              (CK_SESSION_HANDLE session,
                                                          CK_MECHANISM_PTR mechanism,
                                                          CK_OBJECT_HANDLE wrapping_key,
                                                          CK_OBJECT_HANDLE key,
                                                          CK_BYTE_PTR wrapped_key,
                                                          CK_ULONG_PTR wrapped_key_len);

CK_RV        mock_C_WrapKey__invalid_handle              (CK_SESSION_HANDLE session,
                                                          CK_MECHANISM_PTR mechanism,
                                                          CK_OBJECT_HANDLE wrapping_key,
                                                          CK_OBJECT_HANDLE key,
                                                          CK_BYTE_PTR wrapped_key,
                                                          CK_ULONG_PTR wrapped_key_len);

CK_RV        mock_X_WrapKey__invalid_handle              (CK_X_FUNCTION_LIST *self,
                                                          CK_SESSION_HANDLE session,
                                                          CK_MECHANISM_PTR mechanism,
                                                          CK_OBJECT_HANDLE wrapping_key,
                                                          CK_OBJECT_HANDLE key,
                                                          CK_BYTE_PTR wrapped_key,
                                                          CK_ULONG_PTR wrapped_key_len);

CK_RV        mock_C_UnwrapKey                            (CK_SESSION_HANDLE session,
                                                          CK_MECHANISM_PTR mechanism,
                                                          CK_OBJECT_HANDLE unwrapping_key,
                                                          CK_BYTE_PTR wrapped_key,
                                                          CK_ULONG wrapped_key_len,
                                                          CK_ATTRIBUTE_PTR template,
                                                          CK_ULONG count,
                                                          CK_OBJECT_HANDLE_PTR key);

CK_RV        mock_C_UnwrapKey__invalid_handle            (CK_SESSION_HANDLE session,
                                                          CK_MECHANISM_PTR mechanism,
                                                          CK_OBJECT_HANDLE unwrapping_key,
                                                          CK_BYTE_PTR wrapped_key,
                                                          CK_ULONG wrapped_key_len,
                                                          CK_ATTRIBUTE_PTR template,
                                                          CK_ULONG count,
                                                          CK_OBJECT_HANDLE_PTR key);

CK_RV        mock_X_UnwrapKey__invalid_handle            (CK_X_FUNCTION_LIST *self,
                                                          CK_SESSION_HANDLE session,
                                                          CK_MECHANISM_PTR mechanism,
                                                          CK_OBJECT_HANDLE unwrapping_key,
                                                          CK_BYTE_PTR wrapped_key,
                                                          CK_ULONG wrapped_key_len,
                                                          CK_ATTRIBUTE_PTR template,
                                                          CK_ULONG count,
                                                          CK_OBJECT_HANDLE_PTR key);

CK_RV        mock_C_DeriveKey                            (CK_SESSION_HANDLE session,
                                                          CK_MECHANISM_PTR mechanism,
                                                          CK_OBJECT_HANDLE base_key,
                                                          CK_ATTRIBUTE_PTR template,
                                                          CK_ULONG count,
                                                          CK_OBJECT_HANDLE_PTR key);

CK_RV        mock_C_DeriveKey__invalid_handle            (CK_SESSION_HANDLE session,
                                                          CK_MECHANISM_PTR mechanism,
                                                          CK_OBJECT_HANDLE base_key,
                                                          CK_ATTRIBUTE_PTR template,
                                                          CK_ULONG count,
                                                          CK_OBJECT_HANDLE_PTR key);

CK_RV        mock_X_DeriveKey__invalid_handle            (CK_X_FUNCTION_LIST *self,
                                                          CK_SESSION_HANDLE session,
                                                          CK_MECHANISM_PTR mechanism,
                                                          CK_OBJECT_HANDLE base_key,
                                                          CK_ATTRIBUTE_PTR template,
                                                          CK_ULONG count,
                                                          CK_OBJECT_HANDLE_PTR key);

CK_RV        mock_C_SeedRandom                           (CK_SESSION_HANDLE session,
                                                          CK_BYTE_PTR seed,
                                                          CK_ULONG seed_len);

CK_RV        mock_C_SeedRandom__invalid_handle           (CK_SESSION_HANDLE session,
                                                          CK_BYTE_PTR seed,
                                                          CK_ULONG seed_len);

CK_RV        mock_X_SeedRandom__invalid_handle           (CK_X_FUNCTION_LIST *self,
                                                          CK_SESSION_HANDLE session,
                                                          CK_BYTE_PTR seed,
                                                          CK_ULONG seed_len);

CK_RV        mock_C_GenerateRandom                       (CK_SESSION_HANDLE session,
                                                          CK_BYTE_PTR random_data,
                                                          CK_ULONG random_len);

CK_RV        mock_C_GenerateRandom__invalid_handle       (CK_SESSION_HANDLE session,
                                                          CK_BYTE_PTR random_data,
                                                          CK_ULONG random_len);

CK_RV        mock_X_GenerateRandom__invalid_handle       (CK_X_FUNCTION_LIST *self,
                                                          CK_SESSION_HANDLE session,
                                                          CK_BYTE_PTR random_data,
                                                          CK_ULONG random_len);

CK_RV        mock_C_GetInterfaceList_not_supported       (CK_INTERFACE_PTR interfaces_list,
                                                          CK_ULONG_PTR count);

CK_RV        mock_X_GetInterfaceList_not_supported       (CK_X_FUNCTION_LIST *self,
                                                          CK_INTERFACE_PTR interfaces_list,
                                                          CK_ULONG_PTR count);

CK_RV        mock_C_GetInterface_not_supported           (CK_UTF8CHAR_PTR interface_name,
                                                          CK_VERSION_PTR version,
                                                          CK_INTERFACE_PTR_PTR interface,
                                                          CK_FLAGS flags);

CK_RV        mock_X_GetInterface_not_supported           (CK_X_FUNCTION_LIST *self,
                                                          CK_UTF8CHAR_PTR interface_name,
                                                          CK_VERSION_PTR version,
                                                          CK_INTERFACE_PTR_PTR interface,
                                                          CK_FLAGS flags);

CK_RV        mock_C_LoginUser                            (CK_SESSION_HANDLE session,
                                                          CK_USER_TYPE user_type,
                                                          CK_UTF8CHAR_PTR pin,
                                                          CK_ULONG pin_len,
                                                          CK_UTF8CHAR_PTR username,
                                                          CK_ULONG username_len);

CK_RV        mock_C_LoginUser__invalid_handle            (CK_SESSION_HANDLE session,
                                                          CK_USER_TYPE user_type,
                                                          CK_UTF8CHAR_PTR pin,
                                                          CK_ULONG pin_len,
                                                          CK_UTF8CHAR_PTR username,
                                                          CK_ULONG username_len);

CK_RV        mock_X_LoginUser__invalid_handle            (CK_X_FUNCTION_LIST *self,
                                                          CK_SESSION_HANDLE session,
                                                          CK_USER_TYPE user_type,
                                                          CK_UTF8CHAR_PTR pin,
                                                          CK_ULONG pin_len,
                                                          CK_UTF8CHAR_PTR username,
                                                          CK_ULONG username_len);

CK_RV        mock_C_SessionCancel                        (CK_SESSION_HANDLE session,
                                                          CK_FLAGS flags);

CK_RV        mock_C_SessionCancel__invalid_handle        (CK_SESSION_HANDLE session,
                                                          CK_FLAGS flags);

CK_RV        mock_X_SessionCancel__invalid_handle        (CK_X_FUNCTION_LIST *self,
                                                          CK_SESSION_HANDLE session,
                                                          CK_FLAGS flags);

CK_RV        mock_C_MessageEncryptInit                   (CK_SESSION_HANDLE session,
                                                          CK_MECHANISM_PTR mechanism,
                                                          CK_OBJECT_HANDLE key);

CK_RV        mock_C_MessageEncryptInit__invalid_handle   (CK_SESSION_HANDLE session,
                                                          CK_MECHANISM_PTR mechanism,
                                                          CK_OBJECT_HANDLE key);

CK_RV        mock_X_MessageEncryptInit__invalid_handle   (CK_X_FUNCTION_LIST *self,
                                                          CK_SESSION_HANDLE session,
                                                          CK_MECHANISM_PTR mechanism,
                                                          CK_OBJECT_HANDLE key);

CK_RV        mock_C_EncryptMessage                       (CK_SESSION_HANDLE session,
                                                          CK_VOID_PTR parameter,
                                                          CK_ULONG parameter_len,
                                                          CK_BYTE_PTR associated_data,
                                                          CK_ULONG associated_data_len,
                                                          CK_BYTE_PTR plaintext,
                                                          CK_ULONG plaintext_len,
                                                          CK_BYTE_PTR ciphertext,
                                                          CK_ULONG_PTR ciphertext_len);

CK_RV        mock_C_EncryptMessage__invalid_handle       (CK_SESSION_HANDLE session,
                                                          CK_VOID_PTR parameter,
                                                          CK_ULONG parameter_len,
                                                          CK_BYTE_PTR associated_data,
                                                          CK_ULONG associated_data_len,
                                                          CK_BYTE_PTR plaintext,
                                                          CK_ULONG plaintext_len,
                                                          CK_BYTE_PTR ciphertext,
                                                          CK_ULONG_PTR ciphertext_len);

CK_RV        mock_X_EncryptMessage__invalid_handle       (CK_X_FUNCTION_LIST *self,
                                                          CK_SESSION_HANDLE session,
                                                          CK_VOID_PTR parameter,
                                                          CK_ULONG parameter_len,
                                                          CK_BYTE_PTR associated_data,
                                                          CK_ULONG associated_data_len,
                                                          CK_BYTE_PTR plaintext,
                                                          CK_ULONG plaintext_len,
                                                          CK_BYTE_PTR ciphertext,
                                                          CK_ULONG_PTR ciphertext_len);

CK_RV        mock_C_EncryptMessageBegin                  (CK_SESSION_HANDLE session,
                                                          CK_VOID_PTR parameter,
                                                          CK_ULONG parameter_len,
                                                          CK_BYTE_PTR associated_data,
                                                          CK_ULONG associated_data_len);

CK_RV        mock_C_EncryptMessageBegin__invalid_handle  (CK_SESSION_HANDLE session,
                                                          CK_VOID_PTR parameter,
                                                          CK_ULONG parameter_len,
                                                          CK_BYTE_PTR associated_data,
                                                          CK_ULONG associated_data_len);

CK_RV        mock_X_EncryptMessageBegin__invalid_handle  (CK_X_FUNCTION_LIST *self,
                                                          CK_SESSION_HANDLE session,
                                                          CK_VOID_PTR parameter,
                                                          CK_ULONG parameter_len,
                                                          CK_BYTE_PTR associated_data,
                                                          CK_ULONG associated_data_len);

CK_RV        mock_C_EncryptMessageNext                   (CK_SESSION_HANDLE session,
                                                          CK_VOID_PTR parameter,
                                                          CK_ULONG parameter_len,
                                                          CK_BYTE_PTR plaintext_part,
                                                          CK_ULONG plaintext_part_len,
                                                          CK_BYTE_PTR ciphertext_part,
                                                          CK_ULONG_PTR ciphertext_part_len,
                                                          CK_FLAGS flags);

CK_RV        mock_C_EncryptMessageNext__invalid_handle   (CK_SESSION_HANDLE session,
                                                          CK_VOID_PTR parameter,
                                                          CK_ULONG parameter_len,
                                                          CK_BYTE_PTR plaintext_part,
                                                          CK_ULONG plaintext_part_len,
                                                          CK_BYTE_PTR ciphertext_part,
                                                          CK_ULONG_PTR ciphertext_part_len,
                                                          CK_FLAGS flags);

CK_RV        mock_X_EncryptMessageNext__invalid_handle   (CK_X_FUNCTION_LIST *self,
                                                          CK_SESSION_HANDLE session,
                                                          CK_VOID_PTR parameter,
                                                          CK_ULONG parameter_len,
                                                          CK_BYTE_PTR plaintext_part,
                                                          CK_ULONG plaintext_part_len,
                                                          CK_BYTE_PTR ciphertext_part,
                                                          CK_ULONG_PTR ciphertext_part_len,
                                                          CK_FLAGS flags);

CK_RV        mock_C_MessageEncryptFinal                  (CK_SESSION_HANDLE session);

CK_RV        mock_C_MessageEncryptFinal__invalid_handle  (CK_SESSION_HANDLE session);

CK_RV        mock_X_MessageEncryptFinal__invalid_handle  (CK_X_FUNCTION_LIST *self,
                                                          CK_SESSION_HANDLE session);

CK_RV        mock_C_MessageDecryptInit                   (CK_SESSION_HANDLE session,
                                                          CK_MECHANISM_PTR mechanism,
                                                          CK_OBJECT_HANDLE key);

CK_RV        mock_C_MessageDecryptInit__invalid_handle   (CK_SESSION_HANDLE session,
                                                          CK_MECHANISM_PTR mechanism,
                                                          CK_OBJECT_HANDLE key);

CK_RV        mock_X_MessageDecryptInit__invalid_handle   (CK_X_FUNCTION_LIST *self,
                                                          CK_SESSION_HANDLE session,
                                                          CK_MECHANISM_PTR mechanism,
                                                          CK_OBJECT_HANDLE key);

CK_RV        mock_C_DecryptMessage                       (CK_SESSION_HANDLE session,
                                                          CK_VOID_PTR parameter,
                                                          CK_ULONG parameter_len,
                                                          CK_BYTE_PTR associated_data,
                                                          CK_ULONG associated_data_len,
                                                          CK_BYTE_PTR ciphertext,
                                                          CK_ULONG ciphertext_len,
                                                          CK_BYTE_PTR plaintext,
                                                          CK_ULONG_PTR plaintext_len);

CK_RV        mock_C_DecryptMessage__invalid_handle       (CK_SESSION_HANDLE session,
                                                          CK_VOID_PTR parameter,
                                                          CK_ULONG parameter_len,
                                                          CK_BYTE_PTR associated_data,
                                                          CK_ULONG associated_data_len,
                                                          CK_BYTE_PTR ciphertext,
                                                          CK_ULONG ciphertext_len,
                                                          CK_BYTE_PTR plaintext,
                                                          CK_ULONG_PTR plaintext_len);

CK_RV        mock_X_DecryptMessage__invalid_handle       (CK_X_FUNCTION_LIST *self,
                                                          CK_SESSION_HANDLE session,
                                                          CK_VOID_PTR parameter,
                                                          CK_ULONG parameter_len,
                                                          CK_BYTE_PTR associated_data,
                                                          CK_ULONG associated_data_len,
                                                          CK_BYTE_PTR ciphertext,
                                                          CK_ULONG ciphertext_len,
                                                          CK_BYTE_PTR plaintext,
                                                          CK_ULONG_PTR plaintext_len);

CK_RV        mock_C_DecryptMessageBegin                  (CK_SESSION_HANDLE session,
                                                          CK_VOID_PTR parameter,
                                                          CK_ULONG parameter_len,
                                                          CK_BYTE_PTR associated_data,
                                                          CK_ULONG associated_data_len);

CK_RV        mock_C_DecryptMessageBegin__invalid_handle  (CK_SESSION_HANDLE session,
                                                          CK_VOID_PTR parameter,
                                                          CK_ULONG parameter_len,
                                                          CK_BYTE_PTR associated_data,
                                                          CK_ULONG associated_data_len);

CK_RV        mock_X_DecryptMessageBegin__invalid_handle  (CK_X_FUNCTION_LIST *self,
                                                          CK_SESSION_HANDLE session,
                                                          CK_VOID_PTR parameter,
                                                          CK_ULONG parameter_len,
                                                          CK_BYTE_PTR associated_data,
                                                          CK_ULONG associated_data_len);

CK_RV        mock_C_DecryptMessageNext                   (CK_SESSION_HANDLE session,
                                                          CK_VOID_PTR parameter,
                                                          CK_ULONG parameter_len,
                                                          CK_BYTE_PTR ciphertext_part,
                                                          CK_ULONG ciphertext_part_len,
                                                          CK_BYTE_PTR plaintext_part,
                                                          CK_ULONG_PTR plaintext_part_len,
                                                          CK_FLAGS flags);

CK_RV        mock_C_DecryptMessageNext__invalid_handle   (CK_SESSION_HANDLE session,
                                                          CK_VOID_PTR parameter,
                                                          CK_ULONG parameter_len,
                                                          CK_BYTE_PTR ciphertext_part,
                                                          CK_ULONG ciphertext_part_len,
                                                          CK_BYTE_PTR plaintext_part,
                                                          CK_ULONG_PTR plaintext_part_len,
                                                          CK_FLAGS flags);

CK_RV        mock_X_DecryptMessageNext__invalid_handle   (CK_X_FUNCTION_LIST *self,
                                                          CK_SESSION_HANDLE session,
                                                          CK_VOID_PTR parameter,
                                                          CK_ULONG parameter_len,
                                                          CK_BYTE_PTR ciphertext_part,
                                                          CK_ULONG ciphertext_part_len,
                                                          CK_BYTE_PTR plaintext_part,
                                                          CK_ULONG_PTR plaintext_part_len,
                                                          CK_FLAGS flags);

CK_RV        mock_C_MessageDecryptFinal                  (CK_SESSION_HANDLE session);

CK_RV        mock_C_MessageDecryptFinal__invalid_handle  (CK_SESSION_HANDLE session);

CK_RV        mock_X_MessageDecryptFinal__invalid_handle  (CK_X_FUNCTION_LIST *self,
                                                          CK_SESSION_HANDLE session);

CK_RV        mock_C_MessageSignInit                       (CK_SESSION_HANDLE session,
                                                          CK_MECHANISM_PTR mechanism,
                                                          CK_OBJECT_HANDLE key);

CK_RV        mock_C_MessageSignInit__invalid_handle       (CK_SESSION_HANDLE session,
                                                          CK_MECHANISM_PTR mechanism,
                                                          CK_OBJECT_HANDLE key);

CK_RV        mock_X_MessageSignInit__invalid_handle       (CK_X_FUNCTION_LIST *self,
                                                          CK_SESSION_HANDLE session,
                                                          CK_MECHANISM_PTR mechanism,
                                                          CK_OBJECT_HANDLE key);

CK_RV        mock_C_SignMessage                          (CK_SESSION_HANDLE session,
                                                          CK_VOID_PTR parameter,
                                                          CK_ULONG parameter_len,
                                                          CK_BYTE_PTR data,
                                                          CK_ULONG data_len,
                                                          CK_BYTE_PTR signature,
                                                          CK_ULONG_PTR signature_len);

CK_RV        mock_C_SignMessage__invalid_handle          (CK_SESSION_HANDLE session,
                                                          CK_VOID_PTR parameter,
                                                          CK_ULONG parameter_len,
                                                          CK_BYTE_PTR data,
                                                          CK_ULONG data_len,
                                                          CK_BYTE_PTR signature,
                                                          CK_ULONG_PTR signature_len);

CK_RV        mock_X_SignMessage__invalid_handle          (CK_X_FUNCTION_LIST *self,
                                                          CK_SESSION_HANDLE session,
                                                          CK_VOID_PTR parameter,
                                                          CK_ULONG parameter_len,
                                                          CK_BYTE_PTR data,
                                                          CK_ULONG data_len,
                                                          CK_BYTE_PTR signature,
                                                          CK_ULONG_PTR signature_len);

CK_RV        mock_C_SignMessageBegin                     (CK_SESSION_HANDLE session,
                                                          CK_VOID_PTR parameter,
                                                          CK_ULONG parameter_len);

CK_RV        mock_C_SignMessageBegin__invalid_handle     (CK_SESSION_HANDLE session,
                                                          CK_VOID_PTR parameter,
                                                          CK_ULONG parameter_len);

CK_RV        mock_X_SignMessageBegin__invalid_handle     (CK_X_FUNCTION_LIST *self,
                                                          CK_SESSION_HANDLE session,
                                                          CK_VOID_PTR parameter,
                                                          CK_ULONG parameter_len);

CK_RV        mock_C_SignMessageNext                      (CK_SESSION_HANDLE session,
                                                          CK_VOID_PTR parameter,
                                                          CK_ULONG parameter_len,
                                                          CK_BYTE_PTR data,
                                                          CK_ULONG data_len,
                                                          CK_BYTE_PTR signature,
                                                          CK_ULONG_PTR signature_len);

CK_RV        mock_C_SignMessageNext__invalid_handle      (CK_SESSION_HANDLE session,
                                                          CK_VOID_PTR parameter,
                                                          CK_ULONG parameter_len,
                                                          CK_BYTE_PTR data,
                                                          CK_ULONG data_len,
                                                          CK_BYTE_PTR signature,
                                                          CK_ULONG_PTR signature_len);

CK_RV        mock_X_SignMessageNext__invalid_handle      (CK_X_FUNCTION_LIST *self,
                                                          CK_SESSION_HANDLE session,
                                                          CK_VOID_PTR parameter,
                                                          CK_ULONG parameter_len,
                                                          CK_BYTE_PTR data,
                                                          CK_ULONG data_len,
                                                          CK_BYTE_PTR signature,
                                                          CK_ULONG_PTR signature_len);

CK_RV        mock_C_MessageSignFinal                     (CK_SESSION_HANDLE session);

CK_RV        mock_C_MessageSignFinal__invalid_handle     (CK_SESSION_HANDLE session);

CK_RV        mock_X_MessageSignFinal__invalid_handle     (CK_X_FUNCTION_LIST *self,
                                                          CK_SESSION_HANDLE session);

CK_RV        mock_C_MessageVerifyInit                    (CK_SESSION_HANDLE session,
                                                          CK_MECHANISM_PTR mechanism,
                                                          CK_OBJECT_HANDLE key);

CK_RV        mock_C_MessageVerifyInit__invalid_handle    (CK_SESSION_HANDLE session,
                                                          CK_MECHANISM_PTR mechanism,
                                                          CK_OBJECT_HANDLE key);

CK_RV        mock_X_MessageVerifyInit__invalid_handle    (CK_X_FUNCTION_LIST *self,
                                                          CK_SESSION_HANDLE session,
                                                          CK_MECHANISM_PTR mechanism,
                                                          CK_OBJECT_HANDLE key);

CK_RV        mock_C_VerifyMessage                        (CK_SESSION_HANDLE session,
                                                          CK_VOID_PTR parameter,
                                                          CK_ULONG parameter_len,
                                                          CK_BYTE_PTR data,
                                                          CK_ULONG data_len,
                                                          CK_BYTE_PTR signature,
                                                          CK_ULONG signature_len);

CK_RV        mock_C_VerifyMessage__invalid_handle        (CK_SESSION_HANDLE session,
                                                          CK_VOID_PTR parameter,
                                                          CK_ULONG parameter_len,
                                                          CK_BYTE_PTR data,
                                                          CK_ULONG data_len,
                                                          CK_BYTE_PTR signature,
                                                          CK_ULONG signature_len);

CK_RV        mock_X_VerifyMessage__invalid_handle        (CK_X_FUNCTION_LIST *self,
                                                          CK_SESSION_HANDLE session,
                                                          CK_VOID_PTR parameter,
                                                          CK_ULONG parameter_len,
                                                          CK_BYTE_PTR data,
                                                          CK_ULONG data_len,
                                                          CK_BYTE_PTR signature,
                                                          CK_ULONG signature_len);

CK_RV        mock_C_VerifyMessageBegin                   (CK_SESSION_HANDLE session,
                                                          CK_VOID_PTR parameter,
                                                          CK_ULONG parameter_len);

CK_RV        mock_C_VerifyMessageBegin__invalid_handle   (CK_SESSION_HANDLE session,
                                                          CK_VOID_PTR parameter,
                                                          CK_ULONG parameter_len);

CK_RV        mock_X_VerifyMessageBegin__invalid_handle   (CK_X_FUNCTION_LIST *self,
                                                          CK_SESSION_HANDLE session,
                                                          CK_VOID_PTR parameter,
                                                          CK_ULONG parameter_len);

CK_RV        mock_C_VerifyMessageNext                    (CK_SESSION_HANDLE session,
                                                          CK_VOID_PTR parameter,
                                                          CK_ULONG parameter_len,
                                                          CK_BYTE_PTR data,
                                                          CK_ULONG data_len,
                                                          CK_BYTE_PTR signature,
                                                          CK_ULONG signature_len);

CK_RV        mock_C_VerifyMessageNext__invalid_handle    (CK_SESSION_HANDLE session,
                                                          CK_VOID_PTR parameter,
                                                          CK_ULONG parameter_len,
                                                          CK_BYTE_PTR data,
                                                          CK_ULONG data_len,
                                                          CK_BYTE_PTR signature,
                                                          CK_ULONG signature_len);

CK_RV        mock_X_VerifyMessageNext__invalid_handle    (CK_X_FUNCTION_LIST *self,
                                                          CK_SESSION_HANDLE session,
                                                          CK_VOID_PTR parameter,
                                                          CK_ULONG parameter_len,
                                                          CK_BYTE_PTR data,
                                                          CK_ULONG data_len,
                                                          CK_BYTE_PTR signature,
                                                          CK_ULONG signature_len);

CK_RV        mock_C_MessageVerifyFinal                   (CK_SESSION_HANDLE session);

CK_RV        mock_C_MessageVerifyFinal__invalid_handle   (CK_SESSION_HANDLE session);

CK_RV        mock_X_MessageVerifyFinal__invalid_handle   (CK_X_FUNCTION_LIST *self,
                                                          CK_SESSION_HANDLE session);

#endif /* __MOCK_H__ */
