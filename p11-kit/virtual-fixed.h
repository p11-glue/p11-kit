/*
 * Copyright (c) 2016 Red Hat, Inc
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

#ifndef __P11_VIRTUAL_FIXED_H__
#define __P11_VIRTUAL_FIXED_H__

#define P11_VIRTUAL_FIXED_FUNCTIONS(fixed_index)	\
static CK_RV \
fixed ## fixed_index ## _C_Initialize (CK_VOID_PTR init_args) \
{ \
        CK_FUNCTION_LIST *bound; \
        Wrapper *wrapper; \
        CK_X_FUNCTION_LIST *funcs; \
        bound = fixed_closures[fixed_index]; \
        return_val_if_fail (bound != NULL, CKR_GENERAL_ERROR); \
        wrapper = (Wrapper *) bound; \
        funcs = &wrapper->virt->funcs; \
        return funcs->C_Initialize (funcs, init_args); \
} \
\
static CK_RV \
fixed ## fixed_index ## _C_Finalize (CK_VOID_PTR reserved) \
{ \
        CK_FUNCTION_LIST *bound; \
        Wrapper *wrapper; \
        CK_X_FUNCTION_LIST *funcs; \
        bound = fixed_closures[fixed_index]; \
        return_val_if_fail (bound != NULL, CKR_GENERAL_ERROR); \
        wrapper = (Wrapper *) bound; \
        funcs = &wrapper->virt->funcs; \
        return funcs->C_Finalize (funcs, reserved); \
} \
\
static CK_RV \
fixed ## fixed_index ## _C_GetInfo (CK_INFO_PTR info) \
{ \
        CK_FUNCTION_LIST *bound; \
        Wrapper *wrapper; \
        CK_X_FUNCTION_LIST *funcs; \
        bound = fixed_closures[fixed_index]; \
        return_val_if_fail (bound != NULL, CKR_GENERAL_ERROR); \
        wrapper = (Wrapper *) bound; \
        funcs = &wrapper->virt->funcs; \
        return funcs->C_GetInfo (funcs, info); \
} \
\
static CK_RV \
fixed ## fixed_index ## _C_GetSlotList (CK_BBOOL token_present, \
					CK_SLOT_ID_PTR slot_list, \
					CK_ULONG_PTR count) \
{ \
        CK_FUNCTION_LIST *bound; \
        Wrapper *wrapper; \
        CK_X_FUNCTION_LIST *funcs; \
        bound = fixed_closures[fixed_index]; \
        return_val_if_fail (bound != NULL, CKR_GENERAL_ERROR); \
        wrapper = (Wrapper *) bound; \
        funcs = &wrapper->virt->funcs; \
        return funcs->C_GetSlotList (funcs, token_present, slot_list, count); \
} \
\
static CK_RV \
fixed ## fixed_index ## _C_GetSlotInfo (CK_SLOT_ID slot_id, \
					CK_SLOT_INFO_PTR info) \
{ \
        CK_FUNCTION_LIST *bound; \
        Wrapper *wrapper; \
        CK_X_FUNCTION_LIST *funcs; \
        bound = fixed_closures[fixed_index]; \
        return_val_if_fail (bound != NULL, CKR_GENERAL_ERROR); \
        wrapper = (Wrapper *) bound; \
        funcs = &wrapper->virt->funcs; \
        return funcs->C_GetSlotInfo (funcs, slot_id, info); \
} \
\
static CK_RV \
fixed ## fixed_index ## _C_GetTokenInfo (CK_SLOT_ID slot_id, \
					 CK_TOKEN_INFO_PTR info) \
{ \
        CK_FUNCTION_LIST *bound; \
        Wrapper *wrapper; \
        CK_X_FUNCTION_LIST *funcs; \
        bound = fixed_closures[fixed_index]; \
        return_val_if_fail (bound != NULL, CKR_GENERAL_ERROR); \
        wrapper = (Wrapper *) bound; \
        funcs = &wrapper->virt->funcs; \
        return funcs->C_GetTokenInfo (funcs, slot_id, info); \
} \
\
static CK_RV \
fixed ## fixed_index ## _C_GetMechanismList (CK_SLOT_ID slot_id, \
					     CK_MECHANISM_TYPE_PTR mechanism_list, \
					     CK_ULONG_PTR count) \
{ \
        CK_FUNCTION_LIST *bound; \
        Wrapper *wrapper; \
        CK_X_FUNCTION_LIST *funcs; \
        bound = fixed_closures[fixed_index]; \
        return_val_if_fail (bound != NULL, CKR_GENERAL_ERROR); \
        wrapper = (Wrapper *) bound; \
        funcs = &wrapper->virt->funcs; \
        return funcs->C_GetMechanismList (funcs, slot_id, mechanism_list, count); \
} \
\
static CK_RV \
fixed ## fixed_index ## _C_GetMechanismInfo (CK_SLOT_ID slot_id, \
					     CK_MECHANISM_TYPE type, \
					     CK_MECHANISM_INFO_PTR info) \
{ \
        CK_FUNCTION_LIST *bound; \
        Wrapper *wrapper; \
        CK_X_FUNCTION_LIST *funcs; \
        bound = fixed_closures[fixed_index]; \
        return_val_if_fail (bound != NULL, CKR_GENERAL_ERROR); \
        wrapper = (Wrapper *) bound; \
        funcs = &wrapper->virt->funcs; \
        return funcs->C_GetMechanismInfo (funcs, slot_id, type, info); \
} \
\
static CK_RV \
fixed ## fixed_index ## _C_InitToken (CK_SLOT_ID slot_id, \
				      CK_BYTE_PTR pin, \
				      CK_ULONG pin_len, \
				      CK_BYTE_PTR label) \
{ \
        CK_FUNCTION_LIST *bound; \
        Wrapper *wrapper; \
        CK_X_FUNCTION_LIST *funcs; \
        bound = fixed_closures[fixed_index]; \
        return_val_if_fail (bound != NULL, CKR_GENERAL_ERROR); \
        wrapper = (Wrapper *) bound; \
        funcs = &wrapper->virt->funcs; \
        return funcs->C_InitToken (funcs, slot_id, pin, pin_len, label); \
} \
\
static CK_RV \
fixed ## fixed_index ## _C_InitPIN (CK_SESSION_HANDLE session, \
				    CK_BYTE_PTR pin, \
				    CK_ULONG pin_len) \
{ \
        CK_FUNCTION_LIST *bound; \
        Wrapper *wrapper; \
        CK_X_FUNCTION_LIST *funcs; \
        bound = fixed_closures[fixed_index]; \
        return_val_if_fail (bound != NULL, CKR_GENERAL_ERROR); \
        wrapper = (Wrapper *) bound; \
        funcs = &wrapper->virt->funcs; \
        return funcs->C_InitPIN (funcs, session, pin, pin_len); \
} \
\
static CK_RV \
fixed ## fixed_index ## _C_SetPIN (CK_SESSION_HANDLE session, \
				   CK_BYTE_PTR old_pin, \
				   CK_ULONG old_len, \
				   CK_BYTE_PTR new_pin, \
				   CK_ULONG new_len) \
{ \
        CK_FUNCTION_LIST *bound; \
        Wrapper *wrapper; \
        CK_X_FUNCTION_LIST *funcs; \
        bound = fixed_closures[fixed_index]; \
        return_val_if_fail (bound != NULL, CKR_GENERAL_ERROR); \
        wrapper = (Wrapper *) bound; \
        funcs = &wrapper->virt->funcs; \
        return funcs->C_SetPIN (funcs, session, old_pin, old_len, new_pin, new_len); \
} \
\
static CK_RV \
fixed ## fixed_index ## _C_OpenSession (CK_SLOT_ID slot_id, \
					CK_FLAGS flags, \
					CK_VOID_PTR application, \
					CK_NOTIFY notify, \
					CK_SESSION_HANDLE_PTR session) \
{ \
        CK_FUNCTION_LIST *bound; \
        Wrapper *wrapper; \
        CK_X_FUNCTION_LIST *funcs; \
        bound = fixed_closures[fixed_index]; \
        return_val_if_fail (bound != NULL, CKR_GENERAL_ERROR); \
        wrapper = (Wrapper *) bound; \
        funcs = &wrapper->virt->funcs; \
        return funcs->C_OpenSession (funcs, slot_id, flags, application, notify, session); \
} \
\
static CK_RV \
fixed ## fixed_index ## _C_CloseSession (CK_SESSION_HANDLE session) \
{ \
        CK_FUNCTION_LIST *bound; \
        Wrapper *wrapper; \
        CK_X_FUNCTION_LIST *funcs; \
        bound = fixed_closures[fixed_index]; \
        return_val_if_fail (bound != NULL, CKR_GENERAL_ERROR); \
        wrapper = (Wrapper *) bound; \
        funcs = &wrapper->virt->funcs; \
        return funcs->C_CloseSession (funcs, session); \
} \
\
static CK_RV \
fixed ## fixed_index ## _C_CloseAllSessions (CK_SLOT_ID slot_id) \
{ \
        CK_FUNCTION_LIST *bound; \
        Wrapper *wrapper; \
        CK_X_FUNCTION_LIST *funcs; \
        bound = fixed_closures[fixed_index]; \
        return_val_if_fail (bound != NULL, CKR_GENERAL_ERROR); \
        wrapper = (Wrapper *) bound; \
        funcs = &wrapper->virt->funcs; \
        return funcs->C_CloseAllSessions (funcs, slot_id); \
} \
\
static CK_RV \
fixed ## fixed_index ## _C_GetSessionInfo (CK_SESSION_HANDLE session, \
					   CK_SESSION_INFO_PTR info) \
{ \
        CK_FUNCTION_LIST *bound; \
        Wrapper *wrapper; \
        CK_X_FUNCTION_LIST *funcs; \
        bound = fixed_closures[fixed_index]; \
        return_val_if_fail (bound != NULL, CKR_GENERAL_ERROR); \
        wrapper = (Wrapper *) bound; \
        funcs = &wrapper->virt->funcs; \
        return funcs->C_GetSessionInfo (funcs, session, info); \
} \
\
static CK_RV \
fixed ## fixed_index ## _C_GetOperationState (CK_SESSION_HANDLE session, \
					      CK_BYTE_PTR operation_state, \
					      CK_ULONG_PTR operation_state_len) \
{ \
        CK_FUNCTION_LIST *bound; \
        Wrapper *wrapper; \
        CK_X_FUNCTION_LIST *funcs; \
        bound = fixed_closures[fixed_index]; \
        return_val_if_fail (bound != NULL, CKR_GENERAL_ERROR); \
        wrapper = (Wrapper *) bound; \
        funcs = &wrapper->virt->funcs; \
        return funcs->C_GetOperationState (funcs, session, operation_state, operation_state_len); \
} \
\
static CK_RV \
fixed ## fixed_index ## _C_SetOperationState (CK_SESSION_HANDLE session, \
					      CK_BYTE_PTR operation_state, \
					      CK_ULONG operation_state_len, \
					      CK_OBJECT_HANDLE encryption_key, \
					      CK_OBJECT_HANDLE authentiation_key) \
{ \
        CK_FUNCTION_LIST *bound; \
        Wrapper *wrapper; \
        CK_X_FUNCTION_LIST *funcs; \
        bound = fixed_closures[fixed_index]; \
        return_val_if_fail (bound != NULL, CKR_GENERAL_ERROR); \
        wrapper = (Wrapper *) bound; \
        funcs = &wrapper->virt->funcs; \
        return funcs->C_SetOperationState (funcs, session, operation_state, operation_state_len, encryption_key, authentiation_key); \
} \
\
static CK_RV \
fixed ## fixed_index ## _C_Login (CK_SESSION_HANDLE session, \
				  CK_USER_TYPE user_type, \
				  CK_BYTE_PTR pin, \
				  CK_ULONG pin_len) \
{ \
        CK_FUNCTION_LIST *bound; \
        Wrapper *wrapper; \
        CK_X_FUNCTION_LIST *funcs; \
        bound = fixed_closures[fixed_index]; \
        return_val_if_fail (bound != NULL, CKR_GENERAL_ERROR); \
        wrapper = (Wrapper *) bound; \
        funcs = &wrapper->virt->funcs; \
        return funcs->C_Login (funcs, session, user_type, pin, pin_len); \
} \
\
static CK_RV \
fixed ## fixed_index ## _C_Logout (CK_SESSION_HANDLE session) \
{ \
        CK_FUNCTION_LIST *bound; \
        Wrapper *wrapper; \
        CK_X_FUNCTION_LIST *funcs; \
        bound = fixed_closures[fixed_index]; \
        return_val_if_fail (bound != NULL, CKR_GENERAL_ERROR); \
        wrapper = (Wrapper *) bound; \
        funcs = &wrapper->virt->funcs; \
        return funcs->C_Logout (funcs, session); \
} \
\
static CK_RV \
fixed ## fixed_index ## _C_CreateObject (CK_SESSION_HANDLE session, \
					 CK_ATTRIBUTE_PTR templ, \
					 CK_ULONG count, \
					 CK_OBJECT_HANDLE_PTR object) \
{ \
        CK_FUNCTION_LIST *bound; \
        Wrapper *wrapper; \
        CK_X_FUNCTION_LIST *funcs; \
        bound = fixed_closures[fixed_index]; \
        return_val_if_fail (bound != NULL, CKR_GENERAL_ERROR); \
        wrapper = (Wrapper *) bound; \
        funcs = &wrapper->virt->funcs; \
        return funcs->C_CreateObject (funcs, session, templ, count, object); \
} \
\
static CK_RV \
fixed ## fixed_index ## _C_CopyObject (CK_SESSION_HANDLE session, \
				       CK_OBJECT_HANDLE object, \
				       CK_ATTRIBUTE_PTR templ, \
				       CK_ULONG count, \
				       CK_OBJECT_HANDLE_PTR new_object) \
{ \
        CK_FUNCTION_LIST *bound; \
        Wrapper *wrapper; \
        CK_X_FUNCTION_LIST *funcs; \
        bound = fixed_closures[fixed_index]; \
        return_val_if_fail (bound != NULL, CKR_GENERAL_ERROR); \
        wrapper = (Wrapper *) bound; \
        funcs = &wrapper->virt->funcs; \
        return funcs->C_CopyObject (funcs, session, object, templ, count, new_object); \
} \
\
static CK_RV \
fixed ## fixed_index ## _C_DestroyObject (CK_SESSION_HANDLE session, \
					  CK_OBJECT_HANDLE object) \
{ \
        CK_FUNCTION_LIST *bound; \
        Wrapper *wrapper; \
        CK_X_FUNCTION_LIST *funcs; \
        bound = fixed_closures[fixed_index]; \
        return_val_if_fail (bound != NULL, CKR_GENERAL_ERROR); \
        wrapper = (Wrapper *) bound; \
        funcs = &wrapper->virt->funcs; \
        return funcs->C_DestroyObject (funcs, session, object); \
} \
\
static CK_RV \
fixed ## fixed_index ## _C_GetObjectSize (CK_SESSION_HANDLE session, \
					  CK_OBJECT_HANDLE object, \
					  CK_ULONG_PTR size) \
{ \
        CK_FUNCTION_LIST *bound; \
        Wrapper *wrapper; \
        CK_X_FUNCTION_LIST *funcs; \
        bound = fixed_closures[fixed_index]; \
        return_val_if_fail (bound != NULL, CKR_GENERAL_ERROR); \
        wrapper = (Wrapper *) bound; \
        funcs = &wrapper->virt->funcs; \
        return funcs->C_GetObjectSize (funcs, session, object, size); \
} \
\
static CK_RV \
fixed ## fixed_index ## _C_GetAttributeValue (CK_SESSION_HANDLE session, \
					      CK_OBJECT_HANDLE object, \
					      CK_ATTRIBUTE_PTR templ, \
					      CK_ULONG count) \
{ \
        CK_FUNCTION_LIST *bound; \
        Wrapper *wrapper; \
        CK_X_FUNCTION_LIST *funcs; \
        bound = fixed_closures[fixed_index]; \
        return_val_if_fail (bound != NULL, CKR_GENERAL_ERROR); \
        wrapper = (Wrapper *) bound; \
        funcs = &wrapper->virt->funcs; \
        return funcs->C_GetAttributeValue (funcs, session, object, templ, count); \
} \
\
static CK_RV \
fixed ## fixed_index ## _C_SetAttributeValue (CK_SESSION_HANDLE session, \
					      CK_OBJECT_HANDLE object, \
					      CK_ATTRIBUTE_PTR templ, \
					      CK_ULONG count) \
{ \
        CK_FUNCTION_LIST *bound; \
        Wrapper *wrapper; \
        CK_X_FUNCTION_LIST *funcs; \
        bound = fixed_closures[fixed_index]; \
        return_val_if_fail (bound != NULL, CKR_GENERAL_ERROR); \
        wrapper = (Wrapper *) bound; \
        funcs = &wrapper->virt->funcs; \
        return funcs->C_SetAttributeValue (funcs, session, object, templ, count); \
} \
\
static CK_RV \
fixed ## fixed_index ## _C_FindObjectsInit (CK_SESSION_HANDLE session, \
					    CK_ATTRIBUTE_PTR templ, \
					    CK_ULONG count) \
{ \
        CK_FUNCTION_LIST *bound; \
        Wrapper *wrapper; \
        CK_X_FUNCTION_LIST *funcs; \
        bound = fixed_closures[fixed_index]; \
        return_val_if_fail (bound != NULL, CKR_GENERAL_ERROR); \
        wrapper = (Wrapper *) bound; \
        funcs = &wrapper->virt->funcs; \
        return funcs->C_FindObjectsInit (funcs, session, templ, count); \
} \
\
static CK_RV \
fixed ## fixed_index ## _C_FindObjects (CK_SESSION_HANDLE session, \
					CK_OBJECT_HANDLE_PTR object, \
					CK_ULONG max_object_count, \
					CK_ULONG_PTR object_count) \
{ \
        CK_FUNCTION_LIST *bound; \
        Wrapper *wrapper; \
        CK_X_FUNCTION_LIST *funcs; \
        bound = fixed_closures[fixed_index]; \
        return_val_if_fail (bound != NULL, CKR_GENERAL_ERROR); \
        wrapper = (Wrapper *) bound; \
        funcs = &wrapper->virt->funcs; \
        return funcs->C_FindObjects (funcs, session, object, max_object_count, object_count); \
} \
\
static CK_RV \
fixed ## fixed_index ## _C_FindObjectsFinal (CK_SESSION_HANDLE session) \
{ \
        CK_FUNCTION_LIST *bound; \
        Wrapper *wrapper; \
        CK_X_FUNCTION_LIST *funcs; \
        bound = fixed_closures[fixed_index]; \
        return_val_if_fail (bound != NULL, CKR_GENERAL_ERROR); \
        wrapper = (Wrapper *) bound; \
        funcs = &wrapper->virt->funcs; \
        return funcs->C_FindObjectsFinal (funcs, session); \
} \
\
static CK_RV \
fixed ## fixed_index ## _C_EncryptInit (CK_SESSION_HANDLE session, \
					CK_MECHANISM_PTR mechanism, \
					CK_OBJECT_HANDLE key) \
{ \
        CK_FUNCTION_LIST *bound; \
        Wrapper *wrapper; \
        CK_X_FUNCTION_LIST *funcs; \
        bound = fixed_closures[fixed_index]; \
        return_val_if_fail (bound != NULL, CKR_GENERAL_ERROR); \
        wrapper = (Wrapper *) bound; \
        funcs = &wrapper->virt->funcs; \
        return funcs->C_EncryptInit (funcs, session, mechanism, key); \
} \
\
static CK_RV \
fixed ## fixed_index ## _C_Encrypt (CK_SESSION_HANDLE session, \
				    CK_BYTE_PTR data, \
				    CK_ULONG data_len, \
				    CK_BYTE_PTR encrypted_data, \
				    CK_ULONG_PTR encrypted_data_len) \
{ \
        CK_FUNCTION_LIST *bound; \
        Wrapper *wrapper; \
        CK_X_FUNCTION_LIST *funcs; \
        bound = fixed_closures[fixed_index]; \
        return_val_if_fail (bound != NULL, CKR_GENERAL_ERROR); \
        wrapper = (Wrapper *) bound; \
        funcs = &wrapper->virt->funcs; \
        return funcs->C_Encrypt (funcs, session, data, data_len, encrypted_data, encrypted_data_len); \
} \
\
static CK_RV \
fixed ## fixed_index ## _C_EncryptUpdate (CK_SESSION_HANDLE session, \
					  CK_BYTE_PTR part, \
					  CK_ULONG part_len, \
					  CK_BYTE_PTR encrypted_part, \
					  CK_ULONG_PTR encrypted_part_len) \
{ \
        CK_FUNCTION_LIST *bound; \
        Wrapper *wrapper; \
        CK_X_FUNCTION_LIST *funcs; \
        bound = fixed_closures[fixed_index]; \
        return_val_if_fail (bound != NULL, CKR_GENERAL_ERROR); \
        wrapper = (Wrapper *) bound; \
        funcs = &wrapper->virt->funcs; \
        return funcs->C_EncryptUpdate (funcs, session, part, part_len, encrypted_part, encrypted_part_len); \
} \
\
static CK_RV \
fixed ## fixed_index ## _C_EncryptFinal (CK_SESSION_HANDLE session, \
					 CK_BYTE_PTR last_encrypted_part, \
					 CK_ULONG_PTR last_encrypted_part_len) \
{ \
        CK_FUNCTION_LIST *bound; \
        Wrapper *wrapper; \
        CK_X_FUNCTION_LIST *funcs; \
        bound = fixed_closures[fixed_index]; \
        return_val_if_fail (bound != NULL, CKR_GENERAL_ERROR); \
        wrapper = (Wrapper *) bound; \
        funcs = &wrapper->virt->funcs; \
        return funcs->C_EncryptFinal (funcs, session, last_encrypted_part, last_encrypted_part_len); \
} \
\
static CK_RV \
fixed ## fixed_index ## _C_DecryptInit (CK_SESSION_HANDLE session, \
					CK_MECHANISM_PTR mechanism, \
					CK_OBJECT_HANDLE key) \
{ \
        CK_FUNCTION_LIST *bound; \
        Wrapper *wrapper; \
        CK_X_FUNCTION_LIST *funcs; \
        bound = fixed_closures[fixed_index]; \
        return_val_if_fail (bound != NULL, CKR_GENERAL_ERROR); \
        wrapper = (Wrapper *) bound; \
        funcs = &wrapper->virt->funcs; \
        return funcs->C_DecryptInit (funcs, session, mechanism, key); \
} \
\
static CK_RV \
fixed ## fixed_index ## _C_Decrypt (CK_SESSION_HANDLE session, \
				    CK_BYTE_PTR encrypted_data, \
				    CK_ULONG encrypted_data_len, \
				    CK_BYTE_PTR data, \
				    CK_ULONG_PTR data_len) \
{ \
        CK_FUNCTION_LIST *bound; \
        Wrapper *wrapper; \
        CK_X_FUNCTION_LIST *funcs; \
        bound = fixed_closures[fixed_index]; \
        return_val_if_fail (bound != NULL, CKR_GENERAL_ERROR); \
        wrapper = (Wrapper *) bound; \
        funcs = &wrapper->virt->funcs; \
        return funcs->C_Decrypt (funcs, session, encrypted_data, encrypted_data_len, data, data_len); \
} \
\
static CK_RV \
fixed ## fixed_index ## _C_DecryptUpdate (CK_SESSION_HANDLE session, \
					  CK_BYTE_PTR encrypted_part, \
					  CK_ULONG encrypted_part_len, \
					  CK_BYTE_PTR part, \
					  CK_ULONG_PTR part_len) \
{ \
        CK_FUNCTION_LIST *bound; \
        Wrapper *wrapper; \
        CK_X_FUNCTION_LIST *funcs; \
        bound = fixed_closures[fixed_index]; \
        return_val_if_fail (bound != NULL, CKR_GENERAL_ERROR); \
        wrapper = (Wrapper *) bound; \
        funcs = &wrapper->virt->funcs; \
        return funcs->C_DecryptUpdate (funcs, session, encrypted_part, encrypted_part_len, part, part_len); \
} \
\
static CK_RV \
fixed ## fixed_index ## _C_DecryptFinal (CK_SESSION_HANDLE session, \
					 CK_BYTE_PTR last_part, \
					 CK_ULONG_PTR last_part_len) \
{ \
        CK_FUNCTION_LIST *bound; \
        Wrapper *wrapper; \
        CK_X_FUNCTION_LIST *funcs; \
        bound = fixed_closures[fixed_index]; \
        return_val_if_fail (bound != NULL, CKR_GENERAL_ERROR); \
        wrapper = (Wrapper *) bound; \
        funcs = &wrapper->virt->funcs; \
        return funcs->C_DecryptFinal (funcs, session, last_part, last_part_len); \
} \
\
static CK_RV \
fixed ## fixed_index ## _C_DigestInit (CK_SESSION_HANDLE session, \
				       CK_MECHANISM_PTR mechanism) \
{ \
        CK_FUNCTION_LIST *bound; \
        Wrapper *wrapper; \
        CK_X_FUNCTION_LIST *funcs; \
        bound = fixed_closures[fixed_index]; \
        return_val_if_fail (bound != NULL, CKR_GENERAL_ERROR); \
        wrapper = (Wrapper *) bound; \
        funcs = &wrapper->virt->funcs; \
        return funcs->C_DigestInit (funcs, session, mechanism); \
} \
\
static CK_RV \
fixed ## fixed_index ## _C_Digest (CK_SESSION_HANDLE session, \
				   CK_BYTE_PTR data, \
				   CK_ULONG data_len, \
				   CK_BYTE_PTR digest, \
				   CK_ULONG_PTR digest_len) \
{ \
        CK_FUNCTION_LIST *bound; \
        Wrapper *wrapper; \
        CK_X_FUNCTION_LIST *funcs; \
        bound = fixed_closures[fixed_index]; \
        return_val_if_fail (bound != NULL, CKR_GENERAL_ERROR); \
        wrapper = (Wrapper *) bound; \
        funcs = &wrapper->virt->funcs; \
        return funcs->C_Digest (funcs, session, data, data_len, digest, digest_len); \
} \
\
static CK_RV \
fixed ## fixed_index ## _C_DigestUpdate (CK_SESSION_HANDLE session, \
					 CK_BYTE_PTR part, \
					 CK_ULONG part_len) \
{ \
        CK_FUNCTION_LIST *bound; \
        Wrapper *wrapper; \
        CK_X_FUNCTION_LIST *funcs; \
        bound = fixed_closures[fixed_index]; \
        return_val_if_fail (bound != NULL, CKR_GENERAL_ERROR); \
        wrapper = (Wrapper *) bound; \
        funcs = &wrapper->virt->funcs; \
        return funcs->C_DigestUpdate (funcs, session, part, part_len); \
} \
\
static CK_RV \
fixed ## fixed_index ## _C_DigestKey (CK_SESSION_HANDLE session, \
				      CK_OBJECT_HANDLE key) \
{ \
        CK_FUNCTION_LIST *bound; \
        Wrapper *wrapper; \
        CK_X_FUNCTION_LIST *funcs; \
        bound = fixed_closures[fixed_index]; \
        return_val_if_fail (bound != NULL, CKR_GENERAL_ERROR); \
        wrapper = (Wrapper *) bound; \
        funcs = &wrapper->virt->funcs; \
        return funcs->C_DigestKey (funcs, session, key); \
} \
\
static CK_RV \
fixed ## fixed_index ## _C_DigestFinal (CK_SESSION_HANDLE session, \
					CK_BYTE_PTR digest, \
					CK_ULONG_PTR digest_len) \
{ \
        CK_FUNCTION_LIST *bound; \
        Wrapper *wrapper; \
        CK_X_FUNCTION_LIST *funcs; \
        bound = fixed_closures[fixed_index]; \
        return_val_if_fail (bound != NULL, CKR_GENERAL_ERROR); \
        wrapper = (Wrapper *) bound; \
        funcs = &wrapper->virt->funcs; \
        return funcs->C_DigestFinal (funcs, session, digest, digest_len); \
} \
\
static CK_RV \
fixed ## fixed_index ## _C_SignInit (CK_SESSION_HANDLE session, \
				     CK_MECHANISM_PTR mechanism, \
				     CK_OBJECT_HANDLE key) \
{ \
        CK_FUNCTION_LIST *bound; \
        Wrapper *wrapper; \
        CK_X_FUNCTION_LIST *funcs; \
        bound = fixed_closures[fixed_index]; \
        return_val_if_fail (bound != NULL, CKR_GENERAL_ERROR); \
        wrapper = (Wrapper *) bound; \
        funcs = &wrapper->virt->funcs; \
        return funcs->C_SignInit (funcs, session, mechanism, key); \
} \
\
static CK_RV \
fixed ## fixed_index ## _C_Sign (CK_SESSION_HANDLE session, \
				 CK_BYTE_PTR data, \
				 CK_ULONG data_len, \
				 CK_BYTE_PTR signature, \
				 CK_ULONG_PTR signature_len) \
{ \
        CK_FUNCTION_LIST *bound; \
        Wrapper *wrapper; \
        CK_X_FUNCTION_LIST *funcs; \
        bound = fixed_closures[fixed_index]; \
        return_val_if_fail (bound != NULL, CKR_GENERAL_ERROR); \
        wrapper = (Wrapper *) bound; \
        funcs = &wrapper->virt->funcs; \
        return funcs->C_Sign (funcs, session, data, data_len, signature, signature_len); \
} \
\
static CK_RV \
fixed ## fixed_index ## _C_SignUpdate (CK_SESSION_HANDLE session, \
				       CK_BYTE_PTR part, \
				       CK_ULONG part_len) \
{ \
        CK_FUNCTION_LIST *bound; \
        Wrapper *wrapper; \
        CK_X_FUNCTION_LIST *funcs; \
        bound = fixed_closures[fixed_index]; \
        return_val_if_fail (bound != NULL, CKR_GENERAL_ERROR); \
        wrapper = (Wrapper *) bound; \
        funcs = &wrapper->virt->funcs; \
        return funcs->C_SignUpdate (funcs, session, part, part_len); \
} \
\
static CK_RV \
fixed ## fixed_index ## _C_SignFinal (CK_SESSION_HANDLE session, \
				      CK_BYTE_PTR signature, \
				      CK_ULONG_PTR signature_len) \
{ \
        CK_FUNCTION_LIST *bound; \
        Wrapper *wrapper; \
        CK_X_FUNCTION_LIST *funcs; \
        bound = fixed_closures[fixed_index]; \
        return_val_if_fail (bound != NULL, CKR_GENERAL_ERROR); \
        wrapper = (Wrapper *) bound; \
        funcs = &wrapper->virt->funcs; \
        return funcs->C_SignFinal (funcs, session, signature, signature_len); \
} \
\
static CK_RV \
fixed ## fixed_index ## _C_SignRecoverInit (CK_SESSION_HANDLE session, \
					    CK_MECHANISM_PTR mechanism, \
					    CK_OBJECT_HANDLE key) \
{ \
        CK_FUNCTION_LIST *bound; \
        Wrapper *wrapper; \
        CK_X_FUNCTION_LIST *funcs; \
        bound = fixed_closures[fixed_index]; \
        return_val_if_fail (bound != NULL, CKR_GENERAL_ERROR); \
        wrapper = (Wrapper *) bound; \
        funcs = &wrapper->virt->funcs; \
        return funcs->C_SignRecoverInit (funcs, session, mechanism, key); \
} \
\
static CK_RV \
fixed ## fixed_index ## _C_SignRecover (CK_SESSION_HANDLE session, \
					CK_BYTE_PTR data, \
					CK_ULONG data_len, \
					CK_BYTE_PTR signature, \
					CK_ULONG_PTR signature_len) \
{ \
        CK_FUNCTION_LIST *bound; \
        Wrapper *wrapper; \
        CK_X_FUNCTION_LIST *funcs; \
        bound = fixed_closures[fixed_index]; \
        return_val_if_fail (bound != NULL, CKR_GENERAL_ERROR); \
        wrapper = (Wrapper *) bound; \
        funcs = &wrapper->virt->funcs; \
        return funcs->C_SignRecover (funcs, session, data, data_len, signature, signature_len); \
} \
\
static CK_RV \
fixed ## fixed_index ## _C_VerifyInit (CK_SESSION_HANDLE session, \
				       CK_MECHANISM_PTR mechanism, \
				       CK_OBJECT_HANDLE key) \
{ \
        CK_FUNCTION_LIST *bound; \
        Wrapper *wrapper; \
        CK_X_FUNCTION_LIST *funcs; \
        bound = fixed_closures[fixed_index]; \
        return_val_if_fail (bound != NULL, CKR_GENERAL_ERROR); \
        wrapper = (Wrapper *) bound; \
        funcs = &wrapper->virt->funcs; \
        return funcs->C_VerifyInit (funcs, session, mechanism, key); \
} \
\
static CK_RV \
fixed ## fixed_index ## _C_Verify (CK_SESSION_HANDLE session, \
				   CK_BYTE_PTR data, \
				   CK_ULONG data_len, \
				   CK_BYTE_PTR signature, \
				   CK_ULONG signature_len) \
{ \
        CK_FUNCTION_LIST *bound; \
        Wrapper *wrapper; \
        CK_X_FUNCTION_LIST *funcs; \
        bound = fixed_closures[fixed_index]; \
        return_val_if_fail (bound != NULL, CKR_GENERAL_ERROR); \
        wrapper = (Wrapper *) bound; \
        funcs = &wrapper->virt->funcs; \
        return funcs->C_Verify (funcs, session, data, data_len, signature, signature_len); \
} \
\
static CK_RV \
fixed ## fixed_index ## _C_VerifyUpdate (CK_SESSION_HANDLE session, \
					 CK_BYTE_PTR part, \
					 CK_ULONG part_len) \
{ \
        CK_FUNCTION_LIST *bound; \
        Wrapper *wrapper; \
        CK_X_FUNCTION_LIST *funcs; \
        bound = fixed_closures[fixed_index]; \
        return_val_if_fail (bound != NULL, CKR_GENERAL_ERROR); \
        wrapper = (Wrapper *) bound; \
        funcs = &wrapper->virt->funcs; \
        return funcs->C_VerifyUpdate (funcs, session, part, part_len); \
} \
\
static CK_RV \
fixed ## fixed_index ## _C_VerifyFinal (CK_SESSION_HANDLE session, \
					CK_BYTE_PTR signature, \
					CK_ULONG signature_len) \
{ \
        CK_FUNCTION_LIST *bound; \
        Wrapper *wrapper; \
        CK_X_FUNCTION_LIST *funcs; \
        bound = fixed_closures[fixed_index]; \
        return_val_if_fail (bound != NULL, CKR_GENERAL_ERROR); \
        wrapper = (Wrapper *) bound; \
        funcs = &wrapper->virt->funcs; \
        return funcs->C_VerifyFinal (funcs, session, signature, signature_len); \
} \
\
static CK_RV \
fixed ## fixed_index ## _C_VerifyRecoverInit (CK_SESSION_HANDLE session, \
					      CK_MECHANISM_PTR mechanism, \
					      CK_OBJECT_HANDLE key) \
{ \
        CK_FUNCTION_LIST *bound; \
        Wrapper *wrapper; \
        CK_X_FUNCTION_LIST *funcs; \
        bound = fixed_closures[fixed_index]; \
        return_val_if_fail (bound != NULL, CKR_GENERAL_ERROR); \
        wrapper = (Wrapper *) bound; \
        funcs = &wrapper->virt->funcs; \
        return funcs->C_VerifyRecoverInit (funcs, session, mechanism, key); \
} \
\
static CK_RV \
fixed ## fixed_index ## _C_VerifyRecover (CK_SESSION_HANDLE session, \
					  CK_BYTE_PTR signature, \
					  CK_ULONG signature_len, \
					  CK_BYTE_PTR data, \
					  CK_ULONG_PTR data_len) \
{ \
        CK_FUNCTION_LIST *bound; \
        Wrapper *wrapper; \
        CK_X_FUNCTION_LIST *funcs; \
        bound = fixed_closures[fixed_index]; \
        return_val_if_fail (bound != NULL, CKR_GENERAL_ERROR); \
        wrapper = (Wrapper *) bound; \
        funcs = &wrapper->virt->funcs; \
        return funcs->C_VerifyRecover (funcs, session, signature, signature_len, data, data_len); \
} \
\
static CK_RV \
fixed ## fixed_index ## _C_DigestEncryptUpdate (CK_SESSION_HANDLE session, \
						CK_BYTE_PTR part, \
						CK_ULONG part_len, \
						CK_BYTE_PTR encrypted_part, \
						CK_ULONG_PTR encrypted_part_len) \
{ \
        CK_FUNCTION_LIST *bound; \
        Wrapper *wrapper; \
        CK_X_FUNCTION_LIST *funcs; \
        bound = fixed_closures[fixed_index]; \
        return_val_if_fail (bound != NULL, CKR_GENERAL_ERROR); \
        wrapper = (Wrapper *) bound; \
        funcs = &wrapper->virt->funcs; \
        return funcs->C_DigestEncryptUpdate (funcs, session, part, part_len, encrypted_part, encrypted_part_len); \
} \
\
static CK_RV \
fixed ## fixed_index ## _C_DecryptDigestUpdate (CK_SESSION_HANDLE session, \
						CK_BYTE_PTR encrypted_part, \
						CK_ULONG encrypted_part_len, \
						CK_BYTE_PTR part, \
						CK_ULONG_PTR part_len) \
{ \
        CK_FUNCTION_LIST *bound; \
        Wrapper *wrapper; \
        CK_X_FUNCTION_LIST *funcs; \
        bound = fixed_closures[fixed_index]; \
        return_val_if_fail (bound != NULL, CKR_GENERAL_ERROR); \
        wrapper = (Wrapper *) bound; \
        funcs = &wrapper->virt->funcs; \
        return funcs->C_DecryptDigestUpdate (funcs, session, encrypted_part, encrypted_part_len, part, part_len); \
} \
\
static CK_RV \
fixed ## fixed_index ## _C_SignEncryptUpdate (CK_SESSION_HANDLE session, \
					      CK_BYTE_PTR part, \
					      CK_ULONG part_len, \
					      CK_BYTE_PTR encrypted_part, \
					      CK_ULONG_PTR encrypted_part_len) \
{ \
        CK_FUNCTION_LIST *bound; \
        Wrapper *wrapper; \
        CK_X_FUNCTION_LIST *funcs; \
        bound = fixed_closures[fixed_index]; \
        return_val_if_fail (bound != NULL, CKR_GENERAL_ERROR); \
        wrapper = (Wrapper *) bound; \
        funcs = &wrapper->virt->funcs; \
        return funcs->C_SignEncryptUpdate (funcs, session, part, part_len, encrypted_part, encrypted_part_len); \
} \
\
static CK_RV \
fixed ## fixed_index ## _C_DecryptVerifyUpdate (CK_SESSION_HANDLE session, \
						CK_BYTE_PTR encrypted_part, \
						CK_ULONG encrypted_part_len, \
						CK_BYTE_PTR part, \
						CK_ULONG_PTR part_len) \
{ \
        CK_FUNCTION_LIST *bound; \
        Wrapper *wrapper; \
        CK_X_FUNCTION_LIST *funcs; \
        bound = fixed_closures[fixed_index]; \
        return_val_if_fail (bound != NULL, CKR_GENERAL_ERROR); \
        wrapper = (Wrapper *) bound; \
        funcs = &wrapper->virt->funcs; \
        return funcs->C_DecryptVerifyUpdate (funcs, session, encrypted_part, encrypted_part_len, part, part_len); \
} \
\
static CK_RV \
fixed ## fixed_index ## _C_GenerateKey (CK_SESSION_HANDLE session, \
					CK_MECHANISM_PTR mechanism, \
					CK_ATTRIBUTE_PTR templ, \
					CK_ULONG count, \
					CK_OBJECT_HANDLE_PTR key) \
{ \
        CK_FUNCTION_LIST *bound; \
        Wrapper *wrapper; \
        CK_X_FUNCTION_LIST *funcs; \
        bound = fixed_closures[fixed_index]; \
        return_val_if_fail (bound != NULL, CKR_GENERAL_ERROR); \
        wrapper = (Wrapper *) bound; \
        funcs = &wrapper->virt->funcs; \
        return funcs->C_GenerateKey (funcs, session, mechanism, templ, count, key); \
} \
\
static CK_RV \
fixed ## fixed_index ## _C_GenerateKeyPair (CK_SESSION_HANDLE session, \
					    CK_MECHANISM_PTR mechanism, \
					    CK_ATTRIBUTE_PTR public_key_template, \
					    CK_ULONG public_key_attribute_count, \
					    CK_ATTRIBUTE_PTR private_key_template, \
					    CK_ULONG private_key_attribute_count, \
					    CK_OBJECT_HANDLE_PTR public_key, \
					    CK_OBJECT_HANDLE_PTR private_key) \
{ \
        CK_FUNCTION_LIST *bound; \
        Wrapper *wrapper; \
        CK_X_FUNCTION_LIST *funcs; \
        bound = fixed_closures[fixed_index]; \
        return_val_if_fail (bound != NULL, CKR_GENERAL_ERROR); \
        wrapper = (Wrapper *) bound; \
        funcs = &wrapper->virt->funcs; \
        return funcs->C_GenerateKeyPair (funcs, session, mechanism, public_key_template, public_key_attribute_count, private_key_template, private_key_attribute_count, public_key, private_key); \
} \
\
static CK_RV \
fixed ## fixed_index ## _C_WrapKey (CK_SESSION_HANDLE session, \
				    CK_MECHANISM_PTR mechanism, \
				    CK_OBJECT_HANDLE wrapping_key, \
				    CK_OBJECT_HANDLE key, \
				    CK_BYTE_PTR wrapped_key, \
				    CK_ULONG_PTR wrapped_key_len) \
{ \
        CK_FUNCTION_LIST *bound; \
        Wrapper *wrapper; \
        CK_X_FUNCTION_LIST *funcs; \
        bound = fixed_closures[fixed_index]; \
        return_val_if_fail (bound != NULL, CKR_GENERAL_ERROR); \
        wrapper = (Wrapper *) bound; \
        funcs = &wrapper->virt->funcs; \
        return funcs->C_WrapKey (funcs, session, mechanism, wrapping_key, key, wrapped_key, wrapped_key_len); \
} \
\
static CK_RV \
fixed ## fixed_index ## _C_UnwrapKey (CK_SESSION_HANDLE session, \
				      CK_MECHANISM_PTR mechanism, \
				      CK_OBJECT_HANDLE unwrapping_key, \
				      CK_BYTE_PTR wrapped_key, \
				      CK_ULONG wrapped_key_len, \
				      CK_ATTRIBUTE_PTR templ, \
				      CK_ULONG attribute_count, \
				      CK_OBJECT_HANDLE_PTR key) \
{ \
        CK_FUNCTION_LIST *bound; \
        Wrapper *wrapper; \
        CK_X_FUNCTION_LIST *funcs; \
        bound = fixed_closures[fixed_index]; \
        return_val_if_fail (bound != NULL, CKR_GENERAL_ERROR); \
        wrapper = (Wrapper *) bound; \
        funcs = &wrapper->virt->funcs; \
        return funcs->C_UnwrapKey (funcs, session, mechanism, unwrapping_key, wrapped_key, wrapped_key_len, templ, attribute_count, key); \
} \
\
static CK_RV \
fixed ## fixed_index ## _C_DeriveKey (CK_SESSION_HANDLE session, \
				      CK_MECHANISM_PTR mechanism, \
				      CK_OBJECT_HANDLE base_key, \
				      CK_ATTRIBUTE_PTR templ, \
				      CK_ULONG attribute_count, \
				      CK_OBJECT_HANDLE_PTR key) \
{ \
        CK_FUNCTION_LIST *bound; \
        Wrapper *wrapper; \
        CK_X_FUNCTION_LIST *funcs; \
        bound = fixed_closures[fixed_index]; \
        return_val_if_fail (bound != NULL, CKR_GENERAL_ERROR); \
        wrapper = (Wrapper *) bound; \
        funcs = &wrapper->virt->funcs; \
        return funcs->C_DeriveKey (funcs, session, mechanism, base_key, templ, attribute_count, key); \
} \
\
static CK_RV \
fixed ## fixed_index ## _C_SeedRandom (CK_SESSION_HANDLE session, \
				       CK_BYTE_PTR seed, \
				       CK_ULONG seed_len) \
{ \
        CK_FUNCTION_LIST *bound; \
        Wrapper *wrapper; \
        CK_X_FUNCTION_LIST *funcs; \
        bound = fixed_closures[fixed_index]; \
        return_val_if_fail (bound != NULL, CKR_GENERAL_ERROR); \
        wrapper = (Wrapper *) bound; \
        funcs = &wrapper->virt->funcs; \
        return funcs->C_SeedRandom (funcs, session, seed, seed_len); \
} \
\
static CK_RV \
fixed ## fixed_index ## _C_GenerateRandom (CK_SESSION_HANDLE session, \
					   CK_BYTE_PTR random_data, \
					   CK_ULONG random_len) \
{ \
        CK_FUNCTION_LIST *bound; \
        Wrapper *wrapper; \
        CK_X_FUNCTION_LIST *funcs; \
        bound = fixed_closures[fixed_index]; \
        return_val_if_fail (bound != NULL, CKR_GENERAL_ERROR); \
        wrapper = (Wrapper *) bound; \
        funcs = &wrapper->virt->funcs; \
        return funcs->C_GenerateRandom (funcs, session, random_data, random_len); \
} \
\
static CK_RV \
fixed ## fixed_index ## _C_WaitForSlotEvent (CK_FLAGS flags, \
					     CK_SLOT_ID_PTR slot, \
					     CK_VOID_PTR reserved) \
{ \
        CK_FUNCTION_LIST *bound; \
        Wrapper *wrapper; \
        CK_X_FUNCTION_LIST *funcs; \
        bound = fixed_closures[fixed_index]; \
        return_val_if_fail (bound != NULL, CKR_GENERAL_ERROR); \
        wrapper = (Wrapper *) bound; \
        funcs = &wrapper->virt->funcs; \
        return funcs->C_WaitForSlotEvent (funcs, flags, slot, reserved); \
} \
\
static CK_RV \
fixed ## fixed_index ## _C_GetFunctionList (CK_FUNCTION_LIST_PTR_PTR list);

#define P11_VIRTUAL_FIXED_GET_FUNCTION_LIST(fixed_index) \
static CK_RV \
fixed ## fixed_index ## _C_GetFunctionList (CK_FUNCTION_LIST_PTR_PTR list) \
{ \
        if (!list) \
                return CKR_ARGUMENTS_BAD; \
        *list = fixed_closures[fixed_index]; \
        return CKR_OK; \
}

#define P11_VIRTUAL_FIXED_INITIALIZER(fixed_index) \
{ \
        { CRYPTOKI_VERSION_MAJOR, CRYPTOKI_VERSION_MINOR },  /* version */ \
	fixed ## fixed_index ## _C_Initialize, \
	fixed ## fixed_index ## _C_Finalize, \
	fixed ## fixed_index ## _C_GetInfo, \
	fixed ## fixed_index ## _C_GetFunctionList, \
	fixed ## fixed_index ## _C_GetSlotList, \
	fixed ## fixed_index ## _C_GetSlotInfo, \
	fixed ## fixed_index ## _C_GetTokenInfo, \
	fixed ## fixed_index ## _C_GetMechanismList, \
	fixed ## fixed_index ## _C_GetMechanismInfo, \
	fixed ## fixed_index ## _C_InitToken, \
	fixed ## fixed_index ## _C_InitPIN, \
	fixed ## fixed_index ## _C_SetPIN, \
	fixed ## fixed_index ## _C_OpenSession, \
	fixed ## fixed_index ## _C_CloseSession, \
	fixed ## fixed_index ## _C_CloseAllSessions, \
	fixed ## fixed_index ## _C_GetSessionInfo, \
	fixed ## fixed_index ## _C_GetOperationState, \
	fixed ## fixed_index ## _C_SetOperationState, \
	fixed ## fixed_index ## _C_Login, \
	fixed ## fixed_index ## _C_Logout, \
	fixed ## fixed_index ## _C_CreateObject, \
	fixed ## fixed_index ## _C_CopyObject, \
	fixed ## fixed_index ## _C_DestroyObject, \
	fixed ## fixed_index ## _C_GetObjectSize, \
	fixed ## fixed_index ## _C_GetAttributeValue, \
	fixed ## fixed_index ## _C_SetAttributeValue, \
	fixed ## fixed_index ## _C_FindObjectsInit, \
	fixed ## fixed_index ## _C_FindObjects, \
	fixed ## fixed_index ## _C_FindObjectsFinal, \
	fixed ## fixed_index ## _C_EncryptInit, \
	fixed ## fixed_index ## _C_Encrypt, \
	fixed ## fixed_index ## _C_EncryptUpdate, \
	fixed ## fixed_index ## _C_EncryptFinal, \
	fixed ## fixed_index ## _C_DecryptInit, \
	fixed ## fixed_index ## _C_Decrypt, \
	fixed ## fixed_index ## _C_DecryptUpdate, \
	fixed ## fixed_index ## _C_DecryptFinal, \
	fixed ## fixed_index ## _C_DigestInit, \
	fixed ## fixed_index ## _C_Digest, \
	fixed ## fixed_index ## _C_DigestUpdate, \
	fixed ## fixed_index ## _C_DigestKey, \
	fixed ## fixed_index ## _C_DigestFinal, \
	fixed ## fixed_index ## _C_SignInit, \
	fixed ## fixed_index ## _C_Sign, \
	fixed ## fixed_index ## _C_SignUpdate, \
	fixed ## fixed_index ## _C_SignFinal, \
	fixed ## fixed_index ## _C_SignRecoverInit, \
	fixed ## fixed_index ## _C_SignRecover, \
	fixed ## fixed_index ## _C_VerifyInit, \
	fixed ## fixed_index ## _C_Verify, \
	fixed ## fixed_index ## _C_VerifyUpdate, \
	fixed ## fixed_index ## _C_VerifyFinal, \
	fixed ## fixed_index ## _C_VerifyRecoverInit, \
	fixed ## fixed_index ## _C_VerifyRecover, \
	fixed ## fixed_index ## _C_DigestEncryptUpdate, \
	fixed ## fixed_index ## _C_DecryptDigestUpdate, \
	fixed ## fixed_index ## _C_SignEncryptUpdate, \
	fixed ## fixed_index ## _C_DecryptVerifyUpdate, \
	fixed ## fixed_index ## _C_GenerateKey, \
	fixed ## fixed_index ## _C_GenerateKeyPair, \
	fixed ## fixed_index ## _C_WrapKey, \
	fixed ## fixed_index ## _C_UnwrapKey, \
	fixed ## fixed_index ## _C_DeriveKey, \
	fixed ## fixed_index ## _C_SeedRandom, \
	fixed ## fixed_index ## _C_GenerateRandom, \
	short_C_GetFunctionStatus, \
	short_C_CancelFunction, \
	fixed ## fixed_index ## _C_WaitForSlotEvent \
}

#endif /* __P11_VIRTUAL_FIXED_H__ */
