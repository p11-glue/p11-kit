/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* mock-module.c - a mock PKCS#11 module

   Copyright (C) 2011 Collabora Ltd.

   The Gnome Keyring Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   The Gnome Keyring Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with the Gnome Library; see the file COPYING.LIB.  If not,
   write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.

   Author: Stef Walter <stefw@collabora.co.uk>
*/

#ifndef __MOCK_MODULE_H__
#define __MOCK_MODULE_H__

#include "pkcs11.h"

CK_FUNCTION_LIST    mock_module_no_slots;

void        mock_module_init                              (void);

CK_RV       mock_C_Initialize                             (CK_VOID_PTR init_args);

CK_RV       mock_C_Finalize                               (CK_VOID_PTR reserved);

CK_RV       mock_C_GetInfo                                (CK_INFO_PTR info);

CK_RV       mock_C_GetFunctionList                        (CK_FUNCTION_LIST_PTR_PTR list);

CK_RV       mock_C_GetSlotList__no_tokens                 (CK_BBOOL token_present,
                                                           CK_SLOT_ID_PTR slot_list,
                                                           CK_ULONG_PTR count);

CK_RV       mock_C_GetSlotInfo__invalid_slotid            (CK_SLOT_ID id,
                                                           CK_SLOT_INFO_PTR info);

CK_RV       mock_C_GetTokenInfo__invalid_slotid           (CK_SLOT_ID id,
                                                           CK_TOKEN_INFO_PTR info);

CK_RV       mock_C_GetMechanismList__invalid_slotid       (CK_SLOT_ID id,
                                                           CK_MECHANISM_TYPE_PTR mechanism_list,
                                                           CK_ULONG_PTR count);

CK_RV       mock_C_GetMechanismInfo__invalid_slotid       (CK_SLOT_ID id,
                                                           CK_MECHANISM_TYPE type,
                                                           CK_MECHANISM_INFO_PTR info);

CK_RV       mock_C_InitToken__invalid_slotid              (CK_SLOT_ID id,
                                                           CK_UTF8CHAR_PTR pin,
                                                           CK_ULONG pin_len,
                                                           CK_UTF8CHAR_PTR label);

CK_RV       mock_C_WaitForSlotEvent__no_event             (CK_FLAGS flags,
                                                           CK_SLOT_ID_PTR slot,
                                                           CK_VOID_PTR reserved);

CK_RV       mock_C_OpenSession__invalid_slotid            (CK_SLOT_ID id,
                                                           CK_FLAGS flags,
                                                           CK_VOID_PTR user_data,
                                                           CK_NOTIFY callback,
                                                           CK_SESSION_HANDLE_PTR session);

CK_RV       mock_C_CloseSession__invalid_handle           (CK_SESSION_HANDLE session);

CK_RV       mock_C_CloseAllSessions__invalid_slotid       (CK_SLOT_ID id);

CK_RV       mock_C_GetFunctionStatus__not_parallel        (CK_SESSION_HANDLE session);

CK_RV       mock_C_CancelFunction__not_parallel           (CK_SESSION_HANDLE session);

CK_RV       mock_C_GetSessionInfo__invalid_handle         (CK_SESSION_HANDLE session,
                                                           CK_SESSION_INFO_PTR info);

CK_RV       mock_C_InitPIN__invalid_handle                (CK_SESSION_HANDLE session,
                                                           CK_UTF8CHAR_PTR pin,
                                                           CK_ULONG pin_len);

CK_RV       mock_C_SetPIN__invalid_handle                 (CK_SESSION_HANDLE session,
                                                           CK_UTF8CHAR_PTR old_pin,
                                                           CK_ULONG old_pin_len,
                                                           CK_UTF8CHAR_PTR new_pin,
                                                           CK_ULONG new_pin_len);

CK_RV       mock_C_GetOperationState__invalid_handle      (CK_SESSION_HANDLE session,
                                                           CK_BYTE_PTR operation_state,
                                                           CK_ULONG_PTR operation_state_len);

CK_RV       mock_C_SetOperationState__invalid_handle      (CK_SESSION_HANDLE session,
                                                           CK_BYTE_PTR operation_state,
                                                           CK_ULONG operation_state_len,
                                                           CK_OBJECT_HANDLE encryption_key,
                                                           CK_OBJECT_HANDLE authentication_key);

CK_RV       mock_C_Login__invalid_handle                  (CK_SESSION_HANDLE session,
                                                           CK_USER_TYPE user_type,
                                                           CK_UTF8CHAR_PTR pin,
                                                           CK_ULONG pin_len);

CK_RV       mock_C_Logout__invalid_handle                 (CK_SESSION_HANDLE session);

CK_RV       mock_C_CreateObject__invalid_handle           (CK_SESSION_HANDLE session,
                                                           CK_ATTRIBUTE_PTR template,
                                                           CK_ULONG count,
                                                           CK_OBJECT_HANDLE_PTR new_object);

CK_RV       mock_C_CopyObject__invalid_handle             (CK_SESSION_HANDLE session,
                                                           CK_OBJECT_HANDLE object,
                                                           CK_ATTRIBUTE_PTR template,
                                                           CK_ULONG count,
                                                           CK_OBJECT_HANDLE_PTR new_object);

CK_RV       mock_C_DestroyObject__invalid_handle          (CK_SESSION_HANDLE session,
                                                           CK_OBJECT_HANDLE object);

CK_RV       mock_C_GetObjectSize__invalid_handle          (CK_SESSION_HANDLE session,
                                                           CK_OBJECT_HANDLE object,
                                                           CK_ULONG_PTR size);

CK_RV       mock_C_GetAttributeValue__invalid_handle      (CK_SESSION_HANDLE session,
                                                           CK_OBJECT_HANDLE object,
                                                           CK_ATTRIBUTE_PTR template,
                                                           CK_ULONG count);

CK_RV       mock_C_SetAttributeValue__invalid_handle      (CK_SESSION_HANDLE session,
                                                           CK_OBJECT_HANDLE object,
                                                           CK_ATTRIBUTE_PTR template,
                                                           CK_ULONG count);

CK_RV       mock_C_FindObjectsInit__invalid_handle        (CK_SESSION_HANDLE session,
                                                           CK_ATTRIBUTE_PTR template,
                                                           CK_ULONG count);

CK_RV       mock_C_FindObjects__invalid_handle            (CK_SESSION_HANDLE session,
                                                           CK_OBJECT_HANDLE_PTR objects,
                                                           CK_ULONG max_count,
                                                           CK_ULONG_PTR count);

CK_RV       mock_C_FindObjectsFinal__invalid_handle       (CK_SESSION_HANDLE session);

CK_RV       mock_C_EncryptInit__invalid_handle            (CK_SESSION_HANDLE session,
                                                           CK_MECHANISM_PTR mechanism,
                                                           CK_OBJECT_HANDLE key);

CK_RV       mock_C_Encrypt__invalid_handle                (CK_SESSION_HANDLE session,
                                                           CK_BYTE_PTR data,
                                                           CK_ULONG data_len,
                                                           CK_BYTE_PTR encrypted_data,
                                                           CK_ULONG_PTR encrypted_data_len);

CK_RV       mock_C_EncryptUpdate__invalid_handle          (CK_SESSION_HANDLE session,
                                                           CK_BYTE_PTR part,
                                                           CK_ULONG part_len,
                                                           CK_BYTE_PTR encrypted_part,
                                                           CK_ULONG_PTR encrypted_part_len);

CK_RV       mock_C_EncryptFinal__invalid_handle           (CK_SESSION_HANDLE session,
                                                           CK_BYTE_PTR last_part,
                                                           CK_ULONG_PTR last_part_len);

CK_RV       mock_C_DecryptInit__invalid_handle            (CK_SESSION_HANDLE session,
                                                           CK_MECHANISM_PTR mechanism,
                                                           CK_OBJECT_HANDLE key);

CK_RV       mock_C_Decrypt__invalid_handle                (CK_SESSION_HANDLE session,
                                                           CK_BYTE_PTR enc_data,
                                                           CK_ULONG enc_data_len,
                                                           CK_BYTE_PTR data,
                                                           CK_ULONG_PTR data_len);

CK_RV       mock_C_DecryptUpdate__invalid_handle          (CK_SESSION_HANDLE session,
                                                           CK_BYTE_PTR enc_part,
                                                           CK_ULONG enc_part_len,
                                                           CK_BYTE_PTR part,
                                                           CK_ULONG_PTR part_len);

CK_RV       mock_C_DecryptFinal__invalid_handle           (CK_SESSION_HANDLE session,
                                                           CK_BYTE_PTR last_part,
                                                           CK_ULONG_PTR last_part_len);

CK_RV       mock_C_DigestInit__invalid_handle             (CK_SESSION_HANDLE session,
                                                           CK_MECHANISM_PTR mechanism);

CK_RV       mock_C_Digest__invalid_handle                 (CK_SESSION_HANDLE session,
                                                           CK_BYTE_PTR data,
                                                           CK_ULONG data_len,
                                                           CK_BYTE_PTR digest,
                                                           CK_ULONG_PTR digest_len);

CK_RV       mock_C_DigestUpdate__invalid_handle           (CK_SESSION_HANDLE session,
                                                           CK_BYTE_PTR part,
                                                           CK_ULONG part_len);

CK_RV       mock_C_DigestKey__invalid_handle              (CK_SESSION_HANDLE session,
                                                           CK_OBJECT_HANDLE key);

CK_RV       mock_C_DigestFinal__invalid_handle            (CK_SESSION_HANDLE session,
                                                           CK_BYTE_PTR digest,
                                                           CK_ULONG_PTR digest_len);

CK_RV       mock_C_SignInit__invalid_handle               (CK_SESSION_HANDLE session,
                                                           CK_MECHANISM_PTR mechanism,
                                                           CK_OBJECT_HANDLE key);

CK_RV       mock_C_Sign__invalid_handle                   (CK_SESSION_HANDLE session,
                                                           CK_BYTE_PTR data,
                                                           CK_ULONG data_len,
                                                           CK_BYTE_PTR signature,
                                                           CK_ULONG_PTR signature_len);

CK_RV       mock_C_SignUpdate__invalid_handle             (CK_SESSION_HANDLE session,
                                                           CK_BYTE_PTR part,
                                                           CK_ULONG part_len);

CK_RV       mock_C_SignFinal__invalid_handle              (CK_SESSION_HANDLE session,
                                                           CK_BYTE_PTR signature,
                                                           CK_ULONG_PTR signature_len);

CK_RV       mock_C_SignRecoverInit__invalid_handle        (CK_SESSION_HANDLE session,
                                                           CK_MECHANISM_PTR mechanism,
                                                           CK_OBJECT_HANDLE key);

CK_RV       mock_C_SignRecover__invalid_handle            (CK_SESSION_HANDLE session,
                                                           CK_BYTE_PTR data,
                                                           CK_ULONG data_len,
                                                           CK_BYTE_PTR signature,
                                                           CK_ULONG_PTR signature_len);

CK_RV       mock_C_VerifyInit__invalid_handle             (CK_SESSION_HANDLE session,
                                                           CK_MECHANISM_PTR mechanism,
                                                           CK_OBJECT_HANDLE key);

CK_RV       mock_C_Verify__invalid_handle                 (CK_SESSION_HANDLE session,
                                                           CK_BYTE_PTR data,
                                                           CK_ULONG data_len,
                                                           CK_BYTE_PTR signature,
                                                           CK_ULONG signature_len);

CK_RV       mock_C_VerifyUpdate__invalid_handle           (CK_SESSION_HANDLE session,
                                                           CK_BYTE_PTR part,
                                                           CK_ULONG part_len);

CK_RV       mock_C_VerifyFinal__invalid_handle            (CK_SESSION_HANDLE session,
                                                           CK_BYTE_PTR signature,
                                                           CK_ULONG signature_len);

CK_RV       mock_C_VerifyRecoverInit__invalid_handle      (CK_SESSION_HANDLE session,
                                                           CK_MECHANISM_PTR mechanism,
                                                           CK_OBJECT_HANDLE key);

CK_RV       mock_C_VerifyRecover__invalid_handle          (CK_SESSION_HANDLE session,
                                                           CK_BYTE_PTR signature,
                                                           CK_ULONG signature_len,
                                                           CK_BYTE_PTR data,
                                                           CK_ULONG_PTR data_len);

CK_RV       mock_C_DigestEncryptUpdate__invalid_handle    (CK_SESSION_HANDLE session,
                                                           CK_BYTE_PTR part,
                                                           CK_ULONG part_len,
                                                           CK_BYTE_PTR enc_part,
                                                           CK_ULONG_PTR enc_part_len);

CK_RV       mock_C_DecryptDigestUpdate__invalid_handle    (CK_SESSION_HANDLE session,
                                                           CK_BYTE_PTR enc_part,
                                                           CK_ULONG enc_part_len,
                                                           CK_BYTE_PTR part,
                                                           CK_ULONG_PTR part_len);

CK_RV       mock_C_SignEncryptUpdate__invalid_handle       (CK_SESSION_HANDLE session,
                                                            CK_BYTE_PTR part,
                                                            CK_ULONG part_len,
                                                            CK_BYTE_PTR enc_part,
                                                            CK_ULONG_PTR enc_part_len);

CK_RV       mock_C_DecryptVerifyUpdate__invalid_handle     (CK_SESSION_HANDLE session,
                                                            CK_BYTE_PTR enc_part,
                                                            CK_ULONG enc_part_len,
                                                            CK_BYTE_PTR part,
                                                            CK_ULONG_PTR part_len);

CK_RV       mock_C_GenerateKey__invalid_handle             (CK_SESSION_HANDLE session,
                                                            CK_MECHANISM_PTR mechanism,
                                                            CK_ATTRIBUTE_PTR template,
                                                            CK_ULONG count,
                                                            CK_OBJECT_HANDLE_PTR key);

CK_RV       mock_C_GenerateKeyPair__invalid_handle         (CK_SESSION_HANDLE session,
                                                            CK_MECHANISM_PTR mechanism,
                                                            CK_ATTRIBUTE_PTR pub_template,
                                                            CK_ULONG pub_count,
                                                            CK_ATTRIBUTE_PTR priv_template,
                                                            CK_ULONG priv_count,
                                                            CK_OBJECT_HANDLE_PTR pub_key,
                                                            CK_OBJECT_HANDLE_PTR priv_key);

CK_RV       mock_C_WrapKey__invalid_handle                 (CK_SESSION_HANDLE session,
                                                            CK_MECHANISM_PTR mechanism,
                                                            CK_OBJECT_HANDLE wrapping_key,
                                                            CK_OBJECT_HANDLE key,
                                                            CK_BYTE_PTR wrapped_key,
                                                            CK_ULONG_PTR wrapped_key_len);

CK_RV       mock_C_UnwrapKey__invalid_handle               (CK_SESSION_HANDLE session,
                                                            CK_MECHANISM_PTR mechanism,
                                                            CK_OBJECT_HANDLE unwrapping_key,
                                                            CK_BYTE_PTR wrapped_key,
                                                            CK_ULONG wrapped_key_len,
                                                            CK_ATTRIBUTE_PTR template,
                                                            CK_ULONG count,
                                                            CK_OBJECT_HANDLE_PTR key);

CK_RV       mock_C_DeriveKey__invalid_handle               (CK_SESSION_HANDLE session,
                                                            CK_MECHANISM_PTR mechanism,
                                                            CK_OBJECT_HANDLE base_key,
                                                            CK_ATTRIBUTE_PTR template,
                                                            CK_ULONG count,
                                                            CK_OBJECT_HANDLE_PTR key);

CK_RV       mock_C_SeedRandom__invalid_handle              (CK_SESSION_HANDLE session,
                                                            CK_BYTE_PTR seed,
                                                            CK_ULONG seed_len);

CK_RV       mock_C_GenerateRandom__invalid_handle          (CK_SESSION_HANDLE session,
                                                            CK_BYTE_PTR random_data,
                                                            CK_ULONG random_len);

#endif /* __MOCK_MODULE_H__ */
