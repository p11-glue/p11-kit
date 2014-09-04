/*
 * Copyright (c) 2012 Red Hat Inc.
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

#ifndef PKCS11_I_H_
#define PKCS11_I_H_ 1

#if defined(__cplusplus)
extern "C" {
#endif

/* -------------------------------------------------------------------
 * TRUST ASSERTIONS
 *
 * These are retired and should not be used in new code
 */

#define CKO_X_TRUST_ASSERTION                    (CKO_X_VENDOR + 100)
#define CKA_X_ASSERTION_TYPE                     (CKA_X_VENDOR + 1)
#define CKA_X_CERTIFICATE_VALUE                  (CKA_X_VENDOR + 2)
#define CKA_X_PURPOSE                            (CKA_X_VENDOR + 3)
#define CKA_X_PEER                               (CKA_X_VENDOR + 4)
typedef CK_ULONG CK_X_ASSERTION_TYPE;
#define CKT_X_DISTRUSTED_CERTIFICATE             1UL
#define CKT_X_PINNED_CERTIFICATE                 2UL
#define CKT_X_ANCHORED_CERTIFICATE               3UL

/* -------------------------------------------------------------------
 * Other deprecated definitions
 */
#define CKA_X_CRITICAL                               (CKA_X_VENDOR + 101)

/* -------------------------------------------------------------------
 * SUBCLASSABLE PKCS#11 FUNCTIONS
 */

typedef struct _CK_X_FUNCTION_LIST CK_X_FUNCTION_LIST;

typedef CK_RV (* CK_X_Initialize)          (CK_X_FUNCTION_LIST *,
                                            CK_VOID_PTR);

typedef CK_RV (* CK_X_Finalize)            (CK_X_FUNCTION_LIST *,
                                            CK_VOID_PTR);

typedef CK_RV (* CK_X_GetInfo)             (CK_X_FUNCTION_LIST *,
                                            CK_INFO_PTR);

typedef CK_RV (* CK_X_GetSlotList)         (CK_X_FUNCTION_LIST *,
                                            CK_BBOOL,
                                            CK_SLOT_ID_PTR,
                                            CK_ULONG_PTR);

typedef CK_RV (* CK_X_GetSlotInfo)         (CK_X_FUNCTION_LIST *,
                                            CK_SLOT_ID,
                                            CK_SLOT_INFO_PTR);

typedef CK_RV (* CK_X_GetTokenInfo)        (CK_X_FUNCTION_LIST *,
                                            CK_SLOT_ID,
                                            CK_TOKEN_INFO_PTR);

typedef CK_RV (* CK_X_GetMechanismList)    (CK_X_FUNCTION_LIST *,
                                            CK_SLOT_ID,
                                            CK_MECHANISM_TYPE_PTR,
                                            CK_ULONG_PTR);

typedef CK_RV (* CK_X_GetMechanismInfo)    (CK_X_FUNCTION_LIST *,
                                            CK_SLOT_ID,
                                            CK_MECHANISM_TYPE,
                                            CK_MECHANISM_INFO_PTR);

typedef CK_RV (* CK_X_InitToken)           (CK_X_FUNCTION_LIST *,
                                            CK_SLOT_ID,
                                            CK_BYTE_PTR,
                                            CK_ULONG,
                                            CK_BYTE_PTR);

typedef CK_RV (* CK_X_InitPIN)             (CK_X_FUNCTION_LIST *,
                                            CK_SESSION_HANDLE,
                                            CK_BYTE_PTR,
                                            CK_ULONG);

typedef CK_RV (* CK_X_SetPIN)              (CK_X_FUNCTION_LIST *,
                                            CK_SESSION_HANDLE,
                                            CK_BYTE_PTR,
                                            CK_ULONG,
                                            CK_BYTE_PTR,
                                            CK_ULONG);

typedef CK_RV (* CK_X_OpenSession)         (CK_X_FUNCTION_LIST *,
                                            CK_SLOT_ID,
                                            CK_FLAGS,
                                            CK_VOID_PTR,
                                            CK_NOTIFY,
                                            CK_SESSION_HANDLE_PTR);

typedef CK_RV (* CK_X_CloseSession)        (CK_X_FUNCTION_LIST *,
                                            CK_SESSION_HANDLE);

typedef CK_RV (* CK_X_CloseAllSessions)    (CK_X_FUNCTION_LIST *,
                                            CK_SLOT_ID);

typedef CK_RV (* CK_X_GetSessionInfo)      (CK_X_FUNCTION_LIST *,
                                            CK_SESSION_HANDLE,
                                            CK_SESSION_INFO_PTR);

typedef CK_RV (* CK_X_GetOperationState)   (CK_X_FUNCTION_LIST *,
                                            CK_SESSION_HANDLE,
                                            CK_BYTE_PTR,
                                            CK_ULONG_PTR);

typedef CK_RV (* CK_X_SetOperationState)   (CK_X_FUNCTION_LIST *,
                                            CK_SESSION_HANDLE,
                                            CK_BYTE_PTR,
                                            CK_ULONG,
                                            CK_OBJECT_HANDLE,
                                            CK_OBJECT_HANDLE);

typedef CK_RV (* CK_X_Login)               (CK_X_FUNCTION_LIST *,
                                            CK_SESSION_HANDLE,
                                            CK_USER_TYPE,
                                            CK_BYTE_PTR,
                                            CK_ULONG);

typedef CK_RV (* CK_X_Logout)              (CK_X_FUNCTION_LIST *,
                                            CK_SESSION_HANDLE);

typedef CK_RV (* CK_X_CreateObject)        (CK_X_FUNCTION_LIST *,
                                            CK_SESSION_HANDLE,
                                            CK_ATTRIBUTE_PTR,
                                            CK_ULONG,
                                            CK_OBJECT_HANDLE_PTR);

typedef CK_RV (* CK_X_CopyObject)          (CK_X_FUNCTION_LIST *,
                                            CK_SESSION_HANDLE,
                                            CK_OBJECT_HANDLE,
                                            CK_ATTRIBUTE_PTR,
                                            CK_ULONG,
                                            CK_OBJECT_HANDLE_PTR);

typedef CK_RV (* CK_X_DestroyObject)       (CK_X_FUNCTION_LIST *,
                                            CK_SESSION_HANDLE,
                                            CK_OBJECT_HANDLE);

typedef CK_RV (* CK_X_GetObjectSize)       (CK_X_FUNCTION_LIST *,
                                            CK_SESSION_HANDLE,
                                            CK_OBJECT_HANDLE,
                                            CK_ULONG_PTR);

typedef CK_RV (* CK_X_GetAttributeValue)   (CK_X_FUNCTION_LIST *,
                                            CK_SESSION_HANDLE,
                                            CK_OBJECT_HANDLE,
                                            CK_ATTRIBUTE_PTR,
                                            CK_ULONG);

typedef CK_RV (* CK_X_SetAttributeValue)   (CK_X_FUNCTION_LIST *,
                                            CK_SESSION_HANDLE,
                                            CK_OBJECT_HANDLE,
                                            CK_ATTRIBUTE_PTR,
                                            CK_ULONG);

typedef CK_RV (* CK_X_FindObjectsInit)     (CK_X_FUNCTION_LIST *,
                                            CK_SESSION_HANDLE,
                                            CK_ATTRIBUTE_PTR,
                                            CK_ULONG);

typedef CK_RV (* CK_X_FindObjects)         (CK_X_FUNCTION_LIST *,
                                            CK_SESSION_HANDLE,
                                            CK_OBJECT_HANDLE_PTR,
                                            CK_ULONG,
                                            CK_ULONG_PTR);

typedef CK_RV (* CK_X_FindObjectsFinal)    (CK_X_FUNCTION_LIST *,
                                            CK_SESSION_HANDLE);

typedef CK_RV (* CK_X_EncryptInit)         (CK_X_FUNCTION_LIST *,
                                            CK_SESSION_HANDLE,
                                            CK_MECHANISM_PTR,
                                            CK_OBJECT_HANDLE);

typedef CK_RV (* CK_X_Encrypt)             (CK_X_FUNCTION_LIST *,
                                            CK_SESSION_HANDLE,
                                            CK_BYTE_PTR,
                                            CK_ULONG,
                                            CK_BYTE_PTR,
                                            CK_ULONG_PTR);

typedef CK_RV (* CK_X_EncryptUpdate)       (CK_X_FUNCTION_LIST *,
                                            CK_SESSION_HANDLE,
                                            CK_BYTE_PTR,
                                            CK_ULONG,
                                            CK_BYTE_PTR,
                                            CK_ULONG_PTR);

typedef CK_RV (* CK_X_EncryptFinal)        (CK_X_FUNCTION_LIST *,
                                            CK_SESSION_HANDLE,
                                            CK_BYTE_PTR,
                                            CK_ULONG_PTR);

typedef CK_RV (* CK_X_DecryptInit)         (CK_X_FUNCTION_LIST *,
                                            CK_SESSION_HANDLE,
                                            CK_MECHANISM_PTR,
                                            CK_OBJECT_HANDLE);

typedef CK_RV (* CK_X_Decrypt)             (CK_X_FUNCTION_LIST *,
                                            CK_SESSION_HANDLE,
                                            CK_BYTE_PTR,
                                            CK_ULONG,
                                            CK_BYTE_PTR,
                                            CK_ULONG_PTR);

typedef CK_RV (* CK_X_DecryptUpdate)       (CK_X_FUNCTION_LIST *,
                                            CK_SESSION_HANDLE,
                                            CK_BYTE_PTR,
                                            CK_ULONG,
                                            CK_BYTE_PTR,
                                            CK_ULONG_PTR);

typedef CK_RV (* CK_X_DecryptFinal)        (CK_X_FUNCTION_LIST *,
                                            CK_SESSION_HANDLE,
                                            CK_BYTE_PTR,
                                            CK_ULONG_PTR);

typedef CK_RV (* CK_X_DigestInit)          (CK_X_FUNCTION_LIST *,
                                            CK_SESSION_HANDLE,
                                            CK_MECHANISM_PTR);

typedef CK_RV (* CK_X_Digest)              (CK_X_FUNCTION_LIST *,
                                            CK_SESSION_HANDLE,
                                            CK_BYTE_PTR,
                                            CK_ULONG,
                                            CK_BYTE_PTR,
                                            CK_ULONG_PTR);

typedef CK_RV (* CK_X_DigestUpdate)        (CK_X_FUNCTION_LIST *,
                                            CK_SESSION_HANDLE,
                                            CK_BYTE_PTR,
                                            CK_ULONG);

typedef CK_RV (* CK_X_DigestKey)           (CK_X_FUNCTION_LIST *,
                                            CK_SESSION_HANDLE,
                                            CK_OBJECT_HANDLE);

typedef CK_RV (* CK_X_DigestFinal)         (CK_X_FUNCTION_LIST *,
                                            CK_SESSION_HANDLE,
                                            CK_BYTE_PTR,
                                            CK_ULONG_PTR);

typedef CK_RV (* CK_X_SignInit)            (CK_X_FUNCTION_LIST *,
                                            CK_SESSION_HANDLE,
                                            CK_MECHANISM_PTR,
                                            CK_OBJECT_HANDLE);

typedef CK_RV (* CK_X_Sign)                (CK_X_FUNCTION_LIST *,
                                            CK_SESSION_HANDLE,
                                            CK_BYTE_PTR,
                                            CK_ULONG,
                                            CK_BYTE_PTR,
                                            CK_ULONG_PTR);

typedef CK_RV (* CK_X_SignUpdate)          (CK_X_FUNCTION_LIST *,
                                            CK_SESSION_HANDLE,
                                            CK_BYTE_PTR,
                                            CK_ULONG);

typedef CK_RV (* CK_X_SignFinal)           (CK_X_FUNCTION_LIST *,
                                            CK_SESSION_HANDLE,
                                            CK_BYTE_PTR,
                                            CK_ULONG_PTR);

typedef CK_RV (* CK_X_SignRecoverInit)     (CK_X_FUNCTION_LIST *,
                                            CK_SESSION_HANDLE,
                                            CK_MECHANISM_PTR,
                                            CK_OBJECT_HANDLE);

typedef CK_RV (* CK_X_SignRecover)         (CK_X_FUNCTION_LIST *,
                                            CK_SESSION_HANDLE,
                                            CK_BYTE_PTR,
                                            CK_ULONG,
                                            CK_BYTE_PTR,
                                            CK_ULONG_PTR);

typedef CK_RV (* CK_X_VerifyInit)          (CK_X_FUNCTION_LIST *,
                                            CK_SESSION_HANDLE,
                                            CK_MECHANISM_PTR,
                                            CK_OBJECT_HANDLE);

typedef CK_RV (* CK_X_Verify)              (CK_X_FUNCTION_LIST *,
                                            CK_SESSION_HANDLE,
                                            CK_BYTE_PTR,
                                            CK_ULONG,
                                            CK_BYTE_PTR,
                                            CK_ULONG);

typedef CK_RV (* CK_X_VerifyUpdate)        (CK_X_FUNCTION_LIST *,
                                            CK_SESSION_HANDLE,
                                            CK_BYTE_PTR,
                                            CK_ULONG);

typedef CK_RV (* CK_X_VerifyFinal)         (CK_X_FUNCTION_LIST *,
                                            CK_SESSION_HANDLE,
                                            CK_BYTE_PTR,
                                            CK_ULONG);

typedef CK_RV (* CK_X_VerifyRecoverInit)   (CK_X_FUNCTION_LIST *,
                                            CK_SESSION_HANDLE,
                                            CK_MECHANISM_PTR,
                                            CK_OBJECT_HANDLE);

typedef CK_RV (* CK_X_VerifyRecover)       (CK_X_FUNCTION_LIST *,
                                            CK_SESSION_HANDLE,
                                            CK_BYTE_PTR,
                                            CK_ULONG,
                                            CK_BYTE_PTR,
                                            CK_ULONG_PTR);

typedef CK_RV (* CK_X_DigestEncryptUpdate) (CK_X_FUNCTION_LIST *,
                                            CK_SESSION_HANDLE,
                                            CK_BYTE_PTR,
                                            CK_ULONG,
                                            CK_BYTE_PTR,
                                            CK_ULONG_PTR);

typedef CK_RV (* CK_X_DecryptDigestUpdate) (CK_X_FUNCTION_LIST *,
                                            CK_SESSION_HANDLE,
                                            CK_BYTE_PTR,
                                            CK_ULONG,
                                            CK_BYTE_PTR,
                                            CK_ULONG_PTR);

typedef CK_RV (* CK_X_SignEncryptUpdate)   (CK_X_FUNCTION_LIST *,
                                            CK_SESSION_HANDLE,
                                            CK_BYTE_PTR,
                                            CK_ULONG,
                                            CK_BYTE_PTR,
                                            CK_ULONG_PTR);

typedef CK_RV (* CK_X_DecryptVerifyUpdate) (CK_X_FUNCTION_LIST *,
                                            CK_SESSION_HANDLE,
                                            CK_BYTE_PTR,
                                            CK_ULONG,
                                            CK_BYTE_PTR,
                                            CK_ULONG_PTR);

typedef CK_RV (* CK_X_GenerateKey)         (CK_X_FUNCTION_LIST *,
                                            CK_SESSION_HANDLE,
                                            CK_MECHANISM_PTR,
                                            CK_ATTRIBUTE_PTR,
                                            CK_ULONG,
                                            CK_OBJECT_HANDLE_PTR);

typedef CK_RV (* CK_X_GenerateKeyPair)     (CK_X_FUNCTION_LIST *,
                                            CK_SESSION_HANDLE,
                                            CK_MECHANISM_PTR,
                                            CK_ATTRIBUTE_PTR,
                                            CK_ULONG,
                                            CK_ATTRIBUTE_PTR,
                                            CK_ULONG,
                                            CK_OBJECT_HANDLE_PTR,
                                            CK_OBJECT_HANDLE_PTR);

typedef CK_RV (* CK_X_WrapKey)             (CK_X_FUNCTION_LIST *,
                                            CK_SESSION_HANDLE,
                                            CK_MECHANISM_PTR,
                                            CK_OBJECT_HANDLE,
                                            CK_OBJECT_HANDLE,
                                            CK_BYTE_PTR,
                                            CK_ULONG_PTR);

typedef CK_RV (* CK_X_UnwrapKey)           (CK_X_FUNCTION_LIST *,
                                            CK_SESSION_HANDLE,
                                            CK_MECHANISM_PTR,
                                            CK_OBJECT_HANDLE,
                                            CK_BYTE_PTR,
                                            CK_ULONG,
                                            CK_ATTRIBUTE_PTR,
                                            CK_ULONG,
                                            CK_OBJECT_HANDLE_PTR);

typedef CK_RV (* CK_X_DeriveKey)           (CK_X_FUNCTION_LIST *,
                                            CK_SESSION_HANDLE,
                                            CK_MECHANISM_PTR,
                                            CK_OBJECT_HANDLE,
                                            CK_ATTRIBUTE_PTR,
                                            CK_ULONG,
                                            CK_OBJECT_HANDLE_PTR);

typedef CK_RV (* CK_X_SeedRandom)          (CK_X_FUNCTION_LIST *,
                                            CK_SESSION_HANDLE,
                                            CK_BYTE_PTR,
                                            CK_ULONG);

typedef CK_RV (* CK_X_GenerateRandom)      (CK_X_FUNCTION_LIST *,
                                            CK_SESSION_HANDLE,
                                            CK_BYTE_PTR,
                                            CK_ULONG);

typedef CK_RV (* CK_X_WaitForSlotEvent)    (CK_X_FUNCTION_LIST *,
                                            CK_FLAGS,
                                            CK_SLOT_ID_PTR,
                                            CK_VOID_PTR);

struct _CK_X_FUNCTION_LIST {
	CK_VERSION version;
	CK_X_Initialize C_Initialize;
	CK_X_Finalize C_Finalize;
	CK_X_GetInfo C_GetInfo;
	CK_X_GetSlotList C_GetSlotList;
	CK_X_GetSlotInfo C_GetSlotInfo;
	CK_X_GetTokenInfo C_GetTokenInfo;
	CK_X_GetMechanismList C_GetMechanismList;
	CK_X_GetMechanismInfo C_GetMechanismInfo;
	CK_X_InitToken C_InitToken;
	CK_X_InitPIN C_InitPIN;
	CK_X_SetPIN C_SetPIN;
	CK_X_OpenSession C_OpenSession;
	CK_X_CloseSession C_CloseSession;
	CK_X_CloseAllSessions C_CloseAllSessions;
	CK_X_GetSessionInfo C_GetSessionInfo;
	CK_X_GetOperationState C_GetOperationState;
	CK_X_SetOperationState C_SetOperationState;
	CK_X_Login C_Login;
	CK_X_Logout C_Logout;
	CK_X_CreateObject C_CreateObject;
	CK_X_CopyObject C_CopyObject;
	CK_X_DestroyObject C_DestroyObject;
	CK_X_GetObjectSize C_GetObjectSize;
	CK_X_GetAttributeValue C_GetAttributeValue;
	CK_X_SetAttributeValue C_SetAttributeValue;
	CK_X_FindObjectsInit C_FindObjectsInit;
	CK_X_FindObjects C_FindObjects;
	CK_X_FindObjectsFinal C_FindObjectsFinal;
	CK_X_EncryptInit C_EncryptInit;
	CK_X_Encrypt C_Encrypt;
	CK_X_EncryptUpdate C_EncryptUpdate;
	CK_X_EncryptFinal C_EncryptFinal;
	CK_X_DecryptInit C_DecryptInit;
	CK_X_Decrypt C_Decrypt;
	CK_X_DecryptUpdate C_DecryptUpdate;
	CK_X_DecryptFinal C_DecryptFinal;
	CK_X_DigestInit C_DigestInit;
	CK_X_Digest C_Digest;
	CK_X_DigestUpdate C_DigestUpdate;
	CK_X_DigestKey C_DigestKey;
	CK_X_DigestFinal C_DigestFinal;
	CK_X_SignInit C_SignInit;
	CK_X_Sign C_Sign;
	CK_X_SignUpdate C_SignUpdate;
	CK_X_SignFinal C_SignFinal;
	CK_X_SignRecoverInit C_SignRecoverInit;
	CK_X_SignRecover C_SignRecover;
	CK_X_VerifyInit C_VerifyInit;
	CK_X_Verify C_Verify;
	CK_X_VerifyUpdate C_VerifyUpdate;
	CK_X_VerifyFinal C_VerifyFinal;
	CK_X_VerifyRecoverInit C_VerifyRecoverInit;
	CK_X_VerifyRecover C_VerifyRecover;
	CK_X_DigestEncryptUpdate C_DigestEncryptUpdate;
	CK_X_DecryptDigestUpdate C_DecryptDigestUpdate;
	CK_X_SignEncryptUpdate C_SignEncryptUpdate;
	CK_X_DecryptVerifyUpdate C_DecryptVerifyUpdate;
	CK_X_GenerateKey C_GenerateKey;
	CK_X_GenerateKeyPair C_GenerateKeyPair;
	CK_X_WrapKey C_WrapKey;
	CK_X_UnwrapKey C_UnwrapKey;
	CK_X_DeriveKey C_DeriveKey;
	CK_X_SeedRandom C_SeedRandom;
	CK_X_GenerateRandom C_GenerateRandom;
	CK_X_WaitForSlotEvent C_WaitForSlotEvent;
};

#if defined(__cplusplus)
}
#endif

#endif	/* PKCS11_X_H_ */
