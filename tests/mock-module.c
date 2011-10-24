/*
 * Copyright (c) 2011, Collabora Ltd.
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
 * Author: Stef Walter <stefw@collabora.co.uk>
 */

#include "config.h"

#define CRYPTOKI_EXPORTS
#include "pkcs11.h"
#include "mock-module.h"

#include "p11-kit/compat.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* -------------------------------------------------------------------
 * GLOBALS / DEFINES
 */

/* Various mutexes */
static mutex_t init_mutex;

/* Whether we've been initialized, and on what process id it happened */
static int pkcs11_initialized = 0;
static pid_t pkcs11_initialized_pid = 0;

/* -----------------------------------------------------------------------------
 * LOGGING and DEBUGGING
 */

#define DEBUG_OUTPUT 0

#if DEBUG_OUTPUT
#define debug(x) mock_log x
#else
#define debug(x)
#endif

#define warning(x) mock_log x

#define return_val_if_fail(x, v) \
	if (!(x)) { mock_log ("'%s' not true at %s", #x, __func__); return v; }

static void
mock_log (const char *format, ...)
{
	va_list va;
	va_start (va, format);
	fprintf (stderr, "mock-module: ");
	vfprintf (stderr, format, va);
	fprintf (stderr, "\n");
	va_end (va);
}

/* -------------------------------------------------------------------
 * INITIALIZATION and 'GLOBAL' CALLS
 */

CK_RV
mock_C_Initialize (CK_VOID_PTR init_args)
{
	CK_C_INITIALIZE_ARGS_PTR args = NULL;
	CK_RV ret = CKR_OK;
	pid_t pid;

	debug (("C_Initialize: enter"));

	_p11_mutex_lock (&init_mutex);

		if (init_args != NULL) {
			int supplied_ok;

			/* pReserved must be NULL */
			args = init_args;

			/* ALL supplied function pointers need to have the value either NULL or non-NULL. */
			supplied_ok = (args->CreateMutex == NULL && args->DestroyMutex == NULL &&
			               args->LockMutex == NULL && args->UnlockMutex == NULL) ||
			              (args->CreateMutex != NULL && args->DestroyMutex != NULL &&
			               args->LockMutex != NULL && args->UnlockMutex != NULL);
			if (!supplied_ok) {
				warning (("invalid set of mutex calls supplied"));
				ret = CKR_ARGUMENTS_BAD;
				goto done;
			}

			/*
			 * When the CKF_OS_LOCKING_OK flag isn't set return an error.
			 * We must be able to use our pthread functionality.
			 */
			if (!(args->flags & CKF_OS_LOCKING_OK)) {
				warning (("can't do without os locking"));
				ret = CKR_CANT_LOCK;
				goto done;
			}
		}

		pid = getpid ();
		if (pkcs11_initialized) {

			/* This process has called C_Initialize already */
			if (pid == pkcs11_initialized_pid) {
				warning (("C_Initialize called twice for same process"));
				ret = CKR_CRYPTOKI_ALREADY_INITIALIZED;
				goto done;
			}
		}

done:
		/* Mark us as officially initialized */
		if (ret == CKR_OK) {
			pkcs11_initialized = 1;
			pkcs11_initialized_pid = pid;
		} else if (ret != CKR_CRYPTOKI_ALREADY_INITIALIZED) {
			pkcs11_initialized = 0;
			pkcs11_initialized_pid = 0;
		}

	_p11_mutex_unlock (&init_mutex);

	debug (("C_Initialize: %d", ret));
	return ret;
}

CK_RV
mock_C_Finalize (CK_VOID_PTR reserved)
{
	debug (("C_Finalize: enter"));
	return_val_if_fail (pkcs11_initialized != 0, CKR_CRYPTOKI_NOT_INITIALIZED);
	return_val_if_fail (reserved == NULL, CKR_ARGUMENTS_BAD);

	_p11_mutex_lock (&init_mutex);

		/* This should stop all other calls in */
		pkcs11_initialized = 0;
		pkcs11_initialized_pid = 0;

	_p11_mutex_unlock (&init_mutex);

	debug (("C_Finalize: %d", CKR_OK));
	return CKR_OK;
}

static const CK_INFO MOCK_INFO = {
	{ CRYPTOKI_VERSION_MAJOR, CRYPTOKI_VERSION_MINOR },
	"MOCK MANUFACTURER              ",
	0,
	"MOCK LIBRARY                   ",
	{ 45, 145 }
};


CK_RV
mock_C_GetInfo (CK_INFO_PTR info)
{
	return_val_if_fail (info, CKR_ARGUMENTS_BAD);

	memcpy (info, &MOCK_INFO, sizeof (*info));
	return CKR_OK;
}

CK_RV
mock_C_GetFunctionList (CK_FUNCTION_LIST_PTR_PTR list)
{
	/* This would be a strange call to receive */
	return C_GetFunctionList (list);
}

CK_RV
mock_C_GetSlotList__no_tokens (CK_BBOOL token_present,
                               CK_SLOT_ID_PTR slot_list,
                               CK_ULONG_PTR count)
{
	return_val_if_fail (count, CKR_ARGUMENTS_BAD);

	/* No tokens */
	*count = 0;
	return CKR_OK;
}

CK_RV
mock_C_GetSlotInfo__invalid_slotid (CK_SLOT_ID id,
                                    CK_SLOT_INFO_PTR info)
{
	return_val_if_fail (info, CKR_ARGUMENTS_BAD);

	return CKR_SLOT_ID_INVALID;
}

CK_RV
mock_C_GetTokenInfo__invalid_slotid (CK_SLOT_ID id,
                                     CK_TOKEN_INFO_PTR info)
{
	return_val_if_fail (info, CKR_ARGUMENTS_BAD);

	return CKR_SLOT_ID_INVALID;
}

CK_RV
mock_C_GetMechanismList__invalid_slotid (CK_SLOT_ID id,
                                         CK_MECHANISM_TYPE_PTR mechanism_list,
                                         CK_ULONG_PTR count)
{
	return_val_if_fail (count, CKR_ARGUMENTS_BAD);

	return CKR_SLOT_ID_INVALID;
}

CK_RV
mock_C_GetMechanismInfo__invalid_slotid (CK_SLOT_ID id,
                                         CK_MECHANISM_TYPE type,
                                         CK_MECHANISM_INFO_PTR info)
{
	return_val_if_fail (info, CKR_ARGUMENTS_BAD);

	return CKR_SLOT_ID_INVALID;
}

CK_RV
mock_C_InitToken__invalid_slotid (CK_SLOT_ID id,
                                  CK_UTF8CHAR_PTR pin,
                                  CK_ULONG pin_len,
                                  CK_UTF8CHAR_PTR label)
{
	return CKR_SLOT_ID_INVALID;
}

CK_RV
mock_C_WaitForSlotEvent__no_event (CK_FLAGS flags,
                                   CK_SLOT_ID_PTR slot,
                                   CK_VOID_PTR reserved)
{
	return_val_if_fail (slot, CKR_ARGUMENTS_BAD);

	return CKR_NO_EVENT;
}

CK_RV
mock_C_OpenSession__invalid_slotid (CK_SLOT_ID id,
                                    CK_FLAGS flags,
                                    CK_VOID_PTR user_data,
                                    CK_NOTIFY callback,
                                    CK_SESSION_HANDLE_PTR session)
{
	return_val_if_fail (session, CKR_ARGUMENTS_BAD);

	return CKR_SLOT_ID_INVALID;
}

CK_RV
mock_C_CloseSession__invalid_handle (CK_SESSION_HANDLE session)
{
	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_C_CloseAllSessions__invalid_slotid (CK_SLOT_ID id)
{
	return CKR_SLOT_ID_INVALID;
}

CK_RV
mock_C_GetFunctionStatus__not_parallel (CK_SESSION_HANDLE session)
{
	return CKR_FUNCTION_NOT_PARALLEL;
}

CK_RV
mock_C_CancelFunction__not_parallel (CK_SESSION_HANDLE session)
{
	return CKR_FUNCTION_NOT_PARALLEL;
}

CK_RV
mock_C_GetSessionInfo__invalid_handle (CK_SESSION_HANDLE session,
                                       CK_SESSION_INFO_PTR info)
{
	return_val_if_fail (info, CKR_ARGUMENTS_BAD);

	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_C_InitPIN__invalid_handle (CK_SESSION_HANDLE session,
                                CK_UTF8CHAR_PTR pin,
                                CK_ULONG pin_len)
{
	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_C_SetPIN__invalid_handle (CK_SESSION_HANDLE session,
                               CK_UTF8CHAR_PTR old_pin,
                               CK_ULONG old_pin_len,
                               CK_UTF8CHAR_PTR new_pin,
                               CK_ULONG new_pin_len)
{
	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_C_GetOperationState__invalid_handle (CK_SESSION_HANDLE session,
                                         CK_BYTE_PTR operation_state,
                                         CK_ULONG_PTR operation_state_len)
{
	return_val_if_fail (operation_state_len, CKR_ARGUMENTS_BAD);

	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_C_SetOperationState__invalid_handle (CK_SESSION_HANDLE session,
                                          CK_BYTE_PTR operation_state,
                                          CK_ULONG operation_state_len,
                                          CK_OBJECT_HANDLE encryption_key,
                                          CK_OBJECT_HANDLE authentication_key)
{
	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_C_Login__invalid_handle (CK_SESSION_HANDLE session,
                              CK_USER_TYPE user_type,
                              CK_UTF8CHAR_PTR pin,
                              CK_ULONG pin_len)
{
	return CKR_SESSION_HANDLE_INVALID;

}

CK_RV
mock_C_Logout__invalid_handle (CK_SESSION_HANDLE session)
{
	return CKR_SESSION_HANDLE_INVALID;

}

CK_RV
mock_C_CreateObject__invalid_handle (CK_SESSION_HANDLE session,
                                     CK_ATTRIBUTE_PTR template,
                                     CK_ULONG count,
                                     CK_OBJECT_HANDLE_PTR new_object)
{
	return_val_if_fail (new_object, CKR_ARGUMENTS_BAD);

	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_C_CopyObject__invalid_handle (CK_SESSION_HANDLE session,
                                   CK_OBJECT_HANDLE object,
                                   CK_ATTRIBUTE_PTR template,
                                   CK_ULONG count,
                                   CK_OBJECT_HANDLE_PTR new_object)
{
	return_val_if_fail (new_object, CKR_ARGUMENTS_BAD);

	return CKR_SESSION_HANDLE_INVALID;
}


CK_RV
mock_C_DestroyObject__invalid_handle (CK_SESSION_HANDLE session,
                                      CK_OBJECT_HANDLE object)
{
	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_C_GetObjectSize__invalid_handle (CK_SESSION_HANDLE session,
                                      CK_OBJECT_HANDLE object,
                                      CK_ULONG_PTR size)
{
	return_val_if_fail (size, CKR_ARGUMENTS_BAD);

	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_C_GetAttributeValue__invalid_handle (CK_SESSION_HANDLE session,
                                          CK_OBJECT_HANDLE object,
                                          CK_ATTRIBUTE_PTR template,
                                          CK_ULONG count)
{
	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_C_SetAttributeValue__invalid_handle (CK_SESSION_HANDLE session,
                                          CK_OBJECT_HANDLE object,
                                          CK_ATTRIBUTE_PTR template,
                                          CK_ULONG count)
{
	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_C_FindObjectsInit__invalid_handle (CK_SESSION_HANDLE session,
                                        CK_ATTRIBUTE_PTR template,
                                        CK_ULONG count)
{
	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_C_FindObjects__invalid_handle (CK_SESSION_HANDLE session,
                                    CK_OBJECT_HANDLE_PTR objects,
                                    CK_ULONG max_count,
                                    CK_ULONG_PTR count)
{
	return_val_if_fail (count, CKR_ARGUMENTS_BAD);

	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_C_FindObjectsFinal__invalid_handle (CK_SESSION_HANDLE session)
{
	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_C_EncryptInit__invalid_handle (CK_SESSION_HANDLE session,
                                    CK_MECHANISM_PTR mechanism,
                                    CK_OBJECT_HANDLE key)
{
	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_C_Encrypt__invalid_handle (CK_SESSION_HANDLE session,
                                CK_BYTE_PTR data, CK_ULONG data_len,
                                CK_BYTE_PTR encrypted_data,
                                CK_ULONG_PTR encrypted_data_len)
{
	return_val_if_fail (encrypted_data_len, CKR_ARGUMENTS_BAD);

	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_C_EncryptUpdate__invalid_handle (CK_SESSION_HANDLE session,
                                      CK_BYTE_PTR part,
                                      CK_ULONG part_len,
                                      CK_BYTE_PTR encrypted_part,
                                      CK_ULONG_PTR encrypted_part_len)
{
	return_val_if_fail (encrypted_part_len, CKR_ARGUMENTS_BAD);

	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_C_EncryptFinal__invalid_handle (CK_SESSION_HANDLE session,
                                     CK_BYTE_PTR last_part,
                                     CK_ULONG_PTR last_part_len)
{
	return_val_if_fail (last_part_len, CKR_ARGUMENTS_BAD);

	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_C_DecryptInit__invalid_handle (CK_SESSION_HANDLE session,
                                    CK_MECHANISM_PTR mechanism,
                                    CK_OBJECT_HANDLE key)
{
	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_C_Decrypt__invalid_handle (CK_SESSION_HANDLE session,
                                CK_BYTE_PTR enc_data,
                                CK_ULONG enc_data_len,
                                CK_BYTE_PTR data,
                                CK_ULONG_PTR data_len)
{
	return_val_if_fail (data_len, CKR_ARGUMENTS_BAD);

	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_C_DecryptUpdate__invalid_handle (CK_SESSION_HANDLE session,
                                      CK_BYTE_PTR enc_part,
                                      CK_ULONG enc_part_len,
                                      CK_BYTE_PTR part,
                                      CK_ULONG_PTR part_len)
{
	return_val_if_fail (part_len, CKR_ARGUMENTS_BAD);

	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_C_DecryptFinal__invalid_handle (CK_SESSION_HANDLE session,
                                     CK_BYTE_PTR last_part,
                                     CK_ULONG_PTR last_part_len)
{
	return_val_if_fail (last_part_len, CKR_ARGUMENTS_BAD);

	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_C_DigestInit__invalid_handle (CK_SESSION_HANDLE session,
                                   CK_MECHANISM_PTR mechanism)
{
	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_C_Digest__invalid_handle (CK_SESSION_HANDLE session,
                               CK_BYTE_PTR data,
                               CK_ULONG data_len,
                               CK_BYTE_PTR digest,
                               CK_ULONG_PTR digest_len)
{
	return_val_if_fail (digest_len, CKR_ARGUMENTS_BAD);

	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_C_DigestUpdate__invalid_handle (CK_SESSION_HANDLE session,
                                     CK_BYTE_PTR part,
                                     CK_ULONG part_len)
{
	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_C_DigestKey__invalid_handle (CK_SESSION_HANDLE session,
                                  CK_OBJECT_HANDLE key)
{
	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_C_DigestFinal__invalid_handle (CK_SESSION_HANDLE session,
                                    CK_BYTE_PTR digest,
                                    CK_ULONG_PTR digest_len)
{
	return_val_if_fail (digest_len, CKR_ARGUMENTS_BAD);

	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_C_SignInit__invalid_handle (CK_SESSION_HANDLE session,
                                 CK_MECHANISM_PTR mechanism,
                                 CK_OBJECT_HANDLE key)
{
	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_C_Sign__invalid_handle (CK_SESSION_HANDLE session,
                             CK_BYTE_PTR data,
                             CK_ULONG data_len,
                             CK_BYTE_PTR signature,
                             CK_ULONG_PTR signature_len)
{
	return_val_if_fail (signature_len, CKR_ARGUMENTS_BAD);

	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_C_SignUpdate__invalid_handle (CK_SESSION_HANDLE session,
                                   CK_BYTE_PTR part,
                                   CK_ULONG part_len)
{
	return_val_if_fail (part_len, CKR_ARGUMENTS_BAD);

	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_C_SignFinal__invalid_handle (CK_SESSION_HANDLE session,
                                  CK_BYTE_PTR signature,
                                  CK_ULONG_PTR signature_len)
{
	return_val_if_fail (signature_len, CKR_ARGUMENTS_BAD);

	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_C_SignRecoverInit__invalid_handle (CK_SESSION_HANDLE session,
                                        CK_MECHANISM_PTR mechanism,
                                        CK_OBJECT_HANDLE key)
{
	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_C_SignRecover__invalid_handle (CK_SESSION_HANDLE session,
                                    CK_BYTE_PTR data,
                                    CK_ULONG data_len,
                                    CK_BYTE_PTR signature,
                                    CK_ULONG_PTR signature_len)
{
	return_val_if_fail (signature_len, CKR_ARGUMENTS_BAD);

	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_C_VerifyInit__invalid_handle (CK_SESSION_HANDLE session,
                                   CK_MECHANISM_PTR mechanism,
                                   CK_OBJECT_HANDLE key)
{
	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_C_Verify__invalid_handle (CK_SESSION_HANDLE session,
                               CK_BYTE_PTR data,
                               CK_ULONG data_len,
                               CK_BYTE_PTR signature,
                               CK_ULONG signature_len)
{
	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_C_VerifyUpdate__invalid_handle (CK_SESSION_HANDLE session,
                                     CK_BYTE_PTR part,
                                     CK_ULONG part_len)
{
	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_C_VerifyFinal__invalid_handle (CK_SESSION_HANDLE session,
                                    CK_BYTE_PTR signature,
                                    CK_ULONG signature_len)
{
	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_C_VerifyRecoverInit__invalid_handle (CK_SESSION_HANDLE session,
                                          CK_MECHANISM_PTR mechanism,
                                          CK_OBJECT_HANDLE key)
{
	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_C_VerifyRecover__invalid_handle (CK_SESSION_HANDLE session,
                                      CK_BYTE_PTR signature,
                                      CK_ULONG signature_len,
                                      CK_BYTE_PTR data,
                                      CK_ULONG_PTR data_len)
{
	return_val_if_fail (data_len, CKR_ARGUMENTS_BAD);

	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_C_DigestEncryptUpdate__invalid_handle (CK_SESSION_HANDLE session,
                                            CK_BYTE_PTR part,
                           CK_ULONG part_len, CK_BYTE_PTR enc_part,
                           CK_ULONG_PTR enc_part_len)
{
	return_val_if_fail (enc_part_len, CKR_ARGUMENTS_BAD);

	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_C_DecryptDigestUpdate__invalid_handle (CK_SESSION_HANDLE session,
                                            CK_BYTE_PTR enc_part,
                                            CK_ULONG enc_part_len,
                                            CK_BYTE_PTR part,
                                            CK_ULONG_PTR part_len)
{
	return_val_if_fail (part_len, CKR_ARGUMENTS_BAD);

	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_C_SignEncryptUpdate__invalid_handle (CK_SESSION_HANDLE session,
                                          CK_BYTE_PTR part,
                                          CK_ULONG part_len,
                                          CK_BYTE_PTR enc_part,
                                          CK_ULONG_PTR enc_part_len)
{
	return_val_if_fail (enc_part_len, CKR_ARGUMENTS_BAD);

	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_C_DecryptVerifyUpdate__invalid_handle (CK_SESSION_HANDLE session,
                                            CK_BYTE_PTR enc_part,
                                            CK_ULONG enc_part_len,
                                            CK_BYTE_PTR part,
                                            CK_ULONG_PTR part_len)
{
	return_val_if_fail (part_len, CKR_ARGUMENTS_BAD);

	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_C_GenerateKey__invalid_handle (CK_SESSION_HANDLE session,
                                    CK_MECHANISM_PTR mechanism,
                                    CK_ATTRIBUTE_PTR template,
                                    CK_ULONG count,
                                    CK_OBJECT_HANDLE_PTR key)
{
	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_C_GenerateKeyPair__invalid_handle (CK_SESSION_HANDLE session,
                                        CK_MECHANISM_PTR mechanism,
                                        CK_ATTRIBUTE_PTR pub_template,
                                        CK_ULONG pub_count,
                                        CK_ATTRIBUTE_PTR priv_template,
                                        CK_ULONG priv_count,
                                        CK_OBJECT_HANDLE_PTR pub_key,
                                        CK_OBJECT_HANDLE_PTR priv_key)
{
	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_C_WrapKey__invalid_handle (CK_SESSION_HANDLE session,
                                CK_MECHANISM_PTR mechanism,
                                CK_OBJECT_HANDLE wrapping_key,
                                CK_OBJECT_HANDLE key,
                                CK_BYTE_PTR wrapped_key,
                                CK_ULONG_PTR wrapped_key_len)
{
	return_val_if_fail (wrapped_key_len, CKR_ARGUMENTS_BAD);

	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_C_UnwrapKey__invalid_handle (CK_SESSION_HANDLE session,
                                  CK_MECHANISM_PTR mechanism,
                                  CK_OBJECT_HANDLE unwrapping_key,
                                  CK_BYTE_PTR wrapped_key,
                                  CK_ULONG wrapped_key_len,
                                  CK_ATTRIBUTE_PTR template,
                                  CK_ULONG count,
                                  CK_OBJECT_HANDLE_PTR key)
{
	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_C_DeriveKey__invalid_handle (CK_SESSION_HANDLE session,
                                  CK_MECHANISM_PTR mechanism,
                                  CK_OBJECT_HANDLE base_key,
                                  CK_ATTRIBUTE_PTR template,
                                  CK_ULONG count,
                                  CK_OBJECT_HANDLE_PTR key)
{
	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_C_SeedRandom__invalid_handle (CK_SESSION_HANDLE session,
                                   CK_BYTE_PTR seed,
                                   CK_ULONG seed_len)
{
	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_C_GenerateRandom__invalid_handle (CK_SESSION_HANDLE session,
                                       CK_BYTE_PTR random_data,
                                       CK_ULONG random_len)
{
	return CKR_SESSION_HANDLE_INVALID;
}

CK_FUNCTION_LIST mock_module_no_slots = {
	{ CRYPTOKI_VERSION_MAJOR, CRYPTOKI_VERSION_MINOR },  /* version */
	mock_C_Initialize,
	mock_C_Finalize,
	mock_C_GetInfo,
	mock_C_GetFunctionList,
	mock_C_GetSlotList__no_tokens,
	mock_C_GetSlotInfo__invalid_slotid,
	mock_C_GetTokenInfo__invalid_slotid,
	mock_C_GetMechanismList__invalid_slotid,
	mock_C_GetMechanismInfo__invalid_slotid,
	mock_C_InitToken__invalid_slotid,
	mock_C_InitPIN__invalid_handle,
	mock_C_SetPIN__invalid_handle,
	mock_C_OpenSession__invalid_slotid,
	mock_C_CloseSession__invalid_handle,
	mock_C_CloseAllSessions__invalid_slotid,
	mock_C_GetSessionInfo__invalid_handle,
	mock_C_GetOperationState__invalid_handle,
	mock_C_SetOperationState__invalid_handle,
	mock_C_Login__invalid_handle,
	mock_C_Logout__invalid_handle,
	mock_C_CreateObject__invalid_handle,
	mock_C_CopyObject__invalid_handle,
	mock_C_DestroyObject__invalid_handle,
	mock_C_GetObjectSize__invalid_handle,
	mock_C_GetAttributeValue__invalid_handle,
	mock_C_SetAttributeValue__invalid_handle,
	mock_C_FindObjectsInit__invalid_handle,
	mock_C_FindObjects__invalid_handle,
	mock_C_FindObjectsFinal__invalid_handle,
	mock_C_EncryptInit__invalid_handle,
	mock_C_Encrypt__invalid_handle,
	mock_C_EncryptUpdate__invalid_handle,
	mock_C_EncryptFinal__invalid_handle,
	mock_C_DecryptInit__invalid_handle,
	mock_C_Decrypt__invalid_handle,
	mock_C_DecryptUpdate__invalid_handle,
	mock_C_DecryptFinal__invalid_handle,
	mock_C_DigestInit__invalid_handle,
	mock_C_Digest__invalid_handle,
	mock_C_DigestUpdate__invalid_handle,
	mock_C_DigestKey__invalid_handle,
	mock_C_DigestFinal__invalid_handle,
	mock_C_SignInit__invalid_handle,
	mock_C_Sign__invalid_handle,
	mock_C_SignUpdate__invalid_handle,
	mock_C_SignFinal__invalid_handle,
	mock_C_SignRecoverInit__invalid_handle,
	mock_C_SignRecover__invalid_handle,
	mock_C_VerifyInit__invalid_handle,
	mock_C_Verify__invalid_handle,
	mock_C_VerifyUpdate__invalid_handle,
	mock_C_VerifyFinal__invalid_handle,
	mock_C_VerifyRecoverInit__invalid_handle,
	mock_C_VerifyRecover__invalid_handle,
	mock_C_DigestEncryptUpdate__invalid_handle,
	mock_C_DecryptDigestUpdate__invalid_handle,
	mock_C_SignEncryptUpdate__invalid_handle,
	mock_C_DecryptVerifyUpdate__invalid_handle,
	mock_C_GenerateKey__invalid_handle,
	mock_C_GenerateKeyPair__invalid_handle,
	mock_C_WrapKey__invalid_handle,
	mock_C_UnwrapKey__invalid_handle,
	mock_C_DeriveKey__invalid_handle,
	mock_C_SeedRandom__invalid_handle,
	mock_C_GenerateRandom__invalid_handle,
	mock_C_GetFunctionStatus__not_parallel,
	mock_C_CancelFunction__not_parallel,
	mock_C_WaitForSlotEvent__no_event,
};

void
mock_module_init (void)
{
	_p11_mutex_init (&init_mutex);
}
