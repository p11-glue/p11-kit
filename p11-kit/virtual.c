/*
 * Copyright (C) 2008 Stefan Walter
 * Copyright (C) 2012 Red Hat Inc.
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
 * Author: Stef Walter <stefw@gnome.org>
 */

#include "config.h"

#include "compat.h"
#define P11_DEBUG_FLAG P11_DEBUG_LIB
#include "debug.h"
#include "library.h"
#include "virtual.h"

#include <assert.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#ifdef WITH_FFI

/*
 * We use libffi to build closures. Note that even with libffi certain
 * platforms do not support using ffi_closure. In this case FFI_CLOSURES will
 * not be defined. This is checked in configure.ac
 */

#include "ffi.h"
#ifndef FFI_CLOSURES
#error "FFI_CLOSURES should be checked in configure.ac"
#endif

/* There are 66 functions in PKCS#11, with a maximum of 8 args */
#define MAX_FUNCTIONS 66
#define MAX_ARGS 10

typedef struct {
	/* This is first so we can cast between CK_FUNCTION_LIST* and Context* */
	CK_FUNCTION_LIST bound;

	/* The PKCS#11 functions to call into */
	p11_virtual *virt;
	p11_destroyer destroyer;

	/* A list of our libffi built closures, for cleanup later */
	ffi_closure *ffi_closures[MAX_FUNCTIONS];
	ffi_cif ffi_cifs[MAX_FUNCTIONS];
	int ffi_used;
} Wrapper;

static CK_RV
short_C_GetFunctionStatus (CK_SESSION_HANDLE handle)
{
	return CKR_FUNCTION_NOT_PARALLEL;
}

static CK_RV
short_C_CancelFunction (CK_SESSION_HANDLE handle)
{
	return CKR_FUNCTION_NOT_PARALLEL;
}

static void
binding_C_GetFunctionList (ffi_cif *cif,
                           CK_RV *ret,
                           void* args[],
                           Wrapper *wrapper)
{
	CK_FUNCTION_LIST_PTR_PTR list = *(CK_FUNCTION_LIST_PTR_PTR *)args[0];

	if (list == NULL) {
		*ret = CKR_ARGUMENTS_BAD;
	} else {
		*list = &wrapper->bound;
		*ret = CKR_OK;
	}
}

static void
binding_C_Initialize (ffi_cif *cif,
                      CK_RV *ret,
                      void* args[],
                      CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_Initialize (funcs,
	                            *(CK_VOID_PTR *)args[0]);
}

static void
binding_C_Finalize (ffi_cif *cif,
                    CK_RV *ret,
                    void* args[],
                    CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_Finalize (funcs,
	                          *(CK_VOID_PTR *)args[0]);
}

static void
binding_C_GetInfo (ffi_cif *cif,
                   CK_RV *ret,
                   void* args[],
                   CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_GetInfo (funcs,
	                         *(CK_INFO_PTR *)args[0]);
}

static void
binding_C_GetSlotList (ffi_cif *cif,
                       CK_RV *ret,
                       void* args[],
                       CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_GetSlotList (funcs,
	                             *(CK_BBOOL *)args[0],
	                             *(CK_SLOT_ID_PTR *)args[1],
	                             *(CK_ULONG_PTR *)args[2]);
}

static void
binding_C_GetSlotInfo (ffi_cif *cif,
                       CK_RV *ret,
                       void* args[],
                       CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_GetSlotInfo (funcs,
	                             *(CK_SLOT_ID *)args[0],
	                             *(CK_SLOT_INFO_PTR *)args[1]);
}

static void
binding_C_GetTokenInfo (ffi_cif *cif,
                        CK_RV *ret,
                        void* args[],
                        CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_GetTokenInfo (funcs,
	                              *(CK_SLOT_ID *)args[0],
	                              *(CK_TOKEN_INFO_PTR *)args[1]);
}

static void
binding_C_WaitForSlotEvent (ffi_cif *cif,
                            CK_RV *ret,
                            void* args[],
                            CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_WaitForSlotEvent (funcs,
	                                  *(CK_FLAGS *)args[0],
	                                  *(CK_SLOT_ID_PTR *)args[1],
	                                  *(CK_VOID_PTR *)args[2]);
}

static void
binding_C_GetMechanismList (ffi_cif *cif,
                            CK_RV *ret,
                            void* args[],
                            CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_GetMechanismList (funcs,
	                                  *(CK_SLOT_ID *)args[0],
	                                  *(CK_MECHANISM_TYPE_PTR *)args[1],
	                                  *(CK_ULONG_PTR *)args[2]);
}

static void
binding_C_GetMechanismInfo (ffi_cif *cif,
                            CK_RV *ret,
                            void* args[],
                            CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_GetMechanismInfo (funcs,
	                                  *(CK_SLOT_ID *)args[0],
	                                  *(CK_MECHANISM_TYPE *)args[1],
	                                  *(CK_MECHANISM_INFO_PTR *)args[2]);
}

static void
binding_C_InitToken (ffi_cif *cif,
                     CK_RV *ret,
                     void* args[],
                     CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_InitToken (funcs,
	                           *(CK_SLOT_ID *)args[0],
	                           *(CK_BYTE_PTR *)args[1],
	                           *(CK_ULONG *)args[2],
	                           *(CK_BYTE_PTR *)args[3]);
}

static void
binding_C_InitPIN (ffi_cif *cif,
                   CK_RV *ret,
                   void* args[],
                   CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_InitPIN (funcs,
	                         *(CK_SESSION_HANDLE *)args[0],
	                         *(CK_BYTE_PTR *)args[1],
	                         *(CK_ULONG *)args[2]);
}

static void
binding_C_SetPIN (ffi_cif *cif,
                  CK_RV *ret,
                  void* args[],
                  CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_SetPIN (funcs,
	                        *(CK_SESSION_HANDLE *)args[0],
	                        *(CK_BYTE_PTR *)args[1],
	                        *(CK_ULONG *)args[2],
	                        *(CK_BYTE_PTR *)args[3],
	                        *(CK_ULONG *)args[4]);
}

static void
binding_C_OpenSession (ffi_cif *cif,
                       CK_RV *ret,
                       void* args[],
                       CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_OpenSession (funcs,
	                             *(CK_SLOT_ID *)args[0],
	                             *(CK_FLAGS *)args[1],
	                             *(CK_VOID_PTR *)args[2],
	                             *(CK_NOTIFY *)args[3],
	                             *(CK_SESSION_HANDLE_PTR *)args[4]);
}

static void
binding_C_CloseSession (ffi_cif *cif,
                        CK_RV *ret,
                        void* args[],
                        CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_CloseSession (funcs,
	                              *(CK_SESSION_HANDLE *)args[0]);
}

static void
binding_C_CloseAllSessions (ffi_cif *cif,
                            CK_RV *ret,
                            void* args[],
                            CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_CloseAllSessions (funcs,
	                                  *(CK_SLOT_ID *)args[0]);
}

static void
binding_C_GetSessionInfo (ffi_cif *cif,
                       CK_RV *ret,
                       void* args[],
                       CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_GetSessionInfo (funcs,
	                                *(CK_SESSION_HANDLE *)args[0],
	                                *(CK_SESSION_INFO_PTR *)args[1]);
}

static void
binding_C_GetOperationState (ffi_cif *cif,
                       CK_RV *ret,
                       void* args[],
                       CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_GetOperationState (funcs,
	                                   *(CK_SESSION_HANDLE *)args[0],
	                                   *(CK_BYTE_PTR *)args[1],
	                                   *(CK_ULONG_PTR *)args[2]);
}

static void
binding_C_SetOperationState (ffi_cif *cif,
                             CK_RV *ret,
                             void* args[],
                             CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_SetOperationState (funcs,
	                                   *(CK_SESSION_HANDLE *)args[0],
	                                   *(CK_BYTE_PTR *)args[1],
	                                   *(CK_ULONG *)args[2],
	                                   *(CK_OBJECT_HANDLE *)args[3],
	                                   *(CK_OBJECT_HANDLE *)args[4]);
}

static void
binding_C_Login (ffi_cif *cif,
                       CK_RV *ret,
                       void* args[],
                       CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_Login (funcs,
	                       *(CK_SESSION_HANDLE *)args[0],
	                       *(CK_USER_TYPE *)args[1],
	                       *(CK_BYTE_PTR *)args[2],
	                       *(CK_ULONG *)args[3]);
}

static void
binding_C_Logout (ffi_cif *cif,
                  CK_RV *ret,
                  void* args[],
                  CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_Logout (funcs,
	                        *(CK_SESSION_HANDLE *)args[0]);
}

static void
binding_C_CreateObject (ffi_cif *cif,
                       CK_RV *ret,
                       void* args[],
                       CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_CreateObject (funcs,
	                              *(CK_SESSION_HANDLE *)args[0],
	                              *(CK_ATTRIBUTE_PTR *)args[1],
	                              *(CK_ULONG *)args[2],
	                              *(CK_OBJECT_HANDLE_PTR *)args[3]);
}

static void
binding_C_CopyObject (ffi_cif *cif,
                      CK_RV *ret,
                      void* args[],
                      CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_CopyObject (funcs,
	                            *(CK_SESSION_HANDLE *)args[0],
	                            *(CK_OBJECT_HANDLE *)args[1],
	                            *(CK_ATTRIBUTE_PTR *)args[2],
	                            *(CK_ULONG *)args[3],
	                            *(CK_OBJECT_HANDLE_PTR *)args[4]);
}

static void
binding_C_DestroyObject (ffi_cif *cif,
                         CK_RV *ret,
                         void* args[],
                         CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_DestroyObject (funcs,
	                               *(CK_SESSION_HANDLE *)args[0],
	                               *(CK_OBJECT_HANDLE *)args[1]);
}

static void
binding_C_GetObjectSize (ffi_cif *cif,
                       CK_RV *ret,
                       void* args[],
                       CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_GetObjectSize (funcs,
	                               *(CK_SESSION_HANDLE *)args[0],
	                               *(CK_OBJECT_HANDLE *)args[1],
	                               *(CK_ULONG_PTR *)args[2]);
}

static void
binding_C_GetAttributeValue (ffi_cif *cif,
                             CK_RV *ret,
                             void* args[],
                             CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_GetAttributeValue (funcs,
	                                   *(CK_SESSION_HANDLE *)args[0],
	                                   *(CK_OBJECT_HANDLE *)args[1],
	                                   *(CK_ATTRIBUTE_PTR *)args[2],
	                                   *(CK_ULONG *)args[3]);
}

static void
binding_C_SetAttributeValue (ffi_cif *cif,
                       CK_RV *ret,
                       void* args[],
                       CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_SetAttributeValue (funcs,
	                                   *(CK_SESSION_HANDLE *)args[0],
	                                   *(CK_OBJECT_HANDLE *)args[1],
	                                   *(CK_ATTRIBUTE_PTR *)args[2],
	                                   *(CK_ULONG *)args[3]);
}

static void
binding_C_FindObjectsInit (ffi_cif *cif,
                           CK_RV *ret,
                           void* args[],
                           CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_FindObjectsInit (funcs,
	                                 *(CK_SESSION_HANDLE *)args[0],
	                                 *(CK_ATTRIBUTE_PTR *)args[1],
	                                 *(CK_ULONG *)args[2]);
}

static void
binding_C_FindObjects (ffi_cif *cif,
                       CK_RV *ret,
                       void* args[],
                       CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_FindObjects (funcs,
	                             *(CK_SESSION_HANDLE *)args[0],
	                             *(CK_OBJECT_HANDLE_PTR *)args[1],
	                             *(CK_ULONG *)args[2],
	                             *(CK_ULONG_PTR *)args[3]);
}

static void
binding_C_FindObjectsFinal (ffi_cif *cif,
                            CK_RV *ret,
                            void* args[],
                            CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_FindObjectsFinal (funcs,
	                                  *(CK_SESSION_HANDLE *)args[0]);
}

static void
binding_C_EncryptInit (ffi_cif *cif,
                       CK_RV *ret,
                       void* args[],
                       CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_EncryptInit (funcs,
	                             *(CK_SESSION_HANDLE *)args[0],
	                             *(CK_MECHANISM_PTR *)args[1],
	                             *(CK_OBJECT_HANDLE *)args[2]);
}

static void
binding_C_Encrypt (ffi_cif *cif,
                   CK_RV *ret,
                   void* args[],
                   CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_Encrypt (funcs,
	                         *(CK_SESSION_HANDLE *)args[0],
	                         *(CK_BYTE_PTR *)args[1],
	                         *(CK_ULONG *)args[2],
	                         *(CK_BYTE_PTR *)args[3],
	                         *(CK_ULONG_PTR *)args[4]);
}

static void
binding_C_EncryptUpdate (ffi_cif *cif,
                       CK_RV *ret,
                       void* args[],
                       CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_EncryptUpdate (funcs,
	                               *(CK_SESSION_HANDLE *)args[0],
	                               *(CK_BYTE_PTR *)args[1],
	                               *(CK_ULONG *)args[2],
	                               *(CK_BYTE_PTR *)args[3],
	                               *(CK_ULONG_PTR *)args[4]);
}

static void
binding_C_EncryptFinal (ffi_cif *cif,
                        CK_RV *ret,
                        void* args[],
                        CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_EncryptFinal (funcs,
	                              *(CK_SESSION_HANDLE *)args[0],
	                              *(CK_BYTE_PTR *)args[1],
	                              *(CK_ULONG_PTR *)args[2]);
}

static void
binding_C_DecryptInit (ffi_cif *cif,
                       CK_RV *ret,
                       void* args[],
                       CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_DecryptInit (funcs,
	                             *(CK_SESSION_HANDLE *)args[0],
	                             *(CK_MECHANISM_PTR *)args[1],
	                             *(CK_OBJECT_HANDLE *)args[2]);
}

static void
binding_C_Decrypt (ffi_cif *cif,
                   CK_RV *ret,
                   void* args[],
                   CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_Decrypt (funcs,
	                         *(CK_SESSION_HANDLE *)args[0],
	                         *(CK_BYTE_PTR *)args[1],
	                         *(CK_ULONG *)args[2],
	                         *(CK_BYTE_PTR *)args[3],
	                         *(CK_ULONG_PTR *)args[4]);
}

static void
binding_C_DecryptUpdate (ffi_cif *cif,
                         CK_RV *ret,
                         void* args[],
                         CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_DecryptUpdate (funcs,
	                               *(CK_SESSION_HANDLE *)args[0],
	                               *(CK_BYTE_PTR *)args[1],
	                               *(CK_ULONG *)args[2],
	                               *(CK_BYTE_PTR *)args[3],
	                               *(CK_ULONG_PTR *)args[4]);
}

static void
binding_C_DecryptFinal (ffi_cif *cif,
                        CK_RV *ret,
                        void* args[],
                        CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_DecryptFinal (funcs,
	                              *(CK_SESSION_HANDLE *)args[0],
	                              *(CK_BYTE_PTR *)args[1],
	                              *(CK_ULONG_PTR *)args[2]);
}

static void
binding_C_DigestInit (ffi_cif *cif,
                      CK_RV *ret,
                      void* args[],
                      CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_DigestInit (funcs,
	                            *(CK_SESSION_HANDLE *)args[0],
	                            *(CK_MECHANISM_PTR *)args[1]);
}

static void
binding_C_Digest (ffi_cif *cif,
                  CK_RV *ret,
                  void* args[],
                  CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_Digest (funcs,
	                        *(CK_SESSION_HANDLE *)args[0],
	                        *(CK_BYTE_PTR *)args[1],
	                        *(CK_ULONG *)args[2],
	                        *(CK_BYTE_PTR *)args[3],
	                        *(CK_ULONG_PTR *)args[4]);
}

static void
binding_C_DigestUpdate (ffi_cif *cif,
                       CK_RV *ret,
                       void* args[],
                       CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_DigestUpdate (funcs,
	                              *(CK_SESSION_HANDLE *)args[0],
	                              *(CK_BYTE_PTR *)args[1],
	                              *(CK_ULONG *)args[2]);
}

static void
binding_C_DigestKey (ffi_cif *cif,
                       CK_RV *ret,
                       void* args[],
                       CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_DigestKey (funcs,
	                           *(CK_SESSION_HANDLE *)args[0],
	                           *(CK_OBJECT_HANDLE *)args[1]);
}

static void
binding_C_DigestFinal (ffi_cif *cif,
                       CK_RV *ret,
                       void* args[],
                       CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_DigestFinal (funcs,
	                             *(CK_SESSION_HANDLE *)args[0],
	                             *(CK_BYTE_PTR *)args[1],
	                             *(CK_ULONG_PTR *)args[2]);
}

static void
binding_C_SignInit (ffi_cif *cif,
                       CK_RV *ret,
                       void* args[],
                       CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_SignInit (funcs,
	                          *(CK_SESSION_HANDLE *)args[0],
	                          *(CK_MECHANISM_PTR *)args[1],
	                          *(CK_OBJECT_HANDLE *)args[2]);
}

static void
binding_C_Sign (ffi_cif *cif,
                CK_RV *ret,
                void* args[],
                CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_Sign (funcs,
	                      *(CK_SESSION_HANDLE *)args[0],
	                      *(CK_BYTE_PTR *)args[1],
	                      *(CK_ULONG *)args[2],
	                      *(CK_BYTE_PTR *)args[3],
	                      *(CK_ULONG_PTR *)args[4]);
}

static void
binding_C_SignUpdate (ffi_cif *cif,
                      CK_RV *ret,
                      void* args[],
                      CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_SignUpdate (funcs,
	                            *(CK_SESSION_HANDLE *)args[0],
	                            *(CK_BYTE_PTR *)args[1],
	                            *(CK_ULONG *)args[2]);
}

static void
binding_C_SignFinal (ffi_cif *cif,
                     CK_RV *ret,
                     void* args[],
                     CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_SignFinal (funcs,
	                           *(CK_SESSION_HANDLE *)args[0],
	                           *(CK_BYTE_PTR *)args[1],
	                           *(CK_ULONG_PTR *)args[2]);
}

static void
binding_C_SignRecoverInit (ffi_cif *cif,
                           CK_RV *ret,
                           void* args[],
                           CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_SignRecoverInit (funcs,
	                                 *(CK_SESSION_HANDLE *)args[0],
	                                 *(CK_MECHANISM_PTR *)args[1],
	                                 *(CK_OBJECT_HANDLE *)args[2]);
}

static void
binding_C_SignRecover (ffi_cif *cif,
                       CK_RV *ret,
                       void* args[],
                       CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_SignRecover (funcs,
	                             *(CK_SESSION_HANDLE *)args[0],
	                             *(CK_BYTE_PTR *)args[1],
	                             *(CK_ULONG *)args[2],
	                             *(CK_BYTE_PTR *)args[3],
	                             *(CK_ULONG_PTR *)args[4]);
}

static void
binding_C_VerifyInit (ffi_cif *cif,
                      CK_RV *ret,
                      void* args[],
                      CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_VerifyInit (funcs,
	                            *(CK_SESSION_HANDLE *)args[0],
	                            *(CK_MECHANISM_PTR *)args[1],
	                            *(CK_OBJECT_HANDLE *)args[2]);
}

static void
binding_C_Verify (ffi_cif *cif,
                       CK_RV *ret,
                       void* args[],
                       CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_Verify (funcs,
	                        *(CK_SESSION_HANDLE *)args[0],
	                        *(CK_BYTE_PTR *)args[1],
	                        *(CK_ULONG *)args[2],
	                        *(CK_BYTE_PTR *)args[3],
	                        *(CK_ULONG *)args[4]);
}

static void
binding_C_VerifyUpdate (ffi_cif *cif,
                        CK_RV *ret,
                        void* args[],
                        CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_VerifyUpdate (funcs,
	                              *(CK_SESSION_HANDLE *)args[0],
	                              *(CK_BYTE_PTR *)args[1],
	                              *(CK_ULONG *)args[2]);
}

static void
binding_C_VerifyFinal (ffi_cif *cif,
                       CK_RV *ret,
                       void* args[],
                       CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_VerifyFinal (funcs,
	                             *(CK_SESSION_HANDLE *)args[0],
	                             *(CK_BYTE_PTR *)args[1],
	                             *(CK_ULONG *)args[2]);
}

static void
binding_C_VerifyRecoverInit (ffi_cif *cif,
                             CK_RV *ret,
                             void* args[],
                             CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_VerifyRecoverInit (funcs,
	                                   *(CK_SESSION_HANDLE *)args[0],
	                                   *(CK_MECHANISM_PTR *)args[1],
	                                   *(CK_OBJECT_HANDLE *)args[2]);
}

static void
binding_C_VerifyRecover (ffi_cif *cif,
                         CK_RV *ret,
                         void* args[],
                         CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_VerifyRecover (funcs,
	                               *(CK_SESSION_HANDLE *)args[0],
	                               *(CK_BYTE_PTR *)args[1],
	                               *(CK_ULONG *)args[2],
	                               *(CK_BYTE_PTR *)args[3],
	                               *(CK_ULONG_PTR *)args[4]);
}

static void
binding_C_DigestEncryptUpdate (ffi_cif *cif,
                               CK_RV *ret,
                               void* args[],
                               CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_DigestEncryptUpdate (funcs,
	                                     *(CK_SESSION_HANDLE *)args[0],
	                                     *(CK_BYTE_PTR *)args[1],
	                                     *(CK_ULONG *)args[2],
	                                     *(CK_BYTE_PTR *)args[3],
	                                     *(CK_ULONG_PTR *)args[4]);
}

static void
binding_C_DecryptDigestUpdate (ffi_cif *cif,
                               CK_RV *ret,
                               void* args[],
                               CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_DecryptDigestUpdate (funcs,
	                                     *(CK_SESSION_HANDLE *)args[0],
	                                     *(CK_BYTE_PTR *)args[1],
	                                     *(CK_ULONG *)args[2],
	                                     *(CK_BYTE_PTR *)args[3],
	                                     *(CK_ULONG_PTR *)args[4]);
}

static void
binding_C_SignEncryptUpdate (ffi_cif *cif,
                             CK_RV *ret,
                             void* args[],
                             CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_SignEncryptUpdate (funcs,
	                                   *(CK_SESSION_HANDLE *)args[0],
	                                   *(CK_BYTE_PTR *)args[1],
	                                   *(CK_ULONG *)args[2],
	                                   *(CK_BYTE_PTR *)args[3],
	                                   *(CK_ULONG_PTR *)args[4]);
}

static void
binding_C_DecryptVerifyUpdate (ffi_cif *cif,
                               CK_RV *ret,
                               void* args[],
                               CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_DecryptVerifyUpdate (funcs,
	                                     *(CK_SESSION_HANDLE *)args[0],
	                                     *(CK_BYTE_PTR *)args[1],
	                                     *(CK_ULONG *)args[2],
	                                     *(CK_BYTE_PTR *)args[3],
	                                     *(CK_ULONG_PTR *)args[4]);
}

static void
binding_C_GenerateKey (ffi_cif *cif,
                       CK_RV *ret,
                       void* args[],
                       CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_GenerateKey (funcs,
	                             *(CK_SESSION_HANDLE *)args[0],
	                             *(CK_MECHANISM_PTR *)args[1],
	                             *(CK_ATTRIBUTE_PTR *)args[2],
	                             *(CK_ULONG *)args[3],
	                             *(CK_OBJECT_HANDLE_PTR *)args[4]);
}

static void
binding_C_GenerateKeyPair (ffi_cif *cif,
                           CK_RV *ret,
                           void* args[],
                           CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_GenerateKeyPair (funcs,
	                                 *(CK_SESSION_HANDLE *)args[0],
	                                 *(CK_MECHANISM_PTR *)args[1],
	                                 *(CK_ATTRIBUTE_PTR *)args[2],
	                                 *(CK_ULONG *)args[3],
	                                 *(CK_ATTRIBUTE_PTR *)args[4],
	                                 *(CK_ULONG *)args[5],
	                                 *(CK_OBJECT_HANDLE_PTR *)args[6],
	                                 *(CK_OBJECT_HANDLE_PTR *)args[7]);
}

static void
binding_C_WrapKey (ffi_cif *cif,
                       CK_RV *ret,
                       void* args[],
                       CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_WrapKey (funcs,
	                         *(CK_SESSION_HANDLE *)args[0],
	                         *(CK_MECHANISM_PTR *)args[1],
	                         *(CK_OBJECT_HANDLE *)args[2],
	                         *(CK_OBJECT_HANDLE *)args[3],
	                         *(CK_BYTE_PTR *)args[4],
	                         *(CK_ULONG_PTR *)args[5]);
}

static void
binding_C_UnwrapKey (ffi_cif *cif,
                     CK_RV *ret,
                     void* args[],
                     CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_UnwrapKey (funcs,
	                           *(CK_SESSION_HANDLE *)args[0],
	                           *(CK_MECHANISM_PTR *)args[1],
	                           *(CK_OBJECT_HANDLE *)args[2],
	                           *(CK_BYTE_PTR *)args[3],
	                           *(CK_ULONG *)args[4],
	                           *(CK_ATTRIBUTE_PTR *)args[5],
	                           *(CK_ULONG *)args[6],
	                           *(CK_OBJECT_HANDLE_PTR *)args[7]);
}

static void
binding_C_DeriveKey (ffi_cif *cif,
                     CK_RV *ret,
                     void* args[],
                     CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_DeriveKey (funcs,
	                           *(CK_SESSION_HANDLE *)args[0],
	                           *(CK_MECHANISM_PTR *)args[1],
	                           *(CK_OBJECT_HANDLE *)args[2],
	                           *(CK_ATTRIBUTE_PTR *)args[3],
	                           *(CK_ULONG *)args[4],
	                           *(CK_OBJECT_HANDLE_PTR *)args[5]);
}

static void
binding_C_SeedRandom (ffi_cif *cif,
                       CK_RV *ret,
                       void* args[],
                       CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_SeedRandom (funcs,
	                            *(CK_SESSION_HANDLE *)args[0],
	                            *(CK_BYTE_PTR *)args[1],
	                            *(CK_ULONG *)args[2]);
}

static void
binding_C_GenerateRandom (ffi_cif *cif,
                          CK_RV *ret,
                          void* args[],
                          CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_GenerateRandom (funcs,
	                                *(CK_SESSION_HANDLE *)args[0],
	                                *(CK_BYTE_PTR *)args[1],
	                                *(CK_ULONG *)args[2]);
}

#endif /* WITH_FFI */

static CK_RV
stack_C_Initialize (CK_X_FUNCTION_LIST *self,
                    CK_VOID_PTR init_args)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_X_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_Initialize (funcs, init_args);
}

static CK_RV
stack_C_Finalize (CK_X_FUNCTION_LIST *self,
                  CK_VOID_PTR reserved)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_X_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_Finalize (funcs, reserved);
}

static CK_RV
stack_C_GetInfo (CK_X_FUNCTION_LIST *self,
                 CK_INFO_PTR info)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_X_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_GetInfo (funcs, info);
}

static CK_RV
stack_C_GetSlotList (CK_X_FUNCTION_LIST *self,
                     CK_BBOOL token_present,
                     CK_SLOT_ID_PTR slot_list,
                     CK_ULONG_PTR count)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_X_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_GetSlotList (funcs, token_present, slot_list, count);
}

static CK_RV
stack_C_GetSlotInfo (CK_X_FUNCTION_LIST *self,
                     CK_SLOT_ID slot_id,
                     CK_SLOT_INFO_PTR info)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_X_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_GetSlotInfo (funcs, slot_id, info);
}

static CK_RV
stack_C_GetTokenInfo (CK_X_FUNCTION_LIST *self,
                      CK_SLOT_ID slot_id,
                      CK_TOKEN_INFO_PTR info)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_X_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_GetTokenInfo (funcs, slot_id, info);
}

static CK_RV
stack_C_GetMechanismList (CK_X_FUNCTION_LIST *self,
                          CK_SLOT_ID slot_id,
                          CK_MECHANISM_TYPE_PTR mechanism_list,
                          CK_ULONG_PTR count)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_X_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_GetMechanismList (funcs, slot_id, mechanism_list, count);
}

static CK_RV
stack_C_GetMechanismInfo (CK_X_FUNCTION_LIST *self,
                          CK_SLOT_ID slot_id,
                          CK_MECHANISM_TYPE type,
                          CK_MECHANISM_INFO_PTR info)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_X_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_GetMechanismInfo (funcs, slot_id, type, info);
}

static CK_RV
stack_C_InitToken (CK_X_FUNCTION_LIST *self,
                   CK_SLOT_ID slot_id,
                   CK_UTF8CHAR_PTR pin,
                   CK_ULONG pin_len,
                   CK_UTF8CHAR_PTR label)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_X_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_InitToken (funcs, slot_id, pin, pin_len, label);
}

static CK_RV
stack_C_OpenSession (CK_X_FUNCTION_LIST *self,
                     CK_SLOT_ID slot_id,
                     CK_FLAGS flags,
                     CK_VOID_PTR application,
                     CK_NOTIFY notify,
                     CK_SESSION_HANDLE_PTR session)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_X_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_OpenSession (funcs, slot_id, flags, application, notify, session);
}

static CK_RV
stack_C_CloseSession (CK_X_FUNCTION_LIST *self,
                      CK_SESSION_HANDLE session)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_X_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_CloseSession (funcs, session);
}

static CK_RV
stack_C_CloseAllSessions (CK_X_FUNCTION_LIST *self,
                          CK_SLOT_ID slot_id)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_X_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_CloseAllSessions (funcs, slot_id);
}

static CK_RV
stack_C_GetSessionInfo (CK_X_FUNCTION_LIST *self,
                        CK_SESSION_HANDLE session,
                        CK_SESSION_INFO_PTR info)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_X_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_GetSessionInfo (funcs, session, info);
}

static CK_RV
stack_C_InitPIN (CK_X_FUNCTION_LIST *self,
                 CK_SESSION_HANDLE session,
                 CK_UTF8CHAR_PTR pin,
                 CK_ULONG pin_len)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_X_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_InitPIN (funcs, session, pin, pin_len);
}

static CK_RV
stack_C_SetPIN (CK_X_FUNCTION_LIST *self,
                CK_SESSION_HANDLE session,
                CK_UTF8CHAR_PTR old_pin,
                CK_ULONG old_len,
                CK_UTF8CHAR_PTR new_pin,
                CK_ULONG new_len)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_X_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_SetPIN (funcs, session, old_pin, old_len, new_pin, new_len);
}

static CK_RV
stack_C_GetOperationState (CK_X_FUNCTION_LIST *self,
                           CK_SESSION_HANDLE session,
                           CK_BYTE_PTR operation_state,
                           CK_ULONG_PTR operation_state_len)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_X_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_GetOperationState (funcs, session, operation_state, operation_state_len);
}

static CK_RV
stack_C_SetOperationState (CK_X_FUNCTION_LIST *self,
                           CK_SESSION_HANDLE session,
                           CK_BYTE_PTR operation_state,
                           CK_ULONG operation_state_len,
                           CK_OBJECT_HANDLE encryption_key,
                           CK_OBJECT_HANDLE authentication_key)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_X_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_SetOperationState (funcs, session, operation_state, operation_state_len,
	                                   encryption_key, authentication_key);
}

static CK_RV
stack_C_Login (CK_X_FUNCTION_LIST *self,
               CK_SESSION_HANDLE session,
               CK_USER_TYPE user_type,
               CK_UTF8CHAR_PTR pin,
               CK_ULONG pin_len)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_X_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_Login (funcs, session, user_type, pin, pin_len);
}

static CK_RV
stack_C_Logout (CK_X_FUNCTION_LIST *self,
                CK_SESSION_HANDLE session)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_X_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_Logout (funcs, session);
}

static CK_RV
stack_C_CreateObject (CK_X_FUNCTION_LIST *self,
                      CK_SESSION_HANDLE session,
                      CK_ATTRIBUTE_PTR template,
                      CK_ULONG count,
                      CK_OBJECT_HANDLE_PTR object)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_X_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_CreateObject (funcs, session, template, count, object);
}

static CK_RV
stack_C_CopyObject (CK_X_FUNCTION_LIST *self,
                    CK_SESSION_HANDLE session,
                    CK_OBJECT_HANDLE object,
                    CK_ATTRIBUTE_PTR template,
                    CK_ULONG count,
                    CK_OBJECT_HANDLE_PTR new_object)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_X_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_CopyObject (funcs, session, object, template, count, new_object);
}


static CK_RV
stack_C_DestroyObject (CK_X_FUNCTION_LIST *self,
                       CK_SESSION_HANDLE session,
                       CK_OBJECT_HANDLE object)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_X_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_DestroyObject (funcs, session, object);
}

static CK_RV
stack_C_GetObjectSize (CK_X_FUNCTION_LIST *self,
                       CK_SESSION_HANDLE session,
                       CK_OBJECT_HANDLE object,
                       CK_ULONG_PTR size)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_X_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_GetObjectSize (funcs, session, object, size);
}

static CK_RV
stack_C_GetAttributeValue (CK_X_FUNCTION_LIST *self,
                           CK_SESSION_HANDLE session,
                           CK_OBJECT_HANDLE object,
                           CK_ATTRIBUTE_PTR template,
                           CK_ULONG count)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_X_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_GetAttributeValue (funcs, session, object, template, count);
}

static CK_RV
stack_C_SetAttributeValue (CK_X_FUNCTION_LIST *self,
                           CK_SESSION_HANDLE session,
                           CK_OBJECT_HANDLE object,
                           CK_ATTRIBUTE_PTR template,
                           CK_ULONG count)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_X_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_SetAttributeValue (funcs, session, object, template, count);
}

static CK_RV
stack_C_FindObjectsInit (CK_X_FUNCTION_LIST *self,
                         CK_SESSION_HANDLE session,
                         CK_ATTRIBUTE_PTR template,
                         CK_ULONG count)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_X_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_FindObjectsInit (funcs, session, template, count);
}

static CK_RV
stack_C_FindObjects (CK_X_FUNCTION_LIST *self,
                       CK_SESSION_HANDLE session,
                       CK_OBJECT_HANDLE_PTR object,
                       CK_ULONG max_object_count,
                       CK_ULONG_PTR object_count)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_X_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_FindObjects (funcs, session, object, max_object_count, object_count);
}

static CK_RV
stack_C_FindObjectsFinal (CK_X_FUNCTION_LIST *self,
                            CK_SESSION_HANDLE session)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_X_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_FindObjectsFinal (funcs, session);
}

static CK_RV
stack_C_EncryptInit (CK_X_FUNCTION_LIST *self,
                       CK_SESSION_HANDLE session,
                       CK_MECHANISM_PTR mechanism,
                       CK_OBJECT_HANDLE key)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_X_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_EncryptInit (funcs, session, mechanism, key);
}

static CK_RV
stack_C_Encrypt (CK_X_FUNCTION_LIST *self,
                   CK_SESSION_HANDLE session,
                   CK_BYTE_PTR input,
                   CK_ULONG input_len,
                   CK_BYTE_PTR encrypted_data,
                   CK_ULONG_PTR encrypted_data_len)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_X_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_Encrypt (funcs, session, input, input_len,
	                         encrypted_data, encrypted_data_len);
}

static CK_RV
stack_C_EncryptUpdate (CK_X_FUNCTION_LIST *self,
                       CK_SESSION_HANDLE session,
                       CK_BYTE_PTR part,
                       CK_ULONG part_len,
                       CK_BYTE_PTR encrypted_part,
                       CK_ULONG_PTR encrypted_part_len)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_X_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_EncryptUpdate (funcs, session, part, part_len,
	                               encrypted_part, encrypted_part_len);
}

static CK_RV
stack_C_EncryptFinal (CK_X_FUNCTION_LIST *self,
                      CK_SESSION_HANDLE session,
                      CK_BYTE_PTR last_encrypted_part,
                      CK_ULONG_PTR last_encrypted_part_len)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_X_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_EncryptFinal (funcs, session, last_encrypted_part,
	                              last_encrypted_part_len);
}

static CK_RV
stack_C_DecryptInit (CK_X_FUNCTION_LIST *self,
                     CK_SESSION_HANDLE session,
                     CK_MECHANISM_PTR mechanism,
                     CK_OBJECT_HANDLE key)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_X_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_DecryptInit (funcs, session, mechanism, key);
}

static CK_RV
stack_C_Decrypt (CK_X_FUNCTION_LIST *self,
                 CK_SESSION_HANDLE session,
                 CK_BYTE_PTR encrypted_data,
                 CK_ULONG encrypted_data_len,
                 CK_BYTE_PTR output,
                 CK_ULONG_PTR output_len)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_X_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_Decrypt (funcs, session, encrypted_data, encrypted_data_len,
	                         output, output_len);
}

static CK_RV
stack_C_DecryptUpdate (CK_X_FUNCTION_LIST *self,
                       CK_SESSION_HANDLE session,
                       CK_BYTE_PTR encrypted_part,
                       CK_ULONG encrypted_part_len,
                       CK_BYTE_PTR part,
                       CK_ULONG_PTR part_len)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_X_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_DecryptUpdate (funcs, session, encrypted_part, encrypted_part_len,
	                               part, part_len);
}

static CK_RV
stack_C_DecryptFinal (CK_X_FUNCTION_LIST *self,
                      CK_SESSION_HANDLE session,
                      CK_BYTE_PTR last_part,
                      CK_ULONG_PTR last_part_len)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_X_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_DecryptFinal (funcs, session, last_part, last_part_len);
}

static CK_RV
stack_C_DigestInit (CK_X_FUNCTION_LIST *self,
                    CK_SESSION_HANDLE session,
                    CK_MECHANISM_PTR mechanism)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_X_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_DigestInit (funcs, session, mechanism);
}

static CK_RV
stack_C_Digest (CK_X_FUNCTION_LIST *self,
                CK_SESSION_HANDLE session,
                CK_BYTE_PTR input,
                CK_ULONG input_len,
                CK_BYTE_PTR digest,
                CK_ULONG_PTR digest_len)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_X_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_Digest (funcs, session, input, input_len, digest, digest_len);
}

static CK_RV
stack_C_DigestUpdate (CK_X_FUNCTION_LIST *self,
                      CK_SESSION_HANDLE session,
                      CK_BYTE_PTR part,
                      CK_ULONG part_len)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_X_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_DigestUpdate (funcs, session, part, part_len);
}

static CK_RV
stack_C_DigestKey (CK_X_FUNCTION_LIST *self,
                   CK_SESSION_HANDLE session,
                   CK_OBJECT_HANDLE key)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_X_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_DigestKey (funcs, session, key);
}

static CK_RV
stack_C_DigestFinal (CK_X_FUNCTION_LIST *self,
                     CK_SESSION_HANDLE session,
                     CK_BYTE_PTR digest,
                     CK_ULONG_PTR digest_len)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_X_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_DigestFinal (funcs, session, digest, digest_len);
}

static CK_RV
stack_C_SignInit (CK_X_FUNCTION_LIST *self,
                  CK_SESSION_HANDLE session,
                  CK_MECHANISM_PTR mechanism,
                  CK_OBJECT_HANDLE key)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_X_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_SignInit (funcs, session, mechanism, key);
}

static CK_RV
stack_C_Sign (CK_X_FUNCTION_LIST *self,
              CK_SESSION_HANDLE session,
              CK_BYTE_PTR input,
              CK_ULONG input_len,
              CK_BYTE_PTR signature,
              CK_ULONG_PTR signature_len)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_X_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_Sign (funcs, session, input, input_len,
	                      signature, signature_len);
}

static CK_RV
stack_C_SignUpdate (CK_X_FUNCTION_LIST *self,
                    CK_SESSION_HANDLE session,
                    CK_BYTE_PTR part,
                    CK_ULONG part_len)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_X_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_SignUpdate (funcs, session, part, part_len);
}

static CK_RV
stack_C_SignFinal (CK_X_FUNCTION_LIST *self,
                   CK_SESSION_HANDLE session,
                   CK_BYTE_PTR signature,
                   CK_ULONG_PTR signature_len)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_X_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_SignFinal (funcs, session, signature, signature_len);
}

static CK_RV
stack_C_SignRecoverInit (CK_X_FUNCTION_LIST *self,
                         CK_SESSION_HANDLE session,
                         CK_MECHANISM_PTR mechanism,
                         CK_OBJECT_HANDLE key)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_X_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_SignRecoverInit (funcs, session, mechanism, key);
}

static CK_RV
stack_C_SignRecover (CK_X_FUNCTION_LIST *self,
                     CK_SESSION_HANDLE session,
                     CK_BYTE_PTR input,
                     CK_ULONG input_len,
                     CK_BYTE_PTR signature,
                     CK_ULONG_PTR signature_len)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_X_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_SignRecover (funcs, session, input, input_len,
	                             signature, signature_len);
}

static CK_RV
stack_C_VerifyInit (CK_X_FUNCTION_LIST *self,
                    CK_SESSION_HANDLE session,
                    CK_MECHANISM_PTR mechanism,
                    CK_OBJECT_HANDLE key)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_X_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_VerifyInit (funcs, session, mechanism, key);
}

static CK_RV
stack_C_Verify (CK_X_FUNCTION_LIST *self,
                CK_SESSION_HANDLE session,
                CK_BYTE_PTR input,
                CK_ULONG input_len,
                CK_BYTE_PTR signature,
                CK_ULONG signature_len)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_X_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_Verify (funcs, session, input, input_len,
	                        signature, signature_len);
}

static CK_RV
stack_C_VerifyUpdate (CK_X_FUNCTION_LIST *self,
                      CK_SESSION_HANDLE session,
                      CK_BYTE_PTR part,
                      CK_ULONG part_len)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_X_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_VerifyUpdate (funcs, session, part, part_len);
}

static CK_RV
stack_C_VerifyFinal (CK_X_FUNCTION_LIST *self,
                     CK_SESSION_HANDLE session,
                     CK_BYTE_PTR signature,
                     CK_ULONG signature_len)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_X_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_VerifyFinal (funcs, session, signature, signature_len);
}

static CK_RV
stack_C_VerifyRecoverInit (CK_X_FUNCTION_LIST *self,
                           CK_SESSION_HANDLE session,
                           CK_MECHANISM_PTR mechanism,
                           CK_OBJECT_HANDLE key)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_X_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_VerifyRecoverInit (funcs, session, mechanism, key);
}

static CK_RV
stack_C_VerifyRecover (CK_X_FUNCTION_LIST *self,
                       CK_SESSION_HANDLE session,
                       CK_BYTE_PTR signature,
                       CK_ULONG signature_len,
                       CK_BYTE_PTR input,
                       CK_ULONG_PTR input_len)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_X_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_VerifyRecover (funcs, session, signature, signature_len,
	                               input, input_len);
}

static CK_RV
stack_C_DigestEncryptUpdate (CK_X_FUNCTION_LIST *self,
                             CK_SESSION_HANDLE session,
                             CK_BYTE_PTR part,
                             CK_ULONG part_len,
                             CK_BYTE_PTR encrypted_part,
                             CK_ULONG_PTR encrypted_part_len)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_X_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_DigestEncryptUpdate (funcs, session, part, part_len,
	                                     encrypted_part, encrypted_part_len);
}

static CK_RV
stack_C_DecryptDigestUpdate (CK_X_FUNCTION_LIST *self,
                             CK_SESSION_HANDLE session,
                             CK_BYTE_PTR encrypted_part,
                             CK_ULONG encrypted_part_len,
                             CK_BYTE_PTR part,
                             CK_ULONG_PTR part_len)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_X_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_DecryptDigestUpdate (funcs, session, encrypted_part, encrypted_part_len,
	                                          part, part_len);
}

static CK_RV
stack_C_SignEncryptUpdate (CK_X_FUNCTION_LIST *self,
                           CK_SESSION_HANDLE session,
                           CK_BYTE_PTR part,
                           CK_ULONG part_len,
                           CK_BYTE_PTR encrypted_part,
                           CK_ULONG_PTR encrypted_part_len)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_X_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_SignEncryptUpdate (funcs, session, part, part_len,
	                                   encrypted_part, encrypted_part_len);
}

static CK_RV
stack_C_DecryptVerifyUpdate (CK_X_FUNCTION_LIST *self,
                             CK_SESSION_HANDLE session,
                             CK_BYTE_PTR encrypted_part,
                             CK_ULONG encrypted_part_len,
                             CK_BYTE_PTR part,
                             CK_ULONG_PTR part_len)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_X_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_DecryptVerifyUpdate (funcs, session, encrypted_part, encrypted_part_len,
	                                     part, part_len);
}

static CK_RV
stack_C_GenerateKey (CK_X_FUNCTION_LIST *self,
                     CK_SESSION_HANDLE session,
                     CK_MECHANISM_PTR mechanism,
                     CK_ATTRIBUTE_PTR template,
                     CK_ULONG count,
                     CK_OBJECT_HANDLE_PTR key)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_X_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_GenerateKey (funcs, session, mechanism, template, count, key);
}

static CK_RV
stack_C_GenerateKeyPair (CK_X_FUNCTION_LIST *self,
                         CK_SESSION_HANDLE session,
                         CK_MECHANISM_PTR mechanism,
                         CK_ATTRIBUTE_PTR public_key_template,
                         CK_ULONG public_key_count,
                         CK_ATTRIBUTE_PTR private_key_template,
                         CK_ULONG private_key_count,
                         CK_OBJECT_HANDLE_PTR public_key,
                         CK_OBJECT_HANDLE_PTR private_key)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_X_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_GenerateKeyPair (funcs, session, mechanism, public_key_template,
	                                 public_key_count, private_key_template,
	                                 private_key_count, public_key, private_key);
}

static CK_RV
stack_C_WrapKey (CK_X_FUNCTION_LIST *self,
                 CK_SESSION_HANDLE session,
                 CK_MECHANISM_PTR mechanism,
                 CK_OBJECT_HANDLE wrapping_key,
                 CK_OBJECT_HANDLE key,
                 CK_BYTE_PTR wrapped_key,
                 CK_ULONG_PTR wrapped_key_len)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_X_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_WrapKey (funcs, session, mechanism, wrapping_key, key,
	                         wrapped_key, wrapped_key_len);
}

static CK_RV
stack_C_UnwrapKey (CK_X_FUNCTION_LIST *self,
                   CK_SESSION_HANDLE session,
                   CK_MECHANISM_PTR mechanism,
                   CK_OBJECT_HANDLE unwrapping_key,
                   CK_BYTE_PTR wrapped_key,
                   CK_ULONG wrapped_key_len,
                   CK_ATTRIBUTE_PTR template,
                   CK_ULONG count,
                   CK_OBJECT_HANDLE_PTR key)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_X_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_UnwrapKey (funcs, session, mechanism, unwrapping_key, wrapped_key,
	                           wrapped_key_len, template, count, key);
}

static CK_RV
stack_C_DeriveKey (CK_X_FUNCTION_LIST *self,
                   CK_SESSION_HANDLE session,
                   CK_MECHANISM_PTR mechanism,
                   CK_OBJECT_HANDLE base_key,
                   CK_ATTRIBUTE_PTR template,
                   CK_ULONG count,
                   CK_OBJECT_HANDLE_PTR key)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_X_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_DeriveKey (funcs, session, mechanism, base_key, template, count, key);
}

static CK_RV
stack_C_SeedRandom (CK_X_FUNCTION_LIST *self,
                    CK_SESSION_HANDLE session,
                    CK_BYTE_PTR seed,
                    CK_ULONG seed_len)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_X_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_SeedRandom (funcs, session, seed, seed_len);
}

static CK_RV
stack_C_GenerateRandom (CK_X_FUNCTION_LIST *self,
                        CK_SESSION_HANDLE session,
                        CK_BYTE_PTR random_data,
                        CK_ULONG random_len)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_X_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_GenerateRandom (funcs, session, random_data, random_len);
}

static CK_RV
stack_C_WaitForSlotEvent (CK_X_FUNCTION_LIST *self,
                          CK_FLAGS flags,
                          CK_SLOT_ID_PTR slot_id,
                          CK_VOID_PTR reserved)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_X_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_WaitForSlotEvent (funcs, flags, slot_id, reserved);
}

static CK_RV
base_C_Initialize (CK_X_FUNCTION_LIST *self,
                   CK_VOID_PTR init_args)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_Initialize (init_args);
}

static CK_RV
base_C_Finalize (CK_X_FUNCTION_LIST *self,
                 CK_VOID_PTR reserved)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_Finalize (reserved);
}

static CK_RV
base_C_GetInfo (CK_X_FUNCTION_LIST *self,
                CK_INFO_PTR info)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_GetInfo (info);
}

static CK_RV
base_C_GetSlotList (CK_X_FUNCTION_LIST *self,
                    CK_BBOOL token_present,
                    CK_SLOT_ID_PTR slot_list,
                    CK_ULONG_PTR count)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_GetSlotList (token_present, slot_list, count);
}

static CK_RV
base_C_GetSlotInfo (CK_X_FUNCTION_LIST *self,
                    CK_SLOT_ID slot_id,
                    CK_SLOT_INFO_PTR info)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_GetSlotInfo (slot_id, info);
}

static CK_RV
base_C_GetTokenInfo (CK_X_FUNCTION_LIST *self,
                     CK_SLOT_ID slot_id,
                     CK_TOKEN_INFO_PTR info)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_GetTokenInfo (slot_id, info);
}

static CK_RV
base_C_GetMechanismList (CK_X_FUNCTION_LIST *self,
                         CK_SLOT_ID slot_id,
                         CK_MECHANISM_TYPE_PTR mechanism_list,
                         CK_ULONG_PTR count)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_GetMechanismList (slot_id, mechanism_list, count);
}

static CK_RV
base_C_GetMechanismInfo (CK_X_FUNCTION_LIST *self,
                         CK_SLOT_ID slot_id,
                         CK_MECHANISM_TYPE type,
                         CK_MECHANISM_INFO_PTR info)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_GetMechanismInfo (slot_id, type, info);
}

static CK_RV
base_C_InitToken (CK_X_FUNCTION_LIST *self,
                  CK_SLOT_ID slot_id,
                  CK_UTF8CHAR_PTR pin,
                  CK_ULONG pin_len,
                  CK_UTF8CHAR_PTR label)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_InitToken (slot_id, pin, pin_len, label);
}

static CK_RV
base_C_OpenSession (CK_X_FUNCTION_LIST *self,
                    CK_SLOT_ID slot_id,
                    CK_FLAGS flags,
                    CK_VOID_PTR application,
                    CK_NOTIFY notify,
                    CK_SESSION_HANDLE_PTR session)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_OpenSession (slot_id, flags, application, notify, session);
}

static CK_RV
base_C_CloseSession (CK_X_FUNCTION_LIST *self,
                     CK_SESSION_HANDLE session)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_CloseSession (session);
}

static CK_RV
base_C_CloseAllSessions (CK_X_FUNCTION_LIST *self,
                         CK_SLOT_ID slot_id)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_CloseAllSessions (slot_id);
}

static CK_RV
base_C_GetSessionInfo (CK_X_FUNCTION_LIST *self,
                       CK_SESSION_HANDLE session,
                       CK_SESSION_INFO_PTR info)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_GetSessionInfo (session, info);
}

static CK_RV
base_C_InitPIN (CK_X_FUNCTION_LIST *self,
                CK_SESSION_HANDLE session,
                CK_UTF8CHAR_PTR pin,
                CK_ULONG pin_len)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_InitPIN (session, pin, pin_len);
}

static CK_RV
base_C_SetPIN (CK_X_FUNCTION_LIST *self,
               CK_SESSION_HANDLE session,
               CK_UTF8CHAR_PTR old_pin,
               CK_ULONG old_len,
               CK_UTF8CHAR_PTR new_pin,
               CK_ULONG new_len)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_SetPIN (session, old_pin, old_len, new_pin, new_len);
}

static CK_RV
base_C_GetOperationState (CK_X_FUNCTION_LIST *self,
                          CK_SESSION_HANDLE session,
                          CK_BYTE_PTR operation_state,
                          CK_ULONG_PTR operation_state_len)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_GetOperationState (session, operation_state, operation_state_len);
}

static CK_RV
base_C_SetOperationState (CK_X_FUNCTION_LIST *self,
                          CK_SESSION_HANDLE session,
                          CK_BYTE_PTR operation_state,
                          CK_ULONG operation_state_len,
                          CK_OBJECT_HANDLE encryption_key,
                          CK_OBJECT_HANDLE authentication_key)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_SetOperationState (session, operation_state, operation_state_len,
	                                   encryption_key, authentication_key);
}

static CK_RV
base_C_Login (CK_X_FUNCTION_LIST *self,
              CK_SESSION_HANDLE session,
              CK_USER_TYPE user_type,
              CK_UTF8CHAR_PTR pin,
              CK_ULONG pin_len)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_Login (session, user_type, pin, pin_len);
}

static CK_RV
base_C_Logout (CK_X_FUNCTION_LIST *self,
               CK_SESSION_HANDLE session)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_Logout (session);
}

static CK_RV
base_C_CreateObject (CK_X_FUNCTION_LIST *self,
                     CK_SESSION_HANDLE session,
                     CK_ATTRIBUTE_PTR template,
                     CK_ULONG count,
                     CK_OBJECT_HANDLE_PTR object)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_CreateObject (session, template, count, object);
}

static CK_RV
base_C_CopyObject (CK_X_FUNCTION_LIST *self,
                   CK_SESSION_HANDLE session,
                   CK_OBJECT_HANDLE object,
                   CK_ATTRIBUTE_PTR template,
                   CK_ULONG count,
                   CK_OBJECT_HANDLE_PTR new_object)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_CopyObject (session, object, template, count, new_object);
}


static CK_RV
base_C_DestroyObject (CK_X_FUNCTION_LIST *self,
                      CK_SESSION_HANDLE session,
                      CK_OBJECT_HANDLE object)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_DestroyObject (session, object);
}

static CK_RV
base_C_GetObjectSize (CK_X_FUNCTION_LIST *self,
                      CK_SESSION_HANDLE session,
                      CK_OBJECT_HANDLE object,
                      CK_ULONG_PTR size)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_GetObjectSize (session, object, size);
}

static CK_RV
base_C_GetAttributeValue (CK_X_FUNCTION_LIST *self,
                          CK_SESSION_HANDLE session,
                          CK_OBJECT_HANDLE object,
                          CK_ATTRIBUTE_PTR template,
                          CK_ULONG count)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_GetAttributeValue (session, object, template, count);
}

static CK_RV
base_C_SetAttributeValue (CK_X_FUNCTION_LIST *self,
                          CK_SESSION_HANDLE session,
                          CK_OBJECT_HANDLE object,
                          CK_ATTRIBUTE_PTR template,
                          CK_ULONG count)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_SetAttributeValue (session, object, template, count);
}

static CK_RV
base_C_FindObjectsInit (CK_X_FUNCTION_LIST *self,
                        CK_SESSION_HANDLE session,
                        CK_ATTRIBUTE_PTR template,
                        CK_ULONG count)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_FindObjectsInit (session, template, count);
}

static CK_RV
base_C_FindObjects (CK_X_FUNCTION_LIST *self,
                    CK_SESSION_HANDLE session,
                    CK_OBJECT_HANDLE_PTR object,
                    CK_ULONG max_object_count,
                    CK_ULONG_PTR object_count)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_FindObjects (session, object, max_object_count, object_count);
}

static CK_RV
base_C_FindObjectsFinal (CK_X_FUNCTION_LIST *self,
                         CK_SESSION_HANDLE session)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_FindObjectsFinal (session);
}

static CK_RV
base_C_EncryptInit (CK_X_FUNCTION_LIST *self,
                    CK_SESSION_HANDLE session,
                    CK_MECHANISM_PTR mechanism,
                    CK_OBJECT_HANDLE key)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_EncryptInit (session, mechanism, key);
}

static CK_RV
base_C_Encrypt (CK_X_FUNCTION_LIST *self,
                CK_SESSION_HANDLE session,
                CK_BYTE_PTR input,
                CK_ULONG input_len,
                CK_BYTE_PTR encrypted_data,
                CK_ULONG_PTR encrypted_data_len)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_Encrypt (session, input, input_len,
	                              encrypted_data, encrypted_data_len);
}

static CK_RV
base_C_EncryptUpdate (CK_X_FUNCTION_LIST *self,
                      CK_SESSION_HANDLE session,
                      CK_BYTE_PTR part,
                      CK_ULONG part_len,
                      CK_BYTE_PTR encrypted_part,
                      CK_ULONG_PTR encrypted_part_len)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_EncryptUpdate (session, part, part_len,
	                               encrypted_part, encrypted_part_len);
}

static CK_RV
base_C_EncryptFinal (CK_X_FUNCTION_LIST *self,
                     CK_SESSION_HANDLE session,
                     CK_BYTE_PTR last_encrypted_part,
                     CK_ULONG_PTR last_encrypted_part_len)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_EncryptFinal (session, last_encrypted_part,
	                              last_encrypted_part_len);
}

static CK_RV
base_C_DecryptInit (CK_X_FUNCTION_LIST *self,
                    CK_SESSION_HANDLE session,
                    CK_MECHANISM_PTR mechanism,
                    CK_OBJECT_HANDLE key)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_DecryptInit (session, mechanism, key);
}

static CK_RV
base_C_Decrypt (CK_X_FUNCTION_LIST *self,
                CK_SESSION_HANDLE session,
                CK_BYTE_PTR encrypted_data,
                CK_ULONG encrypted_data_len,
                CK_BYTE_PTR output,
                CK_ULONG_PTR output_len)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_Decrypt (session, encrypted_data, encrypted_data_len,
	                         output, output_len);
}

static CK_RV
base_C_DecryptUpdate (CK_X_FUNCTION_LIST *self,
                      CK_SESSION_HANDLE session,
                      CK_BYTE_PTR encrypted_part,
                      CK_ULONG encrypted_part_len,
                      CK_BYTE_PTR part,
                      CK_ULONG_PTR part_len)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_DecryptUpdate (session, encrypted_part, encrypted_part_len,
	                               part, part_len);
}

static CK_RV
base_C_DecryptFinal (CK_X_FUNCTION_LIST *self,
                     CK_SESSION_HANDLE session,
                     CK_BYTE_PTR last_part,
                     CK_ULONG_PTR last_part_len)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_DecryptFinal (session, last_part, last_part_len);
}

static CK_RV
base_C_DigestInit (CK_X_FUNCTION_LIST *self,
                   CK_SESSION_HANDLE session,
                   CK_MECHANISM_PTR mechanism)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_DigestInit (session, mechanism);
}

static CK_RV
base_C_Digest (CK_X_FUNCTION_LIST *self,
               CK_SESSION_HANDLE session,
               CK_BYTE_PTR input,
               CK_ULONG input_len,
               CK_BYTE_PTR digest,
               CK_ULONG_PTR digest_len)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_Digest (session, input, input_len, digest, digest_len);
}

static CK_RV
base_C_DigestUpdate (CK_X_FUNCTION_LIST *self,
                     CK_SESSION_HANDLE session,
                     CK_BYTE_PTR part,
                     CK_ULONG part_len)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_DigestUpdate (session, part, part_len);
}

static CK_RV
base_C_DigestKey (CK_X_FUNCTION_LIST *self,
                  CK_SESSION_HANDLE session,
                  CK_OBJECT_HANDLE key)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_DigestKey (session, key);
}

static CK_RV
base_C_DigestFinal (CK_X_FUNCTION_LIST *self,
                    CK_SESSION_HANDLE session,
                    CK_BYTE_PTR digest,
                    CK_ULONG_PTR digest_len)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_DigestFinal (session, digest, digest_len);
}

static CK_RV
base_C_SignInit (CK_X_FUNCTION_LIST *self,
                 CK_SESSION_HANDLE session,
                 CK_MECHANISM_PTR mechanism,
                 CK_OBJECT_HANDLE key)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_SignInit (session, mechanism, key);
}

static CK_RV
base_C_Sign (CK_X_FUNCTION_LIST *self,
             CK_SESSION_HANDLE session,
             CK_BYTE_PTR input,
             CK_ULONG input_len,
             CK_BYTE_PTR signature,
             CK_ULONG_PTR signature_len)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_Sign (session, input, input_len,
	                      signature, signature_len);
}

static CK_RV
base_C_SignUpdate (CK_X_FUNCTION_LIST *self,
                   CK_SESSION_HANDLE session,
                   CK_BYTE_PTR part,
                   CK_ULONG part_len)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_SignUpdate (session, part, part_len);
}

static CK_RV
base_C_SignFinal (CK_X_FUNCTION_LIST *self,
                  CK_SESSION_HANDLE session,
                  CK_BYTE_PTR signature,
                  CK_ULONG_PTR signature_len)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_SignFinal (session, signature, signature_len);
}

static CK_RV
base_C_SignRecoverInit (CK_X_FUNCTION_LIST *self,
                        CK_SESSION_HANDLE session,
                        CK_MECHANISM_PTR mechanism,
                        CK_OBJECT_HANDLE key)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_SignRecoverInit (session, mechanism, key);
}

static CK_RV
base_C_SignRecover (CK_X_FUNCTION_LIST *self,
                    CK_SESSION_HANDLE session,
                    CK_BYTE_PTR input,
                    CK_ULONG input_len,
                    CK_BYTE_PTR signature,
                    CK_ULONG_PTR signature_len)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_SignRecover (session, input, input_len,
	                             signature, signature_len);
}

static CK_RV
base_C_VerifyInit (CK_X_FUNCTION_LIST *self,
                   CK_SESSION_HANDLE session,
                   CK_MECHANISM_PTR mechanism,
                   CK_OBJECT_HANDLE key)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_VerifyInit (session, mechanism, key);
}

static CK_RV
base_C_Verify (CK_X_FUNCTION_LIST *self,
               CK_SESSION_HANDLE session,
               CK_BYTE_PTR input,
               CK_ULONG input_len,
               CK_BYTE_PTR signature,
               CK_ULONG signature_len)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_Verify (session, input, input_len,
	                        signature, signature_len);
}

static CK_RV
base_C_VerifyUpdate (CK_X_FUNCTION_LIST *self,
                     CK_SESSION_HANDLE session,
                     CK_BYTE_PTR part,
                     CK_ULONG part_len)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_VerifyUpdate (session, part, part_len);
}

static CK_RV
base_C_VerifyFinal (CK_X_FUNCTION_LIST *self,
                    CK_SESSION_HANDLE session,
                    CK_BYTE_PTR signature,
                    CK_ULONG signature_len)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_VerifyFinal (session, signature, signature_len);
}

static CK_RV
base_C_VerifyRecoverInit (CK_X_FUNCTION_LIST *self,
                          CK_SESSION_HANDLE session,
                          CK_MECHANISM_PTR mechanism,
                          CK_OBJECT_HANDLE key)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_VerifyRecoverInit (session, mechanism, key);
}

static CK_RV
base_C_VerifyRecover (CK_X_FUNCTION_LIST *self,
                      CK_SESSION_HANDLE session,
                      CK_BYTE_PTR signature,
                      CK_ULONG signature_len,
                      CK_BYTE_PTR input,
                      CK_ULONG_PTR input_len)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_VerifyRecover (session, signature, signature_len,
	                               input, input_len);
}

static CK_RV
base_C_DigestEncryptUpdate (CK_X_FUNCTION_LIST *self,
                            CK_SESSION_HANDLE session,
                            CK_BYTE_PTR part,
                            CK_ULONG part_len,
                            CK_BYTE_PTR encrypted_part,
                            CK_ULONG_PTR encrypted_part_len)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_DigestEncryptUpdate (session, part, part_len,
	                                     encrypted_part, encrypted_part_len);
}

static CK_RV
base_C_DecryptDigestUpdate (CK_X_FUNCTION_LIST *self,
                            CK_SESSION_HANDLE session,
                            CK_BYTE_PTR encrypted_part,
                            CK_ULONG encrypted_part_len,
                            CK_BYTE_PTR part,
                            CK_ULONG_PTR part_len)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_DecryptDigestUpdate (session, encrypted_part, encrypted_part_len,
	                                     part, part_len);
}

static CK_RV
base_C_SignEncryptUpdate (CK_X_FUNCTION_LIST *self,
                          CK_SESSION_HANDLE session,
                          CK_BYTE_PTR part,
                          CK_ULONG part_len,
                          CK_BYTE_PTR encrypted_part,
                          CK_ULONG_PTR encrypted_part_len)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_SignEncryptUpdate (session, part, part_len,
	                                   encrypted_part, encrypted_part_len);
}

static CK_RV
base_C_DecryptVerifyUpdate (CK_X_FUNCTION_LIST *self,
                            CK_SESSION_HANDLE session,
                            CK_BYTE_PTR encrypted_part,
                            CK_ULONG encrypted_part_len,
                            CK_BYTE_PTR part,
                            CK_ULONG_PTR part_len)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_DecryptVerifyUpdate (session, encrypted_part, encrypted_part_len,
	                                     part, part_len);
}

static CK_RV
base_C_GenerateKey (CK_X_FUNCTION_LIST *self,
                    CK_SESSION_HANDLE session,
                    CK_MECHANISM_PTR mechanism,
                    CK_ATTRIBUTE_PTR template,
                    CK_ULONG count,
                    CK_OBJECT_HANDLE_PTR key)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_GenerateKey (session, mechanism, template, count, key);
}

static CK_RV
base_C_GenerateKeyPair (CK_X_FUNCTION_LIST *self,
                        CK_SESSION_HANDLE session,
                        CK_MECHANISM_PTR mechanism,
                        CK_ATTRIBUTE_PTR public_key_template,
                        CK_ULONG public_key_count,
                        CK_ATTRIBUTE_PTR private_key_template,
                        CK_ULONG private_key_count,
                        CK_OBJECT_HANDLE_PTR public_key,
                        CK_OBJECT_HANDLE_PTR private_key)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_GenerateKeyPair (session, mechanism, public_key_template,
	                                 public_key_count, private_key_template,
	                                 private_key_count, public_key, private_key);
}

static CK_RV
base_C_WrapKey (CK_X_FUNCTION_LIST *self,
                CK_SESSION_HANDLE session,
                CK_MECHANISM_PTR mechanism,
                CK_OBJECT_HANDLE wrapping_key,
                CK_OBJECT_HANDLE key,
                CK_BYTE_PTR wrapped_key,
                CK_ULONG_PTR wrapped_key_len)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_WrapKey (session, mechanism, wrapping_key, key,
	                         wrapped_key, wrapped_key_len);
}

static CK_RV
base_C_UnwrapKey (CK_X_FUNCTION_LIST *self,
                  CK_SESSION_HANDLE session,
                  CK_MECHANISM_PTR mechanism,
                  CK_OBJECT_HANDLE unwrapping_key,
                  CK_BYTE_PTR wrapped_key,
                  CK_ULONG wrapped_key_len,
                  CK_ATTRIBUTE_PTR template,
                  CK_ULONG count,
                  CK_OBJECT_HANDLE_PTR key)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_UnwrapKey (session, mechanism, unwrapping_key, wrapped_key,
	                           wrapped_key_len, template, count, key);
}

static CK_RV
base_C_DeriveKey (CK_X_FUNCTION_LIST *self,
                  CK_SESSION_HANDLE session,
                  CK_MECHANISM_PTR mechanism,
                  CK_OBJECT_HANDLE base_key,
                  CK_ATTRIBUTE_PTR template,
                  CK_ULONG count,
                  CK_OBJECT_HANDLE_PTR key)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_DeriveKey (session, mechanism, base_key, template, count, key);
}

static CK_RV
base_C_SeedRandom (CK_X_FUNCTION_LIST *self,
                   CK_SESSION_HANDLE session,
                   CK_BYTE_PTR seed,
                   CK_ULONG seed_len)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_SeedRandom (session, seed, seed_len);
}

static CK_RV
base_C_GenerateRandom (CK_X_FUNCTION_LIST *self,
                       CK_SESSION_HANDLE session,
                       CK_BYTE_PTR random_data,
                       CK_ULONG random_len)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_GenerateRandom (session, random_data, random_len);
}

static CK_RV
base_C_WaitForSlotEvent (CK_X_FUNCTION_LIST *self,
                         CK_FLAGS flags,
                         CK_SLOT_ID_PTR slot_id,
                         CK_VOID_PTR reserved)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_WaitForSlotEvent (flags, slot_id, reserved);
}

void
p11_virtual_init (p11_virtual *virt,
                  CK_X_FUNCTION_LIST *funcs,
                  void *lower_module,
                  p11_destroyer lower_destroy)
{
	memcpy (virt, funcs, sizeof (CK_X_FUNCTION_LIST));
	virt->lower_module = lower_module;
	virt->lower_destroy = lower_destroy;
}

void
p11_virtual_uninit (p11_virtual *virt)
{
	if (virt->lower_destroy)
		(virt->lower_destroy) (virt->lower_module);
}

#ifdef WITH_FFI

typedef struct {
	const char *name;
	void *binding_function;
	void *stack_fallback;
	size_t virtual_offset;
	void *base_fallback;
	size_t module_offset;
	ffi_type *types[MAX_ARGS];
} FunctionInfo;

#define STRUCT_OFFSET(struct_type, member) \
	((size_t) ((unsigned char *) &((struct_type *) 0)->member))
#define STRUCT_MEMBER_P(struct_p, struct_offset) \
	((void *) ((unsigned char *) (struct_p) + (long) (struct_offset)))
#define STRUCT_MEMBER(member_type, struct_p, struct_offset) \
	(*(member_type*) STRUCT_MEMBER_P ((struct_p), (struct_offset)))

#define FUNCTION(name) \
	#name, binding_C_##name, \
	stack_C_##name, STRUCT_OFFSET (CK_X_FUNCTION_LIST, C_##name), \
	base_C_##name, STRUCT_OFFSET (CK_FUNCTION_LIST, C_##name)

static const FunctionInfo function_info[] = {
	{ FUNCTION (Initialize), { &ffi_type_pointer, NULL } },
	{ FUNCTION (Finalize), { &ffi_type_pointer, NULL } },
	{ FUNCTION (GetInfo), { &ffi_type_pointer, NULL } },
	{ FUNCTION (GetSlotList), { &ffi_type_uchar, &ffi_type_pointer, &ffi_type_pointer, NULL } },
	{ FUNCTION (GetSlotInfo), { &ffi_type_ulong, &ffi_type_pointer, NULL } },
	{ FUNCTION (GetTokenInfo), { &ffi_type_ulong, &ffi_type_pointer, NULL } },
	{ FUNCTION (WaitForSlotEvent), { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_pointer, NULL } },
	{ FUNCTION (GetMechanismList), { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_pointer, NULL } },
	{ FUNCTION (GetMechanismInfo), { &ffi_type_ulong, &ffi_type_ulong, &ffi_type_pointer, NULL } },
	{ FUNCTION (InitToken), { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, &ffi_type_pointer, NULL } },
	{ FUNCTION (InitPIN), { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, NULL } },
	{ FUNCTION (SetPIN), { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, NULL } },
	{ FUNCTION (OpenSession), { &ffi_type_ulong, &ffi_type_ulong, &ffi_type_pointer, &ffi_type_pointer, &ffi_type_pointer, NULL } },
	{ FUNCTION (CloseSession), { &ffi_type_ulong, NULL } },
	{ FUNCTION (CloseAllSessions), { &ffi_type_ulong, NULL } },
	{ FUNCTION (GetSessionInfo), { &ffi_type_ulong, &ffi_type_pointer, NULL } },
	{ FUNCTION (GetOperationState), { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_pointer, NULL } },
	{ FUNCTION (SetOperationState), { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, &ffi_type_ulong, &ffi_type_ulong, NULL } },
	{ FUNCTION (Login), { &ffi_type_ulong, &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, NULL } },
	{ FUNCTION (Logout), { &ffi_type_ulong, NULL } },
	{ FUNCTION (CreateObject), { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, &ffi_type_pointer, NULL } },
	{ FUNCTION (CopyObject), { &ffi_type_ulong, &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, &ffi_type_pointer, NULL } },
	{ FUNCTION (DestroyObject), { &ffi_type_ulong, &ffi_type_ulong, NULL } },
	{ FUNCTION (GetObjectSize), { &ffi_type_ulong, &ffi_type_ulong, &ffi_type_pointer, NULL } },
	{ FUNCTION (GetAttributeValue), { &ffi_type_ulong, &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, NULL } },
	{ FUNCTION (SetAttributeValue), { &ffi_type_ulong, &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, NULL } },
	{ FUNCTION (FindObjectsInit), { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, NULL } },
	{ FUNCTION (FindObjects), { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, &ffi_type_pointer, NULL } },
	{ FUNCTION (FindObjectsFinal), { &ffi_type_ulong, NULL } },
	{ FUNCTION (EncryptInit), { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, NULL } },
	{ FUNCTION (Encrypt), { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, &ffi_type_pointer, &ffi_type_pointer, NULL } },
	{ FUNCTION (EncryptUpdate), { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, &ffi_type_pointer, &ffi_type_pointer, NULL } },
	{ FUNCTION (EncryptFinal), { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_pointer, NULL } },
	{ FUNCTION (DecryptInit), { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, NULL } },
	{ FUNCTION (Decrypt), { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, &ffi_type_pointer, &ffi_type_pointer, NULL } },
	{ FUNCTION (DecryptUpdate), { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, &ffi_type_pointer, &ffi_type_pointer, NULL } },
	{ FUNCTION (DecryptFinal), { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_pointer, NULL } },
	{ FUNCTION (DigestInit), { &ffi_type_ulong, &ffi_type_pointer, NULL } },
	{ FUNCTION (Digest), { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, &ffi_type_pointer, &ffi_type_pointer, NULL } },
	{ FUNCTION (DigestUpdate), { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, NULL } },
	{ FUNCTION (DigestKey), { &ffi_type_ulong, &ffi_type_ulong, NULL } },
	{ FUNCTION (DigestFinal), { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_pointer, NULL } },
	{ FUNCTION (SignInit), { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, NULL } },
	{ FUNCTION (Sign), { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, &ffi_type_pointer, &ffi_type_pointer, NULL } },
	{ FUNCTION (SignUpdate), { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, NULL } },
	{ FUNCTION (SignFinal), { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_pointer, NULL } },
	{ FUNCTION (SignRecoverInit), { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, NULL } },
	{ FUNCTION (SignRecover), { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, &ffi_type_pointer, &ffi_type_pointer, NULL } },
	{ FUNCTION (VerifyInit), { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, NULL } },
	{ FUNCTION (Verify), { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, NULL } },
	{ FUNCTION (VerifyUpdate), { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, NULL } },
	{ FUNCTION (VerifyFinal), { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, NULL } },
	{ FUNCTION (VerifyRecoverInit), { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, NULL } },
	{ FUNCTION (VerifyRecover), { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, &ffi_type_pointer, &ffi_type_pointer, NULL } },
	{ FUNCTION (DigestEncryptUpdate), { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, &ffi_type_pointer, &ffi_type_pointer, NULL } },
	{ FUNCTION (DecryptDigestUpdate), { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, &ffi_type_pointer, &ffi_type_pointer, NULL } },
	{ FUNCTION (SignEncryptUpdate), { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, &ffi_type_pointer, &ffi_type_pointer, NULL } },
	{ FUNCTION (DecryptVerifyUpdate), { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, &ffi_type_pointer, &ffi_type_pointer, NULL } },
	{ FUNCTION (GenerateKey), { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_pointer, &ffi_type_ulong, &ffi_type_pointer, NULL } },
	{ FUNCTION (GenerateKeyPair), { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_pointer, &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, &ffi_type_pointer, &ffi_type_pointer, NULL } },
	{ FUNCTION (WrapKey), { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, &ffi_type_ulong, &ffi_type_pointer, &ffi_type_pointer, NULL } },
	{ FUNCTION (UnwrapKey), { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, &ffi_type_pointer, NULL } },
	{ FUNCTION (DeriveKey), { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, &ffi_type_pointer, NULL } },
	{ FUNCTION (SeedRandom), { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, NULL } },
	{ FUNCTION (GenerateRandom), { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, NULL } },
	{ 0, }
};

static bool
lookup_fall_through (p11_virtual *virt,
                     const FunctionInfo *info,
                     void **bound_func)
{
	void *func;

	/*
	 * So the basic concept here is if we have only fall-through functions
	 * all the way down the stack, then we can just get the actual module
	 * function, so that calls go right through.
	 */

	func = STRUCT_MEMBER (void *, virt, info->virtual_offset);

	/*
	 * This is a fall-through function and the stack goes down further, so
	 * ask the next level down for the
	 */
	if (func == info->stack_fallback) {
		return lookup_fall_through (virt->lower_module, info, bound_func);

	/*
	 * This is a fall-through function at the bottom level of the stack
	 * so return the function from the module.
	 */
	} else if (func == info->base_fallback) {
		*bound_func = STRUCT_MEMBER (void *, virt->lower_module, info->module_offset);
		return true;
	}

	return false;
}

static bool
bind_ffi_closure (Wrapper *wrapper,
                  void *binding_data,
                  void *binding_func,
                  ffi_type **args,
                  void **bound_func)
{
	ffi_closure *clo;
	ffi_cif *cif;
	int nargs = 0;
	int i = 0;
	int ret;

	assert (wrapper->ffi_used < MAX_FUNCTIONS);
	cif = wrapper->ffi_cifs + wrapper->ffi_used;

	/* The number of arguments */
	for (i = 0, nargs = 0; args[i] != NULL; i++)
		nargs++;

	assert (nargs <= MAX_ARGS);

	/*
	 * The failures here are unexpected conditions. There's a chance they
	 * might occur on other esoteric platforms, so we take a little
	 * extra care to print relevant debugging info, and return a status,
	 * so that we can get back useful debug info on platforms that we
	 * don't have access to.
	 */

	ret = ffi_prep_cif (cif, FFI_DEFAULT_ABI, nargs, &ffi_type_ulong, args);
	if (ret != FFI_OK) {
		p11_debug_precond ("ffi_prep_cif failed: %d\n", ret);
		return false;
	}

	clo = ffi_closure_alloc (sizeof (ffi_closure), bound_func);
	if (clo == NULL) {
		p11_debug_precond ("ffi_closure_alloc failed\n");
		return false;
	}

	ret = ffi_prep_closure_loc (clo, cif, binding_func, binding_data, *bound_func);
	if (ret != FFI_OK) {
		p11_debug_precond ("ffi_prep_closure_loc failed: %d\n", ret);
		return false;
	}

	wrapper->ffi_closures[wrapper->ffi_used] = clo;
	wrapper->ffi_used++;
	return true;
}

static bool
init_wrapper_funcs (Wrapper *wrapper)
{
	static const ffi_type *get_function_list_args[] = { &ffi_type_pointer, NULL };
	const FunctionInfo *info;
	CK_X_FUNCTION_LIST *over;
	void **bound;
	int i;

	/* Pointer to where our calls go */
	over = &wrapper->virt->funcs;

	for (i = 0; function_info[i].name != NULL; i++) {
		info = function_info + i;

		/* Address to where we're placing the bound function */
		bound = &STRUCT_MEMBER (void *, &wrapper->bound, info->module_offset);

		/*
		 * See if we can just shoot straight through to the module function
		 * without wrapping at all. If all the stacked virtual modules just
		 * fall through, then this returns the original module function.
		 */
		if (!lookup_fall_through (wrapper->virt, info, bound)) {
			if (!bind_ffi_closure (wrapper, over,
			                       info->binding_function,
			                       (ffi_type **)info->types, bound))
				return_val_if_reached (false);
		}
	}

	/* Always bind the C_GetFunctionList function itself */
	if (!bind_ffi_closure (wrapper, wrapper,
	                       binding_C_GetFunctionList,
	                       (ffi_type **)get_function_list_args,
	                       (void **)&wrapper->bound.C_GetFunctionList))
		return_val_if_reached (false);

	/*
	 * These functions are used as a marker to indicate whether this is
	 * one of our CK_FUNCTION_LIST_PTR sets of functions or not. These
	 * functions are defined to always have the same standard implementation
	 * in PKCS#11 2.x so we don't need to call through to the base for
	 * these guys.
	 */
	wrapper->bound.C_CancelFunction = short_C_CancelFunction;
	wrapper->bound.C_GetFunctionStatus = short_C_GetFunctionStatus;

	return true;
}

static void
uninit_wrapper_funcs (Wrapper *wrapper)
{
	int i;

	for (i = 0; i < wrapper->ffi_used; i++)
		ffi_closure_free (wrapper->ffi_closures[i]);
}

CK_FUNCTION_LIST *
p11_virtual_wrap (p11_virtual *virt,
                  p11_destroyer destroyer)
{
	Wrapper *wrapper;

	return_val_if_fail (virt != NULL, NULL);

	wrapper = calloc (1, sizeof (Wrapper));
	return_val_if_fail (wrapper != NULL, NULL);

	wrapper->virt = virt;
	wrapper->destroyer = destroyer;
	wrapper->bound.version.major = CRYPTOKI_VERSION_MAJOR;
	wrapper->bound.version.minor = CRYPTOKI_VERSION_MINOR;

	if (!init_wrapper_funcs (wrapper))
		return_val_if_reached (NULL);

	assert ((void *)wrapper == (void *)&wrapper->bound);
	assert (p11_virtual_is_wrapper (&wrapper->bound));
	assert (wrapper->bound.C_GetFunctionList != NULL);
	return &wrapper->bound;
}

bool
p11_virtual_can_wrap (void)
{
	return TRUE;
}

bool
p11_virtual_is_wrapper (CK_FUNCTION_LIST_PTR module)
{
	/*
	 * We use these functions as a marker to indicate whether this is
	 * one of our CK_FUNCTION_LIST_PTR sets of functions or not. These
	 * functions are defined to always have the same standard implementation
	 * in PKCS#11 2.x so we don't need to call through to the base for
	 * these guys.
	 */
	return (module->C_GetFunctionStatus == short_C_GetFunctionStatus &&
		module->C_CancelFunction == short_C_CancelFunction);
}

void
p11_virtual_unwrap (CK_FUNCTION_LIST_PTR module)
{
	Wrapper *wrapper;

	return_if_fail (p11_virtual_is_wrapper (module));

	/* The bound CK_FUNCTION_LIST_PTR sits at the front of Context */
	wrapper = (Wrapper *)module;

	/*
	 * Make sure that the CK_FUNCTION_LIST_PTR is invalid, and that
	 * p11_virtual_is_wrapper() recognizes this. This is in case the
	 * destroyer callback tries to do something fancy.
	 */
	memset (&wrapper->bound, 0xFE, sizeof (wrapper->bound));

	if (wrapper->destroyer)
		(wrapper->destroyer) (wrapper->virt);

	uninit_wrapper_funcs (wrapper);
	free (wrapper);
}

#else /* !WITH_FFI */

CK_FUNCTION_LIST *
p11_virtual_wrap (p11_virtual *virt,
                  p11_destroyer destroyer)
{
	assert_not_reached ();
}

bool
p11_virtual_can_wrap (void)
{
	return FALSE;
}

bool
p11_virtual_is_wrapper (CK_FUNCTION_LIST_PTR module)
{
	return FALSE;
}

void
p11_virtual_unwrap (CK_FUNCTION_LIST_PTR module)
{
	assert_not_reached ();
}

#endif /* !WITH_FFI */

CK_X_FUNCTION_LIST p11_virtual_stack = {
	{ CRYPTOKI_VERSION_MAJOR, CRYPTOKI_VERSION_MINOR },  /* version */
	stack_C_Initialize,
	stack_C_Finalize,
	stack_C_GetInfo,
	stack_C_GetSlotList,
	stack_C_GetSlotInfo,
	stack_C_GetTokenInfo,
	stack_C_GetMechanismList,
	stack_C_GetMechanismInfo,
	stack_C_InitToken,
	stack_C_InitPIN,
	stack_C_SetPIN,
	stack_C_OpenSession,
	stack_C_CloseSession,
	stack_C_CloseAllSessions,
	stack_C_GetSessionInfo,
	stack_C_GetOperationState,
	stack_C_SetOperationState,
	stack_C_Login,
	stack_C_Logout,
	stack_C_CreateObject,
	stack_C_CopyObject,
	stack_C_DestroyObject,
	stack_C_GetObjectSize,
	stack_C_GetAttributeValue,
	stack_C_SetAttributeValue,
	stack_C_FindObjectsInit,
	stack_C_FindObjects,
	stack_C_FindObjectsFinal,
	stack_C_EncryptInit,
	stack_C_Encrypt,
	stack_C_EncryptUpdate,
	stack_C_EncryptFinal,
	stack_C_DecryptInit,
	stack_C_Decrypt,
	stack_C_DecryptUpdate,
	stack_C_DecryptFinal,
	stack_C_DigestInit,
	stack_C_Digest,
	stack_C_DigestUpdate,
	stack_C_DigestKey,
	stack_C_DigestFinal,
	stack_C_SignInit,
	stack_C_Sign,
	stack_C_SignUpdate,
	stack_C_SignFinal,
	stack_C_SignRecoverInit,
	stack_C_SignRecover,
	stack_C_VerifyInit,
	stack_C_Verify,
	stack_C_VerifyUpdate,
	stack_C_VerifyFinal,
	stack_C_VerifyRecoverInit,
	stack_C_VerifyRecover,
	stack_C_DigestEncryptUpdate,
	stack_C_DecryptDigestUpdate,
	stack_C_SignEncryptUpdate,
	stack_C_DecryptVerifyUpdate,
	stack_C_GenerateKey,
	stack_C_GenerateKeyPair,
	stack_C_WrapKey,
	stack_C_UnwrapKey,
	stack_C_DeriveKey,
	stack_C_SeedRandom,
	stack_C_GenerateRandom,
	stack_C_WaitForSlotEvent
};

CK_X_FUNCTION_LIST p11_virtual_base = {
	{ CRYPTOKI_VERSION_MAJOR, CRYPTOKI_VERSION_MINOR },  /* version */
	base_C_Initialize,
	base_C_Finalize,
	base_C_GetInfo,
	base_C_GetSlotList,
	base_C_GetSlotInfo,
	base_C_GetTokenInfo,
	base_C_GetMechanismList,
	base_C_GetMechanismInfo,
	base_C_InitToken,
	base_C_InitPIN,
	base_C_SetPIN,
	base_C_OpenSession,
	base_C_CloseSession,
	base_C_CloseAllSessions,
	base_C_GetSessionInfo,
	base_C_GetOperationState,
	base_C_SetOperationState,
	base_C_Login,
	base_C_Logout,
	base_C_CreateObject,
	base_C_CopyObject,
	base_C_DestroyObject,
	base_C_GetObjectSize,
	base_C_GetAttributeValue,
	base_C_SetAttributeValue,
	base_C_FindObjectsInit,
	base_C_FindObjects,
	base_C_FindObjectsFinal,
	base_C_EncryptInit,
	base_C_Encrypt,
	base_C_EncryptUpdate,
	base_C_EncryptFinal,
	base_C_DecryptInit,
	base_C_Decrypt,
	base_C_DecryptUpdate,
	base_C_DecryptFinal,
	base_C_DigestInit,
	base_C_Digest,
	base_C_DigestUpdate,
	base_C_DigestKey,
	base_C_DigestFinal,
	base_C_SignInit,
	base_C_Sign,
	base_C_SignUpdate,
	base_C_SignFinal,
	base_C_SignRecoverInit,
	base_C_SignRecover,
	base_C_VerifyInit,
	base_C_Verify,
	base_C_VerifyUpdate,
	base_C_VerifyFinal,
	base_C_VerifyRecoverInit,
	base_C_VerifyRecover,
	base_C_DigestEncryptUpdate,
	base_C_DecryptDigestUpdate,
	base_C_SignEncryptUpdate,
	base_C_DecryptVerifyUpdate,
	base_C_GenerateKey,
	base_C_GenerateKeyPair,
	base_C_WrapKey,
	base_C_UnwrapKey,
	base_C_DeriveKey,
	base_C_SeedRandom,
	base_C_GenerateRandom,
	base_C_WaitForSlotEvent
};
