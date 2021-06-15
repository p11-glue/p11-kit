/*
 * Copyright (C) 2008 Stefan Walter
 * Copyright (C) 2012-2023 Red Hat Inc.
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
 * Authors: Stef Walter <stefw@gnome.org>
 *          Jakub Jelen <jjelen@redhat.com>
 */

#include "config.h"

#include "compat.h"
#define P11_DEBUG_FLAG P11_DEBUG_LIB
#include "debug.h"
#include "library.h"
#include "virtual.h"
#include "virtual-fixed.h"

#include <assert.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#if defined(WITH_FFI) && WITH_FFI

/*
 * We use libffi to build closures. Note that even with libffi certain
 * platforms do not support using ffi_closure. In this case FFI_CLOSURES will
 * not be defined. This is checked in configure.ac
 */

/*
 * Since libffi uses shared memory to store that, releasing it
 * will cause issues on any other child or parent process that relies
 * on that. Don't release it.
 */
#define LIBFFI_FREE_CLOSURES 0

#include "ffi.h"
#endif

/* There are 90 functions in PKCS#11 3.0, with a maximum of 9 args */
#define MAX_FUNCTIONS 90
#define MAX_ARGS 11

typedef struct {
	/* This is first so we can cast between CK_FUNCTION_LIST, CK_FUNCTION_LIST_3_0* and Context* */
	CK_FUNCTION_LIST_3_0 bound;

	/* The PKCS#11 functions to call into */
	p11_virtual *virt;
	p11_destroyer destroyer;

#if defined(FFI_CLOSURES) && FFI_CLOSURES
	/* A list of our libffi built closures, for cleanup later */
	ffi_closure *ffi_closures[MAX_FUNCTIONS];
	ffi_cif ffi_cifs[MAX_FUNCTIONS];
	int ffi_used;
#endif	/* FFI_CLOSURES */

	/* The index in fixed_closures, or -1 when libffi closures are used */
	int fixed_index;
} Wrapper;

static CK_FUNCTION_LIST_3_0 *fixed_closures[P11_VIRTUAL_MAX_FIXED];
static CK_INTERFACE *fixed_interfaces[P11_VIRTUAL_MAX_FIXED];

static Wrapper          *create_fixed_wrapper   (p11_virtual         *virt,
                                                 size_t               index,
                                                 p11_destroyer        destroyer);
static CK_INTERFACE     *create_fixed_interface (CK_FUNCTION_LIST_3_0_PTR functions);
static CK_FUNCTION_LIST_3_0 *
                         p11_virtual_wrap_fixed (p11_virtual         *virt,
                                                 p11_destroyer        destroyer);
static void
                         p11_virtual_unwrap_fixed
                                                (CK_FUNCTION_LIST_PTR module);

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

#if defined(FFI_CLOSURES) && FFI_CLOSURES

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
		*list = (CK_FUNCTION_LIST_PTR)&wrapper->bound;
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

#define NUM_INTERFACES 1
CK_INTERFACE virtual_interfaces[NUM_INTERFACES] = {
        {"PKCS 11", NULL, 0}, /* 3.0 */
};

static void
binding_C_GetInterfaceList (ffi_cif *cif,
                            CK_RV *ret,
                            void* args[],
                            Wrapper *wrapper)
{
	CK_INTERFACE *interface_list = *(CK_INTERFACE_PTR *)args[0];
	CK_ULONG *count = *(CK_ULONG_PTR *)args[1];

	if (count == NULL)
		*ret = CKR_ARGUMENTS_BAD;

	if (interface_list == NULL) {
		if (*count < NUM_INTERFACES)
			*ret = CKR_BUFFER_TOO_SMALL;
		else
			*ret = CKR_OK;
		*count = NUM_INTERFACES;
		return;
	}
	memcpy (interface_list, virtual_interfaces, NUM_INTERFACES * sizeof(CK_INTERFACE));
	virtual_interfaces[0].pFunctionList = &wrapper->bound;
	*count = NUM_INTERFACES;
	*ret = CKR_OK;
}

static void
binding_C_GetInterface (ffi_cif *cif,
                        CK_RV *ret,
                        void* args[],
                        Wrapper *wrapper)
{
	CK_UTF8CHAR *interface_name = *(CK_UTF8CHAR_PTR *)args[0];
	CK_VERSION *version = *(CK_VERSION_PTR *)args[1];
	CK_INTERFACE_PTR *interface = *(CK_INTERFACE_PTR_PTR *)args[2];
	CK_FLAGS flags = *(CK_FLAGS *)args[3];

	if (interface_name == NULL) {
		virtual_interfaces[0].pFunctionList = &wrapper->bound;
		*interface = &virtual_interfaces[0];
		*ret = CKR_OK;
		return;
	}

	if (strcmp ((char *)interface_name, virtual_interfaces[0].pInterfaceName) != 0 ||
	    (version != NULL && (version->major != wrapper->bound.version.major ||
	                         version->minor != wrapper->bound.version.minor)) ||
	    ((flags & virtual_interfaces[0].flags) != flags)) {
		*ret = CKR_ARGUMENTS_BAD;
	}
	virtual_interfaces[0].pFunctionList = &wrapper->bound;
	*interface = &virtual_interfaces[0];
	*ret = CKR_OK;
}

static void
binding_C_LoginUser (ffi_cif *cif,
                     CK_RV *ret,
                     void *args[],
                     CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_LoginUser (funcs,
	                           *(CK_SESSION_HANDLE *)args[0],
	                           *(CK_USER_TYPE *)args[1],
	                           *(CK_UTF8CHAR_PTR *)args[2],
	                           *(CK_ULONG *)args[3],
	                           *(CK_UTF8CHAR_PTR *)args[4],
	                           *(CK_ULONG *)args[5]);
}

static void
binding_C_SessionCancel (ffi_cif *cif,
                         CK_RV *ret,
                         void *args[],
                         CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_SessionCancel (funcs,
	                               *(CK_SESSION_HANDLE *)args[0],
	                               *(CK_FLAGS *)args[1]);
}

static void
binding_C_MessageEncryptInit (ffi_cif *cif,
                              CK_RV *ret,
                              void *args[],
                              CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_MessageEncryptInit (funcs,
	                                    *(CK_SESSION_HANDLE *)args[0],
	                                    *(CK_MECHANISM_PTR *)args[1],
	                                    *(CK_OBJECT_HANDLE *)args[2]);
}

static void
binding_C_EncryptMessage (ffi_cif *cif,
                          CK_RV *ret,
                          void *args[],
                          CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_EncryptMessage (funcs,
	                                *(CK_SESSION_HANDLE *)args[0],
	                                *(CK_VOID_PTR *)args[1],
	                                *(CK_ULONG *)args[2],
	                                *(CK_BYTE_PTR *)args[3],
	                                *(CK_ULONG *)args[4],
	                                *(CK_BYTE_PTR *)args[5],
	                                *(CK_ULONG *)args[6],
	                                *(CK_BYTE_PTR *)args[7],
	                                *(CK_ULONG_PTR *)args[8]);
}

static void
binding_C_EncryptMessageBegin (ffi_cif *cif,
                               CK_RV *ret,
                               void *args[],
                               CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_EncryptMessageBegin (funcs,
	                                     *(CK_SESSION_HANDLE *)args[0],
	                                     *(CK_VOID_PTR *)args[1],
	                                     *(CK_ULONG *)args[2],
	                                     *(CK_BYTE_PTR *)args[3],
	                                     *(CK_ULONG *)args[4]);
}

static void
binding_C_EncryptMessageNext (ffi_cif *cif,
                              CK_RV *ret,
                              void *args[],
                              CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_EncryptMessageNext (funcs,
	                                    *(CK_SESSION_HANDLE *)args[0],
	                                    *(CK_VOID_PTR *)args[1],
	                                    *(CK_ULONG *)args[2],
	                                    *(CK_BYTE_PTR *)args[3],
	                                    *(CK_ULONG *)args[4],
	                                    *(CK_BYTE_PTR *)args[5],
	                                    *(CK_ULONG_PTR *)args[6],
	                                    *(CK_FLAGS *)args[7]);
}

static void
binding_C_MessageEncryptFinal (ffi_cif *cif,
                               CK_RV *ret,
                               void *args[],
                               CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_MessageEncryptFinal (funcs,
	                                     *(CK_SESSION_HANDLE *)args[0]);
}

static void
binding_C_MessageDecryptInit (ffi_cif *cif,
                              CK_RV *ret,
                              void *args[],
                              CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_MessageDecryptInit (funcs,
	                                    *(CK_SESSION_HANDLE *)args[0],
	                                    *(CK_MECHANISM_PTR *)args[1],
	                                    *(CK_OBJECT_HANDLE *)args[2]);
}

static void
binding_C_DecryptMessage (ffi_cif *cif,
                          CK_RV *ret,
                          void *args[],
                          CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_DecryptMessage (funcs,
	                                *(CK_SESSION_HANDLE *)args[0],
	                                *(CK_VOID_PTR *)args[1],
	                                *(CK_ULONG *)args[2],
	                                *(CK_BYTE_PTR *)args[3],
	                                *(CK_ULONG *)args[4],
	                                *(CK_BYTE_PTR *)args[5],
	                                *(CK_ULONG *)args[6],
	                                *(CK_BYTE_PTR *)args[7],
	                                *(CK_ULONG_PTR *)args[8]);
}

static void
binding_C_DecryptMessageBegin (ffi_cif *cif,
                               CK_RV *ret,
                               void *args[],
                               CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_DecryptMessageBegin (funcs,
	                                     *(CK_SESSION_HANDLE *)args[0],
	                                     *(CK_VOID_PTR *)args[1],
	                                     *(CK_ULONG *)args[2],
	                                     *(CK_BYTE_PTR *)args[3],
	                                     *(CK_ULONG *)args[4]);
}

static void
binding_C_DecryptMessageNext (ffi_cif *cif,
                              CK_RV *ret,
                              void *args[],
                              CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_DecryptMessageNext (funcs,
	                                    *(CK_SESSION_HANDLE *)args[0],
	                                    *(CK_VOID_PTR *)args[1],
	                                    *(CK_ULONG *)args[2],
	                                    *(CK_BYTE_PTR *)args[3],
	                                    *(CK_ULONG *)args[4],
	                                    *(CK_BYTE_PTR *)args[5],
	                                    *(CK_ULONG_PTR *)args[6],
	                                    *(CK_FLAGS *)args[7]);
}

static void
binding_C_MessageDecryptFinal (ffi_cif *cif,
                               CK_RV *ret,
                               void *args[],
                               CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_MessageDecryptFinal (funcs,
	                                     *(CK_SESSION_HANDLE *)args[0]);
}

static void
binding_C_MessageSignInit (ffi_cif *cif,
                           CK_RV *ret,
                           void *args[],
                           CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_MessageSignInit (funcs,
	                                 *(CK_SESSION_HANDLE *)args[0],
	                                 *(CK_MECHANISM_PTR *)args[1],
	                                 *(CK_OBJECT_HANDLE *)args[2]);
}

static void
binding_C_SignMessage (ffi_cif *cif,
                       CK_RV *ret,
                       void *args[],
                       CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_SignMessage (funcs,
	                             *(CK_SESSION_HANDLE *)args[0],
	                             *(CK_VOID_PTR *)args[1],
	                             *(CK_ULONG *)args[2],
	                             *(CK_BYTE_PTR *)args[3],
	                             *(CK_ULONG *)args[4],
	                             *(CK_BYTE_PTR *)args[5],
	                             *(CK_ULONG_PTR *)args[6]);
}

static void
binding_C_SignMessageBegin (ffi_cif *cif,
                            CK_RV *ret,
                            void *args[],
                            CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_SignMessageBegin (funcs,
	                                  *(CK_SESSION_HANDLE *)args[0],
	                                  *(CK_VOID_PTR *)args[1],
	                                  *(CK_ULONG *)args[2]);
}

static void
binding_C_SignMessageNext (ffi_cif *cif,
                           CK_RV *ret,
                           void *args[],
                           CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_SignMessageNext (funcs,
	                                 *(CK_SESSION_HANDLE *)args[0],
	                                 *(CK_VOID_PTR *)args[1],
	                                 *(CK_ULONG *)args[2],
	                                 *(CK_BYTE_PTR *)args[3],
	                                 *(CK_ULONG *)args[4],
	                                 *(CK_BYTE_PTR *)args[5],
	                                 *(CK_ULONG_PTR *)args[6]);
}

static void
binding_C_MessageSignFinal (ffi_cif *cif,
                            CK_RV *ret,
                            void *args[],
                            CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_MessageSignFinal (funcs,
	                                  *(CK_SESSION_HANDLE *)args[0]);
}

static void
binding_C_MessageVerifyInit (ffi_cif *cif,
                             CK_RV *ret,
                             void *args[],
                             CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_MessageVerifyInit (funcs,
	                                   *(CK_SESSION_HANDLE *)args[0],
	                                   *(CK_MECHANISM_PTR *)args[1],
	                                   *(CK_OBJECT_HANDLE *)args[2]);
}

static void
binding_C_VerifyMessage (ffi_cif *cif,
                         CK_RV *ret,
                         void *args[],
                         CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_VerifyMessage (funcs,
	                               *(CK_SESSION_HANDLE *)args[0],
	                               *(CK_VOID_PTR *)args[1],
	                               *(CK_ULONG *)args[2],
	                               *(CK_BYTE_PTR *)args[3],
	                               *(CK_ULONG *)args[4],
	                               *(CK_BYTE_PTR *)args[5],
	                               *(CK_ULONG *)args[6]);
}

static void
binding_C_VerifyMessageBegin (ffi_cif *cif,
                              CK_RV *ret,
                              void *args[],
                              CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_VerifyMessageBegin (funcs,
	                                    *(CK_SESSION_HANDLE *)args[0],
	                                    *(CK_VOID_PTR *)args[1],
	                                    *(CK_ULONG *)args[2]);
}

static void
binding_C_VerifyMessageNext (ffi_cif *cif,
                             CK_RV *ret,
                             void *args[],
                             CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_VerifyMessageNext (funcs,
	                                   *(CK_SESSION_HANDLE *)args[0],
	                                   *(CK_VOID_PTR *)args[1],
	                                   *(CK_ULONG *)args[2],
	                                   *(CK_BYTE_PTR *)args[3],
	                                   *(CK_ULONG *)args[4],
	                                   *(CK_BYTE_PTR *)args[5],
	                                   *(CK_ULONG *)args[6]);
}

static void
binding_C_MessageVerifyFinal (ffi_cif *cif,
                              CK_RV *ret,
                              void *args[],
                              CK_X_FUNCTION_LIST *funcs)
{
	*ret = funcs->C_MessageVerifyFinal (funcs,
	                                    *(CK_SESSION_HANDLE *)args[0]);
}

#endif /* FFI_CLOSURES */

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
stack_C_LoginUser (CK_X_FUNCTION_LIST *self,
                   CK_SESSION_HANDLE session,
                   CK_USER_TYPE user_type,
                   CK_UTF8CHAR_PTR pin,
                   CK_ULONG pin_len,
                   CK_UTF8CHAR_PTR username,
                   CK_ULONG username_len)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_X_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_LoginUser (funcs, session, user_type, pin, pin_len, username, username_len);
}

static CK_RV
stack_C_SessionCancel (CK_X_FUNCTION_LIST *self,
                       CK_SESSION_HANDLE session,
                       CK_FLAGS flags)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_X_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_SessionCancel (funcs, session, flags);
}

static CK_RV
stack_C_MessageEncryptInit (CK_X_FUNCTION_LIST *self,
                            CK_SESSION_HANDLE session,
                            CK_MECHANISM_PTR mechanism,
                            CK_OBJECT_HANDLE key)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_X_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_MessageEncryptInit (funcs, session, mechanism, key);
}

static CK_RV
stack_C_EncryptMessage (CK_X_FUNCTION_LIST *self,
                        CK_SESSION_HANDLE session,
                        CK_VOID_PTR parameter,
                        CK_ULONG parameter_len,
                        CK_BYTE_PTR associated_data,
                        CK_ULONG associated_data_len,
                        CK_BYTE_PTR plaintext,
                        CK_ULONG plaintext_len,
                        CK_BYTE_PTR ciphertext,
                        CK_ULONG_PTR ciphertext_len)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_X_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_EncryptMessage (funcs, session, parameter, parameter_len, associated_data, associated_data_len,
                                       plaintext, plaintext_len, ciphertext, ciphertext_len);
}

static CK_RV
stack_C_EncryptMessageBegin (CK_X_FUNCTION_LIST *self,
                             CK_SESSION_HANDLE session,
                             CK_VOID_PTR parameter,
                             CK_ULONG parameter_len,
                             CK_BYTE_PTR associated_data,
                             CK_ULONG associated_data_len)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_X_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_EncryptMessageBegin (funcs, session, parameter, parameter_len, associated_data, associated_data_len);
}

static CK_RV
stack_C_EncryptMessageNext (CK_X_FUNCTION_LIST *self,
                            CK_SESSION_HANDLE session,
                            CK_VOID_PTR parameter,
                            CK_ULONG parameter_len,
                            CK_BYTE_PTR plaintext_part,
                            CK_ULONG plaintext_part_len,
                            CK_BYTE_PTR ciphertext_part,
                            CK_ULONG_PTR ciphertext_part_len,
                            CK_FLAGS flags)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_X_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_EncryptMessageNext (funcs, session, parameter, parameter_len, plaintext_part, plaintext_part_len,
                                           ciphertext_part, ciphertext_part_len, flags);
}

static CK_RV
stack_C_MessageEncryptFinal (CK_X_FUNCTION_LIST *self,
                             CK_SESSION_HANDLE session)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_X_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_MessageEncryptFinal (funcs, session);
}

static CK_RV
stack_C_MessageDecryptInit (CK_X_FUNCTION_LIST *self,
                            CK_SESSION_HANDLE session,
                            CK_MECHANISM_PTR mechanism,
                            CK_OBJECT_HANDLE key)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_X_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_MessageDecryptInit (funcs, session, mechanism, key);
}

static CK_RV
stack_C_DecryptMessage (CK_X_FUNCTION_LIST *self,
                        CK_SESSION_HANDLE session,
                        CK_VOID_PTR parameter,
                        CK_ULONG parameter_len,
                        CK_BYTE_PTR associated_data,
                        CK_ULONG associated_data_len,
                        CK_BYTE_PTR ciphertext,
                        CK_ULONG ciphertext_len,
                        CK_BYTE_PTR plaintext,
                        CK_ULONG_PTR plaintext_len)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_X_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_DecryptMessage (funcs, session, parameter, parameter_len, associated_data, associated_data_len,
                                       ciphertext, ciphertext_len, plaintext, plaintext_len);
}

static CK_RV
stack_C_DecryptMessageBegin (CK_X_FUNCTION_LIST *self,
                             CK_SESSION_HANDLE session,
                             CK_VOID_PTR parameter,
                             CK_ULONG parameter_len,
                             CK_BYTE_PTR associated_data,
                             CK_ULONG associated_data_len)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_X_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_DecryptMessageBegin (funcs, session, parameter, parameter_len, associated_data, associated_data_len);
}

static CK_RV
stack_C_DecryptMessageNext (CK_X_FUNCTION_LIST *self,
                            CK_SESSION_HANDLE session,
                            CK_VOID_PTR parameter,
                            CK_ULONG parameter_len,
                            CK_BYTE_PTR ciphertext_part,
                            CK_ULONG ciphertext_part_len,
                            CK_BYTE_PTR plaintext_part,
                            CK_ULONG_PTR plaintext_part_len,
                            CK_FLAGS flags)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_X_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_DecryptMessageNext (funcs, session, parameter, parameter_len, ciphertext_part, ciphertext_part_len,
                                           plaintext_part, plaintext_part_len, flags);
}

static CK_RV
stack_C_MessageDecryptFinal (CK_X_FUNCTION_LIST *self,
                             CK_SESSION_HANDLE session)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_X_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_MessageDecryptFinal (funcs, session);
}

static CK_RV
stack_C_MessageSignInit (CK_X_FUNCTION_LIST *self,
                         CK_SESSION_HANDLE session,
                         CK_MECHANISM_PTR mechanism,
                         CK_OBJECT_HANDLE key)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_X_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_MessageSignInit (funcs, session, mechanism, key);
}

static CK_RV
stack_C_SignMessage (CK_X_FUNCTION_LIST *self,
                     CK_SESSION_HANDLE session,
                     CK_VOID_PTR parameter,
                     CK_ULONG parameter_len,
                     CK_BYTE_PTR data,
                     CK_ULONG data_len,
                     CK_BYTE_PTR signature,
                     CK_ULONG_PTR signature_len)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_X_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_SignMessage (funcs, session, parameter, parameter_len, data, data_len, signature, signature_len);
}

static CK_RV
stack_C_SignMessageBegin (CK_X_FUNCTION_LIST *self,
                          CK_SESSION_HANDLE session,
                          CK_VOID_PTR parameter,
                          CK_ULONG parameter_len)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_X_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_SignMessageBegin (funcs, session, parameter, parameter_len);
}

static CK_RV
stack_C_SignMessageNext (CK_X_FUNCTION_LIST *self,
                         CK_SESSION_HANDLE session,
                         CK_VOID_PTR parameter,
                         CK_ULONG parameter_len,
                         CK_BYTE_PTR data,
                         CK_ULONG data_len,
                         CK_BYTE_PTR signature,
                         CK_ULONG_PTR signature_len)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_X_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_SignMessageNext (funcs, session, parameter, parameter_len, data, data_len, signature, signature_len);
}

static CK_RV
stack_C_MessageSignFinal (CK_X_FUNCTION_LIST *self,
                          CK_SESSION_HANDLE session)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_X_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_MessageSignFinal (funcs, session);
}

static CK_RV
stack_C_MessageVerifyInit (CK_X_FUNCTION_LIST *self,
                           CK_SESSION_HANDLE session,
                           CK_MECHANISM_PTR mechanism,
                           CK_OBJECT_HANDLE key)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_X_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_MessageVerifyInit (funcs, session, mechanism, key);
}

static CK_RV
stack_C_VerifyMessage (CK_X_FUNCTION_LIST *self,
                       CK_SESSION_HANDLE session,
                       CK_VOID_PTR parameter,
                       CK_ULONG parameter_len,
                       CK_BYTE_PTR data,
                       CK_ULONG data_len,
                       CK_BYTE_PTR signature,
                       CK_ULONG signature_len)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_X_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_VerifyMessage (funcs, session, parameter, parameter_len, data, data_len,
	                               signature, signature_len);
}

static CK_RV
stack_C_VerifyMessageBegin (CK_X_FUNCTION_LIST *self,
                            CK_SESSION_HANDLE session,
                            CK_VOID_PTR parameter,
                            CK_ULONG parameter_len)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_X_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_VerifyMessageBegin (funcs, session, parameter, parameter_len);
}

static CK_RV
stack_C_VerifyMessageNext (CK_X_FUNCTION_LIST *self,
                           CK_SESSION_HANDLE session,
                           CK_VOID_PTR parameter,
                           CK_ULONG parameter_len,
                           CK_BYTE_PTR data,
                           CK_ULONG data_len,
                           CK_BYTE_PTR signature,
                           CK_ULONG signature_len)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_X_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_VerifyMessageNext (funcs, session, parameter, parameter_len, data, data_len,
                                           signature, signature_len);
}

static CK_RV
stack_C_MessageVerifyFinal (CK_X_FUNCTION_LIST *self,
                            CK_SESSION_HANDLE session)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_X_FUNCTION_LIST *funcs = virt->lower_module;
	return funcs->C_MessageVerifyFinal (funcs, session);
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

static CK_RV
base_C_LoginUser (CK_X_FUNCTION_LIST *self,
                  CK_SESSION_HANDLE session,
                  CK_USER_TYPE user_type,
                  CK_UTF8CHAR_PTR pin,
                  CK_ULONG pin_len,
                  CK_UTF8CHAR_PTR username,
                  CK_ULONG username_len)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_FUNCTION_LIST_3_0 *funcs = virt->lower_module;
	if (funcs->version.major < 3)
		return CKR_FUNCTION_NOT_SUPPORTED;
	return funcs->C_LoginUser (session, user_type, pin, pin_len, username, username_len);
}

static CK_RV
base_C_SessionCancel (CK_X_FUNCTION_LIST *self,
                      CK_SESSION_HANDLE session,
                      CK_FLAGS flags)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_FUNCTION_LIST_3_0 *funcs = virt->lower_module;
	if (funcs->version.major < 3)
		return CKR_FUNCTION_NOT_SUPPORTED;
	return funcs->C_SessionCancel (session, flags);
}

static CK_RV
base_C_MessageEncryptInit (CK_X_FUNCTION_LIST *self,
                           CK_SESSION_HANDLE session,
                           CK_MECHANISM_PTR mechanism,
                           CK_OBJECT_HANDLE key)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_FUNCTION_LIST_3_0 *funcs = virt->lower_module;
	if (funcs->version.major < 3)
		return CKR_FUNCTION_NOT_SUPPORTED;
	return funcs->C_MessageEncryptInit (session, mechanism, key);
}

static CK_RV
base_C_EncryptMessage (CK_X_FUNCTION_LIST *self,
                       CK_SESSION_HANDLE session,
                       CK_VOID_PTR parameter,
                       CK_ULONG parameter_len,
                       CK_BYTE_PTR associated_data,
                       CK_ULONG associated_data_len,
                       CK_BYTE_PTR plaintext,
                       CK_ULONG plaintext_len,
                       CK_BYTE_PTR ciphertext,
                       CK_ULONG_PTR ciphertext_len)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_FUNCTION_LIST_3_0 *funcs = virt->lower_module;

	if (funcs->version.major < 3)
		return CKR_FUNCTION_NOT_SUPPORTED;
	return funcs->C_EncryptMessage (session, parameter, parameter_len, associated_data, associated_data_len,
	                                plaintext, plaintext_len, ciphertext, ciphertext_len);
}

static CK_RV
base_C_EncryptMessageBegin (CK_X_FUNCTION_LIST *self,
                            CK_SESSION_HANDLE session,
                            CK_VOID_PTR parameter,
                            CK_ULONG parameter_len,
                            CK_BYTE_PTR associated_data,
                            CK_ULONG associated_data_len)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_FUNCTION_LIST_3_0 *funcs = virt->lower_module;
	if (funcs->version.major < 3)
		return CKR_FUNCTION_NOT_SUPPORTED;
	return funcs->C_EncryptMessageBegin (session, parameter, parameter_len,
	                                     associated_data, associated_data_len);
}

static CK_RV
base_C_EncryptMessageNext (CK_X_FUNCTION_LIST *self,
                           CK_SESSION_HANDLE session,
                           CK_VOID_PTR parameter,
                           CK_ULONG parameter_len,
                           CK_BYTE_PTR plaintext_part,
                           CK_ULONG plaintext_part_len,
                           CK_BYTE_PTR ciphertext_part,
                           CK_ULONG_PTR ciphertext_part_len,
                           CK_FLAGS flags)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_FUNCTION_LIST_3_0 *funcs = virt->lower_module;
	if (funcs->version.major < 3)
		return CKR_FUNCTION_NOT_SUPPORTED;
	return funcs->C_EncryptMessageNext (session, parameter, parameter_len, plaintext_part, plaintext_part_len,
	                                    ciphertext_part, ciphertext_part_len, flags);
}

static CK_RV
base_C_MessageEncryptFinal (CK_X_FUNCTION_LIST *self,
                            CK_SESSION_HANDLE session)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_FUNCTION_LIST_3_0 *funcs = virt->lower_module;
	if (funcs->version.major < 3)
		return CKR_FUNCTION_NOT_SUPPORTED;
	return funcs->C_MessageEncryptFinal (session);
}

static CK_RV
base_C_MessageDecryptInit (CK_X_FUNCTION_LIST *self,
                           CK_SESSION_HANDLE session,
                           CK_MECHANISM_PTR mechanism,
                           CK_OBJECT_HANDLE key)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_FUNCTION_LIST_3_0 *funcs = virt->lower_module;
	if (funcs->version.major < 3)
		return CKR_FUNCTION_NOT_SUPPORTED;
	return funcs->C_MessageDecryptInit (session, mechanism, key);
}

static CK_RV
base_C_DecryptMessage (CK_X_FUNCTION_LIST *self,
                       CK_SESSION_HANDLE session,
                       CK_VOID_PTR parameter,
                       CK_ULONG parameter_len,
                       CK_BYTE_PTR associated_data,
                       CK_ULONG associated_data_len,
                       CK_BYTE_PTR ciphertext,
                       CK_ULONG ciphertext_len,
                       CK_BYTE_PTR plaintext,
                       CK_ULONG_PTR plaintext_len)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_FUNCTION_LIST_3_0 *funcs = virt->lower_module;
	if (funcs->version.major < 3)
		return CKR_FUNCTION_NOT_SUPPORTED;
	return funcs->C_DecryptMessage (session, parameter, parameter_len, associated_data, associated_data_len,
	                                ciphertext, ciphertext_len, plaintext, plaintext_len);
}

static CK_RV
base_C_DecryptMessageBegin (CK_X_FUNCTION_LIST *self,
                            CK_SESSION_HANDLE session,
                            CK_VOID_PTR parameter,
                            CK_ULONG parameter_len,
                            CK_BYTE_PTR associated_data,
                            CK_ULONG associated_data_len)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_FUNCTION_LIST_3_0 *funcs = virt->lower_module;
	if (funcs->version.major < 3)
		return CKR_FUNCTION_NOT_SUPPORTED;
	return funcs->C_DecryptMessageBegin (session, parameter, parameter_len,
	                                     associated_data, associated_data_len);
}

static CK_RV
base_C_DecryptMessageNext (CK_X_FUNCTION_LIST *self,
                           CK_SESSION_HANDLE session,
                           CK_VOID_PTR parameter,
                           CK_ULONG parameter_len,
                           CK_BYTE_PTR ciphertext_part,
                           CK_ULONG ciphertext_part_len,
                           CK_BYTE_PTR plaintext_part,
                           CK_ULONG_PTR plaintext_part_len,
                           CK_FLAGS flags)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_FUNCTION_LIST_3_0 *funcs = virt->lower_module;
	if (funcs->version.major < 3)
		return CKR_FUNCTION_NOT_SUPPORTED;
	return funcs->C_DecryptMessageNext (session, parameter, parameter_len, ciphertext_part, ciphertext_part_len,
	                                    plaintext_part, plaintext_part_len, flags);
}

static CK_RV
base_C_MessageDecryptFinal (CK_X_FUNCTION_LIST *self,
                            CK_SESSION_HANDLE session)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_FUNCTION_LIST_3_0 *funcs = virt->lower_module;
	if (funcs->version.major < 3)
		return CKR_FUNCTION_NOT_SUPPORTED;
	return funcs->C_MessageDecryptFinal (session);
}

static CK_RV
base_C_MessageSignInit (CK_X_FUNCTION_LIST *self,
                        CK_SESSION_HANDLE session,
                        CK_MECHANISM_PTR mechanism,
                        CK_OBJECT_HANDLE key)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_FUNCTION_LIST_3_0 *funcs = virt->lower_module;
	if (funcs->version.major < 3)
		return CKR_FUNCTION_NOT_SUPPORTED;
	return funcs->C_MessageSignInit (session, mechanism, key);
}

static CK_RV
base_C_SignMessage (CK_X_FUNCTION_LIST *self,
                    CK_SESSION_HANDLE session,
                    CK_VOID_PTR parameter,
                    CK_ULONG parameter_len,
                    CK_BYTE_PTR data,
                    CK_ULONG data_len,
                    CK_BYTE_PTR signature,
                    CK_ULONG_PTR signature_len)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_FUNCTION_LIST_3_0 *funcs = virt->lower_module;
	if (funcs->version.major < 3)
		return CKR_FUNCTION_NOT_SUPPORTED;
	return funcs->C_SignMessage (session, parameter, parameter_len, data, data_len,
	                             signature, signature_len);
}

static CK_RV
base_C_SignMessageBegin (CK_X_FUNCTION_LIST *self,
                         CK_SESSION_HANDLE session,
                         CK_VOID_PTR parameter,
                         CK_ULONG parameter_len)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_FUNCTION_LIST_3_0 *funcs = virt->lower_module;
	if (funcs->version.major < 3)
		return CKR_FUNCTION_NOT_SUPPORTED;
	return funcs->C_SignMessageBegin (session, parameter, parameter_len);
}

static CK_RV
base_C_SignMessageNext (CK_X_FUNCTION_LIST *self,
                        CK_SESSION_HANDLE session,
                        CK_VOID_PTR parameter,
                        CK_ULONG parameter_len,
                        CK_BYTE_PTR data,
                        CK_ULONG data_len,
                        CK_BYTE_PTR signature,
                        CK_ULONG_PTR signature_len)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_FUNCTION_LIST_3_0 *funcs = virt->lower_module;
	if (funcs->version.major < 3)
		return CKR_FUNCTION_NOT_SUPPORTED;
	return funcs->C_SignMessageNext (session, parameter, parameter_len, data, data_len,
	                                 signature, signature_len);
}

static CK_RV
base_C_MessageSignFinal (CK_X_FUNCTION_LIST *self,
                         CK_SESSION_HANDLE session)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_FUNCTION_LIST_3_0 *funcs = virt->lower_module;
	return funcs->C_MessageSignFinal (session);
}

static CK_RV
base_C_MessageVerifyInit (CK_X_FUNCTION_LIST *self,
                          CK_SESSION_HANDLE session,
                          CK_MECHANISM_PTR mechanism,
                          CK_OBJECT_HANDLE key)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_FUNCTION_LIST_3_0 *funcs = virt->lower_module;
	if (funcs->version.major < 3)
		return CKR_FUNCTION_NOT_SUPPORTED;
	return funcs->C_MessageVerifyInit (session, mechanism, key);
}

static CK_RV
base_C_VerifyMessage (CK_X_FUNCTION_LIST *self,
                      CK_SESSION_HANDLE session,
                      CK_VOID_PTR parameter,
                      CK_ULONG parameter_len,
                      CK_BYTE_PTR data,
                      CK_ULONG data_len,
                      CK_BYTE_PTR signature,
                      CK_ULONG signature_len)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_FUNCTION_LIST_3_0 *funcs = virt->lower_module;
	if (funcs->version.major < 3)
		return CKR_FUNCTION_NOT_SUPPORTED;
	return funcs->C_VerifyMessage (session, parameter, parameter_len, data, data_len,
	                               signature, signature_len);
}

static CK_RV
base_C_VerifyMessageBegin (CK_X_FUNCTION_LIST *self,
                           CK_SESSION_HANDLE session,
                           CK_VOID_PTR parameter,
                           CK_ULONG parameter_len)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_FUNCTION_LIST_3_0 *funcs = virt->lower_module;
	if (funcs->version.major < 3)
		return CKR_FUNCTION_NOT_SUPPORTED;
	return funcs->C_VerifyMessageBegin (session, parameter, parameter_len);
}

static CK_RV
base_C_VerifyMessageNext (CK_X_FUNCTION_LIST *self,
                          CK_SESSION_HANDLE session,
                          CK_VOID_PTR parameter,
                          CK_ULONG parameter_len,
                          CK_BYTE_PTR data,
                          CK_ULONG data_len,
                          CK_BYTE_PTR signature,
                          CK_ULONG signature_len)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_FUNCTION_LIST_3_0 *funcs = virt->lower_module;
	if (funcs->version.major < 3)
		return CKR_FUNCTION_NOT_SUPPORTED;
	return funcs->C_VerifyMessageNext (session, parameter, parameter_len, data, data_len,
	                                   signature, signature_len);
}

static CK_RV
base_C_MessageVerifyFinal (CK_X_FUNCTION_LIST *self,
                           CK_SESSION_HANDLE session)
{
	p11_virtual *virt = (p11_virtual *)self;
	CK_FUNCTION_LIST_3_0 *funcs = virt->lower_module;
	if (funcs->version.major < 3)
		return CKR_FUNCTION_NOT_SUPPORTED;
	return funcs->C_MessageVerifyFinal (session);
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

typedef struct {
	const char *name;
	void *stack_fallback;
	size_t virtual_offset;
	void *base_fallback;
	size_t module_offset;
	CK_VERSION min_version;
} FunctionInfo;

#define STRUCT_OFFSET(struct_type, member) \
	((size_t) ((unsigned char *) &((struct_type *) 0)->member))
#define STRUCT_MEMBER_P(struct_p, struct_offset) \
	((void *) ((unsigned char *) (struct_p) + (long) (struct_offset)))
#define STRUCT_MEMBER(member_type, struct_p, struct_offset) \
	(*(member_type*) STRUCT_MEMBER_P ((struct_p), (struct_offset)))

#define FUNCTION(name) \
	#name, \
	stack_C_##name, STRUCT_OFFSET (CK_X_FUNCTION_LIST, C_##name), \
	base_C_##name, STRUCT_OFFSET (CK_FUNCTION_LIST_3_0, C_##name), {0, 0}

#define FUNCTION3(name) \
	#name, \
	stack_C_##name, STRUCT_OFFSET (CK_X_FUNCTION_LIST, C_##name), \
	base_C_##name, STRUCT_OFFSET (CK_FUNCTION_LIST_3_0, C_##name), {3, 0}

static const FunctionInfo function_info[] = {
        { FUNCTION (Initialize) },
        { FUNCTION (Finalize) },
        { FUNCTION (GetInfo) },
        { FUNCTION (GetSlotList) },
        { FUNCTION (GetSlotInfo) },
        { FUNCTION (GetTokenInfo) },
        { FUNCTION (GetMechanismList) },
        { FUNCTION (GetMechanismInfo) },
        { FUNCTION (InitToken) },
        { FUNCTION (InitPIN) },
        { FUNCTION (SetPIN) },
        { FUNCTION (OpenSession) },
        { FUNCTION (CloseSession) },
        { FUNCTION (CloseAllSessions) },
        { FUNCTION (GetSessionInfo) },
        { FUNCTION (GetOperationState) },
        { FUNCTION (SetOperationState) },
        { FUNCTION (Login) },
        { FUNCTION (Logout) },
        { FUNCTION (CreateObject) },
        { FUNCTION (CopyObject) },
        { FUNCTION (DestroyObject) },
        { FUNCTION (GetObjectSize) },
        { FUNCTION (GetAttributeValue) },
        { FUNCTION (SetAttributeValue) },
        { FUNCTION (FindObjectsInit) },
        { FUNCTION (FindObjects) },
        { FUNCTION (FindObjectsFinal) },
        { FUNCTION (EncryptInit) },
        { FUNCTION (Encrypt) },
        { FUNCTION (EncryptUpdate) },
        { FUNCTION (EncryptFinal) },
        { FUNCTION (DecryptInit) },
        { FUNCTION (Decrypt) },
        { FUNCTION (DecryptUpdate) },
        { FUNCTION (DecryptFinal) },
        { FUNCTION (DigestInit) },
        { FUNCTION (Digest) },
        { FUNCTION (DigestUpdate) },
        { FUNCTION (DigestKey) },
        { FUNCTION (DigestFinal) },
        { FUNCTION (SignInit) },
        { FUNCTION (Sign) },
        { FUNCTION (SignUpdate) },
        { FUNCTION (SignFinal) },
        { FUNCTION (SignRecoverInit) },
        { FUNCTION (SignRecover) },
        { FUNCTION (VerifyInit) },
        { FUNCTION (Verify) },
        { FUNCTION (VerifyUpdate) },
        { FUNCTION (VerifyFinal) },
        { FUNCTION (VerifyRecoverInit) },
        { FUNCTION (VerifyRecover) },
        { FUNCTION (DigestEncryptUpdate) },
        { FUNCTION (DecryptDigestUpdate) },
        { FUNCTION (SignEncryptUpdate) },
        { FUNCTION (DecryptVerifyUpdate) },
        { FUNCTION (GenerateKey) },
        { FUNCTION (GenerateKeyPair) },
        { FUNCTION (WrapKey) },
        { FUNCTION (UnwrapKey) },
        { FUNCTION (DeriveKey) },
        { FUNCTION (SeedRandom) },
        { FUNCTION (GenerateRandom) },
        { FUNCTION (WaitForSlotEvent) },
        /* PKCS #11 3.0 */
        { FUNCTION3 (LoginUser) },
        { FUNCTION3 (SessionCancel) },
        { FUNCTION3 (MessageEncryptInit) },
        { FUNCTION3 (EncryptMessage) },
        { FUNCTION3 (EncryptMessageBegin) },
        { FUNCTION3 (EncryptMessageNext) },
        { FUNCTION3 (MessageEncryptFinal) },
        { FUNCTION3 (MessageDecryptInit) },
        { FUNCTION3 (DecryptMessage) },
        { FUNCTION3 (DecryptMessageBegin) },
        { FUNCTION3 (DecryptMessageNext) },
        { FUNCTION3 (MessageDecryptFinal) },
        { FUNCTION3 (MessageSignInit) },
        { FUNCTION3 (SignMessage) },
        { FUNCTION3 (SignMessageBegin) },
        { FUNCTION3 (SignMessageNext) },
        { FUNCTION3 (MessageSignFinal) },
        { FUNCTION3 (MessageVerifyInit) },
        { FUNCTION3 (VerifyMessage) },
        { FUNCTION3 (VerifyMessageBegin) },
        { FUNCTION3 (VerifyMessageNext) },
        { FUNCTION3 (MessageVerifyFinal) },
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
		/* We can not point to 3.0 functions if the underlying module does not have them.
		 * Let the base_C_* functions handle this case */
		CK_X_FUNCTION_LIST *lower = virt->lower_module;
		if ((info->min_version.major > 0 || info->min_version.minor > 0) &&
		    (lower->version.major < info->min_version.major ||
		     (lower->version.major == info->min_version.major ||
		      lower->version.minor < info->min_version.minor)))
			return false;

		*bound_func = STRUCT_MEMBER (void *, virt->lower_module, info->module_offset);
		return true;
	}

	return false;
}

#if defined(FFI_CLOSURES) && FFI_CLOSURES
typedef struct {
	void *function;
	ffi_type *types[MAX_ARGS+1];
} BindingInfo;

static const BindingInfo binding_info[] = {
        { binding_C_Initialize, { &ffi_type_pointer, NULL } },
        { binding_C_Finalize, { &ffi_type_pointer, NULL } },
        { binding_C_GetInfo, { &ffi_type_pointer, NULL } },
        { binding_C_GetSlotList, { &ffi_type_uchar, &ffi_type_pointer, &ffi_type_pointer, NULL } },
        { binding_C_GetSlotInfo, { &ffi_type_ulong, &ffi_type_pointer, NULL } },
        { binding_C_GetTokenInfo, { &ffi_type_ulong, &ffi_type_pointer, NULL } },
        { binding_C_GetMechanismList, { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_pointer, NULL } },
        { binding_C_GetMechanismInfo, { &ffi_type_ulong, &ffi_type_ulong, &ffi_type_pointer, NULL } },
        { binding_C_InitToken, { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, &ffi_type_pointer, NULL } },
        { binding_C_InitPIN, { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, NULL } },
        { binding_C_SetPIN, { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, NULL } },
        { binding_C_OpenSession, { &ffi_type_ulong, &ffi_type_ulong, &ffi_type_pointer, &ffi_type_pointer, &ffi_type_pointer, NULL } },
        { binding_C_CloseSession, { &ffi_type_ulong, NULL } },
        { binding_C_CloseAllSessions, { &ffi_type_ulong, NULL } },
        { binding_C_GetSessionInfo, { &ffi_type_ulong, &ffi_type_pointer, NULL } },
        { binding_C_GetOperationState, { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_pointer, NULL } },
        { binding_C_SetOperationState, { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, &ffi_type_ulong, &ffi_type_ulong, NULL } },
        { binding_C_Login, { &ffi_type_ulong, &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, NULL } },
        { binding_C_Logout, { &ffi_type_ulong, NULL } },
        { binding_C_CreateObject, { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, &ffi_type_pointer, NULL } },
        { binding_C_CopyObject, { &ffi_type_ulong, &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, &ffi_type_pointer, NULL } },
        { binding_C_DestroyObject, { &ffi_type_ulong, &ffi_type_ulong, NULL } },
        { binding_C_GetObjectSize, { &ffi_type_ulong, &ffi_type_ulong, &ffi_type_pointer, NULL } },
        { binding_C_GetAttributeValue, { &ffi_type_ulong, &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, NULL } },
        { binding_C_SetAttributeValue, { &ffi_type_ulong, &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, NULL } },
        { binding_C_FindObjectsInit, { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, NULL } },
        { binding_C_FindObjects, { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, &ffi_type_pointer, NULL } },
        { binding_C_FindObjectsFinal, { &ffi_type_ulong, NULL } },
        { binding_C_EncryptInit, { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, NULL } },
        { binding_C_Encrypt, { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, &ffi_type_pointer, &ffi_type_pointer, NULL } },
        { binding_C_EncryptUpdate, { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, &ffi_type_pointer, &ffi_type_pointer, NULL } },
        { binding_C_EncryptFinal, { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_pointer, NULL } },
        { binding_C_DecryptInit, { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, NULL } },
        { binding_C_Decrypt, { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, &ffi_type_pointer, &ffi_type_pointer, NULL } },
        { binding_C_DecryptUpdate, { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, &ffi_type_pointer, &ffi_type_pointer, NULL } },
        { binding_C_DecryptFinal, { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_pointer, NULL } },
        { binding_C_DigestInit, { &ffi_type_ulong, &ffi_type_pointer, NULL } },
        { binding_C_Digest, { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, &ffi_type_pointer, &ffi_type_pointer, NULL } },
        { binding_C_DigestUpdate, { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, NULL } },
        { binding_C_DigestKey, { &ffi_type_ulong, &ffi_type_ulong, NULL } },
        { binding_C_DigestFinal, { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_pointer, NULL } },
        { binding_C_SignInit, { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, NULL } },
        { binding_C_Sign, { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, &ffi_type_pointer, &ffi_type_pointer, NULL } },
        { binding_C_SignUpdate, { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, NULL } },
        { binding_C_SignFinal, { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_pointer, NULL } },
        { binding_C_SignRecoverInit, { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, NULL } },
        { binding_C_SignRecover, { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, &ffi_type_pointer, &ffi_type_pointer, NULL } },
        { binding_C_VerifyInit, { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, NULL } },
        { binding_C_Verify, { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, NULL } },
        { binding_C_VerifyUpdate, { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, NULL } },
        { binding_C_VerifyFinal, { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, NULL } },
        { binding_C_VerifyRecoverInit, { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, NULL } },
        { binding_C_VerifyRecover, { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, &ffi_type_pointer, &ffi_type_pointer, NULL } },
        { binding_C_DigestEncryptUpdate, { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, &ffi_type_pointer, &ffi_type_pointer, NULL } },
        { binding_C_DecryptDigestUpdate, { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, &ffi_type_pointer, &ffi_type_pointer, NULL } },
        { binding_C_SignEncryptUpdate, { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, &ffi_type_pointer, &ffi_type_pointer, NULL } },
        { binding_C_DecryptVerifyUpdate, { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, &ffi_type_pointer, &ffi_type_pointer, NULL } },
        { binding_C_GenerateKey, { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_pointer, &ffi_type_ulong, &ffi_type_pointer, NULL } },
        { binding_C_GenerateKeyPair, { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_pointer, &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, &ffi_type_pointer, &ffi_type_pointer, NULL } },
        { binding_C_WrapKey, { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, &ffi_type_ulong, &ffi_type_pointer, &ffi_type_pointer, NULL } },
        { binding_C_UnwrapKey, { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, &ffi_type_pointer, NULL } },
        { binding_C_DeriveKey, { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, &ffi_type_pointer, NULL } },
        { binding_C_SeedRandom, { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, NULL } },
        { binding_C_GenerateRandom, { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, NULL } },
        { binding_C_WaitForSlotEvent, { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_pointer, NULL } },
        /* PKCS #11 3.0 */
        { binding_C_LoginUser, { &ffi_type_ulong, &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, NULL } },
        { binding_C_SessionCancel, { &ffi_type_pointer, &ffi_type_ulong, NULL } },
        { binding_C_MessageEncryptInit, { &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, NULL } },
        { binding_C_EncryptMessage, { &ffi_type_pointer, &ffi_type_pointer, &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, &ffi_type_pointer, &ffi_type_pointer, NULL } },
        { binding_C_EncryptMessageBegin, { &ffi_type_pointer, &ffi_type_pointer, &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, NULL } },
        { binding_C_EncryptMessageNext, { &ffi_type_pointer, &ffi_type_pointer, &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, NULL } },
        { binding_C_MessageEncryptFinal, { &ffi_type_pointer, NULL } },
        { binding_C_MessageDecryptInit, { &ffi_type_pointer, &ffi_type_pointer, &ffi_type_ulong, NULL } },
        { binding_C_DecryptMessage, { &ffi_type_pointer, &ffi_type_pointer, &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, &ffi_type_pointer, &ffi_type_pointer, NULL } },
        { binding_C_DecryptMessageBegin, { &ffi_type_pointer, &ffi_type_pointer, &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, NULL } },
        { binding_C_DecryptMessageNext, { &ffi_type_pointer, &ffi_type_pointer, &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, &ffi_type_pointer, &ffi_type_pointer, &ffi_type_ulong, NULL } },
        { binding_C_MessageDecryptFinal, { &ffi_type_pointer, NULL } },
        { binding_C_MessageSignInit, { &ffi_type_pointer, &ffi_type_pointer, &ffi_type_ulong, NULL } },
        { binding_C_SignMessage, { &ffi_type_pointer, &ffi_type_pointer, &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, &ffi_type_pointer, &ffi_type_pointer, NULL } },
        { binding_C_SignMessageBegin, { &ffi_type_pointer, &ffi_type_pointer, &ffi_type_ulong, NULL } },
        { binding_C_SignMessageNext, { &ffi_type_pointer, &ffi_type_pointer, &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, &ffi_type_pointer, &ffi_type_pointer, NULL } },
        { binding_C_MessageSignFinal, { &ffi_type_pointer, NULL } },
        { binding_C_MessageVerifyInit, { &ffi_type_pointer, &ffi_type_pointer, &ffi_type_ulong, NULL } },
        { binding_C_VerifyMessage, { &ffi_type_pointer, &ffi_type_pointer, &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, NULL } },
        { binding_C_VerifyMessageBegin, { &ffi_type_pointer, &ffi_type_pointer, &ffi_type_ulong, NULL } },
        { binding_C_VerifyMessageNext, { &ffi_type_pointer, &ffi_type_pointer, &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, &ffi_type_pointer, &ffi_type_ulong, NULL } },
        { binding_C_MessageVerifyFinal, { &ffi_type_pointer, NULL } },
        { 0, }
};


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
	static const ffi_type *get_interface_list_args[] = { &ffi_type_pointer, &ffi_type_pointer, NULL };
	static const ffi_type *get_interface_args[] = { &ffi_type_pointer, &ffi_type_pointer, &ffi_type_pointer, &ffi_type_ulong, NULL };
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
			const BindingInfo *binding = binding_info + i;
			if (!bind_ffi_closure (wrapper, over,
			                       binding->function,
			                       (ffi_type **)binding->types, bound))
				return false;
		}
	}

	/* Always bind the C_GetFunctionList function itself */
	if (!bind_ffi_closure (wrapper, wrapper,
	                       binding_C_GetFunctionList,
	                       (ffi_type **)get_function_list_args,
	                       (void **)&wrapper->bound.C_GetFunctionList))
		return false;
	/* The same for Interfaces */
	if (!bind_ffi_closure (wrapper, wrapper,
	                       binding_C_GetInterfaceList,
	                       (ffi_type **)get_interface_list_args,
	                       (void **)&wrapper->bound.C_GetInterfaceList))
		return false;
	if (!bind_ffi_closure (wrapper, wrapper,
	                       binding_C_GetInterface,
	                       (ffi_type **)get_interface_args,
	                       (void **)&wrapper->bound.C_GetInterface))
		return false;

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

#if defined(LIBFFI_FREE_CLOSURES) && LIBFFI_FREE_CLOSURES
static void
uninit_wrapper_funcs (Wrapper *wrapper)
{
	int i;

	for (i = 0; i < wrapper->ffi_used; i++)
		ffi_closure_free (wrapper->ffi_closures[i]);
}
#endif

CK_FUNCTION_LIST *
p11_virtual_wrap (p11_virtual *virt,
                  p11_destroyer destroyer)
{
	Wrapper *wrapper;
	CK_FUNCTION_LIST *result;

	return_val_if_fail (virt != NULL, NULL);

	result = (CK_FUNCTION_LIST *)p11_virtual_wrap_fixed (virt, destroyer);
	if (result)
		return result;

	wrapper = calloc (1, sizeof (Wrapper));
	return_val_if_fail (wrapper != NULL, NULL);

	wrapper->virt = virt;
	wrapper->destroyer = destroyer;
	wrapper->bound.version.major = CRYPTOKI_VERSION_MAJOR;
	wrapper->bound.version.minor = CRYPTOKI_VERSION_MINOR;
	wrapper->fixed_index = -1;

	if (!init_wrapper_funcs (wrapper)) {
		free (wrapper);
		return_val_if_reached (NULL);
	}

	assert ((void *)wrapper == (void *)&wrapper->bound);
	assert (p11_virtual_is_wrapper ((CK_FUNCTION_LIST_PTR)&wrapper->bound));
	assert (wrapper->bound.C_GetFunctionList != NULL);
	return (CK_FUNCTION_LIST *)&wrapper->bound;
}

#else /* !FFI_CLOSURES */

CK_FUNCTION_LIST *
p11_virtual_wrap (p11_virtual *virt,
                  p11_destroyer destroyer)
{
	CK_FUNCTION_LIST *result;

	result = (CK_FUNCTION_LIST *)p11_virtual_wrap_fixed (virt, destroyer);
	return_val_if_fail (result != NULL, NULL);
	return result;
}

#endif /* !FFI_CLOSURES */

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

	/* The bound CK_FUNCTION_LIST_3_0 sits at the front of Wrapper */
	wrapper = (Wrapper *)module;

	if (wrapper->fixed_index >= 0)
		p11_virtual_unwrap_fixed (module);

	/*
	 * Make sure that the CK_FUNCTION_LIST_3_0_PTR is invalid, and that
	 * p11_virtual_is_wrapper() recognizes this. This is in case the
	 * destroyer callback tries to do something fancy.
	 */
	memset (&wrapper->bound, 0xFE, sizeof (wrapper->bound));

	if (wrapper->destroyer)
		(wrapper->destroyer) (wrapper->virt);

#if defined(LIBFFI_FREE_CLOSURES) && LIBFFI_FREE_CLOSURES
	uninit_wrapper_funcs (wrapper);
#endif
	free (wrapper);
}

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
	stack_C_WaitForSlotEvent,
	/* PKCS #11 3.0 */
	stack_C_LoginUser,
	stack_C_SessionCancel,
	stack_C_MessageEncryptInit,
	stack_C_EncryptMessage,
	stack_C_EncryptMessageBegin,
	stack_C_EncryptMessageNext,
	stack_C_MessageEncryptFinal,
	stack_C_MessageDecryptInit,
	stack_C_DecryptMessage,
	stack_C_DecryptMessageBegin,
	stack_C_DecryptMessageNext,
	stack_C_MessageDecryptFinal,
	stack_C_MessageSignInit,
	stack_C_SignMessage,
	stack_C_SignMessageBegin,
	stack_C_SignMessageNext,
	stack_C_MessageSignFinal,
	stack_C_MessageVerifyInit,
	stack_C_VerifyMessage,
	stack_C_VerifyMessageBegin,
	stack_C_VerifyMessageNext,
	stack_C_MessageVerifyFinal
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
	base_C_WaitForSlotEvent,
	/* PKCS #11 3.0 */
	base_C_LoginUser,
	base_C_SessionCancel,
	base_C_MessageEncryptInit,
	base_C_EncryptMessage,
	base_C_EncryptMessageBegin,
	base_C_EncryptMessageNext,
	base_C_MessageEncryptFinal,
	base_C_MessageDecryptInit,
	base_C_DecryptMessage,
	base_C_DecryptMessageBegin,
	base_C_DecryptMessageNext,
	base_C_MessageDecryptFinal,
	base_C_MessageSignInit,
	base_C_SignMessage,
	base_C_SignMessageBegin,
	base_C_SignMessageNext,
	base_C_MessageSignFinal,
	base_C_MessageVerifyInit,
	base_C_VerifyMessage,
	base_C_VerifyMessageBegin,
	base_C_VerifyMessageNext,
	base_C_MessageVerifyFinal
};

#include "p11-kit/virtual-fixed-generated.h"

static CK_FUNCTION_LIST_3_0 *
p11_virtual_wrap_fixed (p11_virtual *virt,
			p11_destroyer destroyer)
{
	CK_FUNCTION_LIST_3_0 *result = NULL;
	size_t i;

	p11_mutex_lock (&p11_virtual_mutex);
	for (i = 0; i < P11_VIRTUAL_MAX_FIXED; i++) {
		if (fixed_closures[i] == NULL) {
			Wrapper *wrapper;

			wrapper = create_fixed_wrapper (virt, i, destroyer);
			if (wrapper) {
				CK_INTERFACE *interface;

				result = &wrapper->bound;
				fixed_closures[i] = result;
				interface = create_fixed_interface (result);
				return_val_if_fail (interface != NULL, NULL);
				fixed_interfaces[i] = interface;
			}
			break;
		}
	}
	p11_mutex_unlock (&p11_virtual_mutex);

	return result;
}

static void
p11_virtual_unwrap_fixed (CK_FUNCTION_LIST_PTR module)
{
	size_t i;

	p11_mutex_lock (&p11_virtual_mutex);
	for (i = 0; i < P11_VIRTUAL_MAX_FIXED; i++) {
		if (fixed_closures[i] == (CK_FUNCTION_LIST_3_0 *)module) {
			fixed_closures[i] = NULL;
			free (fixed_interfaces[i]);
			break;
		}
	}
	p11_mutex_unlock (&p11_virtual_mutex);
}

static void
init_wrapper_funcs_fixed (Wrapper *wrapper, CK_FUNCTION_LIST_3_0 *fixed)
{
       const FunctionInfo *info;
       void **bound_to, **bound_from;
       int i;

       for (i = 0; function_info[i].name != NULL; i++) {
               info = function_info + i;

               /* Address to where we're placing the bound function */
               bound_to = &STRUCT_MEMBER (void *, &wrapper->bound, info->module_offset);
               bound_from = &STRUCT_MEMBER (void *, fixed, info->module_offset);

               /*
                * See if we can just shoot straight through to the module function
                * without wrapping at all. If all the stacked virtual modules just
                * fall through, then this returns the original module function.
                */
               if (!lookup_fall_through (wrapper->virt, info, bound_to))
                       *bound_to = *bound_from;
       }

       /* Always bind the C_GetFunctionList function itself */
       wrapper->bound.C_GetFunctionList = fixed->C_GetFunctionList;

       /* Same for the interfaces */
       wrapper->bound.C_GetInterfaceList = fixed->C_GetInterfaceList;
       wrapper->bound.C_GetInterface = fixed->C_GetInterface;

       /*
        * These functions are used as a marker to indicate whether this is
        * one of our CK_FUNCTION_LIST_PTR sets of functions or not. These
        * functions are defined to always have the same standard implementation
        * in PKCS#11 2.x so we don't need to call through to the base for
        * these guys.
        */
       wrapper->bound.C_CancelFunction = short_C_CancelFunction;
       wrapper->bound.C_GetFunctionStatus = short_C_GetFunctionStatus;
}

static Wrapper *
create_fixed_wrapper (p11_virtual *virt,
		      size_t index,
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
       wrapper->fixed_index = index;

       init_wrapper_funcs_fixed (wrapper, &p11_virtual_fixed[index]);

       assert ((void *)wrapper == (void *)&wrapper->bound);
       assert (p11_virtual_is_wrapper ((CK_FUNCTION_LIST_PTR)&wrapper->bound));
       assert (wrapper->bound.C_GetFunctionList != NULL);
       assert (wrapper->bound.C_GetInterfaceList != NULL);
       assert (wrapper->bound.C_GetInterface != NULL);
       return wrapper;
}

static CK_INTERFACE *
create_fixed_interface (CK_FUNCTION_LIST_3_0_PTR functions)
{
	CK_INTERFACE *interface;

	return_val_if_fail (functions != NULL, NULL);

	interface = calloc (1, sizeof (CK_INTERFACE));
	return_val_if_fail (interface != NULL, NULL);

	interface->pFunctionList = functions;
	interface->pInterfaceName = "PKCS 11";
	interface->flags = 0;

	return interface;
}
