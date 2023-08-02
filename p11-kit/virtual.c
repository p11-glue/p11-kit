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

/*
 * Work around for <ffitarget.h> on macOS 12 where it doesn't define
 * necessary platform-dependent macros, such as FFI_GO_CLOSURES.
 */
#ifdef __APPLE__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wundef"
#endif

#include "ffi.h"

#ifdef __APPLE__
#pragma clang diagnostic pop
#endif

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

	if (count == NULL) {
		*ret = CKR_ARGUMENTS_BAD;
		return;
	}

	if (interface_list == NULL) {
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

	if (interface == NULL) {
		*ret = CKR_ARGUMENTS_BAD;
		return;
	}

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
		return;
	}
	virtual_interfaces[0].pFunctionList = &wrapper->bound;
	*interface = &virtual_interfaces[0];
	*ret = CKR_OK;
}

#endif /* FFI_CLOSURES */

#include "p11-kit/virtual-stack-generated.h"
#include "p11-kit/virtual-base-generated.h"

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

#include "p11-kit/virtual-ffi-generated.h"

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
