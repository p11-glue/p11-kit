/*
 * Copyright (c) 2023, Red Hat Inc.
 *
 * All rights reserved.
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
 * Author: Zoltan Fridrich <zfridric@redhat.com>
 */

#include "config.h"

#include "attrs.h"
#include "constants.h"
#include "debug.h"
#include "profile.h"

#include <stdlib.h>
#include <string.h>

#ifdef ENABLE_NLS
#include <libintl.h>
#define _(x) dgettext(PACKAGE_NAME, x)
#else
#define _(x) (x)
#endif

typedef struct {
	p11_virtual virt;
	CK_X_FUNCTION_LIST *lower;
	p11_destroyer destroyer;
        bool override;
        bool found;
	CK_OBJECT_HANDLE object;
	CK_PROFILE_ID *ids;
	CK_ULONG n_ids;
} ProfileData;

static bool
set_profile_object (ProfileData *profile,
		    CK_SESSION_HANDLE handle)
{
	CK_RV rv;
	CK_ULONG i, dummy;
	CK_OBJECT_HANDLE object = -2;

	for (i = 0; i < 3; ++i) {
		rv = profile->lower->C_GetObjectSize (profile->lower, handle, object, &dummy);
		if (rv == CKR_SESSION_HANDLE_INVALID ||
		    rv == CKR_OBJECT_HANDLE_INVALID) {
			profile->object = object;
			return true;
		}
		object -= 8192;
	}

	return false;
}

static CK_RV
profile_C_FindObjectsInit (CK_X_FUNCTION_LIST *self,
			   CK_SESSION_HANDLE handle,
			   CK_ATTRIBUTE_PTR template,
			   CK_ULONG count)
{
	ProfileData *profile = (ProfileData *)self;

	if (profile->override)
		return CKR_OPERATION_ACTIVE;

	if (template == NULL)
		return CKR_ARGUMENTS_BAD;

	if (count == 1 &&
	    template[0].type == CKA_CLASS &&
	    template[0].ulValueLen == sizeof (CK_OBJECT_CLASS) &&
	    *((CK_OBJECT_CLASS *)template[0].pValue) == CKO_PROFILE) {
		if (profile->object == 0 &&
		    !set_profile_object (profile, handle))
			return CKR_FUNCTION_FAILED;
		profile->override = true;
		profile->found = false;
		return CKR_OK;
	}

	return profile->lower->C_FindObjectsInit (profile->lower, handle, template, count);
}

static CK_RV
profile_C_FindObjects (CK_X_FUNCTION_LIST *self,
		       CK_SESSION_HANDLE handle,
		       CK_OBJECT_HANDLE_PTR objects,
		       CK_ULONG max_count,
		       CK_ULONG_PTR count)
{
	ProfileData *profile = (ProfileData *)self;

	if (profile->override) {
		if (profile->found) {
			*count = 0;
			return CKR_OK;
		}
		if (objects == NULL)
			return CKR_ARGUMENTS_BAD;
		if (max_count == 0)
			return CKR_HOST_MEMORY;
		objects[0] = profile->object;
		*count = 1;
		profile->found = true;
		return CKR_OK;
	}

	return profile->lower->C_FindObjects (profile->lower, handle, objects, max_count, count);
}

static CK_RV
profile_C_FindObjectsFinal (CK_X_FUNCTION_LIST *self,
			    CK_SESSION_HANDLE handle)
{
	ProfileData *profile = (ProfileData *)self;

	if (profile->override) {
		profile->override = false;
		profile->found = false;
		return CKR_OK;
	}

	return profile->lower->C_FindObjectsFinal (profile->lower, handle);
}

static CK_RV
profile_C_GetAttributeValue (CK_X_FUNCTION_LIST *self,
			     CK_SESSION_HANDLE hSession,
			     CK_OBJECT_HANDLE hObject,
			     CK_ATTRIBUTE_PTR pTemplate,
			     CK_ULONG ulCount)
{
	CK_RV rv = CKR_OK;
	CK_ULONG i, j;
	ProfileData *profile = (ProfileData *)self;

	if (hObject != profile->object)
		return profile->lower->C_GetAttributeValue (profile->lower,
			hSession, hObject, pTemplate, ulCount);

	for (i = 0, j = 0; i < ulCount; ++i) {
		if (pTemplate[i].type != CKA_PROFILE_ID || j >= profile->n_ids) {
			pTemplate[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
			rv = CKR_ATTRIBUTE_TYPE_INVALID;
		} else if (pTemplate[i].pValue == NULL_PTR) {
			pTemplate[i].ulValueLen = sizeof (CK_PROFILE_ID);
		} else if (pTemplate[i].ulValueLen >= sizeof (CK_PROFILE_ID)) {
			memcpy(pTemplate[i].pValue, profile->ids + j, sizeof (CK_PROFILE_ID));
			pTemplate[i].ulValueLen = sizeof (CK_PROFILE_ID);
			++j;
		} else {
			pTemplate[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
			rv = CKR_BUFFER_TOO_SMALL;
		}
	}

	return rv;
}

CK_RV
p11_profile_add_profile (p11_virtual *virt,
			 CK_PROFILE_ID *ids,
			 CK_ULONG n_ids)
{
	ProfileData *profile = (ProfileData *)virt;

	profile->ids = malloc (n_ids * sizeof (CK_PROFILE_ID));
	if (profile->ids == NULL)
		return CKR_HOST_MEMORY;

	memcpy (profile->ids, ids, n_ids * sizeof (CK_PROFILE_ID));
        profile->n_ids = n_ids;

	return CKR_OK;
}

void
p11_profile_release (void *data)
{
	ProfileData *profile = (ProfileData *)data;

	return_if_fail (data != NULL);
	p11_virtual_uninit (&profile->virt);
	free (profile->ids);
	free (profile);
}

p11_virtual *
p11_profile_subclass (p11_virtual *lower,
		      p11_destroyer destroyer)
{
	ProfileData *profile;
	CK_X_FUNCTION_LIST functions;

	profile = calloc (1, sizeof (ProfileData));
	return_val_if_fail (profile != NULL, NULL);

	memcpy (&functions, &p11_virtual_stack, sizeof (CK_X_FUNCTION_LIST));
	functions.C_FindObjectsInit = profile_C_FindObjectsInit;
	functions.C_FindObjects = profile_C_FindObjects;
	functions.C_FindObjectsFinal = profile_C_FindObjectsFinal;
	functions.C_GetAttributeValue = profile_C_GetAttributeValue;

	p11_virtual_init (&profile->virt, &functions, lower, destroyer);
	profile->lower = &lower->funcs;
	return &profile->virt;
}
