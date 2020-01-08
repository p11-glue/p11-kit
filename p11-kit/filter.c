/*
 * Copyright (c) 2016, Red Hat Inc.
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
 *
 * CONTRIBUTORS
 *  Daiki Ueno
 */

#include "config.h"

#include "attrs.h"
#include "buffer.h"
#include "constants.h"
#include "debug.h"
#include "filter.h"
#include "iter.h"
#include "message.h"
#include "p11-kit.h"
#include "virtual.h"

#include <sys/types.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdarg.h>

typedef struct {
	CK_SLOT_ID slot;
	const CK_TOKEN_INFO *token;
} FilterSlot;

typedef struct {
	p11_virtual virt;
	CK_X_FUNCTION_LIST *lower;
	p11_destroyer destroyer;
	p11_array *entries;
	bool allowed;
	bool initialized;
	FilterSlot *slots;
	CK_ULONG n_slots;
	CK_ULONG max_slots;
} FilterData;

extern int p11_match_uri_token_info (CK_TOKEN_INFO_PTR one,
				     CK_TOKEN_INFO_PTR two);

static const CK_TOKEN_INFO *
filter_match_token (FilterData *filter, CK_TOKEN_INFO *token)
{
	unsigned int i;

	for (i = 0; i < filter->entries->num; i++) {
		CK_TOKEN_INFO *entry = filter->entries->elem[i];
		bool matched = p11_match_uri_token_info (entry, token);

		if ((filter->allowed && matched) ||
		    (!filter->allowed && !matched))
			return entry;
	}

	return NULL;
}

static bool
filter_add_slot (FilterData *filter, CK_SLOT_ID slot, const CK_TOKEN_INFO *token)
{
	if (filter->n_slots >= filter->max_slots) {
		FilterSlot *slots;
		filter->max_slots = filter->max_slots * 2 + 1;
		slots = realloc (filter->slots,
				 filter->max_slots * sizeof (FilterSlot));
		return_val_if_fail (slots != NULL, false);
		filter->slots = slots;
	}
	filter->slots[filter->n_slots].slot = slot;
	filter->slots[filter->n_slots].token = token;
	filter->n_slots++;
	return true;
}

static CK_RV
filter_ensure (FilterData *filter)
{
	CK_FUNCTION_LIST *lower = NULL;
	P11KitIter *iter = NULL;
	CK_RV rv = CKR_OK;

	if (filter->slots != NULL) {
		free (filter->slots);
		filter->slots = NULL;
	}
	filter->n_slots = 0;
	filter->max_slots = 0;

	iter = p11_kit_iter_new (NULL,
				 P11_KIT_ITER_WITH_TOKENS |
				 P11_KIT_ITER_WITHOUT_OBJECTS);
	if (iter == NULL) {
		rv = CKR_HOST_MEMORY;
		goto out;
	}

	lower = p11_virtual_wrap (filter->virt.lower_module, NULL);
	if (lower == NULL) {
		rv = CKR_HOST_MEMORY;
		goto out;
	}

	p11_kit_iter_begin_with (iter, lower, 0, CK_INVALID_HANDLE);
	while (p11_kit_iter_next (iter) == CKR_OK) {
		CK_TOKEN_INFO *token;
		const CK_TOKEN_INFO *match;

		token = p11_kit_iter_get_token (iter);
		match = filter_match_token (filter, token);
		if (match) {
			CK_SLOT_ID slot;

			slot = p11_kit_iter_get_slot (iter);
			if (!filter_add_slot (filter, slot, match)) {
				rv = CKR_HOST_MEMORY;
				goto out;
			}
		}
	}

	rv = CKR_OK;
 out:
	p11_kit_iter_free (iter);
	if (lower)
		p11_virtual_unwrap (lower);
	return rv;
}

static void
filter_reinit (FilterData *filter)
{
	CK_RV rv;

	rv = filter_ensure (filter);
	if (rv == CKR_OK)
		filter->initialized = true;
	else {
		filter->initialized = false;
		p11_message ("filter cannot be initialized");
	}
}

static CK_RV
filter_C_Initialize (CK_X_FUNCTION_LIST *self,
		     CK_VOID_PTR pInitArgs)
{
	FilterData *filter = (FilterData *)self;
	CK_RV rv;

	rv = filter->lower->C_Initialize (filter->lower, pInitArgs);
	if (rv == CKR_OK)
		filter_reinit (filter);
	return rv;
}

static CK_RV
filter_C_Finalize (CK_X_FUNCTION_LIST *self,
		   CK_VOID_PTR pReserved)
{
	FilterData *filter = (FilterData *)self;

	free (filter->slots);
	filter->n_slots = 0;
	p11_array_clear (filter->entries);
	filter->initialized = false;
	filter->allowed = false;

	return filter->lower->C_Finalize (filter->lower, pReserved);
}

static CK_RV
filter_C_GetSlotList (CK_X_FUNCTION_LIST *self,
		      CK_BBOOL tokenPresent,
		      CK_SLOT_ID_PTR pSlotList,
		      CK_ULONG_PTR pulCount)
{
	FilterData *filter = (FilterData *)self;
	CK_ULONG count;

	if (pulCount == NULL)
		return CKR_ARGUMENTS_BAD;

	count = *pulCount;
	*pulCount = filter->n_slots;

	if (pSlotList == NULL)
		return CKR_OK;

	if (filter->n_slots > count)
		return CKR_BUFFER_TOO_SMALL;

	for (count = 0; count < filter->n_slots; count++)
		pSlotList[count] = count;
	*pulCount = filter->n_slots;
	return CKR_OK;
}

static CK_RV
filter_C_GetSlotInfo (CK_X_FUNCTION_LIST *self,
		      CK_SLOT_ID slotID,
		      CK_SLOT_INFO_PTR pInfo)
{
	FilterData *filter = (FilterData *)self;

	if (slotID >= filter->n_slots)
		return CKR_SLOT_ID_INVALID;

	return filter->lower->C_GetSlotInfo (filter->lower, filter->slots[slotID].slot, pInfo);
}

static CK_RV
filter_C_GetTokenInfo (CK_X_FUNCTION_LIST *self,
		       CK_SLOT_ID slotID,
		       CK_TOKEN_INFO_PTR pInfo)
{
	FilterData *filter = (FilterData *)self;

	if (slotID >= filter->n_slots)
		return CKR_SLOT_ID_INVALID;

	return filter->lower->C_GetTokenInfo (filter->lower, filter->slots[slotID].slot, pInfo);
}

static CK_RV
filter_C_GetMechanismList (CK_X_FUNCTION_LIST *self,
			   CK_SLOT_ID slotID,
			   CK_MECHANISM_TYPE_PTR pMechanismList,
			   CK_ULONG_PTR pulCount)
{
	FilterData *filter = (FilterData *)self;

	if (slotID >= filter->n_slots)
		return CKR_SLOT_ID_INVALID;

	return filter->lower->C_GetMechanismList (filter->lower,
						  filter->slots[slotID].slot,
						  pMechanismList,
						  pulCount);
}

static CK_RV
filter_C_GetMechanismInfo (CK_X_FUNCTION_LIST *self,
			   CK_SLOT_ID slotID,
			   CK_MECHANISM_TYPE type,
			   CK_MECHANISM_INFO_PTR pInfo)
{
	FilterData *filter = (FilterData *)self;

	if (slotID >= filter->n_slots)
		return CKR_SLOT_ID_INVALID;

	return filter->lower->C_GetMechanismInfo (filter->lower,
						  filter->slots[slotID].slot,
						  type,
						  pInfo);
}

static CK_RV
filter_C_InitToken (CK_X_FUNCTION_LIST *self,
		    CK_SLOT_ID slotID,
		    CK_UTF8CHAR_PTR pPin,
		    CK_ULONG ulPinLen,
		    CK_UTF8CHAR_PTR pLabel)
{
	FilterData *filter = (FilterData *)self;

	if (slotID >= filter->n_slots)
		return CKR_SLOT_ID_INVALID;

	if (filter->slots[slotID].token->flags & CKF_WRITE_PROTECTED)
		return CKR_TOKEN_WRITE_PROTECTED;

	return filter->lower->C_InitToken (filter->lower, filter->slots[slotID].slot,
					   pPin, ulPinLen, pLabel);
}

static CK_RV
filter_C_WaitForSlotEvent (CK_X_FUNCTION_LIST *self,
			   CK_FLAGS flags,
			   CK_SLOT_ID_PTR pSlot,
			   CK_VOID_PTR pReserved)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV
filter_C_OpenSession (CK_X_FUNCTION_LIST *self,
		      CK_SLOT_ID slotID,
		      CK_FLAGS flags,
		      CK_VOID_PTR pApplication,
		      CK_NOTIFY Notify,
		      CK_SESSION_HANDLE_PTR phSession)
{
	FilterData *filter = (FilterData *)self;

	if (slotID >= filter->n_slots)
		return CKR_SLOT_ID_INVALID;

	if ((flags & CKF_RW_SESSION) &&
	    (filter->slots[slotID].token->flags & CKF_WRITE_PROTECTED))
		return CKR_TOKEN_WRITE_PROTECTED;

	return filter->lower->C_OpenSession (filter->lower,
					     filter->slots[slotID].slot, flags,
					     pApplication, Notify,
					     phSession);
}

static CK_RV
filter_C_CloseAllSessions (CK_X_FUNCTION_LIST *self,
			   CK_SLOT_ID slotID)
{
	FilterData *filter = (FilterData *)self;

	if (slotID >= filter->n_slots)
		return CKR_SLOT_ID_INVALID;

	return filter->lower->C_CloseAllSessions (filter->lower,
						  filter->slots[slotID].slot);
}

void
p11_filter_release (void *data)
{
	FilterData *filter = (FilterData *)data;

	return_if_fail (data != NULL);
	p11_virtual_uninit (&filter->virt);
	p11_array_free (filter->entries);
	free (filter);
}

p11_virtual *
p11_filter_subclass (p11_virtual *lower,
		     p11_destroyer destroyer)
{
	FilterData *filter;
	CK_X_FUNCTION_LIST functions;

	filter = calloc (1, sizeof (FilterData));
	return_val_if_fail (filter != NULL, NULL);

	memcpy (&functions, &p11_virtual_stack, sizeof (CK_X_FUNCTION_LIST));
	functions.C_Initialize = filter_C_Initialize;
	functions.C_Finalize = filter_C_Finalize;
	functions.C_GetSlotList = filter_C_GetSlotList;
	functions.C_GetSlotInfo = filter_C_GetSlotInfo;
	functions.C_GetTokenInfo = filter_C_GetTokenInfo;
	functions.C_GetMechanismList = filter_C_GetMechanismList;
	functions.C_GetMechanismInfo = filter_C_GetMechanismInfo;
	functions.C_InitToken = filter_C_InitToken;
	functions.C_WaitForSlotEvent = filter_C_WaitForSlotEvent;
	functions.C_OpenSession = filter_C_OpenSession;
	functions.C_CloseAllSessions = filter_C_CloseAllSessions;

	p11_virtual_init (&filter->virt, &functions, lower, destroyer);
	filter->lower = &lower->funcs;
	filter->entries = p11_array_new ((p11_destroyer)free);
	return &filter->virt;
}

void
p11_filter_allow_token (p11_virtual *virt,
			CK_TOKEN_INFO *token)
{
	FilterData *filter = (FilterData *)virt;
	CK_TOKEN_INFO *token_copy;

	return_if_fail (filter->allowed || filter->entries->num == 0);
	filter->allowed = true;

	token_copy = memdup (token, sizeof (CK_TOKEN_INFO));
	return_if_fail (token_copy != NULL);

	if (!p11_array_push (filter->entries, token_copy))
		return_if_reached ();

	if (filter->initialized)
		filter_reinit (filter);
}

void
p11_filter_deny_token (p11_virtual *virt,
		       CK_TOKEN_INFO *token)
{
	FilterData *filter = (FilterData *)virt;
	CK_TOKEN_INFO *token_copy;

	return_if_fail (!filter->allowed || filter->entries->num == 0);
	filter->allowed = false;

	token_copy = memdup (token, sizeof (CK_TOKEN_INFO));
	return_if_fail (token_copy != NULL);

	if (!p11_array_push (filter->entries, token_copy))
		return_if_reached ();

	if (filter->initialized)
		filter_reinit (filter);
}
