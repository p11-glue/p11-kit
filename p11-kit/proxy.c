/*
 * Copyright (C) 2008 Stefan Walter
 * Copyright (C) 2011 Collabora Ltd.
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

#include "compat.h"
#define P11_DEBUG_FLAG P11_DEBUG_PROXY
#define CRYPTOKI_EXPORTS

#include "debug.h"
#include "dict.h"
#include "library.h"
#include "message.h"
#include "modules.h"
#include "pkcs11.h"
#include "pkcs11x.h"
#include "p11-kit.h"
#include "private.h"
#include "proxy.h"
#include "virtual.h"

#include <sys/types.h>
#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/* Start wrap slots slightly higher for testing */
#define MAPPING_OFFSET 0x10
#define FIRST_HANDLE   0x10

typedef struct _Mapping {
	CK_SLOT_ID wrap_slot;
	CK_SLOT_ID real_slot;
	CK_FUNCTION_LIST_PTR funcs;
} Mapping;

typedef struct _Session {
	CK_SESSION_HANDLE wrap_session;
	CK_SESSION_HANDLE real_session;
	CK_SLOT_ID wrap_slot;
} Session;

typedef struct {
	int refs;
	Mapping *mappings;
	unsigned int n_mappings;
	p11_dict *sessions;
	CK_FUNCTION_LIST **inited;
	unsigned int forkid;
	CK_SLOT_ID last_id;
} Proxy;

typedef struct _State {
	p11_virtual virt;
	struct _State *next;
	CK_FUNCTION_LIST **loaded;
	CK_FUNCTION_LIST *wrapped;
	CK_ULONG last_handle;
	Proxy *px;
} State;

static State *all_instances = NULL;

#define PROXY_VALID(px) ((px) && (px)->forkid == p11_forkid)
#define PROXY_FORKED(px) ((px) && (px)->forkid != p11_forkid)

#define MANUFACTURER_ID         "PKCS#11 Kit                     "
#define LIBRARY_DESCRIPTION     "PKCS#11 Kit Proxy Module        "
#define LIBRARY_VERSION_MAJOR   1
#define LIBRARY_VERSION_MINOR   1

/* -----------------------------------------------------------------------------
 * PKCS#11 PROXY MODULE
 */

static CK_RV
map_slot_unlocked (Proxy *px,
                   CK_SLOT_ID slot,
                   Mapping *mapping)
{
	unsigned int i;

	assert (px != NULL);
	assert (mapping != NULL);

	for (i = 0; i < px->n_mappings; i++) {
		assert (px->mappings != NULL);
		if (px->mappings[i].wrap_slot == slot) {
			memcpy (mapping, &px->mappings[i], sizeof(Mapping));
			return CKR_OK;
		}
	}

	return CKR_SLOT_ID_INVALID;
}

static CK_RV
map_slot_to_real (Proxy *px,
                  CK_SLOT_ID_PTR slot,
                  Mapping *mapping)
{
	CK_RV rv;

	assert (mapping != NULL);

	p11_lock ();

		if (!PROXY_VALID (px))
			rv = CKR_CRYPTOKI_NOT_INITIALIZED;
		else
			rv = map_slot_unlocked (px, *slot, mapping);
		if (rv == CKR_OK)
			*slot = mapping->real_slot;

	p11_unlock ();

	return rv;
}

static CK_RV
map_session_to_real (Proxy *px,
                     CK_SESSION_HANDLE_PTR handle,
                     Mapping *mapping,
                     Session *session)
{
	CK_RV rv = CKR_OK;
	Session *sess;

	assert (handle != NULL);
	assert (mapping != NULL);

	p11_lock ();

		if (!PROXY_VALID (px)) {
			rv = CKR_CRYPTOKI_NOT_INITIALIZED;
		} else {
			assert (px->sessions);
			sess = p11_dict_get (px->sessions, handle);
			if (sess != NULL) {
				*handle = sess->real_session;
				rv = map_slot_unlocked (px, sess->wrap_slot, mapping);
				if (session != NULL)
					memcpy (session, sess, sizeof (Session));
			} else {
				rv = CKR_SESSION_HANDLE_INVALID;
			}
		}

	p11_unlock ();

	return rv;
}

static void
proxy_free (Proxy *py, unsigned finalize)
{
	if (py) {
		if (finalize)
			p11_kit_modules_finalize (py->inited);
		free (py->inited);
		p11_dict_free (py->sessions);
		free (py->mappings);
		free (py);
	}
}

static CK_RV
proxy_C_Finalize (CK_X_FUNCTION_LIST *self,
                  CK_VOID_PTR reserved)
{
	Proxy *py = NULL;
	State *state = (State *)self;
	CK_RV rv = CKR_OK;

	p11_debug ("in");

	/* WARNING: This function must be reentrant */

	if (reserved) {
		rv = CKR_ARGUMENTS_BAD;

	} else {
		p11_lock ();

			if (!PROXY_VALID (state->px)) {
				rv = CKR_CRYPTOKI_NOT_INITIALIZED;
				py = state->px;
				state->px = NULL;
			} else if (state->px->refs-- == 1) {
				py = state->px;
				state->px = NULL;
			}

		p11_unlock ();

		proxy_free (py, 1);
	}

	p11_debug ("out: %lu", rv);
	return rv;
}

static CK_FUNCTION_LIST **
modules_dup (CK_FUNCTION_LIST **modules)
{
	int count = 0;

	while (modules[count] != NULL)
		count++;

	return memdup (modules, sizeof (CK_FUNCTION_LIST *) * (count + 1));
}

static CK_RV
proxy_list_slots (Proxy *py, Mapping *mappings, unsigned int n_mappings)
{
	CK_FUNCTION_LIST_PTR *f;
	CK_FUNCTION_LIST_PTR funcs;
	CK_SLOT_ID_PTR slots;
	CK_ULONG i, count;
	unsigned int j;
	CK_RV rv = CKR_OK;

	for (f = py->inited; *f; ++f) {
		funcs = *f;
		assert (funcs != NULL);
		slots = NULL;

		/* Ask module for its slots */
		rv = (funcs->C_GetSlotList) (FALSE, NULL, &count);
		if (rv == CKR_OK && count) {
			slots = calloc (sizeof (CK_SLOT_ID), count);
			rv = (funcs->C_GetSlotList) (FALSE, slots, &count);
		}

		if (rv != CKR_OK) {
			free (slots);
			break;
		}

		return_val_if_fail (count == 0 || slots != NULL, CKR_GENERAL_ERROR);

		if (count > 0) {
			Mapping *new_mappings;
			CK_SLOT_ID_PTR new_slots;
			int new_slots_count = 0;

			new_slots = calloc (count, sizeof(CK_SLOT_ID));
			return_val_if_fail (new_slots != NULL, CKR_HOST_MEMORY);
			new_mappings = realloc (py->mappings, sizeof (Mapping) * (py->n_mappings + count));
			return_val_if_fail (new_mappings != NULL, CKR_HOST_MEMORY);
			py->mappings = new_mappings;

			/* Reuse the existing mapping if any */
			for (i = 0; i < count; ++i) {
				for (j = 0; j < n_mappings; ++j) {
					/* cppcheck-suppress nullPointer symbolName=mappings */
					/* false-positive: https://trac.cppcheck.net/ticket/9573 */
					if (mappings[j].funcs == funcs &&
					    mappings[j].real_slot == slots[i]) {
						py->mappings[py->n_mappings].funcs = funcs;
						py->mappings[py->n_mappings].real_slot = slots[i];
						py->mappings[py->n_mappings].wrap_slot =
							mappings[j].wrap_slot;
						++py->n_mappings;
						break;
					}
				}
				if (n_mappings == 0 || j == n_mappings) {
					new_slots[new_slots_count] = slots[i];
					++new_slots_count;
				}
			}

			/* And now add a mapping for each new slot */
			for (i = 0; i < new_slots_count; ++i) {
				++py->last_id;
				py->mappings[py->n_mappings].funcs = funcs;
				py->mappings[py->n_mappings].wrap_slot =
					py->last_id + MAPPING_OFFSET;
				py->mappings[py->n_mappings].real_slot = new_slots[i];
				++py->n_mappings;
			}

			free(new_slots);
		}

		free (slots);
	}
	return rv;
}

static CK_RV
proxy_create (Proxy **res, CK_FUNCTION_LIST **loaded,
	      Mapping *mappings, unsigned int n_mappings)
{
	CK_RV rv = CKR_OK;
	Proxy *py;

	py = calloc (1, sizeof (Proxy));
	return_val_if_fail (py != NULL, CKR_HOST_MEMORY);

	py->forkid = p11_forkid;
	py->last_id = 0;

	py->inited = modules_dup (loaded);
	if (py->inited == NULL) {
		proxy_free (py, 0);
		return_val_if_reached (CKR_HOST_MEMORY);
	}

	rv = p11_kit_modules_initialize (py->inited, NULL);

	if (rv == CKR_OK) {
		rv = proxy_list_slots (py, mappings, n_mappings);
	}

	if (rv != CKR_OK) {
		proxy_free (py, 1);
		return rv;
	}

	py->sessions = p11_dict_new (p11_dict_ulongptr_hash, p11_dict_ulongptr_equal, NULL, free);
	if (py->sessions == NULL) {
		proxy_free (py, 1);
		return_val_if_reached (CKR_HOST_MEMORY);
	}
	py->refs = 1;

	*res = py;
	return CKR_OK;
}

static CK_RV
proxy_C_Initialize (CK_X_FUNCTION_LIST *self,
                    CK_VOID_PTR init_args)
{
	State *state = (State *)self;
	bool initialize = false;
	Mapping *mappings = NULL;
	unsigned int n_mappings = 0;
	Proxy *py;
	CK_RV rv;

	p11_library_init_once ();

	/* WARNING: This function must be reentrant */

	p11_debug ("in");

	p11_lock ();

		if (!PROXY_VALID (state->px)) {
			unsigned call_finalize = 1;

			initialize = true;
			if (PROXY_FORKED(state->px)) {
				call_finalize = 0;
				if (state->px->mappings) {
					mappings = state->px->mappings;
					n_mappings = state->px->n_mappings;
					state->px->mappings = NULL;
					state->px->n_mappings = 0;
				}
			}
			proxy_free (state->px, call_finalize);

			state->px = NULL;
		} else {
			state->px->refs++;
		}

	p11_unlock ();

	if (!initialize) {
		p11_debug ("out: already: %lu", CKR_OK);
		return CKR_OK;
	}

	rv = proxy_create (&py, state->loaded, mappings, n_mappings);
	free (mappings);
	if (rv != CKR_OK) {
		p11_debug ("out: %lu", rv);
		return rv;
	}

	p11_lock ();

		if (state->px == NULL) {
			state->px = py;
			py = NULL;
		}

	p11_unlock ();

	proxy_free (py, 1);
	p11_debug ("out: 0");
	return rv;
}

static CK_RV
proxy_C_GetInfo (CK_X_FUNCTION_LIST *self,
                 CK_INFO_PTR info)
{
	State *state = (State *)self;
	CK_RV rv = CKR_OK;

	p11_library_init_once ();

	return_val_if_fail (info != NULL, CKR_ARGUMENTS_BAD);

	p11_lock ();

		if (!PROXY_VALID (state->px))
			rv = CKR_CRYPTOKI_NOT_INITIALIZED;

	p11_unlock ();

	if (rv != CKR_OK)
		return rv;

	memset (info, 0, sizeof (CK_INFO));
	info->cryptokiVersion.major = CRYPTOKI_VERSION_MAJOR;
	info->cryptokiVersion.minor = CRYPTOKI_VERSION_MINOR;
	info->libraryVersion.major = LIBRARY_VERSION_MAJOR;
	info->libraryVersion.minor = LIBRARY_VERSION_MINOR;
	info->flags = 0;
	memcpy ((char*)info->manufacturerID, MANUFACTURER_ID, 32);
	memcpy ((char*)info->libraryDescription, LIBRARY_DESCRIPTION, 32);
	return CKR_OK;
}

static CK_RV
proxy_C_GetSlotList (CK_X_FUNCTION_LIST *self,
                     CK_BBOOL token_present,
                     CK_SLOT_ID_PTR slot_list,
                     CK_ULONG_PTR count)
{
	State *state = (State *)self;
	CK_SLOT_INFO info;
	Mapping *mapping;
	CK_ULONG index;
	CK_RV rv = CKR_OK;
	unsigned int i;

	return_val_if_fail (count != NULL, CKR_ARGUMENTS_BAD);

	p11_lock ();

		if (!PROXY_VALID (state->px)) {
			rv = CKR_CRYPTOKI_NOT_INITIALIZED;
		}

		if (rv == CKR_OK) {
			Mapping *mappings = NULL;
			unsigned int n_mappings = 0;

			if (state->px->mappings) {
				mappings = state->px->mappings;
				n_mappings = state->px->n_mappings;
				state->px->mappings = NULL;
				state->px->n_mappings = 0;
			}
			rv = proxy_list_slots (state->px, mappings, n_mappings);
			if (rv == CKR_OK) {
				free (mappings);
			} else {
				p11_debug ("failed to list slots: %lu", rv);
				state->px->mappings = mappings;
				state->px->n_mappings = n_mappings;
			}
		}

		if (rv == CKR_OK) {
			index = 0;

			/* Go through and build up a map */
			for (i = 0; i < state->px->n_mappings; ++i) {
				mapping = &state->px->mappings[i];

				/* Skip ones without a token if requested */
				if (token_present) {
					rv = (mapping->funcs->C_GetSlotInfo) (mapping->real_slot, &info);
					if (rv != CKR_OK)
						break;
					if (!(info.flags & CKF_TOKEN_PRESENT))
						continue;
				}

				/* Fill in the slot if we can */
				if (slot_list && *count > index)
					slot_list[index] = mapping->wrap_slot;

				++index;
			}

			if (slot_list && *count < index)
				rv = CKR_BUFFER_TOO_SMALL;

			*count = index;
		}

	p11_unlock ();

	return rv;
}

static CK_RV
proxy_C_GetSlotInfo (CK_X_FUNCTION_LIST *self,
                     CK_SLOT_ID id,
                     CK_SLOT_INFO_PTR info)
{
	State *state = (State *)self;
	Mapping map;
	CK_RV rv;

	rv = map_slot_to_real (state->px, &id, &map);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_GetSlotInfo) (id, info);
}

static CK_RV
proxy_C_GetTokenInfo (CK_X_FUNCTION_LIST *self,
                      CK_SLOT_ID id,
                      CK_TOKEN_INFO_PTR info)
{
	State *state = (State *)self;
	Mapping map;
	CK_RV rv;

	rv = map_slot_to_real (state->px, &id, &map);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_GetTokenInfo) (id, info);
}

static CK_RV
proxy_C_GetMechanismList (CK_X_FUNCTION_LIST *self,
                          CK_SLOT_ID id,
                          CK_MECHANISM_TYPE_PTR mechanism_list,
                          CK_ULONG_PTR count)
{
	State *state = (State *)self;
	Mapping map;
	CK_RV rv;

	rv = map_slot_to_real (state->px, &id, &map);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_GetMechanismList) (id, mechanism_list, count);
}

static CK_RV
proxy_C_GetMechanismInfo (CK_X_FUNCTION_LIST *self,
                          CK_SLOT_ID id,
                          CK_MECHANISM_TYPE type,
                          CK_MECHANISM_INFO_PTR info)
{
	State *state = (State *)self;
	Mapping map;
	CK_RV rv;

	rv = map_slot_to_real (state->px, &id, &map);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_GetMechanismInfo) (id, type, info);
}

static CK_RV
proxy_C_InitToken (CK_X_FUNCTION_LIST *self,
                   CK_SLOT_ID id,
                   CK_UTF8CHAR_PTR pin,
                   CK_ULONG pin_len,
                   CK_UTF8CHAR_PTR label)
{
	State *state = (State *)self;
	Mapping map;
	CK_RV rv;

	rv = map_slot_to_real (state->px, &id, &map);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_InitToken) (id, pin, pin_len, label);
}

static CK_RV
proxy_C_WaitForSlotEvent (CK_X_FUNCTION_LIST *self,
                          CK_FLAGS flags,
                          CK_SLOT_ID_PTR slot,
                          CK_VOID_PTR reserved)
{
	State *state = (State *)self;
	Proxy *py = state->px;
	CK_FUNCTION_LIST_PTR *f;
	CK_FUNCTION_LIST_PTR funcs;
	CK_SLOT_ID real_slot;
	unsigned int i;
	CK_RV rv = CKR_NO_EVENT;

	/* Only the non-blocking case is supported. */
	if ((flags & CKF_DONT_BLOCK) == 0)
		return CKR_FUNCTION_NOT_SUPPORTED;

	p11_lock ();

	for (f = py->inited; *f; ++f) {
		funcs = *f;
		assert (funcs != NULL);

		rv = (funcs->C_WaitForSlotEvent) (flags, &real_slot, reserved);
		if (rv == CKR_NO_EVENT)
			continue;
		if (rv != CKR_OK)
			break;
		for (i = 0; i < py->n_mappings; i++)
			if (py->mappings[i].funcs == funcs &&
			    py->mappings[i].real_slot == real_slot) {
				*slot = py->mappings[i].wrap_slot;
				break;
			}
	}

	p11_unlock ();

	return rv;
}

static CK_RV
proxy_C_OpenSession (CK_X_FUNCTION_LIST *self,
                     CK_SLOT_ID id,
                     CK_FLAGS flags,
                     CK_VOID_PTR user_data,
                     CK_NOTIFY callback,
                     CK_SESSION_HANDLE_PTR handle)
{
	State *state = (State *)self;
	Session *sess;
	Mapping map;
	CK_RV rv;

	return_val_if_fail (handle != NULL, CKR_ARGUMENTS_BAD);

	rv = map_slot_to_real (state->px, &id, &map);
	if (rv != CKR_OK)
		return rv;

	rv = (map.funcs->C_OpenSession) (id, flags, user_data, callback, handle);

	if (rv == CKR_OK) {
		p11_lock ();

			if (!PROXY_VALID (state->px)) {
				/*
				 * The underlying module should have returned an error, so this
				 * code should never be reached with properly behaving modules.
				 * That's why we don't cleanup and close the newly opened session here
				 * or anything like that.
				 */
				rv = CKR_CRYPTOKI_NOT_INITIALIZED;

			} else {
				sess = calloc (1, sizeof (Session));
				return_val_if_fail (sess != NULL, CKR_HOST_MEMORY);
				sess->wrap_slot = map.wrap_slot;
				sess->real_session = *handle;
				sess->wrap_session = ++state->last_handle; /* TODO: Handle wrapping, and then collisions */
				if (!p11_dict_set (state->px->sessions, &sess->wrap_session, sess))
					warn_if_reached ();
				*handle = sess->wrap_session;
			}

		p11_unlock ();
	}

	return rv;
}

static CK_RV
proxy_C_CloseSession (CK_X_FUNCTION_LIST *self,
                      CK_SESSION_HANDLE handle)
{
	State *state = (State *)self;
	CK_SESSION_HANDLE key;
	Mapping map;
	CK_RV rv;

	key = handle;
	rv = map_session_to_real (state->px, &handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	rv = (map.funcs->C_CloseSession) (handle);

	if (rv == CKR_OK) {
		p11_lock ();

			if (state->px)
				p11_dict_remove (state->px->sessions, &key);

		p11_unlock ();
	}

	return rv;
}

static CK_RV
proxy_C_CloseAllSessions (CK_X_FUNCTION_LIST *self,
                          CK_SLOT_ID id)
{
	State *state = (State *)self;
	CK_SESSION_HANDLE_PTR to_close;
	CK_RV rv = CKR_OK;
	Session *sess;
	CK_ULONG i, count = 0;
	p11_dictiter iter;

	p11_lock ();

		if (!PROXY_VALID (state->px)) {
			rv = CKR_CRYPTOKI_NOT_INITIALIZED;
		} else {
			assert (state->px->sessions != NULL);
			to_close = calloc (sizeof (CK_SESSION_HANDLE), p11_dict_size (state->px->sessions));
			if (!to_close) {
				rv = CKR_HOST_MEMORY;
			} else {
				p11_dict_iterate (state->px->sessions, &iter);
				count = 0;
				while (p11_dict_next (&iter, NULL, (void**)&sess)) {
					if (sess->wrap_slot == id)
						to_close[count++] = sess->wrap_session;
				}
			}
		}

	p11_unlock ();

	if (rv != CKR_OK)
		return rv;

	for (i = 0; i < count; ++i)
		proxy_C_CloseSession (self, to_close[i]);

	free (to_close);
	return CKR_OK;
}

static CK_RV
proxy_C_GetSessionInfo (CK_X_FUNCTION_LIST *self,
                        CK_SESSION_HANDLE handle,
                        CK_SESSION_INFO_PTR info)
{
	State *state = (State *)self;
	Mapping map;
	CK_RV rv;

	if (info == NULL)
		return CKR_ARGUMENTS_BAD;

	rv = map_session_to_real (state->px, &handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;

	rv = (map.funcs->C_GetSessionInfo) (handle, info);
	if (rv == CKR_OK)
		info->slotID = map.wrap_slot;

	return rv;
}

static CK_RV
proxy_C_InitPIN (CK_X_FUNCTION_LIST *self,
                 CK_SESSION_HANDLE handle,
                 CK_UTF8CHAR_PTR pin,
                 CK_ULONG pin_len)
{
	State *state = (State *)self;
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (state->px, &handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;

	return (map.funcs->C_InitPIN) (handle, pin, pin_len);
}

static CK_RV
proxy_C_SetPIN (CK_X_FUNCTION_LIST *self,
                CK_SESSION_HANDLE handle,
                CK_UTF8CHAR_PTR old_pin,
                CK_ULONG old_pin_len,
                CK_UTF8CHAR_PTR new_pin,
                CK_ULONG new_pin_len)
{
	State *state = (State *)self;
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (state->px, &handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;

	return (map.funcs->C_SetPIN) (handle, old_pin, old_pin_len, new_pin, new_pin_len);
}

static CK_RV
proxy_C_GetOperationState (CK_X_FUNCTION_LIST *self,
                           CK_SESSION_HANDLE handle,
                           CK_BYTE_PTR operation_state,
                           CK_ULONG_PTR operation_state_len)
{
	State *state = (State *)self;
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (state->px, &handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_GetOperationState) (handle, operation_state, operation_state_len);
}

static CK_RV
proxy_C_SetOperationState (CK_X_FUNCTION_LIST *self,
                           CK_SESSION_HANDLE handle,
                           CK_BYTE_PTR operation_state,
                           CK_ULONG operation_state_len,
                           CK_OBJECT_HANDLE encryption_key,
                           CK_OBJECT_HANDLE authentication_key)
{
	State *state = (State *)self;
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (state->px, &handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_SetOperationState) (handle, operation_state, operation_state_len, encryption_key, authentication_key);
}

static CK_RV
proxy_C_Login (CK_X_FUNCTION_LIST *self,
               CK_SESSION_HANDLE handle,
               CK_USER_TYPE user_type,
               CK_UTF8CHAR_PTR pin,
               CK_ULONG pin_len)
{
	State *state = (State *)self;
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (state->px, &handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;

	return (map.funcs->C_Login) (handle, user_type, pin, pin_len);
}

static CK_RV
proxy_C_Logout (CK_X_FUNCTION_LIST *self,
                CK_SESSION_HANDLE handle)
{
	State *state = (State *)self;
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (state->px, &handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_Logout) (handle);
}

static CK_RV
proxy_C_CreateObject (CK_X_FUNCTION_LIST *self,
                      CK_SESSION_HANDLE handle,
                      CK_ATTRIBUTE_PTR template,
                      CK_ULONG count,
                      CK_OBJECT_HANDLE_PTR new_object)
{
	State *state = (State *)self;
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (state->px, &handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;

	return (map.funcs->C_CreateObject) (handle, template, count, new_object);
}

static CK_RV
proxy_C_CopyObject (CK_X_FUNCTION_LIST *self,
                    CK_SESSION_HANDLE handle,
                    CK_OBJECT_HANDLE object,
                    CK_ATTRIBUTE_PTR template,
                    CK_ULONG count,
                    CK_OBJECT_HANDLE_PTR new_object)
{
	State *state = (State *)self;
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (state->px, &handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_CopyObject) (handle, object, template, count, new_object);
}

static CK_RV
proxy_C_DestroyObject (CK_X_FUNCTION_LIST *self,
                       CK_SESSION_HANDLE handle,
                       CK_OBJECT_HANDLE object)
{
	State *state = (State *)self;
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (state->px, &handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_DestroyObject) (handle, object);
}

static CK_RV
proxy_C_GetObjectSize (CK_X_FUNCTION_LIST *self,
                       CK_SESSION_HANDLE handle,
                       CK_OBJECT_HANDLE object,
                       CK_ULONG_PTR size)
{
	State *state = (State *)self;
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (state->px, &handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_GetObjectSize) (handle, object, size);
}

static CK_RV
proxy_C_GetAttributeValue (CK_X_FUNCTION_LIST *self,
                           CK_SESSION_HANDLE handle,
                           CK_OBJECT_HANDLE object,
                           CK_ATTRIBUTE_PTR template,
                           CK_ULONG count)
{
	State *state = (State *)self;
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (state->px, &handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_GetAttributeValue) (handle, object, template, count);
}

static CK_RV
proxy_C_SetAttributeValue (CK_X_FUNCTION_LIST *self,
                           CK_SESSION_HANDLE handle,
                           CK_OBJECT_HANDLE object,
                           CK_ATTRIBUTE_PTR template,
                           CK_ULONG count)
{
	State *state = (State *)self;
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (state->px, &handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_SetAttributeValue) (handle, object, template, count);
}

static CK_RV
proxy_C_FindObjectsInit (CK_X_FUNCTION_LIST *self,
                         CK_SESSION_HANDLE handle,
                         CK_ATTRIBUTE_PTR template,
                         CK_ULONG count)
{
	State *state = (State *)self;
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (state->px, &handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_FindObjectsInit) (handle, template, count);
}

static CK_RV
proxy_C_FindObjects (CK_X_FUNCTION_LIST *self,
                     CK_SESSION_HANDLE handle,
                     CK_OBJECT_HANDLE_PTR objects,
                     CK_ULONG max_count,
                     CK_ULONG_PTR count)
{
	State *state = (State *)self;
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (state->px, &handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_FindObjects) (handle, objects, max_count, count);
}

static CK_RV
proxy_C_FindObjectsFinal (CK_X_FUNCTION_LIST *self,
                          CK_SESSION_HANDLE handle)
{
	State *state = (State *)self;
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (state->px, &handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_FindObjectsFinal) (handle);
}

static CK_RV
proxy_C_EncryptInit (CK_X_FUNCTION_LIST *self,
                     CK_SESSION_HANDLE handle,
                     CK_MECHANISM_PTR mechanism,
                     CK_OBJECT_HANDLE key)
{
	State *state = (State *)self;
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (state->px, &handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_EncryptInit) (handle, mechanism, key);
}

static CK_RV
proxy_C_Encrypt (CK_X_FUNCTION_LIST *self,
                 CK_SESSION_HANDLE handle,
                 CK_BYTE_PTR input,
                 CK_ULONG input_len,
                 CK_BYTE_PTR encrypted_data,
                 CK_ULONG_PTR encrypted_data_len)
{
	State *state = (State *)self;
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (state->px, &handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_Encrypt) (handle, input, input_len, encrypted_data, encrypted_data_len);
}

static CK_RV
proxy_C_EncryptUpdate (CK_X_FUNCTION_LIST *self,
                       CK_SESSION_HANDLE handle,
                       CK_BYTE_PTR part,
                       CK_ULONG part_len,
                       CK_BYTE_PTR encrypted_part,
                       CK_ULONG_PTR encrypted_part_len)
{
	State *state = (State *)self;
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (state->px, &handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_EncryptUpdate) (handle, part, part_len, encrypted_part, encrypted_part_len);
}

static CK_RV
proxy_C_EncryptFinal (CK_X_FUNCTION_LIST *self,
                      CK_SESSION_HANDLE handle,
                      CK_BYTE_PTR last_part,
                      CK_ULONG_PTR last_part_len)
{
	State *state = (State *)self;
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (state->px, &handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_EncryptFinal) (handle, last_part, last_part_len);
}

static CK_RV
proxy_C_DecryptInit (CK_X_FUNCTION_LIST *self,
                     CK_SESSION_HANDLE handle,
                     CK_MECHANISM_PTR mechanism,
                     CK_OBJECT_HANDLE key)
{
	State *state = (State *)self;
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (state->px, &handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_DecryptInit) (handle, mechanism, key);
}

static CK_RV
proxy_C_Decrypt (CK_X_FUNCTION_LIST *self,
                 CK_SESSION_HANDLE handle,
                 CK_BYTE_PTR enc_data,
                 CK_ULONG enc_data_len,
                 CK_BYTE_PTR output,
                 CK_ULONG_PTR output_len)
{
	State *state = (State *)self;
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (state->px, &handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_Decrypt) (handle, enc_data, enc_data_len, output, output_len);
}

static CK_RV
proxy_C_DecryptUpdate (CK_X_FUNCTION_LIST *self,
                       CK_SESSION_HANDLE handle,
                       CK_BYTE_PTR enc_part,
                       CK_ULONG enc_part_len,
                       CK_BYTE_PTR part,
                       CK_ULONG_PTR part_len)
{
	State *state = (State *)self;
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (state->px, &handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_DecryptUpdate) (handle, enc_part, enc_part_len, part, part_len);
}

static CK_RV
proxy_C_DecryptFinal (CK_X_FUNCTION_LIST *self,
                      CK_SESSION_HANDLE handle,
                      CK_BYTE_PTR last_part,
                      CK_ULONG_PTR last_part_len)
{
	State *state = (State *)self;
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (state->px, &handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_DecryptFinal) (handle, last_part, last_part_len);
}

static CK_RV
proxy_C_DigestInit (CK_X_FUNCTION_LIST *self,
                    CK_SESSION_HANDLE handle,
                    CK_MECHANISM_PTR mechanism)
{
	State *state = (State *)self;
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (state->px, &handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_DigestInit) (handle, mechanism);
}

static CK_RV
proxy_C_Digest (CK_X_FUNCTION_LIST *self,
                CK_SESSION_HANDLE handle,
                CK_BYTE_PTR input,
                CK_ULONG input_len,
                CK_BYTE_PTR digest,
                CK_ULONG_PTR digest_len)
{
	State *state = (State *)self;
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (state->px, &handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_Digest) (handle, input, input_len, digest, digest_len);
}

static CK_RV
proxy_C_DigestUpdate (CK_X_FUNCTION_LIST *self,
                      CK_SESSION_HANDLE handle,
                      CK_BYTE_PTR part,
                      CK_ULONG part_len)
{
	State *state = (State *)self;
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (state->px, &handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_DigestUpdate) (handle, part, part_len);
}

static CK_RV
proxy_C_DigestKey (CK_X_FUNCTION_LIST *self,
                   CK_SESSION_HANDLE handle,
                   CK_OBJECT_HANDLE key)
{
	State *state = (State *)self;
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (state->px, &handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_DigestKey) (handle, key);
}

static CK_RV
proxy_C_DigestFinal (CK_X_FUNCTION_LIST *self,
                     CK_SESSION_HANDLE handle,
                     CK_BYTE_PTR digest,
                     CK_ULONG_PTR digest_len)
{
	State *state = (State *)self;
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (state->px, &handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_DigestFinal) (handle, digest, digest_len);
}

static CK_RV
proxy_C_SignInit (CK_X_FUNCTION_LIST *self,
                  CK_SESSION_HANDLE handle,
                  CK_MECHANISM_PTR mechanism,
                  CK_OBJECT_HANDLE key)
{
	State *state = (State *)self;
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (state->px, &handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_SignInit) (handle, mechanism, key);
}

static CK_RV
proxy_C_Sign (CK_X_FUNCTION_LIST *self,
              CK_SESSION_HANDLE handle,
              CK_BYTE_PTR input,
              CK_ULONG input_len,
              CK_BYTE_PTR signature,
              CK_ULONG_PTR signature_len)
{
	State *state = (State *)self;
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (state->px, &handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_Sign) (handle, input, input_len, signature, signature_len);
}

static CK_RV
proxy_C_SignUpdate (CK_X_FUNCTION_LIST *self,
                    CK_SESSION_HANDLE handle,
                    CK_BYTE_PTR part,
                    CK_ULONG part_len)
{
	State *state = (State *)self;
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (state->px, &handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_SignUpdate) (handle, part, part_len);
}

static CK_RV
proxy_C_SignFinal (CK_X_FUNCTION_LIST *self,
                   CK_SESSION_HANDLE handle,
                   CK_BYTE_PTR signature,
                   CK_ULONG_PTR signature_len)
{
	State *state = (State *)self;
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (state->px, &handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_SignFinal) (handle, signature, signature_len);
}

static CK_RV
proxy_C_SignRecoverInit (CK_X_FUNCTION_LIST *self,
                         CK_SESSION_HANDLE handle,
                         CK_MECHANISM_PTR mechanism,
                         CK_OBJECT_HANDLE key)
{
	State *state = (State *)self;
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (state->px, &handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_SignRecoverInit) (handle, mechanism, key);
}

static CK_RV
proxy_C_SignRecover (CK_X_FUNCTION_LIST *self,
                     CK_SESSION_HANDLE handle,
                     CK_BYTE_PTR input,
                     CK_ULONG input_len,
                     CK_BYTE_PTR signature,
                     CK_ULONG_PTR signature_len)
{
	State *state = (State *)self;
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (state->px, &handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_SignRecover) (handle, input, input_len, signature, signature_len);
}

static CK_RV
proxy_C_VerifyInit (CK_X_FUNCTION_LIST *self,
                    CK_SESSION_HANDLE handle,
                    CK_MECHANISM_PTR mechanism,
                    CK_OBJECT_HANDLE key)
{
	State *state = (State *)self;
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (state->px, &handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_VerifyInit) (handle, mechanism, key);
}

static CK_RV
proxy_C_Verify (CK_X_FUNCTION_LIST *self,
                CK_SESSION_HANDLE handle,
                CK_BYTE_PTR input,
                CK_ULONG input_len,
                CK_BYTE_PTR signature,
                CK_ULONG signature_len)
{
	State *state = (State *)self;
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (state->px, &handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_Verify) (handle, input, input_len, signature, signature_len);
}

static CK_RV
proxy_C_VerifyUpdate (CK_X_FUNCTION_LIST *self,
                      CK_SESSION_HANDLE handle,
                      CK_BYTE_PTR part,
                      CK_ULONG part_len)
{
	State *state = (State *)self;
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (state->px, &handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_VerifyUpdate) (handle, part, part_len);
}

static CK_RV
proxy_C_VerifyFinal (CK_X_FUNCTION_LIST *self,
                     CK_SESSION_HANDLE handle,
                     CK_BYTE_PTR signature,
                     CK_ULONG signature_len)
{
	State *state = (State *)self;
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (state->px, &handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_VerifyFinal) (handle, signature, signature_len);
}

static CK_RV
proxy_C_VerifyRecoverInit (CK_X_FUNCTION_LIST *self,
                           CK_SESSION_HANDLE handle,
                           CK_MECHANISM_PTR mechanism,
                           CK_OBJECT_HANDLE key)
{
	State *state = (State *)self;
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (state->px, &handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_VerifyRecoverInit) (handle, mechanism, key);
}

static CK_RV
proxy_C_VerifyRecover (CK_X_FUNCTION_LIST *self,
                       CK_SESSION_HANDLE handle,
                       CK_BYTE_PTR signature,
                       CK_ULONG signature_len,
                       CK_BYTE_PTR output,
                       CK_ULONG_PTR output_len)
{
	State *state = (State *)self;
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (state->px, &handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_VerifyRecover) (handle, signature, signature_len, output, output_len);
}

static CK_RV
proxy_C_DigestEncryptUpdate (CK_X_FUNCTION_LIST *self,
                             CK_SESSION_HANDLE handle,
                             CK_BYTE_PTR part,
                             CK_ULONG part_len,
                             CK_BYTE_PTR enc_part,
                             CK_ULONG_PTR enc_part_len)
{
	State *state = (State *)self;
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (state->px, &handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_DigestEncryptUpdate) (handle, part, part_len, enc_part, enc_part_len);
}

static CK_RV
proxy_C_DecryptDigestUpdate (CK_X_FUNCTION_LIST *self,
                             CK_SESSION_HANDLE handle,
                             CK_BYTE_PTR enc_part,
                             CK_ULONG enc_part_len,
                             CK_BYTE_PTR part,
                             CK_ULONG_PTR part_len)
{
	State *state = (State *)self;
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (state->px, &handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_DecryptDigestUpdate) (handle, enc_part, enc_part_len, part, part_len);
}

static CK_RV
proxy_C_SignEncryptUpdate (CK_X_FUNCTION_LIST *self,
                           CK_SESSION_HANDLE handle,
                           CK_BYTE_PTR part,
                           CK_ULONG part_len,
                           CK_BYTE_PTR enc_part,
                           CK_ULONG_PTR enc_part_len)
{
	State *state = (State *)self;
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (state->px, &handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_SignEncryptUpdate) (handle, part, part_len, enc_part, enc_part_len);
}

static CK_RV
proxy_C_DecryptVerifyUpdate (CK_X_FUNCTION_LIST *self,
                             CK_SESSION_HANDLE handle,
                             CK_BYTE_PTR enc_part,
                             CK_ULONG enc_part_len,
                             CK_BYTE_PTR part,
                             CK_ULONG_PTR part_len)
{
	State *state = (State *)self;
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (state->px, &handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_DecryptVerifyUpdate) (handle, enc_part, enc_part_len, part, part_len);
}

static CK_RV
proxy_C_GenerateKey (CK_X_FUNCTION_LIST *self,
                     CK_SESSION_HANDLE handle,
                     CK_MECHANISM_PTR mechanism,
                     CK_ATTRIBUTE_PTR template,
                     CK_ULONG count,
                     CK_OBJECT_HANDLE_PTR key)
{
	State *state = (State *)self;
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (state->px, &handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_GenerateKey) (handle, mechanism, template, count, key);
}

static CK_RV
proxy_C_GenerateKeyPair (CK_X_FUNCTION_LIST *self,
                         CK_SESSION_HANDLE handle,
                         CK_MECHANISM_PTR mechanism,
                         CK_ATTRIBUTE_PTR pub_template,
                         CK_ULONG pub_count,
                         CK_ATTRIBUTE_PTR priv_template,
                         CK_ULONG priv_count,
                         CK_OBJECT_HANDLE_PTR pub_key,
                         CK_OBJECT_HANDLE_PTR priv_key)
{
	State *state = (State *)self;
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (state->px, &handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_GenerateKeyPair) (handle, mechanism, pub_template, pub_count, priv_template, priv_count, pub_key, priv_key);
}

static CK_RV
proxy_C_WrapKey (CK_X_FUNCTION_LIST *self,
                 CK_SESSION_HANDLE handle,
                 CK_MECHANISM_PTR mechanism,
                 CK_OBJECT_HANDLE wrapping_key,
                 CK_OBJECT_HANDLE key,
                 CK_BYTE_PTR wrapped_key,
                 CK_ULONG_PTR wrapped_key_len)
{
	State *state = (State *)self;
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (state->px, &handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_WrapKey) (handle, mechanism, wrapping_key, key, wrapped_key, wrapped_key_len);
}

static CK_RV
proxy_C_UnwrapKey (CK_X_FUNCTION_LIST *self,
                   CK_SESSION_HANDLE handle,
                   CK_MECHANISM_PTR mechanism,
                   CK_OBJECT_HANDLE unwrapping_key,
                   CK_BYTE_PTR wrapped_key,
                   CK_ULONG wrapped_key_len,
                   CK_ATTRIBUTE_PTR template,
                   CK_ULONG count,
                   CK_OBJECT_HANDLE_PTR key)
{
	State *state = (State *)self;
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (state->px, &handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_UnwrapKey) (handle, mechanism, unwrapping_key, wrapped_key, wrapped_key_len, template, count, key);
}

static CK_RV
proxy_C_DeriveKey (CK_X_FUNCTION_LIST *self,
                   CK_SESSION_HANDLE handle,
                   CK_MECHANISM_PTR mechanism,
                   CK_OBJECT_HANDLE base_key,
                   CK_ATTRIBUTE_PTR template,
                   CK_ULONG count,
                   CK_OBJECT_HANDLE_PTR key)
{
	State *state = (State *)self;
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (state->px, &handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_DeriveKey) (handle, mechanism, base_key, template, count, key);
}

static CK_RV
proxy_C_SeedRandom (CK_X_FUNCTION_LIST *self,
                    CK_SESSION_HANDLE handle,
                    CK_BYTE_PTR seed,
                    CK_ULONG seed_len)
{
	State *state = (State *)self;
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (state->px, &handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_SeedRandom) (handle, seed, seed_len);
}

static CK_RV
proxy_C_GenerateRandom (CK_X_FUNCTION_LIST *self,
                        CK_SESSION_HANDLE handle,
                        CK_BYTE_PTR random_data,
                        CK_ULONG random_len)
{
	State *state = (State *)self;
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (state->px, &handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_GenerateRandom) (handle, random_data, random_len);
}

/* --------------------------------------------------------------------
 * MODULE ENTRY POINT
 */

static CK_X_FUNCTION_LIST proxy_functions = {
	{ CRYPTOKI_VERSION_MAJOR, CRYPTOKI_VERSION_MINOR  },
	proxy_C_Initialize,
	proxy_C_Finalize,
	proxy_C_GetInfo,
	proxy_C_GetSlotList,
	proxy_C_GetSlotInfo,
	proxy_C_GetTokenInfo,
	proxy_C_GetMechanismList,
	proxy_C_GetMechanismInfo,
	proxy_C_InitToken,
	proxy_C_InitPIN,
	proxy_C_SetPIN,
	proxy_C_OpenSession,
	proxy_C_CloseSession,
	proxy_C_CloseAllSessions,
	proxy_C_GetSessionInfo,
	proxy_C_GetOperationState,
	proxy_C_SetOperationState,
	proxy_C_Login,
	proxy_C_Logout,
	proxy_C_CreateObject,
	proxy_C_CopyObject,
	proxy_C_DestroyObject,
	proxy_C_GetObjectSize,
	proxy_C_GetAttributeValue,
	proxy_C_SetAttributeValue,
	proxy_C_FindObjectsInit,
	proxy_C_FindObjects,
	proxy_C_FindObjectsFinal,
	proxy_C_EncryptInit,
	proxy_C_Encrypt,
	proxy_C_EncryptUpdate,
	proxy_C_EncryptFinal,
	proxy_C_DecryptInit,
	proxy_C_Decrypt,
	proxy_C_DecryptUpdate,
	proxy_C_DecryptFinal,
	proxy_C_DigestInit,
	proxy_C_Digest,
	proxy_C_DigestUpdate,
	proxy_C_DigestKey,
	proxy_C_DigestFinal,
	proxy_C_SignInit,
	proxy_C_Sign,
	proxy_C_SignUpdate,
	proxy_C_SignFinal,
	proxy_C_SignRecoverInit,
	proxy_C_SignRecover,
	proxy_C_VerifyInit,
	proxy_C_Verify,
	proxy_C_VerifyUpdate,
	proxy_C_VerifyFinal,
	proxy_C_VerifyRecoverInit,
	proxy_C_VerifyRecover,
	proxy_C_DigestEncryptUpdate,
	proxy_C_DecryptDigestUpdate,
	proxy_C_SignEncryptUpdate,
	proxy_C_DecryptVerifyUpdate,
	proxy_C_GenerateKey,
	proxy_C_GenerateKeyPair,
	proxy_C_WrapKey,
	proxy_C_UnwrapKey,
	proxy_C_DeriveKey,
	proxy_C_SeedRandom,
	proxy_C_GenerateRandom,
	proxy_C_WaitForSlotEvent,
};

#ifdef OS_WIN32
__declspec(dllexport)
#endif
CK_RV
C_GetFunctionList (CK_FUNCTION_LIST_PTR_PTR list)
{
	CK_FUNCTION_LIST_PTR module = NULL;
	CK_FUNCTION_LIST **loaded = NULL;
	State *state;
	CK_RV rv = CKR_OK;

	p11_library_init_once ();
	p11_lock ();

	/* WARNING: Reentrancy can occur here */
	rv = p11_modules_load_inlock_reentrant (P11_KIT_MODULE_LOADED_FROM_PROXY, &loaded);
	if (rv == CKR_OK) {
		state = calloc (1, sizeof (State));
		if (!state) {
			rv = CKR_HOST_MEMORY;

		} else {
			p11_virtual_init (&state->virt, &proxy_functions, state, NULL);
			state->last_handle = FIRST_HANDLE;
			state->loaded = loaded;
			loaded = NULL;

			module = p11_virtual_wrap (&state->virt, free);
			if (module == NULL) {
				rv = CKR_GENERAL_ERROR;

			} else {
				state->wrapped = module;
				state->next = all_instances;
				all_instances = state;
			}
		}
	}

	if (rv == CKR_OK)
		*list = module;

	if (loaded)
		p11_kit_modules_release (loaded);

	p11_unlock ();

	return rv;
}

void
p11_proxy_module_cleanup (void)
{
	State *state, *next;

	state = all_instances;
	all_instances = NULL;

	for (; state != NULL; state = next) {
		next = state->next;
		p11_kit_modules_release (state->loaded);
		p11_virtual_unwrap (state->wrapped);
	}
}

bool
p11_proxy_module_check (CK_FUNCTION_LIST_PTR module)
{
	State *state;
	bool ret = false;

	if (!p11_virtual_is_wrapper (module))
		return false;

	p11_lock ();
	for (state = all_instances; state != NULL; state = state->next)
		if (state->wrapped == module) {
			ret = true;
			break;
		}
	p11_unlock ();

	return ret;
}

CK_RV
p11_proxy_module_create (CK_FUNCTION_LIST_PTR *module,
			 CK_FUNCTION_LIST_PTR *modules)
{
	State *state;
	CK_RV rv = CKR_OK;

	assert (module != NULL);
	assert (modules != NULL);

	state = calloc (1, sizeof (State));
	if (!state)
		return CKR_HOST_MEMORY;

	p11_virtual_init (&state->virt, &proxy_functions, state, NULL);
	state->last_handle = FIRST_HANDLE;
	state->loaded = modules_dup (modules);
	state->wrapped = p11_virtual_wrap (&state->virt, (p11_destroyer)p11_virtual_uninit);
	if (state->wrapped == NULL) {
		p11_kit_modules_release (state->loaded);
		free (state);
		return CKR_GENERAL_ERROR;
	}

	*module = state->wrapped;

	return rv;
}
