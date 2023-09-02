/*
 * Copyright (C) 2008 Stefan Walter
 * Copyright (C) 2011 Collabora Ltd.
 * Copyright (C) 2021-2023 Red Hat Inc.
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
	CK_INTERFACE wrapped;
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
			p11_kit_modules_finalize ((CK_FUNCTION_LIST **)py->inited);
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
			slots = calloc (count, sizeof (CK_SLOT_ID));
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
			new_mappings = reallocarray (py->mappings, (py->n_mappings + count), sizeof (Mapping));
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
	info->cryptokiVersion.major = self->version.major;
	info->cryptokiVersion.minor = self->version.minor;
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

			if (state->px->n_mappings > 0) {
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
	CK_SESSION_HANDLE_PTR to_close = NULL;
	CK_RV rv = CKR_OK;
	Session *sess;
	CK_ULONG i, count = 0;
	p11_dictiter iter;

	p11_lock ();

		if (!PROXY_VALID (state->px)) {
			rv = CKR_CRYPTOKI_NOT_INITIALIZED;
		} else {
			assert (state->px->sessions != NULL);
			to_close = calloc (p11_dict_size (state->px->sessions) + 1, sizeof (CK_SESSION_HANDLE));
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

#include "p11-kit/proxy-generated.h"

static const char p11_interface_name[] = "PKCS 11";

static const CK_VERSION version_two = {
	CRYPTOKI_LEGACY_VERSION_MAJOR,
	CRYPTOKI_LEGACY_VERSION_MINOR
};

static const CK_VERSION version_three = {
	CRYPTOKI_VERSION_MAJOR,
	CRYPTOKI_VERSION_MINOR
};

/* We are not going to support any special interfaces */
#define NUM_INTERFACES 2

static CK_RV
get_interface_inlock(CK_INTERFACE **interface, const CK_VERSION *version, CK_FLAGS flags)
{
	CK_FUNCTION_LIST_PTR module = NULL;
	CK_FUNCTION_LIST **loaded = NULL;
	State *state = NULL;
	CK_RV rv;

	return_val_if_fail (interface, CKR_ARGUMENTS_BAD);
	return_val_if_fail (version, CKR_ARGUMENTS_BAD);

	if (memcmp (version, &version_three, sizeof(*version)) != 0 &&
	    memcmp (version, &version_two, sizeof(*version)) != 0)
		return CKR_ARGUMENTS_BAD;

	/* WARNING: Reentrancy can occur here */
	rv = p11_modules_load_inlock_reentrant (P11_KIT_MODULE_LOADED_FROM_PROXY, &loaded);
	if (rv != CKR_OK)
		goto cleanup;

	state = calloc (1, sizeof (State));
	if (!state) {
		rv = CKR_HOST_MEMORY;
		goto cleanup;
	}

	p11_virtual_init (&state->virt, &proxy_functions, state, NULL);

	state->last_handle = FIRST_HANDLE;

	state->loaded = loaded;
	loaded = NULL;

	/* Version must be set before calling p11_virtual_wrap, as it
	 * is used to determine which functions are wrapped with
	 * libffi closure.
	 */
	state->virt.funcs.version = *version;

	module = p11_virtual_wrap (&state->virt, free);
	if (module == NULL) {
		rv = CKR_GENERAL_ERROR;
		goto cleanup;
	}

	module->version = *version;

	state->wrapped.pInterfaceName = (char *)p11_interface_name;

	state->wrapped.pFunctionList = module;
	module = NULL;

	state->wrapped.flags = flags;

	*interface = &state->wrapped;

	state->next = all_instances;
	all_instances = state;
	state = NULL;

 cleanup:
	if (module)
		p11_virtual_unwrap (module);
	if (loaded)
		p11_kit_modules_release (loaded);
	if (state) {
		p11_virtual_unwrap (state->wrapped.pFunctionList);
		p11_kit_modules_release (state->loaded);
		free (state);
	}
	return rv;
}

#ifdef OS_WIN32
__declspec(dllexport)
#endif
CK_RV
C_GetFunctionList (CK_FUNCTION_LIST_PTR_PTR list)
{
	CK_RV rv = CKR_OK;
	CK_INTERFACE *res = NULL;

	p11_library_init_once ();
	p11_lock ();

	rv = get_interface_inlock (&res, &version_two, 0);
	if (rv == CKR_OK)
		*list = res->pFunctionList;

	p11_unlock ();

	return rv;
}

#ifdef OS_WIN32
__declspec(dllexport)
#endif
CK_RV
C_GetInterfaceList (CK_INTERFACE_PTR pInterfacesList, CK_ULONG_PTR pulCount)
{
	CK_RV rv = CKR_OK;
	CK_INTERFACE *interfaces[NUM_INTERFACES];
	CK_ULONG count = 0;
	CK_ULONG i;

	if (pulCount == NULL_PTR)
		return CKR_ARGUMENTS_BAD;

	if (pInterfacesList == NULL_PTR) {
		*pulCount = NUM_INTERFACES;
		return CKR_OK;
	}

	if (*pulCount < NUM_INTERFACES) {
		*pulCount = NUM_INTERFACES;
		return CKR_BUFFER_TOO_SMALL;
	}

	p11_library_init_once ();
	p11_lock ();

	rv = get_interface_inlock (&interfaces[count++], &version_three, 0);
	if (rv != CKR_OK)
		goto cleanup;

	rv = get_interface_inlock (&interfaces[count++], &version_two, 0);
	if (rv != CKR_OK)
		goto cleanup;

	for (i = 0; i < count; i++)
		pInterfacesList[i] = *interfaces[i];
	*pulCount = count;

 cleanup:
	p11_unlock ();

	return rv;
}

#ifdef OS_WIN32
__declspec(dllexport)
#endif
CK_RV
C_GetInterface (CK_UTF8CHAR_PTR pInterfaceName, CK_VERSION_PTR pVersion,
                CK_INTERFACE_PTR_PTR ppInterface, CK_FLAGS flags)
{
	int rv;

	if (ppInterface == NULL) {
		return CKR_ARGUMENTS_BAD;
	}

	if (pInterfaceName &&
	    strcmp ((const char *)pInterfaceName, p11_interface_name) != 0) {
		return CKR_ARGUMENTS_BAD;
	}

	p11_library_init_once ();
	p11_lock ();

	rv = get_interface_inlock (ppInterface,
				   pVersion ? pVersion : &version_three,
				   flags);

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
		p11_virtual_unwrap (state->wrapped.pFunctionList);
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
		if (state->wrapped.pFunctionList == module) {
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
	state->wrapped.pFunctionList = p11_virtual_wrap (&state->virt, (p11_destroyer)p11_virtual_uninit);
	if (state->wrapped.pFunctionList == NULL) {
		p11_kit_modules_release (state->loaded);
		free (state);
		return CKR_GENERAL_ERROR;
	}

	*module = state->wrapped.pFunctionList;

	return rv;
}
