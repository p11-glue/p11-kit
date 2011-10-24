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

#define DEBUG_FLAG DEBUG_PROXY
#include "debug.h"
#include "hashmap.h"
#define CRYPTOKI_EXPORTS
#include "pkcs11.h"
#include "p11-kit.h"
#include "private.h"
#include "util.h"

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

/* Forward declaration */
static CK_FUNCTION_LIST proxy_function_list;

/*
 * Shared data between threads, protected by the mutex, a structure so
 * we can audit thread safety easier.
 */
static struct _Shared {
	Mapping *mappings;
	unsigned int n_mappings;
	int mappings_refs;
	hashmap *sessions;
	CK_ULONG last_handle;
} gl = { NULL, 0, 0, NULL, FIRST_HANDLE };

#define MANUFACTURER_ID         "PKCS#11 Kit                     "
#define LIBRARY_DESCRIPTION     "PKCS#11 Kit Proxy Module        "
#define LIBRARY_VERSION_MAJOR   1
#define LIBRARY_VERSION_MINOR   1

/* -----------------------------------------------------------------------------
 * PKCS#11 PROXY MODULE
 */

static CK_RV
map_slot_unlocked (CK_SLOT_ID slot, Mapping *mapping)
{
	assert (mapping);

	if (slot < MAPPING_OFFSET)
		return CKR_SLOT_ID_INVALID;
	slot -= MAPPING_OFFSET;

	if (slot > gl.n_mappings) {
		return CKR_SLOT_ID_INVALID;
	} else {
		assert (gl.mappings);
		memcpy (mapping, &gl.mappings[slot], sizeof (Mapping));
		return CKR_OK;
	}
}

static CK_RV
map_slot_to_real (CK_SLOT_ID_PTR slot, Mapping *mapping)
{
	CK_RV rv;

	assert (mapping);

	_p11_lock ();

		if (!gl.mappings)
			rv = CKR_CRYPTOKI_NOT_INITIALIZED;
		else
			rv = map_slot_unlocked (*slot, mapping);
		if (rv == CKR_OK)
			*slot = mapping->real_slot;

	_p11_unlock ();

	return rv;
}

static CK_RV
map_session_to_real (CK_SESSION_HANDLE_PTR handle, Mapping *mapping, Session *session)
{
	CK_RV rv = CKR_OK;
	Session *sess;

	assert (handle);
	assert (mapping);

	_p11_lock ();

		if (!gl.sessions) {
			rv = CKR_CRYPTOKI_NOT_INITIALIZED;
		} else {
			assert (gl.sessions);
			sess = _p11_hash_get (gl.sessions, handle);
			if (sess != NULL) {
				*handle = sess->real_session;
				rv = map_slot_unlocked (sess->wrap_slot, mapping);
				if (session != NULL)
					memcpy (session, sess, sizeof (Session));
			} else {
				rv = CKR_SESSION_HANDLE_INVALID;
			}
		}

	_p11_unlock ();

	return rv;
}

static void
finalize_mappings_unlocked (void)
{
	assert (gl.mappings_refs);

	if (--gl.mappings_refs)
		return;

	/* No more mappings */
	free (gl.mappings);
	gl.mappings = NULL;
	gl.n_mappings = 0;

	/* no more sessions */
	_p11_hash_free (gl.sessions);
	gl.sessions = NULL;
}

void
_p11_kit_proxy_after_fork (void)
{
	/*
	 * After a fork the callers are supposed to call C_Initialize and all.
	 * In addition the underlying libraries may change their state so free
	 * up any mappings and all
	 */

	_p11_lock ();

		gl.mappings_refs = 1;
		finalize_mappings_unlocked ();
		assert (!gl.mappings);

	_p11_unlock ();
}

static CK_RV
proxy_C_Finalize (CK_VOID_PTR reserved)
{
	CK_RV rv;

	_p11_debug ("in");

	/* WARNING: This function must be reentrant */

	if (reserved) {
		rv = CKR_ARGUMENTS_BAD;

	} else {
		_p11_lock ();

			/* WARNING: Reentrancy can occur here */
			rv = _p11_kit_finalize_registered_unlocked_reentrant ();

			/*
			 * If modules are all gone, then this was the last
			 * finalize, so cleanup our mappings
			 */
			if (gl.mappings_refs)
				finalize_mappings_unlocked ();

		_p11_unlock ();
	}

	_p11_debug ("out: %lu", rv);
	return rv;
}

static CK_RV
initialize_mappings_unlocked_reentrant (void)
{
	CK_FUNCTION_LIST_PTR *funcss, *f;
	CK_FUNCTION_LIST_PTR funcs;
	Mapping *mappings = NULL;
	int n_mappings = 0;
	CK_SLOT_ID_PTR slots;
	CK_ULONG i, count;
	CK_RV rv = CKR_OK;

	assert (!gl.mappings);

	funcss = _p11_kit_registered_modules_unlocked ();
	for (f = funcss; *f; ++f) {
		funcs = *f;

		assert (funcs);
		slots = NULL;

		_p11_unlock ();

			/* Ask module for its slots */
			rv = (funcs->C_GetSlotList) (FALSE, NULL, &count);
			if (rv == CKR_OK && count) {
				slots = calloc (sizeof (CK_SLOT_ID), count);
				if (!slots)
					rv = CKR_HOST_MEMORY;
				else
					rv = (funcs->C_GetSlotList) (FALSE, slots, &count);
			}

		_p11_lock ();

		if (rv != CKR_OK) {
			free (slots);
			break;
		}

		mappings = _p11_realloc (mappings, sizeof (Mapping) * (n_mappings + count));
		if (!mappings) {
			free (slots);
			rv = CKR_HOST_MEMORY;
			break;
		}

		/* And now add a mapping for each of those slots */
		for (i = 0; i < count; ++i) {
			mappings[n_mappings].funcs = funcs;
			mappings[n_mappings].wrap_slot = n_mappings + MAPPING_OFFSET;
			mappings[n_mappings].real_slot = slots[i];
			++n_mappings;
		}

		free (slots);
	}

	/* Another thread raced us here due to above reentrancy */
	if (gl.mappings) {
		free (mappings);
		return CKR_OK;
	}

	assert (!gl.sessions);
	gl.mappings = mappings;
	gl.n_mappings = n_mappings;
	gl.sessions = _p11_hash_create (_p11_hash_ulongptr_hash, _p11_hash_ulongptr_equal, NULL, free);
	++gl.mappings_refs;

	/* Any cleanup necessary for failure will happen at caller */
	return rv;
}

static CK_RV
proxy_C_Initialize (CK_VOID_PTR init_args)
{
	CK_RV rv;

	_p11_library_init_once ();

	/* WARNING: This function must be reentrant */

	_p11_debug ("in");

	_p11_lock ();

		/* WARNING: Reentrancy can occur here */
		rv = _p11_kit_initialize_registered_unlocked_reentrant ();

		/* WARNING: Reentrancy can occur here */
		if (rv == CKR_OK && gl.mappings_refs == 0)
			rv = initialize_mappings_unlocked_reentrant ();

	_p11_unlock ();

	_p11_debug ("here");

	if (rv != CKR_OK)
		proxy_C_Finalize (NULL);

	_p11_debug ("out: %lu", rv);
	return rv;
}

static CK_RV
proxy_C_GetInfo (CK_INFO_PTR info)
{
	CK_RV rv = CKR_OK;

	_p11_library_init_once ();

	if (info == NULL)
		return CKR_ARGUMENTS_BAD;

	_p11_lock ();

		if (!gl.mappings)
			rv = CKR_CRYPTOKI_NOT_INITIALIZED;

	_p11_unlock ();

	if (rv != CKR_OK)
		return rv;

	info->cryptokiVersion.major = CRYPTOKI_VERSION_MAJOR;
	info->cryptokiVersion.minor = CRYPTOKI_VERSION_MINOR;
	info->libraryVersion.major = LIBRARY_VERSION_MAJOR;
	info->libraryVersion.minor = LIBRARY_VERSION_MINOR;
	info->flags = 0;
	strncpy ((char*)info->manufacturerID, MANUFACTURER_ID, 32);
	strncpy ((char*)info->libraryDescription, LIBRARY_DESCRIPTION, 32);
	return CKR_OK;
}

static CK_RV
proxy_C_GetFunctionList (CK_FUNCTION_LIST_PTR_PTR list)
{
	/* Can be called before C_Initialize */

	if (!list)
		return CKR_ARGUMENTS_BAD;
	*list = &proxy_function_list;
	return CKR_OK;
}

static CK_RV
proxy_C_GetSlotList (CK_BBOOL token_present, CK_SLOT_ID_PTR slot_list,
                       CK_ULONG_PTR count)
{
	CK_SLOT_INFO info;
	Mapping *mapping;
	CK_ULONG index;
	CK_RV rv = CKR_OK;
	int i;

	if (!count)
		return CKR_ARGUMENTS_BAD;

	_p11_lock ();

		if (!gl.mappings) {
			rv = CKR_CRYPTOKI_NOT_INITIALIZED;
		} else {
			index = 0;

			/* Go through and build up a map */
			for (i = 0; i < gl.n_mappings; ++i) {
				mapping = &gl.mappings[i];

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

	_p11_unlock ();

	return rv;
}

static CK_RV
proxy_C_GetSlotInfo (CK_SLOT_ID id, CK_SLOT_INFO_PTR info)
{
	Mapping map;
	CK_RV rv;

	rv = map_slot_to_real (&id, &map);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_GetSlotInfo) (id, info);
}

static CK_RV
proxy_C_GetTokenInfo (CK_SLOT_ID id, CK_TOKEN_INFO_PTR info)
{
	Mapping map;
	CK_RV rv;

	rv = map_slot_to_real (&id, &map);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_GetTokenInfo) (id, info);
}

static CK_RV
proxy_C_GetMechanismList (CK_SLOT_ID id, CK_MECHANISM_TYPE_PTR mechanism_list,
                          CK_ULONG_PTR count)
{
	Mapping map;
	CK_RV rv;

	rv = map_slot_to_real (&id, &map);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_GetMechanismList) (id, mechanism_list, count);
}

static CK_RV
proxy_C_GetMechanismInfo (CK_SLOT_ID id, CK_MECHANISM_TYPE type,
                          CK_MECHANISM_INFO_PTR info)
{
	Mapping map;
	CK_RV rv;

	rv = map_slot_to_real (&id, &map);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_GetMechanismInfo) (id, type, info);
}

static CK_RV
proxy_C_InitToken (CK_SLOT_ID id, CK_UTF8CHAR_PTR pin, CK_ULONG pin_len, CK_UTF8CHAR_PTR label)
{
	Mapping map;
	CK_RV rv;

	rv = map_slot_to_real (&id, &map);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_InitToken) (id, pin, pin_len, label);
}

static CK_RV
proxy_C_WaitForSlotEvent (CK_FLAGS flags, CK_SLOT_ID_PTR slot, CK_VOID_PTR reserved)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV
proxy_C_OpenSession (CK_SLOT_ID id, CK_FLAGS flags, CK_VOID_PTR user_data,
                     CK_NOTIFY callback, CK_SESSION_HANDLE_PTR handle)
{
	Session *sess;
	Mapping map;
	CK_RV rv;

	if (handle == NULL)
		return CKR_ARGUMENTS_BAD;

	rv = map_slot_to_real (&id, &map);
	if (rv != CKR_OK)
		return rv;

	rv = (map.funcs->C_OpenSession) (id, flags, user_data, callback, handle);

	if (rv == CKR_OK) {
		_p11_lock ();

			if (!gl.sessions) {
				/*
				 * The underlying module should have returned an error, so this
				 * code should never be reached with properly behaving modules.
				 * That's why we don't cleanup and close the newly opened session here
				 * or anything like that.
				 */
				rv = CKR_CRYPTOKI_NOT_INITIALIZED;

			} else {
				sess = calloc (1, sizeof (Session));
				sess->wrap_slot = map.wrap_slot;
				sess->real_session = *handle;
				sess->wrap_session = ++gl.last_handle; /* TODO: Handle wrapping, and then collisions */
				_p11_hash_set (gl.sessions, &sess->wrap_session, sess);
				*handle = sess->wrap_session;
			}

		_p11_unlock ();
	}

	return rv;
}

static CK_RV
proxy_C_CloseSession (CK_SESSION_HANDLE handle)
{
	CK_SESSION_HANDLE key;
	Mapping map;
	CK_RV rv;

	key = handle;
	rv = map_session_to_real (&handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	rv = (map.funcs->C_CloseSession) (handle);

	if (rv == CKR_OK) {
		_p11_lock ();

			if (gl.sessions)
				_p11_hash_remove (gl.sessions, &key);

		_p11_unlock ();
	}

	return rv;
}

static CK_RV
proxy_C_CloseAllSessions (CK_SLOT_ID id)
{
	CK_SESSION_HANDLE_PTR to_close;
	CK_RV rv = CKR_OK;
	Session *sess;
	CK_ULONG i, count = 0;
	hashiter iter;

	_p11_lock ();

		if (!gl.sessions) {
			rv = CKR_CRYPTOKI_NOT_INITIALIZED;
		} else {
			to_close = calloc (sizeof (CK_SESSION_HANDLE), _p11_hash_size (gl.sessions));
			if (!to_close) {
				rv = CKR_HOST_MEMORY;
			} else {
				_p11_hash_iterate (gl.sessions, &iter);
				count = 0;
				while (_p11_hash_next (&iter, NULL, (void**)&sess)) {
					if (sess->wrap_slot == id && to_close)
						to_close[count++] = sess->wrap_session;
				}
			}
		}

	_p11_unlock ();

	if (rv != CKR_OK)
		return rv;

	for (i = 0; i < count; ++i)
		proxy_C_CloseSession (to_close[i]);

	free (to_close);
	return CKR_OK;
}

static CK_RV
proxy_C_GetFunctionStatus (CK_SESSION_HANDLE handle)
{
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (&handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_GetFunctionStatus) (handle);
}

static CK_RV
proxy_C_CancelFunction (CK_SESSION_HANDLE handle)
{
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (&handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_CancelFunction) (handle);
}

static CK_RV
proxy_C_GetSessionInfo (CK_SESSION_HANDLE handle, CK_SESSION_INFO_PTR info)
{
	Mapping map;
	CK_RV rv;

	if (info == NULL)
		return CKR_ARGUMENTS_BAD;

	rv = map_session_to_real (&handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;

	rv = (map.funcs->C_GetSessionInfo) (handle, info);
	if (rv == CKR_OK)
		info->slotID = map.wrap_slot;

	return rv;
}

static CK_RV
proxy_C_InitPIN (CK_SESSION_HANDLE handle, CK_UTF8CHAR_PTR pin, CK_ULONG pin_len)
{
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (&handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;

	return (map.funcs->C_InitPIN) (handle, pin, pin_len);
}

static CK_RV
proxy_C_SetPIN (CK_SESSION_HANDLE handle, CK_UTF8CHAR_PTR old_pin, CK_ULONG old_pin_len,
                CK_UTF8CHAR_PTR new_pin, CK_ULONG new_pin_len)
{
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (&handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;

	return (map.funcs->C_SetPIN) (handle, old_pin, old_pin_len, new_pin, new_pin_len);
}

static CK_RV
proxy_C_GetOperationState (CK_SESSION_HANDLE handle, CK_BYTE_PTR operation_state, CK_ULONG_PTR operation_state_len)
{
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (&handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_GetOperationState) (handle, operation_state, operation_state_len);
}

static CK_RV
proxy_C_SetOperationState (CK_SESSION_HANDLE handle, CK_BYTE_PTR operation_state,
                           CK_ULONG operation_state_len, CK_OBJECT_HANDLE encryption_key,
                           CK_OBJECT_HANDLE authentication_key)
{
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (&handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_SetOperationState) (handle, operation_state, operation_state_len, encryption_key, authentication_key);
}

static CK_RV
proxy_C_Login (CK_SESSION_HANDLE handle, CK_USER_TYPE user_type,
               CK_UTF8CHAR_PTR pin, CK_ULONG pin_len)
{
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (&handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;

	return (map.funcs->C_Login) (handle, user_type, pin, pin_len);
}

static CK_RV
proxy_C_Logout (CK_SESSION_HANDLE handle)
{
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (&handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_Logout) (handle);
}

static CK_RV
proxy_C_CreateObject (CK_SESSION_HANDLE handle, CK_ATTRIBUTE_PTR template,
                      CK_ULONG count, CK_OBJECT_HANDLE_PTR new_object)
{
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (&handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;

	return (map.funcs->C_CreateObject) (handle, template, count, new_object);
}

static CK_RV
proxy_C_CopyObject (CK_SESSION_HANDLE handle, CK_OBJECT_HANDLE object,
                    CK_ATTRIBUTE_PTR template, CK_ULONG count,
                    CK_OBJECT_HANDLE_PTR new_object)
{
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (&handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_CopyObject) (handle, object, template, count, new_object);
}

static CK_RV
proxy_C_DestroyObject (CK_SESSION_HANDLE handle, CK_OBJECT_HANDLE object)
{
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (&handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_DestroyObject) (handle, object);
}

static CK_RV
proxy_C_GetObjectSize (CK_SESSION_HANDLE handle, CK_OBJECT_HANDLE object,
                       CK_ULONG_PTR size)
{
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (&handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_GetObjectSize) (handle, object, size);
}

static CK_RV
proxy_C_GetAttributeValue (CK_SESSION_HANDLE handle, CK_OBJECT_HANDLE object,
                           CK_ATTRIBUTE_PTR template, CK_ULONG count)
{
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (&handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_GetAttributeValue) (handle, object, template, count);
}

static CK_RV
proxy_C_SetAttributeValue (CK_SESSION_HANDLE handle, CK_OBJECT_HANDLE object,
                           CK_ATTRIBUTE_PTR template, CK_ULONG count)
{
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (&handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_SetAttributeValue) (handle, object, template, count);
}

static CK_RV
proxy_C_FindObjectsInit (CK_SESSION_HANDLE handle, CK_ATTRIBUTE_PTR template,
                         CK_ULONG count)
{
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (&handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_FindObjectsInit) (handle, template, count);
}

static CK_RV
proxy_C_FindObjects (CK_SESSION_HANDLE handle, CK_OBJECT_HANDLE_PTR objects,
                     CK_ULONG max_count, CK_ULONG_PTR count)
{
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (&handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_FindObjects) (handle, objects, max_count, count);
}

static CK_RV
proxy_C_FindObjectsFinal (CK_SESSION_HANDLE handle)
{
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (&handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_FindObjectsFinal) (handle);
}

static CK_RV
proxy_C_EncryptInit (CK_SESSION_HANDLE handle, CK_MECHANISM_PTR mechanism,
                     CK_OBJECT_HANDLE key)
{
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (&handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_EncryptInit) (handle, mechanism, key);
}

static CK_RV
proxy_C_Encrypt (CK_SESSION_HANDLE handle, CK_BYTE_PTR data, CK_ULONG data_len,
                 CK_BYTE_PTR encrypted_data, CK_ULONG_PTR encrypted_data_len)
{
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (&handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_Encrypt) (handle, data, data_len, encrypted_data, encrypted_data_len);
}

static CK_RV
proxy_C_EncryptUpdate (CK_SESSION_HANDLE handle, CK_BYTE_PTR part,
                       CK_ULONG part_len, CK_BYTE_PTR encrypted_part,
                       CK_ULONG_PTR encrypted_part_len)
{
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (&handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_EncryptUpdate) (handle, part, part_len, encrypted_part, encrypted_part_len);
}

static CK_RV
proxy_C_EncryptFinal (CK_SESSION_HANDLE handle, CK_BYTE_PTR last_part,
                      CK_ULONG_PTR last_part_len)
{
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (&handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_EncryptFinal) (handle, last_part, last_part_len);
}

static CK_RV
proxy_C_DecryptInit (CK_SESSION_HANDLE handle, CK_MECHANISM_PTR mechanism,
                     CK_OBJECT_HANDLE key)
{
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (&handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_DecryptInit) (handle, mechanism, key);
}

static CK_RV
proxy_C_Decrypt (CK_SESSION_HANDLE handle, CK_BYTE_PTR enc_data,
                 CK_ULONG enc_data_len, CK_BYTE_PTR data, CK_ULONG_PTR data_len)
{
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (&handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_Decrypt) (handle, enc_data, enc_data_len, data, data_len);
}

static CK_RV
proxy_C_DecryptUpdate (CK_SESSION_HANDLE handle, CK_BYTE_PTR enc_part,
                       CK_ULONG enc_part_len, CK_BYTE_PTR part, CK_ULONG_PTR part_len)
{
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (&handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_DecryptUpdate) (handle, enc_part, enc_part_len, part, part_len);
}

static CK_RV
proxy_C_DecryptFinal (CK_SESSION_HANDLE handle, CK_BYTE_PTR last_part,
                      CK_ULONG_PTR last_part_len)
{
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (&handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_DecryptFinal) (handle, last_part, last_part_len);
}

static CK_RV
proxy_C_DigestInit (CK_SESSION_HANDLE handle, CK_MECHANISM_PTR mechanism)
{
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (&handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_DigestInit) (handle, mechanism);
}

static CK_RV
proxy_C_Digest (CK_SESSION_HANDLE handle, CK_BYTE_PTR data, CK_ULONG data_len,
                CK_BYTE_PTR digest, CK_ULONG_PTR digest_len)
{
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (&handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_Digest) (handle, data, data_len, digest, digest_len);
}

static CK_RV
proxy_C_DigestUpdate (CK_SESSION_HANDLE handle, CK_BYTE_PTR part, CK_ULONG part_len)
{
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (&handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_DigestUpdate) (handle, part, part_len);
}

static CK_RV
proxy_C_DigestKey (CK_SESSION_HANDLE handle, CK_OBJECT_HANDLE key)
{
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (&handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_DigestKey) (handle, key);
}

static CK_RV
proxy_C_DigestFinal (CK_SESSION_HANDLE handle, CK_BYTE_PTR digest,
                     CK_ULONG_PTR digest_len)
{
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (&handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_DigestFinal) (handle, digest, digest_len);
}

static CK_RV
proxy_C_SignInit (CK_SESSION_HANDLE handle, CK_MECHANISM_PTR mechanism,
                  CK_OBJECT_HANDLE key)
{
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (&handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_SignInit) (handle, mechanism, key);
}

static CK_RV
proxy_C_Sign (CK_SESSION_HANDLE handle, CK_BYTE_PTR data, CK_ULONG data_len,
              CK_BYTE_PTR signature, CK_ULONG_PTR signature_len)
{
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (&handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_Sign) (handle, data, data_len, signature, signature_len);
}

static CK_RV
proxy_C_SignUpdate (CK_SESSION_HANDLE handle, CK_BYTE_PTR part, CK_ULONG part_len)
{
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (&handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_SignUpdate) (handle, part, part_len);
}

static CK_RV
proxy_C_SignFinal (CK_SESSION_HANDLE handle, CK_BYTE_PTR signature,
                   CK_ULONG_PTR signature_len)
{
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (&handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_SignFinal) (handle, signature, signature_len);
}

static CK_RV
proxy_C_SignRecoverInit (CK_SESSION_HANDLE handle, CK_MECHANISM_PTR mechanism,
                         CK_OBJECT_HANDLE key)
{
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (&handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_SignRecoverInit) (handle, mechanism, key);
}

static CK_RV
proxy_C_SignRecover (CK_SESSION_HANDLE handle, CK_BYTE_PTR data, CK_ULONG data_len,
                     CK_BYTE_PTR signature, CK_ULONG_PTR signature_len)
{
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (&handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_SignRecover) (handle, data, data_len, signature, signature_len);
}

static CK_RV
proxy_C_VerifyInit (CK_SESSION_HANDLE handle, CK_MECHANISM_PTR mechanism,
                    CK_OBJECT_HANDLE key)
{
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (&handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_VerifyInit) (handle, mechanism, key);
}

static CK_RV
proxy_C_Verify (CK_SESSION_HANDLE handle, CK_BYTE_PTR data, CK_ULONG data_len,
                CK_BYTE_PTR signature, CK_ULONG signature_len)
{
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (&handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_Verify) (handle, data, data_len, signature, signature_len);
}

static CK_RV
proxy_C_VerifyUpdate (CK_SESSION_HANDLE handle, CK_BYTE_PTR part, CK_ULONG part_len)
{
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (&handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_VerifyUpdate) (handle, part, part_len);
}

static CK_RV
proxy_C_VerifyFinal (CK_SESSION_HANDLE handle, CK_BYTE_PTR signature,
                     CK_ULONG signature_len)
{
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (&handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_VerifyFinal) (handle, signature, signature_len);
}

static CK_RV
proxy_C_VerifyRecoverInit (CK_SESSION_HANDLE handle, CK_MECHANISM_PTR mechanism,
                           CK_OBJECT_HANDLE key)
{
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (&handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_VerifyRecoverInit) (handle, mechanism, key);
}

static CK_RV
proxy_C_VerifyRecover (CK_SESSION_HANDLE handle, CK_BYTE_PTR signature,
                       CK_ULONG signature_len, CK_BYTE_PTR data, CK_ULONG_PTR data_len)
{
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (&handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_VerifyRecover) (handle, signature, signature_len, data, data_len);
}

static CK_RV
proxy_C_DigestEncryptUpdate (CK_SESSION_HANDLE handle, CK_BYTE_PTR part,
                             CK_ULONG part_len, CK_BYTE_PTR enc_part,
                             CK_ULONG_PTR enc_part_len)
{
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (&handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_DigestEncryptUpdate) (handle, part, part_len, enc_part, enc_part_len);
}

static CK_RV
proxy_C_DecryptDigestUpdate (CK_SESSION_HANDLE handle, CK_BYTE_PTR enc_part,
                             CK_ULONG enc_part_len, CK_BYTE_PTR part,
                             CK_ULONG_PTR part_len)
{
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (&handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_DecryptDigestUpdate) (handle, enc_part, enc_part_len, part, part_len);
}

static CK_RV
proxy_C_SignEncryptUpdate (CK_SESSION_HANDLE handle, CK_BYTE_PTR part,
                           CK_ULONG part_len, CK_BYTE_PTR enc_part,
                           CK_ULONG_PTR enc_part_len)
{
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (&handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_SignEncryptUpdate) (handle, part, part_len, enc_part, enc_part_len);
}

static CK_RV
proxy_C_DecryptVerifyUpdate (CK_SESSION_HANDLE handle, CK_BYTE_PTR enc_part,
                             CK_ULONG enc_part_len, CK_BYTE_PTR part,
                             CK_ULONG_PTR part_len)
{
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (&handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_DecryptVerifyUpdate) (handle, enc_part, enc_part_len, part, part_len);
}

static CK_RV
proxy_C_GenerateKey (CK_SESSION_HANDLE handle, CK_MECHANISM_PTR mechanism,
                     CK_ATTRIBUTE_PTR template, CK_ULONG count,
                     CK_OBJECT_HANDLE_PTR key)
{
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (&handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_GenerateKey) (handle, mechanism, template, count, key);
}

static CK_RV
proxy_C_GenerateKeyPair (CK_SESSION_HANDLE handle, CK_MECHANISM_PTR mechanism,
                         CK_ATTRIBUTE_PTR pub_template, CK_ULONG pub_count,
                         CK_ATTRIBUTE_PTR priv_template, CK_ULONG priv_count,
                         CK_OBJECT_HANDLE_PTR pub_key, CK_OBJECT_HANDLE_PTR priv_key)
{
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (&handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_GenerateKeyPair) (handle, mechanism, pub_template, pub_count, priv_template, priv_count, pub_key, priv_key);
}

static CK_RV
proxy_C_WrapKey (CK_SESSION_HANDLE handle, CK_MECHANISM_PTR mechanism,
                 CK_OBJECT_HANDLE wrapping_key, CK_OBJECT_HANDLE key,
                 CK_BYTE_PTR wrapped_key, CK_ULONG_PTR wrapped_key_len)
{
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (&handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_WrapKey) (handle, mechanism, wrapping_key, key, wrapped_key, wrapped_key_len);
}

static CK_RV
proxy_C_UnwrapKey (CK_SESSION_HANDLE handle, CK_MECHANISM_PTR mechanism,
                   CK_OBJECT_HANDLE unwrapping_key, CK_BYTE_PTR wrapped_key,
                   CK_ULONG wrapped_key_len, CK_ATTRIBUTE_PTR template,
                   CK_ULONG count, CK_OBJECT_HANDLE_PTR key)
{
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (&handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_UnwrapKey) (handle, mechanism, unwrapping_key, wrapped_key, wrapped_key_len, template, count, key);
}

static CK_RV
proxy_C_DeriveKey (CK_SESSION_HANDLE handle, CK_MECHANISM_PTR mechanism,
                   CK_OBJECT_HANDLE base_key, CK_ATTRIBUTE_PTR template,
                   CK_ULONG count, CK_OBJECT_HANDLE_PTR key)
{
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (&handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_DeriveKey) (handle, mechanism, base_key, template, count, key);
}

static CK_RV
proxy_C_SeedRandom (CK_SESSION_HANDLE handle, CK_BYTE_PTR seed, CK_ULONG seed_len)
{
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (&handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_SeedRandom) (handle, seed, seed_len);
}

static CK_RV
proxy_C_GenerateRandom (CK_SESSION_HANDLE handle, CK_BYTE_PTR random_data,
                          CK_ULONG random_len)
{
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (&handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_GenerateRandom) (handle, random_data, random_len);
}

/* --------------------------------------------------------------------
 * MODULE ENTRY POINT
 */

static CK_FUNCTION_LIST proxy_function_list = {
	{ CRYPTOKI_VERSION_MAJOR, CRYPTOKI_VERSION_MINOR },  /* version */
	proxy_C_Initialize,
	proxy_C_Finalize,
	proxy_C_GetInfo,
	proxy_C_GetFunctionList,
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
	proxy_C_GetFunctionStatus,
	proxy_C_CancelFunction,
	proxy_C_WaitForSlotEvent
};

#ifdef OS_WIN32
__declspec(dllexport)
#endif

CK_RV
C_GetFunctionList (CK_FUNCTION_LIST_PTR_PTR list)
{
	_p11_library_init_once ();
	return proxy_C_GetFunctionList (list);
}
