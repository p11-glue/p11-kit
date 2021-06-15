/*
 * Copyright (c) 2011, Collabora Ltd.
 * Copyright (c) 2021, Red Hat, Inc.
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

#include "debug.h"
#define CRYPTOKI_EXPORTS
#include "pkcs11.h"
#include "message.h"

#include "mock.h"

#include "attrs.h"
#define P11_DEBUG_FLAG P11_DEBUG_LIB
#include "debug.h"
#include "dict.h"
#include "array.h"
#include "library.h"

#include <assert.h>
#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* -------------------------------------------------------------------
 * GLOBALS and SUPPORT STUFF
 */

/* Various mutexes */
static p11_mutex_t init_mutex;

/* Whether we've been initialized, and on what process id it happened */
static bool pkcs11_initialized = false;
static pid_t pkcs11_initialized_pid = 0;

static CK_UTF8CHAR *the_pin = NULL;
static CK_ULONG n_the_pin = 0;

static CK_UTF8CHAR *the_username = NULL;
static CK_ULONG n_the_username = 0;

static bool logged_in = false;
static CK_USER_TYPE the_user_type = 0;

typedef struct _Session {
	CK_SESSION_HANDLE handle;
	p11_dict *objects;
	CK_SESSION_INFO info;

	/* For find operations */
	bool finding;
	p11_array *matches;

	bool want_context_login;

	/* For encrypt, decrypt operations */
	CK_OBJECT_HANDLE crypto_key;
	CK_FLAGS crypto_method;
	CK_MECHANISM_TYPE crypto_mechanism;
	CK_BBOOL crypto_final;
	CK_MECHANISM_TYPE message_method;
	CK_MECHANISM message_mechanism;
	CK_OBJECT_HANDLE message_key;
	bool message_progress;

	/* For sign, verify, digest, CKM_MOCK_COUNT */
	CK_MECHANISM_TYPE hash_mechanism;
	CK_FLAGS hash_method;
	CK_OBJECT_HANDLE hash_key;
	CK_ULONG hash_count;

	/* For 'signing' with CKM_MOCK_PREFIX */
	CK_BYTE sign_prefix[128];
	CK_ULONG n_sign_prefix;

	/* The random seed */
	CK_BYTE random_seed[128];
	CK_ULONG random_seed_len;
} Session;

static unsigned int unique_identifier = 100;
static p11_dict *the_sessions = NULL;
static p11_dict *the_objects = NULL;

#define SIGNED_PREFIX "signed-prefix:"

#define handle_to_pointer(handle) \
	((void *)(size_t)(handle))

#define pointer_to_handle(pointer) \
	((CK_ULONG)(size_t)(pointer))

static void
free_session (void *data)
{
	Session *sess = (Session *)data;
	if (sess) {
		p11_dict_free (sess->objects);
		p11_array_free (sess->matches);
		free (sess->message_mechanism.pParameter);
	}
	free (sess);
}

static CK_RV
lookup_object (Session *sess,
               CK_OBJECT_HANDLE object,
               CK_ATTRIBUTE **attrs,
               p11_dict **table)
{
	CK_BBOOL priv;

	*attrs = p11_dict_get (the_objects, handle_to_pointer (object));
	if (*attrs) {
		if (table)
			*table = the_objects;
	} else {
		*attrs = p11_dict_get (sess->objects, handle_to_pointer (object));
		if (*attrs) {
			if (table)
				*table = sess->objects;
		}
	}

	if (!*attrs)
		return CKR_OBJECT_HANDLE_INVALID;
	else if (!logged_in && p11_attrs_find_bool (*attrs, CKA_PRIVATE, &priv) && priv)
		return CKR_USER_NOT_LOGGED_IN;

	return CKR_OK;
}

void
mock_module_add_object (CK_SLOT_ID slot_id,
                        const CK_ATTRIBUTE *attrs)
{
	CK_ATTRIBUTE *copy;

	return_if_fail (slot_id == MOCK_SLOT_ONE_ID);
	return_if_fail (attrs != NULL);

	copy = p11_attrs_dup (attrs);
	return_if_fail (copy != NULL);

	mock_module_take_object (slot_id, copy);
}

void
mock_module_take_object (CK_SLOT_ID slot_id,
                        CK_ATTRIBUTE *attrs)
{
	CK_OBJECT_HANDLE object;

	return_if_fail (slot_id == MOCK_SLOT_ONE_ID);
	return_if_fail (attrs != NULL);

	object = ++unique_identifier;
	if (!p11_dict_set (the_objects, handle_to_pointer (object), attrs))
		return_if_reached ();
}

static void
module_reset_objects (CK_SLOT_ID slot_id)
{
	return_if_fail (slot_id == MOCK_SLOT_ONE_ID);

	if (!the_objects) {
		the_objects = p11_dict_new (p11_dict_direct_hash,
		                            p11_dict_direct_equal,
		                            NULL, p11_attrs_free);
		return_if_fail (the_objects != NULL);
	}

	p11_dict_clear (the_objects);

	/* Our token object */
	{
		CK_OBJECT_CLASS klass = CKO_DATA;
		char *label = "TEST LABEL";
		CK_ATTRIBUTE attrs[] = {
			{ CKA_CLASS, &klass, sizeof (klass) },
			{ CKA_LABEL, label, strlen (label) },
			{ CKA_INVALID, NULL, 0 },
		};
		p11_dict_set (the_objects, handle_to_pointer (MOCK_DATA_OBJECT), p11_attrs_dup (attrs));
	}

	/* Private capitalize key */
	{
		CK_OBJECT_CLASS klass = CKO_PRIVATE_KEY;
		char *label = "Private Capitalize Key";
		char *value = "value";
		CK_MECHANISM_TYPE type = CKM_MOCK_CAPITALIZE;
		CK_BBOOL btrue = CK_TRUE;
		CK_ATTRIBUTE attrs[] = {
			{ CKA_CLASS, &klass, sizeof (klass) },
			{ CKA_LABEL, label, strlen (label) },
			{ CKA_ALLOWED_MECHANISMS, &type, sizeof (type) },
			{ CKA_DECRYPT, &btrue, sizeof (btrue) },
			{ CKA_PRIVATE, &btrue, sizeof (btrue) },
			{ CKA_WRAP, &btrue, sizeof (btrue) },
			{ CKA_UNWRAP, &btrue, sizeof (btrue) },
			{ CKA_DERIVE, &btrue, sizeof (btrue) },
			{ CKA_VALUE, value, strlen (value) },
			{ CKA_INVALID, NULL, 0 },
		};
		p11_dict_set (the_objects, handle_to_pointer (MOCK_PRIVATE_KEY_CAPITALIZE), p11_attrs_dup (attrs));

	}

	{
		CK_OBJECT_CLASS klass = CKO_PUBLIC_KEY;
		char *label = "Public Capitalize Key";
		char *value = "value";
		CK_MECHANISM_TYPE type = CKM_MOCK_CAPITALIZE;
		CK_BBOOL btrue = CK_TRUE;
		CK_BBOOL bfalse = CK_FALSE;
		CK_ATTRIBUTE attrs[] = {
			{ CKA_CLASS, &klass, sizeof (klass) },
			{ CKA_LABEL, label, strlen (label) },
			{ CKA_ALLOWED_MECHANISMS, &type, sizeof (type) },
			{ CKA_ENCRYPT, &btrue, sizeof (btrue) },
			{ CKA_PRIVATE, &bfalse, sizeof (bfalse) },
			{ CKA_VALUE, value, strlen (value) },
			{ CKA_INVALID, NULL, 0 },
		};
		p11_dict_set (the_objects, handle_to_pointer (MOCK_PUBLIC_KEY_CAPITALIZE), p11_attrs_dup (attrs));

	}

	{
		CK_OBJECT_CLASS klass = CKO_PRIVATE_KEY;
		char *label = "Private prefix key";
		char *value = "value";
		CK_MECHANISM_TYPE type = CKM_MOCK_PREFIX;
		CK_BBOOL btrue = CK_TRUE;
		CK_ATTRIBUTE attrs[] = {
			{ CKA_CLASS, &klass, sizeof (klass) },
			{ CKA_LABEL, label, strlen (label) },
			{ CKA_ALLOWED_MECHANISMS, &type, sizeof (type) },
			{ CKA_SIGN, &btrue, sizeof (btrue) },
			{ CKA_PRIVATE, &btrue, sizeof (btrue) },
			{ CKA_ALWAYS_AUTHENTICATE, &btrue, sizeof (btrue) },
			{ CKA_VALUE, value, strlen (value) },
			{ CKA_INVALID, NULL, 0 },
		};
		p11_dict_set (the_objects, handle_to_pointer (MOCK_PRIVATE_KEY_PREFIX), p11_attrs_dup (attrs));

	}

	{
		CK_OBJECT_CLASS klass = CKO_PUBLIC_KEY;
		char *label = "Public prefix key";
		char *value = "value";
		CK_MECHANISM_TYPE type = CKM_MOCK_PREFIX;
		CK_BBOOL btrue = CK_TRUE;
		CK_BBOOL bfalse = CK_FALSE;
		CK_ATTRIBUTE attrs[] = {
			{ CKA_CLASS, &klass, sizeof (klass) },
			{ CKA_LABEL, label, strlen (label) },
			{ CKA_ALLOWED_MECHANISMS, &type, sizeof (type) },
			{ CKA_VERIFY, &btrue, sizeof (btrue) },
			{ CKA_PRIVATE, &bfalse, sizeof (bfalse) },
			{ CKA_ALWAYS_AUTHENTICATE, &btrue, sizeof (btrue) },
			{ CKA_VALUE, value, strlen (value) },
			{ CKA_INVALID, NULL, 0 },
		};
		p11_dict_set (the_objects, handle_to_pointer (MOCK_PUBLIC_KEY_PREFIX), p11_attrs_dup (attrs));

	}
}

void
mock_module_add_profile (CK_SLOT_ID slot_id, CK_PROFILE_ID profile_id)
{
	return_if_fail (slot_id == MOCK_SLOT_ONE_ID);

	if (!the_objects) {
		the_objects = p11_dict_new (p11_dict_direct_hash,
		                            p11_dict_direct_equal,
		                            NULL, p11_attrs_free);
		return_if_fail (the_objects != NULL);
	}

	{
		CK_OBJECT_CLASS klass = CKO_PROFILE;
		CK_ATTRIBUTE attrs[] = {
			{ CKA_CLASS, &klass, sizeof (klass) },
			{ CKA_PROFILE_ID, &profile_id, sizeof(profile_id) },
			{ CKA_INVALID, NULL, 0 },
		};
		p11_dict_set (the_objects, handle_to_pointer (MOCK_PROFILE_OBJECT), p11_attrs_dup (attrs));
	}
}

static void
module_finalize (void)
{
	p11_mutex_lock (&init_mutex);

		/* This should stop all other calls in */
		pkcs11_initialized = false;
		pkcs11_initialized_pid = 0;

		if (the_objects)
			p11_dict_free (the_objects);
		the_objects = NULL;

		if (the_sessions)
			p11_dict_free (the_sessions);
		the_sessions = NULL;
		logged_in = false;
		the_user_type = 0;

		free (the_pin);
		the_pin = NULL;
		n_the_pin = 0;

		free (the_username);
		the_username = NULL;
		n_the_username = 0;

	p11_mutex_unlock (&init_mutex);
}

bool
mock_module_initialized (void)
{
	return pkcs11_initialized;
}
void
mock_module_reset (void)
{
	module_finalize ();
	module_reset_objects (MOCK_SLOT_ONE_ID);

}

void
mock_module_enumerate_objects (CK_SESSION_HANDLE handle,
                               mock_enumerator func,
                               void *user_data)
{
	p11_dictiter iter;
	void *key;
	void *value;
	Session *sess;

	assert (the_objects != NULL);
	assert (func != NULL);

	/* Token objects */
	p11_dict_iterate (the_objects, &iter);
	while (p11_dict_next (&iter, &key, &value)) {
		if (!(func) (pointer_to_handle (key), value, user_data))
			return;
	}

	/* session objects */
	if (handle) {
		sess = p11_dict_get (the_sessions, handle_to_pointer (handle));
		if (sess) {
			p11_dict_iterate (sess->objects, &iter);
			while (p11_dict_next (&iter, &key, &value)) {
				if (!(func) (pointer_to_handle (key), value, user_data))
					return;
			}
		}
	}
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

	p11_mutex_lock (&init_mutex);

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
				p11_debug_precond ("invalid set of mutex calls supplied\n");
				ret = CKR_ARGUMENTS_BAD;
				goto done;
			}

			/*
			 * When the CKF_OS_LOCKING_OK flag isn't set return an error.
			 * We must be able to use our pthread functionality.
			 */
			if (!(args->flags & CKF_OS_LOCKING_OK)) {
				p11_debug_precond ("can't do without os locking\n");
				ret = CKR_CANT_LOCK;
				goto done;
			}
		}

		pid = getpid ();
		if (pkcs11_initialized) {

			/* This process has called C_Initialize already */
			if (pid == pkcs11_initialized_pid) {
				p11_debug_precond ("p11-kit: C_Initialize called twice for same process\n");
				ret = CKR_CRYPTOKI_ALREADY_INITIALIZED;
				goto done;
			}
		}

		/* We store CK_ULONG as pointers here, so verify that they fit */
		assert (sizeof (CK_ULONG) <= sizeof (void *));

		free (the_pin);
		the_pin = (CK_UTF8CHAR_PTR)strdup ("booo");
		n_the_pin = 4;

		free (the_username);
		the_username = (CK_UTF8CHAR_PTR)strdup ("yeah");
		n_the_username = 4;

		if (the_sessions)
			p11_dict_free (the_sessions);
		the_sessions = p11_dict_new (p11_dict_direct_hash,
		                             p11_dict_direct_equal,
		                             NULL, free_session);
		if (!the_sessions) {
			ret = CKR_HOST_MEMORY;
			goto done;
		}

		module_reset_objects (MOCK_SLOT_ONE_ID);

done:
		/* Mark us as officially initialized */
		if (ret == CKR_OK) {
			pkcs11_initialized = true;
			pkcs11_initialized_pid = pid;
		} else if (ret != CKR_CRYPTOKI_ALREADY_INITIALIZED) {
			pkcs11_initialized = false;
			pkcs11_initialized_pid = 0;
		}

	p11_mutex_unlock (&init_mutex);

	return ret;
}

CK_RV
mock_X_Initialize (CK_X_FUNCTION_LIST *self,
                   CK_VOID_PTR init_args)
{
	return mock_C_Initialize (init_args);
}

CK_RV
mock_C_Initialize__fails (CK_VOID_PTR init_args)
{
	return CKR_FUNCTION_FAILED;
}

CK_RV
mock_X_Initialize__fails (CK_X_FUNCTION_LIST *self,
                          CK_VOID_PTR init_args)
{
	return mock_C_Initialize__fails (init_args);
}

CK_RV
mock_C_Finalize (CK_VOID_PTR reserved)
{
	return_val_if_fail (pkcs11_initialized, CKR_CRYPTOKI_NOT_INITIALIZED);
	return_val_if_fail (reserved == NULL, CKR_ARGUMENTS_BAD);

	module_finalize ();
	return CKR_OK;
}

CK_RV
mock_X_Finalize (CK_X_FUNCTION_LIST *self,
                 CK_VOID_PTR reserved)
{
	return mock_C_Finalize (reserved);
}

CK_RV
mock_C_GetInfo (CK_INFO_PTR info)
{
	return_val_if_fail (info, CKR_ARGUMENTS_BAD);

	memcpy (info, &MOCK_INFO, sizeof (*info));
	return CKR_OK;
}

CK_RV
mock_X_GetInfo (CK_X_FUNCTION_LIST *self,
                CK_INFO_PTR info)
{
	return mock_C_GetInfo (info);
}

CK_RV
mock_C_GetFunctionList_not_supported (CK_FUNCTION_LIST_PTR_PTR list)
{
	/* This would be a strange call to receive, should be overridden  */
	return_val_if_reached (CKR_FUNCTION_NOT_SUPPORTED);
}

CK_RV
mock_C_GetSlotList (CK_BBOOL token_present,
                    CK_SLOT_ID_PTR slot_list,
                    CK_ULONG_PTR count)
{
	CK_ULONG num;

	return_val_if_fail (count, CKR_ARGUMENTS_BAD);

	num = token_present ? 1 : 2;

	/* Application only wants to know the number of slots. */
	if (slot_list == NULL) {
		*count = num;
		return CKR_OK;
	}

	if (*count < num)
		return_val_if_reached (CKR_BUFFER_TOO_SMALL);

	*count = num;
	slot_list[0] = MOCK_SLOT_ONE_ID;
	if (!token_present)
		slot_list[1] = MOCK_SLOT_TWO_ID;

	return CKR_OK;

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
mock_X_GetSlotList__no_tokens (CK_X_FUNCTION_LIST *self,
                               CK_BBOOL token_present,
                               CK_SLOT_ID_PTR slot_list,
                               CK_ULONG_PTR count)
{
	return mock_C_GetSlotList__no_tokens (token_present,
	                                      slot_list,
	                                      count);
;
}

/* Update mock-module.h URIs when updating this */

static const CK_SLOT_INFO MOCK_INFO_ONE = {
	"TEST SLOT                                                       ",
	"TEST MANUFACTURER               ",
	CKF_TOKEN_PRESENT | CKF_REMOVABLE_DEVICE,
	{ 55, 155 },
	{ 65, 165 },
};

/* Update mock-module.h URIs when updating this */

static const CK_SLOT_INFO MOCK_INFO_TWO = {
	"TEST SLOT                                                       ",
	"TEST MANUFACTURER               ",
	CKF_REMOVABLE_DEVICE,
	{ 55, 155 },
	{ 65, 165 },
};

CK_RV
mock_C_GetSlotInfo (CK_SLOT_ID slot_id,
                    CK_SLOT_INFO_PTR info)
{
	return_val_if_fail (info, CKR_ARGUMENTS_BAD);

	if (slot_id == MOCK_SLOT_ONE_ID) {
		memcpy (info, &MOCK_INFO_ONE, sizeof (*info));
		return CKR_OK;
	} else if (slot_id == MOCK_SLOT_TWO_ID) {
		memcpy (info, &MOCK_INFO_TWO, sizeof (*info));
		return CKR_OK;
	} else {
		return CKR_SLOT_ID_INVALID;
	}
}

CK_RV
mock_C_GetSlotList__fail_first (CK_BBOOL token_present,
                                CK_SLOT_ID_PTR slot_list,
                                CK_ULONG_PTR count)
{
	return CKR_VENDOR_DEFINED;
}

CK_RV
mock_C_GetSlotList__fail_late (CK_BBOOL token_present,
                               CK_SLOT_ID_PTR slot_list,
                               CK_ULONG_PTR count)
{
	if (!slot_list)
		return mock_C_GetSlotList (token_present, slot_list, count);
	return CKR_VENDOR_DEFINED;
}

CK_RV
mock_C_GetSlotInfo__invalid_slotid (CK_SLOT_ID id,
                                    CK_SLOT_INFO_PTR info)
{
	return_val_if_fail (info, CKR_ARGUMENTS_BAD);

	return CKR_SLOT_ID_INVALID;
}

CK_RV
mock_X_GetSlotInfo__invalid_slotid (CK_X_FUNCTION_LIST *self,
                                    CK_SLOT_ID id,
                                    CK_SLOT_INFO_PTR info)
{
	return_val_if_fail (info, CKR_ARGUMENTS_BAD);

	return CKR_SLOT_ID_INVALID;
}

/* Update gck-mock.h URIs when updating this */

static const CK_TOKEN_INFO MOCK_TOKEN_ONE = {
	"TEST LABEL                      ",
	"TEST MANUFACTURER               ",
	"TEST MODEL      ",
	"TEST SERIAL     ",
	CKF_LOGIN_REQUIRED | CKF_USER_PIN_INITIALIZED | CKF_CLOCK_ON_TOKEN | CKF_TOKEN_INITIALIZED,
	1,
	2,
	3,
	4,
	5,
	6,
	7,
	8,
	9,
	10,
	{ 75, 175 },
	{ 85, 185 },
	{ '1', '9', '9', '9', '0', '5', '2', '5', '0', '9', '1', '9', '5', '9', '0', '0' }
};

CK_RV
mock_C_GetTokenInfo (CK_SLOT_ID slot_id,
                     CK_TOKEN_INFO_PTR info)
{
	return_val_if_fail (info != NULL, CKR_ARGUMENTS_BAD);

	if (slot_id == MOCK_SLOT_ONE_ID) {
		memcpy (info, &MOCK_TOKEN_ONE, sizeof (*info));
		return CKR_OK;
	} else if (slot_id == MOCK_SLOT_TWO_ID) {
		return CKR_TOKEN_NOT_PRESENT;
	} else {
		return CKR_SLOT_ID_INVALID;
	}
}

CK_RV
mock_C_GetTokenInfo__invalid_slotid (CK_SLOT_ID slot_id,
                                     CK_TOKEN_INFO_PTR info)
{
	return_val_if_fail (info, CKR_ARGUMENTS_BAD);

	return CKR_SLOT_ID_INVALID;
}

CK_RV
mock_X_GetTokenInfo__invalid_slotid (CK_X_FUNCTION_LIST *self,
                                     CK_SLOT_ID slot_id,
                                     CK_TOKEN_INFO_PTR info)
{
	return_val_if_fail (info, CKR_ARGUMENTS_BAD);

	return CKR_SLOT_ID_INVALID;
}

/*
 * TWO mechanisms:
 *  CKM_MOCK_CAPITALIZE
 *  CKM_MOCK_PREFIX
 */

CK_RV
mock_C_GetMechanismList (CK_SLOT_ID slot_id,
                         CK_MECHANISM_TYPE_PTR mechanism_list,
                         CK_ULONG_PTR count)
{
	return_val_if_fail (count != NULL, CKR_ARGUMENTS_BAD);

	if (slot_id == MOCK_SLOT_TWO_ID)
		return CKR_TOKEN_NOT_PRESENT;
	else if (slot_id != MOCK_SLOT_ONE_ID)
		return CKR_SLOT_ID_INVALID;

	/* Application only wants to know the number of slots. */
	if (mechanism_list == NULL) {
		*count = 2;
		return CKR_OK;
	}

	if (*count < 2)
		return_val_if_reached (CKR_BUFFER_TOO_SMALL);

	mechanism_list[0] = CKM_MOCK_CAPITALIZE;
	mechanism_list[1] = CKM_MOCK_PREFIX;
	*count = 2;
	return CKR_OK;
}

CK_RV
mock_C_GetTokenInfo__not_initialized (CK_SLOT_ID slot_id,
                                      CK_TOKEN_INFO_PTR info)
{
	CK_RV rv;

	rv = mock_C_GetTokenInfo (slot_id, info);
	if (rv == CKR_OK)
		info->flags &= ~ CKF_TOKEN_INITIALIZED;

	return rv;
}

/*
 * TWO mechanisms:
 *  CKM_MOCK_CAPITALIZE
 *  CKM_MOCK_PREFIX
 */

CK_RV
mock_C_GetMechanismList__invalid_slotid (CK_SLOT_ID id,
                                         CK_MECHANISM_TYPE_PTR mechanism_list,
                                         CK_ULONG_PTR count)
{
	return_val_if_fail (count, CKR_ARGUMENTS_BAD);

	return CKR_SLOT_ID_INVALID;
}

CK_RV
mock_X_GetMechanismList__invalid_slotid (CK_X_FUNCTION_LIST *self,
                                         CK_SLOT_ID id,
                                         CK_MECHANISM_TYPE_PTR mechanism_list,
                                         CK_ULONG_PTR count)
{
	return_val_if_fail (count, CKR_ARGUMENTS_BAD);

	return CKR_SLOT_ID_INVALID;
}

static const CK_MECHANISM_INFO MOCK_MECH_CAPITALIZE = {
	512, 4096, CKF_ENCRYPT | CKF_DECRYPT
};

static const CK_MECHANISM_INFO MOCK_MECH_PREFIX = {
	2048, 2048, CKF_SIGN | CKF_VERIFY
};

CK_RV
mock_C_GetMechanismInfo (CK_SLOT_ID slot_id,
                         CK_MECHANISM_TYPE type,
                         CK_MECHANISM_INFO_PTR info)
{
	return_val_if_fail (info, CKR_ARGUMENTS_BAD);

	if (slot_id == MOCK_SLOT_TWO_ID)
		return CKR_TOKEN_NOT_PRESENT;
	else if (slot_id != MOCK_SLOT_ONE_ID)
		return CKR_SLOT_ID_INVALID;

	if (type == CKM_MOCK_CAPITALIZE) {
		memcpy (info, &MOCK_MECH_CAPITALIZE, sizeof (*info));
		return CKR_OK;
	} else if (type == CKM_MOCK_PREFIX) {
		memcpy (info, &MOCK_MECH_PREFIX, sizeof (*info));
		return CKR_OK;
	} else {
		return CKR_MECHANISM_INVALID;
	}
}

CK_RV
mock_C_GetMechanismInfo__invalid_slotid (CK_SLOT_ID slot_id,
                                         CK_MECHANISM_TYPE type,
                                         CK_MECHANISM_INFO_PTR info)
{
	return_val_if_fail (info, CKR_ARGUMENTS_BAD);

	return CKR_SLOT_ID_INVALID;
}

CK_RV
mock_X_GetMechanismInfo__invalid_slotid (CK_X_FUNCTION_LIST *self,
                                         CK_SLOT_ID slot_id,
                                         CK_MECHANISM_TYPE type,
                                         CK_MECHANISM_INFO_PTR info)
{
	return_val_if_fail (info, CKR_ARGUMENTS_BAD);

	return CKR_SLOT_ID_INVALID;
}

CK_RV
mock_C_InitToken__specific_args (CK_SLOT_ID slot_id,
                                 CK_UTF8CHAR_PTR pin,
                                 CK_ULONG pin_len,
                                 CK_UTF8CHAR_PTR label)
{
	return_val_if_fail (pin != NULL, CKR_ARGUMENTS_BAD);
	return_val_if_fail (label != NULL, CKR_ARGUMENTS_BAD);

	if (slot_id == MOCK_SLOT_TWO_ID)
		return CKR_TOKEN_NOT_PRESENT;
	else if (slot_id != MOCK_SLOT_ONE_ID)
		return CKR_SLOT_ID_INVALID;

	if (strlen ("TEST PIN") != pin_len ||
	    strncmp ((char *)pin, "TEST PIN", pin_len) != 0)
		return CKR_PIN_INVALID;
	if (strcmp ((char *)label, "TEST LABEL") != 0)
		return CKR_ARGUMENTS_BAD;

	free (the_pin);
	the_pin = memdup (pin, pin_len);
	return_val_if_fail (the_pin != NULL, CKR_HOST_MEMORY);
	n_the_pin = pin_len;
	return CKR_OK;
}

/* TODO specific flags username */

CK_RV
mock_C_InitToken__invalid_slotid (CK_SLOT_ID slot_id,
                                  CK_UTF8CHAR_PTR pin,
                                  CK_ULONG pin_len,
                                  CK_UTF8CHAR_PTR label)
{
	return CKR_SLOT_ID_INVALID;
}

CK_RV
mock_X_InitToken__invalid_slotid (CK_X_FUNCTION_LIST *self,
                                  CK_SLOT_ID slot_id,
                                  CK_UTF8CHAR_PTR pin,
                                  CK_ULONG pin_len,
                                  CK_UTF8CHAR_PTR label)
{
	return CKR_SLOT_ID_INVALID;
}

CK_RV
mock_C_WaitForSlotEvent (CK_FLAGS flags,
                         CK_SLOT_ID_PTR slot,
                         CK_VOID_PTR reserved)
{
	return_val_if_fail (slot, CKR_ARGUMENTS_BAD);

	if (flags & CKF_DONT_BLOCK)
		return CKR_NO_EVENT;

	*slot = MOCK_SLOT_TWO_ID;
	return CKR_OK;
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
mock_X_WaitForSlotEvent__no_event (CK_X_FUNCTION_LIST *self,
                                   CK_FLAGS flags,
                                   CK_SLOT_ID_PTR slot,
                                   CK_VOID_PTR reserved)
{
	return_val_if_fail (slot, CKR_ARGUMENTS_BAD);

	return CKR_NO_EVENT;
}

CK_RV
mock_C_OpenSession (CK_SLOT_ID slot_id,
                    CK_FLAGS flags,
                    CK_VOID_PTR user_data,
                    CK_NOTIFY callback,
                    CK_SESSION_HANDLE_PTR session)
{
	Session *sess;

	return_val_if_fail (session, CKR_ARGUMENTS_BAD);

	if (slot_id == MOCK_SLOT_TWO_ID)
		return CKR_TOKEN_NOT_PRESENT;
	else if (slot_id != MOCK_SLOT_ONE_ID)
		return CKR_SLOT_ID_INVALID;
	if ((flags & CKF_SERIAL_SESSION) != CKF_SERIAL_SESSION)
		return CKR_SESSION_PARALLEL_NOT_SUPPORTED;

	sess = calloc (1, sizeof (Session));
	return_val_if_fail (sess != NULL, CKR_HOST_MEMORY);
	sess->handle = ++unique_identifier;
	sess->info.flags = flags;
	sess->info.slotID = slot_id;
	sess->info.state = 0;
	sess->info.ulDeviceError = 1414;
	sess->objects = p11_dict_new (p11_dict_direct_hash, p11_dict_direct_equal,
	                              NULL, p11_attrs_free);
	*session = sess->handle;

	memcpy (sess->random_seed, "random", 6);
	sess->random_seed_len = 6;

	p11_dict_set (the_sessions, handle_to_pointer (sess->handle), sess);
	return CKR_OK;
}

CK_RV
mock_C_OpenSession__invalid_slotid (CK_SLOT_ID slot_id,
                                    CK_FLAGS flags,
                                    CK_VOID_PTR user_data,
                                    CK_NOTIFY callback,
                                    CK_SESSION_HANDLE_PTR session)
{
	return_val_if_fail (session, CKR_ARGUMENTS_BAD);

	return CKR_SLOT_ID_INVALID;
}

CK_RV
mock_X_OpenSession__invalid_slotid (CK_X_FUNCTION_LIST *self,
                                    CK_SLOT_ID slot_id,
                                    CK_FLAGS flags,
                                    CK_VOID_PTR user_data,
                                    CK_NOTIFY callback,
                                    CK_SESSION_HANDLE_PTR session)
{
	return_val_if_fail (session, CKR_ARGUMENTS_BAD);

	return CKR_SLOT_ID_INVALID;
}

CK_RV
mock_C_OpenSession__fails (CK_SLOT_ID slot_id,
                           CK_FLAGS flags,
                           CK_VOID_PTR user_data,
                           CK_NOTIFY callback,
                           CK_SESSION_HANDLE_PTR session)
{
	return_val_if_fail (session, CKR_ARGUMENTS_BAD);

	return CKR_DEVICE_ERROR;
}

CK_RV
mock_C_CloseSession (CK_SESSION_HANDLE session)
{
	Session *sess;

	sess = p11_dict_get (the_sessions, handle_to_pointer (session));
	if (!sess)
		return CKR_SESSION_HANDLE_INVALID;

	p11_dict_remove (the_sessions, handle_to_pointer (session));
	return CKR_OK;
}

CK_RV
mock_C_CloseSession__invalid_handle (CK_SESSION_HANDLE session)
{
	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_X_CloseSession__invalid_handle (CK_X_FUNCTION_LIST *self,
                                     CK_SESSION_HANDLE session)
{
	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_C_CloseAllSessions (CK_SLOT_ID slot_id)
{
	if (slot_id == MOCK_SLOT_TWO_ID)
		return CKR_TOKEN_NOT_PRESENT;
	else if (slot_id != MOCK_SLOT_ONE_ID)
		return CKR_SLOT_ID_INVALID;

	p11_dict_clear (the_sessions);
	return CKR_OK;
}

CK_RV
mock_C_CloseAllSessions__invalid_slotid (CK_SLOT_ID slot_id)
{
	return CKR_SLOT_ID_INVALID;
}

CK_RV
mock_X_CloseAllSessions__invalid_slotid (CK_X_FUNCTION_LIST *self,
                                         CK_SLOT_ID slot_id)
{
	return CKR_SLOT_ID_INVALID;
}

CK_RV
mock_C_GetFunctionStatus (CK_SESSION_HANDLE session)
{
	if (!p11_dict_get (the_sessions, handle_to_pointer (session)))
		return CKR_SESSION_HANDLE_INVALID;
	return CKR_FUNCTION_NOT_PARALLEL;
}

CK_RV
mock_C_GetFunctionStatus__not_parallel (CK_SESSION_HANDLE session)
{
	return CKR_FUNCTION_NOT_PARALLEL;
}

CK_RV
mock_C_CancelFunction (CK_SESSION_HANDLE session)
{
	if (!p11_dict_get (the_sessions, handle_to_pointer (session)))
		return CKR_SESSION_HANDLE_INVALID;
	return CKR_FUNCTION_NOT_PARALLEL;
}

CK_RV
mock_C_CancelFunction__not_parallel (CK_SESSION_HANDLE session)
{
	return CKR_FUNCTION_NOT_PARALLEL;
}

CK_RV
mock_C_GetSessionInfo (CK_SESSION_HANDLE session,
                       CK_SESSION_INFO_PTR info)
{
	Session *sess;

	return_val_if_fail (info != NULL, CKR_ARGUMENTS_BAD);

	sess = p11_dict_get (the_sessions, handle_to_pointer (session));
	if (!sess)
		return CKR_SESSION_HANDLE_INVALID;

	if (logged_in) {
		if (sess->info.flags & CKF_RW_SESSION)
			sess->info.state = CKS_RW_USER_FUNCTIONS;
		else
			sess->info.state = CKS_RO_USER_FUNCTIONS;
	} else {
		if (sess->info.flags & CKF_RW_SESSION)
			sess->info.state = CKS_RW_PUBLIC_SESSION;
		else
			sess->info.state = CKS_RO_PUBLIC_SESSION;
	}

	memcpy (info, &sess->info, sizeof (*info));
	return CKR_OK;
}

CK_RV
mock_C_GetSessionInfo__invalid_handle (CK_SESSION_HANDLE session,
                                       CK_SESSION_INFO_PTR info)
{
	return_val_if_fail (info, CKR_ARGUMENTS_BAD);

	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_X_GetSessionInfo__invalid_handle (CK_X_FUNCTION_LIST *self,
                                       CK_SESSION_HANDLE session,
                                       CK_SESSION_INFO_PTR info)
{
	return_val_if_fail (info, CKR_ARGUMENTS_BAD);

	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_C_InitPIN__specific_args (CK_SESSION_HANDLE session,
                               CK_UTF8CHAR_PTR pin,
                               CK_ULONG pin_len)
{
	Session *sess;

	sess = p11_dict_get (the_sessions, handle_to_pointer (session));
	if (sess == NULL)
		return CKR_SESSION_HANDLE_INVALID;

	if (strlen ("TEST PIN") != pin_len ||
	    strncmp ((char *)pin, "TEST PIN", pin_len) != 0)
		return CKR_PIN_INVALID;

	free (the_pin);
	the_pin = memdup (pin, pin_len);
	return_val_if_fail (the_pin != NULL, CKR_HOST_MEMORY);
	n_the_pin = pin_len;
	return CKR_OK;
}

CK_RV
mock_C_InitPIN__invalid_handle (CK_SESSION_HANDLE session,
                                CK_UTF8CHAR_PTR pin,
                                CK_ULONG pin_len)
{
	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_X_InitPIN__invalid_handle (CK_X_FUNCTION_LIST *self,
                                CK_SESSION_HANDLE session,
                                CK_UTF8CHAR_PTR pin,
                                CK_ULONG pin_len)
{
	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_C_SetPIN__specific_args (CK_SESSION_HANDLE session,
                              CK_UTF8CHAR_PTR old_pin,
                              CK_ULONG old_pin_len,
                              CK_UTF8CHAR_PTR new_pin,
                              CK_ULONG new_pin_len)
{
	Session *sess;

	sess = p11_dict_get (the_sessions, handle_to_pointer (session));
	if (sess == NULL)
		return CKR_SESSION_HANDLE_INVALID;

	if (old_pin_len != n_the_pin)
		return CKR_PIN_INCORRECT;
	if (memcmp (old_pin, the_pin, n_the_pin) != 0)
		return CKR_PIN_INCORRECT;

	if (strlen ("TEST PIN") != new_pin_len ||
	    strncmp ((char *)new_pin, "TEST PIN", new_pin_len) != 0)
		return CKR_PIN_INVALID;

	free (the_pin);
	the_pin = memdup (new_pin, new_pin_len);
	return_val_if_fail (the_pin != NULL, CKR_HOST_MEMORY);
	n_the_pin = new_pin_len;
	return CKR_OK;
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
mock_X_SetPIN__invalid_handle (CK_X_FUNCTION_LIST *self,
                               CK_SESSION_HANDLE session,
                               CK_UTF8CHAR_PTR old_pin,
                               CK_ULONG old_pin_len,
                               CK_UTF8CHAR_PTR new_pin,
                               CK_ULONG new_pin_len)
{
	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_C_GetOperationState (CK_SESSION_HANDLE session,
                          CK_BYTE_PTR operation_state,
                          CK_ULONG_PTR operation_state_len)
{
	Session *sess;

	return_val_if_fail (operation_state_len, CKR_ARGUMENTS_BAD);

	sess = p11_dict_get (the_sessions, handle_to_pointer (session));
	if (sess == NULL)
		return CKR_SESSION_HANDLE_INVALID;

	if (!operation_state) {
		*operation_state_len = sizeof (sess);
		return CKR_OK;
	}

	if (*operation_state_len < sizeof (sess))
		return CKR_BUFFER_TOO_SMALL;

	memcpy (operation_state, &sess, sizeof (sess));
	*operation_state_len = sizeof (sess);
	return CKR_OK;
}

CK_RV
mock_C_GetOperationState__invalid_handle (CK_SESSION_HANDLE session,
                                          CK_BYTE_PTR operation_state,
                                          CK_ULONG_PTR operation_state_len)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV
mock_X_GetOperationState__invalid_handle (CK_X_FUNCTION_LIST *self,
                                          CK_SESSION_HANDLE session,
                                          CK_BYTE_PTR operation_state,
                                          CK_ULONG_PTR operation_state_len)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV
mock_C_SetOperationState (CK_SESSION_HANDLE session,
                          CK_BYTE_PTR operation_state,
                          CK_ULONG operation_state_len,
                          CK_OBJECT_HANDLE encryption_key,
                          CK_OBJECT_HANDLE authentication_key)
{
	Session *sess;

	sess = p11_dict_get (the_sessions, handle_to_pointer (session));
	if (sess == NULL)
		return CKR_SESSION_HANDLE_INVALID;

	if (!operation_state || operation_state_len != sizeof (sess))
		return CKR_ARGUMENTS_BAD;

	/* Yes, just arbitrary numbers, to make sure they got through */
	if (encryption_key != 355 || authentication_key != 455)
		return CKR_KEY_HANDLE_INVALID;
	if (memcmp (operation_state, &sess, sizeof (sess)) != 0)
		return CKR_SAVED_STATE_INVALID;
	return CKR_OK;
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
mock_X_SetOperationState__invalid_handle (CK_X_FUNCTION_LIST *self,
                                          CK_SESSION_HANDLE session,
                                          CK_BYTE_PTR operation_state,
                                          CK_ULONG operation_state_len,
                                          CK_OBJECT_HANDLE encryption_key,
                                          CK_OBJECT_HANDLE authentication_key)
{
	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_C_Login (CK_SESSION_HANDLE session,
              CK_USER_TYPE user_type,
              CK_UTF8CHAR_PTR pin,
              CK_ULONG pin_len)
{
	Session *sess;

	return_val_if_fail (user_type == CKU_SO ||
	                    user_type == CKU_USER ||
	                    user_type == CKU_CONTEXT_SPECIFIC,
	                    CKR_USER_TYPE_INVALID);

	sess = p11_dict_get (the_sessions, handle_to_pointer (session));
	if (sess == NULL)
		return CKR_SESSION_HANDLE_INVALID;

	if (logged_in && user_type != CKU_CONTEXT_SPECIFIC)
		return CKR_USER_ALREADY_LOGGED_IN;

	if (!pin)
		return CKR_PIN_INCORRECT;

	if (pin_len != n_the_pin)
		return CKR_PIN_INCORRECT;
	if (strncmp ((char *)pin, (char *)the_pin, pin_len) != 0)
		return CKR_PIN_INCORRECT;

	if (user_type == CKU_CONTEXT_SPECIFIC) {
		return_val_if_fail (sess->want_context_login, CKR_OPERATION_NOT_INITIALIZED);
		sess->want_context_login = false;
	} else {
		logged_in = true;
		the_user_type = user_type;
	}

	return CKR_OK;
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
mock_X_Login__invalid_handle (CK_X_FUNCTION_LIST *self,
                              CK_SESSION_HANDLE session,
                              CK_USER_TYPE user_type,
                              CK_UTF8CHAR_PTR pin,
                              CK_ULONG pin_len)
{
	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_C_Logout (CK_SESSION_HANDLE session)
{
	Session *sess;

	sess = p11_dict_get (the_sessions, handle_to_pointer (session));
	if (!sess)
		return CKR_SESSION_HANDLE_INVALID;

	if (!logged_in)
		return CKR_USER_NOT_LOGGED_IN;

	logged_in = false;
	the_user_type = 0;
	return CKR_OK;
}

CK_RV
mock_C_Logout__invalid_handle (CK_SESSION_HANDLE session)
{
	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_X_Logout__invalid_handle (CK_X_FUNCTION_LIST *self,
                               CK_SESSION_HANDLE session)
{
	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_C_CreateObject (CK_SESSION_HANDLE session,
                     CK_ATTRIBUTE_PTR template,
                     CK_ULONG count,
                     CK_OBJECT_HANDLE_PTR object)
{
	CK_ATTRIBUTE *attrs;
	Session *sess;
	CK_BBOOL token, priv;

	return_val_if_fail (object, CKR_ARGUMENTS_BAD);

	sess = p11_dict_get (the_sessions, handle_to_pointer (session));
	if (!sess)
		return CKR_SESSION_HANDLE_INVALID;

	attrs = p11_attrs_buildn (NULL, template, count);

	if (p11_attrs_find_bool (attrs, CKA_PRIVATE, &priv) && priv) {
		if (!logged_in) {
			p11_attrs_free (attrs);
			return CKR_USER_NOT_LOGGED_IN;
		}
	}

	*object = ++unique_identifier;
	if (p11_attrs_find_bool (attrs, CKA_TOKEN, &token) && token)
		p11_dict_set (the_objects, handle_to_pointer (*object), attrs);
	else
		p11_dict_set (sess->objects, handle_to_pointer (*object), attrs);

	return CKR_OK;
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
mock_X_CreateObject__invalid_handle (CK_X_FUNCTION_LIST *self,
                                     CK_SESSION_HANDLE session,
                                     CK_ATTRIBUTE_PTR template,
                                     CK_ULONG count,
                                     CK_OBJECT_HANDLE_PTR new_object)
{
	return_val_if_fail (new_object, CKR_ARGUMENTS_BAD);

	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_C_CopyObject (CK_SESSION_HANDLE session,
                   CK_OBJECT_HANDLE object,
                   CK_ATTRIBUTE_PTR template,
                   CK_ULONG count,
                   CK_OBJECT_HANDLE_PTR new_object)
{
	CK_ATTRIBUTE *attrs;
	Session *sess;
	CK_BBOOL token, priv;
	CK_RV rv;

	return_val_if_fail (object, CKR_ARGUMENTS_BAD);

	sess = p11_dict_get (the_sessions, handle_to_pointer (session));
	if (!sess)
		return CKR_SESSION_HANDLE_INVALID;

	rv = lookup_object (sess, object, &attrs, NULL);
	if (rv != CKR_OK)
		return rv;

	if (p11_attrs_find_bool (attrs, CKA_PRIVATE, &priv) && priv) {
		if (!logged_in)
			return CKR_USER_NOT_LOGGED_IN;
	}

	attrs = p11_attrs_buildn (p11_attrs_dup (attrs), template, count);

	*new_object = ++unique_identifier;
	if (p11_attrs_find_bool (attrs, CKA_TOKEN, &token) && token)
		p11_dict_set (the_objects, handle_to_pointer (*new_object), attrs);
	else
		p11_dict_set (sess->objects, handle_to_pointer (*new_object), attrs);

	return CKR_OK;
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
mock_X_CopyObject__invalid_handle (CK_X_FUNCTION_LIST *self,
                                   CK_SESSION_HANDLE session,
                                   CK_OBJECT_HANDLE object,
                                   CK_ATTRIBUTE_PTR template,
                                   CK_ULONG count,
                                   CK_OBJECT_HANDLE_PTR new_object)
{
	return_val_if_fail (new_object, CKR_ARGUMENTS_BAD);

	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_C_DestroyObject (CK_SESSION_HANDLE session,
                      CK_OBJECT_HANDLE object)
{
	CK_ATTRIBUTE *attrs;
	Session *sess;
	p11_dict *table;
	CK_RV rv;

	sess = p11_dict_get (the_sessions, handle_to_pointer (session));
	if (!sess)
		return CKR_SESSION_HANDLE_INVALID;

	rv = lookup_object (sess, object, &attrs, &table);
	if (rv != CKR_OK)
		return rv;

	p11_dict_remove (table, handle_to_pointer (object));
	return CKR_OK;
}

CK_RV
mock_C_DestroyObject__invalid_handle (CK_SESSION_HANDLE session,
                                      CK_OBJECT_HANDLE object)
{
	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_X_DestroyObject__invalid_handle (CK_X_FUNCTION_LIST *self,
                                      CK_SESSION_HANDLE session,
                                      CK_OBJECT_HANDLE object)
{
	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_C_GetObjectSize (CK_SESSION_HANDLE session,
                      CK_OBJECT_HANDLE object,
                      CK_ULONG_PTR size)
{
	CK_ATTRIBUTE *attrs;
	Session *sess;
	CK_RV rv;
	CK_ULONG i;

	return_val_if_fail (size != NULL, CKR_ARGUMENTS_BAD);

	sess = p11_dict_get (the_sessions, handle_to_pointer (session));
	if (!sess)
		return CKR_SESSION_HANDLE_INVALID;

	rv = lookup_object (sess, object, &attrs, NULL);
	if (rv != CKR_OK)
		return rv;

	*size = 0;
	for (i = 0; !p11_attrs_terminator (attrs + i); i++) {
		if (attrs[i].ulValueLen != (CK_ULONG)-1)
			*size += attrs[i].ulValueLen;
	}

	return CKR_OK;
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
mock_X_GetObjectSize__invalid_handle (CK_X_FUNCTION_LIST *self,
                                      CK_SESSION_HANDLE session,
                                      CK_OBJECT_HANDLE object,
                                      CK_ULONG_PTR size)
{
	return_val_if_fail (size, CKR_ARGUMENTS_BAD);

	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_C_GetAttributeValue (CK_SESSION_HANDLE session,
                          CK_OBJECT_HANDLE object,
                          CK_ATTRIBUTE_PTR template,
                          CK_ULONG count)
{
	CK_ATTRIBUTE *result;
	CK_RV ret = CKR_OK;
	CK_ATTRIBUTE *attrs;
	CK_ATTRIBUTE *attr;
	Session *sess;
	CK_ULONG i;
	CK_RV rv;

	sess = p11_dict_get (the_sessions, handle_to_pointer (session));
	if (sess == NULL)
		return CKR_SESSION_HANDLE_INVALID;

	rv = lookup_object (sess, object, &attrs, NULL);
	if (rv != CKR_OK)
		return rv;

	for (i = 0; i < count; ++i) {
		result = template + i;
		attr = p11_attrs_find (attrs, result->type);
		if (!attr) {
			result->ulValueLen = (CK_ULONG)-1;
			ret = CKR_ATTRIBUTE_TYPE_INVALID;
			continue;
		}

		if (!result->pValue) {
			result->ulValueLen = attr->ulValueLen;
			continue;
		}

		if (result->ulValueLen >= attr->ulValueLen) {
			memcpy (result->pValue, attr->pValue, attr->ulValueLen);
			result->ulValueLen = attr->ulValueLen;
			continue;
		}

		result->ulValueLen = (CK_ULONG)-1;
		ret = CKR_BUFFER_TOO_SMALL;
	}

	return ret;
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
mock_X_GetAttributeValue__invalid_handle (CK_X_FUNCTION_LIST *self,
                                          CK_SESSION_HANDLE session,
                                          CK_OBJECT_HANDLE object,
                                          CK_ATTRIBUTE_PTR template,
                                          CK_ULONG count)
{
	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_C_GetAttributeValue__fail_first (CK_SESSION_HANDLE session,
                                      CK_OBJECT_HANDLE object,
                                      CK_ATTRIBUTE_PTR template,
                                      CK_ULONG count)
{
	return CKR_FUNCTION_REJECTED;
}

CK_RV
mock_C_GetAttributeValue__fail_late (CK_SESSION_HANDLE session,
                                     CK_OBJECT_HANDLE object,
                                     CK_ATTRIBUTE_PTR template,
                                     CK_ULONG count)
{
	CK_ULONG i;

	for (i = 0; i < count; i++) {
		if (template[i].pValue)
			return CKR_FUNCTION_FAILED;
	}
	return mock_C_GetAttributeValue (session, object, template, count);
}

CK_RV
mock_C_SetAttributeValue (CK_SESSION_HANDLE session,
                          CK_OBJECT_HANDLE object,
                          CK_ATTRIBUTE_PTR template,
                          CK_ULONG count)
{
	Session *sess;
	CK_ATTRIBUTE *attrs;
	p11_dict *table;
	CK_RV rv;

	sess = p11_dict_get (the_sessions, handle_to_pointer (session));
	if (!sess)
		return CKR_SESSION_HANDLE_INVALID;

	rv = lookup_object (sess, object, &attrs, &table);
	if (rv != CKR_OK)
		return rv;

	p11_dict_steal (table, handle_to_pointer (object), NULL, (void **)&attrs);
	attrs = p11_attrs_buildn (attrs, template, count);
	p11_dict_set (table, handle_to_pointer (object), attrs);
	return CKR_OK;
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
mock_X_SetAttributeValue__invalid_handle (CK_X_FUNCTION_LIST *self,
                                          CK_SESSION_HANDLE session,
                                          CK_OBJECT_HANDLE object,
                                          CK_ATTRIBUTE_PTR template,
                                          CK_ULONG count)
{
	return CKR_SESSION_HANDLE_INVALID;
}

typedef struct _FindObjects {
	CK_ATTRIBUTE *template;
	CK_ULONG count;
	Session *sess;
} FindObjects;

static bool
enumerate_and_find_objects (CK_OBJECT_HANDLE object,
                            CK_ATTRIBUTE *attrs,
                            void *user_data)
{
	FindObjects *ctx = user_data;
	CK_ATTRIBUTE *match;
	CK_ATTRIBUTE *attr;
	CK_BBOOL private;
	CK_ULONG i;

	if (!logged_in) {
		if (p11_attrs_find_bool (attrs, CKA_PRIVATE, &private) && private)
			return 1; /* Continue */
	}

	for (i = 0; i < ctx->count; ++i) {
		match = ctx->template + i;
		attr = p11_attrs_find (attrs, match->type);
		if (!attr)
			return true; /* Continue */

		if (attr->ulValueLen != match->ulValueLen ||
		    memcmp (attr->pValue, match->pValue, attr->ulValueLen) != 0)
			return true; /* Continue */
	}

	p11_array_push (ctx->sess->matches, handle_to_pointer (object));
	return true; /* Continue */
}

static int
compar_handles (const void *one,
                const void *two)
{
	void **p1 = (void **)one;
	void **p2 = (void **)two;
	return pointer_to_handle (*p2) - pointer_to_handle (*p1);
}

CK_RV
mock_C_FindObjectsInit (CK_SESSION_HANDLE session,
                        CK_ATTRIBUTE_PTR template,
                        CK_ULONG count)
{
	Session *sess;
	FindObjects ctx;

	sess = p11_dict_get (the_sessions, handle_to_pointer (session));
	if (!sess)
		return CKR_SESSION_HANDLE_INVALID;

	/* Starting an operation, cancels any previous one */
	sess->crypto_mechanism = 0;
	sess->hash_mechanism = 0;

	sess->finding = true;
	p11_array_free (sess->matches);
	sess->matches = p11_array_new (NULL);

	ctx.template = template;
	ctx.count = count;
	ctx.sess = sess;

	mock_module_enumerate_objects (session, enumerate_and_find_objects, &ctx);
	qsort (sess->matches->elem, sess->matches->num, sizeof (void *), compar_handles);
	return CKR_OK;
}

CK_RV
mock_C_FindObjectsInit__invalid_handle (CK_SESSION_HANDLE session,
                                        CK_ATTRIBUTE_PTR template,
                                        CK_ULONG count)
{
	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_X_FindObjectsInit__invalid_handle (CK_X_FUNCTION_LIST *self,
                                        CK_SESSION_HANDLE session,
                                        CK_ATTRIBUTE_PTR template,
                                        CK_ULONG count)
{
	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_C_FindObjectsInit__fails (CK_SESSION_HANDLE session,
                               CK_ATTRIBUTE_PTR template,
                               CK_ULONG count)
{
	return CKR_DEVICE_MEMORY;
}

CK_RV
mock_C_FindObjects (CK_SESSION_HANDLE session,
                    CK_OBJECT_HANDLE_PTR objects,
                    CK_ULONG max_object_count,
                    CK_ULONG_PTR object_count)
{
	Session *sess;

	return_val_if_fail (objects, CKR_ARGUMENTS_BAD);
	return_val_if_fail (object_count, CKR_ARGUMENTS_BAD);
	return_val_if_fail (max_object_count != 0, CKR_ARGUMENTS_BAD);

	sess = p11_dict_get (the_sessions, handle_to_pointer (session));
	if (sess == NULL)
		return CKR_SESSION_HANDLE_INVALID;
	if (!sess->finding)
		return CKR_OPERATION_NOT_INITIALIZED;

	*object_count = 0;
	while (max_object_count > 0) {
		if (sess->matches->num == 0)
			break;
		*objects = pointer_to_handle (sess->matches->elem[sess->matches->num - 1]);
		++objects;
		--max_object_count;
		++(*object_count);
		p11_array_remove (sess->matches, sess->matches->num - 1);
	}

	return CKR_OK;
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
mock_X_FindObjects__invalid_handle (CK_X_FUNCTION_LIST *self,
                                    CK_SESSION_HANDLE session,
                                    CK_OBJECT_HANDLE_PTR objects,
                                    CK_ULONG max_count,
                                    CK_ULONG_PTR count)
{
	return_val_if_fail (count, CKR_ARGUMENTS_BAD);

	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_C_FindObjects__fails (CK_SESSION_HANDLE session,
                           CK_OBJECT_HANDLE_PTR objects,
                           CK_ULONG max_count,
                           CK_ULONG_PTR count)
{
	return_val_if_fail (count, CKR_ARGUMENTS_BAD);

	return CKR_DEVICE_REMOVED;
}

CK_RV
mock_C_FindObjectsFinal (CK_SESSION_HANDLE session)
{

	Session *sess;

	sess = p11_dict_get (the_sessions, handle_to_pointer (session));
	if (sess == NULL)
		return CKR_SESSION_HANDLE_INVALID;
	if (!sess->finding)
		return CKR_OPERATION_NOT_INITIALIZED;

	sess->finding = false;
	p11_array_free (sess->matches);
	sess->matches = NULL;

	return CKR_OK;
}

CK_RV
mock_C_FindObjectsFinal__invalid_handle (CK_SESSION_HANDLE session)
{
	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_X_FindObjectsFinal__invalid_handle (CK_X_FUNCTION_LIST *self,
                                         CK_SESSION_HANDLE session)
{
	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_C_EncryptInit (CK_SESSION_HANDLE session,
                    CK_MECHANISM_PTR mechanism,
                    CK_OBJECT_HANDLE key)
{
	Session *sess;

	sess = p11_dict_get (the_sessions, handle_to_pointer (session));
	if (!sess)
		return CKR_SESSION_HANDLE_INVALID;

	/* can be called with pMechanism set to NULL_PTR to terminate an active encryption operation */
	if (mechanism == NULL) {
		if (sess->crypto_method & CKF_ENCRYPT) {
			sess->crypto_method &= ~CKF_ENCRYPT;
			return CKR_OK;
		} else
			return CKR_ARGUMENTS_BAD;
	}

	/* Starting an operation, cancels any previous one */
	sess->finding = CK_FALSE;

	if (mechanism->mechanism != CKM_MOCK_CAPITALIZE)
		return CKR_MECHANISM_INVALID;
	if (key != MOCK_PUBLIC_KEY_CAPITALIZE)
		return CKR_KEY_HANDLE_INVALID;

	sess->crypto_method |= CKF_ENCRYPT;
	sess->crypto_mechanism = CKM_MOCK_CAPITALIZE;
	sess->crypto_key = key;
	return CKR_OK;
}

CK_RV
mock_C_EncryptInit__invalid_handle (CK_SESSION_HANDLE session,
                                    CK_MECHANISM_PTR mechanism,
                                    CK_OBJECT_HANDLE key)
{
	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_X_EncryptInit__invalid_handle (CK_X_FUNCTION_LIST *self,
                                    CK_SESSION_HANDLE session,
                                    CK_MECHANISM_PTR mechanism,
                                    CK_OBJECT_HANDLE key)
{
	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_C_Encrypt (CK_SESSION_HANDLE session,
                CK_BYTE_PTR data,
                CK_ULONG data_len,
                CK_BYTE_PTR encrypted_data,
                CK_ULONG_PTR encrypted_data_len)
{
	CK_ULONG last = 0;
	Session *sess;
	CK_RV rv;

	sess = p11_dict_get (the_sessions, handle_to_pointer (session));
	if (!sess)
		return CKR_SESSION_HANDLE_INVALID;

	rv = mock_C_EncryptUpdate (session, data, data_len, encrypted_data, encrypted_data_len);
	if (rv == CKR_OK && sess->crypto_final)
		rv = mock_C_EncryptFinal (session, encrypted_data, &last);
	return rv;
}

CK_RV
mock_C_Encrypt__invalid_handle (CK_SESSION_HANDLE session,
                                CK_BYTE_PTR data,
                                CK_ULONG data_len,
                                CK_BYTE_PTR encrypted_data,
                                CK_ULONG_PTR encrypted_data_len)
{
	return_val_if_fail (encrypted_data_len, CKR_ARGUMENTS_BAD);

	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_X_Encrypt__invalid_handle (CK_X_FUNCTION_LIST *self,
                                CK_SESSION_HANDLE session,
                                CK_BYTE_PTR data,
                                CK_ULONG data_len,
                                CK_BYTE_PTR encrypted_data,
                                CK_ULONG_PTR encrypted_data_len)
{
	return_val_if_fail (encrypted_data_len, CKR_ARGUMENTS_BAD);

	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_C_EncryptUpdate (CK_SESSION_HANDLE session,
                      CK_BYTE_PTR part,
                      CK_ULONG part_len,
                      CK_BYTE_PTR encrypted_part,
                      CK_ULONG_PTR encrypted_part_len)
{
	Session *sess;
	CK_ULONG i;

	return_val_if_fail (part != NULL, CKR_DATA_INVALID);
	return_val_if_fail (encrypted_part_len != NULL, CKR_ARGUMENTS_BAD);

	sess = p11_dict_get (the_sessions, handle_to_pointer (session));
	if (!sess)
		return CKR_SESSION_HANDLE_INVALID;

	sess->crypto_final = false;
	if (!sess->crypto_mechanism)
		return CKR_OPERATION_NOT_INITIALIZED;
	if (!(sess->crypto_method & CKF_ENCRYPT))
		return CKR_OPERATION_NOT_INITIALIZED;
	assert (sess->crypto_mechanism == CKM_MOCK_CAPITALIZE);
	assert (sess->crypto_key == MOCK_PUBLIC_KEY_CAPITALIZE);

	if (!encrypted_part) {
		*encrypted_part_len = part_len;
		return CKR_OK;
	}

	if (*encrypted_part_len < part_len) {
		*encrypted_part_len = part_len;
		return CKR_BUFFER_TOO_SMALL;
	}

	for (i = 0; i < part_len; ++i)
		encrypted_part[i] = p11_ascii_toupper (part[i]);
	*encrypted_part_len = part_len;
	sess->crypto_final = true;
	return CKR_OK;
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
mock_X_EncryptUpdate__invalid_handle (CK_X_FUNCTION_LIST *self,
                                      CK_SESSION_HANDLE session,
                                      CK_BYTE_PTR part,
                                      CK_ULONG part_len,
                                      CK_BYTE_PTR encrypted_part,
                                      CK_ULONG_PTR encrypted_part_len)
{
	return_val_if_fail (encrypted_part_len, CKR_ARGUMENTS_BAD);

	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_C_EncryptFinal (CK_SESSION_HANDLE session,
                     CK_BYTE_PTR last_encrypted_part,
                     CK_ULONG_PTR last_encrypted_part_len)
{
	Session *sess;

	return_val_if_fail (last_encrypted_part_len != NULL, CKR_ARGUMENTS_BAD);

	sess = p11_dict_get (the_sessions, handle_to_pointer (session));
	if (!sess)
		return CKR_SESSION_HANDLE_INVALID;

	if (!sess->crypto_mechanism)
		return CKR_OPERATION_NOT_INITIALIZED;
	if (!(sess->crypto_method & CKF_ENCRYPT))
		return CKR_OPERATION_NOT_INITIALIZED;

	*last_encrypted_part_len = 0;

	sess->crypto_method &= ~CKF_ENCRYPT;
	sess->crypto_mechanism = 0;
	sess->crypto_key = 0;
	return CKR_OK;
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
mock_X_EncryptFinal__invalid_handle (CK_X_FUNCTION_LIST *self,
                                     CK_SESSION_HANDLE session,
                                     CK_BYTE_PTR last_part,
                                     CK_ULONG_PTR last_part_len)
{
	return_val_if_fail (last_part_len, CKR_ARGUMENTS_BAD);

	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_C_DecryptInit (CK_SESSION_HANDLE session,
                    CK_MECHANISM_PTR mechanism,
                    CK_OBJECT_HANDLE key)
{
	Session *sess;

	sess = p11_dict_get (the_sessions, handle_to_pointer (session));
	if (!sess)
		return CKR_SESSION_HANDLE_INVALID;

	/* can be called with pMechanism set to NULL_PTR to terminate an active decryption operation */
	if (mechanism == NULL) {
		if (sess->crypto_method & CKF_DECRYPT) {
			sess->crypto_method &= ~CKF_DECRYPT;
			return CKR_OK;
		} else
			return CKR_ARGUMENTS_BAD;
	}

	/* Starting an operation, cancels any previous one */
	sess->finding = false;

	if (mechanism->mechanism != CKM_MOCK_CAPITALIZE)
		return CKR_MECHANISM_INVALID;
	if (key != MOCK_PRIVATE_KEY_CAPITALIZE)
		return CKR_KEY_HANDLE_INVALID;

	sess->crypto_method |= CKF_DECRYPT;
	sess->crypto_mechanism = CKM_MOCK_CAPITALIZE;
	sess->crypto_key = key;
	return CKR_OK;
}

CK_RV
mock_C_DecryptInit__invalid_handle (CK_SESSION_HANDLE session,
                                    CK_MECHANISM_PTR mechanism,
                                    CK_OBJECT_HANDLE key)
{
	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_X_DecryptInit__invalid_handle (CK_X_FUNCTION_LIST *self,
                                    CK_SESSION_HANDLE session,
                                    CK_MECHANISM_PTR mechanism,
                                    CK_OBJECT_HANDLE key)
{
	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_C_Decrypt (CK_SESSION_HANDLE session,
                CK_BYTE_PTR encrypted_data,
                CK_ULONG encrypted_data_len,
                CK_BYTE_PTR data,
                CK_ULONG_PTR data_len)
{
	CK_ULONG last = 0;
	Session *sess;
	CK_RV rv;

	sess = p11_dict_get (the_sessions, handle_to_pointer (session));
	if (!sess)
		return CKR_SESSION_HANDLE_INVALID;
	rv = mock_C_DecryptUpdate (session, encrypted_data, encrypted_data_len, data, data_len);
	if (rv == CKR_OK && sess->crypto_final)
		rv = mock_C_DecryptFinal (session, data, &last);
	return rv;
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
mock_X_Decrypt__invalid_handle (CK_X_FUNCTION_LIST *self,
                                CK_SESSION_HANDLE session,
                                CK_BYTE_PTR enc_data,
                                CK_ULONG enc_data_len,
                                CK_BYTE_PTR data,
                                CK_ULONG_PTR data_len)
{
	return_val_if_fail (data_len, CKR_ARGUMENTS_BAD);

	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_C_DecryptUpdate (CK_SESSION_HANDLE session,
                      CK_BYTE_PTR encrypted_part,
                      CK_ULONG encrypted_part_len,
                      CK_BYTE_PTR part,
                      CK_ULONG_PTR part_len)
{
	Session *sess;
	CK_ULONG i;

	return_val_if_fail (encrypted_part, CKR_ENCRYPTED_DATA_INVALID);
	return_val_if_fail (part_len, CKR_ARGUMENTS_BAD);

	sess = p11_dict_get (the_sessions, handle_to_pointer (session));
	if (!sess)
		return CKR_SESSION_HANDLE_INVALID;

	sess->crypto_final = false;
	if (!sess->crypto_mechanism)
		return CKR_OPERATION_NOT_INITIALIZED;
	if (!(sess->crypto_method & CKF_DECRYPT))
		return CKR_OPERATION_NOT_INITIALIZED;
	assert (sess->crypto_mechanism == CKM_MOCK_CAPITALIZE);
	assert (sess->crypto_key == MOCK_PRIVATE_KEY_CAPITALIZE);

	if (!part) {
		*part_len = encrypted_part_len;
		return CKR_OK;
	}

	if (*part_len < encrypted_part_len) {
		*part_len = encrypted_part_len;
		return CKR_BUFFER_TOO_SMALL;
	}

	for (i = 0; i < encrypted_part_len; ++i)
		part[i] = p11_ascii_tolower (encrypted_part[i]);
	*part_len = encrypted_part_len;
	sess->crypto_final = true;
	return CKR_OK;
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
mock_X_DecryptUpdate__invalid_handle (CK_X_FUNCTION_LIST *self,
                                      CK_SESSION_HANDLE session,
                                      CK_BYTE_PTR enc_part,
                                      CK_ULONG enc_part_len,
                                      CK_BYTE_PTR part,
                                      CK_ULONG_PTR part_len)
{
	return_val_if_fail (part_len, CKR_ARGUMENTS_BAD);

	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_C_DecryptFinal (CK_SESSION_HANDLE session,
                     CK_BYTE_PTR last_part,
                     CK_ULONG_PTR last_part_len)
{
	Session *sess;

	return_val_if_fail (last_part_len != NULL, CKR_ARGUMENTS_BAD);

	sess = p11_dict_get (the_sessions, handle_to_pointer (session));
	if (!sess)
		return CKR_SESSION_HANDLE_INVALID;

	if (!sess->crypto_mechanism)
		return CKR_OPERATION_NOT_INITIALIZED;
	if (!(sess->crypto_method & CKF_DECRYPT))
		return CKR_OPERATION_NOT_INITIALIZED;

	*last_part_len = 0;

	sess->crypto_method &= ~CKF_DECRYPT;
	sess->crypto_mechanism = 0;
	sess->crypto_key = 0;

	return CKR_OK;
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
mock_X_DecryptFinal__invalid_handle (CK_X_FUNCTION_LIST *self,
                                     CK_SESSION_HANDLE session,
                                     CK_BYTE_PTR last_part,
                                     CK_ULONG_PTR last_part_len)
{
	return_val_if_fail (last_part_len, CKR_ARGUMENTS_BAD);

	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_C_DigestInit (CK_SESSION_HANDLE session,
                   CK_MECHANISM_PTR mechanism)
{
	Session *sess;

	sess = p11_dict_get (the_sessions, handle_to_pointer (session));
	if (!sess)
		return CKR_SESSION_HANDLE_INVALID;

	/* can be called with pMechanism set to NULL_PTR to terminate an active message-digesting operation */
	if (mechanism == NULL) {
		if (sess->hash_method == CKF_DIGEST) {
			sess->hash_method = 0;
			return CKR_OK;
		} else
			return CKR_ARGUMENTS_BAD;
	}

	/* Starting an operation, cancels any previous one */
	sess->finding = false;

	if (mechanism->mechanism != CKM_MOCK_COUNT)
		return CKR_MECHANISM_INVALID;

	sess->hash_mechanism = CKM_MOCK_COUNT;
	sess->hash_method = CKF_DIGEST;
	sess->hash_count = 0;
	sess->hash_key = 0;
	return CKR_OK;
}

CK_RV
mock_C_DigestInit__invalid_handle (CK_SESSION_HANDLE session,
                                   CK_MECHANISM_PTR mechanism)
{
	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_X_DigestInit__invalid_handle (CK_X_FUNCTION_LIST *self,
                                   CK_SESSION_HANDLE session,
                                   CK_MECHANISM_PTR mechanism)
{
	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_C_Digest (CK_SESSION_HANDLE session,
               CK_BYTE_PTR data,
               CK_ULONG data_len,
               CK_BYTE_PTR digest,
               CK_ULONG_PTR digest_len)
{
	Session *sess;
	CK_RV rv;

	return_val_if_fail (digest_len, CKR_ARGUMENTS_BAD);

	sess = p11_dict_get (the_sessions, handle_to_pointer (session));
	if (!sess)
		return CKR_SESSION_HANDLE_INVALID;

	rv = mock_C_DigestUpdate (session, data, data_len);
	if (rv == CKR_OK) {
		rv = mock_C_DigestFinal (session, digest, digest_len);
		if (sess->hash_method == CKF_DIGEST) {
			/* not finalized -- reset the state */
			sess->hash_count = 0;
		}
	}
	return rv;
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
mock_X_Digest__invalid_handle (CK_X_FUNCTION_LIST *self,
                               CK_SESSION_HANDLE session,
                               CK_BYTE_PTR data,
                               CK_ULONG data_len,
                               CK_BYTE_PTR digest,
                               CK_ULONG_PTR digest_len)
{
	return_val_if_fail (digest_len, CKR_ARGUMENTS_BAD);

	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_C_DigestUpdate (CK_SESSION_HANDLE session,
                     CK_BYTE_PTR part,
                     CK_ULONG part_len)
{
	Session *sess;

	sess = p11_dict_get (the_sessions, handle_to_pointer (session));
	if (!sess)
		return CKR_SESSION_HANDLE_INVALID;

	if (!sess->hash_mechanism)
		return CKR_OPERATION_NOT_INITIALIZED;
	if (sess->hash_method != CKF_DIGEST)
		return CKR_OPERATION_NOT_INITIALIZED;
	assert (sess->hash_mechanism == CKM_MOCK_COUNT);

	sess->hash_count += part_len;
	return CKR_OK;
}

CK_RV
mock_C_DigestUpdate__invalid_handle (CK_SESSION_HANDLE session,
                                     CK_BYTE_PTR part,
                                     CK_ULONG part_len)
{
	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_X_DigestUpdate__invalid_handle (CK_X_FUNCTION_LIST *self,
                                     CK_SESSION_HANDLE session,
                                     CK_BYTE_PTR part,
                                     CK_ULONG part_len)
{
	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_C_DigestKey (CK_SESSION_HANDLE session,
                  CK_OBJECT_HANDLE key)
{
	Session *sess;

	sess = p11_dict_get (the_sessions, handle_to_pointer (session));
	if (!sess)
		return CKR_SESSION_HANDLE_INVALID;

	if (!sess->hash_mechanism)
		return CKR_OPERATION_NOT_INITIALIZED;
	if (sess->hash_method != CKF_DIGEST)
		return CKR_OPERATION_NOT_INITIALIZED;
	assert (sess->hash_mechanism == CKM_MOCK_COUNT);

	sess->hash_count += key;
	return CKR_OK;
}

CK_RV
mock_C_DigestKey__invalid_handle (CK_SESSION_HANDLE session,
                                  CK_OBJECT_HANDLE key)
{
	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_X_DigestKey__invalid_handle (CK_X_FUNCTION_LIST *self,
                                  CK_SESSION_HANDLE session,
                                  CK_OBJECT_HANDLE key)
{
	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_C_DigestFinal (CK_SESSION_HANDLE session,
                    CK_BYTE_PTR digest,
                    CK_ULONG_PTR digest_len)
{
	char buffer[32];
	Session *sess;
	int len;

	return_val_if_fail (digest_len != NULL, CKR_ARGUMENTS_BAD);

	sess = p11_dict_get (the_sessions, handle_to_pointer (session));
	if (!sess)
		return CKR_SESSION_HANDLE_INVALID;

	if (!sess->hash_mechanism)
		return CKR_OPERATION_NOT_INITIALIZED;
	if (sess->hash_method != CKF_DIGEST)
		return CKR_OPERATION_NOT_INITIALIZED;
	assert (sess->hash_mechanism == CKM_MOCK_COUNT);

	len = snprintf (buffer, sizeof (buffer), "%lu", sess->hash_count);

	if (!digest) {
		*digest_len = len;
		return CKR_OK;
	} else if (*digest_len < len) {
		*digest_len = len;
		return CKR_BUFFER_TOO_SMALL;
	}

	memcpy (digest, &buffer, len);
	*digest_len = len;

	sess->hash_count = 0;
	sess->hash_mechanism = 0;
	sess->hash_key = 0;
	sess->hash_method = 0;

	return CKR_OK;
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
mock_X_DigestFinal__invalid_handle (CK_X_FUNCTION_LIST *self,
                                    CK_SESSION_HANDLE session,
                                    CK_BYTE_PTR digest,
                                    CK_ULONG_PTR digest_len)
{
	return_val_if_fail (digest_len, CKR_ARGUMENTS_BAD);

	return CKR_SESSION_HANDLE_INVALID;
}

static CK_RV
prefix_mechanism_init (CK_SESSION_HANDLE session,
                       CK_FLAGS method,
                       CK_MECHANISM_PTR mechanism,
                       CK_OBJECT_HANDLE key)
{
	Session *sess;
	CK_ATTRIBUTE *attrs;
	CK_ATTRIBUTE *value;
	CK_BYTE_PTR param;
	CK_ULONG n_param;
	CK_ULONG length;
	CK_RV rv;

	sess = p11_dict_get (the_sessions, handle_to_pointer (session));
	if (!sess)
		return CKR_SESSION_HANDLE_INVALID;

	if (mechanism->mechanism != CKM_MOCK_PREFIX)
		return CKR_MECHANISM_INVALID;
	if (method == CKF_SIGN || method == CKF_SIGN_RECOVER) {
		if (key != MOCK_PRIVATE_KEY_PREFIX)
			return CKR_KEY_HANDLE_INVALID;
	} else if (method == CKF_VERIFY || method == CKF_VERIFY_RECOVER) {
		if (key != MOCK_PUBLIC_KEY_PREFIX)
			return CKR_KEY_HANDLE_INVALID;
	} else {
		assert_not_reached ();
	}

	rv = lookup_object (sess, key, &attrs, NULL);
	if (rv != CKR_OK)
		return rv;

	value = p11_attrs_find_valid (attrs, CKA_VALUE);
	if (value == NULL)
		return CKR_KEY_TYPE_INCONSISTENT;

	if (mechanism->pParameter) {
		param = mechanism->pParameter;
		n_param = mechanism->ulParameterLen;
	} else {
		param = (CK_BYTE_PTR)SIGNED_PREFIX;
		n_param = strlen (SIGNED_PREFIX) + 1;
	}

	length = value->ulValueLen + n_param;
	if (length > sizeof (sess->sign_prefix))
		return CKR_KEY_SIZE_RANGE;

	/* Starting an operation, cancels any finding */
	sess->finding = false;

	sess->hash_mechanism = CKM_MOCK_PREFIX;
	sess->hash_method = method;
	sess->hash_key = key;
	sess->hash_count = 0;

	memcpy (sess->sign_prefix, param, n_param);
	memcpy (sess->sign_prefix + n_param, value->pValue, value->ulValueLen);
	sess->n_sign_prefix = length;

	/* The private key has CKA_ALWAYS_AUTHENTICATE above */
	if (method == CKF_SIGN || method == CKF_SIGN_RECOVER)
		sess->want_context_login = true;

	return CKR_OK;

}

CK_RV
mock_C_SignInit (CK_SESSION_HANDLE session,
                 CK_MECHANISM_PTR mechanism,
                 CK_OBJECT_HANDLE key)
{
	Session *sess;

	sess = p11_dict_get (the_sessions, handle_to_pointer (session));
	if (!sess)
		return CKR_SESSION_HANDLE_INVALID;

	/* can be called with pMechanism set to NULL_PTR to terminate an active signature operation */
	if (mechanism == NULL) {
		if (sess->hash_method == CKF_SIGN) {
			sess->hash_method = 0;
			return CKR_OK;
		} else
			return CKR_ARGUMENTS_BAD;
	}

	return prefix_mechanism_init (session, CKF_SIGN, mechanism, key);
}

CK_RV
mock_C_SignInit__invalid_handle (CK_SESSION_HANDLE session,
                                 CK_MECHANISM_PTR mechanism,
                                 CK_OBJECT_HANDLE key)
{
	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_X_SignInit__invalid_handle (CK_X_FUNCTION_LIST *self,
                                 CK_SESSION_HANDLE session,
                                 CK_MECHANISM_PTR mechanism,
                                 CK_OBJECT_HANDLE key)
{
	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_C_Sign (CK_SESSION_HANDLE session,
             CK_BYTE_PTR data,
             CK_ULONG data_len,
             CK_BYTE_PTR signature,
             CK_ULONG_PTR signature_len)
{
	Session *sess;
	CK_RV rv;

	sess = p11_dict_get (the_sessions, handle_to_pointer (session));
	if (!sess)
		return CKR_SESSION_HANDLE_INVALID;

	rv = mock_C_SignUpdate (session, data, data_len);

	if (rv == CKR_OK) {
		rv = mock_C_SignFinal (session, signature, signature_len);
		if (sess->hash_method == CKF_SIGN) {
			/* not finalized -- reset the state */
			sess->hash_count = 0;
		}
	}

	return rv;
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
mock_X_Sign__invalid_handle (CK_X_FUNCTION_LIST *self,
                             CK_SESSION_HANDLE session,
                             CK_BYTE_PTR data,
                             CK_ULONG data_len,
                             CK_BYTE_PTR signature,
                             CK_ULONG_PTR signature_len)
{
	return_val_if_fail (signature_len, CKR_ARGUMENTS_BAD);

	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_C_SignUpdate (CK_SESSION_HANDLE session,
                   CK_BYTE_PTR part,
                   CK_ULONG part_len)
{
	Session *sess;

	sess = p11_dict_get (the_sessions, handle_to_pointer (session));
	if (!sess)
		return CKR_SESSION_HANDLE_INVALID;
	if (sess->hash_mechanism != CKM_MOCK_PREFIX ||
	    sess->hash_method != CKF_SIGN)
		return CKR_OPERATION_NOT_INITIALIZED;
	if (sess->want_context_login)
		return CKR_USER_NOT_LOGGED_IN;

	sess->hash_count += part_len;
	return CKR_OK;
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
mock_X_SignUpdate__invalid_handle (CK_X_FUNCTION_LIST *self,
                                   CK_SESSION_HANDLE session,
                                   CK_BYTE_PTR part,
                                   CK_ULONG part_len)
{
	return_val_if_fail (part_len, CKR_ARGUMENTS_BAD);

	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_C_SignFinal (CK_SESSION_HANDLE session,
                  CK_BYTE_PTR signature,
                  CK_ULONG_PTR signature_len)
{
	char buffer[32];
	Session *sess;
	CK_ULONG length;
	int len;

	return_val_if_fail (signature_len, CKR_ARGUMENTS_BAD);

	sess = p11_dict_get (the_sessions, handle_to_pointer (session));
	if (!sess)
		return CKR_SESSION_HANDLE_INVALID;
	if (sess->hash_mechanism != CKM_MOCK_PREFIX ||
	    sess->hash_method != CKF_SIGN)
		return CKR_OPERATION_NOT_INITIALIZED;
	if (sess->want_context_login)
		return CKR_USER_NOT_LOGGED_IN;

	len = snprintf (buffer, sizeof (buffer), "%lu", sess->hash_count);
	length = sess->n_sign_prefix + len;

	if (!signature) {
		*signature_len = length;
		return CKR_OK;
	}

	if (*signature_len < length) {
		*signature_len = length;
		return CKR_BUFFER_TOO_SMALL;
	}

	memcpy (signature, sess->sign_prefix, sess->n_sign_prefix);
	memcpy (signature + sess->n_sign_prefix, buffer, len);
	*signature_len = length;

	sess->hash_mechanism = 0;
	sess->hash_method = 0;
	sess->hash_count = 0;
	sess->hash_key = 0;

	return CKR_OK;
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
mock_X_SignFinal__invalid_handle (CK_X_FUNCTION_LIST *self,
                                  CK_SESSION_HANDLE session,
                                  CK_BYTE_PTR signature,
                                  CK_ULONG_PTR signature_len)
{
	return_val_if_fail (signature_len, CKR_ARGUMENTS_BAD);

	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_C_SignRecoverInit (CK_SESSION_HANDLE session,
                        CK_MECHANISM_PTR mechanism,
                        CK_OBJECT_HANDLE key)
{
	Session *sess;

	sess = p11_dict_get (the_sessions, handle_to_pointer (session));
	if (!sess)
		return CKR_SESSION_HANDLE_INVALID;

	/* can be called with pMechanism set to NULL_PTR to terminate
	 * an active signature with data recovery operation */
	if (mechanism == NULL) {
		if (sess->hash_method == CKF_SIGN_RECOVER) {
			sess->hash_method = 0;
			return CKR_OK;
		} else
			return CKR_ARGUMENTS_BAD;
	}

	return prefix_mechanism_init (session, CKF_SIGN_RECOVER, mechanism, key);
}

CK_RV
mock_C_SignRecoverInit__invalid_handle (CK_SESSION_HANDLE session,
                                        CK_MECHANISM_PTR mechanism,
                                        CK_OBJECT_HANDLE key)
{
	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_X_SignRecoverInit__invalid_handle (CK_X_FUNCTION_LIST *self,
                                        CK_SESSION_HANDLE session,
                                        CK_MECHANISM_PTR mechanism,
                                        CK_OBJECT_HANDLE key)
{
	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_C_SignRecover (CK_SESSION_HANDLE session,
                    CK_BYTE_PTR data,
                    CK_ULONG data_len,
                    CK_BYTE_PTR signature,
                    CK_ULONG_PTR signature_len)
{
	Session *sess;
	CK_ULONG length;

	return_val_if_fail (data, CKR_DATA_INVALID);
	return_val_if_fail (signature_len, CKR_ARGUMENTS_BAD);

	sess = p11_dict_get (the_sessions, handle_to_pointer (session));
	if (!sess)
		return CKR_SESSION_HANDLE_INVALID;
	if (sess->hash_method != CKF_SIGN_RECOVER ||
	    sess->hash_mechanism != CKM_MOCK_PREFIX)
		return CKR_OPERATION_NOT_INITIALIZED;
	if (sess->want_context_login)
		return CKR_USER_NOT_LOGGED_IN;

	length = sess->n_sign_prefix + data_len;

	if (!signature) {
		*signature_len = length;
		return CKR_OK;
	}

	if (*signature_len < length) {
		*signature_len = length;
		return CKR_BUFFER_TOO_SMALL;
	}

	memcpy (signature, sess->sign_prefix, sess->n_sign_prefix);
	memcpy (signature + sess->n_sign_prefix, data, data_len);
	*signature_len = length;

	sess->hash_method = 0;
	sess->hash_mechanism = 0;
	sess->hash_key = 0;
	sess->hash_count = 0;

	return CKR_OK;
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
mock_X_SignRecover__invalid_handle (CK_X_FUNCTION_LIST *self,
                                    CK_SESSION_HANDLE session,
                                    CK_BYTE_PTR data,
                                    CK_ULONG data_len,
                                    CK_BYTE_PTR signature,
                                    CK_ULONG_PTR signature_len)
{
	return_val_if_fail (signature_len, CKR_ARGUMENTS_BAD);

	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_C_VerifyInit (CK_SESSION_HANDLE session,
                   CK_MECHANISM_PTR mechanism,
                   CK_OBJECT_HANDLE key)
{
	Session *sess;

	sess = p11_dict_get (the_sessions, handle_to_pointer (session));
	if (!sess)
		return CKR_SESSION_HANDLE_INVALID;

	/* can be called with pMechanism set to NULL_PTR to terminate an active verification operation */
	if (mechanism == NULL) {
		if (sess->hash_method == CKF_VERIFY) {
			sess->hash_method = 0;
			return CKR_OK;
		} else
			return CKR_ARGUMENTS_BAD;
	}

	return prefix_mechanism_init (session, CKF_VERIFY, mechanism, key);
}

CK_RV
mock_C_VerifyInit__invalid_handle (CK_SESSION_HANDLE session,
                                   CK_MECHANISM_PTR mechanism,
                                   CK_OBJECT_HANDLE key)
{
	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_X_VerifyInit__invalid_handle (CK_X_FUNCTION_LIST *self,
                                   CK_SESSION_HANDLE session,
                                   CK_MECHANISM_PTR mechanism,
                                   CK_OBJECT_HANDLE key)
{
	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_C_Verify (CK_SESSION_HANDLE session,
               CK_BYTE_PTR data,
               CK_ULONG data_len,
               CK_BYTE_PTR signature,
               CK_ULONG signature_len)
{
	CK_RV rv;

	rv = mock_C_VerifyUpdate (session, data, data_len);
	if (rv == CKR_OK)
		rv = mock_C_VerifyFinal (session, signature, signature_len);

	return rv;
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
mock_X_Verify__invalid_handle (CK_X_FUNCTION_LIST *self,
                               CK_SESSION_HANDLE session,
                               CK_BYTE_PTR data,
                               CK_ULONG data_len,
                               CK_BYTE_PTR signature,
                               CK_ULONG signature_len)
{
	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_C_VerifyUpdate (CK_SESSION_HANDLE session,
                     CK_BYTE_PTR part,
                     CK_ULONG part_len)
{
	Session *sess;

	sess = p11_dict_get (the_sessions, handle_to_pointer (session));
	if (!sess)
		return CKR_SESSION_HANDLE_INVALID;
	if (sess->hash_mechanism != CKM_MOCK_PREFIX ||
	    sess->hash_method != CKF_VERIFY)
		return CKR_OPERATION_NOT_INITIALIZED;
	if (sess->want_context_login)
		return CKR_USER_NOT_LOGGED_IN;

	sess->hash_count += part_len;
	return CKR_OK;
}

CK_RV
mock_C_VerifyUpdate__invalid_handle (CK_SESSION_HANDLE session,
                                     CK_BYTE_PTR part,
                                     CK_ULONG part_len)
{
	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_X_VerifyUpdate__invalid_handle (CK_X_FUNCTION_LIST *self,
                                     CK_SESSION_HANDLE session,
                                     CK_BYTE_PTR part,
                                     CK_ULONG part_len)
{
	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_C_VerifyFinal (CK_SESSION_HANDLE session,
                    CK_BYTE_PTR signature,
                    CK_ULONG signature_len)
{
	char buffer[32];
	Session *sess;
	CK_ULONG length;
	int len;
	CK_RV rv = CKR_OK;

	return_val_if_fail (signature, CKR_ARGUMENTS_BAD);

	sess = p11_dict_get (the_sessions, handle_to_pointer (session));
	if (!sess)
		return CKR_SESSION_HANDLE_INVALID;
	if (sess->hash_mechanism != CKM_MOCK_PREFIX ||
	    sess->hash_method != CKF_VERIFY)
		return CKR_OPERATION_NOT_INITIALIZED;
	if (sess->want_context_login)
		return CKR_USER_NOT_LOGGED_IN;

	len = snprintf (buffer, sizeof (buffer), "%lu", sess->hash_count);
	length = sess->n_sign_prefix + len;

	if (signature_len != length)
		return CKR_SIGNATURE_LEN_RANGE;

	if (memcmp (signature, sess->sign_prefix, sess->n_sign_prefix) != 0 ||
	    memcmp (signature + sess->n_sign_prefix, buffer, len) != 0)
		rv = CKR_SIGNATURE_INVALID;

	sess->hash_mechanism = 0;
	sess->hash_method = 0;
	sess->hash_count = 0;
	sess->hash_key = 0;

	return rv;
}

CK_RV
mock_C_VerifyFinal__invalid_handle (CK_SESSION_HANDLE session,
                                    CK_BYTE_PTR signature,
                                    CK_ULONG signature_len)
{
	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_X_VerifyFinal__invalid_handle (CK_X_FUNCTION_LIST *self,
                                    CK_SESSION_HANDLE session,
                                    CK_BYTE_PTR signature,
                                    CK_ULONG signature_len)
{
	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_C_VerifyRecoverInit (CK_SESSION_HANDLE session,
                          CK_MECHANISM_PTR mechanism,
                          CK_OBJECT_HANDLE key)
{
	Session *sess;

	sess = p11_dict_get (the_sessions, handle_to_pointer (session));
	if (!sess)
		return CKR_SESSION_HANDLE_INVALID;

	/* can be called with pMechanism set to NULL_PTR to terminate
	 * an active verification with data recovery operation */
	if (mechanism == NULL) {
		if (sess->hash_method == CKF_VERIFY_RECOVER) {
			sess->hash_method = 0;
			return CKR_OK;
		} else
			return CKR_ARGUMENTS_BAD;
	}

	return prefix_mechanism_init (session, CKF_VERIFY_RECOVER, mechanism, key);
}

CK_RV
mock_C_VerifyRecoverInit__invalid_handle (CK_SESSION_HANDLE session,
                                          CK_MECHANISM_PTR mechanism,
                                          CK_OBJECT_HANDLE key)
{
	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_X_VerifyRecoverInit__invalid_handle (CK_X_FUNCTION_LIST *self,
                                          CK_SESSION_HANDLE session,
                                          CK_MECHANISM_PTR mechanism,
                                          CK_OBJECT_HANDLE key)
{
	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_C_VerifyRecover (CK_SESSION_HANDLE session,
                      CK_BYTE_PTR signature,
                      CK_ULONG signature_len,
                      CK_BYTE_PTR data,
                      CK_ULONG_PTR data_len)
{
	Session *sess;
	CK_ULONG length;

	return_val_if_fail (signature, CKR_ARGUMENTS_BAD);

	sess = p11_dict_get (the_sessions, handle_to_pointer (session));
	if (!sess)
		return CKR_SESSION_HANDLE_INVALID;
	if (sess->hash_mechanism != CKM_MOCK_PREFIX ||
	    sess->hash_method != CKF_VERIFY_RECOVER)
		return CKR_OPERATION_NOT_INITIALIZED;
	if (sess->want_context_login)
		return CKR_USER_NOT_LOGGED_IN;

	if (signature_len < sess->n_sign_prefix)
		return CKR_SIGNATURE_LEN_RANGE;
	if (memcmp (signature, sess->sign_prefix, sess->n_sign_prefix) != 0)
		return CKR_SIGNATURE_INVALID;

	length = signature_len - sess->n_sign_prefix;
	if (!data) {
		*data_len = length;
		return CKR_OK;
	}

	if (*data_len < length) {
		*data_len = length;
		return CKR_BUFFER_TOO_SMALL;
	}

	*data_len = length;
	memcpy (data, signature + sess->n_sign_prefix, length);
	return CKR_OK;
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
mock_X_VerifyRecover__invalid_handle (CK_X_FUNCTION_LIST *self,
                                      CK_SESSION_HANDLE session,
                                      CK_BYTE_PTR signature,
                                      CK_ULONG signature_len,
                                      CK_BYTE_PTR data,
                                      CK_ULONG_PTR data_len)
{
	return_val_if_fail (data_len, CKR_ARGUMENTS_BAD);

	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_C_DigestEncryptUpdate (CK_SESSION_HANDLE session,
                            CK_BYTE_PTR part,
                            CK_ULONG part_len,
                            CK_BYTE_PTR encrypted_part,
                            CK_ULONG_PTR encrypted_part_len)
{
	CK_RV rv;

	rv = mock_C_EncryptUpdate (session, part, part_len, encrypted_part, encrypted_part_len);
	if (rv == CKR_OK)
		rv = mock_C_DigestUpdate (session, part, part_len);

	return rv;
}

CK_RV
mock_C_DigestEncryptUpdate__invalid_handle (CK_SESSION_HANDLE session,
                                            CK_BYTE_PTR part,
                                            CK_ULONG part_len,
                                            CK_BYTE_PTR enc_part,
                                            CK_ULONG_PTR enc_part_len)
{
	return_val_if_fail (enc_part_len, CKR_ARGUMENTS_BAD);

	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_X_DigestEncryptUpdate__invalid_handle (CK_X_FUNCTION_LIST *self,
                                            CK_SESSION_HANDLE session,
                                            CK_BYTE_PTR part,
                                            CK_ULONG part_len,
                                            CK_BYTE_PTR enc_part,
                                            CK_ULONG_PTR enc_part_len)
{
	return_val_if_fail (enc_part_len, CKR_ARGUMENTS_BAD);

	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_C_DecryptDigestUpdate (CK_SESSION_HANDLE session,
                            CK_BYTE_PTR encrypted_part,
                            CK_ULONG encrypted_part_len,
                            CK_BYTE_PTR part,
                            CK_ULONG_PTR part_len)
{
	CK_RV rv;

	rv = mock_C_DecryptUpdate (session, encrypted_part, encrypted_part_len, part, part_len);
	if (rv == CKR_OK)
		rv = mock_C_DigestUpdate (session, part, *part_len);

	return rv;
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
mock_X_DecryptDigestUpdate__invalid_handle (CK_X_FUNCTION_LIST *self,
                                            CK_SESSION_HANDLE session,
                                            CK_BYTE_PTR enc_part,
                                            CK_ULONG enc_part_len,
                                            CK_BYTE_PTR part,
                                            CK_ULONG_PTR part_len)
{
	return_val_if_fail (part_len, CKR_ARGUMENTS_BAD);

	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_C_SignEncryptUpdate (CK_SESSION_HANDLE session,
                          CK_BYTE_PTR part,
                          CK_ULONG part_len,
                          CK_BYTE_PTR encrypted_part,
                          CK_ULONG_PTR encrypted_part_len)
{
	CK_RV rv;

	rv = mock_C_EncryptUpdate (session, part, part_len, encrypted_part, encrypted_part_len);
	if (rv == CKR_OK)
		rv = mock_C_SignUpdate (session, part, part_len);

	return rv;
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
mock_X_SignEncryptUpdate__invalid_handle (CK_X_FUNCTION_LIST *self,
                                          CK_SESSION_HANDLE session,
                                          CK_BYTE_PTR part,
                                          CK_ULONG part_len,
                                          CK_BYTE_PTR enc_part,
                                          CK_ULONG_PTR enc_part_len)
{
	return_val_if_fail (enc_part_len, CKR_ARGUMENTS_BAD);

	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_C_DecryptVerifyUpdate (CK_SESSION_HANDLE session,
                            CK_BYTE_PTR encrypted_part,
                            CK_ULONG encrypted_part_len,
                            CK_BYTE_PTR part,
                            CK_ULONG_PTR part_len)
{
	CK_RV rv;

	rv = mock_C_DecryptUpdate (session, encrypted_part, encrypted_part_len, part, part_len);
	if (rv == CKR_OK)
		rv = mock_C_VerifyUpdate (session, part, *part_len);

	return rv;
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
mock_X_DecryptVerifyUpdate__invalid_handle (CK_X_FUNCTION_LIST *self,
                                            CK_SESSION_HANDLE session,
                                            CK_BYTE_PTR enc_part,
                                            CK_ULONG enc_part_len,
                                            CK_BYTE_PTR part,
                                            CK_ULONG_PTR part_len)
{
	return_val_if_fail (part_len, CKR_ARGUMENTS_BAD);

	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_C_GenerateKey (CK_SESSION_HANDLE session,
                    CK_MECHANISM_PTR mechanism,
                    CK_ATTRIBUTE_PTR template,
                    CK_ULONG count,
                    CK_OBJECT_HANDLE_PTR key)
{
	CK_ATTRIBUTE *attrs;
	CK_ATTRIBUTE value;
	Session *sess;
	CK_BBOOL token;

	return_val_if_fail (mechanism, CKR_MECHANISM_INVALID);
	return_val_if_fail (template, CKR_TEMPLATE_INCOMPLETE);
	return_val_if_fail (count, CKR_TEMPLATE_INCOMPLETE);
	return_val_if_fail (key, CKR_ARGUMENTS_BAD);

	sess = p11_dict_get (the_sessions, handle_to_pointer (session));
	if (!sess)
		return CKR_SESSION_HANDLE_INVALID;

	if (mechanism->mechanism != CKM_MOCK_GENERATE)
		return CKR_MECHANISM_INVALID;

	if (!mechanism->pParameter || mechanism->ulParameterLen != 9 ||
	    memcmp (mechanism->pParameter, "generate", 9) != 0)
		return CKR_MECHANISM_PARAM_INVALID;

	value.type = CKA_VALUE;
	value.pValue = "generated";
	value.ulValueLen = strlen (value.pValue);

	attrs = p11_attrs_buildn (NULL, template, count);
	attrs = p11_attrs_buildn (attrs, &value, 1);

	*key = ++unique_identifier;
	if (p11_attrs_find_bool (attrs, CKA_TOKEN, &token) && token)
		p11_dict_set (the_objects, handle_to_pointer (*key), attrs);
	else
		p11_dict_set (sess->objects, handle_to_pointer (*key), attrs);

	return CKR_OK;
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
mock_X_GenerateKey__invalid_handle (CK_X_FUNCTION_LIST *self,
                                    CK_SESSION_HANDLE session,
                                    CK_MECHANISM_PTR mechanism,
                                    CK_ATTRIBUTE_PTR template,
                                    CK_ULONG count,
                                    CK_OBJECT_HANDLE_PTR key)
{
	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_C_GenerateKeyPair (CK_SESSION_HANDLE session,
                        CK_MECHANISM_PTR mechanism,
                        CK_ATTRIBUTE_PTR public_key_template,
                        CK_ULONG public_key_count,
                        CK_ATTRIBUTE_PTR private_key_template,
                        CK_ULONG private_key_count,
                        CK_OBJECT_HANDLE_PTR public_key,
                        CK_OBJECT_HANDLE_PTR private_key)
{
	CK_ATTRIBUTE *attrs;
	CK_ATTRIBUTE value;
	Session *sess;
	CK_BBOOL token;

	return_val_if_fail (mechanism, CKR_MECHANISM_INVALID);
	return_val_if_fail (public_key_template, CKR_TEMPLATE_INCOMPLETE);
	return_val_if_fail (public_key_count, CKR_TEMPLATE_INCOMPLETE);
	return_val_if_fail (private_key_template, CKR_TEMPLATE_INCOMPLETE);
	return_val_if_fail (private_key_count, CKR_TEMPLATE_INCOMPLETE);
	return_val_if_fail (public_key, CKR_ARGUMENTS_BAD);
	return_val_if_fail (private_key, CKR_ARGUMENTS_BAD);

	sess = p11_dict_get (the_sessions, handle_to_pointer (session));
	if (!sess)
		return CKR_SESSION_HANDLE_INVALID;

	if (mechanism->mechanism != CKM_MOCK_GENERATE)
		return CKR_MECHANISM_INVALID;

	if (!mechanism->pParameter || mechanism->ulParameterLen != 9 ||
	    memcmp (mechanism->pParameter, "generate", 9) != 0)
		return CKR_MECHANISM_PARAM_INVALID;

	value.type = CKA_VALUE;
	value.pValue = "generated";
	value.ulValueLen = strlen (value.pValue);

	attrs = p11_attrs_buildn (NULL, public_key_template, public_key_count);
	attrs = p11_attrs_buildn (attrs, &value, 1);

	*public_key = ++unique_identifier;
	if (p11_attrs_find_bool (attrs, CKA_TOKEN, &token) && token)
		p11_dict_set (the_objects, handle_to_pointer (*public_key), attrs);
	else
		p11_dict_set (sess->objects, handle_to_pointer (*public_key), attrs);

	attrs = p11_attrs_buildn (NULL, private_key_template, private_key_count);
	attrs = p11_attrs_buildn (attrs, &value, 1);

	*private_key = ++unique_identifier;
	if (p11_attrs_find_bool (attrs, CKA_TOKEN, &token) && token)
		p11_dict_set (the_objects, handle_to_pointer (*private_key), attrs);
	else
		p11_dict_set (sess->objects, handle_to_pointer (*private_key), attrs);

	return CKR_OK;
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
mock_X_GenerateKeyPair__invalid_handle (CK_X_FUNCTION_LIST *self,
                                        CK_SESSION_HANDLE session,
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
mock_C_WrapKey (CK_SESSION_HANDLE session,
                CK_MECHANISM_PTR mechanism,
                CK_OBJECT_HANDLE wrapping_key,
                CK_OBJECT_HANDLE key,
                CK_BYTE_PTR wrapped_key,
                CK_ULONG_PTR wrapped_key_len)
{
	CK_ATTRIBUTE *attrs;
	CK_ATTRIBUTE *attr;
	Session *sess;
	CK_RV rv;

	return_val_if_fail (mechanism, CKR_MECHANISM_INVALID);
	return_val_if_fail (wrapping_key, CKR_OBJECT_HANDLE_INVALID);
	return_val_if_fail (key, CKR_OBJECT_HANDLE_INVALID);
	return_val_if_fail (wrapped_key_len, CKR_WRAPPED_KEY_LEN_RANGE);

	sess = p11_dict_get (the_sessions, handle_to_pointer (session));
	if (!sess)
		return CKR_SESSION_HANDLE_INVALID;

	rv = lookup_object (sess, wrapping_key, &attrs, NULL);
	if (rv == CKR_OBJECT_HANDLE_INVALID)
		return CKR_WRAPPING_KEY_HANDLE_INVALID;
	else if (rv != CKR_OK)
		return rv;

	rv = lookup_object (sess, key, &attrs, NULL);
	if (rv == CKR_OBJECT_HANDLE_INVALID)
		return CKR_WRAPPING_KEY_HANDLE_INVALID;
	else if (rv != CKR_OK)
		return rv;

	if (mechanism->mechanism != CKM_MOCK_WRAP)
		return CKR_MECHANISM_INVALID;

	if (mechanism->pParameter == NULL ||
	    mechanism->ulParameterLen != 4 ||
	    memcmp (mechanism->pParameter, "wrap", 4) != 0) {
		return CKR_MECHANISM_PARAM_INVALID;
	}

	attr = p11_attrs_find_valid (attrs, CKA_VALUE);
	if (attr == NULL)
		return CKR_WRAPPED_KEY_INVALID;

	if (!wrapped_key) {
		*wrapped_key_len = attr->ulValueLen;
		return CKR_OK;
	}

	if (*wrapped_key_len < attr->ulValueLen) {
		*wrapped_key_len = attr->ulValueLen;
		return CKR_BUFFER_TOO_SMALL;
	}

	memcpy (wrapped_key, attr->pValue, attr->ulValueLen);
	*wrapped_key_len = attr->ulValueLen;

	return CKR_OK;
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
mock_X_WrapKey__invalid_handle (CK_X_FUNCTION_LIST *self,
                                CK_SESSION_HANDLE session,
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
mock_C_UnwrapKey (CK_SESSION_HANDLE session,
                  CK_MECHANISM_PTR mechanism,
                  CK_OBJECT_HANDLE unwrapping_key,
                  CK_BYTE_PTR wrapped_key,
                  CK_ULONG wrapped_key_len,
                  CK_ATTRIBUTE_PTR template,
                  CK_ULONG count,
                  CK_OBJECT_HANDLE_PTR key)
{
	CK_ATTRIBUTE *attrs;
	CK_ATTRIBUTE value;
	Session *sess;
	CK_BBOOL token;
	CK_RV rv;

	return_val_if_fail (mechanism, CKR_MECHANISM_INVALID);
	return_val_if_fail (unwrapping_key, CKR_WRAPPING_KEY_HANDLE_INVALID);
	return_val_if_fail (wrapped_key, CKR_WRAPPED_KEY_INVALID);
	return_val_if_fail (wrapped_key_len, CKR_WRAPPED_KEY_LEN_RANGE);
	return_val_if_fail (key, CKR_ARGUMENTS_BAD);
	return_val_if_fail (template, CKR_TEMPLATE_INCOMPLETE);
	return_val_if_fail (count, CKR_TEMPLATE_INCONSISTENT);

	sess = p11_dict_get (the_sessions, handle_to_pointer (session));
	if (!sess)
		return CKR_SESSION_HANDLE_INVALID;

	rv = lookup_object (sess, unwrapping_key, &attrs, NULL);
	if (rv == CKR_OBJECT_HANDLE_INVALID)
		return CKR_WRAPPING_KEY_HANDLE_INVALID;
	else if (rv != CKR_OK)
		return rv;

	if (mechanism->mechanism != CKM_MOCK_WRAP)
		return CKR_MECHANISM_INVALID;

	if (mechanism->pParameter == NULL ||
	    mechanism->ulParameterLen != 4 ||
	    memcmp (mechanism->pParameter, "wrap", 4) != 0) {
		return CKR_MECHANISM_PARAM_INVALID;
	}

	value.type = CKA_VALUE;
	value.pValue = wrapped_key;
	value.ulValueLen = wrapped_key_len;

	attrs = p11_attrs_buildn (NULL, template, count);
	attrs = p11_attrs_buildn (attrs, &value, 1);

	*key = ++unique_identifier;
	if (p11_attrs_find_bool (attrs, CKA_TOKEN, &token) && token)
		p11_dict_set (the_objects, handle_to_pointer (*key), attrs);
	else
		p11_dict_set (sess->objects, handle_to_pointer (*key), attrs);

	return CKR_OK;
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
mock_X_UnwrapKey__invalid_handle (CK_X_FUNCTION_LIST *self,
                                  CK_SESSION_HANDLE session,
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
mock_C_DeriveKey (CK_SESSION_HANDLE session,
                  CK_MECHANISM_PTR mechanism,
                  CK_OBJECT_HANDLE base_key,
                  CK_ATTRIBUTE_PTR template,
                  CK_ULONG count,
                  CK_OBJECT_HANDLE_PTR key)
{
	CK_ATTRIBUTE *attrs, *copy;
	CK_ATTRIBUTE value;
	Session *sess;
	CK_BBOOL token;
	CK_RV rv;

	return_val_if_fail (mechanism, CKR_MECHANISM_INVALID);
	return_val_if_fail (count, CKR_TEMPLATE_INCOMPLETE);
	return_val_if_fail (template, CKR_TEMPLATE_INCOMPLETE);
	return_val_if_fail (key, CKR_ARGUMENTS_BAD);

	sess = p11_dict_get (the_sessions, handle_to_pointer (session));
	if (!sess)
		return CKR_SESSION_HANDLE_INVALID;

	rv = lookup_object (sess, base_key, &attrs, NULL);
	if (rv == CKR_OBJECT_HANDLE_INVALID)
		return CKR_KEY_HANDLE_INVALID;
	else if (rv != CKR_OK)
		return rv;

	if (mechanism->mechanism != CKM_MOCK_DERIVE)
		return CKR_MECHANISM_INVALID;

	if (mechanism->pParameter == NULL ||
	    mechanism->ulParameterLen != 6 ||
	    memcmp (mechanism->pParameter, "derive", 6) != 0) {
		return CKR_MECHANISM_PARAM_INVALID;
	}

	value.type = CKA_VALUE;
	value.pValue = "derived";
	value.ulValueLen = strlen (value.pValue);

	copy = p11_attrs_buildn (NULL, template, count);
	copy = p11_attrs_buildn (copy, &value, 1);

	*key = ++unique_identifier;
	if (p11_attrs_find_bool (copy, CKA_TOKEN, &token) && token)
		p11_dict_set (the_objects, handle_to_pointer (*key), copy);
	else
		p11_dict_set (sess->objects, handle_to_pointer (*key), copy);

	return CKR_OK;
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
mock_X_DeriveKey__invalid_handle (CK_X_FUNCTION_LIST *self,
                                  CK_SESSION_HANDLE session,
                                  CK_MECHANISM_PTR mechanism,
                                  CK_OBJECT_HANDLE base_key,
                                  CK_ATTRIBUTE_PTR template,
                                  CK_ULONG count,
                                  CK_OBJECT_HANDLE_PTR key)
{
	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_C_SeedRandom (CK_SESSION_HANDLE session,
                   CK_BYTE_PTR seed,
                   CK_ULONG seed_len)
{
	Session *sess;

	sess = p11_dict_get (the_sessions, handle_to_pointer (session));
	if (!sess)
		return CKR_SESSION_HANDLE_INVALID;

	if (seed_len > sizeof (sess->random_seed))
		return CKR_RANDOM_SEED_NOT_SUPPORTED;

	memcpy (sess->random_seed, seed, seed_len);
	sess->random_seed_len = seed_len;
	return CKR_OK;
}

CK_RV
mock_C_SeedRandom__invalid_handle (CK_SESSION_HANDLE session,
                                   CK_BYTE_PTR seed,
                                   CK_ULONG seed_len)
{
	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_X_SeedRandom__invalid_handle (CK_X_FUNCTION_LIST *self,
                                   CK_SESSION_HANDLE session,
                                   CK_BYTE_PTR seed,
                                   CK_ULONG seed_len)
{
	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_C_GenerateRandom (CK_SESSION_HANDLE session,
                       CK_BYTE_PTR random_data,
                       CK_ULONG random_len)
{
	Session *sess;
	CK_ULONG block;

	sess = p11_dict_get (the_sessions, handle_to_pointer (session));
	if (!sess)
		return CKR_SESSION_HANDLE_INVALID;

	while (random_len > 0) {
		block = sess->random_seed_len;
		if (block > random_len)
			block = random_len;
		memcpy (random_data, sess->random_seed, block);
		random_data += block;
		random_len -= block;
	}

	return CKR_OK;
}

CK_RV
mock_C_GenerateRandom__invalid_handle (CK_SESSION_HANDLE session,
                                       CK_BYTE_PTR random_data,
                                       CK_ULONG random_len)
{
	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_X_GenerateRandom__invalid_handle (CK_X_FUNCTION_LIST *self,
                                       CK_SESSION_HANDLE session,
                                       CK_BYTE_PTR random_data,
                                       CK_ULONG random_len)
{
	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_C_GetInterfaceList_not_supported (CK_INTERFACE_PTR interfaces_list,
                                       CK_ULONG_PTR count)
{
	/* This would be a strange call to receive, should be overridden  */
	return_val_if_reached (CKR_FUNCTION_NOT_SUPPORTED);
}

CK_RV
mock_X_GetInterfaceList_not_supported (CK_X_FUNCTION_LIST *self,
                                       CK_INTERFACE_PTR interfaces_list,
                                       CK_ULONG_PTR count)
{
	/* This would be a strange call to receive, should be overridden  */
	return_val_if_reached (CKR_FUNCTION_NOT_SUPPORTED);
}

CK_RV
mock_C_GetInterface_not_supported (CK_UTF8CHAR_PTR interface_name,
                                   CK_VERSION_PTR version,
                                   CK_INTERFACE_PTR_PTR interface,
                                   CK_FLAGS flags)
{
	/* This would be a strange call to receive, should be overridden  */
	return_val_if_reached (CKR_FUNCTION_NOT_SUPPORTED);
}

CK_RV
mock_X_GetInterface_not_supported (CK_X_FUNCTION_LIST *self,
                                   CK_UTF8CHAR_PTR interface_name,
                                   CK_VERSION_PTR version,
                                   CK_INTERFACE_PTR_PTR interface,
                                   CK_FLAGS flags)
{
	/* This would be a strange call to receive, should be overridden  */
	return_val_if_reached (CKR_FUNCTION_NOT_SUPPORTED);
}

CK_RV
mock_C_LoginUser (CK_SESSION_HANDLE session,
                  CK_USER_TYPE user_type,
                  CK_UTF8CHAR_PTR pin,
                  CK_ULONG pin_len,
                  CK_UTF8CHAR_PTR username,
                  CK_ULONG username_len)
{
	Session *sess;

	sess = p11_dict_get (the_sessions, handle_to_pointer (session));
	if (sess == NULL)
		return CKR_SESSION_HANDLE_INVALID;

	if (!username)
		return CKR_PIN_INCORRECT;

	if (username_len != n_the_username)
		return CKR_PIN_INCORRECT;
	if (strncmp ((char *)username, (char *)the_username, username_len) != 0)
		return CKR_PIN_INCORRECT;

	return mock_C_Login (session, user_type, pin, pin_len);
}

CK_RV
mock_C_LoginUser__invalid_handle (CK_SESSION_HANDLE session,
                                  CK_USER_TYPE user_type,
                                  CK_UTF8CHAR_PTR pin,
                                  CK_ULONG pin_len,
                                  CK_UTF8CHAR_PTR username,
                                  CK_ULONG username_len)
{
	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_X_LoginUser__invalid_handle (CK_X_FUNCTION_LIST *self,
                                  CK_SESSION_HANDLE session,
                                  CK_USER_TYPE user_type,
                                  CK_UTF8CHAR_PTR pin,
                                  CK_ULONG pin_len,
                                  CK_UTF8CHAR_PTR username,
                                  CK_ULONG username_len)
{
	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_C_SessionCancel (CK_SESSION_HANDLE session,
                      CK_FLAGS flags)
{
	Session *sess;

	sess = p11_dict_get (the_sessions, handle_to_pointer (session));
	if (!sess)
		return CKR_SESSION_HANDLE_INVALID;

	if (flags & CKF_FIND_OBJECTS)
		sess->finding = CK_FALSE;
	sess->hash_method &= ~flags;
	sess->crypto_method &= ~flags;
	sess->message_method &= ~flags;
	sess->message_progress = false;
	sess->crypto_mechanism = 0;
	sess->crypto_key = 0;

	return CKR_OK;
}

CK_RV
mock_C_SessionCancel__invalid_handle (CK_SESSION_HANDLE session,
                                      CK_FLAGS flags)
{
	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_X_SessionCancel__invalid_handle (CK_X_FUNCTION_LIST *self,
                                      CK_SESSION_HANDLE session,
                                      CK_FLAGS flags)
{
	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_C_MessageEncryptInit (CK_SESSION_HANDLE session,
                           CK_MECHANISM_PTR mechanism,
                           CK_OBJECT_HANDLE key)
{
	Session *sess;
	CK_RV rv;

	sess = p11_dict_get (the_sessions, handle_to_pointer (session));
	if (!sess)
		return CKR_SESSION_HANDLE_INVALID;
	if (mechanism == NULL && sess->message_method == CKF_MESSAGE_ENCRYPT) {
		sess->message_method = 0;
		return CKR_OK;
	}
	if (sess->message_method != 0)
		return CKR_OPERATION_ACTIVE;

	rv = mock_C_EncryptInit (session, mechanism, key);
	if (rv != CKR_OK)
		return rv;

	sess->message_method = CKF_MESSAGE_ENCRYPT;

	return CKR_OK;
}

CK_RV
mock_C_MessageEncryptInit__invalid_handle (CK_SESSION_HANDLE session,
                                           CK_MECHANISM_PTR mechanism,
                                           CK_OBJECT_HANDLE key)
{
	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_X_MessageEncryptInit__invalid_handle (CK_X_FUNCTION_LIST *self,
                                           CK_SESSION_HANDLE session,
                                           CK_MECHANISM_PTR mechanism,
                                           CK_OBJECT_HANDLE key)
{
	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_C_EncryptMessage (CK_SESSION_HANDLE session,
                       CK_VOID_PTR parameter,
                       CK_ULONG parameter_len,
                       CK_BYTE_PTR associated_data,
                       CK_ULONG associated_data_len,
                       CK_BYTE_PTR plaintext,
                       CK_ULONG plaintext_len,
                       CK_BYTE_PTR ciphertext,
                       CK_ULONG_PTR ciphertext_len)
{
	CK_RV rv;

	rv = mock_C_EncryptMessageBegin (session, parameter, parameter_len,
	                                 associated_data, associated_data_len);
	if (rv != CKR_OK)
		return rv;

	return mock_C_EncryptMessageNext (session, parameter, parameter_len, plaintext, plaintext_len,
	                                  ciphertext, ciphertext_len, CKF_END_OF_MESSAGE);
}

CK_RV
mock_C_EncryptMessage__invalid_handle (CK_SESSION_HANDLE session,
                                       CK_VOID_PTR parameter,
                                       CK_ULONG parameter_len,
                                       CK_BYTE_PTR associated_data,
                                       CK_ULONG associated_data_len,
                                       CK_BYTE_PTR plaintext,
                                       CK_ULONG plaintext_len,
                                       CK_BYTE_PTR ciphertext,
                                       CK_ULONG_PTR ciphertext_len)
{
	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_X_EncryptMessage__invalid_handle (CK_X_FUNCTION_LIST *self,
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
	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_C_EncryptMessageBegin (CK_SESSION_HANDLE session,
                            CK_VOID_PTR parameter,
                            CK_ULONG parameter_len,
                            CK_BYTE_PTR associated_data,
                            CK_ULONG associated_data_len)
{
	Session *sess;

	sess = p11_dict_get (the_sessions, handle_to_pointer (session));
	if (!sess)
		return CKR_SESSION_HANDLE_INVALID;

	if (sess->message_method != CKF_MESSAGE_ENCRYPT)
		return CKR_OPERATION_NOT_INITIALIZED;

	if (parameter_len != 13 || memcmp (parameter, "encrypt-param", 13))
		return CKR_ARGUMENTS_BAD;

	/* no AEAD */
	if (associated_data != NULL || associated_data_len != 0)
		return CKR_ARGUMENTS_BAD;

	sess->message_progress = true;
	return CKR_OK;
}

CK_RV
mock_C_EncryptMessageBegin__invalid_handle (CK_SESSION_HANDLE session,
                                            CK_VOID_PTR parameter,
                                            CK_ULONG parameter_len,
                                            CK_BYTE_PTR associated_data,
                                            CK_ULONG associated_data_len)
{
	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_X_EncryptMessageBegin__invalid_handle (CK_X_FUNCTION_LIST *self,
                                            CK_SESSION_HANDLE session,
                                            CK_VOID_PTR parameter,
                                            CK_ULONG parameter_len,
                                            CK_BYTE_PTR associated_data,
                                            CK_ULONG associated_data_len)
{
	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_C_EncryptMessageNext (CK_SESSION_HANDLE session,
                           CK_VOID_PTR parameter,
                           CK_ULONG parameter_len,
                           CK_BYTE_PTR plaintext_part,
                           CK_ULONG plaintext_part_len,
                           CK_BYTE_PTR ciphertext_part,
                           CK_ULONG_PTR ciphertext_part_len,
                           CK_FLAGS flags)
{
	Session *sess;
	CK_RV rv;

	if (parameter_len != 13 || memcmp (parameter, "encrypt-param", 13))
		return CKR_ARGUMENTS_BAD;

	sess = p11_dict_get (the_sessions, handle_to_pointer (session));
	if (!sess)
		return CKR_SESSION_HANDLE_INVALID;

	if (sess->message_method != CKF_MESSAGE_ENCRYPT || !sess->message_progress)
		return CKR_OPERATION_NOT_INITIALIZED;

	rv = mock_C_EncryptUpdate (session, plaintext_part, plaintext_part_len,
	                           ciphertext_part, ciphertext_part_len);
	if (rv == CKR_OK && flags & CKF_END_OF_MESSAGE)
		sess->message_progress = false;

	return rv;
}

CK_RV
mock_C_EncryptMessageNext__invalid_handle (CK_SESSION_HANDLE session,
                                           CK_VOID_PTR parameter,
                                           CK_ULONG parameter_len,
                                           CK_BYTE_PTR plaintext_part,
                                           CK_ULONG plaintext_part_len,
                                           CK_BYTE_PTR ciphertext_part,
                                           CK_ULONG_PTR ciphertext_part_len,
                                           CK_FLAGS flags)
{
	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_X_EncryptMessageNext__invalid_handle (CK_X_FUNCTION_LIST *self,
                                           CK_SESSION_HANDLE session,
                                           CK_VOID_PTR parameter,
                                           CK_ULONG parameter_len,
                                           CK_BYTE_PTR plaintext_part,
                                           CK_ULONG plaintext_part_len,
                                           CK_BYTE_PTR ciphertext_part,
                                           CK_ULONG_PTR ciphertext_part_len,
                                           CK_FLAGS flags)
{
	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_C_MessageEncryptFinal (CK_SESSION_HANDLE session)
{
	Session *sess;
	unsigned long len = 0;
	int rv;

	sess = p11_dict_get (the_sessions, handle_to_pointer (session));
	if (!sess)
		return CKR_SESSION_HANDLE_INVALID;

	if (sess->message_method != CKF_MESSAGE_ENCRYPT)
		return CKR_OPERATION_NOT_INITIALIZED;

	sess->message_method = 0;
	sess->message_progress = false;

	rv = mock_C_EncryptFinal (session, NULL, &len);
	assert (len == 0);
	return rv;
}

CK_RV
mock_C_MessageEncryptFinal__invalid_handle (CK_SESSION_HANDLE session)
{
	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_X_MessageEncryptFinal__invalid_handle (CK_X_FUNCTION_LIST *self,
                                            CK_SESSION_HANDLE session)
{
	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_C_MessageDecryptInit (CK_SESSION_HANDLE session,
                           CK_MECHANISM_PTR mechanism,
                           CK_OBJECT_HANDLE key)
{
	CK_RV rv;
	Session *sess;

	sess = p11_dict_get (the_sessions, handle_to_pointer (session));
	if (!sess)
		return CKR_SESSION_HANDLE_INVALID;
	if (mechanism == NULL && sess->message_method == CKF_MESSAGE_DECRYPT) {
		sess->message_method = 0;
		return CKR_OK;
	}
	if (sess->message_method != 0)
		return CKR_OPERATION_ACTIVE;

	rv = mock_C_DecryptInit (session, mechanism, key);
	if (rv != CKR_OK)
		return rv;

	sess->message_method = CKF_MESSAGE_DECRYPT;

	return CKR_OK;
}

CK_RV
mock_C_MessageDecryptInit__invalid_handle (CK_SESSION_HANDLE session,
                                           CK_MECHANISM_PTR mechanism,
                                           CK_OBJECT_HANDLE key)
{
	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_X_MessageDecryptInit__invalid_handle (CK_X_FUNCTION_LIST *self,
                                           CK_SESSION_HANDLE session,
                                           CK_MECHANISM_PTR mechanism,
                                           CK_OBJECT_HANDLE key)
{
	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_C_DecryptMessage (CK_SESSION_HANDLE session,
                       CK_VOID_PTR parameter,
                       CK_ULONG parameter_len,
                       CK_BYTE_PTR associated_data,
                       CK_ULONG associated_data_len,
                       CK_BYTE_PTR ciphertext,
                       CK_ULONG ciphertext_len,
                       CK_BYTE_PTR plaintext,
                       CK_ULONG_PTR plaintext_len)
{
	CK_RV rv;

	rv = mock_C_DecryptMessageBegin (session, parameter, parameter_len,
	                                 associated_data, associated_data_len);
	if (rv != CKR_OK)
		return rv;

	return mock_C_DecryptMessageNext (session, parameter, parameter_len, ciphertext, ciphertext_len,
	                                  plaintext, plaintext_len, CKF_END_OF_MESSAGE);
}

CK_RV
mock_C_DecryptMessage__invalid_handle (CK_SESSION_HANDLE session,
                                       CK_VOID_PTR parameter,
                                       CK_ULONG parameter_len,
                                       CK_BYTE_PTR associated_data,
                                       CK_ULONG associated_data_len,
                                       CK_BYTE_PTR ciphertext,
                                       CK_ULONG ciphertext_len,
                                       CK_BYTE_PTR plaintext,
                                       CK_ULONG_PTR plaintext_len)
{
	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_X_DecryptMessage__invalid_handle (CK_X_FUNCTION_LIST *self,
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
	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_C_DecryptMessageBegin (CK_SESSION_HANDLE session,
                            CK_VOID_PTR parameter,
                            CK_ULONG parameter_len,
                            CK_BYTE_PTR associated_data,
                            CK_ULONG associated_data_len)
{
	Session *sess;

	sess = p11_dict_get (the_sessions, handle_to_pointer (session));
	if (!sess)
		return CKR_SESSION_HANDLE_INVALID;

	if (sess->message_method != CKF_MESSAGE_DECRYPT)
		return CKR_OPERATION_NOT_INITIALIZED;

	if (parameter_len != 13 || memcmp (parameter, "decrypt-param", 13))
		return CKR_ARGUMENTS_BAD;

	/* no AEAD */
	if (associated_data != NULL || associated_data_len != 0)
		return CKR_ARGUMENTS_BAD;

	sess->message_progress = true;

	return CKR_OK;
}

CK_RV
mock_C_DecryptMessageBegin__invalid_handle (CK_SESSION_HANDLE session,
                                            CK_VOID_PTR parameter,
                                            CK_ULONG parameter_len,
                                            CK_BYTE_PTR associated_data,
                                            CK_ULONG associated_data_len)
{
	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_X_DecryptMessageBegin__invalid_handle (CK_X_FUNCTION_LIST *self,
                                            CK_SESSION_HANDLE session,
                                            CK_VOID_PTR parameter,
                                            CK_ULONG parameter_len,
                                            CK_BYTE_PTR associated_data,
                                            CK_ULONG associated_data_len)
{
	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_C_DecryptMessageNext (CK_SESSION_HANDLE session,
                           CK_VOID_PTR parameter,
                           CK_ULONG parameter_len,
                           CK_BYTE_PTR ciphertext_part,
                           CK_ULONG ciphertext_part_len,
                           CK_BYTE_PTR plaintext_part,
                           CK_ULONG_PTR plaintext_part_len,
                           CK_FLAGS flags)
{
	Session *sess;
	CK_RV rv;

	if (parameter_len != 13 || memcmp (parameter, "decrypt-param", 13))
		return CKR_ARGUMENTS_BAD;

	sess = p11_dict_get (the_sessions, handle_to_pointer (session));
	if (!sess)
		return CKR_SESSION_HANDLE_INVALID;

	if (sess->message_method != CKF_MESSAGE_DECRYPT || !sess->message_progress)
		return CKR_OPERATION_NOT_INITIALIZED;

	rv = mock_C_DecryptUpdate (session, ciphertext_part, ciphertext_part_len,
	                           plaintext_part, plaintext_part_len);
	if (rv == CKR_OK && flags & CKF_END_OF_MESSAGE)
		sess->message_progress = false;

	return rv;
}

CK_RV
mock_C_DecryptMessageNext__invalid_handle (CK_SESSION_HANDLE session,
                                           CK_VOID_PTR parameter,
                                           CK_ULONG parameter_len,
                                           CK_BYTE_PTR ciphertext_part,
                                           CK_ULONG ciphertext_part_len,
                                           CK_BYTE_PTR plaintext_part,
                                           CK_ULONG_PTR plaintext_part_len,
                                           CK_FLAGS flags)
{
	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_X_DecryptMessageNext__invalid_handle (CK_X_FUNCTION_LIST *self,
                                           CK_SESSION_HANDLE session,
                                           CK_VOID_PTR parameter,
                                           CK_ULONG parameter_len,
                                           CK_BYTE_PTR ciphertext_part,
                                           CK_ULONG ciphertext_part_len,
                                           CK_BYTE_PTR plaintext_part,
                                           CK_ULONG_PTR plaintext_part_len,
                                           CK_FLAGS flags)
{
	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_C_MessageDecryptFinal (CK_SESSION_HANDLE session)
{
	Session *sess;
	unsigned long len = 0;
	int rv;

	sess = p11_dict_get (the_sessions, handle_to_pointer (session));
	if (!sess)
		return CKR_SESSION_HANDLE_INVALID;

	if (sess->message_method != CKF_MESSAGE_DECRYPT)
		return CKR_OPERATION_NOT_INITIALIZED;

	sess->message_method = 0;
	sess->message_progress = false;

	rv = mock_C_DecryptFinal (session, NULL, &len);
	assert (len == 0);
	return rv;
}

CK_RV
mock_C_MessageDecryptFinal__invalid_handle (CK_SESSION_HANDLE session)
{
	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_X_MessageDecryptFinal__invalid_handle (CK_X_FUNCTION_LIST *self,
                                            CK_SESSION_HANDLE session)
{
	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_C_MessageSignInit (CK_SESSION_HANDLE session,
                        CK_MECHANISM_PTR mechanism,
                        CK_OBJECT_HANDLE key)
{
	Session *sess;
	CK_RV rv;

	sess = p11_dict_get (the_sessions, handle_to_pointer (session));
	if (!sess)
		return CKR_SESSION_HANDLE_INVALID;
	if (mechanism == NULL && sess->message_method == CKF_MESSAGE_SIGN) {
		sess->message_method = 0;
		return CKR_OK;
	}
	if (sess->message_method != 0)
		return CKR_OPERATION_ACTIVE;

	rv = mock_C_SignInit (session, mechanism, key);
	if (rv != CKR_OK)
		return rv;

	sess->message_method = CKF_MESSAGE_SIGN;
	free (sess->message_mechanism.pParameter);
	sess->message_mechanism = *mechanism;
	if (mechanism->pParameter != NULL) {
		sess->message_mechanism.pParameter = memdup (mechanism->pParameter, mechanism->ulParameterLen);
		sess->message_mechanism.ulParameterLen = mechanism->ulParameterLen;
	}
	sess->message_key = key;

	return CKR_OK;
}

CK_RV
mock_C_MessageSignInit__invalid_handle (CK_SESSION_HANDLE session,
                                        CK_MECHANISM_PTR mechanism,
                                        CK_OBJECT_HANDLE key)
{
	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_X_MessageSignInit__invalid_handle (CK_X_FUNCTION_LIST *self,
                                        CK_SESSION_HANDLE session,
                                        CK_MECHANISM_PTR mechanism,
                                        CK_OBJECT_HANDLE key)
{
	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_C_SignMessage (CK_SESSION_HANDLE session,
                    CK_VOID_PTR parameter,
                    CK_ULONG parameter_len,
                    CK_BYTE_PTR data,
                    CK_ULONG data_len,
                    CK_BYTE_PTR signature,
                    CK_ULONG_PTR signature_len)
{
	CK_RV rv;

	rv = mock_C_SignMessageBegin (session, parameter, parameter_len);
	if (rv == CKR_OK) {
		rv = mock_C_SignMessageNext (session, parameter, parameter_len, data, data_len,
		                             signature, signature_len);
	}

	return rv;
}

CK_RV
mock_C_SignMessage__invalid_handle (CK_SESSION_HANDLE session,
                                    CK_VOID_PTR parameter,
                                    CK_ULONG parameter_len,
                                    CK_BYTE_PTR data,
                                    CK_ULONG data_len,
                                    CK_BYTE_PTR signature,
                                    CK_ULONG_PTR signature_len)
{
	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_X_SignMessage__invalid_handle (CK_X_FUNCTION_LIST *self,
                                    CK_SESSION_HANDLE session,
                                    CK_VOID_PTR parameter,
                                    CK_ULONG parameter_len,
                                    CK_BYTE_PTR data,
                                    CK_ULONG data_len,
                                    CK_BYTE_PTR signature,
                                    CK_ULONG_PTR signature_len)
{
	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_C_SignMessageBegin (CK_SESSION_HANDLE session,
                         CK_VOID_PTR parameter,
                         CK_ULONG parameter_len)
{
	Session *sess;
	CK_RV rv;

	sess = p11_dict_get (the_sessions, handle_to_pointer (session));
	if (!sess)
		return CKR_SESSION_HANDLE_INVALID;

	if (sess->message_method != CKF_MESSAGE_SIGN)
		return CKR_OPERATION_NOT_INITIALIZED;

	if (parameter_len != 10 || memcmp (parameter, "sign-param", 10))
		return CKR_ARGUMENTS_BAD;

	if (sess->hash_method != CKF_SIGN) {
		/* The Final already terminates this mechanism */
		rv = prefix_mechanism_init (session, CKF_SIGN, &sess->message_mechanism, sess->message_key);
		if (rv != CKR_OK)
			return rv;
	}

	sess->message_progress = true;

	return CKR_OK;
}

CK_RV
mock_C_SignMessageBegin__invalid_handle (CK_SESSION_HANDLE session,
                                         CK_VOID_PTR parameter,
                                         CK_ULONG parameter_len)
{
	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_X_SignMessageBegin__invalid_handle (CK_X_FUNCTION_LIST *self,
                                         CK_SESSION_HANDLE session,
                                         CK_VOID_PTR parameter,
                                         CK_ULONG parameter_len)
{
	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_C_SignMessageNext (CK_SESSION_HANDLE session,
                        CK_VOID_PTR parameter,
                        CK_ULONG parameter_len,
                        CK_BYTE_PTR data,
                        CK_ULONG data_len,
                        CK_BYTE_PTR signature,
                        CK_ULONG_PTR signature_len)
{
	Session *sess;
	CK_RV rv;

	if (parameter_len != 10 || memcmp (parameter, "sign-param", 10))
		return CKR_ARGUMENTS_BAD;

	sess = p11_dict_get (the_sessions, handle_to_pointer (session));
	if (!sess)
		return CKR_SESSION_HANDLE_INVALID;

	if (sess->message_method != CKF_MESSAGE_SIGN || !sess->message_progress)
		return CKR_OPERATION_NOT_INITIALIZED;

	rv = mock_C_SignUpdate (session, data, data_len);
	if (rv != CKR_OK) {
		return rv;
	}

	if (signature_len != NULL) {
		rv = mock_C_SignFinal (session, signature, signature_len);
		if (rv != CKR_BUFFER_TOO_SMALL && rv != CKR_OK)
			sess->message_progress = false;
	}

	return rv;
}

CK_RV
mock_C_SignMessageNext__invalid_handle (CK_SESSION_HANDLE session,
                                        CK_VOID_PTR parameter,
                                        CK_ULONG parameter_len,
                                        CK_BYTE_PTR data,
                                        CK_ULONG data_len,
                                        CK_BYTE_PTR signature,
                                        CK_ULONG_PTR signature_len)
{
	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_X_SignMessageNext__invalid_handle (CK_X_FUNCTION_LIST *self,
                                        CK_SESSION_HANDLE session,
                                        CK_VOID_PTR parameter,
                                        CK_ULONG parameter_len,
                                        CK_BYTE_PTR data,
                                        CK_ULONG data_len,
                                        CK_BYTE_PTR signature,
                                        CK_ULONG_PTR signature_len)
{
	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_C_MessageSignFinal (CK_SESSION_HANDLE session)
{
	Session *sess;

	sess = p11_dict_get (the_sessions, handle_to_pointer (session));
	if (!sess)
		return CKR_SESSION_HANDLE_INVALID;

	if (sess->message_method != CKF_MESSAGE_SIGN)
		return CKR_OPERATION_NOT_INITIALIZED;

	sess->message_method = 0;
	sess->message_progress = false;
	return CKR_OK;
}

CK_RV
mock_C_MessageSignFinal__invalid_handle (CK_SESSION_HANDLE session)
{
	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_X_MessageSignFinal__invalid_handle (CK_X_FUNCTION_LIST *self,
                                         CK_SESSION_HANDLE session)
{
	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_C_MessageVerifyInit (CK_SESSION_HANDLE session,
                          CK_MECHANISM_PTR mechanism,
                          CK_OBJECT_HANDLE key)
{
	Session *sess;
	CK_RV rv;

	sess = p11_dict_get (the_sessions, handle_to_pointer (session));
	if (!sess)
		return CKR_SESSION_HANDLE_INVALID;
	if (mechanism == NULL && sess->message_method == CKF_MESSAGE_VERIFY) {
		sess->message_method = 0;
		return CKR_OK;
	}
	if (sess->message_method != 0)
		return CKR_OPERATION_ACTIVE;

	rv = mock_C_VerifyInit (session, mechanism, key);
	if (rv != CKR_OK)
		return rv;

	sess->message_method = CKF_MESSAGE_VERIFY;
	free (sess->message_mechanism.pParameter);
	sess->message_mechanism = *mechanism;
	if (mechanism->pParameter != NULL) {
		sess->message_mechanism.pParameter = memdup (mechanism->pParameter, mechanism->ulParameterLen);
		assert (sess->message_mechanism.pParameter != NULL);
		sess->message_mechanism.ulParameterLen = mechanism->ulParameterLen;
	}
	sess->message_key = key;

	return CKR_OK;
}

CK_RV
mock_C_MessageVerifyInit__invalid_handle (CK_SESSION_HANDLE session,
                                          CK_MECHANISM_PTR mechanism,
                                          CK_OBJECT_HANDLE key)
{
	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_X_MessageVerifyInit__invalid_handle (CK_X_FUNCTION_LIST *self,
                                          CK_SESSION_HANDLE session,
                                          CK_MECHANISM_PTR mechanism,
                                          CK_OBJECT_HANDLE key)
{
	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_C_VerifyMessage (CK_SESSION_HANDLE session,
                      CK_VOID_PTR parameter,
                      CK_ULONG parameter_len,
                      CK_BYTE_PTR data,
                      CK_ULONG data_len,
                      CK_BYTE_PTR signature,
                      CK_ULONG signature_len)
{
	CK_RV rv;

	rv = mock_C_VerifyMessageBegin (session, parameter, parameter_len);
	if (rv == CKR_OK) {
		rv = mock_C_VerifyMessageNext (session, parameter, parameter_len, data, data_len,
		                               signature, signature_len);
	}

	return rv;
}

CK_RV
mock_C_VerifyMessage__invalid_handle (CK_SESSION_HANDLE session,
                                      CK_VOID_PTR parameter,
                                      CK_ULONG parameter_len,
                                      CK_BYTE_PTR data,
                                      CK_ULONG data_len,
                                      CK_BYTE_PTR signature,
                                      CK_ULONG signature_len)
{
	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_X_VerifyMessage__invalid_handle (CK_X_FUNCTION_LIST *self,
                                      CK_SESSION_HANDLE session,
                                      CK_VOID_PTR parameter,
                                      CK_ULONG parameter_len,
                                      CK_BYTE_PTR data,
                                      CK_ULONG data_len,
                                      CK_BYTE_PTR signature,
                                      CK_ULONG signature_len)
{
	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_C_VerifyMessageBegin (CK_SESSION_HANDLE session,
			   CK_VOID_PTR parameter,
			   CK_ULONG parameter_len)
{
	Session *sess;
	CK_RV rv;

	sess = p11_dict_get (the_sessions, handle_to_pointer (session));
	if (!sess)
		return CKR_SESSION_HANDLE_INVALID;

	if (sess->message_method != CKF_MESSAGE_VERIFY)
		return CKR_OPERATION_NOT_INITIALIZED;

	if (parameter_len != 12 || memcmp (parameter, "verify-param", 12))
		return CKR_ARGUMENTS_BAD;

	if (sess->hash_method != CKF_VERIFY) {
		/* The Final already terminates this mechanism */
		rv = prefix_mechanism_init (session, CKF_VERIFY, &sess->message_mechanism, sess->message_key);
		if (rv != CKR_OK)
			return rv;
	}

	sess->message_progress = true;

	return CKR_OK;
}

CK_RV
mock_C_VerifyMessageBegin__invalid_handle (CK_SESSION_HANDLE session,
                                           CK_VOID_PTR parameter,
                                           CK_ULONG parameter_len)
{
	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_X_VerifyMessageBegin__invalid_handle (CK_X_FUNCTION_LIST *self,
                                           CK_SESSION_HANDLE session,
                                           CK_VOID_PTR parameter,
                                           CK_ULONG parameter_len)
{
	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_C_VerifyMessageNext (CK_SESSION_HANDLE session,
                          CK_VOID_PTR parameter,
                          CK_ULONG parameter_len,
                          CK_BYTE_PTR data,
                          CK_ULONG data_len,
                          CK_BYTE_PTR signature,
                          CK_ULONG signature_len)
{
	Session *sess;
	CK_RV rv;

	if (parameter_len != 12 || memcmp (parameter, "verify-param", 12))
		return CKR_ARGUMENTS_BAD;

	sess = p11_dict_get (the_sessions, handle_to_pointer (session));
	if (!sess)
		return CKR_SESSION_HANDLE_INVALID;

	if (sess->message_method != CKF_MESSAGE_VERIFY || !sess->message_progress)
		return CKR_OPERATION_NOT_INITIALIZED;

	rv = mock_C_VerifyUpdate (session, data, data_len);
	if (rv != CKR_OK) {
		return rv;
	}

	if (signature != NULL) {
		rv = mock_C_VerifyFinal (session, signature, signature_len);
		if (rv != CKR_BUFFER_TOO_SMALL)
			sess->message_progress = false;
	}

	return rv;
}

CK_RV
mock_C_VerifyMessageNext__invalid_handle (CK_SESSION_HANDLE session,
                                          CK_VOID_PTR parameter,
                                          CK_ULONG parameter_len,
                                          CK_BYTE_PTR data,
                                          CK_ULONG data_len,
                                          CK_BYTE_PTR signature,
                                          CK_ULONG signature_len)
{
	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_X_VerifyMessageNext__invalid_handle (CK_X_FUNCTION_LIST *self,
                                          CK_SESSION_HANDLE session,
                                          CK_VOID_PTR parameter,
                                          CK_ULONG parameter_len,
                                          CK_BYTE_PTR data,
                                          CK_ULONG data_len,
                                          CK_BYTE_PTR signature,
                                          CK_ULONG signature_len)
{
	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_C_MessageVerifyFinal (CK_SESSION_HANDLE session)
{
	Session *sess;

	sess = p11_dict_get (the_sessions, handle_to_pointer (session));
	if (!sess)
		return CKR_SESSION_HANDLE_INVALID;

	if (sess->message_method != CKF_MESSAGE_VERIFY)
		return CKR_OPERATION_NOT_INITIALIZED;

	sess->message_method = 0;
	sess->message_progress = false;
	return CKR_OK;
}

CK_RV
mock_C_MessageVerifyFinal__invalid_handle (CK_SESSION_HANDLE session)
{
	return CKR_SESSION_HANDLE_INVALID;
}

CK_RV
mock_X_MessageVerifyFinal__invalid_handle (CK_X_FUNCTION_LIST *self,
                                           CK_SESSION_HANDLE session)
{
	return CKR_SESSION_HANDLE_INVALID;
}

CK_FUNCTION_LIST mock_module_no_slots = {
	{ CRYPTOKI_LEGACY_VERSION_MAJOR, CRYPTOKI_LEGACY_VERSION_MINOR },  /* version */
	mock_C_Initialize,
	mock_C_Finalize,
	mock_C_GetInfo,
	mock_C_GetFunctionList_not_supported,
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

CK_FUNCTION_LIST_3_0 mock_module_v3_no_slots = {
	{ CRYPTOKI_VERSION_MAJOR, CRYPTOKI_VERSION_MINOR },  /* version */
	mock_C_Initialize,
	mock_C_Finalize,
	mock_C_GetInfo,
	mock_C_GetFunctionList_not_supported,
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
	/* PKCS #11 3.0 */
	mock_C_GetInterfaceList_not_supported,
	mock_C_GetInterface_not_supported,
	mock_C_LoginUser__invalid_handle,
	mock_C_SessionCancel__invalid_handle,
	mock_C_MessageEncryptInit__invalid_handle,
	mock_C_EncryptMessage__invalid_handle,
	mock_C_EncryptMessageBegin__invalid_handle,
	mock_C_EncryptMessageNext__invalid_handle,
	mock_C_MessageEncryptFinal__invalid_handle,
	mock_C_MessageDecryptInit__invalid_handle,
	mock_C_DecryptMessage__invalid_handle,
	mock_C_DecryptMessageBegin__invalid_handle,
	mock_C_DecryptMessageNext__invalid_handle,
	mock_C_MessageDecryptFinal__invalid_handle,
	mock_C_MessageSignInit__invalid_handle,
	mock_C_SignMessage__invalid_handle,
	mock_C_SignMessageBegin__invalid_handle,
	mock_C_SignMessageNext__invalid_handle,
	mock_C_MessageSignFinal__invalid_handle,
	mock_C_MessageVerifyInit__invalid_handle,
	mock_C_VerifyMessage__invalid_handle,
	mock_C_VerifyMessageBegin__invalid_handle,
	mock_C_VerifyMessageNext__invalid_handle,
	mock_C_MessageVerifyFinal__invalid_handle
};

CK_X_FUNCTION_LIST mock_x_module_no_slots = {
	{ CRYPTOKI_VERSION_MAJOR, CRYPTOKI_VERSION_MINOR },  /* version */
	mock_X_Initialize,
	mock_X_Finalize,
	mock_X_GetInfo,
	mock_X_GetSlotList__no_tokens,
	mock_X_GetSlotInfo__invalid_slotid,
	mock_X_GetTokenInfo__invalid_slotid,
	mock_X_GetMechanismList__invalid_slotid,
	mock_X_GetMechanismInfo__invalid_slotid,
	mock_X_InitToken__invalid_slotid,
	mock_X_InitPIN__invalid_handle,
	mock_X_SetPIN__invalid_handle,
	mock_X_OpenSession__invalid_slotid,
	mock_X_CloseSession__invalid_handle,
	mock_X_CloseAllSessions__invalid_slotid,
	mock_X_GetSessionInfo__invalid_handle,
	mock_X_GetOperationState__invalid_handle,
	mock_X_SetOperationState__invalid_handle,
	mock_X_Login__invalid_handle,
	mock_X_Logout__invalid_handle,
	mock_X_CreateObject__invalid_handle,
	mock_X_CopyObject__invalid_handle,
	mock_X_DestroyObject__invalid_handle,
	mock_X_GetObjectSize__invalid_handle,
	mock_X_GetAttributeValue__invalid_handle,
	mock_X_SetAttributeValue__invalid_handle,
	mock_X_FindObjectsInit__invalid_handle,
	mock_X_FindObjects__invalid_handle,
	mock_X_FindObjectsFinal__invalid_handle,
	mock_X_EncryptInit__invalid_handle,
	mock_X_Encrypt__invalid_handle,
	mock_X_EncryptUpdate__invalid_handle,
	mock_X_EncryptFinal__invalid_handle,
	mock_X_DecryptInit__invalid_handle,
	mock_X_Decrypt__invalid_handle,
	mock_X_DecryptUpdate__invalid_handle,
	mock_X_DecryptFinal__invalid_handle,
	mock_X_DigestInit__invalid_handle,
	mock_X_Digest__invalid_handle,
	mock_X_DigestUpdate__invalid_handle,
	mock_X_DigestKey__invalid_handle,
	mock_X_DigestFinal__invalid_handle,
	mock_X_SignInit__invalid_handle,
	mock_X_Sign__invalid_handle,
	mock_X_SignUpdate__invalid_handle,
	mock_X_SignFinal__invalid_handle,
	mock_X_SignRecoverInit__invalid_handle,
	mock_X_SignRecover__invalid_handle,
	mock_X_VerifyInit__invalid_handle,
	mock_X_Verify__invalid_handle,
	mock_X_VerifyUpdate__invalid_handle,
	mock_X_VerifyFinal__invalid_handle,
	mock_X_VerifyRecoverInit__invalid_handle,
	mock_X_VerifyRecover__invalid_handle,
	mock_X_DigestEncryptUpdate__invalid_handle,
	mock_X_DecryptDigestUpdate__invalid_handle,
	mock_X_SignEncryptUpdate__invalid_handle,
	mock_X_DecryptVerifyUpdate__invalid_handle,
	mock_X_GenerateKey__invalid_handle,
	mock_X_GenerateKeyPair__invalid_handle,
	mock_X_WrapKey__invalid_handle,
	mock_X_UnwrapKey__invalid_handle,
	mock_X_DeriveKey__invalid_handle,
	mock_X_SeedRandom__invalid_handle,
	mock_X_GenerateRandom__invalid_handle,
	mock_X_WaitForSlotEvent__no_event,
	/* PKCS #11 3.0 */
	mock_X_LoginUser__invalid_handle,
	mock_X_SessionCancel__invalid_handle,
	mock_X_MessageEncryptInit__invalid_handle,
	mock_X_EncryptMessage__invalid_handle,
	mock_X_EncryptMessageBegin__invalid_handle,
	mock_X_EncryptMessageNext__invalid_handle,
	mock_X_MessageEncryptFinal__invalid_handle,
	mock_X_MessageDecryptInit__invalid_handle,
	mock_X_DecryptMessage__invalid_handle,
	mock_X_DecryptMessageBegin__invalid_handle,
	mock_X_DecryptMessageNext__invalid_handle,
	mock_X_MessageDecryptFinal__invalid_handle,
	mock_X_MessageSignInit__invalid_handle,
	mock_X_SignMessage__invalid_handle,
	mock_X_SignMessageBegin__invalid_handle,
	mock_X_SignMessageNext__invalid_handle,
	mock_X_MessageSignFinal__invalid_handle,
	mock_X_MessageVerifyInit__invalid_handle,
	mock_X_VerifyMessage__invalid_handle,
	mock_X_VerifyMessageBegin__invalid_handle,
	mock_X_VerifyMessageNext__invalid_handle,
	mock_X_MessageVerifyFinal__invalid_handle
};

CK_FUNCTION_LIST mock_module = {
	{ CRYPTOKI_LEGACY_VERSION_MAJOR, CRYPTOKI_LEGACY_VERSION_MINOR },  /* version */
	mock_C_Initialize,
	mock_C_Finalize,
	mock_C_GetInfo,
	mock_C_GetFunctionList_not_supported,
	mock_C_GetSlotList,
	mock_C_GetSlotInfo,
	mock_C_GetTokenInfo,
	mock_C_GetMechanismList,
	mock_C_GetMechanismInfo,
	mock_C_InitToken__specific_args,
	mock_C_InitPIN__specific_args,
	mock_C_SetPIN__specific_args,
	mock_C_OpenSession,
	mock_C_CloseSession,
	mock_C_CloseAllSessions,
	mock_C_GetSessionInfo,
	mock_C_GetOperationState,
	mock_C_SetOperationState,
	mock_C_Login,
	mock_C_Logout,
	mock_C_CreateObject,
	mock_C_CopyObject,
	mock_C_DestroyObject,
	mock_C_GetObjectSize,
	mock_C_GetAttributeValue,
	mock_C_SetAttributeValue,
	mock_C_FindObjectsInit,
	mock_C_FindObjects,
	mock_C_FindObjectsFinal,
	mock_C_EncryptInit,
	mock_C_Encrypt,
	mock_C_EncryptUpdate,
	mock_C_EncryptFinal,
	mock_C_DecryptInit,
	mock_C_Decrypt,
	mock_C_DecryptUpdate,
	mock_C_DecryptFinal,
	mock_C_DigestInit,
	mock_C_Digest,
	mock_C_DigestUpdate,
	mock_C_DigestKey,
	mock_C_DigestFinal,
	mock_C_SignInit,
	mock_C_Sign,
	mock_C_SignUpdate,
	mock_C_SignFinal,
	mock_C_SignRecoverInit,
	mock_C_SignRecover,
	mock_C_VerifyInit,
	mock_C_Verify,
	mock_C_VerifyUpdate,
	mock_C_VerifyFinal,
	mock_C_VerifyRecoverInit,
	mock_C_VerifyRecover,
	mock_C_DigestEncryptUpdate,
	mock_C_DecryptDigestUpdate,
	mock_C_SignEncryptUpdate,
	mock_C_DecryptVerifyUpdate,
	mock_C_GenerateKey,
	mock_C_GenerateKeyPair,
	mock_C_WrapKey,
	mock_C_UnwrapKey,
	mock_C_DeriveKey,
	mock_C_SeedRandom,
	mock_C_GenerateRandom,
	mock_C_GetFunctionStatus,
	mock_C_CancelFunction,
	mock_C_WaitForSlotEvent,
};

CK_FUNCTION_LIST_3_0 mock_module_v3 = {
	{ CRYPTOKI_VERSION_MAJOR, CRYPTOKI_VERSION_MINOR },  /* version */
	mock_C_Initialize,
	mock_C_Finalize,
	mock_C_GetInfo,
	mock_C_GetFunctionList_not_supported,
	mock_C_GetSlotList,
	mock_C_GetSlotInfo,
	mock_C_GetTokenInfo,
	mock_C_GetMechanismList,
	mock_C_GetMechanismInfo,
	mock_C_InitToken__specific_args,
	mock_C_InitPIN__specific_args,
	mock_C_SetPIN__specific_args,
	mock_C_OpenSession,
	mock_C_CloseSession,
	mock_C_CloseAllSessions,
	mock_C_GetSessionInfo,
	mock_C_GetOperationState,
	mock_C_SetOperationState,
	mock_C_Login,
	mock_C_Logout,
	mock_C_CreateObject,
	mock_C_CopyObject,
	mock_C_DestroyObject,
	mock_C_GetObjectSize,
	mock_C_GetAttributeValue,
	mock_C_SetAttributeValue,
	mock_C_FindObjectsInit,
	mock_C_FindObjects,
	mock_C_FindObjectsFinal,
	mock_C_EncryptInit,
	mock_C_Encrypt,
	mock_C_EncryptUpdate,
	mock_C_EncryptFinal,
	mock_C_DecryptInit,
	mock_C_Decrypt,
	mock_C_DecryptUpdate,
	mock_C_DecryptFinal,
	mock_C_DigestInit,
	mock_C_Digest,
	mock_C_DigestUpdate,
	mock_C_DigestKey,
	mock_C_DigestFinal,
	mock_C_SignInit,
	mock_C_Sign,
	mock_C_SignUpdate,
	mock_C_SignFinal,
	mock_C_SignRecoverInit,
	mock_C_SignRecover,
	mock_C_VerifyInit,
	mock_C_Verify,
	mock_C_VerifyUpdate,
	mock_C_VerifyFinal,
	mock_C_VerifyRecoverInit,
	mock_C_VerifyRecover,
	mock_C_DigestEncryptUpdate,
	mock_C_DecryptDigestUpdate,
	mock_C_SignEncryptUpdate,
	mock_C_DecryptVerifyUpdate,
	mock_C_GenerateKey,
	mock_C_GenerateKeyPair,
	mock_C_WrapKey,
	mock_C_UnwrapKey,
	mock_C_DeriveKey,
	mock_C_SeedRandom,
	mock_C_GenerateRandom,
	mock_C_GetFunctionStatus,
	mock_C_CancelFunction,
	mock_C_WaitForSlotEvent,
	/* PKCS #11 3.0 */
	mock_C_GetInterfaceList_not_supported,
	mock_C_GetInterface_not_supported,
	mock_C_LoginUser,
	mock_C_SessionCancel,
	mock_C_MessageEncryptInit,
	mock_C_EncryptMessage,
	mock_C_EncryptMessageBegin,
	mock_C_EncryptMessageNext,
	mock_C_MessageEncryptFinal,
	mock_C_MessageDecryptInit,
	mock_C_DecryptMessage,
	mock_C_DecryptMessageBegin,
	mock_C_DecryptMessageNext,
	mock_C_MessageDecryptFinal,
	mock_C_MessageSignInit,
	mock_C_SignMessage,
	mock_C_SignMessageBegin,
	mock_C_SignMessageNext,
	mock_C_MessageSignFinal,
	mock_C_MessageVerifyInit,
	mock_C_VerifyMessage,
	mock_C_VerifyMessageBegin,
	mock_C_VerifyMessageNext,
	mock_C_MessageVerifyFinal
};

CK_INTERFACE mock_interfaces[MOCK_INTERFACES] = {
        {"PKCS 11", &mock_module_v3, 0}, /* 3.0 */
};


void
mock_module_init (void)
{
	static bool initialized = false;
	if (!initialized) {
		p11_mutex_init (&init_mutex);
		initialized = true;
	}
}
