/*
 * Copyright (c) 2013,2016 Red Hat Inc.
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
#include "test.h"

#define P11_KIT_FUTURE_UNSTABLE_API 1

#include "attrs.h"
#include "dict.h"
#include "iter.h"
#include "library.h"
#include "message.h"
#include "mock.h"

#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define ELEMS(x) (sizeof (x) / sizeof (x[0]))

static CK_FUNCTION_LIST_PTR_PTR
initialize_and_get_modules (void)
{
	CK_FUNCTION_LIST_PTR_PTR modules;

	p11_message_quiet ();

	modules = p11_kit_modules_load_and_initialize (0);
	assert (modules != NULL && modules[0] != NULL);

	p11_message_loud ();

	return modules;
}

static void
finalize_and_free_modules (CK_FUNCTION_LIST_PTR_PTR modules)
{
	p11_kit_modules_finalize (modules);
	p11_kit_modules_release (modules);
}

static int
has_handle (CK_ULONG *objects,
            int count,
            CK_ULONG handle)
{
	int i;
	for (i = 0; i < count; i++) {
		if (objects[i] == handle)
			return 1;
	}

	return 0;
}


static void
test_all (void)
{
	CK_OBJECT_HANDLE objects[128];
	CK_FUNCTION_LIST_PTR *modules;
	CK_FUNCTION_LIST_PTR module;
	CK_SESSION_HANDLE session;
	CK_ULONG size;
	P11KitIter *iter;
	CK_RV rv;
	int at;

	modules = initialize_and_get_modules ();

	iter = p11_kit_iter_new (NULL, P11_KIT_ITER_BUSY_SESSIONS);
	p11_kit_iter_begin (iter, modules);

	at = 0;
	while ((rv = p11_kit_iter_next (iter)) == CKR_OK) {
		assert (at < 128);
		objects[at] = p11_kit_iter_get_object (iter);

		module = p11_kit_iter_get_module (iter);
		assert_ptr_not_null (module);

		session = p11_kit_iter_get_session (iter);
		assert (session != 0);

		/* Do something with the object */
		size = 0;
		rv = (module->C_GetObjectSize) (session, objects[at], &size);
		assert (rv == CKR_OK);
		assert (size > 0);

		at++;
	}

	assert (rv == CKR_CANCEL);

	/* Three modules, each with 1 slot, and 3 public objects */
	assert_num_eq (9, at);

	assert (has_handle (objects, at, MOCK_DATA_OBJECT));
	assert (!has_handle (objects, at, MOCK_PRIVATE_KEY_CAPITALIZE));
	assert (has_handle (objects, at, MOCK_PUBLIC_KEY_CAPITALIZE));
	assert (!has_handle (objects, at, MOCK_PRIVATE_KEY_PREFIX));
	assert (has_handle (objects, at, MOCK_PUBLIC_KEY_PREFIX));
	assert (!has_handle (objects, at, MOCK_PROFILE_OBJECT));

	p11_kit_iter_free (iter);

	finalize_and_free_modules (modules);
}

static CK_RV
on_iter_callback (P11KitIter *iter,
                  CK_BBOOL *matches,
                  void *data)
{
	CK_OBJECT_HANDLE object;
	CK_FUNCTION_LIST_PTR module;
	CK_SESSION_HANDLE session;
	CK_ULONG size;
	CK_RV rv;

	assert_str_eq (data, "callback");

	object = p11_kit_iter_get_object (iter);
	if (object != MOCK_PUBLIC_KEY_CAPITALIZE && object != MOCK_PUBLIC_KEY_PREFIX) {
		*matches = CK_FALSE;
		return CKR_OK;
	}

	module = p11_kit_iter_get_module (iter);
	assert_ptr_not_null (module);

	session = p11_kit_iter_get_session (iter);
	assert (session != 0);

	/* Do something with the object */
	size = 0;
	rv = (module->C_GetObjectSize) (session, object, &size);
	assert (rv == CKR_OK);
	assert (size > 0);

	return CKR_OK;
}

static void
test_callback (void)
{
	CK_OBJECT_HANDLE objects[128];
	CK_FUNCTION_LIST_PTR *modules;
	P11KitIter *iter;
	CK_RV rv;
	int at;

	modules = initialize_and_get_modules ();

	iter = p11_kit_iter_new (NULL, 0);
	p11_kit_iter_add_callback (iter, on_iter_callback, "callback", NULL);
	p11_kit_iter_begin (iter, modules);

	at= 0;
	while ((rv = p11_kit_iter_next (iter)) == CKR_OK) {
		assert (at < 128);
		objects[at] = p11_kit_iter_get_object (iter);
		at++;
	}

	assert (rv == CKR_CANCEL);

	/* Three modules, each with 1 slot, and 2 public keys */
	assert_num_eq (6, at);

	assert (!has_handle (objects, at, MOCK_DATA_OBJECT));
	assert (!has_handle (objects, at, MOCK_PRIVATE_KEY_CAPITALIZE));
	assert (has_handle (objects, at, MOCK_PUBLIC_KEY_CAPITALIZE));
	assert (!has_handle (objects, at, MOCK_PRIVATE_KEY_PREFIX));
	assert (has_handle (objects, at, MOCK_PUBLIC_KEY_PREFIX));
	assert (!has_handle (objects, at, MOCK_PROFILE_OBJECT));

	p11_kit_iter_free (iter);

	finalize_and_free_modules (modules);
}

static CK_RV
on_callback_fail (P11KitIter *iter,
                  CK_BBOOL *matches,
                  void *data)
{
	return CKR_DATA_INVALID;
}

static void
test_callback_fails (void)
{
	CK_FUNCTION_LIST_PTR *modules;
	P11KitIter *iter;
	CK_RV rv;
	int at;

	modules = initialize_and_get_modules ();

	iter = p11_kit_iter_new (NULL, 0);
	p11_kit_iter_add_callback (iter, on_callback_fail, "callback", NULL);
	p11_kit_iter_begin (iter, modules);

	at= 0;
	while ((rv = p11_kit_iter_next (iter)) == CKR_OK)
		at++;

	assert (rv == CKR_DATA_INVALID);

	/* Shouldn't have succeeded at all */
	assert_num_eq (0, at);

	p11_kit_iter_free (iter);
	finalize_and_free_modules (modules);
}

static void
on_destroy_increment (void *data)
{
	int *value = data;
	(*value)++;
}

static void
test_callback_destroyer (void)
{
	P11KitIter *iter;
	int value = 1;

	iter = p11_kit_iter_new (NULL, 0);
	p11_kit_iter_add_callback (iter, on_callback_fail, &value, on_destroy_increment);
	p11_kit_iter_free (iter);

	assert_num_eq (2, value);
}

static void
test_with_session (void)
{
	CK_OBJECT_HANDLE objects[128];
	CK_SESSION_HANDLE session;
	CK_FUNCTION_LIST_PTR module;
	CK_SLOT_ID slot;
	P11KitIter *iter;
	CK_RV rv;
	int at;

	mock_module_reset ();
	rv = mock_module.C_Initialize (NULL);
	assert (rv == CKR_OK);

	rv = mock_C_OpenSession (MOCK_SLOT_ONE_ID, CKF_SERIAL_SESSION, NULL, NULL, &session);
	assert (rv == CKR_OK);

	iter = p11_kit_iter_new (NULL, 0);
	p11_kit_iter_begin_with (iter, &mock_module, 0, session);

	at= 0;
	while ((rv = p11_kit_iter_next (iter)) == CKR_OK) {
		assert (at < 128);
		objects[at] = p11_kit_iter_get_object (iter);

		slot = p11_kit_iter_get_slot (iter);
		assert (slot == MOCK_SLOT_ONE_ID);

		module = p11_kit_iter_get_module (iter);
		assert_ptr_eq (module, &mock_module);

		assert (session == p11_kit_iter_get_session (iter));
		at++;
	}

	assert (rv == CKR_CANCEL);

	/* 1 modules, each with 1 slot, and 3 public objects */
	assert_num_eq (3, at);

	assert (has_handle (objects, at, MOCK_DATA_OBJECT));
	assert (!has_handle (objects, at, MOCK_PRIVATE_KEY_CAPITALIZE));
	assert (has_handle (objects, at, MOCK_PUBLIC_KEY_CAPITALIZE));
	assert (!has_handle (objects, at, MOCK_PRIVATE_KEY_PREFIX));
	assert (has_handle (objects, at, MOCK_PUBLIC_KEY_PREFIX));
	assert (!has_handle (objects, at, MOCK_PROFILE_OBJECT));

	p11_kit_iter_free (iter);

	/* The session is still valid ... */
	rv = mock_module.C_CloseSession (session);
	assert (rv == CKR_OK);

	rv = mock_module.C_Finalize (NULL);
	assert (rv == CKR_OK);
}

static void
test_with_slot (void)
{
	CK_OBJECT_HANDLE objects[128];
	CK_FUNCTION_LIST_PTR module;
	CK_SLOT_ID slot;
	P11KitIter *iter;
	CK_RV rv;
	int at;

	mock_module_reset ();
	rv = mock_module.C_Initialize (NULL);
	assert (rv == CKR_OK);

	iter = p11_kit_iter_new (NULL, 0);
	p11_kit_iter_begin_with (iter, &mock_module, MOCK_SLOT_ONE_ID, 0);

	at= 0;
	while ((rv = p11_kit_iter_next (iter)) == CKR_OK) {
		assert (at < 128);
		objects[at] = p11_kit_iter_get_object (iter);

		slot = p11_kit_iter_get_slot (iter);
		assert (slot == MOCK_SLOT_ONE_ID);

		module = p11_kit_iter_get_module (iter);
		assert_ptr_eq (module, &mock_module);
		at++;
	}

	assert (rv == CKR_CANCEL);

	/* 1 modules, each with 1 slot, and 3 public objects */
	assert_num_eq (3, at);

	assert (has_handle (objects, at, MOCK_DATA_OBJECT));
	assert (!has_handle (objects, at, MOCK_PRIVATE_KEY_CAPITALIZE));
	assert (has_handle (objects, at, MOCK_PUBLIC_KEY_CAPITALIZE));
	assert (!has_handle (objects, at, MOCK_PRIVATE_KEY_PREFIX));
	assert (has_handle (objects, at, MOCK_PUBLIC_KEY_PREFIX));
	assert (!has_handle (objects, at, MOCK_PROFILE_OBJECT));

	p11_kit_iter_free (iter);

	rv = (mock_module.C_Finalize) (NULL);
	assert (rv == CKR_OK);
}

static void
test_with_module (void)
{
	CK_OBJECT_HANDLE objects[128];
	CK_FUNCTION_LIST_PTR module;
	P11KitIter *iter;
	CK_RV rv;
	int at;

	mock_module_reset ();
	rv = mock_module.C_Initialize (NULL);
	assert (rv == CKR_OK);

	iter = p11_kit_iter_new (NULL, 0);
	p11_kit_iter_begin_with (iter, &mock_module, 0, 0);

	at= 0;
	while ((rv = p11_kit_iter_next (iter)) == CKR_OK) {
		assert (at < 128);
		objects[at] = p11_kit_iter_get_object (iter);

		module = p11_kit_iter_get_module (iter);
		assert_ptr_eq (module, &mock_module);
		at++;
	}

	assert (rv == CKR_CANCEL);

	/* 1 modules, each with 1 slot, and 3 public objects */
	assert_num_eq (3, at);

	assert (has_handle (objects, at, MOCK_DATA_OBJECT));
	assert (!has_handle (objects, at, MOCK_PRIVATE_KEY_CAPITALIZE));
	assert (has_handle (objects, at, MOCK_PUBLIC_KEY_CAPITALIZE));
	assert (!has_handle (objects, at, MOCK_PRIVATE_KEY_PREFIX));
	assert (has_handle (objects, at, MOCK_PUBLIC_KEY_PREFIX));
	assert (!has_handle (objects, at, MOCK_PROFILE_OBJECT));

	p11_kit_iter_free (iter);

	rv = mock_module.C_Finalize (NULL);
	assert (rv == CKR_OK);
}

static void
test_keep_session (void)
{
	CK_SESSION_HANDLE session;
	P11KitIter *iter;
	CK_RV rv;

	mock_module_reset ();
	rv = mock_module.C_Initialize (NULL);
	assert (rv == CKR_OK);

	iter = p11_kit_iter_new (NULL, 0);
	p11_kit_iter_begin_with (iter, &mock_module, 0, 0);

	rv = p11_kit_iter_next (iter);
	assert (rv == CKR_OK);

	session = p11_kit_iter_keep_session (iter);
	p11_kit_iter_free (iter);

	/* The session is still valid ... */
	rv = mock_module.C_CloseSession (session);
	assert (rv == CKR_OK);

	rv = mock_module.C_Finalize (NULL);
	assert (rv == CKR_OK);
}

static void
test_unrecognized (void)
{
	CK_FUNCTION_LIST_PTR *modules;
	P11KitIter *iter;
	P11KitUri *uri;
	CK_RV rv;
	int count;

	modules = initialize_and_get_modules ();

	uri = p11_kit_uri_new ();
	p11_kit_uri_set_unrecognized (uri, 1);
	iter = p11_kit_iter_new (uri, 0);
	p11_kit_uri_free (uri);

	p11_kit_iter_begin (iter, modules);

	count = 0;
	while ((rv = p11_kit_iter_next (iter)) == CKR_OK)
		count++;

	assert (rv == CKR_CANCEL);

	/* Nothing should have matched */
	assert_num_eq (0, count);

	p11_kit_iter_free (iter);

	finalize_and_free_modules (modules);
}

static void
test_uri_with_type (void)
{
	CK_OBJECT_HANDLE objects[128];
	CK_FUNCTION_LIST_PTR *modules;
	P11KitIter *iter;
	P11KitUri *uri;
	CK_RV rv;
	int at;
	int ret;

	modules = initialize_and_get_modules ();

	uri = p11_kit_uri_new ();
	ret = p11_kit_uri_parse ("pkcs11:object-type=public", P11_KIT_URI_FOR_OBJECT, uri);
	assert_num_eq (ret, P11_KIT_URI_OK);

	iter = p11_kit_iter_new (uri, 0);
	p11_kit_uri_free (uri);

	p11_kit_iter_begin (iter, modules);

	at = 0;
	while ((rv = p11_kit_iter_next (iter)) == CKR_OK) {
		assert (at < 128);
		objects[at] = p11_kit_iter_get_object (iter);
		at++;
	}

	assert (rv == CKR_CANCEL);

	/* Three modules, each with 1 slot, and 2 public keys */
	assert_num_eq (6, at);

	assert (!has_handle (objects, at, MOCK_DATA_OBJECT));
	assert (!has_handle (objects, at, MOCK_PRIVATE_KEY_CAPITALIZE));
	assert (has_handle (objects, at, MOCK_PUBLIC_KEY_CAPITALIZE));
	assert (!has_handle (objects, at, MOCK_PRIVATE_KEY_PREFIX));
	assert (has_handle (objects, at, MOCK_PUBLIC_KEY_PREFIX));
	assert (!has_handle (objects, at, MOCK_PROFILE_OBJECT));

	p11_kit_iter_free (iter);

	finalize_and_free_modules (modules);
}

static void
test_set_uri (void)
{
	CK_FUNCTION_LIST_PTR *modules;
	P11KitIter *iter;
	P11KitUri *uri;
	CK_RV rv;

	modules = initialize_and_get_modules ();

	uri = p11_kit_uri_new ();
	p11_kit_uri_set_unrecognized (uri, 1);
	iter = p11_kit_iter_new (NULL, 0);
	p11_kit_iter_set_uri (iter, uri);
	p11_kit_uri_free (uri);

	p11_kit_iter_begin (iter, modules);

	/* Nothing should have matched */
	rv = p11_kit_iter_next (iter);
	assert_num_eq (rv, CKR_CANCEL);

	p11_kit_iter_free (iter);

	finalize_and_free_modules (modules);
}

static void
test_filter (void)
{
	CK_OBJECT_HANDLE objects[128];
	CK_FUNCTION_LIST_PTR *modules;
	P11KitIter *iter;
	CK_RV rv;
	int at;

	CK_BBOOL vfalse = CK_FALSE;
	CK_OBJECT_CLASS public_key = CKO_PUBLIC_KEY;
	CK_ATTRIBUTE attrs[] = {
		{ CKA_PRIVATE, &vfalse, sizeof (vfalse) },
		{ CKA_CLASS, &public_key, sizeof (public_key) },
	};

	modules = initialize_and_get_modules ();

	iter = p11_kit_iter_new (NULL, 0);
	p11_kit_iter_add_filter (iter, attrs, 2);

	p11_kit_iter_begin (iter, modules);

	at = 0;
	while ((rv = p11_kit_iter_next (iter)) == CKR_OK) {
		assert (at < 128);
		objects[at] = p11_kit_iter_get_object (iter);
		at++;
	}

	assert (rv == CKR_CANCEL);

	/* Three modules, each with 1 slot, and 2 public keys */
	assert_num_eq (6, at);

	assert (!has_handle (objects, at, MOCK_DATA_OBJECT));
	assert (!has_handle (objects, at, MOCK_PRIVATE_KEY_CAPITALIZE));
	assert (has_handle (objects, at, MOCK_PUBLIC_KEY_CAPITALIZE));
	assert (!has_handle (objects, at, MOCK_PRIVATE_KEY_PREFIX));
	assert (has_handle (objects, at, MOCK_PUBLIC_KEY_PREFIX));
	assert (!has_handle (objects, at, MOCK_PROFILE_OBJECT));

	p11_kit_iter_free (iter);

	finalize_and_free_modules (modules);
}

static void
test_session_flags (void)
{
	CK_FUNCTION_LIST_PTR *modules;
	CK_FUNCTION_LIST_PTR module;
	CK_SESSION_HANDLE session;
	CK_SESSION_INFO info;
	P11KitIter *iter;
	CK_RV rv;

	modules = initialize_and_get_modules ();

	iter = p11_kit_iter_new (NULL, P11_KIT_ITER_WANT_WRITABLE);
	p11_kit_iter_begin (iter, modules);

	while ((rv = p11_kit_iter_next (iter)) == CKR_OK) {
		module = p11_kit_iter_get_module (iter);
		assert_ptr_not_null (module);

		session = p11_kit_iter_get_session (iter);
		assert (session != 0);

		rv = (module->C_GetSessionInfo) (session, &info);
		assert (rv == CKR_OK);

		assert_num_eq (CKS_RW_PUBLIC_SESSION, info.state);
	}

	assert (rv == CKR_CANCEL);

	p11_kit_iter_free (iter);

	finalize_and_free_modules (modules);
}

static void
test_module_match (void)
{
	CK_FUNCTION_LIST_PTR *modules;
	P11KitIter *iter;
	P11KitUri *uri;
	CK_RV rv;
	int count;
	int ret;

	modules = initialize_and_get_modules ();

	uri = p11_kit_uri_new ();
	ret = p11_kit_uri_parse ("pkcs11:library-description=MOCK%20LIBRARY", P11_KIT_URI_FOR_MODULE, uri);
	assert_num_eq (P11_KIT_URI_OK, ret);

	iter = p11_kit_iter_new (uri, 0);
	p11_kit_uri_free (uri);

	p11_kit_iter_begin (iter, modules);

	count = 0;
	while ((rv = p11_kit_iter_next (iter)) == CKR_OK)
		count++;

	assert (rv == CKR_CANCEL);

	/* Three modules, each with 1 slot, and 3 public objects */
	assert_num_eq (9, count);

	p11_kit_iter_free (iter);

	finalize_and_free_modules (modules);
}

static void
test_module_mismatch (void)
{
	CK_FUNCTION_LIST_PTR *modules;
	P11KitIter *iter;
	P11KitUri *uri;
	CK_RV rv;
	int count;
	int ret;

	modules = initialize_and_get_modules ();

	uri = p11_kit_uri_new ();
	ret = p11_kit_uri_parse ("pkcs11:library-description=blah", P11_KIT_URI_FOR_MODULE, uri);
	assert_num_eq (P11_KIT_URI_OK, ret);

	iter = p11_kit_iter_new (uri, 0);
	p11_kit_uri_free (uri);

	p11_kit_iter_begin (iter, modules);

	count = 0;
	while ((rv = p11_kit_iter_next (iter)) == CKR_OK)
		count++;

	assert (rv == CKR_CANCEL);

	/* Nothing should have matched */
	assert_num_eq (0, count);

	p11_kit_iter_free (iter);

	finalize_and_free_modules (modules);
}

static void
test_module_only (void)
{
	CK_FUNCTION_LIST_PTR *modules;
	P11KitIter *iter;
	P11KitUri *uri;
	CK_RV rv;
	int count;
	int ret;

	modules = initialize_and_get_modules ();

	uri = p11_kit_uri_new ();
	ret = p11_kit_uri_parse ("pkcs11:library-description=MOCK%20LIBRARY", P11_KIT_URI_FOR_MODULE, uri);
	assert_num_eq (P11_KIT_URI_OK, ret);

	iter = p11_kit_iter_new (uri, P11_KIT_ITER_WITH_MODULES | P11_KIT_ITER_WITHOUT_OBJECTS);
	p11_kit_uri_free (uri);

	p11_kit_iter_begin (iter, modules);

	count = 0;
	while ((rv = p11_kit_iter_next (iter)) == CKR_OK) {
		P11KitIterKind kind = p11_kit_iter_get_kind (iter);
		assert_num_eq (P11_KIT_ITER_KIND_MODULE, kind);
		count++;
	}

	assert (rv == CKR_CANCEL);

	/* Three modules, each with 1 slot, and 3 public objects */
	assert_num_eq (3, count);

	p11_kit_iter_free (iter);

	finalize_and_free_modules (modules);
}

static void
test_slot_match (void)
{
	CK_FUNCTION_LIST_PTR *modules;
	P11KitIter *iter;
	P11KitUri *uri;
	CK_RV rv;
	int count;
	int ret;

	modules = initialize_and_get_modules ();

	uri = p11_kit_uri_new ();
	ret = p11_kit_uri_parse ("pkcs11:slot-manufacturer=TEST%20MANUFACTURER", P11_KIT_URI_FOR_SLOT, uri);
	assert_num_eq (P11_KIT_URI_OK, ret);

	iter = p11_kit_iter_new (uri, 0);
	p11_kit_uri_free (uri);

	p11_kit_iter_begin (iter, modules);

	count = 0;
	while ((rv = p11_kit_iter_next (iter)) == CKR_OK)
		count++;

	assert (rv == CKR_CANCEL);

	/* Three modules, each with 1 slot, and 3 public objects */
	assert_num_eq (9, count);

	p11_kit_iter_free (iter);

	finalize_and_free_modules (modules);
}

static void
test_slot_mismatch (void)
{
	CK_FUNCTION_LIST_PTR *modules;
	P11KitIter *iter;
	P11KitUri *uri;
	CK_RV rv;
	int count;
	int ret;

	modules = initialize_and_get_modules ();

	uri = p11_kit_uri_new ();
	ret = p11_kit_uri_parse ("pkcs11:slot-manufacturer=blah", P11_KIT_URI_FOR_SLOT, uri);
	assert_num_eq (P11_KIT_URI_OK, ret);

	iter = p11_kit_iter_new (uri, 0);
	p11_kit_uri_free (uri);

	p11_kit_iter_begin (iter, modules);

	count = 0;
	while ((rv = p11_kit_iter_next (iter)) == CKR_OK)
		count++;

	assert (rv == CKR_CANCEL);

	/* Nothing should have matched */
	assert_num_eq (0, count);

	p11_kit_iter_free (iter);

	finalize_and_free_modules (modules);
}

static void
test_slot_only (void)
{
	CK_FUNCTION_LIST_PTR *modules;
	P11KitIter *iter;
	P11KitUri *uri;
	CK_RV rv;
	int count;
	int ret;

	modules = initialize_and_get_modules ();

	uri = p11_kit_uri_new ();
	ret = p11_kit_uri_parse ("pkcs11:slot-manufacturer=TEST%20MANUFACTURER", P11_KIT_URI_FOR_SLOT, uri);
	assert_num_eq (P11_KIT_URI_OK, ret);

	iter = p11_kit_iter_new (uri, P11_KIT_ITER_WITH_SLOTS | P11_KIT_ITER_WITHOUT_OBJECTS);
	p11_kit_uri_free (uri);

	p11_kit_iter_begin (iter, modules);

	count = 0;
	while ((rv = p11_kit_iter_next (iter)) == CKR_OK) {
		P11KitIterKind kind = p11_kit_iter_get_kind (iter);
		assert_num_eq (P11_KIT_ITER_KIND_SLOT, kind);
		count++;
	}

	assert (rv == CKR_CANCEL);

	/* Three modules, each with 1 slot, and 3 public objects */
	assert_num_eq (3, count);

	p11_kit_iter_free (iter);

	finalize_and_free_modules (modules);
}

static void
test_slot_match_by_id (void)
{
	CK_FUNCTION_LIST_PTR *modules;
	P11KitIter *iter;
	P11KitUri *uri;
	char *string;
	CK_RV rv;
	int count;
	int ret;

	modules = initialize_and_get_modules ();

	uri = p11_kit_uri_new ();
	ret = asprintf (&string, "pkcs11:slot-id=%d", MOCK_SLOT_ONE_ID);
	assert (ret > 0);
	ret = p11_kit_uri_parse (string, P11_KIT_URI_FOR_SLOT, uri);
	free (string);
	assert_num_eq (P11_KIT_URI_OK, ret);

	iter = p11_kit_iter_new (uri, 0);
	p11_kit_uri_free (uri);

	p11_kit_iter_begin (iter, modules);

	count = 0;
	while ((rv = p11_kit_iter_next (iter)) == CKR_OK)
		count++;

	assert (rv == CKR_CANCEL);

	/* Three modules, each with 1 slot, and 3 public objects */
	assert_num_eq (9, count);

	p11_kit_iter_free (iter);

	finalize_and_free_modules (modules);
}

static void
test_slot_mismatch_by_id (void)
{
	CK_FUNCTION_LIST_PTR *modules;
	P11KitIter *iter;
	P11KitUri *uri;
	CK_RV rv;
	int count;
	int ret;

	modules = initialize_and_get_modules ();

	uri = p11_kit_uri_new ();
	ret = p11_kit_uri_parse ("pkcs11:slot-id=0", P11_KIT_URI_FOR_SLOT, uri);
	assert_num_eq (P11_KIT_URI_OK, ret);

	iter = p11_kit_iter_new (uri, 0);
	p11_kit_uri_free (uri);

	p11_kit_iter_begin (iter, modules);

	count = 0;
	while ((rv = p11_kit_iter_next (iter)) == CKR_OK)
		count++;

	assert (rv == CKR_CANCEL);

	/* Nothing should have matched */
	assert_num_eq (0, count);

	p11_kit_iter_free (iter);

	finalize_and_free_modules (modules);
}

static void
test_slot_info (void)
{
	CK_FUNCTION_LIST_PTR *modules;
	CK_SLOT_INFO *info;
	P11KitIter *iter;
	char *string;
	CK_RV rv;

	modules = initialize_and_get_modules ();

	iter = p11_kit_iter_new (NULL, 0);
	p11_kit_iter_begin (iter, modules);

	rv = p11_kit_iter_next (iter);
	assert_num_eq (rv, CKR_OK);

	info = p11_kit_iter_get_slot_info (iter);
	assert_ptr_not_null (info);

	string = p11_kit_space_strdup (info->slotDescription,
				       sizeof (info->slotDescription));
	assert_ptr_not_null (string);

	assert_str_eq (string, "TEST SLOT");

	free (string);
	p11_kit_iter_free (iter);

	finalize_and_free_modules (modules);
}

static void
test_token_match (void)
{
	CK_FUNCTION_LIST_PTR *modules;
	P11KitIter *iter;
	P11KitUri *uri;
	CK_RV rv;
	int count;
	int ret;

	modules = initialize_and_get_modules ();

	uri = p11_kit_uri_new ();
	ret = p11_kit_uri_parse ("pkcs11:manufacturer=TEST%20MANUFACTURER", P11_KIT_URI_FOR_TOKEN, uri);
	assert_num_eq (P11_KIT_URI_OK, ret);

	iter = p11_kit_iter_new (uri, 0);
	p11_kit_uri_free (uri);

	p11_kit_iter_begin (iter, modules);

	count = 0;
	while ((rv = p11_kit_iter_next (iter)) == CKR_OK)
		count++;

	assert (rv == CKR_CANCEL);

	/* Three modules, each with 1 slot, and 3 public objects */
	assert_num_eq (9, count);

	p11_kit_iter_free (iter);

	finalize_and_free_modules (modules);
}

static void
test_token_mismatch (void)
{
	CK_FUNCTION_LIST_PTR *modules;
	P11KitIter *iter;
	P11KitUri *uri;
	CK_RV rv;
	int count;
	int ret;

	modules = initialize_and_get_modules ();

	uri = p11_kit_uri_new ();
	ret = p11_kit_uri_parse ("pkcs11:manufacturer=blah", P11_KIT_URI_FOR_TOKEN, uri);
	assert_num_eq (P11_KIT_URI_OK, ret);

	iter = p11_kit_iter_new (uri, 0);
	p11_kit_uri_free (uri);

	p11_kit_iter_begin (iter, modules);

	count = 0;
	while ((rv = p11_kit_iter_next (iter)) == CKR_OK)
		count++;

	assert (rv == CKR_CANCEL);

	/* Nothing should have matched */
	assert_num_eq (0, count);

	p11_kit_iter_free (iter);

	finalize_and_free_modules (modules);
}

static void
test_token_only (void)
{
	CK_FUNCTION_LIST_PTR *modules;
	P11KitIter *iter;
	P11KitUri *uri;
	CK_RV rv;
	int count;
	int ret;

	modules = initialize_and_get_modules ();

	uri = p11_kit_uri_new ();
	ret = p11_kit_uri_parse ("pkcs11:manufacturer=TEST%20MANUFACTURER", P11_KIT_URI_FOR_TOKEN, uri);
	assert_num_eq (P11_KIT_URI_OK, ret);

	iter = p11_kit_iter_new (uri, P11_KIT_ITER_WITH_TOKENS | P11_KIT_ITER_WITHOUT_OBJECTS);
	p11_kit_uri_free (uri);

	p11_kit_iter_begin (iter, modules);

	count = 0;
	while ((rv = p11_kit_iter_next (iter)) == CKR_OK) {
		P11KitIterKind kind = p11_kit_iter_get_kind (iter);
		assert_num_eq (P11_KIT_ITER_KIND_TOKEN, kind);
		count++;
	}

	assert (rv == CKR_CANCEL);

	/* Three modules, each with 1 slot, and 3 public objects */
	assert_num_eq (3, count);

	p11_kit_iter_free (iter);

	finalize_and_free_modules (modules);
}

static void
test_token_info (void)
{
	CK_FUNCTION_LIST_PTR *modules;
	CK_TOKEN_INFO *info;
	P11KitIter *iter;
	char *string;
	CK_RV rv;

	modules = initialize_and_get_modules ();

	iter = p11_kit_iter_new (NULL, 0);
	p11_kit_iter_begin (iter, modules);

	rv = p11_kit_iter_next (iter);
	assert_num_eq (rv, CKR_OK);

	info = p11_kit_iter_get_token (iter);
	assert_ptr_not_null (info);

	string = p11_kit_space_strdup (info->label, sizeof (info->label));
	assert_ptr_not_null (string);

	assert_str_eq (string, "TEST LABEL");

	free (string);
	p11_kit_iter_free (iter);

	finalize_and_free_modules (modules);
}

static void
test_getslotlist_fail_first (void)
{
	CK_FUNCTION_LIST module;
	P11KitIter *iter;
	CK_RV rv;
	int at;

	mock_module_reset ();
	rv = mock_module.C_Initialize (NULL);
	assert (rv == CKR_OK);

	memcpy (&module, &mock_module, sizeof (CK_FUNCTION_LIST));
	module.C_GetSlotList = mock_C_GetSlotList__fail_first;

	iter = p11_kit_iter_new (NULL, 0);
	p11_kit_iter_begin_with (iter, &module, 0, 0);

	at= 0;
	while ((rv = p11_kit_iter_next (iter)) == CKR_OK)
		at++;

	assert (rv == CKR_VENDOR_DEFINED);

	/* Should fail on the first iteration */
	assert_num_eq (0, at);

	p11_kit_iter_free (iter);

	rv = mock_module.C_Finalize (NULL);
	assert (rv == CKR_OK);
}

static void
test_getslotlist_fail_late (void)
{
	CK_FUNCTION_LIST module;
	P11KitIter *iter;
	CK_RV rv;
	int at;

	mock_module_reset ();
	rv = mock_module.C_Initialize (NULL);
	assert (rv == CKR_OK);

	memcpy (&module, &mock_module, sizeof (CK_FUNCTION_LIST));
	module.C_GetSlotList = mock_C_GetSlotList__fail_late;

	iter = p11_kit_iter_new (NULL, 0);
	p11_kit_iter_begin_with (iter, &module, 0, 0);

	at= 0;
	while ((rv = p11_kit_iter_next (iter)) == CKR_OK)
		at++;

	assert (rv == CKR_VENDOR_DEFINED);

	/* Should fail on the first iteration */
	assert_num_eq (0, at);

	p11_kit_iter_free (iter);

	rv = mock_module.C_Finalize (NULL);
	assert (rv == CKR_OK);
}

static void
test_open_session_fail (void)
{
	CK_FUNCTION_LIST module;
	P11KitIter *iter;
	CK_RV rv;
	int at;

	mock_module_reset ();
	rv = mock_module.C_Initialize (NULL);
	assert (rv == CKR_OK);

	memcpy (&module, &mock_module, sizeof (CK_FUNCTION_LIST));
	module.C_OpenSession = mock_C_OpenSession__fails;

	iter = p11_kit_iter_new (NULL, 0);
	p11_kit_iter_begin_with (iter, &module, 0, 0);

	at= 0;
	while ((rv = p11_kit_iter_next (iter)) == CKR_OK)
		at++;

	assert (rv == CKR_DEVICE_ERROR);

	/* Should fail on the first iteration */
	assert_num_eq (0, at);

	p11_kit_iter_free (iter);

	rv = mock_module.C_Finalize (NULL);
	assert (rv == CKR_OK);
}

static void
test_find_init_fail (void)
{
	CK_FUNCTION_LIST module;
	P11KitIter *iter;
	CK_RV rv;
	int at;

	mock_module_reset ();
	rv = mock_module.C_Initialize (NULL);
	assert (rv == CKR_OK);

	memcpy (&module, &mock_module, sizeof (CK_FUNCTION_LIST));
	module.C_FindObjectsInit = mock_C_FindObjectsInit__fails;

	iter = p11_kit_iter_new (NULL, 0);
	p11_kit_iter_begin_with (iter, &module, 0, 0);

	at= 0;
	while ((rv = p11_kit_iter_next (iter)) == CKR_OK)
		at++;

	assert (rv == CKR_DEVICE_MEMORY);

	/* Should fail on the first iteration */
	assert_num_eq (0, at);

	p11_kit_iter_free (iter);

	rv = mock_module.C_Finalize (NULL);
	assert (rv == CKR_OK);
}

static void
test_find_objects_fail (void)
{
	CK_FUNCTION_LIST module;
	P11KitIter *iter;
	CK_RV rv;
	int at;

	mock_module_reset ();
	rv = mock_module.C_Initialize (NULL);
	assert (rv == CKR_OK);

	memcpy (&module, &mock_module, sizeof (CK_FUNCTION_LIST));
	module.C_FindObjects = mock_C_FindObjects__fails;

	iter = p11_kit_iter_new (NULL, 0);
	p11_kit_iter_begin_with (iter, &module, 0, 0);

	at= 0;
	while ((rv = p11_kit_iter_next (iter)) == CKR_OK)
		at++;

	assert (rv == CKR_DEVICE_REMOVED);

	/* Should fail on the first iteration */
	assert_num_eq (0, at);

	p11_kit_iter_free (iter);

	rv = mock_module.C_Finalize (NULL);
	assert (rv == CKR_OK);
}

static void
test_get_attributes (void)
{
	CK_FUNCTION_LIST_PTR *modules;
	P11KitIter *iter;
	CK_OBJECT_HANDLE object;
	char label[128];
	CK_ULONG klass;
	CK_ULONG ulong;
	CK_RV rv;
	int at;

	CK_ATTRIBUTE template[] = {
		{ CKA_CLASS, &klass, sizeof (klass) },
		{ CKA_LABEL, label, sizeof (label) },
		{ CKA_INVALID },
	};

	CK_ATTRIBUTE attrs[3];

	modules = initialize_and_get_modules ();

	iter = p11_kit_iter_new (NULL, 0);
	p11_kit_iter_begin (iter, modules);

	at = 0;
	while ((rv = p11_kit_iter_next (iter)) == CKR_OK) {
		assert (sizeof (attrs) == sizeof (template));
		memcpy (&attrs, &template, sizeof (attrs));

		rv = p11_kit_iter_get_attributes (iter, attrs, 2);
		assert (rv == CKR_OK);

		object = p11_kit_iter_get_object (iter);
		switch (object) {
		case MOCK_DATA_OBJECT:
			assert (p11_attrs_find_ulong (attrs, CKA_CLASS, &ulong) && ulong == CKO_DATA);
			assert (p11_attr_match_value (p11_attrs_find (attrs, CKA_LABEL), "TEST LABEL", -1));
			break;
		case MOCK_PUBLIC_KEY_CAPITALIZE:
			assert (p11_attrs_find_ulong (attrs, CKA_CLASS, &ulong) && ulong == CKO_PUBLIC_KEY);
			assert (p11_attr_match_value (p11_attrs_find (attrs, CKA_LABEL), "Public Capitalize Key", -1));
			break;
		case MOCK_PUBLIC_KEY_PREFIX:
			assert (p11_attrs_find_ulong (attrs, CKA_CLASS, &ulong) && ulong == CKO_PUBLIC_KEY);
			assert (p11_attr_match_value (p11_attrs_find (attrs, CKA_LABEL), "Public prefix key", -1));
			break;
		default:
			assert_fail ("Unknown object matched", NULL);
			break;
		}

		at++;
	}

	assert (rv == CKR_CANCEL);

	/* Three modules, each with 1 slot, and 3 public objects */
	assert_num_eq (9, at);

	p11_kit_iter_free (iter);

	finalize_and_free_modules (modules);
}



static void
test_load_attributes (void)
{
	CK_FUNCTION_LIST_PTR *modules;
	P11KitIter *iter;
	CK_ATTRIBUTE *attrs;
	CK_OBJECT_HANDLE object;
	CK_ULONG ulong;
	CK_RV rv;
	int at;

	CK_ATTRIBUTE types[] = {
		{ CKA_CLASS },
		{ CKA_LABEL },
	};

	modules = initialize_and_get_modules ();

	iter = p11_kit_iter_new (NULL, 0);
	p11_kit_iter_begin (iter, modules);

	attrs = p11_attrs_buildn (NULL, types, 2);

	at = 0;
	while ((rv = p11_kit_iter_next (iter)) == CKR_OK) {
		rv = p11_kit_iter_load_attributes (iter, attrs, 2);
		assert (rv == CKR_OK);

		object = p11_kit_iter_get_object (iter);
		switch (object) {
		case MOCK_DATA_OBJECT:
			assert (p11_attrs_find_ulong (attrs, CKA_CLASS, &ulong) && ulong == CKO_DATA);
			assert (p11_attr_match_value (p11_attrs_find (attrs, CKA_LABEL), "TEST LABEL", -1));
			break;
		case MOCK_PUBLIC_KEY_CAPITALIZE:
			assert (p11_attrs_find_ulong (attrs, CKA_CLASS, &ulong) && ulong == CKO_PUBLIC_KEY);
			assert (p11_attr_match_value (p11_attrs_find (attrs, CKA_LABEL), "Public Capitalize Key", -1));
			break;
		case MOCK_PUBLIC_KEY_PREFIX:
			assert (p11_attrs_find_ulong (attrs, CKA_CLASS, &ulong) && ulong == CKO_PUBLIC_KEY);
			assert (p11_attr_match_value (p11_attrs_find (attrs, CKA_LABEL), "Public prefix key", -1));
			break;
		default:
			assert_fail ("Unknown object matched", NULL);
			break;
		}

		at++;
	}

	p11_attrs_free (attrs);

	assert (rv == CKR_CANCEL);

	/* Three modules, each with 1 slot, and 3 public objects */
	assert_num_eq (9, at);

	p11_kit_iter_free (iter);

	finalize_and_free_modules (modules);
}

static void
test_load_attributes_none (void)
{
	CK_FUNCTION_LIST module;
	P11KitIter *iter;
	CK_ATTRIBUTE *attrs;
	CK_RV rv;

	mock_module_reset ();
	rv = mock_module.C_Initialize (NULL);
	assert (rv == CKR_OK);

	memcpy (&module, &mock_module, sizeof (CK_FUNCTION_LIST));

	iter = p11_kit_iter_new (NULL, 0);
	p11_kit_iter_begin_with (iter, &module, 0, 0);

	while ((rv = p11_kit_iter_next (iter)) == CKR_OK) {
		attrs = p11_attrs_buildn (NULL, NULL, 0);
		rv = p11_kit_iter_load_attributes (iter, attrs, 0);
		assert (rv == CKR_OK);
		p11_attrs_free (attrs);
	}

	assert (rv == CKR_CANCEL);

	p11_kit_iter_free (iter);

	rv = mock_module.C_Finalize (NULL);
	assert (rv == CKR_OK);
}

static void
test_load_attributes_fail_first (void)
{
	CK_ATTRIBUTE label = { CKA_LABEL, };
	CK_FUNCTION_LIST module;
	P11KitIter *iter;
	CK_ATTRIBUTE *attrs;
	CK_RV rv;

	mock_module_reset ();
	rv = mock_module.C_Initialize (NULL);
	assert (rv == CKR_OK);

	memcpy (&module, &mock_module, sizeof (CK_FUNCTION_LIST));
	module.C_GetAttributeValue = mock_C_GetAttributeValue__fail_first;

	iter = p11_kit_iter_new (NULL, 0);
	p11_kit_iter_begin_with (iter, &module, 0, 0);

	while ((rv = p11_kit_iter_next (iter)) == CKR_OK) {
		attrs = p11_attrs_build (NULL, &label, NULL);
		rv = p11_kit_iter_load_attributes (iter, attrs, 1);
		assert (rv == CKR_FUNCTION_REJECTED);
		p11_attrs_free (attrs);
	}

	assert (rv == CKR_CANCEL);

	p11_kit_iter_free (iter);

	rv = mock_module.C_Finalize (NULL);
	assert (rv == CKR_OK);
}

static void
test_load_attributes_fail_late (void)
{
	CK_ATTRIBUTE label = { CKA_LABEL, };
	CK_FUNCTION_LIST module;
	P11KitIter *iter;
	CK_ATTRIBUTE *attrs;
	CK_RV rv;

	mock_module_reset ();
	rv = mock_module.C_Initialize (NULL);
	assert (rv == CKR_OK);

	memcpy (&module, &mock_module, sizeof (CK_FUNCTION_LIST));
	module.C_GetAttributeValue = mock_C_GetAttributeValue__fail_late;

	iter = p11_kit_iter_new (NULL, 0);
	p11_kit_iter_begin_with (iter, &module, 0, 0);

	while ((rv = p11_kit_iter_next (iter)) == CKR_OK) {
		attrs = p11_attrs_build (NULL, &label, NULL);
		rv = p11_kit_iter_load_attributes (iter, attrs, 1);
		assert (rv == CKR_FUNCTION_FAILED);
		p11_attrs_free (attrs);
	}

	assert (rv == CKR_CANCEL);

	p11_kit_iter_free (iter);

	rv = mock_module.C_Finalize (NULL);
	assert (rv == CKR_OK);
}

static void
test_many (void *flags)
{
	P11KitIterBehavior behavior;
	CK_SESSION_HANDLE session;
	CK_OBJECT_HANDLE handle;
	p11_dict *seen;
	P11KitIter *iter;
	CK_RV rv;
	int count;
	int i;

	static CK_OBJECT_CLASS data = CKO_DATA;
	static CK_ATTRIBUTE object[] = {
		{ CKA_VALUE, "blah", 4 },
		{ CKA_CLASS, &data, sizeof (data) },
		{ CKA_ID, "ID1", 3 },
		{ CKA_INVALID },
	};

	behavior = 0;
	if (strstr (flags, "busy-sessions"))
		behavior |= P11_KIT_ITER_BUSY_SESSIONS;

	mock_module_reset ();
	rv = mock_module.C_Initialize (NULL);
	assert_num_eq (rv, CKR_OK);

	rv = mock_C_OpenSession (MOCK_SLOT_ONE_ID, CKF_SERIAL_SESSION, NULL, NULL, &session);
	assert_num_eq (rv, CKR_OK);

	for (i = 0; i < 10000; i++)
		mock_module_add_object (MOCK_SLOT_ONE_ID, object);

	seen = p11_dict_new (p11_dict_ulongptr_hash, p11_dict_ulongptr_equal, free, NULL);
	iter = p11_kit_iter_new (NULL, behavior);
	p11_kit_iter_add_filter (iter, object, 3);
	p11_kit_iter_begin_with (iter, &mock_module, 0, session);

	count = 0;
	while ((rv = p11_kit_iter_next (iter)) == CKR_OK) {
		handle = p11_kit_iter_get_object (iter);
		assert (p11_dict_get (seen, &handle) == NULL);
		if (!p11_dict_set (seen, memdup (&handle, sizeof (handle)), "x"))
			assert_not_reached ();
		count++;
	}

	assert_num_eq (rv, CKR_CANCEL);
	assert_num_eq (count, 10000);

	p11_kit_iter_free (iter);
	p11_dict_free (seen);

	rv = mock_module.C_Finalize (NULL);
	assert (rv == CKR_OK);
}

static void
test_destroy_object (void)
{
	CK_FUNCTION_LIST **modules;
	P11KitIter *iter;
	CK_OBJECT_HANDLE object;
	CK_SESSION_HANDLE session;
	CK_FUNCTION_LIST *module;
	CK_ULONG size;
	CK_RV rv;

	modules = initialize_and_get_modules ();

	iter = p11_kit_iter_new (NULL, P11_KIT_ITER_WANT_WRITABLE);

	p11_kit_iter_begin (iter, modules);

	/* Should have matched */
	rv = p11_kit_iter_next (iter);
	assert_num_eq (rv, CKR_OK);

	object = p11_kit_iter_get_object (iter);
	session = p11_kit_iter_get_session (iter);
	module = p11_kit_iter_get_module (iter);

	rv = (module->C_GetObjectSize) (session, object, &size);
	assert_num_eq (rv, CKR_OK);

	rv = p11_kit_iter_destroy_object (iter);
	assert_num_eq (rv, CKR_OK);

	rv = (module->C_GetObjectSize) (session, object, &size);
	assert_num_eq (rv, CKR_OBJECT_HANDLE_INVALID);

	p11_kit_iter_free (iter);

	finalize_and_free_modules (modules);
}

/* Test all combinations of P11_KIT_ITER_WITH_{TOKENS,SLOTS,MODULES}
 * and P11_KIT_ITER_WITHOUT_OBJECTS, against three modules, each
 * with 1 slot, and 3 public objects */
static void
test_exhaustive_match (void)
{
	CK_FUNCTION_LIST_PTR *modules;
	P11KitIter *iter;
	CK_RV rv;
	int counts[] = {
		9, 12, 12, 15, 12, 15, 15, 18, 0, 3, 3, 6, 3, 6, 6, 9
	};
	int count;
	int i;

	for (i = 0; i < ELEMS (counts); i++) {
		modules = initialize_and_get_modules ();

		iter = p11_kit_iter_new (NULL, (P11KitIterBehavior) i << 3);
		p11_kit_iter_begin (iter, modules);

		count = 0;
		while ((rv = p11_kit_iter_next (iter)) == CKR_OK)
			count++;

		assert (rv == CKR_CANCEL);

		assert_num_eq (counts[i], count);

		p11_kit_iter_free (iter);

		finalize_and_free_modules (modules);
	}
}

static void
test_profile (void)
{
	CK_OBJECT_HANDLE objects[128];
	CK_SESSION_HANDLE session;
	CK_FUNCTION_LIST_PTR module;
	CK_SLOT_ID slot;
	P11KitIter *iter;
	CK_RV rv;
	int at;

	mock_module_reset ();
	rv = mock_module_v3.C_Initialize (NULL);
	assert_num_eq (rv, CKR_OK);

	rv = mock_C_OpenSession (MOCK_SLOT_ONE_ID, CKF_SERIAL_SESSION, NULL, NULL, &session);
	assert_num_eq (rv, CKR_OK);

	mock_module_add_profile (MOCK_SLOT_ONE_ID, CKP_PUBLIC_CERTIFICATES_TOKEN);

	iter = p11_kit_iter_new (NULL, 0);
	p11_kit_iter_begin_with (iter, (CK_FUNCTION_LIST *)&mock_module_v3, 0, session);

	at = 0;
	while ((rv = p11_kit_iter_next (iter)) == CKR_OK) {
		assert (at < 128);
		objects[at] = p11_kit_iter_get_object (iter);

		slot = p11_kit_iter_get_slot (iter);
		assert (slot == MOCK_SLOT_ONE_ID);

		module = p11_kit_iter_get_module (iter);
		assert_ptr_eq (module, &mock_module_v3);

		assert (session == p11_kit_iter_get_session (iter));
		at++;
	}

	assert (rv == CKR_CANCEL);

	/* 1 modules, each with 1 slot, and 3 public objects and profile object*/
	assert_num_eq (4, at);

	assert (has_handle (objects, at, MOCK_DATA_OBJECT));
	assert (!has_handle (objects, at, MOCK_PRIVATE_KEY_CAPITALIZE));
	assert (has_handle (objects, at, MOCK_PUBLIC_KEY_CAPITALIZE));
	assert (!has_handle (objects, at, MOCK_PRIVATE_KEY_PREFIX));
	assert (has_handle (objects, at, MOCK_PUBLIC_KEY_PREFIX));
	assert (has_handle (objects, at, MOCK_PROFILE_OBJECT));

	p11_kit_iter_free (iter);

	/* The session is still valid ... */
	rv = mock_module_v3.C_CloseSession (session);
	assert (rv == CKR_OK);

	rv = mock_module_v3.C_Finalize (NULL);
	assert (rv == CKR_OK);
}

int
main (int argc,
      char *argv[])
{
	p11_library_init ();
	mock_module_init ();

	p11_test (test_all, "/iter/test_all");
	p11_test (test_unrecognized, "/iter/test_unrecognized");
	p11_test (test_uri_with_type, "/iter/test_uri_with_type");
	p11_test (test_set_uri, "/iter/set-uri");
	p11_test (test_session_flags, "/iter/test_session_flags");
	p11_test (test_callback, "/iter/test_callback");
	p11_test (test_callback_fails, "/iter/test_callback_fails");
	p11_test (test_callback_destroyer, "/iter/test_callback_destroyer");
	p11_test (test_filter, "/iter/test_filter");
	p11_test (test_with_session, "/iter/test_with_session");
	p11_test (test_with_slot, "/iter/test_with_slot");
	p11_test (test_with_module, "/iter/test_with_module");
	p11_test (test_keep_session, "/iter/test_keep_session");
	p11_test (test_token_match, "/iter/test_token_match");
	p11_test (test_token_mismatch, "/iter/test_token_mismatch");
	p11_test (test_token_info, "/iter/token-info");
	p11_test (test_token_only, "/iter/test_token_only");
	p11_test (test_slot_match, "/iter/test_slot_match");
	p11_test (test_slot_mismatch, "/iter/test_slot_mismatch");
	p11_test (test_slot_match_by_id, "/iter/test_slot_match_by_id");
	p11_test (test_slot_mismatch_by_id, "/iter/test_slot_mismatch_by_id");
	p11_test (test_slot_info, "/iter/slot-info");
	p11_test (test_slot_only, "/iter/test_slot_only");
	p11_test (test_module_match, "/iter/test_module_match");
	p11_test (test_module_mismatch, "/iter/test_module_mismatch");
	p11_test (test_module_only, "/iter/test_module_only");
	p11_test (test_getslotlist_fail_first, "/iter/test_getslotlist_fail_first");
	p11_test (test_getslotlist_fail_late, "/iter/test_getslotlist_fail_late");
	p11_test (test_open_session_fail, "/iter/test_open_session_fail");
	p11_test (test_find_init_fail, "/iter/test_find_init_fail");
	p11_test (test_find_objects_fail, "/iter/test_find_objects_fail");
	p11_test (test_get_attributes, "/iter/get-attributes");
	p11_test (test_load_attributes, "/iter/test_load_attributes");
	p11_test (test_load_attributes_none, "/iter/test_load_attributes_none");
	p11_test (test_load_attributes_fail_first, "/iter/test_load_attributes_fail_first");
	p11_test (test_load_attributes_fail_late, "/iter/test_load_attributes_fail_late");
	p11_testx (test_many, "", "/iter/test-many");
	p11_testx (test_many, "busy-sessions", "/iter/test-many-busy");
	p11_test (test_destroy_object, "/iter/destroy-object");
	p11_test (test_exhaustive_match, "/iter/test_exhaustive_match");
	p11_test (test_profile, "/iter/test_profile");

	return p11_test_run (argc, argv);
}
