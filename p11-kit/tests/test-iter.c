/*
 * Copyright (c) 2013, Red Hat Inc.
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
#include "CuTest.h"

#define P11_KIT_FUTURE_UNSTABLE_API 1

#include "attrs.h"
#include "iter.h"
#include "library.h"
#include "mock.h"

#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

static CK_FUNCTION_LIST_PTR_PTR
initialize_and_get_modules (CuTest *tc)
{
	CK_FUNCTION_LIST_PTR_PTR modules;
	CK_RV rv;

	p11_message_quiet ();

	rv = p11_kit_initialize_registered ();
	CuAssertIntEquals (tc, CKR_OK, rv);
	modules = p11_kit_registered_modules ();
	CuAssertTrue (tc, modules != NULL && modules[0] != NULL);

	p11_message_loud ();

	return modules;
}

static void
finalize_and_free_modules (CuTest *tc,
                           CK_FUNCTION_LIST_PTR_PTR modules)
{
	CK_RV rv;

	free (modules);
	rv = p11_kit_finalize_registered ();
	CuAssertIntEquals (tc, CKR_OK, rv);
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
test_all (CuTest *tc)
{
	CK_OBJECT_HANDLE objects[128];
	CK_FUNCTION_LIST_PTR *modules;
	CK_FUNCTION_LIST_PTR module;
	CK_SESSION_HANDLE session;
	CK_ULONG size;
	P11KitIter *iter;
	CK_RV rv;
	int at;

	modules = initialize_and_get_modules (tc);

	iter = p11_kit_iter_new (NULL);
	p11_kit_iter_begin (iter, modules);

	at = 0;
	while ((rv = p11_kit_iter_next (iter)) == CKR_OK) {
		CuAssertTrue (tc, at < 128);
		objects[at] = p11_kit_iter_get_object (iter);

		module = p11_kit_iter_get_module (iter);
		CuAssertPtrNotNull (tc, module);

		session = p11_kit_iter_get_session (iter);
		CuAssertTrue (tc, session != 0);

		/* Do something with the object */
		size = 0;
		rv = (module->C_GetObjectSize) (session, objects[at], &size);
		CuAssertTrue (tc, rv == CKR_OK);
		CuAssertTrue (tc, size > 0);

		at++;
	}

	CuAssertTrue (tc, rv == CKR_CANCEL);

	/* Three modules, each with 1 slot, and 3 public objects */
	CuAssertIntEquals (tc, 9, at);

	CuAssertTrue (tc, has_handle (objects, at, MOCK_DATA_OBJECT));
	CuAssertTrue (tc, !has_handle (objects, at, MOCK_PRIVATE_KEY_CAPITALIZE));
	CuAssertTrue (tc, has_handle (objects, at, MOCK_PUBLIC_KEY_CAPITALIZE));
	CuAssertTrue (tc, !has_handle (objects, at, MOCK_PRIVATE_KEY_PREFIX));
	CuAssertTrue (tc, has_handle (objects, at, MOCK_PUBLIC_KEY_PREFIX));

	p11_kit_iter_free (iter);

	finalize_and_free_modules (tc, modules);
}

static CK_RV
on_iter_callback (P11KitIter *iter,
                      CK_BBOOL *matches,
                      void *data)
{
	CuTest *tc = data;
	CK_OBJECT_HANDLE object;
	CK_FUNCTION_LIST_PTR module;
	CK_SESSION_HANDLE session;
	CK_ULONG size;
	CK_RV rv;

	object = p11_kit_iter_get_object (iter);
	if (object != MOCK_PUBLIC_KEY_CAPITALIZE && object != MOCK_PUBLIC_KEY_PREFIX) {
		*matches = CK_FALSE;
		return CKR_OK;
	}

	module = p11_kit_iter_get_module (iter);
	CuAssertPtrNotNull (tc, module);

	session = p11_kit_iter_get_session (iter);
	CuAssertTrue (tc, session != 0);

	/* Do something with the object */
	size = 0;
	rv = (module->C_GetObjectSize) (session, object, &size);
	CuAssertTrue (tc, rv == CKR_OK);
	CuAssertTrue (tc, size > 0);

	return CKR_OK;
}

static void
test_callback (CuTest *tc)
{
	CK_OBJECT_HANDLE objects[128];
	CK_FUNCTION_LIST_PTR *modules;
	P11KitIter *iter;
	CK_RV rv;
	int at;

	modules = initialize_and_get_modules (tc);

	iter = p11_kit_iter_new (NULL);
	p11_kit_iter_add_callback (iter, on_iter_callback, tc, NULL);
	p11_kit_iter_begin (iter, modules);

	at= 0;
	while ((rv = p11_kit_iter_next (iter)) == CKR_OK) {
		CuAssertTrue (tc, at < 128);
		objects[at] = p11_kit_iter_get_object (iter);
		at++;
	}

	CuAssertTrue (tc, rv == CKR_CANCEL);

	/* Three modules, each with 1 slot, and 2 public keys */
	CuAssertIntEquals (tc, 6, at);

	CuAssertTrue (tc, !has_handle (objects, at, MOCK_DATA_OBJECT));
	CuAssertTrue (tc, !has_handle (objects, at, MOCK_PRIVATE_KEY_CAPITALIZE));
	CuAssertTrue (tc, has_handle (objects, at, MOCK_PUBLIC_KEY_CAPITALIZE));
	CuAssertTrue (tc, !has_handle (objects, at, MOCK_PRIVATE_KEY_PREFIX));
	CuAssertTrue (tc, has_handle (objects, at, MOCK_PUBLIC_KEY_PREFIX));

	p11_kit_iter_free (iter);

	finalize_and_free_modules (tc, modules);
}

static CK_RV
on_callback_fail (P11KitIter *iter,
                  CK_BBOOL *matches,
                  void *data)
{
	return CKR_DATA_INVALID;
}

static void
test_callback_fails (CuTest *tc)
{
	CK_FUNCTION_LIST_PTR *modules;
	P11KitIter *iter;
	CK_RV rv;
	int at;

	modules = initialize_and_get_modules (tc);

	iter = p11_kit_iter_new (NULL);
	p11_kit_iter_add_callback (iter, on_callback_fail, tc, NULL);
	p11_kit_iter_begin (iter, modules);

	at= 0;
	while ((rv = p11_kit_iter_next (iter)) == CKR_OK)
		at++;

	CuAssertTrue (tc, rv == CKR_DATA_INVALID);

	/* Shouldn't have succeeded at all */
	CuAssertIntEquals (tc, 0, at);

	p11_kit_iter_free (iter);
	finalize_and_free_modules (tc, modules);
}

static void
on_destroy_increment (void *data)
{
	int *value = data;
	(*value)++;
}

static void
test_callback_destroyer (CuTest *tc)
{
	P11KitIter *iter;
	int value = 1;

	iter = p11_kit_iter_new (NULL);
	p11_kit_iter_add_callback (iter, on_callback_fail, &value, on_destroy_increment);
	p11_kit_iter_free (iter);

	CuAssertIntEquals (tc, 2, value);
}

static void
test_with_session (CuTest *tc)
{
	CK_OBJECT_HANDLE objects[128];
	CK_SESSION_HANDLE session;
	CK_FUNCTION_LIST_PTR module;
	CK_SLOT_ID slot;
	P11KitIter *iter;
	CK_RV rv;
	int at;

	rv = p11_kit_initialize_module (&mock_module);
	CuAssertTrue (tc, rv == CKR_OK);

	rv = mock_C_OpenSession (MOCK_SLOT_ONE_ID, CKF_SERIAL_SESSION, NULL, NULL, &session);
	CuAssertTrue (tc, rv == CKR_OK);

	iter = p11_kit_iter_new (NULL);
	p11_kit_iter_begin_with (iter, &mock_module, 0, session);

	at= 0;
	while ((rv = p11_kit_iter_next (iter)) == CKR_OK) {
		CuAssertTrue (tc, at < 128);
		objects[at] = p11_kit_iter_get_object (iter);

		slot = p11_kit_iter_get_slot (iter);
		CuAssertTrue (tc, slot == MOCK_SLOT_ONE_ID);

		module = p11_kit_iter_get_module (iter);
		CuAssertPtrEquals (tc, module, &mock_module);

		CuAssertTrue (tc, session == p11_kit_iter_get_session (iter));
		at++;
	}

	CuAssertTrue (tc, rv == CKR_CANCEL);

	/* 1 modules, each with 1 slot, and 3 public objects */
	CuAssertIntEquals (tc, 3, at);

	CuAssertTrue (tc, has_handle (objects, at, MOCK_DATA_OBJECT));
	CuAssertTrue (tc, !has_handle (objects, at, MOCK_PRIVATE_KEY_CAPITALIZE));
	CuAssertTrue (tc, has_handle (objects, at, MOCK_PUBLIC_KEY_CAPITALIZE));
	CuAssertTrue (tc, !has_handle (objects, at, MOCK_PRIVATE_KEY_PREFIX));
	CuAssertTrue (tc, has_handle (objects, at, MOCK_PUBLIC_KEY_PREFIX));

	p11_kit_iter_free (iter);

	/* The session is still valid ... */
	rv = mock_module.C_CloseSession (session);
	CuAssertTrue (tc, rv == CKR_OK);

	rv = p11_kit_finalize_module (&mock_module);
	CuAssertTrue (tc, rv == CKR_OK);
}

static void
test_with_slot (CuTest *tc)
{
	CK_OBJECT_HANDLE objects[128];
	CK_FUNCTION_LIST_PTR module;
	CK_SLOT_ID slot;
	P11KitIter *iter;
	CK_RV rv;
	int at;

	rv = p11_kit_initialize_module (&mock_module);
	CuAssertTrue (tc, rv == CKR_OK);

	iter = p11_kit_iter_new (NULL);
	p11_kit_iter_begin_with (iter, &mock_module, MOCK_SLOT_ONE_ID, 0);

	at= 0;
	while ((rv = p11_kit_iter_next (iter)) == CKR_OK) {
		CuAssertTrue (tc, at < 128);
		objects[at] = p11_kit_iter_get_object (iter);

		slot = p11_kit_iter_get_slot (iter);
		CuAssertTrue (tc, slot == MOCK_SLOT_ONE_ID);

		module = p11_kit_iter_get_module (iter);
		CuAssertPtrEquals (tc, module, &mock_module);
		at++;
	}

	CuAssertTrue (tc, rv == CKR_CANCEL);

	/* 1 modules, each with 1 slot, and 3 public objects */
	CuAssertIntEquals (tc, 3, at);

	CuAssertTrue (tc, has_handle (objects, at, MOCK_DATA_OBJECT));
	CuAssertTrue (tc, !has_handle (objects, at, MOCK_PRIVATE_KEY_CAPITALIZE));
	CuAssertTrue (tc, has_handle (objects, at, MOCK_PUBLIC_KEY_CAPITALIZE));
	CuAssertTrue (tc, !has_handle (objects, at, MOCK_PRIVATE_KEY_PREFIX));
	CuAssertTrue (tc, has_handle (objects, at, MOCK_PUBLIC_KEY_PREFIX));

	p11_kit_iter_free (iter);

	rv = p11_kit_finalize_module (&mock_module);
	CuAssertTrue (tc, rv == CKR_OK);
}

static void
test_with_module (CuTest *tc)
{
	CK_OBJECT_HANDLE objects[128];
	CK_FUNCTION_LIST_PTR module;
	P11KitIter *iter;
	CK_RV rv;
	int at;

	rv = p11_kit_initialize_module (&mock_module);
	CuAssertTrue (tc, rv == CKR_OK);

	iter = p11_kit_iter_new (NULL);
	p11_kit_iter_begin_with (iter, &mock_module, 0, 0);

	at= 0;
	while ((rv = p11_kit_iter_next (iter)) == CKR_OK) {
		CuAssertTrue (tc, at < 128);
		objects[at] = p11_kit_iter_get_object (iter);

		module = p11_kit_iter_get_module (iter);
		CuAssertPtrEquals (tc, module, &mock_module);
		at++;
	}

	CuAssertTrue (tc, rv == CKR_CANCEL);

	/* 1 modules, each with 1 slot, and 3 public objects */
	CuAssertIntEquals (tc, 3, at);

	CuAssertTrue (tc, has_handle (objects, at, MOCK_DATA_OBJECT));
	CuAssertTrue (tc, !has_handle (objects, at, MOCK_PRIVATE_KEY_CAPITALIZE));
	CuAssertTrue (tc, has_handle (objects, at, MOCK_PUBLIC_KEY_CAPITALIZE));
	CuAssertTrue (tc, !has_handle (objects, at, MOCK_PRIVATE_KEY_PREFIX));
	CuAssertTrue (tc, has_handle (objects, at, MOCK_PUBLIC_KEY_PREFIX));

	p11_kit_iter_free (iter);

	rv = p11_kit_finalize_module (&mock_module);
	CuAssertTrue (tc, rv == CKR_OK);
}

static void
test_keep_session (CuTest *tc)
{
	CK_SESSION_HANDLE session;
	P11KitIter *iter;
	CK_RV rv;

	rv = p11_kit_initialize_module (&mock_module);
	CuAssertTrue (tc, rv == CKR_OK);

	iter = p11_kit_iter_new (NULL);
	p11_kit_iter_begin_with (iter, &mock_module, 0, 0);

	rv = p11_kit_iter_next (iter);
	CuAssertTrue (tc, rv == CKR_OK);

	session = p11_kit_iter_keep_session (iter);
	p11_kit_iter_free (iter);

	/* The session is still valid ... */
	rv = mock_module.C_CloseSession (session);
	CuAssertTrue (tc, rv == CKR_OK);

	rv = p11_kit_finalize_module (&mock_module);
	CuAssertTrue (tc, rv == CKR_OK);
}

static void
test_unrecognized (CuTest *tc)
{
	CK_FUNCTION_LIST_PTR *modules;
	P11KitIter *iter;
	P11KitUri *uri;
	CK_RV rv;
	int count;

	modules = initialize_and_get_modules (tc);

	uri = p11_kit_uri_new ();
	p11_kit_uri_set_unrecognized (uri, 1);
	iter = p11_kit_iter_new (uri);
	p11_kit_uri_free (uri);

	p11_kit_iter_begin (iter, modules);

	count = 0;
	while ((rv = p11_kit_iter_next (iter)) == CKR_OK)
		count++;

	CuAssertTrue (tc, rv == CKR_CANCEL);

	/* Nothing should have matched */
	CuAssertIntEquals (tc, 0, count);

	p11_kit_iter_free (iter);

	finalize_and_free_modules (tc, modules);
}

static void
test_uri_with_type (CuTest *tc)
{
	CK_OBJECT_HANDLE objects[128];
	CK_FUNCTION_LIST_PTR *modules;
	P11KitIter *iter;
	P11KitUri *uri;
	CK_RV rv;
	int at;
	int ret;

	modules = initialize_and_get_modules (tc);

	uri = p11_kit_uri_new ();
	ret = p11_kit_uri_parse ("pkcs11:object-type=public", P11_KIT_URI_FOR_OBJECT, uri);
	CuAssertIntEquals (tc, ret, P11_KIT_URI_OK);

	iter = p11_kit_iter_new (uri);
	p11_kit_uri_free (uri);

	p11_kit_iter_begin (iter, modules);

	at = 0;
	while ((rv = p11_kit_iter_next (iter)) == CKR_OK) {
		CuAssertTrue (tc, at < 128);
		objects[at] = p11_kit_iter_get_object (iter);
		at++;
	}

	CuAssertTrue (tc, rv == CKR_CANCEL);

	/* Three modules, each with 1 slot, and 2 public keys */
	CuAssertIntEquals (tc, 6, at);

	CuAssertTrue (tc, !has_handle (objects, at, MOCK_DATA_OBJECT));
	CuAssertTrue (tc, !has_handle (objects, at, MOCK_PRIVATE_KEY_CAPITALIZE));
	CuAssertTrue (tc, has_handle (objects, at, MOCK_PUBLIC_KEY_CAPITALIZE));
	CuAssertTrue (tc, !has_handle (objects, at, MOCK_PRIVATE_KEY_PREFIX));
	CuAssertTrue (tc, has_handle (objects, at, MOCK_PUBLIC_KEY_PREFIX));

	p11_kit_iter_free (iter);

	finalize_and_free_modules (tc, modules);
}

static void
test_filter (CuTest *tc)
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

	modules = initialize_and_get_modules (tc);

	iter = p11_kit_iter_new (NULL);
	p11_kit_iter_add_filter (iter, attrs, 2);

	p11_kit_iter_begin (iter, modules);

	at = 0;
	while ((rv = p11_kit_iter_next (iter)) == CKR_OK) {
		CuAssertTrue (tc, at < 128);
		objects[at] = p11_kit_iter_get_object (iter);
		at++;
	}

	CuAssertTrue (tc, rv == CKR_CANCEL);

	/* Three modules, each with 1 slot, and 2 public keys */
	CuAssertIntEquals (tc, 6, at);

	CuAssertTrue (tc, !has_handle (objects, at, MOCK_DATA_OBJECT));
	CuAssertTrue (tc, !has_handle (objects, at, MOCK_PRIVATE_KEY_CAPITALIZE));
	CuAssertTrue (tc, has_handle (objects, at, MOCK_PUBLIC_KEY_CAPITALIZE));
	CuAssertTrue (tc, !has_handle (objects, at, MOCK_PRIVATE_KEY_PREFIX));
	CuAssertTrue (tc, has_handle (objects, at, MOCK_PUBLIC_KEY_PREFIX));

	p11_kit_iter_free (iter);

	finalize_and_free_modules (tc, modules);
}

static void
test_session_flags (CuTest *tc)
{
	CK_FUNCTION_LIST_PTR *modules;
	CK_FUNCTION_LIST_PTR module;
	CK_SESSION_HANDLE session;
	CK_SESSION_INFO info;
	P11KitIter *iter;
	CK_RV rv;

	modules = initialize_and_get_modules (tc);

	iter = p11_kit_iter_new (NULL);
	p11_kit_iter_set_session_flags (iter, CKF_RW_SESSION);

	p11_kit_iter_begin (iter, modules);

	while ((rv = p11_kit_iter_next (iter)) == CKR_OK) {
		module = p11_kit_iter_get_module (iter);
		CuAssertPtrNotNull (tc, module);

		session = p11_kit_iter_get_session (iter);
		CuAssertTrue (tc, session != 0);

		rv = (module->C_GetSessionInfo) (session, &info);
		CuAssertTrue (tc, rv == CKR_OK);

		CuAssertIntEquals (tc, CKS_RW_PUBLIC_SESSION, info.state);
	}

	CuAssertTrue (tc, rv == CKR_CANCEL);

	p11_kit_iter_free (iter);

	finalize_and_free_modules (tc, modules);
}

static void
test_module_match (CuTest *tc)
{
	CK_FUNCTION_LIST_PTR *modules;
	P11KitIter *iter;
	P11KitUri *uri;
	CK_RV rv;
	int count;
	int ret;

	modules = initialize_and_get_modules (tc);

	uri = p11_kit_uri_new ();
	ret = p11_kit_uri_parse ("pkcs11:library-description=MOCK%20LIBRARY", P11_KIT_URI_FOR_MODULE, uri);
	CuAssertIntEquals (tc, P11_KIT_URI_OK, ret);

	iter = p11_kit_iter_new (uri);
	p11_kit_uri_free (uri);

	p11_kit_iter_begin (iter, modules);

	count = 0;
	while ((rv = p11_kit_iter_next (iter)) == CKR_OK)
		count++;

	CuAssertTrue (tc, rv == CKR_CANCEL);

	/* Three modules, each with 1 slot, and 3 public objects */
	CuAssertIntEquals (tc, 9, count);

	p11_kit_iter_free (iter);

	finalize_and_free_modules (tc, modules);
}

static void
test_module_mismatch (CuTest *tc)
{
	CK_FUNCTION_LIST_PTR *modules;
	P11KitIter *iter;
	P11KitUri *uri;
	CK_RV rv;
	int count;
	int ret;

	modules = initialize_and_get_modules (tc);

	uri = p11_kit_uri_new ();
	ret = p11_kit_uri_parse ("pkcs11:library-description=blah", P11_KIT_URI_FOR_MODULE, uri);
	CuAssertIntEquals (tc, P11_KIT_URI_OK, ret);

	iter = p11_kit_iter_new (uri);
	p11_kit_uri_free (uri);

	p11_kit_iter_begin (iter, modules);

	count = 0;
	while ((rv = p11_kit_iter_next (iter)) == CKR_OK)
		count++;

	CuAssertTrue (tc, rv == CKR_CANCEL);

	/* Nothing should have matched */
	CuAssertIntEquals (tc, 0, count);

	p11_kit_iter_free (iter);

	finalize_and_free_modules (tc, modules);
}

static void
test_token_match (CuTest *tc)
{
	CK_FUNCTION_LIST_PTR *modules;
	P11KitIter *iter;
	P11KitUri *uri;
	CK_RV rv;
	int count;
	int ret;

	modules = initialize_and_get_modules (tc);

	uri = p11_kit_uri_new ();
	ret = p11_kit_uri_parse ("pkcs11:manufacturer=TEST%20MANUFACTURER", P11_KIT_URI_FOR_TOKEN, uri);
	CuAssertIntEquals (tc, P11_KIT_URI_OK, ret);

	iter = p11_kit_iter_new (uri);
	p11_kit_uri_free (uri);

	p11_kit_iter_begin (iter, modules);

	count = 0;
	while ((rv = p11_kit_iter_next (iter)) == CKR_OK)
		count++;

	CuAssertTrue (tc, rv == CKR_CANCEL);

	/* Three modules, each with 1 slot, and 3 public objects */
	CuAssertIntEquals (tc, 9, count);

	p11_kit_iter_free (iter);

	finalize_and_free_modules (tc, modules);
}

static void
test_token_mismatch (CuTest *tc)
{
	CK_FUNCTION_LIST_PTR *modules;
	P11KitIter *iter;
	P11KitUri *uri;
	CK_RV rv;
	int count;
	int ret;

	modules = initialize_and_get_modules (tc);

	uri = p11_kit_uri_new ();
	ret = p11_kit_uri_parse ("pkcs11:manufacturer=blah", P11_KIT_URI_FOR_TOKEN, uri);
	CuAssertIntEquals (tc, P11_KIT_URI_OK, ret);

	iter = p11_kit_iter_new (uri);
	p11_kit_uri_free (uri);

	p11_kit_iter_begin (iter, modules);

	count = 0;
	while ((rv = p11_kit_iter_next (iter)) == CKR_OK)
		count++;

	CuAssertTrue (tc, rv == CKR_CANCEL);

	/* Nothing should have matched */
	CuAssertIntEquals (tc, 0, count);

	p11_kit_iter_free (iter);

	finalize_and_free_modules (tc, modules);
}

static void
test_getslotlist_fail_first (CuTest *tc)
{
	CK_FUNCTION_LIST module;
	P11KitIter *iter;
	CK_RV rv;
	int at;

	rv = p11_kit_initialize_module (&mock_module);
	CuAssertTrue (tc, rv == CKR_OK);

	memcpy (&module, &mock_module, sizeof (CK_FUNCTION_LIST));
	module.C_GetSlotList = mock_C_GetSlotList__fail_first;

	iter = p11_kit_iter_new (NULL);
	p11_kit_iter_begin_with (iter, &module, 0, 0);

	at= 0;
	while ((rv = p11_kit_iter_next (iter)) == CKR_OK)
		at++;

	CuAssertTrue (tc, rv == CKR_VENDOR_DEFINED);

	/* Should fail on the first iteration */
	CuAssertIntEquals (tc, 0, at);

	p11_kit_iter_free (iter);

	rv = p11_kit_finalize_module (&mock_module);
	CuAssertTrue (tc, rv == CKR_OK);
}

static void
test_getslotlist_fail_late (CuTest *tc)
{
	CK_FUNCTION_LIST module;
	P11KitIter *iter;
	CK_RV rv;
	int at;

	rv = p11_kit_initialize_module (&mock_module);
	CuAssertTrue (tc, rv == CKR_OK);

	memcpy (&module, &mock_module, sizeof (CK_FUNCTION_LIST));
	module.C_GetSlotList = mock_C_GetSlotList__fail_late;

	iter = p11_kit_iter_new (NULL);
	p11_kit_iter_begin_with (iter, &module, 0, 0);

	at= 0;
	while ((rv = p11_kit_iter_next (iter)) == CKR_OK)
		at++;

	CuAssertTrue (tc, rv == CKR_VENDOR_DEFINED);

	/* Should fail on the first iteration */
	CuAssertIntEquals (tc, 0, at);

	p11_kit_iter_free (iter);

	rv = p11_kit_finalize_module (&mock_module);
	CuAssertTrue (tc, rv == CKR_OK);
}

static void
test_token_not_initialized (CuTest *tc)
{
	CK_FUNCTION_LIST module;
	P11KitIter *iter;
	CK_RV rv;
	int at;

	rv = p11_kit_initialize_module (&mock_module);
	CuAssertTrue (tc, rv == CKR_OK);

	memcpy (&module, &mock_module, sizeof (CK_FUNCTION_LIST));
	module.C_GetTokenInfo = mock_C_GetTokenInfo_not_initialized;

	iter = p11_kit_iter_new (NULL);
	p11_kit_iter_begin_with (iter, &module, 0, 0);

	at= 0;
	while ((rv = p11_kit_iter_next (iter)) == CKR_OK)
		at++;

	CuAssertTrue (tc, rv == CKR_CANCEL);

	/* Should fail on the first iteration */
	CuAssertIntEquals (tc, 0, at);

	p11_kit_iter_free (iter);

	rv = p11_kit_finalize_module (&mock_module);
	CuAssertTrue (tc, rv == CKR_OK);
}

static void
test_open_session_fail (CuTest *tc)
{
	CK_FUNCTION_LIST module;
	P11KitIter *iter;
	CK_RV rv;
	int at;

	rv = p11_kit_initialize_module (&mock_module);
	CuAssertTrue (tc, rv == CKR_OK);

	memcpy (&module, &mock_module, sizeof (CK_FUNCTION_LIST));
	module.C_OpenSession = mock_C_OpenSession__fails;

	iter = p11_kit_iter_new (NULL);
	p11_kit_iter_begin_with (iter, &module, 0, 0);

	at= 0;
	while ((rv = p11_kit_iter_next (iter)) == CKR_OK)
		at++;

	CuAssertTrue (tc, rv == CKR_DEVICE_ERROR);

	/* Should fail on the first iteration */
	CuAssertIntEquals (tc, 0, at);

	p11_kit_iter_free (iter);

	rv = p11_kit_finalize_module (&mock_module);
	CuAssertTrue (tc, rv == CKR_OK);
}

static void
test_find_init_fail (CuTest *tc)
{
	CK_FUNCTION_LIST module;
	P11KitIter *iter;
	CK_RV rv;
	int at;

	rv = p11_kit_initialize_module (&mock_module);
	CuAssertTrue (tc, rv == CKR_OK);

	memcpy (&module, &mock_module, sizeof (CK_FUNCTION_LIST));
	module.C_FindObjectsInit = mock_C_FindObjectsInit__fails;

	iter = p11_kit_iter_new (NULL);
	p11_kit_iter_begin_with (iter, &module, 0, 0);

	at= 0;
	while ((rv = p11_kit_iter_next (iter)) == CKR_OK)
		at++;

	CuAssertTrue (tc, rv == CKR_DEVICE_MEMORY);

	/* Should fail on the first iteration */
	CuAssertIntEquals (tc, 0, at);

	p11_kit_iter_free (iter);

	rv = p11_kit_finalize_module (&mock_module);
	CuAssertTrue (tc, rv == CKR_OK);
}

static void
test_find_objects_fail (CuTest *tc)
{
	CK_FUNCTION_LIST module;
	P11KitIter *iter;
	CK_RV rv;
	int at;

	rv = p11_kit_initialize_module (&mock_module);
	CuAssertTrue (tc, rv == CKR_OK);

	memcpy (&module, &mock_module, sizeof (CK_FUNCTION_LIST));
	module.C_FindObjects = mock_C_FindObjects__fails;

	iter = p11_kit_iter_new (NULL);
	p11_kit_iter_begin_with (iter, &module, 0, 0);

	at= 0;
	while ((rv = p11_kit_iter_next (iter)) == CKR_OK)
		at++;

	CuAssertTrue (tc, rv == CKR_DEVICE_REMOVED);

	/* Should fail on the first iteration */
	CuAssertIntEquals (tc, 0, at);

	p11_kit_iter_free (iter);

	rv = p11_kit_finalize_module (&mock_module);
	CuAssertTrue (tc, rv == CKR_OK);
}

static void
test_load_attributes (CuTest *tc)
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

	modules = initialize_and_get_modules (tc);

	iter = p11_kit_iter_new (NULL);
	p11_kit_iter_begin (iter, modules);

	attrs = p11_attrs_buildn (NULL, types, 2);

	at = 0;
	while ((rv = p11_kit_iter_next (iter)) == CKR_OK) {
		rv = p11_kit_iter_load_attributes (iter, attrs, 2);
		CuAssertTrue (tc, rv == CKR_OK);

		object = p11_kit_iter_get_object (iter);
		switch (object) {
		case MOCK_DATA_OBJECT:
			CuAssertTrue (tc, p11_attrs_find_ulong (attrs, CKA_CLASS, &ulong) && ulong == CKO_DATA);
			CuAssertTrue (tc, p11_attr_match_value (p11_attrs_find (attrs, CKA_LABEL), "TEST LABEL", -1));
			break;
		case MOCK_PUBLIC_KEY_CAPITALIZE:
			CuAssertTrue (tc, p11_attrs_find_ulong (attrs, CKA_CLASS, &ulong) && ulong == CKO_PUBLIC_KEY);
			CuAssertTrue (tc, p11_attr_match_value (p11_attrs_find (attrs, CKA_LABEL), "Public Capitalize Key", -1));
			break;
		case MOCK_PUBLIC_KEY_PREFIX:
			CuAssertTrue (tc, p11_attrs_find_ulong (attrs, CKA_CLASS, &ulong) && ulong == CKO_PUBLIC_KEY);
			CuAssertTrue (tc, p11_attr_match_value (p11_attrs_find (attrs, CKA_LABEL), "Public prefix key", -1));
			break;
		default:
			CuFail (tc, "Unknown object matched");
			break;
		}

		at++;
	}

	p11_attrs_free (attrs);

	CuAssertTrue (tc, rv == CKR_CANCEL);

	/* Three modules, each with 1 slot, and 3 public objects */
	CuAssertIntEquals (tc, 9, at);

	p11_kit_iter_free (iter);

	finalize_and_free_modules (tc, modules);
}

static void
test_load_attributes_none (CuTest *tc)
{
	CK_FUNCTION_LIST module;
	P11KitIter *iter;
	CK_ATTRIBUTE *attrs;
	CK_RV rv;

	rv = p11_kit_initialize_module (&mock_module);
	CuAssertTrue (tc, rv == CKR_OK);

	memcpy (&module, &mock_module, sizeof (CK_FUNCTION_LIST));

	iter = p11_kit_iter_new (NULL);
	p11_kit_iter_begin_with (iter, &module, 0, 0);

	while ((rv = p11_kit_iter_next (iter)) == CKR_OK) {
		attrs = p11_attrs_buildn (NULL, NULL, 0);
		rv = p11_kit_iter_load_attributes (iter, attrs, 0);
		CuAssertTrue (tc, rv == CKR_OK);
	}

	CuAssertTrue (tc, rv == CKR_CANCEL);

	p11_kit_iter_free (iter);

	rv = p11_kit_finalize_module (&mock_module);
	CuAssertTrue (tc, rv == CKR_OK);
}

static void
test_load_attributes_fail_first (CuTest *tc)
{
	CK_ATTRIBUTE label = { CKA_LABEL, };
	CK_FUNCTION_LIST module;
	P11KitIter *iter;
	CK_ATTRIBUTE *attrs;
	CK_RV rv;

	rv = p11_kit_initialize_module (&mock_module);
	CuAssertTrue (tc, rv == CKR_OK);

	memcpy (&module, &mock_module, sizeof (CK_FUNCTION_LIST));
	module.C_GetAttributeValue = mock_C_GetAttributeValue__fail_first;

	iter = p11_kit_iter_new (NULL);
	p11_kit_iter_begin_with (iter, &module, 0, 0);

	while ((rv = p11_kit_iter_next (iter)) == CKR_OK) {
		attrs = p11_attrs_build (NULL, &label, NULL);
		rv = p11_kit_iter_load_attributes (iter, attrs, 1);
		CuAssertTrue (tc, rv == CKR_FUNCTION_REJECTED);
		p11_attrs_free (attrs);
	}

	CuAssertTrue (tc, rv == CKR_CANCEL);

	p11_kit_iter_free (iter);

	rv = p11_kit_finalize_module (&mock_module);
	CuAssertTrue (tc, rv == CKR_OK);
}

static void
test_load_attributes_fail_late (CuTest *tc)
{
	CK_ATTRIBUTE label = { CKA_LABEL, };
	CK_FUNCTION_LIST module;
	P11KitIter *iter;
	CK_ATTRIBUTE *attrs;
	CK_RV rv;

	rv = p11_kit_initialize_module (&mock_module);
	CuAssertTrue (tc, rv == CKR_OK);

	memcpy (&module, &mock_module, sizeof (CK_FUNCTION_LIST));
	module.C_GetAttributeValue = mock_C_GetAttributeValue__fail_late;

	iter = p11_kit_iter_new (NULL);
	p11_kit_iter_begin_with (iter, &module, 0, 0);

	while ((rv = p11_kit_iter_next (iter)) == CKR_OK) {
		attrs = p11_attrs_build (NULL, &label, NULL);
		rv = p11_kit_iter_load_attributes (iter, attrs, 1);
		CuAssertTrue (tc, rv == CKR_FUNCTION_FAILED);
		p11_attrs_free (attrs);
	}

	CuAssertTrue (tc, rv == CKR_CANCEL);

	p11_kit_iter_free (iter);

	rv = p11_kit_finalize_module (&mock_module);
	CuAssertTrue (tc, rv == CKR_OK);
}

int
main (void)
{
	CuString *output = CuStringNew ();
	CuSuite* suite = CuSuiteNew ();
	int ret;

	putenv ("P11_KIT_STRICT=1");
	p11_library_init ();
	mock_module_init ();

	SUITE_ADD_TEST (suite, test_all);
	SUITE_ADD_TEST (suite, test_unrecognized);
	SUITE_ADD_TEST (suite, test_uri_with_type);
	SUITE_ADD_TEST (suite, test_session_flags);
	SUITE_ADD_TEST (suite, test_callback);
	SUITE_ADD_TEST (suite, test_callback_fails);
	SUITE_ADD_TEST (suite, test_callback_destroyer);
	SUITE_ADD_TEST (suite, test_filter);
	SUITE_ADD_TEST (suite, test_with_session);
	SUITE_ADD_TEST (suite, test_with_slot);
	SUITE_ADD_TEST (suite, test_with_module);
	SUITE_ADD_TEST (suite, test_keep_session);
	SUITE_ADD_TEST (suite, test_token_match);
	SUITE_ADD_TEST (suite, test_token_mismatch);
	SUITE_ADD_TEST (suite, test_module_match);
	SUITE_ADD_TEST (suite, test_module_mismatch);
	SUITE_ADD_TEST (suite, test_getslotlist_fail_first);
	SUITE_ADD_TEST (suite, test_getslotlist_fail_late);
	SUITE_ADD_TEST (suite, test_token_not_initialized);
	SUITE_ADD_TEST (suite, test_open_session_fail);
	SUITE_ADD_TEST (suite, test_find_init_fail);
	SUITE_ADD_TEST (suite, test_find_objects_fail);
	SUITE_ADD_TEST (suite, test_load_attributes);
	SUITE_ADD_TEST (suite, test_load_attributes_none);
	SUITE_ADD_TEST (suite, test_load_attributes_fail_first);
	SUITE_ADD_TEST (suite, test_load_attributes_fail_late);

	CuSuiteRun (suite);
	CuSuiteSummary (suite, output);
	CuSuiteDetails (suite, output);
	printf ("%s\n", output->buffer);
	ret = suite->failCount;
	CuSuiteDelete (suite);
	CuStringDelete (output);
	return ret;
}
