/*
 * Copyright (c) 2012 Red Hat Inc.
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
 * Author: Stef Walter <stefw@gnome.org>
 */

#define CRYPTOKI_EXPORTS

#include "config.h"
#include "test.h"
#include "test-trust.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "attrs.h"
#include "hash.h"
#include "library.h"
#include "path.h"
#include "pkcs11x.h"
#include "token.h"

#include <assert.h>

/*
 * This is the number of input paths. Should match the
 * paths below near :
 *
 * paths='%s'
 */
#define NUM_SLOTS 3

static CK_OBJECT_CLASS data = CKO_DATA;

struct {
	CK_FUNCTION_LIST *module;
	CK_SLOT_ID slots[NUM_SLOTS];
} test;

static void
setup (void *unused)
{
	CK_C_INITIALIZE_ARGS args;
	const char *paths;
	char *arguments;
	CK_ULONG count;
	CK_RV rv;

	memset (&test, 0, sizeof (test));

	/* This is the entry point of the trust module, linked to this test */
	rv = C_GetFunctionList (&test.module);
	assert (rv == CKR_OK);

	memset (&args, 0, sizeof (args));
	paths = SRCDIR "/input" P11_PATH_SEP \
		SRCDIR "/files/self-signed-with-ku.der" P11_PATH_SEP \
		SRCDIR "/files/thawte.pem";
	if (asprintf (&arguments, "paths='%s'", paths) < 0)
		assert (false && "not reached");
	args.pReserved = arguments;
	args.flags = CKF_OS_LOCKING_OK;

	rv = test.module->C_Initialize (&args);
	assert (rv == CKR_OK);

	free (arguments);

	count = NUM_SLOTS;
	rv = test.module->C_GetSlotList (CK_TRUE, test.slots, &count);
	assert (rv == CKR_OK);
	assert (count == NUM_SLOTS);
}

static void
teardown (void *unused)
{
	CK_RV rv;

	rv = test.module->C_Finalize (NULL);
	assert (rv == CKR_OK);

	memset (&test, 0, sizeof (test));
}

static void
test_get_slot_list (void)
{
	CK_SLOT_ID slots[NUM_SLOTS];
	CK_ULONG count;
	CK_RV rv;
	int i;

	rv = test.module->C_GetSlotList (TRUE, NULL, &count);
	assert_num_eq (CKR_OK, rv);
	assert_num_eq (NUM_SLOTS, count);

	count = 1;
	rv = test.module->C_GetSlotList (TRUE, slots, &count);
	assert_num_eq (CKR_BUFFER_TOO_SMALL, rv);
	assert_num_eq (NUM_SLOTS, count);

	count = NUM_SLOTS;
	memset (slots, 0, sizeof (slots));
	rv = test.module->C_GetSlotList (TRUE, slots, &count);
	assert_num_eq (CKR_OK, rv);
	assert_num_eq (NUM_SLOTS, count);

	for (i = 0; i < NUM_SLOTS; i++)
		assert (slots[i] != 0);
}

static void
test_get_slot_info (void)
{
	CK_SLOT_ID slots[NUM_SLOTS];
	CK_SLOT_INFO info;
	char description[64];
	CK_ULONG count;
	size_t length;
	CK_RV rv;
	int i;

	/* These are the paths passed in in setup() */
	const char *paths[] = {
		SRCDIR "/input",
		SRCDIR "/files/self-signed-with-ku.der",
		SRCDIR "/files/thawte.pem"
	};

	count = NUM_SLOTS;
	rv = test.module->C_GetSlotList (TRUE, slots, &count);
	assert_num_eq (CKR_OK, rv);
	assert_num_eq (NUM_SLOTS, count);

	for (i = 0; i < NUM_SLOTS; i++) {
		rv = test.module->C_GetSlotInfo (slots[i], &info);
		assert_num_eq (CKR_OK, rv);

		memset (description, ' ', sizeof (description));
		length = strlen(paths[i]);
		if (length > sizeof (description))
			length = sizeof (description);
		memcpy (description, paths[i], length);
		assert (memcmp (info.slotDescription, description, sizeof (description)) == 0);
	}
}

static void
test_get_token_info (void)
{
	CK_C_INITIALIZE_ARGS args;
	CK_FUNCTION_LIST *module;
	CK_SLOT_ID slots[NUM_SLOTS];
	CK_TOKEN_INFO info;
	char label[32];
	CK_ULONG count;
	CK_RV rv;
	int i;

	/* These are the paths passed in in setup() */
	const char *labels[] = {
		"System Trust",
		"Default Trust",
		"the-basename",
	};

	/* This is the entry point of the trust module, linked to this test */
	rv = C_GetFunctionList (&module);
	assert (rv == CKR_OK);

	memset (&args, 0, sizeof (args));
	args.pReserved = "paths='" \
		SYSCONFDIR "/input" P11_PATH_SEP \
		DATADIR "/files/blah" P11_PATH_SEP \
		"/some/other/path/the-basename'";
	args.flags = CKF_OS_LOCKING_OK;

	rv = module->C_Initialize (&args);
	assert (rv == CKR_OK);

	count = NUM_SLOTS;
	rv = module->C_GetSlotList (CK_TRUE, slots, &count);
	assert (rv == CKR_OK);
	assert (count == NUM_SLOTS);

	for (i = 0; i < NUM_SLOTS; i++) {
		rv = module->C_GetTokenInfo (slots[i], &info);
		assert_num_eq (CKR_OK, rv);

		memset (label, ' ', sizeof (label));
		memcpy (label, labels[i], strlen (labels[i]));
		assert (memcmp (info.label, label, sizeof (label)) == 0);
	}

	rv = module->C_Finalize (NULL);
	assert_num_eq (CKR_OK, rv);
}

static void
test_get_session_info (void)
{
	CK_SLOT_ID slots[NUM_SLOTS];
	CK_SESSION_HANDLE sessions[NUM_SLOTS];
	CK_SESSION_INFO info;
	CK_ULONG count;
	CK_RV rv;
	int i;

	count = NUM_SLOTS;
	rv = test.module->C_GetSlotList (TRUE, slots, &count);
	assert_num_eq (CKR_OK, rv);
	assert_num_eq (NUM_SLOTS, count);

	/* Open two sessions with each token */
	for (i = 0; i < NUM_SLOTS; i++) {
		rv = test.module->C_OpenSession (slots[i], CKF_SERIAL_SESSION, NULL, NULL, &sessions[i]);
		assert_num_eq (CKR_OK, rv);

		rv = test.module->C_GetSessionInfo (sessions[i], &info);
		assert_num_eq (CKR_OK, rv);

		assert_num_eq (slots[i], info.slotID);
		assert_num_eq (CKF_SERIAL_SESSION, info.flags);
	}
}

static void
test_close_all_sessions (void)
{
	CK_SLOT_ID slots[NUM_SLOTS];
	CK_SESSION_HANDLE sessions[NUM_SLOTS][2];
	CK_SESSION_INFO info;
	CK_ULONG count;
	CK_RV rv;
	int i;

	count = NUM_SLOTS;
	rv = test.module->C_GetSlotList (TRUE, slots, &count);
	assert_num_eq (CKR_OK, rv);
	assert_num_eq (NUM_SLOTS, count);

	/* Open two sessions with each token */
	for (i = 0; i < NUM_SLOTS; i++) {
		rv = test.module->C_OpenSession (slots[i], CKF_SERIAL_SESSION, NULL, NULL, &sessions[i][0]);
		assert_num_eq (CKR_OK, rv);

		rv = test.module->C_GetSessionInfo (sessions[i][0], &info);
		assert_num_eq (CKR_OK, rv);

		rv = test.module->C_OpenSession (slots[i], CKF_SERIAL_SESSION, NULL, NULL, &sessions[i][1]);
		assert_num_eq (CKR_OK, rv);

		rv = test.module->C_GetSessionInfo (sessions[i][0], &info);
		assert_num_eq (CKR_OK, rv);
	}

	/* Close all the sessions on the first token */
	rv = test.module->C_CloseAllSessions (slots[0]);
	assert_num_eq (CKR_OK, rv);

	/* Those sessions should be closed */
	rv = test.module->C_GetSessionInfo (sessions[0][0], &info);
	assert_num_eq (CKR_SESSION_HANDLE_INVALID, rv);
	rv = test.module->C_GetSessionInfo (sessions[0][1], &info);
	assert_num_eq (CKR_SESSION_HANDLE_INVALID, rv);

	/* Other sessions should still be open */
	for (i = 1; i < NUM_SLOTS; i++) {
		rv = test.module->C_GetSessionInfo (sessions[i][0], &info);
		assert_num_eq (CKR_OK, rv);
		rv = test.module->C_GetSessionInfo (sessions[i][0], &info);
		assert_num_eq (CKR_OK, rv);
	}
}

static CK_ULONG
find_objects (CK_ATTRIBUTE *match,
              CK_OBJECT_HANDLE *sessions,
              CK_OBJECT_HANDLE *objects,
              CK_ULONG max_objects)
{
	CK_SESSION_HANDLE session;
	CK_RV rv;
	CK_ULONG found;
	CK_ULONG count;
	int i, j;

	found = 0;
	for (i = 0; i < NUM_SLOTS; i++) {
		rv = test.module->C_OpenSession (test.slots[i], CKF_SERIAL_SESSION, NULL, NULL, &session);
		assert (rv == CKR_OK);

		rv = test.module->C_FindObjectsInit (session, match, p11_attrs_count (match));
		assert (rv == CKR_OK);
		rv = test.module->C_FindObjects (session, objects + found, max_objects - found, &count);
		assert (rv == CKR_OK);
		rv = test.module->C_FindObjectsFinal (session);
		assert (rv == CKR_OK);

		for (j = found ; j < found + count; j++)
			sessions[j] = session;
		found += count;
	}

	assert (found < max_objects);
	return found;
}

static void
check_trust_object_equiv (CK_SESSION_HANDLE session,
                          CK_OBJECT_HANDLE trust,
                          CK_ATTRIBUTE *cert)
{
	unsigned char subject[1024];
	unsigned char issuer[1024];
	unsigned char serial[128];
	CK_BBOOL modifiable;
	CK_BBOOL private;
	CK_BBOOL token;
	CK_RV rv;

	/* The following attributes should be equivalent to the certificate */
	CK_ATTRIBUTE equiv[] = {
		{ CKA_TOKEN, &token, sizeof (token) },
		{ CKA_PRIVATE, &private, sizeof (private) },
		{ CKA_MODIFIABLE, &modifiable, sizeof (modifiable) },
		{ CKA_ISSUER, issuer, sizeof (issuer) },
		{ CKA_SUBJECT, subject, sizeof (subject) },
		{ CKA_SERIAL_NUMBER, serial, sizeof (serial) },
		{ CKA_INVALID, },
	};

	rv = test.module->C_GetAttributeValue (session, trust, equiv, 6);
	assert_num_eq (CKR_OK, rv);

	test_check_attrs (equiv, cert);
}

static void
check_trust_object_hashes (CK_SESSION_HANDLE session,
                           CK_OBJECT_HANDLE trust,
                           CK_ATTRIBUTE *cert)
{
	unsigned char sha1[P11_HASH_SHA1_LEN];
	unsigned char md5[P11_HASH_MD5_LEN];
	unsigned char check[128];
	CK_ATTRIBUTE *value;
	CK_RV rv;

	CK_ATTRIBUTE hashes[] = {
		{ CKA_CERT_SHA1_HASH, sha1, sizeof (sha1) },
		{ CKA_CERT_MD5_HASH, md5, sizeof (md5) },
		{ CKA_INVALID, },
	};

	rv = test.module->C_GetAttributeValue (session, trust, hashes, 2);
	assert (rv == CKR_OK);

	value = p11_attrs_find_valid (cert, CKA_VALUE);
	assert_ptr_not_null (value);

	p11_hash_md5 (check, value->pValue, value->ulValueLen, NULL);
	assert (memcmp (md5, check, sizeof (md5)) == 0);

	p11_hash_sha1 (check, value->pValue, value->ulValueLen, NULL);
	assert (memcmp (sha1, check, sizeof (sha1)) == 0);
}

static void
check_has_trust_object (CK_ATTRIBUTE *cert)
{
	CK_OBJECT_CLASS trust_object = CKO_NSS_TRUST;
	CK_ATTRIBUTE klass = { CKA_CLASS, &trust_object, sizeof (trust_object) };
	CK_OBJECT_HANDLE objects[2];
	CK_SESSION_HANDLE sessions[2];
	CK_ATTRIBUTE *match;
	CK_ATTRIBUTE *attr;
	CK_ULONG count;

	attr = p11_attrs_find_valid (cert, CKA_ID);
	assert_ptr_not_null (attr);

	match = p11_attrs_build (NULL, &klass, attr, NULL);
	count = find_objects (match, sessions, objects, 2);
	assert_num_eq (1, count);

	check_trust_object_equiv (sessions[0], objects[0], cert);
	check_trust_object_hashes (sessions[0], objects[0], cert);

	p11_attrs_free (match);
}

static void
check_certificate (CK_SESSION_HANDLE session,
                   CK_OBJECT_HANDLE handle)
{
	unsigned char label[4096]= { 0, };
	CK_OBJECT_CLASS klass;
	unsigned char value[4096];
	unsigned char subject[1024];
	unsigned char issuer[1024];
	unsigned char serial[128];
	unsigned char id[128];
	CK_CERTIFICATE_TYPE type;
	CK_BYTE check[3];
	CK_DATE start;
	CK_DATE end;
	CK_ULONG category;
	CK_BBOOL modifiable;
	CK_BBOOL private;
	CK_BBOOL token;
	CK_RV rv;

	CK_ATTRIBUTE attrs[] = {
		{ CKA_CLASS, &klass, sizeof (klass) },
		{ CKA_TOKEN, &token, sizeof (token) },
		{ CKA_PRIVATE, &private, sizeof (private) },
		{ CKA_MODIFIABLE, &modifiable, sizeof (modifiable) },
		{ CKA_VALUE, value, sizeof (value) },
		{ CKA_ISSUER, issuer, sizeof (issuer) },
		{ CKA_SUBJECT, subject, sizeof (subject) },
		{ CKA_CERTIFICATE_TYPE, &type, sizeof (type) },
		{ CKA_CERTIFICATE_CATEGORY, &category, sizeof (category) },
		{ CKA_START_DATE, &start, sizeof (start) },
		{ CKA_END_DATE, &end, sizeof (end) },
		{ CKA_SERIAL_NUMBER, serial, sizeof (serial) },
		{ CKA_CHECK_VALUE, check, sizeof (check) },
		{ CKA_ID, id, sizeof (id) },
		{ CKA_LABEL, label, sizeof (label) },
		{ CKA_INVALID, },
	};

	/* Note that we don't pass the CKA_INVALID attribute in */
	rv = test.module->C_GetAttributeValue (session, handle, attrs, 15);
	assert (rv == CKR_OK);

	/* If this is the cacert3 certificate, check its values */
	if (memcmp (value, test_cacert3_ca_der, sizeof (test_cacert3_ca_der)) == 0) {
		CK_BBOOL trusted;
		CK_BBOOL vtrue = CK_TRUE;

		CK_ATTRIBUTE anchor[] = {
			{ CKA_TRUSTED, &trusted, sizeof (trusted) },
			{ CKA_INVALID, },
		};

		CK_ATTRIBUTE check[] = {
			{ CKA_TRUSTED, &vtrue, sizeof (vtrue) },
			{ CKA_INVALID, },
		};

		test_check_cacert3_ca (attrs, NULL);

		/* Get anchor specific attributes */
		rv = test.module->C_GetAttributeValue (session, handle, anchor, 1);
		assert (rv == CKR_OK);

		/* It lives in the trusted directory */
		test_check_attrs (check, anchor);

	/* Other certificates, we can't check the values */
	} else {
		test_check_object (attrs, CKO_CERTIFICATE, NULL);
	}

	check_has_trust_object (attrs);
}

static void
test_find_certificates (void)
{
	CK_OBJECT_CLASS klass = CKO_CERTIFICATE;

	CK_ATTRIBUTE match[] = {
		{ CKA_CLASS, &klass, sizeof (klass) },
		{ CKA_INVALID, }
	};

	CK_OBJECT_HANDLE objects[16];
	CK_SESSION_HANDLE sessions[16];
	CK_ULONG count;
	CK_ULONG i;

	count = find_objects (match, sessions, objects, 16);
	assert_num_eq (8, count);

	for (i = 0; i < count; i++)
		check_certificate (sessions[i], objects[i]);
}

static void
test_find_builtin (void)
{
	CK_OBJECT_CLASS klass = CKO_NSS_BUILTIN_ROOT_LIST;
	CK_BBOOL vtrue = CK_TRUE;
	CK_BBOOL vfalse = CK_FALSE;

	CK_ATTRIBUTE match[] = {
		{ CKA_CLASS, &klass, sizeof (klass) },
		{ CKA_TOKEN, &vtrue, sizeof (vtrue) },
		{ CKA_PRIVATE, &vfalse, sizeof (vfalse) },
		{ CKA_MODIFIABLE, &vfalse, sizeof (vfalse) },
		{ CKA_INVALID, }
	};

	CK_OBJECT_HANDLE objects[16];
	CK_SESSION_HANDLE sessions[16];
	CK_ULONG count;

	/* One per token */
	count = find_objects (match, sessions, objects, 16);
	assert_num_eq (NUM_SLOTS, count);
}

static void
test_session_object (void)
{
	CK_ATTRIBUTE original[] = {
		{ CKA_CLASS, &data, sizeof (data) },
		{ CKA_LABEL, "yay", 3 },
		{ CKA_VALUE, "eight", 5 },
		{ CKA_INVALID }
	};

	CK_SESSION_HANDLE session;
	CK_OBJECT_HANDLE handle;
	CK_ULONG size;
	CK_RV rv;

	rv = test.module->C_OpenSession (test.slots[0], CKF_SERIAL_SESSION, NULL, NULL, &session);
	assert (rv == CKR_OK);

	rv = test.module->C_CreateObject (session, original, 2, &handle);
	assert (rv == CKR_OK);

	rv = test.module->C_GetObjectSize (session, handle, &size);
	assert (rv == CKR_OK);
}

static void
test_session_find (void)
{
	CK_ATTRIBUTE original[] = {
		{ CKA_CLASS, &data, sizeof (data) },
		{ CKA_LABEL, "yay", 3 },
		{ CKA_VALUE, "eight", 5 },
		{ CKA_INVALID }
	};

	CK_SESSION_HANDLE session;
	CK_OBJECT_HANDLE handle;
	CK_OBJECT_HANDLE check;
	CK_ULONG count;
	CK_RV rv;

	rv = test.module->C_OpenSession (test.slots[0], CKF_SERIAL_SESSION, NULL, NULL, &session);
	assert_num_eq (CKR_OK, rv);

	rv = test.module->C_CreateObject (session, original, 2, &handle);
	assert_num_eq (CKR_OK, rv);

	rv = test.module->C_FindObjectsInit (session, original, 2);
	assert_num_eq (CKR_OK, rv);

	rv = test.module->C_FindObjects (session, &check, 1, &count);
	assert_num_eq (CKR_OK, rv);
	assert_num_eq (1, count);
	assert_num_eq (handle, check);

	rv = test.module->C_FindObjectsFinal (session);
	assert_num_eq (CKR_OK, rv);
}

static void
test_session_find_no_attr (void)
{
	CK_ATTRIBUTE original[] = {
		{ CKA_CLASS, &data, sizeof (data) },
		{ CKA_LABEL, "yay", 3 },
		{ CKA_VALUE, "eight", 5 },
		{ CKA_INVALID }
	};

	CK_ATTRIBUTE match[] = {
		{ CKA_COLOR, "blah", 4 },
		{ CKA_INVALID }
	};

	CK_SESSION_HANDLE session;
	CK_OBJECT_HANDLE handle;
	CK_OBJECT_HANDLE check;
	CK_ULONG count;
	CK_RV rv;

	rv = test.module->C_OpenSession (test.slots[0], CKF_SERIAL_SESSION, NULL, NULL, &session);
	assert_num_eq (CKR_OK, rv);

	rv = test.module->C_CreateObject (session, original, 3, &handle);
	assert_num_eq (CKR_OK, rv);

	rv = test.module->C_FindObjectsInit (session, match, 1);
	assert_num_eq (CKR_OK, rv);
	rv = test.module->C_FindObjects (session, &check, 1, &count);
	assert_num_eq (CKR_OK, rv);
	assert_num_eq (0, count);
	rv = test.module->C_FindObjectsFinal (session);
	assert_num_eq (CKR_OK, rv);
}

static void
test_lookup_invalid (void)
{
	CK_SESSION_HANDLE session;
	CK_ULONG size;
	CK_RV rv;

	rv = test.module->C_OpenSession (test.slots[0], CKF_SERIAL_SESSION, NULL, NULL, &session);
	assert (rv == CKR_OK);

	rv = test.module->C_GetObjectSize (session, 88888, &size);
	assert (rv == CKR_OBJECT_HANDLE_INVALID);
}

static void
test_remove_token (void)
{
	CK_SESSION_HANDLE session;
	CK_OBJECT_HANDLE handle;
	CK_ULONG count;
	CK_RV rv;

	rv = test.module->C_OpenSession (test.slots[0], CKF_SERIAL_SESSION, NULL, NULL, &session);
	assert (rv == CKR_OK);

	rv = test.module->C_FindObjectsInit (session, NULL, 0);
	assert (rv == CKR_OK);

	rv = test.module->C_FindObjects (session, &handle, 1, &count);
	assert (rv == CKR_OK);
	assert_num_eq (1, count);

	rv = test.module->C_DestroyObject (session, handle);
	assert (rv == CKR_TOKEN_WRITE_PROTECTED);
}

static void
test_setattr_token (void)
{
	CK_ATTRIBUTE original[] = {
		{ CKA_CLASS, &data, sizeof (data) },
		{ CKA_LABEL, "yay", 3 },
		{ CKA_VALUE, "eight", 5 },
		{ CKA_INVALID }
	};

	CK_SESSION_HANDLE session;
	CK_OBJECT_HANDLE handle;
	CK_ULONG count;
	CK_RV rv;

	rv = test.module->C_OpenSession (test.slots[0], CKF_SERIAL_SESSION, NULL, NULL, &session);
	assert (rv == CKR_OK);

	rv = test.module->C_FindObjectsInit (session, NULL, 0);
	assert (rv == CKR_OK);

	rv = test.module->C_FindObjects (session, &handle, 1, &count);
	assert (rv == CKR_OK);
	assert_num_eq (1, count);

	rv = test.module->C_SetAttributeValue (session, handle, original, 2);
	assert (rv == CKR_TOKEN_WRITE_PROTECTED);
}

static void
test_session_copy (void)
{
	CK_ATTRIBUTE original[] = {
		{ CKA_CLASS, &data, sizeof (data) },
		{ CKA_LABEL, "yay", 3 },
		{ CKA_VALUE, "eight", 5 },
		{ CKA_INVALID }
	};

	CK_SESSION_HANDLE session;
	CK_OBJECT_HANDLE handle;
	CK_OBJECT_HANDLE copy;
	CK_ULONG size;
	CK_RV rv;

	rv = test.module->C_OpenSession (test.slots[0], CKF_SERIAL_SESSION, NULL, NULL, &session);
	assert_num_eq (CKR_OK, rv);

	rv = test.module->C_CreateObject (session, original, 2, &handle);
	assert_num_eq (CKR_OK, rv);

	rv = test.module->C_CopyObject (session, handle, original, 2, &copy);
	assert_num_eq (CKR_OK, rv);

	rv = test.module->C_GetObjectSize (session, copy, &size);
	assert_num_eq (CKR_OK, rv);
}

static void
test_session_setattr (void)
{
	CK_ATTRIBUTE original[] = {
		{ CKA_CLASS, &data, sizeof (data) },
		{ CKA_LABEL, "yay", 3 },
		{ CKA_VALUE, "eight", 5 },
		{ CKA_INVALID }
	};

	CK_SESSION_HANDLE session;
	CK_OBJECT_HANDLE handle;
	CK_RV rv;

	rv = test.module->C_OpenSession (test.slots[0], CKF_SERIAL_SESSION, NULL, NULL, &session);
	assert (rv == CKR_OK);

	rv = test.module->C_CreateObject (session, original, 2, &handle);
	assert (rv == CKR_OK);

	rv = test.module->C_SetAttributeValue (session, handle, original, 2);
	assert (rv == CKR_OK);
}

static void
test_session_remove (void)
{
	CK_ATTRIBUTE original[] = {
		{ CKA_CLASS, &data, sizeof (data) },
		{ CKA_LABEL, "yay", 3 },
		{ CKA_VALUE, "eight", 5 },
		{ CKA_INVALID }
	};

	CK_SESSION_HANDLE session;
	CK_OBJECT_HANDLE handle;
	CK_RV rv;

	rv = test.module->C_OpenSession (test.slots[0], CKF_SERIAL_SESSION, NULL, NULL, &session);
	assert (rv == CKR_OK);

	rv = test.module->C_CreateObject (session, original, 2, &handle);
	assert (rv == CKR_OK);

	rv = test.module->C_DestroyObject (session, handle);
	assert (rv == CKR_OK);

	rv = test.module->C_DestroyObject (session, handle);
	assert (rv == CKR_OBJECT_HANDLE_INVALID);
}

static void
test_find_serial_der_decoded (void)
{
	CK_OBJECT_CLASS nss_trust = CKO_NSS_TRUST;

	CK_ATTRIBUTE object[] = {
		{ CKA_CLASS, &nss_trust, sizeof (nss_trust) },
		{ CKA_SERIAL_NUMBER, "\x02\x03\x01\x02\x03", 5 },
		{ CKA_INVALID }
	};

	CK_ATTRIBUTE match_decoded[] = {
		{ CKA_CLASS, &nss_trust, sizeof (nss_trust) },
		{ CKA_SERIAL_NUMBER, "\x01\x02\x03", 3 },
		{ CKA_INVALID }
	};

	CK_SESSION_HANDLE session;
	CK_OBJECT_HANDLE handle;
	CK_OBJECT_HANDLE check;
	CK_ULONG count;
	CK_RV rv;

	/*
	 * WORKAROUND: NSS calls us asking for CKA_SERIAL_NUMBER items that are
	 * not DER encoded. It shouldn't be doing this. We never return any certificate
	 * serial numbers that are not DER encoded.
	 *
	 * So work around the issue here while the NSS guys fix this issue.
	 * This code should be removed in future versions.
	 *
	 * See work_around_broken_nss_serial_number_lookups().
	 */

	rv = test.module->C_OpenSession (test.slots[0], CKF_SERIAL_SESSION, NULL, NULL, &session);
	assert_num_eq (CKR_OK, rv);

	rv = test.module->C_CreateObject (session, object, 2, &handle);
	assert_num_eq (CKR_OK, rv);

	/* Do a standard find for the same object */
	rv = test.module->C_FindObjectsInit (session, object, 2);
	assert_num_eq (CKR_OK, rv);
	rv = test.module->C_FindObjects (session, &check, 1, &count);
	assert_num_eq (CKR_OK, rv);
	assert_num_eq (1, count);
	assert_num_eq (handle, check);
	rv = test.module->C_FindObjectsFinal (session);
	assert_num_eq (CKR_OK, rv);

	/* Do a find for the serial number decoded */
	rv = test.module->C_FindObjectsInit (session, match_decoded, 2);
	assert_num_eq (CKR_OK, rv);
	rv = test.module->C_FindObjects (session, &check, 1, &count);
	assert_num_eq (CKR_OK, rv);
	assert_num_eq (1, count);
	assert_num_eq (handle, check);
	rv = test.module->C_FindObjectsFinal (session);
	assert_num_eq (CKR_OK, rv);
}

static void
test_find_serial_der_mismatch (void)
{
	CK_OBJECT_CLASS nss_trust = CKO_NSS_TRUST;

	CK_ATTRIBUTE object[] = {
		{ CKA_CLASS, &nss_trust, sizeof (nss_trust) },
		{ CKA_SERIAL_NUMBER, "\x02\x03\x01\x02\x03", 5 },
		{ CKA_INVALID }
	};

	CK_ATTRIBUTE match[] = {
		{ CKA_SERIAL_NUMBER, NULL, 0 },
		{ CKA_CLASS, &nss_trust, sizeof (nss_trust) },
		{ CKA_INVALID }
	};

	CK_SESSION_HANDLE session;
	CK_OBJECT_HANDLE handle;
	CK_OBJECT_HANDLE check;
	CK_ULONG count;
	CK_RV rv;

	rv = test.module->C_OpenSession (test.slots[0], CKF_SERIAL_SESSION, NULL, NULL, &session);
	assert_num_eq (CKR_OK, rv);

	rv = test.module->C_CreateObject (session, object, 2, &handle);
	assert_num_eq (CKR_OK, rv);

	/* Do a find with a null serial number, no match */
	rv = test.module->C_FindObjectsInit (session, match, 2);
	assert_num_eq (CKR_OK, rv);
	rv = test.module->C_FindObjects (session, &check, 1, &count);
	assert_num_eq (CKR_OK, rv);
	assert_num_eq (0, count);
	rv = test.module->C_FindObjectsFinal (session);
	assert_num_eq (CKR_OK, rv);

	/* Do a find with a wrong length, no match */
	match[0].pValue = "at";
	match[0].ulValueLen = 2;
	rv = test.module->C_FindObjectsInit (session, match, 2);
	assert_num_eq (CKR_OK, rv);
	rv = test.module->C_FindObjects (session, &check, 1, &count);
	assert_num_eq (CKR_OK, rv);
	assert_num_eq (0, count);
	rv = test.module->C_FindObjectsFinal (session);
	assert_num_eq (CKR_OK, rv);

	/* Do a find with a right length, wrong value, no match */
	match[0].pValue = "one";
	match[0].ulValueLen = 3;
	rv = test.module->C_FindObjectsInit (session, match, 2);
	assert_num_eq (CKR_OK, rv);
	rv = test.module->C_FindObjects (session, &check, 1, &count);
	assert_num_eq (CKR_OK, rv);
	assert_num_eq (0, count);
	rv = test.module->C_FindObjectsFinal (session);
	assert_num_eq (CKR_OK, rv);
}

static void
test_login_logout (void)
{
	CK_SESSION_HANDLE session;
	CK_RV rv;

	rv = test.module->C_OpenSession (test.slots[0], CKF_SERIAL_SESSION, NULL, NULL, &session);
	assert (rv == CKR_OK);

	/* Just testing our stubs for now */

	rv = test.module->C_Login (session, CKU_USER, NULL, 0);
	assert (rv == CKR_USER_TYPE_INVALID);

	rv = test.module->C_Logout (session);
	assert (rv == CKR_USER_NOT_LOGGED_IN);
}

int
main (int argc,
      char *argv[])
{
	p11_library_init ();

	p11_fixture (setup, teardown);
	p11_test (test_get_slot_list, "/module/get_slot_list");
	p11_test (test_get_slot_info, "/module/get_slot_info");

	p11_fixture (NULL, NULL);
	p11_test (test_get_token_info, "/module/get_token_info");

	p11_fixture (setup, teardown);
	p11_test (test_get_session_info, "/module/get_session_info");
	p11_test (test_close_all_sessions, "/module/close_all_sessions");
	p11_test (test_find_certificates, "/module/find_certificates");
	p11_test (test_find_builtin, "/module/find_builtin");
	p11_test (test_lookup_invalid, "/module/lookup_invalid");
	p11_test (test_remove_token, "/module/remove_token");
	p11_test (test_setattr_token, "/module/setattr_token");
	p11_test (test_session_object, "/module/session_object");
	p11_test (test_session_find, "/module/session_find");
	p11_test (test_session_find_no_attr, "/module/session_find_no_attr");
	p11_test (test_session_copy, "/module/session_copy");
	p11_test (test_session_remove, "/module/session_remove");
	p11_test (test_session_setattr, "/module/session_setattr");
	p11_test (test_find_serial_der_decoded, "/module/find_serial_der_decoded");
	p11_test (test_find_serial_der_mismatch, "/module/find_serial_der_mismatch");
	p11_test (test_login_logout, "/module/login_logout");

	return p11_test_run (argc, argv);
}
