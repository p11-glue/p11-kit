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

#include "config.h"
#include "CuTest.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define CRYPTOKI_EXPORTS

#include "attrs.h"
#include "checksum.h"
#include "debug.h"
#include "library.h"
#include "pkcs11x.h"
#include "test-data.h"
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
setup (CuTest *cu)
{
	CK_C_INITIALIZE_ARGS args;
	const char *paths;
	char *arguments;
	CK_ULONG count;
	CK_RV rv;

	memset (&test, 0, sizeof (test));

	/* This is the entry point of the trust module, linked to this test */
	rv = C_GetFunctionList (&test.module);
	CuAssertTrue (cu, rv == CKR_OK);

	memset (&args, 0, sizeof (args));
	paths = SRCDIR "/input:" SRCDIR "/files/self-signed-with-ku.der:" SRCDIR "/files/thawte.pem";
	if (asprintf (&arguments, "paths='%s'", paths) < 0)
		CuAssertTrue (cu, false && "not reached");
	args.pReserved = arguments;
	args.flags = CKF_OS_LOCKING_OK;

	rv = test.module->C_Initialize (&args);
	CuAssertTrue (cu, rv == CKR_OK);

	free (arguments);

	count = NUM_SLOTS;
	rv = test.module->C_GetSlotList (CK_TRUE, test.slots, &count);
	CuAssertTrue (cu, rv == CKR_OK);
	CuAssertTrue (cu, count == NUM_SLOTS);
}

static void
teardown (CuTest *cu)
{
	CK_RV rv;

	rv = test.module->C_Finalize (NULL);
	CuAssertTrue (cu, rv == CKR_OK);

	memset (&test, 0, sizeof (test));
}

static void
test_get_slot_list (CuTest *cu)
{
	CK_SLOT_ID slots[NUM_SLOTS];
	CK_ULONG count;
	CK_RV rv;
	int i;

	setup (cu);

	rv = test.module->C_GetSlotList (TRUE, NULL, &count);
	CuAssertIntEquals (cu, CKR_OK, rv);
	CuAssertIntEquals (cu, NUM_SLOTS, count);

	count = 1;
	rv = test.module->C_GetSlotList (TRUE, slots, &count);
	CuAssertIntEquals (cu, CKR_BUFFER_TOO_SMALL, rv);
	CuAssertIntEquals (cu, NUM_SLOTS, count);

	count = NUM_SLOTS;
	memset (slots, 0, sizeof (slots));
	rv = test.module->C_GetSlotList (TRUE, slots, &count);
	CuAssertIntEquals (cu, CKR_OK, rv);
	CuAssertIntEquals (cu, NUM_SLOTS, count);

	for (i = 0; i < NUM_SLOTS; i++)
		CuAssertTrue (cu, slots[i] != 0);

	teardown (cu);
}

static void
test_get_slot_info (CuTest *cu)
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

	setup (cu);

	count = NUM_SLOTS;
	rv = test.module->C_GetSlotList (TRUE, slots, &count);
	CuAssertIntEquals (cu, CKR_OK, rv);
	CuAssertIntEquals (cu, NUM_SLOTS, count);

	for (i = 0; i < NUM_SLOTS; i++) {
		rv = test.module->C_GetSlotInfo (slots[i], &info);
		CuAssertIntEquals (cu, CKR_OK, rv);

		memset (description, ' ', sizeof (description));
		length = strlen(paths[i]);
		if (length > sizeof (description))
			length = sizeof (description);
		memcpy (description, paths[i], length);
		CuAssertTrue (cu, memcmp (info.slotDescription, description, sizeof (description)) == 0);
	}

	teardown (cu);
}

static void
test_get_token_info (CuTest *cu)
{
	CK_SLOT_ID slots[NUM_SLOTS];
	CK_TOKEN_INFO info;
	char label[32];
	CK_ULONG count;
	CK_RV rv;
	int i;

	/* These are the paths passed in in setup() */
	const char *labels[] = {
		"input",
		"self-signed-with-ku.der",
		"thawte.pem"
	};

	setup (cu);

	count = NUM_SLOTS;
	rv = test.module->C_GetSlotList (TRUE, slots, &count);
	CuAssertIntEquals (cu, CKR_OK, rv);
	CuAssertIntEquals (cu, NUM_SLOTS, count);

	for (i = 0; i < NUM_SLOTS; i++) {
		rv = test.module->C_GetTokenInfo (slots[i], &info);
		CuAssertIntEquals (cu, CKR_OK, rv);

		memset (label, ' ', sizeof (label));
		memcpy (label, labels[i], strlen (labels[i]));
		CuAssertTrue (cu, memcmp (info.label, label, sizeof (label)) == 0);
	}

	teardown (cu);
}

static void
test_get_session_info (CuTest *cu)
{
	CK_SLOT_ID slots[NUM_SLOTS];
	CK_SESSION_HANDLE sessions[NUM_SLOTS];
	CK_SESSION_INFO info;
	CK_ULONG count;
	CK_RV rv;
	int i;

	setup (cu);

	count = NUM_SLOTS;
	rv = test.module->C_GetSlotList (TRUE, slots, &count);
	CuAssertIntEquals (cu, CKR_OK, rv);
	CuAssertIntEquals (cu, NUM_SLOTS, count);

	/* Open two sessions with each token */
	for (i = 0; i < NUM_SLOTS; i++) {
		rv = test.module->C_OpenSession (slots[i], CKF_SERIAL_SESSION, NULL, NULL, &sessions[i]);
		CuAssertIntEquals (cu, CKR_OK, rv);

		rv = test.module->C_GetSessionInfo (sessions[i], &info);
		CuAssertIntEquals (cu, CKR_OK, rv);

		CuAssertIntEquals (cu, slots[i], info.slotID);
		CuAssertIntEquals (cu, CKF_SERIAL_SESSION, info.flags);
	}

	teardown (cu);
}

static void
test_close_all_sessions (CuTest *cu)
{
	CK_SLOT_ID slots[NUM_SLOTS];
	CK_SESSION_HANDLE sessions[NUM_SLOTS][2];
	CK_SESSION_INFO info;
	CK_ULONG count;
	CK_RV rv;
	int i;

	setup (cu);

	count = NUM_SLOTS;
	rv = test.module->C_GetSlotList (TRUE, slots, &count);
	CuAssertIntEquals (cu, CKR_OK, rv);
	CuAssertIntEquals (cu, NUM_SLOTS, count);

	/* Open two sessions with each token */
	for (i = 0; i < NUM_SLOTS; i++) {
		rv = test.module->C_OpenSession (slots[i], CKF_SERIAL_SESSION, NULL, NULL, &sessions[i][0]);
		CuAssertIntEquals (cu, CKR_OK, rv);

		rv = test.module->C_GetSessionInfo (sessions[i][0], &info);
		CuAssertIntEquals (cu, CKR_OK, rv);

		rv = test.module->C_OpenSession (slots[i], CKF_SERIAL_SESSION, NULL, NULL, &sessions[i][1]);
		CuAssertIntEquals (cu, CKR_OK, rv);

		rv = test.module->C_GetSessionInfo (sessions[i][0], &info);
		CuAssertIntEquals (cu, CKR_OK, rv);
	}

	/* Close all the sessions on the first token */
	rv = test.module->C_CloseAllSessions (slots[0]);
	CuAssertIntEquals (cu, CKR_OK, rv);

	/* Those sessions should be closed */
	rv = test.module->C_GetSessionInfo (sessions[0][0], &info);
	CuAssertIntEquals (cu, CKR_SESSION_HANDLE_INVALID, rv);
	rv = test.module->C_GetSessionInfo (sessions[0][1], &info);
	CuAssertIntEquals (cu, CKR_SESSION_HANDLE_INVALID, rv);

	/* Other sessions should still be open */
	for (i = 1; i < NUM_SLOTS; i++) {
		rv = test.module->C_GetSessionInfo (sessions[i][0], &info);
		CuAssertIntEquals (cu, CKR_OK, rv);
		rv = test.module->C_GetSessionInfo (sessions[i][0], &info);
		CuAssertIntEquals (cu, CKR_OK, rv);
	}

	teardown (cu);
}

static CK_ULONG
find_objects (CuTest *cu,
              CK_ATTRIBUTE *match,
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
		CuAssertTrue (cu, rv == CKR_OK);

		rv = test.module->C_FindObjectsInit (session, match, p11_attrs_count (match));
		CuAssertTrue (cu, rv == CKR_OK);
		rv = test.module->C_FindObjects (session, objects + found, max_objects - found, &count);
		CuAssertTrue (cu, rv == CKR_OK);
		rv = test.module->C_FindObjectsFinal (session);
		CuAssertTrue (cu, rv == CKR_OK);

		for (j = found ; j < found + count; j++)
			sessions[j] = session;
		found += count;
	}

	assert (found < max_objects);
	return found;
}

static void
check_trust_object_equiv (CuTest *cu,
                          CK_SESSION_HANDLE session,
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
	CuAssertIntEquals (cu, CKR_OK, rv);

	test_check_attrs (cu, equiv, cert);
}

static void
check_trust_object_hashes (CuTest *cu,
                           CK_SESSION_HANDLE session,
                           CK_OBJECT_HANDLE trust,
                           CK_ATTRIBUTE *cert)
{
	unsigned char sha1[P11_CHECKSUM_SHA1_LENGTH];
	unsigned char md5[P11_CHECKSUM_MD5_LENGTH];
	unsigned char check[128];
	CK_ATTRIBUTE *value;
	CK_RV rv;

	CK_ATTRIBUTE hashes[] = {
		{ CKA_CERT_SHA1_HASH, sha1, sizeof (sha1) },
		{ CKA_CERT_MD5_HASH, md5, sizeof (md5) },
		{ CKA_INVALID, },
	};

	rv = test.module->C_GetAttributeValue (session, trust, hashes, 2);
	CuAssertTrue (cu, rv == CKR_OK);

	value = p11_attrs_find (cert, CKA_VALUE);
	CuAssertPtrNotNull (cu, value);

	p11_checksum_md5 (check, value->pValue, value->ulValueLen, NULL);
	CuAssertTrue (cu, memcmp (md5, check, sizeof (md5)) == 0);

	p11_checksum_sha1 (check, value->pValue, value->ulValueLen, NULL);
	CuAssertTrue (cu, memcmp (sha1, check, sizeof (sha1)) == 0);
}

static void
check_has_trust_object (CuTest *cu,
                        CK_ATTRIBUTE *cert)
{
	CK_OBJECT_CLASS trust_object = CKO_NSS_TRUST;
	CK_ATTRIBUTE klass = { CKA_CLASS, &trust_object, sizeof (trust_object) };
	CK_OBJECT_HANDLE objects[2];
	CK_SESSION_HANDLE sessions[2];
	CK_ATTRIBUTE *match;
	CK_ATTRIBUTE *attr;
	CK_ULONG count;

	attr = p11_attrs_find (cert, CKA_ID);
	CuAssertPtrNotNull (cu, attr);

	match = p11_attrs_build (NULL, &klass, attr, NULL);
	count = find_objects (cu, match, sessions, objects, 2);
	CuAssertIntEquals (cu, 1, count);

	check_trust_object_equiv (cu, sessions[0], objects[0], cert);
	check_trust_object_hashes (cu, sessions[0], objects[0], cert);
}

static void
check_certificate (CuTest *cu,
                   CK_SESSION_HANDLE session,
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
	CuAssertTrue (cu, rv == CKR_OK);

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

		test_check_cacert3_ca (cu, attrs, NULL);

		/* Get anchor specific attributes */
		rv = test.module->C_GetAttributeValue (session, handle, anchor, 1);
		CuAssertTrue (cu, rv == CKR_OK);

		/* It lives in the trusted directory */
		test_check_attrs (cu, check, anchor);

	/* Other certificates, we can't check the values */
	} else {
		test_check_object (cu, attrs, CKO_CERTIFICATE, NULL);
	}

	check_has_trust_object (cu, attrs);
}

static void
test_find_certificates (CuTest *cu)
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

	setup (cu);

	count = find_objects (cu, match, sessions, objects, 16);
	CuAssertIntEquals (cu, 8, count);

	for (i = 0; i < count; i++)
		check_certificate (cu, sessions[i], objects[i]);

	teardown (cu);
}

static void
test_find_builtin (CuTest *cu)
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

	setup (cu);

	/* One per token */
	count = find_objects (cu, match, sessions, objects, 16);
	CuAssertIntEquals (cu, NUM_SLOTS, count);

	teardown (cu);
}

static void
test_session_object (CuTest *cu)
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

	setup (cu);

	rv = test.module->C_OpenSession (test.slots[0], CKF_SERIAL_SESSION, NULL, NULL, &session);
	CuAssertTrue (cu, rv == CKR_OK);

	rv = test.module->C_CreateObject (session, original, 2, &handle);
	CuAssertTrue (cu, rv == CKR_OK);

	rv = test.module->C_GetObjectSize (session, handle, &size);
	CuAssertTrue (cu, rv == CKR_OK);

	teardown (cu);
}

static void
test_session_find (CuTest *cu)
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

	setup (cu);

	rv = test.module->C_OpenSession (test.slots[0], CKF_SERIAL_SESSION, NULL, NULL, &session);
	CuAssertIntEquals (cu, CKR_OK, rv);

	rv = test.module->C_CreateObject (session, original, 2, &handle);
	CuAssertIntEquals (cu, CKR_OK, rv);

	rv = test.module->C_FindObjectsInit (session, original, 2);
	CuAssertIntEquals (cu, CKR_OK, rv);

	rv = test.module->C_FindObjects (session, &check, 1, &count);
	CuAssertIntEquals (cu, CKR_OK, rv);
	CuAssertIntEquals (cu, 1, count);
	CuAssertIntEquals (cu, handle, check);

	rv = test.module->C_FindObjectsFinal (session);
	CuAssertIntEquals (cu, CKR_OK, rv);

	teardown (cu);
}

static void
test_lookup_invalid (CuTest *cu)
{
	CK_SESSION_HANDLE session;
	CK_ULONG size;
	CK_RV rv;

	setup (cu);

	rv = test.module->C_OpenSession (test.slots[0], CKF_SERIAL_SESSION, NULL, NULL, &session);
	CuAssertTrue (cu, rv == CKR_OK);

	rv = test.module->C_GetObjectSize (session, 88888, &size);
	CuAssertTrue (cu, rv == CKR_OBJECT_HANDLE_INVALID);

	teardown (cu);
}

static void
test_remove_token (CuTest *cu)
{
	CK_SESSION_HANDLE session;
	CK_OBJECT_HANDLE handle;
	CK_ULONG count;
	CK_RV rv;

	setup (cu);

	rv = test.module->C_OpenSession (test.slots[0], CKF_SERIAL_SESSION, NULL, NULL, &session);
	CuAssertTrue (cu, rv == CKR_OK);

	rv = test.module->C_FindObjectsInit (session, NULL, 0);
	CuAssertTrue (cu, rv == CKR_OK);

	rv = test.module->C_FindObjects (session, &handle, 1, &count);
	CuAssertTrue (cu, rv == CKR_OK);
	CuAssertIntEquals (cu, 1, count);

	rv = test.module->C_DestroyObject (session, handle);
	CuAssertTrue (cu, rv == CKR_TOKEN_WRITE_PROTECTED);

	teardown (cu);
}

static void
test_setattr_token (CuTest *cu)
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

	setup (cu);

	rv = test.module->C_OpenSession (test.slots[0], CKF_SERIAL_SESSION, NULL, NULL, &session);
	CuAssertTrue (cu, rv == CKR_OK);

	rv = test.module->C_FindObjectsInit (session, NULL, 0);
	CuAssertTrue (cu, rv == CKR_OK);

	rv = test.module->C_FindObjects (session, &handle, 1, &count);
	CuAssertTrue (cu, rv == CKR_OK);
	CuAssertIntEquals (cu, 1, count);

	rv = test.module->C_SetAttributeValue (session, handle, original, 2);
	CuAssertTrue (cu, rv == CKR_TOKEN_WRITE_PROTECTED);

	teardown (cu);
}

static void
test_session_copy (CuTest *cu)
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

	setup (cu);

	rv = test.module->C_OpenSession (test.slots[0], CKF_SERIAL_SESSION, NULL, NULL, &session);
	CuAssertIntEquals (cu, CKR_OK, rv);

	rv = test.module->C_CreateObject (session, original, 2, &handle);
	CuAssertIntEquals (cu, CKR_OK, rv);

	rv = test.module->C_CopyObject (session, handle, original, 2, &copy);
	CuAssertIntEquals (cu, CKR_OK, rv);

	rv = test.module->C_GetObjectSize (session, copy, &size);
	CuAssertIntEquals (cu, CKR_OK, rv);

	teardown (cu);
}

static void
test_session_setattr (CuTest *cu)
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

	setup (cu);

	rv = test.module->C_OpenSession (test.slots[0], CKF_SERIAL_SESSION, NULL, NULL, &session);
	CuAssertTrue (cu, rv == CKR_OK);

	rv = test.module->C_CreateObject (session, original, 2, &handle);
	CuAssertTrue (cu, rv == CKR_OK);

	rv = test.module->C_SetAttributeValue (session, handle, original, 2);
	CuAssertTrue (cu, rv == CKR_OK);

	teardown (cu);
}

static void
test_session_remove (CuTest *cu)
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

	setup (cu);

	rv = test.module->C_OpenSession (test.slots[0], CKF_SERIAL_SESSION, NULL, NULL, &session);
	CuAssertTrue (cu, rv == CKR_OK);

	rv = test.module->C_CreateObject (session, original, 2, &handle);
	CuAssertTrue (cu, rv == CKR_OK);

	rv = test.module->C_DestroyObject (session, handle);
	CuAssertTrue (cu, rv == CKR_OK);

	rv = test.module->C_DestroyObject (session, handle);
	CuAssertTrue (cu, rv == CKR_OBJECT_HANDLE_INVALID);

	teardown (cu);
}

int
main (void)
{
	CuString *output = CuStringNew ();
	CuSuite* suite = CuSuiteNew ();
	int ret;

	putenv ("P11_KIT_STRICT=1");
	p11_library_init ();
	p11_debug_init ();

	SUITE_ADD_TEST (suite, test_get_slot_list);
	SUITE_ADD_TEST (suite, test_get_slot_info);
	SUITE_ADD_TEST (suite, test_get_token_info);
	SUITE_ADD_TEST (suite, test_get_session_info);
	SUITE_ADD_TEST (suite, test_close_all_sessions);
	SUITE_ADD_TEST (suite, test_find_certificates);
	SUITE_ADD_TEST (suite, test_find_builtin);
	SUITE_ADD_TEST (suite, test_lookup_invalid);
	SUITE_ADD_TEST (suite, test_remove_token);
	SUITE_ADD_TEST (suite, test_setattr_token);
	SUITE_ADD_TEST (suite, test_session_object);
	SUITE_ADD_TEST (suite, test_session_find);
	SUITE_ADD_TEST (suite, test_session_copy);
	SUITE_ADD_TEST (suite, test_session_remove);
	SUITE_ADD_TEST (suite, test_session_setattr);

	CuSuiteRun (suite);
	CuSuiteSummary (suite, output);
	CuSuiteDetails (suite, output);
	printf ("%s\n", output->buffer);
	ret = suite->failCount;
	CuSuiteDelete (suite);
	CuStringDelete (output);

	return ret;
}
