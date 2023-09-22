/*
 * Copyright (c) 2023, Red Hat Inc.
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

#define CRYPTOKI_EXPORTS 1
#include "pkcs11.h"

#include "attrs.h"
#include "debug.h"
#include "mock.h"

#ifdef WITH_ASN1
#include "persist.h"
#endif

#include <stdio.h>
#include <string.h>

static const CK_TOKEN_INFO MOCK_TOKEN_INFO = {
	"PROFILE LABEL ONE               ",
	"PROFILE MANUFACTURER            ",
	"PROFILE MODEL   ",
	"PROFILE SERIAL  ",
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

static CK_RV
override_C_GetTokenInfo (CK_SLOT_ID slot_id,
			 CK_TOKEN_INFO_PTR info)
{
	return_val_if_fail (info != NULL, CKR_ARGUMENTS_BAD);

	switch (slot_id) {
	case MOCK_SLOT_ONE_ID:
		memcpy (info, &MOCK_TOKEN_INFO, sizeof (*info));
		return CKR_OK;
	case MOCK_SLOT_TWO_ID:
		return CKR_TOKEN_NOT_PRESENT;
	default:
		return CKR_SLOT_ID_INVALID;
	}
}

#ifdef WITH_ASN1
static CK_RV
override_C_Initialize (CK_VOID_PTR init_args)
{
	bool ok;
	size_t i, size = 0;
	void *data = NULL;
	const char *filename = "test-profiles.p11-kit";
	p11_mmap *map = NULL;
	p11_persist *persist = NULL;
	p11_array *objects = NULL;
	CK_ATTRIBUTE *attrs = NULL;
	CK_RV rv;

	map = p11_mmap_open (filename, NULL, &data, &size);
	if (map == NULL)
		return mock_C_Initialize (init_args);

	ok = p11_persist_magic (data, size);
	return_val_if_fail (ok, CKR_GENERAL_ERROR);

	persist = p11_persist_new ();
	return_val_if_fail (persist != NULL, CKR_HOST_MEMORY);

	objects = p11_array_new (NULL);
	return_val_if_fail (objects != NULL, CKR_HOST_MEMORY);

	ok = p11_persist_read (persist, filename, (const unsigned char *)data, size, objects);
	return_val_if_fail (ok, CKR_GENERAL_ERROR);

	rv = mock_C_Initialize (init_args);
	for (i = 0; i < objects->num; ++i) {
		attrs = p11_attrs_build (objects->elem[i], NULL);
		mock_module_add_object (MOCK_SLOT_ONE_ID, attrs);
		p11_attrs_free (attrs);
	}

	p11_array_free (objects);
	p11_persist_free (persist);
	p11_mmap_close (map);
	return rv;
}

static CK_RV
override_C_Finalize (CK_VOID_PTR reserved)
{
	bool ok;
	FILE *f = NULL;
	const char *filename = "test-profiles.out.p11-kit";
	p11_buffer buf;
	p11_persist *persist = NULL;
	CK_SESSION_HANDLE session = 0;
	CK_OBJECT_HANDLE object = 0;
	CK_ULONG count = 0;
	CK_OBJECT_CLASS klass = CKO_PROFILE;
	CK_BBOOL token;
	CK_PROFILE_ID profile;
	CK_ATTRIBUTE template = { CKA_CLASS, &klass, sizeof (klass) };
	CK_ATTRIBUTE attrs[] = {
		{ CKA_CLASS, &klass, sizeof (klass) },
		{ CKA_TOKEN, &token, sizeof (token) },
		{ CKA_PROFILE_ID, &profile, sizeof (profile) },
		{ CKA_INVALID, NULL, 0 }
	};
	CK_ULONG n_attrs = sizeof (attrs) / sizeof (attrs[0]);
	CK_RV rv;

	ok = p11_buffer_init (&buf, 0);
	return_val_if_fail (ok, CKR_HOST_MEMORY);

	persist = p11_persist_new ();
	return_val_if_fail (persist != NULL, CKR_HOST_MEMORY);

	rv = mock_C_OpenSession (MOCK_SLOT_ONE_ID, CKF_SERIAL_SESSION, NULL, NULL, &session);
	return_val_if_fail (rv == CKR_OK, CKR_GENERAL_ERROR);

	rv = mock_C_FindObjectsInit (session, &template, 1);
	return_val_if_fail (rv == CKR_OK, CKR_GENERAL_ERROR);

	while ((rv = mock_C_FindObjects (session, &object, 1, &count)) == CKR_OK && count > 0) {
		rv = mock_C_GetAttributeValue (session, object, attrs, n_attrs - 1);
		return_val_if_fail (rv == CKR_OK, CKR_GENERAL_ERROR);

		ok = p11_persist_write (persist, attrs, &buf);
		return_val_if_fail (ok, CKR_GENERAL_ERROR);
	}
	return_val_if_fail (rv == CKR_OK, CKR_GENERAL_ERROR);

	f = fopen (filename, "wb");
	return_val_if_fail (f != NULL, CKR_HOST_MEMORY);
	fwrite (buf.data, 1, buf.len, f);
	fclose (f);

	rv = mock_C_FindObjectsFinal (session);
	return_val_if_fail (rv == CKR_OK, CKR_GENERAL_ERROR);

	rv = mock_C_CloseSession (session);
	return_val_if_fail (rv == CKR_OK, CKR_GENERAL_ERROR);

	p11_persist_free (persist);
	p11_buffer_uninit (&buf);
	return mock_C_Finalize (reserved);
}
#endif /* WITH_ASN1 */

#ifdef OS_WIN32
__declspec(dllexport)
#endif
CK_RV
C_GetFunctionList (CK_FUNCTION_LIST_PTR_PTR list)
{
	mock_module_init ();
#ifdef WITH_ASN1
	mock_module.C_Initialize = override_C_Initialize;
	mock_module.C_Finalize = override_C_Finalize;
#endif
	mock_module.C_GetFunctionList = C_GetFunctionList;
	mock_module.C_GetTokenInfo = override_C_GetTokenInfo;
	if (list == NULL)
		return CKR_ARGUMENTS_BAD;
	*list = &mock_module;
	return CKR_OK;
}
