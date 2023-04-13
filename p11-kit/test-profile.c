/*
 * Copyright (c) 2023 Red Hat Inc
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
#include "test.h"

#include "library.h"
#include "p11-kit.h"

#include <stdlib.h>
#include <string.h>

static CK_FUNCTION_LIST_PTR_PTR
initialize_and_get_modules (void)
{
	CK_FUNCTION_LIST_PTR_PTR modules;

	modules = p11_kit_modules_load_and_initialize (0);
	assert (modules != NULL && modules[0] != NULL);

	return modules;
}

static void
finalize_and_free_modules (CK_FUNCTION_LIST_PTR_PTR modules)
{
	p11_kit_modules_finalize_and_release (modules);
}

static CK_FUNCTION_LIST_PTR
lookup_module_with_name (CK_FUNCTION_LIST_PTR_PTR modules,
			 const char *name)
{
	CK_FUNCTION_LIST_PTR match = NULL;
	CK_FUNCTION_LIST_PTR module;
	char *module_name;
	int i;

	for (i = 0; match == NULL && modules[i] != NULL; i++) {
		module_name = p11_kit_module_get_name (modules[i]);
		assert_ptr_not_null (module_name);
		if (strcmp (module_name, name) == 0)
			match = modules[i];
		free (module_name);
	}

	/*
	 * As a side effect, we should check that the results of this function
	 * matches the above search.
	 */
	module = p11_kit_module_for_name (modules, name);
	if (module != match)
		assert_fail ("different result from p11_kit_module_for_name ()", NULL);

	return match;
}

static void
test_profile (void)
{
	CK_FUNCTION_LIST_PTR_PTR modules;
	CK_FUNCTION_LIST_PTR module;
	CK_SESSION_HANDLE session = 0;
	CK_OBJECT_HANDLE objects[4];
	CK_ULONG count = 0;
	CK_RV rv;

	CK_PROFILE_ID profile1 = CKP_BASELINE_PROVIDER;
	CK_PROFILE_ID profile2 = CKP_AUTHENTICATION_TOKEN;
	CK_PROFILE_ID val1 = CKP_INVALID_ID;
	CK_PROFILE_ID val2 = CKP_INVALID_ID;

	CK_OBJECT_CLASS klass = CKO_PROFILE;
	CK_ATTRIBUTE attr = { CKA_CLASS, &klass, sizeof (klass) };

	CK_ATTRIBUTE attrs[] = {
	    { CKA_PROFILE_ID, NULL_PTR, 0 },
	    { CKA_PROFILE_ID, NULL_PTR, 0 },
	};

	modules = initialize_and_get_modules ();
	module = lookup_module_with_name (modules, "eleven");

	rv = (module->C_FindObjectsInit) (session, &attr, 1);
	assert_num_eq (CKR_OK, rv);

	rv = (module->C_FindObjects) (session, objects, 4, &count);
	assert_num_eq (CKR_OK, rv);
	assert_num_eq (1, count);

	rv = (module->C_FindObjects) (session, objects, 4, &count);
	assert_num_eq (CKR_OK, rv);
	assert_num_eq (0, count);

	rv = (module->C_GetAttributeValue) (session, objects[0], attrs, 2);
	assert_num_eq (CKR_OK, rv);
	assert_num_eq (attrs[0].type, CKA_PROFILE_ID);
	assert (attrs[0].pValue == NULL_PTR);
	assert_num_eq (attrs[0].ulValueLen, sizeof (CK_PROFILE_ID));
	assert_num_eq (attrs[1].type, CKA_PROFILE_ID);
	assert (attrs[1].pValue == NULL_PTR);
	assert_num_eq (attrs[1].ulValueLen, sizeof (CK_PROFILE_ID));

	attrs[0].pValue = &val1;
	attrs[1].pValue = &val2;
	attrs[1].ulValueLen += 100;

	rv = (module->C_GetAttributeValue) (session, objects[0], attrs, 2);
	assert_num_eq (CKR_OK, rv);
	assert_num_eq (attrs[0].type, CKA_PROFILE_ID);
	assert_num_eq (attrs[0].ulValueLen, sizeof (CK_PROFILE_ID));
	assert_num_eq (memcmp(attrs[0].pValue, &profile1, attrs[0].ulValueLen), 0);
	assert_num_eq (attrs[1].type, CKA_PROFILE_ID);
	assert_num_eq (attrs[1].ulValueLen, sizeof (CK_PROFILE_ID));
	assert_num_eq (memcmp(attrs[1].pValue, &profile2, attrs[1].ulValueLen), 0);

	rv = (module->C_FindObjectsFinal) (session);
	assert (rv == CKR_OK);

	finalize_and_free_modules (modules);
}

int
main (int argc,
      char *argv[])
{
	p11_library_init ();

	p11_test (test_profile, "/profile/test_profile");

	return p11_test_run (argc, argv);
}
