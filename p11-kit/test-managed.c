/*
 * Copyright (c) 2012 Red Hat Inc
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
 * Author: Stef Walter <stefw@redhat.com>
 */

#include "config.h"
#include "test.h"

#include "dict.h"
#include "library.h"
#include "mock.h"
#include "modules.h"
#include "p11-kit.h"
#include "virtual.h"
#include "virtual-fixed.h"

#include <sys/types.h>
#ifdef OS_UNIX
#include <sys/wait.h>
#include <unistd.h>
#endif
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

static CK_FUNCTION_LIST_PTR
setup_mock_module (CK_SESSION_HANDLE *session)
{
	CK_FUNCTION_LIST_PTR module = NULL;
	CK_RV rv;

	p11_lock ();

	rv = p11_module_load_inlock_reentrant (&mock_module, 0, &module);

	p11_unlock ();

	if (rv == CKR_OK) {
		assert_ptr_not_null (module);
		assert (p11_virtual_is_wrapper (module));
	} else {
		assert_ptr_eq (NULL, module);
		return NULL;
	}

	rv = p11_kit_module_initialize (module);
	assert (rv == CKR_OK);

	if (session) {
		rv = (module->C_OpenSession) (MOCK_SLOT_ONE_ID,
		                              CKF_RW_SESSION | CKF_SERIAL_SESSION,
		                              NULL, NULL, session);
		assert (rv == CKR_OK);
	}

	return module;
}

static void
teardown_mock_module (CK_FUNCTION_LIST_PTR module)
{
	CK_RV rv;

	rv = p11_kit_module_finalize (module);
	assert (rv == CKR_OK);

	p11_lock ();

	rv = p11_module_release_inlock_reentrant (module);
	assert (rv == CKR_OK);

	p11_unlock ();
}

static CK_RV
fail_C_Initialize (void *init_reserved)
{
	return CKR_FUNCTION_FAILED;
}

static void
test_initialize_finalize (void)
{
	CK_FUNCTION_LIST_PTR module;
	CK_RV rv;

	p11_lock ();

	rv = p11_module_load_inlock_reentrant (&mock_module, 0, &module);
	assert (rv == CKR_OK);
	assert_ptr_not_null (module);
	assert (p11_virtual_is_wrapper (module));

	p11_unlock ();

	rv = module->C_Initialize (NULL);
	assert (rv == CKR_OK);

	rv = module->C_Initialize (NULL);
	assert (rv == CKR_CRYPTOKI_ALREADY_INITIALIZED);

	rv = module->C_Finalize (NULL);
	assert (rv == CKR_OK);

	rv = module->C_Finalize (NULL);
	assert (rv == CKR_CRYPTOKI_NOT_INITIALIZED);

	p11_lock ();

	rv = p11_module_release_inlock_reentrant (module);
	assert (rv == CKR_OK);

	p11_unlock ();
}

static void
test_initialize_fail (void)
{
	CK_FUNCTION_LIST_PTR module;
	CK_FUNCTION_LIST base;
	CK_RV rv;

	memcpy (&base, &mock_module, sizeof (CK_FUNCTION_LIST));
	base.C_Initialize = fail_C_Initialize;

	p11_lock ();

	rv = p11_module_load_inlock_reentrant (&base, 0, &module);
	assert (rv == CKR_OK);

	p11_unlock ();

	rv = p11_kit_module_initialize (module);
	assert (rv == CKR_FUNCTION_FAILED);
}

static void
test_separate_close_all_sessions (void)
{
	CK_FUNCTION_LIST *first;
	CK_FUNCTION_LIST *second;
	CK_SESSION_HANDLE s1;
	CK_SESSION_HANDLE s2;
	CK_SESSION_INFO info;
	CK_RV rv;

	first = setup_mock_module (&s1);
	assert_ptr_not_null (first);
	second = setup_mock_module (&s2);
	assert_ptr_not_null (second);

	rv = first->C_GetSessionInfo (s1, &info);
	assert (rv == CKR_OK);

	rv = second->C_GetSessionInfo (s2, &info);
	assert (rv == CKR_OK);

	first->C_CloseAllSessions (MOCK_SLOT_ONE_ID);
	assert (rv == CKR_OK);

	rv = first->C_GetSessionInfo (s1, &info);
	assert (rv == CKR_SESSION_HANDLE_INVALID);

	rv = second->C_GetSessionInfo (s2, &info);
	assert (rv == CKR_OK);

	second->C_CloseAllSessions (MOCK_SLOT_ONE_ID);
	assert (rv == CKR_OK);

	rv = first->C_GetSessionInfo (s1, &info);
	assert (rv == CKR_SESSION_HANDLE_INVALID);

	rv = second->C_GetSessionInfo (s2, &info);
	assert (rv == CKR_SESSION_HANDLE_INVALID);

	teardown_mock_module (first);
	teardown_mock_module (second);
}

#define MAX_MODS (P11_VIRTUAL_MAX_FIXED+10)
static void
test_max_session_load (void)
{
	CK_FUNCTION_LIST *list[MAX_MODS];
	CK_SESSION_HANDLE s1;
	CK_SESSION_INFO info;
	CK_RV rv;
	unsigned i;
	unsigned registered = 0;

	for (i = 0; i < MAX_MODS; i++) {
		list[i] = setup_mock_module (&s1);
		if (list[i] != NULL)
			registered++;
	}

	assert_num_cmp (registered + 1, >=, P11_VIRTUAL_MAX_FIXED);

	for (i = 0; i < registered; i++) {
		rv = list[i]->C_GetSessionInfo (s1, &info);
		assert (rv == CKR_OK);

		list[i]->C_CloseAllSessions (MOCK_SLOT_ONE_ID);
		assert (rv == CKR_OK);
	}

	for (i = 0; i < registered; i++) {
		teardown_mock_module (list[i]);
	}
}

#ifdef OS_UNIX

static void
test_fork_and_reinitialize (void)
{
	CK_FUNCTION_LIST *module;
	CK_INFO info;
	int status;
	CK_RV rv;
	pid_t pid;
	int i;

	module = setup_mock_module (NULL);
	assert_ptr_not_null (module);

	pid = fork ();
	assert_num_cmp (pid, >=, 0);

	/* The child */
	if (pid == 0) {
		rv = (module->C_Initialize) (NULL);
		assert_num_eq (CKR_OK, rv);

		for (i = 0; i < 32; i++) {
			rv = (module->C_GetInfo) (&info);
			assert_num_eq (CKR_OK, rv);
		}

		rv = (module->C_Finalize) (NULL);
		assert_num_eq (CKR_OK, rv);

		_exit (66);
	}

	for (i = 0; i < 128; i++) {
		rv = (module->C_GetInfo) (&info);
		assert_num_eq (CKR_OK, rv);
	}

	assert_num_eq (waitpid (pid, &status, 0), pid);
	assert_num_eq (WEXITSTATUS (status), 66);

	teardown_mock_module (module);
}

#endif /* OS_UNIX */

/* Bring in all the mock module tests */
#include "test-mock.c"

int
main (int argc,
      char *argv[])
{
	mock_module_init ();
	p11_library_init ();

	p11_test (test_initialize_finalize, "/managed/test_initialize_finalize");
	p11_test (test_initialize_fail, "/managed/test_initialize_fail");
	p11_test (test_separate_close_all_sessions, "/managed/test_separate_close_all_sessions");
	p11_test (test_max_session_load, "/managed/test_max_session_load");

#ifdef OS_UNIX
	p11_test (test_fork_and_reinitialize, "/managed/fork-and-reinitialize");
#endif

	test_mock_add_tests ("/managed", NULL);

	p11_kit_be_quiet ();

	return p11_test_run (argc, argv);
}
