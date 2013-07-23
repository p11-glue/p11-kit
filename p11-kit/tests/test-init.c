/*
 * Copyright (c) 2011, Collabora Ltd.
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

#include <sys/types.h>

#include "library.h"
#include "mock.h"
#include "modules.h"
#include "p11-kit.h"
#include "private.h"
#include "virtual.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static CK_FUNCTION_LIST module;
static p11_mutex_t race_mutex;

#ifdef OS_UNIX

#include <sys/wait.h>

static CK_RV
mock_C_Initialize__with_fork (CK_VOID_PTR init_args)
{
	struct timespec ts = { 0, 100 * 1000 * 1000 };
	CK_RV rv;
	pid_t child;
	pid_t ret;
	int status;

	rv = mock_C_Initialize (init_args);
	assert (rv == CKR_OK);

	/* Fork during the initialization */
	child = fork ();
	if (child == 0) {
		close (1);
		nanosleep (&ts, NULL);
		exit (66);
	}

	ret = waitpid (child, &status, 0);
	assert (ret == child);
	assert (WIFEXITED (status));
	assert (WEXITSTATUS (status) == 66);

	return CKR_OK;
}

static void
test_fork_initialization (void)
{
	CK_FUNCTION_LIST_PTR result;
	CK_RV rv;

	mock_module_reset ();

	/* Build up our own function list */
	memcpy (&module, &mock_module_no_slots, sizeof (CK_FUNCTION_LIST));
	module.C_Initialize = mock_C_Initialize__with_fork;

	p11_lock ();

	rv = p11_module_load_inlock_reentrant (&module, 0, &result);
	assert (rv == CKR_OK);

	p11_unlock ();

	rv = p11_kit_module_initialize (result);
	assert (rv == CKR_OK);

	rv = p11_kit_module_finalize (result);
	assert (rv == CKR_OK);

	p11_lock ();

	rv = p11_module_release_inlock_reentrant (result);
	assert (rv == CKR_OK);

	p11_unlock ();
}

#endif /* OS_UNIX */

static CK_FUNCTION_LIST *recursive_managed;

static CK_RV
mock_C_Initialize__with_recursive (CK_VOID_PTR init_args)
{
	CK_RV rv;

	rv = mock_C_Initialize (init_args);
	assert (rv == CKR_OK);

	return p11_kit_module_initialize (recursive_managed);
}

static void
test_recursive_initialization (void)
{
	CK_RV rv;

	/* Build up our own function list */
	memcpy (&module, &mock_module_no_slots, sizeof (CK_FUNCTION_LIST));
	module.C_Initialize = mock_C_Initialize__with_recursive;

	p11_kit_be_quiet ();

	p11_lock ();

	rv = p11_module_load_inlock_reentrant (&module, 0, &recursive_managed);
	assert (rv == CKR_OK);

	p11_unlock ();

	rv = p11_kit_module_initialize (recursive_managed);
	assert_num_eq (CKR_FUNCTION_FAILED, rv);

	p11_lock ();

	rv = p11_module_release_inlock_reentrant (recursive_managed);
	assert (rv == CKR_OK);

	p11_unlock ();

	p11_kit_be_loud ();
}

static int initialization_count = 0;
static int finalization_count = 0;

static CK_RV
mock_C_Initialize__threaded_race (CK_VOID_PTR init_args)
{
	/* Atomically increment value */
	p11_mutex_lock (&race_mutex);
	initialization_count += 1;
	p11_mutex_unlock (&race_mutex);

	p11_sleep_ms (100);
	return CKR_OK;
}

static CK_RV
mock_C_Finalize__threaded_race (CK_VOID_PTR reserved)
{
	/* Atomically increment value */
	p11_mutex_lock (&race_mutex);
	finalization_count += 1;
	p11_mutex_unlock (&race_mutex);

	p11_sleep_ms (100);
	return CKR_OK;
}

static void *
initialization_thread (void *data)
{
	CK_FUNCTION_LIST *module = data;
	CK_RV rv;

	assert (module != NULL);
	rv = p11_kit_module_initialize (module);
	assert_num_eq (rv, CKR_OK);

	return module;
}

static void *
finalization_thread (void *data)
{
	CK_FUNCTION_LIST *module = data;
	CK_RV rv;

	assert (module != NULL);
	rv = p11_kit_module_finalize (module);
	assert_num_eq (rv, CKR_OK);

	return module;
}

static void
test_threaded_initialization (void)
{
	static const int num_threads = 1;
	CK_FUNCTION_LIST *data[num_threads];
	p11_thread_t threads[num_threads];
	CK_RV rv;
	int ret;
	int i;

	/* Build up our own function list */
	memcpy (&module, &mock_module_no_slots, sizeof (CK_FUNCTION_LIST));
	module.C_Initialize = mock_C_Initialize__threaded_race;
	module.C_Finalize = mock_C_Finalize__threaded_race;

	memset (&data, 0, sizeof (data));

	p11_mutex_lock (&race_mutex);
	initialization_count = 0;
	finalization_count = 0;
	p11_mutex_unlock (&race_mutex);

	p11_lock ();

	for (i = 0; i < num_threads; i++) {
		assert (data[i] == NULL);
		rv = p11_module_load_inlock_reentrant (&module, 0, &data[i]);
		assert (rv == CKR_OK);
	}

	p11_unlock ();

	for (i = 0; i < num_threads; i++) {
		ret = p11_thread_create (&threads[i], initialization_thread, data[i]);
		assert_num_eq (0, ret);
		assert (threads[i] != 0);
	}

	for (i = 0; i < num_threads; i++) {
		ret = p11_thread_join (threads[i]);
		assert_num_eq (0, ret);
		threads[i] = 0;
	}

	for (i = 0; i < num_threads; i++) {
		ret = p11_thread_create (&threads[i], finalization_thread, data[i]);
		assert_num_eq (0, ret);
		assert (threads[i] != 0);
	}

	for (i = 0; i < num_threads; i++) {
		ret = p11_thread_join (threads[i]);
		assert_num_eq (0, ret);
		threads[i] = 0;
	}

	p11_lock ();

	for (i = 0; i < num_threads; i++) {
		assert (data[i] != NULL);
		rv = p11_module_release_inlock_reentrant (data[i]);
		assert (rv == CKR_OK);
	}

	p11_unlock ();

	/* C_Initialize should have been called exactly once */
	assert_num_eq (1, initialization_count);
	assert_num_eq (1, finalization_count);
}

static CK_RV
mock_C_Initialize__test_mutexes (CK_VOID_PTR args)
{
	CK_C_INITIALIZE_ARGS_PTR init_args;
	void *mutex = NULL;
	CK_RV rv;

	assert (args != NULL);
	init_args = args;

	rv = (init_args->CreateMutex) (&mutex);
	assert (rv == CKR_OK);

	rv = (init_args->LockMutex) (mutex);
	assert (rv == CKR_OK);

	rv = (init_args->UnlockMutex) (mutex);
	assert (rv == CKR_OK);

	rv = (init_args->DestroyMutex) (mutex);
	assert (rv == CKR_OK);

	return CKR_OK;
}

static void
test_mutexes (void)
{
	CK_FUNCTION_LIST_PTR result;
	CK_RV rv;

	/* Build up our own function list */
	memcpy (&module, &mock_module_no_slots, sizeof (CK_FUNCTION_LIST));
	module.C_Initialize = mock_C_Initialize__test_mutexes;

	p11_lock ();

	rv = p11_module_load_inlock_reentrant (&module, 0, &result);
	assert (rv == CKR_OK);

	rv = p11_module_release_inlock_reentrant (result);
	assert (rv == CKR_OK);

	p11_unlock ();
}

static void
test_load_and_initialize (void)
{
	CK_FUNCTION_LIST_PTR module;
	CK_INFO info;
	CK_RV rv;
	int ret;

	module = p11_kit_module_load (BUILDDIR "/.libs/mock-one" SHLEXT, 0);
	assert (module != NULL);

	rv = p11_kit_module_initialize (module);
	assert (rv == CKR_OK);

	rv = (module->C_GetInfo) (&info);
	assert (rv == CKR_OK);

	ret = memcmp (info.manufacturerID, "MOCK MANUFACTURER               ", 32);
	assert (ret == 0);

	rv = p11_kit_module_finalize (module);
	assert (rv == CKR_OK);

	p11_kit_module_release (module);
}

static void
test_initalize_fail (void)
{
	CK_FUNCTION_LIST failer;
	CK_FUNCTION_LIST *modules[3] = { &mock_module_no_slots, &failer, NULL };
	CK_RV rv;

	memcpy (&failer, &mock_module, sizeof (CK_FUNCTION_LIST));
	failer.C_Initialize = mock_C_Initialize__fails;

	mock_module_reset ();
	p11_kit_be_quiet ();

	rv = p11_kit_modules_initialize (modules, NULL);
	assert_num_eq (CKR_FUNCTION_FAILED, rv);

	p11_kit_be_loud ();

	/* Failed modules get removed from the list */
	assert_ptr_eq (&mock_module_no_slots, modules[0]);
	assert_ptr_eq (NULL, modules[1]);
	assert_ptr_eq (NULL, modules[2]);

	p11_kit_modules_finalize (modules);
}

static void
test_finalize_fail (void)
{

}

int
main (int argc,
      char *argv[])
{
	p11_mutex_init (&race_mutex);
	mock_module_init ();
	p11_library_init ();

	/* These only work when managed */
	if (p11_virtual_can_wrap ()) {
		p11_test (test_recursive_initialization, "/init/test_recursive_initialization");
		p11_test (test_threaded_initialization, "/init/test_threaded_initialization");
		p11_test (test_mutexes, "/init/test_mutexes");
		p11_test (test_load_and_initialize, "/init/test_load_and_initialize");

#ifdef OS_UNIX
		p11_test (test_fork_initialization, "/init/test_fork_initialization");
#endif
	}

	p11_test (test_initalize_fail, "/init/test_initalize_fail");
	p11_test (test_finalize_fail, "/init/test_finalize_fail");

	return p11_test_run (argc, argv);
}
