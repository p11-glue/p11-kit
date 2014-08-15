/*
 * Copyright (c) 2011, Collabora Ltd.
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

#define P11_KIT_NO_DEPRECATIONS

#include "config.h"
#include "test.h"

#include "dict.h"
#include "library.h"
#include "p11-kit.h"
#include "private.h"
#include "mock.h"

#include <sys/types.h>

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static CK_FUNCTION_LIST_PTR_PTR
initialize_and_get_modules (void)
{
	CK_FUNCTION_LIST_PTR_PTR modules;
	CK_RV rv;

	rv = p11_kit_initialize_registered ();
	assert_num_eq (CKR_OK, rv);
	modules = p11_kit_registered_modules ();
	assert (modules != NULL && modules[0] != NULL);

	return modules;
}

static void
finalize_and_free_modules (CK_FUNCTION_LIST_PTR_PTR modules)
{
	CK_RV rv;

	free (modules);
	rv = p11_kit_finalize_registered ();
	assert_num_eq (CKR_OK, rv);

}

static void
test_no_duplicates (void)
{
	CK_FUNCTION_LIST_PTR_PTR modules;
	p11_dict *paths;
	p11_dict *funcs;
	char *path;
	int i;

	modules = initialize_and_get_modules ();
	paths = p11_dict_new (p11_dict_str_hash, p11_dict_str_equal, NULL, NULL);
	funcs = p11_dict_new (p11_dict_direct_hash, p11_dict_direct_equal, NULL, NULL);

	/* The loaded modules should not contain duplicates */
	for (i = 0; modules[i] != NULL; i++) {
		path = p11_kit_registered_option (modules[i], "module");

		if (p11_dict_get (funcs, modules[i]))
			assert_fail ("found duplicate function list pointer", NULL);
		if (p11_dict_get (paths, path))
			assert_fail ("found duplicate path name", NULL);

		if (!p11_dict_set (funcs, modules[i], ""))
			assert_not_reached ();
		if (!p11_dict_set (paths, path, ""))
			assert_not_reached ();

		free (path);
	}

	p11_dict_free (paths);
	p11_dict_free (funcs);
	finalize_and_free_modules (modules);
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
		module_name = p11_kit_registered_module_to_name (modules[i]);
		assert_ptr_not_null (module_name);
		if (strcmp (module_name, name) == 0)
			match = modules[i];
		free (module_name);
	}

	/*
	 * As a side effect, we should check that the results of this function
	 * matches the above search.
	 */
	module = p11_kit_registered_name_to_module (name);
	if (module != match)
		assert_fail ("different result from p11_kit_registered_name_to_module()", NULL);

	return match;
}

static void
test_disable (void)
{
	CK_FUNCTION_LIST_PTR_PTR modules;

	/*
	 * The module four should be present, as we don't match any prognames
	 * that it has disabled.
	 */

	modules = initialize_and_get_modules ();
	assert (lookup_module_with_name (modules, "four") != NULL);
	finalize_and_free_modules (modules);

	/*
	 * The module two shouldn't have been loaded, because in its config
	 * file we have:
	 *
	 * disable-in: test-disable
	 */

	p11_kit_set_progname ("test-disable");

	modules = initialize_and_get_modules ();
	assert (lookup_module_with_name (modules, "four") == NULL);
	finalize_and_free_modules (modules);

	p11_kit_set_progname (NULL);
}

static void
test_disable_later (void)
{
	CK_FUNCTION_LIST_PTR_PTR modules;
	CK_RV rv;

	/*
	 * The module two shouldn't be matched, because in its config
	 * file we have:
	 *
	 * disable-in: test-disable
	 */

	rv = p11_kit_initialize_registered ();
	assert_num_eq (CKR_OK, rv);

	p11_kit_set_progname ("test-disable");

	modules = p11_kit_registered_modules ();
	assert (modules != NULL && modules[0] != NULL);

	assert (lookup_module_with_name (modules, "two") == NULL);
	finalize_and_free_modules (modules);

	p11_kit_set_progname (NULL);
}

static void
test_enable (void)
{
	CK_FUNCTION_LIST_PTR_PTR modules;

	/*
	 * The module three should not be present, as we don't match the current
	 * program.
	 */

	modules = initialize_and_get_modules ();
	assert (lookup_module_with_name (modules, "three") == NULL);
	finalize_and_free_modules (modules);

	/*
	 * The module three should be loaded here , because in its config
	 * file we have:
	 *
	 * enable-in: test-enable
	 */

	p11_kit_set_progname ("test-enable");

	modules = initialize_and_get_modules ();
	assert (lookup_module_with_name (modules, "three") != NULL);
	finalize_and_free_modules (modules);

	p11_kit_set_progname (NULL);
}

CK_FUNCTION_LIST module;

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
	CK_RV rv;

	assert (!mock_module_initialized ());

	/* Build up our own function list */
	memcpy (&module, &mock_module_no_slots, sizeof (CK_FUNCTION_LIST));
	module.C_Initialize = mock_C_Initialize__with_fork;

	rv = p11_kit_initialize_module (&module);
	assert (rv == CKR_OK);

	rv = p11_kit_finalize_module (&module);
	assert (rv == CKR_OK);

	assert (!mock_module_initialized ());
}

#endif /* OS_UNIX */

static CK_RV
mock_C_Initialize__with_recursive (CK_VOID_PTR init_args)
{
	/* Recursively initialize, this is broken */
	return p11_kit_initialize_module (&module);
}

static void
test_recursive_initialization (void)
{
	CK_RV rv;

	assert (!mock_module_initialized ());

	/* Build up our own function list */
	memcpy (&module, &mock_module_no_slots, sizeof (CK_FUNCTION_LIST));
	module.C_Initialize = mock_C_Initialize__with_recursive;

	rv = p11_kit_initialize_module (&module);
	assert (rv == CKR_FUNCTION_FAILED);

	assert (!mock_module_initialized ());
}

static p11_mutex_t race_mutex;
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
	CK_RV rv;

	assert_str_eq (data, "thread-data");
	rv = p11_kit_initialize_module (&module);
	assert (rv == CKR_OK);

	return "thread-data";
}

static void *
finalization_thread (void *data)
{
	CK_RV rv;

	assert_str_eq (data, "thread-data");
	rv = p11_kit_finalize_module (&module);
	assert (rv == CKR_OK);

	return "thread-data";
}

static void
test_threaded_initialization (void)
{
	static const int num_threads = 2;
	p11_thread_t threads[num_threads];
	int ret;
	int i;

	assert (!mock_module_initialized ());

	/* Build up our own function list */
	memcpy (&module, &mock_module_no_slots, sizeof (CK_FUNCTION_LIST));
	module.C_Initialize = mock_C_Initialize__threaded_race;
	module.C_Finalize = mock_C_Finalize__threaded_race;

	p11_mutex_lock (&race_mutex);
	initialization_count = 0;
	finalization_count = 0;
	p11_mutex_unlock (&race_mutex);

	for (i = 0; i < num_threads; i++) {
		ret = p11_thread_create (&threads[i], initialization_thread, "thread-data");
		assert_num_eq (0, ret);
		assert (threads[i] != 0);
	}

	for (i = 0; i < num_threads; i++) {
		ret = p11_thread_join (threads[i]);
		assert_num_eq (0, ret);
		threads[i] = 0;
	}

	for (i = 0; i < num_threads; i++) {
		ret = p11_thread_create (&threads[i], finalization_thread, "thread-data");
		assert_num_eq (0, ret);
		assert (threads[i] != 0);
	}

	for (i = 0; i < num_threads; i++) {
		ret = p11_thread_join (threads[i]);
		assert_num_eq (0, ret);
		threads[i] = 0;
	}

	/* C_Initialize should have been called exactly once */
	p11_mutex_lock (&race_mutex);
	assert_num_eq (1, initialization_count);
	assert_num_eq (1, finalization_count);
	p11_mutex_unlock (&race_mutex);

	assert (!mock_module_initialized ());
}

static CK_RV
mock_C_Initialize__test_mutexes (CK_VOID_PTR args)
{
	CK_C_INITIALIZE_ARGS_PTR init_args;
	void *mutex = NULL;
	CK_RV rv;

	rv = mock_C_Initialize (NULL);
	if (rv != CKR_OK)
		return rv;

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
	CK_RV rv;

	assert (!mock_module_initialized ());

	/* Build up our own function list */
	memcpy (&module, &mock_module_no_slots, sizeof (CK_FUNCTION_LIST));
	module.C_Initialize = mock_C_Initialize__test_mutexes;

	rv = p11_kit_initialize_module (&module);
	assert (rv == CKR_OK);

	rv = p11_kit_finalize_module (&module);
	assert (rv == CKR_OK);

	assert (!mock_module_initialized ());
}

static void
test_load_and_initialize (void)
{
	CK_FUNCTION_LIST_PTR module;
	CK_INFO info;
	CK_RV rv;
	int ret;

	rv = p11_kit_load_initialize_module (BUILDDIR "/.libs/mock-one" SHLEXT, &module);
	assert (rv == CKR_OK);
	assert (module != NULL);

	rv = (module->C_GetInfo) (&info);
	assert (rv == CKR_OK);

	ret = memcmp (info.manufacturerID, "MOCK MANUFACTURER               ", 32);
	assert (ret == 0);

	rv = p11_kit_finalize_module (module);
	assert_num_eq (rv, CKR_OK);
}

int
main (int argc,
      char *argv[])
{
	p11_mutex_init (&race_mutex);
	mock_module_init ();
	p11_library_init ();

	p11_test (test_no_duplicates, "/deprecated/test_no_duplicates");
	p11_test (test_disable, "/deprecated/test_disable");
	p11_test (test_disable_later, "/deprecated/test_disable_later");
	p11_test (test_enable, "/deprecated/test_enable");

#ifdef OS_UNIX
	p11_test (test_fork_initialization, "/deprecated/test_fork_initialization");
#endif

	p11_test (test_recursive_initialization, "/deprecated/test_recursive_initialization");
	p11_test (test_threaded_initialization, "/deprecated/test_threaded_initialization");
	p11_test (test_mutexes, "/deprecated/test_mutexes");
	p11_test (test_load_and_initialize, "/deprecated/test_load_and_initialize");

	p11_kit_be_quiet ();

	return p11_test_run (argc, argv);
}
