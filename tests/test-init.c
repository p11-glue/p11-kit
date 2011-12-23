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
#include "CuTest.h"

#include <sys/types.h>

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "p11-kit/compat.h"
#include "p11-kit/p11-kit.h"

#include "mock-module.h"

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
test_fork_initialization (CuTest *tc)
{
	CK_RV rv;

	/* Build up our own function list */
	memcpy (&module, &mock_module_no_slots, sizeof (CK_FUNCTION_LIST));
	module.C_Initialize = mock_C_Initialize__with_fork;

	rv = p11_kit_initialize_module (&module);
	CuAssertTrue (tc, rv == CKR_OK);

	rv = p11_kit_finalize_module (&module);
	CuAssertTrue (tc, rv == CKR_OK);
}

#endif /* OS_UNIX */

static CK_RV
mock_C_Initialize__with_recursive (CK_VOID_PTR init_args)
{
	CK_RV rv;

	rv = mock_C_Initialize (init_args);
	assert (rv == CKR_OK);

	/* Recursively initialize, this is broken */
	return p11_kit_initialize_module (&module);
}

static void
test_recursive_initialization (CuTest *tc)
{
	CK_RV rv;

	/* Build up our own function list */
	memcpy (&module, &mock_module_no_slots, sizeof (CK_FUNCTION_LIST));
	module.C_Initialize = mock_C_Initialize__with_recursive;

	rv = p11_kit_initialize_module (&module);
	CuAssertTrue (tc, rv == CKR_FUNCTION_FAILED);
}

static mutex_t race_mutex;
static int initialization_count = 0;
static int finalization_count = 0;

#include "private.h"

static CK_RV
mock_C_Initialize__threaded_race (CK_VOID_PTR init_args)
{
	/* Atomically increment value */
	_p11_mutex_lock (&race_mutex);
	initialization_count += 1;
	_p11_mutex_unlock (&race_mutex);

	_p11_sleep_ms (100);
	return CKR_OK;
}

static CK_RV
mock_C_Finalize__threaded_race (CK_VOID_PTR reserved)
{
	/* Atomically increment value */
	_p11_mutex_lock (&race_mutex);
	finalization_count += 1;
	_p11_mutex_unlock (&race_mutex);

	_p11_sleep_ms (100);
	return CKR_OK;}

static void *
initialization_thread (void *data)
{
	CuTest *tc = data;
	CK_RV rv;

	rv = p11_kit_initialize_module (&module);
	CuAssertTrue (tc, rv == CKR_OK);

	return tc;
}

static void *
finalization_thread (void *data)
{
	CuTest *tc = data;
	CK_RV rv;

	rv = p11_kit_finalize_module (&module);
	CuAssertTrue (tc, rv == CKR_OK);

	return tc;
}

static void
test_threaded_initialization (CuTest *tc)
{
	static const int num_threads = 2;
	thread_t threads[num_threads];
	int ret;
	int i;

	/* Build up our own function list */
	memcpy (&module, &mock_module_no_slots, sizeof (CK_FUNCTION_LIST));
	module.C_Initialize = mock_C_Initialize__threaded_race;
	module.C_Finalize = mock_C_Finalize__threaded_race;

	initialization_count = 0;
	finalization_count = 0;

	for (i = 0; i < num_threads; i++) {
		ret = _p11_thread_create (&threads[i], initialization_thread, tc);
		CuAssertIntEquals (tc, 0, ret);
		CuAssertTrue (tc, threads[i] != 0);
	}

	for (i = 0; i < num_threads; i++) {
		ret = _p11_thread_join (threads[i]);
		CuAssertIntEquals (tc, 0, ret);
		threads[i] = 0;
	}

	for (i = 0; i < num_threads; i++) {
		ret = _p11_thread_create (&threads[i], finalization_thread, tc);
		CuAssertIntEquals (tc, 0, ret);
		CuAssertTrue (tc, threads[i] != 0);
	}

	for (i = 0; i < num_threads; i++) {
		ret = _p11_thread_join (threads[i]);
		CuAssertIntEquals (tc, 0, ret);
		threads[i] = 0;
	}

	/* C_Initialize should have been called exactly once */
	CuAssertIntEquals (tc, 1, initialization_count);
	CuAssertIntEquals (tc, 1, finalization_count);
}

int
main (void)
{
	CuString *output = CuStringNew ();
	CuSuite* suite = CuSuiteNew ();
	int ret;

	_p11_mutex_init (&race_mutex);
	mock_module_init ();
	_p11_library_init ();

#ifdef OS_UNIX
	SUITE_ADD_TEST (suite, test_fork_initialization);
#endif

	SUITE_ADD_TEST (suite, test_recursive_initialization);
	SUITE_ADD_TEST (suite, test_threaded_initialization);

	CuSuiteRun (suite);
	CuSuiteSummary (suite, output);
	CuSuiteDetails (suite, output);
	printf ("%s\n", output->buffer);
	ret = suite->failCount;
	CuSuiteDelete (suite);
	CuStringDelete (output);

	return ret;
}
