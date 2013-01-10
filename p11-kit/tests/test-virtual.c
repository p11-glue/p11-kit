/*
 * Copyright (c) 2012 Stefan Walter
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
 * Author: Stef Walter <stef@thewalter.net>
 */

#include "config.h"

#include "library.h"
#include "p11-kit.h"
#include "private.h"
#include "virtual.h"

#include "CuTest.h"

#include "mock.h"

#include <sys/types.h>
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/*
 * test-managed.c is a pretty good test of the closure code, so we
 * just test a few things here.
 */

typedef struct {
	p11_virtual virt;
	CuTest *cu;
} Override;

static CK_RV
override_initialize (CK_X_FUNCTION_LIST *self,
                     CK_VOID_PTR args)
{
	Override *over = (Override *)self;

	/* We're using CuTest both as closure and as C_Initialize arg */
	CuAssertPtrEquals (over->cu, over->cu, args);

	/* An arbitrary error code to check */
	return CKR_NEED_TO_CREATE_THREADS;
}

static bool test_destroyed = false;

static void
test_destroyer (void *data)
{
	assert (data == &mock_x_module_no_slots);
	assert (test_destroyed == false);
	test_destroyed = true;
}

static void
test_initialize (CuTest *tc)
{
	CK_FUNCTION_LIST_PTR module;
	Override over = { };
	CK_RV rv;

	p11_virtual_init (&over.virt, &p11_virtual_stack, &mock_x_module_no_slots, test_destroyer);
	over.virt.funcs.C_Initialize = override_initialize;
	over.cu = tc;
	test_destroyed = false;

	module = p11_virtual_wrap (&over.virt, (p11_destroyer)p11_virtual_uninit);
	CuAssertPtrNotNull (tc, module);

	rv = (module->C_Initialize) (tc);
	CuAssertIntEquals (tc, CKR_NEED_TO_CREATE_THREADS, rv);

	p11_virtual_unwrap (module);
	CuAssertIntEquals (tc, true, test_destroyed);
}

static void
test_fall_through (CuTest *tc)
{
	CK_FUNCTION_LIST_PTR module;
	Override over = { };
	p11_virtual base;
	CK_RV rv;

	p11_virtual_init (&base, &p11_virtual_base, &mock_module_no_slots, NULL);
	p11_virtual_init (&over.virt, &p11_virtual_stack, &base, NULL);
	over.virt.funcs.C_Initialize = override_initialize;
	over.cu = tc;

	module = p11_virtual_wrap (&over.virt, NULL);
	CuAssertPtrNotNull (tc, module);

	rv = (module->C_Initialize) (tc);
	CuAssertIntEquals (tc, CKR_NEED_TO_CREATE_THREADS, rv);

	/* All other functiosn should have just fallen through */
	CuAssertPtrEquals (tc, mock_module_no_slots.C_Finalize, module->C_Finalize);

	p11_virtual_unwrap (module);
}

static void
test_get_function_list (CuTest *tc)
{
	CK_FUNCTION_LIST_PTR module;
	CK_FUNCTION_LIST_PTR list;
	p11_virtual virt;
	CK_RV rv;

	p11_virtual_init (&virt, &p11_virtual_base, &mock_x_module_no_slots, NULL);
	module = p11_virtual_wrap (&virt, NULL);
	CuAssertPtrNotNull (tc, module);

	rv = (module->C_GetFunctionList) (&list);
	CuAssertIntEquals (tc, CKR_OK, rv);
	CuAssertPtrEquals (tc, module, list);

	rv = (module->C_GetFunctionList) (&list);
	CuAssertIntEquals (tc, CKR_OK, rv);

	rv = (module->C_GetFunctionList) (NULL);
	CuAssertIntEquals (tc, CKR_ARGUMENTS_BAD, rv);

	p11_virtual_unwrap (module);
}

int
main (void)
{
	CuString *output = CuStringNew ();
	CuSuite* suite = CuSuiteNew ();
	int ret;

	putenv ("P11_KIT_STRICT=1");
	mock_module_init ();
	p11_library_init ();

	assert (p11_virtual_can_wrap ());
	SUITE_ADD_TEST (suite, test_initialize);
	SUITE_ADD_TEST (suite, test_fall_through);
	SUITE_ADD_TEST (suite, test_get_function_list);

	CuSuiteRun (suite);
	CuSuiteSummary (suite, output);
	CuSuiteDetails (suite, output);
	printf ("%s\n", output->buffer);
	ret = suite->failCount;
	CuSuiteDelete (suite);
	CuStringDelete (output);

	return ret;
}
