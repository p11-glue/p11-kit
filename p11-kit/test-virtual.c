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

#include "test.h"

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
	void *check;
} Override;

static CK_RV
override_initialize (CK_X_FUNCTION_LIST *self,
                     CK_VOID_PTR args)
{
	Override *over = (Override *)self;

	assert_str_eq ("initialize-arg", args);
	assert_str_eq ("overide-arg", over->check);

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
test_initialize (void)
{
	CK_FUNCTION_LIST_PTR module;
	Override over = { };
	CK_RV rv;

	p11_virtual_init (&over.virt, &p11_virtual_stack, &mock_x_module_no_slots, test_destroyer);
	over.virt.funcs.C_Initialize = override_initialize;
	over.check = "overide-arg";
	test_destroyed = false;

	module = p11_virtual_wrap (&over.virt, (p11_destroyer)p11_virtual_uninit);
	assert_ptr_not_null (module);

	rv = (module->C_Initialize) ("initialize-arg");
	assert_num_eq (CKR_NEED_TO_CREATE_THREADS, rv);

	p11_virtual_unwrap (module);
	assert_num_eq (true, test_destroyed);
}

static void
test_fall_through (void)
{
	CK_FUNCTION_LIST_PTR module;
	Override over = { };
	p11_virtual base;
	CK_RV rv;

	p11_virtual_init (&base, &p11_virtual_base, &mock_module_no_slots, NULL);
	p11_virtual_init (&over.virt, &p11_virtual_stack, &base, NULL);
	over.virt.funcs.C_Initialize = override_initialize;
	over.check = "overide-arg";

	module = p11_virtual_wrap (&over.virt, NULL);
	assert_ptr_not_null (module);

	rv = (module->C_Initialize) ("initialize-arg");
	assert_num_eq (CKR_NEED_TO_CREATE_THREADS, rv);

	/* All other functions should have just fallen through */
	assert_ptr_eq (mock_module_no_slots.C_Finalize, module->C_Finalize);

	p11_virtual_unwrap (module);
}

static void
test_get_function_list (void)
{
	CK_FUNCTION_LIST_PTR module;
	CK_FUNCTION_LIST_PTR list;
	p11_virtual virt;
	CK_RV rv;

	p11_virtual_init (&virt, &p11_virtual_base, &mock_module_no_slots, NULL);
	module = p11_virtual_wrap (&virt, NULL);
	assert_ptr_not_null (module);

	rv = (module->C_GetFunctionList) (&list);
	assert_num_eq (CKR_OK, rv);
	assert_ptr_eq (module, list);

	rv = (module->C_GetFunctionList) (&list);
	assert_num_eq (CKR_OK, rv);

	rv = (module->C_GetFunctionList) (NULL);
	assert_num_eq (CKR_ARGUMENTS_BAD, rv);

	p11_virtual_unwrap (module);
}

static void
test_get_interface (void)
{
	CK_FUNCTION_LIST_3_0_PTR module;
	CK_VERSION version = {3, 0};
	CK_INTERFACE_PTR list;
	CK_INTERFACE_PTR interface;
	CK_ULONG count;
	p11_virtual virt;
	CK_RV rv;

	p11_virtual_init (&virt, &p11_virtual_base, &mock_module_v3_no_slots, NULL);
	module = (CK_FUNCTION_LIST_3_0_PTR)p11_virtual_wrap_version (&virt, NULL, &version);
	assert_ptr_not_null (module);

	rv = (module->C_GetInterface) (NULL, NULL, NULL, 0);
	assert_num_eq (CKR_ARGUMENTS_BAD, rv);

	rv = (module->C_GetInterface) (NULL, NULL, &interface, 0);
	assert_num_eq (CKR_OK, rv);
	assert_ptr_eq (module, interface->pFunctionList);

	rv = (module->C_GetInterface) ((unsigned char *)"PKCS 11", NULL, &interface, 0);
	assert_num_eq (CKR_OK, rv);
	assert_ptr_eq (module, interface->pFunctionList);

	rv = (module->C_GetInterfaceList) (NULL, NULL);
	assert_num_eq (CKR_ARGUMENTS_BAD, rv);

	rv = (module->C_GetInterfaceList) (NULL, &count);
	assert_num_eq (CKR_OK, rv);

	list = malloc (sizeof(CK_INTERFACE) * count);
	assert (list != NULL);

	rv = (module->C_GetInterfaceList) (list, &count);
	assert_num_eq (CKR_OK, rv);
	assert_num_eq (count, 1);
	assert_ptr_eq (module, list[0].pFunctionList);
	assert (strcmp("PKCS 11", list[0].pInterfaceName) == 0);

	p11_virtual_unwrap ((CK_FUNCTION_LIST *)module);
}

int
main (int argc,
      char *argv[])
{
	mock_module_init ();
	p11_library_init ();

	p11_test (test_initialize, "/virtual/test_initialize");
	p11_test (test_fall_through, "/virtual/test_fall_through");
	p11_test (test_get_function_list, "/virtual/test_get_function_list");
	p11_test (test_get_interface, "/virtual/test_get_interface");

	return p11_test_run (argc, argv);
}
