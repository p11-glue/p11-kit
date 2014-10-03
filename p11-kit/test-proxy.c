/*
 * Copyright (c) 2013 Red Hat Inc
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

#define CRYPTOKI_EXPORTS

#include "config.h"
#include "test.h"

#include "library.h"
#include "mock.h"
#include "p11-kit.h"
#include "pkcs11.h"
#include "proxy.h"

#include <sys/types.h>

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* This is the proxy module entry point in proxy.c, and linked to this test */
CK_RV C_GetFunctionList (CK_FUNCTION_LIST_PTR_PTR list);

static CK_SLOT_ID mock_slot_one_id;
static CK_SLOT_ID mock_slot_two_id;
static CK_ULONG mock_slots_present;
static CK_ULONG mock_slots_all;

static void
test_initialize_finalize (void)
{
	CK_FUNCTION_LIST_PTR proxy;
	CK_RV rv;

	rv = C_GetFunctionList (&proxy);
	assert (rv == CKR_OK);

	assert (p11_proxy_module_check (proxy));

	rv = proxy->C_Initialize (NULL);
	assert (rv == CKR_OK);

	rv = proxy->C_Finalize (NULL);
	assert_num_eq (rv, CKR_OK);

	p11_proxy_module_cleanup ();
}

static void
test_initialize_multiple (void)
{
	CK_FUNCTION_LIST_PTR proxy;
	CK_RV rv;

	rv = C_GetFunctionList (&proxy);
	assert (rv == CKR_OK);

	assert (p11_proxy_module_check (proxy));

	rv = proxy->C_Initialize (NULL);
	assert (rv == CKR_OK);

	rv = proxy->C_Initialize (NULL);
	assert (rv == CKR_OK);

	rv = proxy->C_Finalize (NULL);
	assert (rv == CKR_OK);

	rv = proxy->C_Finalize (NULL);
	assert (rv == CKR_OK);

	rv = proxy->C_Finalize (NULL);
	assert (rv == CKR_CRYPTOKI_NOT_INITIALIZED);

	p11_proxy_module_cleanup ();
}

static CK_FUNCTION_LIST_PTR
setup_mock_module (CK_SESSION_HANDLE *session)
{
	CK_FUNCTION_LIST_PTR proxy;
	CK_SLOT_ID slots[32];
	CK_RV rv;

	rv = C_GetFunctionList (&proxy);
	assert (rv == CKR_OK);

	assert (p11_proxy_module_check (proxy));

	rv = proxy->C_Initialize (NULL);
	assert (rv == CKR_OK);

	mock_slots_all = 32;
	rv = proxy->C_GetSlotList (CK_FALSE, slots, &mock_slots_all);
	assert (rv == CKR_OK);
	assert (mock_slots_all >= 2);

	/* Assume this is the slot we want to deal with */
	mock_slot_one_id = slots[0];
	mock_slot_two_id = slots[1];

	rv = proxy->C_GetSlotList (CK_TRUE, NULL, &mock_slots_present);
	assert (rv == CKR_OK);
	assert (mock_slots_present > 1);

	if (session) {
		rv = (proxy->C_OpenSession) (mock_slot_one_id,
		                             CKF_RW_SESSION | CKF_SERIAL_SESSION,
		                             NULL, NULL, session);
		assert (rv == CKR_OK);
	}

	return proxy;
}

static void
teardown_mock_module (CK_FUNCTION_LIST_PTR module)
{
	CK_RV rv;

	rv = module->C_Finalize (NULL);
	assert (rv == CKR_OK);
}

/*
 * We redefine the mock module slot id so that the tests in test-mock.c
 * use the proxy mapped slot id rather than the hard coded one
 */
#define MOCK_SLOT_ONE_ID mock_slot_one_id
#define MOCK_SLOT_TWO_ID mock_slot_two_id
#define MOCK_SLOTS_PRESENT mock_slots_present
#define MOCK_SLOTS_ALL mock_slots_all
#define MOCK_INFO mock_info
#define MOCK_SKIP_WAIT_TEST

static const CK_INFO mock_info = {
	{ CRYPTOKI_VERSION_MAJOR, CRYPTOKI_VERSION_MINOR },
	"PKCS#11 Kit                     ",
	0,
	"PKCS#11 Kit Proxy Module        ",
	{ 1, 1 }
};

/* Bring in all the mock module tests */
#include "test-mock.c"

int
main (int argc,
      char *argv[])
{
	p11_library_init ();
	p11_kit_be_quiet ();

	p11_test (test_initialize_finalize, "/proxy/initialize-finalize");
	p11_test (test_initialize_multiple, "/proxy/initialize-multiple");

	test_mock_add_tests ("/proxy");

	return p11_test_run (argc, argv);
}
