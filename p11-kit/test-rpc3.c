/*
 * Copyright (c) 2012 Stefan Walter
 * Copyright (C) 2012-2022 Red Hat Inc.
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
 * Authors: Stef Walter <stef@thewalter.net>
 *          Jakub Jelen <jjelen@redhat.com>
 */

#include "config.h"
#include "test.h"

#include "debug.h"
#include "library.h"
#include "message.h"
#include "mock.h"
#include "p11-kit.h"
#include "private.h"
#include "rpc.h"
#include "rpc-message.h"
#include "virtual.h"

#include <sys/types.h>
#ifdef OS_UNIX
#include <sys/wait.h>
#endif
#include <assert.h>
#include <limits.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#ifdef OS_UNIX
#include <unistd.h>
#endif

static p11_virtual base;
static unsigned int rpc_initialized = 0;

static CK_RV
rpc_initialize (p11_rpc_client_vtable *vtable,
                void *init_reserved)
{
	assert_str_eq (vtable->data, "vtable-data");
	assert_num_cmp (p11_forkid, !=, rpc_initialized);
	rpc_initialized = p11_forkid;

	return CKR_OK;
}

static CK_RV
rpc_initialize_fails (p11_rpc_client_vtable *vtable,
                      void *init_reserved)
{
	assert_str_eq (vtable->data, "vtable-data");
	assert_num_cmp (p11_forkid, !=, rpc_initialized);
	return CKR_FUNCTION_FAILED;
}

static CK_RV
rpc_initialize_device_removed (p11_rpc_client_vtable *vtable,
                               void *init_reserved)
{
	assert_str_eq (vtable->data, "vtable-data");
	assert_num_cmp (p11_forkid, !=, rpc_initialized);
	return CKR_DEVICE_REMOVED;
}

static CK_RV
rpc_authenticate (p11_rpc_client_vtable *vtable,
		  uint8_t *version)
{
	assert_str_eq (vtable->data, "vtable-data");
	assert_ptr_not_null (version);

	return CKR_OK;
}

static CK_RV
rpc_transport (p11_rpc_client_vtable *vtable,
               p11_buffer *request,
               p11_buffer *response)
{
	bool ret;

	assert_str_eq (vtable->data, "vtable-data");

	/* Just pass directly to the server code */
	ret = p11_rpc_server_handle (&base.funcs, request, response);
	assert (ret == true);

	return CKR_OK;
}

static void
rpc_finalize (p11_rpc_client_vtable *vtable,
              void *fini_reserved)
{
	assert_str_eq (vtable->data, "vtable-data");
	assert_num_cmp (p11_forkid, ==, rpc_initialized);
	rpc_initialized = 0;
}

static void
test_initialize (void)
{
	p11_rpc_client_vtable vtable = { "vtable-data", rpc_initialize, rpc_authenticate, rpc_transport, rpc_finalize };
	p11_virtual mixin;
	bool ret;
	CK_RV rv;

	/* Build up our own function list */
	rpc_initialized = 0;
	p11_virtual_init (&base, &p11_virtual_base, &mock_module_v3_no_slots, NULL);

	ret = p11_rpc_client_init (&mixin, &vtable);
	assert_num_eq (true, ret);

	rv = mixin.funcs.C_Initialize (&mixin.funcs, NULL);
	assert (rv == CKR_OK);
	assert_num_eq (p11_forkid, rpc_initialized);

	rv = mixin.funcs.C_Finalize (&mixin.funcs, NULL);
	assert (rv == CKR_OK);
	assert_num_cmp (p11_forkid, !=, rpc_initialized);

	p11_virtual_uninit (&mixin);
}

static void
test_not_initialized (void)
{
	p11_rpc_client_vtable vtable = { "vtable-data", rpc_initialize, rpc_authenticate, rpc_transport, rpc_finalize };
	p11_virtual mixin;
	CK_INFO info;
	bool ret;
	CK_RV rv;

	/* Build up our own function list */
	rpc_initialized = 0;
	p11_virtual_init (&base, &p11_virtual_base, &mock_module_v3_no_slots, NULL);

	ret = p11_rpc_client_init (&mixin, &vtable);
	assert_num_eq (true, ret);

	rv = (mixin.funcs.C_GetInfo) (&mixin.funcs, &info);
	assert (rv == CKR_CRYPTOKI_NOT_INITIALIZED);

	p11_virtual_uninit (&mixin);
}

static void
test_initialize_fails_on_client (void)
{
	p11_rpc_client_vtable vtable = { "vtable-data", rpc_initialize_fails, rpc_authenticate, rpc_transport, rpc_finalize };
	p11_virtual mixin;
	bool ret;
	CK_RV rv;

	/* Build up our own function list */
	rpc_initialized = 0;
	p11_virtual_init (&base, &p11_virtual_base, &mock_module_v3_no_slots, NULL);

	ret = p11_rpc_client_init (&mixin, &vtable);
	assert_num_eq (true, ret);

	rv = (mixin.funcs.C_Initialize) (&mixin.funcs, NULL);
	assert (rv == CKR_FUNCTION_FAILED);
	assert_num_eq (0, rpc_initialized);

	p11_virtual_uninit (&mixin);
}

static CK_RV
rpc_transport_fails (p11_rpc_client_vtable *vtable,
                     p11_buffer *request,
                     p11_buffer *response)
{
	return CKR_FUNCTION_REJECTED;
}

static void
test_transport_fails (void)
{
	p11_rpc_client_vtable vtable = { "vtable-data", rpc_initialize, rpc_authenticate, rpc_transport_fails, rpc_finalize };
	p11_virtual mixin;
	bool ret;
	CK_RV rv;

	/* Build up our own function list */
	rpc_initialized = 0;
	p11_virtual_init (&base, &p11_virtual_base, &mock_module_v3_no_slots, NULL);

	ret = p11_rpc_client_init (&mixin, &vtable);
	assert_num_eq (true, ret);

	rv = (mixin.funcs.C_Initialize) (&mixin.funcs, NULL);
	assert (rv == CKR_FUNCTION_REJECTED);
	assert_num_eq (0, rpc_initialized);

	p11_virtual_uninit (&mixin);
}

static void
test_initialize_fails_on_server (void)
{
	p11_rpc_client_vtable vtable = { "vtable-data", rpc_initialize, rpc_authenticate, rpc_transport, rpc_finalize };
	p11_virtual mixin;
	bool ret;
	CK_RV rv;

	/* Build up our own function list */
	p11_virtual_init (&base, &p11_virtual_base, &mock_module_v3_no_slots, NULL);
	base.funcs.C_Initialize = mock_X_Initialize__fails;

	ret = p11_rpc_client_init (&mixin, &vtable);
	assert_num_eq (true, ret);

	rv = (mixin.funcs.C_Initialize) (&mixin.funcs, NULL);
	assert (rv == CKR_FUNCTION_FAILED);
	assert_num_eq (0, rpc_initialized);

	p11_virtual_uninit (&mixin);
}

static CK_RV
rpc_transport_bad_parse (p11_rpc_client_vtable *vtable,
                         p11_buffer *request,
                         p11_buffer *response)
{
	int rc;

	assert_str_eq (vtable->data, "vtable-data");

	/* Just zero bytes is an invalid message */
	rc = p11_buffer_reset (response, 2);
	assert (rc >= 0);

	memset (response->data, 0, 2);
	response->len = 2;
	return CKR_OK;
}

static void
test_transport_bad_parse (void)
{
	p11_rpc_client_vtable vtable = { "vtable-data", rpc_initialize, rpc_authenticate, rpc_transport_bad_parse, rpc_finalize };
	p11_virtual mixin;
	bool ret;
	CK_RV rv;

	/* Build up our own function list */
	rpc_initialized = 0;
	p11_virtual_init (&base, &p11_virtual_base, &mock_module_v3_no_slots, NULL);

	ret = p11_rpc_client_init (&mixin, &vtable);
	assert_num_eq (true, ret);

	p11_kit_be_quiet ();

	rv = (mixin.funcs.C_Initialize) (&mixin.funcs, NULL);
	assert (rv == CKR_DEVICE_ERROR);
	assert_num_eq (0, rpc_initialized);

	p11_message_loud ();
	p11_virtual_uninit (&mixin);
}

static CK_RV
rpc_transport_short_error (p11_rpc_client_vtable *vtable,
                           p11_buffer *request,
                           p11_buffer *response)
{
	int rc;

	unsigned char data[] = {
		0x00, 0x00, 0x00, 0x00,       /* RPC_CALL_ERROR */
		0x00, 0x00, 0x00, 0x01, 0x75, /* signature 'u' */
		0x00, 0x01,                   /* short error */
	};

	assert_str_eq (vtable->data, "vtable-data");

	rc = p11_buffer_reset (response, sizeof (data));
	assert (rc >= 0);

	memcpy (response->data, data, sizeof (data));
	response->len = sizeof (data);
	return CKR_OK;
}

static void
test_transport_short_error (void)
{
	p11_rpc_client_vtable vtable = { "vtable-data", rpc_initialize, rpc_authenticate, rpc_transport_short_error, rpc_finalize };
	p11_virtual mixin;
	bool ret;
	CK_RV rv;

	/* Build up our own function list */
	p11_virtual_init (&base, &p11_virtual_base, &mock_module_v3_no_slots, NULL);

	ret = p11_rpc_client_init (&mixin, &vtable);
	assert_num_eq (true, ret);

	p11_kit_be_quiet ();

	rv = (mixin.funcs.C_Initialize) (&mixin.funcs, NULL);
	assert (rv == CKR_DEVICE_ERROR);
	assert_num_eq (0, rpc_initialized);

	p11_message_loud ();
	p11_virtual_uninit (&mixin);
}

static CK_RV
rpc_transport_invalid_error (p11_rpc_client_vtable *vtable,
                             p11_buffer *request,
                             p11_buffer *response)
{
	int rc;

	unsigned char data[] = {
		0x00, 0x00, 0x00, 0x00,       /* RPC_CALL_ERROR */
		0x00, 0x00, 0x00, 0x01, 0x75, /* signature 'u' */
		0x00, 0x00, 0x00, 0x00,       /* a CKR_OK error*/
		0x00, 0x00, 0x00, 0x00,
	};

	assert_str_eq (vtable->data, "vtable-data");

	rc = p11_buffer_reset (response, sizeof (data));
	assert (rc >= 0);
	memcpy (response->data, data, sizeof (data));
	response->len = sizeof (data);
	return CKR_OK;
}

static void
test_transport_invalid_error (void)
{
	p11_rpc_client_vtable vtable = { "vtable-data", rpc_initialize, rpc_authenticate, rpc_transport_invalid_error, rpc_finalize };
	p11_virtual mixin;
	bool ret;
	CK_RV rv;

	/* Build up our own function list */
	p11_virtual_init (&base, &p11_virtual_base, &mock_module_v3_no_slots, NULL);

	ret = p11_rpc_client_init (&mixin, &vtable);
	assert_num_eq (true, ret);

	p11_kit_be_quiet ();

	rv = (mixin.funcs.C_Initialize) (&mixin.funcs, NULL);
	assert (rv == CKR_DEVICE_ERROR);
	assert_num_eq (0, rpc_initialized);

	p11_message_loud ();
	p11_virtual_uninit (&mixin);
}

static CK_RV
rpc_transport_wrong_response (p11_rpc_client_vtable *vtable,
                              p11_buffer *request,
                              p11_buffer *response)
{
	int rc;

	unsigned char data[] = {
		0x00, 0x00, 0x00, 0x02,       /* RPC_CALL_C_Finalize */
		0x00, 0x00, 0x00, 0x00,       /* signature '' */
	};

	assert_str_eq (vtable->data, "vtable-data");

	rc = p11_buffer_reset (response, sizeof (data));
	assert (rc >= 0);
	memcpy (response->data, data, sizeof (data));
	response->len = sizeof (data);
	return CKR_OK;
}

static void
test_transport_wrong_response (void)
{
	p11_rpc_client_vtable vtable = { "vtable-data", rpc_initialize, rpc_authenticate, rpc_transport_wrong_response, rpc_finalize };
	p11_virtual mixin;
	bool ret;
	CK_RV rv;

	/* Build up our own function list */
	p11_virtual_init (&base, &p11_virtual_base, &mock_module_v3_no_slots, NULL);

	ret = p11_rpc_client_init (&mixin, &vtable);
	assert_num_eq (true, ret);

	p11_kit_be_quiet ();

	rv = (mixin.funcs.C_Initialize) (&mixin.funcs, NULL);
	assert (rv == CKR_DEVICE_ERROR);
	assert_num_eq (0, rpc_initialized);

	p11_message_loud ();
	p11_virtual_uninit (&mixin);
}

static CK_RV
rpc_transport_bad_contents (p11_rpc_client_vtable *vtable,
                            p11_buffer *request,
                            p11_buffer *response)
{
	int rc;

	unsigned char data[] = {
		0x00, 0x00, 0x00, 0x02,       /* RPC_CALL_C_GetInfo */
		0x00, 0x00, 0x00, 0x05,       /* signature 'vsusv' */
		'v', 's', 'u', 's', 'v',
		0x00, 0x00, 0x00, 0x00,       /* invalid data */
	};

	assert_str_eq (vtable->data, "vtable-data");

	rc = p11_buffer_reset (response, sizeof (data));
	assert (rc >= 0);
	memcpy (response->data, data, sizeof (data));
	response->len = sizeof (data);
	return CKR_OK;
}

static void
test_transport_bad_contents (void)
{
	p11_rpc_client_vtable vtable = { "vtable-data", rpc_initialize, rpc_authenticate, rpc_transport_bad_contents, rpc_finalize };
	p11_virtual mixin;
	bool ret;
	CK_RV rv;

	/* Build up our own function list */
	p11_virtual_init (&base, &p11_virtual_base, &mock_module_v3_no_slots, NULL);

	ret = p11_rpc_client_init (&mixin, &vtable);
	assert_num_eq (true, ret);

	p11_kit_be_quiet ();

	rv = (mixin.funcs.C_Initialize) (&mixin.funcs, NULL);
	assert (rv == CKR_DEVICE_ERROR);
	assert_num_eq (0, rpc_initialized);

	p11_message_loud ();
	p11_virtual_uninit (&mixin);
}

static p11_rpc_client_vtable test_normal_vtable = {
	NULL,
	rpc_initialize,
	rpc_authenticate,
	rpc_transport,
	rpc_finalize,
};

static p11_rpc_client_vtable test_device_removed_vtable = {
	NULL,
	rpc_initialize_device_removed,
	rpc_authenticate,
	rpc_transport,
	rpc_finalize,
};

static void
mixin_free (void *data)
{
	p11_virtual *mixin = data;
	p11_virtual_uninit (mixin);
	free (mixin);
}

static CK_FUNCTION_LIST_PTR
setup_test_rpc_module (p11_rpc_client_vtable *vtable,
                       CK_FUNCTION_LIST_3_0 *module_template,
                       CK_SESSION_HANDLE *session)
{
	CK_FUNCTION_LIST *rpc_module;
	p11_virtual *mixin;
	CK_RV rv;

	/* Build up our own function list */
	p11_virtual_init (&base, &p11_virtual_base, module_template, NULL);

	mixin = calloc (1, sizeof (p11_virtual));
	assert (mixin != NULL);

	vtable->data = "vtable-data";
	if (!p11_rpc_client_init (mixin, vtable))
		assert_not_reached ();

	rpc_module = p11_virtual_wrap (mixin, mixin_free);
	assert_ptr_not_null (rpc_module);

	rv = p11_kit_module_initialize (rpc_module);
	assert (rv == CKR_OK);

	if (session) {
		rv = (rpc_module->C_OpenSession) (MOCK_SLOT_ONE_ID, CKF_RW_SESSION | CKF_SERIAL_SESSION,
		                                  NULL, NULL, session);
		assert (rv == CKR_OK);
	}

	return rpc_module;
}

static CK_FUNCTION_LIST *
setup_mock_module (CK_SESSION_HANDLE *session)
{
	return setup_test_rpc_module (&test_normal_vtable, &mock_module_v3, session);
}

static void
teardown_mock_module (CK_FUNCTION_LIST *rpc_module)
{
	p11_kit_module_finalize (rpc_module);
	p11_virtual_unwrap (rpc_module);
}

static void
test_get_info_stand_in (void)
{
	CK_FUNCTION_LIST_PTR rpc_module;
	CK_INFO info;
	CK_RV rv;
	char *string;

	rpc_module = setup_test_rpc_module (&test_device_removed_vtable,
	                                    &mock_module_v3_no_slots, NULL);

	rv = (rpc_module->C_GetInfo) (&info);
	assert (rv == CKR_OK);

	assert_num_eq (CRYPTOKI_VERSION_MAJOR, info.cryptokiVersion.major);
	assert_num_eq (CRYPTOKI_VERSION_MINOR, info.cryptokiVersion.minor);
	string = p11_kit_space_strdup (info.manufacturerID, sizeof (info.manufacturerID));
	assert_str_eq ("p11-kit", string);
	free (string);
	string = p11_kit_space_strdup (info.libraryDescription, sizeof (info.libraryDescription));
	assert_str_eq ("p11-kit (no connection)", string);
	free (string);
	assert_num_eq (0, info.flags);
	assert_num_eq (1, info.libraryVersion.major);
	assert_num_eq (1, info.libraryVersion.minor);

	teardown_mock_module (rpc_module);
}

static void
test_get_slot_list_no_device (void)
{
	CK_FUNCTION_LIST_PTR rpc_module;
	CK_SLOT_ID slot_list[8];
	CK_ULONG count;
	CK_RV rv;

	rpc_module = setup_test_rpc_module (&test_device_removed_vtable,
	                                    &mock_module_v3_no_slots, NULL);

	rv = (rpc_module->C_GetSlotList) (CK_TRUE, NULL, &count);
	assert (rv == CKR_OK);
	assert_num_eq (0, count);
	rv = (rpc_module->C_GetSlotList) (CK_FALSE, NULL, &count);
	assert (rv == CKR_OK);
	assert_num_eq (0, count);

	count = 8;
	rv = (rpc_module->C_GetSlotList) (CK_TRUE, slot_list, &count);
	assert (rv == CKR_OK);
	assert_num_eq (0, count);

	count = 8;
	rv = (rpc_module->C_GetSlotList) (CK_FALSE, slot_list, &count);
	assert (rv == CKR_OK);
	assert_num_eq (0, count);

	teardown_mock_module (rpc_module);
}

static void *
invoke_in_thread (void *arg)
{
	CK_FUNCTION_LIST *rpc_module = arg;
	CK_INFO info;
	CK_RV rv;

	rv = (rpc_module->C_GetInfo) (&info);
	assert_num_eq (rv, CKR_OK);

	assert (memcmp (info.manufacturerID, MOCK_INFO.manufacturerID,
	                sizeof (info.manufacturerID)) == 0);

	return NULL;
}

static p11_mutex_t delay_mutex;

static CK_RV
delayed_C_GetInfo (CK_INFO_PTR info)
{
	CK_RV rv;

	p11_sleep_ms (rand () % 100);

	p11_mutex_lock (&delay_mutex);
	rv = mock_C_GetInfo (info);
	p11_mutex_unlock (&delay_mutex);

	return rv;
}

static void
test_simultaneous_functions (void)
{
	CK_FUNCTION_LIST_3_0 real_module;
	CK_FUNCTION_LIST *rpc_module;
	const int num_threads = 128;
	p11_thread_t threads[num_threads];
	int i, ret;

	p11_mutex_init (&delay_mutex);

	memcpy (&real_module, &mock_module_v3_no_slots, sizeof (CK_FUNCTION_LIST));
	real_module.C_GetInfo = delayed_C_GetInfo;

	rpc_module = setup_test_rpc_module (&test_normal_vtable,
	                                    &real_module, NULL);

	/* Make the invoked function (above) wait */
	p11_mutex_lock (&delay_mutex);

	for (i = 0; i < num_threads; i++) {
		ret = p11_thread_create (threads + i, invoke_in_thread, rpc_module);
		assert_num_eq (0, ret);
	}

	/* Let the invoked functions return */
	p11_mutex_unlock (&delay_mutex);

	for (i = 0; i < num_threads; i++)
		p11_thread_join (threads[i]);

	teardown_mock_module (rpc_module);
	p11_mutex_uninit (&delay_mutex);
}

#ifdef OS_UNIX

static void
test_fork_and_reinitialize (void)
{
	CK_FUNCTION_LIST *rpc_module;
	CK_INFO info;
	int status;
	CK_RV rv;
	pid_t pid;
	int i;

	rpc_module = setup_test_rpc_module (&test_normal_vtable,
	                                    &mock_module_v3_no_slots, NULL);

	pid = fork ();
	assert_num_cmp (pid, >=, 0);

	/* The child */
	if (pid == 0) {
		rv = (rpc_module->C_Initialize) (NULL);
		assert_num_eq (CKR_OK, rv);

		for (i = 0; i < 32; i++) {
			rv = (rpc_module->C_GetInfo) (&info);
			assert_num_eq (CKR_OK, rv);
		}

		rv = (rpc_module->C_Finalize) (NULL);
		assert_num_eq (CKR_OK, rv);

		_exit (66);
	}

	for (i = 0; i < 128; i++) {
		rv = (rpc_module->C_GetInfo) (&info);
		assert_num_eq (CKR_OK, rv);
	}

	assert_num_eq (waitpid (pid, &status, 0), pid);
	assert_num_eq (WEXITSTATUS (status), 66);

	teardown_mock_module (rpc_module);
}

#endif /* OS_UNIX */

#include "test-mock.c"

CK_VERSION test_version_three = {CRYPTOKI_VERSION_MAJOR, CRYPTOKI_VERSION_MINOR};

int
main (int argc,
      char *argv[])
{
	CK_MECHANISM_TYPE mechanisms[] = {
		CKM_MOCK_CAPITALIZE,
		CKM_MOCK_PREFIX,
		CKM_MOCK_GENERATE,
		CKM_MOCK_WRAP,
		CKM_MOCK_DERIVE,
		CKM_MOCK_COUNT,
		0,
	};

	mock_module_init ();
	p11_library_init ();

	/* Override the mechanisms that the RPC mechanism will handle */
	p11_rpc_mechanisms_override_supported = mechanisms;

	p11_test (test_initialize_fails_on_client, "/rpc3/initialize-fails-on-client");
	p11_test (test_initialize_fails_on_server, "/rpc3/initialize-fails-on-server");
	p11_test (test_initialize, "/rpc3/initialize");
	p11_test (test_not_initialized, "/rpc3/not-initialized");
	p11_test (test_transport_fails, "/rpc3/transport-fails");
	p11_test (test_transport_bad_parse, "/rpc3/transport-bad-parse");
	p11_test (test_transport_short_error, "/rpc3/transport-short-error");
	p11_test (test_transport_invalid_error, "/rpc3/transport-invalid-error");
	p11_test (test_transport_wrong_response, "/rpc3/transport-wrong-response");
	p11_test (test_transport_bad_contents, "/rpc3/transport-bad-contents");
	p11_test (test_get_info_stand_in, "/rpc3/get-info-stand-in");
	p11_test (test_get_slot_list_no_device, "/rpc3/get-slot-list-no-device");
	p11_test (test_simultaneous_functions, "/rpc3/simultaneous-functions");

#ifdef OS_UNIX
	p11_test (test_fork_and_reinitialize, "/rpc3/fork-and-reinitialize");
#endif

	test_mock_add_tests ("/rpc3", &test_version_three);

	return  p11_test_run (argc, argv);
}
