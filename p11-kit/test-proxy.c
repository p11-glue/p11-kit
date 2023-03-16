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
#ifndef _WIN32
#include <sys/wait.h>
#endif

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
	assert_num_eq (rv, CKR_OK);
	assert_num_eq (proxy->version.major, CRYPTOKI_LEGACY_VERSION_MAJOR);
	assert_num_eq (proxy->version.minor, CRYPTOKI_LEGACY_VERSION_MINOR);

	assert (p11_proxy_module_check (proxy));

	rv = proxy->C_Initialize (NULL);
	assert_num_eq (rv, CKR_OK);

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

#ifndef _WIN32
static void
test_initialize_child (void)
{
	CK_FUNCTION_LIST_PTR proxy;
	CK_RV rv;
	pid_t pid;
	int st;
	CK_SLOT_ID slots[32], last_slot;
	CK_ULONG count, last_count;

	rv = C_GetFunctionList (&proxy);
	assert (rv == CKR_OK);

	assert (p11_proxy_module_check (proxy));

	rv = proxy->C_Initialize(NULL);
	assert_num_eq (rv, CKR_OK);

	count = 32;
	rv = proxy->C_GetSlotList (CK_FALSE, slots, &count);
	assert_num_cmp (count, >=, 2);
	last_slot = slots[count - 1];
	last_count = count;

	pid = fork ();
	if (!pid) {
		/* The PKCS#11 Usage Guide (v2.40) advocates in §2.5.2 that
		 * a child should call C_Initialize() after forking, and
		 * then immediately C_Finalize() if it's not going to do
		 * anything more with the PKCS#11 token. In a multi-threaded
		 * program this is a violation of the POSIX standard, which
		 * puts strict limits on what you're allowed to do between
		 * fork and an eventual exec or exit. But some things (like
		 * pkcs11-helper and thus OpenVPN) do it anyway, and we
		 * need to cope... */

		/* https://bugs.freedesktop.org/show_bug.cgi?id=90289 reports
		 * a deadlock when this happens. Catch it with SIGALRM... */
		alarm(1);

		rv = proxy->C_Initialize(NULL);
		assert_num_eq (rv, CKR_OK);

		rv = proxy->C_GetSlotList (CK_FALSE, slots, &count);
		assert_num_eq (rv, CKR_OK);
		assert_num_cmp (count, >=, 2);

		/* One of the module initializations should fail after
		 * fork (see mock-module-ep4.c) and the total number
		 * of slots should be less than last_count. */
		assert_num_cmp (count, <, last_count);
		/* Check if the last valid slot ID is preserved */
		assert_num_eq (slots[count - 1], last_slot);

		rv = proxy->C_Finalize (NULL);
		assert_num_eq (rv, CKR_OK);

		_exit (0);
	}
	assert (pid != -1);
	waitpid(pid, &st, 0);

	rv = proxy->C_Finalize (NULL);
	assert_num_eq (rv, CKR_OK);

	p11_proxy_module_cleanup ();

	/* If the assertion fails, p11_kit_failed() doesn't return. So make
	 * sure we do all the cleanup before the (expected) failure, or it
	 * causes all the *later* tests to fail too! */
	if (!WIFEXITED (st) || WEXITSTATUS(st) != 0)
		assert_fail("Child failed to C_Initialize() and C_Finalize()", NULL);

}
#endif

struct {
	char *directory;
	const char *system_file;
	const char *package_modules;
	const char *system_modules;
	const char *user_modules;
} test;

extern const char *p11_config_system_file;
extern const char *p11_config_package_modules;
extern const char *p11_config_system_modules;
extern const char *p11_config_user_modules;

static void
setup (void *unused)
{
	test.directory = p11_test_directory ("test-proxy");
	test.system_file = p11_config_system_file;
	p11_config_system_file = SRCDIR "/p11-kit/fixtures/test-system-none.conf";
	test.package_modules = p11_config_package_modules;
	test.system_modules = p11_config_system_modules;
	test.user_modules = p11_config_user_modules;

	p11_config_package_modules = SRCDIR "/p11-kit/fixtures/nonexistent";
	p11_config_system_modules = test.directory;
	p11_config_user_modules = SRCDIR "/p11-kit/fixtures/nonexistent";
}

static void
teardown (void *unused)
{
	p11_test_directory_delete (test.directory);
	free (test.directory);
	p11_config_system_file = test.system_file;
	p11_config_package_modules = test.package_modules;
	p11_config_system_modules = test.system_modules;
	p11_config_user_modules = test.user_modules;
}

#define ONE_MODULE "module: mock-one" SHLEXT "\n"
#define TWO_MODULE "module: mock-two" SHLEXT "\n"
#define ENABLED "enable-in: test-proxy, p11-kit-proxy\n"
#define DISABLED "disable-in: p11-kit-proxy\n"
#define ENABLED_PREFIX "enable-in: test-proxy-suffix, p11-kit-proxy-suffix, test-proxy, p11-kit-proxy\n"
#define EIGHT_MODULE "module: mock-eight" SHLEXT "\n"
#define NINE_MODULE "module: mock-nine" SHLEXT "\n"
#define TEN_MODULE "module: mock-ten" SHLEXT "\n"

static CK_ULONG
load_modules_and_count_slots (void)
{
	CK_FUNCTION_LIST_PTR proxy;
	CK_ULONG count;
	CK_RV rv;

	rv = C_GetFunctionList (&proxy);
	assert (rv == CKR_OK);

	assert (p11_proxy_module_check (proxy));

	rv = proxy->C_Initialize (NULL);
	assert (rv == CKR_OK);

	rv = proxy->C_GetSlotList (CK_TRUE, NULL, &count);
	assert (rv == CKR_OK);

	rv = proxy->C_Finalize (NULL);
	assert_num_eq (rv, CKR_OK);

	p11_proxy_module_cleanup ();

	return count;
}

static void
test_no_slot (void)
{
	CK_FUNCTION_LIST_PTR proxy;
	CK_ULONG count;
	CK_SESSION_HANDLE session;
	CK_RV rv;

	rv = C_GetFunctionList (&proxy);
	assert (rv == CKR_OK);

	assert (p11_proxy_module_check (proxy));

	rv = proxy->C_Initialize (NULL);
	assert (rv == CKR_OK);

	rv = proxy->C_GetSlotList (CK_TRUE, NULL, &count);
	assert (rv == CKR_OK);
	assert_num_eq (count, 0);

	/* 0x10 == MAPPING_OFFSET, defined in proxy.c */
	rv = proxy->C_OpenSession (0x10, CKF_SERIAL_SESSION, NULL, NULL, &session);
	assert (rv == CKR_SLOT_ID_INVALID);

	rv = proxy->C_Finalize (NULL);
	assert_num_eq (rv, CKR_OK);

	p11_proxy_module_cleanup ();
}

static void
test_disable (void)
{
	CK_ULONG count, enabled, disabled;

	p11_test_file_write (test.directory, "one.module", ONE_MODULE, strlen (ONE_MODULE));
	p11_test_file_write (test.directory, "two.module", TWO_MODULE, strlen (TWO_MODULE));
	count = load_modules_and_count_slots ();
	assert_num_cmp (count, >, 1);

	p11_test_file_write (test.directory, "one.module", ONE_MODULE ENABLED, strlen (ONE_MODULE ENABLED));
	p11_test_file_write (test.directory, "two.module", TWO_MODULE, strlen (TWO_MODULE));
	enabled = load_modules_and_count_slots ();
	assert_num_eq (enabled, count);

	p11_test_file_write (test.directory, "one.module", ONE_MODULE, strlen (ONE_MODULE));
	p11_test_file_write (test.directory, "two.module", TWO_MODULE DISABLED, strlen (TWO_MODULE DISABLED));
	disabled = load_modules_and_count_slots ();
	assert_num_cmp (disabled, <, count);

	p11_test_file_write (test.directory, "one.module", ONE_MODULE ENABLED_PREFIX, strlen (ONE_MODULE ENABLED_PREFIX));
	p11_test_file_write (test.directory, "two.module", TWO_MODULE, strlen (TWO_MODULE));
	enabled = load_modules_and_count_slots ();
	assert_num_eq (enabled, count);

}

static void
test_slot_appear (void)
{
	CK_FUNCTION_LIST_PTR proxy;
	CK_ULONG count;
	CK_RV rv;

	p11_test_file_write (test.directory, "eight.module", EIGHT_MODULE, strlen (EIGHT_MODULE));

	rv = C_GetFunctionList (&proxy);
	assert (rv == CKR_OK);

	assert (p11_proxy_module_check (proxy));

	rv = proxy->C_Initialize (NULL);
	assert (rv == CKR_OK);

	rv = proxy->C_GetSlotList (CK_TRUE, NULL, &count);
	assert (rv == CKR_OK);
	assert_num_eq (count, 0);

	rv = proxy->C_GetSlotList (CK_TRUE, NULL, &count);
	assert (rv == CKR_OK);
	assert_num_eq (count, 1);

	rv = proxy->C_Finalize (NULL);
	assert_num_eq (rv, CKR_OK);

	p11_proxy_module_cleanup ();
}

static void
test_slot_event (void)
{
	CK_FUNCTION_LIST_PTR proxy;
	CK_SLOT_ID slot;
	CK_SLOT_ID slots[32];
	CK_ULONG count;
	CK_RV rv;

	p11_test_file_write (test.directory, "nine.module", NINE_MODULE, strlen (NINE_MODULE));

	rv = C_GetFunctionList (&proxy);
	assert (rv == CKR_OK);

	assert (p11_proxy_module_check (proxy));

	rv = proxy->C_Initialize (NULL);
	assert (rv == CKR_OK);

	rv = proxy->C_GetSlotList (CK_FALSE, NULL, &count);
	assert (rv == CKR_OK);
	assert (count == 2);

	rv = proxy->C_GetSlotList (CK_FALSE, slots, &count);
	assert (rv == CKR_OK);
	assert (count == 2);

	slot = 0;
	rv = proxy->C_WaitForSlotEvent (0, &slot, NULL);
	assert_num_eq (rv, CKR_FUNCTION_NOT_SUPPORTED);
	assert_num_eq (slot, 0);

	rv = proxy->C_WaitForSlotEvent (CKF_DONT_BLOCK, &slot, NULL);
	assert_num_eq (rv, CKR_OK);
	assert_num_eq (slot, slots[0]);

	rv = proxy->C_Finalize (NULL);
	assert_num_eq (rv, CKR_OK);

	p11_proxy_module_cleanup ();
}

static void
test_reuse_slots (void)
{
	CK_FUNCTION_LIST_PTR proxy;
	CK_SLOT_ID slots[32];
	CK_ULONG count = 32;
	CK_RV rv;

	p11_test_file_write (test.directory, "ten.module", TEN_MODULE, strlen (TEN_MODULE));

	rv = C_GetFunctionList (&proxy);
	assert (rv == CKR_OK);

	assert (p11_proxy_module_check (proxy));

	rv = proxy->C_Initialize (NULL);
	assert (rv == CKR_OK);

	rv = proxy->C_GetSlotList (CK_FALSE, slots, &count);
	assert (rv == CKR_OK);
	assert_num_eq (count, 1);

	count = 32;

	rv = proxy->C_GetSlotList (CK_FALSE, slots, &count);
	assert (rv == CKR_OK);
	assert_num_eq (count, 2);

	/* Make sure the assigned slot IDs are different */
	assert_num_cmp (slots[0], !=, slots[1]);

	rv = proxy->C_Finalize (NULL);
	assert_num_eq (rv, CKR_OK);

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
	assert_num_cmp (mock_slots_all, >=, 2);

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

	p11_proxy_module_cleanup ();
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
	{ CRYPTOKI_LEGACY_VERSION_MAJOR, CRYPTOKI_LEGACY_VERSION_MINOR },
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
#ifndef _WIN32
	p11_test (test_initialize_child, "/proxy/initialize-child");
#endif

	p11_fixture (setup, teardown);
	p11_test (test_disable, "/proxy/disable");
	p11_test (test_no_slot, "/proxy/no-slot");
	p11_test (test_slot_appear, "/proxy/slot-appear");
	p11_test (test_slot_event, "/proxy/slot-event");
	p11_test (test_reuse_slots, "/proxy/reuse-slots");

	test_mock_add_tests ("/proxy", NULL);

	return p11_test_run (argc, argv);
}
