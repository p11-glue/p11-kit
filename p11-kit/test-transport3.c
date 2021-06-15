/*
 * Copyright (c) 2012 Stefan Walter
 * Copyright (c) 2012-2022 Red Hat Inc.
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

#include "library.h"
#include "mock.h"
#include "path.h"
#include "private.h"

#include "p11-kit.h"
#include "rpc.h"

#include <errno.h>
#include <sys/types.h>
#include <signal.h>
#ifdef OS_UNIX
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>
#endif
#include <stdlib.h>
#include <stdio.h>

struct {
	char *directory;
	char *user_config;
	char *user_modules;
#ifdef OS_UNIX
	pid_t pid;
#endif
} test;

static void
setup_remote (void *unused)
{
	const char *data;

	test.directory = p11_test_directory ("p11-test-transport");
	test.user_modules = p11_path_build (test.directory, "modules", NULL);
#ifdef OS_UNIX
	if (mkdir (test.user_modules, 0700) < 0)
#else
	if (mkdir (test.user_modules) < 0)
#endif
		assert_not_reached ();

	data = "user-config: only\n";
	test.user_config = p11_path_build (test.directory, "pkcs11.conf", NULL);
	p11_test_file_write (NULL, test.user_config, data, strlen (data));

	setenv ("P11_KIT_PRIVATEDIR", BUILDDIR "/p11-kit", 1);
	data = "remote: |" BUILDDIR "/p11-kit/p11-kit" EXEEXT " remote " P11_MODULE_PATH "/mock-v3-two" SHLEXT "\n";
	p11_test_file_write (test.user_modules, "remote.module", data, strlen (data));
	data = "remote: |" BUILDDIR "/p11-kit/p11-kit" EXEEXT " remote " P11_MODULE_PATH "/mock-five" SHLEXT "\nx-init-reserved: initialize-arg";
	p11_test_file_write (test.user_modules, "init-arg.module", data, strlen (data));

	p11_kit_override_system_files (NULL, test.user_config,
				       NULL, NULL,
				       test.user_modules);
}

static void
teardown_remote (void *unused)
{
	p11_test_directory_delete (test.user_modules);
	p11_test_directory_delete (test.directory);

	free (test.directory);
	free (test.user_config);
	free (test.user_modules);
}

static CK_FUNCTION_LIST *
setup_mock_module (CK_SESSION_HANDLE *session)
{
	CK_FUNCTION_LIST **modules;
	CK_FUNCTION_LIST *module;
	CK_RV rv;
	int i;

	setup_remote (NULL);

	modules = p11_kit_modules_load (NULL, 0);

	module = p11_kit_module_for_name (modules, "remote");
	assert (module != NULL);

	rv = p11_kit_module_initialize (module);
	assert_num_eq (rv, CKR_OK);

	if (session) {
		rv = (module->C_OpenSession) (MOCK_SLOT_ONE_ID, CKF_RW_SESSION | CKF_SERIAL_SESSION,
		                              NULL, NULL, session);
		assert (rv == CKR_OK);
	}

	/* Release all the other modules */
	for (i = 0; modules[i] != NULL; i++) {
		if (modules[i] != module)
			p11_kit_module_release (modules[i]);
	}

	free (modules);
	return module;
}

static void
teardown_mock_module (CK_FUNCTION_LIST *module)
{
	p11_kit_module_finalize (module);
	p11_kit_module_release (module);
	teardown_remote (NULL);
}

#ifdef OS_UNIX

static void
launch_server (void)
{
	int fd, nfd, rc;
	socklen_t sa_len;
	struct sockaddr_un sa;
	fd_set fds;
	char *argv[3];

	memset (&sa, 0, sizeof (sa));
	sa.sun_family = AF_UNIX;

	snprintf (sa.sun_path, sizeof (sa.sun_path), "%s/pkcs11",
		  test.directory);

	remove (sa.sun_path);
	fd = socket (AF_UNIX, SOCK_STREAM, 0);
	assert_num_cmp (fd, !=, -1);

	rc = bind (fd, (struct sockaddr *)&sa, SUN_LEN (&sa));
	assert_num_cmp (rc, !=, -1);

	rc = listen (fd, 1024);
	assert_num_cmp (rc, !=, -1);

	FD_ZERO (&fds);
	FD_SET (fd, &fds);
	rc = select (fd + 1, &fds, NULL, NULL, NULL);
	assert_num_cmp (rc, !=, -1);

	assert (FD_ISSET (fd, &fds));

	sa_len = sizeof (sa);
	nfd = accept (fd, (struct sockaddr *)&sa, &sa_len);
	assert_num_cmp (rc, !=, -1);
	close (fd);

	rc = dup2 (nfd, STDIN_FILENO);
	assert_num_cmp (rc, !=, -1);

	rc = dup2 (nfd, STDOUT_FILENO);
	assert_num_cmp (rc, !=, -1);

	argv[0] = "p11-kit-remote";
	argv[1] = P11_MODULE_PATH "/mock-v3-two.so";
	argv[2] = NULL;

	rc = execv (BUILDDIR "/p11-kit/p11-kit-remote", argv);
	assert_num_cmp (rc, !=, -1);
}

static void
setup_remote_unix (void *unused)
{
	char *data;
	char *path;
	pid_t pid;

	test.directory = p11_test_directory ("p11-test-transport");
	test.user_modules = p11_path_build (test.directory, "modules", NULL);
	if (mkdir (test.user_modules, 0700) < 0)
		assert_not_reached ();

	data = "user-config: only\n";
	test.user_config = p11_path_build (test.directory, "pkcs11.conf", NULL);
	p11_test_file_write (NULL, test.user_config, data, strlen (data));

	pid = fork ();
	switch (pid) {
	case -1:
		assert_not_reached ();
		break;
	case 0:
		launch_server ();
		exit (0);
		break;
	default:
		test.pid = pid;
	}

	setenv ("P11_KIT_PRIVATEDIR", BUILDDIR "/p11-kit", 1);

	if (asprintf (&path, "%s/pkcs11", test.directory) < 0)
		assert_not_reached ();
	data = p11_path_encode (path);
	assert_ptr_not_null (data);
	free (path);
	path = data;
	if (asprintf (&data, "remote: unix:path=%s\n", path) < 0)
		assert_not_reached ();
	free (path);
	p11_test_file_write (test.user_modules, "remote.module", data, strlen (data));
	free (data);

	p11_kit_override_system_files (NULL, test.user_config,
				       NULL, NULL,
				       test.user_modules);
}

static void
teardown_remote_unix (void *unused)
{
	kill (test.pid, SIGKILL);
	p11_test_directory_delete (test.directory);
	free (test.directory);
}

#endif /* OS_UNIX */

static void
test_basic_exec (void)
{
	CK_FUNCTION_LIST **modules;
	CK_FUNCTION_LIST *module;
	CK_RV rv;

	modules = p11_kit_modules_load (NULL, 0);

	module = p11_kit_module_for_name (modules, "remote");
	assert (module != NULL);

	rv = p11_kit_module_initialize (module);
	assert_num_eq (rv, CKR_OK);

	rv = p11_kit_module_finalize (module);
	assert_num_eq (rv, CKR_OK);

	p11_kit_modules_release (modules);
}

static void
test_basic_exec_with_init_arg (void)
{
	CK_FUNCTION_LIST **modules;
	CK_FUNCTION_LIST *module;
	CK_RV rv;

	modules = p11_kit_modules_load (NULL, 0);

	module = p11_kit_module_for_name (modules, "init-arg");
	assert (module != NULL);

	rv = p11_kit_module_initialize (module);
	assert_num_eq (rv, CKR_OK);

	rv = p11_kit_module_finalize (module);
	assert_num_eq (rv, CKR_OK);

	p11_kit_modules_release (modules);
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

static void
test_simultaneous_functions (void)
{
	CK_FUNCTION_LIST **modules;
	CK_FUNCTION_LIST *module;
	const int num_threads = 128;
	p11_thread_t threads[num_threads];
	int i, ret;
	CK_RV rv;

	modules = p11_kit_modules_load (NULL, 0);

	module = p11_kit_module_for_name (modules, "remote");
	assert (module != NULL);

	rv = p11_kit_module_initialize (module);
	assert_num_eq (rv, CKR_OK);

	for (i = 0; i < num_threads; i++) {
		ret = p11_thread_create (threads + i, invoke_in_thread, module);
		assert_num_eq (0, ret);
	}

	for (i = 0; i < num_threads; i++)
		p11_thread_join (threads[i]);

	rv = p11_kit_module_finalize (module);
	assert_num_eq (rv, CKR_OK);

	p11_kit_modules_release (modules);
}

#ifdef OS_UNIX

static void
test_fork_and_reinitialize (void)
{
	CK_FUNCTION_LIST **modules;
	CK_FUNCTION_LIST *module;
	CK_INFO info;
	int status;
	CK_RV rv;
	pid_t pid;
	int i;

	modules = p11_kit_modules_load (NULL, 0);

	module = p11_kit_module_for_name (modules, "remote");
	assert (module != NULL);

	rv = p11_kit_module_initialize (module);
	assert_num_eq (rv, CKR_OK);

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

	rv = p11_kit_module_finalize (module);
	assert_num_eq (rv, CKR_OK);

	p11_kit_modules_release (modules);
}

#endif /* OS_UNIX */

#include "test-mock.c"

extern bool p11_conf_force_user_config;

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

	p11_library_init ();

	p11_conf_force_user_config = true;

	/* Override the mechanisms that the RPC mechanism will handle */
	p11_rpc_mechanisms_override_supported = mechanisms;

	p11_fixture (setup_remote, teardown_remote);
	p11_test (test_basic_exec, "/transport/basic");
	p11_test (test_basic_exec_with_init_arg, "/transport/init-arg");
	p11_test (test_simultaneous_functions, "/transport/simultaneous-functions");

#ifdef OS_UNIX
	p11_test (test_fork_and_reinitialize, "/transport/fork-and-reinitialize");
#endif

	test_mock_add_tests ("/transport3", &test_version_three);

#ifdef OS_UNIX
	p11_fixture (setup_remote_unix, teardown_remote_unix);
	p11_test (test_basic_exec, "/transport/unix/basic");
#endif

	return  p11_test_run (argc, argv);
}
