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

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "debug.h"
#include "library.h"
#include "p11-kit.h"
#include "private.h"
#include "dict.h"

static CK_FUNCTION_LIST_PTR_PTR
initialize_and_get_modules (void)
{
	CK_FUNCTION_LIST_PTR_PTR modules;

	modules = p11_kit_modules_load_and_initialize (0);
	assert (modules != NULL && modules[0] != NULL);

	return modules;
}

static void
finalize_and_free_modules (CK_FUNCTION_LIST_PTR_PTR modules)
{
	p11_kit_modules_finalize_and_release (modules);
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
		path = p11_kit_config_option (modules[i], "module");

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
		module_name = p11_kit_module_get_name (modules[i]);
		assert_ptr_not_null (module_name);
		if (strcmp (module_name, name) == 0)
			match = modules[i];
		free (module_name);
	}

	/*
	 * As a side effect, we should check that the results of this function
	 * matches the above search.
	 */
	module = p11_kit_module_for_name (modules, name);
	if (module != match)
		assert_fail ("different result from p11_kit_module_for_name ()", NULL);

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

	/*
	 * The module two shouldn't be matched, because in its config
	 * file we have:
	 *
	 * disable-in: test-disable
	 */

	p11_kit_set_progname ("test-disable");

	modules = p11_kit_modules_load_and_initialize (0);
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

static void
test_priority (void)
{
	CK_FUNCTION_LIST_PTR_PTR modules;
	char *name;
	int i;

	/*
	 * The expected order.
	 * - four is marked with a priority of 4, the highest therefore first
	 * - three is marked with a priority of 3, next highest
	 * - one and two do not have priority marked, so they default to zero
	 *   and fallback to sorting alphabetically. 'o' comes before 't'
	 */

	const char *expected[] = { "four", "three", "one", "two.badname" };

	/* This enables module three */
	p11_kit_set_progname ("test-enable");

	modules = initialize_and_get_modules ();

	/* The loaded modules should not contain duplicates */
	for (i = 0; modules[i] != NULL; i++) {
		name = p11_kit_module_get_name (modules[i]);
		assert_ptr_not_null (name);

		/* Either one of these can be loaded, as this is a duplicate module */
		if (strcmp (name, "two-duplicate") == 0) {
			free (name);
			name = strdup ("two.badname");
		}

		assert_str_eq (expected[i], name);
		free (name);
	}

	assert_num_eq (4, i);
	finalize_and_free_modules (modules);
}

static void
test_module_name (void)
{
	CK_FUNCTION_LIST_PTR_PTR modules;
	CK_FUNCTION_LIST_PTR module;
	char *name;

	/*
	 * The module three should not be present, as we don't match the current
	 * program.
	 */

	modules = initialize_and_get_modules ();

	module = p11_kit_module_for_name (modules, "one");
	assert_ptr_not_null (module);
	name = p11_kit_module_get_name (module);
	assert_str_eq ("one", name);
	free (name);

	module = p11_kit_module_for_name (modules, "invalid");
	assert_ptr_eq (NULL, module);

	module = p11_kit_module_for_name (NULL, "one");
	assert_ptr_eq (NULL, module);

	finalize_and_free_modules (modules);
}

static void
test_module_flags (void)
{
	CK_FUNCTION_LIST **modules;
	CK_FUNCTION_LIST **unmanaged;
	int flags;

	/*
	 * The module three should not be present, as we don't match the current
	 * program.
	 */

	modules = initialize_and_get_modules ();

	flags = p11_kit_module_get_flags (modules[0]);
	assert_num_eq (0, flags);

	unmanaged = p11_kit_modules_load (NULL, P11_KIT_MODULE_UNMANAGED);
	assert (unmanaged != NULL && unmanaged[0] != NULL);

	flags = p11_kit_module_get_flags (unmanaged[0]);
	assert_num_eq (P11_KIT_MODULE_UNMANAGED, flags);

	finalize_and_free_modules (modules);
	p11_kit_modules_release (unmanaged);
}

static void
test_module_trusted_only (void)
{
	CK_FUNCTION_LIST_PTR_PTR modules;
	char *name;

	modules = p11_kit_modules_load_and_initialize (P11_KIT_MODULE_TRUSTED);
	assert_ptr_not_null (modules);
	assert_ptr_not_null (modules[0]);
	assert (modules[1] == NULL);

	name = p11_kit_module_get_name (modules[0]);
	assert_str_eq (name, "one");
	free (name);

	assert_num_eq (p11_kit_module_get_flags (modules[0]), P11_KIT_MODULE_TRUSTED);

	finalize_and_free_modules (modules);
}

static void
test_module_trust_flags (void)
{
	CK_FUNCTION_LIST_PTR_PTR modules;
	char *name;
	int flags;
	int i;

	modules = initialize_and_get_modules ();
	assert_ptr_not_null (modules);

	for (i = 0; modules[i] != NULL; i++) {
		name = p11_kit_module_get_name (modules[i]);
		assert_ptr_not_null (name);

		flags = p11_kit_module_get_flags (modules[i]);
		if (strcmp (name, "one") == 0) {
			assert_num_eq (flags, P11_KIT_MODULE_TRUSTED);
		} else {
			assert_num_eq (flags, 0);
		}

		free (name);
	}

	finalize_and_free_modules (modules);
}

static void
test_config_option (void)
{
	CK_FUNCTION_LIST_PTR_PTR modules;
	CK_FUNCTION_LIST_PTR module;
	char *value;

	/*
	 * The module three should not be present, as we don't match the current
	 * program.
	 */

	modules = initialize_and_get_modules ();

	value = p11_kit_config_option (NULL, "new");
	assert_str_eq ("world", value);
	free (value);

	module = p11_kit_module_for_name (modules, "one");
	assert_ptr_not_null (module);

	value = p11_kit_config_option (module, "setting");
	assert_str_eq ("user1", value);
	free (value);

	value = p11_kit_config_option (NULL, "invalid");
	assert_ptr_eq (NULL, value);

	value = p11_kit_config_option (module, "invalid");
	assert_ptr_eq (NULL, value);

	/* Invalid but non-NULL module pointer */
	value = p11_kit_config_option (module + 1, "setting");
	assert_ptr_eq (NULL, value);

	finalize_and_free_modules (modules);
}

int
main (int argc,
      char *argv[])
{
	p11_library_init ();

	p11_test (test_no_duplicates, "/modules/test_no_duplicates");
	p11_test (test_disable, "/modules/test_disable");
	p11_test (test_disable_later, "/modules/test_disable_later");
	p11_test (test_enable, "/modules/test_enable");
	p11_test (test_priority, "/modules/test_priority");
	p11_test (test_module_name, "/modules/test_module_name");
	p11_test (test_module_flags, "/modules/test_module_flags");
	p11_test (test_config_option, "/modules/test_config_option");
	p11_test (test_module_trusted_only, "/modules/trusted-only");
	p11_test (test_module_trust_flags, "/modules/trust-flags");

	p11_kit_be_quiet ();

	return p11_test_run (argc, argv);
}
