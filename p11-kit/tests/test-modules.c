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
#include "CuTest.h"

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
initialize_and_get_modules (CuTest *tc)
{
	CK_FUNCTION_LIST_PTR_PTR modules;

	modules = p11_kit_modules_load_and_initialize (0);
	CuAssertTrue (tc, modules != NULL && modules[0] != NULL);

	return modules;
}

static void
finalize_and_free_modules (CuTest *tc,
                           CK_FUNCTION_LIST_PTR_PTR modules)
{
	p11_kit_modules_finalize_and_release (modules);
}

static void
test_no_duplicates (CuTest *tc)
{
	CK_FUNCTION_LIST_PTR_PTR modules;
	p11_dict *paths;
	p11_dict *funcs;
	char *path;
	int i;

	modules = initialize_and_get_modules (tc);
	paths = p11_dict_new (p11_dict_str_hash, p11_dict_str_equal, NULL, NULL);
	funcs = p11_dict_new (p11_dict_direct_hash, p11_dict_direct_equal, NULL, NULL);

	/* The loaded modules should not contain duplicates */
	for (i = 0; modules[i] != NULL; i++) {
		path = p11_kit_config_option (modules[i], "module");

		if (p11_dict_get (funcs, modules[i]))
			CuAssert (tc, "found duplicate function list pointer", 0);
		if (p11_dict_get (paths, path))
			CuAssert (tc, "found duplicate path name", 0);

		if (!p11_dict_set (funcs, modules[i], ""))
			CuAssert (tc, "shouldn't be reached", 0);
		if (!p11_dict_set (paths, path, ""))
			CuAssert (tc, "shouldn't be reached", 0);

		free (path);
	}

	p11_dict_free (paths);
	p11_dict_free (funcs);
	finalize_and_free_modules (tc, modules);
}

static CK_FUNCTION_LIST_PTR
lookup_module_with_name (CuTest *tc,
                         CK_FUNCTION_LIST_PTR_PTR modules,
                         const char *name)
{
	CK_FUNCTION_LIST_PTR match = NULL;
	CK_FUNCTION_LIST_PTR module;
	char *module_name;
	int i;

	for (i = 0; match == NULL && modules[i] != NULL; i++) {
		module_name = p11_kit_module_get_name (modules[i]);
		CuAssertPtrNotNull (tc, module_name);
		if (strcmp (module_name, name) == 0)
			match = modules[i];
		free (module_name);
	}

	/*
	 * As a side effect, we should check that the results of this function
	 * matches the above search.
	 */
	module = p11_kit_module_for_name (modules, name);
	CuAssert(tc, "different result from p11_kit_module_for_name ()",
	         module == match);

	return match;
}

static void
test_disable (CuTest *tc)
{
	CK_FUNCTION_LIST_PTR_PTR modules;

	/*
	 * The module four should be present, as we don't match any prognames
	 * that it has disabled.
	 */

	modules = initialize_and_get_modules (tc);
	CuAssertTrue (tc, lookup_module_with_name (tc, modules, "four") != NULL);
	finalize_and_free_modules (tc, modules);

	/*
	 * The module two shouldn't have been loaded, because in its config
	 * file we have:
	 *
	 * disable-in: test-disable
	 */

	p11_kit_set_progname ("test-disable");

	modules = initialize_and_get_modules (tc);
	CuAssertTrue (tc, lookup_module_with_name (tc, modules, "four") == NULL);
	finalize_and_free_modules (tc, modules);

	p11_kit_set_progname (NULL);
}

static void
test_disable_later (CuTest *tc)
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
	CuAssertTrue (tc, modules != NULL && modules[0] != NULL);

	CuAssertTrue (tc, lookup_module_with_name (tc, modules, "two") == NULL);
	finalize_and_free_modules (tc, modules);

	p11_kit_set_progname (NULL);
}

static void
test_enable (CuTest *tc)
{
	CK_FUNCTION_LIST_PTR_PTR modules;

	/*
	 * The module three should not be present, as we don't match the current
	 * program.
	 */

	modules = initialize_and_get_modules (tc);
	CuAssertTrue (tc, lookup_module_with_name (tc, modules, "three") == NULL);
	finalize_and_free_modules (tc, modules);

	/*
	 * The module three should be loaded here , because in its config
	 * file we have:
	 *
	 * enable-in: test-enable
	 */

	p11_kit_set_progname ("test-enable");

	modules = initialize_and_get_modules (tc);
	CuAssertTrue (tc, lookup_module_with_name (tc, modules, "three") != NULL);
	finalize_and_free_modules (tc, modules);

	p11_kit_set_progname (NULL);
}

static void
test_priority (CuTest *tc)
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

	modules = initialize_and_get_modules (tc);

	/* The loaded modules should not contain duplicates */
	for (i = 0; modules[i] != NULL; i++) {
		name = p11_kit_module_get_name (modules[i]);
		CuAssertPtrNotNull (tc, name);

		/* Either one of these can be loaded, as this is a duplicate module */
		if (strcmp (name, "two-duplicate") == 0) {
			free (name);
			name = strdup ("two.badname");
		}

		CuAssertStrEquals (tc, expected[i], name);
		free (name);
	}

	CuAssertIntEquals (tc, 4, i);
	finalize_and_free_modules (tc, modules);
}

static void
test_module_name (CuTest *tc)
{
	CK_FUNCTION_LIST_PTR_PTR modules;
	CK_FUNCTION_LIST_PTR module;
	char *name;

	/*
	 * The module three should not be present, as we don't match the current
	 * program.
	 */

	modules = initialize_and_get_modules (tc);

	module = p11_kit_module_for_name (modules, "one");
	CuAssertPtrNotNull (tc, module);
	name = p11_kit_module_get_name (module);
	CuAssertStrEquals (tc, "one", name);
	free (name);

	module = p11_kit_module_for_name (modules, "invalid");
	CuAssertPtrEquals (tc, NULL, module);

	module = p11_kit_module_for_name (NULL, "one");
	CuAssertPtrEquals (tc, NULL, module);

	finalize_and_free_modules (tc, modules);
}

static void
test_module_flags (CuTest *tc)
{
	CK_FUNCTION_LIST **modules;
	CK_FUNCTION_LIST **unmanaged;
	int flags;

	/*
	 * The module three should not be present, as we don't match the current
	 * program.
	 */

	modules = initialize_and_get_modules (tc);

	flags = p11_kit_module_get_flags (modules[0]);
	CuAssertIntEquals (tc, 0, flags);

	unmanaged = p11_kit_modules_load (NULL, P11_KIT_MODULE_UNMANAGED);
	CuAssertTrue (tc, unmanaged != NULL && unmanaged[0] != NULL);

	flags = p11_kit_module_get_flags (unmanaged[0]);
	CuAssertIntEquals (tc, P11_KIT_MODULE_UNMANAGED, flags);

	finalize_and_free_modules (tc, modules);
	p11_kit_modules_release (unmanaged);
}

static void
test_config_option (CuTest *tc)
{
	CK_FUNCTION_LIST_PTR_PTR modules;
	CK_FUNCTION_LIST_PTR module;
	char *value;

	/*
	 * The module three should not be present, as we don't match the current
	 * program.
	 */

	modules = initialize_and_get_modules (tc);

	value = p11_kit_config_option (NULL, "new");
	CuAssertStrEquals (tc, "world", value);
	free (value);

	module = p11_kit_module_for_name (modules, "one");
	CuAssertPtrNotNull (tc, module);

	value = p11_kit_config_option (module, "setting");
	CuAssertStrEquals (tc, "user1", value);
	free (value);

	value = p11_kit_config_option (NULL, "invalid");
	CuAssertPtrEquals (tc, NULL, value);

	value = p11_kit_config_option (module, "invalid");
	CuAssertPtrEquals (tc, NULL, value);

	/* Invalid but non-NULL module pointer */
	value = p11_kit_config_option (module + 1, "setting");
	CuAssertPtrEquals (tc, NULL, value);

	finalize_and_free_modules (tc, modules);
}

int
main (void)
{
	CuString *output = CuStringNew ();
	CuSuite* suite = CuSuiteNew ();
	int ret;

	putenv ("P11_KIT_STRICT=1");
	p11_library_init ();

	SUITE_ADD_TEST (suite, test_no_duplicates);
	SUITE_ADD_TEST (suite, test_disable);
	SUITE_ADD_TEST (suite, test_disable_later);
	SUITE_ADD_TEST (suite, test_enable);
	SUITE_ADD_TEST (suite, test_priority);
	SUITE_ADD_TEST (suite, test_module_name);
	SUITE_ADD_TEST (suite, test_module_flags);
	SUITE_ADD_TEST (suite, test_config_option);

	p11_kit_be_quiet ();

	CuSuiteRun (suite);
	CuSuiteSummary (suite, output);
	CuSuiteDetails (suite, output);
	printf ("%s\n", output->buffer);
	ret = suite->failCount;
	CuSuiteDelete (suite);
	CuStringDelete (output);
	return ret;
}
