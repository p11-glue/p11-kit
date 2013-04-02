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

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "conf.h"
#include "debug.h"
#include "message.h"
#include "p11-kit.h"
#include "private.h"

static void
test_parse_conf_1 (CuTest *tc)
{
	p11_dict *map;
	const char *value;

	map = _p11_conf_parse_file (SRCDIR "/files/test-1.conf", 0);
	CuAssertPtrNotNull (tc, map);

	value = p11_dict_get (map, "key1");
	CuAssertStrEquals (tc, "value1", value);

	value = p11_dict_get (map, "with-colon");
	CuAssertStrEquals (tc, "value-of-colon", value);

	value = p11_dict_get (map, "with-whitespace");
	CuAssertStrEquals (tc, "value-with-whitespace", value);

	value = p11_dict_get (map, "embedded-comment");
	CuAssertStrEquals (tc, "this is # not a comment", value);

	p11_dict_free (map);
}

static void
test_parse_ignore_missing (CuTest *tc)
{
	p11_dict *map;

	map = _p11_conf_parse_file (SRCDIR "/files/non-existant.conf", CONF_IGNORE_MISSING);
	CuAssertPtrNotNull (tc, map);

	CuAssertIntEquals (tc, 0, p11_dict_size (map));
	CuAssertPtrEquals (tc, NULL, (void*)p11_message_last ());
	p11_dict_free (map);
}

static void
test_parse_fail_missing (CuTest *tc)
{
	p11_dict *map;

	map = _p11_conf_parse_file (SRCDIR "/files/non-existant.conf", 0);
	CuAssertPtrEquals (tc, map, NULL);
	CuAssertPtrNotNull (tc, p11_message_last ());
}

static void
test_merge_defaults (CuTest *tc)
{
	p11_dict *values;
	p11_dict *defaults;

	values = p11_dict_new (p11_dict_str_hash, p11_dict_str_equal, free, free);
	defaults = p11_dict_new (p11_dict_str_hash, p11_dict_str_equal, free, free);

	p11_dict_set (values, strdup ("one"), strdup ("real1"));
	p11_dict_set (values, strdup ("two"), strdup ("real2"));

	p11_dict_set (defaults, strdup ("two"), strdup ("default2"));
	p11_dict_set (defaults, strdup ("three"), strdup ("default3"));

	if (!_p11_conf_merge_defaults (values, defaults))
		CuFail (tc, "should not be reached");

	p11_dict_free (defaults);

	CuAssertStrEquals (tc, p11_dict_get (values, "one"), "real1");
	CuAssertStrEquals (tc, p11_dict_get (values, "two"), "real2");
	CuAssertStrEquals (tc, p11_dict_get (values, "three"), "default3");

	p11_dict_free (values);
}

static void
test_load_globals_merge (CuTest *tc)
{
	int user_mode = -1;
	p11_dict *config;

	p11_message_clear ();

	config = _p11_conf_load_globals (SRCDIR "/files/test-system-merge.conf",
	                                 SRCDIR "/files/test-user.conf",
	                                 &user_mode);
	CuAssertPtrNotNull (tc, config);
	CuAssertStrEquals (tc, NULL, p11_message_last ());
	CuAssertIntEquals (tc, CONF_USER_MERGE, user_mode);

	CuAssertStrEquals (tc, p11_dict_get (config, "key1"), "system1");
	CuAssertStrEquals (tc, p11_dict_get (config, "key2"), "user2");
	CuAssertStrEquals (tc, p11_dict_get (config, "key3"), "user3");

	p11_dict_free (config);
}

static void
test_load_globals_no_user (CuTest *tc)
{
	int user_mode = -1;
	p11_dict *config;

	p11_message_clear ();

	config = _p11_conf_load_globals (SRCDIR "/files/test-system-none.conf",
	                                 SRCDIR "/files/test-user.conf",
	                                 &user_mode);
	CuAssertPtrNotNull (tc, config);
	CuAssertStrEquals (tc, NULL, p11_message_last ());
	CuAssertIntEquals (tc, CONF_USER_NONE, user_mode);

	CuAssertStrEquals (tc, p11_dict_get (config, "key1"), "system1");
	CuAssertStrEquals (tc, p11_dict_get (config, "key2"), "system2");
	CuAssertStrEquals (tc, p11_dict_get (config, "key3"), "system3");

	p11_dict_free (config);
}

static void
test_load_globals_user_sets_only (CuTest *tc)
{
	int user_mode = -1;
	p11_dict *config;

	p11_message_clear ();

	config = _p11_conf_load_globals (SRCDIR "/files/test-system-merge.conf",
	                                 SRCDIR "/files/test-user-only.conf",
	                                 &user_mode);
	CuAssertPtrNotNull (tc, config);
	CuAssertStrEquals (tc, NULL, p11_message_last ());
	CuAssertIntEquals (tc, CONF_USER_ONLY, user_mode);

	CuAssertStrEquals (tc, p11_dict_get (config, "key1"), NULL);
	CuAssertStrEquals (tc, p11_dict_get (config, "key2"), "user2");
	CuAssertStrEquals (tc, p11_dict_get (config, "key3"), "user3");

	p11_dict_free (config);
}

static void
test_load_globals_system_sets_only (CuTest *tc)
{
	int user_mode = -1;
	p11_dict *config;

	p11_message_clear ();

	config = _p11_conf_load_globals (SRCDIR "/files/test-system-only.conf",
	                                 SRCDIR "/files/test-user.conf",
	                                 &user_mode);
	CuAssertPtrNotNull (tc, config);
	CuAssertStrEquals (tc, NULL, p11_message_last ());
	CuAssertIntEquals (tc, CONF_USER_ONLY, user_mode);

	CuAssertStrEquals (tc, p11_dict_get (config, "key1"), NULL);
	CuAssertStrEquals (tc, p11_dict_get (config, "key2"), "user2");
	CuAssertStrEquals (tc, p11_dict_get (config, "key3"), "user3");

	p11_dict_free (config);
}

static void
test_load_globals_system_sets_invalid (CuTest *tc)
{
	int user_mode = -1;
	p11_dict *config;
	int error;

	p11_message_clear ();

	config = _p11_conf_load_globals (SRCDIR "/files/test-system-invalid.conf",
	                                 SRCDIR "/files/non-existant.conf",
	                                 &user_mode);
	error = errno;
	CuAssertPtrEquals (tc, NULL, config);
	CuAssertIntEquals (tc, EINVAL, error);
	CuAssertPtrNotNull (tc, p11_message_last ());

	p11_dict_free (config);
}

static void
test_load_globals_user_sets_invalid (CuTest *tc)
{
	int user_mode = -1;
	p11_dict *config;
	int error;

	p11_message_clear ();

	config = _p11_conf_load_globals (SRCDIR "/files/test-system-merge.conf",
	                                 SRCDIR "/files/test-user-invalid.conf",
	                                 &user_mode);
	error = errno;
	CuAssertPtrEquals (tc, NULL, config);
	CuAssertIntEquals (tc, EINVAL, error);
	CuAssertPtrNotNull (tc, p11_message_last ());

	p11_dict_free (config);
}

static bool
assert_msg_contains (const char *msg,
                     const char *text)
{
	return (msg && strstr (msg, text)) ? true : false;
}

static void
test_load_modules_merge (CuTest *tc)
{
	p11_dict *configs;
	p11_dict *config;

	p11_message_clear ();

	configs = _p11_conf_load_modules (CONF_USER_MERGE,
	                                  SRCDIR "/files/package-modules",
	                                  SRCDIR "/files/system-modules",
	                                  SRCDIR "/files/user-modules");
	CuAssertPtrNotNull (tc, configs);
	CuAssertTrue (tc, assert_msg_contains (p11_message_last (), "invalid config filename"));

	config = p11_dict_get (configs, "one");
	CuAssertPtrNotNull (tc, config);
	CuAssertStrEquals (tc, "mock-one.so", p11_dict_get (config, "module"));
	CuAssertStrEquals (tc, p11_dict_get (config, "setting"), "user1");

	config = p11_dict_get (configs, "two.badname");
	CuAssertPtrNotNull (tc, config);
	CuAssertStrEquals (tc, "mock-two.so", p11_dict_get (config, "module"));
	CuAssertStrEquals (tc, p11_dict_get (config, "setting"), "system2");

	config = p11_dict_get (configs, "three");
	CuAssertPtrNotNull (tc, config);
	CuAssertStrEquals (tc, "mock-three.so", p11_dict_get (config, "module"));
	CuAssertStrEquals (tc, p11_dict_get (config, "setting"), "user3");

	p11_dict_free (configs);
}

static void
test_load_modules_user_none (CuTest *tc)
{
	p11_dict *configs;
	p11_dict *config;

	p11_message_clear ();

	configs = _p11_conf_load_modules (CONF_USER_NONE,
	                                  SRCDIR "/files/package-modules",
	                                  SRCDIR "/files/system-modules",
	                                  SRCDIR "/files/user-modules");
	CuAssertPtrNotNull (tc, configs);
	CuAssertTrue (tc, assert_msg_contains (p11_message_last (), "invalid config filename"));

	config = p11_dict_get (configs, "one");
	CuAssertPtrNotNull (tc, config);
	CuAssertStrEquals (tc, "mock-one.so", p11_dict_get (config, "module"));
	CuAssertStrEquals (tc, p11_dict_get (config, "setting"), "system1");

	config = p11_dict_get (configs, "two.badname");
	CuAssertPtrNotNull (tc, config);
	CuAssertStrEquals (tc, "mock-two.so", p11_dict_get (config, "module"));
	CuAssertStrEquals (tc, p11_dict_get (config, "setting"), "system2");

	config = p11_dict_get (configs, "three");
	CuAssertPtrEquals (tc, NULL, config);

	p11_dict_free (configs);
}

static void
test_load_modules_user_only (CuTest *tc)
{
	p11_dict *configs;
	p11_dict *config;

	p11_message_clear ();

	configs = _p11_conf_load_modules (CONF_USER_ONLY,
	                                  SRCDIR "/files/package-modules",
	                                  SRCDIR "/files/system-modules",
	                                  SRCDIR "/files/user-modules");
	CuAssertPtrNotNull (tc, configs);
	CuAssertPtrEquals (tc, NULL, (void *)p11_message_last ());

	config = p11_dict_get (configs, "one");
	CuAssertPtrNotNull (tc, config);
	CuAssertStrEquals (tc, p11_dict_get (config, "module"), NULL);
	CuAssertStrEquals (tc, p11_dict_get (config, "setting"), "user1");

	config = p11_dict_get (configs, "two.badname");
	CuAssertPtrEquals (tc, NULL, config);

	config = p11_dict_get (configs, "three");
	CuAssertPtrNotNull (tc, config);
	CuAssertStrEquals (tc, "mock-three.so", p11_dict_get (config, "module"));
	CuAssertStrEquals (tc, p11_dict_get (config, "setting"), "user3");

	p11_dict_free (configs);
}

static void
test_load_modules_no_user (CuTest *tc)
{
	p11_dict *configs;
	p11_dict *config;

	p11_message_clear ();

	configs = _p11_conf_load_modules (CONF_USER_MERGE,
	                                  SRCDIR "/files/package-modules",
	                                  SRCDIR "/files/system-modules",
	                                  SRCDIR "/files/non-existant");
	CuAssertPtrNotNull (tc, configs);
	CuAssertTrue (tc, assert_msg_contains (p11_message_last (), "invalid config filename"));

	config = p11_dict_get (configs, "one");
	CuAssertPtrNotNull (tc, config);
	CuAssertStrEquals (tc, "mock-one.so", p11_dict_get (config, "module"));
	CuAssertStrEquals (tc, p11_dict_get (config, "setting"), "system1");

	config = p11_dict_get (configs, "two.badname");
	CuAssertPtrNotNull (tc, config);
	CuAssertStrEquals (tc, "mock-two.so", p11_dict_get (config, "module"));
	CuAssertStrEquals (tc, p11_dict_get (config, "setting"), "system2");

	config = p11_dict_get (configs, "three");
	CuAssertPtrEquals (tc, NULL, config);

	p11_dict_free (configs);
}

static void
test_parse_boolean (CuTest *tc)
{
	p11_message_quiet ();

	CuAssertIntEquals (tc, true, _p11_conf_parse_boolean ("yes", false));
	CuAssertIntEquals (tc, false, _p11_conf_parse_boolean ("no", true));
	CuAssertIntEquals (tc, true, _p11_conf_parse_boolean ("!!!", true));
}

int
main (void)
{
	CuString *output = CuStringNew ();
	CuSuite* suite = CuSuiteNew ();
	int ret;

	putenv ("P11_KIT_STRICT=1");
	p11_debug_init ();

	SUITE_ADD_TEST (suite, test_parse_conf_1);
	SUITE_ADD_TEST (suite, test_parse_ignore_missing);
	SUITE_ADD_TEST (suite, test_parse_fail_missing);
	SUITE_ADD_TEST (suite, test_merge_defaults);
	SUITE_ADD_TEST (suite, test_load_globals_merge);
	SUITE_ADD_TEST (suite, test_load_globals_no_user);
	SUITE_ADD_TEST (suite, test_load_globals_system_sets_only);
	SUITE_ADD_TEST (suite, test_load_globals_user_sets_only);
	SUITE_ADD_TEST (suite, test_load_globals_system_sets_invalid);
	SUITE_ADD_TEST (suite, test_load_globals_user_sets_invalid);
	SUITE_ADD_TEST (suite, test_load_modules_merge);
	SUITE_ADD_TEST (suite, test_load_modules_no_user);
	SUITE_ADD_TEST (suite, test_load_modules_user_only);
	SUITE_ADD_TEST (suite, test_load_modules_user_none);
	SUITE_ADD_TEST (suite, test_parse_boolean);

	CuSuiteRun (suite);
	CuSuiteSummary (suite, output);
	CuSuiteDetails (suite, output);
	printf ("%s\n", output->buffer);
	ret = suite->failCount;
	CuSuiteDelete (suite);
	CuStringDelete (output);
	return ret;
}
