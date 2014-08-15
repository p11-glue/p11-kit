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
#include "test.h"

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "conf.h"
#include "debug.h"
#include "message.h"
#include "p11-kit.h"
#include "private.h"

#ifdef OS_UNIX
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

static void
test_parse_conf_1 (void)
{
	p11_dict *map;
	const char *value;

	map = _p11_conf_parse_file (SRCDIR "/p11-kit/fixtures/test-1.conf", NULL, 0);
	assert_ptr_not_null (map);

	value = p11_dict_get (map, "key1");
	assert_str_eq ("value1", value);

	value = p11_dict_get (map, "with-colon");
	assert_str_eq ("value-of-colon", value);

	value = p11_dict_get (map, "with-whitespace");
	assert_str_eq ("value-with-whitespace", value);

	value = p11_dict_get (map, "embedded-comment");
	assert_str_eq ("this is # not a comment", value);

	p11_dict_free (map);
}

static void
test_parse_ignore_missing (void)
{
	p11_dict *map;

	map = _p11_conf_parse_file (SRCDIR "/p11-kit/fixtures/non-existant.conf", NULL, CONF_IGNORE_MISSING);
	assert_ptr_not_null (map);

	assert_num_eq (0, p11_dict_size (map));
	assert (p11_message_last () == NULL);
	p11_dict_free (map);
}

static void
test_parse_fail_missing (void)
{
	p11_dict *map;

	map = _p11_conf_parse_file (SRCDIR "/p11-kit/fixtures/non-existant.conf", NULL, 0);
	assert (map == NULL);
	assert_ptr_not_null (p11_message_last ());
}

static void
test_merge_defaults (void)
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
		assert_not_reached ();

	p11_dict_free (defaults);

	assert_str_eq (p11_dict_get (values, "one"), "real1");
	assert_str_eq (p11_dict_get (values, "two"), "real2");
	assert_str_eq (p11_dict_get (values, "three"), "default3");

	p11_dict_free (values);
}

static void
test_load_globals_merge (void)
{
	int user_mode = -1;
	p11_dict *config;

	p11_message_clear ();

	config = _p11_conf_load_globals (SRCDIR "/p11-kit/fixtures/test-system-merge.conf",
	                                 SRCDIR "/p11-kit/fixtures/test-user.conf",
	                                 &user_mode);
	assert_ptr_not_null (config);
	assert (NULL == p11_message_last ());
	assert_num_eq (CONF_USER_MERGE, user_mode);

	assert_str_eq (p11_dict_get (config, "key1"), "system1");
	assert_str_eq (p11_dict_get (config, "key2"), "user2");
	assert_str_eq (p11_dict_get (config, "key3"), "user3");

	p11_dict_free (config);
}

static void
test_load_globals_no_user (void)
{
	int user_mode = -1;
	p11_dict *config;

	p11_message_clear ();

	config = _p11_conf_load_globals (SRCDIR "/p11-kit/fixtures/test-system-none.conf",
	                                 SRCDIR "/p11-kit/fixtures/test-user.conf",
	                                 &user_mode);
	assert_ptr_not_null (config);
	assert (NULL == p11_message_last ());
	assert_num_eq (CONF_USER_NONE, user_mode);

	assert_str_eq (p11_dict_get (config, "key1"), "system1");
	assert_str_eq (p11_dict_get (config, "key2"), "system2");
	assert_str_eq (p11_dict_get (config, "key3"), "system3");

	p11_dict_free (config);
}

static void
test_load_globals_user_sets_only (void)
{
	int user_mode = -1;
	p11_dict *config;

	p11_message_clear ();

	config = _p11_conf_load_globals (SRCDIR "/p11-kit/fixtures/test-system-merge.conf",
	                                 SRCDIR "/p11-kit/fixtures/test-user-only.conf",
	                                 &user_mode);
	assert_ptr_not_null (config);
	assert (NULL == p11_message_last ());
	assert_num_eq (CONF_USER_ONLY, user_mode);

	assert (p11_dict_get (config, "key1") == NULL);
	assert_str_eq (p11_dict_get (config, "key2"), "user2");
	assert_str_eq (p11_dict_get (config, "key3"), "user3");

	p11_dict_free (config);
}

static void
test_load_globals_system_sets_only (void)
{
	int user_mode = -1;
	p11_dict *config;

	p11_message_clear ();

	config = _p11_conf_load_globals (SRCDIR "/p11-kit/fixtures/test-system-only.conf",
	                                 SRCDIR "/p11-kit/fixtures/test-user.conf",
	                                 &user_mode);
	assert_ptr_not_null (config);
	assert (NULL == p11_message_last ());
	assert_num_eq (CONF_USER_ONLY, user_mode);

	assert (p11_dict_get (config, "key1") == NULL);
	assert_str_eq (p11_dict_get (config, "key2"), "user2");
	assert_str_eq (p11_dict_get (config, "key3"), "user3");

	p11_dict_free (config);
}

static void
test_load_globals_system_sets_invalid (void)
{
	int user_mode = -1;
	p11_dict *config;
	int error;

	p11_message_clear ();

	config = _p11_conf_load_globals (SRCDIR "/p11-kit/fixtures/test-system-invalid.conf",
	                                 SRCDIR "/p11-kit/fixtures/non-existant.conf",
	                                 &user_mode);
	error = errno;
	assert_ptr_eq (NULL, config);
	assert_num_eq (EINVAL, error);
	assert_ptr_not_null (p11_message_last ());

	p11_dict_free (config);
}

static void
test_load_globals_user_sets_invalid (void)
{
	int user_mode = -1;
	p11_dict *config;
	int error;

	p11_message_clear ();

	config = _p11_conf_load_globals (SRCDIR "/p11-kit/fixtures/test-system-merge.conf",
	                                 SRCDIR "/p11-kit/fixtures/test-user-invalid.conf",
	                                 &user_mode);
	error = errno;
	assert_ptr_eq (NULL, config);
	assert_num_eq (EINVAL, error);
	assert_ptr_not_null (p11_message_last ());

	p11_dict_free (config);
}

static bool
assert_msg_contains (const char *msg,
                     const char *text)
{
	return (msg && strstr (msg, text)) ? true : false;
}

static void
test_load_modules_merge (void)
{
	p11_dict *configs;
	p11_dict *config;

	p11_message_clear ();

	configs = _p11_conf_load_modules (CONF_USER_MERGE,
	                                  SRCDIR "/p11-kit/fixtures/package-modules",
	                                  SRCDIR "/p11-kit/fixtures/system-modules",
	                                  SRCDIR "/p11-kit/fixtures/user-modules");
	assert_ptr_not_null (configs);
	assert (assert_msg_contains (p11_message_last (), "invalid config filename"));

	config = p11_dict_get (configs, "one");
	assert_ptr_not_null (config);
	assert_str_eq ("mock-one.so", p11_dict_get (config, "module"));
	assert_str_eq (p11_dict_get (config, "setting"), "user1");

	config = p11_dict_get (configs, "two.badname");
	assert_ptr_not_null (config);
	assert_str_eq ("mock-two.so", p11_dict_get (config, "module"));
	assert_str_eq (p11_dict_get (config, "setting"), "system2");

	config = p11_dict_get (configs, "three");
	assert_ptr_not_null (config);
	assert_str_eq ("mock-three.so", p11_dict_get (config, "module"));
	assert_str_eq (p11_dict_get (config, "setting"), "user3");

	p11_dict_free (configs);
}

static void
test_load_modules_user_none (void)
{
	p11_dict *configs;
	p11_dict *config;

	p11_message_clear ();

	configs = _p11_conf_load_modules (CONF_USER_NONE,
	                                  SRCDIR "/p11-kit/fixtures/package-modules",
	                                  SRCDIR "/p11-kit/fixtures/system-modules",
	                                  SRCDIR "/p11-kit/fixtures/user-modules");
	assert_ptr_not_null (configs);
	assert (assert_msg_contains (p11_message_last (), "invalid config filename"));

	config = p11_dict_get (configs, "one");
	assert_ptr_not_null (config);
	assert_str_eq ("mock-one.so", p11_dict_get (config, "module"));
	assert_str_eq (p11_dict_get (config, "setting"), "system1");

	config = p11_dict_get (configs, "two.badname");
	assert_ptr_not_null (config);
	assert_str_eq ("mock-two.so", p11_dict_get (config, "module"));
	assert_str_eq (p11_dict_get (config, "setting"), "system2");

	config = p11_dict_get (configs, "three");
	assert_ptr_eq (NULL, config);

	p11_dict_free (configs);
}

static void
test_load_modules_user_only (void)
{
	p11_dict *configs;
	p11_dict *config;

	p11_message_clear ();

	configs = _p11_conf_load_modules (CONF_USER_ONLY,
	                                  SRCDIR "/p11-kit/fixtures/package-modules",
	                                  SRCDIR "/p11-kit/fixtures/system-modules",
	                                  SRCDIR "/p11-kit/fixtures/user-modules");
	assert_ptr_not_null (configs);
	assert_ptr_eq (NULL, (void *)p11_message_last ());

	config = p11_dict_get (configs, "one");
	assert_ptr_not_null (config);
	assert (p11_dict_get (config, "module") == NULL);
	assert_str_eq (p11_dict_get (config, "setting"), "user1");

	config = p11_dict_get (configs, "two.badname");
	assert_ptr_eq (NULL, config);

	config = p11_dict_get (configs, "three");
	assert_ptr_not_null (config);
	assert_str_eq ("mock-three.so", p11_dict_get (config, "module"));
	assert_str_eq (p11_dict_get (config, "setting"), "user3");

	p11_dict_free (configs);
}

static void
test_load_modules_no_user (void)
{
	p11_dict *configs;
	p11_dict *config;

	p11_message_clear ();

	configs = _p11_conf_load_modules (CONF_USER_MERGE,
	                                  SRCDIR "/p11-kit/fixtures/package-modules",
	                                  SRCDIR "/p11-kit/fixtures/system-modules",
	                                  SRCDIR "/p11-kit/fixtures/non-existant");
	assert_ptr_not_null (configs);
	assert (assert_msg_contains (p11_message_last (), "invalid config filename"));

	config = p11_dict_get (configs, "one");
	assert_ptr_not_null (config);
	assert_str_eq ("mock-one.so", p11_dict_get (config, "module"));
	assert_str_eq (p11_dict_get (config, "setting"), "system1");

	config = p11_dict_get (configs, "two.badname");
	assert_ptr_not_null (config);
	assert_str_eq ("mock-two.so", p11_dict_get (config, "module"));
	assert_str_eq (p11_dict_get (config, "setting"), "system2");

	config = p11_dict_get (configs, "three");
	assert_ptr_eq (NULL, config);

	p11_dict_free (configs);
}

static void
test_parse_boolean (void)
{
	p11_message_quiet ();

	assert_num_eq (true, _p11_conf_parse_boolean ("yes", false));
	assert_num_eq (false, _p11_conf_parse_boolean ("no", true));
	assert_num_eq (true, _p11_conf_parse_boolean ("!!!", true));
}

#ifdef OS_UNIX

static void
test_setuid (void)
{
	const char *args[] = { BUILDDIR "/frob-setuid", NULL, };
	char *path;
	int ret;

	/* This is the 'number' setting set in one.module user configuration. */
	ret = p11_test_run_child (args, true);
	assert_num_eq (ret, 33);

	path = p11_test_copy_setgid (args[0]);
	if (path == NULL)
		return;

	args[0] = path;

	/* This is the 'number' setting set in one.module system configuration. */
	ret = p11_test_run_child (args, true);
	assert_num_eq (ret, 18);

	if (unlink (path) < 0)
		assert_fail ("unlink failed", strerror (errno));
	free (path);
}

#endif /* OS_UNIX */

int
main (int argc,
      char *argv[])
{
	p11_test (test_parse_conf_1, "/conf/test_parse_conf_1");
	p11_test (test_parse_ignore_missing, "/conf/test_parse_ignore_missing");
	p11_test (test_parse_fail_missing, "/conf/test_parse_fail_missing");
	p11_test (test_merge_defaults, "/conf/test_merge_defaults");
	p11_test (test_load_globals_merge, "/conf/test_load_globals_merge");
	p11_test (test_load_globals_no_user, "/conf/test_load_globals_no_user");
	p11_test (test_load_globals_system_sets_only, "/conf/test_load_globals_system_sets_only");
	p11_test (test_load_globals_user_sets_only, "/conf/test_load_globals_user_sets_only");
	p11_test (test_load_globals_system_sets_invalid, "/conf/test_load_globals_system_sets_invalid");
	p11_test (test_load_globals_user_sets_invalid, "/conf/test_load_globals_user_sets_invalid");
	p11_test (test_load_modules_merge, "/conf/test_load_modules_merge");
	p11_test (test_load_modules_no_user, "/conf/test_load_modules_no_user");
	p11_test (test_load_modules_user_only, "/conf/test_load_modules_user_only");
	p11_test (test_load_modules_user_none, "/conf/test_load_modules_user_none");
	p11_test (test_parse_boolean, "/conf/test_parse_boolean");
#ifdef OS_UNIX
	/* Don't run this test when under fakeroot */
	if (!getenv ("FAKED_MODE")) {
		p11_test (test_setuid, "/conf/setuid");
	}
#endif
	return p11_test_run (argc, argv);
}
