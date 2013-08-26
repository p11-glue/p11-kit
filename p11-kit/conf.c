/*
 * Copyright (c) 2005 Stefan Walter
 * Copyright (c) 2011 Collabora Ltd.
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
 *
 * CONTRIBUTORS
 *  Stef Walter <stef@memberwebs.com>
 */

#include "config.h"

#include "conf.h"
#define P11_DEBUG_FLAG P11_DEBUG_CONF
#include "debug.h"
#include "lexer.h"
#include "message.h"
#include "path.h"
#include "private.h"

#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <assert.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int
strequal (const char *one, const char *two)
{
	return strcmp (one, two) == 0;
}

/* -----------------------------------------------------------------------------
 * CONFIG PARSER
 */

bool
_p11_conf_merge_defaults (p11_dict *map,
                          p11_dict *defaults)
{
	p11_dictiter iter;
	void *key;
	void *value;

	p11_dict_iterate (defaults, &iter);
	while (p11_dict_next (&iter, &key, &value)) {
		/* Only override if not set */
		if (p11_dict_get (map, key))
			continue;
		key = strdup (key);
		return_val_if_fail (key != NULL, false);
		value = strdup (value);
		return_val_if_fail (key != NULL, false);
		if (!p11_dict_set (map, key, value))
			return_val_if_reached (false);
	}

	return true;
}

p11_dict *
_p11_conf_parse_file (const char* filename,
                      struct stat *sb,
                      int flags)
{
	p11_dict *map = NULL;
	void *data;
	p11_lexer lexer;
	bool failed = false;
	size_t length;
	p11_mmap *mmap;
	int error;

	assert (filename);

	p11_debug ("reading config file: %s", filename);

	mmap = p11_mmap_open (filename, sb, &data, &length);
	if (mmap == NULL) {
		error = errno;
		if ((flags & CONF_IGNORE_MISSING) &&
		    (error == ENOENT || error == ENOTDIR)) {
			p11_debug ("config file does not exist");

		} else if ((flags & CONF_IGNORE_ACCESS_DENIED) &&
		           (error == EPERM || error == EACCES)) {
			p11_debug ("config file is inaccessible");

		} else {
			p11_message_err (error, "couldn't open config file: %s", filename);
			errno = error;
			return NULL;
		}
	}

	map = p11_dict_new (p11_dict_str_hash, p11_dict_str_equal, free, free);
	return_val_if_fail (map != NULL, NULL);

	/* Empty config fall through above */
	if (mmap == NULL)
		return map;

	p11_lexer_init (&lexer, filename, data, length);
	while (p11_lexer_next (&lexer, &failed)) {
		switch (lexer.tok_type) {
		case TOK_FIELD:
			p11_debug ("config value: %s: %s", lexer.tok.field.name,
			           lexer.tok.field.value);
			if (!p11_dict_set (map, lexer.tok.field.name, lexer.tok.field.value))
				return_val_if_reached (NULL);
			lexer.tok.field.name = NULL;
			lexer.tok.field.value = NULL;
			break;
		case TOK_PEM:
			p11_message ("%s: unexpected pem block", filename);
			failed = true;
			break;
		case TOK_SECTION:
			p11_message ("%s: unexpected section header", filename);
			failed = true;
			break;
		case TOK_EOF:
			assert_not_reached ();
			break;
		}

		if (failed)
			break;
	}

	p11_lexer_done (&lexer);
	p11_mmap_close (mmap);

	if (failed) {
		p11_dict_free (map);
		map = NULL;
		errno = EINVAL;
	}

	return map;
}

static int
user_config_mode (p11_dict *config,
                  int defmode)
{
	const char *mode;

	/* Whether we should use or override from user directory */
	mode = p11_dict_get (config, "user-config");
	if (mode == NULL) {
		return defmode;
	} else if (strequal (mode, "none")) {
		return CONF_USER_NONE;
	} else if (strequal (mode, "merge")) {
		return CONF_USER_MERGE;
	} else if (strequal (mode, "only")) {
		return CONF_USER_ONLY;
	} else if (strequal (mode, "override")) {
		return CONF_USER_ONLY;
	} else {
		p11_message ("invalid mode for 'user-config': %s", mode);
		return CONF_USER_INVALID;
	}
}

p11_dict *
_p11_conf_load_globals (const char *system_conf, const char *user_conf,
                        int *user_mode)
{
	p11_dict *config = NULL;
	p11_dict *uconfig = NULL;
	p11_dict *result = NULL;
	char *path = NULL;
	int error = 0;
	int flags;
	int mode;

	/*
	 * This loads the system and user configs. This depends on the user-config
	 * value in both the system and user configs. A bit more complex than
	 * you might imagine, since user-config can be set to 'none' in the
	 * user configuration, essentially turning itself off.
	 */

	/* Load the main configuration */
	config = _p11_conf_parse_file (system_conf, NULL, CONF_IGNORE_MISSING);
	if (!config)
		goto finished;

	/* Whether we should use or override from user directory */
	mode = user_config_mode (config, CONF_USER_MERGE);
	if (mode == CONF_USER_INVALID) {
		error = EINVAL;
		goto finished;
	}

	if (mode != CONF_USER_NONE && getauxval (AT_SECURE)) {
		p11_debug ("skipping user config in setuid or setgid program");
		mode = CONF_USER_NONE;
	}

	if (mode != CONF_USER_NONE) {
		path = p11_path_expand (user_conf);
		if (!path) {
			error = errno;
			goto finished;
		}

		/* Load up the user configuration, ignore selinux denying us access */
		flags = CONF_IGNORE_MISSING | CONF_IGNORE_ACCESS_DENIED;
		uconfig = _p11_conf_parse_file (path, NULL, flags);
		if (!uconfig) {
			error = errno;
			goto finished;
		}

		/* Figure out what the user mode is, defaulting to system mode if not set */
		mode = user_config_mode (uconfig, mode);
		if (mode == CONF_USER_INVALID) {
			error = EINVAL;
			goto finished;
		}

		/* If merging, then supplement user config with system values */
		if (mode == CONF_USER_MERGE) {
			if (!_p11_conf_merge_defaults (uconfig, config)) {
				error = errno;
				goto finished;
			}
		}

		/* If user config valid at all, then replace system with what we have */
		if (mode != CONF_USER_NONE) {
			p11_dict_free (config);
			config = uconfig;
			uconfig = NULL;
		}
	}

	if (user_mode)
		*user_mode = mode;

	result = config;
	config = NULL;

finished:
	free (path);
	p11_dict_free (config);
	p11_dict_free (uconfig);
	errno = error;
	return result;
}

static char *
calc_name_from_filename (const char *fname)
{
	/* We eventually want to settle on .module */
	static const char *const suffix = ".module";
	static const size_t suffix_len = 7;
	const char *c = fname;
	size_t fname_len;
	size_t name_len;
	char *name;

	assert (fname);

	/* Make sure the filename starts with an alphanumeric */
	if (!isalnum(*c))
		return NULL;
	++c;

	/* Only allow alnum, _, -, and . */
	while (*c) {
		if (!isalnum(*c) && *c != '_' && *c != '-' && *c != '.')
			return NULL;
		++c;
	}

	/* Make sure we have one of the suffixes */
	fname_len = strlen (fname);
	if (suffix_len >= fname_len)
		return NULL;
	name_len = (fname_len - suffix_len);
	if (strcmp (fname + name_len, suffix) != 0)
		return NULL;

	name = malloc (name_len + 1);
	return_val_if_fail (name != NULL, NULL);
	memcpy (name, fname, name_len);
	name[name_len] = 0;
	return name;
}

static bool
load_config_from_file (const char *configfile,
                       struct stat *sb,
                       const char *name,
                       p11_dict *configs,
                       int flags)
{
	p11_dict *config;
	p11_dict *prev;
	char *key;
	int error = 0;

	assert (configfile);

	key = calc_name_from_filename (name);
	if (key == NULL) {
		p11_message ("invalid config filename, will be ignored in the future: %s", configfile);
		key = strdup (name);
		return_val_if_fail (key != NULL, false);
	}

	config = _p11_conf_parse_file (configfile, sb, flags);
	if (!config) {
		free (key);
		return false;
	}

	prev = p11_dict_get (configs, key);
	if (prev == NULL) {
		if (!p11_dict_set (configs, key, config))
			return_val_if_reached (false);
		config = NULL;
	} else {
		if (!_p11_conf_merge_defaults (prev, config))
			error = errno;
		free (key);
	}

	/* If still set */
	p11_dict_free (config);

	if (error) {
		errno = error;
		return false;
	}

	return true;
}

static bool
load_configs_from_directory (const char *directory,
                             p11_dict *configs,
                             int flags)
{
	struct dirent *dp;
	struct stat st;
	DIR *dir;
	int error = 0;
	bool is_dir;
	char *path;
	int count = 0;

	p11_debug ("loading module configs in: %s", directory);

	/* First we load all the modules */
	dir = opendir (directory);
	if (!dir) {
		error = errno;
		if ((flags & CONF_IGNORE_MISSING) &&
		    (errno == ENOENT || errno == ENOTDIR)) {
			p11_debug ("module configs do not exist");
			return true;
		} else if ((flags & CONF_IGNORE_ACCESS_DENIED) &&
		           (errno == EPERM || errno == EACCES)) {
			p11_debug ("couldn't list inacessible module configs");
			return true;
		}
		p11_message_err (error, "couldn't list directory: %s", directory);
		errno = error;
		return false;
	}

	while ((dp = readdir(dir)) != NULL) {
		path = p11_path_build (directory, dp->d_name, NULL);
		return_val_if_fail (path != NULL, false);

		if (stat (path, &st) < 0) {
			error = errno;
			p11_message_err (error, "couldn't stat path: %s", path);
			free (path);
			break;
		}

		is_dir = S_ISDIR (st.st_mode);

		if (!is_dir && !load_config_from_file (path, &st, dp->d_name, configs, flags)) {
			error = errno;
			free (path);
			break;
		}

		free (path);
		count ++;
	}

	closedir (dir);

	if (error) {
		errno = error;
		return false;
	}

	return true;
}

p11_dict *
_p11_conf_load_modules (int mode,
                        const char *package_dir,
                        const char *system_dir,
                        const char *user_dir)
{
	p11_dict *configs;
	char *path;
	int error = 0;
	int flags;

	/* A hash table of name -> config */
	configs = p11_dict_new (p11_dict_str_hash, p11_dict_str_equal,
	                        free, (p11_destroyer)p11_dict_free);

	/* Load each user config first, if user config is allowed */
	if (mode != CONF_USER_NONE) {
		flags = CONF_IGNORE_MISSING | CONF_IGNORE_ACCESS_DENIED;
		path = p11_path_expand (user_dir);
		if (!path)
			error = errno;
		else if (!load_configs_from_directory (path, configs, flags))
			error = errno;
		free (path);
		if (error != 0) {
			p11_dict_free (configs);
			errno = error;
			return NULL;
		}
	}

	/*
	 * Now unless user config is overriding, load system modules.
	 * Basically if a value for the same config name is not already
	 * loaded above (in the user configs) then they're loaded here.
	 */
	if (mode != CONF_USER_ONLY) {
		flags = CONF_IGNORE_MISSING;
		if (!load_configs_from_directory (system_dir, configs, flags) ||
		    !load_configs_from_directory (package_dir, configs, flags)) {
			error = errno;
			p11_dict_free (configs);
			errno = error;
			return NULL;
		}
	}

	return configs;
}

bool
_p11_conf_parse_boolean (const char *string,
                         bool default_value)
{
	if (!string)
		return default_value;

	if (strcmp (string, "yes") == 0) {
		return true;
	} else if (strcmp (string, "no") == 0) {
		return false;
	} else {
		p11_message ("invalid setting '%s' defaulting to '%s'",
		             string, default_value ? "yes" : "no");
		return default_value;
	}
}
