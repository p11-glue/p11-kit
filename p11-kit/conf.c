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

#include "compat.h"
#include "conf.h"
#define DEBUG_FLAG DEBUG_CONF
#include "debug.h"
#include "private.h"

#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <assert.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef OS_UNIX
#include <pwd.h>
#endif

#ifdef OS_WIN32
#include <shlobj.h>
#endif

static void
strcln (char* data, char ch)
{
	char* p;
	for (p = data; *data; data++, p++) {
		while (*data == ch)
			data++;
		*p = *data;
	}

	/* Renull terminate */
	*p = 0;
}

static char*
strbtrim (const char* data)
{
	while (*data && isspace (*data))
		++data;
	return (char*)data;
}

static void
stretrim (char* data)
{
	char* t = data + strlen (data);
	while (t > data && isspace (*(t - 1))) {
		t--;
		*t = 0;
	}
}

static char*
strtrim (char* data)
{
	data = (char*)strbtrim (data);
	stretrim (data);
	return data;
}

static int
strequal (const char *one, const char *two)
{
	return strcmp (one, two) == 0;
}

static char*
strconcat (const char *first, ...)
{
	size_t length = 0;
	const char *arg;
	char *result, *at;
	va_list va;

	va_start (va, first);

	for (arg = first; arg; arg = va_arg (va, const char*))
		length += strlen (arg);

	va_end (va);

	at = result = malloc (length + 1);
	if (!result) {
		errno = ENOMEM;
		return NULL;
	}

	va_start (va, first);

	for (arg = first; arg; arg = va_arg (va, const char*)) {
		length = strlen (arg);
		memcpy (at, arg, length);
		at += length;
	}

	va_end (va);

	*at = 0;
	return result;
}

/* -----------------------------------------------------------------------------
 * CONFIG PARSER
 */

static char*
read_config_file (const char* filename, int flags)
{
	char* config = NULL;
	FILE* f = NULL;
	int error = 0;
	long len;

	assert (filename);

	f = fopen (filename, "r");
	if (f == NULL) {
		error = errno;
		if ((flags & CONF_IGNORE_MISSING) &&
		    (error == ENOENT || error == ENOTDIR)) {
			_p11_debug ("config file does not exist");
			config = strdup ("\n");
			if (!config)
				errno = ENOMEM;
			return config;
		}
		_p11_message ("couldn't open config file: %s: %s", filename,
		              strerror (error));
		errno = error;
		return NULL;
	}

	/* Figure out size */
	if (fseek (f, 0, SEEK_END) == -1 ||
	    (len = ftell (f)) == -1 ||
	    fseek (f, 0, SEEK_SET) == -1) {
		error = errno;
		_p11_message ("couldn't seek config file: %s", filename);
		errno = error;
		return NULL;
	}

	if ((config = (char*)malloc (len + 2)) == NULL) {
		_p11_message ("out of memory");
		errno = ENOMEM;
		return NULL;
	}

	/* And read in one block */
	if (fread (config, 1, len, f) != len) {
		error = errno;
		_p11_message ("couldn't read config file: %s", filename);
		errno = error;
		return NULL;
	}

	fclose (f);

	/* Null terminate the data */
	config[len] = '\n';
	config[len + 1] = 0;

	/* Remove nasty dos line endings */
	strcln (config, '\r');

	return config;
}

int
_p11_conf_merge_defaults (hashmap *map, hashmap *defaults)
{
	hashiter iter;
	void *key;
	void *value;

	_p11_hash_iterate (defaults, &iter);
	while (_p11_hash_next (&iter, &key, &value)) {
		/* Only override if not set */
		if (_p11_hash_get (map, key))
			continue;
		key = strdup (key);
		if (key == NULL) {
			errno = ENOMEM;
			return -1;
		}
		value = strdup (value);
		if (value == NULL) {
			free (key);
			errno = ENOMEM;
			return -1;
		}
		if (!_p11_hash_set (map, key, value)) {
			free (key);
			free (value);
			errno = ENOMEM;
			return -1;
		}
		key = NULL;
		value = NULL;
	}

	return 0;
}

hashmap *
_p11_conf_parse_file (const char* filename, int flags)
{
	char *name;
	char *value;
	hashmap *map = NULL;
	char *data;
	char *next;
	char *end;
	int error = 0;

	assert (filename);

	_p11_debug ("reading config file: %s", filename);

	/* Adds an extra newline to end of file */
	data = read_config_file (filename, flags);
	if (!data)
		return NULL;

	map = _p11_hash_create (_p11_hash_string_hash, _p11_hash_string_equal, free, free);
	if (map == NULL) {
		free (data);
		errno = ENOMEM;
		return NULL;
	}
	next = data;

	/* Go through lines and process them */
	while ((end = strchr (next, '\n')) != NULL) {
		*end = 0;
		name = strbtrim (next);
		next = end + 1;

		/* Empty lines / comments at start */
		if (!*name || *name == '#')
			continue;

		/* Look for the break between name: value on the same line */
		value = name + strcspn (name, ":");
		if (!*value) {
			_p11_message ("%s: invalid config line: %s", filename, name);
			error = EINVAL;
			break;
		}

		/* Null terminate and split value part */
		*value = 0;
		value++;

		name = strtrim (name);
		value = strtrim (value);

		name = strdup (name);
		if (!name) {
			error = ENOMEM;
			break;
		}
		value = strdup (value);
		if (!value) {
			free (name);
			error = ENOMEM;
			break;
		}

		_p11_debug ("config value: %s: %s", name, value);

		if (!_p11_hash_set (map, name, value)) {
			free (name);
			free (value);
			error = ENOMEM;
			break;
		}
	}

	free (data);

	if (error != 0) {
		_p11_hash_free (map);
		map = NULL;
		errno = error;
	}

	return map;
}

static char *
expand_user_path (const char *path)
{
	const char *env;

	if (path[0] != '~' || path[1] != '/')
		return strdup (path);

	path += 1;
	env = getenv ("HOME");
	if (env && env[0]) {
		return strconcat (env, path, NULL);

	} else {
#ifdef OS_UNIX
		struct passwd *pwd;
		int error = 0;

		pwd = getpwuid (getuid ());
		if (!pwd) {
			error = errno;
			_p11_message ("couldn't lookup home directory for user %d: %s",
			              getuid (), strerror (errno));
			errno = error;
			return NULL;
		}

		return strconcat (pwd->pw_dir, path, NULL);

#else /* OS_WIN32 */
		char directory[MAX_PATH + 1];

		if (!SHGetSpecialFolderPathA (NULL, directory, CSIDL_PROFILE, TRUE)) {
			_p11_message ("couldn't lookup home directory for user");
			errno = ENOTDIR;
			return NULL;
		}

		return strconcat (directory, path, NULL);
#endif /* OS_WIN32 */
	}
}

static int
user_config_mode (hashmap *config, int defmode)
{
	const char *mode;

	/* Whether we should use or override from user directory */
	mode = _p11_hash_get (config, "user-config");
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
		_p11_message ("invalid mode for 'user-config': %s", mode);
		return CONF_USER_INVALID;
	}
}

hashmap *
_p11_conf_load_globals (const char *system_conf, const char *user_conf,
                        int *user_mode)
{
	hashmap *config = NULL;
	hashmap *uconfig = NULL;
	hashmap *result = NULL;
	char *path = NULL;
	int error = 0;
	int mode;

	/*
	 * This loads the system and user configs. This depends on the user-config
	 * value in both the system and user configs. A bit more complex than
	 * you might imagine, since user-config can be set to 'none' in the
	 * user configuration, essentially turning itself off.
	 */

	/* Load the main configuration */
	config = _p11_conf_parse_file (system_conf, CONF_IGNORE_MISSING);
	if (!config)
		goto finished;

	/* Whether we should use or override from user directory */
	mode = user_config_mode (config, CONF_USER_NONE);
	if (mode == CONF_USER_INVALID) {
		error = EINVAL;
		goto finished;
	}

	if (mode != CONF_USER_NONE) {
		path = expand_user_path (user_conf);
		if (!path) {
			error = errno;
			goto finished;
		}

		/* Load up the user configuration */
		uconfig = _p11_conf_parse_file (path, CONF_IGNORE_MISSING);
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
			if (_p11_conf_merge_defaults (uconfig, config) < 0) {
				error = errno;
				goto finished;
			}
		}

		/* If user config valid at all, then replace system with what we have */
		if (mode != CONF_USER_NONE) {
			_p11_hash_free (config);
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
	_p11_hash_free (config);
	_p11_hash_free (uconfig);
	errno = error;
	return result;
}

static int
load_config_from_file (const char *configfile, const char *name, hashmap *configs)
{
	hashmap *config;
	hashmap *prev;
	char *key;
	int error = 0;

	assert (configfile);

	config = _p11_conf_parse_file (configfile, 0);
	if (!config)
		return -1;

	prev = _p11_hash_get (configs, name);
	if (prev == NULL) {
		key = strdup (name);
		if (key == NULL)
			error = ENOMEM;
		else if (!_p11_hash_set (configs, key, config))
			error = errno;
		else
			config = NULL;
	} else {
		if (_p11_conf_merge_defaults (prev, config) < 0)
			error = errno;
	}

	/* If still set */
	_p11_hash_free (config);

	if (error) {
		errno = error;
		return -1;
	}

	return 0;
}

static int
load_configs_from_directory (const char *directory, hashmap *configs)
{
	struct dirent *dp;
	struct stat st;
	DIR *dir;
	int error = 0;
	int is_dir;
	char *path;
	int count = 0;

	_p11_debug ("loading module configs in: %s", directory);

	/* First we load all the modules */
	dir = opendir (directory);
	if (!dir) {
		error = errno;
		if (errno == ENOENT || errno == ENOTDIR)
			return 0;
		_p11_message ("couldn't list directory: %s: %s", directory,
		              strerror (error));
		errno = error;
		return -1;
	}

	/* We're within a global mutex, so readdir is safe */
	while ((dp = readdir(dir)) != NULL) {
		path = strconcat (directory, "/", dp->d_name, NULL);
		if (!path) {
			error = ENOMEM;
			break;
		}

		is_dir = 0;
#ifdef HAVE_STRUCT_DIRENT_D_TYPE
		if(dp->d_type != DT_UNKNOWN) {
			is_dir = (dp->d_type == DT_DIR);
		} else
#endif
		{
			if (stat (path, &st) < 0) {
				error = errno;
				_p11_message ("couldn't stat path: %s", path);
				free (path);
				break;
			}
			is_dir = S_ISDIR (st.st_mode);
		}

		if (!is_dir && load_config_from_file (path, dp->d_name, configs) < 0) {
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
		return -1;
	}

	return count;
}

hashmap *
_p11_conf_load_modules (int mode, const char *system_dir, const char *user_dir)
{
	hashmap *configs;
	char *path;
	int error = 0;

	/* A hash table of name -> config */
	configs = _p11_hash_create (_p11_hash_string_hash, _p11_hash_string_equal,
	                            free, (hash_destroy_func)_p11_hash_free);

	/* Load each user config first, if user config is allowed */
	if (mode != CONF_USER_NONE) {
		path = expand_user_path (user_dir);
		if (!path)
			error = errno;
		else if (load_configs_from_directory (path, configs) < 0)
			error = errno;
		free (path);
		if (error != 0) {
			_p11_hash_free (configs);
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
		if (load_configs_from_directory (system_dir, configs) < 0) {
			error = errno;
			_p11_hash_free (configs);
			errno = error;
			return NULL;
		}
	}

	return configs;
}

int
_p11_conf_parse_boolean (const char *string,
                         int default_value)
{
	if (!string)
		return default_value;

	if (strcmp (string, "yes") == 0) {
		return 1;
	} else if (strcmp (string, "no") == 0) {
		return 0;
	} else {
		_p11_message ("invalid setting '%s' defaulting to '%s'",
		              default_value ? "yes" : "no");
		return default_value;
	}
}
