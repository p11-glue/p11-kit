/*
 * Copyright (C) 2011 Collabora Ltd.
 * Copyright (C) 2008 Stefan Walter
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

#include "conf.h"
#include "hash.h"
#include "pkcs11.h"
#include "p11-kit.h"
#include "p11-kit-private.h"

#include <sys/types.h>

#include <assert.h>
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <pthread.h>
#include <pwd.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

typedef struct _Module {
	char *name;
	hash_t *config;
	void *dl_module;
	CK_FUNCTION_LIST_PTR funcs;
	int ref_count;
	int initialize_count;
} Module;

/*
 * This is the mutex that protects the global data of this library
 * and the pkcs11 proxy module. Note that we *never* call into our
 * underlying pkcs11 modules while holding this mutex. Therefore it
 * doesn't have to be recursive and we can keep things simple.
 */
pthread_mutex_t _p11_mutex = PTHREAD_MUTEX_INITIALIZER;

/*
 * Shared data between threads, protected by the mutex, a structure so
 * we can audit thread safety easier.
 */
static struct _Shared {
	hash_t *modules;
	hash_t *config;
} gl = { NULL, NULL };

/* -----------------------------------------------------------------------------
 * UTILITIES
 */

static void
warning (const char* msg, ...)
{
	char buffer[512];
	va_list va;

	va_start (va, msg);

	vsnprintf(buffer, sizeof (buffer) - 1, msg, va);
	buffer[sizeof (buffer) - 1] = 0;
	fprintf (stderr, "p11-kit: %s\n", buffer);

	va_end (va);
}

static void
conf_error (const char *buffer)
{
	/* called from conf.c */
	fprintf (stderr, "p11-kit: %s\n", buffer);
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

	at = result = malloc (length);
	if (!result)
		return NULL;

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

static int
strequal (const char *one, const char *two)
{
	return strcmp (one, two) == 0;
}

/* -----------------------------------------------------------------------------
 * P11-KIT FUNCTIONALITY
 */

static void
free_module_unlocked (void *data)
{
	Module *module = data;

	assert (module);

	/* Module must be finalized */
	assert (module->initialize_count == 0);

	/* Module must have no outstanding references */
	assert (module->ref_count == 0);

	dlclose (module->dl_module);
	hash_free (module->config);
	free (module->name);
	free (module);
}

static CK_RV
load_module_from_config_unlocked (const char *configfile, const char *name)
{
	Module *module, *prev;
	const char *path;
	CK_C_GetFunctionList gfl;
	CK_RV rv;

	assert (configfile);

	module = calloc (sizeof (Module), 1);
	if (!module)
		return CKR_HOST_MEMORY;

	module->config = conf_parse_file (configfile, 0, conf_error);
	if (!module->config) {
		free_module_unlocked (module);
		if (errno == ENOMEM)
			return CKR_HOST_MEMORY;
		return CKR_GENERAL_ERROR;
	}

	module->name = strdup (name);
	if (!module->name) {
		free_module_unlocked (module);
		return CKR_HOST_MEMORY;
	}

	path = hash_get (module->config, "module");
	if (path == NULL) {
		free_module_unlocked (module);
		warning ("no module path specified in config: %s", configfile);
		return CKR_GENERAL_ERROR;
	}

	module->dl_module = dlopen (path, RTLD_LOCAL | RTLD_NOW);
	if (module->dl_module == NULL) {
		warning ("couldn't load module: %s: %s", path, dlerror ());
		free_module_unlocked (module);
		return CKR_GENERAL_ERROR;
	}

	gfl = dlsym (module->dl_module, "C_GetFunctionList");
	if (!gfl) {
		warning ("couldn't find C_GetFunctionList entry point in module: %s: %s",
		         path, dlerror ());
		free_module_unlocked (module);
		return CKR_GENERAL_ERROR;
	}

	rv = gfl (&module->funcs);
	if (rv != CKR_OK) {
		warning ("call to C_GetFunctiontList failed in module: %s: %lu",
		         path, (unsigned long)rv);
		free_module_unlocked (module);
		return rv;
	}

	prev = hash_get (gl.modules, module->funcs);

	/* Replace previous module that was loaded explicitly? */
	if (prev && !prev->name) {
		module->ref_count = prev->ref_count;
		module->initialize_count = prev->initialize_count;
		prev->ref_count = 0;
		prev->initialize_count = 0;
		hash_set (gl.modules, module->funcs, module);
		prev = NULL; /* freed by hash above */
	}

	/* Refuse to load duplicate module */
	if (prev) {
		warning ("duplicate configured module: %s: %s",
		         module->name, path);
		free_module_unlocked (module);
		return CKR_GENERAL_ERROR;
	}

	return CKR_OK;
}

static CK_RV
load_modules_from_config_unlocked (const char *directory)
{
	struct dirent *dp;
	CK_RV rv = CKR_OK;
	DIR *dir;
	char *path;

	/* First we load all the modules */
	dir = opendir (directory);
	if (!dir) {
		if (errno == ENOENT || errno == ENOTDIR)
			warning ("couldn't list directory: %s", directory);
		return CKR_GENERAL_ERROR;
	}

	/* We're within a global mutex, so readdir is safe */
	while ((dp = readdir(dir)) != NULL) {
		path = strconcat (directory, "/", dp->d_name);
		if (!path) {
			rv = CKR_HOST_MEMORY;
			break;
		}

		rv = load_module_from_config_unlocked (path, dp->d_name);
		free (path);

		if (rv != CKR_OK)
			break;
	}

	closedir (dir);

	return rv;
}

static char*
expand_user_path (const char *path)
{
	const char *env;
	struct passwd *pwd;

	if (path[0] == '~' && path[1] == '/') {
		env = getenv ("HOME");
		if (env && env[0]) {
			return strconcat (env, path + 1, NULL);
		} else {
			pwd = getpwuid (getuid ());
			if (!pwd)
				return NULL;
			return strconcat (pwd->pw_dir, path + 1, NULL);
		}
	}

	return strdup (path);
}

enum {
	USER_CONFIG_INVALID = 0,
	USER_CONFIG_NONE = 1,
	USER_CONFIG_MERGE,
	USER_CONFIG_OVERRIDE
};

static int
user_config_mode (hash_t *config, int defmode)
{
	const char *mode;

	/* Whether we should use or override from user directory */
	mode = hash_get (config, "user-config");
	if (mode == NULL) {
		return defmode;
	} else if (strequal (mode, "none")) {
		return USER_CONFIG_NONE;
	} else if (strequal (mode, "merge")) {
		return USER_CONFIG_MERGE;
	} else if (strequal (mode, "override")) {
		return USER_CONFIG_OVERRIDE;
	} else {
		warning ("invalid mode for 'user-config': %s", mode);
		return USER_CONFIG_INVALID;
	}
}

static CK_RV
load_config_files_unlocked (int *user_mode)
{
	hash_t *config = NULL;
	hash_t *uconfig = NULL;
	void *key = NULL;
	void *value = NULL;
	char *path;
	int mode;
	CK_RV rv = CKR_GENERAL_ERROR;
	hash_iter_t hi;

	/* Should only be called after everything has been unloaded */
	assert (!gl.config);

	/* Load the main configuration */
	config = conf_parse_file (P11_SYSTEM_CONF, CONF_IGNORE_MISSING, conf_error);
	if (!config) {
		rv = (errno == ENOMEM) ? CKR_HOST_MEMORY : CKR_GENERAL_ERROR;
		goto finished;
	}

	/* Whether we should use or override from user directory */
	mode = user_config_mode (config, USER_CONFIG_INVALID);
	if (mode == USER_CONFIG_INVALID)
		goto finished;

	if (mode != USER_CONFIG_NONE) {
		path = expand_user_path (P11_USER_CONF);
		if (!path)
			goto finished;

		/* Load up the user configuration */
		uconfig = conf_parse_file (path, CONF_IGNORE_MISSING, conf_error);
		free (path);

		if (!uconfig) {
			rv = (errno == ENOMEM) ? CKR_HOST_MEMORY : CKR_GENERAL_ERROR;
			goto finished;
		}

		/* Figure out what the user mode is */
		mode = user_config_mode (uconfig, mode);
		if (mode == USER_CONFIG_INVALID)
			goto finished;

		/* Merge everything into the system config */
		if (mode == USER_CONFIG_MERGE) {
			hash_iterate (uconfig, &hi);
			while (hash_next (&hi, &key, &value)) {
				key = strdup (key);
				if (key == NULL)
					goto finished;
				value = strdup (value);
				if (value == NULL)
					goto finished;
				if (!hash_set (config, key, value))
					goto finished;
				key = NULL;
				value = NULL;
			}

		/* Override the system config */
		} else if (mode == USER_CONFIG_OVERRIDE) {
			hash_free (config);
			config = uconfig;
			uconfig = NULL;
		}
	}

	gl.config = config;
	config = NULL;
	rv = CKR_OK;

	if (user_mode)
		*user_mode = mode;

finished:
	hash_free (config);
	hash_free (uconfig);
	free (key);
	free (value);
	return rv;
}

static CK_RV
load_registered_modules_unlocked (void)
{
	char *path;
	int mode;
	CK_RV rv;

	rv = load_config_files_unlocked (&mode);
	if (rv != CKR_OK)
		return rv;

	assert (gl.config);
	assert (mode != USER_CONFIG_INVALID);

	/* Load each module from the main list */
	if (mode != USER_CONFIG_OVERRIDE) {
		rv = load_modules_from_config_unlocked (P11_SYSTEM_MODULES);
		if (rv != CKR_OK);
			return rv;
	}

	/* Load each module from the user list */
	if (mode != USER_CONFIG_NONE) {
		path = expand_user_path (P11_USER_MODULES);
		if (!path)
			rv = CKR_GENERAL_ERROR;
		else
			rv = load_modules_from_config_unlocked (path);
		free (path);
		if (rv != CKR_OK);
			return rv;
	}

	return CKR_OK;
}

static CK_RV
create_mutex (CK_VOID_PTR_PTR mut)
{
	pthread_mutex_t *pmutex;
	int err;

	pmutex = malloc (sizeof (pthread_mutex_t));
	if (!pmutex)
		return CKR_HOST_MEMORY;
	err = pthread_mutex_init (pmutex, NULL);
	if (err == ENOMEM)
		return CKR_HOST_MEMORY;
	else if (err != 0)
		return CKR_GENERAL_ERROR;
	*mut = pmutex;
	return CKR_OK;
}

static CK_RV
destroy_mutex (CK_VOID_PTR mut)
{
	pthread_mutex_t *pmutex = mut;
	int err;

	err = pthread_mutex_destroy (pmutex);
	if (err == EINVAL)
		return CKR_MUTEX_BAD;
	else if (err != 0)
		return CKR_GENERAL_ERROR;
	free (pmutex);
	return CKR_OK;
}

static CK_RV
lock_mutex (CK_VOID_PTR mut)
{
	pthread_mutex_t *pmutex = mut;
	int err;

	err = pthread_mutex_lock (pmutex);
	if (err == EINVAL)
		return CKR_MUTEX_BAD;
	else if (err != 0)
		return CKR_GENERAL_ERROR;
	return CKR_OK;
}

static CK_RV
unlock_mutex (CK_VOID_PTR mut)
{
	pthread_mutex_t *pmutex = mut;
	int err;

	err = pthread_mutex_unlock (pmutex);
	if (err == EINVAL)
		return CKR_MUTEX_BAD;
	else if (err == EPERM)
		return CKR_MUTEX_NOT_LOCKED;
	else if (err != 0)
		return CKR_GENERAL_ERROR;
	return CKR_OK;
}

static CK_RV
initialize_module_unlocked_reentrant (Module *module, CK_C_INITIALIZE_ARGS_PTR args)
{
	CK_RV rv = CKR_OK;

	assert (module);

	/*
	 * Initialize first, so module doesn't get freed out from
	 * underneath us when the mutex is unlocked below.
	 */
	++module->ref_count;

	if (!module->initialize_count) {

		_p11_unlock ();

			assert (module->funcs);
			rv = module->funcs->C_Initialize (args);

		_p11_lock ();

		/*
		 * Because we have the mutex unlocked above, two initializes could
		 * race. Therefore we need to take CKR_CRYPTOKI_ALREADY_INITIALIZED
		 * into account.
		 *
		 * We also need to take into account where in a race both calls return
		 * CKR_OK (which is not according to the spec but may happen, I mean we
		 * do it in this module, so it's not unimaginable).
		 */

		if (rv == CKR_OK)
			++module->initialize_count;
		else if (rv == CKR_CRYPTOKI_ALREADY_INITIALIZED)
			rv = CKR_OK;
		else
			--module->ref_count;
	}

	return rv;
}

static void
reinitialize_after_fork (void)
{
	CK_C_INITIALIZE_ARGS args;
	hash_iter_t it;
	Module *module;

	/* WARNING: This function must be reentrant */

	memset (&args, 0, sizeof (args));
	args.CreateMutex = create_mutex;
	args.DestroyMutex = destroy_mutex;
	args.LockMutex = lock_mutex;
	args.UnlockMutex = unlock_mutex;
	args.flags = CKF_OS_LOCKING_OK;

	_p11_lock ();

		if (gl.modules) {
			hash_iterate (gl.modules, &it);
			while (hash_next (&it, NULL, (void**)&module)) {
				module->initialize_count = 0;

				/* WARNING: Reentrancy can occur here */
				initialize_module_unlocked_reentrant (module, &args);
			}
		}

	_p11_unlock ();

	_p11_kit_proxy_after_fork ();
}

static CK_RV
init_globals_unlocked (void)
{
	static int once = 0;

	if (!gl.modules)
		gl.modules = hash_create (hash_direct_hash, hash_direct_equal,
		                          NULL, free_module_unlocked);
	if (!gl.modules)
		return CKR_HOST_MEMORY;

	if (once)
		return CKR_OK;

	pthread_atfork (NULL, NULL, reinitialize_after_fork);
	once = 1;

	return CKR_OK;
}

static void
free_modules_when_no_refs_unlocked (void)
{
	Module *module;
	hash_iter_t it;

	/* Check if any modules have a ref count */
	hash_iterate (gl.modules, &it);
	while (hash_next (&it, NULL, (void**)&module)) {
		if (module->ref_count)
			return;
	}

	hash_free (gl.modules);
	gl.modules = NULL;
	hash_free (gl.config);
	gl.config = NULL;
}

static CK_RV
finalize_module_unlocked_reentrant (Module *module, CK_VOID_PTR args)
{
	assert (module);

	/*
	 * We leave module info around until all are finalized
	 * so we can encounter these zombie Module structures.
	 */
	if (module->ref_count == 0)
		return CKR_ARGUMENTS_BAD;

	if (--module->ref_count > 0)
		return CKR_OK;

	/*
	 * Becuase of the mutex unlock below, we temporarily increase
	 * the ref count. This prevents module from being freed out
	 * from ounder us.
	 */
	++module->ref_count;

	while (module->initialize_count > 0) {

		_p11_unlock ();

			assert (module->funcs);
			module->funcs->C_Finalize (args);

		_p11_lock ();

		if (module->initialize_count > 0)
			--module->initialize_count;
	}

	/* Match the increment above */
	--module->ref_count;

	free_modules_when_no_refs_unlocked ();
	return CKR_OK;
}

static Module*
find_module_for_name_unlocked (const char *name)
{
	Module *module;
	hash_iter_t it;

	assert (name);

	hash_iterate (gl.modules, &it);
	while (hash_next (&it, NULL, (void**)&module))
		if (module->ref_count && module->name && strcmp (name, module->name))
			return module;
	return NULL;
}

CK_RV
_p11_kit_initialize_registered_unlocked_reentrant (CK_C_INITIALIZE_ARGS_PTR args)
{
	Module *module;
	hash_iter_t it;
	CK_RV rv;

	rv = init_globals_unlocked ();
	if (rv == CKR_OK)
		rv = load_registered_modules_unlocked ();
	if (rv == CKR_OK) {
		hash_iterate (gl.modules, &it);
		while (hash_next (&it, NULL, (void**)&module)) {

			/* Skip all modules that aren't registered */
			if (!module->name)
				continue;

			rv = initialize_module_unlocked_reentrant (module, args);

			if (rv != CKR_OK)
				break;
		}
	}

	return rv;
}

CK_RV
p11_kit_initialize_registered (void)
{
	CK_C_INITIALIZE_ARGS args;
	CK_RV rv;

	/* WARNING: This function must be reentrant */

	memset (&args, 0, sizeof (args));
	args.CreateMutex = create_mutex;
	args.DestroyMutex = destroy_mutex;
	args.LockMutex = lock_mutex;
	args.UnlockMutex = unlock_mutex;
	args.flags = CKF_OS_LOCKING_OK;

	_p11_lock ();

		/* WARNING: Reentrancy can occur here */
		rv = _p11_kit_initialize_registered_unlocked_reentrant (&args);

	_p11_unlock ();

	/* Cleanup any partial initialization */
	if (rv != CKR_OK)
		p11_kit_finalize_registered ();

	return rv;
}

CK_RV
_p11_kit_finalize_registered_unlocked_reentrant (CK_VOID_PTR args)
{
	Module *module;
	hash_iter_t it;
	Module **to_finalize;
	int i, count;

	if (!gl.modules)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	/* WARNING: This function must be reentrant */

	to_finalize = calloc (hash_count (gl.modules), sizeof (Module*));
	if (!to_finalize)
		return CKR_HOST_MEMORY;

	count = 0;
	hash_iterate (gl.modules, &it);
	while (hash_next (&it, NULL, (void**)&module)) {

		/* Skip all modules that aren't registered */
		if (module->name)
			to_finalize[count++] = module;
	}

	for (i = 0; i < count; ++i) {
		/* WARNING: Reentrant calls can occur here */
		finalize_module_unlocked_reentrant (to_finalize[i], args);
	}

	free (to_finalize);
	return CKR_OK;
}

CK_RV
p11_kit_finalize_registered (void)
{
	CK_RV rv;

	/* WARNING: This function must be reentrant */

	_p11_lock ();

		/* WARNING: Reentrant calls can occur here */
		rv = _p11_kit_finalize_registered_unlocked_reentrant (NULL);

	_p11_unlock ();

	return rv;
}

CK_FUNCTION_LIST_PTR_PTR
_p11_kit_registered_modules_unlocked (void)
{
	CK_FUNCTION_LIST_PTR_PTR result;
	Module *module;
	hash_iter_t it;
	int i = 0;

	result = calloc (hash_count (gl.modules) + 1, sizeof (CK_FUNCTION_LIST_PTR));
	if (result) {
		hash_iterate (gl.modules, &it);
		while (hash_next (&it, NULL, (void**)&module)) {
			if (module->ref_count && module->name)
				result[i++] = module->funcs;
		}
	}

	return result;
}

CK_FUNCTION_LIST_PTR_PTR
p11_kit_registered_modules (void)
{
	CK_FUNCTION_LIST_PTR_PTR result;

	_p11_lock ();

		result = _p11_kit_registered_modules_unlocked ();

	_p11_unlock ();

	return result;
}

char*
p11_kit_registered_module_to_name (CK_FUNCTION_LIST_PTR funcs)
{
	Module *module;
	char *name = NULL;

	if (!funcs)
		return NULL;

	_p11_lock ();

		module = gl.modules ? hash_get (gl.modules, funcs) : NULL;
		if (module && module->name)
			name = strdup (module->name);

	_p11_unlock ();

	return name;
}

CK_FUNCTION_LIST_PTR
p11_kit_registered_name_to_module (const char *name)
{
	CK_FUNCTION_LIST_PTR funcs = NULL;
	Module *module;

	_p11_lock ();

		if (gl.modules) {
			module = find_module_for_name_unlocked (name);
			if (module)
				funcs = module->funcs;
		}

	_p11_unlock ();

	return funcs;
}

char*
p11_kit_registered_option (CK_FUNCTION_LIST_PTR funcs, const char *field)
{
	Module *module;
	char *option = NULL;

	if (!funcs || !field)
		return NULL;

	_p11_lock ();

		module = gl.modules ? hash_get (gl.modules, funcs) : NULL;
		if (module && module->config) {
			option = hash_get (module->config, field);
			if (option)
				option = strdup (option);
		}

	_p11_unlock ();

	return option;
}

CK_RV
p11_kit_initialize_module (CK_FUNCTION_LIST_PTR funcs, CK_C_INITIALIZE_ARGS_PTR init_args)
{
	Module *module;
	Module *allocated = NULL;
	CK_RV rv = CKR_OK;

	/* WARNING: This function must be reentrant for the same arguments */

	_p11_lock ();

		rv = init_globals_unlocked ();
		if (rv == CKR_OK) {

			module = hash_get (gl.modules, funcs);
			if (module == NULL) {
				allocated = module = calloc (1, sizeof (Module));
				module->funcs = funcs;
			}

			/* WARNING: Reentrancy can occur here */
			rv = initialize_module_unlocked_reentrant (module, init_args);

			/* If this was newly allocated, add it to the list */
			if (rv == CKR_OK && allocated) {
				hash_set (gl.modules, allocated->funcs, allocated);
				allocated = NULL;
			}

			free (allocated);
		}

	_p11_unlock ();

	return rv;
}

CK_RV
p11_kit_finalize_module (CK_FUNCTION_LIST_PTR funcs, CK_VOID_PTR reserved)
{
	Module *module;
	CK_RV rv = CKR_OK;

	/* WARNING: This function must be reentrant for the same arguments */

	_p11_lock ();

		module = gl.modules ? hash_get (gl.modules, funcs) : NULL;
		if (module == NULL) {
			rv = CKR_ARGUMENTS_BAD;
		} else {
			/* WARNING: Rentrancy can occur here */
			rv = finalize_module_unlocked_reentrant (module, reserved);
		}

	_p11_unlock ();

	return rv;
}
