/*
 * Copyright (C) 2008 Stefan Walter
 * Copyright (C) 2011 Collabora Ltd.
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
#define DEBUG_FLAG DEBUG_LIB
#include "debug.h"
#include "hashmap.h"
#include "pkcs11.h"
#include "p11-kit.h"
#include "private.h"

#include <sys/stat.h>
#include <sys/types.h>

#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/**
 * SECTION:p11-kit
 * @title: Modules
 * @short_description: Module loading and initializing
 *
 * PKCS\#11 modules are used by crypto libraries and applications to access
 * crypto objects (like keys and certificates) and to perform crypto operations.
 *
 * In order for applications to behave consistently with regard to the user's
 * installed PKCS\#11 modules, each module must be registered so that applications
 * or libraries know that they should load it.
 *
 * The functions here provide support for initializing registered modules. The
 * p11_kit_initialize_registered() function should be used to load and initialize
 * the registered modules. When done, the p11_kit_finalize_registered() function
 * should be used to release those modules and associated resources.
 *
 * In addition p11_kit_registered_option() can be used to access other parts
 * of the module configuration.
 *
 * When multiple consumers of a module (such as libraries or applications) are
 * in the same process, coordination of the initialization and finalization
 * of PKCS\#11 modules is required. The functions here automatically provide
 * initialization reference counting to make this work.
 *
 * If a consumer wishes to load an arbitrary PKCS\#11 module that's not
 * registered, that module should be initialized with p11_kit_initialize_module()
 * and finalized with p11_kit_finalize_module(). The module's own
 * <code>C_Initialize</code> and <code>C_Finalize</code> methods should not
 * be called directly.
 *
 * Modules are represented by a pointer to their <code>CK_FUNCTION_LIST</code>
 * entry points. This means that callers can load modules elsewhere, using
 * dlopen() for example, and then still use these methods on them.
 */

typedef struct _Module {
	CK_FUNCTION_LIST_PTR funcs;
	CK_C_INITIALIZE_ARGS init_args;
	int ref_count;

	/* Registered modules */
	char *name;
	hashmap *config;

	/* Loaded modules */
	dl_module_t dl_module;

	/* Initialization, mutex must be held */
	mutex_t initialize_mutex;
	int initialize_called;
	thread_t initialize_thread;
} Module;

/*
 * Shared data between threads, protected by the mutex, a structure so
 * we can audit thread safety easier.
 */
static struct _Shared {
	hashmap *modules;
	hashmap *config;
} gl = { NULL, NULL };

/* -----------------------------------------------------------------------------
 * P11-KIT FUNCTIONALITY
 */

static CK_RV
create_mutex (CK_VOID_PTR_PTR mut)
{
	mutex_t *pmutex;

	if (mut == NULL)
		return CKR_ARGUMENTS_BAD;

	pmutex = malloc (sizeof (mutex_t));
	if (!pmutex)
		return CKR_HOST_MEMORY;
	_p11_mutex_init (pmutex);
	*mut = pmutex;
	return CKR_OK;
}

static CK_RV
destroy_mutex (CK_VOID_PTR mut)
{
	mutex_t *pmutex = mut;

	if (mut == NULL)
		return CKR_MUTEX_BAD;

	_p11_mutex_uninit (pmutex);
	free (pmutex);
	return CKR_OK;
}

static CK_RV
lock_mutex (CK_VOID_PTR mut)
{
	mutex_t *pmutex = mut;

	if (mut == NULL)
		return CKR_MUTEX_BAD;

	_p11_mutex_lock (pmutex);
	return CKR_OK;
}

static CK_RV
unlock_mutex (CK_VOID_PTR mut)
{
	mutex_t *pmutex = mut;

	if (mut == NULL)
		return CKR_MUTEX_BAD;

	_p11_mutex_unlock (pmutex);
	return CKR_OK;
}

static void
free_module_unlocked (void *data)
{
	Module *mod = data;

	assert (mod);

	/* Module must be finalized */
	assert (mod->initialize_called == 0);
	assert (mod->initialize_thread == 0);

	/* Module must have no outstanding references */
	assert (mod->ref_count == 0);

	if (mod->dl_module)
		_p11_module_close (mod->dl_module);

	_p11_mutex_uninit (&mod->initialize_mutex);
	_p11_hash_free (mod->config);
	free (mod->name);
	free (mod);
}

static Module*
alloc_module_unlocked (void)
{
	Module *mod;

	mod = calloc (1, sizeof (Module));
	if (!mod)
		return NULL;

	mod->init_args.CreateMutex = create_mutex;
	mod->init_args.DestroyMutex = destroy_mutex;
	mod->init_args.LockMutex = lock_mutex;
	mod->init_args.UnlockMutex = unlock_mutex;
	mod->init_args.flags = CKF_OS_LOCKING_OK;
	_p11_mutex_init (&mod->initialize_mutex);

	return mod;
}

static int
is_relative_path (const char *path)
{
	assert (path);

	return (*path != '/');
}

static char*
build_path (const char *dir, const char *filename)
{
	char *path;
	int len;

	assert (dir);
	assert (filename);

	len = snprintf (NULL, 0, "%s/%s", dir, filename) + 1;
	if (len <= 0)
		return NULL;

#ifdef PATH_MAX
	if (len > PATH_MAX)
		return NULL;
#endif

	if (!(path = malloc (len)))
		return NULL;

	sprintf (path, "%s/%s", dir, filename);

	return path;
}

static CK_RV
dlopen_and_get_function_list (Module *mod, const char *path)
{
	CK_C_GetFunctionList gfl;
	CK_RV rv;

	assert (mod);
	assert (path);

	mod->dl_module = _p11_module_open (path);
	if (mod->dl_module == NULL) {
		_p11_message ("couldn't load module: %s: %s", path, _p11_module_error ());
		return CKR_GENERAL_ERROR;
	}

	gfl = _p11_module_symbol (mod->dl_module, "C_GetFunctionList");
	if (!gfl) {
		_p11_message ("couldn't find C_GetFunctionList entry point in module: %s: %s",
		              path, _p11_module_error ());
		return CKR_GENERAL_ERROR;
	}

	rv = gfl (&mod->funcs);
	if (rv != CKR_OK) {
		_p11_message ("call to C_GetFunctiontList failed in module: %s: %s",
		              path, p11_kit_strerror (rv));
		return rv;
	}

	_p11_debug ("opened module: %s", path);
	return CKR_OK;
}

static CK_RV
load_module_from_file_unlocked (const char *path, Module **result)
{
	Module *mod;
	Module *prev;
	CK_RV rv;

	mod = alloc_module_unlocked ();
	if (!mod)
		return CKR_HOST_MEMORY;

	rv = dlopen_and_get_function_list (mod, path);
	if (rv != CKR_OK) {
		free_module_unlocked (mod);
		return rv;
	}

	/* Do we have a previous one like this, if so ignore load */
	prev = _p11_hash_get (gl.modules, mod->funcs);

	if (prev != NULL) {
		_p11_debug ("duplicate module %s, using previous", path);
		free_module_unlocked (mod);
		mod = prev;

	} else if (!_p11_hash_set (gl.modules, mod->funcs, mod)) {
		free_module_unlocked (mod);
		return CKR_HOST_MEMORY;
	}

	if (result)
		*result= mod;
	return CKR_OK;
}

static char*
expand_module_path (const char *filename)
{
	char *path;

	if (is_relative_path (filename)) {
		_p11_debug ("module path is relative, loading from: %s", P11_MODULE_PATH);
		path = build_path (P11_MODULE_PATH, filename);
	} else {
		path = strdup (filename);
	}

	return path;
}

static CK_RV
take_config_and_load_module_unlocked (char **name, hashmap **config)
{
	Module *mod, *prev;
	const char *module_filename;
	char *path;
	CK_RV rv;

	assert (name);
	assert (*name);
	assert (config);
	assert (*config);

	module_filename = _p11_hash_get (*config, "module");
	if (module_filename == NULL) {
		_p11_debug ("no module path for module, skipping: %s", *name);
		return CKR_OK;
	}

	path = expand_module_path (module_filename);
	if (!path)
		return CKR_HOST_MEMORY;

	/* The hash map will take ownership of the variable */
	if (!_p11_hash_set (*config, "module", path)) {
		free (path);
		return CKR_HOST_MEMORY;
	}

	mod = alloc_module_unlocked ();
	if (!mod)
		return CKR_HOST_MEMORY;

	/* Take ownership of thes evariables */
	mod->config = *config;
	*config = NULL;
	mod->name = *name;
	*name = NULL;

	rv = dlopen_and_get_function_list (mod, path);
	if (rv != CKR_OK) {
		free_module_unlocked (mod);
		return rv;
	}

	prev = _p11_hash_get (gl.modules, mod->funcs);

	/* If same module was loaded previously, just take over config */
	if (prev && !prev->name && !prev->config) {
		prev->name = mod->name;
		mod->name = NULL;
		prev->config = mod->config;
		mod->config = NULL;
		free_module_unlocked (mod);

	/* Ignore duplicate module */
	} else if (prev) {
		_p11_message ("duplicate configured module: %s: %s", mod->name, path);
		free_module_unlocked (mod);

	/* Add this new module to our hash table */
	} else {
		if (!_p11_hash_set (gl.modules, mod->funcs, mod)) {
			free_module_unlocked (mod);
			return CKR_HOST_MEMORY;
		}

	}
	/*
	 * We support setting of CK_C_INITIALIZE_ARGS.pReserved from
	 * 'x-init-reserved' setting in the config. This only works with specific
	 * PKCS#11 modules, and is non-standard use of that field.
	 */
	mod->init_args.pReserved = _p11_hash_get (mod->config, "x-init-reserved");

	return CKR_OK;
}

static CK_RV
load_registered_modules_unlocked (void)
{
	hashiter iter;
	hashmap *configs;
	void *key;
	char *name;
	hashmap *config;
	int mode;
	CK_RV rv;
	int critical;

	if (gl.config)
		return CKR_OK;

	/* Load the global configuration files */
	config = _p11_conf_load_globals (P11_SYSTEM_CONFIG_FILE, P11_USER_CONFIG_FILE, &mode);
	if (config == NULL)
		return (errno == ENOMEM) ? CKR_HOST_MEMORY : CKR_GENERAL_ERROR;

	assert (mode != CONF_USER_INVALID);

	configs = _p11_conf_load_modules (mode, P11_SYSTEM_CONFIG_MODULES,
	                                  P11_USER_CONFIG_MODULES);
	if (configs == NULL) {
		rv = (errno == ENOMEM) ? CKR_HOST_MEMORY : CKR_GENERAL_ERROR;
		_p11_hash_free (config);
		return rv;
	}

	assert (gl.config == NULL);
	gl.config = config;

	/*
	 * Now go through each config and turn it into a module. As we iterate
	 * we steal the values of the config.
	 */
	_p11_hash_iterate (configs, &iter);
	while (_p11_hash_next (&iter, &key, NULL)) {
		if (!_p11_hash_steal (configs, key, (void**)&name, (void**)&config))
			assert (0 && "not reached");

		/* Is this a critical module, should abort loading of others? */
		critical = _p11_conf_parse_boolean (_p11_hash_get (config, "critical"), 0);

		rv = take_config_and_load_module_unlocked (&name, &config);

		/*
		 * These variables will be cleared if ownership is transeferred
		 * by the above function call.
		 */
		free (name);
		_p11_hash_free (config);

		if (critical && rv != CKR_OK) {
			_p11_message ("aborting initializationg because module '%s' was marked as critical");
			_p11_hash_free (configs);
			return rv;
		}
	}

	_p11_hash_free (configs);
	return CKR_OK;
}

static CK_RV
initialize_module_unlocked_reentrant (Module *mod)
{
	CK_RV rv = CKR_OK;
	thread_t self;
	assert (mod);

	self = _p11_thread_self ();

	if (mod->initialize_thread == self) {
		_p11_message ("p11-kit initialization called recursively");
		return CKR_FUNCTION_FAILED;
	}

	/*
	 * Increase ref first, so module doesn't get freed out from
	 * underneath us when the mutex is unlocked below.
	 */
	++mod->ref_count;
	mod->initialize_thread = self;

	/* Change over to the module specific mutex */
	_p11_mutex_lock (&mod->initialize_mutex);
	_p11_unlock ();

	if (!mod->initialize_called) {

		_p11_debug ("C_Initialize: calling");

		assert (mod->funcs);
		rv = mod->funcs->C_Initialize (&mod->init_args);

		_p11_debug ("C_Initialize: result: %lu", rv);

		/* Module was initialized and C_Finalize should be called */
		if (rv == CKR_OK)
			mod->initialize_called = 1;

		/* Module was already initialized, we don't call C_Finalize */
		else if (rv == CKR_CRYPTOKI_ALREADY_INITIALIZED)
			rv = CKR_OK;
	}

	_p11_mutex_unlock (&mod->initialize_mutex);
	_p11_lock ();

	/* Don't claim reference if failed */
	if (rv != CKR_OK)
		--mod->ref_count;

	mod->initialize_thread = 0;
	return rv;
}

#ifdef OS_UNIX

static void
reinitialize_after_fork (void)
{
	hashiter iter;
	Module *mod;

	_p11_debug ("forked");

	_p11_lock ();

		if (gl.modules) {
			_p11_hash_iterate (gl.modules, &iter);
			while (_p11_hash_next (&iter, NULL, (void **)&mod))
				mod->initialize_called = 0;
		}

	_p11_unlock ();

	_p11_kit_proxy_after_fork ();
}

#endif /* OS_UNIX */

static CK_RV
init_globals_unlocked (void)
{
	static int once = 0;

	if (!gl.modules)
		gl.modules = _p11_hash_create (_p11_hash_direct_hash, _p11_hash_direct_equal,
		                          NULL, free_module_unlocked);
	if (!gl.modules)
		return CKR_HOST_MEMORY;

	if (once)
		return CKR_OK;

#ifdef OS_UNIX
	pthread_atfork (NULL, NULL, reinitialize_after_fork);
#endif
	once = 1;

	return CKR_OK;
}

static void
free_modules_when_no_refs_unlocked (void)
{
	Module *mod;
	hashiter iter;

	/* Check if any modules have a ref count */
	_p11_hash_iterate (gl.modules, &iter);
	while (_p11_hash_next (&iter, NULL, (void **)&mod)) {
		if (mod->ref_count)
			return;
	}

	_p11_hash_free (gl.modules);
	gl.modules = NULL;
	_p11_hash_free (gl.config);
	gl.config = NULL;
}

static CK_RV
finalize_module_unlocked_reentrant (Module *mod)
{
	assert (mod);

	/*
	 * We leave module info around until all are finalized
	 * so we can encounter these zombie Module structures.
	 */
	if (mod->ref_count == 0)
		return CKR_ARGUMENTS_BAD;

	if (--mod->ref_count > 0)
		return CKR_OK;

	/*
	 * Becuase of the mutex unlock below, we temporarily increase
	 * the ref count. This prevents module from being freed out
	 * from ounder us.
	 */
	++mod->ref_count;

	_p11_mutex_lock (&mod->initialize_mutex);
	_p11_unlock ();

	if (mod->initialize_called) {

		assert (mod->funcs);
		mod->funcs->C_Finalize (NULL);

		mod->initialize_called = 0;
	}

	_p11_mutex_unlock (&mod->initialize_mutex);
	_p11_lock ();

	/* Match the increment above */
	--mod->ref_count;

	free_modules_when_no_refs_unlocked ();
	return CKR_OK;
}

static Module*
find_module_for_name_unlocked (const char *name)
{
	Module *mod;
	hashiter iter;

	assert (name);

	_p11_hash_iterate (gl.modules, &iter);
	while (_p11_hash_next (&iter, NULL, (void **)&mod))
		if (mod->ref_count && mod->name && strcmp (name, mod->name) == 0)
			return mod;
	return NULL;
}

CK_RV
_p11_kit_initialize_registered_unlocked_reentrant (void)
{
	Module *mod;
	hashiter iter;
	CK_RV rv;

	rv = init_globals_unlocked ();
	if (rv != CKR_OK)
		return rv;

	rv = load_registered_modules_unlocked ();
	if (rv == CKR_OK) {
		_p11_hash_iterate (gl.modules, &iter);
		while (_p11_hash_next (&iter, NULL, (void **)&mod)) {

			/* Skip all modules that aren't registered */
			if (!mod->name)
				continue;

			rv = initialize_module_unlocked_reentrant (mod);

			if (rv != CKR_OK) {
				_p11_debug ("failed to initialize module: %s: %s",
				       mod->name, p11_kit_strerror (rv));
				break;
			}
		}
	}

	return rv;
}

/**
 * p11_kit_initialize_registered:
 *
 * Initialize all the registered PKCS\#11 modules.
 *
 * If this is the first time this function is called multiple times
 * consecutively within a single process, then it merely increments an
 * initialization reference count for each of these modules.
 *
 * Use p11_kit_finalize_registered() to finalize these registered modules once
 * the caller is done with them.
 *
 * If this function fails, then an error message will be available via the
 * p11_kit_message() function.
 *
 * Returns: CKR_OK if the initialization succeeded, or an error code.
 */
CK_RV
p11_kit_initialize_registered (void)
{
	CK_RV rv;

	_p11_library_init_once ();

	/* WARNING: This function must be reentrant */
	_p11_debug ("in");

	_p11_lock ();

		_p11_kit_clear_message ();

		/* WARNING: Reentrancy can occur here */
		rv = _p11_kit_initialize_registered_unlocked_reentrant ();

		_p11_kit_default_message (rv);

	_p11_unlock ();

	/* Cleanup any partial initialization */
	if (rv != CKR_OK)
		p11_kit_finalize_registered ();

	_p11_debug ("out: %lu", rv);
	return rv;
}

CK_RV
_p11_kit_finalize_registered_unlocked_reentrant (void)
{
	Module *mod;
	hashiter iter;
	Module **to_finalize;
	int i, count;

	if (!gl.modules)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	/* WARNING: This function must be reentrant */

	to_finalize = calloc (_p11_hash_size (gl.modules), sizeof (Module *));
	if (!to_finalize)
		return CKR_HOST_MEMORY;

	count = 0;
	_p11_hash_iterate (gl.modules, &iter);
	while (_p11_hash_next (&iter, NULL, (void **)&mod)) {

		/* Skip all modules that aren't registered */
		if (mod->name)
			to_finalize[count++] = mod;
	}

	_p11_debug ("finalizing %d modules", count);

	for (i = 0; i < count; ++i) {
		/* WARNING: Reentrant calls can occur here */
		finalize_module_unlocked_reentrant (to_finalize[i]);
	}

	free (to_finalize);

	/* In case nothing loaded, free up internal memory */
	if (count == 0)
		free_modules_when_no_refs_unlocked ();

	return CKR_OK;
}

/**
 * p11_kit_finalize_registered:
 *
 * Finalize all the registered PKCS\#11 modules. These should have been
 * initialized with p11_kit_initialize_registered().
 *
 * If p11_kit_initialize_registered() has been called more than once in this
 * process, then this function must be called the same number of times before
 * actual finalization will occur.
 *
 * If this function fails, then an error message will be available via the
 * p11_kit_message() function.
 *
 * Returns: CKR_OK if the finalization succeeded, or an error code.
 */

CK_RV
p11_kit_finalize_registered (void)
{
	CK_RV rv;

	_p11_library_init_once ();

	/* WARNING: This function must be reentrant */
	_p11_debug ("in");

	_p11_lock ();

		_p11_kit_clear_message ();

		/* WARNING: Reentrant calls can occur here */
		rv = _p11_kit_finalize_registered_unlocked_reentrant ();

		_p11_kit_default_message (rv);

	_p11_unlock ();

	_p11_debug ("out: %lu", rv);
	return rv;
}

CK_FUNCTION_LIST_PTR_PTR
_p11_kit_registered_modules_unlocked (void)
{
	CK_FUNCTION_LIST_PTR_PTR result = NULL;
	Module *mod;
	hashiter iter;
	int i = 0;

	if (gl.modules)
		result = calloc (_p11_hash_size (gl.modules) + 1, sizeof (CK_FUNCTION_LIST_PTR));
	if (result) {
		_p11_hash_iterate (gl.modules, &iter);
		while (_p11_hash_next (&iter, NULL, (void **)&mod)) {
			if (mod->ref_count && mod->name)
				result[i++] = mod->funcs;
		}
	}

	return result;
}

/**
 * p11_kit_registered_modules:
 *
 * Get a list of all the registered PKCS\#11 modules. This list will be valid
 * once the p11_kit_initialize_registered() function has been called.
 *
 * The returned value is a <code>NULL</code> terminated array of
 * <code>CK_FUNCTION_LIST_PTR</code> pointers.
 *
 * Returns: A list of all the registered modules. Use the free() function to
 * free the list.
 */
CK_FUNCTION_LIST_PTR_PTR
p11_kit_registered_modules (void)
{
	CK_FUNCTION_LIST_PTR_PTR result;

	_p11_library_init_once ();

	_p11_lock ();

		_p11_kit_clear_message ();

		result = _p11_kit_registered_modules_unlocked ();

	_p11_unlock ();

	return result;
}

/**
 * p11_kit_registered_module_to_name:
 * @module: pointer to a registered module
 *
 * Get the name of a registered PKCS\#11 module.
 *
 * You can use p11_kit_registered_modules() to get a list of all the registered
 * modules. This name is specified by the registered module configuration.
 *
 * Returns: A newly allocated string containing the module name, or
 *     <code>NULL</code> if no such registered module exists. Use free() to
 *     free this string.
 */
char*
p11_kit_registered_module_to_name (CK_FUNCTION_LIST_PTR module)
{
	Module *mod;
	char *name = NULL;

	_p11_library_init_once ();

	_p11_lock ();

		_p11_kit_clear_message ();

		mod = module && gl.modules ? _p11_hash_get (gl.modules, module) : NULL;
		if (mod && mod->name)
			name = strdup (mod->name);

	_p11_unlock ();

	return name;
}

/**
 * p11_kit_registered_name_to_module:
 * @name: name of a registered module
 *
 * Lookup a registered PKCS\#11 module by its name. This name is specified by
 * the registered module configuration.
 *
 * Returns: a pointer to a PKCS\#11 module, or <code>NULL</code> if this name was
 *     not found.
 */
CK_FUNCTION_LIST_PTR
p11_kit_registered_name_to_module (const char *name)
{
	CK_FUNCTION_LIST_PTR module = NULL;
	Module *mod;

	_p11_lock ();

		_p11_kit_clear_message ();

		if (gl.modules) {
			mod = find_module_for_name_unlocked (name);
			if (mod)
				module = mod->funcs;
		}

	_p11_unlock ();

	return module;
}

/**
 * p11_kit_registered_option:
 * @module: a pointer to a registered module
 * @field: the name of the option to lookup.
 *
 * Lookup a configured option for a registered PKCS\#11 module. If a
 * <code>NULL</code> module argument is specified, then this will lookup
 * the configuration option in the global config file.
 *
 * Returns: A newly allocated string containing the option value, or
 *     <code>NULL</code> if the registered module or the option were not found.
 *     Use free() to free the returned string.
 */
char*
p11_kit_registered_option (CK_FUNCTION_LIST_PTR module, const char *field)
{
	Module *mod = NULL;
	char *option = NULL;
	hashmap *config = NULL;

	_p11_library_init_once ();

	_p11_lock ();

		_p11_kit_clear_message ();

		if (module == NULL) {
			config = gl.config;

		} else {
			mod = gl.modules ? _p11_hash_get (gl.modules, module) : NULL;
			if (mod)
				config = mod->config;
		}

		if (config && field) {
			option = _p11_hash_get (config, field);
			if (option)
				option = strdup (option);
		}

	_p11_unlock ();

	return option;
}

/**
 * p11_kit_initialize_module:
 * @module: loaded module to initialize.
 *
 * Initialize an arbitrary PKCS\#11 module. Normally using the
 * p11_kit_initialize_registered() is preferred.
 *
 * Using this function to initialize modules allows coordination between
 * multiple users of the same module in a single process. It should be called
 * on modules that have been loaded (with dlopen() for example) but not yet
 * initialized. The caller should not yet have called the module's
 * <code>C_Initialize</code> method. This function will call
 * <code>C_Initialize</code> as necessary.
 *
 * Subsequent calls to this function for the same module will result in an
 * initialization count being incremented for the module. It is safe (although
 * usually unnecessary) to use this function on registered modules.
 *
 * The module must be finalized with p11_kit_finalize_module() instead of
 * calling its <code>C_Finalize</code> method directly.
 *
 * This function does not accept a <code>CK_C_INITIALIZE_ARGS</code> argument.
 * Custom initialization arguments cannot be supported when multiple consumers
 * load the same module.
 *
 * If this function fails, then an error message will be available via the
 * p11_kit_message() function.
 *
 * Returns: CKR_OK if the initialization was successful.
 */
CK_RV
p11_kit_initialize_module (CK_FUNCTION_LIST_PTR module)
{
	Module *allocated = NULL;
	Module *mod;
	CK_RV rv = CKR_OK;

	_p11_library_init_once ();

	/* WARNING: This function must be reentrant for the same arguments */
	_p11_debug ("in");

	_p11_lock ();

		_p11_kit_clear_message ();

		rv = init_globals_unlocked ();
		if (rv == CKR_OK) {

			mod = _p11_hash_get (gl.modules, module);
			if (mod == NULL) {
				_p11_debug ("allocating new module");
				allocated = mod = alloc_module_unlocked ();
				if (mod == NULL)
					rv = CKR_HOST_MEMORY;
				else
					mod->funcs = module;
			}

			/* If this was newly allocated, add it to the list */
			if (rv == CKR_OK && allocated) {
				if (_p11_hash_set (gl.modules, allocated->funcs, allocated))
					allocated = NULL;
				else
					rv = CKR_HOST_MEMORY;
			}

			if (rv == CKR_OK) {

				/* WARNING: Reentrancy can occur here */
				rv = initialize_module_unlocked_reentrant (mod);
			}

			free (allocated);
		}

		/*
		 * If initialization failed, we may need to cleanup.
		 * If we added this module above, then this will
		 * clean things up as expected.
		 */
		if (rv != CKR_OK)
			free_modules_when_no_refs_unlocked ();

		_p11_kit_default_message (rv);

	_p11_unlock ();

	_p11_debug ("out: %lu", rv);
	return rv;
}

/**
 * p11_kit_finalize_module:
 * @module: loaded module to finalize.
 *
 * Finalize an arbitrary PKCS\#11 module. The module must have been initialized
 * using p11_kit_initialize_module(). In most cases callers will want to use
 * p11_kit_finalize_registered() instead of this function.
 *
 * Using this function to finalize modules allows coordination between
 * multiple users of the same module in a single process. The caller should
 * call the module's <code>C_Finalize</code> method. This function will call
 * <code>C_Finalize</code> as necessary.
 *
 * If the module was initialized more than once, then this function will
 * decrement an initialization count for the module. When the count reaches zero
 * the module will be truly finalized. It is safe (although usually unnecessary)
 * to use this function on registered modules if (and only if) they were
 * initialized using p11_kit_initialize_module() for some reason.
 *
 * If this function fails, then an error message will be available via the
 * p11_kit_message() function.
 *
 * Returns: CKR_OK if the finalization was successful.
 */
CK_RV
p11_kit_finalize_module (CK_FUNCTION_LIST_PTR module)
{
	Module *mod;
	CK_RV rv = CKR_OK;

	_p11_library_init_once ();

	/* WARNING: This function must be reentrant for the same arguments */
	_p11_debug ("in");

	_p11_lock ();

		_p11_kit_clear_message ();

		mod = gl.modules ? _p11_hash_get (gl.modules, module) : NULL;
		if (mod == NULL) {
			_p11_debug ("module not found");
			rv = CKR_ARGUMENTS_BAD;
		} else {
			/* WARNING: Rentrancy can occur here */
			rv = finalize_module_unlocked_reentrant (mod);
		}

		_p11_kit_default_message (rv);

	_p11_unlock ();

	_p11_debug ("out: %lu", rv);
	return rv;
}

/**
 * p11_kit_load_initialize_module:
 * @module_path: full file path of module library
 * @module: location to place loaded module pointer
 *
 * Load an arbitrary PKCS\#11 module from a dynamic library file, and
 * initialize it. Normally using the p11_kit_initialize_registered() function
 * is preferred.
 *
 * Using this function to load and initialize modules allows coordination between
 * multiple users of the same module in a single process. The caller should not
 * call the module's <code>C_Initialize</code> method. This function will call
 * <code>C_Initialize</code> as necessary.
 *
 * If a module has already been loaded, then use of this function is unnecesasry.
 * Instead use the p11_kit_initialize_module() function to initialize it.
 *
 * Subsequent calls to this function for the same module will result in an
 * initialization count being incremented for the module. It is safe (although
 * usually unnecessary) to use this function on registered modules.
 *
 * The module must be finalized with p11_kit_finalize_module() instead of
 * calling its <code>C_Finalize</code> method directly.
 *
 * This function does not accept a <code>CK_C_INITIALIZE_ARGS</code> argument.
 * Custom initialization arguments cannot be supported when multiple consumers
 * load the same module.
 *
 * If this function fails, then an error message will be available via the
 * p11_kit_message() function.
 *
 * Returns: CKR_OK if the initialization was successful.
 */
CK_RV
p11_kit_load_initialize_module (const char *module_path,
                                CK_FUNCTION_LIST_PTR_PTR module)
{
	Module *mod;
	CK_RV rv = CKR_OK;

	_p11_library_init_once ();

	/* WARNING: This function must be reentrant for the same arguments */
	_p11_debug ("in: %s", module_path);

	_p11_lock ();

		_p11_kit_clear_message ();

		rv = init_globals_unlocked ();
		if (rv == CKR_OK) {

			rv = load_module_from_file_unlocked (module_path, &mod);
			if (rv == CKR_OK) {

				/* WARNING: Reentrancy can occur here */
				rv = initialize_module_unlocked_reentrant (mod);
			}
		}

		if (rv == CKR_OK && module)
			*module = mod->funcs;

		/*
		 * If initialization failed, we may need to cleanup.
		 * If we added this module above, then this will
		 * clean things up as expected.
		 */
		if (rv != CKR_OK)
			free_modules_when_no_refs_unlocked ();

		_p11_kit_default_message (rv);

	_p11_unlock ();

	_p11_debug ("out: %lu", rv);
	return rv;
}
