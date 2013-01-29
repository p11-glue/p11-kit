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
#define P11_DEBUG_FLAG P11_DEBUG_LIB
#include "debug.h"
#include "dict.h"
#include "library.h"
#include "pkcs11.h"
#include "p11-kit.h"
#include "private.h"

#include <sys/stat.h>
#include <sys/types.h>

#include <assert.h>
#include <ctype.h>
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
	p11_dict *config;

	/* Loaded modules */
	dl_module_t dl_module;

	/* Initialization, mutex must be held */
	p11_mutex_t initialize_mutex;
	bool initialize_called;
	p11_thread_id_t initialize_thread;
} Module;

/*
 * Shared data between threads, protected by the mutex, a structure so
 * we can audit thread safety easier.
 */
static struct _Shared {
	p11_dict *modules;
	p11_dict *config;
} gl = { NULL, NULL };

/* -----------------------------------------------------------------------------
 * P11-KIT FUNCTIONALITY
 */

static CK_RV
create_mutex (CK_VOID_PTR_PTR mut)
{
	p11_mutex_t *pmutex;

	return_val_if_fail (mut != NULL, CKR_ARGUMENTS_BAD);

	pmutex = malloc (sizeof (p11_mutex_t));
	return_val_if_fail (pmutex != NULL, CKR_HOST_MEMORY);

	p11_mutex_init (pmutex);
	*mut = pmutex;
	return CKR_OK;
}

static CK_RV
destroy_mutex (CK_VOID_PTR mut)
{
	p11_mutex_t *pmutex = mut;

	return_val_if_fail (mut != NULL, CKR_MUTEX_BAD);

	p11_mutex_uninit (pmutex);
	free (pmutex);
	return CKR_OK;
}

static CK_RV
lock_mutex (CK_VOID_PTR mut)
{
	p11_mutex_t *pmutex = mut;

	return_val_if_fail (mut != NULL, CKR_MUTEX_BAD);

	p11_mutex_lock (pmutex);
	return CKR_OK;
}

static CK_RV
unlock_mutex (CK_VOID_PTR mut)
{
	p11_mutex_t *pmutex = mut;

	return_val_if_fail (mut != NULL, CKR_MUTEX_BAD);

	p11_mutex_unlock (pmutex);
	return CKR_OK;
}

static void
free_module_unlocked (void *data)
{
	Module *mod = data;

	assert (mod != NULL);

	/* Module must be finalized */
	assert (!mod->initialize_called);
	assert (mod->initialize_thread == 0);

	/* Module must have no outstanding references */
	assert (mod->ref_count == 0);

	if (mod->dl_module)
		p11_module_close (mod->dl_module);

	p11_mutex_uninit (&mod->initialize_mutex);
	p11_dict_free (mod->config);
	free (mod->name);
	free (mod);
}

static Module *
alloc_module_unlocked (void)
{
	Module *mod;

	mod = calloc (1, sizeof (Module));
	return_val_if_fail (mod != NULL, NULL);

	mod->init_args.CreateMutex = create_mutex;
	mod->init_args.DestroyMutex = destroy_mutex;
	mod->init_args.LockMutex = lock_mutex;
	mod->init_args.UnlockMutex = unlock_mutex;
	mod->init_args.flags = CKF_OS_LOCKING_OK;
	p11_mutex_init (&mod->initialize_mutex);

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
	return_val_if_fail (len > 0, NULL);

#ifdef PATH_MAX
	if (len > PATH_MAX)
		return NULL;
#endif

	path = malloc (len);
	return_val_if_fail (path != NULL, NULL);

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

	mod->dl_module = p11_module_open (path);
	if (mod->dl_module == NULL) {
		p11_message ("couldn't load module: %s: %s", path, p11_module_error ());
		return CKR_GENERAL_ERROR;
	}

	gfl = p11_module_symbol (mod->dl_module, "C_GetFunctionList");
	if (!gfl) {
		p11_message ("couldn't find C_GetFunctionList entry point in module: %s: %s",
		             path, p11_module_error ());
		return CKR_GENERAL_ERROR;
	}

	rv = gfl (&mod->funcs);
	if (rv != CKR_OK) {
		p11_message ("call to C_GetFunctiontList failed in module: %s: %s",
		             path, p11_kit_strerror (rv));
		return rv;
	}

	p11_debug ("opened module: %s", path);
	return CKR_OK;
}

static CK_RV
load_module_from_file_unlocked (const char *path, Module **result)
{
	Module *mod;
	Module *prev;
	CK_RV rv;

	mod = alloc_module_unlocked ();
	return_val_if_fail (mod != NULL, CKR_HOST_MEMORY);

	rv = dlopen_and_get_function_list (mod, path);
	if (rv != CKR_OK) {
		free_module_unlocked (mod);
		return rv;
	}

	/* Do we have a previous one like this, if so ignore load */
	prev = p11_dict_get (gl.modules, mod->funcs);

	if (prev != NULL) {
		p11_debug ("duplicate module %s, using previous", path);
		free_module_unlocked (mod);
		mod = prev;

	} else if (!p11_dict_set (gl.modules, mod->funcs, mod)) {
		return_val_if_reached (CKR_HOST_MEMORY);
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
		p11_debug ("module path is relative, loading from: %s", P11_MODULE_PATH);
		path = build_path (P11_MODULE_PATH, filename);
	} else {
		path = strdup (filename);
	}

	return path;
}

static int
is_list_delimiter (char ch)
{
	return ch == ',' ||  isspace (ch);
}

static bool
is_string_in_list (const char *list,
                   const char *string)
{
	const char *where;

	where = strstr (list, string);
	if (where == NULL)
		return false;

	/* Has to be at beginning/end of string, and delimiter before/after */
	if (where != list && !is_list_delimiter (*(where - 1)))
		return false;

	where += strlen (string);
	return (*where == '\0' || is_list_delimiter (*where));
}

static bool
is_module_enabled_unlocked (const char *name,
                            p11_dict *config)
{
	const char *progname;
	const char *enable_in;
	const char *disable_in;
	bool enable = false;

	enable_in = p11_dict_get (config, "enable-in");
	disable_in = p11_dict_get (config, "disable-in");

	/* Defaults to enabled if neither of these are set */
	if (!enable_in && !disable_in)
		return true;

	progname = _p11_get_progname_unlocked ();
	if (enable_in && disable_in)
		p11_message ("module '%s' has both enable-in and disable-in options", name);
	if (enable_in)
		enable = (progname != NULL && is_string_in_list (enable_in, progname));
	else if (disable_in)
		enable = (progname == NULL || !is_string_in_list (disable_in, progname));

	p11_debug ("%s module '%s' running in '%s'",
	            enable ? "enabled" : "disabled",
	            name,
	            progname ? progname : "(null)");
	return enable;
}

static CK_RV
take_config_and_load_module_unlocked (char **name,
                                      p11_dict **config)
{
	Module *mod, *prev;
	const char *module_filename;
	char *path;
	char *key;
	CK_RV rv;

	assert (name);
	assert (*name);
	assert (config);
	assert (*config);

	if (!is_module_enabled_unlocked (*name, *config))
		return CKR_OK;

	module_filename = p11_dict_get (*config, "module");
	if (module_filename == NULL) {
		p11_debug ("no module path for module, skipping: %s", *name);
		return CKR_OK;
	}

	path = expand_module_path (module_filename);
	return_val_if_fail (path != NULL, CKR_HOST_MEMORY);

	key = strdup ("module");
	return_val_if_fail (key != NULL, CKR_HOST_MEMORY);

	/* The hash map will take ownership of the variable */
	if (!p11_dict_set (*config, key, path))
		return_val_if_reached (CKR_HOST_MEMORY);

	mod = alloc_module_unlocked ();
	return_val_if_fail (mod != NULL, CKR_HOST_MEMORY);

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

	/*
	 * We support setting of CK_C_INITIALIZE_ARGS.pReserved from
	 * 'x-init-reserved' setting in the config. This only works with specific
	 * PKCS#11 modules, and is non-standard use of that field.
	 */
	mod->init_args.pReserved = p11_dict_get (mod->config, "x-init-reserved");

	prev = p11_dict_get (gl.modules, mod->funcs);

	/* If same module was loaded previously, just take over config */
	if (prev && !prev->name && !prev->config) {
		prev->name = mod->name;
		mod->name = NULL;
		prev->config = mod->config;
		mod->config = NULL;
		free_module_unlocked (mod);

	/* Ignore duplicate module */
	} else if (prev) {
		p11_message ("duplicate configured module: %s: %s", mod->name, path);
		free_module_unlocked (mod);

	/* Add this new module to our hash table */
	} else {
		if (!p11_dict_set (gl.modules, mod->funcs, mod))
			return_val_if_reached (CKR_HOST_MEMORY);
	}

	return CKR_OK;
}

static CK_RV
load_registered_modules_unlocked (void)
{
	p11_dictiter iter;
	p11_dict *configs;
	void *key;
	char *name;
	p11_dict *config;
	int mode;
	CK_RV rv;
	bool critical;

	if (gl.config)
		return CKR_OK;

	/* Load the global configuration files */
	config = _p11_conf_load_globals (P11_SYSTEM_CONFIG_FILE, P11_USER_CONFIG_FILE, &mode);
	if (config == NULL)
		return CKR_GENERAL_ERROR;

	assert (mode != CONF_USER_INVALID);

	configs = _p11_conf_load_modules (mode,
	                                  P11_PACKAGE_CONFIG_MODULES,
	                                  P11_SYSTEM_CONFIG_MODULES,
	                                  P11_USER_CONFIG_MODULES);
	if (configs == NULL) {
		rv = CKR_GENERAL_ERROR;
		p11_dict_free (config);
		return rv;
	}

	assert (gl.config == NULL);
	gl.config = config;

	/*
	 * Now go through each config and turn it into a module. As we iterate
	 * we steal the values of the config.
	 */
	p11_dict_iterate (configs, &iter);
	while (p11_dict_next (&iter, &key, NULL)) {
		if (!p11_dict_steal (configs, key, (void**)&name, (void**)&config))
			assert_not_reached ();

		/* Is this a critical module, should abort loading of others? */
		critical = _p11_conf_parse_boolean (p11_dict_get (config, "critical"), false);

		rv = take_config_and_load_module_unlocked (&name, &config);

		/*
		 * These variables will be cleared if ownership is transeferred
		 * by the above function call.
		 */
		p11_dict_free (config);

		if (critical && rv != CKR_OK) {
			p11_message ("aborting initialization because module '%s' was marked as critical",
			             name);
			p11_dict_free (configs);
			free (name);
			return rv;
		}

		free (name);
	}

	p11_dict_free (configs);
	return CKR_OK;
}

static CK_RV
initialize_module_unlocked_reentrant (Module *mod)
{
	CK_RV rv = CKR_OK;
	p11_thread_id_t self;
	assert (mod);

	self = p11_thread_id_self ();

	if (mod->initialize_thread == self) {
		p11_message ("p11-kit initialization called recursively");
		return CKR_FUNCTION_FAILED;
	}

	/*
	 * Increase ref first, so module doesn't get freed out from
	 * underneath us when the mutex is unlocked below.
	 */
	++mod->ref_count;
	mod->initialize_thread = self;

	/* Change over to the module specific mutex */
	p11_mutex_lock (&mod->initialize_mutex);
	p11_unlock ();

	if (!mod->initialize_called) {
		assert (mod->funcs);

		if (mod->funcs == &_p11_proxy_function_list) {
			p11_message ("refusing to load the p11-kit-proxy.so module as a registered module");
			rv = CKR_FUNCTION_FAILED;

		} else {
			p11_debug ("C_Initialize: calling");

			rv = mod->funcs->C_Initialize (&mod->init_args);

			p11_debug ("C_Initialize: result: %lu", rv);
		}

		/* Module was initialized and C_Finalize should be called */
		if (rv == CKR_OK)
			mod->initialize_called = true;

		/* Module was already initialized, we don't call C_Finalize */
		else if (rv == CKR_CRYPTOKI_ALREADY_INITIALIZED)
			rv = CKR_OK;
	}

	p11_mutex_unlock (&mod->initialize_mutex);
	p11_lock ();

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
	p11_dictiter iter;
	Module *mod;

	p11_debug ("forked");

	p11_lock ();

		if (gl.modules) {
			p11_dict_iterate (gl.modules, &iter);
			while (p11_dict_next (&iter, NULL, (void **)&mod))
				mod->initialize_called = false;
		}

	p11_unlock ();

	_p11_kit_proxy_after_fork ();
}

#endif /* OS_UNIX */

static CK_RV
init_globals_unlocked (void)
{
	static bool once = false;

	if (!gl.modules) {
		gl.modules = p11_dict_new (p11_dict_direct_hash, p11_dict_direct_equal,
		                           NULL, free_module_unlocked);
		return_val_if_fail (gl.modules != NULL, CKR_HOST_MEMORY);
	}

	if (once)
		return CKR_OK;

#ifdef OS_UNIX
	pthread_atfork (NULL, NULL, reinitialize_after_fork);
#endif
	once = true;

	return CKR_OK;
}

static void
free_modules_when_no_refs_unlocked (void)
{
	Module *mod;
	p11_dictiter iter;

	/* Check if any modules have a ref count */
	p11_dict_iterate (gl.modules, &iter);
	while (p11_dict_next (&iter, NULL, (void **)&mod)) {
		if (mod->ref_count)
			return;
	}

	p11_dict_free (gl.modules);
	gl.modules = NULL;
	p11_dict_free (gl.config);
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

	p11_mutex_lock (&mod->initialize_mutex);
	p11_unlock ();

	if (mod->initialize_called) {

		assert (mod->funcs);
		mod->funcs->C_Finalize (NULL);

		mod->initialize_called = false;
	}

	p11_mutex_unlock (&mod->initialize_mutex);
	p11_lock ();

	/* Match the increment above */
	--mod->ref_count;

	free_modules_when_no_refs_unlocked ();
	return CKR_OK;
}

static Module*
find_module_for_name_unlocked (const char *name)
{
	Module *mod;
	p11_dictiter iter;

	assert (name);

	p11_dict_iterate (gl.modules, &iter);
	while (p11_dict_next (&iter, NULL, (void **)&mod))
		if (mod->ref_count && mod->name && strcmp (name, mod->name) == 0)
			return mod;
	return NULL;
}

CK_RV
_p11_kit_initialize_registered_unlocked_reentrant (void)
{
	Module *mod;
	p11_dictiter iter;
	int critical;
	CK_RV rv;

	rv = init_globals_unlocked ();
	if (rv != CKR_OK)
		return rv;

	rv = load_registered_modules_unlocked ();
	if (rv == CKR_OK) {
		p11_dict_iterate (gl.modules, &iter);
		while (p11_dict_next (&iter, NULL, (void **)&mod)) {

			/* Skip all modules that aren't registered */
			if (mod->name == NULL || !is_module_enabled_unlocked (mod->name, mod->config))
				continue;

			rv = initialize_module_unlocked_reentrant (mod);

			/*
			 * Module failed to initialize. If this is a critical module,
			 * then this, should abort loading of others.
			 */
			if (rv != CKR_OK) {
				p11_message ("failed to initialize module: %s: %s",
				             mod->name, p11_kit_strerror (rv));

				critical = _p11_conf_parse_boolean (p11_dict_get (mod->config, "critical"), false);
				if (!critical) {
					p11_debug ("ignoring failure, non-critical module: %s", mod->name);
					rv = CKR_OK;
				}
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

	p11_library_init_once ();

	/* WARNING: This function must be reentrant */
	p11_debug ("in");

	p11_lock ();

		p11_message_clear ();

		/* WARNING: Reentrancy can occur here */
		rv = _p11_kit_initialize_registered_unlocked_reentrant ();

		_p11_kit_default_message (rv);

	p11_unlock ();

	/* Cleanup any partial initialization */
	if (rv != CKR_OK)
		p11_kit_finalize_registered ();

	p11_debug ("out: %lu", rv);
	return rv;
}

CK_RV
_p11_kit_finalize_registered_unlocked_reentrant (void)
{
	Module *mod;
	p11_dictiter iter;
	Module **to_finalize;
	int i, count;

	if (!gl.modules)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	/* WARNING: This function must be reentrant */

	to_finalize = calloc (p11_dict_size (gl.modules), sizeof (Module *));
	if (!to_finalize)
		return CKR_HOST_MEMORY;

	count = 0;
	p11_dict_iterate (gl.modules, &iter);
	while (p11_dict_next (&iter, NULL, (void **)&mod)) {

		/* Skip all modules that aren't registered */
		if (mod->name)
			to_finalize[count++] = mod;
	}

	p11_debug ("finalizing %d modules", count);

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

	p11_library_init_once ();

	/* WARNING: This function must be reentrant */
	p11_debug ("in");

	p11_lock ();

		p11_message_clear ();

		/* WARNING: Reentrant calls can occur here */
		rv = _p11_kit_finalize_registered_unlocked_reentrant ();

		_p11_kit_default_message (rv);

	p11_unlock ();

	p11_debug ("out: %lu", rv);
	return rv;
}

CK_FUNCTION_LIST_PTR_PTR
_p11_kit_registered_modules_unlocked (void)
{
	CK_FUNCTION_LIST_PTR_PTR result = NULL;
	Module *mod;
	p11_dictiter iter;
	int i = 0;

	if (gl.modules) {
		result = calloc (p11_dict_size (gl.modules) + 1, sizeof (CK_FUNCTION_LIST_PTR));
		return_val_if_fail (result != NULL, NULL);

		p11_dict_iterate (gl.modules, &iter);
		while (p11_dict_next (&iter, NULL, (void **)&mod)) {

			/*
			 * We don't include unreferenced modules. We don't include
			 * modules that have been initialized but aren't in the
			 * registry. These have a NULL name.
			 *
			 * In addition we check again that the module isn't disabled
			 * using enable-in or disable-in. This is because a caller
			 * can change the progname we recognize the process as after
			 * having initialized. This is a corner case, but want to make
			 * sure to cover it.
			 */
			if (mod->ref_count && mod->name &&
			    is_module_enabled_unlocked (mod->name, mod->config)) {
				result[i++] = mod->funcs;
			}
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

	p11_library_init_once ();

	p11_lock ();

		p11_message_clear ();

		result = _p11_kit_registered_modules_unlocked ();

	p11_unlock ();

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

	return_val_if_fail (module != NULL, NULL);

	p11_library_init_once ();

	p11_lock ();

		p11_message_clear ();

		mod = module && gl.modules ? p11_dict_get (gl.modules, module) : NULL;
		if (mod && mod->name)
			name = strdup (mod->name);

	p11_unlock ();

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

	return_val_if_fail (name != NULL, NULL);

	p11_lock ();

		p11_message_clear ();

		if (gl.modules) {
			mod = find_module_for_name_unlocked (name);
			if (mod != NULL && is_module_enabled_unlocked (name, mod->config))
				module = mod->funcs;
		}

	p11_unlock ();

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
	p11_dict *config = NULL;

	return_val_if_fail (field != NULL, NULL);

	p11_library_init_once ();

	p11_lock ();

		p11_message_clear ();

		if (module == NULL) {
			config = gl.config;

		} else {
			mod = gl.modules ? p11_dict_get (gl.modules, module) : NULL;
			if (mod)
				config = mod->config;
		}

		if (config && field) {
			option = p11_dict_get (config, field);
			if (option)
				option = strdup (option);
		}

	p11_unlock ();

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

	return_val_if_fail (module != NULL, CKR_ARGUMENTS_BAD);

	p11_library_init_once ();

	/* WARNING: This function must be reentrant for the same arguments */
	p11_debug ("in");

	p11_lock ();

		p11_message_clear ();

		rv = init_globals_unlocked ();
		if (rv == CKR_OK) {

			mod = p11_dict_get (gl.modules, module);
			if (mod == NULL) {
				p11_debug ("allocating new module");
				allocated = mod = alloc_module_unlocked ();
				if (mod == NULL)
					rv = CKR_HOST_MEMORY;
				else
					mod->funcs = module;
			}

			/* If this was newly allocated, add it to the list */
			if (rv == CKR_OK && allocated) {
				if (p11_dict_set (gl.modules, allocated->funcs, allocated))
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

	p11_unlock ();

	p11_debug ("out: %lu", rv);
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

	return_val_if_fail (module != NULL, CKR_ARGUMENTS_BAD);

	p11_library_init_once ();

	/* WARNING: This function must be reentrant for the same arguments */
	p11_debug ("in");

	p11_lock ();

		p11_message_clear ();

		mod = gl.modules ? p11_dict_get (gl.modules, module) : NULL;
		if (mod == NULL) {
			p11_debug ("module not found");
			rv = CKR_ARGUMENTS_BAD;
		} else {
			/* WARNING: Rentrancy can occur here */
			rv = finalize_module_unlocked_reentrant (mod);
		}

		_p11_kit_default_message (rv);

	p11_unlock ();

	p11_debug ("out: %lu", rv);
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

	return_val_if_fail (module_path != NULL, CKR_ARGUMENTS_BAD);
	return_val_if_fail (module != NULL, CKR_ARGUMENTS_BAD);

	p11_library_init_once ();

	/* WARNING: This function must be reentrant for the same arguments */
	p11_debug ("in: %s", module_path);

	p11_lock ();

		p11_message_clear ();

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

	p11_unlock ();

	p11_debug ("out: %lu", rv);
	return rv;
}
