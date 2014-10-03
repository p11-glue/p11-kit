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

/* We use and define deprecated functions here */
#define P11_KIT_NO_DEPRECATIONS
#define P11_DEBUG_FLAG P11_DEBUG_LIB

#include "conf.h"
#include "debug.h"
#include "dict.h"
#include "library.h"
#include "log.h"
#include "message.h"
#include "modules.h"
#include "path.h"
#include "pkcs11.h"
#include "p11-kit.h"
#include "private.h"
#include "proxy.h"
#include "rpc.h"
#include "virtual.h"

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
 * installed PKCS\#11 modules, each module must be configured so that applications
 * or libraries know that they should load it.
 *
 * When multiple consumers of a module (such as libraries or applications) are
 * in the same process, coordination of the initialization and finalization
 * of PKCS\#11 modules is required. To do this modules are managed by p11-kit.
 * This means that various unsafe methods are coordinated between callers. Unmanaged
 * modules are simply the raw PKCS\#11 module pointers without p11-kit getting in the
 * way. It is highly recommended that the default managed behavior is used.
 *
 * The functions here provide support for initializing configured modules. The
 * p11_kit_modules_load() function should be used to load and initialize
 * the configured modules. When done, the p11_kit_modules_release() function
 * should be used to release those modules and associated resources.
 *
 * In addition p11_kit_config_option() can be used to access other parts
 * of the module configuration.
 *
 * If a consumer wishes to load an arbitrary PKCS\#11 module that's not
 * configured use p11_kit_module_load() to do so. And use p11_kit_module_release()
 * to later release it.
 *
 * Modules are represented by a pointer to their <code>CK_FUNCTION_LIST</code>
 * entry points.
 */

/**
 * SECTION:p11-kit-deprecated
 * @title: Deprecated
 * @short_description: Deprecated functions
 *
 * These functions have been deprecated from p11-kit and are not recommended for
 * general usage. In large part they were deprecated because they did not adequately
 * insulate multiple callers of a PKCS\#11 module from another, and could not
 * support the 'managed' mode needed to do this.
 */

/**
 * P11_KIT_MODULE_UNMANAGED:
 *
 * Module is loaded in non 'managed' mode. This is not recommended,
 * disables many features, and prevents coordination between multiple
 * callers of the same module.
 */

/**
 * P11_KIT_MODULE_CRITICAL:
 *
 * Flag to load a module in 'critical' mode. Failure to load a critical module
 * will prevent all other modules from loading. A failure when loading a
 * non-critical module skips that module.
 */

typedef struct _Module {
	/*
	 * When using managed modules, this forms the base of the
	 * virtual stack into which all the other modules call. This is also
	 * the first field in this structure so we can cast between them.
	 */
	p11_virtual virt;

	/* The initialize args built from configuration */
	CK_C_INITIALIZE_ARGS init_args;
	int ref_count;
	int init_count;

	/* Registered modules */
	char *name;
	p11_dict *config;
	bool critical;

	/*
	 * This is a pointer to the actual dl shared module, or perhaps
	 * the RPC client context.
	 */
	void *loaded_module;
	p11_kit_destroyer loaded_destroy;

	/* Initialization, mutex must be held */
	p11_mutex_t initialize_mutex;
	unsigned int initialize_called;
	p11_thread_id_t initialize_thread;
} Module;

/*
 * Shared data between threads, protected by the mutex, a structure so
 * we can audit thread safety easier.
 */
static struct _Shared {
	p11_dict *modules;
	p11_dict *unmanaged_by_funcs;
	p11_dict *managed_by_closure;
	p11_dict *config;
} gl = { NULL, NULL };

/* These are global variables to be overridden in tests */
const char *p11_config_system_file = P11_SYSTEM_CONFIG_FILE;
const char *p11_config_user_file = P11_USER_CONFIG_FILE;
const char *p11_config_package_modules = P11_PACKAGE_CONFIG_MODULES;
const char *p11_config_system_modules = P11_SYSTEM_CONFIG_MODULES;
const char *p11_config_user_modules = P11_USER_CONFIG_MODULES;

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

	/* Module must have no outstanding references */
	assert (mod->ref_count == 0);

	if (mod->init_count > 0) {
		p11_debug_precond ("module unloaded without C_Finalize having been "
		                   "called for each C_Initialize");
	} else {
		assert (mod->initialize_thread == 0);
	}

	if (mod->loaded_destroy)
		mod->loaded_destroy (mod->loaded_module);

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

	/*
	 * The default for configured modules is non-critical, but for
	 * modules loaded explicitly, and not from config, we treat them
	 * as critical. So this gets overridden for configured modules
	 * later when the config is loaded.
	 */
	mod->critical = true;

	return mod;
}

static CK_RV
dlopen_and_get_function_list (Module *mod,
                              const char *path,
                              CK_FUNCTION_LIST **funcs)
{
	CK_C_GetFunctionList gfl;
	dl_module_t dl;
	char *error;
	CK_RV rv;

	assert (mod != NULL);
	assert (path != NULL);
	assert (funcs != NULL);

	dl = p11_dl_open (path);
	if (dl == NULL) {
		error = p11_dl_error ();
		p11_message ("couldn't load module: %s: %s", path, error);
		free (error);
		return CKR_GENERAL_ERROR;
	}

	/* When the Module goes away, dlclose the loaded module */
	mod->loaded_destroy = (p11_kit_destroyer)p11_dl_close;
	mod->loaded_module = dl;

	gfl = p11_dl_symbol (dl, "C_GetFunctionList");
	if (!gfl) {
		error = p11_dl_error ();
		p11_message ("couldn't find C_GetFunctionList entry point in module: %s: %s",
		             path, error);
		free (error);
		return CKR_GENERAL_ERROR;
	}

	rv = gfl (funcs);
	if (rv != CKR_OK) {
		p11_message ("call to C_GetFunctiontList failed in module: %s: %s",
		             path, p11_kit_strerror (rv));
		return rv;
	}

	if (p11_proxy_module_check (*funcs)) {
		p11_message ("refusing to load the p11-kit-proxy.so module as a registered module");
		return CKR_FUNCTION_FAILED;
	}

	p11_virtual_init (&mod->virt, &p11_virtual_base, *funcs, NULL);
	p11_debug ("opened module: %s", path);
	return CKR_OK;
}

static CK_RV
load_module_from_file_inlock (const char *name,
                              const char *path,
                              Module **result)
{
	CK_FUNCTION_LIST *funcs;
	char *expand = NULL;
	Module *mod;
	Module *prev;
	CK_RV rv;

	assert (path != NULL);
	assert (result != NULL);

	mod = alloc_module_unlocked ();
	return_val_if_fail (mod != NULL, CKR_HOST_MEMORY);

	if (!p11_path_absolute (path)) {
		p11_debug ("module path is relative, loading from: %s", P11_MODULE_PATH);
		path = expand = p11_path_build (P11_MODULE_PATH, path, NULL);
		return_val_if_fail (path != NULL, CKR_HOST_MEMORY);
	}

	p11_debug ("loading module %s%sfrom path: %s",
	           name ? name : "", name ? " " : "", path);

	rv = dlopen_and_get_function_list (mod, path, &funcs);
	free (expand);

	if (rv != CKR_OK) {
		free_module_unlocked (mod);
		return rv;
	}

	/* Do we have a previous one like this, if so ignore load */
	prev = p11_dict_get (gl.unmanaged_by_funcs, funcs);

	/* If same module was loaded previously, just take over config */
	if (prev != NULL) {
		if (!name || prev->name || prev->config)
			p11_debug ("duplicate module %s, using previous", name);
		free_module_unlocked (mod);
		mod = prev;

	/* This takes ownership of the module */
	} else if (!p11_dict_set (gl.modules, mod, mod) ||
		   !p11_dict_set (gl.unmanaged_by_funcs, funcs, mod)) {
		return_val_if_reached (CKR_HOST_MEMORY);
	}

	*result= mod;
	return CKR_OK;
}

static CK_RV
setup_module_for_remote_inlock (const char *name,
                                const char *remote,
                                Module **result)
{
	p11_rpc_transport *rpc;
	Module *mod;

	p11_debug ("remoting module %s using: %s", name, remote);

	mod = alloc_module_unlocked ();
	return_val_if_fail (mod != NULL, CKR_HOST_MEMORY);

	rpc = p11_rpc_transport_new (&mod->virt, remote, name);
	if (rpc == NULL) {
		free_module_unlocked (mod);
		return CKR_DEVICE_ERROR;
	}

	mod->loaded_module = rpc;
	mod->loaded_destroy = p11_rpc_transport_free;

	/* This takes ownership of the module */
	if (!p11_dict_set (gl.modules, mod, mod))
		return_val_if_reached (CKR_HOST_MEMORY);

	*result = mod;
	return CKR_OK;
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
take_config_and_load_module_inlock (char **name,
                                    p11_dict **config,
                                    bool critical)
{
	const char *filename = NULL;
	const char *remote = NULL;
	char *value = NULL;
	CK_RV rv = CKR_OK;
	Module *mod;

	assert (name);
	assert (*name);
	assert (config);
	assert (*config);

	if (!is_module_enabled_unlocked (*name, *config))
		goto out;

	remote = p11_dict_get (*config, "remote");
	if (remote == NULL) {
		filename = p11_dict_get (*config, "module");
		if (filename == NULL) {
			p11_debug ("no module path for module, skipping: %s", *name);
			goto out;
		}
	}

	if (remote != NULL) {
		rv = setup_module_for_remote_inlock (*name, remote, &mod);
		if (rv != CKR_OK)
			goto out;

	} else {

		rv = load_module_from_file_inlock (*name, filename, &mod);
		if (rv != CKR_OK)
			goto out;

		/*
		 * We support setting of CK_C_INITIALIZE_ARGS.pReserved from
		 * 'x-init-reserved' setting in the config. This only works with specific
		 * PKCS#11 modules, and is non-standard use of that field.
		 */
		mod->init_args.pReserved = p11_dict_get (*config, "x-init-reserved");
	}

	/* Take ownership of thes evariables */
	p11_dict_free (mod->config);
	mod->config = *config;
	*config = NULL;
	free (mod->name);
	mod->name = *name;
	*name = NULL;
	mod->critical = critical;

out:
	free (value);
	return rv;
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
	config = _p11_conf_load_globals (p11_config_system_file, p11_config_user_file, &mode);
	if (config == NULL)
		return CKR_GENERAL_ERROR;

	assert (mode != CONF_USER_INVALID);

	configs = _p11_conf_load_modules (mode,
	                                  p11_config_package_modules,
	                                  p11_config_system_modules,
	                                  p11_config_user_modules);
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
		rv = take_config_and_load_module_inlock (&name, &config, critical);

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
initialize_module_inlock_reentrant (Module *mod)
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
	p11_unlock ();
	p11_mutex_lock (&mod->initialize_mutex);

	if (mod->initialize_called != p11_forkid) {
		p11_debug ("C_Initialize: calling");

		rv = mod->virt.funcs.C_Initialize (&mod->virt.funcs,
		                                   &mod->init_args);

		p11_debug ("C_Initialize: result: %lu", rv);

		/* Module was initialized and C_Finalize should be called */
		if (rv == CKR_OK)
			mod->initialize_called = p11_forkid;
		else
			mod->initialize_called = 0;

		/* Module was already initialized, we don't call C_Finalize */
		if (rv == CKR_CRYPTOKI_ALREADY_INITIALIZED)
			rv = CKR_OK;
	}

	p11_mutex_unlock (&mod->initialize_mutex);
	p11_lock ();

	if (rv == CKR_OK) {
		/* Matches the ref count in finalize_module_inlock_reentrant() */
		if (mod->init_count == 0)
			mod->ref_count++;
		mod->init_count++;
	}

	mod->ref_count--;
	mod->initialize_thread = 0;
	return rv;
}

static CK_RV
init_globals_unlocked (void)
{
	static bool once = false;

	if (!gl.modules) {
		gl.modules = p11_dict_new (p11_dict_direct_hash,
		                           p11_dict_direct_equal,
		                           free_module_unlocked, NULL);
		return_val_if_fail (gl.modules != NULL, CKR_HOST_MEMORY);
	}

	if (!gl.unmanaged_by_funcs) {
		gl.unmanaged_by_funcs = p11_dict_new (p11_dict_direct_hash,
		                                      p11_dict_direct_equal,
		                                      NULL, NULL);
		return_val_if_fail (gl.unmanaged_by_funcs != NULL, CKR_HOST_MEMORY);
	}

	if (!gl.managed_by_closure) {
		gl.managed_by_closure = p11_dict_new (p11_dict_direct_hash,
		                                      p11_dict_direct_equal,
		                                      NULL, NULL);
		return_val_if_fail (gl.managed_by_closure != NULL, CKR_HOST_MEMORY);
	}

	if (once)
		return CKR_OK;

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
	while (p11_dict_next (&iter, (void **)&mod, NULL)) {
		if (mod->ref_count)
			return;
	}

	p11_dict_free (gl.unmanaged_by_funcs);
	gl.unmanaged_by_funcs = NULL;

	p11_dict_free (gl.managed_by_closure);
	gl.managed_by_closure = NULL;

	p11_dict_free (gl.modules);
	gl.modules = NULL;

	p11_dict_free (gl.config);
	gl.config = NULL;
}

static CK_RV
finalize_module_inlock_reentrant (Module *mod)
{
	assert (mod);

	/*
	 * We leave module info around until all are finalized
	 * so we can encounter these zombie Module structures.
	 */
	if (mod->ref_count == 0)
		return CKR_ARGUMENTS_BAD;

	if (--mod->init_count > 0)
		return CKR_OK;

	/*
	 * Becuase of the mutex unlock below, we temporarily increase
	 * the ref count. This prevents module from being freed out
	 * from ounder us.
	 */

	p11_unlock ();
	p11_mutex_lock (&mod->initialize_mutex);

	if (mod->initialize_called == p11_forkid) {
		mod->virt.funcs.C_Finalize (&mod->virt.funcs, NULL);
		mod->initialize_called = 0;
	}

	p11_mutex_unlock (&mod->initialize_mutex);
	p11_lock ();

	/* Match the ref increment in initialize_module_inlock_reentrant() */
	mod->ref_count--;

	free_modules_when_no_refs_unlocked ();
	return CKR_OK;
}

static CK_RV
initialize_registered_inlock_reentrant (void)
{
	p11_dictiter iter;
	Module *mod;
	CK_RV rv;

	/*
	 * This is only called by deprecated code. The caller expects all
	 * configured and enabled modules to be initialized.
	 */

	rv = init_globals_unlocked ();
	if (rv != CKR_OK)
		return rv;

	rv = load_registered_modules_unlocked ();
	if (rv == CKR_OK) {
		p11_dict_iterate (gl.unmanaged_by_funcs, &iter);
		while (rv == CKR_OK && p11_dict_next (&iter, NULL, (void **)&mod)) {

			/* Skip all modules that aren't registered or enabled */
			if (mod->name == NULL || !is_module_enabled_unlocked (mod->name, mod->config))
				continue;

			rv = initialize_module_inlock_reentrant (mod);
			if (rv != CKR_OK) {
				if (mod->critical) {
					p11_message ("initialization of critical module '%s' failed: %s",
					             mod->name, p11_kit_strerror (rv));
				} else {
					p11_message ("skipping module '%s' whose initialization failed: %s",
					             mod->name, p11_kit_strerror (rv));
					rv = CKR_OK;
				}
			}
		}
	}

	return rv;
}

static Module *
module_for_functions_inlock (CK_FUNCTION_LIST *funcs)
{
	if (p11_virtual_is_wrapper (funcs))
		return p11_dict_get (gl.managed_by_closure, funcs);
	else
		return p11_dict_get (gl.unmanaged_by_funcs, funcs);
}

static CK_FUNCTION_LIST *
unmanaged_for_module_inlock (Module *mod)
{
	CK_FUNCTION_LIST *funcs;

	funcs = mod->virt.lower_module;
	if (p11_dict_get (gl.unmanaged_by_funcs, funcs) == mod)
		return funcs;

	return NULL;
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
 * Deprecated: Since: 0.19.0: Use p11_kit_modules_load() instead.
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
		rv = initialize_registered_inlock_reentrant ();

		_p11_kit_default_message (rv);

	p11_unlock ();

	/* Cleanup any partial initialization */
	if (rv != CKR_OK)
		p11_kit_finalize_registered ();

	p11_debug ("out: %lu", rv);
	return rv;
}

static CK_RV
finalize_registered_inlock_reentrant (void)
{
	Module *mod;
	p11_dictiter iter;
	Module **to_finalize;
	int i, count;

	/*
	 * This is only called from deprecated code. The caller expects all
	 * modules initialized earlier to be finalized (once). If non-critical
	 * modules failed to initialize, then it is not possible to completely
	 * guarantee the internal state.
	 */

	if (!gl.modules)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	/* WARNING: This function must be reentrant */

	to_finalize = calloc (p11_dict_size (gl.unmanaged_by_funcs), sizeof (Module *));
	if (!to_finalize)
		return CKR_HOST_MEMORY;

	count = 0;
	p11_dict_iterate (gl.unmanaged_by_funcs, &iter);
	while (p11_dict_next (&iter, NULL, (void **)&mod)) {

		/* Skip all modules that aren't registered */
		if (mod->name && mod->init_count)
			to_finalize[count++] = mod;
	}

	p11_debug ("finalizing %d modules", count);

	for (i = 0; i < count; ++i) {
		/* WARNING: Reentrant calls can occur here */
		finalize_module_inlock_reentrant (to_finalize[i]);
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
 * Deprecated: Since 0.19.0: Use p11_kit_modules_release() instead.
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
		rv = finalize_registered_inlock_reentrant ();

		_p11_kit_default_message (rv);

	p11_unlock ();

	p11_debug ("out: %lu", rv);
	return rv;
}

static int
compar_priority (const void *one,
                 const void *two)
{
	CK_FUNCTION_LIST_PTR f1 = *((CK_FUNCTION_LIST_PTR *)one);
	CK_FUNCTION_LIST_PTR f2 = *((CK_FUNCTION_LIST_PTR *)two);
	Module *m1, *m2;
	const char *v1, *v2;
	int o1, o2;

	m1 = module_for_functions_inlock (f1);
	m2 = module_for_functions_inlock (f2);
	assert (m1 != NULL && m2 != NULL);

	v1 = p11_dict_get (m1->config, "priority");
	v2 = p11_dict_get (m2->config, "priority");

	o1 = atoi (v1 ? v1 : "0");
	o2 = atoi (v2 ? v2 : "0");

	/* Priority is in descending order, highest first */
	if (o1 != o2)
		return o1 > o2 ? -1 : 1;

	/*
	 * Otherwise use the names alphabetically in ascending order. This
	 * is really just to provide consistency between various loads of
	 * the configuration.
	 */
	if (m1->name == m2->name)
		return 0;
	if (!m1->name)
		return -1;
	if (!m2->name)
		return 1;
	return strcmp (m1->name, m2->name);
}

static void
sort_modules_by_priority (CK_FUNCTION_LIST_PTR *modules,
                          int count)
{
	qsort (modules, count, sizeof (CK_FUNCTION_LIST_PTR), compar_priority);
}

static CK_FUNCTION_LIST **
list_registered_modules_inlock (void)
{
	CK_FUNCTION_LIST **result = NULL;
	CK_FUNCTION_LIST *funcs;
	Module *mod;
	p11_dictiter iter;
	int i = 0;

	/*
	 * This is only called by deprecated code. The caller expects to get
	 * a list of all registered enabled modules that have been initialized.
	 */

	if (gl.unmanaged_by_funcs) {
		result = calloc (p11_dict_size (gl.unmanaged_by_funcs) + 1,
		                 sizeof (CK_FUNCTION_LIST *));
		return_val_if_fail (result != NULL, NULL);

		p11_dict_iterate (gl.unmanaged_by_funcs, &iter);
		while (p11_dict_next (&iter, (void **)&funcs, (void **)&mod)) {

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
			if (mod->ref_count && mod->name && mod->init_count &&
			    is_module_enabled_unlocked (mod->name, mod->config)) {
				result[i++] = funcs;
			}
		}

		sort_modules_by_priority (result, i);
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
 * The returned modules are unmanaged.
 *
 * Deprecated: Since 0.19.0: Use p11_kit_modules_load() instead.
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

		result = list_registered_modules_inlock ();

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
 * Deprecated: Since 0.19.0: Use p11_kit_module_get_name() instead.
 *
 * Returns: A newly allocated string containing the module name, or
 *     <code>NULL</code> if no such registered module exists. Use free() to
 *     free this string.
 */
char*
p11_kit_registered_module_to_name (CK_FUNCTION_LIST_PTR module)
{
	return_val_if_fail (module != NULL, NULL);
	return p11_kit_module_get_name (module);
}

/**
 * p11_kit_module_get_name:
 * @module: pointer to a loaded module
 *
 * Get the configured name of the PKCS\#11 module.
 *
 * Configured modules are loaded by p11_kit_modules_load(). The module
 * passed to this function can be either managed or unmanaged. Non
 * configured modules will return %NULL.
 *
 * Use free() to release the return value when you're done with it.
 *
 * Returns: a newly allocated string containing the module name, or
 *     <code>NULL</code> if the module is not a configured module
 */
char *
p11_kit_module_get_name (CK_FUNCTION_LIST *module)
{
	Module *mod;
	char *name = NULL;

	return_val_if_fail (module != NULL, NULL);

	p11_library_init_once ();

	p11_lock ();

		p11_message_clear ();

		if (gl.modules) {
			mod = module_for_functions_inlock (module);
			if (mod && mod->name)
				name = strdup (mod->name);
		}

	p11_unlock ();

	return name;
}

static const char *
module_get_option_inlock (Module *mod,
                          const char *option)
{
	p11_dict *config;

	if (mod == NULL)
		config = gl.config;
	else
		config = mod->config;
	if (config == NULL)
		return NULL;
	return p11_dict_get (config, option);
}

/**
 * p11_kit_module_get_flags:
 * @module: the module
 *
 * Get the flags for this module.
 *
 * The %P11_KIT_MODULE_UNMANAGED flag will be set if the module is not
 * managed by p11-kit. It is a raw PKCS\#11 module function list.
 *
 * The %P11_KIT_MODULE_CRITICAL flag will be set if the module is configured
 * to be critical, and not be skipped over if it fails to initialize or
 * load. This flag is also set for modules that are not configured, but have
 * been loaded in another fashion.
 *
 * Returns: the flags for the module
 */
int
p11_kit_module_get_flags (CK_FUNCTION_LIST *module)
{
	const char *trusted;
	Module *mod;
	int flags = 0;

	return_val_if_fail (module != NULL, 0);

	p11_library_init_once ();

	p11_lock ();

		p11_message_clear ();

		if (gl.modules) {
			if (p11_virtual_is_wrapper (module)) {
				mod = p11_dict_get (gl.managed_by_closure, module);
			} else {
				flags |= P11_KIT_MODULE_UNMANAGED;
				mod = p11_dict_get (gl.unmanaged_by_funcs, module);
			}
			if (!mod || mod->critical)
				flags |= P11_KIT_MODULE_CRITICAL;
			if (mod) {
				trusted = module_get_option_inlock (mod, "trust-policy");
				if (_p11_conf_parse_boolean (trusted, false))
					flags |= P11_KIT_MODULE_TRUSTED;
			}
		}

	p11_unlock ();

	return flags;
}

/**
 * p11_kit_registered_name_to_module:
 * @name: name of a registered module
 *
 * Lookup a registered PKCS\#11 module by its name. This name is specified by
 * the registered module configuration.
 *
 * Deprecated: Since 0.19.0: Use p11_kit_module_for_name() instead.
 *
 * Returns: a pointer to a PKCS\#11 module, or <code>NULL</code> if this name was
 *     not found.
 */
CK_FUNCTION_LIST_PTR
p11_kit_registered_name_to_module (const char *name)
{
	CK_FUNCTION_LIST_PTR module = NULL;
	CK_FUNCTION_LIST_PTR funcs;
	p11_dictiter iter;
	Module *mod;

	return_val_if_fail (name != NULL, NULL);

	p11_lock ();

	p11_message_clear ();

	if (gl.modules) {

		assert (name);

		p11_dict_iterate (gl.unmanaged_by_funcs, &iter);
		while (p11_dict_next (&iter, (void **)&funcs, (void **)&mod)) {
			if (mod->ref_count && mod->name && strcmp (name, mod->name) == 0) {
				module = funcs;
				break;
			}
		}
	}

	p11_unlock ();

	return module;
}

/**
 * p11_kit_module_for_name:
 * @modules: a list of modules to look through
 * @name: the name of the module to find
 *
 * Look through the list of @modules and return the module whose @name
 * matches.
 *
 * Only configured modules have names. Configured modules are loaded by
 * p11_kit_modules_load(). The module passed to this function can be either
 * managed or unmanaged.
 *
 * The return value is not copied or duplicated in anyway. It is still
 * 'owned' by the @modules list.
 *
 * Returns: the module which matches the name, or %NULL if no match.
 */
CK_FUNCTION_LIST *
p11_kit_module_for_name (CK_FUNCTION_LIST **modules,
                         const char *name)
{
	CK_FUNCTION_LIST *ret = NULL;
	Module *mod;
	int i;

	return_val_if_fail (name != NULL, NULL);

	if (!modules)
		return NULL;

	p11_library_init_once ();

	p11_lock ();

		p11_message_clear ();

		for (i = 0; gl.modules && modules[i] != NULL; i++) {
			mod = module_for_functions_inlock (modules[i]);
			if (mod && mod->name && strcmp (mod->name, name) == 0) {
				ret = modules[i];
				break;
			}
		}

	p11_unlock ();

	return ret;
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
 * Deprecated: Since 0.19.0: Use p11_kit_config_option() instead.
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
	const char *value;

	return_val_if_fail (field != NULL, NULL);

	p11_library_init_once ();

	p11_lock ();

		p11_message_clear ();

		if (module == NULL)
			mod = NULL;
		else
			mod = gl.unmanaged_by_funcs ? p11_dict_get (gl.unmanaged_by_funcs, module) : NULL;

		value = module_get_option_inlock (mod, field);
		if (value)
			option = strdup (value);

	p11_unlock ();

	return option;
}

/**
 * p11_kit_config_option:
 * @module: the module to retrieve the option for, or %NULL for global options
 * @option: the option to retrieve
 *
 * Retrieve the value for a configured option.
 *
 * If @module is %NULL, then the global option with the given name will
 * be retrieved. Otherwise @module should point to a configured loaded module.
 * If no such @option or configured @module exists, then %NULL will be returned.
 *
 * Use free() to release the returned value.
 *
 * Returns: the option value or %NULL
 */
char *
p11_kit_config_option (CK_FUNCTION_LIST *module,
                       const char *option)
{
	Module *mod = NULL;
	const char *value = NULL;
	char *ret = NULL;

	return_val_if_fail (option != NULL, NULL);

	p11_library_init_once ();

	p11_lock ();

		p11_message_clear ();

		if (gl.modules) {
			if (module != NULL) {
				mod = module_for_functions_inlock (module);
				if (mod == NULL)
					goto cleanup;
			}

			value = module_get_option_inlock (mod, option);
			if (value)
				ret = strdup (value);
		}


cleanup:
	p11_unlock ();
	return ret;
}

typedef struct {
	p11_virtual virt;
	Module *mod;
	unsigned int initialized;
	p11_dict *sessions;
} Managed;

static CK_RV
managed_C_Initialize (CK_X_FUNCTION_LIST *self,
                      CK_VOID_PTR init_args)
{
	Managed *managed = ((Managed *)self);
	p11_dict *sessions;
	CK_RV rv;

	p11_debug ("in");
	p11_lock ();

	if (managed->initialized == p11_forkid) {
		rv = CKR_CRYPTOKI_ALREADY_INITIALIZED;

	} else {
		sessions = p11_dict_new (p11_dict_ulongptr_hash,
		                         p11_dict_ulongptr_equal,
		                         free, free);
		if (!sessions)
			rv = CKR_HOST_MEMORY;
		else
			rv = initialize_module_inlock_reentrant (managed->mod);
		if (rv == CKR_OK) {
			managed->sessions = sessions;
			managed->initialized = p11_forkid;
		} else {
			p11_dict_free (sessions);
		}
	}

	p11_unlock ();
	p11_debug ("out: %lu", rv);

	return rv;
}

static CK_RV
managed_track_session_inlock (p11_dict *sessions,
                              CK_SLOT_ID slot_id,
                              CK_SESSION_HANDLE session)
{
	void *key;
	void *value;

	key = memdup (&session, sizeof (CK_SESSION_HANDLE));
	return_val_if_fail (key != NULL, CKR_HOST_MEMORY);

	value = memdup (&slot_id, sizeof (CK_SESSION_HANDLE));
	return_val_if_fail (value != NULL, CKR_HOST_MEMORY);

	if (!p11_dict_set (sessions, key, value))
		return_val_if_reached (CKR_HOST_MEMORY);

	return CKR_OK;
}

static void
managed_untrack_session_inlock (p11_dict *sessions,
                                CK_SESSION_HANDLE session)
{
	p11_dict_remove (sessions, &session);
}

static CK_SESSION_HANDLE *
managed_steal_sessions_inlock (p11_dict *sessions,
                        bool matching_slot_id,
                        CK_SLOT_ID slot_id,
                        int *count)
{
	CK_SESSION_HANDLE *stolen;
	CK_SESSION_HANDLE *key;
	CK_SLOT_ID *value;
	p11_dictiter iter;
	int at, i;

	assert (sessions != NULL);
	assert (count != NULL);

	stolen = calloc (p11_dict_size (sessions), sizeof (CK_SESSION_HANDLE));
	return_val_if_fail (stolen != NULL, NULL);

	at = 0;
	p11_dict_iterate (sessions, &iter);
	while (p11_dict_next (&iter, (void **)&key, (void **)&value)) {
		if (!matching_slot_id || slot_id == *value)
			stolen[at++] = *key;
	}

	/* Removed them all, clear the whole array */
	if (at == p11_dict_size (sessions)) {
		p11_dict_clear (sessions);

	/* Only removed some, go through and remove those */
	} else {
		for (i = 0; i < at; i++) {
			if (!p11_dict_remove (sessions, stolen + at))
				assert_not_reached ();
		}
	}

	*count = at;
	return stolen;
}

static void
managed_close_sessions (CK_X_FUNCTION_LIST *funcs,
                        CK_SESSION_HANDLE *stolen,
                        int count)
{
	CK_RV rv;
	int i;

	for (i = 0; i < count; i++) {
		rv = funcs->C_CloseSession (funcs, stolen[i]);
		if (rv != CKR_OK)
			p11_message ("couldn't close session: %s", p11_kit_strerror (rv));
	}
}

static CK_RV
managed_C_Finalize (CK_X_FUNCTION_LIST *self,
                    CK_VOID_PTR reserved)
{
	Managed *managed = ((Managed *)self);
	CK_SESSION_HANDLE *sessions;
	int count;
	CK_RV rv;

	p11_debug ("in");
	p11_lock ();

	if (managed->initialized == 0) {
		rv = CKR_CRYPTOKI_NOT_INITIALIZED;

	} else if (managed->initialized != p11_forkid) {
		/*
		 * In theory we should be returning CKR_CRYPTOKI_NOT_INITIALIZED here
		 * but enough callers are not completely aware of their forking.
		 * So we just clean up any state we have, rather than forcing callers
		 * to initialize just to finalize.
		 */
		p11_debug ("finalizing module in wrong process, skipping C_Finalize");
		rv = CKR_OK;

	} else {
		sessions = managed_steal_sessions_inlock (managed->sessions, false, 0, &count);

		if (sessions && count) {
			/* WARNING: reentrancy can occur here */
			p11_unlock ();
			managed_close_sessions (&managed->mod->virt.funcs, sessions, count);
			p11_lock ();
		}

		free (sessions);

		/* WARNING: reentrancy can occur here */
		rv = finalize_module_inlock_reentrant (managed->mod);
	}

	if (rv == CKR_OK) {
		managed->initialized = 0;
		p11_dict_free (managed->sessions);
		managed->sessions = NULL;
	}

	p11_unlock ();
	p11_debug ("out: %lu", rv);

	return rv;
}

static CK_RV
managed_C_OpenSession (CK_X_FUNCTION_LIST *self,
                       CK_SLOT_ID slot_id,
                       CK_FLAGS flags,
                       CK_VOID_PTR application,
                       CK_NOTIFY notify,
                       CK_SESSION_HANDLE_PTR session)
{
	Managed *managed = ((Managed *)self);
	CK_RV rv;

	return_val_if_fail (session != NULL, CKR_ARGUMENTS_BAD);

	self = &managed->mod->virt.funcs;
	rv = self->C_OpenSession (self, slot_id, flags, application, notify, session);

	if (rv == CKR_OK) {
		p11_lock ();
		rv = managed_track_session_inlock (managed->sessions, slot_id, *session);
		p11_unlock ();
	}

	return rv;
}

static CK_RV
managed_C_CloseSession (CK_X_FUNCTION_LIST *self,
                        CK_SESSION_HANDLE session)
{
	Managed *managed = ((Managed *)self);
	CK_RV rv;

	self = &managed->mod->virt.funcs;
	rv = self->C_CloseSession (self, session);

	if (rv == CKR_OK) {
		p11_lock ();
		managed_untrack_session_inlock (managed->sessions, session);
		p11_unlock ();
	}

	return rv;
}

static CK_RV
managed_C_CloseAllSessions (CK_X_FUNCTION_LIST *self,
                            CK_SLOT_ID slot_id)
{
	Managed *managed = ((Managed *)self);
	CK_SESSION_HANDLE *stolen;
	int count;

	p11_lock ();
	stolen = managed_steal_sessions_inlock (managed->sessions, true, slot_id, &count);
	p11_unlock ();

	self = &managed->mod->virt.funcs;
	managed_close_sessions (self, stolen, count);
	free (stolen);

	return stolen ? CKR_OK : CKR_GENERAL_ERROR;
}

static void
managed_free_inlock (void *data)
{
	Managed *managed = data;
	managed->mod->ref_count--;
	free (managed);
}

static p11_virtual *
managed_create_inlock (Module *mod)
{
	Managed *managed;

	managed = calloc (1, sizeof (Managed));
	return_val_if_fail (managed != NULL, NULL);

	p11_virtual_init (&managed->virt, &p11_virtual_stack,
	                  &mod->virt, NULL);
	managed->virt.funcs.C_Initialize = managed_C_Initialize;
	managed->virt.funcs.C_Finalize = managed_C_Finalize;
	managed->virt.funcs.C_CloseAllSessions = managed_C_CloseAllSessions;
	managed->virt.funcs.C_CloseSession = managed_C_CloseSession;
	managed->virt.funcs.C_OpenSession = managed_C_OpenSession;
	managed->mod = mod;
	mod->ref_count++;

	return &managed->virt;
}

static bool
lookup_managed_option (Module *mod,
                       bool supported,
                       const char *option,
                       bool def_value)
{
	const char *string;
	bool value;

	string = module_get_option_inlock (NULL, option);
	if (!string)
		string = module_get_option_inlock (mod, option);
	if (!string) {
		if (!supported)
			return false;
		return def_value;
	}

	value = _p11_conf_parse_boolean (string, def_value);

	if (!supported && value != supported) {
		if (!p11_virtual_can_wrap ()) {
			/*
			 * This is because libffi dependency was not built. The libffi dependency
			 * is highly recommended and building without it results in a large loss
			 * of functionality.
			 */
			p11_message ("the '%s' option for module '%s' is not supported on this system",
			             option, mod->name);
		} else {
			/*
			 * This is because the module is running in unmanaged mode, so turn off the
			 */
			p11_message ("the '%s' option for module '%s' is only supported for managed modules",
			             option, mod->name);
		}
		return false;
	}

	return value;
}

static CK_RV
release_module_inlock_rentrant (CK_FUNCTION_LIST *module,
                                const char *caller_func)
{
	Module *mod;

	assert (module != NULL);

	/* See if a managed module, and finalize if so */
	if (p11_virtual_is_wrapper (module)) {
		mod = p11_dict_get (gl.managed_by_closure, module);
		if (mod != NULL) {
			if (!p11_dict_remove (gl.managed_by_closure, module))
				assert_not_reached ();
			p11_virtual_unwrap (module);
		}

	/* If an unmanaged module then caller should have finalized */
	} else {
		mod = p11_dict_get (gl.unmanaged_by_funcs, module);
	}

	if (mod == NULL) {
		p11_debug_precond ("invalid module pointer passed to %s", caller_func);
		return CKR_ARGUMENTS_BAD;
	}

	/* Matches the ref in prepare_module_inlock_reentrant() */
	mod->ref_count--;
	return CKR_OK;
}

CK_RV
p11_modules_release_inlock_reentrant (CK_FUNCTION_LIST **modules)
{
	CK_RV ret = CKR_OK;
	CK_RV rv;
	int i;

	for (i = 0; modules[i] != NULL; i++) {
		rv = release_module_inlock_rentrant (modules[i], __PRETTY_FUNCTION__);
		if (rv != CKR_OK)
			ret = rv;
	}

	free (modules);

	/* In case nothing loaded, free up internal memory */
	free_modules_when_no_refs_unlocked ();

	return ret;
}

static CK_RV
prepare_module_inlock_reentrant (Module *mod,
                                 int flags,
                                 CK_FUNCTION_LIST **module)
{
	p11_destroyer destroyer;
	const char *trusted;
	p11_virtual *virt;
	bool is_managed;
	bool with_log;

	assert (module != NULL);

	if (flags & P11_KIT_MODULE_TRUSTED) {
		trusted = module_get_option_inlock (mod, "trust-policy");
		if (!_p11_conf_parse_boolean (trusted, false))
			return CKR_FUNCTION_NOT_SUPPORTED;
	}

	if (flags & P11_KIT_MODULE_UNMANAGED) {
		is_managed = false;
		with_log = false;
	} else {
		is_managed = lookup_managed_option (mod, p11_virtual_can_wrap (), "managed", true);
		with_log = lookup_managed_option (mod, is_managed, "log-calls", false);
	}

	if (is_managed) {
		virt = managed_create_inlock (mod);
		return_val_if_fail (virt != NULL, CKR_HOST_MEMORY);
		destroyer = managed_free_inlock;

		/* Add the logger if configured */
		if (p11_log_force || with_log) {
			virt = p11_log_subclass (virt, destroyer);
			destroyer = p11_log_release;
		}

		*module = p11_virtual_wrap (virt, destroyer);
		return_val_if_fail (*module != NULL, CKR_GENERAL_ERROR);

		if (!p11_dict_set (gl.managed_by_closure, *module, mod))
			return_val_if_reached (CKR_HOST_MEMORY);

	} else {
		*module = unmanaged_for_module_inlock (mod);
		if (*module == NULL)
			return CKR_FUNCTION_NOT_SUPPORTED;
	}

	/* Matches the deref in release_module_inlock_rentrant() */
	mod->ref_count++;
	return CKR_OK;
}

CK_RV
p11_modules_load_inlock_reentrant (int flags,
                                   CK_FUNCTION_LIST ***results)
{
	CK_FUNCTION_LIST **modules;
	Module *mod;
	p11_dictiter iter;
	CK_RV rv;
	int at;

	rv = init_globals_unlocked ();
	if (rv != CKR_OK)
		return rv;

	rv = load_registered_modules_unlocked ();
	if (rv != CKR_OK)
		return rv;

	modules = calloc (p11_dict_size (gl.modules) + 1, sizeof (CK_FUNCTION_LIST *));
	return_val_if_fail (modules != NULL, CKR_HOST_MEMORY);

	at = 0;
	rv = CKR_OK;

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
		if (!mod->name || !is_module_enabled_unlocked (mod->name, mod->config))
			continue;

		rv = prepare_module_inlock_reentrant (mod, flags, modules + at);
		if (rv == CKR_OK)
			at++;
		else if (rv == CKR_FUNCTION_NOT_SUPPORTED)
			rv = CKR_OK;
		else
			break;
	}

	modules[at] = NULL;

	if (rv != CKR_OK) {
		p11_modules_release_inlock_reentrant (modules);
		return rv;
	}

	sort_modules_by_priority (modules, at);
	*results = modules;
	return CKR_OK;
}

/**
 * p11_kit_modules_load:
 * @reserved: set to %NULL
 * @flags: flags to use to load the module
 *
 * Load the configured PKCS\#11 modules.
 *
 * If @flags contains the %P11_KIT_MODULE_UNMANAGED flag, then the
 * modules will be not be loaded in 'managed' mode regardless of its
 * configuration. This is not recommended for general usage.
 *
 * If @flags contains the %P11_KIT_MODULE_CRITICAL flag then the
 * modules will all be treated as 'critical', regardless of the module
 * configuration. This means that a failure to load any module will
 * cause this funtion to fail.
 *
 * For unmanaged modules there is no guarantee to the state of the
 * modules. Other callers may be using the modules. Using unmanaged
 * modules haphazardly is not recommended for this reason. Some
 * modules (such as those configured with RPC) cannot be loaded in
 * unmanaged mode, and will be skipped.
 *
 * Use p11_kit_modules_release() to release the modules returned by
 * this function.
 *
 * If this function fails, then an error message will be available via the
 * p11_kit_message() function.
 *
 * Returns: a null terminated list of modules represented as PKCS\#11
 *     function lists, or %NULL on failure
 */
CK_FUNCTION_LIST **
p11_kit_modules_load (const char *reserved,
                      int flags)
{
	CK_FUNCTION_LIST **modules;
	CK_RV rv;

	/* progname attribute not implemented yet */
	return_val_if_fail (reserved == NULL, NULL);

	p11_library_init_once ();

	/* WARNING: This function must be reentrant */
	p11_debug ("in");

	p11_lock ();

		p11_message_clear ();

		/* WARNING: Reentrancy can occur here */
		rv = p11_modules_load_inlock_reentrant (flags, &modules);

	p11_unlock ();

	if (rv != CKR_OK)
		modules = NULL;

	p11_debug ("out: %s", modules ? "success" : "fail");
	return modules;
}

/**
 * p11_kit_modules_initialize:
 * @modules: a %NULL terminated list of modules
 * @failure_callback: called with modules that fail to initialize
 *
 * Initialize all the modules in the @modules list by calling their
 * <literal>C_Initialize</literal> function.
 *
 * For managed modules the <literal>C_Initialize</literal> function
 * is overridden so that multiple callers can initialize the same
 * modules. In addition for managed modules multiple callers can
 * initialize from different threads, and still guarantee consistent
 * thread-safe behavior.
 *
 * For unmanaged modules if multiple callers try to initialize
 * a module, then one of the calls will return
 * <literal>CKR_CRYPTOKI_ALREADY_INITIALIZED</literal> according to the
 * PKCS\#11 specification. In addition there are no guarantees that
 * thread-safe behavior will occur if multiple callers initialize from
 * different threads.
 *
 * When a module fails to initialize it is removed from the @modules list.
 * If the @failure_callback is not %NULL then it is called with the modules that
 * fail to initialize. For example, you may pass p11_kit_module_release()
 * as a @failure_callback if the @modules list was loaded wit p11_kit_modules_load().
 *
 * The return value will return the failure code of the last critical
 * module that failed to initialize. Non-critical module failures do not affect
 * the return value. If no critical modules failed to initialize then the
 * return value will be <literal>CKR_OK</literal>.
 *
 * When modules are removed, the list will be %NULL terminated at the
 * appropriate place so it can continue to be used as a modules list.
 *
 * This function does not accept a <code>CK_C_INITIALIZE_ARGS</code> argument.
 * Custom initialization arguments cannot be supported when multiple consumers
 * load the same module.
 *
 * Returns: <literal>CKR_OK</literal> or the failure code of the last critical
 * 	module that failed to initialize.
 */
CK_RV
p11_kit_modules_initialize (CK_FUNCTION_LIST **modules,
                            p11_kit_destroyer failure_callback)
{
	CK_RV ret = CKR_OK;
	CK_RV rv;
	bool critical;
	char *name;
	int i, out;

	return_val_if_fail (modules != NULL, CKR_ARGUMENTS_BAD);

	for (i = 0, out = 0; modules[i] != NULL; i++, out++) {
		rv = modules[i]->C_Initialize (NULL);
		if (rv != CKR_OK) {
			name = p11_kit_module_get_name (modules[i]);
			if (name == NULL)
				name = strdup ("(unknown)");
			return_val_if_fail (name != NULL, CKR_HOST_MEMORY);
			critical = (p11_kit_module_get_flags (modules[i]) & P11_KIT_MODULE_CRITICAL);
			p11_message ("%s: module failed to initialize%s: %s",
			             name, critical ? "" : ", skipping", p11_kit_strerror (rv));
			if (critical)
				ret = rv;
			if (failure_callback)
				failure_callback (modules[i]);
			out--;
			free (name);
		} else {
			modules[out] = modules[i];
		}
	}

	/* NULL terminate after above changes */
	modules[out] = NULL;
	return ret;
}

/**
 * p11_kit_modules_load_and_initialize:
 * @flags: flags to use to load the modules
 *
 * Load and initialize configured modules.
 *
 * If a critical module fails to load or initialize then the function will
 * return <literal>NULL</literal>. Non-critical modules will be skipped
 * and not included in the returned module list.
 *
 * Use p11_kit_modules_finalize_and_release() when you're done with the
 * modules returned by this function.
 *
 * Returns: a <literal>NULL</literal> terminated list of modules, or
 * 	<literal>NULL</literal> on failure
 */
CK_FUNCTION_LIST **
p11_kit_modules_load_and_initialize (int flags)
{
	CK_FUNCTION_LIST **modules;
	CK_RV rv;

	modules = p11_kit_modules_load (NULL, flags);
	if (modules == NULL)
		return NULL;

	rv = p11_kit_modules_initialize (modules, (p11_destroyer)p11_kit_module_release);
	if (rv != CKR_OK) {
		p11_kit_modules_release (modules);
		modules = NULL;
	}

	return modules;
}

/**
 * p11_kit_modules_finalize:
 * @modules: a <literal>NULL</literal> terminated list of modules
 *
 * Finalize each module in the @modules list by calling its
 * <literal>C_Finalize</literal> function. Regardless of failures, all
 * @modules will have their <literal>C_Finalize</literal> function called.
 *
 * If a module returns a failure from its <literal>C_Finalize</literal>
 * method it will be returned. If multiple modules fail, the last failure
 * will be returned.
 *
 * For managed modules the <literal>C_Finalize</literal> function
 * is overridden so that multiple callers can finalize the same
 * modules. In addition for managed modules multiple callers can
 * finalize from different threads, and still guarantee consistent
 * thread-safe behavior.
 *
 * For unmanaged modules if multiple callers try to finalize
 * a module, then one of the calls will return
 * <literal>CKR_CRYPTOKI_NOT_INITIALIZED</literal> according to the
 * PKCS\#11 specification. In addition there are no guarantees that
 * thread-safe behavior will occur if multiple callers finalize from
 * different threads.
 *
 * Returns: <literal>CKR_OK</literal> or the failure code of the last
 * 	module that failed to finalize
 */
CK_RV
p11_kit_modules_finalize (CK_FUNCTION_LIST **modules)
{
	CK_RV ret = CKR_OK;
	CK_RV rv;
	char *name;
	int i;

	return_val_if_fail (modules != NULL, CKR_ARGUMENTS_BAD);

	for (i = 0; modules[i] != NULL; i++) {
		rv = modules[i]->C_Finalize (NULL);
		if (rv != CKR_OK) {
			name = p11_kit_module_get_name (modules[i]);
			p11_message ("%s: module failed to finalize: %s",
			             name ? name : "(unknown)", p11_kit_strerror (rv));
			free (name);
			ret = rv;
		}
	}

	return ret;
}

/**
 * p11_kit_modules_release:
 * @modules: the modules to release
 *
 * Release the a set of loaded PKCS\#11 modules.
 *
 * The modules may be either managed or unmanaged. The array containing
 * the module pointers is also freed by this function.
 *
 * Managed modules will not be actually released until all
 * callers using them have done so. If the modules were initialized, they
 * should have been finalized first.
 */
void
p11_kit_modules_release (CK_FUNCTION_LIST **modules)
{
	p11_library_init_once ();

	return_if_fail (modules != NULL);

	/* WARNING: This function must be reentrant */
	p11_debug ("in");

	p11_lock ();

		p11_message_clear ();
		p11_modules_release_inlock_reentrant (modules);

	p11_unlock ();

	p11_debug ("out");
}

/**
 * p11_kit_modules_finalize_and_release:
 * @modules: the modules to release
 *
 * Finalize and then release the a set of loaded PKCS\#11 modules.
 *
 * The modules may be either managed or unmanaged. The array containing
 * the module pointers is also freed by this function.
 *
 * Modules are released even if their finalization returns an error code.
 * Managed modules will not be actually finalized or released until all
 * callers using them have done so.
 *
 * For managed modules the <literal>C_Finalize</literal> function
 * is overridden so that multiple callers can finalize the same
 * modules. In addition for managed modules multiple callers can
 * finalize from different threads, and still guarantee consistent
 * thread-safe behavior.
 *
 * For unmanaged modules if multiple callers try to finalize
 * a module, then one of the calls will return
 * <literal>CKR_CRYPTOKI_NOT_INITIALIZED</literal> according to the
 * PKCS\#11 specification. In addition there are no guarantees that
 * thread-safe behavior will occur if multiple callers initialize from
 * different threads.
 */
void
p11_kit_modules_finalize_and_release (CK_FUNCTION_LIST **modules)
{
	return_if_fail (modules != NULL);
	p11_kit_modules_finalize (modules);
	p11_kit_modules_release (modules);
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
 * Deprecated: Since 0.19.0: Use p11_kit_module_initialize() instead.
 *
 * Returns: CKR_OK if the initialization was successful.
 */
CK_RV
p11_kit_initialize_module (CK_FUNCTION_LIST_PTR module)
{
	CK_FUNCTION_LIST_PTR result;
	Module *mod;
	int flags;
	CK_RV rv;

	return_val_if_fail (module != NULL, CKR_ARGUMENTS_BAD);

	p11_library_init_once ();

	/* WARNING: This function must be reentrant for the same arguments */
	p11_debug ("in");

	p11_lock ();

		p11_message_clear ();

		flags = P11_KIT_MODULE_CRITICAL | P11_KIT_MODULE_UNMANAGED;
		rv = p11_module_load_inlock_reentrant (module, flags, &result);

		/* An unmanaged module should return the same pointer */
		assert (rv != CKR_OK || result == module);

		if (rv == CKR_OK) {
			mod = p11_dict_get (gl.unmanaged_by_funcs, module);
			assert (mod != NULL);
			rv = initialize_module_inlock_reentrant (mod);
			if (rv != CKR_OK) {
				p11_message ("module initialization failed: %s", p11_kit_strerror (rv));
				p11_module_release_inlock_reentrant (module);
			}
		}

	p11_unlock ();

	p11_debug ("out: %lu", rv);
	return rv;
}

CK_RV
p11_module_load_inlock_reentrant (CK_FUNCTION_LIST *module,
                                  int flags,
                                  CK_FUNCTION_LIST **result)
{
	Module *allocated = NULL;
	Module *mod;
	CK_RV rv = CKR_OK;

	rv = init_globals_unlocked ();
	if (rv == CKR_OK) {

		mod = p11_dict_get (gl.unmanaged_by_funcs, module);
		if (mod == NULL) {
			p11_debug ("allocating new module");
			allocated = mod = alloc_module_unlocked ();
			return_val_if_fail (mod != NULL, CKR_HOST_MEMORY);
			p11_virtual_init (&mod->virt, &p11_virtual_base, module, NULL);
		}

		/* If this was newly allocated, add it to the list */
		if (rv == CKR_OK && allocated) {
			if (!p11_dict_set (gl.modules, allocated, allocated) ||
			    !p11_dict_set (gl.unmanaged_by_funcs, module, allocated))
				return_val_if_reached (CKR_HOST_MEMORY);
			allocated = NULL;
		}

		if (rv == CKR_OK) {
			/* WARNING: Reentrancy can occur here */
			rv = prepare_module_inlock_reentrant (mod, flags, result);
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
	return rv;
}

/**
 * p11_kit_module_load:
 * @module_path: full file path of module library
 * @flags: flags to use when loading the module
 *
 * Load an arbitrary PKCS\#11 module from a dynamic library file, and
 * initialize it. Normally using the p11_kit_modules_load() function
 * is preferred.
 *
 * Using this function to load modules allows coordination between multiple
 * callers of the same module in a single process. If @flags contains the
 * %P11_KIT_MODULE_UNMANAGED flag, then the modules will be not be loaded
 * in 'managed' mode and not be coordinated. This is not recommended
 * for general usage.
 *
 * Subsequent calls to this function for the same module will result in an
 * initialization count being incremented for the module. It is safe (although
 * usually unnecessary) to use this function on registered modules.
 *
 * The module should be released with p11_kit_module_release().
 *
 * If this function fails, then an error message will be available via the
 * p11_kit_message() function.
 *
 * Returns: the loaded module PKCS\#11 functions or %NULL on failure
 */
CK_FUNCTION_LIST *
p11_kit_module_load (const char *module_path,
                     int flags)
{
	CK_FUNCTION_LIST *module = NULL;
	CK_RV rv;
	Module *mod;

	return_val_if_fail (module_path != NULL, NULL);

	p11_library_init_once ();

	/* WARNING: This function must be reentrant for the same arguments */
	p11_debug ("in: %s", module_path);

	p11_lock ();

		p11_message_clear ();

		rv = init_globals_unlocked ();
		if (rv == CKR_OK) {

			rv = load_module_from_file_inlock (NULL, module_path, &mod);
			if (rv == CKR_OK) {
				/* WARNING: Reentrancy can occur here */
				rv = prepare_module_inlock_reentrant (mod, flags, &module);
				if (rv != CKR_OK)
					module = NULL;
			}
		}

		/*
		 * If initialization failed, we may need to cleanup.
		 * If we added this module above, then this will
		 * clean things up as expected.
		 */
		if (rv != CKR_OK)
			free_modules_when_no_refs_unlocked ();

	p11_unlock ();

	p11_debug ("out: %s", module ? "success" : "fail");
	return module;

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
 * multiple users of the same module in a single process. The caller should not
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
 * Deprecated: Since 0.19.0: Use p11_kit_module_finalize() and
 * 	p11_kit_module_release() instead.
 *
 * Returns: CKR_OK if the finalization was successful.
 */
CK_RV
p11_kit_finalize_module (CK_FUNCTION_LIST *module)
{
	Module *mod;
	CK_RV rv = CKR_OK;

	return_val_if_fail (module != NULL, CKR_ARGUMENTS_BAD);

	p11_library_init_once ();

	/* WARNING: This function must be reentrant for the same arguments */
	p11_debug ("in");

	p11_lock ();

		p11_message_clear ();

		mod = gl.unmanaged_by_funcs ? p11_dict_get (gl.unmanaged_by_funcs, module) : NULL;
		if (mod == NULL) {
			p11_debug ("module not found");
			rv = CKR_ARGUMENTS_BAD;
		} else {
			/* WARNING: Rentrancy can occur here */
			rv = finalize_module_inlock_reentrant (mod);
		}

		_p11_kit_default_message (rv);

	p11_unlock ();

	p11_debug ("out: %lu", rv);
	return rv;
}

/**
 * p11_kit_module_initialize:
 * @module: the module to initialize
 *
 * Initialize a PKCS\#11 module by calling its <literal>C_Initialize</literal>
 * function.
 *
 * For managed modules the <literal>C_Initialize</literal> function
 * is overridden so that multiple callers can initialize the same
 * modules. In addition for managed modules multiple callers can
 * initialize from different threads, and still guarantee consistent
 * thread-safe behavior.
 *
 * For unmanaged modules if multiple callers try to initialize
 * a module, then one of the calls will return
 * <literal>CKR_CRYPTOKI_ALREADY_INITIALIZED</literal> according to the
 * PKCS\#11 specification. In addition there are no guarantees that
 * thread-safe behavior will occur if multiple callers initialize from
 * different threads.
 *
 * This function does not accept a <code>CK_C_INITIALIZE_ARGS</code> argument.
 * Custom initialization arguments cannot be supported when multiple consumers
 * load the same module.
 *
 * Returns: <literal>CKR_OK</literal> or a failure code
 */
CK_RV
p11_kit_module_initialize (CK_FUNCTION_LIST *module)
{
	char *name;
	CK_RV rv;

	return_val_if_fail (module != NULL, CKR_ARGUMENTS_BAD);

	rv = module->C_Initialize (NULL);
	if (rv != CKR_OK) {
		name = p11_kit_module_get_name (module);
		p11_message ("%s: module failed to initialize: %s",
		             name ? name : "(unknown)", p11_kit_strerror (rv));
		free (name);
	}

	return rv;
}

/**
 * p11_kit_module_finalize:
 * @module: the module to finalize
 *
 * Finalize a PKCS\#11 module by calling its <literal>C_Finalize</literal>
 * function.
 *
 * For managed modules the <literal>C_Finalize</literal> function
 * is overridden so that multiple callers can finalize the same
 * modules. In addition for managed modules multiple callers can
 * finalize from different threads, and still guarantee consistent
 * thread-safe behavior.
 *
 * For unmanaged modules if multiple callers try to finalize
 * a module, then one of the calls will return
 * <literal>CKR_CRYPTOKI_NOT_INITIALIZED</literal> according to the
 * PKCS\#11 specification. In addition there are no guarantees that
 * thread-safe behavior will occur if multiple callers finalize from
 * different threads.
 *
 * Returns: <literal>CKR_OK</literal> or a failure code
 */
CK_RV
p11_kit_module_finalize (CK_FUNCTION_LIST *module)
{
	char *name;
	CK_RV rv;

	return_val_if_fail (module != NULL, CKR_ARGUMENTS_BAD);

	rv = module->C_Finalize (NULL);
	if (rv != CKR_OK) {
		name = p11_kit_module_get_name (module);
		p11_message ("%s: module failed to finalize: %s",
		             name ? name : "(unknown)", p11_kit_strerror (rv));
		free (name);
	}

	return rv;

}


/**
 * p11_kit_module_release:
 * @module: the module to release
 *
 * Release the a loaded PKCS\#11 modules.
 *
 * The module may be either managed or unmanaged. The <literal>C_Finalize</literal>
 * function will be called if no other callers are using this module.
 */
void
p11_kit_module_release (CK_FUNCTION_LIST *module)
{
	return_if_fail (module != NULL);

	p11_library_init_once ();

	/* WARNING: This function must be reentrant for the same arguments */
	p11_debug ("in");

	p11_lock ();

		p11_message_clear ();

		release_module_inlock_rentrant (module, __PRETTY_FUNCTION__);

	p11_unlock ();

	p11_debug ("out");
}

CK_RV
p11_module_release_inlock_reentrant (CK_FUNCTION_LIST *module)
{
	return release_module_inlock_rentrant (module, __PRETTY_FUNCTION__);
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
 * Deprecated: Since 0.19.0: Use p11_kit_module_load() instead.
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

			rv = load_module_from_file_inlock (NULL, module_path, &mod);
			if (rv == CKR_OK) {

				/* WARNING: Reentrancy can occur here */
				rv = initialize_module_inlock_reentrant (mod);
			}
		}

		if (rv == CKR_OK && module) {
			*module = unmanaged_for_module_inlock (mod);
			assert (*module != NULL);
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
