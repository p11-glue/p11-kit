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

#include "hash.h"
#include "pkcs11.h"
#include "p11-kit.h"

#include <sys/types.h>
#include <assert.h>
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <pthread.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/* Start wrap slots slightly higher for testing */
#define MAPPING_OFFSET 0x10
#define FIRST_HANDLE   0x10

typedef struct _Mapping {
	CK_SLOT_ID wrap_slot;
	CK_SLOT_ID real_slot;
	CK_FUNCTION_LIST_PTR funcs;
} Mapping;

typedef struct _Session {
	CK_SESSION_HANDLE wrap_session;
	CK_SESSION_HANDLE real_session;
	CK_SLOT_ID wrap_slot;
} Session;

typedef struct _Module {
	char *name;
	char *path;
	void *dl_module;
	CK_FUNCTION_LIST_PTR funcs;
	int ref_count;
	int initialize_count;
	struct _Module *next;
} Module;

/* Forward declaration */
static CK_FUNCTION_LIST proxy_function_list;

/*
 * This is the mutex that protects the global data of this library
 * and the pkcs11 proxy module. Note that we *never* call into our
 * underlying pkcs11 modules while holding this mutex. Therefore it
 * doesn't have to be recursive and we can keep things simple.
 */
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

/*
 * Shared data between threads, protected by the mutex, a structure so
 * we can audit thread safety easier.
 */
static struct _Shared {
	Mapping *mappings;
	unsigned int n_mappings;
	hsh_t *sessions;
	Module *modules;
	CK_ULONG last_handle;
	int registered_loaded;
} gl = { NULL, 0, NULL, NULL, FIRST_HANDLE, 0 };

#define MANUFACTURER_ID         "PKCS#11 Kit                     "
#define LIBRARY_DESCRIPTION     "PKCS#11 Kit Proxy Module        "
#define LIBRARY_VERSION_MAJOR   1
#define LIBRARY_VERSION_MINOR   1

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
ends_with (const char *haystack, const char *needle)
{
	size_t haystack_len, needle_len;

	assert (haystack);
	assert (needle);

	haystack_len = strlen (haystack);
	needle_len = strlen (needle);

	if (needle_len > haystack_len)
		return 0;
	return memcmp (haystack + (haystack_len - needle_len),
	               needle, needle_len) == 0;
}

static void*
xrealloc (void * memory, size_t length)
{
	void *allocated = realloc (memory, length);
	if (!allocated)
		free (memory);
	return allocated;
}

/* -----------------------------------------------------------------------------
 * P11-KIT FUNCTIONALITY
 */

static CK_RV
load_module_unlocked (const char *name, Module *module)
{
	CK_C_GetFunctionList gfl;
	CK_RV rv;

	/*
	 * TODO: This function will change significantly once we're loading
	 * from a config, see below.
	 */
	assert (name);
	assert (module);

	module->name = strdup (name);
	if (!module->name)
		return CKR_HOST_MEMORY;

	module->path = strconcat (PKCS11_MODULE_PATH, "/", name, NULL);
	if (!module->path)
		return CKR_HOST_MEMORY;

	module->dl_module = dlopen (module->path, RTLD_LOCAL | RTLD_NOW);
	if (module->dl_module == NULL) {
		warning ("couldn't load module: %s: %s",
		         module->path, dlerror ());
		return CKR_GENERAL_ERROR;
	}

	gfl = dlsym (module->dl_module, "C_GetFunctionList");
	if (!gfl) {
		warning ("couldn't find C_GetFunctionList entry point in module: %s: %s",
		         module->path, dlerror ());
		return CKR_GENERAL_ERROR;
	}

	rv = gfl (&module->funcs);
	if (rv != CKR_OK) {
		warning ("call to C_GetFunctiontList failed in module: %s: %lu",
		         module->path, (unsigned long)rv);
		return rv;
	}

	return CKR_OK;
}

static void
unload_module_unlocked (Module *module)
{
	assert (module);

	/* Should have been finalized before this */
	assert (!module->initialize_count);

	if (module->dl_module) {
		dlclose (module->dl_module);
		module->dl_module = NULL;
	}

	free (module->path);
	module->path = NULL;

	free (module->name);
	module->name = NULL;

	module->funcs = NULL;
}

static CK_RV
load_registered_modules_unlocked (void)
{
	struct dirent *dp;
	Module *module;
	DIR *dir;
	CK_RV rv;

	/* First we load all the modules */
	dir = opendir (PKCS11_MODULE_PATH);

	/* We're within a global mutex, so readdir is safe */
	while ((dp = readdir(dir)) != NULL) {
		if ((dp->d_type == DT_LNK || dp->d_type == DT_REG) &&
		    !ends_with (dp->d_name, ".la")) {

			module = calloc (sizeof (Module), 1);
			if (!module)
				rv = CKR_HOST_MEMORY;
			else
				rv = load_module_unlocked (dp->d_name, module);

			/* Cleanup for failures happens at caller */
			module->next = gl.modules;
			gl.modules = module;

			if (rv != CKR_OK)
				break;
		}
	}

	closedir (dir);

	return rv;
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

		pthread_mutex_unlock (&mutex);

			assert (module->funcs);
			rv = module->funcs->C_Initialize (args);

		pthread_mutex_lock (&mutex);

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

static CK_RV
finalize_module_unlocked_reentrant (Module *module, CK_VOID_PTR args)
{
	Module *mod, *next;

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

		pthread_mutex_unlock (&mutex);

			assert (module->funcs);
			module->funcs->C_Finalize (args);

		pthread_mutex_lock (&mutex);

		if (module->initialize_count > 0)
			--module->initialize_count;
	}

	/* Match the increment above */
	--module->ref_count;

	/* Check if any modules have a ref count */
	for (mod = gl.modules; mod; mod = mod->next) {
		if (mod->ref_count)
			break;
	}

	/* No modules had a refcount? unload and free all info */
	if (mod == NULL) {
		for (mod = gl.modules; mod; mod = next) {
			next = mod->next;
			unload_module_unlocked (mod);
			free (mod);
		}
		gl.modules = NULL;
		gl.registered_loaded = 0;
	}

	return CKR_OK;
}

static Module*
find_module_for_funcs_unlocked (CK_FUNCTION_LIST_PTR funcs)
{
	Module *module;

	assert (funcs);

	for (module = gl.modules; module; module = module->next)
		if (module->ref_count && module->funcs == funcs)
			return module;
	return NULL;
}

static Module*
find_module_for_name_unlocked (const char *name)
{
	Module *module;

	assert (name);

	for (module = gl.modules; module; module = module->next)
		if (module->ref_count && module->name && strcmp (name, module->name))
			return module;
	return NULL;
}

static CK_RV
initialize_registered_unlocked_reentrant (CK_C_INITIALIZE_ARGS_PTR args)
{
	Module *module;
	CK_RV rv;

	rv = load_registered_modules_unlocked ();
	if (rv == CKR_OK) {
		for (module = gl.modules; module; module = module->next) {

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

	pthread_mutex_lock (&mutex);

		/* WARNING: Reentrancy can occur here */
		rv = initialize_registered_unlocked_reentrant (&args);

	pthread_mutex_unlock (&mutex);

	/* Cleanup any partial initialization */
	if (rv != CKR_OK)
		p11_kit_finalize_registered ();

	return rv;
}

static CK_RV
finalize_registered_unlocked_reentrant (CK_VOID_PTR args)
{
	Module *module;

	/* WARNING: This function must be reentrant */

	for (module = gl.modules; module; module = module->next) {

		/* Skip all modules that aren't registered */
		if (!module->name)
			continue;

		/* WARNING: Reentrant calls can occur here */
		finalize_module_unlocked_reentrant (module, args);
	}

	return CKR_OK;
}
CK_RV
p11_kit_finalize_registered (void)
{
	CK_RV rv;

	/* WARNING: This function must be reentrant */

	pthread_mutex_lock (&mutex);

		/* WARNING: Reentrant calls can occur here */
		rv = finalize_registered_unlocked_reentrant (NULL);

	pthread_mutex_unlock (&mutex);

	return rv;
}

char**
p11_kit_registered_names (void)
{
	Module *module;
	char **result;
	int count, i;

	pthread_mutex_lock (&mutex);

		for (module = gl.modules, count = 0;
		     module; module = module->next)
			++count;
		result = calloc (count + 1, sizeof (char*));
		if (result) {
			for (module = gl.modules, i = 0;
			     module; module = module->next, ++i)
				result[i] = strdup (module->name);
		}

	pthread_mutex_unlock (&mutex);

	return result;
}

CK_FUNCTION_LIST_PTR
p11_kit_registered_module (const char *module_name)
{
	CK_FUNCTION_LIST_PTR result;
	Module *module;

	if (!module_name)
		return NULL;

	pthread_mutex_lock (&mutex);

		module = find_module_for_name_unlocked (module_name);
		if (module) {
			assert (module);
			result = module->funcs;
		}

	pthread_mutex_unlock (&mutex);

	return result;
}

void
p11_kit_free_names (char **module_names)
{
	char **name;
	for (name = module_names; *name; ++name)
		free (name);
}

char*
p11_kit_registered_option (const char *module_name, const char *field)
{
	/* TODO: Need to implement */
	assert (0);
	return NULL;
}

CK_RV
p11_kit_initialize_module (CK_FUNCTION_LIST_PTR funcs, CK_C_INITIALIZE_ARGS_PTR init_args)
{
	Module *module;
	Module *allocated = NULL;
	CK_RV rv = CKR_OK;

	/* WARNING: This function must be reentrant for the same arguments */

	pthread_mutex_lock (&mutex);

		module = find_module_for_funcs_unlocked (funcs);
		if (module == NULL) {
			allocated = module = calloc (1, sizeof (Module));
			module->name = NULL;
			module->dl_module = NULL;
			module->path = NULL;
			module->funcs = funcs;
		}

		/* WARNING: Reentrancy can occur here */
		rv = initialize_module_unlocked_reentrant (module, init_args);

		/* If this was newly allocated, add it to the list */
		if (rv == CKR_OK && allocated) {
			allocated->next = gl.modules;
			gl.modules = allocated;
			allocated = NULL;
		}

		free (allocated);

	pthread_mutex_unlock (&mutex);

	return rv;
}

CK_RV
p11_kit_finalize_module (CK_FUNCTION_LIST_PTR funcs, CK_VOID_PTR reserved)
{
	Module *module;
	CK_RV rv = CKR_OK;

	/* WARNING: This function must be reentrant for the same arguments */

	pthread_mutex_lock (&mutex);

		module = find_module_for_funcs_unlocked (funcs);
		if (module == NULL) {
			rv = CKR_ARGUMENTS_BAD;
		} else {
			/* WARNING: Rentrancy can occur here */
			rv = finalize_module_unlocked_reentrant (module, reserved);
		}

	pthread_mutex_unlock (&mutex);

	return rv;
}

/* -----------------------------------------------------------------------------
 * PKCS#11 PROXY MODULE
 */

static CK_RV
map_slot_unlocked (CK_SLOT_ID slot, Mapping *mapping)
{
	assert (mapping);

	if (slot < MAPPING_OFFSET)
		return CKR_SLOT_ID_INVALID;
	slot -= MAPPING_OFFSET;

	if (slot > gl.n_mappings) {
		return CKR_SLOT_ID_INVALID;
	} else {
		assert (gl.mappings);
		memcpy (mapping, &gl.mappings[slot], sizeof (Mapping));
		return CKR_OK;
	}
}

static CK_RV
map_slot_to_real (CK_SLOT_ID_PTR slot, Mapping *mapping)
{
	CK_RV rv;

	assert (mapping);

	pthread_mutex_lock (&mutex);

		if (!gl.mappings)
			rv = CKR_CRYPTOKI_NOT_INITIALIZED;
		else
			rv = map_slot_unlocked (*slot, mapping);
		if (rv == CKR_OK)
			*slot = mapping->real_slot;

	pthread_mutex_unlock (&mutex);

	return rv;
}

static CK_RV
map_session_to_real (CK_SESSION_HANDLE_PTR handle, Mapping *mapping, Session *session)
{
	CK_RV rv = CKR_OK;
	Session *sess;

	assert (handle);
	assert (mapping);

	pthread_mutex_lock (&mutex);

		if (!gl.sessions) {
			rv = CKR_CRYPTOKI_NOT_INITIALIZED;
		} else {
			assert (gl.sessions);
			sess = hsh_get (gl.sessions, handle, sizeof (handle));
			if (sess != NULL) {
				*handle = sess->real_session;
				rv = map_slot_unlocked (sess->wrap_slot, mapping);
				if (session != NULL)
					memcpy (session, sess, sizeof (Session));
			} else {
				rv = CKR_SESSION_HANDLE_INVALID;
			}
		}

	pthread_mutex_unlock (&mutex);

	return rv;
}

static void
finalize_mappings_unlocked (void)
{
	hsh_index_t *iter;

	/* No more mappings */
	free (gl.mappings);
	gl.mappings = NULL;
	gl.n_mappings = 0;

	/* no more sessions */
	if (gl.sessions) {
		for (iter = hsh_first (gl.sessions); iter; iter = hsh_next (iter))
			free (hsh_this (iter, NULL, NULL));
		hsh_free (gl.sessions);
		gl.sessions = NULL;
	}
}

static CK_RV
proxy_C_Finalize (CK_VOID_PTR reserved)
{
	CK_RV rv;

	/* WARNING: This function must be reentrant */

	if (reserved)
		return CKR_ARGUMENTS_BAD;

	pthread_mutex_lock (&mutex);

		/* WARNING: Reentrancy can occur here */
		rv = finalize_registered_unlocked_reentrant (reserved);

		/*
		 * If modules are all gone, then this was the last
		 * finalize, so cleanup our mappings
		 */
		if (gl.modules == NULL)
			finalize_mappings_unlocked ();

	pthread_mutex_unlock (&mutex);

	return rv;
}

static CK_RV
initialize_mappings_unlocked_reentrant (void)
{
	CK_FUNCTION_LIST_PTR funcs;
	Mapping *mappings = NULL;
	int n_mappings = 0;
	CK_SLOT_ID_PTR slots;
	CK_ULONG i, count;
	Module *module;
	CK_RV rv;

	assert (!gl.mappings);

	for (module = gl.modules; module; module = module->next) {

		/* Only do registered modules */
		if (module->ref_count && !module->name)
			continue;

		funcs = module->funcs;
		assert (funcs);
		slots = NULL;

		pthread_mutex_unlock (&mutex);

			/* Ask module for its slots */
			rv = (funcs->C_GetSlotList) (FALSE, NULL, &count);
			if (rv == CKR_OK && count) {
				slots = calloc (sizeof (CK_SLOT_ID), count);
				if (!slots)
					rv = CKR_HOST_MEMORY;
				else
					rv = (funcs->C_GetSlotList) (FALSE, slots, &count);
			}

		pthread_mutex_lock (&mutex);

		if (rv != CKR_OK) {
			free (slots);
			break;
		}

		mappings = xrealloc (mappings, sizeof (Mapping) * (n_mappings + count));
		if (!mappings) {
			free (slots);
			rv = CKR_HOST_MEMORY;
			break;
		}

		/* And now add a mapping for each of those slots */
		for (i = 0; i < count; ++i) {
			mappings[n_mappings].funcs = funcs;
			mappings[n_mappings].wrap_slot = n_mappings + MAPPING_OFFSET;
			mappings[n_mappings].real_slot = slots[i];
			++n_mappings;
		}

		free (slots);
	}

	/* Another thread raced us here due to above reentrancy */
	if (gl.mappings) {
		free (mappings);
		return CKR_OK;
	}

	assert (!gl.sessions);
	gl.sessions = hsh_create ();

	/* Any cleanup necessary for failure will happen at caller */
	return rv;
}

static CK_RV
proxy_C_Initialize (CK_VOID_PTR init_args)
{
	CK_RV rv;

	/* WARNING: This function must be reentrant */

	pthread_mutex_lock (&mutex);

		/* WARNING: Reentrancy can occur here */
		rv = initialize_registered_unlocked_reentrant (init_args);

		/* WARNING: Reentrancy can occur here */
		if (rv == CKR_OK && !gl.mappings)
			rv = initialize_mappings_unlocked_reentrant ();

	pthread_mutex_unlock (&mutex);

	if (rv != CKR_OK)
		proxy_C_Finalize (NULL);

	return rv;
}

static CK_RV
proxy_C_GetInfo (CK_INFO_PTR info)
{
	CK_RV rv = CKR_OK;

	if (info == NULL)
		return CKR_ARGUMENTS_BAD;

	pthread_mutex_lock (&mutex);

		if (!gl.mappings)
			rv = CKR_CRYPTOKI_NOT_INITIALIZED;

	pthread_mutex_unlock (&mutex);

	if (rv != CKR_OK)
		return rv;

	info->cryptokiVersion.major = CRYPTOKI_VERSION_MAJOR;
	info->cryptokiVersion.minor = CRYPTOKI_VERSION_MINOR;
	info->libraryVersion.major = LIBRARY_VERSION_MAJOR;
	info->libraryVersion.minor = LIBRARY_VERSION_MINOR;
	info->flags = 0;
	strncpy ((char*)info->manufacturerID, MANUFACTURER_ID, 32);
	strncpy ((char*)info->libraryDescription, LIBRARY_DESCRIPTION, 32);
	return CKR_OK;
}

static CK_RV
proxy_C_GetFunctionList (CK_FUNCTION_LIST_PTR_PTR list)
{
	/* Can be called before C_Initialize */

	if (!list)
		return CKR_ARGUMENTS_BAD;
	*list = &proxy_function_list;
	return CKR_OK;
}

static CK_RV
proxy_C_GetSlotList (CK_BBOOL token_present, CK_SLOT_ID_PTR slot_list,
                       CK_ULONG_PTR count)
{
	CK_SLOT_INFO info;
	Mapping *mapping;
	CK_ULONG index;
	CK_RV rv = CKR_OK;
	int i;

	if (!count)
		return CKR_ARGUMENTS_BAD;

	pthread_mutex_lock (&mutex);

		if (!gl.mappings) {
			rv = CKR_CRYPTOKI_NOT_INITIALIZED;
		} else {
			index = 0;

			/* Go through and build up a map */
			for (i = 0; i < gl.n_mappings; ++i) {
				mapping = &gl.mappings[i];

				/* Skip ones without a token if requested */
				if (token_present) {
					rv = (mapping->funcs->C_GetSlotInfo) (mapping->real_slot, &info);
					if (rv != CKR_OK)
						break;
					if (!(info.flags & CKF_TOKEN_PRESENT))
						continue;
				}

				/* Fill in the slot if we can */
				if (slot_list && *count > index)
					slot_list[index] = mapping->wrap_slot;

				++index;
			}

			if (slot_list && *count < index)
				rv = CKR_BUFFER_TOO_SMALL;

			*count = index;
		}

	pthread_mutex_unlock (&mutex);

	return rv;
}

static CK_RV
proxy_C_GetSlotInfo (CK_SLOT_ID id, CK_SLOT_INFO_PTR info)
{
	Mapping map;
	CK_RV rv;

	rv = map_slot_to_real (&id, &map);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_GetSlotInfo) (id, info);
}

static CK_RV
proxy_C_GetTokenInfo (CK_SLOT_ID id, CK_TOKEN_INFO_PTR info)
{
	Mapping map;
	CK_RV rv;

	rv = map_slot_to_real (&id, &map);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_GetTokenInfo) (id, info);
}

static CK_RV
proxy_C_GetMechanismList (CK_SLOT_ID id, CK_MECHANISM_TYPE_PTR mechanism_list,
                          CK_ULONG_PTR count)
{
	Mapping map;
	CK_RV rv;

	rv = map_slot_to_real (&id, &map);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_GetMechanismList) (id, mechanism_list, count);
}

static CK_RV
proxy_C_GetMechanismInfo (CK_SLOT_ID id, CK_MECHANISM_TYPE type,
                          CK_MECHANISM_INFO_PTR info)
{
	Mapping map;
	CK_RV rv;

	rv = map_slot_to_real (&id, &map);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_GetMechanismInfo) (id, type, info);
}

static CK_RV
proxy_C_InitToken (CK_SLOT_ID id, CK_UTF8CHAR_PTR pin, CK_ULONG pin_len, CK_UTF8CHAR_PTR label)
{
	Mapping map;
	CK_RV rv;

	rv = map_slot_to_real (&id, &map);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_InitToken) (id, pin, pin_len, label);
}

static CK_RV
proxy_C_WaitForSlotEvent (CK_FLAGS flags, CK_SLOT_ID_PTR slot, CK_VOID_PTR reserved)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV
proxy_C_OpenSession (CK_SLOT_ID id, CK_FLAGS flags, CK_VOID_PTR user_data,
                     CK_NOTIFY callback, CK_SESSION_HANDLE_PTR handle)
{
	Session *sess;
	Mapping map;
	CK_RV rv;

	if (handle == NULL)
		return CKR_ARGUMENTS_BAD;

	rv = map_slot_to_real (&id, &map);
	if (rv != CKR_OK)
		return rv;

	rv = (map.funcs->C_OpenSession) (id, flags, user_data, callback, handle);

	if (rv == CKR_OK) {
		pthread_mutex_lock (&mutex);

			if (!gl.sessions) {
				/*
				 * The underlying module should have returned an error, so this
				 * code should never be reached with properly behaving modules.
				 * That's why we don't cleanup and close the newly opened session here
				 * or anything like that.
				 */
				rv = CKR_CRYPTOKI_NOT_INITIALIZED;

			} else {
				sess = calloc (1, sizeof (Session));
				sess->wrap_slot = map.wrap_slot;
				sess->real_session = *handle;
				sess->wrap_session = ++gl.last_handle; /* TODO: Handle wrapping, and then collisions */
				hsh_set (gl.sessions, &sess->wrap_session, sizeof (sess->wrap_session), sess);
				*handle = sess->wrap_session;
			}

		pthread_mutex_unlock (&mutex);
	}

	return rv;
}

static CK_RV
proxy_C_CloseSession (CK_SESSION_HANDLE handle)
{
	CK_SESSION_HANDLE key;
	Mapping map;
	CK_RV rv;

	key = handle;
	rv = map_session_to_real (&handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	rv = (map.funcs->C_CloseSession) (handle);

	if (rv == CKR_OK) {
		pthread_mutex_lock (&mutex);

			if (gl.sessions)
				hsh_rem (gl.sessions, &key, sizeof (key));

		pthread_mutex_unlock (&mutex);
	}

	return rv;
}

static CK_RV
proxy_C_CloseAllSessions (CK_SLOT_ID id)
{
	CK_SESSION_HANDLE_PTR to_close;
	CK_RV rv = CKR_OK;
	Session *sess;
	CK_ULONG i, count;
	hsh_index_t *iter;

	pthread_mutex_lock (&mutex);

		if (!gl.sessions) {
			rv = CKR_CRYPTOKI_NOT_INITIALIZED;
		} else {
			to_close = calloc (sizeof (CK_SESSION_HANDLE), hsh_count (gl.sessions));
			if (!to_close) {
				rv = CKR_HOST_MEMORY;
			} else {
				for (iter = hsh_first (gl.sessions), count = 0;
				     iter; iter = hsh_next (iter)) {
					sess = hsh_this (iter, NULL, NULL);
					if (sess->wrap_slot == id && to_close)
						to_close[count++] = sess->wrap_session;
				}
			}
		}

	pthread_mutex_unlock (&mutex);

	if (rv != CKR_OK)
		return rv;

	for (i = 0; i < count; ++i)
		proxy_C_CloseSession (to_close[i]);

	free (to_close);
	return CKR_OK;
}

static CK_RV
proxy_C_GetFunctionStatus (CK_SESSION_HANDLE handle)
{
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (&handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_GetFunctionStatus) (handle);
}

static CK_RV
proxy_C_CancelFunction (CK_SESSION_HANDLE handle)
{
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (&handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_CancelFunction) (handle);
}

static CK_RV
proxy_C_GetSessionInfo (CK_SESSION_HANDLE handle, CK_SESSION_INFO_PTR info)
{
	Mapping map;
	CK_RV rv;

	if (info == NULL)
		return CKR_ARGUMENTS_BAD;

	rv = map_session_to_real (&handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;

	rv = (map.funcs->C_GetSessionInfo) (handle, info);
	if (rv == CKR_OK)
		info->slotID = map.wrap_slot;

	return rv;
}

static CK_RV
proxy_C_InitPIN (CK_SESSION_HANDLE handle, CK_UTF8CHAR_PTR pin, CK_ULONG pin_len)
{
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (&handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;

	return (map.funcs->C_InitPIN) (handle, pin, pin_len);
}

static CK_RV
proxy_C_SetPIN (CK_SESSION_HANDLE handle, CK_UTF8CHAR_PTR old_pin, CK_ULONG old_pin_len,
                CK_UTF8CHAR_PTR new_pin, CK_ULONG new_pin_len)
{
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (&handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;

	return (map.funcs->C_SetPIN) (handle, old_pin, old_pin_len, new_pin, new_pin_len);
}

static CK_RV
proxy_C_GetOperationState (CK_SESSION_HANDLE handle, CK_BYTE_PTR operation_state, CK_ULONG_PTR operation_state_len)
{
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (&handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_GetOperationState) (handle, operation_state, operation_state_len);
}

static CK_RV
proxy_C_SetOperationState (CK_SESSION_HANDLE handle, CK_BYTE_PTR operation_state,
                           CK_ULONG operation_state_len, CK_OBJECT_HANDLE encryption_key,
                           CK_OBJECT_HANDLE authentication_key)
{
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (&handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_SetOperationState) (handle, operation_state, operation_state_len, encryption_key, authentication_key);
}

static CK_RV
proxy_C_Login (CK_SESSION_HANDLE handle, CK_USER_TYPE user_type,
               CK_UTF8CHAR_PTR pin, CK_ULONG pin_len)
{
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (&handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;

	return (map.funcs->C_Login) (handle, user_type, pin, pin_len);
}

static CK_RV
proxy_C_Logout (CK_SESSION_HANDLE handle)
{
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (&handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_Logout) (handle);
}

static CK_RV
proxy_C_CreateObject (CK_SESSION_HANDLE handle, CK_ATTRIBUTE_PTR template,
                      CK_ULONG count, CK_OBJECT_HANDLE_PTR new_object)
{
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (&handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;

	return (map.funcs->C_CreateObject) (handle, template, count, new_object);
}

static CK_RV
proxy_C_CopyObject (CK_SESSION_HANDLE handle, CK_OBJECT_HANDLE object,
                    CK_ATTRIBUTE_PTR template, CK_ULONG count,
                    CK_OBJECT_HANDLE_PTR new_object)
{
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (&handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_CopyObject) (handle, object, template, count, new_object);
}

static CK_RV
proxy_C_DestroyObject (CK_SESSION_HANDLE handle, CK_OBJECT_HANDLE object)
{
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (&handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_DestroyObject) (handle, object);
}

static CK_RV
proxy_C_GetObjectSize (CK_SESSION_HANDLE handle, CK_OBJECT_HANDLE object,
                       CK_ULONG_PTR size)
{
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (&handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_GetObjectSize) (handle, object, size);
}

static CK_RV
proxy_C_GetAttributeValue (CK_SESSION_HANDLE handle, CK_OBJECT_HANDLE object,
                           CK_ATTRIBUTE_PTR template, CK_ULONG count)
{
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (&handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_GetAttributeValue) (handle, object, template, count);
}

static CK_RV
proxy_C_SetAttributeValue (CK_SESSION_HANDLE handle, CK_OBJECT_HANDLE object,
                           CK_ATTRIBUTE_PTR template, CK_ULONG count)
{
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (&handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_SetAttributeValue) (handle, object, template, count);
}

static CK_RV
proxy_C_FindObjectsInit (CK_SESSION_HANDLE handle, CK_ATTRIBUTE_PTR template,
                         CK_ULONG count)
{
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (&handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_FindObjectsInit) (handle, template, count);
}

static CK_RV
proxy_C_FindObjects (CK_SESSION_HANDLE handle, CK_OBJECT_HANDLE_PTR objects,
                     CK_ULONG max_count, CK_ULONG_PTR count)
{
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (&handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_FindObjects) (handle, objects, max_count, count);
}

static CK_RV
proxy_C_FindObjectsFinal (CK_SESSION_HANDLE handle)
{
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (&handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_FindObjectsFinal) (handle);
}

static CK_RV
proxy_C_EncryptInit (CK_SESSION_HANDLE handle, CK_MECHANISM_PTR mechanism,
                     CK_OBJECT_HANDLE key)
{
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (&handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_EncryptInit) (handle, mechanism, key);
}

static CK_RV
proxy_C_Encrypt (CK_SESSION_HANDLE handle, CK_BYTE_PTR data, CK_ULONG data_len,
                 CK_BYTE_PTR encrypted_data, CK_ULONG_PTR encrypted_data_len)
{
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (&handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_Encrypt) (handle, data, data_len, encrypted_data, encrypted_data_len);
}

static CK_RV
proxy_C_EncryptUpdate (CK_SESSION_HANDLE handle, CK_BYTE_PTR part,
                       CK_ULONG part_len, CK_BYTE_PTR encrypted_part,
                       CK_ULONG_PTR encrypted_part_len)
{
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (&handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_EncryptUpdate) (handle, part, part_len, encrypted_part, encrypted_part_len);
}

static CK_RV
proxy_C_EncryptFinal (CK_SESSION_HANDLE handle, CK_BYTE_PTR last_part,
                      CK_ULONG_PTR last_part_len)
{
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (&handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_EncryptFinal) (handle, last_part, last_part_len);
}

static CK_RV
proxy_C_DecryptInit (CK_SESSION_HANDLE handle, CK_MECHANISM_PTR mechanism,
                     CK_OBJECT_HANDLE key)
{
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (&handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_DecryptInit) (handle, mechanism, key);
}

static CK_RV
proxy_C_Decrypt (CK_SESSION_HANDLE handle, CK_BYTE_PTR enc_data,
                 CK_ULONG enc_data_len, CK_BYTE_PTR data, CK_ULONG_PTR data_len)
{
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (&handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_Decrypt) (handle, enc_data, enc_data_len, data, data_len);
}

static CK_RV
proxy_C_DecryptUpdate (CK_SESSION_HANDLE handle, CK_BYTE_PTR enc_part,
                       CK_ULONG enc_part_len, CK_BYTE_PTR part, CK_ULONG_PTR part_len)
{
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (&handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_DecryptUpdate) (handle, enc_part, enc_part_len, part, part_len);
}

static CK_RV
proxy_C_DecryptFinal (CK_SESSION_HANDLE handle, CK_BYTE_PTR last_part,
                      CK_ULONG_PTR last_part_len)
{
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (&handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_DecryptFinal) (handle, last_part, last_part_len);
}

static CK_RV
proxy_C_DigestInit (CK_SESSION_HANDLE handle, CK_MECHANISM_PTR mechanism)
{
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (&handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_DigestInit) (handle, mechanism);
}

static CK_RV
proxy_C_Digest (CK_SESSION_HANDLE handle, CK_BYTE_PTR data, CK_ULONG data_len,
                CK_BYTE_PTR digest, CK_ULONG_PTR digest_len)
{
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (&handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_Digest) (handle, data, data_len, digest, digest_len);
}

static CK_RV
proxy_C_DigestUpdate (CK_SESSION_HANDLE handle, CK_BYTE_PTR part, CK_ULONG part_len)
{
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (&handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_DigestUpdate) (handle, part, part_len);
}

static CK_RV
proxy_C_DigestKey (CK_SESSION_HANDLE handle, CK_OBJECT_HANDLE key)
{
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (&handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_DigestKey) (handle, key);
}

static CK_RV
proxy_C_DigestFinal (CK_SESSION_HANDLE handle, CK_BYTE_PTR digest,
                     CK_ULONG_PTR digest_len)
{
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (&handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_DigestFinal) (handle, digest, digest_len);
}

static CK_RV
proxy_C_SignInit (CK_SESSION_HANDLE handle, CK_MECHANISM_PTR mechanism,
                  CK_OBJECT_HANDLE key)
{
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (&handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_SignInit) (handle, mechanism, key);
}

static CK_RV
proxy_C_Sign (CK_SESSION_HANDLE handle, CK_BYTE_PTR data, CK_ULONG data_len,
              CK_BYTE_PTR signature, CK_ULONG_PTR signature_len)
{
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (&handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_Sign) (handle, data, data_len, signature, signature_len);
}

static CK_RV
proxy_C_SignUpdate (CK_SESSION_HANDLE handle, CK_BYTE_PTR part, CK_ULONG part_len)
{
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (&handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_SignUpdate) (handle, part, part_len);
}

static CK_RV
proxy_C_SignFinal (CK_SESSION_HANDLE handle, CK_BYTE_PTR signature,
                   CK_ULONG_PTR signature_len)
{
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (&handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_SignFinal) (handle, signature, signature_len);
}

static CK_RV
proxy_C_SignRecoverInit (CK_SESSION_HANDLE handle, CK_MECHANISM_PTR mechanism,
                         CK_OBJECT_HANDLE key)
{
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (&handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_SignRecoverInit) (handle, mechanism, key);
}

static CK_RV
proxy_C_SignRecover (CK_SESSION_HANDLE handle, CK_BYTE_PTR data, CK_ULONG data_len,
                     CK_BYTE_PTR signature, CK_ULONG_PTR signature_len)
{
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (&handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_SignRecover) (handle, data, data_len, signature, signature_len);
}

static CK_RV
proxy_C_VerifyInit (CK_SESSION_HANDLE handle, CK_MECHANISM_PTR mechanism,
                    CK_OBJECT_HANDLE key)
{
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (&handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_VerifyInit) (handle, mechanism, key);
}

static CK_RV
proxy_C_Verify (CK_SESSION_HANDLE handle, CK_BYTE_PTR data, CK_ULONG data_len,
                CK_BYTE_PTR signature, CK_ULONG signature_len)
{
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (&handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_Verify) (handle, data, data_len, signature, signature_len);
}

static CK_RV
proxy_C_VerifyUpdate (CK_SESSION_HANDLE handle, CK_BYTE_PTR part, CK_ULONG part_len)
{
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (&handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_VerifyUpdate) (handle, part, part_len);
}

static CK_RV
proxy_C_VerifyFinal (CK_SESSION_HANDLE handle, CK_BYTE_PTR signature,
                     CK_ULONG signature_len)
{
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (&handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_VerifyFinal) (handle, signature, signature_len);
}

static CK_RV
proxy_C_VerifyRecoverInit (CK_SESSION_HANDLE handle, CK_MECHANISM_PTR mechanism,
                           CK_OBJECT_HANDLE key)
{
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (&handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_VerifyRecoverInit) (handle, mechanism, key);
}

static CK_RV
proxy_C_VerifyRecover (CK_SESSION_HANDLE handle, CK_BYTE_PTR signature,
                       CK_ULONG signature_len, CK_BYTE_PTR data, CK_ULONG_PTR data_len)
{
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (&handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_VerifyRecover) (handle, signature, signature_len, data, data_len);
}

static CK_RV
proxy_C_DigestEncryptUpdate (CK_SESSION_HANDLE handle, CK_BYTE_PTR part,
                             CK_ULONG part_len, CK_BYTE_PTR enc_part,
                             CK_ULONG_PTR enc_part_len)
{
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (&handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_DigestEncryptUpdate) (handle, part, part_len, enc_part, enc_part_len);
}

static CK_RV
proxy_C_DecryptDigestUpdate (CK_SESSION_HANDLE handle, CK_BYTE_PTR enc_part,
                             CK_ULONG enc_part_len, CK_BYTE_PTR part,
                             CK_ULONG_PTR part_len)
{
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (&handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_DecryptDigestUpdate) (handle, enc_part, enc_part_len, part, part_len);
}

static CK_RV
proxy_C_SignEncryptUpdate (CK_SESSION_HANDLE handle, CK_BYTE_PTR part,
                           CK_ULONG part_len, CK_BYTE_PTR enc_part,
                           CK_ULONG_PTR enc_part_len)
{
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (&handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_SignEncryptUpdate) (handle, part, part_len, enc_part, enc_part_len);
}

static CK_RV
proxy_C_DecryptVerifyUpdate (CK_SESSION_HANDLE handle, CK_BYTE_PTR enc_part,
                             CK_ULONG enc_part_len, CK_BYTE_PTR part,
                             CK_ULONG_PTR part_len)
{
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (&handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_DecryptVerifyUpdate) (handle, enc_part, enc_part_len, part, part_len);
}

static CK_RV
proxy_C_GenerateKey (CK_SESSION_HANDLE handle, CK_MECHANISM_PTR mechanism,
                     CK_ATTRIBUTE_PTR template, CK_ULONG count,
                     CK_OBJECT_HANDLE_PTR key)
{
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (&handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_GenerateKey) (handle, mechanism, template, count, key);
}

static CK_RV
proxy_C_GenerateKeyPair (CK_SESSION_HANDLE handle, CK_MECHANISM_PTR mechanism,
                         CK_ATTRIBUTE_PTR pub_template, CK_ULONG pub_count,
                         CK_ATTRIBUTE_PTR priv_template, CK_ULONG priv_count,
                         CK_OBJECT_HANDLE_PTR pub_key, CK_OBJECT_HANDLE_PTR priv_key)
{
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (&handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_GenerateKeyPair) (handle, mechanism, pub_template, pub_count, priv_template, priv_count, pub_key, priv_key);
}

static CK_RV
proxy_C_WrapKey (CK_SESSION_HANDLE handle, CK_MECHANISM_PTR mechanism,
                 CK_OBJECT_HANDLE wrapping_key, CK_OBJECT_HANDLE key,
                 CK_BYTE_PTR wrapped_key, CK_ULONG_PTR wrapped_key_len)
{
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (&handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_WrapKey) (handle, mechanism, wrapping_key, key, wrapped_key, wrapped_key_len);
}

static CK_RV
proxy_C_UnwrapKey (CK_SESSION_HANDLE handle, CK_MECHANISM_PTR mechanism,
                   CK_OBJECT_HANDLE unwrapping_key, CK_BYTE_PTR wrapped_key,
                   CK_ULONG wrapped_key_len, CK_ATTRIBUTE_PTR template,
                   CK_ULONG count, CK_OBJECT_HANDLE_PTR key)
{
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (&handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_UnwrapKey) (handle, mechanism, unwrapping_key, wrapped_key, wrapped_key_len, template, count, key);
}

static CK_RV
proxy_C_DeriveKey (CK_SESSION_HANDLE handle, CK_MECHANISM_PTR mechanism,
                   CK_OBJECT_HANDLE base_key, CK_ATTRIBUTE_PTR template,
                   CK_ULONG count, CK_OBJECT_HANDLE_PTR key)
{
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (&handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_DeriveKey) (handle, mechanism, base_key, template, count, key);
}

static CK_RV
proxy_C_SeedRandom (CK_SESSION_HANDLE handle, CK_BYTE_PTR seed, CK_ULONG seed_len)
{
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (&handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_SeedRandom) (handle, seed, seed_len);
}

static CK_RV
proxy_C_GenerateRandom (CK_SESSION_HANDLE handle, CK_BYTE_PTR random_data,
                          CK_ULONG random_len)
{
	Mapping map;
	CK_RV rv;

	rv = map_session_to_real (&handle, &map, NULL);
	if (rv != CKR_OK)
		return rv;
	return (map.funcs->C_GenerateRandom) (handle, random_data, random_len);
}

/* --------------------------------------------------------------------
 * MODULE ENTRY POINT
 */

static CK_FUNCTION_LIST proxy_function_list = {
	{ CRYPTOKI_VERSION_MAJOR, CRYPTOKI_VERSION_MINOR },  /* version */
	proxy_C_Initialize,
	proxy_C_Finalize,
	proxy_C_GetInfo,
	proxy_C_GetFunctionList,
	proxy_C_GetSlotList,
	proxy_C_GetSlotInfo,
	proxy_C_GetTokenInfo,
	proxy_C_GetMechanismList,
	proxy_C_GetMechanismInfo,
	proxy_C_InitToken,
	proxy_C_InitPIN,
	proxy_C_SetPIN,
	proxy_C_OpenSession,
	proxy_C_CloseSession,
	proxy_C_CloseAllSessions,
	proxy_C_GetSessionInfo,
	proxy_C_GetOperationState,
	proxy_C_SetOperationState,
	proxy_C_Login,
	proxy_C_Logout,
	proxy_C_CreateObject,
	proxy_C_CopyObject,
	proxy_C_DestroyObject,
	proxy_C_GetObjectSize,
	proxy_C_GetAttributeValue,
	proxy_C_SetAttributeValue,
	proxy_C_FindObjectsInit,
	proxy_C_FindObjects,
	proxy_C_FindObjectsFinal,
	proxy_C_EncryptInit,
	proxy_C_Encrypt,
	proxy_C_EncryptUpdate,
	proxy_C_EncryptFinal,
	proxy_C_DecryptInit,
	proxy_C_Decrypt,
	proxy_C_DecryptUpdate,
	proxy_C_DecryptFinal,
	proxy_C_DigestInit,
	proxy_C_Digest,
	proxy_C_DigestUpdate,
	proxy_C_DigestKey,
	proxy_C_DigestFinal,
	proxy_C_SignInit,
	proxy_C_Sign,
	proxy_C_SignUpdate,
	proxy_C_SignFinal,
	proxy_C_SignRecoverInit,
	proxy_C_SignRecover,
	proxy_C_VerifyInit,
	proxy_C_Verify,
	proxy_C_VerifyUpdate,
	proxy_C_VerifyFinal,
	proxy_C_VerifyRecoverInit,
	proxy_C_VerifyRecover,
	proxy_C_DigestEncryptUpdate,
	proxy_C_DecryptDigestUpdate,
	proxy_C_SignEncryptUpdate,
	proxy_C_DecryptVerifyUpdate,
	proxy_C_GenerateKey,
	proxy_C_GenerateKeyPair,
	proxy_C_WrapKey,
	proxy_C_UnwrapKey,
	proxy_C_DeriveKey,
	proxy_C_SeedRandom,
	proxy_C_GenerateRandom,
	proxy_C_GetFunctionStatus,
	proxy_C_CancelFunction,
	proxy_C_WaitForSlotEvent
};

CK_RV
C_GetFunctionList (CK_FUNCTION_LIST_PTR_PTR list)
{
	return proxy_C_GetFunctionList (list);
}
