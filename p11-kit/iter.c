/*
 * Copyright (C) 2013 Red Hat Inc.
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

#include "array.h"
#include "attrs.h"
#include "debug.h"
#include "iter.h"
#include "pin.h"
#include "private.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

typedef struct _Callback {
	p11_kit_iter_callback func;
	void *callback_data;
	p11_kit_destroyer destroyer;
	struct _Callback *next;
} Callback;

/**
 * P11KitIter:
 *
 * Used to iterate over PKCS\#11 objects.
 */
struct p11_kit_iter {

	/* Iterator matching data */
	CK_INFO match_module;
	CK_TOKEN_INFO match_token;
	CK_ATTRIBUTE *match_attrs;
	Callback *callbacks;

	/* The input modules */
	p11_array *modules;

	/* The results of C_GetSlotList */
	CK_SLOT_ID *slots;
	CK_ULONG num_slots;
	CK_ULONG saw_slots;

	/* The results of C_FindObjects */
	CK_OBJECT_HANDLE *objects;
	CK_ULONG max_objects;
	CK_ULONG num_objects;
	CK_ULONG saw_objects;

	/* The current iteration */
	CK_FUNCTION_LIST_PTR module;
	CK_SLOT_ID slot;
	CK_SESSION_HANDLE session;
	CK_OBJECT_HANDLE object;
	CK_TOKEN_INFO token_info;

	/* And various flags */
	unsigned int searching : 1;
	unsigned int searched : 1;
	unsigned int iterating : 1;
	unsigned int match_nothing : 1;
	unsigned int keep_session : 1;
	unsigned int preload_results : 1;
	unsigned int want_writable : 1;
};

/**
 * P11KitIterBehavior:
 * @P11_KIT_ITER_BUSY_SESSIONS: Allow the iterator's sessions to be
 *   in a busy state when the iterator returns an object.
 * @P11_KIT_ITER_WANT_WRITABLE: Try to open read-write sessions when
 *   iterating over obojects.
 *
 * Various flags controling the behavior of the iterator.
 */

/**
 * p11_kit_iter_new:
 * @uri: (allow-none): a PKCS\#11 URI to filter on, or %NULL
 * @behavior: various behavior flags for iterator
 *
 * Create a new PKCS\#11 iterator for iterating over objects. Only
 * objects that match the @uri will be returned by the iterator.
 * Relevant information in @uri is copied, and you need not keep
 * @uri around.
 *
 * If no @uri is specified then the iterator will iterate over all
 * objects, unless otherwise filtered.
 *
 * Returns: (transfer full): a new iterator, which should be freed
 *          with p11_kit_iter_free()
 */
P11KitIter *
p11_kit_iter_new (P11KitUri *uri,
                  P11KitIterBehavior behavior)
{
	P11KitIter *iter;

	iter = calloc (1, sizeof (P11KitIter));
	return_val_if_fail (iter != NULL, NULL);

	iter->modules = p11_array_new (NULL);
	return_val_if_fail (iter->modules != NULL, NULL);

	iter->want_writable = !!(behavior & P11_KIT_ITER_WANT_WRITABLE);
	iter->preload_results = !(behavior & P11_KIT_ITER_BUSY_SESSIONS);

	p11_kit_iter_set_uri (iter, uri);
	return iter;
}

/**
 * p11_kit_iter_set_uri:
 * @iter: the iterator
 * @uri: (allow-none): a PKCS\#11 URI to filter on, or %NULL
 *
 * Set the PKCS\#11 uri for iterator. Only
 * objects that match the @uri will be returned by the iterator.
 * Relevant information in @uri is copied, and you need not keep
 * @uri around.
 *
 * If no @uri is specified then the iterator will iterate over all
 * objects, unless otherwise filtered.
 *
 * This function should be called at most once, and should be
 * called before iterating begins.
 *
 */
void
p11_kit_iter_set_uri (P11KitIter *iter,
                      P11KitUri *uri)
{
	CK_ATTRIBUTE *attrs;
	CK_TOKEN_INFO *tinfo;
	CK_INFO *minfo;
	CK_ULONG count;

	return_if_fail (iter != NULL);

	if (uri != NULL) {

		if (p11_kit_uri_any_unrecognized (uri)) {
			iter->match_nothing = 1;

		} else {
			attrs = p11_kit_uri_get_attributes (uri, &count);
			iter->match_attrs = p11_attrs_buildn (NULL, attrs, count);

			minfo = p11_kit_uri_get_module_info (uri);
			if (minfo != NULL)
				memcpy (&iter->match_module, minfo, sizeof (CK_INFO));

			tinfo = p11_kit_uri_get_token_info (uri);
			if (tinfo != NULL)
				memcpy (&iter->match_token, tinfo, sizeof (CK_TOKEN_INFO));
		}
	} else {
		/* Match any module version number*/
		memset (&iter->match_module, 0, sizeof (iter->match_module));
		iter->match_module.libraryVersion.major = (CK_BYTE)-1;
		iter->match_module.libraryVersion.minor = (CK_BYTE)-1;
	}
}

/**
 * p11_kit_destroyer:
 * @data: data to destroy
 *
 * A callback called to free a resource.
 */

/**
 * p11_kit_iter_callback:
 * @iter: the iterator
 * @matches: (out): whether to match the current object
 * @data: callback data
 *
 * A callback setup with p11_kit_iter_add_callback(). This callback is
 * called for each object iterated.
 *
 * If the callback sets @matches to CK_FALSE, then this object is
 * skipped and not matched by p11_kit_iter_next(). If you return
 * anything but CKR_OK, then the iteration is stopped, and
 * p11_kit_iter_next() returns the result code.
 *
 * Returns: CKR_OK to continue iterating, CKR_CANCEL to stop, or
 *          anything else to fail
 */

/**
 * p11_kit_iter_add_callback:
 * @iter: the iterator
 * @callback: a function to call for each iteration
 * @callback_data: (allow-none): data to pass to the function
 * @callback_destroy: (allow-none): used to cleanup the data
 *
 * Adds a callback to the iterator which will be called each time
 * that an object is iterated.
 *
 * These callbacks can also perform filtering. If any callback
 * indicates through it's <literal>matches</literal> argument that
 * the object should not match, then that object will not be iterated
 * as far as p11_kit_iter_next() is concerned.
 *
 * The callbacks will be called with the <literal>matches</literal>
 * set to <literal>CK_TRUE</literal> and it's up to filters to change
 * it to <literal>CK_FALSE</literal> when necessary.
 */
void
p11_kit_iter_add_callback (P11KitIter *iter,
                           p11_kit_iter_callback callback,
                           void *callback_data,
                           p11_kit_destroyer callback_destroy)
{
	Callback *cb;

	return_if_fail (iter != NULL);
	return_if_fail (callback != NULL);

	cb = calloc (1, sizeof (Callback));
	return_if_fail (cb != NULL);

	cb->func = callback;
	cb->destroyer = callback_destroy;
	cb->callback_data = callback_data;
	cb->next = iter->callbacks;
	iter->callbacks = cb;
}

/**
 * p11_kit_iter_add_filter:
 * @iter: the iterator
 * @matching: (array length=count): the attributes that the objects should match
 * @count: the number of attributes
 *
 * Add a filter to limit the objects that the iterator iterates over.
 *
 * Only objects matching the passed in attributes will be iterated.
 * This function can be called multiple times.
 *
 * The @matching attributes are copied.
 */
void
p11_kit_iter_add_filter (P11KitIter *iter,
                         CK_ATTRIBUTE *matching,
                         CK_ULONG count)
{
	return_if_fail (iter != NULL);
	return_if_fail (!iter->iterating);

	iter->match_attrs = p11_attrs_buildn (iter->match_attrs, matching, count);
	return_if_fail (iter->match_attrs != NULL);
}

static void
finish_object (P11KitIter *iter)
{
	iter->object = 0;
}

static void
finish_slot (P11KitIter *iter)
{
	if (iter->session && !iter->keep_session) {
		assert (iter->module != NULL);
		(iter->module->C_CloseSession) (iter->session);
	}

	iter->keep_session = 0;
	iter->session = 0;
	iter->searched = 0;
	iter->searching = 0;
	iter->slot = 0;
}

static void
finish_module (P11KitIter *iter)
{
	iter->num_slots = 0;
	iter->saw_slots = 0;
	iter->module = NULL;
}

static CK_RV
finish_iterating (P11KitIter *iter,
                  CK_RV rv)
{
	finish_object (iter);
	finish_slot (iter);
	finish_module (iter);
	p11_array_clear (iter->modules);

	iter->iterating = 0;
	return rv;
}

/**
 * p11_kit_iter_begin:
 * @iter: the iterator
 * @modules: (array zero-terminated=1): null-terminated list of
 *           modules to iterate over
 *
 * Begin iterating PKCS\#11 objects in the given @modules.
 *
 * The @modules arguments should be a null-terminated list of
 * pointers to the modules' PKCS\#11 function pointers.
 *
 * For each module, all initialized slots will be iterated over,
 * having sessions opened for each of them in turn, and searched
 * for objects matching the search criteria.
 */
void
p11_kit_iter_begin (P11KitIter *iter,
                    CK_FUNCTION_LIST_PTR *modules)
{
	int i;

	return_if_fail (modules != NULL);

	finish_iterating (iter, CKR_OK);

	/* Use this module */
	for (i = 0; modules[i] != NULL; i++) {
		if (!p11_array_push (iter->modules, modules[i]))
			return_if_reached ();
	}

	iter->iterating = 1;
	iter->searched = 1;
}

/**
 * p11_kit_iter_begin_with:
 * @iter: the iterator
 * @module: the module to iterate over
 * @slot: (allow-none): the slot to iterate objects in, or zero
 * @session: (allow-none): the session to search for objects on, or zero
 *
 * Begin iterating PKCS\#11 objects in the given @module.
 *
 * If @slot is non-zero then the iteration will be limited to that
 * slot.
 *
 * If @session is non-zero then the iteration will be limited to
 * objects visible through that session, which implies that they
 * are also limited to the slot which the session was opened for.
 */
void
p11_kit_iter_begin_with (P11KitIter *iter,
                         CK_FUNCTION_LIST_PTR module,
                         CK_SLOT_ID slot,
                         CK_SESSION_HANDLE session)
{
	CK_SESSION_INFO info;
	CK_RV rv;

	finish_iterating (iter, CKR_OK);

	return_if_fail (module != NULL);

	if (session != 0) {
		/*
		 * A currently active session. Initialize as if we're ready
		 * to search using this session.
		 */

		/* If we have a session, but no slot, then look it up */
		if (slot == 0) {
			assert (module != NULL);
			rv = (module->C_GetSessionInfo) (session, &info);
			if (rv == CKR_OK)
				slot = info.slotID;
		}

		/* So initialize as if we're ready to search */
		iter->session = session;
		iter->slot = slot;
		iter->module = module;
		iter->keep_session = 1;

	} else if (slot != 0) {

		/*
		 * Limit to this slot. Initialize as if we're ready to use the
		 * slot from the slots list.
		 */

		iter->module = module;
		iter->slots = realloc (iter->slots, sizeof (CK_SLOT_ID));
		return_if_fail (iter->slots != NULL);
		iter->slots[0] = slot;
		iter->num_slots = 1;
		iter->searched = 1;

	} else {

		/*
		 * Limit to this module. Initialize as if we're ready to use
		 * the module from the modules array.
		 */

		assert (module != NULL);
		p11_array_push (iter->modules, module);
		iter->session = 0;
		iter->slot = 0;
		iter->searched = 1;
	}

	iter->iterating = 1;
}

static CK_RV
call_all_filters (P11KitIter *iter,
                  CK_BBOOL *matches)
{
	Callback *cb;
	CK_RV rv;

	*matches = CK_TRUE;

	for (cb = iter->callbacks; cb != NULL; cb = cb->next) {
		rv = (cb->func) (iter, matches, cb->callback_data);
		if (rv != CKR_OK || !*matches)
			return rv;
	}

	return CKR_OK;
}

static CK_RV
move_next_session (P11KitIter *iter)
{
	CK_ULONG session_flags;
	CK_ULONG num_slots;
	CK_INFO minfo;
	CK_RV rv;

	finish_slot (iter);

	/* If we have no more slots, then move to next module */
	while (iter->saw_slots >= iter->num_slots) {
		finish_module (iter);

		/* Iter is finished */
		if (iter->modules->num == 0)
			return finish_iterating (iter, CKR_CANCEL);

		iter->module = iter->modules->elem[0];
		p11_array_remove (iter->modules, 0);

		/* Skip module if it doesn't match uri */
		assert (iter->module != NULL);
		rv = (iter->module->C_GetInfo) (&minfo);
		if (rv != CKR_OK || !p11_match_uri_module_info (&iter->match_module, &minfo))
			continue;

		rv = (iter->module->C_GetSlotList) (CK_TRUE, NULL, &num_slots);
		if (rv != CKR_OK)
			return finish_iterating (iter, rv);

		iter->slots = realloc (iter->slots, sizeof (CK_SLOT_ID) * (num_slots + 1));
		return_val_if_fail (iter->slots != NULL, CKR_HOST_MEMORY);

		rv = (iter->module->C_GetSlotList) (CK_TRUE, iter->slots, &num_slots);
		if (rv != CKR_OK)
			return finish_iterating (iter, rv);

		iter->num_slots = num_slots;
		assert (iter->saw_slots == 0);
	}

	/* Move to the next slot, and open a session on it */
	while (iter->saw_slots < iter->num_slots) {
		iter->slot = iter->slots[iter->saw_slots++];

		assert (iter->module != NULL);
		rv = (iter->module->C_GetTokenInfo) (iter->slot, &iter->token_info);
		if (rv != CKR_OK || !p11_match_uri_token_info (&iter->match_token, &iter->token_info))
			continue;

		session_flags = CKF_SERIAL_SESSION;

		/* Skip if the read/write on a read-only token */
		if (iter->want_writable && (iter->token_info.flags & CKF_WRITE_PROTECTED) == 0)
			session_flags |= CKF_RW_SESSION;

		rv = (iter->module->C_OpenSession) (iter->slot, session_flags,
		                                    NULL, NULL, &iter->session);
		if (rv != CKR_OK)
			return finish_iterating (iter, rv);

		if (iter->session != 0)
			return CKR_OK;
	}

	/* Otherwise try again */
	return move_next_session (iter);
}

/**
 * p11_kit_iter_next:
 * @iter: the iterator
 *
 * Iterate to the next matching object.
 *
 * To access the object, session and so on, use the p11_kit_iter_get_object(),
 * p11_kit_iter_get_session(), and p11_kit_iter_get_module() functions.
 *
 * This call must only be called after either p11_kit_iter_begin()
 * or p11_kit_iter_begin_with() have been called.
 *
 * Objects which are skipped by callbacks will not be returned here
 * as matching objects.
 *
 * Returns: CKR_OK if an object matched, CKR_CANCEL if no more objects, or another error
 */
CK_RV
p11_kit_iter_next (P11KitIter *iter)
{
	CK_ULONG batch;
	CK_ULONG count;
	CK_BBOOL matches;
	CK_RV rv;

	return_val_if_fail (iter->iterating, CKR_OPERATION_NOT_INITIALIZED);

	iter->object = 0;

	if (iter->match_nothing)
		return finish_iterating (iter, CKR_CANCEL);

	/*
	 * If we have outstanding objects, then iterate one through those
	 * Note that we pass each object through the filters, and only
	 * assume it's iterated if it matches
	 */
	while (iter->saw_objects < iter->num_objects) {
		iter->object = iter->objects[iter->saw_objects++];

		rv = call_all_filters (iter, &matches);
		if (rv != CKR_OK)
			return finish_iterating (iter, rv);

		if (matches)
			return CKR_OK;
	}

	/* If we have finished searching then move to next session */
	if (iter->searched) {
		rv = move_next_session (iter);
		if (rv != CKR_OK)
			return finish_iterating (iter, rv);
	}

	/* Ready to start searching */
	if (!iter->searching && !iter->searched) {
		count = p11_attrs_count (iter->match_attrs);
		rv = (iter->module->C_FindObjectsInit) (iter->session, iter->match_attrs, count);
		if (rv != CKR_OK)
			return finish_iterating (iter, rv);
		iter->searching = 1;
		iter->searched = 0;
	}

	/* If we have searched on this session then try to continue */
	if (iter->searching) {
		assert (iter->module != NULL);
		assert (iter->session != 0);
		iter->num_objects = 0;
		iter->saw_objects = 0;

		for (;;) {
			if (iter->max_objects - iter->num_objects == 0) {
				iter->max_objects = iter->max_objects ? iter->max_objects * 2 : 64;
				iter->objects = realloc (iter->objects, iter->max_objects * sizeof (CK_ULONG));
				return_val_if_fail (iter->objects != NULL, CKR_HOST_MEMORY);
			}

			batch = iter->max_objects - iter->num_objects;
			rv = (iter->module->C_FindObjects) (iter->session,
			                                    iter->objects + iter->num_objects,
			                                    batch, &count);
			if (rv != CKR_OK)
				return finish_iterating (iter, rv);

			iter->num_objects += count;

			/*
			 * Done searching on this session, although there are still
			 * objects outstanding, which will be returned on next
			 * iterations.
			 */
			if (batch != count) {
				iter->searching = 0;
				iter->searched = 1;
				(iter->module->C_FindObjectsFinal) (iter->session);
				break;
			}

			if (!iter->preload_results)
				break;
		}
	}

	/* Try again */
	return p11_kit_iter_next (iter);
}

/**
 * p11_kit_iter_get_module:
 * @iter: the iterator
 *
 * Get the module function pointers for the current matching object.
 *
 * This can only be called after p11_kit_iter_next() succeeds.
 *
 * Returns: the module which the current matching object is in
 */
CK_FUNCTION_LIST_PTR
p11_kit_iter_get_module (P11KitIter *iter)
{
	return_val_if_fail (iter != NULL, NULL);
	return_val_if_fail (iter->iterating, 0);
	return iter->module;
}

/**
 * p11_kit_iter_get_slot:
 * @iter: the iterator
 *
 * Get the slot which the current matching object is on.
 *
 * This can only be called after p11_kit_iter_next() succeeds.
 *
 * Returns: the slot of the current matching object
 */
CK_SLOT_ID
p11_kit_iter_get_slot (P11KitIter *iter)
{
	return_val_if_fail (iter != NULL, 0);
	return_val_if_fail (iter->iterating, 0);
	return iter->slot;
}

/**
 * p11_kit_iter_get_token:
 * @iter: the iterator
 *
 * Get the token info for the token which the current matching object is on.
 *
 * This can only be called after p11_kit_iter_next(0 succeeds.
 *
 * Returns: the slot of the current matching object.
 */
CK_TOKEN_INFO *
p11_kit_iter_get_token (P11KitIter *iter)
{
	return_val_if_fail (iter != NULL, NULL);
	return &iter->token_info;
}

/**
 * p11_kit_iter_get_session:
 * @iter: the iterator
 *
 * Get the session which the current matching object is acessible
 * through.
 *
 * This can only be called after p11_kit_iter_next() succeeds.
 *
 * The session may be closed after the next p11_kit_iter_next() call
 * unless p11_kit_iter_keep_session() is called.
 *
 * Returns: the session used to find the current matching object
 */
CK_SESSION_HANDLE
p11_kit_iter_get_session (P11KitIter *iter)
{
	return_val_if_fail (iter != NULL, 0);
	return_val_if_fail (iter->iterating, 0);
	return iter->session;
}

/**
 * p11_kit_iter_get_object:
 * @iter: the iterator
 *
 * Get the current matching object.
 *
 * This can only be called after p11_kit_iter_next() succeeds.
 *
 * Returns: the current matching object
 */
CK_OBJECT_HANDLE
p11_kit_iter_get_object (P11KitIter *iter)
{
	return_val_if_fail (iter != NULL, 0);
	return iter->object;
}

/**
 * p11_kit_iter_destroy_object:
 * @iter: teh iterator
 *
 * Destory the current matching object.
 *
 * This can only be called after p11_kit_iter_next() succeeds.
 *
 * Returns: CKR_OK or a failure code
 */
CK_RV
p11_kit_iter_destroy_object (P11KitIter *iter)
{
	return_val_if_fail (iter != NULL, CKR_GENERAL_ERROR);
	return_val_if_fail (iter->iterating, CKR_GENERAL_ERROR);
	return (iter->module->C_DestroyObject) (iter->session, iter->object);
}

/**
 * p11_kit_iter_get_attributes:
 * @iter: the iterator
 * @template: (array length=count) (inout): the attributes to get
 * @count: the number of attributes
 *
 * Get attributes for the current matching object.
 *
 * This calls <literal>C_GetAttributeValue</literal> for the object
 * currently iterated to. Return value and attribute memory behavior
 * is identical to the PKCS\#11 <literal>C_GetAttributeValue</literal>
 * function.
 *
 * You might choose to use p11_kit_iter_load_attributes() for a more
 * helpful variant.
 *
 * This can only be called after p11_kit_iter_next() succeeds.
 *
 * Returns: The result from <literal>C_GetAttributeValue</literal>.
 */
CK_RV
p11_kit_iter_get_attributes (P11KitIter *iter,
                             CK_ATTRIBUTE *template,
                             CK_ULONG count)
{
	return_val_if_fail (iter != NULL, CKR_GENERAL_ERROR);
	return_val_if_fail (iter->iterating, CKR_GENERAL_ERROR);
	return_val_if_fail (iter->module != NULL, CKR_GENERAL_ERROR);
	return_val_if_fail (iter->session != 0, CKR_GENERAL_ERROR);
	return_val_if_fail (iter->object != 0, CKR_GENERAL_ERROR);

	return (iter->module->C_GetAttributeValue) (iter->session, iter->object,
	                                            template, count);
}

/**
 * p11_kit_iter_load_attributes:
 * @iter: the iterator
 * @template: (array length=count) (inout): the attributes to load
 * @count: the number of attributes
 *
 * Retrieve attributes for the current matching object.
 *
 * Each attribute in the array will be filled in with the value
 * of that attribute retrieved from the object. After use the
 * attribute value memory pointed to by the <literal>pValue</literal>
 * of each attribute should be freed with the <literal>free<!-- -->()</literal>
 * function.
 *
 * If the <literal>pValue</literal> of an attribute is not %NULL passed
 * to this function, then it will be passed to
 * <literal>realloc<!-- -->()</literal> to allocate the correct amount
 * of space for the attribute value.
 *
 * If any attribute is not present on the object, or is sensitive and
 * cannot be retrieved, then the <literal>pValue</literal> will be NULL.
 * If <literal>pValue</literal> was not %NULL when passed to this function
 * then it will be freed with <literal>free<!-- -->()</literal>. In these
 * cases <literal>CKR_OK</literal> is returned.
 *
 * This can only be called after p11_kit_iter_next() succeeds.
 *
 * Returns: CKR_OK or a failure code
 */
CK_RV
p11_kit_iter_load_attributes (P11KitIter *iter,
                              CK_ATTRIBUTE *template,
                              CK_ULONG count)
{
	CK_ATTRIBUTE *original = NULL;
	CK_ULONG i;
	CK_RV rv;

	return_val_if_fail (iter != NULL, CKR_GENERAL_ERROR);
	return_val_if_fail (iter->iterating, CKR_GENERAL_ERROR);
	return_val_if_fail (iter->module != NULL, CKR_GENERAL_ERROR);
	return_val_if_fail (iter->session != 0, CKR_GENERAL_ERROR);
	return_val_if_fail (iter->object != 0, CKR_GENERAL_ERROR);

	if (count == 0)
		return CKR_OK;

	original = memdup (template, count * sizeof (CK_ATTRIBUTE));
	return_val_if_fail (original != NULL, CKR_HOST_MEMORY);

	for (i = 0; i < count; i++)
		template[i].pValue = NULL;

	rv = (iter->module->C_GetAttributeValue) (iter->session, iter->object, template, count);

	switch (rv) {
	case CKR_OK:
	case CKR_ATTRIBUTE_TYPE_INVALID:
	case CKR_ATTRIBUTE_SENSITIVE:
	case CKR_BUFFER_TOO_SMALL:
		break;
	default:
		free (original);
		return rv;
	}

	for (i = 0; i < count; i++) {
		if (template[i].ulValueLen == (CK_ULONG)-1 ||
		    template[i].ulValueLen == 0) {
			free (original[i].pValue);

		} else if (original[i].pValue != NULL &&
		           template[i].ulValueLen == original[i].ulValueLen) {
			template[i].pValue = original[i].pValue;

		} else {
			template[i].pValue = realloc (original[i].pValue, template[i].ulValueLen);
			return_val_if_fail (template[i].pValue != NULL, CKR_HOST_MEMORY);
		}
	}

	free (original);

	rv = (iter->module->C_GetAttributeValue) (iter->session, iter->object, template, count);

	switch (rv) {
	case CKR_OK:
	case CKR_ATTRIBUTE_TYPE_INVALID:
	case CKR_ATTRIBUTE_SENSITIVE:
		rv = CKR_OK;
		break;
	default:
		return_val_if_fail (rv != CKR_BUFFER_TOO_SMALL, rv);
		return rv;
	}

	for (i = 0; i < count; i++) {
		if (template[i].ulValueLen == (CK_ULONG)-1 ||
		    template[i].ulValueLen == 0) {
			free (template[i].pValue);
			template[i].pValue = NULL;
		}
	}

	return rv;
}

/**
 * p11_kit_iter_keep_session:
 * @iter: the iterator
 *
 * After calling this function the session open for iterating
 * the current object will not be automatically closed by
 * the iterator after later calls to p11_kit_iter_next() or
 * p11_kit_iter_free().
 *
 * It is the callers responsibility to close this session,
 * after the iterator has been freed. The session may still be
 * used by the iterator if further iterations are performed.
 *
 * This can only be called after p11_kit_iter_next() succeeds.
 *
 * Returns: the current session
 */
CK_SESSION_HANDLE
p11_kit_iter_keep_session (P11KitIter *iter)
{
	return_val_if_fail (iter != NULL, 0);
	return_val_if_fail (iter->iterating, 0);
	return_val_if_fail (iter->session != 0, 0);

	iter->keep_session = 1;
	return iter->session;
}

/**
 * p11_kit_iter_free:
 * @iter: the iterator
 *
 * Frees the iterator and all resources, such as sessions
 * or callbacks held by the iterator.
 */
void
p11_kit_iter_free (P11KitIter *iter)
{
	Callback *cb, *next;

	if (iter == NULL)
		return;

	finish_iterating (iter, CKR_OK);
	p11_array_free (iter->modules);
	p11_attrs_free (iter->match_attrs);
	free (iter->objects);
	free (iter->slots);

	for (cb = iter->callbacks; cb != NULL; cb = next) {
		next = cb->next;
		if (cb->destroyer)
			(cb->destroyer) (cb->callback_data);
		free (cb);
	}

	free (iter);
}
