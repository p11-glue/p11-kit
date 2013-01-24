/*
 * Copyright (C) 2012 Red Hat Inc.
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

#include "attrs.h"
#define P11_DEBUG_FLAG P11_DEBUG_TRUST
#include "debug.h"
#include "dict.h"
#include "library.h"
#include "pkcs11.h"
#include "module.h"
#include "session.h"

#include <assert.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
	CK_OBJECT_HANDLE handle;
	CK_ATTRIBUTE *attrs;
} Object;

static void
object_free (void *data)
{
	Object *object = data;
	p11_attrs_free (object->attrs);
	free (object);
}

p11_session *
p11_session_new (p11_token *token)
{
	p11_session *session;

	session = calloc (1, sizeof (p11_session));
	return_val_if_fail (session != NULL, NULL);

	session->handle = p11_module_next_id ();

	session->objects =  p11_dict_new (p11_dict_ulongptr_hash,
	                                  p11_dict_ulongptr_equal,
	                                  NULL, object_free);
	return_val_if_fail (session->objects != NULL, NULL);

	session->token = token;

	return session;
}

void
p11_session_free (void *data)
{
	p11_session *session = data;

	p11_session_set_operation (session, NULL, NULL);
	p11_dict_free (session->objects);

	free (session);
}

CK_RV
p11_session_add_object (p11_session *session,
                        CK_ATTRIBUTE *attrs,
                        CK_OBJECT_HANDLE *handle)
{
	Object *object;

	assert (handle != NULL);
	assert (session != NULL);

	return_val_if_fail (attrs != NULL, CKR_GENERAL_ERROR);

	object = malloc (sizeof (Object));
	return_val_if_fail (object != NULL, CKR_HOST_MEMORY);

	object->handle = p11_module_next_id ();
	object->attrs = attrs;

	if (!p11_dict_set (session->objects, &object->handle, object))
		return_val_if_reached (CKR_HOST_MEMORY);

	*handle = object->handle;
	return CKR_OK;
}

CK_RV
p11_session_del_object (p11_session *session,
                        CK_OBJECT_HANDLE handle)
{
	p11_dict *objects;

	assert (session != NULL);

	if (p11_dict_remove (session->objects, &handle))
		return CKR_OK;

	/* Look for in the global objects */
	objects = p11_token_objects (session->token);
	if (p11_dict_get (objects, &handle))
		return CKR_TOKEN_WRITE_PROTECTED;

	return CKR_OBJECT_HANDLE_INVALID;
}

CK_ATTRIBUTE *
p11_session_get_object (p11_session *session,
                        CK_OBJECT_HANDLE handle,
                        CK_BBOOL *token)
{
	CK_ATTRIBUTE *attrs;
	p11_dict *objects;
	Object *object;

	assert (session != NULL);

	object = p11_dict_get (session->objects, &handle);
	if (object) {
		if (token)
			*token = CK_FALSE;
		return object->attrs;
	}

	objects = p11_token_objects (session->token);
	attrs = p11_dict_get (objects, &handle);
	if (attrs) {
		if (token)
			*token = CK_TRUE;
		return attrs;
	}

	return NULL;
}

CK_RV
p11_session_set_object (p11_session *session,
                        CK_OBJECT_HANDLE handle,
                        CK_ATTRIBUTE *template,
                        CK_ULONG count)
{
	CK_BBOOL token;
	p11_dict *objects;
	Object *object;

	assert (session != NULL);

	object = p11_dict_get (session->objects, &handle);
	if (object == NULL) {
		objects = p11_token_objects (session->token);
		if (p11_dict_get (objects, &handle))
			return CKR_TOKEN_WRITE_PROTECTED;
		return CKR_OBJECT_HANDLE_INVALID;
	}

	if (!p11_attrs_findn_bool (template, count, CKA_TOKEN, &token) && token)
		return CKR_TEMPLATE_INCONSISTENT;

	object->attrs = p11_attrs_buildn (object->attrs, template, count);
	return CKR_OK;
}

void
p11_session_set_operation (p11_session *session,
                           p11_session_cleanup cleanup,
                           void *operation)
{
	assert (session != NULL);

	if (session->cleanup)
		(session->cleanup) (session->operation);
	session->cleanup = cleanup;
	session->operation = operation;
}
