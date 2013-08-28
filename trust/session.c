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
#include "message.h"
#include "pkcs11.h"
#include "module.h"
#include "session.h"

#include <assert.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>

p11_session *
p11_session_new (p11_token *token)
{
	p11_session *session;

	session = calloc (1, sizeof (p11_session));
	return_val_if_fail (session != NULL, NULL);

	session->handle = p11_module_next_id ();

	session->builder = p11_builder_new (P11_BUILDER_FLAG_NONE);
	return_val_if_fail (session->builder, NULL);

	session->index = p11_index_new (p11_builder_build, NULL, NULL,
	                                p11_builder_changed,
	                                session->builder);
	return_val_if_fail (session->index != NULL, NULL);

	session->token = token;

	return session;
}

void
p11_session_free (void *data)
{
	p11_session *session = data;

	p11_session_set_operation (session, NULL, NULL);
	p11_builder_free (session->builder);
	p11_index_free (session->index);

	free (session);
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
