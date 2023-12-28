/*
 * Copyright (c) 2023, Red Hat Inc.
 *
 * All rights reserved.
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
 * Author: Daiki Ueno
 */

#include "config.h"

#include "tool.h"

#include "debug.h"
#include <stdlib.h>
#include <string.h>

#ifdef OS_UNIX
#include "tty.h"
#endif

struct p11_tool {
	P11KitUri *uri;
	bool login;
	char *provider;
	CK_FUNCTION_LIST **modules;
};

p11_tool *
p11_tool_new (void)
{
	return calloc (1, sizeof (p11_tool));
}

void
p11_tool_free (p11_tool *tool)
{
	if (!tool)
		return;
	p11_kit_uri_free (tool->uri);
	if (tool->modules)
		p11_kit_modules_finalize_and_release (tool->modules);

#ifdef OS_UNIX
	if (tool->login)
		p11_kit_pin_unregister_callback ("tty", p11_pin_tty_callback, NULL);
#endif

	free (tool->provider);
	free (tool);
}

P11KitUriResult
p11_tool_set_uri (p11_tool *tool,
		  const char *string,
		  P11KitUriType type)
{
	P11KitUri *uri;
	P11KitUriResult res;

	uri = p11_kit_uri_new ();
	if (!uri)
		return P11_KIT_URI_NO_MEMORY;

	res = p11_kit_uri_parse (string, type, uri);
	if (res == P11_KIT_URI_OK) {
		tool->uri = uri;
		uri = NULL;
	}

	p11_kit_uri_free (uri);
	return res;
}

void
p11_tool_set_login (p11_tool *tool,
		    bool login)
{
	tool->login = login;

#ifdef OS_UNIX
	/* Register a fallback PIN callback that reads from terminal.
	 * We don't care whether the registration succeeds as it is a fallback.
	 */
	if (tool->login)
		(void)p11_kit_pin_register_callback ("tty", p11_pin_tty_callback, NULL, NULL);
	else
		p11_kit_pin_unregister_callback ("tty", p11_pin_tty_callback, NULL);
#endif
}

bool
p11_tool_set_provider (p11_tool *tool,
		       const char *provider)
{
	free (tool->provider);

	if (provider) {
		tool->provider = strdup (provider);
		return tool->provider != NULL;
	} else {
		tool->provider = NULL;
		return true;
	}
}

P11KitIter *
p11_tool_begin_iter (p11_tool *tool,
		     P11KitIterBehavior behavior)
{
	P11KitIter *iter = NULL;

	return_val_if_fail (tool, NULL);

	/* Iteration is already in progress */
	return_val_if_fail (!tool->modules, NULL);

	if (tool->provider) {
		CK_FUNCTION_LIST **modules;

		modules = calloc (2, sizeof (CK_FUNCTION_LIST *));
		return_val_if_fail (modules, NULL);

		modules[0] = p11_kit_module_load (tool->provider, 0);
		if (!modules[0]) {
			free (modules);
			return NULL;
		}

		if (p11_kit_module_initialize (modules[0]) != CKR_OK) {
			p11_kit_module_release (modules[0]);
			free (modules);
			return NULL;
		}

		tool->modules = modules;
	} else {
		tool->modules = p11_kit_modules_load_and_initialize (0);
	}

	if (!tool->modules)
		return NULL;

	if (tool->login) {
		behavior |= P11_KIT_ITER_WITH_LOGIN;
#ifdef OS_UNIX
		p11_kit_uri_set_pin_source (tool->uri, "tty");
#endif
	}

	iter = p11_kit_iter_new (tool->uri, behavior);
	if (!iter)
		return NULL;

	p11_kit_iter_begin (iter, tool->modules);

	return iter;
}

void
p11_tool_end_iter (p11_tool *tool,
		   P11KitIter *iter)
{
	/* No iteration has started yet */
	p11_kit_iter_free (iter);

	return_if_fail (tool->modules);
	p11_kit_modules_finalize_and_release (tool->modules);
	tool->modules = NULL;
}
