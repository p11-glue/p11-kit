/*
 * Copyright (c) 2012 Red Hat Inc
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

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "compat.h"
#include "p11-kit.h"

int
main (void)
{
	CK_FUNCTION_LIST **modules;
	CK_FUNCTION_LIST *module;
	char *field;
	char *name;
	int ret;
	int i;

	/*
	 * Use 'chmod ug+s frob-setuid' to change this program
	 * and test the output with/without setuid or setgid.
	 */

	putenv ("P11_KIT_STRICT=1");

	modules = p11_kit_modules_load_and_initialize (0);
	assert (modules != NULL);

	/* This is a system configured module */
	module = p11_kit_module_for_name (modules, "one");
	assert (module != NULL);

	field = p11_kit_config_option (module, "setting");
	printf ("'setting' on module 'one': %s\n", field ? field : "(null)");

	assert (field != NULL);
	if (getauxval (AT_SECURE))
		assert (strcmp (field, "system1") == 0);
	else
		assert (strcmp (field, "user1") == 0);

	free (field);

	for (i = 0; modules[i] != NULL; i++) {
		name = p11_kit_module_get_name (modules[i]);
		printf ("%s\n", name);
		free (name);
	}

	field = p11_kit_config_option (module, "number");
	printf ("'number' on module 'one': %s\n", field ? field : "(null)");

	ret = atoi (field ? field : "0");
	assert (ret != 0);
	free (field);

	p11_kit_modules_finalize_and_release (modules);
	return ret;
}
