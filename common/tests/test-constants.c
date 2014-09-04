/*
 * Copyright (c) 2012 Red Hat Inc.
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
 * Author: Stef Walter <stefw@gnome.org>
 */

#include "config.h"
#include "test.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "attrs.h"
#include "constants.h"
#include "debug.h"

static void
test_constants (void *arg)
{
	const p11_constant *constant = arg;
	p11_dict *nicks, *names;
	CK_ULONG check;
	int i, j;

	nicks = p11_constant_reverse (true);
	names = p11_constant_reverse (false);

	for (i = 1; constant[i].value != CKA_INVALID; i++) {
		if (constant[i].value < constant[i - 1].value)
			assert_fail ("attr constant out of order", constant[i].name);
	}
	for (i = 0; constant[i].value != CKA_INVALID; i++) {
		assert_ptr_not_null (constant[i].name);

		if (constant[i].nicks[0]) {
			assert_str_eq (constant[i].nicks[0],
				       p11_constant_nick (constant, constant[i].value));
		}

		assert_str_eq (constant[i].name,
			       p11_constant_name (constant, constant[i].value));

		for (j = 0; constant[i].nicks[j] != NULL; j++) {
			check = p11_constant_resolve (nicks, constant[i].nicks[j]);
			assert_num_eq (constant[i].value, check);
		}

		check = p11_constant_resolve (names, constant[i].name);
		assert_num_eq (constant[i].value, check);
	}

	p11_dict_free (names);
	p11_dict_free (nicks);
}

int
main (int argc,
      char *argv[])
{
	p11_testx (test_constants, (void *)p11_constant_types, "/constants/types");
	p11_testx (test_constants, (void *)p11_constant_classes, "/constants/classes");
	p11_testx (test_constants, (void *)p11_constant_trusts, "/constants/trusts");
	p11_testx (test_constants, (void *)p11_constant_certs, "/constants/certs");
	p11_testx (test_constants, (void *)p11_constant_keys, "/constants/keys");
	p11_testx (test_constants, (void *)p11_constant_asserts, "/constants/asserts");
	p11_testx (test_constants, (void *)p11_constant_categories, "/constants/categories");
	p11_testx (test_constants, (void *)p11_constant_mechanisms, "/constants/mechanisms");
	p11_testx (test_constants, (void *)p11_constant_users, "/constants/users");
	p11_testx (test_constants, (void *)p11_constant_states, "/constants/states");
	p11_testx (test_constants, (void *)p11_constant_returns, "/constants/returns");

	return p11_test_run (argc, argv);
}
