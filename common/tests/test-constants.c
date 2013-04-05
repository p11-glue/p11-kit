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
test_constants (void)
{
	const p11_constant *constant;
	p11_dict *nicks, *names;
	CK_ULONG check;
	int i, j;

	static const p11_constant *constants[] = {
		p11_constant_types,
		p11_constant_classes,
		p11_constant_trusts,
		p11_constant_certs,
		p11_constant_keys,
		p11_constant_asserts,
		p11_constant_categories,
		p11_constant_mechanisms,
		p11_constant_users,
		p11_constant_states,
		p11_constant_returns,
		NULL
	};

	nicks = p11_constant_reverse (true);
	names = p11_constant_reverse (false);

	for (j = 0; constants[j] != NULL; j++) {
		constant = constants[j];
		for (i = 1; constant[i].value != CKA_INVALID; i++) {
			if (constant[i].value < constant[i - 1].value)
				assert_fail ("attr constant out of order", constant[i].name);
		}
		for (i = 0; constant[i].value != CKA_INVALID; i++) {
			assert_ptr_not_null (constant[i].name);

			if (constant[i].nick) {
				assert_str_eq (constant[i].nick,
				               p11_constant_nick (constant, constant[i].value));
			}

			assert_str_eq (constant[i].name,
			               p11_constant_name (constant, constant[i].value));

			if (constant[i].nick) {
				check = p11_constant_resolve (nicks, constant[i].nick);
				assert_num_eq (constant[i].value, check);
			}

			check = p11_constant_resolve (names, constant[i].name);
			assert_num_eq (constant[i].value, check);
		}
	}

	p11_dict_free (names);
	p11_dict_free (nicks);
}

int
main (int argc,
      char *argv[])
{
	p11_test (test_constants, "/constants/all");

	return p11_test_run (argc, argv);
}
