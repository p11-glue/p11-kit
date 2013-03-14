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
#include "CuTest.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "attrs.h"
#include "constants.h"
#include "debug.h"

static void
test_constants (CuTest *tc)
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
		NULL
	};

	nicks = p11_constant_reverse (true);
	names = p11_constant_reverse (false);

	for (j = 0; constants[j] != NULL; j++) {
		constant = constants[j];
		for (i = 1; constant[i].value != CKA_INVALID; i++) {
			if (constant[i].value < constant[i - 1].value) {
				CuFail_Line (tc, __FILE__, __LINE__,
				             "attr constant out of order", constant[i].name);
			}
		}
		for (i = 0; constant[i].value != CKA_INVALID; i++) {
			CuAssertPtrNotNull (tc, constant[i].nick);
			CuAssertPtrNotNull (tc, constant[i].name);

			CuAssertStrEquals (tc, constant[i].nick,
			                   p11_constant_nick (constant, constant[i].value));
			CuAssertStrEquals (tc, constant[i].name,
			                   p11_constant_name (constant, constant[i].value));

			check = p11_constant_resolve (nicks, constant[i].nick);
			CuAssertIntEquals (tc, constant[i].value, check);

			check = p11_constant_resolve (names, constant[i].name);
			CuAssertIntEquals (tc, constant[i].value, check);
		}
	}

	p11_dict_free (names);
	p11_dict_free (nicks);
}

int
main (void)
{
	CuString *output = CuStringNew ();
	CuSuite* suite = CuSuiteNew ();
	int ret;

	putenv ("P11_KIT_STRICT=1");
	p11_debug_init ();
	SUITE_ADD_TEST (suite, test_constants);

	CuSuiteRun (suite);
	CuSuiteSummary (suite, output);
	CuSuiteDetails (suite, output);
	printf ("%s\n", output->buffer);
	ret = suite->failCount;
	CuSuiteDelete (suite);
	CuStringDelete (output);

	return ret;
}
