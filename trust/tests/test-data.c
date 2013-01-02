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

#include "attrs.h"
#include "test-data.h"

#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

void
test_check_object_msg (CuTest *cu,
                       const char *file,
                       int line,
                       CK_ATTRIBUTE *attrs,
                       CK_OBJECT_CLASS klass,
                       const char *label)
{
	CK_BBOOL vtrue = CK_TRUE;
	CK_BBOOL vfalse = CK_FALSE;

	CK_ATTRIBUTE expected[] = {
		{ CKA_TOKEN, &vtrue, sizeof (vtrue) },
		{ CKA_PRIVATE, &vfalse, sizeof (vfalse) },
		{ CKA_MODIFIABLE, &vfalse, sizeof (vfalse) },
		{ CKA_CLASS, &klass, sizeof (klass) },
		{ label ? CKA_LABEL : CKA_INVALID, (void *)label, label ? strlen (label) : 0 },
		{ CKA_INVALID },
	};

	test_check_attrs_msg (cu, file, line, expected, attrs);
}

void
test_check_cacert3_ca_msg (CuTest *cu,
                           const char *file,
                           int line,
                           CK_ATTRIBUTE *attrs,
                           const char *label)
{
	CK_CERTIFICATE_TYPE x509 = CKC_X_509;
	CK_ULONG category = 0; /* TODO: Implement */

	CK_ATTRIBUTE expected[] = {
		{ CKA_CERTIFICATE_TYPE, &x509, sizeof (x509) },
		{ CKA_CERTIFICATE_CATEGORY, &category, sizeof (category) },
		{ CKA_VALUE, (void *)test_cacert3_ca_der, sizeof (test_cacert3_ca_der) },
		{ CKA_CHECK_VALUE, "\xad\x7c\x3f", 3 },
		{ CKA_START_DATE, "20110523", 8 },
		{ CKA_END_DATE, "20210520", 8, },
		{ CKA_SUBJECT, (void *)test_cacert3_ca_subject, sizeof (test_cacert3_ca_subject) },
		{ CKA_ISSUER, (void *)test_cacert3_ca_issuer, sizeof (test_cacert3_ca_issuer) },
		{ CKA_SERIAL_NUMBER, (void *)test_cacert3_ca_serial, sizeof (test_cacert3_ca_serial) },
		{ CKA_INVALID },
	};

	test_check_object_msg (cu, file, line, attrs, CKO_CERTIFICATE, label);
	test_check_attrs_msg (cu, file, line, expected, attrs);
}

void
test_check_attrs_msg (CuTest *cu,
                      const char *file,
                      int line,
                      CK_ATTRIBUTE *expected,
                      CK_ATTRIBUTE *attrs)
{
	CK_ATTRIBUTE *attr;

	while (!p11_attrs_is_empty (expected)) {
		attr = p11_attrs_find (attrs, expected->type);
		test_check_attr_msg (cu, file, line, expected, attr);
		expected++;
	}
}

void
test_check_attr_msg (CuTest *cu,
                     const char *file,
                     int line,
                     CK_ATTRIBUTE *expected,
                     CK_ATTRIBUTE *attr)
{
	char *message;
	assert (expected != NULL);

	if (attr == NULL) {
		asprintf (&message, "expected %s but found NULL",
		          p11_attr_to_string (expected));
		CuFail_Line (cu, file, line, "attribute does not match", message);
	}

	if (!p11_attr_equal (attr, expected)) {
		asprintf (&message, "expected %s but found %s",
		          p11_attr_to_string (expected),
		          p11_attr_to_string (attr));
		CuFail_Line (cu, file, line, "attribute does not match", message);
	}
}

void
test_fail_attrs_match (CuTest *cu,
                       const char *file,
                       const char *line,
                       CK_ATTRIBUTE *expect,
                       CK_ATTRIBUTE *attrs);
