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

#include "attrs.h"
#include "test-trust.h"

#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

void
test_check_object_msg (const char *file,
                       int line,
                       const char *function,
                       CK_ATTRIBUTE *attrs,
                       CK_OBJECT_CLASS klass,
                       const char *label)
{
	CK_BBOOL vfalse = CK_FALSE;

	CK_ATTRIBUTE expected[] = {
		{ CKA_PRIVATE, &vfalse, sizeof (vfalse) },
		{ CKA_MODIFIABLE, &vfalse, sizeof (vfalse) },
		{ CKA_CLASS, &klass, sizeof (klass) },
		{ label ? CKA_LABEL : CKA_INVALID, (void *)label, label ? strlen (label) : 0 },
		{ CKA_INVALID },
	};

	test_check_attrs_msg (file, line, function, expected, attrs);
}

void
test_check_cacert3_ca_msg (const char *file,
                           int line,
                           const char *function,
                           CK_ATTRIBUTE *attrs,
                           const char *label)
{
	CK_CERTIFICATE_TYPE x509 = CKC_X_509;
	CK_ULONG category = 2; /* authority */

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

	test_check_object_msg (file, line, function, attrs, CKO_CERTIFICATE, label);
	test_check_attrs_msg (file, line, function, expected, attrs);
}

void
test_check_id_msg (const char *file,
                   int line,
                   const char *function,
                   CK_ATTRIBUTE *expected,
                   CK_ATTRIBUTE *attr)
{
	CK_ATTRIBUTE *one;
	CK_ATTRIBUTE *two;

	one = p11_attrs_find (expected, CKA_ID);
	two = p11_attrs_find (attr, CKA_ID);

	test_check_attr_msg (file, line, function, CKA_INVALID, one, two);
}

void
test_check_attrs_msg (const char *file,
                      int line,
                      const char *function,
                      CK_ATTRIBUTE *expected,
                      CK_ATTRIBUTE *attrs)
{
	CK_OBJECT_CLASS klass;
	CK_ATTRIBUTE *attr;

	if (!p11_attrs_find_ulong (expected, CKA_CLASS, &klass))
		klass = CKA_INVALID;

	while (!p11_attrs_terminator (expected)) {
		attr = p11_attrs_find (attrs, expected->type);
		test_check_attr_msg (file, line, function, klass, expected, attr);
		expected++;
	}
}

void
test_check_attr_msg (const char *file,
                     int line,
                     const char *function,
                     CK_OBJECT_CLASS klass,
                     CK_ATTRIBUTE *expected,
                     CK_ATTRIBUTE *attr)
{
	assert (expected != NULL);

	if (attr == NULL) {
		p11_test_fail (file, line, function,
		               "attribute does not match: (expected %s but found NULL)",
		               p11_attr_to_string (expected, klass));
	}

	if (!p11_attr_equal (attr, expected)) {
		p11_test_fail (file, line, function,
		               "attribute does not match: (expected %s but found %s)",
		               p11_attr_to_string (expected, klass),
		               p11_attr_to_string (attr, klass));
	}
}
