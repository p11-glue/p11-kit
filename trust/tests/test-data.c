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
#include "test-data.h"

void
test_check_object (CuTest *cu,
                   CK_ATTRIBUTE *attrs,
                   CK_OBJECT_CLASS klass,
                   const char *label)
{
	CK_BBOOL val;
	CK_ULONG ulong;
	CK_ATTRIBUTE *attr;

	if (!p11_attrs_find_bool (attrs, CKA_TOKEN, &val))
		CuFail (cu, "missing CKA_TOKEN");
	CuAssertIntEquals (cu, CK_TRUE, val);

	if (!p11_attrs_find_bool (attrs, CKA_PRIVATE, &val))
		CuFail (cu, "missing CKA_PRIVATE");
	CuAssertIntEquals (cu, CK_FALSE, val);

	if (!p11_attrs_find_bool (attrs, CKA_MODIFIABLE, &val))
		CuFail (cu, "missing CKA_MODIFIABLE");
	CuAssertIntEquals (cu, CK_FALSE, val);

	if (!p11_attrs_find_ulong (attrs, CKA_CLASS, &ulong))
		CuFail (cu, "missing CKA_CLASS");
	CuAssertIntEquals (cu, klass, ulong);

	if (label) {
		attr = p11_attrs_find_valid (attrs, CKA_LABEL);
		CuAssertPtrNotNull (cu, attr);
		CuAssertTrue (cu, p11_attr_match_value (attr, label, -1));
	}
}

void
test_check_cacert3_ca (CuTest *cu,
                      CK_ATTRIBUTE *attrs,
                      const char *label)
{
	CK_ATTRIBUTE *attr;
	CK_ULONG ulong;

	test_check_object (cu, attrs, CKO_CERTIFICATE, label);

	if (!p11_attrs_find_ulong (attrs, CKA_CERTIFICATE_TYPE, &ulong))
		CuFail (cu, "missing CKA_CERTIFICATE_TYPE");
	CuAssertIntEquals (cu, CKC_X_509, ulong);

	/* TODO: Implement */
	if (!p11_attrs_find_ulong (attrs, CKA_CERTIFICATE_CATEGORY, &ulong))
		CuFail (cu, "missing CKA_CERTIFICATE_CATEGORY");
	CuAssertIntEquals (cu, 0, ulong);

	attr = p11_attrs_find (attrs, CKA_VALUE);
	CuAssertPtrNotNull (cu, attr);
	CuAssertTrue (cu, p11_attr_match_value (attr, test_cacert3_ca_der,
	                                        sizeof (test_cacert3_ca_der)));

	attr = p11_attrs_find_valid (attrs, CKA_CHECK_VALUE);
	CuAssertPtrNotNull (cu, attr);
	CuAssertTrue (cu, p11_attr_match_value (attr, "\xad\x7c\x3f", 3));

	attr = p11_attrs_find (attrs, CKA_START_DATE);
	CuAssertPtrNotNull (cu, attr);
	CuAssertTrue (cu, p11_attr_match_value (attr, "20110523", -1));

	attr = p11_attrs_find_valid (attrs, CKA_END_DATE);
	CuAssertPtrNotNull (cu, attr);
	CuAssertTrue (cu, p11_attr_match_value (attr, "20210520", -1));

	attr = p11_attrs_find (attrs, CKA_SUBJECT);
	CuAssertPtrNotNull (cu, attr);
	CuAssertTrue (cu, p11_attr_match_value (attr, test_cacert3_ca_subject,
	                                        sizeof (test_cacert3_ca_subject)));

	attr = p11_attrs_find (attrs, CKA_ISSUER);
	CuAssertPtrNotNull (cu, attr);
	CuAssertTrue (cu, p11_attr_match_value (attr, test_cacert3_ca_issuer,
	                                        sizeof (test_cacert3_ca_issuer)));

	attr = p11_attrs_find (attrs, CKA_SERIAL_NUMBER);
	CuAssertPtrNotNull (cu, attr);
	CuAssertTrue (cu, p11_attr_match_value (attr, test_cacert3_ca_serial,
	                                        sizeof (test_cacert3_ca_serial)));
}
