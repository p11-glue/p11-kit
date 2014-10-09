/*
 * Copyright (c) 2013 Red Hat Inc.
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
#include "test-trust.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "attrs.h"
#include "builder.h"
#include "debug.h"
#include "digest.h"
#include "index.h"
#include "message.h"
#include "oid.h"
#include "pkcs11i.h"
#include "pkcs11x.h"

struct {
	p11_builder *builder;
	p11_index *index;
} test;

static CK_TRUST trusted = CKT_NSS_TRUSTED;
static CK_TRUST trusted_delegator = CKT_NSS_TRUSTED_DELEGATOR;
static CK_TRUST not_trusted = CKT_NSS_NOT_TRUSTED;
static CK_TRUST trust_unknown = CKT_NSS_TRUST_UNKNOWN;
static CK_OBJECT_CLASS certificate = CKO_CERTIFICATE;
static CK_OBJECT_CLASS data = CKO_DATA;
static CK_OBJECT_CLASS certificate_extension = CKO_X_CERTIFICATE_EXTENSION;
static CK_OBJECT_CLASS nss_trust = CKO_NSS_TRUST;
static CK_OBJECT_CLASS trust_assertion = CKO_X_TRUST_ASSERTION;
static CK_X_ASSERTION_TYPE anchored_certificate = CKT_X_ANCHORED_CERTIFICATE;
static CK_X_ASSERTION_TYPE distrusted_certificate = CKT_X_DISTRUSTED_CERTIFICATE;
static CK_CERTIFICATE_TYPE x509 = CKC_X_509;
static CK_ULONG certificate_authority = 2;
static CK_ULONG other_entity = 3;
static CK_BBOOL truev = CK_TRUE;
static CK_BBOOL falsev = CK_FALSE;

static void
setup (void *unused)
{
	test.builder = p11_builder_new (P11_BUILDER_FLAG_TOKEN);
	assert_ptr_not_null (test.builder);

	test.index = p11_index_new (p11_builder_build, NULL, NULL, p11_builder_changed, test.builder);
	assert_ptr_not_null (test.index);
}

static void
teardown (void *unused)
{
	p11_builder_free (test.builder);
	p11_index_free (test.index);
	memset (&test, 0, sizeof (test));
}

static void
test_get_cache (void)
{
	p11_asn1_cache *cache;

	cache = p11_builder_get_cache (test.builder);
	assert_ptr_eq (NULL, p11_asn1_cache_get (cache, "blah", (unsigned char *)"blah", 4));
}

static void
test_build_data (void)
{
	CK_ATTRIBUTE input[] = {
		{ CKA_CLASS, &data, sizeof (data) },
		{ CKA_VALUE, "the value", 9 },
		{ CKA_INVALID },
	};

	CK_ATTRIBUTE check[] = {
		{ CKA_CLASS, &data, sizeof (data) },
		{ CKA_TOKEN, &truev, sizeof (truev) },
		{ CKA_MODIFIABLE, &falsev, sizeof (falsev) },
		{ CKA_PRIVATE, &falsev, sizeof (falsev) },
		{ CKA_LABEL, "", 0 },
		{ CKA_VALUE, "the value", 9 },
		{ CKA_APPLICATION, "", 0 },
		{ CKA_OBJECT_ID, "", 0 },
		{ CKA_INVALID },
	};

	CK_ATTRIBUTE *attrs;
	CK_ATTRIBUTE *merge;
	CK_ATTRIBUTE *extra;
	CK_RV rv;

	attrs = NULL;
	extra = NULL;
	merge = p11_attrs_dup (input);
	rv = p11_builder_build (test.builder, test.index, attrs, merge, &extra);
	assert_num_eq (CKR_OK, rv);

	attrs = p11_attrs_merge (attrs, merge, true);
	attrs = p11_attrs_merge (attrs, extra, false);

	test_check_attrs (check, attrs);
	p11_attrs_free (attrs);
}

static void
test_build_certificate (void)
{
	CK_ATTRIBUTE input[] = {
		{ CKA_CLASS, &certificate, sizeof (certificate) },
		{ CKA_CERTIFICATE_TYPE, &x509, sizeof (x509) },
		{ CKA_VALUE, (void *)test_cacert3_ca_der, sizeof (test_cacert3_ca_der) },
		{ CKA_LABEL, "the label", 9 },
		{ CKA_INVALID },
	};

	CK_ATTRIBUTE expected[] = {
		{ CKA_CERTIFICATE_TYPE, &x509, sizeof (x509) },
		{ CKA_CERTIFICATE_CATEGORY, &certificate_authority, sizeof (certificate_authority) },
		{ CKA_VALUE, (void *)test_cacert3_ca_der, sizeof (test_cacert3_ca_der) },
		{ CKA_CHECK_VALUE, "\xad\x7c\x3f", 3 },
		{ CKA_START_DATE, "20110523", 8 },
		{ CKA_END_DATE, "20210520", 8, },
		{ CKA_SUBJECT, (void *)test_cacert3_ca_subject, sizeof (test_cacert3_ca_subject) },
		{ CKA_ISSUER, (void *)test_cacert3_ca_issuer, sizeof (test_cacert3_ca_issuer) },
		{ CKA_SERIAL_NUMBER, (void *)test_cacert3_ca_serial, sizeof (test_cacert3_ca_serial) },
		{ CKA_LABEL, "the label", 9 },
		{ CKA_ID, "u\xa8q`L\x88\x13\xf0x\xd9\x89w\xb5m\xc5\x89\xdf\xbc\xb1z", 20},
		{ CKA_INVALID },
	};

	CK_ATTRIBUTE *attrs;
	CK_ATTRIBUTE *merge;
	CK_ATTRIBUTE *extra;
	CK_RV rv;

	attrs = NULL;
	extra = NULL;
	merge = p11_attrs_dup (input);
	rv = p11_builder_build (test.builder, test.index, attrs, merge, &extra);
	assert_num_eq (CKR_OK, rv);

	attrs = p11_attrs_merge (attrs, merge, true);
	attrs = p11_attrs_merge (attrs, extra, false);

	test_check_attrs (expected, attrs);
	p11_attrs_free (attrs);
}

static void
test_build_certificate_empty (void)
{
	unsigned char checksum[P11_DIGEST_SHA1_LEN];
	CK_ULONG domain = 0;
	CK_ULONG category = 0;

	CK_ATTRIBUTE input[] = {
		{ CKA_CLASS, &certificate, sizeof (certificate) },
		{ CKA_CERTIFICATE_TYPE, &x509, sizeof (x509) },
		{ CKA_URL, "http://blah", 11 },
		{ CKA_HASH_OF_ISSUER_PUBLIC_KEY, checksum, sizeof (checksum) },
		{ CKA_HASH_OF_SUBJECT_PUBLIC_KEY, checksum, sizeof (checksum) },
		{ CKA_SUBJECT, (void *)test_cacert3_ca_subject, sizeof (test_cacert3_ca_subject) },
		{ CKA_LABEL, "the label", 9 },
		{ CKA_INVALID },
	};

	CK_ATTRIBUTE expected[] = {
		{ CKA_CLASS, &certificate, sizeof (certificate) },
		{ CKA_CERTIFICATE_TYPE, &x509, sizeof (x509) },
		{ CKA_CERTIFICATE_CATEGORY, &category, sizeof (category) },
		{ CKA_VALUE, "", 0 },
		{ CKA_START_DATE, "", 0 },
		{ CKA_END_DATE, "", 0, },
		{ CKA_SUBJECT, (void *)test_cacert3_ca_subject, sizeof (test_cacert3_ca_subject) },
		{ CKA_ISSUER, "", 0 },
		{ CKA_SERIAL_NUMBER, "", 0 },
		{ CKA_HASH_OF_ISSUER_PUBLIC_KEY, checksum, sizeof (checksum) },
		{ CKA_HASH_OF_SUBJECT_PUBLIC_KEY, checksum, sizeof (checksum) },
		{ CKA_LABEL, "the label", 9 },
		{ CKA_JAVA_MIDP_SECURITY_DOMAIN, &domain, sizeof (domain) },
		{ CKA_INVALID },
	};

	CK_ATTRIBUTE *attrs;
	CK_ATTRIBUTE *merge;
	CK_ATTRIBUTE *extra;
	CK_RV rv;

	p11_digest_sha1 (checksum, test_cacert3_ca_der, sizeof (test_cacert3_ca_der), NULL);

	attrs = NULL;
	extra = NULL;
	merge = p11_attrs_dup (input);
	rv = p11_builder_build (test.builder, test.index, attrs, merge, &extra);
	assert_num_eq (CKR_OK, rv);

	attrs = p11_attrs_merge (attrs, merge, true);
	attrs = p11_attrs_merge (attrs, extra, false);

	test_check_attrs (expected, attrs);
	p11_attrs_free (attrs);
}

static const unsigned char entrust_pretend_ca[] = {
	0x30, 0x82, 0x04, 0x5c, 0x30, 0x82, 0x03, 0x44, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x04, 0x38,
	0x63, 0xb9, 0x66, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05,
	0x05, 0x00, 0x30, 0x81, 0xb4, 0x31, 0x14, 0x30, 0x12, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x0b,
	0x45, 0x6e, 0x74, 0x72, 0x75, 0x73, 0x74, 0x2e, 0x6e, 0x65, 0x74, 0x31, 0x40, 0x30, 0x3e, 0x06,
	0x03, 0x55, 0x04, 0x0b, 0x14, 0x37, 0x77, 0x77, 0x77, 0x2e, 0x65, 0x6e, 0x74, 0x72, 0x75, 0x73,
	0x74, 0x2e, 0x6e, 0x65, 0x74, 0x2f, 0x43, 0x50, 0x53, 0x5f, 0x32, 0x30, 0x34, 0x38, 0x20, 0x69,
	0x6e, 0x63, 0x6f, 0x72, 0x70, 0x2e, 0x20, 0x62, 0x79, 0x20, 0x72, 0x65, 0x66, 0x2e, 0x20, 0x28,
	0x6c, 0x69, 0x6d, 0x69, 0x74, 0x73, 0x20, 0x6c, 0x69, 0x61, 0x62, 0x2e, 0x29, 0x31, 0x25, 0x30,
	0x23, 0x06, 0x03, 0x55, 0x04, 0x0b, 0x13, 0x1c, 0x28, 0x63, 0x29, 0x20, 0x31, 0x39, 0x39, 0x39,
	0x20, 0x45, 0x6e, 0x74, 0x72, 0x75, 0x73, 0x74, 0x2e, 0x6e, 0x65, 0x74, 0x20, 0x4c, 0x69, 0x6d,
	0x69, 0x74, 0x65, 0x64, 0x31, 0x33, 0x30, 0x31, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x2a, 0x45,
	0x6e, 0x74, 0x72, 0x75, 0x73, 0x74, 0x2e, 0x6e, 0x65, 0x74, 0x20, 0x43, 0x65, 0x72, 0x74, 0x69,
	0x66, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x41, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69,
	0x74, 0x79, 0x20, 0x28, 0x32, 0x30, 0x34, 0x38, 0x29, 0x30, 0x1e, 0x17, 0x0d, 0x39, 0x39, 0x31,
	0x32, 0x32, 0x34, 0x31, 0x37, 0x35, 0x30, 0x35, 0x31, 0x5a, 0x17, 0x0d, 0x31, 0x39, 0x31, 0x32,
	0x32, 0x34, 0x31, 0x38, 0x32, 0x30, 0x35, 0x31, 0x5a, 0x30, 0x81, 0xb4, 0x31, 0x14, 0x30, 0x12,
	0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x0b, 0x45, 0x6e, 0x74, 0x72, 0x75, 0x73, 0x74, 0x2e, 0x6e,
	0x65, 0x74, 0x31, 0x40, 0x30, 0x3e, 0x06, 0x03, 0x55, 0x04, 0x0b, 0x14, 0x37, 0x77, 0x77, 0x77,
	0x2e, 0x65, 0x6e, 0x74, 0x72, 0x75, 0x73, 0x74, 0x2e, 0x6e, 0x65, 0x74, 0x2f, 0x43, 0x50, 0x53,
	0x5f, 0x32, 0x30, 0x34, 0x38, 0x20, 0x69, 0x6e, 0x63, 0x6f, 0x72, 0x70, 0x2e, 0x20, 0x62, 0x79,
	0x20, 0x72, 0x65, 0x66, 0x2e, 0x20, 0x28, 0x6c, 0x69, 0x6d, 0x69, 0x74, 0x73, 0x20, 0x6c, 0x69,
	0x61, 0x62, 0x2e, 0x29, 0x31, 0x25, 0x30, 0x23, 0x06, 0x03, 0x55, 0x04, 0x0b, 0x13, 0x1c, 0x28,
	0x63, 0x29, 0x20, 0x31, 0x39, 0x39, 0x39, 0x20, 0x45, 0x6e, 0x74, 0x72, 0x75, 0x73, 0x74, 0x2e,
	0x6e, 0x65, 0x74, 0x20, 0x4c, 0x69, 0x6d, 0x69, 0x74, 0x65, 0x64, 0x31, 0x33, 0x30, 0x31, 0x06,
	0x03, 0x55, 0x04, 0x03, 0x13, 0x2a, 0x45, 0x6e, 0x74, 0x72, 0x75, 0x73, 0x74, 0x2e, 0x6e, 0x65,
	0x74, 0x20, 0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x20,
	0x41, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x74, 0x79, 0x20, 0x28, 0x32, 0x30, 0x34, 0x38, 0x29,
	0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
	0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00, 0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01,
	0x00, 0xad, 0x4d, 0x4b, 0xa9, 0x12, 0x86, 0xb2, 0xea, 0xa3, 0x20, 0x07, 0x15, 0x16, 0x64, 0x2a,
	0x2b, 0x4b, 0xd1, 0xbf, 0x0b, 0x4a, 0x4d, 0x8e, 0xed, 0x80, 0x76, 0xa5, 0x67, 0xb7, 0x78, 0x40,
	0xc0, 0x73, 0x42, 0xc8, 0x68, 0xc0, 0xdb, 0x53, 0x2b, 0xdd, 0x5e, 0xb8, 0x76, 0x98, 0x35, 0x93,
	0x8b, 0x1a, 0x9d, 0x7c, 0x13, 0x3a, 0x0e, 0x1f, 0x5b, 0xb7, 0x1e, 0xcf, 0xe5, 0x24, 0x14, 0x1e,
	0xb1, 0x81, 0xa9, 0x8d, 0x7d, 0xb8, 0xcc, 0x6b, 0x4b, 0x03, 0xf1, 0x02, 0x0c, 0xdc, 0xab, 0xa5,
	0x40, 0x24, 0x00, 0x7f, 0x74, 0x94, 0xa1, 0x9d, 0x08, 0x29, 0xb3, 0x88, 0x0b, 0xf5, 0x87, 0x77,
	0x9d, 0x55, 0xcd, 0xe4, 0xc3, 0x7e, 0xd7, 0x6a, 0x64, 0xab, 0x85, 0x14, 0x86, 0x95, 0x5b, 0x97,
	0x32, 0x50, 0x6f, 0x3d, 0xc8, 0xba, 0x66, 0x0c, 0xe3, 0xfc, 0xbd, 0xb8, 0x49, 0xc1, 0x76, 0x89,
	0x49, 0x19, 0xfd, 0xc0, 0xa8, 0xbd, 0x89, 0xa3, 0x67, 0x2f, 0xc6, 0x9f, 0xbc, 0x71, 0x19, 0x60,
	0xb8, 0x2d, 0xe9, 0x2c, 0xc9, 0x90, 0x76, 0x66, 0x7b, 0x94, 0xe2, 0xaf, 0x78, 0xd6, 0x65, 0x53,
	0x5d, 0x3c, 0xd6, 0x9c, 0xb2, 0xcf, 0x29, 0x03, 0xf9, 0x2f, 0xa4, 0x50, 0xb2, 0xd4, 0x48, 0xce,
	0x05, 0x32, 0x55, 0x8a, 0xfd, 0xb2, 0x64, 0x4c, 0x0e, 0xe4, 0x98, 0x07, 0x75, 0xdb, 0x7f, 0xdf,
	0xb9, 0x08, 0x55, 0x60, 0x85, 0x30, 0x29, 0xf9, 0x7b, 0x48, 0xa4, 0x69, 0x86, 0xe3, 0x35, 0x3f,
	0x1e, 0x86, 0x5d, 0x7a, 0x7a, 0x15, 0xbd, 0xef, 0x00, 0x8e, 0x15, 0x22, 0x54, 0x17, 0x00, 0x90,
	0x26, 0x93, 0xbc, 0x0e, 0x49, 0x68, 0x91, 0xbf, 0xf8, 0x47, 0xd3, 0x9d, 0x95, 0x42, 0xc1, 0x0e,
	0x4d, 0xdf, 0x6f, 0x26, 0xcf, 0xc3, 0x18, 0x21, 0x62, 0x66, 0x43, 0x70, 0xd6, 0xd5, 0xc0, 0x07,
	0xe1, 0x02, 0x03, 0x01, 0x00, 0x01, 0xa3, 0x74, 0x30, 0x72, 0x30, 0x11, 0x06, 0x09, 0x60, 0x86,
	0x48, 0x01, 0x86, 0xf8, 0x42, 0x01, 0x01, 0x04, 0x04, 0x03, 0x02, 0x00, 0x07, 0x30, 0x1f, 0x06,
	0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0x55, 0xe4, 0x81, 0xd1, 0x11, 0x80,
	0xbe, 0xd8, 0x89, 0xb9, 0x08, 0xa3, 0x31, 0xf9, 0xa1, 0x24, 0x09, 0x16, 0xb9, 0x70, 0x30, 0x1d,
	0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0x55, 0xe4, 0x81, 0xd1, 0x11, 0x80, 0xbe,
	0xd8, 0x89, 0xb9, 0x08, 0xa3, 0x31, 0xf9, 0xa1, 0x24, 0x09, 0x16, 0xb9, 0x70, 0x30, 0x1d, 0x06,
	0x09, 0x2a, 0x86, 0x48, 0x86, 0xf6, 0x7d, 0x07, 0x41, 0x00, 0x04, 0x10, 0x30, 0x0e, 0x1b, 0x08,
	0x56, 0x35, 0x2e, 0x30, 0x3a, 0x34, 0x2e, 0x30, 0x03, 0x02, 0x04, 0x90, 0x30, 0x0d, 0x06, 0x09,
	0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05, 0x05, 0x00, 0x03, 0x82, 0x01, 0x01, 0x00,
	0x59, 0x47, 0xac, 0x21, 0x84, 0x8a, 0x17, 0xc9, 0x9c, 0x89, 0x53, 0x1e, 0xba, 0x80, 0x85, 0x1a,
	0xc6, 0x3c, 0x4e, 0x3e, 0xb1, 0x9c, 0xb6, 0x7c, 0xc6, 0x92, 0x5d, 0x18, 0x64, 0x02, 0xe3, 0xd3,
	0x06, 0x08, 0x11, 0x61, 0x7c, 0x63, 0xe3, 0x2b, 0x9d, 0x31, 0x03, 0x70, 0x76, 0xd2, 0xa3, 0x28,
	0xa0, 0xf4, 0xbb, 0x9a, 0x63, 0x73, 0xed, 0x6d, 0xe5, 0x2a, 0xdb, 0xed, 0x14, 0xa9, 0x2b, 0xc6,
	0x36, 0x11, 0xd0, 0x2b, 0xeb, 0x07, 0x8b, 0xa5, 0xda, 0x9e, 0x5c, 0x19, 0x9d, 0x56, 0x12, 0xf5,
	0x54, 0x29, 0xc8, 0x05, 0xed, 0xb2, 0x12, 0x2a, 0x8d, 0xf4, 0x03, 0x1b, 0xff, 0xe7, 0x92, 0x10,
	0x87, 0xb0, 0x3a, 0xb5, 0xc3, 0x9d, 0x05, 0x37, 0x12, 0xa3, 0xc7, 0xf4, 0x15, 0xb9, 0xd5, 0xa4,
	0x39, 0x16, 0x9b, 0x53, 0x3a, 0x23, 0x91, 0xf1, 0xa8, 0x82, 0xa2, 0x6a, 0x88, 0x68, 0xc1, 0x79,
	0x02, 0x22, 0xbc, 0xaa, 0xa6, 0xd6, 0xae, 0xdf, 0xb0, 0x14, 0x5f, 0xb8, 0x87, 0xd0, 0xdd, 0x7c,
	0x7f, 0x7b, 0xff, 0xaf, 0x1c, 0xcf, 0xe6, 0xdb, 0x07, 0xad, 0x5e, 0xdb, 0x85, 0x9d, 0xd0, 0x2b,
	0x0d, 0x33, 0xdb, 0x04, 0xd1, 0xe6, 0x49, 0x40, 0x13, 0x2b, 0x76, 0xfb, 0x3e, 0xe9, 0x9c, 0x89,
	0x0f, 0x15, 0xce, 0x18, 0xb0, 0x85, 0x78, 0x21, 0x4f, 0x6b, 0x4f, 0x0e, 0xfa, 0x36, 0x67, 0xcd,
	0x07, 0xf2, 0xff, 0x08, 0xd0, 0xe2, 0xde, 0xd9, 0xbf, 0x2a, 0xaf, 0xb8, 0x87, 0x86, 0x21, 0x3c,
	0x04, 0xca, 0xb7, 0x94, 0x68, 0x7f, 0xcf, 0x3c, 0xe9, 0x98, 0xd7, 0x38, 0xff, 0xec, 0xc0, 0xd9,
	0x50, 0xf0, 0x2e, 0x4b, 0x58, 0xae, 0x46, 0x6f, 0xd0, 0x2e, 0xc3, 0x60, 0xda, 0x72, 0x55, 0x72,
	0xbd, 0x4c, 0x45, 0x9e, 0x61, 0xba, 0xbf, 0x84, 0x81, 0x92, 0x03, 0xd1, 0xd2, 0x69, 0x7c, 0xc5,
};

static const unsigned char entrust_public_key[] = {
	0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
	0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00, 0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01,
	0x00, 0xad, 0x4d, 0x4b, 0xa9, 0x12, 0x86, 0xb2, 0xea, 0xa3, 0x20, 0x07, 0x15, 0x16, 0x64, 0x2a,
	0x2b, 0x4b, 0xd1, 0xbf, 0x0b, 0x4a, 0x4d, 0x8e, 0xed, 0x80, 0x76, 0xa5, 0x67, 0xb7, 0x78, 0x40,
	0xc0, 0x73, 0x42, 0xc8, 0x68, 0xc0, 0xdb, 0x53, 0x2b, 0xdd, 0x5e, 0xb8, 0x76, 0x98, 0x35, 0x93,
	0x8b, 0x1a, 0x9d, 0x7c, 0x13, 0x3a, 0x0e, 0x1f, 0x5b, 0xb7, 0x1e, 0xcf, 0xe5, 0x24, 0x14, 0x1e,
	0xb1, 0x81, 0xa9, 0x8d, 0x7d, 0xb8, 0xcc, 0x6b, 0x4b, 0x03, 0xf1, 0x02, 0x0c, 0xdc, 0xab, 0xa5,
	0x40, 0x24, 0x00, 0x7f, 0x74, 0x94, 0xa1, 0x9d, 0x08, 0x29, 0xb3, 0x88, 0x0b, 0xf5, 0x87, 0x77,
	0x9d, 0x55, 0xcd, 0xe4, 0xc3, 0x7e, 0xd7, 0x6a, 0x64, 0xab, 0x85, 0x14, 0x86, 0x95, 0x5b, 0x97,
	0x32, 0x50, 0x6f, 0x3d, 0xc8, 0xba, 0x66, 0x0c, 0xe3, 0xfc, 0xbd, 0xb8, 0x49, 0xc1, 0x76, 0x89,
	0x49, 0x19, 0xfd, 0xc0, 0xa8, 0xbd, 0x89, 0xa3, 0x67, 0x2f, 0xc6, 0x9f, 0xbc, 0x71, 0x19, 0x60,
	0xb8, 0x2d, 0xe9, 0x2c, 0xc9, 0x90, 0x76, 0x66, 0x7b, 0x94, 0xe2, 0xaf, 0x78, 0xd6, 0x65, 0x53,
	0x5d, 0x3c, 0xd6, 0x9c, 0xb2, 0xcf, 0x29, 0x03, 0xf9, 0x2f, 0xa4, 0x50, 0xb2, 0xd4, 0x48, 0xce,
	0x05, 0x32, 0x55, 0x8a, 0xfd, 0xb2, 0x64, 0x4c, 0x0e, 0xe4, 0x98, 0x07, 0x75, 0xdb, 0x7f, 0xdf,
	0xb9, 0x08, 0x55, 0x60, 0x85, 0x30, 0x29, 0xf9, 0x7b, 0x48, 0xa4, 0x69, 0x86, 0xe3, 0x35, 0x3f,
	0x1e, 0x86, 0x5d, 0x7a, 0x7a, 0x15, 0xbd, 0xef, 0x00, 0x8e, 0x15, 0x22, 0x54, 0x17, 0x00, 0x90,
	0x26, 0x93, 0xbc, 0x0e, 0x49, 0x68, 0x91, 0xbf, 0xf8, 0x47, 0xd3, 0x9d, 0x95, 0x42, 0xc1, 0x0e,
	0x4d, 0xdf, 0x6f, 0x26, 0xcf, 0xc3, 0x18, 0x21, 0x62, 0x66, 0x43, 0x70, 0xd6, 0xd5, 0xc0, 0x07,
	0xe1, 0x02, 0x03, 0x01, 0x00, 0x01,
};

static void
test_build_certificate_non_ca (void)
{
	CK_ATTRIBUTE input[] = {
		{ CKA_CLASS, &certificate, sizeof (certificate) },
		{ CKA_CERTIFICATE_TYPE, &x509, sizeof (x509) },
		{ CKA_VALUE, (void *)entrust_pretend_ca, sizeof (entrust_pretend_ca) },
		{ CKA_INVALID },
	};

	CK_ATTRIBUTE expected[] = {
		{ CKA_CERTIFICATE_CATEGORY, &other_entity, sizeof (other_entity) },
		{ CKA_INVALID },
	};

	CK_ATTRIBUTE *attrs;
	CK_ATTRIBUTE *extra;
	CK_RV rv;

	attrs = NULL;
	extra = NULL;
	rv = p11_builder_build (test.builder, test.index, attrs, input, &extra);
	assert_num_eq (CKR_OK, rv);

	attrs = p11_attrs_merge (attrs, p11_attrs_dup (input), true);
	attrs = p11_attrs_merge (attrs, extra, false);

	test_check_attrs (expected, attrs);
	p11_attrs_free (attrs);
}

static void
test_build_certificate_v1_ca (void)
{
	CK_ATTRIBUTE input[] = {
		{ CKA_CLASS, &certificate, sizeof (certificate) },
		{ CKA_CERTIFICATE_TYPE, &x509, sizeof (x509) },
		{ CKA_VALUE, (void *)verisign_v1_ca, sizeof (verisign_v1_ca) },
		{ CKA_INVALID },
	};

	CK_ATTRIBUTE expected[] = {
		{ CKA_CERTIFICATE_CATEGORY, &certificate_authority, sizeof (certificate_authority) },
		{ CKA_INVALID },
	};

	CK_ATTRIBUTE *attrs;
	CK_ATTRIBUTE *extra;
	CK_RV rv;

	attrs = NULL;
	extra = NULL;
	rv = p11_builder_build (test.builder, test.index, attrs, input, &extra);
	assert_num_eq (CKR_OK, rv);

	attrs = p11_attrs_merge (attrs, p11_attrs_dup (input), true);
	attrs = p11_attrs_merge (attrs, extra, false);

	test_check_attrs (expected, attrs);
	p11_attrs_free (attrs);
}

static void
test_build_certificate_staple_ca (void)
{
	CK_ULONG category = 2; /* CA */

	CK_ATTRIBUTE attached[] = {
		{ CKA_CLASS, &certificate_extension, sizeof (certificate_extension) },
		{ CKA_OBJECT_ID, (void *)P11_OID_BASIC_CONSTRAINTS, sizeof (P11_OID_BASIC_CONSTRAINTS) },
		{ CKA_VALUE, "\x30\x0f\x06\x03\x55\x1d\x13\x01\x01\xff\x04\x05\x30\x03\x01\x01\xff", 17 },
		{ CKA_PUBLIC_KEY_INFO, (void *)entrust_public_key, sizeof (entrust_public_key) },
		{ CKA_INVALID },
	};

	CK_ATTRIBUTE input[] = {
		{ CKA_CLASS, &certificate, sizeof (certificate) },
		{ CKA_CERTIFICATE_TYPE, &x509, sizeof (x509) },
		{ CKA_VALUE, (void *)entrust_pretend_ca, sizeof (entrust_pretend_ca) },
		{ CKA_INVALID },
	};

	CK_ATTRIBUTE expected[] = {
		{ CKA_CERTIFICATE_CATEGORY, &category, sizeof (category) },
		{ CKA_INVALID },
	};

	CK_ATTRIBUTE *attrs;
	CK_ATTRIBUTE *extra;
	CK_RV rv;

	/* Adding the attached extension *first*, and then the certificate */

	/* Add a attached certificate */
	rv = p11_index_add (test.index, attached, 4, NULL);
	assert_num_eq (CKR_OK, rv);

	attrs = NULL;
	extra = NULL;
	rv = p11_builder_build (test.builder, test.index, attrs, input, &extra);
	assert_num_eq (CKR_OK, rv);

	attrs = p11_attrs_merge (attrs, p11_attrs_dup (input), true);
	attrs = p11_attrs_merge (attrs, extra, false);

	/*
	 * Even though the certificate is not a valid CA, the presence of the
	 * attached certificate extension transforms it into a CA.
	 */
	test_check_attrs (expected, attrs);
	p11_attrs_free (attrs);
}

static void
test_build_certificate_staple_ca_backwards (void)
{
	CK_ULONG category = 2; /* CA */

	CK_ATTRIBUTE attached[] = {
		{ CKA_CLASS, &certificate_extension, sizeof (certificate_extension) },
		{ CKA_OBJECT_ID, (void *)P11_OID_BASIC_CONSTRAINTS, sizeof (P11_OID_BASIC_CONSTRAINTS) },
		{ CKA_VALUE, "\x30\x0f\x06\x03\x55\x1d\x13\x01\x01\xff\x04\x05\x30\x03\x01\x01\xff", 17 },
		{ CKA_PUBLIC_KEY_INFO, (void *)entrust_public_key, sizeof (entrust_public_key) },
		{ CKA_INVALID },
	};

	CK_ATTRIBUTE input[] = {
		{ CKA_CLASS, &certificate, sizeof (certificate) },
		{ CKA_CERTIFICATE_TYPE, &x509, sizeof (x509) },
		{ CKA_VALUE, (void *)entrust_pretend_ca, sizeof (entrust_pretend_ca) },
		{ CKA_INVALID },
	};

	CK_ATTRIBUTE expected[] = {
		{ CKA_CERTIFICATE_CATEGORY, &category, sizeof (category) },
		{ CKA_INVALID },
	};

	CK_RV rv;
	CK_ATTRIBUTE *attrs;
	CK_OBJECT_HANDLE handle;

	/* Adding the certificate *first*, and then the attached extension */

	rv = p11_index_add (test.index, input, 4, &handle);
	assert_num_eq (CKR_OK, rv);

	/* Add a attached certificate */
	rv = p11_index_add (test.index, attached, 4, NULL);
	assert_num_eq (CKR_OK, rv);

	/*
	 * Even though the certificate is not a valid CA, the presence of the
	 * attached certificate extension transforms it into a CA.
	 */
	attrs = p11_index_lookup (test.index, handle);
	test_check_attrs (expected, attrs);
}

static void
test_build_certificate_no_type (void)
{
	CK_ATTRIBUTE input[] = {
		{ CKA_CLASS, &certificate, sizeof (certificate) },
		{ CKA_INVALID },
	};

	CK_ATTRIBUTE *attrs;
	CK_ATTRIBUTE *merge;
	CK_ATTRIBUTE *extra;
	CK_RV rv;

	p11_message_quiet ();

	attrs = NULL;
	extra = NULL;
	merge = p11_attrs_dup (input);
	rv = p11_builder_build (test.builder, test.index, attrs, merge, &extra);
	assert_num_eq (CKR_TEMPLATE_INCOMPLETE, rv);
	p11_attrs_free (merge);

	p11_message_loud ();
}

static void
test_build_certificate_bad_type (void)
{
	CK_CERTIFICATE_TYPE type = CKC_WTLS;

	CK_ATTRIBUTE input[] = {
		{ CKA_CLASS, &certificate, sizeof (certificate) },
		{ CKA_CERTIFICATE_TYPE, &type, sizeof (type) },
		{ CKA_INVALID },
	};

	CK_ATTRIBUTE *attrs;
	CK_ATTRIBUTE *merge;
	CK_ATTRIBUTE *extra;
	CK_RV rv;

	p11_message_quiet ();

	attrs = NULL;
	merge = p11_attrs_dup (input);
	rv = p11_builder_build (test.builder, test.index, attrs, merge, &extra);
	assert_num_eq (CKR_TEMPLATE_INCONSISTENT, rv);
	p11_attrs_free (merge);

	p11_message_loud ();
}

static void
test_build_extension (void)
{
	CK_ATTRIBUTE input[] = {
		{ CKA_CLASS, &certificate_extension, sizeof (certificate_extension) },
		{ CKA_PUBLIC_KEY_INFO, (void *)test_cacert3_ca_public_key, sizeof (test_cacert3_ca_public_key) },
		{ CKA_VALUE, "\x30\x11\x06\x03\x55\x1d\x50\x04\x0a\x74\x68\x65\x20\x76\x61\x6c\x75\x65\x0a", 19 },
		{ CKA_INVALID },
	};

	CK_ATTRIBUTE check[] = {
		{ CKA_CLASS, &certificate_extension, sizeof (certificate_extension) },
		{ CKA_TOKEN, &truev, sizeof (truev) },
		{ CKA_MODIFIABLE, &falsev, sizeof (falsev) },
		{ CKA_PRIVATE, &falsev, sizeof (falsev) },
		{ CKA_OBJECT_ID, "\x06\x03\x55\x1d\x50", 5 },
		{ CKA_VALUE, "\x30\x11\x06\x03\x55\x1d\x50\x04\x0a\x74\x68\x65\x20\x76\x61\x6c\x75\x65\x0a", 19 },
		{ CKA_PUBLIC_KEY_INFO, (void *)test_cacert3_ca_public_key, sizeof (test_cacert3_ca_public_key) },
		{ CKA_LABEL, "", 0 },
		{ CKA_INVALID },
	};

	CK_ATTRIBUTE *attrs;
	CK_ATTRIBUTE *extra;
	CK_RV rv;

	attrs = NULL;
	extra = NULL;
	rv = p11_builder_build (test.builder, test.index, attrs, input, &extra);
	assert_num_eq (CKR_OK, rv);

	attrs = p11_attrs_merge (attrs, p11_attrs_dup (input), true);
	attrs = p11_attrs_merge (attrs, extra, false);

	test_check_attrs (check, attrs);
	p11_attrs_free (attrs);
}

/* This certificate has and end date in 2067 */
static const unsigned char cert_distant_end_date[] = {
	0x30, 0x82, 0x01, 0x6a, 0x30, 0x82, 0x01, 0x14, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x02, 0x03,
	0xe7, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05, 0x05, 0x00,
	0x30, 0x28, 0x31, 0x26, 0x30, 0x24, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x1d, 0x66, 0x61, 0x72,
	0x2d, 0x69, 0x6e, 0x2d, 0x74, 0x68, 0x65, 0x2d, 0x66, 0x75, 0x74, 0x75, 0x72, 0x65, 0x2e, 0x65,
	0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x30, 0x20, 0x17, 0x0d, 0x31, 0x33,
	0x30, 0x33, 0x32, 0x37, 0x31, 0x36, 0x34, 0x39, 0x33, 0x33, 0x5a, 0x18, 0x0f, 0x32, 0x30, 0x36,
	0x37, 0x31, 0x32, 0x32, 0x39, 0x31, 0x36, 0x34, 0x39, 0x33, 0x33, 0x5a, 0x30, 0x28, 0x31, 0x26,
	0x30, 0x24, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x1d, 0x66, 0x61, 0x72, 0x2d, 0x69, 0x6e, 0x2d,
	0x74, 0x68, 0x65, 0x2d, 0x66, 0x75, 0x74, 0x75, 0x72, 0x65, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70,
	0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x30, 0x5c, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
	0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x4b, 0x00, 0x30, 0x48, 0x02, 0x41, 0x00, 0xe2,
	0x2d, 0x35, 0x70, 0x75, 0xc0, 0x07, 0x56, 0x40, 0x7d, 0x63, 0xbc, 0xd2, 0x60, 0xb3, 0xcf, 0xb8,
	0x3d, 0x27, 0x6e, 0x10, 0xcd, 0x42, 0x50, 0x51, 0x9d, 0x79, 0x30, 0x79, 0x5a, 0xe3, 0xc3, 0x51,
	0x38, 0x85, 0x4c, 0xb4, 0x91, 0xd9, 0xe6, 0x8d, 0x69, 0x6a, 0xd4, 0x9c, 0x1c, 0x49, 0xc2, 0x25,
	0x2a, 0xc9, 0x2b, 0xf2, 0xf4, 0x8e, 0x8a, 0x3f, 0x8b, 0x4c, 0x97, 0xc3, 0x16, 0x96, 0x99, 0x02,
	0x03, 0x01, 0x00, 0x01, 0xa3, 0x26, 0x30, 0x24, 0x30, 0x22, 0x06, 0x03, 0x55, 0x1d, 0x25, 0x04,
	0x1b, 0x30, 0x19, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02, 0x06, 0x08, 0x2b,
	0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x04, 0x06, 0x03, 0x2a, 0x03, 0x04, 0x30, 0x0d, 0x06, 0x09,
	0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05, 0x05, 0x00, 0x03, 0x41, 0x00, 0xc2, 0x83,
	0x27, 0x32, 0x80, 0x74, 0x73, 0xe2, 0xa3, 0x92, 0xaa, 0x7c, 0xd8, 0x50, 0xf4, 0x61, 0x50, 0xb1,
	0x63, 0x9e, 0x29, 0xef, 0x38, 0x1d, 0xc0, 0x55, 0x20, 0x0f, 0x7e, 0xe9, 0x1f, 0xa1, 0x54, 0x1a,
	0x5f, 0x8c, 0x26, 0x1b, 0x66, 0x96, 0x0e, 0x64, 0x52, 0x1c, 0x00, 0x96, 0xfb, 0x81, 0x77, 0xa2,
	0x3a, 0x1d, 0x49, 0x0c, 0x03, 0xd5, 0x19, 0xf2, 0x6a, 0x01, 0x29, 0x31, 0xfb, 0xf5,
};

static void
test_build_distant_end_date (void)
{
	CK_ATTRIBUTE input[] = {
		{ CKA_CLASS, &certificate, sizeof (certificate) },
		{ CKA_CERTIFICATE_TYPE, &x509, sizeof (x509) },
		{ CKA_VALUE, (void *)cert_distant_end_date, sizeof (cert_distant_end_date) },
		{ CKA_INVALID },
	};

	CK_ATTRIBUTE expected[] = {
		{ CKA_END_DATE, "20671229", 8 },
		{ CKA_START_DATE, "20130327", 8 },
		{ CKA_INVALID },
	};

	CK_ATTRIBUTE *attrs;
	CK_ATTRIBUTE *extra;
	CK_RV rv;

	attrs = NULL;
	extra = NULL;
	rv = p11_builder_build (test.builder, test.index, attrs, input, &extra);
	assert_num_eq (CKR_OK, rv);

	attrs = p11_attrs_merge (attrs, p11_attrs_dup (input), true);
	attrs = p11_attrs_merge (attrs, extra, false);

	test_check_attrs (expected, attrs);
	p11_attrs_free (attrs);
}

static void
test_valid_bool (void)
{
	CK_ATTRIBUTE *attrs = NULL;
	CK_ATTRIBUTE *extra = NULL;
	CK_BBOOL value = CK_TRUE;
	CK_RV rv;

	CK_ATTRIBUTE input[] = {
		{ CKA_PRIVATE, &value, sizeof (value) },
		{ CKA_CLASS, &certificate, sizeof (certificate) },
		{ CKA_CERTIFICATE_TYPE, &x509, sizeof (x509) },
		{ CKA_INVALID },
	};

	rv = p11_builder_build (test.builder, test.index, attrs, input, &extra);
	assert_num_eq (CKR_OK, rv);

	p11_attrs_free (extra);
}

static void
test_invalid_bool (void)
{
	CK_ATTRIBUTE *attrs = NULL;
	CK_ATTRIBUTE *extra = NULL;
	CK_RV rv;

	CK_ATTRIBUTE input[] = {
		{ CKA_PRIVATE, NULL, 0 },
		{ CKA_CLASS, &certificate, sizeof (certificate) },
		{ CKA_CERTIFICATE_TYPE, &x509, sizeof (x509) },
		{ CKA_INVALID },
	};

	p11_message_quiet ();

	input[0].pValue = "123";
	input[0].ulValueLen = 3;
	rv = p11_builder_build (test.builder, test.index, attrs, input, &extra);
	assert_num_eq (CKR_ATTRIBUTE_VALUE_INVALID, rv);


	input[0].pValue = NULL;
	input[0].ulValueLen = sizeof (CK_BBOOL);
	rv = p11_builder_build (test.builder, test.index, attrs, input, &extra);
	assert_num_eq (CKR_ATTRIBUTE_VALUE_INVALID, rv);

	p11_message_loud ();
}

static void
test_valid_ulong (void)
{
	CK_ATTRIBUTE *attrs = NULL;
	CK_ATTRIBUTE *extra = NULL;
	CK_ULONG value = 2;
	CK_RV rv;

	CK_ATTRIBUTE input[] = {
		{ CKA_CERTIFICATE_CATEGORY, &value, sizeof (value) },
		{ CKA_CLASS, &certificate, sizeof (certificate) },
		{ CKA_CERTIFICATE_TYPE, &x509, sizeof (x509) },
		{ CKA_INVALID },
	};

	rv = p11_builder_build (test.builder, test.index, attrs, input, &extra);
	assert_num_eq (CKR_OK, rv);

	p11_attrs_free (extra);
}

static void
test_invalid_ulong (void)
{
	CK_ATTRIBUTE *attrs = NULL;
	CK_ATTRIBUTE *extra = NULL;
	CK_RV rv;

	CK_ATTRIBUTE input[] = {
		{ CKA_CERTIFICATE_CATEGORY, NULL, 0 },
		{ CKA_CLASS, &certificate, sizeof (certificate) },
		{ CKA_CERTIFICATE_TYPE, &x509, sizeof (x509) },
		{ CKA_INVALID },
	};

	p11_message_quiet ();

	input[0].pValue = "123";
	input[0].ulValueLen = 3;
	rv = p11_builder_build (test.builder, test.index, attrs, input, &extra);
	assert_num_eq (CKR_ATTRIBUTE_VALUE_INVALID, rv);


	input[0].pValue = NULL;
	input[0].ulValueLen = sizeof (CK_ULONG);
	rv = p11_builder_build (test.builder, test.index, attrs, input, &extra);
	assert_num_eq (CKR_ATTRIBUTE_VALUE_INVALID, rv);

	p11_message_loud ();
}

static void
test_valid_utf8 (void)
{
	CK_ATTRIBUTE *attrs = NULL;
	CK_ATTRIBUTE *extra = NULL;
	CK_RV rv;

	CK_ATTRIBUTE input[] = {
		{ CKA_LABEL, NULL, 0 },
		{ CKA_CLASS, &certificate, sizeof (certificate) },
		{ CKA_CERTIFICATE_TYPE, &x509, sizeof (x509) },
		{ CKA_INVALID },
	};

	input[0].pValue = NULL;
	input[0].ulValueLen = 0;
	rv = p11_builder_build (test.builder, test.index, attrs, input, &extra);
	assert_num_eq (CKR_OK, rv);

	p11_attrs_free (extra);
}

static void
test_invalid_utf8 (void)
{
	CK_ATTRIBUTE *attrs = NULL;
	CK_ATTRIBUTE *extra = NULL;
	CK_RV rv;

	CK_ATTRIBUTE input[] = {
		{ CKA_LABEL, NULL, 0 },
		{ CKA_CLASS, &certificate, sizeof (certificate) },
		{ CKA_CERTIFICATE_TYPE, &x509, sizeof (x509) },
		{ CKA_INVALID },
	};

	p11_message_quiet ();

	input[0].pValue = "\xfex23";
	input[0].ulValueLen = 4;
	rv = p11_builder_build (test.builder, test.index, attrs, input, &extra);
	assert_num_eq (CKR_ATTRIBUTE_VALUE_INVALID, rv);


	input[0].pValue = NULL;
	input[0].ulValueLen = 4;
	rv = p11_builder_build (test.builder, test.index, attrs, input, &extra);
	assert_num_eq (CKR_ATTRIBUTE_VALUE_INVALID, rv);

	p11_message_loud ();
}

static void
test_valid_dates (void)
{
	CK_ATTRIBUTE *attrs = NULL;
	CK_ATTRIBUTE *extra = NULL;
	CK_DATE date;
	CK_RV rv;

	CK_ATTRIBUTE input[] = {
		{ CKA_START_DATE, &date, sizeof (CK_DATE) },
		{ CKA_CLASS, &certificate, sizeof (certificate) },
		{ CKA_CERTIFICATE_TYPE, &x509, sizeof (x509) },
		{ CKA_INVALID },
	};

	memcpy (date.year, "2000", sizeof (date.year));
	memcpy (date.month, "10", sizeof (date.month));
	memcpy (date.day, "10", sizeof (date.day));
	rv = p11_builder_build (test.builder, test.index, attrs, input, &extra);
	assert_num_eq (CKR_OK, rv);

	p11_attrs_free (extra);
	p11_attrs_free (attrs);
	attrs = NULL;

	input[0].ulValueLen = 0;
	rv = p11_builder_build (test.builder, test.index, attrs, input, &extra);
	assert_num_eq (CKR_OK, rv);

	p11_attrs_free (extra);
	p11_attrs_free (attrs);
}

static void
test_invalid_dates (void)
{
	CK_ATTRIBUTE *attrs = NULL;
	CK_ATTRIBUTE *extra = NULL;
	CK_DATE date;
	CK_RV rv;

	CK_ATTRIBUTE input[] = {
		{ CKA_START_DATE, &date, sizeof (CK_DATE) },
		{ CKA_CLASS, &certificate, sizeof (certificate) },
		{ CKA_CERTIFICATE_TYPE, &x509, sizeof (x509) },
		{ CKA_INVALID },
	};

	p11_message_quiet ();

	memcpy (date.year, "AAAA", sizeof (date.year));
	memcpy (date.month, "BB", sizeof (date.month));
	memcpy (date.day, "CC", sizeof (date.day));
	rv = p11_builder_build (test.builder, test.index, attrs, input, &extra);
	assert_num_eq (CKR_ATTRIBUTE_VALUE_INVALID, rv);

	memcpy (date.year, "2000", sizeof (date.year));
	memcpy (date.month, "15", sizeof (date.month));
	memcpy (date.day, "80", sizeof (date.day));
	rv = p11_builder_build (test.builder, test.index, attrs, input, &extra);
	assert_num_eq (CKR_ATTRIBUTE_VALUE_INVALID, rv);

	input[0].pValue = NULL;
	rv = p11_builder_build (test.builder, test.index, attrs, input, &extra);
	assert_num_eq (CKR_ATTRIBUTE_VALUE_INVALID, rv);

	p11_message_loud ();
}

static void
test_valid_name (void)
{
	CK_ATTRIBUTE *attrs = NULL;
	CK_ATTRIBUTE *extra = NULL;
	CK_RV rv;

	CK_ATTRIBUTE input[] = {
		{ CKA_SUBJECT, NULL, 0 },
		{ CKA_CLASS, &certificate, sizeof (certificate) },
		{ CKA_CERTIFICATE_TYPE, &x509, sizeof (x509) },
		{ CKA_INVALID },
	};

	input[0].pValue = NULL;
	input[0].ulValueLen = 0;
	rv = p11_builder_build (test.builder, test.index, attrs, input, &extra);
	assert_num_eq (CKR_OK, rv);

	p11_attrs_free (extra);
	p11_attrs_free (attrs);
	attrs = NULL;

	input[0].pValue = (void *)test_cacert3_ca_issuer;
	input[0].ulValueLen = sizeof (test_cacert3_ca_issuer);
	rv = p11_builder_build (test.builder, test.index, attrs, input, &extra);
	assert_num_eq (CKR_OK, rv);

	p11_attrs_free (extra);
	p11_attrs_free (attrs);
}

static void
test_invalid_name (void)
{
	CK_ATTRIBUTE *attrs = NULL;
	CK_ATTRIBUTE *extra = NULL;
	CK_RV rv;

	CK_ATTRIBUTE input[] = {
		{ CKA_SUBJECT, NULL, 0 },
		{ CKA_CLASS, &certificate, sizeof (certificate) },
		{ CKA_CERTIFICATE_TYPE, &x509, sizeof (x509) },
		{ CKA_INVALID },
	};

	p11_message_quiet ();

	input[0].pValue = "blah";
	input[0].ulValueLen = 4;
	rv = p11_builder_build (test.builder, test.index, attrs, input, &extra);
	assert_num_eq (CKR_ATTRIBUTE_VALUE_INVALID, rv);

	input[0].pValue = NULL;
	input[0].ulValueLen = 4;
	rv = p11_builder_build (test.builder, test.index, attrs, input, &extra);
	assert_num_eq (CKR_ATTRIBUTE_VALUE_INVALID, rv);

	p11_message_loud ();
}

static void
test_valid_serial (void)
{
	CK_ATTRIBUTE *attrs = NULL;
	CK_ATTRIBUTE *extra = NULL;
	CK_RV rv;

	CK_ATTRIBUTE input[] = {
		{ CKA_SERIAL_NUMBER, NULL, 0 },
		{ CKA_CLASS, &certificate, sizeof (certificate) },
		{ CKA_CERTIFICATE_TYPE, &x509, sizeof (x509) },
		{ CKA_INVALID },
	};

	input[0].pValue = NULL;
	input[0].ulValueLen = 0;
	rv = p11_builder_build (test.builder, test.index, attrs, input, &extra);
	assert_num_eq (CKR_OK, rv);

	p11_attrs_free (extra);
	attrs = NULL;

	input[0].pValue = (void *)test_cacert3_ca_serial;
	input[0].ulValueLen = sizeof (test_cacert3_ca_serial);
	rv = p11_builder_build (test.builder, test.index, attrs, input, &extra);
	assert_num_eq (CKR_OK, rv);

	p11_attrs_free (extra);
}

static void
test_invalid_serial (void)
{
	CK_ATTRIBUTE *attrs = NULL;
	CK_ATTRIBUTE *extra = NULL;
	CK_RV rv;

	CK_ATTRIBUTE input[] = {
		{ CKA_SERIAL_NUMBER, NULL, 0 },
		{ CKA_CLASS, &certificate, sizeof (certificate) },
		{ CKA_CERTIFICATE_TYPE, &x509, sizeof (x509) },
		{ CKA_INVALID },
	};

	p11_message_quiet ();

	input[0].pValue = "blah";
	input[0].ulValueLen = 4;
	rv = p11_builder_build (test.builder, test.index, attrs, input, &extra);
	assert_num_eq (CKR_ATTRIBUTE_VALUE_INVALID, rv);

	input[0].pValue = (void *)test_cacert3_ca_subject;
	input[0].ulValueLen = sizeof (test_cacert3_ca_subject);
	rv = p11_builder_build (test.builder, test.index, attrs, input, &extra);
	assert_num_eq (CKR_ATTRIBUTE_VALUE_INVALID, rv);

	input[0].pValue = NULL;
	input[0].ulValueLen = 4;
	rv = p11_builder_build (test.builder, test.index, attrs, input, &extra);
	assert_num_eq (CKR_ATTRIBUTE_VALUE_INVALID, rv);

	p11_message_loud ();
}

static void
test_valid_cert (void)
{
	CK_ATTRIBUTE *attrs = NULL;
	CK_ATTRIBUTE *extra = NULL;
	CK_RV rv;

	CK_ATTRIBUTE input[] = {
		{ CKA_VALUE, NULL, 0 },
		{ CKA_CLASS, &certificate, sizeof (certificate) },
		{ CKA_CERTIFICATE_TYPE, &x509, sizeof (x509) },
		{ CKA_INVALID },
	};

	input[0].pValue = NULL;
	input[0].ulValueLen = 0;
	rv = p11_builder_build (test.builder, test.index, attrs, input, &extra);
	assert_num_eq (CKR_OK, rv);

	p11_attrs_free (extra);
	attrs = NULL;

	input[0].pValue = (void *)test_cacert3_ca_der;
	input[0].ulValueLen = sizeof (test_cacert3_ca_der);
	rv = p11_builder_build (test.builder, test.index, attrs, input, &extra);
	assert_num_eq (CKR_OK, rv);

	p11_attrs_free (extra);
}

static void
test_invalid_cert (void)
{
	CK_ATTRIBUTE *attrs = NULL;
	CK_ATTRIBUTE *extra = NULL;
	CK_RV rv;

	CK_ATTRIBUTE input[] = {
		{ CKA_VALUE, NULL, 0 },
		{ CKA_CLASS, &certificate, sizeof (certificate) },
		{ CKA_CERTIFICATE_TYPE, &x509, sizeof (x509) },
		{ CKA_INVALID },
	};

	p11_message_quiet ();

	input[0].pValue = "blah";
	input[0].ulValueLen = 4;
	rv = p11_builder_build (test.builder, test.index, attrs, input, &extra);
	assert_num_eq (CKR_ATTRIBUTE_VALUE_INVALID, rv);

	input[0].pValue = (void *)test_cacert3_ca_subject;
	input[0].ulValueLen = sizeof (test_cacert3_ca_subject);
	rv = p11_builder_build (test.builder, test.index, attrs, input, &extra);
	assert_num_eq (CKR_ATTRIBUTE_VALUE_INVALID, rv);

	input[0].pValue = NULL;
	input[0].ulValueLen = 4;
	rv = p11_builder_build (test.builder, test.index, attrs, input, &extra);
	assert_num_eq (CKR_ATTRIBUTE_VALUE_INVALID, rv);

	p11_message_loud ();
}

static void
test_invalid_schema (void)
{
	CK_ATTRIBUTE *attrs = NULL;
	CK_ATTRIBUTE *extra = NULL;
	CK_RV rv;

	CK_ATTRIBUTE input[] = {
		{ CKA_CLASS, &certificate, sizeof (certificate) },
		{ CKA_CERTIFICATE_TYPE, &x509, sizeof (x509) },
		{ CKA_URL, "http://blah", 11 },
		{ CKA_INVALID },
	};

	p11_message_quiet ();

	/* Missing CKA_HASH_OF_SUBJECT_PUBLIC_KEY and CKA_HASH_OF_ISSUER_PUBLIC_KEY */
	rv = p11_builder_build (test.builder, test.index, attrs, input, &extra);
	assert_num_eq (CKR_TEMPLATE_INCONSISTENT, rv);

	p11_message_loud ();
}

static void
test_create_not_settable (void)
{
	/*
	 * CKA_PUBLIC_KEY_INFO cannot be created/modified
	 */

	CK_ATTRIBUTE input[] = {
		{ CKA_CLASS, &certificate, sizeof (certificate) },
		{ CKA_CERTIFICATE_TYPE, &x509, sizeof (x509) },
		{ CKA_VALUE, (void *)test_cacert3_ca_der, sizeof (test_cacert3_ca_der) },
		{ CKA_PUBLIC_KEY_INFO, (void *)verisign_v1_ca_public_key, sizeof (verisign_v1_ca_public_key) },
		{ CKA_INVALID },
	};

	CK_ATTRIBUTE *attrs;
	CK_ATTRIBUTE *merge;
	CK_ATTRIBUTE *extra;
	CK_RV rv;

	p11_message_quiet ();

	attrs = NULL;
	merge = p11_attrs_dup (input);
	rv = p11_builder_build (test.builder, test.index, attrs, merge, &extra);
	assert_num_eq (CKR_ATTRIBUTE_READ_ONLY, rv);
	p11_attrs_free (merge);

	p11_message_loud ();

	p11_attrs_free (attrs);
}

static void
test_create_but_loadable (void)
{
	/*
	 * CKA_PUBLIC_KEY_INFO cannot be set on creation, but can be set if we're
	 * loading from our store. This is signified by batching.
	 */

	CK_ATTRIBUTE input[] = {
		{ CKA_CLASS, &certificate, sizeof (certificate) },
		{ CKA_CERTIFICATE_TYPE, &x509, sizeof (x509) },
		{ CKA_VALUE, (void *)test_cacert3_ca_der, sizeof (test_cacert3_ca_der) },
		{ CKA_PUBLIC_KEY_INFO, (void *)verisign_v1_ca_public_key, sizeof (verisign_v1_ca_public_key) },
		{ CKA_INVALID },
	};

	CK_ATTRIBUTE *attrs;
	CK_ATTRIBUTE *extra;
	CK_RV rv;

	p11_index_load (test.index);

	attrs = NULL;
	rv = p11_builder_build (test.builder, test.index, attrs, input, &extra);
	assert_num_eq (CKR_OK, rv);

	p11_index_finish (test.index);

	attrs = p11_attrs_merge (attrs, p11_attrs_dup (input), true);
	attrs = p11_attrs_merge (attrs, extra, false);

	test_check_attrs (input, attrs);
	p11_attrs_free (attrs);
}

static void
test_create_unsupported (void)
{
	CK_OBJECT_CLASS klass = CKO_PRIVATE_KEY;

	CK_ATTRIBUTE input[] = {
		{ CKA_CLASS, &klass, sizeof (klass) },
		{ CKA_INVALID },
	};

	CK_ATTRIBUTE *attrs;
	CK_ATTRIBUTE *merge;
	CK_ATTRIBUTE *extra;
	CK_RV rv;

	p11_message_quiet ();

	attrs = NULL;
	extra = NULL;
	merge = p11_attrs_dup (input);
	rv = p11_builder_build (test.builder, test.index, attrs, merge, &extra);
	assert_num_eq (CKR_TEMPLATE_INCONSISTENT, rv);
	p11_attrs_free (merge);

	p11_message_loud ();
}

static void
test_create_generated (void)
{
	CK_OBJECT_CLASS klass = CKO_NSS_TRUST;

	CK_ATTRIBUTE input[] = {
		{ CKA_CLASS, &klass, sizeof (klass) },
		{ CKA_INVALID },
	};

	CK_ATTRIBUTE *attrs;
	CK_ATTRIBUTE *merge;
	CK_ATTRIBUTE *extra;
	CK_RV rv;

	p11_message_quiet ();

	attrs = NULL;
	extra = NULL;
	merge = p11_attrs_dup (input);
	rv = p11_builder_build (test.builder, test.index, attrs, merge, &extra);
	assert_num_eq (CKR_TEMPLATE_INCONSISTENT, rv);
	p11_attrs_free (merge);

	p11_message_loud ();
}

static void
test_create_bad_attribute (void)
{
	CK_ATTRIBUTE input[] = {
		{ CKA_CLASS, &data, sizeof (data) },
		{ CKA_VALUE, "the value", 9 },
		{ CKA_COLOR, "blue", 4 },
		{ CKA_INVALID },
	};

	CK_ATTRIBUTE *attrs;
	CK_ATTRIBUTE *merge;
	CK_ATTRIBUTE *extra;
	CK_RV rv;

	p11_message_quiet ();

	attrs = NULL;
	extra = NULL;
	merge = p11_attrs_dup (input);
	rv = p11_builder_build (test.builder, test.index, attrs, merge, &extra);
	assert_num_eq (CKR_TEMPLATE_INCONSISTENT, rv);
	p11_attrs_free (merge);

	p11_message_loud ();
}

static void
test_create_missing_attribute (void)
{
	CK_ATTRIBUTE input[] = {
		{ CKA_CLASS, &certificate_extension, sizeof (certificate_extension) },
		{ CKA_INVALID },
	};

	CK_ATTRIBUTE *attrs;
	CK_ATTRIBUTE *merge;
	CK_ATTRIBUTE *extra;
	CK_RV rv;

	p11_message_quiet ();

	attrs = NULL;
	extra = NULL;
	merge = p11_attrs_dup (input);
	rv = p11_builder_build (test.builder, test.index, attrs, merge, &extra);
	assert_num_eq (CKR_TEMPLATE_INCOMPLETE, rv);
	p11_attrs_free (merge);

	p11_message_loud ();
}

static void
test_create_no_class (void)
{
	CK_ATTRIBUTE input[] = {
		{ CKA_VALUE, "the value", 9 },
		{ CKA_INVALID },
	};

	CK_ATTRIBUTE *attrs;
	CK_ATTRIBUTE *merge;
	CK_ATTRIBUTE *extra;
	CK_RV rv;

	p11_message_quiet ();

	attrs = NULL;
	extra = NULL;
	merge = p11_attrs_dup (input);
	rv = p11_builder_build (test.builder, test.index, attrs, merge, &extra);
	assert_num_eq (CKR_TEMPLATE_INCOMPLETE, rv);
	p11_attrs_free (merge);

	p11_message_loud ();
}

static void
test_create_token_mismatch (void)
{
	CK_ATTRIBUTE input[] = {
		{ CKA_CLASS, &data, sizeof (data) },
		{ CKA_TOKEN, &falsev, sizeof (falsev) },
		{ CKA_INVALID },
	};

	CK_ATTRIBUTE *attrs;
	CK_ATTRIBUTE *merge;
	CK_ATTRIBUTE *extra;
	CK_RV rv;

	p11_message_quiet ();

	attrs = NULL;
	extra = NULL;
	merge = p11_attrs_dup (input);
	rv = p11_builder_build (test.builder, test.index, attrs, merge, &extra);
	assert_num_eq (CKR_TEMPLATE_INCONSISTENT, rv);
	p11_attrs_free (merge);

	p11_message_loud ();
}

static void
test_modify_success (void)
{
	CK_ATTRIBUTE input[] = {
		{ CKA_CLASS, &data, sizeof (data) },
		{ CKA_MODIFIABLE, &truev, sizeof (truev) },
		{ CKA_VALUE, "the value", 9 },
		{ CKA_INVALID },
	};

	CK_ATTRIBUTE modify[] = {
		{ CKA_VALUE, "new value long", 14 },
		{ CKA_LABEL, "new label", 9 },
		{ CKA_INVALID },
	};

	CK_ATTRIBUTE expected[] = {
		{ CKA_CLASS, &data, sizeof (data) },
		{ CKA_MODIFIABLE, &truev, sizeof (truev) },
		{ CKA_VALUE, "new value long", 14 },
		{ CKA_LABEL, "new label", 9 },
		{ CKA_INVALID },
	};

	CK_ATTRIBUTE *attrs;
	CK_ATTRIBUTE *extra;
	CK_RV rv;

	attrs = NULL;
	extra = NULL;
	rv = p11_builder_build (test.builder, test.index, attrs, input, &extra);
	assert_num_eq (CKR_OK, rv);

	attrs = p11_attrs_merge (attrs, p11_attrs_dup (input), true);
	attrs = p11_attrs_merge (attrs, extra, false);

	extra = NULL;
	rv = p11_builder_build (test.builder, test.index, attrs, modify, &extra);
	assert_num_eq (CKR_OK, rv);

	attrs = p11_attrs_merge (attrs, p11_attrs_dup (modify), true);
	attrs = p11_attrs_merge (attrs, extra, false);

	test_check_attrs (expected, attrs);
	p11_attrs_free (attrs);
}

static void
test_modify_read_only (void)
{
	CK_ATTRIBUTE input[] = {
		{ CKA_CLASS, &data, sizeof (data) },
		{ CKA_MODIFIABLE, &truev, sizeof (truev) },
		{ CKA_VALUE, "the value", 9 },
		{ CKA_INVALID },
	};

	CK_ATTRIBUTE modify[] = {
		{ CKA_CLASS, &certificate, sizeof (certificate) },
		{ CKA_INVALID },
	};

	CK_ATTRIBUTE *attrs;
	CK_ATTRIBUTE *merge;
	CK_ATTRIBUTE *extra;
	CK_RV rv;

	attrs = NULL;
	extra = NULL;
	merge = p11_attrs_dup (input);
	rv = p11_builder_build (test.builder, test.index, attrs, merge, &extra);
	assert_num_eq (CKR_OK, rv);

	attrs = p11_attrs_merge (attrs, merge, true);
	attrs = p11_attrs_merge (attrs, extra, false);

	p11_message_quiet ();

	extra = NULL;
	merge = p11_attrs_dup (modify);
	rv = p11_builder_build (test.builder, test.index, attrs, merge, &extra);
	assert_num_eq (CKR_ATTRIBUTE_READ_ONLY, rv);
	p11_attrs_free (merge);

	p11_message_loud ();

	p11_attrs_free (attrs);
}

static void
test_modify_unchanged (void)
{
	CK_ATTRIBUTE input[] = {
		{ CKA_CLASS, &data, sizeof (data) },
		{ CKA_MODIFIABLE, &truev, sizeof (truev) },
		{ CKA_VALUE, "the value", 9 },
		{ CKA_INVALID },
	};

	/*
	 * Although CKA_CLASS is read-only, changing to same value
	 * shouldn't fail
	 */

	CK_ATTRIBUTE modify[] = {
		{ CKA_CLASS, &data, sizeof (data) },
		{ CKA_VALUE, "the other", 9 },
		{ CKA_INVALID },
	};

	CK_ATTRIBUTE expected[] = {
		{ CKA_CLASS, &data, sizeof (data) },
		{ CKA_VALUE, "the other", 9 },
		{ CKA_INVALID },
	};

	CK_ATTRIBUTE *attrs;
	CK_ATTRIBUTE *extra;
	CK_RV rv;

	attrs = NULL;
	rv = p11_builder_build (test.builder, test.index, attrs, input, &extra);
	assert_num_eq (CKR_OK, rv);

	attrs = p11_attrs_merge (attrs, p11_attrs_dup (input), true);
	attrs = p11_attrs_merge (attrs, extra, false);

	extra = NULL;
	rv = p11_builder_build (test.builder, test.index, attrs, modify, &extra);
	assert_num_eq (CKR_OK, rv);

	attrs = p11_attrs_merge (attrs, p11_attrs_dup (modify), true);
	attrs = p11_attrs_merge (attrs, extra, false);

	test_check_attrs (expected, attrs);
	p11_attrs_free (attrs);
}

static void
test_modify_not_modifiable (void)
{
	CK_ATTRIBUTE input[] = {
		{ CKA_CLASS, &data, sizeof (data) },
		{ CKA_MODIFIABLE, &falsev, sizeof (falsev) },
		{ CKA_VALUE, "the value", 9 },
		{ CKA_INVALID },
	};

	CK_ATTRIBUTE modify[] = {
		{ CKA_VALUE, "the value", 9 },
		{ CKA_INVALID },
	};

	CK_ATTRIBUTE *attrs;
	CK_ATTRIBUTE *merge;
	CK_ATTRIBUTE *extra;
	CK_RV rv;

	attrs = NULL;
	extra = NULL;
	rv = p11_builder_build (test.builder, test.index, attrs, input, &extra);
	assert_num_eq (CKR_OK, rv);

	attrs = p11_attrs_merge (attrs, p11_attrs_dup (input), true);
	attrs = p11_attrs_merge (attrs, extra, false);

	p11_message_quiet ();

	extra = NULL;
	merge = p11_attrs_dup (modify);
	rv = p11_builder_build (test.builder, test.index, attrs, merge, &extra);
	assert_num_eq (CKR_ATTRIBUTE_READ_ONLY, rv);
	p11_attrs_free (merge);

	p11_message_loud ();

	p11_attrs_free (attrs);
}

static CK_ATTRIBUTE cacert3_assert_distrust_server[] = {
	{ CKA_CLASS, &trust_assertion, sizeof (trust_assertion) },
	{ CKA_X_PURPOSE, (void *)P11_OID_SERVER_AUTH_STR, sizeof (P11_OID_SERVER_AUTH_STR) - 1 },
	{ CKA_ISSUER, (void *)test_cacert3_ca_issuer, sizeof (test_cacert3_ca_issuer) },
	{ CKA_SERIAL_NUMBER, (void *)test_cacert3_ca_serial, sizeof (test_cacert3_ca_serial) },
	{ CKA_X_ASSERTION_TYPE, &distrusted_certificate, sizeof (distrusted_certificate) },
	{ CKA_ID, "cacert3", 7 },
	{ CKA_INVALID },
};

static CK_ATTRIBUTE cacert3_assert_distrust_client[] = {
	{ CKA_CLASS, &trust_assertion, sizeof (trust_assertion) },
	{ CKA_X_PURPOSE, (void *)P11_OID_CLIENT_AUTH_STR, sizeof (P11_OID_CLIENT_AUTH_STR) - 1},
	{ CKA_ISSUER, (void *)test_cacert3_ca_issuer, sizeof (test_cacert3_ca_issuer) },
	{ CKA_SERIAL_NUMBER, (void *)test_cacert3_ca_serial, sizeof (test_cacert3_ca_serial) },
	{ CKA_X_ASSERTION_TYPE, &distrusted_certificate, sizeof (distrusted_certificate) },
	{ CKA_ID, "cacert3", 7 },
	{ CKA_INVALID },
};

static CK_ATTRIBUTE cacert3_assert_distrust_code[] = {
	{ CKA_CLASS, &trust_assertion, sizeof (trust_assertion) },
	{ CKA_X_PURPOSE, (void *)P11_OID_CODE_SIGNING_STR, sizeof (P11_OID_CODE_SIGNING_STR) - 1},
	{ CKA_ISSUER, (void *)test_cacert3_ca_issuer, sizeof (test_cacert3_ca_issuer) },
	{ CKA_SERIAL_NUMBER, (void *)test_cacert3_ca_serial, sizeof (test_cacert3_ca_serial) },
	{ CKA_X_ASSERTION_TYPE, &distrusted_certificate, sizeof (distrusted_certificate) },
	{ CKA_ID, "cacert3", 7 },
	{ CKA_INVALID },
};

static CK_ATTRIBUTE cacert3_assert_distrust_email[] = {
	{ CKA_CLASS, &trust_assertion, sizeof (trust_assertion) },
	{ CKA_X_PURPOSE, (void *)P11_OID_EMAIL_PROTECTION_STR, sizeof (P11_OID_EMAIL_PROTECTION_STR) - 1},
	{ CKA_ISSUER, (void *)test_cacert3_ca_issuer, sizeof (test_cacert3_ca_issuer) },
	{ CKA_SERIAL_NUMBER, (void *)test_cacert3_ca_serial, sizeof (test_cacert3_ca_serial) },
	{ CKA_X_ASSERTION_TYPE, &distrusted_certificate, sizeof (distrusted_certificate) },
	{ CKA_ID, "cacert3", 7 },
	{ CKA_INVALID },
};

static CK_ATTRIBUTE cacert3_assert_distrust_system[] = {
	{ CKA_CLASS, &trust_assertion, sizeof (trust_assertion) },
	{ CKA_X_PURPOSE, (void *)P11_OID_IPSEC_END_SYSTEM_STR, sizeof (P11_OID_IPSEC_END_SYSTEM_STR) - 1},
	{ CKA_ISSUER, (void *)test_cacert3_ca_issuer, sizeof (test_cacert3_ca_issuer) },
	{ CKA_SERIAL_NUMBER, (void *)test_cacert3_ca_serial, sizeof (test_cacert3_ca_serial) },
	{ CKA_X_ASSERTION_TYPE, &distrusted_certificate, sizeof (distrusted_certificate) },
	{ CKA_ID, "cacert3", 7 },
	{ CKA_INVALID },
};

static CK_ATTRIBUTE cacert3_assert_distrust_tunnel[] = {
	{ CKA_CLASS, &trust_assertion, sizeof (trust_assertion) },
	{ CKA_X_PURPOSE, (void *)P11_OID_IPSEC_TUNNEL_STR, sizeof (P11_OID_IPSEC_TUNNEL_STR) - 1},
	{ CKA_ISSUER, (void *)test_cacert3_ca_issuer, sizeof (test_cacert3_ca_issuer) },
	{ CKA_SERIAL_NUMBER, (void *)test_cacert3_ca_serial, sizeof (test_cacert3_ca_serial) },
	{ CKA_X_ASSERTION_TYPE, &distrusted_certificate, sizeof (distrusted_certificate) },
	{ CKA_ID, "cacert3", 7 },
	{ CKA_INVALID },
};

static CK_ATTRIBUTE cacert3_assert_distrust_user[] = {
	{ CKA_CLASS, &trust_assertion, sizeof (trust_assertion) },
	{ CKA_X_PURPOSE, (void *)P11_OID_IPSEC_USER_STR, sizeof (P11_OID_IPSEC_USER_STR) - 1},
	{ CKA_ISSUER, (void *)test_cacert3_ca_issuer, sizeof (test_cacert3_ca_issuer) },
	{ CKA_SERIAL_NUMBER, (void *)test_cacert3_ca_serial, sizeof (test_cacert3_ca_serial) },
	{ CKA_X_ASSERTION_TYPE, &distrusted_certificate, sizeof (distrusted_certificate) },
	{ CKA_ID, "cacert3", 7 },
	{ CKA_INVALID },
};

static CK_ATTRIBUTE cacert3_assert_distrust_time[] = {
	{ CKA_CLASS, &trust_assertion, sizeof (trust_assertion) },
	{ CKA_X_PURPOSE, (void *)P11_OID_TIME_STAMPING_STR, sizeof (P11_OID_TIME_STAMPING_STR) - 1},
	{ CKA_ISSUER, (void *)test_cacert3_ca_issuer, sizeof (test_cacert3_ca_issuer) },
	{ CKA_SERIAL_NUMBER, (void *)test_cacert3_ca_serial, sizeof (test_cacert3_ca_serial) },
	{ CKA_X_ASSERTION_TYPE, &distrusted_certificate, sizeof (distrusted_certificate) },
	{ CKA_ID, "cacert3", 7 },
	{ CKA_INVALID },
};

static void
test_changed_trusted_certificate (void)
{
	static CK_ATTRIBUTE cacert3_trusted_certificate[] = {
		{ CKA_CLASS, &certificate, sizeof (certificate) },
		{ CKA_CERTIFICATE_TYPE, &x509, sizeof (x509) },
		{ CKA_CERTIFICATE_CATEGORY, &certificate_authority, sizeof (certificate_authority) },
		{ CKA_VALUE, (void *)test_cacert3_ca_der, sizeof (test_cacert3_ca_der) },
		{ CKA_CHECK_VALUE, "\xad\x7c\x3f", 3 },
		{ CKA_START_DATE, "20110523", 8 },
		{ CKA_END_DATE, "20210520", 8, },
		{ CKA_SUBJECT, (void *)test_cacert3_ca_subject, sizeof (test_cacert3_ca_subject) },
		{ CKA_ISSUER, (void *)test_cacert3_ca_issuer, sizeof (test_cacert3_ca_issuer) },
		{ CKA_SERIAL_NUMBER, (void *)test_cacert3_ca_serial, sizeof (test_cacert3_ca_serial) },
		{ CKA_TRUSTED, &truev, sizeof (truev) },
		{ CKA_ID, "cacert3", 7 },
		{ CKA_LABEL, "Custom Label", 12 },
		{ CKA_INVALID },
	};

	static unsigned char eku_server_and_client[] = {
		0x30, 0x20, 0x06, 0x03, 0x55, 0x1d, 0x25, 0x01, 0x01, 0xff, 0x04, 0x16, 0x30, 0x14, 0x06, 0x08,
		0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07,
		0x03, 0x02,
	};

	CK_ATTRIBUTE eku_extension_server_and_client[] = {
		{ CKA_CLASS, &certificate_extension, sizeof (certificate_extension), },
		{ CKA_OBJECT_ID, (void *)P11_OID_EXTENDED_KEY_USAGE, sizeof (P11_OID_EXTENDED_KEY_USAGE) },
		{ CKA_PUBLIC_KEY_INFO, (void *)test_cacert3_ca_public_key, sizeof (test_cacert3_ca_public_key) },
		{ CKA_LABEL, "Custom Label", 12 },
		{ CKA_VALUE, eku_server_and_client, sizeof (eku_server_and_client) },
		{ CKA_ID, "cacert3", 7 },
		{ CKA_INVALID },
	};

	static char eku_client_email[] = {
		0x30, 0x1a, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x99, 0x77, 0x06, 0x0a, 0x01, 0x04, 0x0c,
		0x30, 0x0a, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x04,
	};

	static CK_ATTRIBUTE reject_extension_email[] = {
		{ CKA_CLASS, &certificate_extension, sizeof (certificate_extension), },
		{ CKA_OBJECT_ID, (void *)P11_OID_OPENSSL_REJECT, sizeof (P11_OID_OPENSSL_REJECT) },
		{ CKA_PUBLIC_KEY_INFO, (void *)test_cacert3_ca_public_key, sizeof (test_cacert3_ca_public_key) },
		{ CKA_LABEL, "Custom Label", 12 },
		{ CKA_VALUE, eku_client_email, sizeof (eku_client_email) },
		{ CKA_ID, "cacert3", 7 },
		{ CKA_INVALID },
	};

	static CK_ATTRIBUTE nss_trust_server_and_client_distrust_email[] = {
		{ CKA_CLASS, &nss_trust, sizeof (nss_trust), },
		{ CKA_ID, "cacert3", 7 },
		{ CKA_CERT_SHA1_HASH, "\xad\x7c\x3f\x64\xfc\x44\x39\xfe\xf4\xe9\x0b\xe8\xf4\x7c\x6c\xfa\x8a\xad\xfd\xce", 20 },
		{ CKA_CERT_MD5_HASH, "\xf7\x25\x12\x82\x4e\x67\xb5\xd0\x8d\x92\xb7\x7c\x0b\x86\x7a\x42", 16 },
		{ CKA_LABEL, "Custom Label", 12 },
		{ CKA_ISSUER, (void *)test_cacert3_ca_issuer, sizeof (test_cacert3_ca_issuer) },
		{ CKA_SUBJECT, (void *)test_cacert3_ca_subject, sizeof (test_cacert3_ca_subject) },
		{ CKA_SERIAL_NUMBER, (void *)test_cacert3_ca_serial, sizeof (test_cacert3_ca_serial) },
		{ CKA_TRUST_SERVER_AUTH, &trusted_delegator, sizeof (trusted_delegator) },
		{ CKA_TRUST_CLIENT_AUTH, &trusted_delegator, sizeof (trusted_delegator) },
		{ CKA_TRUST_EMAIL_PROTECTION, &not_trusted, sizeof (not_trusted) },
		{ CKA_TRUST_CODE_SIGNING, &trust_unknown, sizeof (trust_unknown) },
		{ CKA_TRUST_IPSEC_END_SYSTEM, &trust_unknown, sizeof (trust_unknown) },
		{ CKA_TRUST_IPSEC_TUNNEL, &trust_unknown, sizeof (trust_unknown) },
		{ CKA_TRUST_IPSEC_USER, &trust_unknown, sizeof (trust_unknown) },
		{ CKA_TRUST_TIME_STAMPING, &trust_unknown, sizeof (trust_unknown) },
		{ CKA_TRUST_DIGITAL_SIGNATURE, &trusted_delegator, sizeof (trusted_delegator) },
		{ CKA_TRUST_NON_REPUDIATION, &trusted_delegator, sizeof (trusted_delegator) },
		{ CKA_TRUST_KEY_ENCIPHERMENT, &trusted_delegator, sizeof (trusted_delegator) },
		{ CKA_TRUST_DATA_ENCIPHERMENT, &trusted_delegator, sizeof (trusted_delegator) },
		{ CKA_TRUST_KEY_AGREEMENT, &trusted_delegator, sizeof (trusted_delegator) },
		{ CKA_TRUST_KEY_CERT_SIGN, &trusted_delegator, sizeof (trusted_delegator) },
		{ CKA_TRUST_CRL_SIGN, &trusted_delegator, sizeof (trusted_delegator) },
		{ CKA_INVALID, }
	};

	static CK_ATTRIBUTE server_anchor_assertion[] = {
		{ CKA_CLASS, &trust_assertion, sizeof (trust_assertion) },
		{ CKA_X_PURPOSE, (void *)P11_OID_SERVER_AUTH_STR, sizeof (P11_OID_SERVER_AUTH_STR) - 1 },
		{ CKA_LABEL, "Custom Label", 12 },
		{ CKA_X_CERTIFICATE_VALUE, (void *)test_cacert3_ca_der, sizeof (test_cacert3_ca_der) },
		{ CKA_X_ASSERTION_TYPE, &anchored_certificate, sizeof (anchored_certificate) },
		{ CKA_ID, "cacert3", 7 },
		{ CKA_INVALID },
	};

	static CK_ATTRIBUTE client_anchor_assertion[] = {
		{ CKA_CLASS, &trust_assertion, sizeof (trust_assertion) },
		{ CKA_X_PURPOSE, (void *)P11_OID_CLIENT_AUTH_STR, sizeof (P11_OID_CLIENT_AUTH_STR) - 1 },
		{ CKA_LABEL, "Custom Label", 12 },
		{ CKA_X_CERTIFICATE_VALUE, (void *)test_cacert3_ca_der, sizeof (test_cacert3_ca_der) },
		{ CKA_X_ASSERTION_TYPE, &anchored_certificate, sizeof (anchored_certificate) },
		{ CKA_ID, "cacert3", 7 },
		{ CKA_INVALID },
	};

	/*
	 * We should get an NSS trust object and various assertions here.
	 * The first two attributes of each object are enough to look it up,
	 * and then we check the rest of the attributes match.
	 */

	CK_ATTRIBUTE *expected[] = {
		nss_trust_server_and_client_distrust_email,
		cacert3_assert_distrust_email,
		server_anchor_assertion,
		client_anchor_assertion,
		NULL,
	};

	CK_OBJECT_HANDLE handle;
	CK_ATTRIBUTE *attrs;
	CK_RV rv;
	int i;

	/*
	 * A trusted cetrificate, trusted for server and client purposes,
	 * and explicitly rejects the email and timestamping purposes.
	 */
	p11_index_load (test.index);
	rv = p11_index_take (test.index, p11_attrs_dup (cacert3_trusted_certificate), NULL);
	assert_num_eq (CKR_OK, rv);
	rv = p11_index_take (test.index, p11_attrs_dup (eku_extension_server_and_client), NULL);
	assert_num_eq (CKR_OK, rv);
	rv = p11_index_take (test.index, p11_attrs_dup (reject_extension_email), NULL);
	assert_num_eq (CKR_OK, rv);
	p11_index_finish (test.index);


	/* The other objects */
	for (i = 0; expected[i]; i++) {
		handle = p11_index_find (test.index, expected[i], 2);
		assert (handle != 0);

		attrs = p11_index_lookup (test.index, handle);
		assert_ptr_not_null (attrs);

		test_check_attrs (expected[i], attrs);
	}
}

static void
test_changed_distrust_value (void)
{
	CK_ATTRIBUTE distrust_cert[] = {
		{ CKA_CLASS, &certificate, sizeof (certificate), },
		{ CKA_CERTIFICATE_CATEGORY, &certificate_authority, sizeof (certificate_authority) },
		{ CKA_PRIVATE, &falsev, sizeof (falsev) },
		{ CKA_MODIFIABLE, &falsev, sizeof (falsev) },
		{ CKA_CERTIFICATE_TYPE, &x509, sizeof (x509) },
		{ CKA_TRUSTED, &falsev, sizeof (falsev) },
		{ CKA_X_DISTRUSTED, &truev, sizeof (truev) },
		{ CKA_VALUE, (void *)test_cacert3_ca_der, sizeof (test_cacert3_ca_der) },
		{ CKA_ID, "cacert3", 7 },
		{ CKA_INVALID },
	};

	CK_ATTRIBUTE eku_extension[] = {
		{ CKA_CLASS, &certificate_extension, sizeof (certificate_extension), },
		{ CKA_OBJECT_ID, (void *)P11_OID_EXTENDED_KEY_USAGE, sizeof (P11_OID_EXTENDED_KEY_USAGE) },
		{ CKA_VALUE, "\x30\x18\x06\x03\x55\x1d\x25\x01\x01\xff\x04\x0e\x30\x0c\x06\x0a\x2b\x06\x01\x04\x01\x99\x77\x06\x0a\x10", 26 },
		{ CKA_PUBLIC_KEY_INFO, (void *)test_cacert3_ca_public_key, sizeof (test_cacert3_ca_public_key) },
		{ CKA_ID, "cacert3", 7 },
		{ CKA_INVALID },
	};

	CK_ATTRIBUTE reject_extension[] = {
		{ CKA_CLASS, &certificate_extension, sizeof (certificate_extension), },
		{ CKA_OBJECT_ID, (void *)P11_OID_OPENSSL_REJECT, sizeof (P11_OID_OPENSSL_REJECT) },
		{ CKA_VALUE, "\x30\x1a\x06\x0a\x2b\x06\x01\x04\x01\x99\x77\x06\x0a\x01\x04\x0c\x30\x0a\x06\x08\x2b\x06\x01\x05\x05\x07\x03\x02", 28 },
		{ CKA_PUBLIC_KEY_INFO, (void *)test_cacert3_ca_public_key, sizeof (test_cacert3_ca_public_key) },
		{ CKA_ID, "cacert3", 7 },
		{ CKA_INVALID },
	};

	CK_ATTRIBUTE nss_trust_nothing[] = {
		{ CKA_CLASS, &nss_trust, sizeof (nss_trust), },
		{ CKA_ID, "cacert3", 7 },
		{ CKA_CERT_SHA1_HASH, "\xad\x7c\x3f\x64\xfc\x44\x39\xfe\xf4\xe9\x0b\xe8\xf4\x7c\x6c\xfa\x8a\xad\xfd\xce", 20 },
		{ CKA_CERT_MD5_HASH, "\xf7\x25\x12\x82\x4e\x67\xb5\xd0\x8d\x92\xb7\x7c\x0b\x86\x7a\x42", 16 },
		{ CKA_SUBJECT, (void *)test_cacert3_ca_subject, sizeof (test_cacert3_ca_subject) },
		{ CKA_ISSUER, (void *)test_cacert3_ca_issuer, sizeof (test_cacert3_ca_issuer) },
		{ CKA_SERIAL_NUMBER, (void *)test_cacert3_ca_serial, sizeof (test_cacert3_ca_serial) },
		{ CKA_TRUST_SERVER_AUTH, &not_trusted, sizeof (not_trusted) },
		{ CKA_TRUST_CLIENT_AUTH, &not_trusted, sizeof (not_trusted) },
		{ CKA_TRUST_EMAIL_PROTECTION, &not_trusted, sizeof (not_trusted) },
		{ CKA_TRUST_CODE_SIGNING, &not_trusted, sizeof (not_trusted) },
		{ CKA_TRUST_IPSEC_END_SYSTEM, &not_trusted, sizeof (not_trusted) },
		{ CKA_TRUST_IPSEC_TUNNEL, &not_trusted, sizeof (not_trusted) },
		{ CKA_TRUST_IPSEC_USER, &not_trusted, sizeof (not_trusted) },
		{ CKA_TRUST_TIME_STAMPING, &not_trusted, sizeof (not_trusted) },
		{ CKA_TRUST_DIGITAL_SIGNATURE, &not_trusted, sizeof (not_trusted) },
		{ CKA_TRUST_NON_REPUDIATION, &not_trusted, sizeof (not_trusted) },
		{ CKA_TRUST_KEY_ENCIPHERMENT, &not_trusted, sizeof (not_trusted) },
		{ CKA_TRUST_DATA_ENCIPHERMENT, &not_trusted, sizeof (not_trusted) },
		{ CKA_TRUST_KEY_AGREEMENT, &not_trusted, sizeof (not_trusted) },
		{ CKA_TRUST_KEY_CERT_SIGN, &not_trusted, sizeof (not_trusted) },
		{ CKA_TRUST_CRL_SIGN, &not_trusted, sizeof (not_trusted) },
		{ CKA_INVALID, }
	};

	/*
	 * We should get an NSS trust object and various assertions here.
	 * The first two attributes of each object are enough to look it up,
	 * and then we check the rest of the attributes match.
	 */

	CK_ATTRIBUTE *expected[] = {
		nss_trust_nothing,
		cacert3_assert_distrust_server,
		cacert3_assert_distrust_client,
		cacert3_assert_distrust_code,
		cacert3_assert_distrust_email,
		cacert3_assert_distrust_system,
		cacert3_assert_distrust_tunnel,
		cacert3_assert_distrust_user,
		cacert3_assert_distrust_time,
		NULL
	};

	CK_OBJECT_HANDLE handle;
	CK_ATTRIBUTE *attrs;
	CK_RV rv;
	int i;

	/*
	 * A distrusted certificate with a value, plus some extra
	 * extensions (which should be ignored).
	 */
	p11_index_load (test.index);
	rv = p11_index_take (test.index, p11_attrs_dup (distrust_cert), NULL);
	assert_num_eq (CKR_OK, rv);
	rv = p11_index_take (test.index, p11_attrs_dup (eku_extension), NULL);
	assert_num_eq (CKR_OK, rv);
	rv = p11_index_take (test.index, p11_attrs_dup (reject_extension), NULL);
	assert_num_eq (CKR_OK, rv);
	p11_index_finish (test.index);

	/* The other objects */
	for (i = 0; expected[i]; i++) {
		handle = p11_index_find (test.index, expected[i], 2);
		assert (handle != 0);

		attrs = p11_index_lookup (test.index, handle);
		assert_ptr_not_null (attrs);

		test_check_attrs (expected[i], attrs);
	}
}

static void
test_changed_distrust_serial (void)
{
	CK_ATTRIBUTE distrust_cert[] = {
		{ CKA_CLASS, &certificate, sizeof (certificate), },
		{ CKA_SERIAL_NUMBER, (void *)test_cacert3_ca_serial, sizeof (test_cacert3_ca_serial) },
		{ CKA_ISSUER, (void *)test_cacert3_ca_issuer, sizeof (test_cacert3_ca_issuer) },
		{ CKA_CERTIFICATE_TYPE, &x509, sizeof (x509) },
		{ CKA_TRUSTED, &falsev, sizeof (falsev) },
		{ CKA_X_DISTRUSTED, &truev, sizeof (truev) },
		{ CKA_ID, "cacert3", 7 },
		{ CKA_INVALID },
	};

	CK_ATTRIBUTE nss_trust_distrust[] = {
		{ CKA_CLASS, &nss_trust, sizeof (nss_trust), },
		{ CKA_ID, "cacert3", 7 },
		{ CKA_ISSUER, (void *)test_cacert3_ca_issuer, sizeof (test_cacert3_ca_issuer) },
		{ CKA_SERIAL_NUMBER, (void *)test_cacert3_ca_serial, sizeof (test_cacert3_ca_serial) },
		{ CKA_TRUST_SERVER_AUTH, &not_trusted, sizeof (not_trusted) },
		{ CKA_TRUST_CLIENT_AUTH, &not_trusted, sizeof (not_trusted) },
		{ CKA_TRUST_EMAIL_PROTECTION, &not_trusted, sizeof (not_trusted) },
		{ CKA_TRUST_CODE_SIGNING, &not_trusted, sizeof (not_trusted) },
		{ CKA_TRUST_IPSEC_END_SYSTEM, &not_trusted, sizeof (not_trusted) },
		{ CKA_TRUST_IPSEC_TUNNEL, &not_trusted, sizeof (not_trusted) },
		{ CKA_TRUST_IPSEC_USER, &not_trusted, sizeof (not_trusted) },
		{ CKA_TRUST_TIME_STAMPING, &not_trusted, sizeof (not_trusted) },
		{ CKA_TRUST_DIGITAL_SIGNATURE, &not_trusted, sizeof (not_trusted) },
		{ CKA_TRUST_NON_REPUDIATION, &not_trusted, sizeof (not_trusted) },
		{ CKA_TRUST_KEY_ENCIPHERMENT, &not_trusted, sizeof (not_trusted) },
		{ CKA_TRUST_DATA_ENCIPHERMENT, &not_trusted, sizeof (not_trusted) },
		{ CKA_TRUST_KEY_AGREEMENT, &not_trusted, sizeof (not_trusted) },
		{ CKA_TRUST_KEY_CERT_SIGN, &not_trusted, sizeof (not_trusted) },
		{ CKA_TRUST_CRL_SIGN, &not_trusted, sizeof (not_trusted) },
		{ CKA_INVALID, }
	};

	/*
	 * We should get an NSS trust object and various assertions here.
	 * The first two attributes of each object are enough to look it up,
	 * and then we check the rest of the attributes match.
	 */

	CK_ATTRIBUTE *expected[] = {
		nss_trust_distrust,
		cacert3_assert_distrust_server,
		cacert3_assert_distrust_client,
		cacert3_assert_distrust_code,
		cacert3_assert_distrust_email,
		cacert3_assert_distrust_system,
		cacert3_assert_distrust_tunnel,
		cacert3_assert_distrust_user,
		cacert3_assert_distrust_time,
		NULL
	};

	CK_OBJECT_HANDLE handle;
	CK_ATTRIBUTE *attrs;
	CK_RV rv;
	int i;

	/*
	 * A distrusted certificate without a value.
	 */
	p11_index_load (test.index);
	rv = p11_index_take (test.index, p11_attrs_dup (distrust_cert), NULL);
	assert_num_eq (CKR_OK, rv);
	p11_index_finish (test.index);

	for (i = 0; expected[i]; i++) {
		handle = p11_index_find (test.index, expected[i], 2);
		assert (handle != 0);
		attrs = p11_index_lookup (test.index, handle);
		assert_ptr_not_null (attrs);
		test_check_attrs (expected[i], attrs);
	}
}

static void
test_changed_dup_certificates (void)
{
	static CK_ATTRIBUTE trusted_cert[] = {
		{ CKA_CLASS, &certificate, sizeof (certificate) },
		{ CKA_CERTIFICATE_TYPE, &x509, sizeof (x509) },
		{ CKA_CERTIFICATE_CATEGORY, &certificate_authority, sizeof (certificate_authority) },
		{ CKA_VALUE, (void *)test_cacert3_ca_der, sizeof (test_cacert3_ca_der) },
		{ CKA_TRUSTED, &truev, sizeof (truev) },
		{ CKA_ID, "cacert3", 7 },
		{ CKA_INVALID },
	};

	static CK_ATTRIBUTE distrust_cert[] = {
		{ CKA_CLASS, &certificate, sizeof (certificate) },
		{ CKA_CERTIFICATE_TYPE, &x509, sizeof (x509) },
		{ CKA_CERTIFICATE_CATEGORY, &certificate_authority, sizeof (certificate_authority) },
		{ CKA_VALUE, (void *)test_cacert3_ca_der, sizeof (test_cacert3_ca_der) },
		{ CKA_X_DISTRUSTED, &truev, sizeof (truev) },
		{ CKA_ID, "cacert3", 7 },
		{ CKA_INVALID },
	};

	static CK_ATTRIBUTE trusted_nss[] = {
		{ CKA_CLASS, &nss_trust, sizeof (nss_trust), },
		{ CKA_CERT_SHA1_HASH, "\xad\x7c\x3f\x64\xfc\x44\x39\xfe\xf4\xe9\x0b\xe8\xf4\x7c\x6c\xfa\x8a\xad\xfd\xce", 20 },
		{ CKA_TRUST_SERVER_AUTH, &trusted_delegator, sizeof (trusted_delegator) },
		{ CKA_ID, "cacert3", 7 },
		{ CKA_INVALID, }
	};

	static CK_ATTRIBUTE distrust_nss[] = {
		{ CKA_CLASS, &nss_trust, sizeof (nss_trust), },
		{ CKA_CERT_SHA1_HASH, "\xad\x7c\x3f\x64\xfc\x44\x39\xfe\xf4\xe9\x0b\xe8\xf4\x7c\x6c\xfa\x8a\xad\xfd\xce", 20 },
		{ CKA_TRUST_SERVER_AUTH, &not_trusted, sizeof (not_trusted) },
		{ CKA_ID, "cacert3", 7 },
		{ CKA_INVALID, }
	};

	static CK_ATTRIBUTE unknown_nss[] = {
		{ CKA_CLASS, &nss_trust, sizeof (nss_trust), },
		{ CKA_CERT_SHA1_HASH, "\xad\x7c\x3f\x64\xfc\x44\x39\xfe\xf4\xe9\x0b\xe8\xf4\x7c\x6c\xfa\x8a\xad\xfd\xce", 20 },
		{ CKA_TRUST_SERVER_AUTH, &trust_unknown, sizeof (trust_unknown) },
		{ CKA_ID, "cacert3", 7 },
		{ CKA_INVALID, }
	};

	static CK_ATTRIBUTE match_nss[] = {
		{ CKA_CLASS, &nss_trust, sizeof (nss_trust), },
		{ CKA_ID, "cacert3", 7 },
		{ CKA_INVALID, }
	};

	static CK_ATTRIBUTE anchor_assertion[] = {
		{ CKA_CLASS, &trust_assertion, sizeof (trust_assertion) },
		{ CKA_X_PURPOSE, (void *)P11_OID_SERVER_AUTH_STR, sizeof (P11_OID_SERVER_AUTH_STR) - 1 },
		{ CKA_X_CERTIFICATE_VALUE, (void *)test_cacert3_ca_der, sizeof (test_cacert3_ca_der) },
		{ CKA_X_ASSERTION_TYPE, &anchored_certificate, sizeof (anchored_certificate) },
		{ CKA_ID, "cacert3", 7 },
		{ CKA_INVALID },
	};

	static CK_ATTRIBUTE distrust_assertion[] = {
		{ CKA_CLASS, &trust_assertion, sizeof (trust_assertion) },
		{ CKA_X_PURPOSE, (void *)P11_OID_SERVER_AUTH_STR, sizeof (P11_OID_SERVER_AUTH_STR) - 1 },
		{ CKA_ISSUER, (void *)test_cacert3_ca_issuer, sizeof (test_cacert3_ca_issuer) },
		{ CKA_SERIAL_NUMBER, (void *)test_cacert3_ca_serial, sizeof (test_cacert3_ca_serial) },
		{ CKA_X_ASSERTION_TYPE, &distrusted_certificate, sizeof (distrusted_certificate) },
		{ CKA_ID, "cacert3", 7 },
		{ CKA_INVALID },
	};

	static CK_ATTRIBUTE match_assertion[] = {
		{ CKA_CLASS, &trust_assertion, sizeof (trust_assertion) },
		{ CKA_ID, "cacert3", 7 },
		{ CKA_INVALID, }
	};

	CK_OBJECT_HANDLE handle1;
	CK_OBJECT_HANDLE handle2;
	CK_OBJECT_HANDLE handle;
	CK_RV rv;

	/*
	 * A trusted certificate, should create trutsed nss trust
	 * and anchor assertions
	 */
	p11_index_load (test.index);
	rv = p11_index_take (test.index, p11_attrs_dup (trusted_cert), &handle1);
	assert_num_eq (CKR_OK, rv);
	p11_index_finish (test.index);

	handle = p11_index_find (test.index, match_nss, -1);
	assert (handle != 0);
	handle = p11_index_find (test.index, match_assertion, -1);
	assert (handle != 0);
	handle = p11_index_find (test.index, trusted_nss, -1);
	assert (handle != 0);
	handle = p11_index_find (test.index, anchor_assertion, -1);
	assert (handle != 0);

	/* Now we add a distrusted certificate, should update the objects */
	p11_index_load (test.index);
	rv = p11_index_take (test.index, p11_attrs_dup (distrust_cert), &handle2);
	assert_num_eq (CKR_OK, rv);
	p11_index_finish (test.index);

	handle = p11_index_find (test.index, trusted_nss, -1);
	assert (handle == 0);
	handle = p11_index_find (test.index, distrust_nss, -1);
	assert (handle != 0);
	handle = p11_index_find (test.index, anchor_assertion, -1);
	assert (handle == 0);
	handle = p11_index_find (test.index, distrust_assertion, -1);
	assert (handle != 0);

	/* Now remove the trusted cetrificate, should update again */
	rv = p11_index_remove (test.index, handle2);
	assert_num_eq (CKR_OK, rv);

	handle = p11_index_find (test.index, trusted_nss, -1);
	assert (handle != 0);
	handle = p11_index_find (test.index, distrust_nss, -1);
	assert (handle == 0);
	handle = p11_index_find (test.index, anchor_assertion, -1);
	assert (handle != 0);
	handle = p11_index_find (test.index, distrust_assertion, -1);
	assert (handle == 0);

	/* Now remove the original certificate, unknown nss and no assertions */
	rv = p11_index_remove (test.index, handle1);
	assert_num_eq (CKR_OK, rv);

	handle = p11_index_find (test.index, unknown_nss, -1);
	assert (handle != 0);
	handle = p11_index_find (test.index, match_assertion, -1);
	assert (handle == 0);
}

static void
test_changed_without_id (void)
{
	static CK_ATTRIBUTE trusted_without_id[] = {
		{ CKA_CLASS, &certificate, sizeof (certificate) },
		{ CKA_CERTIFICATE_TYPE, &x509, sizeof (x509) },
		{ CKA_CERTIFICATE_CATEGORY, &certificate_authority, sizeof (certificate_authority) },
		{ CKA_VALUE, (void *)test_cacert3_ca_der, sizeof (test_cacert3_ca_der) },
		{ CKA_TRUSTED, &truev, sizeof (truev) },
		{ CKA_ID, NULL, 0, },
		{ CKA_INVALID },
	};

	CK_OBJECT_CLASS klass = 0;
	CK_ATTRIBUTE match[] = {
		{ CKA_CLASS, &klass, sizeof (klass) },
		{ CKA_INVALID },
	};

	/*
	 * A cetrificate without a CKA_ID that's created should still
	 * automatically create compat objects.
	 */

	CK_OBJECT_HANDLE handle;
	CK_RV rv;

	p11_index_load (test.index);
	rv = p11_index_take (test.index, p11_attrs_dup (trusted_without_id), NULL);
	assert_num_eq (CKR_OK, rv);
	p11_index_finish (test.index);

	klass = CKO_NSS_TRUST;
	handle = p11_index_find (test.index, match, -1);
	assert (handle != 0);

	klass = CKO_X_TRUST_ASSERTION;
	handle = p11_index_find (test.index, match, -1);
	assert (handle != 0);
}

static void
test_changed_staple_ca (void)
{
	CK_ULONG category = 0;

	CK_ATTRIBUTE attached[] = {
		{ CKA_CLASS, &certificate_extension, sizeof (certificate_extension) },
		{ CKA_OBJECT_ID, (void *)P11_OID_BASIC_CONSTRAINTS, sizeof (P11_OID_BASIC_CONSTRAINTS) },
		{ CKA_VALUE, "\x30\x0c\x06\x03\x55\x1d\x13\x04\x05\x30\x03\x01\x01\xff", 14 },
		{ CKA_PUBLIC_KEY_INFO, (void *)entrust_public_key, sizeof (entrust_public_key) },
		{ CKA_ID, "the id", 6 },
		{ CKA_INVALID },
	};

	CK_ATTRIBUTE input[] = {
		{ CKA_CLASS, &certificate, sizeof (certificate) },
		{ CKA_CERTIFICATE_TYPE, &x509, sizeof (x509) },
		{ CKA_VALUE, (void *)entrust_pretend_ca, sizeof (entrust_pretend_ca) },
		{ CKA_ID, "the id", 6 },
		{ CKA_INVALID },
	};

	CK_ATTRIBUTE match[] = {
		{ CKA_VALUE, (void *)entrust_pretend_ca, sizeof (entrust_pretend_ca) },
		{ CKA_CERTIFICATE_CATEGORY, &category, sizeof (category) },
		{ CKA_INVALID },
	};

	CK_ATTRIBUTE *attrs;
	CK_RV rv;

	attrs = NULL;
	rv = p11_index_take (test.index, p11_attrs_dup (input), NULL);
	assert_num_eq (CKR_OK, rv);

	/* Not a CA at this point, until we staple */
	category = 0;
	assert (p11_index_find (test.index, match, -1) == 0);

	/* Add a attached basic constraint */
	rv = p11_index_add (test.index, attached, 4, NULL);
	assert_num_eq (CKR_OK, rv);

	/* Now should be a CA */
	category = 2;
	assert (p11_index_find (test.index, match, -1) != 0);

	p11_attrs_free (attrs);
}

static void
test_changed_staple_ku (void)
{
	CK_ATTRIBUTE attached_ds_and_np[] = {
		{ CKA_CLASS, &certificate_extension, sizeof (certificate_extension) },
		{ CKA_OBJECT_ID, (void *)P11_OID_KEY_USAGE, sizeof (P11_OID_KEY_USAGE) },
		{ CKA_VALUE, "\x30\x0c\x06\x03\x55\x1d\x0f\x04\x05\x03\x03\x07\xc0\x00", 14 },
		{ CKA_PUBLIC_KEY_INFO, (void *)entrust_public_key, sizeof (entrust_public_key) },
		{ CKA_ID, "the id", 6 },
		{ CKA_INVALID },
	};

	CK_ATTRIBUTE input[] = {
		{ CKA_CLASS, &certificate, sizeof (certificate) },
		{ CKA_CERTIFICATE_TYPE, &x509, sizeof (x509) },
		{ CKA_VALUE, (void *)entrust_pretend_ca, sizeof (entrust_pretend_ca) },
		{ CKA_TRUSTED, &truev, sizeof (truev) },
		{ CKA_ID, "the id", 6 },
		{ CKA_INVALID },
	};

	static CK_ATTRIBUTE nss_trust_ds_and_np[] = {
		{ CKA_CLASS, &nss_trust, sizeof (nss_trust), },
		{ CKA_ID, "the id", 6 },
		{ CKA_TRUST_SERVER_AUTH, &trusted, sizeof (trusted) },
		{ CKA_TRUST_CLIENT_AUTH, &trusted, sizeof (trusted) },
		{ CKA_TRUST_EMAIL_PROTECTION, &trusted, sizeof (trusted) },
		{ CKA_TRUST_CODE_SIGNING, &trusted, sizeof (trusted) },
		{ CKA_TRUST_IPSEC_END_SYSTEM, &trusted, sizeof (trusted) },
		{ CKA_TRUST_IPSEC_TUNNEL, &trusted, sizeof (trusted) },
		{ CKA_TRUST_IPSEC_USER, &trusted, sizeof (trusted) },
		{ CKA_TRUST_TIME_STAMPING, &trusted, sizeof (trusted) },
		{ CKA_TRUST_DIGITAL_SIGNATURE, &trusted, sizeof (trusted) },
		{ CKA_TRUST_NON_REPUDIATION, &trusted, sizeof (trusted) },
		{ CKA_TRUST_KEY_ENCIPHERMENT, &trust_unknown, sizeof (trust_unknown) },
		{ CKA_TRUST_DATA_ENCIPHERMENT, &trust_unknown, sizeof (trust_unknown) },
		{ CKA_TRUST_KEY_AGREEMENT, &trust_unknown, sizeof (trust_unknown) },
		{ CKA_TRUST_KEY_CERT_SIGN, &trust_unknown, sizeof (trust_unknown) },
		{ CKA_TRUST_CRL_SIGN, &trust_unknown, sizeof (trust_unknown) },
		{ CKA_INVALID, }
	};

	CK_OBJECT_HANDLE handle;
	CK_ATTRIBUTE *attrs;
	CK_RV rv;

	p11_index_load (test.index);
	rv = p11_index_take (test.index, p11_attrs_dup (input), NULL);
	assert_num_eq (CKR_OK, rv);
	rv = p11_index_take (test.index, p11_attrs_dup (attached_ds_and_np), NULL);
	assert_num_eq (CKR_OK, rv);
	p11_index_finish (test.index);

	handle = p11_index_find (test.index, nss_trust_ds_and_np, 2);
	assert (handle != 0);

	attrs = p11_index_lookup (test.index, handle);
	test_check_attrs (nss_trust_ds_and_np, attrs);
}

int
main (int argc,
      char *argv[])
{
	p11_fixture (setup, teardown);
	p11_test (test_get_cache, "/builder/get_cache");
	p11_test (test_build_data, "/builder/build_data");
	p11_test (test_build_certificate, "/builder/build_certificate");
	p11_test (test_build_certificate_empty, "/builder/build_certificate_empty");
	p11_test (test_build_certificate_non_ca, "/builder/build_certificate_non_ca");
	p11_test (test_build_certificate_v1_ca, "/builder/build_certificate_v1_ca");
	p11_test (test_build_certificate_staple_ca, "/builder/build_certificate_staple_ca");
	p11_test (test_build_certificate_staple_ca_backwards, "/builder/build-certificate-staple-ca-backwards");
	p11_test (test_build_certificate_no_type, "/builder/build_certificate_no_type");
	p11_test (test_build_certificate_bad_type, "/builder/build_certificate_bad_type");
	p11_test (test_build_extension, "/builder/build_extension");
	p11_test (test_build_distant_end_date, "/builder/build_distant_end_date");

	p11_test (test_valid_bool, "/builder/valid-bool");
	p11_test (test_valid_ulong, "/builder/valid-ulong");
	p11_test (test_valid_utf8, "/builder/valid-utf8");
	p11_test (test_valid_dates, "/builder/valid-date");
	p11_test (test_valid_name, "/builder/valid-name");
	p11_test (test_valid_serial, "/builder/valid-serial");
	p11_test (test_valid_cert, "/builder/valid-cert");
	p11_test (test_invalid_bool, "/builder/invalid-bool");
	p11_test (test_invalid_ulong, "/builder/invalid-ulong");
	p11_test (test_invalid_utf8, "/builder/invalid-utf8");
	p11_test (test_invalid_dates, "/builder/invalid-date");
	p11_test (test_invalid_name, "/builder/invalid-name");
	p11_test (test_invalid_serial, "/builder/invalid-serial");
	p11_test (test_invalid_cert, "/builder/invalid-cert");
	p11_test (test_invalid_schema, "/builder/invalid-schema");

	p11_test (test_create_not_settable, "/builder/create_not_settable");
	p11_test (test_create_but_loadable, "/builder/create_but_loadable");
	p11_test (test_create_unsupported, "/builder/create_unsupported");
	p11_test (test_create_generated, "/builder/create_generated");
	p11_test (test_create_bad_attribute, "/builder/create_bad_attribute");
	p11_test (test_create_missing_attribute, "/builder/create_missing_attribute");
	p11_test (test_create_no_class, "/builder/create_no_class");
	p11_test (test_create_token_mismatch, "/builder/create_token_mismatch");
	p11_test (test_modify_success, "/builder/modify_success");
	p11_test (test_modify_read_only, "/builder/modify_read_only");
	p11_test (test_modify_unchanged, "/builder/modify_unchanged");
	p11_test (test_modify_not_modifiable, "/builder/modify_not_modifiable");

	p11_test (test_changed_trusted_certificate, "/builder/changed_trusted_certificate");
	p11_test (test_changed_distrust_value, "/builder/changed_distrust_value");
	p11_test (test_changed_distrust_serial, "/builder/changed_distrust_serial");
	p11_test (test_changed_without_id, "/builder/changed_without_id");
	p11_test (test_changed_staple_ca, "/builder/changed_staple_ca");
	p11_test (test_changed_staple_ku, "/builder/changed_staple_ku");
	p11_test (test_changed_dup_certificates, "/builder/changed_dup_certificates");
	return p11_test_run (argc, argv);
}
