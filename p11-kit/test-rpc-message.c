/*
 * Copyright (c) 2012 Stefan Walter
 * Copyright (C) 2012-2023 Red Hat Inc.
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
 * Author: Stef Walter <stef@thewalter.net>
 */

#include "config.h"
#include "test.h"

#include "debug.h"
#include "library.h"
#include "message.h"
#include "mock.h"
#include "p11-kit.h"
#include "private.h"
#include "rpc.h"
#include "rpc-attribute.h"
#include "rpc-mechanism.h"
#include "rpc-message.h"
#include "virtual.h"

#include <sys/types.h>
#ifdef OS_UNIX
#include <sys/wait.h>
#endif
#include <assert.h>
#include <limits.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#ifdef OS_UNIX
#include <unistd.h>
#endif

#define ELEMS(x) (sizeof (x) / sizeof (x[0]))

#if SIZEOF_UNSIGNED_LONG == 8
#define ULONG_VAL 0x0123456708ABCDEF
#elif SIZEOF_UNSIGNED_LONG == 4
#define ULONG_VAL 0x01234567
#else
#error "unsupported size of CK_ULONG"
#endif

static p11_virtual base;
static unsigned int rpc_initialized = 0;

static CK_RV
rpc_initialize (p11_rpc_client_vtable *vtable,
                void *init_reserved)
{
	assert_str_eq (vtable->data, "vtable-data");
	assert_num_cmp (p11_forkid, !=, rpc_initialized);
	rpc_initialized = p11_forkid;

	return CKR_OK;
}

static CK_RV
rpc_authenticate (p11_rpc_client_vtable *vtable,
		  uint8_t *version)
{
	assert_str_eq (vtable->data, "vtable-data");
	assert_ptr_not_null (version);

	return CKR_OK;
}

static CK_RV
rpc_transport (p11_rpc_client_vtable *vtable,
               p11_buffer *request,
               p11_buffer *response)
{
	bool ret;

	assert_str_eq (vtable->data, "vtable-data");

	/* Just pass directly to the server code */
	ret = p11_rpc_server_handle (&base.funcs, request, response);
	assert (ret == true);

	return CKR_OK;
}

static void
rpc_finalize (p11_rpc_client_vtable *vtable,
              void *fini_reserved)
{
	assert_str_eq (vtable->data, "vtable-data");
	assert_num_cmp (p11_forkid, ==, rpc_initialized);
	rpc_initialized = 0;
}

static p11_rpc_client_vtable test_normal_vtable = {
	NULL,
	rpc_initialize,
	rpc_authenticate,
	rpc_transport,
	rpc_finalize,
};

static void
mixin_free (void *data)
{
	p11_virtual *mixin = data;
	p11_virtual_uninit (mixin);
	free (mixin);
}

static CK_FUNCTION_LIST_PTR
setup_test_rpc_module (p11_rpc_client_vtable *vtable,
                       CK_FUNCTION_LIST *module_template,
                       CK_SESSION_HANDLE *session)
{
	CK_FUNCTION_LIST *rpc_module;
	p11_virtual *mixin;
	CK_RV rv;

	/* Build up our own function list */
	p11_virtual_init (&base, &p11_virtual_base, module_template, NULL);

	mixin = calloc (1, sizeof (p11_virtual));
	assert (mixin != NULL);

	vtable->data = "vtable-data";
	if (!p11_rpc_client_init (mixin, vtable))
		assert_not_reached ();

	rpc_module = p11_virtual_wrap (mixin, mixin_free);
	assert_ptr_not_null (rpc_module);

	rv = p11_kit_module_initialize (rpc_module);
	assert (rv == CKR_OK);

	if (session) {
		rv = (rpc_module->C_OpenSession) (MOCK_SLOT_ONE_ID, CKF_RW_SESSION | CKF_SERIAL_SESSION,
		                                  NULL, NULL, session);
		assert (rv == CKR_OK);
	}

	return rpc_module;
}

static CK_FUNCTION_LIST *
setup_mock_module (CK_SESSION_HANDLE *session)
{
	return setup_test_rpc_module (&test_normal_vtable, &mock_module, session);
}

static void
teardown_mock_module (CK_FUNCTION_LIST *rpc_module)
{
	p11_kit_module_finalize (rpc_module);
	p11_virtual_unwrap (rpc_module);
}

static void
test_new_free (void)
{
	p11_buffer *buf;

	buf = p11_rpc_buffer_new (0);

	assert_ptr_not_null (buf->data);
	assert_num_eq (0, buf->len);
	assert_num_eq (0, buf->flags);
	assert (buf->size == 0);
	assert_ptr_not_null (buf->ffree);
	assert_ptr_not_null (buf->frealloc);

	p11_rpc_buffer_free (buf);
}

static void
test_uint16 (void)
{
	p11_buffer buffer;
	uint16_t val = UINT16_MAX;
	size_t next;
	bool ret;

	p11_buffer_init (&buffer, 0);

	next = 0;
	ret = p11_rpc_buffer_get_uint16 (&buffer, &next, &val);
	assert_num_eq (false, ret);
	assert_num_eq (0, next);
	assert_num_eq (UINT16_MAX, val);

	p11_buffer_reset (&buffer, 0);

	ret = p11_rpc_buffer_set_uint16 (&buffer, 0, 0x6789);
	assert_num_eq (false, ret);

	p11_buffer_reset (&buffer, 0);

	p11_buffer_add (&buffer, (unsigned char *)"padding", 7);

	p11_rpc_buffer_add_uint16 (&buffer, 0x6789);
	assert_num_eq (9, buffer.len);
	assert (!p11_buffer_failed (&buffer));

	next = 7;
	ret = p11_rpc_buffer_get_uint16 (&buffer, &next, &val);
	assert_num_eq (true, ret);
	assert_num_eq (9, next);
	assert_num_eq (0x6789, val);

	p11_buffer_uninit (&buffer);
}

static void
test_uint16_static (void)
{
	p11_buffer buf = { (unsigned char *)"pad0\x67\x89", 6, };
	uint16_t val = UINT16_MAX;
	size_t next;
	bool ret;

	next = 4;
	ret = p11_rpc_buffer_get_uint16 (&buf, &next, &val);
	assert_num_eq (true, ret);
	assert_num_eq (6, next);
	assert_num_eq (0x6789, val);
}

static void
test_uint32 (void)
{
	p11_buffer buffer;
	uint32_t val = UINT32_MAX;
	size_t next;
	bool ret;

	p11_buffer_init (&buffer, 0);

	next = 0;
	ret = p11_rpc_buffer_get_uint32 (&buffer, &next, &val);
	assert_num_eq (false, ret);
	assert_num_eq (0, next);
	assert_num_eq (UINT32_MAX, val);

	p11_buffer_reset (&buffer, 0);

	ret = p11_rpc_buffer_set_uint32 (&buffer, 0, 0x12345678);
	assert_num_eq (false, ret);

	p11_buffer_reset (&buffer, 0);

	p11_buffer_add (&buffer, (unsigned char *)"padding", 7);

	p11_rpc_buffer_add_uint32 (&buffer, 0x12345678);
	assert_num_eq (11, buffer.len);
	assert (!p11_buffer_failed (&buffer));

	next = 7;
	ret = p11_rpc_buffer_get_uint32 (&buffer, &next, &val);
	assert_num_eq (true, ret);
	assert_num_eq (11, next);
	assert_num_eq (0x12345678, val);

	p11_buffer_uninit (&buffer);
}

static void
test_uint32_static (void)
{
	p11_buffer buf = { (unsigned char *)"pad0\x23\x45\x67\x89", 8, };
	uint32_t val = UINT32_MAX;
	size_t next;
	bool ret;

	next = 4;
	ret = p11_rpc_buffer_get_uint32 (&buf, &next, &val);
	assert_num_eq (true, ret);
	assert_num_eq (8, next);
	assert_num_eq (0x23456789, val);
}

static void
test_uint64 (void)
{
	p11_buffer buffer;
	uint64_t val = UINT64_MAX;
	size_t next;
	bool ret;

	p11_buffer_init (&buffer, 0);

	next = 0;
	ret = p11_rpc_buffer_get_uint64 (&buffer, &next, &val);
	assert_num_eq (0, ret);
	assert_num_eq (0, next);
	assert (UINT64_MAX == val);

	p11_buffer_reset (&buffer, 0);

	p11_buffer_add (&buffer, (unsigned char *)"padding", 7);

	p11_rpc_buffer_add_uint64 (&buffer, 0x0123456708ABCDEFull);
	assert_num_eq (15, buffer.len);
	assert (!p11_buffer_failed (&buffer));

	next = 7;
	ret = p11_rpc_buffer_get_uint64 (&buffer, &next, &val);
	assert_num_eq (true, ret);
	assert_num_eq (15, next);
	assert (0x0123456708ABCDEFull == val);

	p11_buffer_uninit (&buffer);
}

static void
test_uint64_static (void)
{
	p11_buffer buf = { (unsigned char *)"pad0\x89\x67\x45\x23\x11\x22\x33\x44", 12, };
	uint64_t val = UINT64_MAX;
	size_t next;
	bool ret;

	next = 4;
	ret = p11_rpc_buffer_get_uint64 (&buf, &next, &val);
	assert_num_eq (true, ret);
	assert_num_eq (12, next);
	assert (0x8967452311223344ull == val);
}

static void
test_byte_array (void)
{
	p11_buffer buffer;
	unsigned char bytes[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	                          0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
	                          0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	                          0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F };

	const unsigned char *val;
	size_t length = ~0;
	size_t next;
	bool ret;

	p11_buffer_init (&buffer, 0);

	/* Invalid read */

	next = 0;
	ret = p11_rpc_buffer_get_byte_array (&buffer, &next, &val, &length);
	assert_num_eq (false, ret);
	assert_num_eq (0, next);
	assert_num_eq (~0, length);

	/* Test full array */

	p11_buffer_reset (&buffer, 0);
	p11_buffer_add (&buffer, (unsigned char *)"padding", 7);

	p11_rpc_buffer_add_byte_array (&buffer, bytes, 32);
	assert_num_eq (43, buffer.len);
	assert (!p11_buffer_failed (&buffer));

	next = 7;
	ret = p11_rpc_buffer_get_byte_array (&buffer, &next, &val, &length);
	assert_num_eq (true, ret);
	assert_num_eq (43, next);
	assert_num_eq (32, length);
	assert (memcmp (val, bytes, 32) == 0);

	p11_buffer_uninit (&buffer);
}

static void
test_byte_array_null (void)
{
	p11_buffer buffer;
	const unsigned char *val;
	size_t length = ~0;
	size_t next;
	bool ret;

	p11_buffer_init (&buffer, 0);

	p11_buffer_reset (&buffer, 0);
	p11_buffer_add (&buffer, (unsigned char *)"padding", 7);

	p11_rpc_buffer_add_byte_array (&buffer, NULL, 0);
	assert_num_eq (11, buffer.len);
	assert (!p11_buffer_failed (&buffer));

	next = 7;
	ret = p11_rpc_buffer_get_byte_array (&buffer, &next, &val, &length);
	assert_num_eq (true, ret);
	assert_num_eq (11, next);
	assert_num_eq (0, length);
	assert_ptr_eq (NULL, (void*)val);

	p11_buffer_uninit (&buffer);
}

static void
test_byte_array_too_long (void)
{
	p11_buffer buffer;
	const unsigned char *val = NULL;
	size_t length = ~0;
	size_t next;
	bool ret;

	p11_buffer_init (&buffer, 0);

	p11_buffer_reset (&buffer, 0);
	p11_buffer_add (&buffer, (unsigned char *)"padding", 7);
	assert (!p11_buffer_failed (&buffer));

	/* Passing a too short buffer here shouldn't matter, as length is checked for sanity */
	p11_rpc_buffer_add_byte_array (&buffer, (unsigned char *)"", 0x9fffffff);
	assert (p11_buffer_failed (&buffer));

	/* Force write a too long byte arary to buffer */
	p11_buffer_reset (&buffer, 0);
	p11_rpc_buffer_add_uint32 (&buffer, 0x9fffffff);

	next = 0;
	ret = p11_rpc_buffer_get_byte_array (&buffer, &next, &val, &length);
	assert_num_eq (false, ret);
	assert_num_eq (0, next);
	assert_num_eq (~0, length);
	assert_ptr_eq (NULL, (void*)val);

	p11_buffer_uninit (&buffer);
}

static void
test_byte_array_static (void)
{
	unsigned char data[] = { 'p', 'a', 'd', 0x00, 0x00, 0x00, 0x00, 0x20,
	                         0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	                         0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
	                         0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	                         0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F };
	p11_buffer buf = { data, 0x40, };
	const unsigned char *val;
	size_t length = ~0;
	size_t next;
	bool ret;

	next = 4;
	ret = p11_rpc_buffer_get_byte_array (&buf, &next, &val, &length);
	assert_num_eq (true, ret);
	assert_num_eq (40, next);
	assert_num_eq (32, length);
	assert (memcmp (data + 8, val, 32) == 0);
}

static void
test_byte_value (void)
{
	p11_buffer buffer;
	unsigned char bytes[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	                          0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
	                          0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	                          0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F };

	char val[16];
	size_t offset = 0;
	CK_ULONG val_size;
	bool ret;

	p11_buffer_init (&buffer, 0);

	p11_rpc_buffer_add_byte_value (&buffer, bytes, sizeof(bytes));
	assert (p11_buffer_failed (&buffer));

	p11_buffer_reset (&buffer, 0);

	p11_rpc_buffer_add_byte_value (&buffer, bytes, 1);
	assert (!p11_buffer_failed (&buffer));

	ret = p11_rpc_buffer_get_byte_value (&buffer, &offset, val, &val_size);
	assert_num_eq (true, ret);

	assert_num_eq (bytes[0], val[0]);

	/* Read out of bound */
	ret = p11_rpc_buffer_get_byte_value (&buffer, &offset, val, &val_size);
	assert_num_eq (false, ret);

	p11_buffer_uninit (&buffer);
}

static void
test_ulong_value (void)
{
	p11_buffer buffer;
	p11_buffer buf = { (unsigned char *)"pad0\x00\x00\x00\x00\x23\x45\x67\x89", 12, };
	CK_ULONG val = ULONG_MAX;
	size_t offset = 0;
	CK_ULONG val_size;
	bool ret;

	offset = 4;
	ret = p11_rpc_buffer_get_ulong_value (&buf, &offset, &val, &val_size);
	assert_num_eq (true, ret);
	assert_num_eq (12, offset);
	assert_num_eq (sizeof(val), val_size);
	assert_num_eq (0x23456789, val);

	p11_buffer_init (&buffer, 0);

	val = ULONG_MAX;
	offset = 0;
	val_size = SIZEOF_UNSIGNED_LONG;
	ret = p11_rpc_buffer_get_ulong_value (&buffer, &offset, &val, &val_size);
	assert_num_eq (0, ret);
	assert_num_eq (0, offset);
	assert_num_eq (SIZEOF_UNSIGNED_LONG, val_size);
	assert_num_eq (ULONG_MAX, val);

	p11_buffer_reset (&buffer, 0);

	p11_buffer_add (&buffer, (unsigned char *)"padding", 7);

	val = ULONG_VAL;
	p11_rpc_buffer_add_ulong_value (&buffer, &val, SIZEOF_UNSIGNED_LONG);
	assert (!p11_buffer_failed (&buffer));
	/* The value is always stored as 64-bit integer */
	assert_num_eq (7 + 8, buffer.len);

	val = ULONG_MAX;
	offset = 7;
	ret = p11_rpc_buffer_get_ulong_value (&buffer, &offset, &val, &val_size);
	assert_num_eq (true, ret);
	/* The value is always stored as 64-bit integer */
	assert_num_eq (7 + 8, offset);
	assert_num_eq (ULONG_VAL, *(CK_ULONG *)&val);

	/* Read out of bound */
	val = ULONG_MAX;
	ret = p11_rpc_buffer_get_ulong_value (&buffer, &offset, &val, &val_size);
	assert_num_eq (false, ret);

	p11_buffer_uninit (&buffer);
}

static void
test_attribute_array_value (void)
{
	p11_buffer buffer;
	CK_BBOOL truev = CK_TRUE;
	char labelv[] = "label";
	CK_ATTRIBUTE attrs[] = {
		{ CKA_MODIFIABLE, &truev, sizeof (truev) },
		{ CKA_LABEL, labelv, sizeof (labelv) }
	};
	CK_BBOOL boolv = CK_FALSE;
	char strv[] = "\0\0\0\0\0";
	CK_ATTRIBUTE val[] = {
		{ CKA_MODIFIABLE, &boolv, sizeof (boolv) },
		{ CKA_LABEL, strv, sizeof (strv) }
	};
	CK_ULONG val_size;
	size_t offset = 0, offset2;
	bool ret;

	p11_buffer_init (&buffer, 0);

	p11_rpc_buffer_add_attribute_array_value(&buffer, attrs, sizeof(attrs));
	assert (!p11_buffer_failed (&buffer));

	offset2 = offset;
	ret = p11_rpc_buffer_get_attribute_array_value(&buffer, &offset, NULL, &val_size);
	assert_num_eq (true, ret);

	offset = offset2;
	ret = p11_rpc_buffer_get_attribute_array_value(&buffer, &offset, val, &val_size);
	assert_num_eq (true, ret);
	assert_num_eq (val[0].type, CKA_MODIFIABLE);
	assert_num_eq (*(CK_BBOOL *)val[0].pValue, CK_TRUE);
	assert_num_eq (val[0].ulValueLen, sizeof (truev));
	assert_num_eq (val[1].type, CKA_LABEL);
	assert_str_eq (val[1].pValue, "label");
	assert_num_eq (val[1].ulValueLen, sizeof (labelv));

	p11_buffer_uninit (&buffer);
}

static void
test_mechanism_type_array_value (void)
{
	p11_buffer buffer;
	CK_MECHANISM_TYPE mechs[] = { CKM_RSA_PKCS, CKM_DSA, CKM_SHA256_RSA_PKCS };
	CK_MECHANISM_TYPE val[3];
	CK_ULONG val_size;
	size_t offset = 0, offset2;
	bool ret;

	p11_buffer_init (&buffer, 0);

	p11_rpc_buffer_add_mechanism_type_array_value(&buffer, mechs, sizeof(mechs));
	assert (!p11_buffer_failed (&buffer));

	offset2 = offset;
	ret = p11_rpc_buffer_get_mechanism_type_array_value(&buffer, &offset, NULL, &val_size);
	assert_num_eq (true, ret);

	offset = offset2;
	ret = p11_rpc_buffer_get_mechanism_type_array_value(&buffer, &offset, val, &val_size);
	assert_num_eq (true, ret);
	assert_num_eq (val[0], CKM_RSA_PKCS);
	assert_num_eq (val[1], CKM_DSA);
	assert_num_eq (val[2], CKM_SHA256_RSA_PKCS);

	p11_buffer_uninit (&buffer);
}

static void
test_date_value (void)
{
	p11_buffer buffer;
	CK_DATE date, val;
	size_t offset = 0;
	CK_ULONG val_size;
	bool ret;

	memcpy (date.year, "2017", 4);
	memcpy (date.month, "05", 2);
	memcpy (date.day, "16", 2);

	p11_buffer_init (&buffer, 0);

	p11_rpc_buffer_add_date_value(&buffer, &date, sizeof(date));
	assert (!p11_buffer_failed (&buffer));

	ret = p11_rpc_buffer_get_date_value(&buffer, &offset, &val, &val_size);
	assert_num_eq (true, ret);

	assert (memcmp (val.year, date.year, 4) == 0);
	assert (memcmp (val.month, date.month, 2) == 0);
	assert (memcmp (val.day, date.day, 2) == 0);

	p11_buffer_uninit (&buffer);
}

static void
test_date_value_empty (void)
{
	p11_buffer buffer;
	CK_DATE val;
	size_t offset = 0;
	CK_ULONG val_size;
	bool ret;

	p11_buffer_init (&buffer, 0);

	p11_rpc_buffer_add_date_value(&buffer, NULL, 0);
	assert (!p11_buffer_failed (&buffer));

	ret = p11_rpc_buffer_get_date_value(&buffer, &offset, &val, &val_size);
	assert_num_eq (true, ret);

	assert_num_eq (0, val_size);

	p11_buffer_uninit (&buffer);
}

static void
test_byte_array_value (void)
{
	p11_buffer buffer;
	unsigned char bytes[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	                          0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
	                          0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	                          0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F };

	unsigned char val[32];
	size_t offset = 0;
	CK_ULONG val_size;
	bool ret;

	p11_buffer_init (&buffer, 0);

	p11_rpc_buffer_add_byte_array_value(&buffer, bytes, sizeof(bytes));
	assert (!p11_buffer_failed (&buffer));

	ret = p11_rpc_buffer_get_byte_array_value(&buffer, &offset, val, &val_size);
	assert_num_eq (true, ret);

	assert_num_eq (bytes[0], val[0]);

	p11_buffer_uninit (&buffer);
}

static void
test_mechanism_value (void)
{
	p11_buffer buffer;
	CK_MECHANISM_TYPE *mechanisms;
	CK_RSA_PKCS_PSS_PARAMS pss_params = {
		CKM_SHA256,
		CKG_MGF1_SHA256,
		32
	};
	CK_RSA_PKCS_OAEP_PARAMS oaep_params = {
		CKM_SHA384,
		CKG_MGF1_SHA384,
		0,
		NULL,
		0
	};
	CK_MECHANISM mechs[] = {
		{ CKM_RSA_PKCS_PSS, &pss_params, sizeof (pss_params) },
		{ CKM_RSA_PKCS_OAEP, &oaep_params, sizeof (oaep_params) }
	};

	CK_MECHANISM val;
	size_t offset = 0;
	bool ret;
	size_t i;

	mechanisms = p11_rpc_mechanisms_override_supported;
	p11_rpc_mechanisms_override_supported = NULL;

	p11_buffer_init (&buffer, 0);

	for (i = 0; i < ELEMS (mechs); i++) {
		size_t offset2 = offset;

		p11_rpc_buffer_add_mechanism (&buffer, &mechs[i]);
		assert (!p11_buffer_failed (&buffer));

		memset (&val, 0, sizeof (val));
		ret = p11_rpc_buffer_get_mechanism (&buffer, &offset, &val);
		assert_num_eq (true, ret);
		assert_num_eq (mechs[i].mechanism, val.mechanism);
		assert_ptr_eq (NULL, val.pParameter);
		assert_num_eq (mechs[i].ulParameterLen, val.ulParameterLen);

		val.pParameter = malloc (val.ulParameterLen);
		assert_ptr_not_null (val.pParameter);

		offset = offset2;
		ret = p11_rpc_buffer_get_mechanism (&buffer, &offset, &val);
		assert_num_eq (true, ret);
		assert_num_eq (mechs[i].mechanism, val.mechanism);
		assert_num_eq (mechs[i].ulParameterLen, val.ulParameterLen);
		assert (memcmp (val.pParameter, mechs[i].pParameter, val.ulParameterLen) == 0);

		free (val.pParameter);
	}

	p11_buffer_uninit (&buffer);

	p11_rpc_mechanisms_override_supported = mechanisms;
}

/*
 * Bit counts arrive on the wire as 64 bit values, but end up in CK_ULONG
 * fields.  Counts that do not fit must be rejected, whether or not the
 * array they describe is present.
 */
static void
test_mechanism_value_bits_overflow (void)
{
	CK_BYTE counter[8] = { 0, 1, 2, 3, 4, 5, 6, 7 };
	CK_BYTE nonce[12] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11 };
	CK_CHACHA20_PARAMS chacha20;
	CK_SALSA20_PARAMS salsa20;
	CK_SALSA20_CHACHA20_POLY1305_PARAMS poly1305;
	p11_buffer buffer;
	size_t offset;
	CK_ULONG len;

	p11_buffer_init (&buffer, 0);

	/* A well formed ChaCha20 parameter still decodes */
	offset = 0;
	p11_buffer_reset (&buffer, 0);
	p11_rpc_buffer_add_uint64 (&buffer, 64);
	p11_rpc_buffer_add_byte_array (&buffer, counter, sizeof (counter));
	p11_rpc_buffer_add_uint64 (&buffer, 96);
	p11_rpc_buffer_add_byte_array (&buffer, nonce, sizeof (nonce));
	assert (!p11_buffer_failed (&buffer));
	assert_num_eq (true, p11_rpc_buffer_get_chacha20_mechanism_value (&buffer, &offset,
									  &chacha20, &len));
	assert_num_eq (sizeof (CK_CHACHA20_PARAMS), len);
	assert_num_eq (64, chacha20.blockCounterBits);
	assert_num_eq (96, chacha20.ulNonceBits);

	/* A block counter bit count that cannot be represented is rejected */
	offset = 0;
	p11_buffer_reset (&buffer, 0);
	p11_rpc_buffer_add_uint64 (&buffer, UINT64_MAX);
	p11_rpc_buffer_add_byte_array (&buffer, counter, sizeof (counter));
	p11_rpc_buffer_add_uint64 (&buffer, 96);
	p11_rpc_buffer_add_byte_array (&buffer, nonce, sizeof (nonce));
	assert (!p11_buffer_failed (&buffer));
	assert_num_eq (false, p11_rpc_buffer_get_chacha20_mechanism_value (&buffer, &offset,
									   NULL, NULL));

	/* ... even when the array it describes is absent */
	offset = 0;
	p11_buffer_reset (&buffer, 0);
	p11_rpc_buffer_add_uint64 (&buffer, 64);
	p11_rpc_buffer_add_byte_array (&buffer, counter, sizeof (counter));
	p11_rpc_buffer_add_uint64 (&buffer, UINT64_MAX);
	p11_rpc_buffer_add_byte_array (&buffer, NULL, 0);
	assert (!p11_buffer_failed (&buffer));
	assert_num_eq (false, p11_rpc_buffer_get_chacha20_mechanism_value (&buffer, &offset,
									   NULL, NULL));

#if ULONG_MAX < UINT64_MAX
	/*
	 * A count that only fits once truncated to CK_ULONG must not be
	 * accepted by matching the truncated value against the array length.
	 */
	offset = 0;
	p11_buffer_reset (&buffer, 0);
	p11_rpc_buffer_add_uint64 (&buffer, 64);
	p11_rpc_buffer_add_byte_array (&buffer, counter, sizeof (counter));
	p11_rpc_buffer_add_uint64 (&buffer, (uint64_t) ULONG_MAX + 1 + 96);
	p11_rpc_buffer_add_byte_array (&buffer, nonce, sizeof (nonce));
	assert (!p11_buffer_failed (&buffer));
	assert_num_eq (false, p11_rpc_buffer_get_chacha20_mechanism_value (&buffer, &offset,
									   NULL, NULL));
#endif

	/* The same guard applies to Salsa20 ... */
	offset = 0;
	p11_buffer_reset (&buffer, 0);
	p11_rpc_buffer_add_byte_array (&buffer, counter, sizeof (counter));
	p11_rpc_buffer_add_uint64 (&buffer, 96);
	p11_rpc_buffer_add_byte_array (&buffer, nonce, sizeof (nonce));
	assert (!p11_buffer_failed (&buffer));
	assert_num_eq (true, p11_rpc_buffer_get_salsa20_mechanism_value (&buffer, &offset,
									 &salsa20, &len));
	assert_num_eq (96, salsa20.ulNonceBits);

	offset = 0;
	p11_buffer_reset (&buffer, 0);
	p11_rpc_buffer_add_byte_array (&buffer, counter, sizeof (counter));
	p11_rpc_buffer_add_uint64 (&buffer, UINT64_MAX);
	p11_rpc_buffer_add_byte_array (&buffer, NULL, 0);
	assert (!p11_buffer_failed (&buffer));
	assert_num_eq (false, p11_rpc_buffer_get_salsa20_mechanism_value (&buffer, &offset,
									  NULL, NULL));

	/* ... and to Poly1305 */
	offset = 0;
	p11_buffer_reset (&buffer, 0);
	p11_rpc_buffer_add_uint64 (&buffer, 96);
	p11_rpc_buffer_add_byte_array (&buffer, nonce, sizeof (nonce));
	p11_rpc_buffer_add_byte_array (&buffer, NULL, 0);
	assert (!p11_buffer_failed (&buffer));
	assert_num_eq (true, p11_rpc_buffer_get_poly1305_mechanism_value (&buffer, &offset,
									  &poly1305, &len));
	assert_num_eq (96, poly1305.ulNonceBits);

	offset = 0;
	p11_buffer_reset (&buffer, 0);
	p11_rpc_buffer_add_uint64 (&buffer, UINT64_MAX);
	p11_rpc_buffer_add_byte_array (&buffer, NULL, 0);
	p11_rpc_buffer_add_byte_array (&buffer, NULL, 0);
	assert (!p11_buffer_failed (&buffer));
	assert_num_eq (false, p11_rpc_buffer_get_poly1305_mechanism_value (&buffer, &offset,
									   NULL, NULL));

	p11_buffer_uninit (&buffer);
}

static void
test_message_write (void)
{
	p11_rpc_message msg;
	p11_buffer buffer;
	CK_BBOOL truev = CK_TRUE;
	CK_ULONG zerov = (CK_ULONG)0;
	char labelv[] = "label";
	CK_ATTRIBUTE attrs[] = {
		{ CKA_MODIFIABLE, &truev, sizeof (truev) },
		{ CKA_LABEL, labelv, sizeof (labelv) },
		/* These are cases when C_GetAttributeValue is called
		 * to obtain the length */
		{ CKA_COPYABLE, NULL, sizeof (truev) },
		{ CKA_BITS_PER_PIXEL, NULL, sizeof (zerov) }
	};
	bool ret;

	ret = p11_buffer_init (&buffer, 0);
	assert_num_eq (true, ret);
	p11_rpc_message_init (&msg, &buffer, &buffer);
	ret = p11_rpc_message_write_attribute_array (&msg, attrs, ELEMS(attrs));
	assert_num_eq (true, ret);
	p11_rpc_message_clear (&msg);
	p11_buffer_uninit (&buffer);
}

static void
test_attribute_recursion_limit (void)
{
	bool ret;
	p11_rpc_message msg;
	p11_buffer buffer;
	size_t offset = 0;
	CK_BBOOL truev = CK_TRUE;
	CK_ATTRIBUTE attrs_out;
	CK_ATTRIBUTE attrs[P11_RPC_MAX_RECURSION_DEPTH + 2];
	for (size_t i = 0; i <= P11_RPC_MAX_RECURSION_DEPTH; i++) {
		attrs[i].type = CKA_WRAP_TEMPLATE;
		attrs[i].pValue = &attrs[i + 1];
		attrs[i].ulValueLen = sizeof (CK_ATTRIBUTE);
	}
	attrs[P11_RPC_MAX_RECURSION_DEPTH + 1].type = CKA_ENCRYPT;
	attrs[P11_RPC_MAX_RECURSION_DEPTH + 1].pValue = &truev;
	attrs[P11_RPC_MAX_RECURSION_DEPTH + 1].ulValueLen = sizeof (CK_BBOOL);

	ret = p11_buffer_init (&buffer, 0);
	assert_num_eq (true, ret);
	p11_rpc_message_init (&msg, &buffer, &buffer);
	ret = p11_rpc_message_write_attribute_array (&msg, attrs, ELEMS(attrs));
	assert_num_eq (true, ret);

	/* Skip the array count */
	ret = p11_rpc_buffer_get_uint32(&buffer, &offset, NULL);
	assert_num_eq (true, ret);

	/* Hit recursion limit */
	ret = p11_rpc_message_get_attribute(&msg, &buffer, &offset, &attrs_out);
	assert_num_eq (false, ret);

	p11_rpc_message_clear (&msg);
	p11_buffer_uninit (&buffer);
}

/*
 * Decoding a nested template attribute writes into storage the caller
 * supplied, but the length of the child value comes from the peer.  The
 * nested levels have to refuse to write past the caller's child buffer,
 * the way rpc-client.c already does for the top level attribute.
 */
static void
test_attribute_nested_short_buffer (void)
{
	p11_buffer buffer;
	size_t offset = 0;
	bool ret;

	/* What the peer sends: CKA_WRAP_TEMPLATE holding a 9 byte CKA_LABEL */
	unsigned char wire_label[9];
	CK_ATTRIBUTE wire_child;
	CK_ATTRIBUTE wire;

	/*
	 * What the caller provides.  The array is larger than the buffer the
	 * caller declares, so that an overrun lands in the spare bytes and
	 * can be detected without relying on a sanitizer.
	 */
	unsigned char value[16];
	CK_ATTRIBUTE child;
	CK_ATTRIBUTE attr;

	memset (wire_label, 'A', sizeof (wire_label));
	wire_child.type = CKA_LABEL;
	wire_child.pValue = wire_label;
	wire_child.ulValueLen = sizeof (wire_label);
	wire.type = CKA_WRAP_TEMPLATE;
	wire.pValue = &wire_child;
	wire.ulValueLen = sizeof (wire_child);

	p11_buffer_init (&buffer, 0);
	p11_rpc_buffer_add_attribute (&buffer, &wire);
	assert (!p11_buffer_failed (&buffer));

	memset (value, 0, sizeof (value));
	child.type = CKA_LABEL;
	child.pValue = value;
	child.ulValueLen = 8;
	attr.type = CKA_WRAP_TEMPLATE;
	attr.pValue = &child;
	attr.ulValueLen = sizeof (child);

	/* The same call the RPC client makes on a C_GetAttributeValue reply */
	ret = p11_rpc_buffer_get_attribute (&buffer, &offset, &attr);
	assert_num_eq (false, ret);

	/* Nothing was written past the 8 bytes the caller offered */
	assert_num_eq (0, value[8]);

	p11_buffer_uninit (&buffer);
}

static void
test_pqc_mechanism_no_params (void)
{
	p11_buffer buffer;
	CK_MECHANISM_TYPE *mechanisms;
	CK_MECHANISM mechs[] = {
		{ CKM_ML_DSA_KEY_PAIR_GEN, NULL, 0 },
		/* CKM_ML_DSA has an optional parameter, so omitting it is valid */
		{ CKM_ML_DSA, NULL, 0 },
		{ CKM_ML_KEM_KEY_PAIR_GEN, NULL, 0 },
		{ CKM_ML_KEM, NULL, 0 },
		{ CKM_SLH_DSA_KEY_PAIR_GEN, NULL, 0 },
		{ CKM_SLH_DSA, NULL, 0 },
		{ CKM_HASH_ML_DSA_SHA256, NULL, 0 },
		{ CKM_HASH_ML_DSA_SHA512, NULL, 0 },
		{ CKM_HASH_SLH_DSA_SHA256, NULL, 0 },
		{ CKM_HASH_SLH_DSA_SHAKE128, NULL, 0 }
	};
	CK_MECHANISM val;
	size_t offset = 0;
	bool ret;
	size_t i;

	mechanisms = p11_rpc_mechanisms_override_supported;
	p11_rpc_mechanisms_override_supported = NULL;

	p11_buffer_init (&buffer, 0);

	for (i = 0; i < ELEMS (mechs); i++) {
		p11_rpc_buffer_add_mechanism (&buffer, &mechs[i]);
		assert (!p11_buffer_failed (&buffer));

		memset (&val, 0, sizeof (val));
		ret = p11_rpc_buffer_get_mechanism (&buffer, &offset, &val);
		assert_num_eq (true, ret);
		assert_num_eq (mechs[i].mechanism, val.mechanism);
		assert_ptr_eq (NULL, val.pParameter);
		assert_num_eq (0, val.ulParameterLen);
	}

	/* Verify a second decode pass from the same buffer produces
	 * consistent results (re-read from the start). */
	offset = 0;
	for (i = 0; i < ELEMS (mechs); i++) {
		memset (&val, 0, sizeof (val));
		ret = p11_rpc_buffer_get_mechanism (&buffer, &offset, &val);
		assert_num_eq (true, ret);
		assert_num_eq (mechs[i].mechanism, val.mechanism);
		assert_ptr_eq (NULL, val.pParameter);
		assert_num_eq (0, val.ulParameterLen);
	}

	p11_buffer_uninit (&buffer);

	p11_rpc_mechanisms_override_supported = mechanisms;
}

static void
test_pqc_attribute_serialization (void)
{
	p11_buffer buffer;
	CK_BBOOL encap = CK_TRUE;
	CK_BBOOL decap = CK_FALSE;
	CK_ULONG param_set = CKP_ML_DSA_65;
	CK_ATTRIBUTE attrs[] = {
		{ CKA_ENCAPSULATE, &encap, sizeof (encap) },
		{ CKA_DECAPSULATE, &decap, sizeof (decap) },
		{ CKA_PARAMETER_SET, &param_set, sizeof (param_set) }
	};
	CK_BBOOL boolv1 = CK_FALSE, boolv2 = CK_TRUE;
	CK_ULONG ulongv = 0;
	CK_ATTRIBUTE val[] = {
		{ CKA_ENCAPSULATE, &boolv1, sizeof (boolv1) },
		{ CKA_DECAPSULATE, &boolv2, sizeof (boolv2) },
		{ CKA_PARAMETER_SET, &ulongv, sizeof (ulongv) }
	};
	CK_ULONG val_size;
	size_t offset = 0, offset2;
	bool ret;

	p11_buffer_init (&buffer, 0);

	p11_rpc_buffer_add_attribute_array_value (&buffer, attrs, sizeof (attrs));
	assert (!p11_buffer_failed (&buffer));

	offset2 = offset;
	ret = p11_rpc_buffer_get_attribute_array_value (&buffer, &offset, NULL, &val_size);
	assert_num_eq (true, ret);

	offset = offset2;
	ret = p11_rpc_buffer_get_attribute_array_value (&buffer, &offset, val, &val_size);
	assert_num_eq (true, ret);

	assert_num_eq (CKA_ENCAPSULATE, val[0].type);
	assert_num_eq (CK_TRUE, *(CK_BBOOL *)val[0].pValue);
	assert_num_eq (sizeof (CK_BBOOL), val[0].ulValueLen);

	assert_num_eq (CKA_DECAPSULATE, val[1].type);
	assert_num_eq (CK_FALSE, *(CK_BBOOL *)val[1].pValue);
	assert_num_eq (sizeof (CK_BBOOL), val[1].ulValueLen);

	assert_num_eq (CKA_PARAMETER_SET, val[2].type);
	assert_num_eq (CKP_ML_DSA_65, *(CK_ULONG *)val[2].pValue);

	p11_buffer_uninit (&buffer);
}

static void
test_eddsa_mechanism (void)
{
	p11_buffer buffer;
	CK_MECHANISM_TYPE *mechanisms;
	CK_BYTE context[] = { 't', 'e', 's', 't' };
	CK_EDDSA_PARAMS params = {
		CK_TRUE,
		sizeof (context),
		context
	};
	CK_MECHANISM mech = { CKM_EDDSA, &params, sizeof (params) };
	CK_MECHANISM mech_no_value = { CKM_EDDSA, NULL, 0 };
	CK_EDDSA_PARAMS *decoded;
	CK_MECHANISM val;
	size_t offset = 0, offset2;
	bool ret;

	mechanisms = p11_rpc_mechanisms_override_supported;
	p11_rpc_mechanisms_override_supported = NULL;

	p11_buffer_init (&buffer, 0);

	/* Test with a parameter */
	p11_rpc_buffer_add_mechanism (&buffer, &mech);
	assert (!p11_buffer_failed (&buffer));

	/* First pass only reports the length of the parameter */
	offset2 = offset;
	memset (&val, 0, sizeof (val));
	ret = p11_rpc_buffer_get_mechanism (&buffer, &offset, &val);
	assert_num_eq (true, ret);
	assert_num_eq (CKM_EDDSA, val.mechanism);
	assert_ptr_eq (NULL, val.pParameter);
	assert_num_eq (sizeof (CK_EDDSA_PARAMS), val.ulParameterLen);

	val.pParameter = malloc (val.ulParameterLen);
	assert_ptr_not_null (val.pParameter);

	offset = offset2;
	ret = p11_rpc_buffer_get_mechanism (&buffer, &offset, &val);
	assert_num_eq (true, ret);
	assert_num_eq (CKM_EDDSA, val.mechanism);
	assert_num_eq (sizeof (CK_EDDSA_PARAMS), val.ulParameterLen);

	decoded = val.pParameter;
	assert_num_eq (CK_TRUE, decoded->phFlag);
	assert_num_eq (sizeof (context), decoded->ulContextDataLen);
	assert (memcmp (decoded->pContextData, context, sizeof (context)) == 0);

	free (val.pParameter);

	/* Test without a parameter */
	p11_rpc_buffer_add_mechanism (&buffer, &mech_no_value);
	assert (!p11_buffer_failed (&buffer));

	memset (&val, 0, sizeof (val));
	ret = p11_rpc_buffer_get_mechanism (&buffer, &offset, &val);
	assert_num_eq (true, ret);
	assert_num_eq (CKM_EDDSA, val.mechanism);
	assert_ptr_eq (NULL, val.pParameter);
	assert_num_eq (0, val.ulParameterLen);

	p11_buffer_uninit (&buffer);

	p11_rpc_mechanisms_override_supported = mechanisms;
}

/*
 * The mechanism parameter update returned by C_DeriveKey2 () is decoded
 * into the buffer the application supplied.  It must never be made to
 * point into the reply buffer, which the RPC client frees before the
 * call returns.
 */
static void
test_ibm_kyber_mech_param_update (void)
{
	CK_BYTE cipher[768];
	CK_BYTE output[1568];
	CK_IBM_KYBER_PARAMS reply = { 0 };
	CK_IBM_KYBER_PARAMS params;
	p11_buffer buffer;
	size_t offset;
	bool ret;

	memset (cipher, 0x5a, sizeof (cipher));
	memset (output, 0, sizeof (output));

	reply.mode = CK_IBM_KYBER_KEM_ENCAPSULATE;
	reply.pCipher = cipher;
	reply.ulCipherLen = sizeof (cipher);

	p11_buffer_init (&buffer, 0);
	p11_rpc_buffer_add_ibm_kyber_mech_param_update (&buffer, &reply,
							sizeof (reply));
	assert (!p11_buffer_failed (&buffer));

	/* The module wrote fewer bytes than the caller's buffer holds */
	memset (&params, 0, sizeof (params));
	params.mode = CK_IBM_KYBER_KEM_ENCAPSULATE;
	params.pCipher = output;
	params.ulCipherLen = sizeof (output);

	offset = 0;
	ret = p11_rpc_buffer_get_ibm_kyber_mech_param_update (&buffer, &offset,
							      &params, NULL);
	assert_num_eq (true, ret);
	assert_ptr_eq (output, params.pCipher);
	assert_num_eq (sizeof (cipher), params.ulCipherLen);
	assert_mem_eq (output, sizeof (cipher), cipher, sizeof (cipher));

	/* A reply longer than the caller's buffer is rejected */
	memset (&params, 0, sizeof (params));
	params.mode = CK_IBM_KYBER_KEM_ENCAPSULATE;
	params.pCipher = output;
	params.ulCipherLen = sizeof (cipher) - 1;

	offset = 0;
	ret = p11_rpc_buffer_get_ibm_kyber_mech_param_update (&buffer, &offset,
							      &params, NULL);
	assert_num_eq (false, ret);
	assert_ptr_eq (output, params.pCipher);

	p11_buffer_uninit (&buffer);

	/* Without a caller buffer only the required length is reported */
	memset (&reply, 0, sizeof (reply));
	reply.mode = CK_IBM_KYBER_KEM_ENCAPSULATE;
	reply.ulCipherLen = sizeof (cipher);

	p11_buffer_init (&buffer, 0);
	p11_rpc_buffer_add_ibm_kyber_mech_param_update (&buffer, &reply,
							sizeof (reply));
	assert (!p11_buffer_failed (&buffer));

	memset (&params, 0, sizeof (params));
	params.mode = CK_IBM_KYBER_KEM_ENCAPSULATE;

	offset = 0;
	ret = p11_rpc_buffer_get_ibm_kyber_mech_param_update (&buffer, &offset,
							      &params, NULL);
	assert_num_eq (true, ret);
	assert_ptr_eq (NULL, params.pCipher);
	assert_num_eq (sizeof (cipher), params.ulCipherLen);

	p11_buffer_uninit (&buffer);
}

static void
test_ibm_btc_derive_mech_param_update (void)
{
	CK_BYTE chain_code[CK_IBM_BTC_CHAINCODE_LENGTH];
	CK_BYTE output[64];
	CK_IBM_BTC_DERIVE_PARAMS reply = { 0 };
	CK_IBM_BTC_DERIVE_PARAMS params;
	p11_buffer buffer;
	size_t offset;
	bool ret;

	memset (chain_code, 0xa5, sizeof (chain_code));
	memset (output, 0, sizeof (output));

	reply.pChainCode = chain_code;
	reply.ulChainCodeLen = sizeof (chain_code);

	p11_buffer_init (&buffer, 0);
	p11_rpc_buffer_add_ibm_btc_derive_mech_param_update (&buffer, &reply,
							     sizeof (reply));
	assert (!p11_buffer_failed (&buffer));

	/* The module wrote fewer bytes than the caller's buffer holds */
	memset (&params, 0, sizeof (params));
	params.pChainCode = output;
	params.ulChainCodeLen = sizeof (output);

	offset = 0;
	ret = p11_rpc_buffer_get_ibm_btc_derive_mech_param_update (&buffer, &offset,
								   &params, NULL);
	assert_num_eq (true, ret);
	assert_ptr_eq (output, params.pChainCode);
	assert_num_eq (sizeof (chain_code), params.ulChainCodeLen);
	assert_mem_eq (output, sizeof (chain_code), chain_code, sizeof (chain_code));

	/* A reply longer than the caller's buffer is rejected */
	memset (&params, 0, sizeof (params));
	params.pChainCode = output;
	params.ulChainCodeLen = sizeof (chain_code) - 1;

	offset = 0;
	ret = p11_rpc_buffer_get_ibm_btc_derive_mech_param_update (&buffer, &offset,
								   &params, NULL);
	assert_num_eq (false, ret);
	assert_ptr_eq (output, params.pChainCode);

	p11_buffer_uninit (&buffer);

	/* Without a caller buffer only the required length is reported */
	memset (&reply, 0, sizeof (reply));
	reply.ulChainCodeLen = sizeof (chain_code);

	p11_buffer_init (&buffer, 0);
	p11_rpc_buffer_add_ibm_btc_derive_mech_param_update (&buffer, &reply,
							     sizeof (reply));
	assert (!p11_buffer_failed (&buffer));

	memset (&params, 0, sizeof (params));

	offset = 0;
	ret = p11_rpc_buffer_get_ibm_btc_derive_mech_param_update (&buffer, &offset,
								   &params, NULL);
	assert_num_eq (true, ret);
	assert_ptr_eq (NULL, params.pChainCode);
	assert_num_eq (sizeof (chain_code), params.ulChainCodeLen);

	p11_buffer_uninit (&buffer);
}

/*
 * A module that supports CKM_IBM_BTC_DERIVE and writes a chain code
 * shorter than the buffer the caller provided.  Anything else is left
 * to the mock module.
 */
static CK_RV
mock_C_DeriveKey__btc (CK_SESSION_HANDLE session,
		       CK_MECHANISM_PTR mechanism,
		       CK_OBJECT_HANDLE base_key,
		       CK_ATTRIBUTE_PTR template,
		       CK_ULONG count,
		       CK_OBJECT_HANDLE_PTR key)
{
	CK_MECHANISM derive = { CKM_MOCK_DERIVE, "derive", 6 };
	CK_IBM_BTC_DERIVE_PARAMS *params;

	if (mechanism == NULL || mechanism->mechanism != CKM_IBM_BTC_DERIVE)
		return mock_C_DeriveKey (session, mechanism, base_key,
					 template, count, key);

	params = mechanism->pParameter;
	if (params == NULL || mechanism->ulParameterLen != sizeof (*params))
		return CKR_MECHANISM_PARAM_INVALID;

	if (params->pChainCode != NULL) {
		if (params->ulChainCodeLen < CK_IBM_BTC_CHAINCODE_LENGTH)
			return CKR_BUFFER_TOO_SMALL;
		memset (params->pChainCode, 0xbc, CK_IBM_BTC_CHAINCODE_LENGTH);
	}
	params->ulChainCodeLen = CK_IBM_BTC_CHAINCODE_LENGTH;

	return mock_C_DeriveKey (session, &derive, base_key, template, count, key);
}

static CK_FUNCTION_LIST *
setup_btc_derive_module (CK_SESSION_HANDLE *session)
{
	static CK_FUNCTION_LIST module_template;

	memcpy (&module_template, &mock_module, sizeof (module_template));
	module_template.C_DeriveKey = mock_C_DeriveKey__btc;

	return setup_test_rpc_module (&test_normal_vtable, &module_template,
				      session);
}

/*
 * Drive C_DeriveKey () all the way through the RPC client and server,
 * with a module that writes a chain code shorter than the buffer the
 * caller supplied.  The caller's buffer must come back filled in, and
 * still be the caller's own memory once the call has returned.
 */
static void
test_ibm_btc_derive_roundtrip (void)
{
	CK_FUNCTION_LIST_PTR module;
	CK_SESSION_HANDLE session = 0;
	CK_OBJECT_HANDLE object;
	CK_IBM_BTC_DERIVE_PARAMS params;
	CK_MECHANISM mech = { CKM_IBM_BTC_DERIVE, &params, sizeof (params) };
	CK_BYTE chain_code[64];
	CK_BYTE expected[CK_IBM_BTC_CHAINCODE_LENGTH];
	CK_ATTRIBUTE attrs[1];
	char label[] = "Derived";
	CK_RV rv;

	module = setup_btc_derive_module (&session);

	memset (chain_code, 0, sizeof (chain_code));
	memset (expected, 0xbc, sizeof (expected));

	memset (&params, 0, sizeof (params));
	params.type = CK_IBM_BIP0032_MASTERK;
	params.version = CK_IBM_BTC_DERIVE_PARAMS_VERSION_1;
	params.pChainCode = chain_code;
	params.ulChainCodeLen = sizeof (chain_code);

	attrs[0].type = CKA_LABEL;
	attrs[0].pValue = label;
	attrs[0].ulValueLen = strlen (label);

	rv = (module->C_DeriveKey) (session, &mech, MOCK_PUBLIC_KEY_PREFIX,
	                            attrs, 1, &object);
	assert (rv == CKR_OK);

	/* The parameter still points at the caller's buffer, not the reply */
	assert_ptr_eq (chain_code, params.pChainCode);
	assert_num_eq (sizeof (expected), params.ulChainCodeLen);
	assert_mem_eq (chain_code, sizeof (expected), expected, sizeof (expected));

	teardown_mock_module (module);
}

/* Mechanisms taking an optional CK_SIGN_ADDITIONAL_CONTEXT parameter,
 * as defined by PKCS#11 3.2 sections 6.67.5, 6.67.7, 6.68.5 and 6.68.7 */
static CK_MECHANISM_TYPE sign_additional_context_mechs[] = {
	CKM_ML_DSA,
	CKM_HASH_ML_DSA_SHA224,
	CKM_HASH_ML_DSA_SHA256,
	CKM_HASH_ML_DSA_SHA384,
	CKM_HASH_ML_DSA_SHA512,
	CKM_HASH_ML_DSA_SHA3_224,
	CKM_HASH_ML_DSA_SHA3_256,
	CKM_HASH_ML_DSA_SHA3_384,
	CKM_HASH_ML_DSA_SHA3_512,
	CKM_HASH_ML_DSA_SHAKE128,
	CKM_HASH_ML_DSA_SHAKE256,
	CKM_SLH_DSA,
	CKM_HASH_SLH_DSA_SHA224,
	CKM_HASH_SLH_DSA_SHA256,
	CKM_HASH_SLH_DSA_SHA384,
	CKM_HASH_SLH_DSA_SHA512,
	CKM_HASH_SLH_DSA_SHA3_224,
	CKM_HASH_SLH_DSA_SHA3_256,
	CKM_HASH_SLH_DSA_SHA3_384,
	CKM_HASH_SLH_DSA_SHA3_512,
	CKM_HASH_SLH_DSA_SHAKE128,
	CKM_HASH_SLH_DSA_SHAKE256,
};

static void
test_sign_additional_context_mechanism (void)
{
	p11_buffer buffer;
	CK_MECHANISM_TYPE *mechanisms;
	CK_BYTE context[] = { 't', 'e', 's', 't' };
	CK_SIGN_ADDITIONAL_CONTEXT params = {
		CKH_DETERMINISTIC_REQUIRED,
		context,
		sizeof (context)
	};
	CK_SIGN_ADDITIONAL_CONTEXT *decoded;
	CK_MECHANISM mech, val;
	size_t offset = 0, offset2;
	bool ret;
	size_t i;

	mechanisms = p11_rpc_mechanisms_override_supported;
	p11_rpc_mechanisms_override_supported = NULL;

	p11_buffer_init (&buffer, 0);

	for (i = 0; i < ELEMS (sign_additional_context_mechs); i++) {
		mech.mechanism = sign_additional_context_mechs[i];
		mech.pParameter = &params;
		mech.ulParameterLen = sizeof (params);

		p11_rpc_buffer_add_mechanism (&buffer, &mech);
		assert (!p11_buffer_failed (&buffer));

		/* First pass only reports the length of the parameter */
		offset2 = offset;
		memset (&val, 0, sizeof (val));
		ret = p11_rpc_buffer_get_mechanism (&buffer, &offset, &val);
		assert_num_eq (true, ret);
		assert_num_eq (mech.mechanism, val.mechanism);
		assert_ptr_eq (NULL, val.pParameter);
		assert_num_eq (sizeof (CK_SIGN_ADDITIONAL_CONTEXT), val.ulParameterLen);

		val.pParameter = malloc (val.ulParameterLen);
		assert_ptr_not_null (val.pParameter);

		offset = offset2;
		ret = p11_rpc_buffer_get_mechanism (&buffer, &offset, &val);
		assert_num_eq (true, ret);
		assert_num_eq (mech.mechanism, val.mechanism);
		assert_num_eq (sizeof (CK_SIGN_ADDITIONAL_CONTEXT), val.ulParameterLen);

		/* pContext points into the buffer, so the decoded parameter
		 * has to be compared field by field. */
		decoded = val.pParameter;
		assert_num_eq (CKH_DETERMINISTIC_REQUIRED, decoded->hedgeVariant);
		assert_num_eq (sizeof (context), decoded->ulContextLen);
		assert (memcmp (decoded->pContext, context, sizeof (context)) == 0);

		free (val.pParameter);

		/* The parameter is optional */
		mech.pParameter = NULL;
		mech.ulParameterLen = 0;

		p11_rpc_buffer_add_mechanism (&buffer, &mech);
		assert (!p11_buffer_failed (&buffer));

		memset (&val, 0, sizeof (val));
		ret = p11_rpc_buffer_get_mechanism (&buffer, &offset, &val);
		assert_num_eq (true, ret);
		assert_num_eq (mech.mechanism, val.mechanism);
		assert_ptr_eq (NULL, val.pParameter);
		assert_num_eq (0, val.ulParameterLen);
	}

	p11_buffer_uninit (&buffer);

	p11_rpc_mechanisms_override_supported = mechanisms;
}

/* Mechanisms taking a required CK_HASH_SIGN_ADDITIONAL_CONTEXT parameter,
 * as defined by PKCS#11 3.2 sections 6.67.6 and 6.68.6 */
static CK_MECHANISM_TYPE hash_sign_additional_context_mechs[] = {
	CKM_HASH_ML_DSA,
	CKM_HASH_SLH_DSA,
};

static void
test_hash_sign_additional_context_mechanism (void)
{
	p11_buffer buffer;
	CK_MECHANISM_TYPE *mechanisms;
	CK_BYTE context[] = { 't', 'e', 's', 't' };
	CK_HASH_SIGN_ADDITIONAL_CONTEXT params = {
		CKH_HEDGE_REQUIRED,
		context,
		sizeof (context),
		CKM_SHA3_384
	};
	CK_HASH_SIGN_ADDITIONAL_CONTEXT *decoded;
	CK_MECHANISM mech, val;
	size_t offset = 0, offset2;
	bool ret;
	size_t i;

	mechanisms = p11_rpc_mechanisms_override_supported;
	p11_rpc_mechanisms_override_supported = NULL;

	p11_buffer_init (&buffer, 0);

	for (i = 0; i < ELEMS (hash_sign_additional_context_mechs); i++) {
		mech.mechanism = hash_sign_additional_context_mechs[i];
		mech.pParameter = &params;
		mech.ulParameterLen = sizeof (params);

		p11_rpc_buffer_add_mechanism (&buffer, &mech);
		assert (!p11_buffer_failed (&buffer));

		/* First pass only reports the length of the parameter */
		offset2 = offset;
		memset (&val, 0, sizeof (val));
		ret = p11_rpc_buffer_get_mechanism (&buffer, &offset, &val);
		assert_num_eq (true, ret);
		assert_num_eq (mech.mechanism, val.mechanism);
		assert_ptr_eq (NULL, val.pParameter);
		assert_num_eq (sizeof (CK_HASH_SIGN_ADDITIONAL_CONTEXT), val.ulParameterLen);

		val.pParameter = malloc (val.ulParameterLen);
		assert_ptr_not_null (val.pParameter);

		offset = offset2;
		ret = p11_rpc_buffer_get_mechanism (&buffer, &offset, &val);
		assert_num_eq (true, ret);
		assert_num_eq (mech.mechanism, val.mechanism);
		assert_num_eq (sizeof (CK_HASH_SIGN_ADDITIONAL_CONTEXT), val.ulParameterLen);

		/* pContext points into the buffer, so the decoded parameter
		 * has to be compared field by field. */
		decoded = val.pParameter;
		assert_num_eq (CKH_HEDGE_REQUIRED, decoded->hedgeVariant);
		assert_num_eq (sizeof (context), decoded->ulContextLen);
		assert (memcmp (decoded->pContext, context, sizeof (context)) == 0);
		assert_num_eq (CKM_SHA3_384, decoded->hash);

		free (val.pParameter);

		/* The parameter is required for these mechanisms, but rejecting
		 * it is up to the token, so an absent parameter has to survive
		 * the round trip instead of corrupting the stream. */
		mech.pParameter = NULL;
		mech.ulParameterLen = 0;

		p11_rpc_buffer_add_mechanism (&buffer, &mech);
		assert (!p11_buffer_failed (&buffer));

		memset (&val, 0, sizeof (val));
		ret = p11_rpc_buffer_get_mechanism (&buffer, &offset, &val);
		assert_num_eq (true, ret);
		assert_num_eq (mech.mechanism, val.mechanism);
		assert_ptr_eq (NULL, val.pParameter);
		assert_num_eq (0, val.ulParameterLen);
	}

	p11_buffer_uninit (&buffer);

	p11_rpc_mechanisms_override_supported = mechanisms;
}

#include "test-mock.c"

static CK_MECHANISM_TYPE mechanisms[] = {
	CKM_MOCK_CAPITALIZE,
	CKM_MOCK_PREFIX,
	CKM_MOCK_GENERATE,
	CKM_MOCK_WRAP,
	CKM_MOCK_DERIVE,
	CKM_MOCK_COUNT,
	CKM_IBM_BTC_DERIVE,
	0,
};

int
main (int argc,
      char *argv[])
{
	mock_module_init ();
	p11_library_init ();

	/* Override the mechanisms that the RPC mechanism will handle */
	p11_rpc_mechanisms_override_supported = mechanisms;

	p11_test (test_new_free, "/rpc-message/new-free");
	p11_test (test_uint16, "/rpc-message/uint16");
	p11_test (test_uint16_static, "/rpc-message/uint16-static");
	p11_test (test_uint32, "/rpc-message/uint32");
	p11_test (test_uint32_static, "/rpc-message/uint32-static");
	p11_test (test_uint64, "/rpc-message/uint64");
	p11_test (test_uint64_static, "/rpc-message/uint64-static");
	p11_test (test_byte_array, "/rpc-message/byte-array");
	p11_test (test_byte_array_null, "/rpc-message/byte-array-null");
	p11_test (test_byte_array_too_long, "/rpc-message/byte-array-too-long");
	p11_test (test_byte_array_static, "/rpc-message/byte-array-static");
	p11_test (test_byte_value, "/rpc-message/byte-value");
	p11_test (test_ulong_value, "/rpc-message/ulong-value");
	p11_test (test_attribute_array_value, "/rpc-message/attribute-array-value");
	p11_test (test_mechanism_type_array_value, "/rpc-message/mechanism-type-array-value");
	p11_test (test_date_value, "/rpc-message/date-value");
	p11_test (test_date_value_empty, "/rpc-message/date-value-empty");
	p11_test (test_byte_array_value, "/rpc-message/byte-array-value");
	p11_test (test_mechanism_value, "/rpc-message/mechanism-value");
	p11_test (test_mechanism_value_bits_overflow, "/rpc-message/mechanism-value-bits-overflow");
	p11_test (test_eddsa_mechanism, "/rpc-message/eddsa-mechanism");
	p11_test (test_ibm_kyber_mech_param_update, "/rpc-message/ibm-kyber-mech-param-update");
	p11_test (test_ibm_btc_derive_mech_param_update, "/rpc-message/ibm-btc-derive-mech-param-update");
	p11_test (test_ibm_btc_derive_roundtrip, "/rpc-message/ibm-btc-derive-roundtrip");
	p11_test (test_sign_additional_context_mechanism, "/rpc-message/sign-additional-context-mechanism");
	p11_test (test_hash_sign_additional_context_mechanism, "/rpc-message/hash-sign-additional-context-mechanism");
	p11_test (test_message_write, "/rpc-message/message-write");
	p11_test (test_attribute_recursion_limit, "/rpc-message/attribute-recursion-limit");
	p11_test (test_attribute_nested_short_buffer, "/rpc-message/attribute-nested-short-buffer");
	p11_test (test_pqc_mechanism_no_params, "/rpc-message/pqc-mechanism-no-params");
	p11_test (test_pqc_attribute_serialization, "/rpc-message/pqc-attribute-serialization");

	test_mock_add_tests ("/rpc-message", NULL);

	return  p11_test_run (argc, argv);
}
