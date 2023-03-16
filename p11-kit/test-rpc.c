/*
 * Copyright (c) 2012 Stefan Walter
 * Copyright (C) 2012-2017 Red Hat Inc.
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
rpc_initialize_fails (p11_rpc_client_vtable *vtable,
                      void *init_reserved)
{
	assert_str_eq (vtable->data, "vtable-data");
	assert_num_cmp (p11_forkid, !=, rpc_initialized);
	return CKR_FUNCTION_FAILED;
}

static CK_RV
rpc_initialize_device_removed (p11_rpc_client_vtable *vtable,
                               void *init_reserved)
{
	assert_str_eq (vtable->data, "vtable-data");
	assert_num_cmp (p11_forkid, !=, rpc_initialized);
	return CKR_DEVICE_REMOVED;
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

static void
test_initialize (void)
{
	p11_rpc_client_vtable vtable = { "vtable-data", rpc_initialize, rpc_authenticate, rpc_transport, rpc_finalize };
	p11_virtual mixin;
	bool ret;
	CK_RV rv;

	/* Build up our own function list */
	rpc_initialized = 0;
	p11_virtual_init (&base, &p11_virtual_base, &mock_module_no_slots, NULL);

	ret = p11_rpc_client_init (&mixin, &vtable);
	assert_num_eq (true, ret);

	rv = mixin.funcs.C_Initialize (&mixin.funcs, NULL);
	assert (rv == CKR_OK);
	assert_num_eq (p11_forkid, rpc_initialized);

	rv = mixin.funcs.C_Finalize (&mixin.funcs, NULL);
	assert (rv == CKR_OK);
	assert_num_cmp (p11_forkid, !=, rpc_initialized);

	p11_virtual_uninit (&mixin);
}

static void
test_not_initialized (void)
{
	p11_rpc_client_vtable vtable = { "vtable-data", rpc_initialize, rpc_authenticate, rpc_transport, rpc_finalize };
	p11_virtual mixin;
	CK_INFO info;
	bool ret;
	CK_RV rv;

	/* Build up our own function list */
	rpc_initialized = 0;
	p11_virtual_init (&base, &p11_virtual_base, &mock_module_no_slots, NULL);

	ret = p11_rpc_client_init (&mixin, &vtable);
	assert_num_eq (true, ret);

	rv = (mixin.funcs.C_GetInfo) (&mixin.funcs, &info);
	assert (rv == CKR_CRYPTOKI_NOT_INITIALIZED);

	p11_virtual_uninit (&mixin);
}

static void
test_initialize_fails_on_client (void)
{
	p11_rpc_client_vtable vtable = { "vtable-data", rpc_initialize_fails, rpc_authenticate, rpc_transport, rpc_finalize };
	p11_virtual mixin;
	bool ret;
	CK_RV rv;

	/* Build up our own function list */
	rpc_initialized = 0;
	p11_virtual_init (&base, &p11_virtual_base, &mock_module_no_slots, NULL);

	ret = p11_rpc_client_init (&mixin, &vtable);
	assert_num_eq (true, ret);

	rv = (mixin.funcs.C_Initialize) (&mixin.funcs, NULL);
	assert (rv == CKR_FUNCTION_FAILED);
	assert_num_eq (0, rpc_initialized);

	p11_virtual_uninit (&mixin);
}

static CK_RV
rpc_transport_fails (p11_rpc_client_vtable *vtable,
                     p11_buffer *request,
                     p11_buffer *response)
{
	return CKR_FUNCTION_REJECTED;
}

static void
test_transport_fails (void)
{
	p11_rpc_client_vtable vtable = { "vtable-data", rpc_initialize, rpc_authenticate, rpc_transport_fails, rpc_finalize };
	p11_virtual mixin;
	bool ret;
	CK_RV rv;

	/* Build up our own function list */
	rpc_initialized = 0;
	p11_virtual_init (&base, &p11_virtual_base, &mock_module_no_slots, NULL);

	ret = p11_rpc_client_init (&mixin, &vtable);
	assert_num_eq (true, ret);

	rv = (mixin.funcs.C_Initialize) (&mixin.funcs, NULL);
	assert (rv == CKR_FUNCTION_REJECTED);
	assert_num_eq (0, rpc_initialized);

	p11_virtual_uninit (&mixin);
}

static void
test_initialize_fails_on_server (void)
{
	p11_rpc_client_vtable vtable = { "vtable-data", rpc_initialize, rpc_authenticate, rpc_transport, rpc_finalize };
	p11_virtual mixin;
	bool ret;
	CK_RV rv;

	/* Build up our own function list */
	p11_virtual_init (&base, &p11_virtual_base, &mock_module_no_slots, NULL);
	base.funcs.C_Initialize = mock_X_Initialize__fails;

	ret = p11_rpc_client_init (&mixin, &vtable);
	assert_num_eq (true, ret);

	rv = (mixin.funcs.C_Initialize) (&mixin.funcs, NULL);
	assert (rv == CKR_FUNCTION_FAILED);
	assert_num_eq (0, rpc_initialized);

	p11_virtual_uninit (&mixin);
}

static CK_RV
rpc_transport_bad_parse (p11_rpc_client_vtable *vtable,
                         p11_buffer *request,
                         p11_buffer *response)
{
	int rc;

	assert_str_eq (vtable->data, "vtable-data");

	/* Just zero bytes is an invalid message */
	rc = p11_buffer_reset (response, 2);
	assert (rc >= 0);

	memset (response->data, 0, 2);
	response->len = 2;
	return CKR_OK;
}

static void
test_transport_bad_parse (void)
{
	p11_rpc_client_vtable vtable = { "vtable-data", rpc_initialize, rpc_authenticate, rpc_transport_bad_parse, rpc_finalize };
	p11_virtual mixin;
	bool ret;
	CK_RV rv;

	/* Build up our own function list */
	rpc_initialized = 0;
	p11_virtual_init (&base, &p11_virtual_base, &mock_module_no_slots, NULL);

	ret = p11_rpc_client_init (&mixin, &vtable);
	assert_num_eq (true, ret);

	p11_kit_be_quiet ();

	rv = (mixin.funcs.C_Initialize) (&mixin.funcs, NULL);
	assert (rv == CKR_DEVICE_ERROR);
	assert_num_eq (0, rpc_initialized);

	p11_message_loud ();
	p11_virtual_uninit (&mixin);
}

static CK_RV
rpc_transport_short_error (p11_rpc_client_vtable *vtable,
                           p11_buffer *request,
                           p11_buffer *response)
{
	int rc;

	unsigned char data[] = {
		0x00, 0x00, 0x00, 0x00,       /* RPC_CALL_ERROR */
		0x00, 0x00, 0x00, 0x01, 0x75, /* signature 'u' */
		0x00, 0x01,                   /* short error */
	};

	assert_str_eq (vtable->data, "vtable-data");

	rc = p11_buffer_reset (response, sizeof (data));
	assert (rc >= 0);

	memcpy (response->data, data, sizeof (data));
	response->len = sizeof (data);
	return CKR_OK;
}

static void
test_transport_short_error (void)
{
	p11_rpc_client_vtable vtable = { "vtable-data", rpc_initialize, rpc_authenticate, rpc_transport_short_error, rpc_finalize };
	p11_virtual mixin;
	bool ret;
	CK_RV rv;

	/* Build up our own function list */
	p11_virtual_init (&base, &p11_virtual_base, &mock_module_no_slots, NULL);

	ret = p11_rpc_client_init (&mixin, &vtable);
	assert_num_eq (true, ret);

	p11_kit_be_quiet ();

	rv = (mixin.funcs.C_Initialize) (&mixin.funcs, NULL);
	assert (rv == CKR_DEVICE_ERROR);
	assert_num_eq (0, rpc_initialized);

	p11_message_loud ();
	p11_virtual_uninit (&mixin);
}

static CK_RV
rpc_transport_invalid_error (p11_rpc_client_vtable *vtable,
                             p11_buffer *request,
                             p11_buffer *response)
{
	int rc;

	unsigned char data[] = {
		0x00, 0x00, 0x00, 0x00,       /* RPC_CALL_ERROR */
		0x00, 0x00, 0x00, 0x01, 0x75, /* signature 'u' */
		0x00, 0x00, 0x00, 0x00,       /* a CKR_OK error*/
		0x00, 0x00, 0x00, 0x00,
	};

	assert_str_eq (vtable->data, "vtable-data");

	rc = p11_buffer_reset (response, sizeof (data));
	assert (rc >= 0);
	memcpy (response->data, data, sizeof (data));
	response->len = sizeof (data);
	return CKR_OK;
}

static void
test_transport_invalid_error (void)
{
	p11_rpc_client_vtable vtable = { "vtable-data", rpc_initialize, rpc_authenticate, rpc_transport_invalid_error, rpc_finalize };
	p11_virtual mixin;
	bool ret;
	CK_RV rv;

	/* Build up our own function list */
	p11_virtual_init (&base, &p11_virtual_base, &mock_module_no_slots, NULL);

	ret = p11_rpc_client_init (&mixin, &vtable);
	assert_num_eq (true, ret);

	p11_kit_be_quiet ();

	rv = (mixin.funcs.C_Initialize) (&mixin.funcs, NULL);
	assert (rv == CKR_DEVICE_ERROR);
	assert_num_eq (0, rpc_initialized);

	p11_message_loud ();
	p11_virtual_uninit (&mixin);
}

static CK_RV
rpc_transport_wrong_response (p11_rpc_client_vtable *vtable,
                              p11_buffer *request,
                              p11_buffer *response)
{
	int rc;

	unsigned char data[] = {
		0x00, 0x00, 0x00, 0x02,       /* RPC_CALL_C_Finalize */
		0x00, 0x00, 0x00, 0x00,       /* signature '' */
	};

	assert_str_eq (vtable->data, "vtable-data");

	rc = p11_buffer_reset (response, sizeof (data));
	assert (rc >= 0);
	memcpy (response->data, data, sizeof (data));
	response->len = sizeof (data);
	return CKR_OK;
}

static void
test_transport_wrong_response (void)
{
	p11_rpc_client_vtable vtable = { "vtable-data", rpc_initialize, rpc_authenticate, rpc_transport_wrong_response, rpc_finalize };
	p11_virtual mixin;
	bool ret;
	CK_RV rv;

	/* Build up our own function list */
	p11_virtual_init (&base, &p11_virtual_base, &mock_module_no_slots, NULL);

	ret = p11_rpc_client_init (&mixin, &vtable);
	assert_num_eq (true, ret);

	p11_kit_be_quiet ();

	rv = (mixin.funcs.C_Initialize) (&mixin.funcs, NULL);
	assert (rv == CKR_DEVICE_ERROR);
	assert_num_eq (0, rpc_initialized);

	p11_message_loud ();
	p11_virtual_uninit (&mixin);
}

static CK_RV
rpc_transport_bad_contents (p11_rpc_client_vtable *vtable,
                            p11_buffer *request,
                            p11_buffer *response)
{
	int rc;

	unsigned char data[] = {
		0x00, 0x00, 0x00, 0x02,       /* RPC_CALL_C_GetInfo */
		0x00, 0x00, 0x00, 0x05,       /* signature 'vsusv' */
		'v', 's', 'u', 's', 'v',
		0x00, 0x00, 0x00, 0x00,       /* invalid data */
	};

	assert_str_eq (vtable->data, "vtable-data");

	rc = p11_buffer_reset (response, sizeof (data));
	assert (rc >= 0);
	memcpy (response->data, data, sizeof (data));
	response->len = sizeof (data);
	return CKR_OK;
}

static void
test_transport_bad_contents (void)
{
	p11_rpc_client_vtable vtable = { "vtable-data", rpc_initialize, rpc_authenticate, rpc_transport_bad_contents, rpc_finalize };
	p11_virtual mixin;
	bool ret;
	CK_RV rv;

	/* Build up our own function list */
	p11_virtual_init (&base, &p11_virtual_base, &mock_module_no_slots, NULL);

	ret = p11_rpc_client_init (&mixin, &vtable);
	assert_num_eq (true, ret);

	p11_kit_be_quiet ();

	rv = (mixin.funcs.C_Initialize) (&mixin.funcs, NULL);
	assert (rv == CKR_DEVICE_ERROR);
	assert_num_eq (0, rpc_initialized);

	p11_message_loud ();
	p11_virtual_uninit (&mixin);
}

static p11_rpc_client_vtable test_normal_vtable = {
	NULL,
	rpc_initialize,
	rpc_authenticate,
	rpc_transport,
	rpc_finalize,
};

static p11_rpc_client_vtable test_device_removed_vtable = {
	NULL,
	rpc_initialize_device_removed,
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
test_get_info_stand_in (void)
{
	CK_FUNCTION_LIST_PTR rpc_module;
	CK_INFO info;
	CK_RV rv;
	char *string;

	rpc_module = setup_test_rpc_module (&test_device_removed_vtable,
	                                    &mock_module_no_slots, NULL);

	rv = (rpc_module->C_GetInfo) (&info);
	assert (rv == CKR_OK);

	assert_num_eq (CRYPTOKI_VERSION_MAJOR, info.cryptokiVersion.major);
	assert_num_eq (CRYPTOKI_VERSION_MINOR, info.cryptokiVersion.minor);
	string = p11_kit_space_strdup (info.manufacturerID, sizeof (info.manufacturerID));
	assert_str_eq ("p11-kit", string);
	free (string);
	string = p11_kit_space_strdup (info.libraryDescription, sizeof (info.libraryDescription));
	assert_str_eq ("p11-kit (no connection)", string);
	free (string);
	assert_num_eq (0, info.flags);
	assert_num_eq (1, info.libraryVersion.major);
	assert_num_eq (1, info.libraryVersion.minor);

	teardown_mock_module (rpc_module);
}

static void
test_get_slot_list_no_device (void)
{
	CK_FUNCTION_LIST_PTR rpc_module;
	CK_SLOT_ID slot_list[8];
	CK_ULONG count;
	CK_RV rv;

	rpc_module = setup_test_rpc_module (&test_device_removed_vtable,
	                                    &mock_module_no_slots, NULL);

	rv = (rpc_module->C_GetSlotList) (CK_TRUE, NULL, &count);
	assert (rv == CKR_OK);
	assert_num_eq (0, count);
	rv = (rpc_module->C_GetSlotList) (CK_FALSE, NULL, &count);
	assert (rv == CKR_OK);
	assert_num_eq (0, count);

	count = 8;
	rv = (rpc_module->C_GetSlotList) (CK_TRUE, slot_list, &count);
	assert (rv == CKR_OK);
	assert_num_eq (0, count);

	count = 8;
	rv = (rpc_module->C_GetSlotList) (CK_FALSE, slot_list, &count);
	assert (rv == CKR_OK);
	assert_num_eq (0, count);

	teardown_mock_module (rpc_module);
}

static void *
invoke_in_thread (void *arg)
{
	CK_FUNCTION_LIST *rpc_module = arg;
	CK_INFO info;
	CK_RV rv;

	rv = (rpc_module->C_GetInfo) (&info);
	assert_num_eq (rv, CKR_OK);

	assert (memcmp (info.manufacturerID, MOCK_INFO.manufacturerID,
	                sizeof (info.manufacturerID)) == 0);

	return NULL;
}

static p11_mutex_t delay_mutex;

static CK_RV
delayed_C_GetInfo (CK_INFO_PTR info)
{
	CK_RV rv;

	p11_sleep_ms (rand () % 100);

	p11_mutex_lock (&delay_mutex);
	rv = mock_C_GetInfo (info);
	p11_mutex_unlock (&delay_mutex);

	return rv;
}

static void
test_simultaneous_functions (void)
{
	CK_FUNCTION_LIST real_module;
	CK_FUNCTION_LIST *rpc_module;
	const int num_threads = 128;
	p11_thread_t threads[num_threads];
	int i, ret;

	p11_mutex_init (&delay_mutex);

	memcpy (&real_module, &mock_module_no_slots, sizeof (CK_FUNCTION_LIST));
	real_module.C_GetInfo = delayed_C_GetInfo;

	rpc_module = setup_test_rpc_module (&test_normal_vtable,
	                                    &real_module, NULL);

	/* Make the invoked function (above) wait */
	p11_mutex_lock (&delay_mutex);

	for (i = 0; i < num_threads; i++) {
		ret = p11_thread_create (threads + i, invoke_in_thread, rpc_module);
		assert_num_eq (0, ret);
	}

	/* Let the invoked functions return */
	p11_mutex_unlock (&delay_mutex);

	for (i = 0; i < num_threads; i++)
		p11_thread_join (threads[i]);

	teardown_mock_module (rpc_module);
	p11_mutex_uninit (&delay_mutex);
}

#ifdef OS_UNIX

static void
test_fork_and_reinitialize (void)
{
	CK_FUNCTION_LIST *rpc_module;
	CK_INFO info;
	int status;
	CK_RV rv;
	pid_t pid;
	int i;

	rpc_module = setup_test_rpc_module (&test_normal_vtable,
	                                    &mock_module_no_slots, NULL);

	pid = fork ();
	assert_num_cmp (pid, >=, 0);

	/* The child */
	if (pid == 0) {
		rv = (rpc_module->C_Initialize) (NULL);
		assert_num_eq (CKR_OK, rv);

		for (i = 0; i < 32; i++) {
			rv = (rpc_module->C_GetInfo) (&info);
			assert_num_eq (CKR_OK, rv);
		}

		rv = (rpc_module->C_Finalize) (NULL);
		assert_num_eq (CKR_OK, rv);

		_exit (66);
	}

	for (i = 0; i < 128; i++) {
		rv = (rpc_module->C_GetInfo) (&info);
		assert_num_eq (CKR_OK, rv);
	}

	assert_num_eq (waitpid (pid, &status, 0), pid);
	assert_num_eq (WEXITSTATUS (status), 66);

	teardown_mock_module (rpc_module);
}

#endif /* OS_UNIX */

#include "test-mock.c"

int
main (int argc,
      char *argv[])
{
	CK_MECHANISM_TYPE mechanisms[] = {
		CKM_MOCK_CAPITALIZE,
		CKM_MOCK_PREFIX,
		CKM_MOCK_GENERATE,
		CKM_MOCK_WRAP,
		CKM_MOCK_DERIVE,
		CKM_MOCK_COUNT,
		0,
	};

	mock_module_init ();
	p11_library_init ();

	/* Override the mechanisms that the RPC mechanism will handle */
	p11_rpc_mechanisms_override_supported = mechanisms;

	p11_test (test_new_free, "/rpc/new-free");
	p11_test (test_uint16, "/rpc/uint16");
	p11_test (test_uint16_static, "/rpc/uint16-static");
	p11_test (test_uint32, "/rpc/uint32");
	p11_test (test_uint32_static, "/rpc/uint32-static");
	p11_test (test_uint64, "/rpc/uint64");
	p11_test (test_uint64_static, "/rpc/uint64-static");
	p11_test (test_byte_array, "/rpc/byte-array");
	p11_test (test_byte_array_null, "/rpc/byte-array-null");
	p11_test (test_byte_array_too_long, "/rpc/byte-array-too-long");
	p11_test (test_byte_array_static, "/rpc/byte-array-static");
	p11_test (test_byte_value, "/rpc/byte-value");
	p11_test (test_ulong_value, "/rpc/ulong-value");
	p11_test (test_attribute_array_value, "/rpc/attribute-array-value");
	p11_test (test_mechanism_type_array_value, "/rpc/mechanism-type-array-value");
	p11_test (test_date_value, "/rpc/date-value");
	p11_test (test_date_value_empty, "/rpc/date-value-empty");
	p11_test (test_byte_array_value, "/rpc/byte-array-value");
	p11_test (test_mechanism_value, "/rpc/mechanism-value");
	p11_test (test_message_write, "/rpc/message-write");

	p11_test (test_initialize_fails_on_client, "/rpc/initialize-fails-on-client");
	p11_test (test_initialize_fails_on_server, "/rpc/initialize-fails-on-server");
	p11_test (test_initialize, "/rpc/initialize");
	p11_test (test_not_initialized, "/rpc/not-initialized");
	p11_test (test_transport_fails, "/rpc/transport-fails");
	p11_test (test_transport_bad_parse, "/rpc/transport-bad-parse");
	p11_test (test_transport_short_error, "/rpc/transport-short-error");
	p11_test (test_transport_invalid_error, "/rpc/transport-invalid-error");
	p11_test (test_transport_wrong_response, "/rpc/transport-wrong-response");
	p11_test (test_transport_bad_contents, "/rpc/transport-bad-contents");
	p11_test (test_get_info_stand_in, "/rpc/get-info-stand-in");
	p11_test (test_get_slot_list_no_device, "/rpc/get-slot-list-no-device");
	p11_test (test_simultaneous_functions, "/rpc/simultaneous-functions");

#ifdef OS_UNIX
	p11_test (test_fork_and_reinitialize, "/rpc/fork-and-reinitialize");
#endif

	test_mock_add_tests ("/rpc", NULL);

	return  p11_test_run (argc, argv);
}
