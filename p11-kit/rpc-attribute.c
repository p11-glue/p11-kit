/*
 * Copyright (C) 2008 Stefan Walter
 * Copyright (C) 2012 Red Hat Inc.
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

#define P11_DEBUG_FLAG P11_DEBUG_RPC
#include "debug.h"
#include "private.h"
#include "rpc-attribute.h"

#include <assert.h>
#include <string.h>

#define ELEMS(x) (sizeof (x) / sizeof (x[0]))

static p11_rpc_value_type
map_attribute_to_value_type (CK_ATTRIBUTE_TYPE type)
{
	switch (type) {
	case CKA_TOKEN:
	case CKA_PRIVATE:
	case CKA_TRUSTED:
	case CKA_SENSITIVE:
	case CKA_ENCRYPT:
	case CKA_DECRYPT:
	case CKA_WRAP:
	case CKA_UNWRAP:
	case CKA_SIGN:
	case CKA_SIGN_RECOVER:
	case CKA_VERIFY:
	case CKA_VERIFY_RECOVER:
	case CKA_DERIVE:
	case CKA_EXTRACTABLE:
	case CKA_LOCAL:
	case CKA_NEVER_EXTRACTABLE:
	case CKA_ALWAYS_SENSITIVE:
	case CKA_MODIFIABLE:
	case CKA_COPYABLE:
	case CKA_SECONDARY_AUTH: /* Deprecated */
	case CKA_ALWAYS_AUTHENTICATE:
	case CKA_WRAP_WITH_TRUSTED:
	case CKA_RESET_ON_INIT:
	case CKA_HAS_RESET:
	case CKA_COLOR:
	case CKA_IBM_RESTRICTABLE:
	case CKA_IBM_NEVER_MODIFIABLE:
	case CKA_IBM_RETAINKEY:
	case CKA_IBM_ATTRBOUND:
	case CKA_IBM_USE_AS_DATA:
	case CKA_IBM_PROTKEY_EXTRACTABLE:
	case CKA_IBM_PROTKEY_NEVER_EXTRACTABLE:
	case CKA_ENCAPSULATE:
	case CKA_DECAPSULATE:
		return P11_RPC_VALUE_BYTE;
	case CKA_CLASS:
	case CKA_CERTIFICATE_TYPE:
	case CKA_CERTIFICATE_CATEGORY:
	case CKA_JAVA_MIDP_SECURITY_DOMAIN:
	case CKA_KEY_TYPE:
	case CKA_MODULUS_BITS:
	case CKA_PRIME_BITS:
	case CKA_SUB_PRIME_BITS:
	case CKA_VALUE_BITS:
	case CKA_VALUE_LEN:
	case CKA_KEY_GEN_MECHANISM:
	case CKA_AUTH_PIN_FLAGS: /* Deprecated */
	case CKA_HW_FEATURE_TYPE:
	case CKA_PIXEL_X:
	case CKA_PIXEL_Y:
	case CKA_RESOLUTION:
	case CKA_CHAR_ROWS:
	case CKA_CHAR_COLUMNS:
	case CKA_BITS_PER_PIXEL:
	case CKA_MECHANISM_TYPE:
	case CKA_IBM_DILITHIUM_KEYFORM:
	case CKA_IBM_CCA_AES_KEY_MODE:
	case CKA_IBM_STD_COMPLIANCE1:
	case CKA_IBM_KEYTYPE:
	case CKA_IBM_KYBER_KEYFORM:
	case CKA_PARAMETER_SET:
	case CKA_HSS_LEVELS:
	case CKA_HSS_LMS_TYPE:
	case CKA_HSS_LMOTS_TYPE:
	case CKA_HSS_KEYS_REMAINING:
		return P11_RPC_VALUE_ULONG;
	case CKA_WRAP_TEMPLATE:
	case CKA_UNWRAP_TEMPLATE:
	case CKA_DERIVE_TEMPLATE:
	case CKA_ENCAPSULATE_TEMPLATE:
	case CKA_DECAPSULATE_TEMPLATE:
		return P11_RPC_VALUE_ATTRIBUTE_ARRAY;
	case CKA_ALLOWED_MECHANISMS:
		return P11_RPC_VALUE_MECHANISM_TYPE_ARRAY;
	case CKA_START_DATE:
	case CKA_END_DATE:
		return P11_RPC_VALUE_DATE;
	default:
		p11_debug ("cannot determine the type of attribute value for %lu; assuming byte array",
			   type);
		/* fallthrough */
	case CKA_LABEL:
	case CKA_APPLICATION:
	case CKA_VALUE:
	case CKA_OBJECT_ID:
	case CKA_ISSUER:
	case CKA_SERIAL_NUMBER:
	case CKA_AC_ISSUER:
	case CKA_OWNER:
	case CKA_ATTR_TYPES:
	case CKA_URL:
	case CKA_HASH_OF_SUBJECT_PUBLIC_KEY:
	case CKA_HASH_OF_ISSUER_PUBLIC_KEY:
	case CKA_CHECK_VALUE:
	case CKA_SUBJECT:
	case CKA_ID:
	case CKA_MODULUS:
	case CKA_PUBLIC_EXPONENT:
	case CKA_PRIVATE_EXPONENT:
	case CKA_PRIME_1:
	case CKA_PRIME_2:
	case CKA_EXPONENT_1:
	case CKA_EXPONENT_2:
	case CKA_COEFFICIENT:
	case CKA_PRIME:
	case CKA_SUBPRIME:
	case CKA_BASE:
	case CKA_EC_PARAMS:
		/* same as CKA_ECDSA_PARAMS */
	case CKA_EC_POINT:
	case CKA_CHAR_SETS:
	case CKA_ENCODING_METHODS:
	case CKA_MIME_TYPES:
	case CKA_REQUIRED_CMS_ATTRIBUTES:
	case CKA_DEFAULT_CMS_ATTRIBUTES:
	case CKA_SUPPORTED_CMS_ATTRIBUTES:
	case CKA_IBM_OPAQUE:
	case CKA_IBM_OPAQUE_REENC:
	case CKA_IBM_OPAQUE_OLD:
	case CKA_IBM_CV:
	case CKA_IBM_MACKEY:
	case CKA_IBM_STRUCT_PARAMS:
	case CKA_IBM_OPAQUE_PKEY:
	case CKA_IBM_DILITHIUM_MODE:
	case CKA_IBM_DILITHIUM_RHO:
	case CKA_IBM_DILITHIUM_SEED:
	case CKA_IBM_DILITHIUM_TR:
	case CKA_IBM_DILITHIUM_S1:
	case CKA_IBM_DILITHIUM_S2:
	case CKA_IBM_DILITHIUM_T0:
	case CKA_IBM_DILITHIUM_T1:
	case CKA_IBM_KYBER_MODE:
	case CKA_IBM_KYBER_PK:
	case CKA_IBM_KYBER_SK:
		return P11_RPC_VALUE_BYTE_ARRAY;
	}
}

static bool
p11_rpc_message_get_byte_value (p11_rpc_message *msg,
			        p11_buffer *buffer,
			        size_t *offset,
			        void *value,
			        CK_ULONG *value_length,
			        size_t unused)
{
	return p11_rpc_buffer_get_byte_value (buffer, offset, value, value_length);
}

static bool
p11_rpc_message_get_ulong_value (p11_rpc_message *msg,
			         p11_buffer *buffer,
			         size_t *offset,
			         void *value,
			         CK_ULONG *value_length,
			         size_t unused)
{
	return p11_rpc_buffer_get_ulong_value (buffer, offset, value, value_length);
}

static bool
p11_rpc_message_get_attribute_recursive (p11_rpc_message *msg,
					 p11_buffer *buffer,
					 size_t *offset,
					 CK_ATTRIBUTE *attr,
					 size_t depth);

static bool
p11_rpc_message_get_attribute_array_value (p11_rpc_message *msg,
					   p11_buffer *buffer,
					   size_t *offset,
					   void *value,
					   CK_ULONG *value_length,
					   size_t depth)
{
	uint32_t count, i;
	CK_ATTRIBUTE *attr = value;

	/* To enforce the same depth as proto_read_attribute_buffer_array
	 * we need >= instead of > because this function is only called
	 * for recursive attribute types instead of all types */
	if (depth >= P11_RPC_MAX_RECURSION_DEPTH) {
		p11_debug ("recursion depth limit reached");
		return false;
	}

	if (!p11_rpc_buffer_get_uint32 (buffer, offset, &count))
		return false;

	/* Guard against overflow */
	if (count != 0 && (SIZE_MAX / count) < sizeof (CK_ATTRIBUTE))
		return false;

	if (value_length != NULL)
		*value_length = count * sizeof (CK_ATTRIBUTE);

	if (value == NULL)
		return true;

	for (i = 0; i < count; ++i)
		if (!p11_rpc_message_get_attribute_recursive (msg, buffer, offset,
							      attr + i, depth + 1))
			return false;

	return true;
}

static bool
p11_rpc_message_get_mechanism_type_array_value (p11_rpc_message *msg,
					        p11_buffer *buffer,
					        size_t *offset,
					        void *value,
					        CK_ULONG *value_length,
					        size_t unused)
{
	return p11_rpc_buffer_get_mechanism_type_array_value (buffer, offset, value, value_length);
}

static bool
p11_rpc_message_get_date_value (p11_rpc_message *msg,
			        p11_buffer *buffer,
			        size_t *offset,
			        void *value,
			        CK_ULONG *value_length,
			        size_t unused)
{
	return p11_rpc_buffer_get_date_value (buffer, offset, value, value_length);
}

static bool
p11_rpc_message_get_byte_array_value (p11_rpc_message *msg,
				      p11_buffer *buffer,
				      size_t *offset,
				      void *value,
				      CK_ULONG *value_length,
				      size_t unused)
{
	return p11_rpc_buffer_get_byte_array_value (buffer, offset, value, value_length);
}

typedef struct {
	p11_rpc_value_type type;
	p11_rpc_value_encoder encode;
	p11_rpc_message_decoder decode;
} p11_rpc_attribute_serializer;

static p11_rpc_attribute_serializer p11_rpc_attribute_serializers[] = {
	{ P11_RPC_VALUE_BYTE, p11_rpc_buffer_add_byte_value, p11_rpc_message_get_byte_value },
	{ P11_RPC_VALUE_ULONG, p11_rpc_buffer_add_ulong_value, p11_rpc_message_get_ulong_value },
	{ P11_RPC_VALUE_ATTRIBUTE_ARRAY, p11_rpc_buffer_add_attribute_array_value, p11_rpc_message_get_attribute_array_value },
	{ P11_RPC_VALUE_MECHANISM_TYPE_ARRAY, p11_rpc_buffer_add_mechanism_type_array_value, p11_rpc_message_get_mechanism_type_array_value },
	{ P11_RPC_VALUE_DATE, p11_rpc_buffer_add_date_value, p11_rpc_message_get_date_value },
	{ P11_RPC_VALUE_BYTE_ARRAY, p11_rpc_buffer_add_byte_array_value, p11_rpc_message_get_byte_array_value }
};

P11_STATIC_ASSERT(sizeof(CK_BYTE) <= sizeof(uint8_t));

void
p11_rpc_buffer_add_byte_value (p11_buffer *buffer,
			       const void *value,
			       CK_ULONG value_length)
{
	CK_BYTE byte_value = 0;

	/* Check if value can be converted to CK_BYTE. */
	if (value_length > sizeof (CK_BYTE)) {
		p11_buffer_fail (buffer);
		return;
	}
	if (value)
		memcpy (&byte_value, value, value_length);

	p11_rpc_buffer_add_byte (buffer, byte_value);
}

void
p11_rpc_buffer_add_ulong_value (p11_buffer *buffer,
				const void *value,
				CK_ULONG value_length)
{
	CK_ULONG ulong_value = 0;

	/* Check if value can be converted to CK_ULONG. */
	if (value_length > sizeof (CK_ULONG)) {
		p11_buffer_fail (buffer);
		return;
	}
	if (value)
		memcpy (&ulong_value, value, value_length);

	/* Check if ulong_value can be converted to uint64_t. */
	if (ulong_value > UINT64_MAX) {
		p11_buffer_fail (buffer);
		return;
	}

	p11_rpc_buffer_add_uint64 (buffer, ulong_value);
}

void
p11_rpc_buffer_add_attribute_array_value (p11_buffer *buffer,
					  const void *value,
					  CK_ULONG value_length)
{
	const CK_ATTRIBUTE *attrs = value;
	size_t count = value_length / sizeof (CK_ATTRIBUTE);
	size_t i;

	/* Check if count can be converted to uint32_t. */
	if (count > UINT32_MAX) {
		p11_buffer_fail (buffer);
		return;
	}

	/* When value is NULL, write an empty attribute array */
	if (attrs == NULL) {
		p11_rpc_buffer_add_uint32 (buffer, 0);
		return;
	}

	/* Write the number of items */
	p11_rpc_buffer_add_uint32 (buffer, count);

	/* Actually write the attributes.  */
	for (i = 0; i < count; i++) {
		const CK_ATTRIBUTE *attr = &(attrs[i]);
		p11_rpc_buffer_add_attribute (buffer, attr);
	}
}

void
p11_rpc_buffer_add_mechanism_type_array_value (p11_buffer *buffer,
					       const void *value,
					       CK_ULONG value_length)
{
	size_t count = value_length / sizeof (CK_MECHANISM_TYPE);

	/* Check if count can be converted to uint32_t. */
	if (count > UINT32_MAX) {
		p11_buffer_fail (buffer);
		return;
	}

	/* Write the number of items */
	p11_rpc_buffer_add_uint32 (buffer, count);

	if (value) {
		const CK_MECHANISM_TYPE *mechs = value;
		size_t i;

		for (i = 0; i < count; i++) {
			if (mechs[i] > UINT64_MAX) {
				p11_buffer_fail (buffer);
				return;
			}
			p11_rpc_buffer_add_uint64 (buffer, mechs[i]);
		}
	}
}

void
p11_rpc_buffer_add_date_value (p11_buffer *buffer,
			       const void *value,
			       CK_ULONG value_length)
{
	CK_DATE date_value;
	unsigned char array[8];
	unsigned char *ptr = NULL;

	/* Check if value is empty or can be converted to CK_DATE. */
	if (value_length != 0 && value_length != sizeof (CK_DATE)) {
		p11_buffer_fail (buffer);
		return;
	}

	if (value && value_length == sizeof (CK_DATE)) {
		memcpy (&date_value, value, value_length);
		memcpy (array, date_value.year, 4);
		memcpy (array + 4, date_value.month, 2);
		memcpy (array + 6, date_value.day, 2);
		ptr = array;
	}

	p11_rpc_buffer_add_byte_array (buffer, ptr, value_length);
}

void
p11_rpc_buffer_add_byte_array_value (p11_buffer *buffer,
				     const void *value,
				     CK_ULONG value_length)
{
	/* Check if value length can be converted to uint32_t, as
	 * p11_rpc_buffer_add_byte_array expects. */
	if (value_length > UINT32_MAX) {
		p11_buffer_fail (buffer);
		return;
	}

	p11_rpc_buffer_add_byte_array (buffer, value, value_length);
}

void
p11_rpc_buffer_add_attribute (p11_buffer *buffer, const CK_ATTRIBUTE *attr)
{
	unsigned char validity;
	p11_rpc_attribute_serializer *serializer;
	p11_rpc_value_type value_type;

	/* The attribute type */
	if (attr->type > UINT32_MAX) {
		p11_buffer_fail (buffer);
		return;
	}
	p11_rpc_buffer_add_uint32 (buffer, attr->type);

	/* Write out the attribute validity */
	validity = (((CK_LONG)attr->ulValueLen) == -1) ? 0 : 1;
	p11_rpc_buffer_add_byte (buffer, validity);

	if (!validity)
		return;

	/* The attribute length */
	if (attr->ulValueLen > UINT32_MAX) {
		p11_buffer_fail (buffer);
		return;
	}
	p11_rpc_buffer_add_uint32 (buffer, attr->ulValueLen);

	/* The attribute value */
	value_type = map_attribute_to_value_type (attr->type);
	assert (value_type < ELEMS (p11_rpc_attribute_serializers));
	serializer = &p11_rpc_attribute_serializers[value_type];
	assert (serializer != NULL);
	serializer->encode (buffer, attr->pValue, attr->ulValueLen);
}

bool
p11_rpc_buffer_get_byte_value (p11_buffer *buffer,
			       size_t *offset,
			       void *value,
			       CK_ULONG *value_length)
{
	unsigned char val;

	if (!p11_rpc_buffer_get_byte (buffer, offset, &val))
		return false;

	if (value) {
		CK_BYTE byte_value = val;
		memcpy (value, &byte_value, sizeof (CK_BYTE));
	}

	if (value_length)
		*value_length = sizeof (CK_BYTE);

	return true;
}

bool
p11_rpc_buffer_get_ulong_value (p11_buffer *buffer,
				size_t *offset,
				void *value,
				CK_ULONG *value_length)
{
	uint64_t val;

	if (!p11_rpc_buffer_get_uint64 (buffer, offset, &val))
		return false;

	if (value) {
		CK_ULONG ulong_value = val;
		memcpy (value, &ulong_value, sizeof (CK_ULONG));
	}

	if (value_length)
		*value_length = sizeof (CK_ULONG);

	return true;
}

bool
p11_rpc_buffer_get_attribute_array_value (p11_buffer *buffer,
					  size_t *offset,
					  void *value,
					  CK_ULONG *value_length)
{
	return p11_rpc_message_get_attribute_array_value (NULL, buffer, offset, value, value_length, 0);
}

bool
p11_rpc_buffer_get_mechanism_type_array_value (p11_buffer *buffer,
					       size_t *offset,
					       void *value,
					       CK_ULONG *value_length)
{
	uint32_t count, i;
	CK_MECHANISM_TYPE *mech, temp;

	if (!p11_rpc_buffer_get_uint32 (buffer, offset, &count))
		return false;

	/* Guard against overflow */
	if (count != 0 && (SIZE_MAX / count) < sizeof (CK_MECHANISM_TYPE))
		return false;

	if (!value) {
		memset (&temp, 0, sizeof (CK_MECHANISM_TYPE));
		mech = &temp;
	} else
		mech = value;

	for (i = 0; i < count; i++) {
		CK_ULONG len;
		if (!p11_rpc_buffer_get_ulong_value (buffer, offset, mech, &len))
			return false;
		if (value)
			mech++;
	}

	if (value_length)
		*value_length = count * sizeof (CK_MECHANISM_TYPE);

	return true;
}

bool
p11_rpc_buffer_get_date_value (p11_buffer *buffer,
			       size_t *offset,
			       void *value,
			       CK_ULONG *value_length)
{
	CK_DATE date_value = { 0 };
	const unsigned char *array;
	size_t array_length;

	/* The encoded date may be empty. */
	if (!p11_rpc_buffer_get_byte_array (buffer, offset,
					    &array, &array_length) ||
	    (array_length != 0 && array_length != sizeof (CK_DATE)))
		return false;

	if (value && array_length == sizeof (CK_DATE)) {
		memcpy (date_value.year, array, 4);
		memcpy (date_value.month, array + 4, 2);
		memcpy (date_value.day, array + 6, 2);
		memcpy (value, &date_value, sizeof (CK_DATE));
	}

	if (value_length)
		*value_length = array_length;

	return true;
}

bool
p11_rpc_buffer_get_byte_array_value (p11_buffer *buffer,
				     size_t *offset,
				     void *value,
				     CK_ULONG *value_length)
{
	const unsigned char *val;
	size_t len;

	if (!p11_rpc_buffer_get_byte_array (buffer, offset, &val, &len))
		return false;

	if (val && value)
		memcpy (value, val, len);

	if (value_length)
		*value_length = len;

	return true;
}

static bool
p11_rpc_message_get_attribute_recursive (p11_rpc_message *msg,
					 p11_buffer *buffer,
					 size_t *offset,
					 CK_ATTRIBUTE *attr,
					 size_t depth)
{
	uint32_t type, length;
	CK_ULONG decode_length;
	size_t saved_offset;
	unsigned char validity;
	p11_rpc_attribute_serializer *serializer;
	p11_rpc_value_type value_type;

	/* The attribute type */
	if (!p11_rpc_buffer_get_uint32 (buffer, offset, &type))
		return false;

	/* Attribute validity */
	if (!p11_rpc_buffer_get_byte (buffer, offset, &validity))
		return false;

	/* Not a valid attribute */
	if (!validity) {
		attr->ulValueLen = ((CK_ULONG)-1);
		attr->type = type;
		return true;
	}

	if (!p11_rpc_buffer_get_uint32 (buffer, offset, &length))
		return false;

	if (length == 0) {
		attr->pValue = NULL;
	} else if (msg != NULL) {
		/* Allocate memory for the attribute value */
		attr->pValue = p11_rpc_message_alloc_extra (msg, length);
		if (attr->pValue == NULL)
			return false;
	}

	value_type = map_attribute_to_value_type (type);
	assert (value_type < ELEMS (p11_rpc_attribute_serializers));
	serializer = &p11_rpc_attribute_serializers[value_type];
	assert (serializer != NULL);

	/* Get the attribute value length */
	saved_offset = *offset;
	if (!serializer->decode (NULL, buffer, offset, NULL, &decode_length, depth))
		return false;

	/* Decode the attribute value */
	if (attr->pValue != NULL) {
		if (length < decode_length)
			return false;

		*offset = saved_offset;
		if (!serializer->decode (msg, buffer, offset, attr->pValue, NULL, depth))
			return false;
	}

	attr->type = type;
	attr->ulValueLen = length;
	return true;
}

bool
p11_rpc_message_get_attribute (p11_rpc_message *msg,
			       p11_buffer *buffer,
			       size_t *offset,
			       CK_ATTRIBUTE *attr)
{
	return p11_rpc_message_get_attribute_recursive (msg, buffer, offset, attr, 0);
}

bool
p11_rpc_buffer_get_attribute (p11_buffer *buffer,
			      size_t *offset,
			      CK_ATTRIBUTE *attr)
{
	return p11_rpc_message_get_attribute (NULL, buffer, offset, attr);
}
