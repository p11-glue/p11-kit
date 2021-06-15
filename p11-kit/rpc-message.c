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
#include "library.h"
#include "message.h"
#include "private.h"
#include "rpc-message.h"

#include <assert.h>
#include <errno.h>
#include <string.h>

#ifdef ENABLE_NLS
#include <libintl.h>
#define _(x) dgettext(PACKAGE_NAME, x)
#else
#define _(x) (x)
#endif

#define ELEMS(x) (sizeof (x) / sizeof (x[0]))

void
p11_rpc_message_init (p11_rpc_message *msg,
                      p11_buffer *input,
                      p11_buffer *output)
{
	assert (input != NULL);
	assert (output != NULL);
	assert (output->ffree != NULL);
	assert (output->frealloc != NULL);

	memset (msg, 0, sizeof (*msg));

	msg->output = output;
	msg->input = input;
}

void
p11_rpc_message_clear (p11_rpc_message *msg)
{
	void *allocated;
	void **data;

	assert (msg != NULL);

	/* Free up the extra allocated memory */
	allocated = msg->extra;
	while (allocated != NULL) {
		data = (void **)allocated;

		/* Pointer to the next allocation */
		allocated = *data;
		assert (msg->output->ffree);
		(msg->output->ffree) (data);
	}

	msg->output = NULL;
	msg->input = NULL;
	msg->extra = NULL;
}

void *
p11_rpc_message_alloc_extra (p11_rpc_message *msg,
                             size_t length)
{
	void **data;

	assert (msg != NULL);

	if (length > 0x7fffffff)
		return NULL;

	assert (msg->output->frealloc != NULL);
	data = (msg->output->frealloc) (NULL, sizeof (void *) + length);
	if (data == NULL)
		return NULL;

	/* Munch up the memory to help catch bugs */
	memset (data, 0xff, sizeof (void *) + length);

	/* Store pointer to next allocated block at beginning */
	*data = msg->extra;
	msg->extra = data;

	/* Data starts after first pointer */
	return (void *)(data + 1);
}

void *
p11_rpc_message_alloc_extra_array (p11_rpc_message *msg,
				   size_t nmemb,
				   size_t size)
{
	if (nmemb != 0 && (SIZE_MAX - sizeof (void *)) / nmemb < size) {
		errno = ENOMEM;
		return NULL;
	}
	return p11_rpc_message_alloc_extra (msg, nmemb * size);
}

bool
p11_rpc_message_prep (p11_rpc_message *msg,
                      int call_id,
                      p11_rpc_message_type type)
{
	int len;

	assert (type != 0);
	assert (call_id >= P11_RPC_CALL_ERROR);
	assert (call_id < P11_RPC_CALL_MAX);

	p11_buffer_reset (msg->output, 0);
	msg->signature = NULL;

	/* The call id and signature */
	if (type == P11_RPC_REQUEST)
		msg->signature = p11_rpc_calls[call_id].request;
	else if (type == P11_RPC_RESPONSE)
		msg->signature = p11_rpc_calls[call_id].response;
	else
		assert_not_reached ();
	assert (msg->signature != NULL);
	msg->sigverify = msg->signature;

	msg->call_id = call_id;
	msg->call_type = type;

	/* Encode the two of them */
	p11_rpc_buffer_add_uint32 (msg->output, call_id);
	if (msg->signature) {
		len = strlen (msg->signature);
		p11_rpc_buffer_add_byte_array (msg->output, (unsigned char*)msg->signature, len);
	}

	msg->parsed = 0;
	return !p11_buffer_failed (msg->output);
}

bool
p11_rpc_message_parse (p11_rpc_message *msg,
                       p11_rpc_message_type type)
{
	const unsigned char *val;
	size_t len;
	uint32_t call_id;

	assert (msg != NULL);
	assert (msg->input != NULL);

	msg->parsed = 0;

	/* Pull out the call identifier */
	if (!p11_rpc_buffer_get_uint32 (msg->input, &msg->parsed, &call_id)) {
		p11_message (_("invalid message: couldn't read call identifier"));
		return false;
	}

	msg->signature = msg->sigverify = NULL;

	/* The call id and signature */
	if (call_id >= P11_RPC_CALL_MAX ||
	    (type == P11_RPC_REQUEST && call_id == P11_RPC_CALL_ERROR)) {
		p11_message (_("invalid message: bad call id: %d"), call_id);
		return false;
	}
	if (type == P11_RPC_REQUEST)
		msg->signature = p11_rpc_calls[call_id].request;
	else if (type == P11_RPC_RESPONSE)
		msg->signature = p11_rpc_calls[call_id].response;
	else
		assert_not_reached ();
	assert (msg->signature != NULL);
	msg->call_id = call_id;
	msg->call_type = type;
	msg->sigverify = msg->signature;

	/* Verify the incoming signature */
	if (!p11_rpc_buffer_get_byte_array (msg->input, &msg->parsed, &val, &len) ||
	    /* This can happen if the length header == 0xffffffff */
	    val == NULL) {
		p11_message (_("invalid message: couldn't read signature"));
		return false;
	}

	if ((strlen (msg->signature) != len) || (memcmp (val, msg->signature, len) != 0)) {
		p11_message (_("invalid message: signature doesn't match"));
		return false;
	}

	return true;
}

bool
p11_rpc_message_verify_part (p11_rpc_message *msg,
                             const char* part)
{
	int len;
	bool ok;

	if (!msg->sigverify)
		return true;

	len = strlen (part);
	ok = (strncmp (msg->sigverify, part, len) == 0);
	if (ok)
		msg->sigverify += len;
	return ok;
}

bool
p11_rpc_message_write_attribute_buffer (p11_rpc_message *msg,
                                        CK_ATTRIBUTE_PTR arr,
                                        CK_ULONG num)
{
	CK_ATTRIBUTE_PTR attr;
	CK_ULONG i;

	assert (num == 0 || arr != NULL);
	assert (msg != NULL);
	assert (msg->output != NULL);

	/* Make sure this is in the right order */
	assert (!msg->signature || p11_rpc_message_verify_part (msg, "fA"));

	/* Write the number of items */
	p11_rpc_buffer_add_uint32 (msg->output, num);

	for (i = 0; i < num; ++i) {
		attr = &(arr[i]);

		/* The attribute type */
		p11_rpc_buffer_add_uint32 (msg->output, attr->type);

		/* And the attribute buffer length */
		p11_rpc_buffer_add_uint32 (msg->output, attr->pValue ? attr->ulValueLen : 0);
	}

	return !p11_buffer_failed (msg->output);
}

bool
p11_rpc_message_write_attribute_array (p11_rpc_message *msg,
                                       CK_ATTRIBUTE_PTR arr,
                                       CK_ULONG num)
{
	CK_ULONG i;

	assert (num == 0 || arr != NULL);
	assert (msg != NULL);
	assert (msg->output != NULL);

	/* Make sure this is in the right order */
	assert (!msg->signature || p11_rpc_message_verify_part (msg, "aA"));

	/* Write the number of items */
	p11_rpc_buffer_add_uint32 (msg->output, num);

	for (i = 0; i < num; ++i)
		p11_rpc_buffer_add_attribute (msg->output, &(arr[i]));

	return !p11_buffer_failed (msg->output);
}

bool
p11_rpc_message_read_byte (p11_rpc_message *msg,
                           CK_BYTE *val)
{
	assert (msg != NULL);
	assert (msg->input != NULL);

	/* Make sure this is in the right order */
	assert (!msg->signature || p11_rpc_message_verify_part (msg, "y"));
	return p11_rpc_buffer_get_byte (msg->input, &msg->parsed, val);
}

bool
p11_rpc_message_write_byte (p11_rpc_message *msg,
                            CK_BYTE val)
{
	assert (msg != NULL);
	assert (msg->output != NULL);

	/* Make sure this is in the right order */
	assert (!msg->signature || p11_rpc_message_verify_part (msg, "y"));
	p11_rpc_buffer_add_byte (msg->output, val);
	return !p11_buffer_failed (msg->output);
}

bool
p11_rpc_message_read_ulong (p11_rpc_message *msg,
                            CK_ULONG *val)
{
	uint64_t v;

	assert (msg != NULL);
	assert (msg->input != NULL);

	/* Make sure this is in the right order */
	assert (!msg->signature || p11_rpc_message_verify_part (msg, "u"));

	if (!p11_rpc_buffer_get_uint64 (msg->input, &msg->parsed, &v))
		return false;
	if (val)
		*val = (CK_ULONG)v;
	return true;
}

bool
p11_rpc_message_write_ulong (p11_rpc_message *msg,
                             CK_ULONG val)
{
	assert (msg != NULL);
	assert (msg->output != NULL);

	/* Make sure this is in the right order */
	assert (!msg->signature || p11_rpc_message_verify_part (msg, "u"));
	p11_rpc_buffer_add_uint64 (msg->output, val);
	return !p11_buffer_failed (msg->output);
}

bool
p11_rpc_message_write_byte_buffer (p11_rpc_message *msg,
                                   CK_ULONG count)
{
	assert (msg != NULL);
	assert (msg->output != NULL);

	/* Make sure this is in the right order */
	assert (!msg->signature || p11_rpc_message_verify_part (msg, "fy"));
	p11_rpc_buffer_add_uint32 (msg->output, count);
	return !p11_buffer_failed (msg->output);
}

bool
p11_rpc_message_write_byte_buffer_null (p11_rpc_message *msg,
                                        CK_ULONG *count)
{
	assert (msg != NULL);
	assert (msg->output != NULL);

	/* Make sure this is in the right order */
	assert (!msg->signature || p11_rpc_message_verify_part (msg, "fy"));
	/* Validity byte */
	p11_rpc_buffer_add_byte (msg->output, count != NULL ? 1 : 0);
	if (count != NULL)
		p11_rpc_buffer_add_uint32 (msg->output, *count);
	return !p11_buffer_failed (msg->output);
}

bool
p11_rpc_message_write_byte_array (p11_rpc_message *msg,
                                  CK_BYTE_PTR arr,
                                  CK_ULONG num)
{
	assert (msg != NULL);
	assert (msg->output != NULL);

	/* Make sure this is in the right order */
	assert (!msg->signature || p11_rpc_message_verify_part (msg, "ay"));

	/* No array, no data, just length */
	if (!arr && num != 0) {
		p11_rpc_buffer_add_byte (msg->output, 0);
		p11_rpc_buffer_add_uint32 (msg->output, num);
	} else {
		p11_rpc_buffer_add_byte (msg->output, 1);
		p11_rpc_buffer_add_byte_array (msg->output, arr, num);
	}

	return !p11_buffer_failed (msg->output);
}

bool
p11_rpc_message_write_ulong_buffer (p11_rpc_message *msg,
                                    CK_ULONG count)
{
	assert (msg != NULL);
	assert (msg->output != NULL);

	/* Make sure this is in the right order */
	assert (!msg->signature || p11_rpc_message_verify_part (msg, "fu"));
	p11_rpc_buffer_add_uint32 (msg->output, count);
	return !p11_buffer_failed (msg->output);
}

bool
p11_rpc_message_write_ulong_array (p11_rpc_message *msg,
                                   CK_ULONG_PTR array,
                                   CK_ULONG n_array)
{
	CK_ULONG i;

	assert (msg != NULL);
	assert (msg->output != NULL);

	/* Check that we're supposed to have this at this point */
	assert (!msg->signature || p11_rpc_message_verify_part (msg, "au"));

	/* We send a byte which determines whether there's actual data present or not */
	p11_rpc_buffer_add_byte (msg->output, array ? 1 : 0);
	p11_rpc_buffer_add_uint32 (msg->output, n_array);

	/* Now send the data if valid */
	if (array) {
		for (i = 0; i < n_array; ++i)
			p11_rpc_buffer_add_uint64 (msg->output, array[i]);
	}

	return !p11_buffer_failed (msg->output);
}

bool
p11_rpc_message_read_version (p11_rpc_message *msg,
                              CK_VERSION *version)
{
	assert (msg != NULL);
	assert (msg->input != NULL);
	assert (version != NULL);

	/* Check that we're supposed to have this at this point */
	assert (!msg->signature || p11_rpc_message_verify_part (msg, "v"));

	return p11_rpc_buffer_get_byte (msg->input, &msg->parsed, &version->major) &&
	       p11_rpc_buffer_get_byte (msg->input, &msg->parsed, &version->minor);
}

bool
p11_rpc_message_write_version (p11_rpc_message *msg,
                               CK_VERSION *version)
{
	assert (msg != NULL);
	assert (msg->output != NULL);
	assert (version != NULL);

	/* Check that we're supposed to have this at this point */
	assert (!msg->signature || p11_rpc_message_verify_part (msg, "v"));

	p11_rpc_buffer_add_byte (msg->output, version->major);
	p11_rpc_buffer_add_byte (msg->output, version->minor);

	return !p11_buffer_failed (msg->output);
}

bool
p11_rpc_message_read_space_string (p11_rpc_message *msg,
                                   CK_UTF8CHAR *buffer,
                                   CK_ULONG length)
{
	const unsigned char *data;
	size_t n_data;

	assert (msg != NULL);
	assert (msg->input != NULL);
	assert (buffer != NULL);
	assert (length != 0);

	assert (!msg->signature || p11_rpc_message_verify_part (msg, "s"));

	if (!p11_rpc_buffer_get_byte_array (msg->input, &msg->parsed, &data, &n_data))
		return false;

	if (n_data != length) {
		p11_message (_("invalid length space padded string received: %d != %d"),
		             (int)length, (int)n_data);
		return false;
	}

	memcpy (buffer, data, length);
	return true;
}

bool
p11_rpc_message_write_space_string (p11_rpc_message *msg,
                                    CK_UTF8CHAR *data,
                                    CK_ULONG length)
{
	assert (msg != NULL);
	assert (msg->output != NULL);
	assert (data != NULL);
	assert (length != 0);

	assert (!msg->signature || p11_rpc_message_verify_part (msg, "s"));

	p11_rpc_buffer_add_byte_array (msg->output, data, length);
	return !p11_buffer_failed (msg->output);
}

bool
p11_rpc_message_write_zero_string (p11_rpc_message *msg,
                                   CK_UTF8CHAR *string)
{
	assert (msg != NULL);
	assert (msg->output != NULL);
	assert (string != NULL);

	assert (!msg->signature || p11_rpc_message_verify_part (msg, "z"));

	p11_rpc_buffer_add_byte_array (msg->output, string,
	                               string ? strlen ((char *)string) : 0);
	return !p11_buffer_failed (msg->output);
}

static void *
log_allocator (void *pointer,
               size_t size)
{
	void *result = realloc (pointer, (size_t)size);
	return_val_if_fail (!size || result != NULL, NULL);
	return result;
}

p11_buffer *
p11_rpc_buffer_new (size_t reserve)
{
	return p11_rpc_buffer_new_full (reserve, log_allocator, free);
}

p11_buffer *
p11_rpc_buffer_new_full (size_t reserve,
                         void * (* frealloc) (void *data, size_t size),
                         void (* ffree) (void *data))
{
	p11_buffer *buffer;

	buffer = calloc (1, sizeof (p11_buffer));
	return_val_if_fail (buffer != NULL, NULL);

	p11_buffer_init_full (buffer, NULL, 0, 0, frealloc, ffree);
	if (!p11_buffer_reset (buffer, reserve))
		return_val_if_reached (NULL);

	return buffer;
}

void
p11_rpc_buffer_free (p11_buffer *buf)
{
	if (buf == NULL)
		return;

	p11_buffer_uninit (buf);
	free (buf);
}

void
p11_rpc_buffer_add_byte (p11_buffer *buf,
                         unsigned char value)
{
	p11_buffer_add (buf, &value, 1);
}

int
p11_rpc_buffer_get_byte (p11_buffer *buf,
                         size_t *offset,
                         unsigned char *val)
{
	unsigned char *ptr;
	if (buf->len < 1 || *offset > buf->len - 1) {
		p11_buffer_fail (buf);
		return 0;
	}
	ptr = (unsigned char *)buf->data + *offset;
	if (val != NULL)
		*val = *ptr;
	*offset = *offset + 1;
	return 1;
}

void
p11_rpc_buffer_encode_uint16 (unsigned char* data,
                              uint16_t value)
{
	data[0] = (value >> 8) & 0xff;
	data[1] = (value >> 0) & 0xff;
}

uint16_t
p11_rpc_buffer_decode_uint16 (unsigned char* data)
{
	uint16_t value = data[0] << 8 | data[1];
	return value;
}

void
p11_rpc_buffer_add_uint16 (p11_buffer *buffer,
                           uint16_t value)
{
	size_t offset = buffer->len;
	if (!p11_buffer_append (buffer, 2))
		return_if_reached ();
	p11_rpc_buffer_set_uint16 (buffer, offset, value);
}

bool
p11_rpc_buffer_set_uint16 (p11_buffer *buffer,
                           size_t offset,
                           uint16_t value)
{
	unsigned char *ptr;
	if (buffer->len < 2 || offset > buffer->len - 2) {
		p11_buffer_fail (buffer);
		return false;
	}
	ptr = (unsigned char *)buffer->data + offset;
	p11_rpc_buffer_encode_uint16 (ptr, value);
	return true;
}

bool
p11_rpc_buffer_get_uint16 (p11_buffer *buf,
                           size_t *offset,
                           uint16_t *value)
{
	unsigned char *ptr;
	if (buf->len < 2 || *offset > buf->len - 2) {
		p11_buffer_fail (buf);
		return false;
	}
	ptr = (unsigned char*)buf->data + *offset;
	if (value != NULL)
		*value = p11_rpc_buffer_decode_uint16 (ptr);
	*offset = *offset + 2;
	return true;
}

void
p11_rpc_buffer_encode_uint32 (unsigned char* data,
                          uint32_t value)
{
	data[0] = (value >> 24) & 0xff;
	data[1] = (value >> 16) & 0xff;
	data[2] = (value >> 8) & 0xff;
	data[3] = (value >> 0) & 0xff;
}

uint32_t
p11_rpc_buffer_decode_uint32 (unsigned char* ptr)
{
	uint32_t val = (uint32_t) ptr[0] << 24 | ptr[1] << 16 | ptr[2] << 8 | ptr[3];
	return val;
}

void
p11_rpc_buffer_add_uint32 (p11_buffer *buffer,
                           uint32_t value)
{
	size_t offset = buffer->len;
	if (!p11_buffer_append (buffer, 4))
		return_val_if_reached ();
	p11_rpc_buffer_set_uint32 (buffer, offset, value);
}

bool
p11_rpc_buffer_set_uint32 (p11_buffer *buffer,
                           size_t offset,
                           uint32_t value)
{
	unsigned char *ptr;
	if (buffer->len < 4 || offset > buffer->len - 4) {
		p11_buffer_fail (buffer);
		return false;
	}
	ptr = (unsigned char*)buffer->data + offset;
	p11_rpc_buffer_encode_uint32 (ptr, value);
	return true;
}

bool
p11_rpc_buffer_get_uint32 (p11_buffer *buf,
                           size_t *offset,
                           uint32_t *value)
{
	unsigned char *ptr;
	if (buf->len < 4 || *offset > buf->len - 4) {
		p11_buffer_fail (buf);
		return false;
	}
	ptr = (unsigned char*)buf->data + *offset;
	if (value != NULL)
		*value = p11_rpc_buffer_decode_uint32 (ptr);
	*offset = *offset + 4;
	return true;
}

void
p11_rpc_buffer_add_uint64 (p11_buffer *buffer,
                           uint64_t value)
{
	p11_rpc_buffer_add_uint32 (buffer, ((value >> 32) & 0xffffffff));
	p11_rpc_buffer_add_uint32 (buffer, (value & 0xffffffff));
}

bool
p11_rpc_buffer_get_uint64 (p11_buffer *buf,
                           size_t *offset,
                           uint64_t *value)
{
	size_t off = *offset;
	uint32_t a, b;
	if (!p11_rpc_buffer_get_uint32 (buf, &off, &a) ||
	    !p11_rpc_buffer_get_uint32 (buf, &off, &b))
		return false;
	if (value != NULL)
		*value = ((uint64_t)a) << 32 | b;
	*offset = off;
	return true;
}

void
p11_rpc_buffer_add_byte_array (p11_buffer *buffer,
                               const unsigned char *data,
                               size_t length)
{
	if (data == NULL) {
		p11_rpc_buffer_add_uint32 (buffer, 0xffffffff);
		return;
	} else if (length >= 0x7fffffff) {
		p11_buffer_fail (buffer);
		return;
	}
	p11_rpc_buffer_add_uint32 (buffer, length);
	p11_buffer_add (buffer, data, length);
}

bool
p11_rpc_buffer_get_byte_array (p11_buffer *buf,
                               size_t *offset,
                               const unsigned char **data,
                               size_t *length)
{
	size_t off = *offset;
	uint32_t len;
	if (!p11_rpc_buffer_get_uint32 (buf, &off, &len))
		return false;
	if (len == 0xffffffff) {
		*offset = off;
		if (data)
			*data = NULL;
		if (length)
			*length = 0;
		return true;
	} else if (len >= 0x7fffffff) {
		p11_buffer_fail (buf);
		return false;
	}

	if (buf->len < len || off > buf->len - len) {
		p11_buffer_fail (buf);
		return false;
	}

	if (data)
		*data = (unsigned char *)buf->data + off;
	if (length)
		*length = len;
	*offset = off + len;

	return true;
}

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
	case CKA_IBM_STD_COMPLIANCE1:
	case CKA_IBM_KEYTYPE:
		return P11_RPC_VALUE_ULONG;
	case CKA_WRAP_TEMPLATE:
	case CKA_UNWRAP_TEMPLATE:
	case CKA_DERIVE_TEMPLATE:
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
	case CKA_IBM_CV:
	case CKA_IBM_MACKEY:
	case CKA_IBM_STRUCT_PARAMS:
	case CKA_IBM_OPAQUE_PKEY:
	case CKA_IBM_DILITHIUM_RHO:
	case CKA_IBM_DILITHIUM_SEED:
	case CKA_IBM_DILITHIUM_TR:
	case CKA_IBM_DILITHIUM_S1:
	case CKA_IBM_DILITHIUM_S2:
	case CKA_IBM_DILITHIUM_T0:
	case CKA_IBM_DILITHIUM_T1:
		return P11_RPC_VALUE_BYTE_ARRAY;
	}
}

typedef struct {
	p11_rpc_value_type type;
	p11_rpc_value_encoder encode;
	p11_rpc_value_decoder decode;
} p11_rpc_attribute_serializer;

static p11_rpc_attribute_serializer p11_rpc_attribute_serializers[] = {
	{ P11_RPC_VALUE_BYTE, p11_rpc_buffer_add_byte_value, p11_rpc_buffer_get_byte_value },
	{ P11_RPC_VALUE_ULONG, p11_rpc_buffer_add_ulong_value, p11_rpc_buffer_get_ulong_value },
	{ P11_RPC_VALUE_ATTRIBUTE_ARRAY, p11_rpc_buffer_add_attribute_array_value, p11_rpc_buffer_get_attribute_array_value },
	{ P11_RPC_VALUE_MECHANISM_TYPE_ARRAY, p11_rpc_buffer_add_mechanism_type_array_value, p11_rpc_buffer_get_mechanism_type_array_value },
	{ P11_RPC_VALUE_DATE, p11_rpc_buffer_add_date_value, p11_rpc_buffer_get_date_value },
	{ P11_RPC_VALUE_BYTE_ARRAY, p11_rpc_buffer_add_byte_array_value, p11_rpc_buffer_get_byte_array_value }
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
	uint32_t count, i;
	CK_ATTRIBUTE *attr, temp;

	if (!p11_rpc_buffer_get_uint32 (buffer, offset, &count))
		return false;

	if (!value) {
		memset (&temp, 0, sizeof (CK_ATTRIBUTE));
		attr = &temp;
	} else
		attr = value;

	for (i = 0; i < count; i++) {
		if (!p11_rpc_buffer_get_attribute (buffer, offset, attr))
			return false;
		if (value)
			attr++;
	}

	if (value_length)
		*value_length = count * sizeof (CK_ATTRIBUTE);

	return true;
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
	CK_DATE date_value;
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

bool
p11_rpc_buffer_get_attribute (p11_buffer *buffer,
			      size_t *offset,
			      CK_ATTRIBUTE *attr)
{
	uint32_t type, length, decode_length;
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

	/* Decode the attribute value */
	value_type = map_attribute_to_value_type (type);
	assert (value_type < ELEMS (p11_rpc_attribute_serializers));
	serializer = &p11_rpc_attribute_serializers[value_type];
	assert (serializer != NULL);
	if (!serializer->decode (buffer, offset, attr->pValue, &attr->ulValueLen))
		return false;
	if (!attr->pValue) {
		decode_length = attr->ulValueLen;
		attr->ulValueLen = length;
		if (decode_length > length) {
			return false;
		}
	}
	attr->type = type;
	return true;
}

/* Used to override the supported mechanisms in tests */
CK_MECHANISM_TYPE *p11_rpc_mechanisms_override_supported = NULL;

typedef struct {
	CK_MECHANISM_TYPE type;
	p11_rpc_value_encoder encode;
	p11_rpc_value_decoder decode;
} p11_rpc_mechanism_serializer;

void
p11_rpc_buffer_add_rsa_pkcs_pss_mechanism_value (p11_buffer *buffer,
						 const void *value,
						 CK_ULONG value_length)
{
	CK_RSA_PKCS_PSS_PARAMS params;

	/* Check if value can be converted to CK_RSA_PKCS_PSS_PARAMS. */
	if (value_length != sizeof (CK_RSA_PKCS_PSS_PARAMS)) {
		p11_buffer_fail (buffer);
		return;
	}

	memcpy (&params, value, value_length);

	/* Check if params.hashAlg, params.mgf, and params.sLen can be
	 * converted to uint64_t. */
	if (params.hashAlg > UINT64_MAX || params.mgf > UINT64_MAX ||
	    params.sLen > UINT64_MAX) {
		p11_buffer_fail (buffer);
		return;
	}

	p11_rpc_buffer_add_uint64 (buffer, params.hashAlg);
	p11_rpc_buffer_add_uint64 (buffer, params.mgf);
	p11_rpc_buffer_add_uint64 (buffer, params.sLen);
}

bool
p11_rpc_buffer_get_rsa_pkcs_pss_mechanism_value (p11_buffer *buffer,
						 size_t *offset,
						 void *value,
						 CK_ULONG *value_length)
{
	uint64_t val[3];

	if (!p11_rpc_buffer_get_uint64 (buffer, offset, &val[0]))
		return false;
	if (!p11_rpc_buffer_get_uint64 (buffer, offset, &val[1]))
		return false;
	if (!p11_rpc_buffer_get_uint64 (buffer, offset, &val[2]))
		return false;

	if (value) {
		CK_RSA_PKCS_PSS_PARAMS params;

		params.hashAlg = val[0];
		params.mgf = val[1];
		params.sLen = val[2];

		memcpy (value, &params, sizeof (CK_RSA_PKCS_PSS_PARAMS));
	}

	if (value_length)
		*value_length = sizeof (CK_RSA_PKCS_PSS_PARAMS);

	return true;
}

void
p11_rpc_buffer_add_rsa_pkcs_oaep_mechanism_value (p11_buffer *buffer,
						  const void *value,
						  CK_ULONG value_length)
{
	CK_RSA_PKCS_OAEP_PARAMS params;

	/* Check if value can be converted to CK_RSA_PKCS_OAEP_PARAMS. */
	if (value_length != sizeof (CK_RSA_PKCS_OAEP_PARAMS)) {
		p11_buffer_fail (buffer);
		return;
	}

	memcpy (&params, value, value_length);

	/* Check if params.hashAlg, params.mgf, and params.source can be
	 * converted to uint64_t. */
	if (params.hashAlg > UINT64_MAX || params.mgf > UINT64_MAX ||
	    params.source > UINT64_MAX) {
		p11_buffer_fail (buffer);
		return;
	}

	p11_rpc_buffer_add_uint64 (buffer, params.hashAlg);
	p11_rpc_buffer_add_uint64 (buffer, params.mgf);
	p11_rpc_buffer_add_uint64 (buffer, params.source);

	/* parmas.pSourceData can only be an array of CK_BYTE or
	 * NULL */
	p11_rpc_buffer_add_byte_array (buffer,
				       (unsigned char *)params.pSourceData,
				       params.ulSourceDataLen);
}

bool
p11_rpc_buffer_get_rsa_pkcs_oaep_mechanism_value (p11_buffer *buffer,
						  size_t *offset,
						  void *value,
						  CK_ULONG *value_length)
{
	uint64_t val[3];
	const unsigned char *data;
	size_t len;

	if (!p11_rpc_buffer_get_uint64 (buffer, offset, &val[0]))
		return false;
	if (!p11_rpc_buffer_get_uint64 (buffer, offset, &val[1]))
		return false;
	if (!p11_rpc_buffer_get_uint64 (buffer, offset, &val[2]))
		return false;
	if (!p11_rpc_buffer_get_byte_array (buffer, offset, &data, &len))
		return false;

	if (value) {
		CK_RSA_PKCS_OAEP_PARAMS params;

		params.hashAlg = val[0];
		params.mgf = val[1];
		params.source = val[2];
		params.pSourceData = (void *) data;
		params.ulSourceDataLen = len;

		memcpy (value, &params, sizeof (CK_RSA_PKCS_OAEP_PARAMS));
	}

	if (value_length)
		*value_length = sizeof (CK_RSA_PKCS_OAEP_PARAMS);

	return true;
}

void
p11_rpc_buffer_add_ecdh1_derive_mechanism_value (p11_buffer *buffer,
						 const void *value,
						 CK_ULONG value_length)
{
	CK_ECDH1_DERIVE_PARAMS params;

	/* Check if value can be converted to CK_ECDH1_DERIVE_PARAMS. */
	if (value_length != sizeof (CK_ECDH1_DERIVE_PARAMS)) {
		p11_buffer_fail (buffer);
		return;
	}

	memcpy (&params, value, value_length);

	/* Check if params.kdf can be converted to uint64_t. */
	if (params.kdf > UINT64_MAX) {
		p11_buffer_fail (buffer);
		return;
	}

	p11_rpc_buffer_add_uint64 (buffer, params.kdf);

	/* parmas.shared_data can only be an array of CK_BYTE or
	 * NULL */
	p11_rpc_buffer_add_byte_array (buffer,
				       (unsigned char *)params.shared_data,
				       params.shared_data_len);

	/* parmas.public_data can only be an array of CK_BYTE or
	 * NULL */
	p11_rpc_buffer_add_byte_array (buffer,
				       (unsigned char *)params.public_data,
				       params.public_data_len);
}

bool
p11_rpc_buffer_get_ecdh1_derive_mechanism_value (p11_buffer *buffer,
						 size_t *offset,
						 void *value,
						 CK_ULONG *value_length)
{
	uint64_t val;
	const unsigned char *data1, *data2;
	size_t len1, len2;

	if (!p11_rpc_buffer_get_uint64 (buffer, offset, &val))
		return false;

	if (!p11_rpc_buffer_get_byte_array (buffer, offset, &data1, &len1))
		return false;

	if (!p11_rpc_buffer_get_byte_array (buffer, offset, &data2, &len2))
		return false;


	if (value) {
		CK_ECDH1_DERIVE_PARAMS params;

		params.kdf = val;
		params.shared_data = (void *) data1;
		params.shared_data_len = len1;
		params.public_data = (void *) data2;
		params.public_data_len = len2;

		memcpy (value, &params, sizeof (CK_ECDH1_DERIVE_PARAMS));
	}

	if (value_length)
		*value_length = sizeof (CK_ECDH1_DERIVE_PARAMS);

	return true;
}

void
p11_rpc_buffer_add_ibm_attrbound_wrap_mechanism_value (p11_buffer *buffer,
						       const void *value,
						       CK_ULONG value_length)
{
	CK_IBM_ATTRIBUTEBOUND_WRAP_PARAMS params;

	/* Check if value can be converted to CKM_IBM_ATTRIBUTEBOUND_WRAP. */
	if (value_length != sizeof (CK_IBM_ATTRIBUTEBOUND_WRAP_PARAMS)) {
		p11_buffer_fail (buffer);
		return;
	}

	memcpy (&params, value, value_length);

	/* Check if params.hSignVerifyKey can be converted to uint64_t. */
	if (params.hSignVerifyKey > UINT64_MAX) {
		p11_buffer_fail (buffer);
		return;
	}

	p11_rpc_buffer_add_uint64 (buffer, params.hSignVerifyKey);
}

bool
p11_rpc_buffer_get_ibm_attrbound_wrap_mechanism_value (p11_buffer *buffer,
						       size_t *offset,
						       void *value,
						       CK_ULONG *value_length)
{
	uint64_t val;

	if (!p11_rpc_buffer_get_uint64 (buffer, offset, &val))
		return false;

	if (value) {
		CK_IBM_ATTRIBUTEBOUND_WRAP_PARAMS params;

		params.hSignVerifyKey = val;

		memcpy (value, &params, sizeof (CK_IBM_ATTRIBUTEBOUND_WRAP_PARAMS));
	}

	if (value_length)
		*value_length = sizeof (CK_IBM_ATTRIBUTEBOUND_WRAP_PARAMS);

	return true;
}

void
p11_rpc_buffer_add_aes_iv_mechanism_value (p11_buffer *buffer,
					   const void *value,
					   CK_ULONG value_length)
{
	/* Check if value can be converted to an AES IV. */
	if (value_length != 16) {
		p11_buffer_fail (buffer);
		return;
	}

	p11_rpc_buffer_add_byte_array (buffer,
				       (unsigned char *)value,
				       value_length);
}

bool
p11_rpc_buffer_get_aes_iv_mechanism_value (p11_buffer *buffer,
					   size_t *offset,
					   void *value,
					   CK_ULONG *value_length)
{
	const unsigned char *data;
	size_t len;

	if (!p11_rpc_buffer_get_byte_array (buffer, offset, &data, &len))
		return false;

	if (len != 16)
		return false;

	if (value)
		memcpy (value, data, len);

	if (value_length)
		*value_length = len;

	return true;
}

void
p11_rpc_buffer_add_aes_ctr_mechanism_value (p11_buffer *buffer,
					    const void *value,
					    CK_ULONG value_length)
{
	CK_AES_CTR_PARAMS params;

	/* Check if value can be converted to CK_AES_CTR_PARAMS. */
	if (value_length != sizeof (CK_AES_CTR_PARAMS)) {
		p11_buffer_fail (buffer);
		return;
	}

	memcpy (&params, value, value_length);

	/* Check if params.counter_bits can be converted to uint64_t. */
	if (params.counter_bits > UINT64_MAX) {
		p11_buffer_fail (buffer);
		return;
	}

	p11_rpc_buffer_add_uint64 (buffer, params.counter_bits);

	p11_rpc_buffer_add_byte_array (buffer,
				       (unsigned char *)params.cb,
				       sizeof(params.cb));
}

bool
p11_rpc_buffer_get_aes_ctr_mechanism_value (p11_buffer *buffer,
					    size_t *offset,
					    void *value,
					    CK_ULONG *value_length)
{
	uint64_t val;
	const unsigned char *data;
	size_t len;

	if (!p11_rpc_buffer_get_uint64 (buffer, offset, &val))
		return false;
	if (!p11_rpc_buffer_get_byte_array (buffer, offset, &data, &len))
		return false;

	if (value) {
		CK_AES_CTR_PARAMS params;

		params.ulCounterBits = val;

		if (len != sizeof (params.cb))
			return false;

		memcpy (params.cb, data, sizeof (params.cb));
		memcpy (value, &params, sizeof (CK_AES_CTR_PARAMS));
	}

	if (value_length)
		*value_length = sizeof (CK_AES_CTR_PARAMS);

	return true;
}

void
p11_rpc_buffer_add_aes_gcm_mechanism_value (p11_buffer *buffer,
					    const void *value,
					    CK_ULONG value_length)
{
	CK_GCM_PARAMS params;

	/* Check if value can be converted to CK_GCM_PARAMS. */
	if (value_length != sizeof (CK_GCM_PARAMS)) {
		p11_buffer_fail (buffer);
		return;
	}

	memcpy (&params, value, value_length);

	/* Check if params.ulTagBits/ulIvBits can be converted to uint64_t. */
	if (params.ulTagBits > UINT64_MAX || params.ulIvBits > UINT64_MAX) {
		p11_buffer_fail (buffer);
		return;
	}

	p11_rpc_buffer_add_byte_array (buffer,
				       (unsigned char *)params.pIv,
				       params.ulIvLen);
	p11_rpc_buffer_add_uint64 (buffer, params.ulIvBits);
	p11_rpc_buffer_add_byte_array (buffer,
				       (unsigned char *)params.pAAD,
				       params.ulAADLen);
	p11_rpc_buffer_add_uint64 (buffer, params.ulTagBits);
}

bool
p11_rpc_buffer_get_aes_gcm_mechanism_value (p11_buffer *buffer,
					    size_t *offset,
					    void *value,
					    CK_ULONG *value_length)
{
	uint64_t val1, val2;
	const unsigned char *data1, *data2;
	size_t len1, len2;

	if (!p11_rpc_buffer_get_byte_array (buffer, offset, &data1, &len1))
		return false;
	if (!p11_rpc_buffer_get_uint64 (buffer, offset, &val1))
		return false;
	if (!p11_rpc_buffer_get_byte_array (buffer, offset, &data2, &len2))
		return false;
	if (!p11_rpc_buffer_get_uint64 (buffer, offset, &val2))
		return false;

	if (value) {
		CK_GCM_PARAMS params;

		params.pIv = (void *) data1;
		params.ulIvLen = len1;
		params.ulIvBits = val1;
		params.pAAD = (void *) data2;
		params.ulAADLen = len2;
		params.ulTagBits = val2;

		memcpy (value, &params, sizeof (CK_GCM_PARAMS));
	}

	if (value_length)
		*value_length = sizeof (CK_GCM_PARAMS);

	return true;
}

void
p11_rpc_buffer_add_des_iv_mechanism_value (p11_buffer *buffer,
					   const void *value,
					   CK_ULONG value_length)
{
	/* Check if value can be converted to an DES IV. */
	if (value_length != 8) {
		p11_buffer_fail (buffer);
		return;
	}

	p11_rpc_buffer_add_byte_array (buffer,
				       (unsigned char *)value,
				       value_length);
}

bool
p11_rpc_buffer_get_des_iv_mechanism_value (p11_buffer *buffer,
					   size_t *offset,
					   void *value,
					   CK_ULONG *value_length)
{
	const unsigned char *data;
	size_t len;

	if (!p11_rpc_buffer_get_byte_array (buffer, offset, &data, &len))
		return false;

	if (len != 8)
		return false;

	if (value)
		memcpy (value, data, len);

	if (value_length)
		*value_length = len;

	return true;
}

void
p11_rpc_buffer_add_mac_general_mechanism_value (p11_buffer *buffer,
						const void *value,
						CK_ULONG value_length)
{
	CK_ULONG val;
	uint64_t params;

	/*
	 * Check if value can be converted to an CK_MAC_GENERAL_PARAMS which
	 * is a CK_ULONG.
	 */
	if (value_length != sizeof (CK_ULONG)) {
		p11_buffer_fail (buffer);
		return;
	}

	memcpy (&val, value, value_length);
	params = val;

	p11_rpc_buffer_add_uint64 (buffer, params);
}

bool
p11_rpc_buffer_get_mac_general_mechanism_value (p11_buffer *buffer,
						size_t *offset,
						void *value,
						CK_ULONG *value_length)
{
	uint64_t val;
	CK_ULONG params;

	if (!p11_rpc_buffer_get_uint64 (buffer, offset, &val))
		return false;

	params = val;

	if (value)
		memcpy (value, &params, sizeof (params));

	if (value_length)
		*value_length = sizeof (params);

	return true;
}

void
p11_rpc_buffer_add_dh_pkcs_derive_mechanism_value (p11_buffer *buffer,
						   const void *value,
						   CK_ULONG value_length)
{
	/* Mechanism parameter is public value of the other party */
	if (value_length == 0) {
		p11_buffer_fail (buffer);
		return;
	}

	p11_rpc_buffer_add_byte_array (buffer,
				       (unsigned char *)value,
				       value_length);
}

bool
p11_rpc_buffer_get_dh_pkcs_derive_mechanism_value (p11_buffer *buffer,
						   size_t *offset,
						   void *value,
						   CK_ULONG *value_length)
{
	const unsigned char *data;
	size_t len;

	if (!p11_rpc_buffer_get_byte_array (buffer, offset, &data, &len))
		return false;

	if (len == 0)
		return false;

	if (value)
		memcpy (value, data, len);

	if (value_length)
		*value_length = len;

	return true;
}

static p11_rpc_mechanism_serializer p11_rpc_mechanism_serializers[] = {
	{ CKM_RSA_PKCS_PSS, p11_rpc_buffer_add_rsa_pkcs_pss_mechanism_value, p11_rpc_buffer_get_rsa_pkcs_pss_mechanism_value },
	{ CKM_SHA1_RSA_PKCS_PSS, p11_rpc_buffer_add_rsa_pkcs_pss_mechanism_value, p11_rpc_buffer_get_rsa_pkcs_pss_mechanism_value },
	{ CKM_SHA224_RSA_PKCS_PSS, p11_rpc_buffer_add_rsa_pkcs_pss_mechanism_value, p11_rpc_buffer_get_rsa_pkcs_pss_mechanism_value },
	{ CKM_SHA256_RSA_PKCS_PSS, p11_rpc_buffer_add_rsa_pkcs_pss_mechanism_value, p11_rpc_buffer_get_rsa_pkcs_pss_mechanism_value },
	{ CKM_SHA384_RSA_PKCS_PSS, p11_rpc_buffer_add_rsa_pkcs_pss_mechanism_value, p11_rpc_buffer_get_rsa_pkcs_pss_mechanism_value },
	{ CKM_SHA512_RSA_PKCS_PSS, p11_rpc_buffer_add_rsa_pkcs_pss_mechanism_value, p11_rpc_buffer_get_rsa_pkcs_pss_mechanism_value },
	{ CKM_RSA_PKCS_OAEP, p11_rpc_buffer_add_rsa_pkcs_oaep_mechanism_value, p11_rpc_buffer_get_rsa_pkcs_oaep_mechanism_value },
	{ CKM_ECDH1_DERIVE, p11_rpc_buffer_add_ecdh1_derive_mechanism_value, p11_rpc_buffer_get_ecdh1_derive_mechanism_value },
	{ CKM_IBM_ATTRIBUTEBOUND_WRAP, p11_rpc_buffer_add_ibm_attrbound_wrap_mechanism_value, p11_rpc_buffer_get_ibm_attrbound_wrap_mechanism_value },
	{ CKM_IBM_EC_X25519, p11_rpc_buffer_add_ecdh1_derive_mechanism_value, p11_rpc_buffer_get_ecdh1_derive_mechanism_value },
	{ CKM_IBM_EC_X448, p11_rpc_buffer_add_ecdh1_derive_mechanism_value, p11_rpc_buffer_get_ecdh1_derive_mechanism_value },
	{ CKM_AES_CBC, p11_rpc_buffer_add_aes_iv_mechanism_value, p11_rpc_buffer_get_aes_iv_mechanism_value },
	{ CKM_AES_CBC_PAD, p11_rpc_buffer_add_aes_iv_mechanism_value, p11_rpc_buffer_get_aes_iv_mechanism_value },
	{ CKM_AES_OFB, p11_rpc_buffer_add_aes_iv_mechanism_value, p11_rpc_buffer_get_aes_iv_mechanism_value },
	{ CKM_AES_CFB1, p11_rpc_buffer_add_aes_iv_mechanism_value, p11_rpc_buffer_get_aes_iv_mechanism_value },
	{ CKM_AES_CFB8, p11_rpc_buffer_add_aes_iv_mechanism_value, p11_rpc_buffer_get_aes_iv_mechanism_value },
	{ CKM_AES_CFB64, p11_rpc_buffer_add_aes_iv_mechanism_value, p11_rpc_buffer_get_aes_iv_mechanism_value },
	{ CKM_AES_CFB128, p11_rpc_buffer_add_aes_iv_mechanism_value, p11_rpc_buffer_get_aes_iv_mechanism_value },
	{ CKM_AES_CTS, p11_rpc_buffer_add_aes_iv_mechanism_value, p11_rpc_buffer_get_aes_iv_mechanism_value },
	{ CKM_AES_CTR, p11_rpc_buffer_add_aes_ctr_mechanism_value, p11_rpc_buffer_get_aes_ctr_mechanism_value },
	{ CKM_AES_GCM, p11_rpc_buffer_add_aes_gcm_mechanism_value, p11_rpc_buffer_get_aes_gcm_mechanism_value },
	{ CKM_DES_CBC, p11_rpc_buffer_add_des_iv_mechanism_value, p11_rpc_buffer_get_des_iv_mechanism_value },
	{ CKM_DES_CBC_PAD, p11_rpc_buffer_add_des_iv_mechanism_value, p11_rpc_buffer_get_des_iv_mechanism_value },
	{ CKM_DES3_CBC, p11_rpc_buffer_add_des_iv_mechanism_value, p11_rpc_buffer_get_des_iv_mechanism_value },
	{ CKM_DES3_CBC_PAD, p11_rpc_buffer_add_des_iv_mechanism_value, p11_rpc_buffer_get_des_iv_mechanism_value },
	{ CKM_DES_CFB8, p11_rpc_buffer_add_des_iv_mechanism_value, p11_rpc_buffer_get_des_iv_mechanism_value },
	{ CKM_DES_CFB64, p11_rpc_buffer_add_des_iv_mechanism_value, p11_rpc_buffer_get_des_iv_mechanism_value },
	{ CKM_DES_OFB64, p11_rpc_buffer_add_des_iv_mechanism_value, p11_rpc_buffer_get_des_iv_mechanism_value },
	{ CKM_SHA_1_HMAC_GENERAL, p11_rpc_buffer_add_mac_general_mechanism_value, p11_rpc_buffer_get_mac_general_mechanism_value },
	{ CKM_SHA224_HMAC_GENERAL, p11_rpc_buffer_add_mac_general_mechanism_value, p11_rpc_buffer_get_mac_general_mechanism_value },
	{ CKM_SHA256_HMAC_GENERAL, p11_rpc_buffer_add_mac_general_mechanism_value, p11_rpc_buffer_get_mac_general_mechanism_value },
	{ CKM_SHA384_HMAC_GENERAL, p11_rpc_buffer_add_mac_general_mechanism_value, p11_rpc_buffer_get_mac_general_mechanism_value },
	{ CKM_SHA512_HMAC_GENERAL, p11_rpc_buffer_add_mac_general_mechanism_value, p11_rpc_buffer_get_mac_general_mechanism_value },
	{ CKM_SHA512_224_HMAC_GENERAL, p11_rpc_buffer_add_mac_general_mechanism_value, p11_rpc_buffer_get_mac_general_mechanism_value },
	{ CKM_SHA512_256_HMAC_GENERAL, p11_rpc_buffer_add_mac_general_mechanism_value, p11_rpc_buffer_get_mac_general_mechanism_value },
	{ CKM_AES_MAC_GENERAL, p11_rpc_buffer_add_mac_general_mechanism_value, p11_rpc_buffer_get_mac_general_mechanism_value },
	{ CKM_AES_CMAC_GENERAL, p11_rpc_buffer_add_mac_general_mechanism_value, p11_rpc_buffer_get_mac_general_mechanism_value },
	{ CKM_DES3_MAC_GENERAL, p11_rpc_buffer_add_mac_general_mechanism_value, p11_rpc_buffer_get_mac_general_mechanism_value },
	{ CKM_DES3_CMAC_GENERAL, p11_rpc_buffer_add_mac_general_mechanism_value, p11_rpc_buffer_get_mac_general_mechanism_value },
	{ CKM_DH_PKCS_DERIVE, p11_rpc_buffer_add_dh_pkcs_derive_mechanism_value, p11_rpc_buffer_get_dh_pkcs_derive_mechanism_value },
};

static p11_rpc_mechanism_serializer p11_rpc_byte_array_mechanism_serializer = {
	0, p11_rpc_buffer_add_byte_array_value, p11_rpc_buffer_get_byte_array_value
};

static bool
mechanism_has_sane_parameters (CK_MECHANISM_TYPE type)
{
	int i;

	/* This can be set from tests, to override default set of supported */
	if (p11_rpc_mechanisms_override_supported) {
		for (i = 0; p11_rpc_mechanisms_override_supported[i] != 0; i++) {
			if (p11_rpc_mechanisms_override_supported[i] == type)
				return true;
		}

		return false;
	}

	for (i = 0; i < ELEMS(p11_rpc_mechanism_serializers); i++) {
		if (p11_rpc_mechanism_serializers[i].type == type)
			return true;
	}

	return false;
}

static bool
mechanism_has_no_parameters (CK_MECHANISM_TYPE mech)
{
	/* This list is incomplete */

	switch (mech) {
	case CKM_RSA_PKCS_KEY_PAIR_GEN:
	case CKM_RSA_X9_31_KEY_PAIR_GEN:
	case CKM_RSA_PKCS:
	case CKM_RSA_9796:
	case CKM_RSA_X_509:
	case CKM_RSA_X9_31:
	case CKM_MD2_RSA_PKCS:
	case CKM_MD5_RSA_PKCS:
	case CKM_SHA1_RSA_PKCS:
	case CKM_SHA224_RSA_PKCS:
	case CKM_SHA256_RSA_PKCS:
	case CKM_SHA384_RSA_PKCS:
	case CKM_SHA512_RSA_PKCS:
	case CKM_RIPEMD128_RSA_PKCS:
	case CKM_RIPEMD160_RSA_PKCS:
	case CKM_SHA1_RSA_X9_31:
	case CKM_DSA_KEY_PAIR_GEN:
	case CKM_DSA_PARAMETER_GEN:
	case CKM_DSA:
	case CKM_DSA_SHA1:
	case CKM_FORTEZZA_TIMESTAMP:
	case CKM_EC_KEY_PAIR_GEN:
	case CKM_ECDSA:
	case CKM_ECDSA_SHA1:
	case CKM_ECDSA_SHA224:
	case CKM_ECDSA_SHA256:
	case CKM_ECDSA_SHA384:
	case CKM_ECDSA_SHA512:
	case CKM_DH_PKCS_KEY_PAIR_GEN:
	case CKM_DH_PKCS_PARAMETER_GEN:
	case CKM_X9_42_DH_KEY_PAIR_GEN:
	case CKM_X9_42_DH_PARAMETER_GEN:
	case CKM_KEA_KEY_PAIR_GEN:
	case CKM_GENERIC_SECRET_KEY_GEN:
	case CKM_RC2_KEY_GEN:
	case CKM_RC4_KEY_GEN:
	case CKM_RC4:
	case CKM_RC5_KEY_GEN:
	case CKM_AES_KEY_GEN:
	case CKM_AES_ECB:
	case CKM_AES_MAC:
	case CKM_AES_CMAC:
	case CKM_DES_KEY_GEN:
	case CKM_DES2_KEY_GEN:
	case CKM_DES3_KEY_GEN:
	case CKM_CDMF_KEY_GEN:
	case CKM_CAST_KEY_GEN:
	case CKM_CAST3_KEY_GEN:
	case CKM_CAST128_KEY_GEN:
	case CKM_IDEA_KEY_GEN:
	case CKM_SSL3_PRE_MASTER_KEY_GEN:
	case CKM_TLS_PRE_MASTER_KEY_GEN:
	case CKM_SKIPJACK_KEY_GEN:
	case CKM_BATON_KEY_GEN:
	case CKM_JUNIPER_KEY_GEN:
	case CKM_RC2_ECB:
	case CKM_DES_ECB:
	case CKM_DES3_ECB:
	case CKM_CDMF_ECB:
	case CKM_CAST_ECB:
	case CKM_CAST3_ECB:
	case CKM_CAST128_ECB:
	case CKM_RC5_ECB:
	case CKM_IDEA_ECB:
	case CKM_RC2_MAC:
	case CKM_DES_MAC:
	case CKM_DES3_MAC:
	case CKM_DES3_CMAC:
	case CKM_CDMF_MAC:
	case CKM_CAST_MAC:
	case CKM_CAST3_MAC:
	case CKM_RC5_MAC:
	case CKM_IDEA_MAC:
	case CKM_SSL3_MD5_MAC:
	case CKM_SSL3_SHA1_MAC:
	case CKM_SKIPJACK_WRAP:
	case CKM_BATON_WRAP:
	case CKM_JUNIPER_WRAP:
	case CKM_MD2:
	case CKM_MD2_HMAC:
	case CKM_MD5:
	case CKM_MD5_HMAC:
	case CKM_SHA_1:
	case CKM_SHA_1_HMAC:
	case CKM_SHA1_KEY_DERIVATION:
	case CKM_SHA224:
	case CKM_SHA224_HMAC:
	case CKM_SHA224_KEY_DERIVATION:
	case CKM_SHA256:
	case CKM_SHA256_HMAC:
	case CKM_SHA256_KEY_DERIVATION:
	case CKM_SHA384:
	case CKM_SHA384_HMAC:
	case CKM_SHA384_KEY_DERIVATION:
	case CKM_SHA512:
	case CKM_SHA512_HMAC:
	case CKM_SHA512_KEY_DERIVATION:
	case CKM_SHA512_T:
	case CKM_SHA512_T_HMAC:
	case CKM_SHA512_T_KEY_DERIVATION:
	case CKM_SHA512_224:
	case CKM_SHA512_224_HMAC:
	case CKM_SHA512_224_KEY_DERIVATION:
	case CKM_SHA512_256:
	case CKM_SHA512_256_HMAC:
	case CKM_SHA512_256_KEY_DERIVATION:
	case CKM_FASTHASH:
	case CKM_RIPEMD128:
	case CKM_RIPEMD128_HMAC:
	case CKM_RIPEMD160:
	case CKM_RIPEMD160_HMAC:
	case CKM_KEY_WRAP_LYNKS:
	case CKM_IBM_SHA3_224:
	case CKM_IBM_SHA3_256:
	case CKM_IBM_SHA3_384:
	case CKM_IBM_SHA3_512:
	case CKM_IBM_CMAC:
	case CKM_IBM_DILITHIUM:
	case CKM_IBM_SHA3_224_HMAC:
	case CKM_IBM_SHA3_256_HMAC:
	case CKM_IBM_SHA3_384_HMAC:
	case CKM_IBM_SHA3_512_HMAC:
	case CKM_IBM_ED25519_SHA512:
	case CKM_IBM_ED448_SHA3:
		return true;
	default:
		return false;
	};
}

bool
p11_rpc_mechanism_is_supported (CK_MECHANISM_TYPE mech)
{
	if (mechanism_has_no_parameters (mech) ||
	    mechanism_has_sane_parameters (mech))
		return true;
	return false;
}

void
p11_rpc_buffer_add_mechanism (p11_buffer *buffer, const CK_MECHANISM *mech)
{
	p11_rpc_mechanism_serializer *serializer = NULL;
	size_t i;

	/* The mechanism type */
	p11_rpc_buffer_add_uint32 (buffer, mech->mechanism);

	if (mechanism_has_no_parameters (mech->mechanism)) {
		p11_rpc_buffer_add_byte_array (buffer, NULL, 0);
		return;
	}

	assert (mechanism_has_sane_parameters (mech->mechanism));

	for (i = 0; i < ELEMS (p11_rpc_mechanism_serializers); i++) {
		if (p11_rpc_mechanism_serializers[i].type == mech->mechanism) {
			serializer = &p11_rpc_mechanism_serializers[i];
			break;
		}
	}

	if (serializer == NULL)
		serializer = &p11_rpc_byte_array_mechanism_serializer;

	serializer->encode (buffer, mech->pParameter, mech->ulParameterLen);
}

bool
p11_rpc_buffer_get_mechanism (p11_buffer *buffer,
			      size_t *offset,
			      CK_MECHANISM *mech)
{
	uint32_t mechanism;
	p11_rpc_mechanism_serializer *serializer = NULL;
	size_t i;

	/* The mechanism type */
	if (!p11_rpc_buffer_get_uint32 (buffer, offset, &mechanism))
		return false;

	mech->mechanism = mechanism;

	/* special NULL case */
	if (mechanism == 0) {
		return true;
	}

	for (i = 0; i < ELEMS (p11_rpc_mechanism_serializers); i++) {
		if (p11_rpc_mechanism_serializers[i].type == mech->mechanism) {
			serializer = &p11_rpc_mechanism_serializers[i];
			break;
		}
	}

	if (serializer == NULL)
		serializer = &p11_rpc_byte_array_mechanism_serializer;

	if (!serializer->decode (buffer, offset,
				 mech->pParameter, &mech->ulParameterLen))
		return false;

	return true;
}
