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

#include "debug.h"
#include "library.h"
#include "message.h"
#include "private.h"
#include "rpc-message.h"

#include <assert.h>
#include <string.h>

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
		p11_message ("invalid message: couldn't read call identifier");
		return false;
	}

	msg->signature = msg->sigverify = NULL;

	/* The call id and signature */
	if (call_id < 0 || call_id >= P11_RPC_CALL_MAX) {
		p11_message ("invalid message: bad call id: %d", call_id);
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
	if (!p11_rpc_buffer_get_byte_array (msg->input, &msg->parsed, &val, &len)) {
		p11_message ("invalid message: couldn't read signature");
		return false;
	}

	if ((strlen (msg->signature) != len) || (memcmp (val, msg->signature, len) != 0)) {
		p11_message ("invalid message: signature doesn't match");
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

	/* Make sure this is in the rigth order */
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
	CK_ATTRIBUTE_PTR attr;
	unsigned char validity;

	assert (num == 0 || arr != NULL);
	assert (msg != NULL);
	assert (msg->output != NULL);

	/* Make sure this is in the rigth order */
	assert (!msg->signature || p11_rpc_message_verify_part (msg, "aA"));

	/* Write the number of items */
	p11_rpc_buffer_add_uint32 (msg->output, num);

	for (i = 0; i < num; ++i) {
		attr = &(arr[i]);

		/* The attribute type */
		p11_rpc_buffer_add_uint32 (msg->output, attr->type);

		/* Write out the attribute validity */
		validity = (((CK_LONG)attr->ulValueLen) == -1) ? 0 : 1;
		p11_rpc_buffer_add_byte (msg->output, validity);

		/* The attribute length and value */
		if (validity) {
			p11_rpc_buffer_add_uint32 (msg->output, attr->ulValueLen);
			p11_rpc_buffer_add_byte_array (msg->output, attr->pValue, attr->ulValueLen);
		}
	}

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

	/* Make sure this is in the rigth order */
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
p11_rpc_message_write_byte_array (p11_rpc_message *msg,
                                  CK_BYTE_PTR arr,
                                  CK_ULONG num)
{
	assert (msg != NULL);
	assert (msg->output != NULL);

	/* Make sure this is in the right order */
	assert (!msg->signature || p11_rpc_message_verify_part (msg, "ay"));

	/* No array, no data, just length */
	if (!arr) {
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
		p11_message ("invalid length space padded string received: %d != %d",
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
	uint32_t val = ptr[0] << 24 | ptr[1] << 16 | ptr[2] << 8 | ptr[3];
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

	if (buf->len < len || *offset > buf->len - len) {
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
