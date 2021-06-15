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

#include "attrs.h"
#include "conf.h"
#define P11_DEBUG_FLAG P11_DEBUG_RPC
#include "debug.h"
#include "filter.h"
#include "iter.h"
#include "pkcs11.h"
#include "library.h"
#include "private.h"
#include "message.h"
#include "proxy.h"
#include "remote.h"
#include "rpc.h"
#include "rpc-message.h"
#include "uri.h"

#include <sys/types.h>
#include <sys/param.h>
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef ENABLE_NLS
#include <libintl.h>
#define _(x) dgettext(PACKAGE_NAME, x)
#else
#define _(x) (x)
#endif

/* The error returned on protocol failures */
#define PARSE_ERROR CKR_DEVICE_ERROR
#define PREP_ERROR  CKR_DEVICE_MEMORY

typedef struct {
	p11_virtual virt;
	uint8_t version;
} rpc_server;

static CK_RV
proto_read_byte_buffer (p11_rpc_message *msg,
                        CK_BYTE_PTR *buffer,
                        CK_ULONG *n_buffer)
{
	uint32_t length;

	assert (msg != NULL);
	assert (buffer != NULL);
	assert (n_buffer != NULL);
	assert (msg->input != NULL);

	/* Check that we're supposed to be reading this at this point */
	assert (!msg->signature || p11_rpc_message_verify_part (msg, "fy"));

	/* The number of ulongs there's room for on the other end */
	if (!p11_rpc_buffer_get_uint32 (msg->input, &msg->parsed, &length))
		return PARSE_ERROR;

	*n_buffer = length;
	*buffer = NULL;

	/* length = -1 indicates length = 0, but buffer not NULL */
	if (length == (uint32_t)-1) {
		*n_buffer = 0;
		length = 1; /*allocate 1 dummy byte */
	}

	/* If set to zero, then they just want the length */
	if (length == 0)
		return CKR_OK;

	*buffer = p11_rpc_message_alloc_extra_array (msg, length, sizeof (CK_BYTE));
	if (*buffer == NULL)
		return CKR_DEVICE_MEMORY;

	return CKR_OK;
}

static CK_RV
proto_read_byte_buffer_null (p11_rpc_message *msg,
                             CK_BYTE_PTR *buffer,
                             CK_ULONG **n_buffer)
{
	unsigned char valid;
	uint32_t length;

	assert (msg != NULL);
	assert (buffer != NULL);
	assert (n_buffer != NULL);
	assert (msg->input != NULL);

	/* Check that we're supposed to be reading this at this point */
	assert (!msg->signature || p11_rpc_message_verify_part (msg, "fy"));

	/* NULL is indicated with the first byte */
	if (!p11_rpc_buffer_get_byte (msg->input, &msg->parsed, &valid))
		return PARSE_ERROR;

	if (!valid) {
		*buffer = NULL;
		*n_buffer = NULL;
		return CKR_OK;
	}

	/* The number of ulongs there's room for on the other end */
	if (!p11_rpc_buffer_get_uint32 (msg->input, &msg->parsed, &length))
		return PARSE_ERROR;

	**n_buffer = length;
	*buffer = NULL;

	/* If set to zero, then they just want the length */
	if (length == 0)
		return CKR_OK;

	*buffer = p11_rpc_message_alloc_extra_array (msg, length, sizeof (CK_BYTE));
	if (*buffer == NULL)
		return CKR_DEVICE_MEMORY;

	return CKR_OK;
}

static CK_RV
proto_read_byte_array (p11_rpc_message *msg,
                       CK_BYTE_PTR *array,
                       CK_ULONG *n_array)
{
	const unsigned char *data;
	unsigned char valid;
	uint32_t len;
	size_t n_data;

	assert (msg != NULL);
	assert (msg->input != NULL);

	/* Check that we're supposed to have this at this point */
	assert (!msg->signature || p11_rpc_message_verify_part (msg, "ay"));

	/* Read out the byte which says whether data is present or not */
	if (!p11_rpc_buffer_get_byte (msg->input, &msg->parsed, &valid))
		return PARSE_ERROR;

	if (!valid) {
		if (!p11_rpc_buffer_get_uint32 (msg->input, &msg->parsed, &len))
			return PARSE_ERROR;
		*array = NULL;
		*n_array = len;
		return CKR_OK;
	}

	/* Point our arguments into the buffer */
	if (!p11_rpc_buffer_get_byte_array (msg->input, &msg->parsed, &data, &n_data))
		return PARSE_ERROR;

	*array = (CK_BYTE_PTR)data;
	*n_array = n_data;
	return CKR_OK;
}

static CK_RV
proto_write_byte_array (p11_rpc_message *msg,
                        CK_BYTE_PTR array,
                        CK_ULONG len,
                        CK_RV ret)
{
	assert (msg != NULL);

	/*
	 * When returning an byte array, in many cases we need to pass
	 * an invalid array along with a length, which signifies CKR_BUFFER_TOO_SMALL.
	 */

	switch (ret) {
	case CKR_BUFFER_TOO_SMALL:
		array = NULL;
		/* fall through */
	case CKR_OK:
		break;

	/* Pass all other errors straight through */
	default:
		return ret;
	};

	if (!p11_rpc_message_write_byte_array (msg, array, len))
		return PREP_ERROR;

	return CKR_OK;
}

static CK_RV
proto_read_ulong_buffer (p11_rpc_message *msg,
                         CK_ULONG_PTR *buffer,
                         CK_ULONG *n_buffer)
{
	uint32_t length;

	assert (msg != NULL);
	assert (buffer != NULL);
	assert (n_buffer != NULL);
	assert (msg->input != NULL);

	/* Check that we're supposed to be reading this at this point */
	assert (!msg->signature || p11_rpc_message_verify_part (msg, "fu"));

	/* The number of ulongs there's room for on the other end */
	if (!p11_rpc_buffer_get_uint32 (msg->input, &msg->parsed, &length))
		return PARSE_ERROR;

	*n_buffer = length;
	*buffer = NULL;

	/* If set to zero, then they just want the length */
	if (length == 0)
		return CKR_OK;

	*buffer = p11_rpc_message_alloc_extra_array (msg, length, sizeof (CK_ULONG));
	if (!*buffer)
		return CKR_DEVICE_MEMORY;

	return CKR_OK;
}

static CK_RV
proto_write_ulong_array (p11_rpc_message *msg,
                         CK_ULONG_PTR array,
                         CK_ULONG len,
                         CK_RV ret)
{
	assert (msg != NULL);

	/*
	 * When returning an ulong array, in many cases we need to pass
	 * an invalid array along with a length, which signifies CKR_BUFFER_TOO_SMALL.
	 */

	switch (ret) {
	case CKR_BUFFER_TOO_SMALL:
		array = NULL;
		/* fall through */
	case CKR_OK:
		break;

	/* Pass all other errors straight through */
	default:
		return ret;
	};

	if (!p11_rpc_message_write_ulong_array (msg, array, len))
		return PREP_ERROR;

	return CKR_OK;
}

static CK_RV
proto_read_attribute_buffer (p11_rpc_message *msg,
                             CK_ATTRIBUTE_PTR *result,
                             CK_ULONG *n_result)
{
	CK_ATTRIBUTE_PTR attrs;
	uint32_t n_attrs, i;
	uint32_t value;

	assert (msg != NULL);
	assert (result != NULL);
	assert (n_result != NULL);
	assert (msg->input != NULL);

	/* Make sure this is in the right order */
	assert (!msg->signature || p11_rpc_message_verify_part (msg, "fA"));

	/* Read the number of attributes */
	if (!p11_rpc_buffer_get_uint32 (msg->input, &msg->parsed, &n_attrs))
		return PARSE_ERROR;

	/* Allocate memory for the attribute structures */
	attrs = p11_rpc_message_alloc_extra_array (msg, n_attrs, sizeof (CK_ATTRIBUTE));
	if (attrs == NULL)
		return CKR_DEVICE_MEMORY;

	/* Now go through and fill in each one */
	for (i = 0; i < n_attrs; ++i) {

		/* The attribute type */
		if (!p11_rpc_buffer_get_uint32 (msg->input, &msg->parsed, &value))
			return PARSE_ERROR;

		attrs[i].type = value;

		/* The number of bytes to allocate */
		if (!p11_rpc_buffer_get_uint32 (msg->input, &msg->parsed, &value))
			return PARSE_ERROR;

		if (value == 0) {
			attrs[i].pValue = NULL;
			attrs[i].ulValueLen = 0;
		} else {
			attrs[i].pValue = p11_rpc_message_alloc_extra (msg, value);
			if (!attrs[i].pValue)
				return CKR_DEVICE_MEMORY;
			attrs[i].ulValueLen = value;
		}
	}

	*result = attrs;
	*n_result = n_attrs;
	return CKR_OK;
}

static CK_RV
proto_read_attribute_array (p11_rpc_message *msg,
                            CK_ATTRIBUTE_PTR *result,
                            CK_ULONG *n_result)
{
	CK_ATTRIBUTE_PTR attrs;
	uint32_t n_attrs, i;

	assert (msg != NULL);
	assert (result != NULL);
	assert (n_result != NULL);
	assert (msg->input != NULL);

	/* Make sure this is in the right order */
	assert (!msg->signature || p11_rpc_message_verify_part (msg, "aA"));

	/* Read the number of attributes */
	if (!p11_rpc_buffer_get_uint32 (msg->input, &msg->parsed, &n_attrs))
		return PARSE_ERROR;

	/* Allocate memory for the attribute structures */
	attrs = p11_rpc_message_alloc_extra_array (msg, n_attrs, sizeof (CK_ATTRIBUTE));
	if (attrs == NULL)
		return CKR_DEVICE_MEMORY;

	/* Now go through and fill in each one */
	for (i = 0; i < n_attrs; ++i) {
		size_t offset = msg->parsed;
		CK_ATTRIBUTE temp;

		/* Check the length needed to store the value */
		memset (&temp, 0, sizeof (temp));
		if (!p11_rpc_buffer_get_attribute (msg->input, &offset, &temp)) {
			msg->parsed = offset;
			return PARSE_ERROR;
		}

		if (IS_ATTRIBUTE_ARRAY (&temp)) {
			p11_debug("recursive attribute array is not supported");
			return PARSE_ERROR;
		}

		attrs[i].type = temp.type;

		/* Whether this one is valid or not */
		if (temp.ulValueLen != ((CK_ULONG)-1)) {
			size_t offset2 = msg->parsed;
			attrs[i].pValue = p11_rpc_message_alloc_extra (msg, temp.ulValueLen);
			if (!p11_rpc_buffer_get_attribute (msg->input, &offset2, &attrs[i])) {
				msg->parsed = offset2;
				return PARSE_ERROR;
			}
		} else {
			attrs[i].pValue = NULL;
			attrs[i].ulValueLen = -1;
		}

		msg->parsed = offset;
	}

	*result = attrs;
	*n_result = n_attrs;
	return CKR_OK;
}

static CK_RV
proto_write_attribute_array (p11_rpc_message *msg,
                             CK_ATTRIBUTE_PTR array,
                             CK_ULONG len,
                             CK_RV ret)
{
	assert (msg != NULL);

	/*
	 * When returning an attribute array, certain errors aren't
	 * actually real errors, these are passed through to the other
	 * side along with the attribute array.
	 */

	switch (ret) {
	case CKR_ATTRIBUTE_SENSITIVE:
	case CKR_ATTRIBUTE_TYPE_INVALID:
	case CKR_BUFFER_TOO_SMALL:
	case CKR_OK:
		break;

	/* Pass all other errors straight through */
	default:
		return ret;
	};

	if (!p11_rpc_message_write_attribute_array (msg, array, len) ||
	    !p11_rpc_message_write_ulong (msg, ret))
		return PREP_ERROR;

	return CKR_OK;
}

static CK_RV
proto_read_null_string (p11_rpc_message *msg,
                        CK_UTF8CHAR_PTR *val)
{
	const unsigned char *data;
	size_t n_data;

	assert (msg != NULL);
	assert (val != NULL);
	assert (msg->input != NULL);

	/* Check that we're supposed to have this at this point */
	assert (!msg->signature || p11_rpc_message_verify_part (msg, "z"));

	if (!p11_rpc_buffer_get_byte_array (msg->input, &msg->parsed, &data, &n_data))
		return PARSE_ERROR;

	/* Allocate a block of memory for it */
	*val = p11_rpc_message_alloc_extra (msg, n_data + 1);
	if (*val == NULL)
		return CKR_DEVICE_MEMORY;

	memcpy (*val, data, n_data);
	(*val)[n_data] = 0;

	return CKR_OK;
}

static CK_RV
proto_read_mechanism (p11_rpc_message *msg,
                      CK_MECHANISM_PTR *mech)
{
	size_t offset;
	CK_MECHANISM temp;

	assert (msg != NULL);
	assert (mech != NULL);
	assert (msg->input != NULL);

	/* Make sure this is in the right order */
	assert (!msg->signature || p11_rpc_message_verify_part (msg, "M"));

	/* Check the length needed to store the parameter */
	memset (&temp, 0, sizeof (temp));
	offset = msg->parsed;
	if (!p11_rpc_buffer_get_mechanism (msg->input, &offset, &temp)) {
		msg->parsed = offset;
		return PARSE_ERROR;
	}

	if (temp.mechanism == 0) {
		*mech = NULL;
		return CKR_OK;
	}

	(*mech)->mechanism = temp.mechanism;

	/* The mechanism doesn't require parameter */
	if (temp.ulParameterLen == 0) {
		(*mech)->pParameter = NULL;
		(*mech)->ulParameterLen = 0;
		msg->parsed = offset;
		return CKR_OK;
	}

	/* Actually retrieve the parameter */
	(*mech)->pParameter = p11_rpc_message_alloc_extra (msg, temp.ulParameterLen);
	if (!p11_rpc_buffer_get_mechanism (msg->input, &msg->parsed, *mech))
		return PARSE_ERROR;

	assert (msg->parsed == offset);

	return CKR_OK;
}

static CK_RV
proto_write_info (p11_rpc_message *msg,
                  CK_INFO_PTR info)
{
	assert (msg != NULL);
	assert (info != NULL);

	if (!p11_rpc_message_write_version (msg, &info->cryptokiVersion) ||
	    !p11_rpc_message_write_space_string (msg, info->manufacturerID, 32) ||
	    !p11_rpc_message_write_ulong (msg, info->flags) ||
	    !p11_rpc_message_write_space_string (msg, info->libraryDescription, 32) ||
	    !p11_rpc_message_write_version (msg, &info->libraryVersion))
		return PREP_ERROR;

	return CKR_OK;
}

static CK_RV
proto_write_slot_info (p11_rpc_message *msg,
                       CK_SLOT_INFO_PTR info)
{
	assert (msg != NULL);
	assert (info != NULL);

	if (!p11_rpc_message_write_space_string (msg, info->slotDescription, 64) ||
	    !p11_rpc_message_write_space_string (msg, info->manufacturerID, 32) ||
	    !p11_rpc_message_write_ulong (msg, info->flags) ||
	    !p11_rpc_message_write_version (msg, &info->hardwareVersion) ||
	    !p11_rpc_message_write_version (msg, &info->firmwareVersion))
		return PREP_ERROR;

	return CKR_OK;
}

static CK_RV
proto_write_token_info (p11_rpc_message *msg,
                        CK_TOKEN_INFO_PTR info)
{
	assert (msg != NULL);
	assert (info != NULL);

	if (!p11_rpc_message_write_space_string (msg, info->label, 32) ||
	    !p11_rpc_message_write_space_string (msg, info->manufacturerID, 32) ||
	    !p11_rpc_message_write_space_string (msg, info->model, 16) ||
	    !p11_rpc_message_write_space_string (msg, info->serialNumber, 16) ||
	    !p11_rpc_message_write_ulong (msg, info->flags) ||
	    !p11_rpc_message_write_ulong (msg, info->ulMaxSessionCount) ||
	    !p11_rpc_message_write_ulong (msg, info->ulSessionCount) ||
	    !p11_rpc_message_write_ulong (msg, info->ulMaxRwSessionCount) ||
	    !p11_rpc_message_write_ulong (msg, info->ulRwSessionCount) ||
	    !p11_rpc_message_write_ulong (msg, info->ulMaxPinLen) ||
	    !p11_rpc_message_write_ulong (msg, info->ulMinPinLen) ||
	    !p11_rpc_message_write_ulong (msg, info->ulTotalPublicMemory) ||
	    !p11_rpc_message_write_ulong (msg, info->ulFreePublicMemory) ||
	    !p11_rpc_message_write_ulong (msg, info->ulTotalPrivateMemory) ||
	    !p11_rpc_message_write_ulong (msg, info->ulFreePrivateMemory) ||
	    !p11_rpc_message_write_version (msg, &info->hardwareVersion) ||
	    !p11_rpc_message_write_version (msg, &info->firmwareVersion) ||
	    !p11_rpc_message_write_space_string (msg, info->utcTime, 16))
		return PREP_ERROR;

	return CKR_OK;
}

static CK_RV
proto_write_mechanism_info (p11_rpc_message *msg,
                            CK_MECHANISM_INFO_PTR info)
{
	assert (msg != NULL);
	assert (info != NULL);

	if (!p11_rpc_message_write_ulong (msg, info->ulMinKeySize) ||
	    !p11_rpc_message_write_ulong (msg, info->ulMaxKeySize) ||
	    !p11_rpc_message_write_ulong (msg, info->flags))
		return PREP_ERROR;

	return CKR_OK;
}

static CK_RV
proto_write_session_info (p11_rpc_message *msg,
                          CK_SESSION_INFO_PTR info)
{
	assert (msg != NULL);
	assert (info != NULL);

	if (!p11_rpc_message_write_ulong (msg, info->slotID) ||
	    !p11_rpc_message_write_ulong (msg, info->state) ||
	    !p11_rpc_message_write_ulong (msg, info->flags) ||
	    !p11_rpc_message_write_ulong (msg, info->ulDeviceError))
		return PREP_ERROR;

	return CKR_OK;
}

static CK_RV
call_ready (p11_rpc_message *msg)
{
	assert (msg->output);

	/*
	 * Called right before invoking the actual PKCS#11 function
	 * Reading out of data is complete, get ready to write return values.
	 */

	if (p11_buffer_failed (msg->output)) {
		p11_message (_("invalid request from module, probably too short")); \
		return PARSE_ERROR;
	}

	assert (p11_rpc_message_is_verified (msg));

	/* All done parsing input */
	msg->input = NULL;

	if (!p11_rpc_message_prep (msg, msg->call_id, P11_RPC_RESPONSE)) {
		p11_message (_("couldn't initialize rpc response"));
		return CKR_DEVICE_MEMORY;
	}

	return CKR_OK;
}

/* -------------------------------------------------------------------
 * CALL MACROS
 */

#define BEGIN_CALL(call_id) \
	p11_debug (#call_id ": enter"); \
	assert (msg != NULL); \
	assert (self != NULL); \
	{  \
		CK_X_##call_id _func = self->C_##call_id; \
		CK_RV _ret = CKR_OK; \
		if (!_func) { _ret = CKR_GENERAL_ERROR; goto _cleanup; }

#define PROCESS_CALL(args) \
		_ret = call_ready (msg); \
		if (_ret != CKR_OK) { goto _cleanup; } \
		_ret = _func args

#define END_CALL \
	_cleanup: \
		p11_debug ("ret: %d", (int)_ret); \
		return _ret; \
	}

#define IN_BYTE(val) \
	if (!p11_rpc_message_read_byte (msg, &val)) \
		{ _ret = PARSE_ERROR; goto _cleanup; }

#define IN_ULONG(val) \
	if (!p11_rpc_message_read_ulong (msg, &val)) \
		{ _ret = PARSE_ERROR; goto _cleanup; }

#define IN_STRING(val) \
	_ret = proto_read_null_string (msg, &val); \
	if (_ret != CKR_OK) goto _cleanup;

#define IN_BYTE_BUFFER(buffer, buffer_len) \
	_ret = proto_read_byte_buffer (msg, &buffer, &buffer_len); \
	if (_ret != CKR_OK) goto _cleanup;

#define IN_BYTE_BUFFER_NULL(buffer, buffer_len) \
	_ret = proto_read_byte_buffer_null (msg, &buffer, &buffer_len); \
	if (_ret != CKR_OK) goto _cleanup;

#define IN_BYTE_ARRAY(buffer, buffer_len) \
	_ret = proto_read_byte_array (msg, &buffer, &buffer_len); \
	if (_ret != CKR_OK) goto _cleanup;

#define IN_ULONG_BUFFER(buffer, buffer_len) \
	_ret = proto_read_ulong_buffer (msg, &buffer, &buffer_len); \
	if (_ret != CKR_OK) goto _cleanup;

#define IN_ATTRIBUTE_BUFFER(buffer, buffer_len) \
	_ret = proto_read_attribute_buffer (msg, &buffer, &buffer_len); \
	if (_ret != CKR_OK) goto _cleanup;

#define IN_ATTRIBUTE_ARRAY(attrs, n_attrs) \
	_ret = proto_read_attribute_array (msg, &attrs, &n_attrs); \
	if (_ret != CKR_OK) goto _cleanup;

#define IN_MECHANISM(mech) \
	_ret = proto_read_mechanism (msg, &mech); \
	if (_ret != CKR_OK) goto _cleanup;


#define OUT_ULONG(val) \
	if (_ret == CKR_OK && !p11_rpc_message_write_ulong (msg, val)) \
		_ret = PREP_ERROR;

#define OUT_BYTE_ARRAY(array, len) \
	/* Note how we filter return codes */ \
	_ret = proto_write_byte_array (msg, array, len, _ret);

#define OUT_ULONG_ARRAY(array, len) \
	/* Note how we filter return codes */ \
	_ret = proto_write_ulong_array (msg, array, len, _ret);

#define OUT_ATTRIBUTE_ARRAY(array, len) \
	/* Note how we filter return codes */ \
	_ret = proto_write_attribute_array (msg, array, len, _ret);

#define OUT_INFO(val) \
	if (_ret == CKR_OK) \
		_ret = proto_write_info (msg, &val);

#define OUT_SLOT_INFO(val) \
	if (_ret == CKR_OK) \
		_ret = proto_write_slot_info (msg, &val);

#define OUT_TOKEN_INFO(val) \
	if (_ret == CKR_OK) \
		_ret = proto_write_token_info (msg, &val);

#define OUT_MECHANISM_INFO(val) \
	if (_ret == CKR_OK) \
		_ret = proto_write_mechanism_info (msg, &val);

#define OUT_SESSION_INFO(val) \
	if (_ret == CKR_OK) \
		_ret = proto_write_session_info (msg, &val);

/* ---------------------------------------------------------------------------
 * DISPATCH SPECIFIC CALLS
 */

static CK_RV
rpc_C_Initialize (CK_X_FUNCTION_LIST *self,
                  p11_rpc_message *msg)
{
	CK_X_Initialize func;
	CK_C_INITIALIZE_ARGS init_args;
	CK_BYTE_PTR handshake;
	CK_ULONG n_handshake;
	CK_BYTE reserved_present = 0;
	CK_BYTE_PTR reserved = NULL;
	CK_ULONG n_reserved;
	CK_RV ret = CKR_OK;

	p11_debug ("C_Initialize: enter");

	assert (msg != NULL);
	assert (self != NULL);

	ret = proto_read_byte_array (msg, &handshake, &n_handshake);
	if (ret == CKR_OK) {

		/* Check to make sure the header matches */
		if (!handshake ||
		    n_handshake != P11_RPC_HANDSHAKE_LEN ||
		    memcmp (handshake, P11_RPC_HANDSHAKE, n_handshake) != 0) {
			p11_message (_("invalid handshake received from connecting module"));
			ret = CKR_GENERAL_ERROR;
		}
	}

	if (ret == CKR_OK) {
		if (!p11_rpc_message_read_byte (msg, &reserved_present))
			ret = PARSE_ERROR;
	}

	if (ret == CKR_OK) {
		ret = proto_read_byte_array (msg, &reserved, &n_reserved);

		assert (p11_rpc_message_is_verified (msg));
	}

	if (ret == CKR_OK) {
		memset (&init_args, 0, sizeof (init_args));
		init_args.flags = CKF_OS_LOCKING_OK;
		init_args.pReserved = reserved_present ? reserved : NULL;

		func = self->C_Initialize;
		assert (func != NULL);
		ret = (func) (self, &init_args);

		/* Empty response */
		if (ret == CKR_OK)
			ret = call_ready (msg);
	}

	p11_debug ("ret: %d", (int)ret);
	return ret;
}

static CK_RV
rpc_C_Finalize (CK_X_FUNCTION_LIST *self,
                p11_rpc_message *msg)
{
	BEGIN_CALL (Finalize);
	PROCESS_CALL ((self, NULL));
	END_CALL;
}

static CK_RV
rpc_C_GetInfo (CK_X_FUNCTION_LIST *self,
               p11_rpc_message *msg)
{
	CK_INFO info;

	BEGIN_CALL (GetInfo);
	PROCESS_CALL ((self, &info));
		OUT_INFO (info);
	END_CALL;
}

static CK_RV
rpc_C_GetSlotList (CK_X_FUNCTION_LIST *self,
                   p11_rpc_message *msg)
{
	CK_BBOOL token_present;
	CK_SLOT_ID_PTR slot_list;
	CK_ULONG count;

	BEGIN_CALL (GetSlotList);
		IN_BYTE (token_present);
		IN_ULONG_BUFFER (slot_list, count);
	PROCESS_CALL ((self, token_present, slot_list, &count));
		OUT_ULONG_ARRAY (slot_list, count);
	END_CALL;
}

static CK_RV
rpc_C_GetSlotInfo (CK_X_FUNCTION_LIST *self,
                   p11_rpc_message *msg)
{
	CK_SLOT_ID slot_id;
	CK_SLOT_INFO info;

	BEGIN_CALL (GetSlotInfo);
		IN_ULONG (slot_id);
	PROCESS_CALL ((self, slot_id, &info));
		OUT_SLOT_INFO (info);
	END_CALL;
}

static CK_RV
rpc_C_GetTokenInfo (CK_X_FUNCTION_LIST *self,
                    p11_rpc_message *msg)
{
	CK_SLOT_ID slot_id;
	CK_TOKEN_INFO info;

	BEGIN_CALL (GetTokenInfo);
		IN_ULONG (slot_id);
	PROCESS_CALL ((self, slot_id, &info));
		OUT_TOKEN_INFO (info);
	END_CALL;
}

static CK_RV
rpc_C_GetMechanismList (CK_X_FUNCTION_LIST *self,
                        p11_rpc_message *msg)
{
	CK_SLOT_ID slot_id;
	CK_MECHANISM_TYPE_PTR mechanism_list;
	CK_ULONG count;

	BEGIN_CALL (GetMechanismList);
		IN_ULONG (slot_id);
		IN_ULONG_BUFFER (mechanism_list, count);
	PROCESS_CALL ((self, slot_id, mechanism_list, &count));
		OUT_ULONG_ARRAY (mechanism_list, count);
	END_CALL;
}

static CK_RV
rpc_C_GetMechanismInfo (CK_X_FUNCTION_LIST *self,
                        p11_rpc_message *msg)
{
	CK_SLOT_ID slot_id;
	CK_MECHANISM_TYPE type;
	CK_MECHANISM_INFO info;

	BEGIN_CALL (GetMechanismInfo);
		IN_ULONG (slot_id);
		IN_ULONG (type);
	PROCESS_CALL ((self, slot_id, type, &info));
		OUT_MECHANISM_INFO (info);
	END_CALL;
}

static CK_RV
rpc_C_InitToken (CK_X_FUNCTION_LIST *self,
                 p11_rpc_message *msg)
{
	CK_SLOT_ID slot_id;
	CK_UTF8CHAR_PTR pin;
	CK_ULONG pin_len;
	CK_UTF8CHAR_PTR label;

	BEGIN_CALL (InitToken);
		IN_ULONG (slot_id);
		IN_BYTE_ARRAY (pin, pin_len);
		IN_STRING (label);
	PROCESS_CALL ((self, slot_id, pin, pin_len, label));
	END_CALL;
}

static CK_RV
rpc_C_WaitForSlotEvent (CK_X_FUNCTION_LIST *self,
                        p11_rpc_message *msg)
{
	CK_FLAGS flags;
	CK_SLOT_ID slot_id;

	BEGIN_CALL (WaitForSlotEvent);
		IN_ULONG (flags);
	PROCESS_CALL ((self, flags, &slot_id, NULL));
		OUT_ULONG (slot_id);
	END_CALL;
}

static CK_RV
rpc_C_OpenSession (CK_X_FUNCTION_LIST *self,
                   p11_rpc_message *msg)
{
	CK_SLOT_ID slot_id;
	CK_FLAGS flags;
	CK_SESSION_HANDLE session;

	BEGIN_CALL (OpenSession);
		IN_ULONG (slot_id);
		IN_ULONG (flags);
	PROCESS_CALL ((self, slot_id, flags, NULL, NULL, &session));
		OUT_ULONG (session);
	END_CALL;
}


static CK_RV
rpc_C_CloseSession (CK_X_FUNCTION_LIST *self,
                    p11_rpc_message *msg)
{
	CK_SESSION_HANDLE session;

	BEGIN_CALL (CloseSession);
		IN_ULONG (session);
	PROCESS_CALL ((self, session));
	END_CALL;
}

static CK_RV
rpc_C_CloseAllSessions (CK_X_FUNCTION_LIST *self,
                        p11_rpc_message *msg)
{
	CK_SLOT_ID slot_id;

	/* Slot id becomes apartment so lower layers can tell clients apart. */

	BEGIN_CALL (CloseAllSessions);
		IN_ULONG (slot_id);
	PROCESS_CALL ((self, slot_id));
	END_CALL;
}

static CK_RV
rpc_C_GetSessionInfo (CK_X_FUNCTION_LIST *self,
                      p11_rpc_message *msg)
{
	CK_SESSION_HANDLE session;
	CK_SESSION_INFO info;

	BEGIN_CALL (GetSessionInfo);
		IN_ULONG (session);
	PROCESS_CALL ((self, session, &info));
		OUT_SESSION_INFO (info);
	END_CALL;
}

static CK_RV
rpc_C_InitPIN (CK_X_FUNCTION_LIST *self,
               p11_rpc_message *msg)
{
	CK_SESSION_HANDLE session;
	CK_UTF8CHAR_PTR pin;
	CK_ULONG pin_len;

	BEGIN_CALL (InitPIN);
		IN_ULONG (session);
		IN_BYTE_ARRAY (pin, pin_len);
	PROCESS_CALL ((self, session, pin, pin_len));
	END_CALL;
}

static CK_RV
rpc_C_SetPIN (CK_X_FUNCTION_LIST *self,
              p11_rpc_message *msg)
{
	CK_SESSION_HANDLE session;
	CK_UTF8CHAR_PTR old_pin;
	CK_ULONG old_len;
	CK_UTF8CHAR_PTR new_pin;
	CK_ULONG new_len;

	BEGIN_CALL (SetPIN);
		IN_ULONG (session);
		IN_BYTE_ARRAY (old_pin, old_len);
		IN_BYTE_ARRAY (new_pin, new_len);
	PROCESS_CALL ((self, session, old_pin, old_len, new_pin, new_len));
	END_CALL;
}

static CK_RV
rpc_C_GetOperationState (CK_X_FUNCTION_LIST *self,
                                p11_rpc_message *msg)
{
	CK_SESSION_HANDLE session;
	CK_BYTE_PTR operation_state;
	CK_ULONG operation_state_len;

	BEGIN_CALL (GetOperationState);
		IN_ULONG (session);
		IN_BYTE_BUFFER (operation_state, operation_state_len);
	PROCESS_CALL ((self, session, operation_state, &operation_state_len));
		OUT_BYTE_ARRAY (operation_state, operation_state_len);
	END_CALL;
}

static CK_RV
rpc_C_SetOperationState (CK_X_FUNCTION_LIST *self,
                         p11_rpc_message *msg)
{
	CK_SESSION_HANDLE session;
	CK_BYTE_PTR operation_state;
	CK_ULONG operation_state_len;
	CK_OBJECT_HANDLE encryption_key;
	CK_OBJECT_HANDLE authentication_key;

	BEGIN_CALL (SetOperationState);
		IN_ULONG (session);
		IN_BYTE_ARRAY (operation_state, operation_state_len);
		IN_ULONG (encryption_key);
		IN_ULONG (authentication_key);
	PROCESS_CALL ((self, session, operation_state, operation_state_len, encryption_key, authentication_key));
	END_CALL;
}

static CK_RV
rpc_C_Login (CK_X_FUNCTION_LIST *self,
             p11_rpc_message *msg)
{
	CK_SESSION_HANDLE session;
	CK_USER_TYPE user_type;
	CK_UTF8CHAR_PTR pin;
	CK_ULONG pin_len;

	BEGIN_CALL (Login);
		IN_ULONG (session);
		IN_ULONG (user_type);
		IN_BYTE_ARRAY (pin, pin_len);
	PROCESS_CALL ((self, session, user_type, pin, pin_len));
	END_CALL;
}

static CK_RV
rpc_C_Logout (CK_X_FUNCTION_LIST *self,
              p11_rpc_message *msg)
{
	CK_SESSION_HANDLE session;

	BEGIN_CALL (Logout);
		IN_ULONG (session);
	PROCESS_CALL ((self, session));
	END_CALL;
}

static CK_RV
rpc_C_CreateObject (CK_X_FUNCTION_LIST *self,
                    p11_rpc_message *msg)
{
	CK_SESSION_HANDLE session;
	CK_ATTRIBUTE_PTR template;
	CK_ULONG count;
	CK_OBJECT_HANDLE new_object;

	BEGIN_CALL (CreateObject);
		IN_ULONG (session);
		IN_ATTRIBUTE_ARRAY (template, count);
	PROCESS_CALL ((self, session, template, count, &new_object));
		OUT_ULONG (new_object);
	END_CALL;
}

static CK_RV
rpc_C_CopyObject (CK_X_FUNCTION_LIST *self,
                  p11_rpc_message *msg)
{
	CK_SESSION_HANDLE session;
	CK_OBJECT_HANDLE object;
	CK_ATTRIBUTE_PTR template;
	CK_ULONG count;
	CK_OBJECT_HANDLE new_object;

	BEGIN_CALL (CopyObject);
		IN_ULONG (session);
		IN_ULONG (object);
		IN_ATTRIBUTE_ARRAY (template, count);
	PROCESS_CALL ((self, session, object, template, count, &new_object));
		OUT_ULONG (new_object);
	END_CALL;
}

static CK_RV
rpc_C_DestroyObject (CK_X_FUNCTION_LIST *self,
                     p11_rpc_message *msg)
{
	CK_SESSION_HANDLE session;
	CK_OBJECT_HANDLE object;

	BEGIN_CALL (DestroyObject);
		IN_ULONG (session);
		IN_ULONG (object);
	PROCESS_CALL ((self, session, object));
	END_CALL;
}

static CK_RV
rpc_C_GetObjectSize (CK_X_FUNCTION_LIST *self,
                     p11_rpc_message *msg)
{
	CK_SESSION_HANDLE session;
	CK_OBJECT_HANDLE object;
	CK_ULONG size;

	BEGIN_CALL (GetObjectSize);
		IN_ULONG (session);
		IN_ULONG (object);
	PROCESS_CALL ((self, session, object, &size));
		OUT_ULONG (size);
	END_CALL;
}

static CK_RV
rpc_C_GetAttributeValue (CK_X_FUNCTION_LIST *self,
                         p11_rpc_message *msg)
{
	CK_SESSION_HANDLE session;
	CK_OBJECT_HANDLE object;
	CK_ATTRIBUTE_PTR template;
	CK_ULONG count;

	BEGIN_CALL (GetAttributeValue);
		IN_ULONG (session);
		IN_ULONG (object);
		IN_ATTRIBUTE_BUFFER (template, count);
	PROCESS_CALL ((self, session, object, template, count));
		OUT_ATTRIBUTE_ARRAY (template, count);
	END_CALL;
}

static CK_RV
rpc_C_SetAttributeValue (CK_X_FUNCTION_LIST *self,
                         p11_rpc_message *msg)
{
	CK_SESSION_HANDLE session;
	CK_OBJECT_HANDLE object;
	CK_ATTRIBUTE_PTR template;
	CK_ULONG count;

	BEGIN_CALL (SetAttributeValue);
		IN_ULONG (session);
		IN_ULONG (object);
		IN_ATTRIBUTE_ARRAY (template, count);
	PROCESS_CALL ((self, session, object, template, count));
	END_CALL;
}

static CK_RV
rpc_C_FindObjectsInit (CK_X_FUNCTION_LIST *self,
                       p11_rpc_message *msg)
{
	CK_SESSION_HANDLE session;
	CK_ATTRIBUTE_PTR template;
	CK_ULONG count;

	BEGIN_CALL (FindObjectsInit);
		IN_ULONG (session);
		IN_ATTRIBUTE_ARRAY (template, count);
	PROCESS_CALL ((self, session, template, count));
	END_CALL;
}

static CK_RV
rpc_C_FindObjects (CK_X_FUNCTION_LIST *self,
                    p11_rpc_message *msg)
{
	CK_SESSION_HANDLE session;
	CK_OBJECT_HANDLE_PTR objects;
	CK_ULONG max_object_count;
	CK_ULONG object_count;

	BEGIN_CALL (FindObjects);
		IN_ULONG (session);
		IN_ULONG_BUFFER (objects, max_object_count);
	PROCESS_CALL ((self, session, objects, max_object_count, &object_count));
		OUT_ULONG_ARRAY (objects, object_count);
	END_CALL;
}

static CK_RV
rpc_C_FindObjectsFinal (CK_X_FUNCTION_LIST *self,
                        p11_rpc_message *msg)
{
	CK_SESSION_HANDLE session;

	BEGIN_CALL (FindObjectsFinal);
		IN_ULONG (session);
	PROCESS_CALL ((self, session));
	END_CALL;
}

static CK_RV
rpc_C_EncryptInit (CK_X_FUNCTION_LIST *self,
                   p11_rpc_message *msg)
{
	CK_SESSION_HANDLE session;
	CK_MECHANISM mechanism_;
	CK_MECHANISM_PTR mechanism = &mechanism_;
	CK_OBJECT_HANDLE key;

	BEGIN_CALL (EncryptInit);
		IN_ULONG (session);
		IN_MECHANISM (mechanism);
		IN_ULONG (key);
	PROCESS_CALL ((self, session, mechanism, key));
	END_CALL;

}

static CK_RV
rpc_C_Encrypt (CK_X_FUNCTION_LIST *self,
               p11_rpc_message *msg)
{
	CK_SESSION_HANDLE session;
	CK_BYTE_PTR data;
	CK_ULONG data_len;
	CK_BYTE_PTR encrypted_data;
	CK_ULONG encrypted_data_len;

	BEGIN_CALL (Encrypt);
		IN_ULONG (session);
		IN_BYTE_ARRAY (data, data_len);
		IN_BYTE_BUFFER (encrypted_data, encrypted_data_len);
	PROCESS_CALL ((self, session, data, data_len, encrypted_data, &encrypted_data_len));
		OUT_BYTE_ARRAY (encrypted_data, encrypted_data_len);
	END_CALL;
}

static CK_RV
rpc_C_EncryptUpdate (CK_X_FUNCTION_LIST *self,
                        p11_rpc_message *msg)
{
	CK_SESSION_HANDLE session;
	CK_BYTE_PTR part;
	CK_ULONG part_len;
	CK_BYTE_PTR encrypted_part;
	CK_ULONG encrypted_part_len;

	BEGIN_CALL (EncryptUpdate);
		IN_ULONG (session);
		IN_BYTE_ARRAY (part, part_len);
		IN_BYTE_BUFFER (encrypted_part, encrypted_part_len);
	PROCESS_CALL ((self, session, part, part_len, encrypted_part, &encrypted_part_len));
		OUT_BYTE_ARRAY (encrypted_part, encrypted_part_len);
	END_CALL;
}

static CK_RV
rpc_C_EncryptFinal (CK_X_FUNCTION_LIST *self,
                    p11_rpc_message *msg)
{
	CK_SESSION_HANDLE session;
	CK_BYTE_PTR last_encrypted_part;
	CK_ULONG last_encrypted_part_len;

	BEGIN_CALL (EncryptFinal);
		IN_ULONG (session);
		IN_BYTE_BUFFER (last_encrypted_part, last_encrypted_part_len);
	PROCESS_CALL ((self, session, last_encrypted_part, &last_encrypted_part_len));
		OUT_BYTE_ARRAY (last_encrypted_part, last_encrypted_part_len);
	END_CALL;
}

static CK_RV
rpc_C_DecryptInit (CK_X_FUNCTION_LIST *self,
                    p11_rpc_message *msg)
{
	CK_SESSION_HANDLE session;
	CK_MECHANISM mechanism_;
	CK_MECHANISM_PTR mechanism = &mechanism_;
	CK_OBJECT_HANDLE key;

	BEGIN_CALL (DecryptInit);
		IN_ULONG (session);
		IN_MECHANISM (mechanism);
		IN_ULONG (key);
	PROCESS_CALL ((self, session, mechanism, key));
	END_CALL;
}

static CK_RV
rpc_C_Decrypt (CK_X_FUNCTION_LIST *self,
               p11_rpc_message *msg)
{
	CK_SESSION_HANDLE session;
	CK_BYTE_PTR encrypted_data;
	CK_ULONG encrypted_data_len;
	CK_BYTE_PTR data;
	CK_ULONG data_len;

	BEGIN_CALL (Decrypt);
		IN_ULONG (session);
		IN_BYTE_ARRAY (encrypted_data, encrypted_data_len);
		IN_BYTE_BUFFER (data, data_len);
	PROCESS_CALL ((self, session, encrypted_data, encrypted_data_len, data, &data_len));
		OUT_BYTE_ARRAY (data, data_len);
	END_CALL;
}

static CK_RV
rpc_C_DecryptUpdate (CK_X_FUNCTION_LIST *self,
                     p11_rpc_message *msg)
{
	CK_SESSION_HANDLE session;
	CK_BYTE_PTR encrypted_part;
	CK_ULONG encrypted_part_len;
	CK_BYTE_PTR part;
	CK_ULONG part_len;

	BEGIN_CALL (DecryptUpdate);
		IN_ULONG (session);
		IN_BYTE_ARRAY (encrypted_part, encrypted_part_len);
		IN_BYTE_BUFFER (part, part_len);
	PROCESS_CALL ((self, session, encrypted_part, encrypted_part_len, part, &part_len));
		OUT_BYTE_ARRAY (part, part_len);
	END_CALL;
}

static CK_RV
rpc_C_DecryptFinal (CK_X_FUNCTION_LIST *self,
                    p11_rpc_message *msg)
{
	CK_SESSION_HANDLE session;
	CK_BYTE_PTR last_part;
	CK_ULONG last_part_len;

	BEGIN_CALL (DecryptFinal);
		IN_ULONG (session);
		IN_BYTE_BUFFER (last_part, last_part_len);
	PROCESS_CALL ((self, session, last_part, &last_part_len));
		OUT_BYTE_ARRAY (last_part, last_part_len);
	END_CALL;
}

static CK_RV
rpc_C_DigestInit (CK_X_FUNCTION_LIST *self,
                  p11_rpc_message *msg)
{
	CK_SESSION_HANDLE session;
	CK_MECHANISM mechanism_;
	CK_MECHANISM_PTR mechanism = &mechanism_;

	BEGIN_CALL (DigestInit);
		IN_ULONG (session);
		IN_MECHANISM (mechanism);
	PROCESS_CALL ((self, session, mechanism));
	END_CALL;
}

static CK_RV
rpc_C_Digest (CK_X_FUNCTION_LIST *self,
              p11_rpc_message *msg)
{
	CK_SESSION_HANDLE session;
	CK_BYTE_PTR data;
	CK_ULONG data_len;
	CK_BYTE_PTR digest;
	CK_ULONG digest_len;

	BEGIN_CALL (Digest);
		IN_ULONG (session);
		IN_BYTE_ARRAY (data, data_len);
		IN_BYTE_BUFFER (digest, digest_len);
	PROCESS_CALL ((self, session, data, data_len, digest, &digest_len));
		OUT_BYTE_ARRAY (digest, digest_len);
	END_CALL;
}

static CK_RV
rpc_C_DigestUpdate (CK_X_FUNCTION_LIST *self,
                    p11_rpc_message *msg)
{
	CK_SESSION_HANDLE session;
	CK_BYTE_PTR part;
	CK_ULONG part_len;

	BEGIN_CALL (DigestUpdate);
		IN_ULONG (session);
		IN_BYTE_ARRAY (part, part_len);
	PROCESS_CALL ((self, session, part, part_len));
	END_CALL;
}

static CK_RV
rpc_C_DigestKey (CK_X_FUNCTION_LIST *self,
                 p11_rpc_message *msg)
{
	CK_SESSION_HANDLE session;
	CK_OBJECT_HANDLE key;

	BEGIN_CALL (DigestKey);
		IN_ULONG (session);
		IN_ULONG (key);
	PROCESS_CALL ((self, session, key));
	END_CALL;
}

static CK_RV
rpc_C_DigestFinal (CK_X_FUNCTION_LIST *self,
                   p11_rpc_message *msg)
{
	CK_SESSION_HANDLE session;
	CK_BYTE_PTR digest;
	CK_ULONG digest_len;

	BEGIN_CALL (DigestFinal);
		IN_ULONG (session);
		IN_BYTE_BUFFER (digest, digest_len);
	PROCESS_CALL ((self, session, digest, &digest_len));
		OUT_BYTE_ARRAY (digest, digest_len);
	END_CALL;
}

static CK_RV
rpc_C_SignInit (CK_X_FUNCTION_LIST *self,
                p11_rpc_message *msg)
{
	CK_SESSION_HANDLE session;
	CK_MECHANISM mechanism_;
	CK_MECHANISM_PTR mechanism = &mechanism_;
	CK_OBJECT_HANDLE key;

	BEGIN_CALL (SignInit);
		IN_ULONG (session);
		IN_MECHANISM (mechanism);
		IN_ULONG (key);
	PROCESS_CALL ((self, session, mechanism, key));
	END_CALL;
}

static CK_RV
rpc_C_Sign (CK_X_FUNCTION_LIST *self,
            p11_rpc_message *msg)
{
	CK_SESSION_HANDLE session;
	CK_BYTE_PTR part;
	CK_ULONG part_len;
	CK_BYTE_PTR signature;
	CK_ULONG signature_len;

	BEGIN_CALL (Sign);
		IN_ULONG (session);
		IN_BYTE_ARRAY (part, part_len);
		IN_BYTE_BUFFER (signature, signature_len);
	PROCESS_CALL ((self, session, part, part_len, signature, &signature_len));
		OUT_BYTE_ARRAY (signature, signature_len);
	END_CALL;

}

static CK_RV
rpc_C_SignUpdate (CK_X_FUNCTION_LIST *self,
                  p11_rpc_message *msg)
{
	CK_SESSION_HANDLE session;
	CK_BYTE_PTR part;
	CK_ULONG part_len;

	BEGIN_CALL (SignUpdate);
		IN_ULONG (session);
		IN_BYTE_ARRAY (part, part_len);
	PROCESS_CALL ((self, session, part, part_len));
	END_CALL;
}

static CK_RV
rpc_C_SignFinal (CK_X_FUNCTION_LIST *self,
                 p11_rpc_message *msg)
{
	CK_SESSION_HANDLE session;
	CK_BYTE_PTR signature;
	CK_ULONG signature_len;

	BEGIN_CALL (SignFinal);
		IN_ULONG (session);
		IN_BYTE_BUFFER (signature, signature_len);
	PROCESS_CALL ((self, session, signature, &signature_len));
		OUT_BYTE_ARRAY (signature, signature_len);
	END_CALL;
}

static CK_RV
rpc_C_SignRecoverInit (CK_X_FUNCTION_LIST *self,
                       p11_rpc_message *msg)
{
	CK_SESSION_HANDLE session;
	CK_MECHANISM mechanism_;
	CK_MECHANISM_PTR mechanism = &mechanism_;
	CK_OBJECT_HANDLE key;

	BEGIN_CALL (SignRecoverInit);
		IN_ULONG (session);
		IN_MECHANISM (mechanism);
		IN_ULONG (key);
	PROCESS_CALL ((self, session, mechanism, key));
	END_CALL;
}

static CK_RV
rpc_C_SignRecover (CK_X_FUNCTION_LIST *self,
                   p11_rpc_message *msg)
{
	CK_SESSION_HANDLE session;
	CK_BYTE_PTR data;
	CK_ULONG data_len;
	CK_BYTE_PTR signature;
	CK_ULONG signature_len;

	BEGIN_CALL (SignRecover);
		IN_ULONG (session);
		IN_BYTE_ARRAY (data, data_len);
		IN_BYTE_BUFFER (signature, signature_len);
	PROCESS_CALL ((self, session, data, data_len, signature, &signature_len));
		OUT_BYTE_ARRAY (signature, signature_len);
	END_CALL;
}

static CK_RV
rpc_C_VerifyInit (CK_X_FUNCTION_LIST *self,
                  p11_rpc_message *msg)
{
	CK_SESSION_HANDLE session;
	CK_MECHANISM mechanism_;
	CK_MECHANISM_PTR mechanism = &mechanism_;
	CK_OBJECT_HANDLE key;

	BEGIN_CALL (VerifyInit);
		IN_ULONG (session);
		IN_MECHANISM (mechanism);
		IN_ULONG (key);
	PROCESS_CALL ((self, session, mechanism, key));
	END_CALL;
}

static CK_RV
rpc_C_Verify (CK_X_FUNCTION_LIST *self,
              p11_rpc_message *msg)
{
	CK_SESSION_HANDLE session;
	CK_BYTE_PTR data;
	CK_ULONG data_len;
	CK_BYTE_PTR signature;
	CK_ULONG signature_len;

	BEGIN_CALL (Verify);
		IN_ULONG (session);
		IN_BYTE_ARRAY (data, data_len);
		IN_BYTE_ARRAY (signature, signature_len);
	PROCESS_CALL ((self, session, data, data_len, signature, signature_len));
	END_CALL;
}

static CK_RV
rpc_C_VerifyUpdate (CK_X_FUNCTION_LIST *self,
                    p11_rpc_message *msg)
{
	CK_SESSION_HANDLE session;
	CK_BYTE_PTR part;
	CK_ULONG part_len;

	BEGIN_CALL (VerifyUpdate);
		IN_ULONG (session);
		IN_BYTE_ARRAY (part, part_len);
	PROCESS_CALL ((self, session, part, part_len));
	END_CALL;
}

static CK_RV
rpc_C_VerifyFinal (CK_X_FUNCTION_LIST *self,
                   p11_rpc_message *msg)
{
	CK_SESSION_HANDLE session;
	CK_BYTE_PTR signature;
	CK_ULONG signature_len;

	BEGIN_CALL (VerifyFinal);
		IN_ULONG (session);
		IN_BYTE_ARRAY (signature, signature_len);
	PROCESS_CALL ((self, session, signature, signature_len));
	END_CALL;
}

static CK_RV
rpc_C_VerifyRecoverInit (CK_X_FUNCTION_LIST *self,
                         p11_rpc_message *msg)
{
	CK_SESSION_HANDLE session;
	CK_MECHANISM mechanism_;
	CK_MECHANISM_PTR mechanism = &mechanism_;
	CK_OBJECT_HANDLE key;

	BEGIN_CALL (VerifyRecoverInit);
		IN_ULONG (session);
		IN_MECHANISM (mechanism);
		IN_ULONG (key);
	PROCESS_CALL ((self, session, mechanism, key));
	END_CALL;
}

static CK_RV
rpc_C_VerifyRecover (CK_X_FUNCTION_LIST *self,
                     p11_rpc_message *msg)
{
	CK_SESSION_HANDLE session;
	CK_BYTE_PTR signature;
	CK_ULONG signature_len;
	CK_BYTE_PTR data;
	CK_ULONG data_len;

	BEGIN_CALL (VerifyRecover);
		IN_ULONG (session);
		IN_BYTE_ARRAY (signature, signature_len);
		IN_BYTE_BUFFER (data, data_len);
	PROCESS_CALL ((self, session, signature, signature_len, data, &data_len));
		OUT_BYTE_ARRAY (data, data_len);
	END_CALL;
}

static CK_RV
rpc_C_DigestEncryptUpdate (CK_X_FUNCTION_LIST *self,
                           p11_rpc_message *msg)
{
	CK_SESSION_HANDLE session;
	CK_BYTE_PTR part;
	CK_ULONG part_len;
	CK_BYTE_PTR encrypted_part;
	CK_ULONG encrypted_part_len;

	BEGIN_CALL (DigestEncryptUpdate);
		IN_ULONG (session);
		IN_BYTE_ARRAY (part, part_len);
		IN_BYTE_BUFFER (encrypted_part, encrypted_part_len);
	PROCESS_CALL ((self, session, part, part_len, encrypted_part, &encrypted_part_len));
		OUT_BYTE_ARRAY (encrypted_part, encrypted_part_len);
	END_CALL;
}

static CK_RV
rpc_C_DecryptDigestUpdate (CK_X_FUNCTION_LIST *self,
                                    p11_rpc_message *msg)
{
	CK_SESSION_HANDLE session;
	CK_BYTE_PTR encrypted_part;
	CK_ULONG encrypted_part_len;
	CK_BYTE_PTR part;
	CK_ULONG part_len;

	BEGIN_CALL (DecryptDigestUpdate);
		IN_ULONG (session);
		IN_BYTE_ARRAY (encrypted_part, encrypted_part_len);
		IN_BYTE_BUFFER (part, part_len);
	PROCESS_CALL ((self, session, encrypted_part, encrypted_part_len, part, &part_len));
		OUT_BYTE_ARRAY (part, part_len);
	END_CALL;
}

static CK_RV
rpc_C_SignEncryptUpdate (CK_X_FUNCTION_LIST *self,
                         p11_rpc_message *msg)
{
	CK_SESSION_HANDLE session;
	CK_BYTE_PTR part;
	CK_ULONG part_len;
	CK_BYTE_PTR encrypted_part;
	CK_ULONG encrypted_part_len;

	BEGIN_CALL (SignEncryptUpdate);
		IN_ULONG (session);
		IN_BYTE_ARRAY (part, part_len);
		IN_BYTE_BUFFER (encrypted_part, encrypted_part_len);
	PROCESS_CALL ((self, session, part, part_len, encrypted_part, &encrypted_part_len));
		OUT_BYTE_ARRAY (encrypted_part, encrypted_part_len);
	END_CALL;
}

static CK_RV
rpc_C_DecryptVerifyUpdate (CK_X_FUNCTION_LIST *self,
                           p11_rpc_message *msg)
{
	CK_SESSION_HANDLE session;
	CK_BYTE_PTR encrypted_part;
	CK_ULONG encrypted_part_len;
	CK_BYTE_PTR part;
	CK_ULONG part_len;

	BEGIN_CALL (DecryptVerifyUpdate);
		IN_ULONG (session);
		IN_BYTE_ARRAY (encrypted_part, encrypted_part_len);
		IN_BYTE_BUFFER (part, part_len);
	PROCESS_CALL ((self, session, encrypted_part, encrypted_part_len, part, &part_len));
		OUT_BYTE_ARRAY (part, part_len);
	END_CALL;
}

static CK_RV
rpc_C_GenerateKey (CK_X_FUNCTION_LIST *self,
                   p11_rpc_message *msg)
{
	CK_SESSION_HANDLE session;
	CK_MECHANISM mechanism_;
	CK_MECHANISM_PTR mechanism = &mechanism_;
	CK_ATTRIBUTE_PTR template;
	CK_ULONG count;
	CK_OBJECT_HANDLE key;

	BEGIN_CALL (GenerateKey);
		IN_ULONG (session);
		IN_MECHANISM (mechanism);
		IN_ATTRIBUTE_ARRAY (template, count);
	PROCESS_CALL ((self, session, mechanism, template, count, &key));
		OUT_ULONG (key);
	END_CALL;
}

static CK_RV
rpc_C_GenerateKeyPair (CK_X_FUNCTION_LIST *self,
                       p11_rpc_message *msg)
{
	CK_SESSION_HANDLE session;
	CK_MECHANISM mechanism_;
	CK_MECHANISM_PTR mechanism = &mechanism_;
	CK_ATTRIBUTE_PTR public_key_template;
	CK_ULONG public_key_attribute_count;
	CK_ATTRIBUTE_PTR private_key_template;
	CK_ULONG private_key_attribute_count;
	CK_OBJECT_HANDLE public_key;
	CK_OBJECT_HANDLE private_key;

	BEGIN_CALL (GenerateKeyPair);
		IN_ULONG (session);
		IN_MECHANISM (mechanism);
		IN_ATTRIBUTE_ARRAY (public_key_template, public_key_attribute_count);
		IN_ATTRIBUTE_ARRAY (private_key_template, private_key_attribute_count);
	PROCESS_CALL ((self, session, mechanism, public_key_template, public_key_attribute_count,
	               private_key_template, private_key_attribute_count, &public_key, &private_key));
		OUT_ULONG (public_key);
		OUT_ULONG (private_key);
	END_CALL;
}

static CK_RV
rpc_C_WrapKey (CK_X_FUNCTION_LIST *self,
               p11_rpc_message *msg)
{
	CK_SESSION_HANDLE session;
	CK_MECHANISM mechanism_;
	CK_MECHANISM_PTR mechanism = &mechanism_;
	CK_OBJECT_HANDLE wrapping_key;
	CK_OBJECT_HANDLE key;
	CK_BYTE_PTR wrapped_key;
	CK_ULONG wrapped_key_len;

	BEGIN_CALL (WrapKey);
		IN_ULONG (session);
		IN_MECHANISM (mechanism);
		IN_ULONG (wrapping_key);
		IN_ULONG (key);
		IN_BYTE_BUFFER (wrapped_key, wrapped_key_len);
	PROCESS_CALL ((self, session, mechanism, wrapping_key, key, wrapped_key, &wrapped_key_len));
		OUT_BYTE_ARRAY (wrapped_key, wrapped_key_len);
	END_CALL;
}

static CK_RV
rpc_C_UnwrapKey (CK_X_FUNCTION_LIST *self,
                 p11_rpc_message *msg)
{
	CK_SESSION_HANDLE session;
	CK_MECHANISM mechanism_;
	CK_MECHANISM_PTR mechanism = &mechanism_;
	CK_OBJECT_HANDLE unwrapping_key;
	CK_BYTE_PTR wrapped_key;
	CK_ULONG wrapped_key_len;
	CK_ATTRIBUTE_PTR template;
	CK_ULONG attribute_count;
	CK_OBJECT_HANDLE key;

	BEGIN_CALL (UnwrapKey);
		IN_ULONG (session);
		IN_MECHANISM (mechanism);
		IN_ULONG (unwrapping_key);
		IN_BYTE_ARRAY (wrapped_key, wrapped_key_len);
		IN_ATTRIBUTE_ARRAY (template, attribute_count);
	PROCESS_CALL ((self, session, mechanism, unwrapping_key, wrapped_key, wrapped_key_len, template, attribute_count, &key));
		OUT_ULONG (key);
	END_CALL;
}

static CK_RV
rpc_C_DeriveKey (CK_X_FUNCTION_LIST *self,
                 p11_rpc_message *msg)
{
	CK_SESSION_HANDLE session;
	CK_MECHANISM mechanism_;
	CK_MECHANISM_PTR mechanism = &mechanism_;
	CK_OBJECT_HANDLE base_key;
	CK_ATTRIBUTE_PTR template;
	CK_ULONG attribute_count;
	CK_OBJECT_HANDLE key;

	BEGIN_CALL (DeriveKey);
		IN_ULONG (session);
		IN_MECHANISM (mechanism);
		IN_ULONG (base_key);
		IN_ATTRIBUTE_ARRAY (template, attribute_count);
	PROCESS_CALL ((self, session, mechanism, base_key, template, attribute_count, &key));
		OUT_ULONG (key);
	END_CALL;
}

static CK_RV
rpc_C_SeedRandom (CK_X_FUNCTION_LIST *self,
                  p11_rpc_message *msg)
{
	CK_SESSION_HANDLE session;
	CK_BYTE_PTR seed;
	CK_ULONG seed_len;

	BEGIN_CALL (SeedRandom);
		IN_ULONG (session);
		IN_BYTE_ARRAY (seed, seed_len);
	PROCESS_CALL ((self, session, seed, seed_len));
	END_CALL;
}

static CK_RV
rpc_C_GenerateRandom (CK_X_FUNCTION_LIST *self,
                      p11_rpc_message *msg)
{
	CK_SESSION_HANDLE session;
	CK_BYTE_PTR random_data;
	CK_ULONG random_len;

	BEGIN_CALL (GenerateRandom);
		IN_ULONG (session);
		IN_BYTE_BUFFER (random_data, random_len);
	PROCESS_CALL ((self, session, random_data, random_len));
		OUT_BYTE_ARRAY (random_data, random_len);
	END_CALL;
}

static CK_RV
rpc_C_LoginUser (CK_X_FUNCTION_LIST *self,
                 p11_rpc_message *msg)
{
	CK_SESSION_HANDLE session;
	CK_USER_TYPE user_type;
	CK_UTF8CHAR_PTR pin;
	CK_ULONG pin_len;
	CK_UTF8CHAR_PTR username;
	CK_ULONG username_len;

	BEGIN_CALL (LoginUser);
		IN_ULONG (session);
		IN_ULONG (user_type);
		IN_BYTE_ARRAY (pin, pin_len);
		IN_BYTE_ARRAY (username, username_len);
	PROCESS_CALL ((self, session, user_type, pin, pin_len, username, username_len));
	END_CALL;
}

static CK_RV
rpc_C_SessionCancel (CK_X_FUNCTION_LIST *self,
                     p11_rpc_message *msg)
{
	CK_SESSION_HANDLE session;
	CK_FLAGS flags;

	BEGIN_CALL (SessionCancel);
		IN_ULONG (session);
		IN_ULONG (flags);
	PROCESS_CALL ((self, session, flags));
	END_CALL;
}

static CK_RV
rpc_C_MessageEncryptInit (CK_X_FUNCTION_LIST *self,
                          p11_rpc_message *msg)
{
	CK_SESSION_HANDLE session;
	CK_MECHANISM mechanism_;
	CK_MECHANISM_PTR mechanism = &mechanism_;
	CK_OBJECT_HANDLE key;

	BEGIN_CALL (MessageEncryptInit);
		IN_ULONG (session);
		IN_MECHANISM (mechanism);
		IN_ULONG (key);
	PROCESS_CALL ((self, session, mechanism, key));
	END_CALL;
}

static CK_RV
rpc_C_EncryptMessage (CK_X_FUNCTION_LIST *self,
                      p11_rpc_message *msg)
{
	CK_SESSION_HANDLE session;
	CK_BYTE_PTR parameter;
	CK_ULONG parameter_len;
	CK_BYTE_PTR associated_data;
	CK_ULONG associated_data_len;
	CK_BYTE_PTR plaintext;
	CK_ULONG plaintext_len;
	CK_BYTE_PTR ciphertext;
	CK_ULONG ciphertext_len;

	BEGIN_CALL (EncryptMessage);
		IN_ULONG (session);
		IN_BYTE_ARRAY (parameter, parameter_len);
		IN_BYTE_ARRAY (associated_data, associated_data_len);
		IN_BYTE_ARRAY (plaintext, plaintext_len);
		IN_BYTE_BUFFER (ciphertext, ciphertext_len);
	PROCESS_CALL ((self, session, (void *)parameter, parameter_len, associated_data, associated_data_len,
	               plaintext, plaintext_len, ciphertext, &ciphertext_len));
		OUT_BYTE_ARRAY (ciphertext, ciphertext_len);
	END_CALL;
}

static CK_RV
rpc_C_EncryptMessageBegin (CK_X_FUNCTION_LIST *self,
                           p11_rpc_message *msg)
{
	CK_SESSION_HANDLE session;
	CK_BYTE_PTR parameter;
	CK_ULONG parameter_len;
	CK_BYTE_PTR associated_data;
	CK_ULONG associated_data_len;

	BEGIN_CALL (EncryptMessageBegin);
		IN_ULONG (session)
		IN_BYTE_ARRAY (parameter, parameter_len)
		IN_BYTE_ARRAY (associated_data, associated_data_len)
	PROCESS_CALL ((self, session, (void *)parameter, parameter_len, associated_data, associated_data_len));
	END_CALL;
}

static CK_RV
rpc_C_EncryptMessageNext (CK_X_FUNCTION_LIST *self,
                          p11_rpc_message *msg)
{
	CK_SESSION_HANDLE session;
	CK_BYTE_PTR parameter;
	CK_ULONG parameter_len;
	CK_BYTE_PTR plaintext_part;
	CK_ULONG plaintext_part_len;
	CK_BYTE_PTR ciphertext_part;
	CK_ULONG ciphertext_part_len;
	CK_FLAGS flags;

	BEGIN_CALL (EncryptMessageNext);
		IN_ULONG (session);
		IN_BYTE_ARRAY (parameter, parameter_len);
		IN_BYTE_ARRAY (plaintext_part, plaintext_part_len);
		IN_BYTE_BUFFER (ciphertext_part, ciphertext_part_len);
		IN_ULONG (flags);
	PROCESS_CALL ((self, session, (void *)parameter, parameter_len, plaintext_part, plaintext_part_len,
	               ciphertext_part, &ciphertext_part_len, flags));
		OUT_BYTE_ARRAY (ciphertext_part, ciphertext_part_len)
	END_CALL;
}

static CK_RV
rpc_C_MessageEncryptFinal (CK_X_FUNCTION_LIST *self,
                           p11_rpc_message *msg)
{
	CK_SESSION_HANDLE session;

	BEGIN_CALL (MessageEncryptFinal);
		IN_ULONG (session);
	PROCESS_CALL ((self, session));
	END_CALL;
}

static CK_RV
rpc_C_MessageDecryptInit (CK_X_FUNCTION_LIST *self,
                          p11_rpc_message *msg)
{
	CK_SESSION_HANDLE session;
	CK_MECHANISM mechanism_;
	CK_MECHANISM_PTR mechanism = &mechanism_;
	CK_OBJECT_HANDLE key;

	BEGIN_CALL (MessageDecryptInit);
		IN_ULONG (session);
		IN_MECHANISM (mechanism);
		IN_ULONG (key);
	PROCESS_CALL ((self, session, mechanism, key));
	END_CALL;
}

static CK_RV
rpc_C_DecryptMessage (CK_X_FUNCTION_LIST *self,
                      p11_rpc_message *msg)
{
	CK_SESSION_HANDLE session;
	CK_BYTE_PTR parameter;
	CK_ULONG parameter_len;
	CK_BYTE_PTR associated_data;
	CK_ULONG associated_data_len;
	CK_BYTE_PTR ciphertext;
	CK_ULONG ciphertext_len;
	CK_BYTE_PTR plaintext;
	CK_ULONG plaintext_len;

	BEGIN_CALL (DecryptMessage);
		IN_ULONG (session);
		IN_BYTE_ARRAY (parameter, parameter_len);
		IN_BYTE_ARRAY (associated_data, associated_data_len);
		IN_BYTE_ARRAY (ciphertext, ciphertext_len);
		IN_BYTE_BUFFER (plaintext, plaintext_len);
	PROCESS_CALL ((self, session, (void *)parameter, parameter_len, associated_data, associated_data_len,
	               ciphertext, ciphertext_len, plaintext, &plaintext_len));
		OUT_BYTE_ARRAY (plaintext, plaintext_len);
	END_CALL;
}

static CK_RV
rpc_C_DecryptMessageBegin (CK_X_FUNCTION_LIST *self,
                           p11_rpc_message *msg)
{
	CK_SESSION_HANDLE session;
	CK_BYTE_PTR parameter;
	CK_ULONG parameter_len;
	CK_BYTE_PTR associated_data;
	CK_ULONG associated_data_len;

	BEGIN_CALL (DecryptMessageBegin);
		IN_ULONG (session);
		IN_BYTE_ARRAY (parameter, parameter_len);
		IN_BYTE_ARRAY (associated_data, associated_data_len);
	PROCESS_CALL ((self, session, (void *)parameter, parameter_len, associated_data, associated_data_len));
	END_CALL;
}

static CK_RV
rpc_C_DecryptMessageNext (CK_X_FUNCTION_LIST *self,
                          p11_rpc_message *msg)
{
	CK_SESSION_HANDLE session;
	CK_BYTE_PTR parameter;
	CK_ULONG parameter_len;
	CK_BYTE_PTR ciphertext_part;
	CK_ULONG ciphertext_part_len;
	CK_BYTE_PTR plaintext_part;
	CK_ULONG plaintext_part_len;
	CK_FLAGS flags;

	BEGIN_CALL (DecryptMessageNext);
		IN_ULONG (session);
		IN_BYTE_ARRAY (parameter, parameter_len);
		IN_BYTE_ARRAY (ciphertext_part, ciphertext_part_len);
		IN_BYTE_BUFFER (plaintext_part, plaintext_part_len);
		IN_ULONG (flags);
	PROCESS_CALL ((self, session, (void *)parameter, parameter_len, ciphertext_part, ciphertext_part_len,
	               plaintext_part, &plaintext_part_len, flags));
		OUT_BYTE_ARRAY (plaintext_part, plaintext_part_len);
	END_CALL;
}

static CK_RV
rpc_C_MessageDecryptFinal (CK_X_FUNCTION_LIST *self,
                           p11_rpc_message *msg)
{
	CK_SESSION_HANDLE session;

	BEGIN_CALL (MessageDecryptFinal);
		IN_ULONG (session);
	PROCESS_CALL ((self, session));
	END_CALL;
}

static CK_RV
rpc_C_MessageSignInit (CK_X_FUNCTION_LIST *self,
                       p11_rpc_message *msg)
{
	CK_SESSION_HANDLE session;
	CK_MECHANISM mechanism_;
	CK_MECHANISM_PTR mechanism = &mechanism_;
	CK_OBJECT_HANDLE key;

	BEGIN_CALL (MessageSignInit);
		IN_ULONG (session);
		IN_MECHANISM (mechanism);
		IN_ULONG (key);
	PROCESS_CALL ((self, session, mechanism, key));
	END_CALL;
}

static CK_RV
rpc_C_SignMessage (CK_X_FUNCTION_LIST *self,
                   p11_rpc_message *msg)
{
	CK_SESSION_HANDLE session;
	CK_BYTE_PTR parameter;
	CK_ULONG parameter_len;
	CK_BYTE_PTR data;
	CK_ULONG data_len;
	CK_BYTE_PTR signature;
	CK_ULONG signature_len;

	BEGIN_CALL (SignMessage);
		IN_ULONG (session);
		IN_BYTE_ARRAY (parameter, parameter_len);
		IN_BYTE_ARRAY (data, data_len);
		IN_BYTE_BUFFER (signature, signature_len);
	PROCESS_CALL ((self, session, (void *)parameter, parameter_len, data, data_len,
	               signature, &signature_len));
		OUT_BYTE_ARRAY (signature, signature_len);
	END_CALL;
}

static CK_RV
rpc_C_SignMessageBegin (CK_X_FUNCTION_LIST *self,
                        p11_rpc_message *msg)
{
	CK_SESSION_HANDLE session;
	CK_BYTE_PTR parameter;
	CK_ULONG parameter_len;

	BEGIN_CALL (SignMessageBegin);
		IN_ULONG (session);
		IN_BYTE_ARRAY (parameter, parameter_len);
	PROCESS_CALL ((self, session, (void *)parameter, parameter_len));
	END_CALL;
}

static CK_RV
rpc_C_SignMessageNext (CK_X_FUNCTION_LIST *self,
                       p11_rpc_message *msg)
{
	CK_SESSION_HANDLE session;
	CK_BYTE_PTR parameter;
	CK_ULONG parameter_len;
	CK_BYTE_PTR data;
	CK_ULONG data_len;
	CK_BYTE_PTR signature;
	CK_ULONG signature_len_;
	CK_ULONG_PTR signature_len = &signature_len_;

	BEGIN_CALL (SignMessageNext);
		IN_ULONG (session);
		IN_BYTE_ARRAY (parameter, parameter_len);
		IN_BYTE_ARRAY (data, data_len);
		IN_BYTE_BUFFER_NULL (signature, signature_len);
	PROCESS_CALL ((self, session, (void *)parameter, parameter_len, data, data_len,
	               signature, signature_len));
		OUT_BYTE_ARRAY (signature, signature_len ? *signature_len : 0);
	END_CALL;
}

static CK_RV
rpc_C_MessageSignFinal (CK_X_FUNCTION_LIST *self,
                        p11_rpc_message *msg)
{
	CK_SESSION_HANDLE session;

	BEGIN_CALL (MessageSignFinal);
		IN_ULONG (session);
	PROCESS_CALL ((self, session));
	END_CALL;
}

static CK_RV
rpc_C_MessageVerifyInit (CK_X_FUNCTION_LIST *self,
                         p11_rpc_message *msg)
{
	CK_SESSION_HANDLE session;
	CK_MECHANISM mechanism_;
	CK_MECHANISM_PTR mechanism = &mechanism_;
	CK_OBJECT_HANDLE key;

	BEGIN_CALL (MessageVerifyInit);
		IN_ULONG (session);
		IN_MECHANISM (mechanism);
		IN_ULONG (key);
	PROCESS_CALL ((self, session, mechanism, key));
	END_CALL;
}

static CK_RV
rpc_C_VerifyMessage (CK_X_FUNCTION_LIST *self,
                     p11_rpc_message *msg)
{
	CK_SESSION_HANDLE session;
	CK_BYTE_PTR parameter;
	CK_ULONG parameter_len;
	CK_BYTE_PTR data;
	CK_ULONG data_len;
	CK_BYTE_PTR signature;
	CK_ULONG signature_len;

	BEGIN_CALL (VerifyMessage);
		IN_ULONG (session);
		IN_BYTE_ARRAY (parameter, parameter_len);
		IN_BYTE_ARRAY (data, data_len);
		IN_BYTE_ARRAY (signature, signature_len);
	PROCESS_CALL ((self, session, (void *)parameter, parameter_len, data, data_len,
	               signature, signature_len));
	END_CALL;
}

static CK_RV
rpc_C_VerifyMessageBegin (CK_X_FUNCTION_LIST *self,
                          p11_rpc_message *msg)
{
	CK_SESSION_HANDLE session;
	CK_BYTE_PTR parameter;
	CK_ULONG parameter_len;

	BEGIN_CALL (VerifyMessageBegin);
		IN_ULONG (session);
		IN_BYTE_ARRAY (parameter, parameter_len);
	PROCESS_CALL ((self, session, (void *)parameter, parameter_len));
	END_CALL;
}

static CK_RV
rpc_C_VerifyMessageNext (CK_X_FUNCTION_LIST *self,
                         p11_rpc_message *msg)
{
	CK_SESSION_HANDLE session;
	CK_BYTE_PTR parameter;
	CK_ULONG parameter_len;
	CK_BYTE_PTR data;
	CK_ULONG data_len;
	CK_BYTE_PTR signature;
	CK_ULONG signature_len;

	BEGIN_CALL (VerifyMessageNext);
		IN_ULONG (session);
		IN_BYTE_ARRAY (parameter, parameter_len);
		IN_BYTE_ARRAY (data, data_len);
		IN_BYTE_ARRAY (signature, signature_len);
	PROCESS_CALL ((self, session, (void *)parameter, parameter_len, data, data_len, signature, signature_len));
	END_CALL;
}

static CK_RV
rpc_C_MessageVerifyFinal (CK_X_FUNCTION_LIST *self,
                          p11_rpc_message *msg)
{
	CK_SESSION_HANDLE session;

	BEGIN_CALL (MessageVerifyFinal);
		IN_ULONG (session);
	PROCESS_CALL ((self, session));
	END_CALL;
}

bool
p11_rpc_server_handle (CK_X_FUNCTION_LIST *self,
                       p11_buffer *request,
                       p11_buffer *response)
{
	p11_rpc_message msg;
	CK_RV ret;
	int req_id;

	return_val_if_fail (self != NULL, false);
	return_val_if_fail (request != NULL, false);
	return_val_if_fail (response != NULL, false);

	p11_message_clear ();

	p11_rpc_message_init (&msg, request, response);

	if (!p11_rpc_message_parse (&msg, P11_RPC_REQUEST)) {
		p11_rpc_message_clear (&msg);
		p11_message (_("couldn't parse pkcs11 rpc message"));
		return false;
	}

	/* This should have been checked by the parsing code */
	assert (msg.call_id > P11_RPC_CALL_ERROR);
	assert (msg.call_id < P11_RPC_CALL_MAX);
	req_id = msg.call_id;

	switch(req_id) {
	#define CASE_CALL(name) \
	case P11_RPC_CALL_##name: \
		ret = rpc_##name (self, &msg); \
		break;
	CASE_CALL (C_Initialize)
	CASE_CALL (C_Finalize)
	CASE_CALL (C_GetInfo)
	CASE_CALL (C_GetSlotList)
	CASE_CALL (C_GetSlotInfo)
	CASE_CALL (C_GetTokenInfo)
	CASE_CALL (C_GetMechanismList)
	CASE_CALL (C_GetMechanismInfo)
	CASE_CALL (C_InitToken)
	CASE_CALL (C_OpenSession)
	CASE_CALL (C_CloseSession)
	CASE_CALL (C_CloseAllSessions)
	CASE_CALL (C_GetSessionInfo)
	CASE_CALL (C_InitPIN)
	CASE_CALL (C_SetPIN)
	CASE_CALL (C_GetOperationState)
	CASE_CALL (C_SetOperationState)
	CASE_CALL (C_Login)
	CASE_CALL (C_Logout)
	CASE_CALL (C_CreateObject)
	CASE_CALL (C_CopyObject)
	CASE_CALL (C_DestroyObject)
	CASE_CALL (C_GetObjectSize)
	CASE_CALL (C_GetAttributeValue)
	CASE_CALL (C_SetAttributeValue)
	CASE_CALL (C_FindObjectsInit)
	CASE_CALL (C_FindObjects)
	CASE_CALL (C_FindObjectsFinal)
	CASE_CALL (C_EncryptInit)
	CASE_CALL (C_Encrypt)
	CASE_CALL (C_EncryptUpdate)
	CASE_CALL (C_EncryptFinal)
	CASE_CALL (C_DecryptInit)
	CASE_CALL (C_Decrypt)
	CASE_CALL (C_DecryptUpdate)
	CASE_CALL (C_DecryptFinal)
	CASE_CALL (C_DigestInit)
	CASE_CALL (C_Digest)
	CASE_CALL (C_DigestUpdate)
	CASE_CALL (C_DigestKey)
	CASE_CALL (C_DigestFinal)
	CASE_CALL (C_SignInit)
	CASE_CALL (C_Sign)
	CASE_CALL (C_SignUpdate)
	CASE_CALL (C_SignFinal)
	CASE_CALL (C_SignRecoverInit)
	CASE_CALL (C_SignRecover)
	CASE_CALL (C_VerifyInit)
	CASE_CALL (C_Verify)
	CASE_CALL (C_VerifyUpdate)
	CASE_CALL (C_VerifyFinal)
	CASE_CALL (C_VerifyRecoverInit)
	CASE_CALL (C_VerifyRecover)
	CASE_CALL (C_DigestEncryptUpdate)
	CASE_CALL (C_DecryptDigestUpdate)
	CASE_CALL (C_SignEncryptUpdate)
	CASE_CALL (C_DecryptVerifyUpdate)
	CASE_CALL (C_GenerateKey)
	CASE_CALL (C_GenerateKeyPair)
	CASE_CALL (C_WrapKey)
	CASE_CALL (C_UnwrapKey)
	CASE_CALL (C_DeriveKey)
	CASE_CALL (C_SeedRandom)
	CASE_CALL (C_GenerateRandom)
	CASE_CALL (C_WaitForSlotEvent)
	/* PKCS #11 3.0 */
	CASE_CALL (C_LoginUser)
	CASE_CALL (C_SessionCancel)
	CASE_CALL (C_MessageEncryptInit)
	CASE_CALL (C_EncryptMessage)
	CASE_CALL (C_EncryptMessageBegin)
	CASE_CALL (C_EncryptMessageNext)
	CASE_CALL (C_MessageEncryptFinal)
	CASE_CALL (C_MessageDecryptInit)
	CASE_CALL (C_DecryptMessage)
	CASE_CALL (C_DecryptMessageBegin)
	CASE_CALL (C_DecryptMessageNext)
	CASE_CALL (C_MessageDecryptFinal)
	CASE_CALL (C_MessageSignInit)
	CASE_CALL (C_SignMessage)
	CASE_CALL (C_SignMessageBegin)
	CASE_CALL (C_SignMessageNext)
	CASE_CALL (C_MessageSignFinal)
	CASE_CALL (C_MessageVerifyInit)
	CASE_CALL (C_VerifyMessage)
	CASE_CALL (C_VerifyMessageBegin)
	CASE_CALL (C_VerifyMessageNext)
	CASE_CALL (C_MessageVerifyFinal)
	#undef CASE_CALL
	default:
		/* This should have been caught by the parse code */
		assert (0 && "Unchecked call");
		break;
	};

	if (p11_buffer_failed (msg.output)) {
		p11_message (_("out of memory error putting together message"));
		p11_rpc_message_clear (&msg);
		return false;
	}

	/* A filled in response */
	if (ret == CKR_OK) {

		/*
		 * Since we're dealing with many many functions above generating
		 * these messages we want to make sure each of them actually
		 * does what it's supposed to.
		 */
		assert (p11_rpc_message_is_verified (&msg));
		assert (msg.call_type == P11_RPC_RESPONSE);
		assert (msg.call_id == req_id);
		assert (p11_rpc_calls[msg.call_id].response);
		assert (strcmp (p11_rpc_calls[msg.call_id].response, msg.signature) == 0);

	/* Fill in an error respnose */
	} else {
		if (!p11_rpc_message_prep (&msg, P11_RPC_CALL_ERROR, P11_RPC_RESPONSE) ||
		    !p11_rpc_message_write_ulong (&msg, (uint32_t)ret) ||
		    p11_buffer_failed (msg.output)) {
			p11_message (_("out of memory responding with error"));
			p11_rpc_message_clear (&msg);
			return false;
		}
	}

	p11_rpc_message_clear (&msg);
	return true;
}

/**
 * p11_kit_remote_serve_module:
 * @module: a pointer to a loaded module
 * @in_fd: input fd
 * @out_fd: output fd
 *
 * Run a module on a given pair of input/output FDs.
 *
 * Returns: 0 if success, non-zero otherwise.
 */
int
p11_kit_remote_serve_module (CK_FUNCTION_LIST *module,
                             int in_fd,
                             int out_fd)
{
	p11_rpc_status status;
	rpc_server server;
	p11_buffer options;
	p11_buffer buffer;
	size_t state;
	int ret = 1;
	int code;

	return_val_if_fail (module != NULL, 1);

	p11_buffer_init (&options, 0);
	p11_buffer_init (&buffer, 0);

	p11_virtual_init (&server.virt, &p11_virtual_base, module, NULL);

	switch (read (in_fd, &server.version, 1)) {
	case 0:
		goto out;
	case 1:
#if P11_RPC_PROTOCOL_VERSION_MINIMUM > 0
		if (server.version < P11_RPC_PROTOCOL_VERSION_MINIMUM) {
			p11_message (_("unsupported version received: %d"), (int)version);
			goto out;
		}
#endif
		break;
	default:
		p11_message_err (errno, _("couldn't read credential byte"));
		goto out;
	}

	if (server.version > P11_RPC_PROTOCOL_VERSION_MAXIMUM) {
		server.version = P11_RPC_PROTOCOL_VERSION_MAXIMUM;
	}

	switch (write (out_fd, &server.version, 1)) {
	case 1:
		break;
	default:
		p11_message_err (errno, _("couldn't write credential byte"));
		goto out;
	}

	status = P11_RPC_OK;
	while (status == P11_RPC_OK) {
		state = 0;
		code = 0;

		do {
			status = p11_rpc_transport_read (in_fd, &state, &code,
			                                 &options, &buffer);
		} while (status == P11_RPC_AGAIN);

		switch (status) {
		case P11_RPC_OK:
			break;
		case P11_RPC_EOF:
			ret = 0;
			continue;
		case P11_RPC_AGAIN:
			assert_not_reached ();
		case P11_RPC_ERROR:
			p11_message_err (errno, _("failed to read rpc message"));
			goto out;
		}

		if (!p11_rpc_server_handle (&server.virt.funcs, &buffer, &buffer)) {
			p11_message (_("unexpected error handling rpc message"));
			goto out;
		}

		state = 0;
		options.len = 0;
		do {
			status = p11_rpc_transport_write (out_fd, &state, code,
			                                  &options, &buffer);
		} while (status == P11_RPC_AGAIN);

		switch (status) {
		case P11_RPC_OK:
			break;
		case P11_RPC_EOF:
		case P11_RPC_AGAIN:
			assert_not_reached ();
		case P11_RPC_ERROR:
			p11_message_err (errno, _("failed to write rpc message"));
			goto out;
		}
	}

out:
	p11_buffer_uninit (&buffer);
	p11_buffer_uninit (&options);

	p11_virtual_uninit (&server.virt);

	return ret;
}

/**
 * p11_kit_remote_serve_token:
 * @module: a pointer to a loaded module
 * @token: a token info
 * @in_fd: input fd
 * @out_fd: output fd
 *
 * Run a token wrapped in a module on a given pair of input/output FDs.
 *
 * Returns: 0 if success, non-zero otherwise.
 *
 * Deprecated: use p11_kit_remote_serve_tokens()
 */
int
p11_kit_remote_serve_token (CK_FUNCTION_LIST *module,
			    CK_TOKEN_INFO *token,
			    int in_fd,
			    int out_fd)
{
	p11_virtual virt;
	p11_virtual *filter = NULL;
	CK_FUNCTION_LIST *filtered = NULL;
	int ret = 1;

	return_val_if_fail (module != NULL, 1);
	return_val_if_fail (token != NULL, 1);

	p11_virtual_init (&virt, &p11_virtual_base, module, NULL);
	filter = p11_filter_subclass (&virt, NULL);
	if (filter == NULL)
		goto out;

	filtered = p11_virtual_wrap (filter, (p11_destroyer)p11_virtual_uninit);
	if (filtered == NULL)
		goto out;

	p11_filter_allow_token (filter, token);

	ret = p11_kit_remote_serve_module (filtered, in_fd, out_fd);

 out:
	if (filtered != NULL)
		p11_virtual_unwrap (filtered);
	if (filter != NULL)
		p11_filter_release (filter);

	return ret;
}

static void
token_set_write_protected (CK_TOKEN_INFO *token, P11KitUri *uri)
{
	const char *write_protected =
		p11_kit_uri_get_vendor_query (uri, "write-protected");
	if (write_protected &&
	    _p11_conf_parse_boolean (write_protected, false))
		token->flags |= CKF_WRITE_PROTECTED;
	else
		token->flags &= ~CKF_WRITE_PROTECTED;
}

static void
module_unwrap (CK_FUNCTION_LIST *module)
{
	if (module)
		p11_virtual_unwrap (module);
}

/**
 * p11_kit_remote_serve_tokens:
 * @tokens: a list of token URIs
 * @n_tokens: the length of @tokens
 * @provider: (nullable): a PKCS\#11 module that provides the tokens
 * @in_fd: input fd
 * @out_fd: output fd
 *
 * Expose tokens on a given pair of input/output FDs.  If @provider is
 * not NULL, all the tokens must be provided by the same module.
 *
 * Returns: 0 if success, non-zero otherwise.
 */
int
p11_kit_remote_serve_tokens (const char **tokens,
			     size_t n_tokens,
			     CK_FUNCTION_LIST *provider,
			     int in_fd,
			     int out_fd)
{
	p11_virtual *lower = NULL;
	p11_virtual *filter = NULL;
	CK_FUNCTION_LIST *proxy = NULL;
	CK_FUNCTION_LIST **modules = NULL;
	CK_FUNCTION_LIST *provider_modules[2] = { NULL, NULL };
	CK_FUNCTION_LIST *module;
	p11_dict *filters = NULL;
	p11_dictiter filters_iter;
	p11_array *filtered = NULL;
	P11KitIter *iter;
	P11KitUri **uris = NULL;
	void *value;
	int ret = 1;
	int error = 0;
	size_t i;

	return_val_if_fail (tokens != NULL, 2);
	return_val_if_fail (n_tokens > 0, 2);
	return_val_if_fail (in_fd >= 0, 2);
	return_val_if_fail (out_fd >= 0, 2);

	uris = calloc (n_tokens, sizeof (P11KitUri *));
	if (uris == NULL) {
		error = ENOMEM;
		goto out;
	}

	for (i = 0; i < n_tokens; i++) {
		uris[i] = p11_kit_uri_new ();
		if (uris[i] == NULL) {
			error = ENOMEM;
			goto out;
		}
		if (p11_kit_uri_parse (tokens[i], P11_KIT_URI_FOR_TOKEN, uris[i]) !=
		    P11_KIT_URI_OK) {
			error = EINVAL;
			goto out;
		}
	}

	if (provider) {
		if (p11_kit_module_initialize (provider) != CKR_OK) {
			error = EINVAL;
			goto out;
		}
		provider_modules[0] = provider;
		modules = provider_modules;
	} else {
		modules = p11_kit_modules_load_and_initialize (0);
		if (modules == NULL) {
			error = EINVAL;
			goto out;
		}
	}

	filters = p11_dict_new (p11_dict_direct_hash, p11_dict_direct_equal,
				NULL, p11_filter_release);
	if (filters == NULL) {
		error = ENOMEM;
		goto out;
	}

	iter = p11_kit_iter_new (NULL,
				 P11_KIT_ITER_WITH_TOKENS |
				 P11_KIT_ITER_WITHOUT_OBJECTS);
	if (iter == NULL) {
		error = ENOMEM;
		goto out;
	}

	p11_kit_iter_begin (iter, modules);
	while (p11_kit_iter_next (iter) == CKR_OK) {
		CK_TOKEN_INFO *token;

		assert (p11_kit_iter_get_kind (iter) == P11_KIT_ITER_KIND_TOKEN);

		token = p11_kit_iter_get_token (iter);

		/* Check if the token is the one we want to export */
		for (i = 0; i < n_tokens; i++)
			if (p11_kit_uri_match_token_info (uris[i], token))
				break;
		if (i == n_tokens)
			continue;

		module = p11_kit_iter_get_module (iter);
		assert (module != NULL);

		/* Create a virtual module that provides only the
		 * specified tokens */
		filter = p11_dict_get (filters, module);
		if (filter == NULL) {
			lower = calloc (1, sizeof (p11_virtual));
			if (lower == NULL) {
				error = ENOMEM;
				goto out;
			}
			p11_virtual_init (lower, &p11_virtual_base, module, NULL);
			filter = p11_filter_subclass (lower, NULL);
			if (filter == NULL) {
				error = EINVAL;
				p11_message_err (error, "couldn't subclass filter");
				goto out;
			}
			if (!p11_dict_set (filters, module, filter)) {
				error = EINVAL;
				p11_message_err (error, "couldn't register filter");
				goto out;
			}
		}

		for (i = 0; i < n_tokens; i++) {
			if (p11_kit_uri_match_token_info (uris[i], token)) {
				token_set_write_protected (token, uris[i]);
				p11_filter_allow_token (filter, token);
			}
		}
	}
	p11_kit_iter_free (iter);

	filtered = p11_array_new ((p11_destroyer)module_unwrap);
	p11_dict_iterate (filters, &filters_iter);
	while (p11_dict_next (&filters_iter, NULL, &value)) {
		module = p11_virtual_wrap ((p11_virtual *)value,
					   (p11_destroyer)p11_virtual_uninit);
		if (module == NULL) {
			error = EINVAL;
			p11_message_err (error, "couldn't wrap filter module");
			goto out;
		}
		if (!p11_array_push (filtered, module)) {
			error = ENOMEM;
			goto out;
		}
	}

	/* NULL terminate the array */
	if (!p11_array_push (filtered, NULL)) {
		error = ENOMEM;
		goto out;
	}

	/* Need to finalize the modules that we initialized for iteration */
	p11_kit_modules_finalize (modules);

	if (p11_proxy_module_create (&proxy, (CK_FUNCTION_LIST **)filtered->elem)
	    != CKR_OK) {
		error = EINVAL;
		p11_message_err (error, "couldn't create a proxy module");
		goto out;
	}

	ret = p11_kit_remote_serve_module (proxy, in_fd, out_fd);

 out:
	if (filtered != NULL)
		p11_array_free (filtered);
	if (filters != NULL)
		p11_dict_free (filters);
	if (modules != provider_modules)
		p11_kit_modules_release (modules);
	if (error != 0)
		errno = error;
	if (uris) {
		for (i = 0; i < n_tokens; i++)
			p11_kit_uri_free (uris[i]);
		free (uris);
	}

	return ret;
}
