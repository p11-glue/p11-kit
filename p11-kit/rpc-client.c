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
#define P11_DEBUG_FLAG P11_DEBUG_RPC
#include "debug.h"
#include "pkcs11.h"
#include "pkcs11x.h"
#include "library.h"
#include "message.h"
#include "private.h"
#include "rpc.h"
#include "rpc-message.h"
#include "virtual.h"

#include <assert.h>
#include <string.h>
#include <unistd.h>

#ifdef ENABLE_NLS
#include <libintl.h>
#define _(x) dgettext(PACKAGE_NAME, x)
#else
#define _(x) (x)
#endif

/* The error used by us when parsing of rpc message fails */
#define PARSE_ERROR   CKR_DEVICE_ERROR

typedef struct {
	p11_mutex_t mutex;
	p11_rpc_client_vtable *vtable;
	unsigned int initialized_forkid;
	bool initialize_done;
	uint8_t version;
} rpc_client;

/* Allocator for call session buffers */
static void *
log_allocator (void *pointer,
               size_t size)
{
	void *result = realloc (pointer, (size_t)size);
	return_val_if_fail (!size || result != NULL, NULL);
	return result;
}

static CK_RV
call_prepare (rpc_client *module,
              p11_rpc_message *msg,
              int call_id)
{
	p11_buffer *buffer;

	assert (module != NULL);
	assert (msg != NULL);

	if (module->initialized_forkid != p11_forkid)
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	if (!module->initialize_done)
		return CKR_DEVICE_REMOVED;

	buffer = p11_rpc_buffer_new_full (64, log_allocator, free);
	return_val_if_fail (buffer != NULL, CKR_GENERAL_ERROR);

	/* We use the same buffer for reading and writing */
	p11_rpc_message_init (msg, buffer, buffer);

	/* Put in the Call ID and signature */
	if (!p11_rpc_message_prep (msg, call_id, P11_RPC_REQUEST))
		return_val_if_reached (CKR_HOST_MEMORY);

	p11_debug ("prepared call: %d", call_id);
	return CKR_OK;
}

static CK_RV
call_run (rpc_client *module,
          p11_rpc_message *msg)
{
	CK_RV ret = CKR_OK;
	CK_ULONG ckerr;

	int call_id;

	assert (module != NULL);
	assert (msg != NULL);

	/* Did building the call fail? */
	if (p11_buffer_failed (msg->output))
		return_val_if_reached (CKR_HOST_MEMORY);

	/* Make sure that the signature is valid */
	assert (p11_rpc_message_is_verified (msg));
	call_id = msg->call_id;

	/* Do the transport send and receive */
	assert (module->vtable->transport != NULL);
	ret = (module->vtable->transport) (module->vtable,
	                                   msg->output,
	                                   msg->input);

	if (ret != CKR_OK)
		return ret;

	if (!p11_rpc_message_parse (msg, P11_RPC_RESPONSE))
		return CKR_DEVICE_ERROR;

	/* If it's an error code then return it */
	if (msg->call_id == P11_RPC_CALL_ERROR) {
		if (!p11_rpc_message_read_ulong (msg, &ckerr)) {
			p11_message (_("invalid rpc error response: too short"));
			return CKR_DEVICE_ERROR;
		}

		if (ckerr <= CKR_OK) {
			p11_message (_("invalid rpc error response: bad error code"));
			return CKR_DEVICE_ERROR;
		}

		/* An error code from the other side */
		return (CK_RV)ckerr;
	}

	/* Make sure other side answered the right call */
	if (call_id != msg->call_id) {
		p11_message (_("invalid rpc response: call mismatch"));
		return CKR_DEVICE_ERROR;
	}

	assert (!p11_buffer_failed (msg->input));

	p11_debug ("parsing response values");
	return CKR_OK;
}

static CK_RV
call_done (rpc_client *module,
           p11_rpc_message *msg,
           CK_RV ret)
{
	assert (module != NULL);
	assert (msg != NULL);

	/* Check for parsing errors that were not caught elsewhere */
	if (ret == CKR_OK) {
		if (p11_buffer_failed (msg->input)) {
			p11_message (_("invalid rpc response: bad argument data"));
			ret = CKR_GENERAL_ERROR;
		} else {
			/* Double check that the signature matched our decoding */
			assert (p11_rpc_message_is_verified (msg));
		}
	}

	/* We used the same buffer for input/output, so this frees both */
	assert (msg->input == msg->output);
	p11_rpc_buffer_free (msg->input);

	p11_rpc_message_clear (msg);

	return ret;
}

/* -----------------------------------------------------------------------------
 * MODULE SPECIFIC PROTOCOL CODE
 */

static CK_RV
proto_read_attribute_array (p11_rpc_message *msg,
                            CK_ATTRIBUTE_PTR arr,
                            CK_ULONG len)
{
	uint32_t i, num;
	CK_RV ret;

	assert (len != 0);
	assert (msg != NULL);
	assert (msg->input != NULL);

	/* Make sure this is in the right order */
	assert (!msg->signature || p11_rpc_message_verify_part (msg, "aA"));

	/* Get the number of items. We need this value to be correct */
	if (!p11_rpc_buffer_get_uint32 (msg->input, &msg->parsed, &num))
		return PARSE_ERROR;

	/*
	 * This should never happen in normal operation. It denotes a goof up
	 * on the other side of our RPC. We should be indicating the exact number
	 * of attributes to the other side. And it should respond with the same
	 * number.
	 */
	if (len != num) {
		p11_message (_("received an attribute array with wrong number of attributes"));
		return PARSE_ERROR;
	}

	ret = CKR_OK;

	/* We need to go ahead and read everything in all cases */
	for (i = 0; i < num; ++i) {
		size_t offset = msg->parsed;
		CK_ATTRIBUTE temp;

		memset (&temp, 0, sizeof (temp));
		if (!p11_rpc_buffer_get_attribute (msg->input, &offset, &temp)) {
			msg->parsed = offset;
			return PARSE_ERROR;
		}

		if (IS_ATTRIBUTE_ARRAY (&temp)) {
			p11_debug("recursive attribute array is not supported");
			return PARSE_ERROR;
		}

		/* Try and stuff it in the output data */
		if (arr) {
			CK_ATTRIBUTE *attr = &(arr[i]);

			if (temp.type != attr->type) {
				p11_message (_("returned attributes in invalid order"));
				msg->parsed = offset;
				return PARSE_ERROR;
			}

			if (temp.ulValueLen != ((CK_ULONG)-1)) {
				/* Just requesting the attribute size */
				if (!attr->pValue) {
					attr->ulValueLen = temp.ulValueLen;

				/* Wants attribute data, but too small */
				} else if (attr->ulValueLen < temp.ulValueLen) {
					attr->ulValueLen = temp.ulValueLen;
					ret = CKR_BUFFER_TOO_SMALL;

				/* Wants attribute data, enough space */
				} else {
					size_t offset2 = msg->parsed;
					if (!p11_rpc_buffer_get_attribute (msg->input, &offset2, attr)) {
						msg->parsed = offset2;
						return PARSE_ERROR;
					}
				}
			} else {
				attr->ulValueLen = temp.ulValueLen;
			}
		}

		msg->parsed = offset;
	}

	if (p11_buffer_failed (msg->input))
		return PARSE_ERROR;

	/* Read in the code that goes along with these attributes */
	if (!p11_rpc_message_read_ulong (msg, &ret))
		return PARSE_ERROR;

	return ret;
}

static CK_RV
proto_read_byte_array (p11_rpc_message *msg,
                       CK_BYTE_PTR arr,
                       CK_ULONG_PTR len,
                       CK_ULONG max)
{
	const unsigned char *val;
	unsigned char valid;
	uint32_t length;
	size_t vlen;

	assert (msg != NULL);
	assert (msg->input != NULL);

	/* Make sure this is in the right order */
	assert (!msg->signature || p11_rpc_message_verify_part (msg, "ay"));

	/* A single byte which determines whether valid or not */
	if (!p11_rpc_buffer_get_byte (msg->input, &msg->parsed, &valid))
		return PARSE_ERROR;

	/* If not valid, then just the length is encoded, this can signify CKR_BUFFER_TOO_SMALL */
	if (!valid) {
		if (!p11_rpc_buffer_get_uint32 (msg->input, &msg->parsed, &length))
			return PARSE_ERROR;

		if (len != NULL)
			*len = length;

		if (arr)
			return CKR_BUFFER_TOO_SMALL;
		else
			return CKR_OK;
	}

	/* Get the actual bytes */
	if (!p11_rpc_buffer_get_byte_array (msg->input, &msg->parsed, &val, &vlen))
		return PARSE_ERROR;

	if (len != NULL)
		*len = vlen;

	/* Just asking us for size */
	if (!arr)
		return CKR_OK;

	if (max < vlen)
		return CKR_BUFFER_TOO_SMALL;

	/* Enough space, yay */
	memcpy (arr, val, vlen);
	return CKR_OK;
}

static CK_RV
proto_read_ulong_array (p11_rpc_message *msg, CK_ULONG_PTR arr,
                        CK_ULONG_PTR len, CK_ULONG max)
{
	uint32_t i, num;
	uint64_t val;
	unsigned char valid;

	assert (len != NULL);
	assert (msg != NULL);
	assert (msg->input != NULL);

	/* Make sure this is in the right order */
	assert (!msg->signature || p11_rpc_message_verify_part (msg, "au"));

	/* A single byte which determines whether valid or not */
	if (!p11_rpc_buffer_get_byte (msg->input, &msg->parsed, &valid))
		return PARSE_ERROR;

	/* Get the number of items. */
	if (!p11_rpc_buffer_get_uint32 (msg->input, &msg->parsed, &num))
		return PARSE_ERROR;

	*len = num;

	/* If not valid, then just the length is encoded, this can signify CKR_BUFFER_TOO_SMALL */
	if (!valid) {
		if (arr)
			return CKR_BUFFER_TOO_SMALL;
		else
			return CKR_OK;
	}

	if (max < num)
		return CKR_BUFFER_TOO_SMALL;

	/* We need to go ahead and read everything in all cases */
	for (i = 0; i < num; ++i) {
		if (!p11_rpc_buffer_get_uint64 (msg->input, &msg->parsed, &val))
			return PARSE_ERROR;
		if (arr)
			arr[i] = (CK_ULONG)val;
	}

	return p11_buffer_failed (msg->input) ? PARSE_ERROR : CKR_OK;
}

static void
mechanism_list_purge (CK_MECHANISM_TYPE_PTR mechs,
                      CK_ULONG *n_mechs)
{
	CK_ULONG i;

	assert (mechs != NULL);
	assert (n_mechs != NULL);

	/* Trim unsupported mechanisms at the end */
	for (; *n_mechs > 0 && !p11_rpc_mechanism_is_supported (mechs[*n_mechs - 1]); --*n_mechs)
		;

	for (i = 0; i < *n_mechs; ++i) {
		if (!p11_rpc_mechanism_is_supported (mechs[i])) {
			/* Remove the mechanism from the list */
			memmove (&mechs[i], &mechs[i + 1],
				 (*n_mechs - (i + 1)) * sizeof (CK_MECHANISM_TYPE));

			--(*n_mechs);
			--i;
		}
	}
}

static CK_RV
proto_write_mechanism (p11_rpc_message *msg,
                       CK_MECHANISM_PTR mech)
{
	assert (msg != NULL);
	assert (msg->output != NULL);

	/* Make sure this is in the right order */
	assert (!msg->signature || p11_rpc_message_verify_part (msg, "M"));

	/* This case is valid for C_*Init () functions to cancel operation */
	if (mech == NULL) {
		p11_rpc_buffer_add_uint32 (msg->output, 0);
		return p11_buffer_failed (msg->output) ? CKR_HOST_MEMORY : CKR_OK;
	}

	if (!p11_rpc_mechanism_is_supported (mech->mechanism))
		return CKR_MECHANISM_INVALID;

	/*
	 * PKCS#11 mechanism parameters are not easy to serialize. They're
	 * completely different for so many mechanisms, they contain
	 * pointers to arbitrary memory, and many callers don't initialize
	 * them completely or properly.
	 *
	 * We only support certain mechanisms.
	 *
	 * Also callers do yucky things like leaving parts of the structure
	 * pointing to garbage if they don't think it's going to be used.
	 */

	p11_rpc_buffer_add_mechanism (msg->output, mech);

	return p11_buffer_failed (msg->output) ? CKR_HOST_MEMORY : CKR_OK;
}

static CK_RV
proto_read_info (p11_rpc_message *msg,
                 CK_INFO_PTR info)
{
	assert (msg != NULL);
	assert (info != NULL);

	if (!p11_rpc_message_read_version (msg, &info->cryptokiVersion) ||
	    !p11_rpc_message_read_space_string (msg, info->manufacturerID, 32) ||
	    !p11_rpc_message_read_ulong (msg, &info->flags) ||
	    !p11_rpc_message_read_space_string (msg, info->libraryDescription, 32) ||
	    !p11_rpc_message_read_version (msg, &info->libraryVersion))
		return PARSE_ERROR;

	return CKR_OK;
}

static CK_RV
proto_read_slot_info (p11_rpc_message *msg,
                      CK_SLOT_INFO_PTR info)
{
	assert (msg != NULL);
	assert (info != NULL);

	if (!p11_rpc_message_read_space_string (msg, info->slotDescription, 64) ||
	    !p11_rpc_message_read_space_string (msg, info->manufacturerID, 32) ||
	    !p11_rpc_message_read_ulong (msg, &info->flags) ||
	    !p11_rpc_message_read_version (msg, &info->hardwareVersion) ||
	    !p11_rpc_message_read_version (msg, &info->firmwareVersion))
		return PARSE_ERROR;

	return CKR_OK;
}

static CK_RV
proto_read_token_info (p11_rpc_message *msg,
                       CK_TOKEN_INFO_PTR info)
{
	assert (msg != NULL);
	assert (info != NULL);

	if (!p11_rpc_message_read_space_string (msg, info->label, 32) ||
	    !p11_rpc_message_read_space_string (msg, info->manufacturerID, 32) ||
	    !p11_rpc_message_read_space_string (msg, info->model, 16) ||
	    !p11_rpc_message_read_space_string (msg, info->serialNumber, 16) ||
	    !p11_rpc_message_read_ulong (msg, &info->flags) ||
	    !p11_rpc_message_read_ulong (msg, &info->ulMaxSessionCount) ||
	    !p11_rpc_message_read_ulong (msg, &info->ulSessionCount) ||
	    !p11_rpc_message_read_ulong (msg, &info->ulMaxRwSessionCount) ||
	    !p11_rpc_message_read_ulong (msg, &info->ulRwSessionCount) ||
	    !p11_rpc_message_read_ulong (msg, &info->ulMaxPinLen) ||
	    !p11_rpc_message_read_ulong (msg, &info->ulMinPinLen) ||
	    !p11_rpc_message_read_ulong (msg, &info->ulTotalPublicMemory) ||
	    !p11_rpc_message_read_ulong (msg, &info->ulFreePublicMemory) ||
	    !p11_rpc_message_read_ulong (msg, &info->ulTotalPrivateMemory) ||
	    !p11_rpc_message_read_ulong (msg, &info->ulFreePrivateMemory) ||
	    !p11_rpc_message_read_version (msg, &info->hardwareVersion) ||
	    !p11_rpc_message_read_version (msg, &info->firmwareVersion) ||
	    !p11_rpc_message_read_space_string (msg, info->utcTime, 16))
		return PARSE_ERROR;

	return CKR_OK;
}

static CK_RV
proto_read_mechanism_info (p11_rpc_message *msg,
                           CK_MECHANISM_INFO_PTR info)
{
	assert (msg != NULL);
	assert (info != NULL);

	if (!p11_rpc_message_read_ulong (msg, &info->ulMinKeySize) ||
	    !p11_rpc_message_read_ulong (msg, &info->ulMaxKeySize) ||
	    !p11_rpc_message_read_ulong (msg, &info->flags))
		return PARSE_ERROR;

	return CKR_OK;
}

static CK_RV
proto_read_sesssion_info (p11_rpc_message *msg,
                          CK_SESSION_INFO_PTR info)
{
	assert (msg != NULL);
	assert (info != NULL);

	if (!p11_rpc_message_read_ulong (msg, &info->slotID) ||
	    !p11_rpc_message_read_ulong (msg, &info->state) ||
	    !p11_rpc_message_read_ulong (msg, &info->flags) ||
	    !p11_rpc_message_read_ulong (msg, &info->ulDeviceError))
		return PARSE_ERROR;

	return CKR_OK;
}

/* -------------------------------------------------------------------
 * CALL MACROS
 */

#define BEGIN_CALL_OR(call_id, self, if_no_daemon) \
	p11_debug (#call_id ": enter"); \
	{ \
		rpc_client *_mod = ((p11_virtual *)self)->lower_module; p11_rpc_message _msg; \
		CK_RV _ret = call_prepare (_mod, &_msg, P11_RPC_CALL_##call_id); \
		if (_ret == CKR_DEVICE_REMOVED) return (if_no_daemon); \
		if (_ret != CKR_OK) return _ret;

#define PROCESS_CALL \
		_ret = call_run (_mod, &_msg); \
		if (_ret != CKR_OK) goto _cleanup;

#define RETURN(ret) \
		_ret = ret; \
		goto _cleanup;

#define END_CALL \
	_cleanup: \
		_ret = call_done (_mod, &_msg, _ret); \
		p11_debug ("ret: %lu", _ret); \
		return _ret; \
	}

#define IN_BYTE(val) \
	if (!p11_rpc_message_write_byte (&_msg, val)) \
		{ _ret = CKR_HOST_MEMORY; goto _cleanup; }

#define IN_ULONG(val) \
	if (!p11_rpc_message_write_ulong (&_msg, val)) \
		{ _ret = CKR_HOST_MEMORY; goto _cleanup; }

#define IN_STRING(val) \
	if (!p11_rpc_message_write_zero_string (&_msg, val)) \
		{ _ret = CKR_HOST_MEMORY; goto _cleanup; }

#define IN_BYTE_BUFFER(arr, len) \
	if (len == NULL) \
		{ _ret = CKR_ARGUMENTS_BAD; goto _cleanup; } \
	if (!p11_rpc_message_write_byte_buffer (&_msg, arr ? (*len > 0 ? *len : (uint32_t)-1) : 0)) \
		{ _ret = CKR_HOST_MEMORY; goto _cleanup; }

#define IN_BYTE_BUFFER_NULL(arr, len) \
	if (!p11_rpc_message_write_byte_buffer_null (&_msg, len)) \
		{ _ret = CKR_HOST_MEMORY; goto _cleanup; }

#define IN_BYTE_ARRAY(arr, len) \
	if (len != 0 && arr == NULL) \
		{ _ret = CKR_ARGUMENTS_BAD; goto _cleanup; } \
	if (!p11_rpc_message_write_byte_array (&_msg, arr, len)) \
		{ _ret = CKR_HOST_MEMORY; goto _cleanup; }

#define IN_ULONG_BUFFER(arr, len) \
	if (len == NULL) \
		{ _ret = CKR_ARGUMENTS_BAD; goto _cleanup; } \
	if (!p11_rpc_message_write_ulong_buffer (&_msg, arr ? *len : 0)) \
		{ _ret = CKR_HOST_MEMORY; goto _cleanup; }

#define IN_ULONG_ARRAY(arr, len) \
	if (len != 0 && arr == NULL) \
		{ _ret = CKR_ARGUMENTS_BAD; goto _cleanup; }\
	if (!p11_rpc_message_write_ulong_array (&_msg, arr, len)) \
		{ _ret = CKR_HOST_MEMORY; goto _cleanup; }

#define IN_ATTRIBUTE_BUFFER(arr, num) \
	if (num != 0 && arr == NULL) \
		{ _ret = CKR_ARGUMENTS_BAD; goto _cleanup; } \
	if (!p11_rpc_message_write_attribute_buffer (&_msg, (arr), (num))) \
		{ _ret = CKR_HOST_MEMORY; goto _cleanup; }

#define IN_ATTRIBUTE_ARRAY(arr, num) \
	if (num != 0 && arr == NULL) \
		{ _ret = CKR_ARGUMENTS_BAD; goto _cleanup; } \
	if (!p11_rpc_message_write_attribute_array (&_msg, (arr), (num))) \
		{ _ret = CKR_HOST_MEMORY; goto _cleanup; }

#define IN_MECHANISM_TYPE(val) \
	if(!p11_rpc_mechanism_is_supported (val)) \
		{ _ret = CKR_MECHANISM_INVALID; goto _cleanup; } \
	if (!p11_rpc_message_write_ulong (&_msg, val)) \
		{ _ret = CKR_HOST_MEMORY; goto _cleanup; }

#define IN_MECHANISM(val) \
	_ret = proto_write_mechanism (&_msg, val); \
	if (_ret != CKR_OK) goto _cleanup;



#define OUT_ULONG(val) \
	if (val == NULL) \
		_ret = CKR_ARGUMENTS_BAD; \
	if (_ret == CKR_OK && !p11_rpc_message_read_ulong (&_msg, val)) \
		_ret = PARSE_ERROR;

#define OUT_BYTE_ARRAY(arr, len)  \
	if (len == NULL) \
		_ret = CKR_ARGUMENTS_BAD; \
	if (_ret == CKR_OK) \
		_ret = proto_read_byte_array (&_msg, (arr), (len), *(len));

#define OUT_BYTE_ARRAY_NULL(arr, len)  \
	_ret = proto_read_byte_array (&_msg, (arr), (len), (len) ? *(len) : 0); \
	if (_ret != CKR_OK) goto _cleanup;

#define OUT_ULONG_ARRAY(a, len) \
	if (len == NULL) \
		_ret = CKR_ARGUMENTS_BAD; \
	if (_ret == CKR_OK) \
		_ret = proto_read_ulong_array (&_msg, (a), (len), *(len));

#define OUT_ATTRIBUTE_ARRAY(arr, num) \
	if (_ret == CKR_OK) \
		_ret = proto_read_attribute_array (&_msg, (arr), (num));

#define OUT_INFO(info) \
	if (info == NULL) \
		_ret = CKR_ARGUMENTS_BAD; \
	if (_ret == CKR_OK) \
		_ret = proto_read_info (&_msg, info);

#define OUT_SLOT_INFO(info) \
	if (info == NULL) \
		_ret = CKR_ARGUMENTS_BAD; \
	if (_ret == CKR_OK) \
		_ret = proto_read_slot_info (&_msg, info);

#define OUT_TOKEN_INFO(info) \
	if (info == NULL) \
		_ret = CKR_ARGUMENTS_BAD; \
	if (_ret == CKR_OK) \
		_ret = proto_read_token_info (&_msg, info);

#define OUT_SESSION_INFO(info) \
	if (info == NULL) \
		_ret = CKR_ARGUMENTS_BAD; \
	if (_ret == CKR_OK) \
		_ret = proto_read_sesssion_info (&_msg, info);

#define OUT_MECHANISM_TYPE_ARRAY(arr, len) \
	if (len == NULL) \
		_ret = CKR_ARGUMENTS_BAD; \
	if (_ret == CKR_OK) \
		_ret = proto_read_ulong_array (&_msg, (arr), (len), *(len)); \
	if (_ret == CKR_OK && arr) \
		mechanism_list_purge (arr, len);

#define OUT_MECHANISM_INFO(info) \
	if (info == NULL) \
		_ret = CKR_ARGUMENTS_BAD; \
	if (_ret == CKR_OK) \
		_ret = proto_read_mechanism_info (&_msg, info);


/* -------------------------------------------------------------------
 * INITIALIZATION and 'GLOBAL' CALLS
 */

static CK_RV
rpc_C_Initialize (CK_X_FUNCTION_LIST *self,
                  CK_VOID_PTR init_args)
{
	rpc_client *module = ((p11_virtual *)self)->lower_module;
	CK_C_INITIALIZE_ARGS_PTR args = NULL;
	void *reserved = NULL;
	CK_RV ret = CKR_OK;
	p11_rpc_message msg;

	assert (module != NULL);
	p11_debug ("C_Initialize: enter");

	if (init_args != NULL) {
		int supplied_ok;

		/*
		 * pReserved is either a string or NULL.  Other cases
		 * should be rejected by the caller of this function.
		 */
		args = init_args;

		/* ALL supplied function pointers need to have the value either NULL or non-NULL. */
		supplied_ok = (args->CreateMutex == NULL && args->DestroyMutex == NULL &&
		               args->LockMutex == NULL && args->UnlockMutex == NULL) ||
		              (args->CreateMutex != NULL && args->DestroyMutex != NULL &&
		               args->LockMutex != NULL && args->UnlockMutex != NULL);
		if (!supplied_ok) {
			p11_message (_("invalid set of mutex calls supplied"));
			return CKR_ARGUMENTS_BAD;
		}

		/*
		 * When the CKF_OS_LOCKING_OK flag isn't set return an error.
		 * We must be able to use our mutex functionality.
		 */
		if (!(args->flags & CKF_OS_LOCKING_OK)) {
			p11_message (_("can't do without os locking"));
			return CKR_CANT_LOCK;
		}

		if (args->pReserved)
			reserved = args->pReserved;
	}

	p11_mutex_lock (&module->mutex);

	if (module->initialized_forkid != 0) {
		/* This process has called C_Initialize already */
		if (p11_forkid == module->initialized_forkid) {
			p11_message (_("C_Initialize called twice for same process"));
			ret = CKR_CRYPTOKI_ALREADY_INITIALIZED;
			goto done;
		}
	}

	/* Call out to initialize client callback */
	assert (module->vtable->connect != NULL);
	ret = (module->vtable->connect) (module->vtable, reserved);

	if (ret == CKR_OK) {
		module->version = P11_RPC_PROTOCOL_VERSION_MAXIMUM;
		ret = (module->vtable->authenticate) (module->vtable,
						      &module->version);

#if P11_RPC_PROTOCOL_VERSION_MAXIMUM > 0
		/* If the server is too old to support version negotiation
		 * (i.e., not accepting version bytes other than 0), try to
		 * reconnect and reauthenticate with version 0 */
		if (ret != CKR_OK) {
			assert (module->vtable->disconnect != NULL);
			(module->vtable->disconnect) (module->vtable, reserved);
			ret = (module->vtable->connect) (module->vtable, reserved);

			module->version = 0;
			ret = (module->vtable->authenticate) (module->vtable,
							      &module->version);
		}
#endif
	}

	/* Successfully initialized */
	if (ret == CKR_OK) {
		module->initialized_forkid = p11_forkid;
		module->initialize_done = true;
		p11_debug ("authenticated with protocol version %u",
			   module->version);

	/* Server doesn't exist, initialize but don't call */
	} else if (ret == CKR_DEVICE_REMOVED) {
		module->initialized_forkid = p11_forkid;
		module->initialize_done = false;
		ret = CKR_OK;
		goto done;

	} else {
		goto done;
	}

	/* If we don't have read and write fds now, then initialize other side */
	ret = call_prepare (module, &msg, P11_RPC_CALL_C_Initialize);
	if (ret == CKR_OK)
		if (!p11_rpc_message_write_byte_array (&msg, P11_RPC_HANDSHAKE, P11_RPC_HANDSHAKE_LEN))
			ret = CKR_HOST_MEMORY;
	if (ret == CKR_OK) {
		if (!p11_rpc_message_write_byte (&msg, reserved != NULL))
			ret = CKR_HOST_MEMORY;
	}
	if (ret == CKR_OK) {
		char *reserved_string = "";
		if (reserved != NULL)
			reserved_string = (char *) reserved;
		if (!p11_rpc_message_write_byte_array (&msg, (CK_BYTE_PTR) reserved_string, strlen (reserved_string) + 1))
			ret = CKR_HOST_MEMORY;
	}
	if (ret == CKR_OK)
		ret = call_run (module, &msg);
	call_done (module, &msg, ret);

done:
	/* If failed then unmark initialized */
	if (ret != CKR_OK && ret != CKR_CRYPTOKI_ALREADY_INITIALIZED)
		module->initialized_forkid = 0;

	/* If we told our caller that we're initialized, but not really, then finalize */
	if (ret != CKR_OK && ret != CKR_CRYPTOKI_ALREADY_INITIALIZED && module->initialize_done) {
		module->initialize_done = false;
		assert (module->vtable->disconnect != NULL);
		(module->vtable->disconnect) (module->vtable, reserved);
	}

	p11_mutex_unlock (&module->mutex);

	p11_debug ("C_Initialize: %lu", ret);
	return ret;
}

static CK_RV
rpc_C_Finalize (CK_X_FUNCTION_LIST *self,
                CK_VOID_PTR reserved)
{
	rpc_client *module = ((p11_virtual *)self)->lower_module;
	CK_RV ret = CKR_OK;
	p11_rpc_message msg;

	p11_debug ("C_Finalize: enter");
	return_val_if_fail (module->initialized_forkid == p11_forkid, CKR_CRYPTOKI_NOT_INITIALIZED);
	return_val_if_fail (!reserved, CKR_ARGUMENTS_BAD);

	p11_mutex_lock (&module->mutex);

	if (module->initialize_done) {
		ret = call_prepare (module, &msg, P11_RPC_CALL_C_Finalize);
		if (ret == CKR_OK)
			ret = call_run (module, &msg);
		call_done (module, &msg, ret);
		if (ret != CKR_OK)
			p11_message (_("finalizing rpc module returned an error: %lu"), ret);

		module->initialize_done = false;
		assert (module->vtable->disconnect != NULL);
		(module->vtable->disconnect) (module->vtable, reserved);
	}

	module->initialized_forkid = 0;

	p11_mutex_unlock (&module->mutex);

	p11_debug ("C_Finalize: %lu", CKR_OK);
	return CKR_OK;
}

static CK_RV
fill_stand_in_info (CK_INFO_PTR info)
{
	static CK_INFO stand_in_info = {
		{ CRYPTOKI_VERSION_MAJOR, CRYPTOKI_VERSION_MINOR },
		"p11-kit                         ",
		0,
		"p11-kit (no connection)         ",
		{ 1, 1 },
	};
	memcpy (info, &stand_in_info, sizeof (CK_INFO));
	return CKR_OK;

}

static CK_RV
rpc_C_GetInfo (CK_X_FUNCTION_LIST *self,
               CK_INFO_PTR info)
{
	return_val_if_fail (info, CKR_ARGUMENTS_BAD);

	BEGIN_CALL_OR (C_GetInfo, self, fill_stand_in_info (info));
	PROCESS_CALL;
		OUT_INFO (info);
	END_CALL;
}

static CK_RV
rpc_C_GetSlotList (CK_X_FUNCTION_LIST *self,
                   CK_BBOOL token_present,
                   CK_SLOT_ID_PTR slot_list,
                   CK_ULONG_PTR count)
{
	return_val_if_fail (count, CKR_ARGUMENTS_BAD);

	BEGIN_CALL_OR (C_GetSlotList, self, (*count = 0, CKR_OK));
		IN_BYTE (token_present);
		IN_ULONG_BUFFER (slot_list, count);
	PROCESS_CALL;
		OUT_ULONG_ARRAY (slot_list, count);
	END_CALL;
}

static CK_RV
rpc_C_GetSlotInfo (CK_X_FUNCTION_LIST *self,
                   CK_SLOT_ID slot_id,
                   CK_SLOT_INFO_PTR info)
{
	return_val_if_fail (info, CKR_ARGUMENTS_BAD);

	BEGIN_CALL_OR (C_GetSlotInfo, self, CKR_SLOT_ID_INVALID);
		IN_ULONG (slot_id);
	PROCESS_CALL;
		OUT_SLOT_INFO (info);
	END_CALL;
}

static CK_RV
rpc_C_GetTokenInfo (CK_X_FUNCTION_LIST *self,
                    CK_SLOT_ID slot_id,
                    CK_TOKEN_INFO_PTR info)
{
	return_val_if_fail (info, CKR_ARGUMENTS_BAD);

	BEGIN_CALL_OR (C_GetTokenInfo, self, CKR_SLOT_ID_INVALID);
		IN_ULONG (slot_id);
	PROCESS_CALL;
		OUT_TOKEN_INFO (info);
	END_CALL;
}

static CK_RV
rpc_C_GetMechanismList (CK_X_FUNCTION_LIST *self,
                        CK_SLOT_ID slot_id,
                        CK_MECHANISM_TYPE_PTR mechanism_list,
                        CK_ULONG_PTR count)
{
	return_val_if_fail (count, CKR_ARGUMENTS_BAD);

	BEGIN_CALL_OR (C_GetMechanismList, self, CKR_SLOT_ID_INVALID);
		IN_ULONG (slot_id);
		IN_ULONG_BUFFER (mechanism_list, count);
	PROCESS_CALL;
		OUT_MECHANISM_TYPE_ARRAY (mechanism_list, count);
	END_CALL;
}

static CK_RV
rpc_C_GetMechanismInfo (CK_X_FUNCTION_LIST *self,
                        CK_SLOT_ID slot_id,
                        CK_MECHANISM_TYPE type,
                        CK_MECHANISM_INFO_PTR info)
{
	return_val_if_fail (info, CKR_ARGUMENTS_BAD);

	BEGIN_CALL_OR (C_GetMechanismInfo, self, CKR_SLOT_ID_INVALID);
		IN_ULONG (slot_id);
		IN_MECHANISM_TYPE (type);
	PROCESS_CALL;
		OUT_MECHANISM_INFO (info);
	END_CALL;
}

static CK_RV
rpc_C_InitToken (CK_X_FUNCTION_LIST *self,
                 CK_SLOT_ID slot_id,
                 CK_UTF8CHAR_PTR pin, CK_ULONG pin_len,
                 CK_UTF8CHAR_PTR label)
{
	BEGIN_CALL_OR (C_InitToken, self, CKR_SLOT_ID_INVALID);
		IN_ULONG (slot_id);
		IN_BYTE_ARRAY (pin, pin_len);
		IN_STRING (label);
	PROCESS_CALL;
	END_CALL;
}

static CK_RV
rpc_C_WaitForSlotEvent (CK_X_FUNCTION_LIST *self,
                        CK_FLAGS flags,
                        CK_SLOT_ID_PTR slot,
                        CK_VOID_PTR reserved)
{
	return_val_if_fail (slot, CKR_ARGUMENTS_BAD);

	BEGIN_CALL_OR (C_WaitForSlotEvent, self, CKR_DEVICE_REMOVED);
		IN_ULONG (flags);
	PROCESS_CALL;
		OUT_ULONG (slot);
	END_CALL;
}

static CK_RV
rpc_C_OpenSession (CK_X_FUNCTION_LIST *self,
                   CK_SLOT_ID slot_id,
                   CK_FLAGS flags,
                   CK_VOID_PTR user_data,
                   CK_NOTIFY callback,
                   CK_SESSION_HANDLE_PTR session)
{
	return_val_if_fail (session, CKR_ARGUMENTS_BAD);

	BEGIN_CALL_OR (C_OpenSession, self, CKR_SLOT_ID_INVALID);
		IN_ULONG (slot_id);
		IN_ULONG (flags);
	PROCESS_CALL;
		OUT_ULONG (session);
	END_CALL;
}

static CK_RV
rpc_C_CloseSession (CK_X_FUNCTION_LIST *self,
                    CK_SESSION_HANDLE session)
{
	BEGIN_CALL_OR (C_CloseSession, self, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session);
	PROCESS_CALL;
	END_CALL;
}

static CK_RV
rpc_C_CloseAllSessions (CK_X_FUNCTION_LIST *self,
                        CK_SLOT_ID slot_id)
{
	BEGIN_CALL_OR (C_CloseAllSessions, self, CKR_SLOT_ID_INVALID);
		IN_ULONG (slot_id);
	PROCESS_CALL;
	END_CALL;
}

static CK_RV
rpc_C_GetSessionInfo (CK_X_FUNCTION_LIST *self,
                      CK_SESSION_HANDLE session,
                      CK_SESSION_INFO_PTR info)
{
	return_val_if_fail (info, CKR_ARGUMENTS_BAD);

	BEGIN_CALL_OR (C_GetSessionInfo, self, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session);
	PROCESS_CALL;
		OUT_SESSION_INFO (info);
	END_CALL;
}

static CK_RV
rpc_C_InitPIN (CK_X_FUNCTION_LIST *self,
               CK_SESSION_HANDLE session,
               CK_UTF8CHAR_PTR pin,
               CK_ULONG pin_len)
{
	BEGIN_CALL_OR (C_InitPIN, self, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session);
		IN_BYTE_ARRAY (pin, pin_len);
	PROCESS_CALL;
	END_CALL;
}

static CK_RV
rpc_C_SetPIN (CK_X_FUNCTION_LIST *self,
              CK_SESSION_HANDLE session,
              CK_UTF8CHAR_PTR old_pin,
              CK_ULONG old_pin_len,
              CK_UTF8CHAR_PTR new_pin,
              CK_ULONG new_pin_len)
{
	BEGIN_CALL_OR (C_SetPIN, self, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session);
		IN_BYTE_ARRAY (old_pin, old_pin_len);
		IN_BYTE_ARRAY (new_pin, new_pin_len);
	PROCESS_CALL;
	END_CALL;
}

static CK_RV
rpc_C_GetOperationState (CK_X_FUNCTION_LIST *self,
                         CK_SESSION_HANDLE session,
                         CK_BYTE_PTR operation_state,
                         CK_ULONG_PTR operation_state_len)
{
	return_val_if_fail (operation_state_len, CKR_ARGUMENTS_BAD);

	BEGIN_CALL_OR (C_GetOperationState, self, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session);
		IN_BYTE_BUFFER (operation_state, operation_state_len);
	PROCESS_CALL;
		OUT_BYTE_ARRAY (operation_state, operation_state_len);
	END_CALL;
}

static CK_RV
rpc_C_SetOperationState (CK_X_FUNCTION_LIST *self,
                         CK_SESSION_HANDLE session,
                         CK_BYTE_PTR operation_state,
                         CK_ULONG operation_state_len,
                         CK_OBJECT_HANDLE encryption_key,
                         CK_OBJECT_HANDLE authentication_key)
{
	BEGIN_CALL_OR (C_SetOperationState, self, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session);
		IN_BYTE_ARRAY (operation_state, operation_state_len);
		IN_ULONG (encryption_key);
		IN_ULONG (authentication_key);
	PROCESS_CALL;
	END_CALL;
}

static CK_RV
rpc_C_Login (CK_X_FUNCTION_LIST *self,
             CK_SESSION_HANDLE session,
             CK_USER_TYPE user_type,
             CK_UTF8CHAR_PTR pin,
             CK_ULONG pin_len)
{
	BEGIN_CALL_OR (C_Login, self, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session);
		IN_ULONG (user_type);
		IN_BYTE_ARRAY (pin, pin_len);
	PROCESS_CALL;
	END_CALL;
}

static CK_RV
rpc_C_Logout (CK_X_FUNCTION_LIST *self,
              CK_SESSION_HANDLE session)
{
	BEGIN_CALL_OR (C_Logout, self, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session);
	PROCESS_CALL;
	END_CALL;
}

static CK_RV
rpc_C_CreateObject (CK_X_FUNCTION_LIST *self,
                    CK_SESSION_HANDLE session,
                    CK_ATTRIBUTE_PTR template,
                    CK_ULONG count,
                    CK_OBJECT_HANDLE_PTR new_object)
{
	return_val_if_fail (new_object, CKR_ARGUMENTS_BAD);

	BEGIN_CALL_OR (C_CreateObject, self, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session);
		IN_ATTRIBUTE_ARRAY (template, count);
	PROCESS_CALL;
		OUT_ULONG (new_object);
	END_CALL;
}

static CK_RV
rpc_C_CopyObject (CK_X_FUNCTION_LIST *self,
                  CK_SESSION_HANDLE session,
                  CK_OBJECT_HANDLE object,
                  CK_ATTRIBUTE_PTR template,
                  CK_ULONG count,
                  CK_OBJECT_HANDLE_PTR new_object)
{
	return_val_if_fail (new_object, CKR_ARGUMENTS_BAD);

	BEGIN_CALL_OR (C_CopyObject, self, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session);
		IN_ULONG (object);
		IN_ATTRIBUTE_ARRAY (template, count);
	PROCESS_CALL;
		OUT_ULONG (new_object);
	END_CALL;
}


static CK_RV
rpc_C_DestroyObject (CK_X_FUNCTION_LIST *self,
                     CK_SESSION_HANDLE session,
                     CK_OBJECT_HANDLE object)
{
	BEGIN_CALL_OR (C_DestroyObject, self, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session);
		IN_ULONG (object);
	PROCESS_CALL;
	END_CALL;
}

static CK_RV
rpc_C_GetObjectSize (CK_X_FUNCTION_LIST *self,
                     CK_SESSION_HANDLE session,
                     CK_OBJECT_HANDLE object,
                     CK_ULONG_PTR size)
{
	return_val_if_fail (size, CKR_ARGUMENTS_BAD);

	BEGIN_CALL_OR (C_GetObjectSize, self, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session);
		IN_ULONG (object);
	PROCESS_CALL;
		OUT_ULONG (size);
	END_CALL;
}

static CK_RV
rpc_C_GetAttributeValue (CK_X_FUNCTION_LIST *self,
                         CK_SESSION_HANDLE session,
                         CK_OBJECT_HANDLE object,
                         CK_ATTRIBUTE_PTR template,
                         CK_ULONG count)
{
	BEGIN_CALL_OR (C_GetAttributeValue, self, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session);
		IN_ULONG (object);
		IN_ATTRIBUTE_BUFFER (template, count);
	PROCESS_CALL;
		OUT_ATTRIBUTE_ARRAY (template, count);
	END_CALL;
}

static CK_RV
rpc_C_SetAttributeValue (CK_X_FUNCTION_LIST *self,
                         CK_SESSION_HANDLE session,
                         CK_OBJECT_HANDLE object,
                         CK_ATTRIBUTE_PTR template,
                         CK_ULONG count)
{
	BEGIN_CALL_OR (C_SetAttributeValue, self, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session);
		IN_ULONG (object);
		IN_ATTRIBUTE_ARRAY (template, count);
	PROCESS_CALL;
	END_CALL;
}

static CK_RV
rpc_C_FindObjectsInit (CK_X_FUNCTION_LIST *self,
                       CK_SESSION_HANDLE session,
                       CK_ATTRIBUTE_PTR template,
                       CK_ULONG count)
{
	BEGIN_CALL_OR (C_FindObjectsInit, self, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session);
		IN_ATTRIBUTE_ARRAY (template, count);
	PROCESS_CALL;
	END_CALL;
}

static CK_RV
rpc_C_FindObjects (CK_X_FUNCTION_LIST *self,
                   CK_SESSION_HANDLE session,
                   CK_OBJECT_HANDLE_PTR objects,
                   CK_ULONG max_count,
                   CK_ULONG_PTR count)
{
	/* HACK: To fix a stupid gcc warning */
	CK_ULONG_PTR address_of_max_count = &max_count;

	return_val_if_fail (count, CKR_ARGUMENTS_BAD);

	BEGIN_CALL_OR (C_FindObjects, self, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session);
		IN_ULONG_BUFFER (objects, address_of_max_count);
	PROCESS_CALL;
		*count = max_count;
		OUT_ULONG_ARRAY (objects, count);
	END_CALL;
}

static CK_RV
rpc_C_FindObjectsFinal (CK_X_FUNCTION_LIST *self,
                        CK_SESSION_HANDLE session)
{
	BEGIN_CALL_OR (C_FindObjectsFinal, self, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session);
	PROCESS_CALL;
	END_CALL;
}

static CK_RV
rpc_C_EncryptInit (CK_X_FUNCTION_LIST *self,
                   CK_SESSION_HANDLE session,
                   CK_MECHANISM_PTR mechanism,
                   CK_OBJECT_HANDLE key)
{
	BEGIN_CALL_OR (C_EncryptInit, self, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session);
		IN_MECHANISM (mechanism);
		IN_ULONG (key);
	PROCESS_CALL;
	END_CALL;
}

static CK_RV
rpc_C_Encrypt (CK_X_FUNCTION_LIST *self,
               CK_SESSION_HANDLE session,
               CK_BYTE_PTR data,
               CK_ULONG data_len,
               CK_BYTE_PTR encrypted_data,
               CK_ULONG_PTR encrypted_data_len)
{
	return_val_if_fail (encrypted_data_len, CKR_ARGUMENTS_BAD);

	BEGIN_CALL_OR (C_Encrypt, self, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session);
		IN_BYTE_ARRAY (data, data_len);
		IN_BYTE_BUFFER (encrypted_data, encrypted_data_len);
	PROCESS_CALL;
		OUT_BYTE_ARRAY (encrypted_data, encrypted_data_len);
	END_CALL;
}

static CK_RV
rpc_C_EncryptUpdate (CK_X_FUNCTION_LIST *self,
                     CK_SESSION_HANDLE session,
                     CK_BYTE_PTR part,
                     CK_ULONG part_len,
                     CK_BYTE_PTR encrypted_part,
                     CK_ULONG_PTR encrypted_part_len)
{
	return_val_if_fail (encrypted_part_len, CKR_ARGUMENTS_BAD);

	BEGIN_CALL_OR (C_EncryptUpdate, self, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session);
		IN_BYTE_ARRAY (part, part_len);
		IN_BYTE_BUFFER (encrypted_part, encrypted_part_len);
	PROCESS_CALL;
		OUT_BYTE_ARRAY (encrypted_part, encrypted_part_len);
	END_CALL;
}

static CK_RV
rpc_C_EncryptFinal (CK_X_FUNCTION_LIST *self,
                    CK_SESSION_HANDLE session,
                    CK_BYTE_PTR last_part,
                    CK_ULONG_PTR last_part_len)
{
	return_val_if_fail (last_part_len, CKR_ARGUMENTS_BAD);

	BEGIN_CALL_OR (C_EncryptFinal, self, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session);
		IN_BYTE_BUFFER (last_part, last_part_len);
	PROCESS_CALL;
		OUT_BYTE_ARRAY (last_part, last_part_len);
	END_CALL;
}

static CK_RV
rpc_C_DecryptInit (CK_X_FUNCTION_LIST *self,
                   CK_SESSION_HANDLE session,
                   CK_MECHANISM_PTR mechanism,
                   CK_OBJECT_HANDLE key)
{
	BEGIN_CALL_OR (C_DecryptInit, self, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session);
		IN_MECHANISM (mechanism);
		IN_ULONG (key);
	PROCESS_CALL;
	END_CALL;
}

static CK_RV
rpc_C_Decrypt (CK_X_FUNCTION_LIST *self,
               CK_SESSION_HANDLE session,
               CK_BYTE_PTR enc_data,
               CK_ULONG enc_data_len,
               CK_BYTE_PTR data,
               CK_ULONG_PTR data_len)
{
	return_val_if_fail (data_len, CKR_ARGUMENTS_BAD);

	BEGIN_CALL_OR (C_Decrypt, self, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session);
		IN_BYTE_ARRAY (enc_data, enc_data_len);
		IN_BYTE_BUFFER (data, data_len);
	PROCESS_CALL;
		OUT_BYTE_ARRAY (data, data_len);
	END_CALL;
}

static CK_RV
rpc_C_DecryptUpdate (CK_X_FUNCTION_LIST *self,
                     CK_SESSION_HANDLE session,
                     CK_BYTE_PTR enc_part,
                     CK_ULONG enc_part_len,
                     CK_BYTE_PTR part,
                     CK_ULONG_PTR part_len)
{
	return_val_if_fail (part_len, CKR_ARGUMENTS_BAD);

	BEGIN_CALL_OR (C_DecryptUpdate, self, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session);
		IN_BYTE_ARRAY (enc_part, enc_part_len);
		IN_BYTE_BUFFER (part, part_len);
	PROCESS_CALL;
		OUT_BYTE_ARRAY (part, part_len);
	END_CALL;
}

static CK_RV
rpc_C_DecryptFinal (CK_X_FUNCTION_LIST *self,
                    CK_SESSION_HANDLE session,
                    CK_BYTE_PTR last_part,
                    CK_ULONG_PTR last_part_len)
{
	return_val_if_fail (last_part_len, CKR_ARGUMENTS_BAD);

	BEGIN_CALL_OR (C_DecryptFinal, self, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session);
		IN_BYTE_BUFFER (last_part, last_part_len);
	PROCESS_CALL;
		OUT_BYTE_ARRAY (last_part, last_part_len);
	END_CALL;
}

static CK_RV
rpc_C_DigestInit (CK_X_FUNCTION_LIST *self,
                  CK_SESSION_HANDLE session,
                  CK_MECHANISM_PTR mechanism)
{
	BEGIN_CALL_OR (C_DigestInit, self, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session);
		IN_MECHANISM (mechanism);
	PROCESS_CALL;
	END_CALL;
}

static CK_RV
rpc_C_Digest (CK_X_FUNCTION_LIST *self,
              CK_SESSION_HANDLE session,
              CK_BYTE_PTR data,
              CK_ULONG data_len,
              CK_BYTE_PTR digest,
              CK_ULONG_PTR digest_len)
{
	return_val_if_fail (digest_len, CKR_ARGUMENTS_BAD);

	BEGIN_CALL_OR (C_Digest, self, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session);
		IN_BYTE_ARRAY (data, data_len);
		IN_BYTE_BUFFER (digest, digest_len);
	PROCESS_CALL;
		OUT_BYTE_ARRAY (digest, digest_len);
	END_CALL;
}

static CK_RV
rpc_C_DigestUpdate (CK_X_FUNCTION_LIST *self,
                    CK_SESSION_HANDLE session,
                    CK_BYTE_PTR part,
                    CK_ULONG part_len)
{
	BEGIN_CALL_OR (C_DigestUpdate, self, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session);
		IN_BYTE_ARRAY (part, part_len);
	PROCESS_CALL;
	END_CALL;
}

static CK_RV
rpc_C_DigestKey (CK_X_FUNCTION_LIST *self,
                 CK_SESSION_HANDLE session,
                 CK_OBJECT_HANDLE key)
{
	BEGIN_CALL_OR (C_DigestKey, self, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session);
		IN_ULONG (key);
	PROCESS_CALL;
	END_CALL;
}

static CK_RV
rpc_C_DigestFinal (CK_X_FUNCTION_LIST *self,
                   CK_SESSION_HANDLE session,
                   CK_BYTE_PTR digest,
                   CK_ULONG_PTR digest_len)
{
	return_val_if_fail (digest_len, CKR_ARGUMENTS_BAD);

	BEGIN_CALL_OR (C_DigestFinal, self, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session);
		IN_BYTE_BUFFER (digest, digest_len);
	PROCESS_CALL;
		OUT_BYTE_ARRAY (digest, digest_len);
	END_CALL;
}

static CK_RV
rpc_C_SignInit (CK_X_FUNCTION_LIST *self,
                CK_SESSION_HANDLE session,
                CK_MECHANISM_PTR mechanism,
                CK_OBJECT_HANDLE key)
{
	BEGIN_CALL_OR (C_SignInit, self, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session);
		IN_MECHANISM (mechanism);
		IN_ULONG (key);
	PROCESS_CALL;
	END_CALL;
}

static CK_RV
rpc_C_Sign (CK_X_FUNCTION_LIST *self,
            CK_SESSION_HANDLE session,
            CK_BYTE_PTR data,
            CK_ULONG data_len,
            CK_BYTE_PTR signature,
            CK_ULONG_PTR signature_len)
{
	return_val_if_fail (signature_len, CKR_ARGUMENTS_BAD);

	BEGIN_CALL_OR (C_Sign, self, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session);
		IN_BYTE_ARRAY (data, data_len);
		IN_BYTE_BUFFER (signature, signature_len);
	PROCESS_CALL;
		OUT_BYTE_ARRAY (signature, signature_len);
	END_CALL;
}

static CK_RV
rpc_C_SignUpdate (CK_X_FUNCTION_LIST *self,
                  CK_SESSION_HANDLE session,
                  CK_BYTE_PTR part,
                  CK_ULONG part_len)
{
	BEGIN_CALL_OR (C_SignUpdate, self, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session);
		IN_BYTE_ARRAY (part, part_len);
	PROCESS_CALL;
	END_CALL;
}

static CK_RV
rpc_C_SignFinal (CK_X_FUNCTION_LIST *self,
                 CK_SESSION_HANDLE session,
                 CK_BYTE_PTR signature,
                 CK_ULONG_PTR signature_len)
{
	return_val_if_fail (signature_len, CKR_ARGUMENTS_BAD);

	BEGIN_CALL_OR (C_SignFinal, self, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session);
		IN_BYTE_BUFFER (signature, signature_len);
	PROCESS_CALL;
		OUT_BYTE_ARRAY (signature, signature_len);
	END_CALL;
}

static CK_RV
rpc_C_SignRecoverInit (CK_X_FUNCTION_LIST *self,
                       CK_SESSION_HANDLE session,
                       CK_MECHANISM_PTR mechanism,
                       CK_OBJECT_HANDLE key)
{
	BEGIN_CALL_OR (C_SignRecoverInit, self, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session);
		IN_MECHANISM (mechanism);
		IN_ULONG (key);
	PROCESS_CALL;
	END_CALL;
}

static CK_RV
rpc_C_SignRecover (CK_X_FUNCTION_LIST *self,
                   CK_SESSION_HANDLE session,
                   CK_BYTE_PTR data,
                   CK_ULONG data_len,
                   CK_BYTE_PTR signature, CK_ULONG_PTR signature_len)
{
	return_val_if_fail (signature_len, CKR_ARGUMENTS_BAD);

	BEGIN_CALL_OR (C_SignRecover, self, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session);
		IN_BYTE_ARRAY (data, data_len);
		IN_BYTE_BUFFER (signature, signature_len);
	PROCESS_CALL;
		OUT_BYTE_ARRAY (signature, signature_len);
	END_CALL;
}

static CK_RV
rpc_C_VerifyInit (CK_X_FUNCTION_LIST *self,
                  CK_SESSION_HANDLE session,
                  CK_MECHANISM_PTR mechanism,
                  CK_OBJECT_HANDLE key)
{
	BEGIN_CALL_OR (C_VerifyInit, self, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session);
		IN_MECHANISM (mechanism);
		IN_ULONG (key);
	PROCESS_CALL;
	END_CALL;
}

static CK_RV
rpc_C_Verify (CK_X_FUNCTION_LIST *self,
              CK_SESSION_HANDLE session,
              CK_BYTE_PTR data,
              CK_ULONG data_len,
              CK_BYTE_PTR signature,
              CK_ULONG signature_len)
{
	BEGIN_CALL_OR (C_Verify, self, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session);
		IN_BYTE_ARRAY (data, data_len);
		IN_BYTE_ARRAY (signature, signature_len);
	PROCESS_CALL;
	END_CALL;
}

static CK_RV
rpc_C_VerifyUpdate (CK_X_FUNCTION_LIST *self,
                    CK_SESSION_HANDLE session,
                    CK_BYTE_PTR part,
                    CK_ULONG part_len)
{
	BEGIN_CALL_OR (C_VerifyUpdate, self, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session);
		IN_BYTE_ARRAY (part, part_len);
	PROCESS_CALL;
	END_CALL;
}

static CK_RV
rpc_C_VerifyFinal (CK_X_FUNCTION_LIST *self,
                   CK_SESSION_HANDLE session,
                   CK_BYTE_PTR signature,
                   CK_ULONG signature_len)
{
	BEGIN_CALL_OR (C_VerifyFinal, self, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session);
		IN_BYTE_ARRAY (signature, signature_len);
	PROCESS_CALL;
	END_CALL;
}

static CK_RV
rpc_C_VerifyRecoverInit (CK_X_FUNCTION_LIST *self,
                         CK_SESSION_HANDLE session,
                         CK_MECHANISM_PTR mechanism,
                         CK_OBJECT_HANDLE key)
{
	BEGIN_CALL_OR (C_VerifyRecoverInit, self, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session);
		IN_MECHANISM (mechanism);
		IN_ULONG (key);
	PROCESS_CALL;
	END_CALL;
}

static CK_RV
rpc_C_VerifyRecover (CK_X_FUNCTION_LIST *self,
                     CK_SESSION_HANDLE session,
                     CK_BYTE_PTR signature,
                     CK_ULONG signature_len,
                     CK_BYTE_PTR data,
                     CK_ULONG_PTR data_len)
{
	return_val_if_fail (data_len, CKR_ARGUMENTS_BAD);

	BEGIN_CALL_OR (C_VerifyRecover, self, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session);
		IN_BYTE_ARRAY (signature, signature_len);
		IN_BYTE_BUFFER (data, data_len);
	PROCESS_CALL;
		OUT_BYTE_ARRAY (data, data_len);
	END_CALL;
}

static CK_RV
rpc_C_DigestEncryptUpdate (CK_X_FUNCTION_LIST *self,
                           CK_SESSION_HANDLE session,
                           CK_BYTE_PTR part,
                           CK_ULONG part_len,
                           CK_BYTE_PTR enc_part,
                           CK_ULONG_PTR enc_part_len)
{
	return_val_if_fail (enc_part_len, CKR_ARGUMENTS_BAD);

	BEGIN_CALL_OR (C_DigestEncryptUpdate, self, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session);
		IN_BYTE_ARRAY (part, part_len);
		IN_BYTE_BUFFER (enc_part, enc_part_len);
	PROCESS_CALL;
		OUT_BYTE_ARRAY (enc_part, enc_part_len);
	END_CALL;
}

static CK_RV
rpc_C_DecryptDigestUpdate (CK_X_FUNCTION_LIST *self,
                           CK_SESSION_HANDLE session,
                           CK_BYTE_PTR enc_part,
                           CK_ULONG enc_part_len,
                           CK_BYTE_PTR part,
                           CK_ULONG_PTR part_len)
{
	return_val_if_fail (part_len, CKR_ARGUMENTS_BAD);

	BEGIN_CALL_OR (C_DecryptDigestUpdate, self, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session);
		IN_BYTE_ARRAY (enc_part, enc_part_len);
		IN_BYTE_BUFFER (part, part_len);
	PROCESS_CALL;
		OUT_BYTE_ARRAY (part, part_len);
	END_CALL;
}

static CK_RV
rpc_C_SignEncryptUpdate (CK_X_FUNCTION_LIST *self,
                         CK_SESSION_HANDLE session,
                         CK_BYTE_PTR part,
                         CK_ULONG part_len,
                         CK_BYTE_PTR enc_part,
                         CK_ULONG_PTR enc_part_len)
{
	return_val_if_fail (enc_part_len, CKR_ARGUMENTS_BAD);

	BEGIN_CALL_OR (C_SignEncryptUpdate, self, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session);
		IN_BYTE_ARRAY (part, part_len);
		IN_BYTE_BUFFER (enc_part, enc_part_len);
	PROCESS_CALL;
		OUT_BYTE_ARRAY (enc_part, enc_part_len);
	END_CALL;
}

static CK_RV
rpc_C_DecryptVerifyUpdate (CK_X_FUNCTION_LIST *self,
                           CK_SESSION_HANDLE session,
                           CK_BYTE_PTR enc_part,
                           CK_ULONG enc_part_len,
                           CK_BYTE_PTR part,
                           CK_ULONG_PTR part_len)
{
	return_val_if_fail (part_len, CKR_ARGUMENTS_BAD);

	BEGIN_CALL_OR (C_DecryptVerifyUpdate, self, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session);
		IN_BYTE_ARRAY (enc_part, enc_part_len);
		IN_BYTE_BUFFER (part, part_len);
	PROCESS_CALL;
		OUT_BYTE_ARRAY (part, part_len);
	END_CALL;
}

static CK_RV
rpc_C_GenerateKey (CK_X_FUNCTION_LIST *self,
                   CK_SESSION_HANDLE session,
                   CK_MECHANISM_PTR mechanism,
                   CK_ATTRIBUTE_PTR template,
                   CK_ULONG count,
                   CK_OBJECT_HANDLE_PTR key)
{
	BEGIN_CALL_OR (C_GenerateKey, self, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session);
		IN_MECHANISM (mechanism);
		IN_ATTRIBUTE_ARRAY (template, count);
	PROCESS_CALL;
		OUT_ULONG (key);
	END_CALL;
}

static CK_RV
rpc_C_GenerateKeyPair (CK_X_FUNCTION_LIST *self,
                       CK_SESSION_HANDLE session,
                       CK_MECHANISM_PTR mechanism,
                       CK_ATTRIBUTE_PTR pub_template,
                       CK_ULONG pub_count,
                       CK_ATTRIBUTE_PTR priv_template,
                       CK_ULONG priv_count,
                       CK_OBJECT_HANDLE_PTR pub_key,
                       CK_OBJECT_HANDLE_PTR priv_key)
{
	BEGIN_CALL_OR (C_GenerateKeyPair, self, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session);
		IN_MECHANISM (mechanism);
		IN_ATTRIBUTE_ARRAY (pub_template, pub_count);
		IN_ATTRIBUTE_ARRAY (priv_template, priv_count);
	PROCESS_CALL;
		OUT_ULONG (pub_key);
		OUT_ULONG (priv_key);
	END_CALL;
}

static CK_RV
rpc_C_WrapKey (CK_X_FUNCTION_LIST *self,
               CK_SESSION_HANDLE session,
               CK_MECHANISM_PTR mechanism,
               CK_OBJECT_HANDLE wrapping_key,
               CK_OBJECT_HANDLE key,
               CK_BYTE_PTR wrapped_key,
               CK_ULONG_PTR wrapped_key_len)
{
	return_val_if_fail (wrapped_key_len, CKR_ARGUMENTS_BAD);

	BEGIN_CALL_OR (C_WrapKey, self, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session);
		IN_MECHANISM (mechanism);
		IN_ULONG (wrapping_key);
		IN_ULONG (key);
		IN_BYTE_BUFFER (wrapped_key, wrapped_key_len);
	PROCESS_CALL;
		OUT_BYTE_ARRAY (wrapped_key, wrapped_key_len);
	END_CALL;
}

static CK_RV
rpc_C_UnwrapKey (CK_X_FUNCTION_LIST *self,
                 CK_SESSION_HANDLE session,
                 CK_MECHANISM_PTR mechanism,
                 CK_OBJECT_HANDLE unwrapping_key,
                 CK_BYTE_PTR wrapped_key,
                 CK_ULONG wrapped_key_len,
                 CK_ATTRIBUTE_PTR template,
                 CK_ULONG count,
                 CK_OBJECT_HANDLE_PTR key)
{
	BEGIN_CALL_OR (C_UnwrapKey, self, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session);
		IN_MECHANISM (mechanism);
		IN_ULONG (unwrapping_key);
		IN_BYTE_ARRAY (wrapped_key, wrapped_key_len);
		IN_ATTRIBUTE_ARRAY (template, count);
	PROCESS_CALL;
		OUT_ULONG (key);
	END_CALL;
}

static CK_RV
rpc_C_DeriveKey (CK_X_FUNCTION_LIST *self,
                 CK_SESSION_HANDLE session,
                 CK_MECHANISM_PTR mechanism,
                 CK_OBJECT_HANDLE base_key,
                 CK_ATTRIBUTE_PTR template,
                 CK_ULONG count,
                 CK_OBJECT_HANDLE_PTR key)
{
	BEGIN_CALL_OR (C_DeriveKey, self, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session);
		IN_MECHANISM (mechanism);
		IN_ULONG (base_key);
		IN_ATTRIBUTE_ARRAY (template, count);
	PROCESS_CALL;
		OUT_ULONG (key);
	END_CALL;
}

static CK_RV
rpc_C_SeedRandom (CK_X_FUNCTION_LIST *self,
                  CK_SESSION_HANDLE session,
                  CK_BYTE_PTR seed,
                  CK_ULONG seed_len)
{
	BEGIN_CALL_OR (C_SeedRandom, self, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session);
		IN_BYTE_ARRAY (seed, seed_len);
	PROCESS_CALL;
	END_CALL;
}

static CK_RV
rpc_C_GenerateRandom (CK_X_FUNCTION_LIST *self,
                      CK_SESSION_HANDLE session,
                      CK_BYTE_PTR random_data,
                      CK_ULONG random_len)
{
	CK_ULONG_PTR address = &random_len;

	BEGIN_CALL_OR (C_GenerateRandom, self, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session);
		IN_BYTE_BUFFER (random_data, address);
	PROCESS_CALL;
		OUT_BYTE_ARRAY (random_data, address);
	END_CALL;
}

static CK_RV
rpc_C_LoginUser (CK_X_FUNCTION_LIST *self,
                 CK_SESSION_HANDLE session,
                 CK_USER_TYPE user_type,
                 CK_UTF8CHAR_PTR pin,
                 CK_ULONG pin_len,
                 CK_UTF8CHAR_PTR username,
                 CK_ULONG username_len)
{
	BEGIN_CALL_OR (C_LoginUser, self, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session)
		IN_ULONG (user_type)
		IN_BYTE_ARRAY (pin, pin_len)
		IN_BYTE_ARRAY (username, username_len)
	PROCESS_CALL;
	END_CALL;
}

static CK_RV
rpc_C_SessionCancel (CK_X_FUNCTION_LIST *self,
                     CK_SESSION_HANDLE session,
                     CK_FLAGS flags)
{
	BEGIN_CALL_OR (C_SessionCancel, self, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session)
		IN_ULONG (flags)
	PROCESS_CALL;
	END_CALL;
}

static CK_RV
rpc_C_MessageEncryptInit (CK_X_FUNCTION_LIST *self,
                          CK_SESSION_HANDLE session,
                          CK_MECHANISM_PTR mechanism,
                          CK_OBJECT_HANDLE key)
{
	BEGIN_CALL_OR (C_MessageEncryptInit, self, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session)
		IN_MECHANISM (mechanism)
		IN_ULONG (key)
	PROCESS_CALL;
	END_CALL;
}

static CK_RV
rpc_C_EncryptMessage (CK_X_FUNCTION_LIST *self,
                      CK_SESSION_HANDLE session,
                      CK_VOID_PTR parameter,
                      CK_ULONG parameter_len,
                      CK_BYTE_PTR associated_data,
                      CK_ULONG associated_data_len,
                      CK_BYTE_PTR plaintext,
                      CK_ULONG plaintext_len,
                      CK_BYTE_PTR ciphertext,
                      CK_ULONG_PTR ciphertext_len)
{
	return_val_if_fail (ciphertext_len, CKR_ARGUMENTS_BAD);

	BEGIN_CALL_OR (C_EncryptMessage, self, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session)
		IN_BYTE_ARRAY (parameter, parameter_len)
		IN_BYTE_ARRAY (associated_data, associated_data_len)
		IN_BYTE_ARRAY (plaintext, plaintext_len)
		IN_BYTE_BUFFER (ciphertext, ciphertext_len);
	PROCESS_CALL;
		OUT_BYTE_ARRAY (ciphertext, ciphertext_len)
	END_CALL;
}

static CK_RV
rpc_C_EncryptMessageBegin (CK_X_FUNCTION_LIST *self,
                           CK_SESSION_HANDLE session,
                           CK_VOID_PTR parameter,
                           CK_ULONG parameter_len,
                           CK_BYTE_PTR associated_data,
                           CK_ULONG associated_data_len)
{
	BEGIN_CALL_OR (C_EncryptMessageBegin, self, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session)
		IN_BYTE_ARRAY (parameter, parameter_len)
		IN_BYTE_ARRAY (associated_data, associated_data_len)
	PROCESS_CALL;
	END_CALL;
}

static CK_RV
rpc_C_EncryptMessageNext (CK_X_FUNCTION_LIST *self,
                          CK_SESSION_HANDLE session,
                          CK_VOID_PTR parameter,
                          CK_ULONG parameter_len,
                          CK_BYTE_PTR plaintext_part,
                          CK_ULONG plaintext_part_len,
                          CK_BYTE_PTR ciphertext_part,
                          CK_ULONG_PTR ciphertext_part_len,
                          CK_FLAGS flags)
{
	BEGIN_CALL_OR (C_EncryptMessageNext, self, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session)
		IN_BYTE_ARRAY (parameter, parameter_len)
		IN_BYTE_ARRAY (plaintext_part, plaintext_part_len)
		IN_BYTE_BUFFER (ciphertext_part, ciphertext_part_len);
		IN_ULONG (flags)
	PROCESS_CALL;
		OUT_BYTE_ARRAY (ciphertext_part, ciphertext_part_len)
	END_CALL;
}

static CK_RV
rpc_C_MessageEncryptFinal (CK_X_FUNCTION_LIST *self,
                           CK_SESSION_HANDLE session)
{
	BEGIN_CALL_OR (C_MessageEncryptFinal, self, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session)
	PROCESS_CALL;
	END_CALL;
}

static CK_RV
rpc_C_MessageDecryptInit (CK_X_FUNCTION_LIST *self,
                          CK_SESSION_HANDLE session,
                          CK_MECHANISM_PTR mechanism,
                          CK_OBJECT_HANDLE key)
{
	BEGIN_CALL_OR (C_MessageDecryptInit, self, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session)
		IN_MECHANISM (mechanism)
		IN_ULONG (key)
	PROCESS_CALL;
	END_CALL;
}

static CK_RV
rpc_C_DecryptMessage (CK_X_FUNCTION_LIST *self,
                      CK_SESSION_HANDLE session,
                      CK_VOID_PTR parameter,
                      CK_ULONG parameter_len,
                      CK_BYTE_PTR associated_data,
                      CK_ULONG associated_data_len,
                      CK_BYTE_PTR ciphertext,
                      CK_ULONG ciphertext_len,
                      CK_BYTE_PTR plaintext,
                      CK_ULONG_PTR plaintext_len)
{
	return_val_if_fail (plaintext_len, CKR_ARGUMENTS_BAD);

	BEGIN_CALL_OR (C_DecryptMessage, self, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session)
		IN_BYTE_ARRAY (parameter, parameter_len)
		IN_BYTE_ARRAY (associated_data, associated_data_len)
		IN_BYTE_ARRAY (ciphertext, ciphertext_len)
		IN_BYTE_BUFFER (plaintext, plaintext_len);
	PROCESS_CALL;
		OUT_BYTE_ARRAY (plaintext, plaintext_len)
	END_CALL;
}

static CK_RV
rpc_C_DecryptMessageBegin (CK_X_FUNCTION_LIST *self,
                           CK_SESSION_HANDLE session,
                           CK_VOID_PTR parameter,
                           CK_ULONG parameter_len,
                           CK_BYTE_PTR associated_data,
                           CK_ULONG associated_data_len)
{
	BEGIN_CALL_OR (C_DecryptMessageBegin, self, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session)
		IN_BYTE_ARRAY (parameter, parameter_len)
		IN_BYTE_ARRAY (associated_data, associated_data_len)
	PROCESS_CALL;
	END_CALL;
}

static CK_RV
rpc_C_DecryptMessageNext (CK_X_FUNCTION_LIST *self,
                          CK_SESSION_HANDLE session,
                          CK_VOID_PTR parameter,
                          CK_ULONG parameter_len,
                          CK_BYTE_PTR ciphertext_part,
                          CK_ULONG ciphertext_part_len,
                          CK_BYTE_PTR plaintext_part,
                          CK_ULONG_PTR plaintext_part_len,
                          CK_FLAGS flags)
{
	BEGIN_CALL_OR (C_DecryptMessageNext, self, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session)
		IN_BYTE_ARRAY (parameter, parameter_len)
		IN_BYTE_ARRAY (ciphertext_part, ciphertext_part_len)
		IN_BYTE_BUFFER (plaintext_part, plaintext_part_len);
		IN_ULONG (flags)
	PROCESS_CALL;
		OUT_BYTE_ARRAY (plaintext_part, plaintext_part_len)
	END_CALL;
}

static CK_RV
rpc_C_MessageDecryptFinal (CK_X_FUNCTION_LIST *self,
                           CK_SESSION_HANDLE session)
{
	BEGIN_CALL_OR (C_MessageDecryptFinal, self, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session)
	PROCESS_CALL;
	END_CALL;
}

static CK_RV
rpc_C_MessageSignInit (CK_X_FUNCTION_LIST *self,
                       CK_SESSION_HANDLE session,
                       CK_MECHANISM_PTR mechanism,
                       CK_OBJECT_HANDLE key)
{
	BEGIN_CALL_OR (C_MessageSignInit, self, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session)
		IN_MECHANISM (mechanism)
		IN_ULONG (key)
	PROCESS_CALL;
	END_CALL;
}

static CK_RV
rpc_C_SignMessage (CK_X_FUNCTION_LIST *self,
                   CK_SESSION_HANDLE session,
                   CK_VOID_PTR parameter,
                   CK_ULONG parameter_len,
                   CK_BYTE_PTR data,
                   CK_ULONG data_len,
                   CK_BYTE_PTR signature,
                   CK_ULONG_PTR signature_len)
{
	return_val_if_fail (signature_len, CKR_ARGUMENTS_BAD);

	BEGIN_CALL_OR (C_SignMessage, self, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session)
		IN_BYTE_ARRAY (parameter, parameter_len)
		IN_BYTE_ARRAY (data, data_len)
		IN_BYTE_BUFFER (signature, signature_len);
	PROCESS_CALL;
		OUT_BYTE_ARRAY (signature, signature_len)
	END_CALL;
}

static CK_RV
rpc_C_SignMessageBegin (CK_X_FUNCTION_LIST *self,
                        CK_SESSION_HANDLE session,
                        CK_VOID_PTR parameter,
                        CK_ULONG parameter_len)
{
	BEGIN_CALL_OR (C_SignMessageBegin, self, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session)
		IN_BYTE_ARRAY (parameter, parameter_len)

	PROCESS_CALL;
	END_CALL;
}

static CK_RV
rpc_C_SignMessageNext (CK_X_FUNCTION_LIST *self,
                       CK_SESSION_HANDLE session,
                       CK_VOID_PTR parameter,
                       CK_ULONG parameter_len,
                       CK_BYTE_PTR data,
                       CK_ULONG data_len,
                       CK_BYTE_PTR signature,
                       CK_ULONG_PTR signature_len)
{
	BEGIN_CALL_OR (C_SignMessageNext, self, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session)
		IN_BYTE_ARRAY (parameter, parameter_len)
		IN_BYTE_ARRAY (data, data_len)
		IN_BYTE_BUFFER_NULL (signature, signature_len);
	PROCESS_CALL;
		OUT_BYTE_ARRAY_NULL (signature, signature_len)
	END_CALL;
}

static CK_RV
rpc_C_MessageSignFinal (CK_X_FUNCTION_LIST *self,
                        CK_SESSION_HANDLE session)
{
	BEGIN_CALL_OR (C_MessageSignFinal, self, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session)
	PROCESS_CALL;
	END_CALL;
}

static CK_RV
rpc_C_MessageVerifyInit (CK_X_FUNCTION_LIST *self,
                         CK_SESSION_HANDLE session,
                         CK_MECHANISM_PTR mechanism,
                         CK_OBJECT_HANDLE key)
{
	BEGIN_CALL_OR (C_MessageVerifyInit, self, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session)
		IN_MECHANISM (mechanism)
		IN_ULONG (key)
	PROCESS_CALL;
	END_CALL;
}

static CK_RV
rpc_C_VerifyMessage (CK_X_FUNCTION_LIST *self,
                     CK_SESSION_HANDLE session,
                     CK_VOID_PTR parameter,
                     CK_ULONG parameter_len,
                     CK_BYTE_PTR data,
                     CK_ULONG data_len,
                     CK_BYTE_PTR signature,
                     CK_ULONG signature_len)
{
	BEGIN_CALL_OR (C_VerifyMessage, self, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session)
		IN_BYTE_ARRAY (parameter, parameter_len)
		IN_BYTE_ARRAY (data, data_len)
		IN_BYTE_ARRAY (signature, signature_len)
	PROCESS_CALL;
	END_CALL;
}

static CK_RV
rpc_C_VerifyMessageBegin (CK_X_FUNCTION_LIST *self,
                          CK_SESSION_HANDLE session,
                          CK_VOID_PTR parameter,
                          CK_ULONG parameter_len)
{
	BEGIN_CALL_OR (C_VerifyMessageBegin, self, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session)
		IN_BYTE_ARRAY (parameter, parameter_len)
	PROCESS_CALL;
	END_CALL;
}

static CK_RV
rpc_C_VerifyMessageNext (CK_X_FUNCTION_LIST *self,
                         CK_SESSION_HANDLE session,
                         CK_VOID_PTR parameter,
                         CK_ULONG parameter_len,
                         CK_BYTE_PTR data,
                         CK_ULONG data_len,
                         CK_BYTE_PTR signature,
                         CK_ULONG signature_len)
{
	BEGIN_CALL_OR (C_VerifyMessageNext, self, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session)
		IN_BYTE_ARRAY (parameter, parameter_len)
		IN_BYTE_ARRAY (data, data_len)
		IN_BYTE_ARRAY (signature, signature_len)
	PROCESS_CALL;
	END_CALL;
}

static CK_RV
rpc_C_MessageVerifyFinal (CK_X_FUNCTION_LIST *self,
                          CK_SESSION_HANDLE session)
{
	BEGIN_CALL_OR (C_MessageVerifyFinal, self, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session)
	PROCESS_CALL;
	END_CALL;
}

static CK_X_FUNCTION_LIST rpc_functions = {
	{ -1, -1 },
	rpc_C_Initialize,
	rpc_C_Finalize,
	rpc_C_GetInfo,
	rpc_C_GetSlotList,
	rpc_C_GetSlotInfo,
	rpc_C_GetTokenInfo,
	rpc_C_GetMechanismList,
	rpc_C_GetMechanismInfo,
	rpc_C_InitToken,
	rpc_C_InitPIN,
	rpc_C_SetPIN,
	rpc_C_OpenSession,
	rpc_C_CloseSession,
	rpc_C_CloseAllSessions,
	rpc_C_GetSessionInfo,
	rpc_C_GetOperationState,
	rpc_C_SetOperationState,
	rpc_C_Login,
	rpc_C_Logout,
	rpc_C_CreateObject,
	rpc_C_CopyObject,
	rpc_C_DestroyObject,
	rpc_C_GetObjectSize,
	rpc_C_GetAttributeValue,
	rpc_C_SetAttributeValue,
	rpc_C_FindObjectsInit,
	rpc_C_FindObjects,
	rpc_C_FindObjectsFinal,
	rpc_C_EncryptInit,
	rpc_C_Encrypt,
	rpc_C_EncryptUpdate,
	rpc_C_EncryptFinal,
	rpc_C_DecryptInit,
	rpc_C_Decrypt,
	rpc_C_DecryptUpdate,
	rpc_C_DecryptFinal,
	rpc_C_DigestInit,
	rpc_C_Digest,
	rpc_C_DigestUpdate,
	rpc_C_DigestKey,
	rpc_C_DigestFinal,
	rpc_C_SignInit,
	rpc_C_Sign,
	rpc_C_SignUpdate,
	rpc_C_SignFinal,
	rpc_C_SignRecoverInit,
	rpc_C_SignRecover,
	rpc_C_VerifyInit,
	rpc_C_Verify,
	rpc_C_VerifyUpdate,
	rpc_C_VerifyFinal,
	rpc_C_VerifyRecoverInit,
	rpc_C_VerifyRecover,
	rpc_C_DigestEncryptUpdate,
	rpc_C_DecryptDigestUpdate,
	rpc_C_SignEncryptUpdate,
	rpc_C_DecryptVerifyUpdate,
	rpc_C_GenerateKey,
	rpc_C_GenerateKeyPair,
	rpc_C_WrapKey,
	rpc_C_UnwrapKey,
	rpc_C_DeriveKey,
	rpc_C_SeedRandom,
	rpc_C_GenerateRandom,
	rpc_C_WaitForSlotEvent,
	/* PKCS #11 3.0 */
	rpc_C_LoginUser,
	rpc_C_SessionCancel,
	rpc_C_MessageEncryptInit,
	rpc_C_EncryptMessage,
	rpc_C_EncryptMessageBegin,
	rpc_C_EncryptMessageNext,
	rpc_C_MessageEncryptFinal,
	rpc_C_MessageDecryptInit,
	rpc_C_DecryptMessage,
	rpc_C_DecryptMessageBegin,
	rpc_C_DecryptMessageNext,
	rpc_C_MessageDecryptFinal,
	rpc_C_MessageSignInit,
	rpc_C_SignMessage,
	rpc_C_SignMessageBegin,
	rpc_C_SignMessageNext,
	rpc_C_MessageSignFinal,
	rpc_C_MessageVerifyInit,
	rpc_C_VerifyMessage,
	rpc_C_VerifyMessageBegin,
	rpc_C_VerifyMessageNext,
	rpc_C_MessageVerifyFinal
};

static void
rpc_client_free (void *data)
{
	rpc_client *client = data;
	p11_mutex_uninit (&client->mutex);
	free (client);
}

bool
p11_rpc_client_init (p11_virtual *virt,
                     p11_rpc_client_vtable *vtable)
{
	rpc_client *client;

	p11_message_clear ();

	return_val_if_fail (vtable != NULL, false);
	return_val_if_fail (vtable->connect != NULL, false);
	return_val_if_fail (vtable->transport != NULL, false);
	return_val_if_fail (vtable->disconnect != NULL, false);

	P11_RPC_CHECK_CALLS ();

	client = calloc (1, sizeof (rpc_client));
	return_val_if_fail (client != NULL, false);

	p11_mutex_init (&client->mutex);
	client->vtable = vtable;

	p11_virtual_init (virt, &rpc_functions, client, rpc_client_free);
	return true;
}
