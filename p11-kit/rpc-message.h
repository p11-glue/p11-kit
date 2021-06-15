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

#ifndef _RPC_MESSAGE_H
#define _RPC_MESSAGE_H

#include <stdlib.h>
#include <stdarg.h>
#include <stdint.h>

#include "buffer.h"
#include "pkcs11.h"
#include "pkcs11x.h"

/* The calls, must be in sync with array below */
enum {
	P11_RPC_CALL_ERROR = 0,

	P11_RPC_CALL_C_Initialize,
	P11_RPC_CALL_C_Finalize,
	P11_RPC_CALL_C_GetInfo,
	P11_RPC_CALL_C_GetSlotList,
	P11_RPC_CALL_C_GetSlotInfo,
	P11_RPC_CALL_C_GetTokenInfo,
	P11_RPC_CALL_C_GetMechanismList,
	P11_RPC_CALL_C_GetMechanismInfo,
	P11_RPC_CALL_C_InitToken,
	P11_RPC_CALL_C_OpenSession,
	P11_RPC_CALL_C_CloseSession,
	P11_RPC_CALL_C_CloseAllSessions,
	P11_RPC_CALL_C_GetSessionInfo,
	P11_RPC_CALL_C_InitPIN,
	P11_RPC_CALL_C_SetPIN,
	P11_RPC_CALL_C_GetOperationState,
	P11_RPC_CALL_C_SetOperationState,
	P11_RPC_CALL_C_Login,
	P11_RPC_CALL_C_Logout,
	P11_RPC_CALL_C_CreateObject,
	P11_RPC_CALL_C_CopyObject,
	P11_RPC_CALL_C_DestroyObject,
	P11_RPC_CALL_C_GetObjectSize,
	P11_RPC_CALL_C_GetAttributeValue,
	P11_RPC_CALL_C_SetAttributeValue,
	P11_RPC_CALL_C_FindObjectsInit,
	P11_RPC_CALL_C_FindObjects,
	P11_RPC_CALL_C_FindObjectsFinal,
	P11_RPC_CALL_C_EncryptInit,
	P11_RPC_CALL_C_Encrypt,
	P11_RPC_CALL_C_EncryptUpdate,
	P11_RPC_CALL_C_EncryptFinal,
	P11_RPC_CALL_C_DecryptInit,
	P11_RPC_CALL_C_Decrypt,
	P11_RPC_CALL_C_DecryptUpdate,
	P11_RPC_CALL_C_DecryptFinal,
	P11_RPC_CALL_C_DigestInit,
	P11_RPC_CALL_C_Digest,
	P11_RPC_CALL_C_DigestUpdate,
	P11_RPC_CALL_C_DigestKey,
	P11_RPC_CALL_C_DigestFinal,
	P11_RPC_CALL_C_SignInit,
	P11_RPC_CALL_C_Sign,
	P11_RPC_CALL_C_SignUpdate,
	P11_RPC_CALL_C_SignFinal,
	P11_RPC_CALL_C_SignRecoverInit,
	P11_RPC_CALL_C_SignRecover,
	P11_RPC_CALL_C_VerifyInit,
	P11_RPC_CALL_C_Verify,
	P11_RPC_CALL_C_VerifyUpdate,
	P11_RPC_CALL_C_VerifyFinal,
	P11_RPC_CALL_C_VerifyRecoverInit,
	P11_RPC_CALL_C_VerifyRecover,
	P11_RPC_CALL_C_DigestEncryptUpdate,
	P11_RPC_CALL_C_DecryptDigestUpdate,
	P11_RPC_CALL_C_SignEncryptUpdate,
	P11_RPC_CALL_C_DecryptVerifyUpdate,
	P11_RPC_CALL_C_GenerateKey,
	P11_RPC_CALL_C_GenerateKeyPair,
	P11_RPC_CALL_C_WrapKey,
	P11_RPC_CALL_C_UnwrapKey,
	P11_RPC_CALL_C_DeriveKey,
	P11_RPC_CALL_C_SeedRandom,
	P11_RPC_CALL_C_GenerateRandom,
	P11_RPC_CALL_C_WaitForSlotEvent,
	/* PKCS #11 3.0 */
	P11_RPC_CALL_C_LoginUser,
	P11_RPC_CALL_C_SessionCancel,
	P11_RPC_CALL_C_MessageEncryptInit,
	P11_RPC_CALL_C_EncryptMessage,
	P11_RPC_CALL_C_EncryptMessageBegin,
	P11_RPC_CALL_C_EncryptMessageNext,
	P11_RPC_CALL_C_MessageEncryptFinal,
	P11_RPC_CALL_C_MessageDecryptInit,
	P11_RPC_CALL_C_DecryptMessage,
	P11_RPC_CALL_C_DecryptMessageBegin,
	P11_RPC_CALL_C_DecryptMessageNext,
	P11_RPC_CALL_C_MessageDecryptFinal,
	P11_RPC_CALL_C_MessageSignInit,
	P11_RPC_CALL_C_SignMessage,
	P11_RPC_CALL_C_SignMessageBegin,
	P11_RPC_CALL_C_SignMessageNext,
	P11_RPC_CALL_C_MessageSignFinal,
	P11_RPC_CALL_C_MessageVerifyInit,
	P11_RPC_CALL_C_VerifyMessage,
	P11_RPC_CALL_C_VerifyMessageBegin,
	P11_RPC_CALL_C_VerifyMessageNext,
	P11_RPC_CALL_C_MessageVerifyFinal,

	P11_RPC_CALL_MAX
};

typedef struct {
	int call_id;
	const char* name;
	const char* request;
	const char* response;
} p11_rpc_call;

/*
 *  a_ = prefix denotes array of _
 *  A  = CK_ATTRIBUTE
 *  f_ = prefix denotes buffer for _
 *  M  = CK_MECHANISM
 *  u  = CK_ULONG
 *  s  = space padded string
 *  v  = CK_VERSION
 *  y  = CK_BYTE
 *  z  = null terminated string
 */

static const p11_rpc_call p11_rpc_calls[] = {
	{ P11_RPC_CALL_ERROR,                  "ERROR",                  NULL,      "u"                    },
	{ P11_RPC_CALL_C_Initialize,           "C_Initialize",           "ayyay",   ""                     },
	{ P11_RPC_CALL_C_Finalize,             "C_Finalize",             "",        ""                     },
	{ P11_RPC_CALL_C_GetInfo,              "C_GetInfo",              "",        "vsusv"                },
	{ P11_RPC_CALL_C_GetSlotList,          "C_GetSlotList",          "yfu",     "au"                   },
	{ P11_RPC_CALL_C_GetSlotInfo,          "C_GetSlotInfo",          "u",       "ssuvv"                },
	{ P11_RPC_CALL_C_GetTokenInfo,         "C_GetTokenInfo",         "u",       "ssssuuuuuuuuuuuvvs"   },
	{ P11_RPC_CALL_C_GetMechanismList,     "C_GetMechanismList",     "ufu",     "au"                   },
	{ P11_RPC_CALL_C_GetMechanismInfo,     "C_GetMechanismInfo",     "uu",      "uuu"                  },
	{ P11_RPC_CALL_C_InitToken,            "C_InitToken",            "uayz",    ""                     },
	{ P11_RPC_CALL_C_OpenSession,          "C_OpenSession",          "uu",      "u"                    },
	{ P11_RPC_CALL_C_CloseSession,         "C_CloseSession",         "u",       ""                     },
	{ P11_RPC_CALL_C_CloseAllSessions,     "C_CloseAllSessions",     "u",       ""                     },
	{ P11_RPC_CALL_C_GetSessionInfo,       "C_GetSessionInfo",       "u",       "uuuu"                 },
	{ P11_RPC_CALL_C_InitPIN,              "C_InitPIN",              "uay",     ""                     },
	{ P11_RPC_CALL_C_SetPIN,               "C_SetPIN",               "uayay",   ""                     },
	{ P11_RPC_CALL_C_GetOperationState,    "C_GetOperationState",    "ufy",     "ay"                   },
	{ P11_RPC_CALL_C_SetOperationState,    "C_SetOperationState",    "uayuu",   ""                     },
	{ P11_RPC_CALL_C_Login,                "C_Login",                "uuay",    ""                     },
	{ P11_RPC_CALL_C_Logout,               "C_Logout",               "u",       ""                     },
	{ P11_RPC_CALL_C_CreateObject,         "C_CreateObject",         "uaA",     "u"                    },
	{ P11_RPC_CALL_C_CopyObject,           "C_CopyObject",           "uuaA",    "u"                    },
	{ P11_RPC_CALL_C_DestroyObject,        "C_DestroyObject",        "uu",      ""                     },
	{ P11_RPC_CALL_C_GetObjectSize,        "C_GetObjectSize",        "uu",      "u"                    },
	{ P11_RPC_CALL_C_GetAttributeValue,    "C_GetAttributeValue",    "uufA",    "aAu"                  },
	{ P11_RPC_CALL_C_SetAttributeValue,    "C_SetAttributeValue",    "uuaA",    ""                     },
	{ P11_RPC_CALL_C_FindObjectsInit,      "C_FindObjectsInit",      "uaA",     ""                     },
	{ P11_RPC_CALL_C_FindObjects,          "C_FindObjects",          "ufu",     "au"                   },
	{ P11_RPC_CALL_C_FindObjectsFinal,     "C_FindObjectsFinal",     "u",       ""                     },
	{ P11_RPC_CALL_C_EncryptInit,          "C_EncryptInit",          "uMu",     ""                     },
	{ P11_RPC_CALL_C_Encrypt,              "C_Encrypt",              "uayfy",   "ay"                   },
	{ P11_RPC_CALL_C_EncryptUpdate,        "C_EncryptUpdate",        "uayfy",   "ay"                   },
	{ P11_RPC_CALL_C_EncryptFinal,         "C_EncryptFinal",         "ufy",     "ay"                   },
	{ P11_RPC_CALL_C_DecryptInit,          "C_DecryptInit",          "uMu",     ""                     },
	{ P11_RPC_CALL_C_Decrypt,              "C_Decrypt",              "uayfy",   "ay"                   },
	{ P11_RPC_CALL_C_DecryptUpdate,        "C_DecryptUpdate",        "uayfy",   "ay"                   },
	{ P11_RPC_CALL_C_DecryptFinal,         "C_DecryptFinal",         "ufy",     "ay"                   },
	{ P11_RPC_CALL_C_DigestInit,           "C_DigestInit",           "uM",      ""                     },
	{ P11_RPC_CALL_C_Digest,               "C_Digest",               "uayfy",   "ay"                   },
	{ P11_RPC_CALL_C_DigestUpdate,         "C_DigestUpdate",         "uay",     ""                     },
	{ P11_RPC_CALL_C_DigestKey,            "C_DigestKey",            "uu",      ""                     },
	{ P11_RPC_CALL_C_DigestFinal,          "C_DigestFinal",          "ufy",     "ay"                   },
	{ P11_RPC_CALL_C_SignInit,             "C_SignInit",             "uMu",     ""                     },
	{ P11_RPC_CALL_C_Sign,                 "C_Sign",                 "uayfy",   "ay"                   },
	{ P11_RPC_CALL_C_SignUpdate,           "C_SignUpdate",           "uay",     ""                     },
	{ P11_RPC_CALL_C_SignFinal,            "C_SignFinal",            "ufy",     "ay"                   },
	{ P11_RPC_CALL_C_SignRecoverInit,      "C_SignRecoverInit",      "uMu",     ""                     },
	{ P11_RPC_CALL_C_SignRecover,          "C_SignRecover",          "uayfy",   "ay"                   },
	{ P11_RPC_CALL_C_VerifyInit,           "C_VerifyInit",           "uMu",     ""                     },
	{ P11_RPC_CALL_C_Verify,               "C_Verify",               "uayay",   ""                     },
	{ P11_RPC_CALL_C_VerifyUpdate,         "C_VerifyUpdate",         "uay",     ""                     },
	{ P11_RPC_CALL_C_VerifyFinal,          "C_VerifyFinal",          "uay",     ""                     },
	{ P11_RPC_CALL_C_VerifyRecoverInit,    "C_VerifyRecoverInit",    "uMu",     ""                     },
	{ P11_RPC_CALL_C_VerifyRecover,        "C_VerifyRecover",        "uayfy",   "ay"                   },
	{ P11_RPC_CALL_C_DigestEncryptUpdate,  "C_DigestEncryptUpdate",  "uayfy",   "ay"                   },
	{ P11_RPC_CALL_C_DecryptDigestUpdate,  "C_DecryptDigestUpdate",  "uayfy",   "ay"                   },
	{ P11_RPC_CALL_C_SignEncryptUpdate,    "C_SignEncryptUpdate",    "uayfy",   "ay"                   },
	{ P11_RPC_CALL_C_DecryptVerifyUpdate,  "C_DecryptVerifyUpdate",  "uayfy",   "ay"                   },
	{ P11_RPC_CALL_C_GenerateKey,          "C_GenerateKey",          "uMaA",    "u"                    },
	{ P11_RPC_CALL_C_GenerateKeyPair,      "C_GenerateKeyPair",      "uMaAaA",  "uu"                   },
	{ P11_RPC_CALL_C_WrapKey,              "C_WrapKey",              "uMuufy",  "ay"                   },
	{ P11_RPC_CALL_C_UnwrapKey,            "C_UnwrapKey",            "uMuayaA", "u"                    },
	{ P11_RPC_CALL_C_DeriveKey,            "C_DeriveKey",            "uMuaA",   "u"                    },
	{ P11_RPC_CALL_C_SeedRandom,           "C_SeedRandom",           "uay",     ""                     },
	{ P11_RPC_CALL_C_GenerateRandom,       "C_GenerateRandom",       "ufy",     "ay"                   },
	{ P11_RPC_CALL_C_WaitForSlotEvent,     "C_WaitForSlotEvent",     "u",       "u"                    },
	/* PKCS #11 3.0 */
	{ P11_RPC_CALL_C_LoginUser,            "C_LoginUser",            "uuayay",  ""                     },
	{ P11_RPC_CALL_C_SessionCancel,        "C_SessionCancel",        "uu",      ""                     },
	{ P11_RPC_CALL_C_MessageEncryptInit,   "C_MessageEncryptInit",   "uMu",     ""                     },
	{ P11_RPC_CALL_C_EncryptMessage,       "C_EncryptMessage",       "uayayayfy", "ay"                 },
	{ P11_RPC_CALL_C_EncryptMessageBegin,  "C_EncryptMessageBegin",  "uayay",   ""                     },
	{ P11_RPC_CALL_C_EncryptMessageNext,   "C_EncryptMessageNext",   "uayayfyu", "ay"                  },
	{ P11_RPC_CALL_C_MessageEncryptFinal,  "C_MessageEncryptFinal",  "u",       ""                     },
	{ P11_RPC_CALL_C_MessageDecryptInit,   "C_MessageDecryptInit",   "uMu",     ""                     },
	{ P11_RPC_CALL_C_DecryptMessage,       "C_DecryptMessage",       "uayayayfy", "ay"                 },
	{ P11_RPC_CALL_C_DecryptMessageBegin,  "C_DecryptMessageBegin",  "uayay",   ""                     },
	{ P11_RPC_CALL_C_DecryptMessageNext,   "C_DecryptMessageNext",   "uayayfyu", "ay"                  },
	{ P11_RPC_CALL_C_MessageDecryptFinal,  "C_MessageDecryptFinal",  "u",       ""                     },
	{ P11_RPC_CALL_C_MessageSignInit,      "C_MessageSignInit",      "uMu",     ""                     },
	{ P11_RPC_CALL_C_SignMessage,          "C_SignMessage",          "uayayfy", "ay"                   },
	{ P11_RPC_CALL_C_SignMessageBegin,     "C_SignMessageBegin",     "uay",     ""                     },
	{ P11_RPC_CALL_C_SignMessageNext,      "C_SignMessageNext",      "uayayfy", "ay"                   },
	{ P11_RPC_CALL_C_MessageSignFinal,     "C_MessageSignFinal",     "u",       ""                     },
	{ P11_RPC_CALL_C_MessageVerifyInit,    "C_MessageVerifyInit",    "uMu",     ""                     },
	{ P11_RPC_CALL_C_VerifyMessage,        "C_VerifyMessage",        "uayayay", ""                     },
	{ P11_RPC_CALL_C_VerifyMessageBegin,   "C_VerifyMessageBegin",   "uay",     ""                     },
	{ P11_RPC_CALL_C_VerifyMessageNext,    "C_VerifyMessageNext",    "uayayay", ""                     },
	{ P11_RPC_CALL_C_MessageVerifyFinal,   "C_MessageVerifyFinal",   "u",       ""                     },
};

#ifdef _DEBUG
#define P11_RPC_CHECK_CALLS() \
	{ int i; for (i = 0; i < P11_RPC_CALL_MAX; ++i) assert (p11_rpc_calls[i].call_id == i); }
#else
#define P11_RPC_CHECK_CALLS()
#endif

#define P11_RPC_HANDSHAKE \
	((unsigned char *)"PRIVATE-GNOME-KEYRING-PKCS11-PROTOCOL-V-1")
#define P11_RPC_HANDSHAKE_LEN \
	(strlen ((char *)P11_RPC_HANDSHAKE))

typedef enum _p11_rpc_value_type {
	P11_RPC_VALUE_BYTE = 0,
	P11_RPC_VALUE_ULONG,
	P11_RPC_VALUE_ATTRIBUTE_ARRAY,
	P11_RPC_VALUE_MECHANISM_TYPE_ARRAY,
	P11_RPC_VALUE_DATE,
	P11_RPC_VALUE_BYTE_ARRAY
} p11_rpc_value_type;

typedef void (*p11_rpc_value_encoder) (p11_buffer *, const void *, CK_ULONG);
typedef bool (*p11_rpc_value_decoder) (p11_buffer *, size_t *, void *, CK_ULONG *);

typedef enum _p11_rpc_message_type {
	P11_RPC_REQUEST = 1,
	P11_RPC_RESPONSE
} p11_rpc_message_type;

typedef struct {
	int call_id;
	p11_rpc_message_type call_type;
	const char *signature;
	p11_buffer *input;
	p11_buffer *output;
	size_t parsed;
	const char *sigverify;
	void *extra;
} p11_rpc_message;

void             p11_rpc_message_init                    (p11_rpc_message *msg,
                                                          p11_buffer *input,
                                                          p11_buffer *output);

void             p11_rpc_message_clear                   (p11_rpc_message *msg);

#define          p11_rpc_message_is_verified(msg)        (!(msg)->sigverify || (msg)->sigverify[0] == 0)

void *           p11_rpc_message_alloc_extra             (p11_rpc_message *msg,
                                                          size_t length);

void *           p11_rpc_message_alloc_extra_array       (p11_rpc_message *msg,
                                                          size_t nmemb,
                                                          size_t size);

bool             p11_rpc_message_prep                    (p11_rpc_message *msg,
                                                          int call_id,
                                                          p11_rpc_message_type type);

bool             p11_rpc_message_parse                   (p11_rpc_message *msg,
                                                          p11_rpc_message_type type);

bool             p11_rpc_message_verify_part             (p11_rpc_message *msg,
                                                          const char* part);

bool             p11_rpc_message_write_byte              (p11_rpc_message *msg,
                                                          CK_BYTE val);

bool             p11_rpc_message_write_ulong             (p11_rpc_message *msg,
                                                          CK_ULONG val);

bool             p11_rpc_message_write_zero_string       (p11_rpc_message *msg,
                                                          CK_UTF8CHAR *string);

bool             p11_rpc_message_write_space_string      (p11_rpc_message *msg,
                                                          CK_UTF8CHAR *buffer,
                                                                   CK_ULONG length);

bool             p11_rpc_message_write_byte_buffer       (p11_rpc_message *msg,
                                                          CK_ULONG count);

bool             p11_rpc_message_write_byte_buffer_null  (p11_rpc_message *msg,
                                                          CK_ULONG_PTR count);

bool             p11_rpc_message_write_byte_array        (p11_rpc_message *msg,
                                                          CK_BYTE_PTR arr,
                                                          CK_ULONG num);

bool             p11_rpc_message_write_ulong_buffer      (p11_rpc_message *msg,
                                                          CK_ULONG count);

bool             p11_rpc_message_write_ulong_array       (p11_rpc_message *msg,
                                                          CK_ULONG_PTR arr,
                                                          CK_ULONG num);

bool             p11_rpc_message_write_attribute_buffer  (p11_rpc_message *msg,
                                                          CK_ATTRIBUTE_PTR arr,
                                                          CK_ULONG num);

bool             p11_rpc_message_write_attribute_array   (p11_rpc_message *msg,
                                                          CK_ATTRIBUTE_PTR arr,
                                                          CK_ULONG num);

bool             p11_rpc_message_write_version           (p11_rpc_message *msg,
                                                          CK_VERSION* version);

bool             p11_rpc_message_read_byte               (p11_rpc_message *msg,
                                                          CK_BYTE* val);

bool             p11_rpc_message_read_ulong              (p11_rpc_message *msg,
                                                          CK_ULONG* val);

bool             p11_rpc_message_read_space_string       (p11_rpc_message *msg,
                                                          CK_UTF8CHAR* buffer,
                                                          CK_ULONG length);

bool             p11_rpc_message_read_version            (p11_rpc_message *msg,
                                                          CK_VERSION* version);

p11_buffer *     p11_rpc_buffer_new                      (size_t reserve);

p11_buffer *     p11_rpc_buffer_new_full                 (size_t reserve,
                                                          void * (* frealloc) (void *data, size_t size),
                                                          void (* ffree) (void *data));

void             p11_rpc_buffer_free                     (p11_buffer *buf);

void             p11_rpc_buffer_add_byte                 (p11_buffer *buf,
                                                          unsigned char value);

int              p11_rpc_buffer_get_byte                 (p11_buffer *buf,
                                                          size_t *offset,
                                                          unsigned char *val);

void             p11_rpc_buffer_encode_uint32            (unsigned char *data,
                                                          uint32_t value);

uint32_t         p11_rpc_buffer_decode_uint32            (unsigned char *data);

void             p11_rpc_buffer_add_uint32               (p11_buffer *buffer,
                                                          uint32_t value);

bool             p11_rpc_buffer_set_uint32               (p11_buffer *buffer,
                                                          size_t offset,
                                                          uint32_t value);

bool             p11_rpc_buffer_get_uint32               (p11_buffer *buf,
                                                          size_t *offset,
                                                          uint32_t *value);

void             p11_rpc_buffer_encode_uint16            (unsigned char *data,
                                                          uint16_t value);

uint16_t         p11_rpc_buffer_decode_uint16            (unsigned char *data);

void             p11_rpc_buffer_add_uint16               (p11_buffer *buffer,
                                                          uint16_t val);

bool             p11_rpc_buffer_set_uint16               (p11_buffer *buffer,
                                                          size_t offset,
                                                          uint16_t val);

bool             p11_rpc_buffer_get_uint16               (p11_buffer *buf,
                                                          size_t *offset,
                                                          uint16_t *val);

void             p11_rpc_buffer_add_byte_array           (p11_buffer *buffer,
                                                          const unsigned char *val,
                                                          size_t len);

bool             p11_rpc_buffer_get_byte_array           (p11_buffer *buf,
                                                          size_t *offset,
                                                          const unsigned char **val,
                                                          size_t *vlen);

void             p11_rpc_buffer_add_uint64               (p11_buffer *buffer,
                                                          uint64_t val);

bool             p11_rpc_buffer_get_uint64               (p11_buffer *buf,
                                                          size_t *offset,
                                                          uint64_t *val);

void             p11_rpc_buffer_add_attribute            (p11_buffer *buffer,
							  const CK_ATTRIBUTE *attr);

bool             p11_rpc_buffer_get_attribute            (p11_buffer *buffer,
							  size_t *offset,
							  CK_ATTRIBUTE *attr);

void             p11_rpc_buffer_add_byte_value           (p11_buffer *buffer,
							  const void *value,
							  CK_ULONG value_length);

bool             p11_rpc_buffer_get_byte_value           (p11_buffer *buffer,
							  size_t *offset,
							  void *value,
							  CK_ULONG *value_length);

void             p11_rpc_buffer_add_ulong_value          (p11_buffer *buffer,
							  const void *value,
							  CK_ULONG value_length);

bool             p11_rpc_buffer_get_ulong_value          (p11_buffer *buffer,
							  size_t *offset,
							  void *value,
							  CK_ULONG *value_length);

void             p11_rpc_buffer_add_attribute_array_value
                                                         (p11_buffer *buffer,
							  const void *value,
							  CK_ULONG value_length);

bool             p11_rpc_buffer_get_attribute_array_value
                                                         (p11_buffer *buffer,
							  size_t *offset,
							  void *value,
							  CK_ULONG *value_length);

void             p11_rpc_buffer_add_mechanism_type_array_value
                                                         (p11_buffer *buffer,
							  const void *value,
							  CK_ULONG value_length);

bool             p11_rpc_buffer_get_mechanism_type_array_value
                                                         (p11_buffer *buffer,
							  size_t *offset,
							  void *value,
							  CK_ULONG *value_length);

void             p11_rpc_buffer_add_date_value           (p11_buffer *buffer,
							  const void *value,
							  CK_ULONG value_length);

bool             p11_rpc_buffer_get_date_value           (p11_buffer *buffer,
							  size_t *offset,
							  void *value,
							  CK_ULONG *value_length);

void             p11_rpc_buffer_add_byte_array_value     (p11_buffer *buffer,
							  const void *value,
							  CK_ULONG value_length);

bool             p11_rpc_buffer_get_byte_array_value     (p11_buffer *buffer,
							  size_t *offset,
							  void *value,
							  CK_ULONG *value_length);

bool             p11_rpc_mechanism_is_supported          (CK_MECHANISM_TYPE mech);

void             p11_rpc_buffer_add_mechanism            (p11_buffer *buffer,
							  const CK_MECHANISM *mech);

bool             p11_rpc_buffer_get_mechanism            (p11_buffer *buffer,
							  size_t *offset,
							  CK_MECHANISM *mech);

void             p11_rpc_buffer_add_rsa_pkcs_pss_mechanism_value
                                                         (p11_buffer *buffer,
							  const void *value,
							  CK_ULONG value_length);

bool             p11_rpc_buffer_get_rsa_pkcs_pss_mechanism_value
                                                         (p11_buffer *buffer,
							  size_t *offset,
							  void *value,
							  CK_ULONG *value_length);

void             p11_rpc_buffer_add_rsa_pkcs_oaep_mechanism_value
                                                          (p11_buffer *buffer,
							   const void *value,
							   CK_ULONG value_length);

bool             p11_rpc_buffer_get_rsa_pkcs_oaep_mechanism_value
                                                          (p11_buffer *buffer,
							   size_t *offset,
							   void *value,
							   CK_ULONG *value_length);

void            p11_rpc_buffer_add_ecdh1_derive_mechanism_value
							  (p11_buffer *buffer,
							   const void *value,
							   CK_ULONG value_length);

bool            p11_rpc_buffer_get_ecdh1_derive_mechanism_value
							  (p11_buffer *buffer,
							   size_t *offset,
							   void *value,
							   CK_ULONG *value_length);

void            p11_rpc_buffer_add_ibm_attrbound_wrap_mechanism_value
							  (p11_buffer *buffer,
							   const void *value,
							   CK_ULONG value_length);

bool            p11_rpc_buffer_get_ibm_attrbound_wrap_mechanism_value
							  (p11_buffer *buffer,
							   size_t *offset,
							   void *value,
							   CK_ULONG *value_length);

void		p11_rpc_buffer_add_aes_iv_mechanism_value (p11_buffer *buffer,
							   const void *value,
							   CK_ULONG value_length);

bool		p11_rpc_buffer_get_aes_iv_mechanism_value (p11_buffer *buffer,
							   size_t *offset,
							   void *value,
							   CK_ULONG *value_length);

void		p11_rpc_buffer_add_aes_ctr_mechanism_value (p11_buffer *buffer,
							    const void *value,
							    CK_ULONG value_length);

bool		p11_rpc_buffer_get_aes_ctr_mechanism_value (p11_buffer *buffer,
							    size_t *offset,
							    void *value,
							    CK_ULONG *value_length);

void		p11_rpc_buffer_add_aes_gcm_mechanism_value (p11_buffer *buffer,
							    const void *value,
							    CK_ULONG value_length);

bool		p11_rpc_buffer_get_aes_gcm_mechanism_value (p11_buffer *buffer,
							    size_t *offset,
							    void *value,
							    CK_ULONG *value_length);

void		p11_rpc_buffer_add_des_iv_mechanism_value (p11_buffer *buffer,
							   const void *value,
							   CK_ULONG value_length);

bool		p11_rpc_buffer_get_des_iv_mechanism_value (p11_buffer *buffer,
							   size_t *offset,
							   void *value,
							   CK_ULONG *value_length);

void		p11_rpc_buffer_add_mac_general_mechanism_value
							  (p11_buffer *buffer,
							   const void *value,
							   CK_ULONG value_length);

bool		p11_rpc_buffer_get_mac_general_mechanism_value
							  (p11_buffer *buffer,
							   size_t *offset,
							   void *value,
							   CK_ULONG *value_length);

void		p11_rpc_buffer_add_dh_pkcs_derive_mechanism_value
							  (p11_buffer *buffer,
							   const void *value,
							   CK_ULONG value_length);

bool		p11_rpc_buffer_get_dh_pkcs_derive_mechanism_value
							  (p11_buffer *buffer,
							   size_t *offset,
							   void *value,
							   CK_ULONG *value_length);

#endif /* _RPC_MESSAGE_H */
