/*
 * Copyright (c) 2007, Stefan Walter
 * Copyright (c) 2013, Red Hat Inc.
 *
 * All rights reserved.
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
 *
 * CONTRIBUTORS
 *  Stef Walter <stef@memberwebs.com>
 */

#include "config.h"

#include "attrs.h"
#include "buffer.h"
#include "constants.h"
#include "debug.h"
#include "log.h"
#include "p11-kit.h"
#include "virtual.h"

#include <sys/types.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdarg.h>

bool p11_log_force = false;
bool p11_log_output = true;

typedef struct {
	p11_virtual virt;
	CK_X_FUNCTION_LIST *lower;
	p11_destroyer destroyer;
} LogData;

#define LOG_FLAG(buf, flags, had, flag) \
	if ((flags & flag) == flag) { \
		p11_buffer_add (buf, had ? " | " : " = ", 3); \
		p11_buffer_add (buf, #flag, -1); \
		had++; \
	}

static void
log_CKM (p11_buffer *buf,
         CK_MECHANISM_TYPE v)
{
	char temp[32];
	const char *string;

	string = p11_constant_name (p11_constant_mechanisms, v);
	if (string == NULL) {
		snprintf (temp, sizeof (temp), "CKM_0x%08lX", v);
		p11_buffer_add (buf, temp, -1);
	} else {
		p11_buffer_add (buf, string, -1);
	}
}

static void
log_CKS (p11_buffer *buf,
         CK_STATE v)
{
	char temp[32];
	const char *string;

	string = p11_constant_name (p11_constant_states, v);
	if (string == NULL) {
		snprintf (temp, sizeof (temp), "CKS_0x%08lX", v);
		p11_buffer_add (buf, temp, -1);
	} else {
		p11_buffer_add (buf, string, -1);
	}
}

static void
log_CKU (p11_buffer *buf,
         CK_USER_TYPE v)
{
	char temp[32];
	const char *string;

	string = p11_constant_name (p11_constant_users, v);
	if (string == NULL) {
		snprintf (temp, sizeof (temp), "CKU_0x%08lX", v);
		p11_buffer_add (buf, temp, -1);
	} else {
		p11_buffer_add (buf, string, -1);
	}
}

static void
log_CKR (p11_buffer *buf,
         CK_RV v)
{
	char temp[32];
	const char *string;

	string = p11_constant_name (p11_constant_returns, v);
	if (string == NULL) {
		snprintf (temp, sizeof (temp), "CKR_0x%08lX", v);
		p11_buffer_add (buf, temp, -1);
	} else {
		p11_buffer_add (buf, string, -1);
	}
}

static void
log_some_bytes (p11_buffer *buf,
                CK_BYTE_PTR arr,
                CK_ULONG num)
{
	CK_ULONG i;
	char temp[128];
	char *p, *e;
	CK_BYTE ch;

	if(!arr) {
		p11_buffer_add (buf, "NULL", 4);
		return;
	} else if (num == (CK_ULONG)-1) {
		p11_buffer_add (buf, "????", 4);
		return;
	}

	temp[0] = '\"';
	p = temp + 1;
	e = temp + (sizeof (temp) - 8);

	for(i = 0; i < num && p < e; ++i, ++p) {
		ch = arr[i];
		if (ch == '\t') {
			p[0] = '\\'; p[1] = 't';
			++p;
		} else if (ch == '\n') {
			p[0] = '\\'; p[1] = 'n';
			++p;
		} else if (ch == '\r') {
			p[0] = '\\'; p[1] = 'r';
			++p;
		} else if (ch >= 32 && ch < 127) {
			*p = ch;
		} else {
			p[0] = '\\';
			p[1] = 'x';
			sprintf(p + 2, "%02X", ch);
			p += 3;
		}
	}

	*p = 0;
	if (p >= e)
		strcpy (e, "...");
	strcat (p, "\"");
	p11_buffer_add (buf, temp, -1);
}

static void
log_pointer (p11_buffer *buf,
             const char *pref,
             const char *name,
             CK_VOID_PTR val,
             CK_RV status)
{
	char temp[32];

	if (status != CKR_OK)
		return;

	p11_buffer_add (buf, pref, -1);
	p11_buffer_add (buf, name, -1);
	p11_buffer_add (buf, " = ", 3);
	if (val == NULL) {
		p11_buffer_add (buf, "NULL\n", 5);
	} else {
		snprintf (temp, sizeof (temp), "0x%08lX\n", (unsigned long)(size_t)val);
		p11_buffer_add (buf, temp, -1);
	}
}

static void
log_attribute_types (p11_buffer *buf,
                     const char *pref,
                     const char *name,
                     CK_ATTRIBUTE_PTR arr,
                     CK_ULONG num,
                     CK_RV status)
{
	const char *string;
	char temp[32];
	CK_ULONG i;

	if (status == CKR_BUFFER_TOO_SMALL) {
		arr = NULL;
		status = CKR_OK;
	}
	if (status != CKR_OK)
		return;

	p11_buffer_add (buf, pref, -1);
	p11_buffer_add (buf, name, -1);
	p11_buffer_add (buf, " = ", 3);
	if (arr == NULL) {
		snprintf (temp, sizeof (temp), "(%lu) NONE\n", num);
		p11_buffer_add (buf, temp, -1);
	} else {
		snprintf (temp, sizeof (temp), "(%lu) [ ", num);
		p11_buffer_add (buf, temp, -1);
		for (i = 0; i < num; i++) {
			if (i > 0)
				p11_buffer_add (buf, ", ", 2);
			string = p11_constant_name (p11_constant_types, arr[i].type);
			if (string != NULL) {
				p11_buffer_add (buf, string, -1);
			} else {
				snprintf (temp, sizeof (temp), "CKA_0x%08lX", arr[i].type);
				p11_buffer_add (buf, temp, -1);
			}
		}

		p11_buffer_add (buf, " ]\n", 3);
	}
}

static void
log_attribute_array (p11_buffer *buf,
                     const char *pref,
                     const char *name,
                     CK_ATTRIBUTE_PTR arr,
                     CK_ULONG num,
                     CK_RV status)
{
	char temp[32];

	if (status == CKR_BUFFER_TOO_SMALL) {
		arr = NULL;
		status = CKR_OK;
	}
	if (status != CKR_OK)
		return;

	p11_buffer_add (buf, pref, -1);
	p11_buffer_add (buf, name, -1);
	p11_buffer_add (buf, " = ", 3);
	if (arr == NULL) {
		snprintf (temp, sizeof (temp), "(%lu) NONE\n", num);
		p11_buffer_add (buf, temp, -1);
	} else {
		p11_attrs_format (buf, arr, num);
		p11_buffer_add (buf, "\n", 1);
	}
}

static void
log_bool (p11_buffer *buf,
          const char *pref,
          const char *name,
          CK_BBOOL val,
          CK_RV status)
{
	if (status == CKR_OK) {
		p11_buffer_add (buf, pref, -1);
		p11_buffer_add (buf, name, -1);
		p11_buffer_add (buf, " = ", 3);
		p11_buffer_add (buf, val ? "CK_TRUE" : "CK_FALSE", -1);
		p11_buffer_add (buf, "\n", 1);
	}
}

static void
log_byte_array (p11_buffer *buf,
                const char *pref,
                const char *name,
                CK_BYTE_PTR arr,
                CK_ULONG_PTR num,
                CK_RV status)
{
	char temp[32];

	if (status == CKR_BUFFER_TOO_SMALL) {
		arr = NULL;
		status = CKR_OK;
	}

	if (status != CKR_OK)
		return;
	p11_buffer_add (buf, pref, -1);
	p11_buffer_add (buf, name, -1);
	p11_buffer_add (buf, " = ", 3);
	if (num == NULL) {
		p11_buffer_add (buf, "(?) NOTHING\n", -1);
	} else if (arr == NULL) {
		snprintf (temp, sizeof (temp), "(%lu) NOTHING\n", *num);
		p11_buffer_add (buf, temp, -1);
	} else {
		snprintf (temp, sizeof (temp), "(%lu) ", *num);
		p11_buffer_add (buf, temp, -1);
		log_some_bytes (buf, arr, *num);
		p11_buffer_add (buf, "\n", 1);
	}
}

static void
log_info (p11_buffer *buf,
          const char *pref,
          const char *name,
          CK_INFO_PTR info,
          CK_RV status)
{
	char temp[32];

	if (status != CKR_OK)
		return;
	if (info == NULL) {
		log_pointer (buf, pref, name, info, status);
	} else {
		p11_buffer_add (buf, pref, -1);
		p11_buffer_add (buf, name, -1);
		p11_buffer_add (buf, " = {\n", 5);
		p11_buffer_add (buf, "\tcryptokiVersion: ", -1);
		snprintf (temp, sizeof (temp), "%u.%u", (unsigned int)info->cryptokiVersion.major,
		          (unsigned int)info->cryptokiVersion.minor);
		p11_buffer_add (buf, temp, -1);
		p11_buffer_add (buf, "\n\tmanufacturerID: \"", -1);
		p11_buffer_add (buf, info->manufacturerID, p11_kit_space_strlen (info->manufacturerID, sizeof (info->manufacturerID)));
		p11_buffer_add (buf, "\"\n\tflags: ", -1);
		snprintf (temp, sizeof (temp), "%lX", info->flags);
		p11_buffer_add (buf, temp, -1);
		p11_buffer_add (buf, "\n\tlibraryDescription: \"", -1);
		p11_buffer_add (buf, info->libraryDescription, p11_kit_space_strlen (info->libraryDescription, sizeof (info->libraryDescription)));
		p11_buffer_add (buf, "\"\n\tlibraryVersion: ", -1);
		snprintf (temp, sizeof (temp), "%u.%u", (unsigned int)info->libraryVersion.major,
		          (unsigned int)info->libraryVersion.minor);
		p11_buffer_add (buf, temp, -1);
		p11_buffer_add (buf, "\n      }\n", -1);
	}
}

static void
log_pInitArgs (p11_buffer *buf,
               const char *pref,
               const char *name,
               CK_VOID_PTR pInitArgs,
               CK_RV status)
{
	char temp[32];
	int had = 0;

	if (status != CKR_OK)
		return;
	if (pInitArgs == NULL)
		log_pointer (buf, pref, name, pInitArgs, status);
	else {
		CK_C_INITIALIZE_ARGS *args = (CK_C_INITIALIZE_ARGS*)pInitArgs;
		p11_buffer_add (buf, pref, -1);
		p11_buffer_add (buf, name, -1);
		p11_buffer_add (buf, " = {\n", 5);
		p11_buffer_add (buf, "\tCreateMutex: ", -1);
		snprintf (temp, sizeof (temp), "0x%08lX", (unsigned long)(size_t)args->CreateMutex);
		p11_buffer_add (buf, temp, -1);
		p11_buffer_add (buf, "\n\tDestroyMutex: ", -1);
		snprintf (temp, sizeof (temp), "0x%08lX", (unsigned long)(size_t)args->DestroyMutex);
		p11_buffer_add (buf, temp, -1);
		p11_buffer_add (buf, "\n\tLockMutex: ", -1);
		snprintf (temp, sizeof (temp), "0x%08lX", (unsigned long)(size_t)args->LockMutex);
		p11_buffer_add (buf, temp, -1);
		p11_buffer_add (buf, "\n\tUnlockMutex: ", -1);
		snprintf (temp, sizeof (temp), "0x%08lX", (unsigned long)(size_t)args->UnlockMutex);
		p11_buffer_add (buf, temp, -1);
		p11_buffer_add (buf, "\n\tflags: ", -1);
		snprintf (temp, sizeof (temp), "%lX", args->flags);
		LOG_FLAG (buf, args->flags, had, CKF_OS_LOCKING_OK);
		p11_buffer_add (buf, "\n\treserved: ", -1);
		snprintf (temp, sizeof (temp), "0x%08lX", (unsigned long)(size_t)args->pReserved);
		p11_buffer_add (buf, temp, -1);
		p11_buffer_add (buf, "\n      }\n", -1);
	}
}

static void
log_mechanism_info (p11_buffer *buf,
                    const char *pref,
                    const char *name,
                    CK_MECHANISM_INFO_PTR info,
                    CK_RV status)
{
	char temp[32];
	int had = 0;

	if (status != CKR_OK)
		return;
	if (info == NULL) {
		log_pointer (buf, pref, name, info, status);
	} else {
		p11_buffer_add (buf, pref, -1);
		p11_buffer_add (buf, name, -1);
		p11_buffer_add (buf, " = {\n", 5);
		p11_buffer_add (buf, "\tulMinKeySize: ", -1);
		snprintf (temp, sizeof (temp), "%lu", info->ulMinKeySize);
		p11_buffer_add (buf, temp, -1);
		p11_buffer_add (buf, "\n\tulMaxKeySize: ", -1);
		snprintf (temp, sizeof (temp), "%lu", info->ulMaxKeySize);
		p11_buffer_add (buf, temp, -1);
		p11_buffer_add (buf, "\n\tflags: ", -1);
		snprintf (temp, sizeof (temp), "%lX", info->flags);
		p11_buffer_add (buf, temp, -1);
		LOG_FLAG (buf, info->flags, had, CKF_HW);
		LOG_FLAG (buf, info->flags, had, CKF_ENCRYPT);
		LOG_FLAG (buf, info->flags, had, CKF_DECRYPT);
		LOG_FLAG (buf, info->flags, had, CKF_DIGEST);
		LOG_FLAG (buf, info->flags, had, CKF_SIGN);
		LOG_FLAG (buf, info->flags, had, CKF_SIGN_RECOVER);
		LOG_FLAG (buf, info->flags, had, CKF_VERIFY);
		LOG_FLAG (buf, info->flags, had, CKF_VERIFY_RECOVER);
		LOG_FLAG (buf, info->flags, had, CKF_GENERATE);
		LOG_FLAG (buf, info->flags, had, CKF_GENERATE_KEY_PAIR);
		LOG_FLAG (buf, info->flags, had, CKF_WRAP);
		LOG_FLAG (buf, info->flags, had, CKF_UNWRAP);
		LOG_FLAG (buf, info->flags, had, CKF_DERIVE);
		LOG_FLAG (buf, info->flags, had, CKF_EXTENSION);
		p11_buffer_add (buf, "\n      }\n", -1);
	}
}

static void
log_mechanism (p11_buffer *buf,
               const char *pref,
               const char *name,
               CK_MECHANISM_PTR mech,
               CK_RV status)
{
	char temp[32];

	if (status != CKR_OK)
		return;
	p11_buffer_add (buf, pref, -1);
	p11_buffer_add (buf, name, -1);
	p11_buffer_add (buf, " = {\n", 5);
	p11_buffer_add (buf, "\tmechanism: ", -1);
	if (mech != NULL) {
		log_CKM (buf, mech->mechanism);
		p11_buffer_add (buf, "\n\tpParameter: ", -1);
		snprintf (temp, sizeof (temp), "(%lu) ", mech->ulParameterLen);
		p11_buffer_add (buf, temp, -1);
		log_some_bytes (buf, mech->pParameter, mech->ulParameterLen);
	} else {
		p11_buffer_add (buf, "NULL", 4);
	}
	p11_buffer_add (buf, "\n      }\n", -1);
}

static void
log_mechanism_type (p11_buffer *buf,
                    const char *pref,
                    const char *name,
                    CK_MECHANISM_TYPE val,
                    CK_RV status)
{
	if (status != CKR_OK)
		return;
	p11_buffer_add (buf, pref, -1);
	p11_buffer_add (buf, name, -1);
	p11_buffer_add (buf, " = ", 3);
	log_CKM (buf, val);
	p11_buffer_add (buf, "\n", 1);
}

static void
log_mechanism_type_array (p11_buffer *buf,
                          const char *pref,
                          const char *name,
                          CK_MECHANISM_TYPE_PTR arr,
                          CK_ULONG_PTR num,
                          CK_RV status)
{
	char temp[32];
	CK_ULONG i;

	if (status == CKR_BUFFER_TOO_SMALL) {
		arr = NULL;
		status = CKR_OK;
	}
	if (status != CKR_OK)
		return;

	p11_buffer_add (buf, pref, -1);
	p11_buffer_add (buf, name, -1);
	p11_buffer_add (buf, " = ", 3);
	if (num == NULL) {
		p11_buffer_add (buf, "(?) NO-VALUES\n", -1);
	} else if (arr == NULL) {
		snprintf (temp, sizeof (temp), "(%lu) NO-VALUES\n", *num);
		p11_buffer_add (buf, temp, -1);
	} else {
		snprintf (temp, sizeof (temp), "(%lu) [ ", *num);
		p11_buffer_add (buf, temp, -1);
		for(i = 0; i < *num; ++i) {
			if (i > 0)
				p11_buffer_add (buf, ", ", 2);
			log_CKM (buf, arr[i]);
		}
		p11_buffer_add (buf, " ]\n", 3);
	}
}

static void
log_session_info (p11_buffer *buf,
                  const char *pref,
                  const char *name,
                  CK_SESSION_INFO_PTR info,
                  CK_RV status)
{
	char temp[32];
	int had = 0;

	if (status != CKR_OK)
		return;
	if (info == NULL) {
		log_pointer (buf, pref, name, info, status);
	} else {
		p11_buffer_add (buf, pref, -1);
		p11_buffer_add (buf, name, -1);
		p11_buffer_add (buf, " = {\n", 5);
		p11_buffer_add (buf, "\tslotID: ", -1);
		snprintf (temp, sizeof (temp), "SL%lu", info->slotID);
		p11_buffer_add (buf, temp, -1);
		p11_buffer_add (buf, "\n\tstate: ", -1);
		log_CKS (buf, info->state);
		p11_buffer_add (buf, "\n\tflags: ", -1);
		snprintf (temp, sizeof (temp), "%lX", info->flags);
		p11_buffer_add (buf, temp, -1);
		LOG_FLAG (buf, info->flags, had, CKF_SERIAL_SESSION);
		LOG_FLAG (buf, info->flags, had, CKF_RW_SESSION);
		p11_buffer_add (buf, "\n\tulDeviceError: ", -1);
		snprintf (temp, sizeof (temp), "%lu", info->ulDeviceError);
		p11_buffer_add (buf, temp, -1);
		p11_buffer_add (buf, "\n      }\n", -1);
	}
}

static void
log_slot_info (p11_buffer *buf,
               const char *pref,
               const char *name,
               CK_SLOT_INFO_PTR info,
               CK_RV status)
{
	char temp[32];
	int had = 0;

	if (status != CKR_OK)
		return;
	if (info == NULL) {
		log_pointer (buf, pref, name, info, status);
	} else {
		p11_buffer_add (buf, pref, -1);
		p11_buffer_add (buf, name, -1);
		p11_buffer_add (buf, " = {\n", 5);
		p11_buffer_add (buf, "\tslotDescription: \"", -1);
		p11_buffer_add (buf, info->slotDescription, p11_kit_space_strlen (info->slotDescription, sizeof (info->slotDescription)));
		p11_buffer_add (buf, "\"\n\tmanufacturerID: \"", -1);
		p11_buffer_add (buf, info->manufacturerID, p11_kit_space_strlen (info->manufacturerID, sizeof (info->manufacturerID)));
		p11_buffer_add (buf, "\"\n\tflags: ", -1);
		snprintf (temp, sizeof (temp), "%lu", info->flags);
		p11_buffer_add (buf, temp, -1);
		LOG_FLAG (buf, info->flags, had, CKF_TOKEN_PRESENT);
		LOG_FLAG (buf, info->flags, had, CKF_REMOVABLE_DEVICE);
		LOG_FLAG (buf, info->flags, had, CKF_HW_SLOT);
		p11_buffer_add (buf, "\n\thardwareVersion: ", -1);
		snprintf (temp, sizeof (temp), "%u.%u", (unsigned int)info->hardwareVersion.major,
		          (unsigned int)info->hardwareVersion.minor);
		p11_buffer_add (buf, temp, -1);
		p11_buffer_add (buf, "\n\tfirmwareVersion: ", -1);
		snprintf (temp, sizeof (temp), "%u.%u", (unsigned int)info->firmwareVersion.major,
		          (unsigned int)info->firmwareVersion.minor);
		p11_buffer_add (buf, temp, -1);
		p11_buffer_add (buf, "\n      }\n", -1);
	}
}

static void
log_string (p11_buffer *buf,
            const char *pref,
            const char *name,
            CK_UTF8CHAR_PTR str,
            const CK_RV status)
{
	if (status != CKR_OK)
		return;
	if (str == NULL) {
		log_pointer (buf, pref, name, str, status);
	} else {
		p11_buffer_add (buf, pref, -1);
		p11_buffer_add (buf, name, -1);
		p11_buffer_add (buf, " = \"", 4);
		p11_buffer_add (buf, str, -1);
		p11_buffer_add (buf, "\"\n", 2);
	}
}

static void
log_token_number (p11_buffer *buf,
                  CK_ULONG number)
{
	char temp[32];

	if (number == 0) {
		p11_buffer_add (buf, "CK_UNAVAILABLE_INFORMATION", -1);
	} else if (number == (CK_ULONG)-1) {
		p11_buffer_add (buf, "CK_EFFECTIVELY_INFINITE", -1);
	} else {
		snprintf (temp, sizeof (temp), "%lu", number);
		p11_buffer_add (buf, temp, -1);
	}
}

static void
log_token_info (p11_buffer *buf,
                const char *pref,
                const char *name,
                CK_TOKEN_INFO_PTR info,
                CK_RV status)
{
	char temp[32];
	int had = 0;

	if (status != CKR_OK)
		return;
	if (info == NULL) {
		log_pointer (buf, pref, name, info, status);
	} else {
		p11_buffer_add (buf, pref, -1);
		p11_buffer_add (buf, name, -1);
		p11_buffer_add (buf, " = {\n", 5);
		p11_buffer_add (buf, "\tlabel: \"", -1);
		p11_buffer_add (buf, info->label, p11_kit_space_strlen (info->label, sizeof (info->label)));
		p11_buffer_add (buf, "\"\n\tmanufacturerID: \"", -1);
		p11_buffer_add (buf, info->manufacturerID, p11_kit_space_strlen (info->manufacturerID, sizeof (info->manufacturerID)));
		p11_buffer_add (buf, "\"\n\tmodel: \"", -1);
		p11_buffer_add (buf, info->model, p11_kit_space_strlen (info->model, sizeof (info->model)));
		p11_buffer_add (buf, "\"\n\tserialNumber: \"", -1);
		p11_buffer_add (buf, info->serialNumber, p11_kit_space_strlen (info->serialNumber, sizeof (info->serialNumber)));
		p11_buffer_add (buf, "\"\n\tflags: ", -1);
		snprintf (temp, sizeof (temp), "%lu", info->flags);
		p11_buffer_add (buf, temp, -1);
		LOG_FLAG (buf, info->flags, had, CKF_RNG);
		LOG_FLAG (buf, info->flags, had, CKF_WRITE_PROTECTED);
		LOG_FLAG (buf, info->flags, had, CKF_LOGIN_REQUIRED);
		LOG_FLAG (buf, info->flags, had, CKF_USER_PIN_INITIALIZED);
		LOG_FLAG (buf, info->flags, had, CKF_RESTORE_KEY_NOT_NEEDED);
		LOG_FLAG (buf, info->flags, had, CKF_CLOCK_ON_TOKEN);
		LOG_FLAG (buf, info->flags, had, CKF_PROTECTED_AUTHENTICATION_PATH);
		LOG_FLAG (buf, info->flags, had, CKF_DUAL_CRYPTO_OPERATIONS);
		LOG_FLAG (buf, info->flags, had, CKF_TOKEN_INITIALIZED);
		LOG_FLAG (buf, info->flags, had, CKF_SECONDARY_AUTHENTICATION);
		LOG_FLAG (buf, info->flags, had, CKF_USER_PIN_COUNT_LOW);
		LOG_FLAG (buf, info->flags, had, CKF_USER_PIN_FINAL_TRY);
		LOG_FLAG (buf, info->flags, had, CKF_USER_PIN_LOCKED);
		LOG_FLAG (buf, info->flags, had, CKF_USER_PIN_TO_BE_CHANGED);
		LOG_FLAG (buf, info->flags, had, CKF_SO_PIN_COUNT_LOW);
		LOG_FLAG (buf, info->flags, had, CKF_SO_PIN_FINAL_TRY);
		LOG_FLAG (buf, info->flags, had, CKF_SO_PIN_LOCKED);
		LOG_FLAG (buf, info->flags, had, CKF_SO_PIN_TO_BE_CHANGED);
		if (!had) {
			snprintf (temp, sizeof (temp), "%lu", info->flags);
			p11_buffer_add (buf, temp, -1);
		}

		p11_buffer_add (buf, "\n\tulMaxSessionCount: ", -1);
		log_token_number (buf, info->ulMaxSessionCount);
		p11_buffer_add (buf, "\n\tulSessionCount: ", -1);
		snprintf (temp, sizeof (temp), "%lu", info->ulSessionCount);
		p11_buffer_add (buf, temp, -1);
		p11_buffer_add (buf, "\n\tulMaxRwSessionCount: ", -1);
		log_token_number (buf, info->ulMaxSessionCount);
		p11_buffer_add (buf, "\n\tulRwSessionCount: ", -1);
		snprintf (temp, sizeof (temp), "%lu", info->ulRwSessionCount);
		p11_buffer_add (buf, temp, -1);
		p11_buffer_add (buf, "\n\tulMaxPinLen: ", -1);
		snprintf (temp, sizeof (temp), "%lu", info->ulMaxPinLen);
		p11_buffer_add (buf, temp, -1);
		p11_buffer_add (buf, "\n\tulMinPinLen: ", -1);
		snprintf (temp, sizeof (temp), "%lu", info->ulMinPinLen);
		p11_buffer_add (buf, temp, -1);
		p11_buffer_add (buf, "\n\tulTotalPublicMemory: ", -1);
		log_token_number (buf, info->ulMaxSessionCount);
		p11_buffer_add (buf, "\n\tulFreePublicMemory: ", -1);
		log_token_number (buf, info->ulMaxSessionCount);
		p11_buffer_add (buf, "\n\tulTotalPrivateMemory: ", -1);
		log_token_number (buf, info->ulMaxSessionCount);
		p11_buffer_add (buf, "\n\tulFreePrivateMemory: ", -1);
		log_token_number (buf, info->ulMaxSessionCount);
		p11_buffer_add (buf, "\n\tulFreePrivateMemory: ", -1);
		log_token_number (buf, info->ulMaxSessionCount);
		p11_buffer_add (buf, "\n\thardwareVersion: ", -1);
		snprintf (temp, sizeof (temp), "%u.%u", (unsigned int)info->hardwareVersion.major,
		          (unsigned int)info->hardwareVersion.minor);
		p11_buffer_add (buf, temp, -1);
		p11_buffer_add (buf, "\n\tfirmwareVersion: ", -1);
		snprintf (temp, sizeof (temp), "%u.%u", (unsigned int)info->firmwareVersion.major,
		          (unsigned int)info->firmwareVersion.minor);
		p11_buffer_add (buf, temp, -1);
		p11_buffer_add (buf, "\n\tutcTime: ", -1);
		p11_buffer_add (buf, (info->flags & CKF_CLOCK_ON_TOKEN) ? (const char*)info->utcTime : "", sizeof (info->utcTime));
		p11_buffer_add (buf, "\n      }\n", -1);
	}
}

static void
log_ulong (p11_buffer *buf,
           const char *pref,
           const char *name,
           CK_ULONG val,
           const char* npref,
           CK_RV status)
{
	char temp[32];

	if (!npref)
		npref = "";
	if (status == CKR_OK) {
		p11_buffer_add (buf, pref, -1);
		p11_buffer_add (buf, name, -1);
		p11_buffer_add (buf, " = ", 3);
		p11_buffer_add (buf, npref, -1);
		snprintf (temp, sizeof (temp), "%lu", val);
		p11_buffer_add (buf, temp, -1);
		p11_buffer_add (buf, "\n", 1);
	}
}

static void
log_ulong_array (p11_buffer *buf,
                 const char *pref,
                 const char *name,
                 CK_ULONG_PTR arr,
                 CK_ULONG_PTR num,
                 const char *npref,
                 CK_RV status)
{
	char temp[32];
	CK_ULONG i;

	if (status == CKR_BUFFER_TOO_SMALL) {
		arr = NULL;
		status = CKR_OK;
	}

	if (status != CKR_OK)
		return;
	if (npref == NULL)
		npref = "";
	p11_buffer_add (buf, pref, -1);
	p11_buffer_add (buf, name, -1);
	p11_buffer_add (buf, " = ", 3);
	if (num == NULL) {
		p11_buffer_add (buf, "(?) NO-VALUES\n", -1);
	} else if (arr == NULL) {
		snprintf (temp, sizeof (temp), "(%lu) NO-VALUES\n", *num);
		p11_buffer_add (buf, temp, -1);
	} else {
		snprintf (temp, sizeof (temp), "(%lu) [ ", *num);
		p11_buffer_add (buf, temp, -1);
		for (i = 0; i < *num; ++i) {
			if (i > 0)
				p11_buffer_add (buf, ", ", 2);
			p11_buffer_add (buf, npref, -1);
			snprintf (temp, sizeof (temp), "%lu", arr[i]);
			p11_buffer_add (buf, temp, -1);
		}
		p11_buffer_add (buf, " ]\n", 3);
	}
}

static void
log_ulong_pointer (p11_buffer *buf,
                   const char *pref,
                   const char *name,
                   CK_ULONG_PTR val,
                   const char *npref,
                   CK_RV status)
{
	char temp[32];

	if (status != CKR_OK)
		return;
	if (npref == NULL)
		npref = "";
	p11_buffer_add (buf, pref, -1);
	p11_buffer_add (buf, name, -1);
	p11_buffer_add (buf, " = ", 3);
	if (val == NULL) {
		p11_buffer_add (buf, "NULL\n", 5);
	} else {
		snprintf (temp, sizeof (temp), "0x%08lX", (unsigned long)(size_t)val);
		p11_buffer_add (buf, temp, -1);
		p11_buffer_add (buf, " = ", 3);
		p11_buffer_add (buf, npref, -1);
		snprintf (temp, sizeof (temp), "%lu", *val);
		p11_buffer_add (buf, temp, -1);
		p11_buffer_add (buf, "\n", 1);
	}
}

static void
log_user_type (p11_buffer *buf,
               const char *pref,
               const char *name,
               CK_USER_TYPE val,
               CK_RV status)
{
	if (status != CKR_OK)
		return;
	p11_buffer_add (buf, pref, -1);
	p11_buffer_add (buf, name, -1);
	p11_buffer_add (buf, " = ", 3);
	log_CKU (buf, val);
	p11_buffer_add (buf, "\n", 1);
}

static void
flush_buffer (p11_buffer *buf)
{
	if (p11_log_output) {
		fwrite (buf->data, 1, buf->len, stderr);
		fflush (stderr);
	}
	p11_buffer_reset (buf, 128);
}

#define BEGIN_CALL(name) \
	{ \
		LogData *_log = (LogData *)self; \
		const char* _name = "C_" #name; \
		p11_buffer _buf; \
		CK_X_##name _func = _log->lower->C_##name; \
		CK_RV _ret = CKR_OK; \
		p11_buffer_init_null (&_buf, 128); \
		return_val_if_fail (_func != NULL, CKR_DEVICE_ERROR); \
		p11_buffer_add (&_buf, _name, -1); \
		p11_buffer_add (&_buf, "\n", 1); \
		self = _log->lower;

#define PROCESS_CALL(args) \
		flush_buffer (&_buf); \
		_ret = (_func) args;

#define DONE_CALL \
		p11_buffer_add (&_buf, _name, -1); \
		p11_buffer_add (&_buf, " = ", 3); \
		log_CKR (&_buf, _ret); \
		p11_buffer_add (&_buf, "\n", 1); \
		flush_buffer (&_buf); \
		p11_buffer_uninit (&_buf); \
		return _ret; \
	}

#define LIN  "  IN: "
#define LOUT " OUT: "

#define IN_ATTRIBUTE_ARRAY(a, n) \
		log_attribute_types (&_buf, LIN, #a, a, n, CKR_OK);

#define IN_BOOL(a) \
		log_bool (&_buf, LIN, #a, a, CKR_OK);

#define IN_BYTE_ARRAY(a, n) \
		log_byte_array (&_buf, LIN, #a, a, &n, CKR_OK);

#define IN_HANDLE(a) \
		log_ulong (&_buf, LIN, #a, a, "H", CKR_OK);

#define IN_INIT_ARGS(a) \
		log_pInitArgs (&_buf, LIN, #a, a, CKR_OK);

#define IN_POINTER(a) \
		log_pointer (&_buf, LIN, #a, a, CKR_OK);

#define IN_MECHANISM(a) \
		log_mechanism (&_buf, LIN, #a, a, CKR_OK);

#define IN_MECHANISM_TYPE(a) \
		log_mechanism_type (&_buf, LIN, #a, a, CKR_OK);

#define IN_SESSION(a) \
		log_ulong (&_buf, LIN, #a, a, "S", CKR_OK);

#define IN_SLOT_ID(a) \
		log_ulong (&_buf, LIN, #a, a, "SL", CKR_OK);

#define IN_STRING(a) \
		log_string (&_buf, LIN, #a, a, CKR_OK);

#define IN_ULONG(a) \
		log_ulong (&_buf, LIN, #a, a, NULL, CKR_OK);

#define IN_ULONG_PTR(a) \
		log_ulong_pointer (&_buf, LIN, #a, a, NULL, CKR_OK);

#define IN_USER_TYPE(a) \
		log_user_type (&_buf, LIN, #a, a, CKR_OK);

#define OUT_ATTRIBUTE_ARRAY(a, n) \
		log_attribute_array (&_buf, LOUT, #a, a, n, _ret);

#define OUT_BYTE_ARRAY(a, n) \
		log_byte_array(&_buf, LOUT, #a, a, n, _ret);

#define OUT_HANDLE(a) \
		log_ulong_pointer (&_buf, LOUT, #a, a, "H", _ret);

#define OUT_HANDLE_ARRAY(a, n) \
		log_ulong_array (&_buf, LOUT, #a, a, n, "H", _ret);

#define OUT_INFO(a) \
		log_info (&_buf, LOUT, #a, a, _ret);

#define OUT_MECHANISM_INFO(a) \
		log_mechanism_info (&_buf, LOUT, #a, a, _ret);

#define OUT_MECHANISM_TYPE_ARRAY(a, n) \
		log_mechanism_type_array (&_buf, LOUT, #a, a, n, _ret);

#define OUT_POINTER(a) \
		log_pointer (&_buf, LOUT, #a, a, _ret);

#define OUT_SESSION(a) \
		log_ulong_pointer (&_buf, LOUT, #a, a, "S", _ret);

#define OUT_SESSION_INFO(a) \
		log_session_info (&_buf, LOUT, #a, a, _ret);

#define OUT_SLOT_ID_ARRAY(a, n) \
		log_ulong_array (&_buf, LOUT, #a, a, n, "SL", _ret);

#define OUT_SLOT_ID(a) \
		log_ulong_pointer (&_buf, LOUT, #a, a, "SL", _ret);

#define OUT_SLOT_INFO(a) \
		log_slot_info (&_buf, LOUT, #a, a, _ret);

#define OUT_TOKEN_INFO(a) \
		log_token_info (&_buf, LOUT, #a, a, _ret);

#define OUT_ULONG(a) \
		log_ulong_pointer (&_buf, LOUT, #a, a, NULL, _ret);

#define OUT_ULONG_ARRAY(a, n) \
		log_ulong_array (&_buf, LOUT, #a, a, n, NULL, _ret);



/* ---------------------------------------------------------------- */

static CK_RV
log_C_Initialize (CK_X_FUNCTION_LIST *self,
                  CK_VOID_PTR pInitArgs)
{
	BEGIN_CALL (Initialize)
		IN_INIT_ARGS (pInitArgs)
	PROCESS_CALL ((self, pInitArgs))
	DONE_CALL
}

static CK_RV
log_C_Finalize (CK_X_FUNCTION_LIST *self,
                CK_VOID_PTR pReserved)
{
	BEGIN_CALL (Finalize)
		IN_POINTER (pReserved)
	PROCESS_CALL ((self, pReserved))
	DONE_CALL
}

static CK_RV
log_C_GetInfo (CK_X_FUNCTION_LIST *self,
               CK_INFO_PTR pInfo)
{
	BEGIN_CALL (GetInfo)
	PROCESS_CALL ((self, pInfo))
		OUT_INFO (pInfo)
	DONE_CALL
}

static CK_RV
log_C_GetSlotList (CK_X_FUNCTION_LIST *self,
                   CK_BBOOL tokenPresent,
                   CK_SLOT_ID_PTR pSlotList,
                   CK_ULONG_PTR pulCount)
{
	BEGIN_CALL (GetSlotList)
		IN_BOOL (tokenPresent)
		IN_ULONG_PTR (pulCount)
	PROCESS_CALL ((self, tokenPresent, pSlotList, pulCount))
		OUT_SLOT_ID_ARRAY (pSlotList, pulCount)
	DONE_CALL
}

static CK_RV
log_C_GetSlotInfo (CK_X_FUNCTION_LIST *self,
                   CK_SLOT_ID slotID,
                   CK_SLOT_INFO_PTR pInfo)
{
	BEGIN_CALL (GetSlotInfo)
		IN_SLOT_ID (slotID)
	PROCESS_CALL ((self, slotID, pInfo))
		OUT_SLOT_INFO (pInfo)
	DONE_CALL
}

static CK_RV
log_C_GetTokenInfo (CK_X_FUNCTION_LIST *self,
                    CK_SLOT_ID slotID,
                    CK_TOKEN_INFO_PTR pInfo)
{
	BEGIN_CALL (GetTokenInfo)
		IN_SLOT_ID (slotID)
	PROCESS_CALL ((self, slotID, pInfo))
		OUT_TOKEN_INFO (pInfo)
	DONE_CALL
}

static CK_RV
log_C_GetMechanismList (CK_X_FUNCTION_LIST *self,
                        CK_SLOT_ID slotID,
                        CK_MECHANISM_TYPE_PTR pMechanismList,
                        CK_ULONG_PTR pulCount)
{
	BEGIN_CALL (GetMechanismList)
		IN_SLOT_ID (slotID)
		IN_ULONG_PTR (pulCount)
	PROCESS_CALL ((self, slotID, pMechanismList, pulCount))
		OUT_MECHANISM_TYPE_ARRAY (pMechanismList, pulCount)
	DONE_CALL
}

static CK_RV
log_C_GetMechanismInfo (CK_X_FUNCTION_LIST *self,
                        CK_SLOT_ID slotID,
                        CK_MECHANISM_TYPE type,
                        CK_MECHANISM_INFO_PTR pInfo)
{
	BEGIN_CALL (GetMechanismInfo)
		IN_SLOT_ID (slotID)
		IN_MECHANISM_TYPE (type)
	PROCESS_CALL ((self, slotID, type, pInfo))
		OUT_MECHANISM_INFO (pInfo)
	DONE_CALL
}

static CK_RV
log_C_InitToken (CK_X_FUNCTION_LIST *self,
                 CK_SLOT_ID slotID,
                 CK_UTF8CHAR_PTR pPin,
                 CK_ULONG ulPinLen,
                 CK_UTF8CHAR_PTR pLabel)
{
	BEGIN_CALL (InitToken)
		IN_SLOT_ID (slotID)
		IN_BYTE_ARRAY (pPin, ulPinLen)
		IN_STRING (pLabel)
	PROCESS_CALL ((self, slotID, pPin, ulPinLen, pLabel))
	DONE_CALL
}

static CK_RV
log_C_WaitForSlotEvent (CK_X_FUNCTION_LIST *self,
                        CK_FLAGS flags,
                        CK_SLOT_ID_PTR pSlot,
                        CK_VOID_PTR pReserved)
{
	char temp[32];
	int had = 0;

	BEGIN_CALL (WaitForSlotEvent)
		p11_buffer_add (&_buf, "  IN: flags = ", -1);
		snprintf (temp, sizeof (temp), "%lu", flags);
		p11_buffer_add (&_buf, temp, -1);
		LOG_FLAG (&_buf, flags, had, CKF_DONT_BLOCK);
		p11_buffer_add (&_buf, "\n", 1);
	PROCESS_CALL ((self, flags, pSlot, pReserved))
		OUT_SLOT_ID (pSlot)
		OUT_POINTER (pReserved)
	DONE_CALL
}

static CK_RV
log_C_OpenSession (CK_X_FUNCTION_LIST *self,
                   CK_SLOT_ID slotID,
                   CK_FLAGS flags,
                   CK_VOID_PTR pApplication,
                   CK_NOTIFY Notify,
                   CK_SESSION_HANDLE_PTR phSession)
{
	char temp[32];
	int had = 0;

	BEGIN_CALL (OpenSession)
		IN_SLOT_ID (slotID)
		p11_buffer_add (&_buf, "  IN: flags = ", -1);
		snprintf (temp, sizeof (temp), "%lu", flags);
		p11_buffer_add (&_buf, temp, -1);
		LOG_FLAG (&_buf, flags, had, CKF_SERIAL_SESSION);
		LOG_FLAG (&_buf, flags, had, CKF_RW_SESSION);
		p11_buffer_add (&_buf, "\n", 1);
		IN_POINTER (pApplication);
		IN_POINTER (Notify);
	PROCESS_CALL ((self, slotID, flags, pApplication, Notify, phSession));
		OUT_SESSION (phSession)
	DONE_CALL
}

static CK_RV
log_C_CloseSession (CK_X_FUNCTION_LIST *self,
                    CK_SESSION_HANDLE hSession)
{
	BEGIN_CALL (CloseSession)
		IN_SESSION (hSession)
	PROCESS_CALL ((self, hSession))
	DONE_CALL
}

static CK_RV
log_C_CloseAllSessions (CK_X_FUNCTION_LIST *self,
                        CK_SLOT_ID slotID)
{
	BEGIN_CALL (CloseAllSessions)
		IN_SLOT_ID (slotID)
	PROCESS_CALL ((self, slotID))
	DONE_CALL
}

static CK_RV
log_C_GetSessionInfo (CK_X_FUNCTION_LIST *self,
                      CK_SESSION_HANDLE hSession,
                      CK_SESSION_INFO_PTR pInfo)
{
	BEGIN_CALL (GetSessionInfo)
		IN_SESSION (hSession)
	PROCESS_CALL ((self, hSession, pInfo))
		OUT_SESSION_INFO (pInfo)
	DONE_CALL
}

static CK_RV
log_C_InitPIN (CK_X_FUNCTION_LIST *self,
               CK_SESSION_HANDLE hSession,
               CK_UTF8CHAR_PTR pPin,
               CK_ULONG ulPinLen)
{
	BEGIN_CALL (InitPIN)
		IN_SESSION (hSession)
		IN_BYTE_ARRAY (pPin, ulPinLen)
	PROCESS_CALL ((self, hSession, pPin, ulPinLen))
	DONE_CALL
}

static CK_RV
log_C_SetPIN (CK_X_FUNCTION_LIST *self,
              CK_SESSION_HANDLE hSession,
              CK_UTF8CHAR_PTR pOldPin,
              CK_ULONG ulOldLen,
              CK_UTF8CHAR_PTR pNewPin,
              CK_ULONG ulNewLen)
{
	BEGIN_CALL (SetPIN)
		IN_SESSION (hSession)
		IN_BYTE_ARRAY (pOldPin, ulOldLen)
		IN_BYTE_ARRAY (pNewPin, ulNewLen);
	PROCESS_CALL ((self, hSession, pOldPin, ulOldLen, pNewPin, ulNewLen))
	DONE_CALL
}

static CK_RV
log_C_GetOperationState (CK_X_FUNCTION_LIST *self,
                         CK_SESSION_HANDLE hSession,
                         CK_BYTE_PTR pOperationState,
                         CK_ULONG_PTR pulOperationStateLen)
{
	BEGIN_CALL (GetOperationState)
		IN_SESSION (hSession)
		IN_ULONG_PTR (pulOperationStateLen)
	PROCESS_CALL ((self, hSession, pOperationState, pulOperationStateLen))
		OUT_BYTE_ARRAY (pOperationState, pulOperationStateLen)
	DONE_CALL
}

static CK_RV
log_C_SetOperationState (CK_X_FUNCTION_LIST *self,
                         CK_SESSION_HANDLE hSession,
                         CK_BYTE_PTR pOperationState,
                         CK_ULONG ulOperationStateLen,
                         CK_OBJECT_HANDLE hEncryptionKey,
                         CK_OBJECT_HANDLE hAuthenticationKey)
{
	BEGIN_CALL (SetOperationState)
		IN_SESSION (hSession)
		IN_BYTE_ARRAY (pOperationState, ulOperationStateLen)
		IN_HANDLE (hEncryptionKey)
		IN_HANDLE (hAuthenticationKey)
	PROCESS_CALL ((self, hSession, pOperationState, ulOperationStateLen, hEncryptionKey, hAuthenticationKey))
	DONE_CALL
}

static CK_RV
log_C_Login (CK_X_FUNCTION_LIST *self,
             CK_SESSION_HANDLE hSession,
             CK_USER_TYPE userType,
             CK_UTF8CHAR_PTR pPin,
             CK_ULONG ulPinLen)
{
	BEGIN_CALL (Login)
		IN_SESSION (hSession)
		IN_USER_TYPE (userType)
		IN_BYTE_ARRAY (pPin, ulPinLen);
	PROCESS_CALL ((self, hSession, userType, pPin, ulPinLen))
	DONE_CALL
}

static CK_RV
log_C_Logout (CK_X_FUNCTION_LIST *self,
              CK_SESSION_HANDLE hSession)
{
	BEGIN_CALL (Logout)
		IN_SESSION (hSession)
	PROCESS_CALL ((self, hSession))
	DONE_CALL
}

static CK_RV
log_C_CreateObject (CK_X_FUNCTION_LIST *self,
                    CK_SESSION_HANDLE hSession,
                    CK_ATTRIBUTE_PTR pTemplate,
                    CK_ULONG ulCount,
                    CK_OBJECT_HANDLE_PTR phObject)
{
	BEGIN_CALL (CreateObject)
		IN_SESSION (hSession)
		IN_ATTRIBUTE_ARRAY (pTemplate, ulCount)
	PROCESS_CALL ((self, hSession, pTemplate, ulCount, phObject))
		OUT_HANDLE (phObject)
	DONE_CALL
}

static CK_RV
log_C_CopyObject (CK_X_FUNCTION_LIST *self,
                  CK_SESSION_HANDLE hSession,
                  CK_OBJECT_HANDLE hObject,
                  CK_ATTRIBUTE_PTR pTemplate,
                  CK_ULONG ulCount,
                  CK_OBJECT_HANDLE_PTR phNewObject)
{
	BEGIN_CALL (CopyObject)
		IN_SESSION (hSession)
		IN_HANDLE (hObject)
		IN_ATTRIBUTE_ARRAY (pTemplate, ulCount)
	PROCESS_CALL ((self, hSession, hObject, pTemplate, ulCount, phNewObject))
		OUT_HANDLE (phNewObject)
	DONE_CALL
}


static CK_RV
log_C_DestroyObject (CK_X_FUNCTION_LIST *self,
                     CK_SESSION_HANDLE hSession,
                     CK_OBJECT_HANDLE hObject)
{
	BEGIN_CALL (DestroyObject);
		IN_SESSION (hSession)
		IN_HANDLE (hObject)
	PROCESS_CALL ((self, hSession, hObject))
	DONE_CALL
}

static CK_RV
log_C_GetObjectSize (CK_X_FUNCTION_LIST *self,
                     CK_SESSION_HANDLE hSession,
                     CK_OBJECT_HANDLE hObject,
                     CK_ULONG_PTR size)
{
	BEGIN_CALL (GetObjectSize);
		IN_SESSION (hSession)
		IN_HANDLE (hObject)
	PROCESS_CALL ((self, hSession, hObject, size))
		OUT_ULONG (size)
	DONE_CALL
}

static CK_RV
log_C_GetAttributeValue (CK_X_FUNCTION_LIST *self,
                         CK_SESSION_HANDLE hSession,
                         CK_OBJECT_HANDLE hObject,
                         CK_ATTRIBUTE_PTR pTemplate,
                         CK_ULONG ulCount)
{
	BEGIN_CALL (GetAttributeValue)
		IN_SESSION (hSession)
		IN_HANDLE (hObject)
		IN_ATTRIBUTE_ARRAY (pTemplate, ulCount)
	PROCESS_CALL ((self, hSession, hObject, pTemplate, ulCount))
		OUT_ATTRIBUTE_ARRAY (pTemplate, ulCount)
	DONE_CALL
}

static CK_RV
log_C_SetAttributeValue (CK_X_FUNCTION_LIST *self,
                         CK_SESSION_HANDLE hSession,
                         CK_OBJECT_HANDLE hObject,
                         CK_ATTRIBUTE_PTR pTemplate,
                         CK_ULONG ulCount)
{
	BEGIN_CALL (SetAttributeValue)
		IN_SESSION (hSession)
		IN_HANDLE (hObject)
		IN_ATTRIBUTE_ARRAY (pTemplate, ulCount)
	PROCESS_CALL ((self, hSession, hObject, pTemplate, ulCount))
	DONE_CALL
}

static CK_RV
log_C_FindObjectsInit (CK_X_FUNCTION_LIST *self,
                       CK_SESSION_HANDLE hSession,
                       CK_ATTRIBUTE_PTR pTemplate,
                       CK_ULONG ulCount)
{
	BEGIN_CALL (FindObjectsInit)
		IN_SESSION (hSession)
		IN_ATTRIBUTE_ARRAY (pTemplate, ulCount)
	PROCESS_CALL ((self, hSession, pTemplate, ulCount))
	DONE_CALL
}

static CK_RV
log_C_FindObjects (CK_X_FUNCTION_LIST *self,
                   CK_SESSION_HANDLE hSession,
                   CK_OBJECT_HANDLE_PTR object,
                   CK_ULONG max_object_count,
                   CK_ULONG_PTR object_count)
{
	BEGIN_CALL (FindObjects)
		IN_SESSION (hSession)
		IN_ULONG (max_object_count)
	PROCESS_CALL ((self, hSession, object, max_object_count, object_count))
		OUT_HANDLE_ARRAY (object, object_count)
	DONE_CALL
}

static CK_RV
log_C_FindObjectsFinal (CK_X_FUNCTION_LIST *self,
                        CK_SESSION_HANDLE hSession)
{
	BEGIN_CALL (FindObjectsFinal)
		IN_SESSION (hSession)
	PROCESS_CALL ((self, hSession))
	DONE_CALL
}

static CK_RV
log_C_EncryptInit (CK_X_FUNCTION_LIST *self,
                   CK_SESSION_HANDLE hSession,
                   CK_MECHANISM_PTR pMechanism,
                   CK_OBJECT_HANDLE hKey)
{
	BEGIN_CALL (EncryptInit)
		IN_SESSION (hSession)
		IN_MECHANISM (pMechanism)
		IN_HANDLE (hKey)
	PROCESS_CALL ((self, hSession, pMechanism, hKey))
	DONE_CALL
}

static CK_RV
log_C_Encrypt (CK_X_FUNCTION_LIST *self,
               CK_SESSION_HANDLE hSession,
               CK_BYTE_PTR pData,
               CK_ULONG ulDataLen,
               CK_BYTE_PTR pEncryptedData,
               CK_ULONG_PTR pulEncryptedDataLen)
{
	BEGIN_CALL (Encrypt)
		IN_SESSION (hSession)
		IN_BYTE_ARRAY (pData, ulDataLen)
	PROCESS_CALL ((self, hSession, pData, ulDataLen, pEncryptedData, pulEncryptedDataLen))
		OUT_BYTE_ARRAY (pEncryptedData, pulEncryptedDataLen)
	DONE_CALL
}

static CK_RV
log_C_EncryptUpdate (CK_X_FUNCTION_LIST *self,
                     CK_SESSION_HANDLE hSession,
                     CK_BYTE_PTR pPart,
                     CK_ULONG ulPartLen,
                     CK_BYTE_PTR pEncryptedPart,
                     CK_ULONG_PTR pulEncryptedPartLen)
{
	BEGIN_CALL (EncryptUpdate)
		IN_SESSION (hSession)
		IN_BYTE_ARRAY (pPart, ulPartLen)
	PROCESS_CALL ((self, hSession, pPart, ulPartLen, pEncryptedPart, pulEncryptedPartLen))
		OUT_BYTE_ARRAY (pEncryptedPart, pulEncryptedPartLen)
	DONE_CALL
}

static CK_RV
log_C_EncryptFinal (CK_X_FUNCTION_LIST *self,
                    CK_SESSION_HANDLE hSession,
                    CK_BYTE_PTR pLastEncryptedPart,
                    CK_ULONG_PTR pulLastEncryptedPartLen)
{
	BEGIN_CALL (EncryptFinal)
		IN_SESSION (hSession)
	PROCESS_CALL ((self, hSession, pLastEncryptedPart, pulLastEncryptedPartLen))
		OUT_BYTE_ARRAY (pLastEncryptedPart, pulLastEncryptedPartLen)
	DONE_CALL
}

static CK_RV
log_C_DecryptInit (CK_X_FUNCTION_LIST *self,
                   CK_SESSION_HANDLE hSession,
                   CK_MECHANISM_PTR pMechanism,
                   CK_OBJECT_HANDLE hKey)
{
	BEGIN_CALL (DecryptInit)
		IN_SESSION (hSession)
		IN_MECHANISM (pMechanism)
		IN_HANDLE (hKey)
	PROCESS_CALL ((self, hSession, pMechanism, hKey))
	DONE_CALL
}

static CK_RV
log_C_Decrypt (CK_X_FUNCTION_LIST *self,
               CK_SESSION_HANDLE hSession,
               CK_BYTE_PTR pEncryptedData,
               CK_ULONG ulEncryptedDataLen,
               CK_BYTE_PTR pData,
               CK_ULONG_PTR pulDataLen)
{
	BEGIN_CALL (Decrypt)
		IN_SESSION (hSession)
		IN_BYTE_ARRAY (pEncryptedData, ulEncryptedDataLen)
	PROCESS_CALL ((self, hSession, pEncryptedData, ulEncryptedDataLen, pData, pulDataLen))
		OUT_BYTE_ARRAY (pData, pulDataLen)
	DONE_CALL
}

static CK_RV
log_C_DecryptUpdate (CK_X_FUNCTION_LIST *self,
                     CK_SESSION_HANDLE hSession,
                     CK_BYTE_PTR pEncryptedPart,
                     CK_ULONG ulEncryptedPartLen,
                     CK_BYTE_PTR pPart,
                     CK_ULONG_PTR pulPartLen)
{
	BEGIN_CALL (DecryptUpdate)
		IN_SESSION (hSession)
		IN_BYTE_ARRAY (pEncryptedPart, ulEncryptedPartLen)
	PROCESS_CALL ((self, hSession, pEncryptedPart, ulEncryptedPartLen, pPart, pulPartLen))
		OUT_BYTE_ARRAY (pPart, pulPartLen)
	DONE_CALL
}

static CK_RV
log_C_DecryptFinal (CK_X_FUNCTION_LIST *self,
                    CK_SESSION_HANDLE hSession,
                    CK_BYTE_PTR pLastPart,
                    CK_ULONG_PTR pulLastPartLen)
{
	BEGIN_CALL (DecryptFinal)
		IN_SESSION (hSession)
	PROCESS_CALL ((self, hSession, pLastPart, pulLastPartLen))
		OUT_BYTE_ARRAY (pLastPart, pulLastPartLen)
	DONE_CALL
}

static CK_RV
log_C_DigestInit (CK_X_FUNCTION_LIST *self,
                  CK_SESSION_HANDLE hSession,
                  CK_MECHANISM_PTR pMechanism)
{
	BEGIN_CALL (DigestInit)
		IN_SESSION (hSession)
		IN_MECHANISM (pMechanism)
	PROCESS_CALL ((self, hSession, pMechanism))
	DONE_CALL
}

static CK_RV
log_C_Digest (CK_X_FUNCTION_LIST *self,
              CK_SESSION_HANDLE hSession,
              CK_BYTE_PTR pData,
              CK_ULONG ulDataLen,
              CK_BYTE_PTR pDigest,
              CK_ULONG_PTR pulDigestLen)
{
	BEGIN_CALL (Digest)
		IN_SESSION (hSession)
		IN_BYTE_ARRAY (pData, ulDataLen)
	PROCESS_CALL ((self, hSession, pData, ulDataLen, pDigest, pulDigestLen))
		OUT_BYTE_ARRAY (pDigest, pulDigestLen)
	DONE_CALL
}

static CK_RV
log_C_DigestUpdate (CK_X_FUNCTION_LIST *self,
                    CK_SESSION_HANDLE hSession,
                    CK_BYTE_PTR pPart,
                    CK_ULONG ulPartLen)
{
	BEGIN_CALL (DigestUpdate)
		IN_SESSION (hSession)
		IN_BYTE_ARRAY (pPart, ulPartLen)
	PROCESS_CALL ((self, hSession, pPart, ulPartLen))
	DONE_CALL
}

static CK_RV
log_C_DigestKey (CK_X_FUNCTION_LIST *self,
                 CK_SESSION_HANDLE hSession,
                 CK_OBJECT_HANDLE hKey)
{
	BEGIN_CALL (DigestKey)
		IN_SESSION (hSession)
		IN_HANDLE (hKey)
	PROCESS_CALL ((self, hSession, hKey))
	DONE_CALL
}

static CK_RV
log_C_DigestFinal (CK_X_FUNCTION_LIST *self,
                   CK_SESSION_HANDLE hSession,
                   CK_BYTE_PTR pDigest,
                   CK_ULONG_PTR pulDigestLen)
{
	BEGIN_CALL (DigestFinal)
		IN_SESSION (hSession)
	PROCESS_CALL ((self, hSession, pDigest, pulDigestLen))
		OUT_BYTE_ARRAY (pDigest, pulDigestLen)
	DONE_CALL
}

static CK_RV
log_C_SignInit (CK_X_FUNCTION_LIST *self,
                CK_SESSION_HANDLE hSession,
                CK_MECHANISM_PTR pMechanism,
                CK_OBJECT_HANDLE hKey)
{
	BEGIN_CALL (SignInit)
		IN_SESSION (hSession)
		IN_MECHANISM (pMechanism)
		IN_HANDLE (hKey)
	PROCESS_CALL ((self, hSession, pMechanism, hKey))
	DONE_CALL
}

static CK_RV
log_C_Sign (CK_X_FUNCTION_LIST *self,
            CK_SESSION_HANDLE hSession,
            CK_BYTE_PTR pData,
            CK_ULONG ulDataLen,
            CK_BYTE_PTR pSignature,
            CK_ULONG_PTR pulSignatureLen)
{
	BEGIN_CALL (Sign)
		IN_SESSION (hSession)
		IN_BYTE_ARRAY (pData, ulDataLen)
	PROCESS_CALL ((self, hSession, pData, ulDataLen, pSignature, pulSignatureLen))
		OUT_BYTE_ARRAY (pSignature, pulSignatureLen)
	DONE_CALL
}

static CK_RV
log_C_SignUpdate (CK_X_FUNCTION_LIST *self,
                  CK_SESSION_HANDLE hSession,
                  CK_BYTE_PTR pPart,
                  CK_ULONG ulPartLen)
{
	BEGIN_CALL (SignUpdate)
		IN_SESSION (hSession)
		IN_BYTE_ARRAY (pPart, ulPartLen)
	PROCESS_CALL ((self, hSession, pPart, ulPartLen))
	DONE_CALL
}

static CK_RV
log_C_SignFinal (CK_X_FUNCTION_LIST *self,
                 CK_SESSION_HANDLE hSession,
                 CK_BYTE_PTR pSignature,
                 CK_ULONG_PTR pulSignatureLen)
{
	BEGIN_CALL (SignFinal)
		IN_SESSION (hSession)
	PROCESS_CALL ((self, hSession, pSignature, pulSignatureLen))
		OUT_BYTE_ARRAY (pSignature, pulSignatureLen)
	DONE_CALL
}

static CK_RV
log_C_SignRecoverInit (CK_X_FUNCTION_LIST *self,
                       CK_SESSION_HANDLE hSession,
                       CK_MECHANISM_PTR pMechanism,
                       CK_OBJECT_HANDLE hKey)
{
	BEGIN_CALL (SignRecoverInit)
		IN_SESSION (hSession)
		IN_MECHANISM (pMechanism)
		IN_HANDLE (hKey)
	PROCESS_CALL ((self, hSession, pMechanism, hKey))
	DONE_CALL
}

static CK_RV
log_C_SignRecover (CK_X_FUNCTION_LIST *self,
                   CK_SESSION_HANDLE hSession,
                   CK_BYTE_PTR pData,
                   CK_ULONG ulDataLen,
                   CK_BYTE_PTR pSignature,
                   CK_ULONG_PTR pulSignatureLen)
{
	BEGIN_CALL (SignRecover)
		IN_SESSION (hSession)
		IN_BYTE_ARRAY (pData, ulDataLen)
	PROCESS_CALL ((self, hSession, pData, ulDataLen, pSignature, pulSignatureLen))
		OUT_BYTE_ARRAY (pSignature, pulSignatureLen)
	DONE_CALL
}

static CK_RV
log_C_VerifyInit (CK_X_FUNCTION_LIST *self,
                  CK_SESSION_HANDLE hSession,
                  CK_MECHANISM_PTR pMechanism,
                  CK_OBJECT_HANDLE hKey)
{
	BEGIN_CALL (VerifyInit);
		IN_SESSION (hSession)
		IN_MECHANISM (pMechanism)
		IN_HANDLE (hKey)
	PROCESS_CALL ((self, hSession, pMechanism, hKey))
	DONE_CALL
}

static CK_RV
log_C_Verify (CK_X_FUNCTION_LIST *self,
              CK_SESSION_HANDLE hSession,
              CK_BYTE_PTR pData,
              CK_ULONG ulDataLen,
              CK_BYTE_PTR pSignature,
              CK_ULONG ulSignatureLen)
{
	BEGIN_CALL (Verify)
		IN_SESSION (hSession)
		IN_BYTE_ARRAY (pData, ulDataLen)
		IN_BYTE_ARRAY (pSignature, ulSignatureLen)
	PROCESS_CALL ((self, hSession, pData, ulDataLen, pSignature, ulSignatureLen))
	DONE_CALL
}

static CK_RV
log_C_VerifyUpdate (CK_X_FUNCTION_LIST *self,
                    CK_SESSION_HANDLE hSession,
                    CK_BYTE_PTR pPart,
                    CK_ULONG ulPartLen)
{
	BEGIN_CALL (VerifyUpdate)
		IN_SESSION (hSession)
		IN_BYTE_ARRAY (pPart, ulPartLen)
	PROCESS_CALL ((self, hSession, pPart, ulPartLen))
	DONE_CALL
}

static CK_RV
log_C_VerifyFinal (CK_X_FUNCTION_LIST *self,
                   CK_SESSION_HANDLE hSession,
                   CK_BYTE_PTR pSignature,
                   CK_ULONG ulSignatureLen)
{
	BEGIN_CALL (VerifyFinal)
		IN_SESSION (hSession)
		IN_BYTE_ARRAY (pSignature, ulSignatureLen);
	PROCESS_CALL ((self, hSession, pSignature, ulSignatureLen))
	DONE_CALL
}

static CK_RV
log_C_VerifyRecoverInit (CK_X_FUNCTION_LIST *self,
                         CK_SESSION_HANDLE hSession,
                         CK_MECHANISM_PTR pMechanism,
                         CK_OBJECT_HANDLE hKey)
{
	BEGIN_CALL (VerifyRecoverInit)
		IN_SESSION (hSession)
		IN_MECHANISM (pMechanism)
		IN_HANDLE (hKey)
	PROCESS_CALL ((self, hSession, pMechanism, hKey))
	DONE_CALL
}

static CK_RV
log_C_VerifyRecover (CK_X_FUNCTION_LIST *self,
                     CK_SESSION_HANDLE hSession,
                     CK_BYTE_PTR pSignature,
                     CK_ULONG ulSignatureLen,
                     CK_BYTE_PTR pData,
                     CK_ULONG_PTR pulDataLen)
{
	BEGIN_CALL (VerifyRecover)
		IN_SESSION (hSession)
		IN_BYTE_ARRAY (pSignature, ulSignatureLen)
	PROCESS_CALL ((self, hSession, pSignature, ulSignatureLen, pData, pulDataLen))
		OUT_BYTE_ARRAY (pData, pulDataLen)
	DONE_CALL
}

static CK_RV
log_C_DigestEncryptUpdate (CK_X_FUNCTION_LIST *self,
                           CK_SESSION_HANDLE hSession,
                           CK_BYTE_PTR pPart,
                           CK_ULONG ulPartLen,
                           CK_BYTE_PTR pEncryptedPart,
                           CK_ULONG_PTR pulEncryptedPartLen)
{
	BEGIN_CALL (DigestEncryptUpdate);
		IN_SESSION (hSession)
		IN_BYTE_ARRAY (pPart, ulPartLen)
	PROCESS_CALL ((self, hSession, pPart, ulPartLen, pEncryptedPart, pulEncryptedPartLen))
		OUT_BYTE_ARRAY (pEncryptedPart, pulEncryptedPartLen)
	DONE_CALL
}

static CK_RV
log_C_DecryptDigestUpdate (CK_X_FUNCTION_LIST *self,
                           CK_SESSION_HANDLE hSession,
                           CK_BYTE_PTR pEncryptedPart,
                           CK_ULONG ulEncryptedPartLen,
                           CK_BYTE_PTR pPart,
                           CK_ULONG_PTR pulPartLen)
{
	BEGIN_CALL (DecryptDigestUpdate)
		IN_SESSION (hSession)
		IN_BYTE_ARRAY (pEncryptedPart, ulEncryptedPartLen)
	PROCESS_CALL ((self, hSession, pEncryptedPart, ulEncryptedPartLen, pPart, pulPartLen))
		OUT_BYTE_ARRAY (pPart, pulPartLen)
	DONE_CALL
}

static CK_RV
log_C_SignEncryptUpdate (CK_X_FUNCTION_LIST *self,
                         CK_SESSION_HANDLE hSession,
                         CK_BYTE_PTR pPart,
                         CK_ULONG ulPartLen,
                         CK_BYTE_PTR pEncryptedPart,
                         CK_ULONG_PTR pulEncryptedPartLen)
{
	BEGIN_CALL (SignEncryptUpdate)
		IN_SESSION (hSession)
		IN_BYTE_ARRAY (pPart, ulPartLen)
	PROCESS_CALL ((self, hSession, pPart, ulPartLen, pEncryptedPart, pulEncryptedPartLen))
		OUT_BYTE_ARRAY (pEncryptedPart, pulEncryptedPartLen)
	DONE_CALL
}

static CK_RV
log_C_DecryptVerifyUpdate (CK_X_FUNCTION_LIST *self,
                           CK_SESSION_HANDLE hSession,
                           CK_BYTE_PTR pEncryptedPart,
                           CK_ULONG ulEncryptedPartLen,
                           CK_BYTE_PTR pPart,
                           CK_ULONG_PTR pulPartLen)
{
	BEGIN_CALL (DecryptVerifyUpdate)
		IN_SESSION (hSession)
		IN_BYTE_ARRAY (pEncryptedPart, ulEncryptedPartLen)
	PROCESS_CALL ((self, hSession, pEncryptedPart, ulEncryptedPartLen, pPart, pulPartLen))
		OUT_BYTE_ARRAY (pPart, pulPartLen)
	DONE_CALL
}

static CK_RV
log_C_GenerateKey (CK_X_FUNCTION_LIST *self,
                   CK_SESSION_HANDLE hSession,
                   CK_MECHANISM_PTR pMechanism,
                   CK_ATTRIBUTE_PTR pTemplate,
                   CK_ULONG ulCount,
                   CK_OBJECT_HANDLE_PTR phKey)
{
	BEGIN_CALL (GenerateKey)
		IN_SESSION (hSession)
		IN_MECHANISM (pMechanism)
		IN_ATTRIBUTE_ARRAY (pTemplate, ulCount)
	PROCESS_CALL ((self, hSession, pMechanism, pTemplate, ulCount, phKey))
		OUT_HANDLE (phKey)
	DONE_CALL
}

static CK_RV
log_C_GenerateKeyPair (CK_X_FUNCTION_LIST *self,
                       CK_SESSION_HANDLE hSession,
                       CK_MECHANISM_PTR pMechanism,
                       CK_ATTRIBUTE_PTR pPublicKeyTemplate,
                       CK_ULONG ulPublicKeyAttributeCount,
                       CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
                       CK_ULONG ulPrivateKeyAttributeCount,
                       CK_OBJECT_HANDLE_PTR phPublicKey,
                       CK_OBJECT_HANDLE_PTR phPrivateKey)
{
	BEGIN_CALL (GenerateKeyPair)
		IN_SESSION (hSession)
		IN_MECHANISM (pMechanism)
		IN_ATTRIBUTE_ARRAY (pPublicKeyTemplate, ulPublicKeyAttributeCount)
		IN_ATTRIBUTE_ARRAY (pPrivateKeyTemplate, ulPrivateKeyAttributeCount)
	PROCESS_CALL ((self, hSession, pMechanism, pPublicKeyTemplate, ulPublicKeyAttributeCount,
	               pPrivateKeyTemplate, ulPrivateKeyAttributeCount, phPublicKey, phPrivateKey))
		OUT_HANDLE (phPublicKey)
		OUT_HANDLE (phPrivateKey)
	DONE_CALL
}

static CK_RV
log_C_WrapKey (CK_X_FUNCTION_LIST *self,
               CK_SESSION_HANDLE hSession,
               CK_MECHANISM_PTR pMechanism,
               CK_OBJECT_HANDLE hWrappingKey,
               CK_OBJECT_HANDLE hKey,
               CK_BYTE_PTR pWrappedKey,
               CK_ULONG_PTR pulWrappedKeyLen)
{
	BEGIN_CALL (WrapKey)
		IN_SESSION (hSession)
		IN_MECHANISM (pMechanism)
		IN_HANDLE (hWrappingKey)
		IN_HANDLE (hKey)
	PROCESS_CALL ((self, hSession, pMechanism, hWrappingKey, hKey, pWrappedKey, pulWrappedKeyLen))
		OUT_BYTE_ARRAY (pWrappedKey, pulWrappedKeyLen)
	DONE_CALL
}

static CK_RV
log_C_UnwrapKey (CK_X_FUNCTION_LIST *self,
                 CK_SESSION_HANDLE hSession,
                 CK_MECHANISM_PTR pMechanism,
                 CK_OBJECT_HANDLE hUnwrappingKey,
                 CK_BYTE_PTR pWrappedKey,
                 CK_ULONG ulWrappedKeyLen,
                 CK_ATTRIBUTE_PTR pTemplate,
                 CK_ULONG ulAttributeCount,
                 CK_OBJECT_HANDLE_PTR phKey)
{
	BEGIN_CALL (UnwrapKey)
		IN_SESSION (hSession)
		IN_MECHANISM (pMechanism)
		IN_HANDLE (hUnwrappingKey)
		IN_BYTE_ARRAY (pWrappedKey, ulWrappedKeyLen)
		IN_ATTRIBUTE_ARRAY (pTemplate, ulAttributeCount)
	PROCESS_CALL ((self, hSession, pMechanism, hUnwrappingKey, pWrappedKey,
			ulWrappedKeyLen, pTemplate, ulAttributeCount, phKey))
		OUT_HANDLE (phKey)
	DONE_CALL
}

static CK_RV
log_C_DeriveKey (CK_X_FUNCTION_LIST *self,
                 CK_SESSION_HANDLE hSession,
                 CK_MECHANISM_PTR pMechanism,
                 CK_OBJECT_HANDLE hBaseKey,
                 CK_ATTRIBUTE_PTR pTemplate,
                 CK_ULONG ulAttributeCount,
                 CK_OBJECT_HANDLE_PTR phObject)
{
	BEGIN_CALL (DeriveKey)
		IN_SESSION (hSession)
		IN_MECHANISM (pMechanism)
		IN_HANDLE (hBaseKey)
		IN_ATTRIBUTE_ARRAY (pTemplate, ulAttributeCount)
	PROCESS_CALL ((self, hSession, pMechanism, hBaseKey, pTemplate, ulAttributeCount, phObject))
		OUT_HANDLE (phObject)
	DONE_CALL
}

static CK_RV
log_C_SeedRandom (CK_X_FUNCTION_LIST *self,
                  CK_SESSION_HANDLE hSession,
                  CK_BYTE_PTR pSeed,
                  CK_ULONG ulSeedLen)
{
	BEGIN_CALL (SeedRandom)
		IN_SESSION (hSession)
		IN_BYTE_ARRAY (pSeed, ulSeedLen);
	PROCESS_CALL ((self, hSession, pSeed, ulSeedLen))
	DONE_CALL
}

static CK_RV
log_C_GenerateRandom (CK_X_FUNCTION_LIST *self,
                      CK_SESSION_HANDLE hSession,
                      CK_BYTE_PTR pRandomData,
                      CK_ULONG ulRandomLen)
{
	BEGIN_CALL (GenerateRandom)
		IN_SESSION (hSession)
		IN_ULONG (ulRandomLen)
	PROCESS_CALL ((self, hSession, pRandomData, ulRandomLen))
		OUT_BYTE_ARRAY (pRandomData, &ulRandomLen)
	DONE_CALL
}

static CK_RV
log_C_LoginUser (CK_X_FUNCTION_LIST *self,
                 CK_SESSION_HANDLE session,
                 CK_USER_TYPE user_type,
                 CK_UTF8CHAR_PTR pin,
                 CK_ULONG pin_len,
                 CK_UTF8CHAR_PTR username,
                 CK_ULONG username_len)
{
	BEGIN_CALL (LoginUser)
		IN_SESSION (session)
		IN_USER_TYPE (user_type)
		IN_BYTE_ARRAY (pin, pin_len)
		IN_BYTE_ARRAY (username, username_len)
	PROCESS_CALL ((self, session, user_type, pin, pin_len, username, username_len))

	DONE_CALL
}

static CK_RV
log_C_SessionCancel (CK_X_FUNCTION_LIST *self,
                     CK_SESSION_HANDLE session,
                     CK_FLAGS flags)
{
	char temp[32];
	int had = 0;

	BEGIN_CALL (SessionCancel)
		IN_SESSION (session)
		p11_buffer_add (&_buf, "  IN: flags = ", -1);
		snprintf (temp, sizeof (temp), "%lu", flags);
		p11_buffer_add (&_buf, temp, -1);
		LOG_FLAG (&_buf, flags, had, CKF_MESSAGE_ENCRYPT);
		LOG_FLAG (&_buf, flags, had, CKF_MESSAGE_DECRYPT);
		LOG_FLAG (&_buf, flags, had, CKF_MESSAGE_SIGN);
		LOG_FLAG (&_buf, flags, had, CKF_MESSAGE_VERIFY);
		LOG_FLAG (&_buf, flags, had, CKF_FIND_OBJECTS);
		LOG_FLAG (&_buf, flags, had, CKF_ENCRYPT);
		LOG_FLAG (&_buf, flags, had, CKF_DECRYPT);
		LOG_FLAG (&_buf, flags, had, CKF_DIGEST);
		LOG_FLAG (&_buf, flags, had, CKF_SIGN);
		LOG_FLAG (&_buf, flags, had, CKF_SIGN_RECOVER);
		LOG_FLAG (&_buf, flags, had, CKF_VERIFY);
		LOG_FLAG (&_buf, flags, had, CKF_VERIFY_RECOVER);
		LOG_FLAG (&_buf, flags, had, CKF_GENERATE);
		LOG_FLAG (&_buf, flags, had, CKF_GENERATE_KEY_PAIR);
		LOG_FLAG (&_buf, flags, had, CKF_WRAP);
		LOG_FLAG (&_buf, flags, had, CKF_UNWRAP);
		LOG_FLAG (&_buf, flags, had, CKF_DERIVE);
		p11_buffer_add (&_buf, "\n", 1);
	PROCESS_CALL ((self, session, flags))
	DONE_CALL
}

static CK_RV
log_C_MessageEncryptInit (CK_X_FUNCTION_LIST *self,
                          CK_SESSION_HANDLE session,
                          CK_MECHANISM_PTR mechanism,
                          CK_OBJECT_HANDLE key)
{
	BEGIN_CALL (MessageEncryptInit)
		IN_SESSION (session)
		IN_MECHANISM (mechanism)
		IN_HANDLE (key)
	PROCESS_CALL ((self, session, mechanism, key))
	DONE_CALL
}

static CK_RV
log_C_EncryptMessage (CK_X_FUNCTION_LIST *self,
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
	BEGIN_CALL (EncryptMessage)
		IN_SESSION (session)
		IN_POINTER (parameter)
		IN_ULONG (parameter_len)
		IN_BYTE_ARRAY (associated_data, associated_data_len)
		IN_BYTE_ARRAY (plaintext, plaintext_len)
	PROCESS_CALL ((self, session, parameter, parameter_len, associated_data, associated_data_len,
	               plaintext, plaintext_len, ciphertext, ciphertext_len))
		OUT_BYTE_ARRAY (ciphertext, ciphertext_len)
	DONE_CALL
}

static CK_RV
log_C_EncryptMessageBegin (CK_X_FUNCTION_LIST *self,
                           CK_SESSION_HANDLE session,
                           CK_VOID_PTR parameter,
                           CK_ULONG parameter_len,
                           CK_BYTE_PTR associated_data,
                           CK_ULONG associated_data_len)
{
	BEGIN_CALL (EncryptMessageBegin)
		IN_SESSION (session)
		IN_POINTER (parameter)
		IN_ULONG (parameter_len)
		IN_BYTE_ARRAY (associated_data, associated_data_len)
	PROCESS_CALL ((self, session, parameter, parameter_len, associated_data, associated_data_len))
	DONE_CALL
}

static CK_RV
log_C_EncryptMessageNext (CK_X_FUNCTION_LIST *self,
                          CK_SESSION_HANDLE session,
                          CK_VOID_PTR parameter,
                          CK_ULONG parameter_len,
                          CK_BYTE_PTR plaintext_part,
                          CK_ULONG plaintext_part_len,
                          CK_BYTE_PTR ciphertext_part,
                          CK_ULONG_PTR ciphertext_part_len,
                          CK_FLAGS flags)
{
	char temp[32];
	int had = 0;

	BEGIN_CALL (EncryptMessageNext)
		IN_SESSION (session)
		IN_POINTER (parameter)
		IN_ULONG (parameter_len)
		IN_BYTE_ARRAY (plaintext_part, plaintext_part_len)
		p11_buffer_add (&_buf, "  IN: flags = ", -1);
		snprintf (temp, sizeof (temp), "%lu", flags);
		p11_buffer_add (&_buf, temp, -1);
		LOG_FLAG (&_buf, flags, had, CKF_END_OF_MESSAGE);
		p11_buffer_add (&_buf, "\n", 1);
	PROCESS_CALL ((self, session, parameter, parameter_len, plaintext_part, plaintext_part_len,
	               ciphertext_part, ciphertext_part_len, flags))
		OUT_BYTE_ARRAY (ciphertext_part, ciphertext_part_len)
	DONE_CALL
}

static CK_RV
log_C_MessageEncryptFinal (CK_X_FUNCTION_LIST *self,
                           CK_SESSION_HANDLE session)
{
	BEGIN_CALL (MessageEncryptFinal)
		IN_SESSION (session)
	PROCESS_CALL ((self, session))
	DONE_CALL
}

static CK_RV
log_C_MessageDecryptInit (CK_X_FUNCTION_LIST *self,
                          CK_SESSION_HANDLE session,
                          CK_MECHANISM_PTR mechanism,
                          CK_OBJECT_HANDLE key)
{
	BEGIN_CALL (MessageDecryptInit)
		IN_SESSION (session)
		IN_MECHANISM (mechanism)
		IN_HANDLE (key)
	PROCESS_CALL ((self, session, mechanism, key))
	DONE_CALL
}

static CK_RV
log_C_DecryptMessage (CK_X_FUNCTION_LIST *self,
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
	BEGIN_CALL (DecryptMessage)
		IN_SESSION (session)
		IN_POINTER (parameter)
		IN_ULONG (parameter_len)
		IN_BYTE_ARRAY (associated_data, associated_data_len)
		IN_BYTE_ARRAY (ciphertext, ciphertext_len)
	PROCESS_CALL ((self, session, parameter, parameter_len, associated_data, associated_data_len,
	               ciphertext, ciphertext_len, plaintext, plaintext_len));
		OUT_BYTE_ARRAY (plaintext, plaintext_len)
	DONE_CALL
}

static CK_RV
log_C_DecryptMessageBegin (CK_X_FUNCTION_LIST *self,
                           CK_SESSION_HANDLE session,
                           CK_VOID_PTR parameter,
                           CK_ULONG parameter_len,
                           CK_BYTE_PTR associated_data,
                           CK_ULONG associated_data_len)
{
	BEGIN_CALL (DecryptMessageBegin)
		IN_SESSION (session)
		IN_POINTER (parameter)
		IN_ULONG (parameter_len)
		IN_BYTE_ARRAY (associated_data, associated_data_len)
	PROCESS_CALL ((self, session, parameter, parameter_len, associated_data, associated_data_len))
	DONE_CALL
}

static CK_RV
log_C_DecryptMessageNext (CK_X_FUNCTION_LIST *self,
                          CK_SESSION_HANDLE session,
                          CK_VOID_PTR parameter,
                          CK_ULONG parameter_len,
                          CK_BYTE_PTR ciphertext_part,
                          CK_ULONG ciphertext_part_len,
                          CK_BYTE_PTR plaintext_part,
                          CK_ULONG_PTR plaintext_part_len,
                          CK_FLAGS flags)
{
	char temp[32];
	int had = 0;

	BEGIN_CALL (DecryptMessageNext)
		IN_SESSION (session)
		IN_POINTER (parameter)
		IN_ULONG (parameter_len)
		IN_BYTE_ARRAY (ciphertext_part, ciphertext_part_len)
		p11_buffer_add (&_buf, "  IN: flags = ", -1);
		snprintf (temp, sizeof (temp), "%lu", flags);
		p11_buffer_add (&_buf, temp, -1);
		LOG_FLAG (&_buf, flags, had, CKF_END_OF_MESSAGE);
		p11_buffer_add (&_buf, "\n", 1);
	PROCESS_CALL ((self, session, parameter, parameter_len, ciphertext_part, ciphertext_part_len,
	               plaintext_part, plaintext_part_len, flags))
		OUT_BYTE_ARRAY (plaintext_part, plaintext_part_len)
	DONE_CALL
}

static CK_RV
log_C_MessageDecryptFinal (CK_X_FUNCTION_LIST *self,
                           CK_SESSION_HANDLE session)
{
	BEGIN_CALL (MessageDecryptFinal)
		IN_SESSION (session)
	PROCESS_CALL ((self, session))
	DONE_CALL
}

static CK_RV
log_C_MessageSignInit (CK_X_FUNCTION_LIST *self,
                       CK_SESSION_HANDLE session,
                       CK_MECHANISM_PTR mechanism,
                       CK_OBJECT_HANDLE key)
{
	BEGIN_CALL (MessageSignInit)
		IN_SESSION (session)
		IN_MECHANISM (mechanism)
		IN_HANDLE (key)
	PROCESS_CALL ((self, session, mechanism, key))
	DONE_CALL
}

static CK_RV
log_C_SignMessage (CK_X_FUNCTION_LIST *self,
                   CK_SESSION_HANDLE session,
                   CK_VOID_PTR parameter,
                   CK_ULONG parameter_len,
                   CK_BYTE_PTR data,
                   CK_ULONG data_len,
                   CK_BYTE_PTR signature,
                   CK_ULONG_PTR signature_len)
{
	BEGIN_CALL (SignMessage)
		IN_SESSION (session)
		IN_POINTER (parameter)
		IN_ULONG (parameter_len)
		IN_BYTE_ARRAY (data, data_len)
	PROCESS_CALL ((self, session, parameter, parameter_len, data, data_len, signature, signature_len))
		OUT_BYTE_ARRAY (signature, signature_len)
	DONE_CALL
}

static CK_RV
log_C_SignMessageBegin (CK_X_FUNCTION_LIST *self,
                        CK_SESSION_HANDLE session,
                        CK_VOID_PTR parameter,
                        CK_ULONG parameter_len)
{
	BEGIN_CALL (SignMessageBegin)
		IN_SESSION (session)
		IN_POINTER (parameter)
		IN_ULONG (parameter_len)
	PROCESS_CALL ((self, session, parameter, parameter_len))
	DONE_CALL
}

static CK_RV
log_C_SignMessageNext (CK_X_FUNCTION_LIST *self,
                       CK_SESSION_HANDLE session,
                       CK_VOID_PTR parameter,
                       CK_ULONG parameter_len,
                       CK_BYTE_PTR data,
                       CK_ULONG data_len,
                       CK_BYTE_PTR signature,
                       CK_ULONG_PTR signature_len)
{
	BEGIN_CALL (SignMessageNext)
		IN_SESSION (session)
		IN_POINTER (parameter)
		IN_ULONG (parameter_len)
		IN_BYTE_ARRAY (data, data_len)
	PROCESS_CALL ((self, session, parameter, parameter_len, data, data_len, signature, signature_len))
		OUT_BYTE_ARRAY (signature, signature_len)
	DONE_CALL
}

static CK_RV
log_C_MessageSignFinal (CK_X_FUNCTION_LIST *self,
                        CK_SESSION_HANDLE session)
{
	BEGIN_CALL (MessageSignFinal)
		IN_SESSION (session)
	PROCESS_CALL ((self, session))
	DONE_CALL
}

static CK_RV
log_C_MessageVerifyInit (CK_X_FUNCTION_LIST *self,
                         CK_SESSION_HANDLE session,
                         CK_MECHANISM_PTR mechanism,
                         CK_OBJECT_HANDLE key)
{
	BEGIN_CALL (MessageVerifyInit)
		IN_SESSION (session)
		IN_MECHANISM (mechanism)
		IN_HANDLE (key)
	PROCESS_CALL ((self, session, mechanism, key))
	DONE_CALL
}

static CK_RV
log_C_VerifyMessage (CK_X_FUNCTION_LIST *self,
                     CK_SESSION_HANDLE session,
                     CK_VOID_PTR parameter,
                     CK_ULONG parameter_len,
                     CK_BYTE_PTR data,
                     CK_ULONG data_len,
                     CK_BYTE_PTR signature,
                     CK_ULONG signature_len)
{
	BEGIN_CALL (VerifyMessage)
		IN_SESSION (session)
		IN_POINTER (parameter)
		IN_ULONG (parameter_len)
		IN_BYTE_ARRAY (data, data_len)
		IN_BYTE_ARRAY (signature, signature_len)
	PROCESS_CALL ((self, session, parameter, parameter_len, data, data_len,
	               signature, signature_len))
	DONE_CALL
}

static CK_RV
log_C_VerifyMessageBegin (CK_X_FUNCTION_LIST *self,
                          CK_SESSION_HANDLE session,
                          CK_VOID_PTR parameter,
                          CK_ULONG parameter_len)
{
	BEGIN_CALL (VerifyMessageBegin)
		IN_SESSION (session)
		IN_POINTER (parameter)
		IN_ULONG (parameter_len)
	PROCESS_CALL ((self, session, parameter, parameter_len))
	DONE_CALL
}

static CK_RV
log_C_VerifyMessageNext (CK_X_FUNCTION_LIST *self,
                         CK_SESSION_HANDLE session,
                         CK_VOID_PTR parameter,
                         CK_ULONG parameter_len,
                         CK_BYTE_PTR data,
                         CK_ULONG data_len,
                         CK_BYTE_PTR signature,
                         CK_ULONG signature_len)
{
	BEGIN_CALL (VerifyMessageNext)
		IN_SESSION (session)
		IN_POINTER (parameter)
		IN_ULONG (parameter_len)
		IN_BYTE_ARRAY (data, data_len)
		IN_BYTE_ARRAY (signature, signature_len)
	PROCESS_CALL ((self, session, parameter, parameter_len, data, data_len,
	               signature, signature_len))
	DONE_CALL
}

static CK_RV
log_C_MessageVerifyFinal (CK_X_FUNCTION_LIST *self,
                          CK_SESSION_HANDLE session)
{
	BEGIN_CALL (MessageVerifyFinal)
		IN_SESSION (session)
	PROCESS_CALL ((self, session))
	DONE_CALL
}

static CK_X_FUNCTION_LIST log_functions = {
	{ -1, -1 },
	log_C_Initialize,
	log_C_Finalize,
	log_C_GetInfo,
	log_C_GetSlotList,
	log_C_GetSlotInfo,
	log_C_GetTokenInfo,
	log_C_GetMechanismList,
	log_C_GetMechanismInfo,
	log_C_InitToken,
	log_C_InitPIN,
	log_C_SetPIN,
	log_C_OpenSession,
	log_C_CloseSession,
	log_C_CloseAllSessions,
	log_C_GetSessionInfo,
	log_C_GetOperationState,
	log_C_SetOperationState,
	log_C_Login,
	log_C_Logout,
	log_C_CreateObject,
	log_C_CopyObject,
	log_C_DestroyObject,
	log_C_GetObjectSize,
	log_C_GetAttributeValue,
	log_C_SetAttributeValue,
	log_C_FindObjectsInit,
	log_C_FindObjects,
	log_C_FindObjectsFinal,
	log_C_EncryptInit,
	log_C_Encrypt,
	log_C_EncryptUpdate,
	log_C_EncryptFinal,
	log_C_DecryptInit,
	log_C_Decrypt,
	log_C_DecryptUpdate,
	log_C_DecryptFinal,
	log_C_DigestInit,
	log_C_Digest,
	log_C_DigestUpdate,
	log_C_DigestKey,
	log_C_DigestFinal,
	log_C_SignInit,
	log_C_Sign,
	log_C_SignUpdate,
	log_C_SignFinal,
	log_C_SignRecoverInit,
	log_C_SignRecover,
	log_C_VerifyInit,
	log_C_Verify,
	log_C_VerifyUpdate,
	log_C_VerifyFinal,
	log_C_VerifyRecoverInit,
	log_C_VerifyRecover,
	log_C_DigestEncryptUpdate,
	log_C_DecryptDigestUpdate,
	log_C_SignEncryptUpdate,
	log_C_DecryptVerifyUpdate,
	log_C_GenerateKey,
	log_C_GenerateKeyPair,
	log_C_WrapKey,
	log_C_UnwrapKey,
	log_C_DeriveKey,
	log_C_SeedRandom,
	log_C_GenerateRandom,
	log_C_WaitForSlotEvent,
	/* PKCS #11 3.0 */
	log_C_LoginUser,
	log_C_SessionCancel,
	log_C_MessageEncryptInit,
	log_C_EncryptMessage,
	log_C_EncryptMessageBegin,
	log_C_EncryptMessageNext,
	log_C_MessageEncryptFinal,
	log_C_MessageDecryptInit,
	log_C_DecryptMessage,
	log_C_DecryptMessageBegin,
	log_C_DecryptMessageNext,
	log_C_MessageDecryptFinal,
	log_C_MessageSignInit,
	log_C_SignMessage,
	log_C_SignMessageBegin,
	log_C_SignMessageNext,
	log_C_MessageSignFinal,
	log_C_MessageVerifyInit,
	log_C_VerifyMessage,
	log_C_VerifyMessageBegin,
	log_C_VerifyMessageNext,
	log_C_MessageVerifyFinal
};

void
p11_log_release (void *data)
{
	LogData *log = (LogData *)data;

	return_if_fail (data != NULL);
	p11_virtual_uninit (&log->virt);
	free (log);
}

p11_virtual *
p11_log_subclass (p11_virtual *lower,
                  p11_destroyer destroyer)
{
	LogData *log;

	log = calloc (1, sizeof (LogData));
	return_val_if_fail (log != NULL, NULL);

	p11_virtual_init (&log->virt, &log_functions, lower, destroyer);
	log->lower = &lower->funcs;
	return &log->virt;
}
