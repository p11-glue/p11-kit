/*
 * Copyright (c) 2011, Collabora Ltd.
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
 * Author: Stef Walter <stefw@collabora.co.uk>
 */

#include "config.h"

#include "compat.h"

#include <assert.h>
#include <ctype.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "p11-kit/p11-kit.h"
#include "p11-kit/uri.h"

typedef int (*operation) (int argc, char *argv[]);
int verbose = 0;

static void
usage (void)
{
	fprintf (stderr, "usage: p11-kit [-v] -l\n");
	fprintf (stderr, "       p11-kit -h\n");
	exit (2);
}

static const char HEXC_LOWER[] = "0123456789abcdef";

static char *
hex_encode (const unsigned char *data,
            size_t n_data)
{
	char *result;
	size_t i;
	size_t o;

	result = malloc (n_data * 3 + 1);
	if (result == NULL)
		return NULL;

	for (i = 0, o = 0; i < n_data; i++) {
		if (i > 0)
			result[o++] = ':';
		result[o++] = HEXC_LOWER[data[i] >> 4 & 0xf];
		result[o++] = HEXC_LOWER[data[i] & 0xf];
	}

	result[o] = 0;
	return result;
}

static int
is_ascii_string (const unsigned char *data,
                 size_t n_data)
{
	size_t i;

	for (i = 0; i < n_data; i++) {
		if (!isascii (data[i]) &&
		    (data[i] < 0x20 && !isspace (data[i])))
			return 0;
	}

	return 1;
}

static void
print_token_info (CK_FUNCTION_LIST_PTR module, CK_SLOT_ID slot_id)
{
	CK_TOKEN_INFO info;
	char *value;
	CK_RV rv;

	rv = (module->C_GetTokenInfo) (slot_id, &info);
	if (rv != CKR_OK) {
		warnx ("couldn't load module info: %s", p11_kit_strerror (rv));
		return;
	}

	value = p11_kit_space_strdup (info.label, sizeof (info.label));
	printf ("    token: %s\n", value);
	free (value);

	value = p11_kit_space_strdup (info.manufacturerID, sizeof (info.manufacturerID));
	printf ("        manufacturer: %s\n", value);
	free (value);

	value = p11_kit_space_strdup (info.model, sizeof (info.model));
	printf ("        model: %s\n", value);
	free (value);

	if (is_ascii_string (info.serialNumber, sizeof (info.serialNumber)))
		value = p11_kit_space_strdup (info.serialNumber, sizeof (info.serialNumber));
	else
		value = hex_encode (info.serialNumber, sizeof (info.serialNumber));
	printf ("        serial-number: %s\n", value);
	free (value);

	if (info.hardwareVersion.major || info.hardwareVersion.minor)
		printf ("        hardware-version: %d.%d\n",
		        info.hardwareVersion.major,
		        info.hardwareVersion.minor);

	if (info.firmwareVersion.major || info.firmwareVersion.minor)
		printf ("        firmware-version: %d.%d\n",
		        info.firmwareVersion.major,
		        info.firmwareVersion.minor);

	printf ("        flags:\n");
	#define X(x, y)   if (info.flags & (x)) printf ("               %s\n", (y))
	X(CKF_RNG, "rng");
	X(CKF_WRITE_PROTECTED, "write-protected");
	X(CKF_LOGIN_REQUIRED, "login-required");
	X(CKF_USER_PIN_INITIALIZED, "user-pin-initialized");
	X(CKF_RESTORE_KEY_NOT_NEEDED, "restore-key-not-needed");
	X(CKF_CLOCK_ON_TOKEN, "clock-on-tokne");
	X(CKF_PROTECTED_AUTHENTICATION_PATH, "protected-authentication-path");
	X(CKF_DUAL_CRYPTO_OPERATIONS, "dual-crypto-operations");
	X(CKF_TOKEN_INITIALIZED, "token-initialized");
	X(CKF_SECONDARY_AUTHENTICATION, "secondary-authentication");
	X(CKF_USER_PIN_COUNT_LOW, "user-pin-count-low");
	X(CKF_USER_PIN_FINAL_TRY, "user-pin-final-try");
	X(CKF_USER_PIN_LOCKED, "user-pin-locked");
	X(CKF_USER_PIN_TO_BE_CHANGED, "user-pin-to-be-changed");
	X(CKF_SO_PIN_COUNT_LOW, "so-pin-count-low");
	X(CKF_SO_PIN_FINAL_TRY, "so-pin-final-try");
	X(CKF_SO_PIN_LOCKED, "so-pin-locked");
	X(CKF_SO_PIN_TO_BE_CHANGED, "so-pin-to-be-changed");
	#undef X
}

static void
print_module_info (CK_FUNCTION_LIST_PTR module)
{
	CK_SLOT_ID slot_list[256];
	CK_ULONG i, count;
	CK_INFO info;
	char *value;
	CK_RV rv;

	rv = (module->C_GetInfo) (&info);
	if (rv != CKR_OK) {
		warnx ("couldn't load module info: %s", p11_kit_strerror (rv));
		return;
	}

	value = p11_kit_space_strdup (info.libraryDescription,
	                              sizeof (info.libraryDescription));
	printf ("    library-description: %s\n", value);
	free (value);

	value = p11_kit_space_strdup (info.manufacturerID,
	                              sizeof (info.manufacturerID));
	printf ("    library-manufacturer: %s\n", value);
	free (value);

	printf ("    library-version: %d.%d\n",
	        info.libraryVersion.major,
	        info.libraryVersion.minor);

	count = sizeof (slot_list) / sizeof (slot_list[0]);
	rv = (module->C_GetSlotList) (CK_TRUE, slot_list, &count);
	if (rv != CKR_OK) {
		warnx ("couldn't load module info: %s", p11_kit_strerror (rv));
		return;
	}

	for (i = 0; i < count; i++)
		print_token_info (module, slot_list[i]);
}

static int
list_modules (int argc, char *argv[])
{
	CK_FUNCTION_LIST_PTR *module_list;
	char *name;
	char *path;
	CK_RV rv;
	int i;

	if (argc != 0)
		usage ();

	rv = p11_kit_initialize_registered ();
	if (rv != CKR_OK)
		errx (1, "couldn't initialize registered modules: %s",
		      p11_kit_strerror (rv));

	module_list = p11_kit_registered_modules ();
	for (i = 0; module_list[i]; i++) {
		name = p11_kit_registered_module_to_name (module_list[i]);
		path = p11_kit_registered_option (module_list[i], "module");

		printf ("%s: %s\n",
		        name ? name : "(null)",
		        path ? path : "(null)");
		print_module_info (module_list[i]);

		free (name);
		free (path);
	}
	free (module_list);

	p11_kit_finalize_registered ();

	return 0;
}

int
main (int argc, char *argv[])
{
	operation oper = NULL;
	int opt;

	while ((opt = getopt (argc, argv, "lv")) != -1) {
		switch (opt) {
		case 'l':
			if (oper != NULL)
				usage ();
			oper = list_modules;
			break;
		case 'v':
			verbose = 1;
			putenv ("P11_KIT_DEBUG=all");
			break;
		case 'h':
		case '?':
			usage();
			break;
		}
	}

	if (!oper)
		usage ();

	argc -= optind;
	argv += optind;

	return (oper) (argc, argv);
}
