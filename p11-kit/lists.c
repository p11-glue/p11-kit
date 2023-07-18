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
#include "debug.h"

#include <assert.h>
#include <ctype.h>
#include <limits.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "message.h"
#include "p11-kit.h"
#include "print.h"
#include "tool.h"
#include "uri.h"

#ifdef ENABLE_NLS
#include <libintl.h>
#define _(x) dgettext(PACKAGE_NAME, x)
#else
#define _(x) (x)
#endif

int p11_kit_list_modules (int argc,
                          char *argv[]);

bool verbose = false;

static const char HEXC_LOWER[] = "0123456789abcdef";

static char *
hex_encode (const unsigned char *data,
            size_t n_data)
{
	char *result;
	size_t i;
	size_t o;

	if ((SIZE_MAX - 1) / 3 < n_data)
		return NULL;
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

static bool
is_ascii_string (const unsigned char *data,
                 size_t n_data)
{
	size_t i;

	for (i = 0; i < n_data; i++) {
		if (!isascii (data[i]) &&
		    (data[i] < 0x20 && !isspace (data[i])))
			return false;
	}

	return true;
}

static void
print_token_uri (p11_list_printer *printer, CK_FUNCTION_LIST_PTR module, CK_TOKEN_INFO *info)
{
	int ret;
	char *str;
	P11KitUri *uri;

	uri = p11_kit_uri_new ();
	if (uri == NULL) {
		p11_message (_("failed to allocate memory for URI"));
		return;
	}

	str = p11_kit_module_get_name (module);
	p11_kit_uri_set_module_name (uri, str);
	free (str);

	str = p11_kit_config_option (module, "module");
	p11_kit_uri_set_module_path (uri, str);
	free (str);

	p11_kit_uri_set_token_info (uri, info);

	ret = p11_kit_uri_format (uri, P11_KIT_URI_FOR_TOKEN, &str);
	if (ret != P11_KIT_URI_OK) {
		p11_message (_("couldn't format URI into string: %s"), p11_kit_uri_message (ret));
		p11_kit_uri_free (uri);
		return;
	}

	p11_list_printer_write_value (printer, "uri", "%s", str);

	free (str);
	p11_kit_uri_free (uri);
}

static void
print_module_uri (p11_list_printer *printer, CK_FUNCTION_LIST_PTR module, CK_INFO *info)
{
	int ret;
	char *str;
	P11KitUri *uri;

	uri = p11_kit_uri_new ();
	if (uri == NULL) {
		p11_message (_("failed to allocate memory for URI"));
		return;
	}

	str = p11_kit_module_get_name (module);
	p11_kit_uri_set_module_name (uri, str);
	free (str);

	str = p11_kit_config_option (module, "module");
	p11_kit_uri_set_module_path (uri, str);
	free (str);

	p11_kit_uri_set_module_info (uri, info);

	ret = p11_kit_uri_format (uri, P11_KIT_URI_FOR_MODULE, &str);
	if (ret != P11_KIT_URI_OK) {
		p11_message (_("couldn't format URI into string: %s"), p11_kit_uri_message (ret));
		p11_kit_uri_free (uri);
		return;
	}

	p11_list_printer_write_value (printer, "uri", "%s", str);

	free (str);
	p11_kit_uri_free (uri);
}

static void
print_token_info (p11_list_printer *printer, CK_FUNCTION_LIST_PTR module, CK_SLOT_ID slot_id)
{
	CK_TOKEN_INFO info;
	char *value;
	CK_RV rv;
	p11_array *flags;

	rv = (module->C_GetTokenInfo) (slot_id, &info);
	if (rv != CKR_OK) {
		p11_message (_("couldn't load module info: %s"), p11_kit_strerror (rv));
		return;
	}

	value = p11_kit_space_strdup (info.label, sizeof (info.label));
	p11_list_printer_start_section (printer, "token", "%s", value);
	free (value);

	print_token_uri (printer, module, &info);

	value = p11_kit_space_strdup (info.manufacturerID, sizeof (info.manufacturerID));
	p11_list_printer_write_value (printer, "manufacturer", "%s", value);
	free (value);

	value = p11_kit_space_strdup (info.model, sizeof (info.model));
	p11_list_printer_write_value (printer, "model", "%s", value);
	free (value);

	if (is_ascii_string (info.serialNumber, sizeof (info.serialNumber)))
		value = p11_kit_space_strdup (info.serialNumber, sizeof (info.serialNumber));
	else
		value = hex_encode (info.serialNumber, sizeof (info.serialNumber));
	p11_list_printer_write_value (printer, "serial-number", "%s", value);
	free (value);

	if (info.hardwareVersion.major || info.hardwareVersion.minor)
		p11_list_printer_write_value (printer, "hardware-version",
					      "%d.%d", info.hardwareVersion.major, info.hardwareVersion.minor);

	if (info.firmwareVersion.major || info.firmwareVersion.minor)
		p11_list_printer_write_value (printer, "firmware-version",
					      "%d.%d", info.firmwareVersion.major, info.firmwareVersion.minor);

	flags = p11_array_new (NULL);
	return_if_fail (flags);

	#define X(x, y)   if (info.flags & (x)) (void) p11_array_push (flags, y)
	X(CKF_RNG, "rng");
	X(CKF_WRITE_PROTECTED, "write-protected");
	X(CKF_LOGIN_REQUIRED, "login-required");
	X(CKF_USER_PIN_INITIALIZED, "user-pin-initialized");
	X(CKF_RESTORE_KEY_NOT_NEEDED, "restore-key-not-needed");
	X(CKF_CLOCK_ON_TOKEN, "clock-on-token");
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

	p11_list_printer_write_array (printer, "flags", flags);
	p11_array_free (flags);

	p11_list_printer_end_section (printer);
}

static void
print_module_info (p11_list_printer *printer, CK_FUNCTION_LIST_PTR module)
{
	CK_SLOT_ID slot_list[256];
	CK_ULONG i, count;
	CK_INFO info;
	char *value;
	CK_RV rv;

	rv = (module->C_GetInfo) (&info);
	if (rv != CKR_OK) {
		p11_message (_("couldn't load module info: %s"), p11_kit_strerror (rv));
		return;
	}

	print_module_uri (printer, module, &info);

	value = p11_kit_space_strdup (info.libraryDescription, sizeof (info.libraryDescription));
	p11_list_printer_write_value (printer, "library-description", "%s", value);
	free (value);

	value = p11_kit_space_strdup (info.manufacturerID, sizeof (info.manufacturerID));
	p11_list_printer_write_value (printer, "library-manufacturer", "%s", value);
	free (value);

	p11_list_printer_write_value (printer, "library-version",
				 "%d.%d", info.libraryVersion.major, info.libraryVersion.minor);

	count = sizeof (slot_list) / sizeof (slot_list[0]);
	rv = (module->C_GetSlotList) (CK_TRUE, slot_list, &count);
	if (rv != CKR_OK) {
		p11_message (_("couldn't load module info: %s"), p11_kit_strerror (rv));
		return;
	}

	for (i = 0; i < count; i++)
		print_token_info (printer, module, slot_list[i]);
}

static int
print_modules (void)
{
	CK_FUNCTION_LIST_PTR *module_list;
	char *name;
	char *path;
	p11_list_printer printer;
	int i;

	module_list = p11_kit_modules_load_and_initialize (0);
	if (!module_list)
		return 1;

	p11_list_printer_init (&printer, stdout, 0);

	for (i = 0; module_list[i]; i++) {
		name = p11_kit_module_get_name (module_list[i]);
		path = p11_kit_config_option (module_list[i], "module");

		p11_list_printer_start_section (&printer,
						name ? name : "(null)",
						"%s", path ? path : "(null)");
		print_module_info (&printer, module_list[i]);
		p11_list_printer_end_section (&printer);

		free (name);
		free (path);
	}

	p11_kit_modules_finalize_and_release (module_list);
	return 0;
}

int
p11_kit_list_modules (int argc,
                      char *argv[])
{
	int opt;

	enum {
		opt_verbose = 'v',
		opt_quiet = 'q',
		opt_list = 'l',
		opt_help = 'h',
	};

	struct option options[] = {
		{ "verbose", no_argument, NULL, opt_verbose },
		{ "quiet", no_argument, NULL, opt_quiet },
		{ "list", no_argument, NULL, opt_list },
		{ "help", no_argument, NULL, opt_help },
		{ 0 },
	};

	p11_tool_desc usages[] = {
		{ 0, "usage: p11-kit list-modules" },
		{ opt_verbose, "show verbose debug output", },
		{ opt_quiet, "suppress command output", },
		{ 0 },
	};

	while ((opt = p11_tool_getopt (argc, argv, options)) != -1) {
		switch (opt) {

		case opt_verbose:
			p11_kit_be_loud ();
			break;

		case opt_quiet:
			p11_kit_be_quiet ();
			break;

		case opt_list:
			break;

		case opt_help:
			p11_tool_usage (usages, options);
			return 0;
		case '?':
			return 2;
		default:
			assert_not_reached ();
			break;
		}
	}

	if (argc - optind != 0) {
		p11_message (_("extra arguments specified"));
		return 2;
	}

	return print_modules ();
}
