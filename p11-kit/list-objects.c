/*
 * Copyright (c) 2023, Red Hat Inc.
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
 * Author: Zoltan Fridrich <zfridric@redhat.com>
 */

#include "config.h"

#include "constants.h"
#include "debug.h"
#include "hex.h"
#include "iter.h"
#include "message.h"
#include "print.h"
#include "tool.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#ifdef ENABLE_NLS
#include <libintl.h>
#define _(x) dgettext(PACKAGE_NAME, x)
#else
#define _(x) (x)
#endif

int
p11_kit_list_objects (int argc,
		      char *argv[]);

static inline void
print_ulong_attribute (p11_list_printer *printer,
		       CK_ATTRIBUTE attr,
		       const p11_constant *constants)
{
	const char *type_str;
	const char *value_str;

	if (attr.ulValueLen == CK_UNAVAILABLE_INFORMATION)
		return;

	type_str = p11_constant_nick (p11_constant_types, attr.type);
	if (type_str == NULL)
		type_str = "(unknown)";

	value_str = p11_constant_nick (constants, *((CK_ULONG *)attr.pValue));
	if (value_str == NULL)
		p11_list_printer_write_value (printer, type_str, "0x%lX (unknown)", attr.pValue);
	else
		p11_list_printer_write_value (printer, type_str, "%s", value_str);
}

static inline void
print_string_attribute (p11_list_printer *printer,
			CK_ATTRIBUTE attr)
{
	const char *type_str;

	if (attr.ulValueLen == CK_UNAVAILABLE_INFORMATION)
		return;

	type_str = p11_constant_nick (p11_constant_types, attr.type);
	if (type_str == NULL)
		type_str = "(unknown)";

	p11_list_printer_write_value (printer, type_str, "%s", attr.pValue);
}

static inline void
print_byte_array_attribute (p11_list_printer *printer,
			    CK_ATTRIBUTE attr)
{
	const char *type_str;
	char *value;

	if (attr.ulValueLen == CK_UNAVAILABLE_INFORMATION)
		return;

	type_str = p11_constant_nick (p11_constant_types, attr.type);
	if (type_str == NULL)
		type_str = "(unknown)";

	value = hex_encode (attr.pValue, attr.ulValueLen);
	p11_list_printer_write_value (printer, type_str, "%s", value);
	free (value);
}

static inline void
print_date_attribute (p11_list_printer *printer,
		      CK_ATTRIBUTE attr)
{
	const char *type_str;
	char year[5] = { '\0' };
	char month[3] = { '\0' };
	char day[3] = { '\0' };

	if (attr.ulValueLen == CK_UNAVAILABLE_INFORMATION)
		return;

	type_str = p11_constant_nick (p11_constant_types, attr.type);
	if (type_str == NULL)
		type_str = "(unknown)";

	memcpy (year, ((CK_DATE *)attr.pValue)->year, 4);
	memcpy (month, ((CK_DATE *)attr.pValue)->month, 2);
	memcpy (day, ((CK_DATE *)attr.pValue)->day, 2);

	p11_list_printer_write_value (printer, type_str, "%s.%s.%s", year, month, day);
}

static inline void
print_bool_attribute (p11_list_printer *printer,
		      CK_ATTRIBUTE attr)
{
	const char *type_str;

	if (attr.ulValueLen == CK_UNAVAILABLE_INFORMATION)
		return;

	type_str = p11_constant_nick (p11_constant_types, attr.type);
	if (type_str == NULL)
		type_str = "(unknown)";

	p11_list_printer_write_value (printer, type_str, "%s",
				      *((CK_BBOOL *)attr.pValue) ? "true" : "false");
}

static void
print_object (p11_list_printer *printer,
	      P11KitIter *iter,
	      size_t index)
{
	CK_OBJECT_CLASS klass;
	CK_HW_FEATURE_TYPE hw_feature_type;
	CK_KEY_TYPE key_type;
	CK_PROFILE_ID profile_id;
	CK_CERTIFICATE_TYPE cert_type;
	CK_ULONG cert_category;
	CK_MECHANISM_TYPE mechanism_type;
	CK_BBOOL trusted, local, token, private, modifiable, copyable, destroyable;
	CK_DATE start_date, end_date;
	char label[128] = { '\0' };
	char application[128] = { '\0' };
	char id[128] = { '\0' };

	CK_ATTRIBUTE attrs[] = {
		/* ulong attributes */
		{ CKA_CLASS, &klass, sizeof (klass) },
		{ CKA_HW_FEATURE_TYPE, &hw_feature_type, sizeof (hw_feature_type) },
		{ CKA_MECHANISM_TYPE, &mechanism_type, sizeof (mechanism_type) },
		{ CKA_CERTIFICATE_TYPE, &cert_type, sizeof (cert_type) },
		{ CKA_CERTIFICATE_CATEGORY, &cert_category, sizeof (cert_category) },
		{ CKA_KEY_TYPE, &key_type, sizeof (key_type) },
		{ CKA_PROFILE_ID, &profile_id, sizeof (profile_id) },
		/* string attributes */
		{ CKA_LABEL, label, sizeof (label) - 1 },
		{ CKA_APPLICATION, application, sizeof (application) - 1 },
		/* byte array attributes */
		{ CKA_ID, id, sizeof (id) - 1 },
		/* date attributes */
		{ CKA_START_DATE, &start_date, sizeof (start_date) },
		{ CKA_END_DATE, &end_date, sizeof (end_date) },
		/* bool attributes */
		{ CKA_TRUSTED, &trusted, sizeof (trusted) },
		{ CKA_LOCAL, &local, sizeof (local) },
		{ CKA_TOKEN, &token, sizeof (token) },
		{ CKA_PRIVATE, &private, sizeof (private) },
		{ CKA_MODIFIABLE, &modifiable, sizeof (modifiable) },
		{ CKA_COPYABLE, &copyable, sizeof (copyable) },
		{ CKA_DESTROYABLE, &destroyable, sizeof (destroyable) }
	};
	CK_ULONG n_attrs = sizeof (attrs) / sizeof (attrs[0]);

	p11_kit_iter_get_attributes (iter, attrs, n_attrs);
	p11_list_printer_start_section (printer, "Object", "#%lu", index);
	print_ulong_attribute (printer, attrs[0], p11_constant_classes);
	print_ulong_attribute (printer, attrs[1], p11_constant_hw_features);
	print_ulong_attribute (printer, attrs[2], p11_constant_mechanisms);
	print_ulong_attribute (printer, attrs[3], p11_constant_certs);
	print_ulong_attribute (printer, attrs[4], p11_constant_categories);
	print_ulong_attribute (printer, attrs[5], p11_constant_keys);
	print_ulong_attribute (printer, attrs[6], p11_constant_profiles);
	print_string_attribute (printer, attrs[7]);
	print_string_attribute (printer, attrs[8]);
	print_byte_array_attribute (printer, attrs[9]);
	print_date_attribute (printer, attrs[10]);
	print_date_attribute (printer, attrs[11]);
	print_bool_attribute (printer, attrs[12]);
	print_bool_attribute (printer, attrs[13]);
	print_bool_attribute (printer, attrs[14]);
	print_bool_attribute (printer, attrs[15]);
	print_bool_attribute (printer, attrs[16]);
	print_bool_attribute (printer, attrs[17]);
	print_bool_attribute (printer, attrs[18]);
	p11_list_printer_end_section (printer);
}

static int
list_objects (const char *token_str)
{
	int ret = 1;
	size_t i;
	CK_FUNCTION_LIST **modules = NULL;
	P11KitUri *uri = NULL;
	P11KitIter *iter = NULL;
	p11_list_printer printer;

	uri = p11_kit_uri_new ();
	if (uri == NULL) {
		p11_message (_("failed to allocate memory for URI"));
		goto cleanup;
	}

	if (p11_kit_uri_parse (token_str, P11_KIT_URI_FOR_TOKEN, uri) != P11_KIT_URI_OK) {
		p11_message (_("failed to parse the token URI"));
		goto cleanup;
	}

	modules = p11_kit_modules_load_and_initialize (0);
	if (modules == NULL) {
		p11_message (_("failed to load and initialize modules"));
		goto cleanup;
	}

	iter = p11_kit_iter_new (uri, P11_KIT_ITER_WITH_LOGIN);
	if (iter == NULL) {
		p11_message (_("failed to initialize iterator"));
		goto cleanup;
	}

	p11_list_printer_init (&printer, stdout, 0);
	p11_kit_iter_begin (iter, modules);
	for (i = 0; p11_kit_iter_next (iter) == CKR_OK; ++i)
		print_object (&printer, iter, i);

	ret = 0;

cleanup:
	p11_kit_iter_free (iter);
	p11_kit_modules_finalize (modules);
	p11_kit_modules_release (modules);
	p11_kit_uri_free (uri);

	return ret;
}

int
p11_kit_list_objects (int argc,
		      char *argv[])
{
	int opt;

	enum {
		opt_verbose = 'v',
		opt_quiet = 'q',
		opt_help = 'h',
	};

	struct option options[] = {
		{ "verbose", no_argument, NULL, opt_verbose },
		{ "quiet", no_argument, NULL, opt_quiet },
		{ "help", no_argument, NULL, opt_help },
		{ 0 },
	};

	p11_tool_desc usages[] = {
		{ 0, "usage: p11-kit list-objects pkcs11:token" },
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

	argc -= optind;
	argv += optind;

	if (argc != 1) {
		p11_tool_usage (usages, options);
		return 2;
	}

	return list_objects (*argv);
}
