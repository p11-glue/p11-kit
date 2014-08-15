/*
 * Copyright (c) 2013 Red Hat Inc.
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
 * Author: Stef Walter <stefw@redhat.com>
 */

#include "config.h"

#include "compat.h"
#include "attrs.h"
#include "debug.h"
#include "pkcs11x.h"

#include "p11-kit/iter.h"
#include "p11-kit/p11-kit.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void
dump_object (P11KitIter *iter,
             CK_ATTRIBUTE *attrs)
{
	CK_ATTRIBUTE label = { CKA_LABEL, };
	CK_ATTRIBUTE *attr;
	char *string;
	char *name;
	CK_RV rv;

	attr = p11_attrs_find_valid (attrs, CKA_LABEL);
	if (!attr) {
		rv = p11_kit_iter_load_attributes (iter, &label, 1);
		if (rv == CKR_OK)
			attr = &label;
	}

	if (attr)
		name = strndup (attr->pValue, attr->ulValueLen);
	else
		name = strdup ("unknown");

	string = p11_attrs_to_string (attrs, -1);
	printf ("\"%s\" = %s\n", name, string);
	free (string);

	free (label.pValue);
	free (name);
}

static int
dump_trust_module (const char *path)
{
	CK_FUNCTION_LIST *module;
	CK_OBJECT_CLASS nss_trust = CKO_NSS_TRUST;
	CK_ATTRIBUTE match =
		{ CKA_CLASS, &nss_trust, sizeof (nss_trust) };
	P11KitIter *iter;
	CK_ATTRIBUTE *attrs;
	CK_RV rv;

	CK_ATTRIBUTE template[] = {
		{ CKA_CLASS,},
		{ CKA_LABEL, },
		{ CKA_CERT_MD5_HASH, },
		{ CKA_CERT_SHA1_HASH },
		{ CKA_ISSUER, },
		{ CKA_SERIAL_NUMBER, },
		{ CKA_TRUST_SERVER_AUTH, },
		{ CKA_TRUST_EMAIL_PROTECTION, },
		{ CKA_TRUST_CODE_SIGNING, },
		{ CKA_TRUST_STEP_UP_APPROVED, },
		{ CKA_INVALID, }
	};

	CK_ULONG count = p11_attrs_count (template);

	module = p11_kit_module_load (path, 0);
	return_val_if_fail (module != NULL, 1);

	rv = p11_kit_module_initialize (module);
	return_val_if_fail (rv == CKR_OK, 1);

	iter = p11_kit_iter_new (NULL, 0);
	p11_kit_iter_add_filter (iter, &match, 1);
	p11_kit_iter_begin_with (iter, module, 0, 0);

	while ((rv = p11_kit_iter_next (iter)) == CKR_OK) {
		attrs = p11_attrs_dup (template);
		rv = p11_kit_iter_load_attributes (iter, attrs, count);
		return_val_if_fail (rv == CKR_OK || rv == CKR_ATTRIBUTE_VALUE_INVALID, 1);
		p11_attrs_purge (attrs);
		dump_object (iter, attrs);
		p11_attrs_free (attrs);
	}

	return_val_if_fail (rv == CKR_CANCEL, 1);

	p11_kit_module_finalize (module);
	p11_kit_module_release (module);

	return 0;
}

static int
compare_trust_modules (const char *path1,
                       const char *path2)
{
	CK_FUNCTION_LIST *module1;
	CK_FUNCTION_LIST *module2;
	CK_OBJECT_CLASS nss_trust = CKO_NSS_TRUST;
	CK_ATTRIBUTE match =
		{ CKA_CLASS, &nss_trust, sizeof (nss_trust) };
	P11KitIter *iter;
	P11KitIter *iter2;
	CK_ATTRIBUTE *check;
	CK_RV rv;

	CK_ATTRIBUTE template[] = {
		{ CKA_CLASS, },
		{ CKA_ISSUER, },
		{ CKA_SERIAL_NUMBER, },
		{ CKA_CERT_MD5_HASH, },
		{ CKA_CERT_SHA1_HASH },
		{ CKA_TRUST_SERVER_AUTH, },
		{ CKA_TRUST_EMAIL_PROTECTION, },
		{ CKA_TRUST_CODE_SIGNING, },
		{ CKA_TRUST_STEP_UP_APPROVED, },
		{ CKA_INVALID, }
	};

	module1 = p11_kit_module_load (path1, 0);
	return_val_if_fail (module1 != NULL, 1);

	rv = p11_kit_module_initialize (module1);
	return_val_if_fail (rv == CKR_OK, 1);

	module2 = p11_kit_module_load (path2, 0);
	return_val_if_fail (module2 != NULL, 1);

	rv = p11_kit_module_initialize (module2);
	return_val_if_fail (rv == CKR_OK, 1);

	iter = p11_kit_iter_new (NULL, 0);
	p11_kit_iter_add_filter (iter, &match, 1);
	p11_kit_iter_begin_with (iter, module1, 0, 0);

	while ((rv = p11_kit_iter_next (iter)) == CKR_OK) {
		check = p11_attrs_dup (template);

		rv = p11_kit_iter_load_attributes (iter, check, p11_attrs_count (check));
		return_val_if_fail (rv == CKR_OK || rv == CKR_ATTRIBUTE_TYPE_INVALID, 1);

		/* Go through and remove anything not found */
		p11_attrs_purge (check);

		/* Check that this object exists */
		iter2 = p11_kit_iter_new (NULL, 0);
		p11_kit_iter_add_filter (iter2, check, p11_attrs_count (check));
		p11_kit_iter_begin_with (iter2, module2, 0, 0);
		rv = p11_kit_iter_next (iter2);
		p11_kit_iter_free (iter2);

		if (rv != CKR_OK)
			dump_object (iter, check);

		p11_attrs_free (check);
	}

	return_val_if_fail (rv == CKR_CANCEL, 1);
	p11_kit_module_finalize (module1);
	p11_kit_module_release (module1);

	p11_kit_module_finalize (module2);
	p11_kit_module_release (module2);

	return 0;
}

int
main (int argc,
      char *argv[])
{
	if (argc == 2) {
		return dump_trust_module (argv[1]);
	} else if (argc == 3) {
		return compare_trust_modules (argv[1], argv[2]);
	} else {
		fprintf (stderr, "usage: frob-nss-trust module\n");
		fprintf (stderr, "       frob-nss-trust module1 module2\n");
		return 2;
	}
}
