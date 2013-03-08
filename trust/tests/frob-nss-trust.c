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

#include "common/attrs.h"
#include "common/debug.h"
#include "common/pkcs11x.h"

#include "p11-kit/iter.h"
#include "p11-kit/p11-kit.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int
main (int argc,
      char *argv[])
{
	CK_FUNCTION_LIST *module;
	CK_TRUST untrusted = CKT_NSS_NOT_TRUSTED;
	CK_ATTRIBUTE server_not_trusted =
		{ CKA_TRUST_SERVER_AUTH, &untrusted, sizeof (untrusted) };
	P11KitIter *iter;
	CK_RV rv;
	char *string;

	CK_ATTRIBUTE attrs[] = {
		{ CKA_CLASS, NULL, 0 },
		{ CKA_LABEL, NULL, 0  },
		{ CKA_ISSUER, NULL, 0  },
		{ CKA_SERIAL_NUMBER, NULL, 0  },
		{ CKA_TRUST_SERVER_AUTH, NULL, 0  },
		{ CKA_TRUST_EMAIL_PROTECTION, NULL, 0  },
		{ CKA_TRUST_CODE_SIGNING, NULL, 0  },
		{ CKA_TRUST_STEP_UP_APPROVED, NULL, 0  },
		{ CKA_INVALID, }
	};

	CK_ULONG count = p11_attrs_count (attrs);
	CK_ULONG i;

	if (argc != 2) {
		fprintf (stderr, "usage: frob-nss-trust module\n");
		return 2;
	}

	rv = p11_kit_load_initialize_module (argv[1], &module);
	return_val_if_fail (rv == CKR_OK, 1);

	iter = p11_kit_iter_new (NULL);
	p11_kit_iter_add_filter (iter, &server_not_trusted, 1);
	p11_kit_iter_begin_with (iter, module, 0, 0);

	while ((rv = p11_kit_iter_next (iter)) == CKR_OK) {
		rv = p11_kit_iter_load_attributes (iter, attrs, count);
		return_val_if_fail (rv == CKR_OK, 1);
		string = p11_attrs_to_string (attrs);
		printf ("%s\n", string);
		free (string);
	}

	return_val_if_fail (rv == CKR_CANCEL, 1);

	for (i = 0; i < count; i++)
		free (attrs[i].pValue);

	p11_kit_finalize_module (module);

	return 0;
}
