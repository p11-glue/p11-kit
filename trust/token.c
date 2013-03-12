/*
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
 * Author: Stef Walter <stefw@redhat.com>
 */

#include "config.h"

#include "attrs.h"
#include "compat.h"
#define P11_DEBUG_FLAG P11_DEBUG_TRUST
#include "debug.h"
#include "errno.h"
#include "library.h"
#include "module.h"
#include "parser.h"
#include "pkcs11.h"
#include "pkcs11x.h"
#include "token.h"

#include <sys/stat.h>
#include <sys/types.h>

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ELEMS(x) (sizeof (x) / sizeof (x[0]))

struct _p11_token {
	p11_parser *parser;
	p11_index *index;
	const char *path;
	CK_SLOT_ID slot;
	int loaded;
};

static void
on_parser_object (CK_ATTRIBUTE *attrs,
                  void *user_data)
{
	p11_token *token = user_data;

	return_if_fail (attrs != NULL);

	if (p11_index_take (token->index, attrs, NULL) != CKR_OK)
		return_if_reached ();
}

static int
loader_load_file (p11_token *token,
                  const char *filename,
                  struct stat *sb,
                  int flags)
{
	int ret;

	ret = p11_parse_file (token->parser, filename, flags,
	                      on_parser_object, token);

	switch (ret) {
	case P11_PARSE_SUCCESS:
		p11_debug ("loaded: %s", filename);
		return 1;
	case P11_PARSE_UNRECOGNIZED:
		p11_debug ("skipped: %s", filename);
		return 0;
	default:
		p11_debug ("failed to parse: %s", filename);
		return 0;
	}
}

static int
loader_load_directory (p11_token *token,
                       const char *directory,
                       int flags)
{
	struct dirent *dp;
	struct stat sb;
	char *path;
	int total = 0;
	int ret;
	DIR *dir;

	/* First we load all the modules */
	dir = opendir (directory);
	if (!dir) {
		p11_message ("couldn't list directory: %s: %s",
		             directory, strerror (errno));
		return 0;
	}

	/* We're within a global mutex, so readdir is safe */
	while ((dp = readdir (dir)) != NULL) {
		path = strconcat (directory, "/", dp->d_name, NULL);
		return_val_if_fail (path != NULL, -1);

		if (stat (path, &sb) < 0) {
			p11_message ("couldn't stat path: %s", path);

		} else if (!S_ISDIR (sb.st_mode)) {
			ret = loader_load_file (token, path, &sb, flags);
			return_val_if_fail (ret >= 0, ret);
			total += ret;
		}

		free (path);
	}

	closedir (dir);
	return total;
}

static int
loader_load_subdirectory (p11_token *token,
                          const char *directory,
                          const char *subdir,
                          int flags)
{
	struct stat sb;
	char *path;
	int ret = 0;

	if (asprintf (&path, "%s/%s", directory, subdir) < 0)
		return_val_if_reached (-1);

	if (stat (path, &sb) >= 0 && S_ISDIR (sb.st_mode))
		ret = loader_load_directory (token, path, flags);

	free (path);
	return ret;
}

static int
loader_load_path (p11_token *token,
                  const char *path)
{
	struct stat sb;
	int total;
	int ret;

	if (stat (path, &sb) < 0) {
		if (errno == ENOENT) {
			p11_message ("trust certificate path does not exist: %s",
			             path);
		} else {
			p11_message ("cannot access trust certificate path: %s: %s",
			             path, strerror (errno));
		}

		return 0;
	}

	if (S_ISDIR (sb.st_mode)) {
		total = 0;

		ret = loader_load_subdirectory (token, path, "anchors", P11_PARSE_FLAG_ANCHOR);
		return_val_if_fail (ret >= 0, ret);
		total += ret;

		ret = loader_load_subdirectory (token, path, "blacklist", P11_PARSE_FLAG_BLACKLIST);
		return_val_if_fail (ret >= 0, ret);
		total += ret;

		ret = loader_load_directory (token, path, P11_PARSE_FLAG_NONE);
		return_val_if_fail (ret >= 0, ret);
		total += ret;

		return total;
	} else {
		return loader_load_file (token, path, &sb, P11_PARSE_FLAG_ANCHOR);
	}
}

static int
load_builtin_objects (p11_token *token)
{
	CK_OBJECT_CLASS builtin = CKO_NSS_BUILTIN_ROOT_LIST;
	CK_OBJECT_CLASS nss_trust = CKO_NSS_TRUST;
	CK_TRUST nss_not_trusted = CKT_NSS_NOT_TRUSTED;
	CK_BBOOL vtrue = CK_TRUE;
	CK_BBOOL vfalse = CK_FALSE;

	const char *trust_anchor_roots = "Trust Anchor Roots";
	CK_ATTRIBUTE builtin_root_list[] = {
		{ CKA_CLASS, &builtin, sizeof (builtin) },
		{ CKA_TOKEN, &vtrue, sizeof (vtrue) },
		{ CKA_PRIVATE, &vfalse, sizeof (vfalse) },
		{ CKA_MODIFIABLE, &vfalse, sizeof (vfalse) },
		{ CKA_LABEL, (void *)trust_anchor_roots, strlen (trust_anchor_roots) },
	};

	/* Explicitly Distrust "MITM subCA 1 issued by Trustwave", Bug 724929 */
	char label_trustwave1[] = "MITM subCA 1 issued by Trustwave";
	char issuer_trustwave1[] =
		"\060\201\253\061\013\060\011\006\003\125\004\006\023\002\125\123"
		"\061\021\060\017\006\003\125\004\010\023\010\111\154\154\151\156"
		"\157\151\163\061\020\060\016\006\003\125\004\007\023\007\103\150"
		"\151\143\141\147\157\061\041\060\037\006\003\125\004\012\023\030"
		"\124\162\165\163\164\167\141\166\145\040\110\157\154\144\151\156"
		"\147\163\054\040\111\156\143\056\061\063\060\061\006\003\125\004"
		"\003\023\052\124\162\165\163\164\167\141\166\145\040\117\162\147"
		"\141\156\151\172\141\164\151\157\156\040\111\163\163\165\151\156"
		"\147\040\103\101\054\040\114\145\166\145\154\040\062\061\037\060"
		"\035\006\011\052\206\110\206\367\015\001\011\001\026\020\143\141"
		"\100\164\162\165\163\164\167\141\166\145\056\143\157\155";
	char serial_trustwave1[] = "\002\004\153\111\322\005";
	CK_ATTRIBUTE distrust_trustwave1[] = {
		{ CKA_CLASS, &nss_trust, sizeof (nss_trust) },
		{ CKA_TOKEN, &vtrue, sizeof (vtrue) },
		{ CKA_PRIVATE, &vfalse, sizeof (vfalse) },
		{ CKA_MODIFIABLE, &vfalse, sizeof (vfalse) },
		{ CKA_LABEL, label_trustwave1, sizeof (label_trustwave1) - 1 },
		{ CKA_ISSUER, issuer_trustwave1, sizeof (issuer_trustwave1) -1 },
		{ CKA_SERIAL_NUMBER, serial_trustwave1, sizeof (serial_trustwave1) - 1 },
		{ CKA_TRUST_SERVER_AUTH, &nss_not_trusted, sizeof (nss_not_trusted) },
		{ CKA_TRUST_EMAIL_PROTECTION, &nss_not_trusted, sizeof (nss_not_trusted) },
		{ CKA_TRUST_CODE_SIGNING, &nss_not_trusted, sizeof (nss_not_trusted) },
		{ CKA_TRUST_STEP_UP_APPROVED, &vfalse, sizeof (vfalse) },
	};

	/* Explicitly Distrust "MITM subCA 2 issued by Trustwave", Bug 724929 */
	char label_trustwave2[] = "MITM subCA 2 issued by Trustwave";
	char issuer_trustwave2[] =
		"\060\201\253\061\013\060\011\006\003\125\004\006\023\002\125\123"
		"\061\021\060\017\006\003\125\004\010\023\010\111\154\154\151\156"
		"\157\151\163\061\020\060\016\006\003\125\004\007\023\007\103\150"
		"\151\143\141\147\157\061\041\060\037\006\003\125\004\012\023\030"
		"\124\162\165\163\164\167\141\166\145\040\110\157\154\144\151\156"
		"\147\163\054\040\111\156\143\056\061\063\060\061\006\003\125\004"
		"\003\023\052\124\162\165\163\164\167\141\166\145\040\117\162\147"
		"\141\156\151\172\141\164\151\157\156\040\111\163\163\165\151\156"
		"\147\040\103\101\054\040\114\145\166\145\154\040\062\061\037\060"
		"\035\006\011\052\206\110\206\367\015\001\011\001\026\020\143\141"
		"\100\164\162\165\163\164\167\141\166\145\056\143\157\155";
	char serial_trustwave2[] = "\002\004\153\111\322\006";
	CK_ATTRIBUTE distrust_trustwave2[] = {
		{ CKA_CLASS, &nss_trust, sizeof (nss_trust) },
		{ CKA_TOKEN, &vtrue, sizeof (vtrue) },
		{ CKA_PRIVATE, &vfalse, sizeof (vfalse) },
		{ CKA_MODIFIABLE, &vfalse, sizeof (vfalse) },
		{ CKA_LABEL, label_trustwave2, sizeof (label_trustwave2) - 1 },
		{ CKA_ISSUER, issuer_trustwave2, sizeof (issuer_trustwave2) -1 },
		{ CKA_SERIAL_NUMBER, serial_trustwave2, sizeof (serial_trustwave2) - 1 },
		{ CKA_TRUST_SERVER_AUTH, &nss_not_trusted, sizeof (nss_not_trusted) },
		{ CKA_TRUST_EMAIL_PROTECTION, &nss_not_trusted, sizeof (nss_not_trusted) },
		{ CKA_TRUST_CODE_SIGNING, &nss_not_trusted, sizeof (nss_not_trusted) },
		{ CKA_TRUST_STEP_UP_APPROVED, &vfalse, sizeof (vfalse) },
	};

	/* Explicitly Distrust "TURKTRUST Mis-issued Intermediate CA 1", Bug 825022 */
	char label_turktrust1[] = "TURKTRUST Mis-issued Intermediate CA 1";
	char issuer_turktrust1[] =
		"\060\201\254\061\075\060\073\006\003\125\004\003\014\064\124\303"
		"\234\122\113\124\122\125\123\124\040\105\154\145\153\164\162\157"
		"\156\151\153\040\123\165\156\165\143\165\040\123\145\162\164\151"
		"\146\151\153\141\163\304\261\040\110\151\172\155\145\164\154\145"
		"\162\151\061\013\060\011\006\003\125\004\006\023\002\124\122\061"
		"\136\060\134\006\003\125\004\012\014\125\124\303\234\122\113\124"
		"\122\125\123\124\040\102\151\154\147\151\040\304\260\154\145\164"
		"\151\305\237\151\155\040\166\145\040\102\151\154\151\305\237\151"
		"\155\040\107\303\274\166\145\156\154\151\304\237\151\040\110\151"
		"\172\155\145\164\154\145\162\151\040\101\056\305\236\056\040\050"
		"\143\051\040\113\141\163\304\261\155\040\040\062\060\060\065";
	char serial_turktrust1[] = "\002\002\010\047";
	CK_ATTRIBUTE distrust_turktrust1[] = {
		{ CKA_CLASS, &nss_trust, sizeof (nss_trust) },
		{ CKA_TOKEN, &vtrue, sizeof (vtrue) },
		{ CKA_PRIVATE, &vfalse, sizeof (vfalse) },
		{ CKA_MODIFIABLE, &vfalse, sizeof (vfalse) },
		{ CKA_LABEL, label_turktrust1, sizeof (label_turktrust1) - 1 },
		{ CKA_ISSUER, issuer_turktrust1, sizeof (issuer_turktrust1) -1 },
		{ CKA_SERIAL_NUMBER, serial_turktrust1, sizeof (serial_turktrust1) - 1 },
		{ CKA_TRUST_SERVER_AUTH, &nss_not_trusted, sizeof (nss_not_trusted) },
		{ CKA_TRUST_EMAIL_PROTECTION, &nss_not_trusted, sizeof (nss_not_trusted) },
		{ CKA_TRUST_CODE_SIGNING, &nss_not_trusted, sizeof (nss_not_trusted) },
		{ CKA_TRUST_STEP_UP_APPROVED, &vfalse, sizeof (vfalse) },
	};

	/* Explicitly Distrust "TURKTRUST Mis-issued Intermediate CA 2", Bug 825022 */
	char label_turktrust2[] = "TURKTRUST Mis-issued Intermediate CA 2";
	char issuer_turktrust2[] =
		"\060\201\254\061\075\060\073\006\003\125\004\003\014\064\124\303"
		"\234\122\113\124\122\125\123\124\040\105\154\145\153\164\162\157"
		"\156\151\153\040\123\165\156\165\143\165\040\123\145\162\164\151"
		"\146\151\153\141\163\304\261\040\110\151\172\155\145\164\154\145"
		"\162\151\061\013\060\011\006\003\125\004\006\023\002\124\122\061"
		"\136\060\134\006\003\125\004\012\014\125\124\303\234\122\113\124"
		"\122\125\123\124\040\102\151\154\147\151\040\304\260\154\145\164"
		"\151\305\237\151\155\040\166\145\040\102\151\154\151\305\237\151"
		"\155\040\107\303\274\166\145\156\154\151\304\237\151\040\110\151"
		"\172\155\145\164\154\145\162\151\040\101\056\305\236\056\040\050"
		"\143\051\040\113\141\163\304\261\155\040\040\062\060\060\065";
	char serial_turktrust2[] = "\002\002\010\144";
	CK_ATTRIBUTE distrust_turktrust2[] = {
		{ CKA_CLASS, &nss_trust, sizeof (nss_trust) },
		{ CKA_TOKEN, &vtrue, sizeof (vtrue) },
		{ CKA_PRIVATE, &vfalse, sizeof (vfalse) },
		{ CKA_MODIFIABLE, &vfalse, sizeof (vfalse) },
		{ CKA_LABEL, label_turktrust2, sizeof (label_turktrust2) - 1 },
		{ CKA_ISSUER, issuer_turktrust2, sizeof (issuer_turktrust2) -1 },
		{ CKA_SERIAL_NUMBER, serial_turktrust2, sizeof (serial_turktrust2) - 1 },
		{ CKA_TRUST_SERVER_AUTH, &nss_not_trusted, sizeof (nss_not_trusted) },
		{ CKA_TRUST_EMAIL_PROTECTION, &nss_not_trusted, sizeof (nss_not_trusted) },
		{ CKA_TRUST_CODE_SIGNING, &nss_not_trusted, sizeof (nss_not_trusted) },
		{ CKA_TRUST_STEP_UP_APPROVED, &vfalse, sizeof (vfalse) },
	};

	/* Explicitly Distrust "Explicitly distrust p11-kit Test SUB CA" */
	char label_p11subca[] = "Explicitly distrust p11-kit Test SUB CA";
	char issuer_p11subca[] =
		"\060\152\061\013\060\011\006\003\125\004\006\023\002\104\105\061"
		"\023\060\021\006\003\125\004\010\023\012\124\145\163\164\040\123"
		"\164\141\164\145\061\021\060\017\006\003\125\004\007\023\010\124"
		"\145\163\164\040\114\157\143\061\031\060\027\006\003\125\004\012"
		"\023\020\160\061\061\055\153\151\164\040\124\145\163\164\040\117"
		"\162\147\061\030\060\026\006\003\125\004\003\023\017\160\061\061"
		"\055\153\151\164\040\124\145\163\164\040\103\101";
	char serial_p11subca[] = "\002\002\047\020";
	CK_ATTRIBUTE distrust_p11subca[] = {
		{ CKA_CLASS, &nss_trust, sizeof (nss_trust) },
		{ CKA_TOKEN, &vtrue, sizeof (vtrue) },
		{ CKA_PRIVATE, &vfalse, sizeof (vfalse) },
		{ CKA_MODIFIABLE, &vfalse, sizeof (vfalse) },
		{ CKA_LABEL, label_p11subca, sizeof (label_p11subca) - 1 },
		{ CKA_ISSUER, issuer_p11subca, sizeof (issuer_p11subca) -1 },
		{ CKA_SERIAL_NUMBER, serial_p11subca, sizeof (serial_p11subca) - 1 },
		{ CKA_TRUST_SERVER_AUTH, &nss_not_trusted, sizeof (nss_not_trusted) },
		{ CKA_TRUST_EMAIL_PROTECTION, &nss_not_trusted, sizeof (nss_not_trusted) },
		{ CKA_TRUST_CODE_SIGNING, &nss_not_trusted, sizeof (nss_not_trusted) },
		{ CKA_TRUST_STEP_UP_APPROVED, &vfalse, sizeof (vfalse) },
	};

	on_parser_object (p11_attrs_buildn (NULL, builtin_root_list, ELEMS (builtin_root_list)), token);
	on_parser_object (p11_attrs_buildn (NULL, distrust_trustwave1, ELEMS (distrust_trustwave1)), token);
	on_parser_object (p11_attrs_buildn (NULL, distrust_trustwave2, ELEMS (distrust_trustwave2)), token);
	on_parser_object (p11_attrs_buildn (NULL, distrust_turktrust1, ELEMS (distrust_turktrust1)), token);
	on_parser_object (p11_attrs_buildn (NULL, distrust_turktrust2, ELEMS (distrust_turktrust2)), token);
	on_parser_object (p11_attrs_buildn (NULL, distrust_p11subca, ELEMS (distrust_p11subca)), token);
	return 1;
}

int
p11_token_load (p11_token *token)
{
	int builtins;
	int count;

	if (token->loaded)
		return 0;
	token->loaded = 1;

	builtins = load_builtin_objects (token);

	count = loader_load_path (token, token->path);
	return_val_if_fail (count >= 0, count);

	return count + builtins;
}

void
p11_token_free (p11_token *token)
{
	if (!token)
		return;

	p11_index_free (token->index);
	p11_parser_free (token->parser);
	free (token);
}

p11_token *
p11_token_new (CK_SLOT_ID slot,
               const char *path)
{
	p11_token *token;

	token = calloc (1, sizeof (p11_token));
	return_val_if_fail (token != NULL, NULL);

	token->parser = p11_parser_new ();
	return_val_if_fail (token->parser != NULL, NULL);

	token->index = p11_index_new (NULL, NULL, NULL);
	return_val_if_fail (token->index != NULL, NULL);

	token->path = strdup (path);
	return_val_if_fail (token->path != NULL, NULL);

	token->slot = slot;
	token->loaded = 0;

	return token;
}

const char *
p11_token_get_path (p11_token *token)
{
	return_val_if_fail (token != NULL, NULL);
	return token->path;
}

CK_SLOT_ID
p11_token_get_slot (p11_token *token)
{
	return_val_if_fail (token != NULL, 0);
	return token->slot;
}

p11_index *
p11_token_index (p11_token *token)
{
	return_val_if_fail (token != NULL, NULL);
	return token->index;
}
