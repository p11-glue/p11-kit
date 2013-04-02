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

#include "asn1.h"
#include "attrs.h"
#include "builder.h"
#include "compat.h"
#define P11_DEBUG_FLAG P11_DEBUG_TRUST
#include "debug.h"
#include "errno.h"
#include "message.h"
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

struct _p11_token {
	p11_parser *parser;
	p11_index *index;
	p11_builder *builder;
	char *path;
	char *label;
	CK_SLOT_ID slot;
	int loaded;
};

static int
loader_load_file (p11_token *token,
                  const char *filename,
                  struct stat *sb,
                  int flags)
{
	int ret;

	ret = p11_parse_file (token->parser, filename, flags);

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
	CK_BBOOL vtrue = CK_TRUE;
	CK_BBOOL vfalse = CK_FALSE;
	CK_RV rv;

	const char *trust_anchor_roots = "Trust Anchor Roots";
	CK_ATTRIBUTE builtin_root_list[] = {
		{ CKA_CLASS, &builtin, sizeof (builtin) },
		{ CKA_TOKEN, &vtrue, sizeof (vtrue) },
		{ CKA_PRIVATE, &vfalse, sizeof (vfalse) },
		{ CKA_MODIFIABLE, &vfalse, sizeof (vfalse) },
		{ CKA_LABEL, (void *)trust_anchor_roots, strlen (trust_anchor_roots) },
		{ CKA_INVALID },
	};

	p11_index_batch (token->index);
	rv = p11_index_take (token->index, p11_attrs_dup (builtin_root_list), NULL);
	return_val_if_fail (rv == CKR_OK, 0);
	p11_index_finish (token->index);
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
	p11_builder_free (token->builder);
	free (token->path);
	free (token->label);
	free (token);
}

p11_token *
p11_token_new (CK_SLOT_ID slot,
               const char *path,
               const char *label)
{
	p11_token *token;

	return_val_if_fail (path != NULL, NULL);
	return_val_if_fail (label != NULL, NULL);

	token = calloc (1, sizeof (p11_token));
	return_val_if_fail (token != NULL, NULL);

	token->builder = p11_builder_new (P11_BUILDER_FLAG_TOKEN);
	return_val_if_fail (token->builder != NULL, NULL);

	token->index = p11_index_new (p11_builder_build,
	                              p11_builder_changed,
	                              token->builder);
	return_val_if_fail (token->index != NULL, NULL);

	token->parser = p11_parser_new (token->index,
	                                p11_builder_get_cache (token->builder));
	return_val_if_fail (token->parser != NULL, NULL);

	token->path = strdup (path);
	return_val_if_fail (token->path != NULL, NULL);

	token->label = strdup (label);
	return_val_if_fail (token->label != NULL, NULL);

	token->slot = slot;
	token->loaded = 0;

	p11_debug ("token: %s: %s", token->label, token->path);
	return token;
}

const char *
p11_token_get_label (p11_token *token)
{
	return_val_if_fail (token != NULL, NULL);
	return token->label;
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
