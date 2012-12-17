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
#include <stdlib.h>
#include <string.h>

struct _p11_token {
	p11_parser *parser;
	p11_dict *objects;
	const char *anchor_paths;
	const char *other_paths;
	const char *certificate_paths;
	int loaded;
};

static void
on_parser_object (CK_ATTRIBUTE *attrs,
                  void *user_data)
{
	CK_OBJECT_HANDLE object;
	CK_OBJECT_HANDLE *key;
	p11_token *token = user_data;

	object = p11_module_next_id ();

	key = memdup (&object, sizeof (object));
	return_if_fail (key != NULL);

	if (!p11_dict_set (token->objects, key, attrs))
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

	return ret == P11_PARSE_SUCCESS ? 1 : 0;
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
			return_val_if_fail (ret > 0, ret);
			total += ret;
		}

		free (path);
	}

	closedir (dir);
	return total;
}

static int
loader_load_path (p11_token *token,
                  const char *path,
                  int flags)
{
	struct stat sb;

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

	if (S_ISDIR (sb.st_mode))
		return loader_load_directory (token, path, flags);
	else
		return loader_load_file (token, path, &sb, flags);
}

static int
loader_load_paths (p11_token *token,
                   const char *paths,
                   int flags)
{
	const char *pos;
	int total = 0;
	char *path;
	int ret;

	while (paths) {
		pos = strchr (paths, ':');
		if (pos == NULL) {
			path = strdup (paths);
			paths = NULL;
		} else {
			path = strndup (paths, pos - paths);
			paths = pos + 1;
		}

		return_val_if_fail (path != NULL, -1);

		if (path[0] != '\0') {
			/* We don't expect this to fail except for in strange circumstances */
			ret = loader_load_path (token, path, flags);
			if (ret < 0)
				return_val_if_reached (-1);
			total += ret;
		}

		free (path);
	}

	return total;
}

static int
load_builtin_objects (p11_token *token)
{
	CK_OBJECT_CLASS builtin = CKO_NETSCAPE_BUILTIN_ROOT_LIST;
	const char *vlabel = "Trust Anchor Roots";
	CK_BBOOL vtrue = CK_TRUE;
	CK_BBOOL vfalse = CK_FALSE;
	CK_ATTRIBUTE *attrs;

	CK_ATTRIBUTE klass = { CKA_CLASS, &builtin, sizeof (builtin) };
	CK_ATTRIBUTE tok = { CKA_TOKEN, &vtrue, sizeof (vtrue) };
	CK_ATTRIBUTE priv = { CKA_PRIVATE, &vfalse, sizeof (vfalse) };
	CK_ATTRIBUTE modifiable = { CKA_MODIFIABLE, &vfalse, sizeof (vfalse) };
	CK_ATTRIBUTE label = { CKA_LABEL, (void *)vlabel, strlen (vlabel) };

	attrs = p11_attrs_build (NULL, &klass, &tok, &priv, &modifiable, &label, NULL);
	return_val_if_fail (attrs != NULL, 0);

	on_parser_object (attrs, token);
	return 1;
}

int
p11_token_load (p11_token *token)
{
	int builtins;
	int anchors;
	int other;

	if (token->loaded)
		return 0;
	token->loaded = 1;

	builtins = load_builtin_objects (token);

	anchors = loader_load_paths (token, token->anchor_paths, P11_PARSE_FLAG_ANCHOR);
	if (anchors < 0)
		return anchors;

	other = loader_load_paths (token, token->other_paths, P11_PARSE_FLAG_NONE);
	if (other < 0)
		return other;

	return anchors + builtins + other;
}

p11_dict *
p11_token_objects (p11_token *token)
{
	return token->objects;
}

void
p11_token_free (p11_token *token)
{
	if (!token)
		return;

	p11_dict_free (token->objects);
	p11_parser_free (token->parser);
	free (token);
}

p11_token *
p11_token_new (const char *anchor_paths,
               const char *other_paths)
{
	p11_token *token;

	token = calloc (1, sizeof (p11_token));
	return_val_if_fail (token != NULL, NULL);

	token->parser = p11_parser_new ();
	return_val_if_fail (token->parser != NULL, NULL);

	token->objects = p11_dict_new (p11_dict_ulongptr_hash,
	                               p11_dict_ulongptr_equal,
	                               free, p11_attrs_free);
	return_val_if_fail (token->objects != NULL, NULL);

	token->anchor_paths = anchor_paths;
	token->other_paths = other_paths;
	token->loaded = 0;

	return token;
}
