/*
 * Copyright (C) 2012-2013 Red Hat Inc.
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
#include "constants.h"
#define P11_DEBUG_FLAG P11_DEBUG_TRUST
#include "debug.h"
#include "errno.h"
#include "message.h"
#include "module.h"
#include "parser.h"
#include "path.h"
#include "persist.h"
#include "pkcs11.h"
#include "pkcs11x.h"
#include "save.h"
#include "token.h"

#include <sys/stat.h>
#include <sys/types.h>

#include <assert.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct _p11_token {
	p11_parser *parser;       /* Parser we use to load files */
	p11_index *index;         /* Index we load objects into */
	p11_builder *builder;     /* Expands objects and applies policy */
	p11_dict *loaded;         /* stat structs for loaded files, track reloads */

	char *path;               /* Main path to load from */
	char *anchors;            /* Path to load anchors from */
	char *blacklist;          /* Path to load blacklist from */
	char *label;              /* The token label */
	CK_SLOT_ID slot;          /* The slot id */

	bool checked_path;
	bool is_writable;
	bool make_directory;
};

static bool
loader_is_necessary (p11_token *token,
                     const char *filename,
                     struct stat *sb)
{
	struct stat *last;

	last = p11_dict_get (token->loaded, filename);

	/* Never seen this before, load it */
	if (last == NULL)
		return true;

	/*
	 * If any of these are different assume that the file
	 * needs to be reloaded
	 */
	return (sb->st_mode != last->st_mode ||
	        sb->st_mtime != last->st_mtime ||
	        sb->st_size != last->st_size);
}

static void
loader_was_loaded (p11_token *token,
                   const char *filename,
                   struct stat *sb)
{
	char *key;

	key = strdup (filename);
	return_if_fail (key != NULL);

	sb = memdup (sb, sizeof (struct stat));
	return_if_fail (sb != NULL);

	/* Track the info about this file, so we don't reload unnecessarily */
	if (!p11_dict_set (token->loaded, key, sb))
		return_if_reached ();
}

static bool
loader_not_loaded (p11_token *token,
                   const char *filename)
{
	/* No longer track info about this file */
	return p11_dict_remove (token->loaded, filename);
}

static void
loader_gone_file (p11_token *token,
                  const char *filename)
{
	CK_ATTRIBUTE origin[] = {
		{ CKA_X_ORIGIN, (void *)filename, strlen (filename) },
		{ CKA_INVALID },
	};

	CK_RV rv;

	p11_index_load (token->index);

	/* Remove everything at this origin */
	rv = p11_index_replace_all (token->index, origin, CKA_INVALID, NULL);
	return_if_fail (rv == CKR_OK);

	p11_index_finish (token->index);

	/* No longer track info about this file */
	loader_not_loaded (token, filename);
}

static int
loader_load_file (p11_token *token,
                  const char *filename,
                  struct stat *sb)
{
	CK_ATTRIBUTE origin[] = {
		{ CKA_X_ORIGIN, (void *)filename, strlen (filename) },
		{ CKA_INVALID },
	};

	p11_array *parsed;
	CK_RV rv;
	int flags;
	int ret;
	int i;

	/* Check if this file is already loaded */
	if (!loader_is_necessary (token, filename, sb))
		return 0;

	flags = P11_PARSE_FLAG_NONE;

	/* If it's in the anchors subdirectory, treat as an anchor */
	if (p11_path_prefix (filename, token->anchors))
		flags = P11_PARSE_FLAG_ANCHOR;

	/* If it's in the blacklist subdirectory, treat as a blacklist */
	else if (p11_path_prefix (filename, token->blacklist))
		flags = P11_PARSE_FLAG_BLACKLIST;

	/* If the token is just one path, then assume they are anchors */
	else if (strcmp (filename, token->path) == 0 && !S_ISDIR (sb->st_mode))
		flags = P11_PARSE_FLAG_ANCHOR;

	ret = p11_parse_file (token->parser, filename, sb, flags);

	switch (ret) {
	case P11_PARSE_SUCCESS:
		p11_debug ("loaded: %s", filename);
		break;
	case P11_PARSE_UNRECOGNIZED:
		p11_debug ("skipped: %s", filename);
		loader_gone_file (token, filename);
		return 0;
	default:
		p11_debug ("failed to parse: %s", filename);
		loader_gone_file (token, filename);
		return 0;
	}

	/* Update each parsed object with the origin */
	parsed = p11_parser_parsed (token->parser);
	for (i = 0; i < parsed->num; i++) {
		parsed->elem[i] = p11_attrs_build (parsed->elem[i], origin, NULL);
		return_val_if_fail (parsed->elem[i] != NULL, 0);
	}

	p11_index_load (token->index);

	/* Now place all of these in the index */
	rv = p11_index_replace_all (token->index, origin, CKA_CLASS, parsed);

	p11_index_finish (token->index);

	if (rv != CKR_OK) {
		p11_message ("couldn't load file into objects: %s", filename);
		return 0;
	}

	loader_was_loaded (token, filename, sb);
	return 1;
}

static int
loader_load_if_file (p11_token *token,
                     const char *path)
{
	struct stat sb;

	if (stat (path, &sb) < 0) {
		if (errno != ENOENT)
			p11_message_err (errno, "couldn't stat path: %d: %s", errno, path);

	} else if (!S_ISDIR (sb.st_mode)) {
		return loader_load_file (token, path, &sb);
	}

	/* Perhaps the file became unloadable, so track properly */
	loader_gone_file (token, path);
	return 0;
}

static int
loader_load_directory (p11_token *token,
                       const char *directory,
                       p11_dict *present)
{
	p11_dictiter iter;
	struct dirent *dp;
	char *path;
	int total = 0;
	int ret;
	DIR *dir;

	/* First we load all the modules */
	dir = opendir (directory);
	if (!dir) {
		p11_message_err (errno, "couldn't list directory: %s", directory);
		loader_not_loaded (token, directory);
		return 0;
	}

	while ((dp = readdir (dir)) != NULL) {
		path = p11_path_build (directory, dp->d_name, NULL);
		return_val_if_fail (path != NULL, -1);

		ret = loader_load_if_file (token, path);
		return_val_if_fail (ret >=0, -1);
		total += ret;

		/* Make note that this file was seen */
		p11_dict_remove (present, path);

		free (path);
	}

	closedir (dir);

	/* All other files that were present, not here now */
	p11_dict_iterate (present, &iter);
	while (p11_dict_next (&iter, (void **)&path, NULL))
		loader_gone_file (token, path);

	return total;
}

static int
loader_load_path (p11_token *token,
                  const char *path,
                  bool *is_dir)
{
	p11_dictiter iter;
	p11_dict *present;
	char *filename;
	struct stat sb;
	int total;
	int ret;

	if (stat (path, &sb) < 0) {
		if (errno != ENOENT)
			p11_message_err (errno, "cannot access trust certificate path: %s", path);
		loader_gone_file (token, path);
		*is_dir = false;
		ret = 0;

	} else if (S_ISDIR (sb.st_mode)) {
		*is_dir = true;
		ret = 0;

		/* All the files we know about at this path */
		present = p11_dict_new (p11_dict_str_hash, p11_dict_str_equal, NULL, NULL);
		p11_dict_iterate (token->loaded, &iter);
		while (p11_dict_next (&iter, (void **)&filename, NULL)) {
			if (p11_path_prefix (filename, path)) {
				if (!p11_dict_set (present, filename, filename))
					return_val_if_reached (-1);
			}
		}

		/* If the directory has changed, reload it */
		if (loader_is_necessary (token, path, &sb)) {
			ret = loader_load_directory (token, path, present);

		/* Directory didn't change, but maybe files changed? */
		} else {
			total = 0;
			p11_dict_iterate (present, &iter);
			while (p11_dict_next (&iter, (void **)&filename, NULL)) {
				ret = loader_load_if_file (token, filename);
				return_val_if_fail (ret >= 0, ret);
				total += ret;
			}
		}

		p11_dict_free (present);
		loader_was_loaded (token, path, &sb);

	} else {
		*is_dir = false;
		ret = loader_load_file (token, path, &sb);
	}

	return ret;
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

	p11_index_load (token->index);
	rv = p11_index_take (token->index, p11_attrs_dup (builtin_root_list), NULL);
	return_val_if_fail (rv == CKR_OK, 0);
	p11_index_finish (token->index);
	return 1;
}

int
p11_token_load (p11_token *token)
{
	int total = 0;
	bool is_dir;
	int ret;

	ret = loader_load_path (token, token->path, &is_dir);
	return_val_if_fail (ret >= 0, -1);
	total += ret;

	if (is_dir) {
		ret = loader_load_path (token, token->anchors, &is_dir);
		return_val_if_fail (ret >= 0, -1);
		total += ret;

		ret = loader_load_path (token, token->blacklist, &is_dir);
		return_val_if_fail (ret >= 0, -1);
		total += ret;
	}

	return total;
}

bool
p11_token_reload (p11_token *token,
                  CK_ATTRIBUTE *attrs)
{
	CK_ATTRIBUTE *attr;
	struct stat sb;
	char *origin;
	bool ret;

	attr = p11_attrs_find (attrs, CKA_X_ORIGIN);
	if (attr == NULL)
		return false;

	origin = strndup (attr->pValue, attr->ulValueLen);
	return_val_if_fail (origin != NULL, false);

	if (stat (origin, &sb) < 0) {
		if (errno == ENOENT) {
			loader_gone_file (token, origin);
		} else {
			p11_message_err (errno, "cannot access trust file: %s", origin);
		}
		ret = false;

	} else {
		ret = loader_load_file (token, origin, &sb) > 0;
	}

	free (origin);
	return ret;
}

static bool
check_directory (const char *path,
                 bool *make_directory,
                 bool *is_writable)
{
	struct stat sb;
	char *parent;
	bool dummy;
	bool ret;

	/*
	 * This function attempts to determine whether a later write
	 * to this token will succeed so we can setup the appropriate
	 * token flags. Yes, it is racy, but that's inherent to the problem.
	 */

	if (stat (path, &sb) == 0) {
		*make_directory = false;
		*is_writable = S_ISDIR (sb.st_mode) && access (path, W_OK) == 0;
		return true;
	}

	switch (errno) {
	case EACCES:
		*is_writable = false;
		*make_directory = false;
		return true;
	case ENOENT:
		*make_directory = true;
		parent = p11_path_parent (path);
		if (parent == NULL)
			ret = false;
		else
			ret = check_directory (parent, &dummy, is_writable);
		free (parent);
		return ret;
	default:
		p11_message_err (errno, "couldn't access: %s", path);
		return false;
	}
}

static bool
check_token_directory (p11_token *token)
{
	if (!token->checked_path) {
		token->checked_path = check_directory (token->path,
		                                       &token->make_directory,
		                                       &token->is_writable);
	}

	return token->checked_path;
}

static bool
writer_remove_origin (p11_token *token,
                         CK_ATTRIBUTE *origin)
{
	bool ret = true;
	char *path;

	path = strndup (origin->pValue, origin->ulValueLen);
	return_val_if_fail (path != NULL, false);

	if (unlink (path) < 0) {
		p11_message_err (errno, "couldn't remove file: %s", path);
		ret = false;
	}

	free (path);
	return ret;
}

static p11_save_file *
writer_overwrite_origin (p11_token *token,
                         CK_ATTRIBUTE *origin)
{
	p11_save_file *file;
	char *path;

	path = strndup (origin->pValue, origin->ulValueLen);
	return_val_if_fail (path != NULL, NULL);

	file = p11_save_open_file (path, NULL, P11_SAVE_OVERWRITE);
	free (path);

	return file;
}

static char *
writer_suggest_name (CK_ATTRIBUTE *attrs)
{
	CK_ATTRIBUTE *label;
	CK_OBJECT_CLASS klass;
	const char *nick;

	label = p11_attrs_find (attrs, CKA_LABEL);
	if (label && label->ulValueLen)
		return strndup (label->pValue, label->ulValueLen);

	nick = NULL;
	if (p11_attrs_find_ulong (attrs, CKA_CLASS, &klass))
		nick = p11_constant_nick (p11_constant_classes, klass);
	if (nick == NULL)
		nick = "object";
	return strdup (nick);
}

static p11_save_file *
writer_create_origin (p11_token *token,
                      CK_ATTRIBUTE *attrs)
{
	p11_save_file *file;
	char *name;
	char *path;

	name = writer_suggest_name (attrs);
	return_val_if_fail (name != NULL, NULL);

	p11_path_canon (name);

	path = p11_path_build (token->path, name, NULL);
	free (name);

	file = p11_save_open_file (path, ".p11-kit", P11_SAVE_UNIQUE);
	free (path);

	return file;
}

static CK_RV
writer_put_header (p11_save_file *file)
{
	const char *header =
		"# This file has been auto-generated and written by p11-kit. Changes will be\n"
		"# unceremoniously overwritten.\n"
		"#\n"
		"# The format is designed to be somewhat human readable and debuggable, and a\n"
		"# bit transparent but it is not encouraged to read/write this format from other\n"
		"# applications or tools without first discussing this at the the mailing list:\n"
		"#\n"
		"#       p11-glue@lists.freedesktop.org\n"
		"#\n";

	if (!p11_save_write (file, header, -1))
		return CKR_FUNCTION_FAILED;

	return CKR_OK;
}

static CK_RV
writer_put_object (p11_save_file *file,
                   p11_persist *persist,
                   p11_buffer *buffer,
                   CK_ATTRIBUTE *attrs)
{
	if (!p11_buffer_reset (buffer, 0))
		assert_not_reached ();
	if (!p11_persist_write (persist, attrs, buffer))
		return_val_if_reached (CKR_GENERAL_ERROR);
	if (!p11_save_write (file, buffer->data, buffer->len))
		return CKR_FUNCTION_FAILED;

	return CKR_OK;
}

static bool
mkdir_with_parents (const char *path)
{
	char *parent;
	bool ret;

#ifdef OS_UNIX
	int mode = S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH;
	if (mkdir (path, mode) == 0)
#else
	if (mkdir (path) == 0)
#endif
		return true;

	switch (errno) {
	case ENOENT:
		parent = p11_path_parent (path);
		if (parent != NULL) {
			ret = mkdir_with_parents (parent);
			free (parent);
			if (ret == true) {
#ifdef OS_UNIX
				if (mkdir (path, mode) == 0)
#else
				if (mkdir (path) == 0)
#endif
					return true;
			}
		}
		/* fall through */
	default:
		p11_message_err (errno, "couldn't create directory: %s", path);
		return false;
	}
}

static CK_RV
on_index_build (void *data,
                p11_index *index,
                CK_ATTRIBUTE *attrs,
                CK_ATTRIBUTE *merge,
                CK_ATTRIBUTE **extra)
{
	p11_token *token = data;
	return p11_builder_build (token->builder, index, attrs, merge, extra);
}

static CK_RV
on_index_store (void *data,
                p11_index *index,
                CK_OBJECT_HANDLE handle,
                CK_ATTRIBUTE **attrs)
{
	p11_token *token = data;
	CK_OBJECT_HANDLE *other;
	p11_persist *persist;
	p11_buffer buffer;
	CK_ATTRIBUTE *origin;
	CK_ATTRIBUTE *object;
	p11_save_file *file;
	bool creating = false;
	char *path;
	CK_RV rv;
	int i;

	/* Signifies that data is being loaded, don't write out */
	if (p11_index_loading (index))
		return CKR_OK;

	if (!check_token_directory (token))
		return CKR_FUNCTION_FAILED;

	if (token->make_directory) {
		if (!mkdir_with_parents (token->path))
			return CKR_FUNCTION_FAILED;
		token->make_directory = false;
	}

	/* Do we already have a filename? */
	origin = p11_attrs_find (*attrs, CKA_X_ORIGIN);
	if (origin == NULL) {
		file = writer_create_origin (token, *attrs);
		creating = true;
		other = NULL;

	} else {
		other = p11_index_find_all (index, origin, 1);
		file = writer_overwrite_origin (token, origin);
		creating = false;
	}

	if (file == NULL) {
		free (origin);
		free (other);
		return CKR_GENERAL_ERROR;
	}

	persist = p11_persist_new ();
	p11_buffer_init (&buffer, 1024);

	rv = writer_put_header (file);
	if (rv == CKR_OK)
		rv = writer_put_object (file, persist, &buffer, *attrs);

	for (i = 0; rv == CKR_OK && other && other[i] != 0; i++) {
		if (other[i] != handle) {
			object = p11_index_lookup (index, other[i]);
			if (object != NULL)
				rv = writer_put_object (file, persist, &buffer, object);
		}
	}

	p11_buffer_uninit (&buffer);
	p11_persist_free (persist);
	free (other);

	if (rv == CKR_OK) {
		if (!p11_save_finish_file (file, &path, true))
			rv = CKR_FUNCTION_FAILED;
		else if (creating)
			*attrs = p11_attrs_take (*attrs, CKA_X_ORIGIN, path, strlen (path));
		else
			free (path);
	} else {
		p11_save_finish_file (file, NULL, false);
	}

	return rv;
}

static CK_RV
on_index_remove (void *data,
                 p11_index *index,
                 CK_ATTRIBUTE *attrs)
{
	p11_token *token = data;
	CK_OBJECT_HANDLE *other;
	p11_persist *persist;
	p11_buffer buffer;
	CK_ATTRIBUTE *origin;
	CK_ATTRIBUTE *object;
	p11_save_file *file;
	CK_RV rv = CKR_OK;
	int i;

	/* Signifies that data is being loaded, don't write out */
	if (p11_index_loading (index))
		return CKR_OK;

	if (!check_token_directory (token))
		return CKR_FUNCTION_FAILED;

	/* We should have a file name */
	origin = p11_attrs_find (attrs, CKA_X_ORIGIN);
	return_val_if_fail (origin != NULL, CKR_GENERAL_ERROR);

	/* If there are other objects in this file, then rewrite it */
	other = p11_index_find_all (index, origin, 1);
	if (other && other[0]) {
		file = writer_overwrite_origin (token, origin);
		if (file == NULL) {
			free (other);
			return CKR_GENERAL_ERROR;
		}

		persist = p11_persist_new ();
		p11_buffer_init (&buffer, 1024);

		rv = writer_put_header (file);
		for (i = 0; rv == CKR_OK && other && other[i] != 0; i++) {
			object = p11_index_lookup (index, other[i]);
			if (object != NULL)
				rv = writer_put_object (file, persist, &buffer, object);
		}

		if (rv == CKR_OK) {
			if (!p11_save_finish_file (file, NULL, true))
				rv = CKR_FUNCTION_FAILED;
		} else {
			p11_save_finish_file (file, NULL, false);
		}

		p11_persist_free (persist);
		p11_buffer_uninit (&buffer);

	/* Otherwise just remove the file */
	} else {
		if (!writer_remove_origin (token, origin))
			rv = CKR_FUNCTION_FAILED;
	}

	free (other);

	return rv;
}

static void
on_index_notify (void *data,
                 p11_index *index,
                 CK_OBJECT_HANDLE handle,
                 CK_ATTRIBUTE *attrs)
{
	p11_token *token = data;
	p11_builder_changed (token->builder, index, handle, attrs);
}

void
p11_token_free (p11_token *token)
{
	if (!token)
		return;

	p11_index_free (token->index);
	p11_parser_free (token->parser);
	p11_builder_free (token->builder);
	p11_dict_free (token->loaded);
	free (token->path);
	free (token->anchors);
	free (token->blacklist);
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

	token->index = p11_index_new (on_index_build,
	                              on_index_store,
	                              on_index_remove,
	                              on_index_notify,
	                              token);
	return_val_if_fail (token->index != NULL, NULL);

	token->parser = p11_parser_new (p11_builder_get_cache (token->builder));
	return_val_if_fail (token->parser != NULL, NULL);
	p11_parser_formats (token->parser, p11_parser_format_persist,
	                    p11_parser_format_pem, p11_parser_format_x509, NULL);

	token->loaded = p11_dict_new (p11_dict_str_hash, p11_dict_str_equal, free, free);
	return_val_if_fail (token->loaded != NULL, NULL);

	token->path = p11_path_expand (path);
	return_val_if_fail (token->path != NULL, NULL);

	token->anchors = p11_path_build (token->path, "anchors", NULL);
	return_val_if_fail (token->anchors != NULL, NULL);

	token->blacklist = p11_path_build (token->path, "blacklist", NULL);
	return_val_if_fail (token->blacklist != NULL, NULL);

	token->label = strdup (label);
	return_val_if_fail (token->label != NULL, NULL);

	token->slot = slot;

	load_builtin_objects (token);

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

p11_parser *
p11_token_parser (p11_token *token)
{
	return_val_if_fail (token != NULL, NULL);
	return token->parser;
}

bool
p11_token_is_writable (p11_token *token)
{
	if (!check_token_directory (token))
		return false;
	return token->is_writable;
}
