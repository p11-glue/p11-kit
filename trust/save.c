/*
 * Copyright (c) 2013, Red Hat Inc.
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

#include "buffer.h"
#include "debug.h"
#include "dict.h"
#include "message.h"
#include "save.h"

#include <sys/stat.h>

#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct _p11_save_file {
	char *bare;
	char *extension;
	char *temp;
	int fd;
	int flags;
};

struct _p11_save_dir {
	p11_dict *cache;
	char *path;
	int flags;
};

static char *   make_unique_name    (const char *bare,
                                     const char *extension,
                                     int (*check) (void *, char *),
                                     void *data);

bool
p11_save_write_and_finish (p11_save_file *file,
                           const void *data,
                           ssize_t length)
{
	bool ret;

	if (!file)
		return false;

	ret = p11_save_write (file, data, length);
	if (!p11_save_finish_file (file, NULL, ret))
		ret = false;

	return ret;
}

p11_save_file *
p11_save_open_file (const char *path,
                    const char *extension,
                    int flags)
{
	p11_save_file *file;
	char *temp;
	int fd;

	return_val_if_fail (path != NULL, NULL);

	if (extension == NULL)
		extension = "";

	if (asprintf (&temp, "%s%s.XXXXXX", path, extension) < 0)
		return_val_if_reached (NULL);

	fd = mkstemp (temp);
	if (fd < 0) {
		p11_message_err (errno, "couldn't create file: %s%s", path, extension);
		free (temp);
		return NULL;
	}

	file = calloc (1, sizeof (p11_save_file));
	return_val_if_fail (file != NULL, NULL);
	file->temp = temp;
	file->bare = strdup (path);
	return_val_if_fail (file->bare != NULL, NULL);
	file->extension = strdup (extension);
	return_val_if_fail (file->extension != NULL, NULL);
	file->flags = flags;
	file->fd = fd;

	return file;
}

bool
p11_save_write (p11_save_file *file,
                const void *data,
                ssize_t length)
{
	const unsigned char *buf = data;
	ssize_t written = 0;
	ssize_t res;

	if (!file)
		return false;

	/* Automatically calculate length */
	if (length < 0) {
		if (!data)
			return true;
		length = strlen (data);
	}

	while (written < length) {
		res = write (file->fd, buf + written, length - written);
		if (res <= 0) {
			if (errno == EAGAIN && errno == EINTR)
				continue;
			p11_message_err (errno, "couldn't write to file: %s", file->temp);
			return false;
		} else {
			written += res;
		}
	}

	return true;
}

static void
filo_free (p11_save_file *file)
{
	free (file->temp);
	free (file->bare);
	free (file->extension);
	free (file);
}

#ifdef OS_UNIX

static int
on_unique_try_link (void *data,
                    char *path)
{
	p11_save_file *file = data;

	if (link (file->temp, path) < 0) {
		if (errno == EEXIST)
			return 0; /* Continue trying other names */
		p11_message_err (errno, "couldn't complete writing of file: %s", path);
		return -1;
	}

	return 1; /* All done */
}

#else /* OS_WIN32 */

static int
on_unique_try_rename (void *data,
                      char *path)
{
	p11_save_file *file = data;

	if (rename (file->temp, path) < 0) {
		if (errno == EEXIST)
			return 0; /* Continue trying other names */
		p11_message ("couldn't complete writing of file: %s", path);
		return -1;
	}

	return 1; /* All done */
}

#endif /* OS_WIN32 */

bool
p11_save_finish_file (p11_save_file *file,
                      char **path_out,
                      bool commit)
{
	bool ret = true;
	char *path;

	if (!file)
		return false;

	if (!commit) {
		close (file->fd);
		unlink (file->temp);
		filo_free (file);
		return true;
	}

	if (asprintf (&path, "%s%s", file->bare, file->extension) < 0)
		return_val_if_reached (false);

	if (close (file->fd) < 0) {
		p11_message_err (errno, "couldn't write file: %s", file->temp);
		ret = false;

#ifdef OS_UNIX
	/* Set the mode of the file, readable by everyone, but not writable */
	} else if (chmod (file->temp, S_IRUSR | S_IRGRP | S_IROTH) < 0) {
		p11_message_err (errno, "couldn't set file permissions: %s", file->temp);
		close (file->fd);
		ret = false;

	/* Atomically rename the tempfile over the filename */
	} else if (file->flags & P11_SAVE_OVERWRITE) {
		if (rename (file->temp, path) < 0) {
			p11_message_err (errno, "couldn't complete writing file: %s", path);
			ret = false;
		} else {
			unlink (file->temp);
		}

	/* Create a unique name if requested unique file name */
	} else if (file->flags & P11_SAVE_UNIQUE) {
		free (path);
		path = make_unique_name (file->bare, file->extension,
		                         on_unique_try_link, file);
		if (!path)
			ret = false;
		unlink (file->temp);

	/* When not overwriting, link will fail if filename exists. */
	} else {
		if (link (file->temp, path) < 0) {
			p11_message_err (errno, "couldn't complete writing of file: %s", path);
			ret = false;
		}
		unlink (file->temp);

#else /* OS_WIN32 */

	/* Windows does not do atomic renames, so delete original file first */
	} else {
		/* Create a unique name if requested unique file name */
		if (file->flags & P11_SAVE_UNIQUE) {
			free (path);
			path = make_unique_name (file->bare, file->extension,
			                         on_unique_try_rename, file);
			if (!path)
				ret = false;

		} else if ((file->flags & P11_SAVE_OVERWRITE) &&
			    unlink (path) < 0 && errno != ENOENT) {
			p11_message_err (errno, "couldn't remove original file: %s", path);
			ret = false;
		}

		if (ret == true &&
		    rename (file->temp, path) < 0) {
			p11_message_err (errno, "couldn't complete writing file: %s", path);
			ret = false;
		}

		unlink (file->temp);

#endif /* OS_WIN32 */
	}

	if (ret && path_out) {
		*path_out = path;
		path = NULL;
	}

	free (path);
	filo_free (file);
	return ret;
}

p11_save_dir *
p11_save_open_directory (const char *path,
                         int flags)
{
#ifdef OS_UNIX
	struct stat sb;
#endif
	p11_save_dir *dir;

	return_val_if_fail (path != NULL, NULL);

#ifdef OS_UNIX
	/* We update the permissions when we finish writing */
	if (mkdir (path, S_IRWXU) < 0) {
#else /* OS_WIN32 */
	if (mkdir (path) < 0) {
#endif
		/* Some random error, report it */
		if (errno != EEXIST) {
			p11_message_err (errno, "couldn't create directory: %s", path);

		/* The directory exists and we're not overwriting */
		} else if (!(flags & P11_SAVE_OVERWRITE)) {
			p11_message ("directory already exists: %s", path);
			return NULL;
		}
#ifdef OS_UNIX
		/*
		 * If the directory exists on unix, we may have restricted
		 * the directory permissions to read-only. We have to change
		 * them back to writable in order for things to work.
		 */
		if (stat (path, &sb) >= 0) {
			if ((sb.st_mode & S_IRWXU) != S_IRWXU &&
			    chmod (path, S_IRWXU | sb.st_mode) < 0) {
				p11_message_err (errno, "couldn't make directory writable: %s", path);
				return NULL;
			}
		}
#endif /* OS_UNIX */
	}

	dir = calloc (1, sizeof (p11_save_dir));
	return_val_if_fail (dir != NULL, NULL);

	dir->path = strdup (path);
	return_val_if_fail (dir->path != NULL, NULL);

	dir->cache = p11_dict_new (p11_dict_str_hash, p11_dict_str_equal, free, NULL);
	return_val_if_fail (dir->cache != NULL, NULL);

	dir->flags = flags;
	return dir;
}

static char *
make_unique_name (const char *bare,
                  const char *extension,
                  int (*check) (void *, char *),
                  void *data)
{
	char unique[16];
	p11_buffer buf;
	int ret;
	int i;

	assert (bare != NULL);
	assert (check != NULL);

	p11_buffer_init_null (&buf, 0);

	for (i = 0; true; i++) {

		p11_buffer_reset (&buf, 64);

		switch (i) {

		/*
		 * For the first iteration, just build the filename as
		 * provided by the caller.
		 */
		case 0:
			p11_buffer_add (&buf, bare, -1);
			break;

		/*
		 * On later iterations we try to add a numeric .N suffix
		 * before the extension, so the resulting file might look
		 * like filename.1.ext.
		 *
		 * As a special case if the extension is already '.0' then
		 * just just keep incerementing that.
		 */
		case 1:
			if (extension && strcmp (extension, ".0") == 0)
				extension = NULL;
			/* fall through */

		default:
			p11_buffer_add (&buf, bare, -1);
			snprintf (unique, sizeof (unique), ".%d", i);
			p11_buffer_add (&buf, unique, -1);
			break;
		}

		if (extension)
			p11_buffer_add (&buf, extension, -1);

		return_val_if_fail (p11_buffer_ok (&buf), NULL);

		ret = check (data, buf.data);
		if (ret < 0)
			return NULL;
		else if (ret > 0)
			return p11_buffer_steal (&buf, NULL);
	}

	assert_not_reached ();
}

static int
on_unique_check_dir (void *data,
                     char *name)
{
	p11_save_dir *dir = data;

	if (!p11_dict_get (dir->cache, name))
		return 1;

	return 0; /* Keep looking */
}

p11_save_file *
p11_save_open_file_in (p11_save_dir *dir,
                       const char *basename,
                       const char *extension)
{
	p11_save_file *file = NULL;
	char *name;
	char *path;

	return_val_if_fail (dir != NULL, NULL);
	return_val_if_fail (basename != NULL, NULL);

	name = make_unique_name (basename, extension, on_unique_check_dir, dir);
	return_val_if_fail (name != NULL, NULL);

	if (asprintf (&path, "%s/%s", dir->path, name) < 0)
		return_val_if_reached (NULL);

	file = p11_save_open_file (path, NULL, dir->flags);

	if (file) {
		if (!p11_dict_set (dir->cache, name, name))
			return_val_if_reached (NULL);
		name = NULL;
	}

	free (name);
	free (path);

	return file;
}

#ifdef OS_UNIX

bool
p11_save_symlink_in (p11_save_dir *dir,
                     const char *linkname,
                     const char *extension,
                     const char *destination)
{
	char *name;
	char *path;
	bool ret;

	return_val_if_fail (dir != NULL, false);
	return_val_if_fail (linkname != NULL, false);
	return_val_if_fail (destination != NULL, false);

	name = make_unique_name (linkname, extension, on_unique_check_dir, dir);
	return_val_if_fail (name != NULL, false);

	if (asprintf (&path, "%s/%s", dir->path, name) < 0)
		return_val_if_reached (false);

	unlink (path);

	if (symlink (destination, path) < 0) {
		p11_message_err (errno, "couldn't create symlink: %s", path);
		ret = false;
	} else {
		if (!p11_dict_set (dir->cache, name, name))
			return_val_if_reached (false);
		name = NULL;
		ret = true;
	}

	free (path);
	free (name);

	return ret;
}

#endif /* OS_UNIX */

static bool
cleanup_directory (const char *directory,
                   p11_dict *cache)
{
	struct dirent *dp;
	struct stat st;
	p11_dict *remove;
	p11_dictiter iter;
	char *path;
	DIR *dir;
	bool ret;

	/* First we load all the modules */
	dir = opendir (directory);
	if (!dir) {
		p11_message_err (errno, "couldn't list directory: %s", directory);
		return false;
	}

	remove = p11_dict_new (p11_dict_str_hash, p11_dict_str_equal, free, NULL);

	while ((dp = readdir (dir)) != NULL) {
		if (p11_dict_get (cache, dp->d_name))
			continue;

		if (asprintf (&path, "%s/%s", directory, dp->d_name) < 0)
			return_val_if_reached (false);


		if (stat (path, &st) >= 0 && !S_ISDIR (st.st_mode)) {
			if (!p11_dict_set (remove, path, path))
				return_val_if_reached (false);
		} else {
			free (path);
		}
	}

	closedir (dir);

	ret = true;

	/* Remove all the files still in the cache */
	p11_dict_iterate (remove, &iter);
	while (p11_dict_next (&iter, (void **)&path, NULL)) {
		if (unlink (path) < 0 && errno != ENOENT) {
			p11_message_err (errno, "couldn't remove file: %s", path);
			ret = false;
			break;
		}
	}

	p11_dict_free (remove);

	return ret;
}

bool
p11_save_finish_directory (p11_save_dir *dir,
                           bool commit)
{
	bool ret = true;

	if (!dir)
		return false;

	if (commit) {
		if (dir->flags & P11_SAVE_OVERWRITE)
			ret = cleanup_directory (dir->path, dir->cache);

#ifdef OS_UNIX
		/* Try to set the mode of the directory to readable */
		if (ret && chmod (dir->path, S_IRUSR | S_IXUSR | S_IRGRP |
		                             S_IXGRP | S_IROTH | S_IXOTH) < 0) {
			p11_message_err (errno, "couldn't set directory permissions: %s", dir->path);
			ret = false;
		}
#endif /* OS_UNIX */
	}

	p11_dict_free (dir->cache);
	free (dir->path);
	free (dir);

	return ret;
}
