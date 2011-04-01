/*
 * Copyright (c) 2005 Stefan Walter
 * Copyright (c) 2011 Collabora Ltd.
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
 *
 * CONTRIBUTORS
 *  Stef Walter <stef@memberwebs.com>
 */

#include "config.h"

#include "conf.h"

#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <assert.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void
errmsg (conf_error_func error_func, const char* msg, ...)
{
	#define MAX_MSGLEN  1024
	char buf[MAX_MSGLEN];
	va_list ap;

	if (!error_func)
		return;

	va_start (ap, msg);
	vsnprintf (buf, MAX_MSGLEN, msg, ap);
	buf[MAX_MSGLEN - 1] = 0;
	error_func (buf);
	va_end (ap);
}

static void
strcln (char* data, char ch)
{
	char* p;
	for (p = data; *data; data++, p++) {
		while (*data == ch)
			data++;
		*p = *data;
	}

	/* Renull terminate */
	*p = 0;
}

static char*
strbtrim (const char* data)
{
	while (*data && isspace (*data))
		++data;
	return (char*)data;
}

static void
stretrim (char* data)
{
	char* t = data + strlen (data);
	while (t > data && isspace (*(t - 1))) {
		t--;
		*t = 0;
	}
}

static char*
strtrim (char* data)
{
	data = (char*)strbtrim (data);
	stretrim (data);
	return data;
}

/* -----------------------------------------------------------------------------
 * CONFIG PARSER
 */

static char*
read_config_file (const char* filename, int flags,
                  conf_error_func error_func)
{
	char* config = NULL;
	FILE* f = NULL;
	long len;

	assert (filename);

	f = fopen (filename, "r");
	if (f == NULL) {
		if ((flags & CONF_IGNORE_MISSING) &&
		    (errno == ENOENT || errno == ENOTDIR)) {
			config = strdup ("\n");
			if (!config)
				errno = ENOMEM;
			return config;
		}
		errmsg (error_func, "couldn't open config file: %s", filename);
		return NULL;
	}

	/* Figure out size */
	if (fseek (f, 0, SEEK_END) == -1 ||
	    (len = ftell (f)) == -1 ||
	    fseek (f, 0, SEEK_SET) == -1) {
		errmsg (error_func, "couldn't seek config file: %s", filename);
		return NULL;
	}

	if ((config = (char*)malloc (len + 2)) == NULL) {
		errmsg (error_func, "out of memory");
		errno = ENOMEM;
		return NULL;
	}

	/* And read in one block */
	if (fread (config, 1, len, f) != len) {
		errmsg (error_func, "couldn't read config file: %s", filename);
		return NULL;
	}

	fclose (f);

	/* Null terminate the data */
	config[len] = '\n';
	config[len + 1] = 0;

	/* Remove nasty dos line endings */
	strcln (config, '\r');

	return config;
}

hash_t*
conf_parse_file (const char* filename, int flags,
                 conf_error_func error_func)
{
	char *name;
	char *value;
	hash_t *ht = NULL;
	char *config;
	char *next;
	char *end;

	assert (filename);

	/* Adds an extra newline to end of file */
	config = read_config_file (filename, flags, error_func);
	if (!config)
		return NULL;

	ht = hash_create (hash_string_hash, hash_string_equal, free, free);
	next = config;

	/* Go through lines and process them */
	while ((end = strchr (next, '\n')) != NULL) {
		*end = 0;
		name = strbtrim (next);
		next = end + 1;

		/* Empty lines / comments at start */
		if (!*name || *name == '#')
			continue;

		/* Look for the break between name: value on the same line */
		value = name + strcspn (name, ":");
		if (!*value) {
			errmsg (error_func, "%s: invalid config line: %s", filename, name);
			errno = EINVAL;
			break;
		}

		/* Null terminate and split value part */
		*value = 0;
		value++;

		name = strtrim (name);
		value = strtrim (value);

		name = strdup (name);
		if (!name) {
			errno = ENOMEM;
			break;
		}
		value = strdup (value);
		if (!value) {
			free (name);
			errno = ENOMEM;
			break;
		}
		if (!hash_set (ht, name, value)) {
			free (name);
			free (value);
			errno = ENOMEM;
			break;
		}
	}

	/* Unsuccessful? */
	if (end != NULL) {
		hash_free (ht);
		ht = NULL;
	}

	free (config);
	return ht;
}
