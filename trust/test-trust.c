/*
 * Copyright (c) 2012 Red Hat Inc.
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
 * Author: Stef Walter <stefw@gnome.org>
 */

#include "config.h"

#include "attrs.h"
#include "debug.h"
#include "message.h"
#include "path.h"
#include "test.h"

#include "test-trust.h"

#include <sys/stat.h>

#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#ifdef OS_UNIX
#include <paths.h>
#endif

void
test_check_object_msg (const char *file,
                       int line,
                       const char *function,
                       CK_ATTRIBUTE *attrs,
                       CK_OBJECT_CLASS klass,
                       const char *label)
{
	CK_BBOOL vfalse = CK_FALSE;

	CK_ATTRIBUTE expected[] = {
		{ CKA_PRIVATE, &vfalse, sizeof (vfalse) },
		{ CKA_CLASS, &klass, sizeof (klass) },
		{ label ? CKA_LABEL : CKA_INVALID, (void *)label, label ? strlen (label) : 0 },
		{ CKA_INVALID },
	};

	test_check_attrs_msg (file, line, function, expected, attrs);
}

void
test_check_cacert3_ca_msg (const char *file,
                           int line,
                           const char *function,
                           CK_ATTRIBUTE *attrs,
                           const char *label)
{
	CK_CERTIFICATE_TYPE x509 = CKC_X_509;
	CK_ULONG category = 2; /* authority */

	CK_ATTRIBUTE expected[] = {
		{ CKA_CERTIFICATE_TYPE, &x509, sizeof (x509) },
		{ CKA_CERTIFICATE_CATEGORY, &category, sizeof (category) },
		{ CKA_VALUE, (void *)test_cacert3_ca_der, sizeof (test_cacert3_ca_der) },
		{ CKA_CHECK_VALUE, "\xad\x7c\x3f", 3 },
		{ CKA_START_DATE, "20110523", 8 },
		{ CKA_END_DATE, "20210520", 8, },
		{ CKA_SUBJECT, (void *)test_cacert3_ca_subject, sizeof (test_cacert3_ca_subject) },
		{ CKA_ISSUER, (void *)test_cacert3_ca_issuer, sizeof (test_cacert3_ca_issuer) },
		{ CKA_SERIAL_NUMBER, (void *)test_cacert3_ca_serial, sizeof (test_cacert3_ca_serial) },
		{ CKA_INVALID },
	};

	test_check_object_msg (file, line, function, attrs, CKO_CERTIFICATE, label);
	test_check_attrs_msg (file, line, function, expected, attrs);
}

void
test_check_id_msg (const char *file,
                   int line,
                   const char *function,
                   CK_ATTRIBUTE *expected,
                   CK_ATTRIBUTE *attr)
{
	CK_ATTRIBUTE *one;
	CK_ATTRIBUTE *two;

	one = p11_attrs_find (expected, CKA_ID);
	two = p11_attrs_find (attr, CKA_ID);

	test_check_attr_msg (file, line, function, CKA_INVALID, one, two);
}

void
test_check_attrs_msg (const char *file,
                      int line,
                      const char *function,
                      CK_ATTRIBUTE *expected,
                      CK_ATTRIBUTE *attrs)
{
	CK_OBJECT_CLASS klass;
	CK_ATTRIBUTE *attr;

	assert (expected != NULL);

	if (!p11_attrs_find_ulong (expected, CKA_CLASS, &klass))
		klass = CKA_INVALID;

	while (!p11_attrs_terminator (expected)) {
		attr = p11_attrs_find (attrs, expected->type);
		test_check_attr_msg (file, line, function, klass, expected, attr);
		expected++;
	}
}

void
test_check_attr_msg (const char *file,
                     int line,
                     const char *function,
                     CK_OBJECT_CLASS klass,
                     CK_ATTRIBUTE *expected,
                     CK_ATTRIBUTE *attr)
{
	assert (expected != NULL);

	if (attr == NULL) {
		p11_test_fail (file, line, function,
		               "attribute does not match: (expected %s but found NULL)",
		               p11_attr_to_string (expected, klass));
	}

	if (!p11_attr_equal (attr, expected)) {
		p11_test_fail (file, line, function,
		               "attribute does not match: (expected %s but found %s)",
		               p11_attr_to_string (expected, klass),
		               attr ? p11_attr_to_string (attr, klass) : "(null)");
	}
}

static char *
read_file (const char *file,
           int line,
           const char *function,
           const char *filename,
           long *len)
{
	struct stat sb;
	FILE *f = NULL;
	char *data;

	f = fopen (filename, "rb");
	if (f == NULL)
		p11_test_fail (file, line, function, "Couldn't open file: %s", filename);

	/* Figure out size */
	if (stat (filename, &sb) < 0)
		p11_test_fail (file, line, function, "Couldn't stat file: %s", filename);

	*len = sb.st_size;
	data = malloc (*len ? *len : 1);
	assert (data != NULL);

	/* And read in one block */
	if (fread (data, 1, *len, f) != *len)
		p11_test_fail (file, line, function, "Couldn't read file: %s", filename);

	fclose (f);

	return data;
}

void
test_check_file_msg (const char *file,
                     int line,
                     const char *function,
                     const char *directory,
                     const char *name,
                     const char *reference)
{
	char *refdata;
	long reflen;

	refdata = read_file (file, line, function, reference, &reflen);
	test_check_data_msg (file, line, function, directory, name, refdata, reflen);
	free (refdata);
}

void
test_check_data_msg (const char *file,
                     int line,
                     const char *function,
                     const char *directory,
                     const char *name,
                     const void *refdata,
                     long reflen)
{
	char *filedata;
	char *filename;
	long filelen;

	if (asprintf (&filename, "%s/%s", directory, name) < 0)
		assert_not_reached ();

	filedata = read_file (file, line, function, filename, &filelen);

	if (filelen != reflen || memcmp (filedata, refdata, reflen) != 0)
		p11_test_fail (file, line, function, "File contents not as expected: %s", filename);

	if (unlink (filename) < 0)
		p11_test_fail (file, line, function, "Couldn't remove file: %s", filename);
	free (filename);
	free (filedata);
}

#ifdef OS_UNIX

void
test_check_symlink_msg (const char *file,
                        int line,
                        const char *function,
                        const char *directory,
                        const char *name,
                        const char *destination)
{
	char buf[1024] = { 0, };
	char *filename;

	if (asprintf (&filename, "%s/%s", directory, name) < 0)
		assert_not_reached ();

	if (readlink (filename, buf, sizeof (buf)) < 0)
		p11_test_fail (file, line, function, "Couldn't read symlink: %s", filename);

	if (strcmp (destination, buf) != 0)
		p11_test_fail (file, line, function, "Symlink contents wrong: %s != %s", destination, buf);

	if (unlink (filename) < 0)
		p11_test_fail (file, line, function, "Couldn't remove symlink: %s", filename);
	free (filename);
}

#endif /* OS_UNIX */

p11_dict *
test_check_directory_files (const char *file,
                            ...)
{
	p11_dict *files;
	va_list va;

	files = p11_dict_new (p11_dict_str_hash, p11_dict_str_equal, NULL, NULL);

	va_start (va, file);

	while (file != NULL) {
		if (!p11_dict_set (files, (void *)file, (void *)file))
			return_val_if_reached (NULL);
		file = va_arg (va, const char *);
	}

	va_end (va);

	return files;
}

void
test_check_directory_msg (const char *file,
                          int line,
                          const char *function,
                          const char *directory,
                          p11_dict *files)
{
	p11_dictiter iter;
	struct dirent *dp;
	const char *name;
	DIR *dir;

	dir = opendir (directory);
	if (dir == NULL)
		p11_test_fail (file ,line, function, "Couldn't open directory: %s", directory);

	while ((dp = readdir (dir)) != NULL) {
		if (strcmp (dp->d_name, ".") == 0 ||
		    strcmp (dp->d_name, "..") == 0)
			continue;

		if (!p11_dict_remove (files, dp->d_name))
			p11_test_fail  (file, line, function, "Unexpected file in directory: %s", dp->d_name);
	}

	closedir (dir);

#ifdef OS_UNIX
	if (chmod (directory, S_IRWXU) < 0)
		p11_test_fail (file, line, function, "couldn't chown directory: %s: %s", directory, strerror (errno));
#endif

	p11_dict_iterate (files, &iter);
	while (p11_dict_next (&iter, (void **)&name, NULL))
		p11_test_fail (file, line, function, "Couldn't find file in directory: %s", name);

	p11_dict_free (files);
}
