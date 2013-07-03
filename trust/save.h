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

#ifndef P11_SAVE_H_
#define P11_SAVE_H_

#include "compat.h"

enum {
	P11_SAVE_OVERWRITE = 1 << 0,
	P11_SAVE_UNIQUE = 1 << 1,
};

typedef struct _p11_save_file p11_save_file;
typedef struct _p11_save_dir p11_save_dir;

p11_save_file *  p11_save_open_file         (const char *path,
                                             const char *extension,
                                             int flags);

bool             p11_save_write             (p11_save_file *file,
                                             const void *data,
                                             ssize_t length);

bool             p11_save_write_and_finish  (p11_save_file *file,
                                             const void *data,
                                             ssize_t length);

bool             p11_save_finish_file       (p11_save_file *file,
                                             char **path,
                                             bool commit);

const char *     p11_save_file_name         (p11_save_file *file);

p11_save_dir *   p11_save_open_directory    (const char *path,
                                             int flags);

p11_save_file *  p11_save_open_file_in      (p11_save_dir *directory,
                                             const char *basename,
                                             const char *extension);

#ifdef OS_UNIX

bool             p11_save_symlink_in        (p11_save_dir *dir,
                                             const char *linkname,
                                             const char *extension,
                                             const char *destination);

#endif /* OS_UNIX */

bool             p11_save_finish_directory  (p11_save_dir *dir,
                                             bool commit);

#endif /* P11_SAVE_H_ */
