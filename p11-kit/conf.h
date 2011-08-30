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
 * Author: Stef Walter <stefw@collabora.co.uk>
 */

#ifndef __CONF_H__
#define __CONF_H__

#include "hashmap.h"

enum {
	CONF_IGNORE_MISSING = 0x01,
};

enum {
	CONF_USER_INVALID = 0,
	CONF_USER_NONE = 1,
	CONF_USER_MERGE,
	CONF_USER_ONLY
};

int           _p11_conf_merge_defaults       (hashmap *config,
                                              hashmap *defaults);

/* Returns a hash of char *key -> char *value */
hashmap *     _p11_conf_parse_file           (const char *filename,
                                              int flags);

/* Returns a hash of char *key -> char *value */
hashmap *     _p11_conf_load_globals         (const char *system_conf, const char *user_conf,
                                              int *user_mode);

/* Returns a hash of char* name -> hash_t *config */
hashmap *     _p11_conf_load_modules         (int user_mode, const char *system_dir,
                                              const char *user_dir);

int           _p11_conf_parse_boolean        (const char *string,
                                              int default_value);

#endif /* __CONF_H__ */
