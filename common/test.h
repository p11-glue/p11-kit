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

#include "compat.h"

#ifndef P11_TEST_H_
#define P11_TEST_H_

#ifndef P11_TEST_SOURCE

#include <string.h>

#ifdef assert_not_reached
#undef assert_not_reached
#endif

#ifdef assert
#undef assert
#endif

#define assert(expr) \
	assert_true(expr)
#define assert_true(expr) \
	do { if (expr) ; else \
		p11_test_fail (__FILE__, __LINE__, __FUNCTION__, "assertion failed (%s)", #expr); \
	} while (0)
#define assert_false(expr) \
	do { if (expr) \
		p11_test_fail (__FILE__, __LINE__, __FUNCTION__, "assertion failed (!(%s))", #expr); \
	} while (0)
#define assert_fail(msg, detail) \
	do { const char *__s = (detail); \
		p11_test_fail (__FILE__, __LINE__, __FUNCTION__, "%s%s%s", (msg), __s ? ": ": "", __s ? __s : ""); \
	} while (0)
#define assert_not_reached(msg) \
	do { \
		p11_test_fail (__FILE__, __LINE__, __FUNCTION__, "code should not be reached"); \
	} while (0)
#define assert_ptr_not_null(ptr) \
	do { if ((ptr) != NULL) ; else \
		p11_test_fail (__FILE__, __LINE__, __FUNCTION__, "assertion failed (%s != NULL)", #ptr); \
	} while (0)
#define assert_num_cmp(a1, cmp, a2) \
	do { unsigned long __n1 = (a1); \
	     unsigned long __n2 = (a2); \
	     if (__n1 cmp __n2) ; else \
		p11_test_fail (__FILE__, __LINE__, __FUNCTION__, "assertion failed (%s %s %s): (%lu %s %lu)", \
		               #a1, #cmp, #a2, __n1, #cmp, __n2); \
	} while (0)
#define assert_num_eq(a1, a2) \
	assert_num_cmp(a1, ==, a2)
#define assert_str_cmp(a1, cmp, a2) \
	do { const char *__s1 = (a1); \
	     const char *__s2 = (a2); \
	     if (__s1 && __s2 && strcmp (__s1, __s2) cmp 0) ; else \
	         p11_test_fail (__FILE__, __LINE__, __FUNCTION__, "assertion failed (%s %s %s): (%s %s %s)", \
	                        #a1, #cmp, #a2, __s1 ? __s1 : "(null)", #cmp, __s2 ? __s2 : "(null)"); \
	} while (0)
#define assert_str_eq(a1, a2) \
	assert_str_cmp(a1, ==, a2)
#define assert_ptr_eq(a1, a2) \
	do { const void *__p1 = (a1); \
	     const void *__p2 = (a2); \
	     if (__p1 == __p2) ; else \
	         p11_test_fail (__FILE__, __LINE__, __FUNCTION__, "assertion failed (%s == %s): (0x%08lx == 0x%08lx)", \
	                        #a1, #a2, (unsigned long)(size_t)__p1, (unsigned long)(size_t)__p2); \
	} while (0)

#define assert_str_contains(expr, needle) \
	do { const char *__str = (expr); \
	     if (__str && strstr (__str, needle)) ; else \
	         p1_test_fail (__FILE__, __LINE__, __FUNCTION__, "assertion failed (%s): '%s' does not contain '%s'", \
	                       #expr, __str, needle); \
	} while (0)

#endif /* !P11_TEST_SOURCE */


void        p11_test_fail           (const char *filename,
                                     int line,
                                     const char *function,
                                     const char *message,
                                     ...) GNUC_PRINTF(4, 5) CLANG_ANALYZER_NORETURN;

void        p11_test                (void (* function) (void),
                                     const char *name,
                                     ...) GNUC_PRINTF(2, 3);

void        p11_testx               (void (* function) (void *),
                                     void *argument,
                                     const char *name,
                                     ...) GNUC_PRINTF(3, 4);

void        p11_fixture             (void (* setup) (void *),
                                     void (* teardown) (void *));

int         p11_test_run            (int argc,
                                     char **argv);

char *      p11_test_directory      (const char *prefix);

void        p11_test_directory_delete  (const char *directory);

void        p11_test_file_write     (const char *directory,
                                     const char *name,
                                     const void *contents,
                                     size_t length);

void        p11_test_file_delete    (const char *directory,
                                     const char *name);

#ifdef OS_UNIX

char *      p11_test_copy_setgid    (const char *path);

int         p11_test_run_child      (const char **argv,
                                     bool quiet_out);

#endif

#endif /* P11_TEST_H_ */
