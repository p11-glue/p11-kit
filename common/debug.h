/*
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

#ifndef P11_DEBUG_H
#define P11_DEBUG_H

#include "compat.h"

/* Please keep this enum in sync with keys in debug.c */
enum {
	P11_DEBUG_LIB = 1 << 1,
	P11_DEBUG_CONF = 1 << 2,
	P11_DEBUG_URI = 1 << 3,
	P11_DEBUG_PROXY = 1 << 4,
	P11_DEBUG_TRUST = 1 << 5,
	P11_DEBUG_TOOL = 1 << 6,
	P11_DEBUG_RPC = 1 << 7,
};

extern int        p11_debug_current_flags;

void              p11_debug_init                (void);

void              p11_debug_message             (int flag,
                                                 const char *format,
                                                 ...) GNUC_PRINTF (2, 3);

void              p11_debug_precond             (const char *format,
                                                 ...) GNUC_PRINTF (1, 2)
                                                 CLANG_ANALYZER_NORETURN;

#ifndef assert_not_reached
#define assert_not_reached() \
	(assert (false && "this code should not be reached"))
#endif

#define return_val_if_fail(x, v) \
	do { if (!(x)) { \
	     p11_debug_precond ("p11-kit: '%s' not true at %s\n", #x, __func__); \
	     return v; \
	} } while (false)

#define return_if_fail(x) \
	do { if (!(x)) { \
	     p11_debug_precond ("p11-kit: '%s' not true at %s\n", #x, __func__); \
	     return; \
	} } while (false)

#define return_if_reached() \
	do { \
	     p11_debug_precond ("p11-kit: shouldn't be reached at %s\n", __func__); \
	     return; \
	} while (false)

#define return_val_if_reached(v) \
	do { \
	     p11_debug_precond ("p11-kit: shouldn't be reached at %s\n", __func__); \
	     return v; \
	} while (false)

#define warn_if_reached(v) \
	do { \
	     p11_debug_precond ("p11-kit: shouldn't be reached at %s\n", __func__); \
	} while (false)

#define warn_if_fail(x) \
	do { if (!(x)) { \
	     p11_debug_precond ("p11-kit: '%s' not true at %s\n", #x, __func__); \
	} } while (false)

#endif /* DEBUG_H */

/* -----------------------------------------------------------------------------
 * Below this point is outside the DEBUG_H guard - so it can take effect
 * more than once. So you can do:
 *
 * #define P11_DEBUG_FLAG P11_DEBUG_ONE_THING
 * #include "debug.h"
 * ...
 * p11_debug ("if we're debugging one thing");
 * ...
 * #undef P11_DEBUG_FLAG
 * #define P11_DEBUG_FLAG DEBUG_OTHER_THING
 * #include "debug.h"
 * ...
 * p11_debug ("if we're debugging the other thing");
 * ...
 */

#ifdef P11_DEBUG_FLAG
#ifdef WITH_DEBUG

#undef p11_debug
#define p11_debug(format, ...) do { \
	if (P11_DEBUG_FLAG & p11_debug_current_flags) \
		p11_debug_message (P11_DEBUG_FLAG, "%s: " format, __PRETTY_FUNCTION__, ##__VA_ARGS__); \
	} while (0)

#undef p11_debugging
#define p11_debugging \
	(P11_DEBUG_FLAG & p11_debug_current_flags)

#else /* !defined (WITH_DEBUG) */

#undef p11_debug
#define p11_debug(format, ...) \
	do {} while (false)

#undef p11_debugging
#define p11_debugging (0)

#endif /* !defined (WITH_DEBUG) */

#endif /* defined (P11_DEBUG_FLAG) */
