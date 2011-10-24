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

#ifndef DEBUG_H
#define DEBUG_H

/* Please keep this enum in sync with keys in debug.c */
typedef enum {
	DEBUG_LIB = 1 << 1,
	DEBUG_CONF = 1 << 2,
	DEBUG_URI = 1 << 3,
	DEBUG_PROXY = 1 << 4,
} DebugFlags;

extern int        _p11_debug_current_flags;

void              _p11_debug_init                (void);

void              _p11_debug_message             (int flag,
                                                  const char *format,
                                                  ...);

#endif /* DEBUG_H */

/* -----------------------------------------------------------------------------
 * Below this point is outside the DEBUG_H guard - so it can take effect
 * more than once. So you can do:
 *
 * #define DEBUG_FLAG DEBUG_ONE_THING
 * #include "debug.h"
 * ...
 * DEBUG ("if we're debugging one thing");
 * ...
 * #undef DEBUG_FLAG
 * #define DEBUG_FLAG DEBUG_OTHER_THING
 * #include "debug.h"
 * ...
 * DEBUG ("if we're debugging the other thing");
 * ...
 */

#ifdef DEBUG_FLAG
#ifdef WITH_DEBUG

#undef _p11_debug
#define _p11_debug(format, ...) do { \
	if (DEBUG_FLAG & _p11_debug_current_flags) \
		_p11_debug_message (DEBUG_FLAG, "%s: " format, __PRETTY_FUNCTION__, ##__VA_ARGS__); \
	} while (0)

#undef _p11_debugging
#define _p11_debugging \
	(DEBUG_FLAG & _p11_debug_current_flags)

#else /* !defined (WITH_DEBUG) */

#undef _p11_debug
#define _p11_debug(format, ...) \
	do {} while (0)

#undef _p11_debugging
#define _p11_debugging 0

#endif /* !defined (WITH_DEBUG) */

#endif /* defined (DEBUG_FLAG) */
