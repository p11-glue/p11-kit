/*
 * Copyright (c) 2012 Stefan Walter
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
 * Author: Stef Walter <stef@thewalter.net>
 */

#include "config.h"
#include "test.h"

#include "library.h"

#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "p11-kit/uri.h"
#include "p11-kit/p11-kit.h"
#include "p11-kit/private.h"

static void
test_progname_default (void)
{
	const char *progname;

	progname = _p11_get_progname_unlocked ();
	assert_str_eq ("test-progname", progname);
}

static void
test_progname_set (void)
{
	const char *progname;

	p11_kit_set_progname ("love-generation");

	progname = _p11_get_progname_unlocked ();
	assert_str_eq ("love-generation", progname);

	_p11_set_progname_unlocked (NULL);

	progname = _p11_get_progname_unlocked ();
	assert_str_eq ("test-progname", progname);
}

/* Defined in util.c */
extern char p11_my_progname[];

int
main (int argc,
      char *argv[])
{
	p11_library_init ();

	p11_test (test_progname_default, "/progname/test_progname_default");
	p11_test (test_progname_set, "/progname/test_progname_set");
	return p11_test_run (argc, argv);
}
