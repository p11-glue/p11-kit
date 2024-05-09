/*
 * Copyright (c) 2024 Red Hat Inc.
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
 * Author: Daiki Ueno
 */

#include "config.h"

#include "p11-kit/version.h"
#include "library.h"
#include "test.h"

static void
test_check_compile_time (void)
{
#if !P11_KIT_CHECK_VERSION (P11_KIT_VERSION_MAJOR, P11_KIT_VERSION_MINOR, P11_KIT_VERSION_MICRO)
	assert_not_reached ();
#endif

#if !P11_KIT_CHECK_VERSION (P11_KIT_VERSION_MAJOR, P11_KIT_VERSION_MINOR, 0)
	assert_not_reached ();
#endif

#if !P11_KIT_CHECK_VERSION (P11_KIT_VERSION_MAJOR, 0, 0)
	assert_not_reached ();
#endif

#if P11_KIT_CHECK_VERSION (P11_KIT_VERSION_MAJOR + 1, P11_KIT_VERSION_MINOR, P11_KIT_VERSION_MICRO)
	assert_not_reached ();
#endif

#if P11_KIT_CHECK_VERSION (P11_KIT_VERSION_MAJOR, P11_KIT_VERSION_MINOR + 1, P11_KIT_VERSION_MICRO)
	assert_not_reached ();
#endif

#if P11_KIT_CHECK_VERSION (P11_KIT_VERSION_MAJOR, P11_KIT_VERSION_MINOR, P11_KIT_VERSION_MICRO + 1)
	assert_not_reached ();
#endif
}

static void
test_check_run_time (void)
{
	assert_num_eq (1, p11_kit_check_version (P11_KIT_VERSION_MAJOR, P11_KIT_VERSION_MINOR, P11_KIT_VERSION_MICRO));
	assert_num_eq (1, p11_kit_check_version (P11_KIT_VERSION_MAJOR, P11_KIT_VERSION_MINOR, 0));
	assert_num_eq (1, p11_kit_check_version (P11_KIT_VERSION_MAJOR, 0, 0));
	assert_num_eq (0, p11_kit_check_version (P11_KIT_VERSION_MAJOR + 1, P11_KIT_VERSION_MINOR, P11_KIT_VERSION_MICRO));
	assert_num_eq (0, p11_kit_check_version (P11_KIT_VERSION_MAJOR, P11_KIT_VERSION_MINOR + 1, P11_KIT_VERSION_MICRO));
	assert_num_eq (0, p11_kit_check_version (P11_KIT_VERSION_MAJOR, P11_KIT_VERSION_MINOR, P11_KIT_VERSION_MICRO + 1));
}

int
main (int argc,
      char *argv[])
{
	p11_library_init ();

	p11_test (test_check_compile_time, "/version/test_check_compile_time");
	p11_test (test_check_run_time, "/version/test_check_run_time");

	return p11_test_run (argc, argv);
}
