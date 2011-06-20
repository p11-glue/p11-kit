/*
 * Copyright (c) 2011, Collabora Ltd.
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

#include "config.h"
#include "CuTest.h"

#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "p11-kit/pin.h"

static int
callback_one (const char *pinfile, P11KitUri *pin_uri, const char *pin_description,
              P11KitPinFlags pin_flags, void *callback_data, char *pin,
              size_t pin_max)
{
	int *data = callback_data;
	assert (*data == 33);
	strncpy (pin, "one", pin_max);
	return 1;
}

static int
callback_other (const char *pinfile, P11KitUri *pin_uri, const char *pin_description,
                P11KitPinFlags pin_flags, void *callback_data, char *pin,
                size_t pin_max)
{
	char *data = callback_data;
	strncpy (pin, data, pin_max);
	return 1;
}

static void
destroy_data (void *callback_data)
{
	int *data = callback_data;
	(*data)++;
}

static void
test_pin_register_unregister (CuTest *tc)
{
	int data = 33;

	p11_kit_pin_register_callback ("/the/pinfile", callback_one,
	                               &data, destroy_data);

	p11_kit_pin_unregister_callback ("/the/pinfile", callback_one,
	                                 &data);

	CuAssertIntEquals (tc, 34, data);
}

static void
test_pin_read (CuTest *tc)
{
	P11KitUri *uri;
	char buffer[256];
	int data = 33;
	int ret;

	p11_kit_pin_register_callback ("/the/pinfile", callback_one,
	                               &data, destroy_data);

	uri = p11_kit_uri_new ();
	ret = p11_kit_pin_read_pinfile ("/the/pinfile", uri, "The token",
	                                P11_KIT_PIN_FLAGS_USER_LOGIN,
	                                buffer, sizeof (buffer));
	p11_kit_uri_free (uri);

	CuAssertIntEquals (tc, 1, ret);
	CuAssertStrEquals (tc, "one", buffer);

	p11_kit_pin_unregister_callback ("/the/pinfile", callback_one,
	                                 &data);
}

static void
test_pin_read_no_match (CuTest *tc)
{
	P11KitUri *uri;
	char buffer[256];
	int ret;

	uri = p11_kit_uri_new ();
	ret = p11_kit_pin_read_pinfile ("/the/pinfile", uri, "The token",
	                                P11_KIT_PIN_FLAGS_USER_LOGIN,
	                                buffer, sizeof (buffer));
	p11_kit_uri_free (uri);

	CuAssertIntEquals (tc, 0, ret);
}

static void
test_pin_register_duplicate (CuTest *tc)
{
	P11KitUri *uri;
	char *value = "secret";
	char buffer[256];
	int data = 33;
	int ret;

	uri = p11_kit_uri_new ();

	p11_kit_pin_register_callback ("/the/pinfile", callback_one,
	                               &data, destroy_data);

	p11_kit_pin_register_callback ("/the/pinfile", callback_other,
	                               value, NULL);

	ret = p11_kit_pin_read_pinfile ("/the/pinfile", uri, "The token",
	                                P11_KIT_PIN_FLAGS_USER_LOGIN,
	                                buffer, sizeof (buffer));

	CuAssertIntEquals (tc, 1, ret);
	CuAssertStrEquals (tc, "secret", buffer);

	p11_kit_pin_unregister_callback ("/the/pinfile", callback_other,
	                                 value);

	ret = p11_kit_pin_read_pinfile ("/the/pinfile", uri, "The token",
	                                P11_KIT_PIN_FLAGS_USER_LOGIN,
	                                buffer, sizeof (buffer));

	CuAssertIntEquals (tc, 1, ret);
	CuAssertStrEquals (tc, "one", buffer);

	p11_kit_pin_unregister_callback ("/the/pinfile", callback_one,
	                                 &data);

	ret = p11_kit_pin_read_pinfile ("/the/pinfile", uri, "The token",
	                                P11_KIT_PIN_FLAGS_USER_LOGIN,
	                                buffer, sizeof (buffer));

	CuAssertIntEquals (tc, 0, ret);

	p11_kit_uri_free (uri);
}

static void
test_pin_register_fallback (CuTest *tc)
{
	char *value = "secret";
	P11KitUri *uri;
	char buffer[256];
	int data = 33;
	int ret;

	uri = p11_kit_uri_new ();

	p11_kit_pin_register_callback (P11_KIT_PIN_FALLBACK, callback_one,
	                               &data, destroy_data);

	ret = p11_kit_pin_read_pinfile ("/the/pinfile", uri, "The token",
	                                P11_KIT_PIN_FLAGS_USER_LOGIN,
	                                buffer, sizeof (buffer));

	CuAssertIntEquals (tc, 1, ret);
	CuAssertStrEquals (tc, "one", buffer);

	p11_kit_pin_register_callback ("/the/pinfile", callback_other,
	                               value, NULL);

	ret = p11_kit_pin_read_pinfile ("/the/pinfile", uri, "The token",
	                                P11_KIT_PIN_FLAGS_USER_LOGIN,
	                                buffer, sizeof (buffer));

	CuAssertIntEquals (tc, 1, ret);
	CuAssertStrEquals (tc, "secret", buffer);

	p11_kit_pin_unregister_callback ("/the/pinfile", callback_other,
	                                 value);

	p11_kit_pin_unregister_callback (P11_KIT_PIN_FALLBACK, callback_one,
	                                 &data);

	p11_kit_uri_free (uri);
}

int
main (void)
{
	CuString *output = CuStringNew ();
	CuSuite* suite = CuSuiteNew ();
	int ret;

	SUITE_ADD_TEST (suite, test_pin_register_unregister);
	SUITE_ADD_TEST (suite, test_pin_read);
	SUITE_ADD_TEST (suite, test_pin_read_no_match);
	SUITE_ADD_TEST (suite, test_pin_register_duplicate);
	SUITE_ADD_TEST (suite, test_pin_register_fallback);

	CuSuiteRun (suite);
	CuSuiteSummary (suite, output);
	CuSuiteDetails (suite, output);
	printf ("%s\n", output->buffer);
	ret = suite->failCount;
	CuSuiteDelete (suite);
	CuStringDelete (output);

	return ret;
}

#include "CuTest.c"
