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
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "p11-kit/pin.h"
#include "p11-kit/private.h"

static P11KitPin *
callback_one (const char *pin_source, P11KitUri *pin_uri, const char *pin_description,
              P11KitPinFlags pin_flags, void *callback_data)
{
	int *data = callback_data;
	assert (*data == 33);
	return p11_kit_pin_new_for_buffer ((unsigned char*)strdup ("one"), 3, free);
}

static P11KitPin*
callback_other (const char *pin_source, P11KitUri *pin_uri, const char *pin_description,
                P11KitPinFlags pin_flags, void *callback_data)
{
	char *data = callback_data;
	return p11_kit_pin_new_for_string (data);
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

	p11_kit_pin_register_callback ("/the/pin_source", callback_one,
	                               &data, destroy_data);

	p11_kit_pin_unregister_callback ("/the/pin_source", callback_one,
	                                 &data);

	CuAssertIntEquals (tc, 34, data);
}

static void
test_pin_read (CuTest *tc)
{
	P11KitUri *uri;
	P11KitPin *pin;
	int data = 33;
	size_t length;
	const unsigned char *ptr;

	p11_kit_pin_register_callback ("/the/pin_source", callback_one,
	                               &data, destroy_data);

	uri = p11_kit_uri_new ();
	pin = p11_kit_pin_request ("/the/pin_source", uri, "The token",
	                            P11_KIT_PIN_FLAGS_USER_LOGIN);
	p11_kit_uri_free (uri);

	CuAssertPtrNotNull (tc, pin);
	ptr = p11_kit_pin_get_value (pin, &length);
	CuAssertIntEquals (tc, 3, length);
	CuAssertTrue (tc, memcmp (ptr, "one", 3) == 0);

	p11_kit_pin_unregister_callback ("/the/pin_source", callback_one,
	                                 &data);

	p11_kit_pin_ref (pin);
	p11_kit_pin_unref (pin);
}

static void
test_pin_read_no_match (CuTest *tc)
{
	P11KitUri *uri;
	P11KitPin *pin;

	uri = p11_kit_uri_new ();
	pin = p11_kit_pin_request ("/the/pin_source", uri, "The token",
	                            P11_KIT_PIN_FLAGS_USER_LOGIN);
	p11_kit_uri_free (uri);

	CuAssertPtrEquals (tc, NULL, pin);
}

static void
test_pin_register_duplicate (CuTest *tc)
{
	P11KitUri *uri;
	P11KitPin *pin;
	char *value = "secret";
	int data = 33;
	size_t length;
	const unsigned char *ptr;

	uri = p11_kit_uri_new ();

	p11_kit_pin_register_callback ("/the/pin_source", callback_one,
	                               &data, destroy_data);

	p11_kit_pin_register_callback ("/the/pin_source", callback_other,
	                               value, NULL);

	pin = p11_kit_pin_request ("/the/pin_source", uri, "The token",
	                            P11_KIT_PIN_FLAGS_USER_LOGIN);

	CuAssertPtrNotNull (tc, pin);
	ptr = p11_kit_pin_get_value (pin, &length);
	CuAssertIntEquals (tc, 6, length);
	CuAssertTrue (tc, memcmp (ptr, "secret", length) == 0);
	p11_kit_pin_unref (pin);

	p11_kit_pin_unregister_callback ("/the/pin_source", callback_other,
	                                 value);

	pin = p11_kit_pin_request ("/the/pin_source", uri, "The token",
	                            P11_KIT_PIN_FLAGS_USER_LOGIN);

	CuAssertPtrNotNull (tc, pin);
	ptr = p11_kit_pin_get_value (pin, &length);
	CuAssertIntEquals (tc, 3, length);
	CuAssertTrue (tc, memcmp (ptr, "one", length) == 0);
	p11_kit_pin_unref (pin);

	p11_kit_pin_unregister_callback ("/the/pin_source", callback_one,
	                                 &data);

	pin = p11_kit_pin_request ("/the/pin_source", uri, "The token",
	                            P11_KIT_PIN_FLAGS_USER_LOGIN);

	CuAssertPtrEquals (tc, NULL, pin);

	p11_kit_uri_free (uri);
}

static void
test_pin_register_fallback (CuTest *tc)
{
	char *value = "secret";
	P11KitUri *uri;
	P11KitPin *pin;
	int data = 33;
	size_t length;
	const unsigned char *ptr;

	uri = p11_kit_uri_new ();

	p11_kit_pin_register_callback (P11_KIT_PIN_FALLBACK, callback_one,
	                               &data, destroy_data);

	pin = p11_kit_pin_request ("/the/pin_source", uri, "The token",
	                            P11_KIT_PIN_FLAGS_USER_LOGIN);

	CuAssertPtrNotNull (tc, pin);
	ptr = p11_kit_pin_get_value (pin, &length);
	CuAssertIntEquals (tc, 3, length);
	CuAssertTrue (tc, memcmp (ptr, "one", length) == 0);
	p11_kit_pin_unref (pin);

	p11_kit_pin_register_callback ("/the/pin_source", callback_other,
	                               value, NULL);

	pin = p11_kit_pin_request ("/the/pin_source", uri, "The token",
	                            P11_KIT_PIN_FLAGS_USER_LOGIN);

	CuAssertPtrNotNull (tc, pin);
	ptr = p11_kit_pin_get_value (pin, &length);
	CuAssertIntEquals (tc, 6, length);
	CuAssertTrue (tc, memcmp (ptr, "secret", length) == 0);
	p11_kit_pin_unref (pin);

	p11_kit_pin_unregister_callback ("/the/pin_source", callback_other,
	                                 value);

	p11_kit_pin_unregister_callback (P11_KIT_PIN_FALLBACK, callback_one,
	                                 &data);

	p11_kit_uri_free (uri);
}

static void
test_pin_file (CuTest *tc)
{
	P11KitUri *uri;
	P11KitPin *pin;
	size_t length;
	const unsigned char *ptr;

	uri = p11_kit_uri_new ();

	p11_kit_pin_register_callback (P11_KIT_PIN_FALLBACK, p11_kit_pin_file_callback,
	                               NULL, NULL);

	pin = p11_kit_pin_request (SRCDIR "/files/test-pinfile", uri, "The token",
	                            P11_KIT_PIN_FLAGS_USER_LOGIN);

	CuAssertPtrNotNull (tc, pin);
	ptr = p11_kit_pin_get_value (pin, &length);
	CuAssertIntEquals (tc, 12, length);
	CuAssertTrue (tc, memcmp (ptr, "yogabbagabba", length) == 0);
	p11_kit_pin_unref (pin);

	pin = p11_kit_pin_request (SRCDIR "/files/nonexistant", uri, "The token",
	                            P11_KIT_PIN_FLAGS_USER_LOGIN);

	CuAssertPtrEquals (tc, NULL, pin);

	p11_kit_pin_unregister_callback (P11_KIT_PIN_FALLBACK, p11_kit_pin_file_callback,
	                                 NULL);

	p11_kit_uri_free (uri);
}

static void
test_pin_ref_unref (CuTest *tc)
{
	P11KitPin *pin;
	P11KitPin *check;

	pin = p11_kit_pin_new_for_string ("crack of lies");

	check = p11_kit_pin_ref (pin);
	CuAssertPtrEquals (tc, pin, check);

	p11_kit_pin_unref (pin);
	p11_kit_pin_unref (check);
}

int
main (void)
{
	CuString *output = CuStringNew ();
	CuSuite* suite = CuSuiteNew ();
	int ret;

	_p11_library_init ();

	SUITE_ADD_TEST (suite, test_pin_register_unregister);
	SUITE_ADD_TEST (suite, test_pin_read);
	SUITE_ADD_TEST (suite, test_pin_read_no_match);
	SUITE_ADD_TEST (suite, test_pin_register_duplicate);
	SUITE_ADD_TEST (suite, test_pin_register_fallback);
	SUITE_ADD_TEST (suite, test_pin_file);
	SUITE_ADD_TEST (suite, test_pin_ref_unref);

	CuSuiteRun (suite);
	CuSuiteSummary (suite, output);
	CuSuiteDetails (suite, output);
	printf ("%s\n", output->buffer);
	ret = suite->failCount;
	CuSuiteDelete (suite);
	CuStringDelete (output);

	return ret;
}
