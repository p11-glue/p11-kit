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
 * Author: Stef Walter <stef@thewalter.net>
 */

#include "config.h"
#include "CuTest.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "debug.h"
#include "buffer.h"

static void
test_init_uninit (CuTest *tc)
{
	p11_buffer buffer;

	p11_buffer_init (&buffer, 10);
	CuAssertPtrNotNull (tc, buffer.data);
	CuAssertIntEquals (tc, 0, buffer.len);
	CuAssertIntEquals (tc, 0, buffer.flags);
	CuAssertTrue (tc, buffer.size >= 10);
	CuAssertPtrNotNull (tc, buffer.ffree);
	CuAssertPtrNotNull (tc, buffer.frealloc);

	p11_buffer_uninit (&buffer);
}

static void
test_append (CuTest *tc)
{
	p11_buffer buffer;

	p11_buffer_init (&buffer, 10);
	buffer.len = 5;
	p11_buffer_append (&buffer, 35);
	CuAssertIntEquals (tc, 5 + 35, buffer.len);
	CuAssertTrue (tc, buffer.size >= 35 + 5);

	p11_buffer_append (&buffer, 15);
	CuAssertIntEquals (tc, 5 + 35 + 15, buffer.len);
	CuAssertTrue (tc, buffer.size >= 5 + 35 + 15);

	p11_buffer_uninit (&buffer);
}

static void
test_null (CuTest *tc)
{
	p11_buffer buffer;

	p11_buffer_init_null (&buffer, 10);
	p11_buffer_add (&buffer, "Blah", -1);
	p11_buffer_add (&buffer, " blah", -1);

	CuAssertStrEquals (tc, "Blah blah", buffer.data);

	p11_buffer_uninit (&buffer);
}

static int mock_realloced = 0;
static int mock_freed = 0;

static void *
mock_realloc (void *data,
              size_t size)
{
	mock_realloced++;
	return realloc (data, size);
}

static void
mock_free (void *data)
{
	mock_freed++;
	free (data);
}

static void
test_init_for_data (CuTest *tc)
{
	p11_buffer buffer;
	unsigned char *ret;
	size_t len;

	mock_realloced = 0;
	mock_freed = 0;

	p11_buffer_init_full (&buffer, (unsigned char *)strdup ("blah"), 4, 0,
	                       mock_realloc, mock_free);

	CuAssertPtrNotNull (tc, buffer.data);
	CuAssertStrEquals (tc, "blah", (char *)buffer.data);
	CuAssertIntEquals (tc, 4, buffer.len);
	CuAssertIntEquals (tc, 0, buffer.flags);
	CuAssertIntEquals (tc, 4, buffer.size);
	CuAssertPtrEquals (tc, mock_free, buffer.ffree);
	CuAssertPtrEquals (tc, mock_realloc, buffer.frealloc);

	CuAssertIntEquals (tc, 0, mock_realloced);
	CuAssertIntEquals (tc, 0, mock_freed);

	len = buffer.len;
	ret = p11_buffer_append (&buffer, 1024);
	CuAssertPtrEquals (tc, (char *)buffer.data + len, ret);
	CuAssertIntEquals (tc, 1, mock_realloced);

	p11_buffer_uninit (&buffer);
	CuAssertIntEquals (tc, 1, mock_realloced);
	CuAssertIntEquals (tc, 1, mock_freed);
}

static void
test_steal (CuTest *tc)
{
	p11_buffer buffer;
	char *string;
	size_t length;

	mock_freed = 0;

	p11_buffer_init_full (&buffer, (unsigned char *)strdup ("blah"), 4,
	                      P11_BUFFER_NULL, mock_realloc, mock_free);

	CuAssertPtrNotNull (tc, buffer.data);
	CuAssertStrEquals (tc, "blah", buffer.data);

	p11_buffer_add (&buffer, " yada", -1);
	CuAssertStrEquals (tc, "blah yada", buffer.data);

	string = p11_buffer_steal (&buffer, &length);
	p11_buffer_uninit (&buffer);

	CuAssertStrEquals (tc, "blah yada", string);
	CuAssertIntEquals (tc, 9, length);
	CuAssertIntEquals (tc, 0, mock_freed);

	free (string);
}

static void
test_add (CuTest *tc)
{
	p11_buffer buffer;

	p11_buffer_init (&buffer, 10);

	p11_buffer_add (&buffer, (unsigned char *)"Planet Express", 15);
	CuAssertIntEquals (tc, 15, buffer.len);
	CuAssertStrEquals (tc, "Planet Express", (char *)buffer.data);
	CuAssertTrue (tc, p11_buffer_ok (&buffer));

	p11_buffer_uninit (&buffer);
}

int
main (void)
{
	CuString *output = CuStringNew ();
	CuSuite* suite = CuSuiteNew ();
	int ret;

	setenv ("P11_KIT_STRICT", "1", 1);
	p11_debug_init ();

	SUITE_ADD_TEST (suite, test_init_uninit);
	SUITE_ADD_TEST (suite, test_init_for_data);
	SUITE_ADD_TEST (suite, test_append);
	SUITE_ADD_TEST (suite, test_null);
	SUITE_ADD_TEST (suite, test_add);
	SUITE_ADD_TEST (suite, test_steal);

	CuSuiteRun (suite);
	CuSuiteSummary (suite, output);
	CuSuiteDetails (suite, output);
	printf ("%s\n", output->buffer);
	ret = suite->failCount;
	CuSuiteDelete (suite);
	CuStringDelete (output);

	return ret;
}
