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
#include "test.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "debug.h"
#include "buffer.h"

static void
test_init_uninit (void)
{
	p11_buffer buffer;

	p11_buffer_init (&buffer, 10);
	assert_ptr_not_null (buffer.data);
	assert_num_eq (0, buffer.len);
	assert_num_eq (0, buffer.flags);
	assert (buffer.size >= 10);
	assert_ptr_not_null (buffer.ffree);
	assert_ptr_not_null (buffer.frealloc);

	p11_buffer_uninit (&buffer);
}

static void
test_append (void)
{
	p11_buffer buffer;

	p11_buffer_init (&buffer, 10);
	buffer.len = 5;
	p11_buffer_append (&buffer, 35);
	assert_num_eq (5 + 35, buffer.len);
	assert (buffer.size >= 35 + 5);

	p11_buffer_append (&buffer, 15);
	assert_num_eq (5 + 35 + 15, buffer.len);
	assert (buffer.size >= 5 + 35 + 15);

	p11_buffer_uninit (&buffer);
}

static void
test_null (void)
{
	p11_buffer buffer;

	p11_buffer_init_null (&buffer, 10);
	p11_buffer_add (&buffer, "Blah", -1);
	p11_buffer_add (&buffer, " blah", -1);

	assert_str_eq ("Blah blah", buffer.data);

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
test_init_for_data (void)
{
	p11_buffer buffer;
	unsigned char *ret;
	size_t len;

	mock_realloced = 0;
	mock_freed = 0;

	p11_buffer_init_full (&buffer, (unsigned char *)strdup ("blah"), 4, 0,
	                       mock_realloc, mock_free);

	assert_ptr_not_null (buffer.data);
	assert_str_eq ("blah", (char *)buffer.data);
	assert_num_eq (4, buffer.len);
	assert_num_eq (0, buffer.flags);
	assert_num_eq (4, buffer.size);
	assert_ptr_eq (mock_free, buffer.ffree);
	assert_ptr_eq (mock_realloc, buffer.frealloc);

	assert_num_eq (0, mock_realloced);
	assert_num_eq (0, mock_freed);

	len = buffer.len;
	ret = p11_buffer_append (&buffer, 1024);
	assert_ptr_eq ((char *)buffer.data + len, ret);
	assert_num_eq (1, mock_realloced);

	p11_buffer_uninit (&buffer);
	assert_num_eq (1, mock_realloced);
	assert_num_eq (1, mock_freed);
}

static void
test_steal (void)
{
	p11_buffer buffer;
	char *string;
	size_t length;

	mock_freed = 0;

	p11_buffer_init_full (&buffer, (unsigned char *)strdup ("blah"), 4,
	                      P11_BUFFER_NULL, mock_realloc, mock_free);

	assert_ptr_not_null (buffer.data);
	assert_str_eq ("blah", buffer.data);

	p11_buffer_add (&buffer, " yada", -1);
	assert_str_eq ("blah yada", buffer.data);

	string = p11_buffer_steal (&buffer, &length);
	p11_buffer_uninit (&buffer);

	assert_str_eq ("blah yada", string);
	assert_num_eq (9, length);
	assert_num_eq (0, mock_freed);

	free (string);
}

static void
test_add (void)
{
	p11_buffer buffer;

	p11_buffer_init (&buffer, 10);

	p11_buffer_add (&buffer, (unsigned char *)"Planet Express", 15);
	assert_num_eq (15, buffer.len);
	assert_str_eq ("Planet Express", (char *)buffer.data);
	assert (p11_buffer_ok (&buffer));

	p11_buffer_uninit (&buffer);
}

int
main (int argc,
      char *argv[])
{
	p11_test (test_init_uninit, "/buffer/init-uninit");
	p11_test (test_init_for_data, "/buffer/init-for-data");
	p11_test (test_append, "/buffer/append");
	p11_test (test_null, "/buffer/null");
	p11_test (test_add, "/buffer/add");
	p11_test (test_steal, "/buffer/steal");
	return p11_test_run (argc, argv);
}
