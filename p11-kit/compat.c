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

#include "config.h"

#include "compat.h"
#include "private.h"

#include <assert.h>

#ifdef OS_UNIX

void
_p11_mutex_init (mutex_t *mutex)
{
	pthread_mutexattr_t attr;
	int ret;

	pthread_mutexattr_init (&attr);
	pthread_mutexattr_settype (&attr, PTHREAD_MUTEX_RECURSIVE);
	ret = pthread_mutex_init (mutex, &attr);
	assert (ret == 0);
	pthread_mutexattr_destroy (&attr);
}

#endif /* OS_UNIX */

#ifdef OS_WIN32

const char *
_p11_module_error (void)
{
	DWORD code = GetLastError();
	p11_local *local;
	LPVOID msg_buf;

	local = _p11_library_get_thread_local ();

	FormatMessageA (FORMAT_MESSAGE_ALLOCATE_BUFFER |
	                FORMAT_MESSAGE_FROM_SYSTEM |
	                FORMAT_MESSAGE_IGNORE_INSERTS,
	                NULL, code,
	                MAKELANGID (LANG_NEUTRAL, SUBLANG_DEFAULT),
	                (LPSTR)&msg_buf, 0, NULL);

	if (local->last_error)
		LocalFree (local->last_error);
	local->last_error = msg_buf;

	return msg_buf;
}

int
_p11_thread_create (thread_t *thread,
               thread_routine routine,
               void *arg)
{
	assert (thread);

	*thread = CreateThread (NULL, 0,
	                        (LPTHREAD_START_ROUTINE)routine,
	                        arg, 0, NULL);

	if (*thread == NULL)
		return GetLastError ();

	return 0;
}

int
_p11_thread_join (thread_t thread)
{
	DWORD res;

	res = WaitForSingleObject (thread, INFINITE);
	if (res == WAIT_FAILED)
		return GetLastError ();

	CloseHandle (thread);
	return 0;
}

#endif /* OS_WIN32 */
