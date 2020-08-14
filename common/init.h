/*
 * Copyright (c) 2011 Collabora Ltd
 * Copyright (c) 2012 Stef Walter
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
 *
 * CONTRIBUTORS
 *  Stef Walter <stef@thewalter.net>
 */

#include "library.h"

#ifndef P11_INIT_H
#define P11_INIT_H

#ifdef OS_UNIX

void INIT (void);

void FINI (void);

#ifdef __GNUC__
__attribute__((constructor))
#endif
void
INIT (void)
{
	p11_library_init ();
}

#ifdef __GNUC__
__attribute__((destructor))
#endif
void
FINI (void)
{
	CLEANUP;
	p11_library_uninit ();
}

#endif /* OS_UNIX */

#ifdef OS_WIN32

BOOL WINAPI DllMain (HINSTANCE, DWORD, LPVOID);

BOOL WINAPI
DllMain (HINSTANCE instance,
         DWORD reason,
         LPVOID reserved)
{
	switch (reason) {
	case DLL_PROCESS_ATTACH:
		p11_library_init ();
		break;
	case DLL_THREAD_DETACH:
		p11_library_thread_cleanup ();
		break;
	case DLL_PROCESS_DETACH:
		CLEANUP;
		p11_library_uninit ();
		break;
	default:
		break;
	}

	return TRUE;
}

#endif /* OS_WIN32 */

#endif /* P11_INIT_H */
