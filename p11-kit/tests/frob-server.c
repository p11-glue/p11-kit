/*
 * Copyright (C) 2013 Red Hat Inc.
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
 * Author: Stef Walter <stefw@redhat.com>
 */

#include "config.h"

#include "buffer.h"
#include "compat.h"
#include "debug.h"
#include "p11-kit.h"
#include "rpc.h"
#include "virtual.h"

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int
main (int argc,
      char *argv[])
{
	CK_FUNCTION_LIST *funcs;
	CK_C_GetFunctionList gfl;
	p11_rpc_status status;
	unsigned char version;
	p11_virtual virt;
	p11_buffer options;
	p11_buffer buffer;
	dl_module_t dl;
	size_t state;
	int code;
	CK_RV rv;

	p11_debug_init ();

	if (argc != 2) {
		fprintf (stderr, "usage: frob-server module\n");
		exit (2);
	}

	dl = p11_dl_open (argv[1]);
	if (dl == NULL) {
		fprintf (stderr, "couldn't load module: %s: %s\n",
		         argv[1], p11_dl_error ());
		exit (1);
	}

	gfl = p11_dl_symbol (dl, "C_GetFunctionList");
	if (!gfl) {
		fprintf (stderr, "couldn't find C_GetFunctionList entry point in module: %s: %s\n",
		         argv[1], p11_dl_error ());
		exit (1);
	}

	rv = gfl (&funcs);
	if (rv != CKR_OK) {
		fprintf (stderr, "call to C_GetFunctiontList failed in module: %s: %s\n",
		         argv[1], p11_kit_strerror (rv));
		exit (1);
	}

	p11_virtual_init (&virt, &p11_virtual_base, funcs, NULL);
	p11_buffer_init (&options, 0);
	p11_buffer_init (&buffer, 0);

	switch (read (0, &version, 1)) {
	case 0:
		status = P11_RPC_EOF;
		break;
	case 1:
		if (version != 0) {
			fprintf (stderr, "unspported version received: %d", (int)version);
			exit (1);
		}
		break;
	default:
		fprintf (stderr, "couldn't read creds: %s", strerror (errno));
		exit (1);
	}

	version = 0;
	switch (write (1, &version, 1)) {
	case 1:
		break;
	default:
		fprintf (stderr, "couldn't read creds: %s", strerror (errno));
		exit (1);
	}

	status = P11_RPC_OK;
	while (status == P11_RPC_OK) {
		state = 0;
		code = 0;

		do {
			status = p11_rpc_transport_read (0, &state, &code,
			                                 &options, &buffer);
		} while (status == P11_RPC_AGAIN);

		switch (status) {
		case P11_RPC_OK:
			break;
		case P11_RPC_EOF:
			continue;
		case P11_RPC_AGAIN:
			assert_not_reached ();
		case P11_RPC_ERROR:
			fprintf (stderr, "failed to read rpc message: %s\n", strerror (errno));
			exit (1);
		}

		if (!p11_rpc_server_handle (&virt.funcs, &buffer, &buffer)) {
			fprintf (stderr, "unexpected error handling rpc message\n");
			exit (1);
		}

		state = 0;
		options.len = 0;
		do {
			status = p11_rpc_transport_write (1, &state, code,
			                                  &options, &buffer);
		} while (status == P11_RPC_AGAIN);

		switch (status) {
		case P11_RPC_OK:
			break;
		case P11_RPC_EOF:
		case P11_RPC_AGAIN:
			assert_not_reached ();
		case P11_RPC_ERROR:
			fprintf (stderr, "failed to write rpc message: %s\n", strerror (errno));
			exit (1);
		}
	}

	p11_buffer_uninit (&buffer);
	p11_buffer_uninit (&options);
	p11_dl_close (dl);

	return 0;
}
