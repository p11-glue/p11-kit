/*
 * Copyright (C) 2014 Red Hat Inc.
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
#include "message.h"
#include "rpc.h"
#include "remote.h"
#include "virtual.h"

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int
p11_kit_remote_serve_module (CK_FUNCTION_LIST *module,
                             int in_fd,
                             int out_fd)
{
	p11_rpc_status status;
	unsigned char version;
	p11_virtual virt;
	p11_buffer options;
	p11_buffer buffer;
	size_t state;
	int ret = 1;
	int code;

	return_val_if_fail (module != NULL, 1);

	p11_buffer_init (&options, 0);
	p11_buffer_init (&buffer, 0);

	p11_virtual_init (&virt, &p11_virtual_base, module, NULL);

	switch (read (in_fd, &version, 1)) {
	case 0:
		status = P11_RPC_EOF;
		break;
	case 1:
		if (version != 0) {
			p11_message ("unspported version received: %d", (int)version);
			goto out;
		}
		break;
	default:
		p11_message_err (errno, "couldn't read credential byte");
		goto out;
	}

	version = 0;
	switch (write (out_fd, &version, out_fd)) {
	case 1:
		break;
	default:
		p11_message_err (errno, "couldn't write credential byte");
		goto out;
	}

	status = P11_RPC_OK;
	while (status == P11_RPC_OK) {
		state = 0;
		code = 0;

		do {
			status = p11_rpc_transport_read (in_fd, &state, &code,
			                                 &options, &buffer);
		} while (status == P11_RPC_AGAIN);

		switch (status) {
		case P11_RPC_OK:
			break;
		case P11_RPC_EOF:
			ret = 0;
			continue;
		case P11_RPC_AGAIN:
			assert_not_reached ();
		case P11_RPC_ERROR:
			p11_message_err (errno, "failed to read rpc message");
			goto out;
		}

		if (!p11_rpc_server_handle (&virt.funcs, &buffer, &buffer)) {
			p11_message ("unexpected error handling rpc message");
			goto out;
		}

		state = 0;
		options.len = 0;
		do {
			status = p11_rpc_transport_write (out_fd, &state, code,
			                                  &options, &buffer);
		} while (status == P11_RPC_AGAIN);

		switch (status) {
		case P11_RPC_OK:
			break;
		case P11_RPC_EOF:
		case P11_RPC_AGAIN:
			assert_not_reached ();
		case P11_RPC_ERROR:
			p11_message_err (errno, "failed to write rpc message");
			goto out;
		}
	}

out:
	p11_buffer_uninit (&buffer);
	p11_buffer_uninit (&options);

	p11_virtual_uninit (&virt);

	return ret;
}
