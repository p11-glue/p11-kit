/*
 * Copyright (C) 2012 Stefan Walter
 * Copyright (C) 2013 Stefan Walter
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
 * Author: Stef Walter <stefw@gnome.org>
 */

#ifndef __P11_RPC_H__
#define __P11_RPC_H__

#include "pkcs11.h"
#include "buffer.h"
#include "virtual.h"

typedef struct _p11_rpc_client_vtable p11_rpc_client_vtable;

struct _p11_rpc_client_vtable {
	void *data;

	CK_RV       (* connect)       (p11_rpc_client_vtable *vtable,
	                               void *init_reserved);

	CK_RV       (* transport)     (p11_rpc_client_vtable *vtable,
	                               p11_buffer *request,
	                               p11_buffer *response);

	void        (* disconnect)    (p11_rpc_client_vtable *vtable,
	                               void *fini_reserved);
};

bool                   p11_rpc_client_init         (p11_virtual *virt,
                                                    p11_rpc_client_vtable *vtable);

bool                   p11_rpc_server_handle       (CK_X_FUNCTION_LIST *funcs,
                                                    p11_buffer *request,
                                                    p11_buffer *response);

extern CK_MECHANISM_TYPE *  p11_rpc_mechanisms_override_supported;

typedef struct _p11_rpc_transport p11_rpc_transport;

p11_rpc_transport *    p11_rpc_transport_new       (p11_virtual *virt,
                                                    const char *remote,
                                                    const char *name);

void                   p11_rpc_transport_free      (void *transport);

typedef enum {
	P11_RPC_OK,
	P11_RPC_EOF,
	P11_RPC_AGAIN,
	P11_RPC_ERROR
} p11_rpc_status;

p11_rpc_status         p11_rpc_transport_read      (int fd,
                                                    size_t *state,
                                                    int *call_code,
                                                    p11_buffer *options,
                                                    p11_buffer *buffer);

p11_rpc_status         p11_rpc_transport_write     (int fd,
                                                    size_t *state,
                                                    int call_code,
                                                    p11_buffer *options,
                                                    p11_buffer *buffer);

#endif /* __P11_RPC_H__ */
