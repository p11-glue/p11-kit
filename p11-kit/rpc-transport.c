/*
 * Copyright (C) 2012 Stefan Walter
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
 * Author: Stef Walter <stefw@gnome.org>
 */

#include "config.h"

#include "argv.h"
#include "compat.h"
#define P11_DEBUG_FLAG P11_DEBUG_RPC
#include "debug.h"
#include "message.h"
#include "pkcs11.h"
#include "private.h"
#include "rpc.h"
#include "rpc-message.h"
#include "path.h"

#include <sys/types.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef OS_UNIX
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/un.h>
#include <signal.h>
#include <unistd.h>
#include <limits.h>
#endif

#ifdef OS_WIN32
#include <process.h>
#include <signal.h>
#include <winsock2.h>
#ifndef EWOULDBLOCK
#define EWOULDBLOCK WSAEWOULDBLOCK
#endif
#endif

#ifndef EPROTO
#define EPROTO EIO
#endif

typedef struct {
	/* Never changes.  On Unix, these are identical, as it is
	 * backed by a socket.  On Windows, it is another file
	 * descriptor, as they are backed by two pipes */
	int read_fd;
	int write_fd;

	/* Protected by the lock */
	p11_mutex_t write_lock;
	int refs;
	int last_code;
	bool sent_creds;

	/* This data is protected by read mutex */
	p11_mutex_t read_lock;
#ifdef OS_UNIX
        /* Signalled when read_code changes */
        p11_cond_t read_code_cond;
#endif
	bool read_creds;
	uint32_t read_code;
	uint32_t read_olen;
	uint32_t read_dlen;
} rpc_socket;

static rpc_socket *
rpc_socket_new (int fd)
{
	rpc_socket *sock;

	sock = calloc (1, sizeof (rpc_socket));
	return_val_if_fail (sock != NULL, NULL);

	sock->read_fd = fd;
	sock->write_fd = fd;
	sock->last_code = 0x10;
	sock->read_creds = false;
	sock->sent_creds = false;
	sock->refs = 1;

	p11_mutex_init (&sock->write_lock);
	p11_mutex_init (&sock->read_lock);

#ifdef OS_UNIX
        p11_cond_init (&sock->read_code_cond);
#endif

	return sock;
}

#if 0
static rpc_socket *
rpc_socket_ref (rpc_socket *sock)
{
	assert (sock != NULL);

	p11_mutex_lock (&sock->write_lock);
	sock->refs++;
	p11_mutex_unlock (&sock->write_lock);

	return sock;
}

static bool
rpc_socket_is_open (rpc_socket *sock)
{
	assert (sock != NULL);
	return sock->read_fd >= 0;
}
#endif

static void
rpc_socket_close (rpc_socket *sock)
{
	assert (sock != NULL);
	if (sock->read_fd != -1)
		close (sock->read_fd);
	sock->read_fd = -1;
#ifdef OS_WIN32
	if (sock->write_fd != -1)
		close (sock->write_fd);
	sock->write_fd = -1;
#endif
}

static void
rpc_socket_unref (rpc_socket *sock)
{
	int release = 0;

	assert (sock != NULL);

	p11_mutex_lock (&sock->write_lock);
	if (--sock->refs == 0)
		release = 1;
	p11_mutex_unlock (&sock->write_lock);

	if (!release)
		return;

	assert (sock != NULL);
	assert (sock->refs == 0);

	rpc_socket_close (sock);
	p11_mutex_uninit (&sock->write_lock);
	p11_mutex_uninit (&sock->read_lock);
#ifdef OS_UNIX
        p11_cond_uninit (&sock->read_code_cond);
#endif
	free (sock);
}

static bool
write_all (int fd,
           unsigned char* data,
           size_t len)
{
	int r;

	while (len > 0) {
		r = write (fd, data, len);
		if (r == -1) {
			if (errno == EPIPE) {
				p11_message ("couldn't send data: closed connection");
				return false;
			} else if (errno != EAGAIN && errno != EINTR) {
				p11_message_err (errno, "couldn't send data");
				return false;
			}
		} else {
			p11_debug ("wrote %d bytes", r);
			data += r;
			len -= r;
		}
	}

	return true;
}

static bool
read_all (int fd,
          unsigned char* data,
          size_t len)
{
	int r;

	while (len > 0) {
		r = read (fd, data, len);
		if (r == 0) {
			p11_message ("couldn't receive data: closed connection");
			return false;
		} else if (r == -1) {
			if (errno != EAGAIN && errno != EINTR) {
				p11_message_err (errno, "couldn't receive data");
				return false;
			}
		} else {
			p11_debug ("read %d bytes", r);
			data += r;
			len -= r;
		}
	}

	return true;
}

static CK_RV
rpc_socket_write_inlock (rpc_socket *sock,
                         int code,
                         p11_buffer *options,
                         p11_buffer *buffer)
{
	unsigned char header[12];
	unsigned char dummy = '\0';

	/* The socket is locked and referenced at this point */
	assert (buffer != NULL);

	/* Place holder byte, will later carry unix credentials (on some systems) */
	if (!sock->sent_creds) {
		if (write_all (sock->write_fd, &dummy, 1) != 1) {
			p11_message_err (errno, "couldn't send socket credentials");
			return CKR_DEVICE_ERROR;
		}
		sock->sent_creds = true;
	}

	p11_rpc_buffer_encode_uint32 (header, code);
	p11_rpc_buffer_encode_uint32 (header + 4, options->len);
	p11_rpc_buffer_encode_uint32 (header + 8, buffer->len);

	if (!write_all (sock->write_fd, header, 12) ||
	    !write_all (sock->write_fd, options->data, options->len) ||
	    !write_all (sock->write_fd, buffer->data, buffer->len))
		return CKR_DEVICE_ERROR;

	return CKR_OK;
}

static p11_rpc_status
write_at (int fd,
          unsigned char *data,
          size_t len,
          size_t offset,
          size_t *at)
{
	p11_rpc_status status;
	ssize_t num;
	size_t from;
	int errn;

	assert (*at >= offset);

	if (*at >= offset + len)
		return P11_RPC_OK;

	from = *at - offset;
	assert (from < len);

	num = write (fd, data + from, len - from);
	errn = errno;

	/* Update state */
	if (num > 0)
		*at += num;

	/* Completely written out this block */
	if (num == len - from) {
		p11_debug ("ok: wrote block of %d", (int)num);
		status = P11_RPC_OK;

	/* Partially written out this block */
	} else if (num >= 0) {
		p11_debug ("again: partial read of %d", (int)num);
		status = P11_RPC_AGAIN;

	/* Didn't write out block due to transient issue */
	} else if (errn == EINTR || errn == EAGAIN || errn == EWOULDBLOCK) {
		p11_debug ("again: due to %d", errn);
		status = P11_RPC_AGAIN;

	/* Failure */
	} else {
		p11_debug ("error: due to %d", errn);
		status = P11_RPC_ERROR;
	}

	errno = errn;
	return status;
}

p11_rpc_status
p11_rpc_transport_write (int fd,
                         size_t *state,
                         int call_code,
                         p11_buffer *options,
                         p11_buffer *buffer)
{
	unsigned char header[12] = { 0, };
	p11_rpc_status status;

	assert (state != NULL);
	assert (options != NULL);
	assert (buffer != NULL);

	if (*state < 12) {
		p11_rpc_buffer_encode_uint32 (header, call_code);
		p11_rpc_buffer_encode_uint32 (header + 4, options->len);
		p11_rpc_buffer_encode_uint32 (header + 8, buffer->len);
	}

	status = write_at (fd, header, 12, 0, state);

	if (status == P11_RPC_OK) {
		status = write_at (fd, options->data, options->len,
		                   12, state);
	}

	if (status == P11_RPC_OK) {
		status = write_at (fd, buffer->data, buffer->len,
		                   12 + options->len, state);
	}

	/* All done */
	if (status == P11_RPC_OK)
		*state = 0;

	return status;
}

static void
rpc_socket_set_read_code_inlock (rpc_socket *sock,
                                 int code)
{
        sock->read_code = code;
#ifdef OS_UNIX
        p11_cond_broadcast (&sock->read_code_cond);
#endif
}

#ifdef OS_UNIX
static void
rpc_socket_wait_for_read_code_change_inlock (rpc_socket *sock)
{
        p11_cond_wait (&sock->read_code_cond, &sock->read_lock);
}
#endif

static int
rpc_socket_read (rpc_socket *sock,
                 int *code,
                 p11_buffer *buffer)
{
	CK_RV ret = CKR_DEVICE_ERROR;
	unsigned char header[12];
	unsigned char dummy;
#ifdef OS_WIN32
	HANDLE handle;
	DWORD mode;
#endif

	assert (code != NULL);
	assert (buffer != NULL);

	/*
	 * We are not in the main socket lock here, but the socket
	 * is referenced, and won't go away
	 */

	p11_mutex_lock (&sock->read_lock);

	if (!sock->read_creds) {
		if (read_all (sock->read_fd, &dummy, 1) != 1) {
			p11_mutex_unlock (&sock->read_lock);
			return CKR_DEVICE_ERROR;
		}
		sock->read_creds = true;
	}

	for (;;) {
		/* No message header has been read yet? ... read one in */
		if (sock->read_code == 0) {
			if (!read_all (sock->read_fd, header, 12))
				break;

			/* Decode and check the message header */
			rpc_socket_set_read_code_inlock (sock, p11_rpc_buffer_decode_uint32 (header));
			sock->read_olen = p11_rpc_buffer_decode_uint32 (header + 4);
			sock->read_dlen = p11_rpc_buffer_decode_uint32 (header + 8);
			if (sock->read_code == 0) {
				p11_message ("received invalid rpc header values: perhaps wrong protocol");
				break;
			}
		}

		/* If it's our header (or caller doesn't care), then yay! */
		if (*code == -1 || sock->read_code == *code) {

			/* We ignore the options, so read into the same as buffer */
			if (!p11_buffer_reset (buffer, sock->read_olen) ||
			    !p11_buffer_reset (buffer, sock->read_dlen)) {
				warn_if_reached ();
				break;
			}

			/* Read in the the options first, and then data */
			if (!read_all (sock->read_fd, buffer->data, sock->read_olen) ||
			    !read_all (sock->read_fd, buffer->data, sock->read_dlen))
				break;

			buffer->len = sock->read_dlen;
			*code = sock->read_code;

			/* Yay, we got our data, off we go */
                        rpc_socket_set_read_code_inlock (sock, 0);
			sock->read_olen = 0;
			sock->read_dlen = 0;
			ret = CKR_OK;
			break;
		}

		/* Give another thread the chance to read data for this header */
		if (sock->read_code != 0) {
			p11_debug ("received header in wrong thread");

#ifdef OS_UNIX
                        rpc_socket_wait_for_read_code_change_inlock (sock);
#endif
#ifdef OS_WIN32
			/* Used as a simple wait */
			p11_mutex_unlock (&sock->read_lock);
			handle = (HANDLE) _get_osfhandle (sock->read_fd);
			if (!ReadFile (handle, NULL, 0, &mode, NULL))
				p11_message ("couldn't use select to wait on rpc pipe");
			p11_mutex_lock (&sock->read_lock);
#endif
		}
	}

	p11_mutex_unlock (&sock->read_lock);
	return ret;
}

static p11_rpc_status
read_at (int fd,
         unsigned char *data,
         size_t len,
         size_t offset,
         size_t *at)
{
	p11_rpc_status status;
	int errn;
	ssize_t num;
	size_t from;

	assert (*at >= offset);

	if (*at >= offset + len)
		return P11_RPC_OK;

	from = *at - offset;
	assert (from < len);

	num = read (fd, data + from, len - from);
	errn = errno;

	/* Update state */
	if (num > 0)
		*at += num;

	/* Completely read out this block */
	if (num == len - from) {
		p11_debug ("ok: read block of %d", (int)num);
		status = P11_RPC_OK;

	/* Partially read out this block */
	} else if (num > 0) {
		p11_debug ("again: partial read of %d", (int)num);
		status = P11_RPC_AGAIN;

	/* End of file, valid if at offset zero */
	} else if (num == 0) {
		if (offset == 0) {
			p11_debug ("eof: read zero bytes");
			status = P11_RPC_EOF;
		} else {
			p11_debug ("error: early truncate");
			errn = EPROTO;
			status = P11_RPC_ERROR;
		}

	/* Didn't read out block due to transient issue */
	} else if (errn == EINTR || errn == EAGAIN || errn == EWOULDBLOCK) {
		p11_debug ("again: due to %d", errn);
		status = P11_RPC_AGAIN;

	/* Failure */
	} else {
		p11_debug ("error: due to %d", errn);
		status = P11_RPC_ERROR;
	}

	errno = errn;
	return status;
}

p11_rpc_status
p11_rpc_transport_read (int fd,
                        size_t *state,
                        int *call_code,
                        p11_buffer *options,
                        p11_buffer *buffer)
{
	unsigned char *header;
	p11_rpc_status status;
	size_t len;

	assert (state != NULL);
	assert (call_code != NULL);
	assert (options != NULL);
	assert (buffer != NULL);

	/* Reading the header, we read it into @buffer */
	if (*state < 12) {
		if (!p11_buffer_reset (buffer, 12))
			return_val_if_reached (P11_RPC_ERROR);
		status = read_at (fd, buffer->data, 12, 0, state);
		if (status != P11_RPC_OK)
			return status;

		/* Parse out the header */
		header = buffer->data;
		*call_code = p11_rpc_buffer_decode_uint32 (header);
		len = p11_rpc_buffer_decode_uint32 (header + 4);
		if (!p11_buffer_reset (options, len))
			return_val_if_reached (P11_RPC_ERROR);
		options->len = len;
		len = p11_rpc_buffer_decode_uint32 (header + 8);
		if (!p11_buffer_reset (buffer, len))
			return_val_if_reached (P11_RPC_ERROR);
		buffer->len = len;
	}

	/* At this point options has a valid len field */
	status = read_at (fd, options->data, options->len, 12, state);
	if (status == P11_RPC_OK) {
		status = read_at (fd, buffer->data, buffer->len,
		                  12 + options->len, state);
	}

	if (status == P11_RPC_OK)
		*state = 0;

	return status;
}

struct _p11_rpc_transport {
	p11_rpc_client_vtable vtable;
	p11_destroyer destroyer;
	rpc_socket *socket;
	p11_buffer options;
};

static void
rpc_transport_disconnect (p11_rpc_client_vtable *vtable,
                          void *init_reserved)
{
	p11_rpc_transport *rpc = (p11_rpc_transport *)vtable;

	if (rpc->socket) {
		rpc_socket_close (rpc->socket);
		rpc_socket_unref (rpc->socket);
		rpc->socket = NULL;
	}
}

static bool
rpc_transport_init (p11_rpc_transport *rpc,
                    const char *module_name,
                    p11_destroyer destroyer)
{
	rpc->destroyer = destroyer;

	p11_buffer_init_null (&rpc->options, 0);
	p11_buffer_add (&rpc->options, module_name, -1);
	return_val_if_fail (p11_buffer_ok (&rpc->options), false);

	return true;
}

static void
rpc_transport_uninit (p11_rpc_transport *rpc)
{
	p11_buffer_uninit (&rpc->options);
}

static CK_RV
rpc_transport_buffer (p11_rpc_client_vtable *vtable,
                      p11_buffer *request,
                      p11_buffer *response)
{
	p11_rpc_transport *rpc = (p11_rpc_transport *)vtable;
	CK_RV rv = CKR_OK;
	rpc_socket *sock;
	int call_code;

	assert (rpc != NULL);
	assert (request != NULL);
	assert (response != NULL);

	sock = rpc->socket;
	assert (sock != NULL);

	p11_mutex_lock (&sock->write_lock);
	assert (sock->refs > 0);
	sock->refs++;

	/* Get the next socket reply code */
	call_code = sock->last_code++;

	if (sock->read_fd == -1)
		rv = CKR_DEVICE_ERROR;
#ifdef OS_WIN32
	if (sock->write_fd == -1)
		rv = CKR_DEVICE_ERROR;
#endif
	if (rv == CKR_OK)
		rv = rpc_socket_write_inlock (sock, call_code, &rpc->options, request);

	/* We unlock the socket mutex while reading a response */
	if (rv == CKR_OK) {
		p11_mutex_unlock (&sock->write_lock);

		rv = rpc_socket_read (sock, &call_code, response);

		p11_mutex_lock (&sock->write_lock);
	}

	if (rv != CKR_OK && sock->read_fd != -1) {
		p11_message ("closing socket due to protocol failure");
		close (sock->read_fd);
		sock->read_fd = -1;
	}
#ifdef OS_WIN32
	if (rv != CKR_OK && sock->write_fd != -1) {
		p11_message ("closing socket due to protocol failure");
		close (sock->write_fd);
		sock->write_fd = -1;
	}
#endif

	sock->refs--;
	assert (sock->refs > 0);
	p11_mutex_unlock (&sock->write_lock);

	return rv;
}

#ifdef OS_UNIX

typedef struct {
	p11_rpc_transport base;
	p11_array *argv;
	pid_t pid;
} rpc_exec;

static void
rpc_exec_wait_or_terminate (pid_t pid)
{
	bool terminated = false;
	int status;
	int sig;
	int ret;
	int i;


	for (i = 0; i < 3 * 1000; i += 100) {
		ret = waitpid (pid, &status, WNOHANG);
		if (ret != 0)
			break;
		p11_sleep_ms (100);
	}

	if (ret == 0) {
		p11_message ("process %d did not exit, terminating", (int)pid);
		kill (pid, SIGTERM);
		terminated = true;
		ret = waitpid (pid, &status, 0);
	}

	if (ret < 0) {
		p11_message_err (errno, "failed to wait for executed child: %d", (int)pid);
		status = 0;
	} else if (WIFEXITED (status)) {
		status = WEXITSTATUS (status);
		if (status == 0)
			p11_debug ("process %d exited with status 0", (int)pid);
		else
			p11_message ("process %d exited with status %d", (int)pid, status);
	} else if (WIFSIGNALED (status)) {
		sig = WTERMSIG (status);
		if (!terminated || sig != SIGTERM)
			p11_message ("process %d was terminated with signal %d", (int)pid, sig);
	}
}

static void
rpc_exec_disconnect (p11_rpc_client_vtable *vtable,
                     void *fini_reserved)
{
	rpc_exec *rex = (rpc_exec *)vtable;

	if (rex->base.socket)
		rpc_socket_close (rex->base.socket);

	if (rex->pid)
		rpc_exec_wait_or_terminate (rex->pid);
	rex->pid = 0;

	/* Do the common disconnect stuff */
	rpc_transport_disconnect (vtable, fini_reserved);
}

static int
set_cloexec_on_fd (void *data,
                   int fd)
{
	int *max_fd = data;
	if (fd >= *max_fd)
		fcntl (fd, F_SETFD, FD_CLOEXEC);
	return 0;
}

static CK_RV
rpc_exec_connect (p11_rpc_client_vtable *vtable,
                  void *init_reserved)
{
	rpc_exec *rex = (rpc_exec *)vtable;
	pid_t pid;
	int max_fd;
	int fds[2];
	int errn;

	p11_debug ("executing rpc transport: %s", (char *)rex->argv->elem[0]);

	if (socketpair (AF_UNIX, SOCK_STREAM, 0, fds) < 0) {
		p11_message_err (errno, "failed to create pipe for remote");
		return CKR_DEVICE_ERROR;
	}

	pid = fork ();
	switch (pid) {

	/* Failure */
	case -1:
		close (fds[0]);
		close (fds[1]);
		p11_message_err (errno, "failed to fork for remote");
		return CKR_DEVICE_ERROR;

	/* Child */
	case 0:
		if (dup2 (fds[1], STDIN_FILENO) < 0 ||
		    dup2 (fds[1], STDOUT_FILENO) < 0) {
			errn = errno;
			p11_message_err (errn, "couldn't dup file descriptors in remote child");
			_exit (errn);
		}

		/* Close file descriptors, except for above on exec */
		max_fd = STDERR_FILENO + 1;
		fdwalk (set_cloexec_on_fd, &max_fd);
		execvp (rex->argv->elem[0], (char **)rex->argv->elem);

		errn = errno;
		p11_message_err (errn, "couldn't execute program for rpc: %s",
		                 (char *)rex->argv->elem[0]);
		_exit (errn);

	/* The parent */
	default:
		break;
	}

	close (fds[1]);
	rex->pid = pid;
	rex->base.socket = rpc_socket_new (fds[0]);
	return_val_if_fail (rex->base.socket != NULL, CKR_GENERAL_ERROR);

	return CKR_OK;
}

#endif /* OS_UNIX */

#ifdef OS_WIN32

typedef struct {
	p11_rpc_transport base;
	p11_array *argv;
	HANDLE pid;
} rpc_exec;

static void
rpc_exec_wait_or_terminate (HANDLE pid)
{
	DWORD status;
	int ret;
	int i;


	for (i = 0; i < 3 * 1000; i += 100) {
		ret = WaitForSingleObject (pid, 10000);
		if (ret == WAIT_OBJECT_0)
			break;
	}

	if (ret != WAIT_OBJECT_0) {
		p11_message ("process %p did not exit, terminating", pid);
		if (!TerminateProcess (pid, SIGTERM))
			p11_message ("couldn't terminate process %p", pid);
		ret = WaitForSingleObject (pid, 0);
	}

	if (ret != WAIT_OBJECT_0) {
		p11_message ("failed to wait for executed child: %p", pid);
		status = 0;
	} else if (!GetExitCodeProcess (pid, &status)) {
		p11_message ("failed to get the exit status of %p", pid);
	} else if (status == 0) {
		p11_debug ("process %p exited with status 0", pid);
	} else {
		p11_message ("process %p exited with status %lu", pid, status);
	}

	CloseHandle (pid);
}

static void
rpc_exec_disconnect (p11_rpc_client_vtable *vtable,
                     void *fini_reserved)
{
	rpc_exec *rex = (rpc_exec *)vtable;

	if (rex->base.socket)
		rpc_socket_close (rex->base.socket);

	if (rex->pid != INVALID_HANDLE_VALUE)
		rpc_exec_wait_or_terminate (rex->pid);
	rex->pid = INVALID_HANDLE_VALUE;

	/* Do the common disconnect stuff */
	rpc_transport_disconnect (vtable, fini_reserved);
}

static int
set_cloexec_on_fd (int fd)
{
	HANDLE handle;

	handle = (HANDLE) _get_osfhandle (fd);
	if (!SetHandleInformation (handle, HANDLE_FLAG_INHERIT, 0))
		return -1;

	return 0;
}

static CK_RV
rpc_exec_connect (p11_rpc_client_vtable *vtable,
                  void *init_reserved)
{
	rpc_exec *rex = (rpc_exec *)vtable;
	intptr_t pid = -1;
	int pw[2] = { -1, -1 }, pr[2] = { -1, -1 };
	int fds[2] = { -1, -1 };
	CK_RV rv = CKR_OK;

	p11_debug ("executing rpc transport: %s", (char *)rex->argv->elem[0]);

	setvbuf (stdout, NULL, _IONBF, 0 );

	if (_pipe (pw, 256, _O_BINARY) == -1 ||
	    set_cloexec_on_fd (pw[1]) == -1) {
		p11_message_err (errno, "failed to create pipe for remote");
		rv = CKR_DEVICE_ERROR;
		goto out;
	}

	if (_pipe (pr, 256, _O_BINARY) == -1 ||
	    set_cloexec_on_fd (pr[0]) == -1) {
		p11_message_err (errno, "failed to create pipe for remote");
		rv = CKR_DEVICE_ERROR;
		goto out;
	}

	/* Save the original stdin and stdout */
	fds[0] = dup (STDIN_FILENO);
	if (fds[0] == -1) {
		p11_message_err (errno, "failed to duplicate stdin");
		rv = CKR_DEVICE_ERROR;
		goto out;
	}

	fds[1] = dup (STDOUT_FILENO);
	if (fds[1] == -1) {
		p11_message_err (errno, "failed to duplicate stdout");
		rv = CKR_DEVICE_ERROR;
		goto out;
	}

	/* Temporarily redirect pipe descriptors to stdin/stdout for child */
	if (dup2 (pw[0], STDIN_FILENO) == -1 ||
	    dup2 (pr[1], STDOUT_FILENO) == -1) {
		p11_message_err (errno, "failed to duplicate child end of pipe");
		rv = CKR_DEVICE_ERROR;
		goto out;
	}

	pid = _spawnv (P_NOWAIT,
		       rex->argv->elem[0],
		       (const char * const *)rex->argv->elem);

	if (pid == -1) {
		p11_message_err (errno, "failed to spawn remote");
		rv = CKR_DEVICE_ERROR;
		goto out;
	}

	close (pw[0]);
	pw[0] = -1;
	close (pr[1]);
	pr[1] = -1;

	/* Restore the original stdin and stdout */
	if (dup2 (fds[0], STDIN_FILENO) == -1 ||
	    dup2 (fds[1], STDOUT_FILENO) == -1) {
		p11_message_err (errno, "failed to restore file descriptors");
		rv = CKR_DEVICE_ERROR;
		goto out;
	}

	close (fds[0]);
	fds[0] = -1;
	close (fds[1]);
	fds[1] = -1;

	rex->pid = (HANDLE) pid;
	rex->base.socket = rpc_socket_new (pr[0]);
	return_val_if_fail (rex->base.socket != NULL, CKR_GENERAL_ERROR);
	rex->base.socket->write_fd = pw[1];

 out:
	if (rv != CKR_OK) {
		if (pid != -1) {
			TerminateProcess ((HANDLE) pid, SIGTERM);
			CloseHandle ((HANDLE) pid);
		}
		if (pw[0] != -1)
			close (pw[0]);
		if (pw[1] != -1)
			close (pw[1]);
		if (pr[0] != -1)
			close (pr[0]);
		if (pr[1] != -1)
			close (pr[1]);
		if (fds[0] != -1)
			close (fds[0]);
		if (fds[1] != -1)
			close (fds[1]);
	}

	return rv;
}

#endif /* OS_WIN32 */

static void
rpc_exec_free (void *data)
{
	rpc_exec *rex = data;
	rpc_exec_disconnect (data, NULL);
	rpc_transport_uninit (&rex->base);
	p11_array_free (rex->argv);
	free (rex);
}

static void
on_argv_parsed (char *argument,
                void *data)
{
	p11_array *argv = data;

	if (!p11_array_push (argv, strdup (argument)))
		return_if_reached ();
}

static p11_rpc_transport *
rpc_exec_init (const char *remote,
               const char *name)
{
	p11_array *argv;
	rpc_exec *rex;

	argv = p11_array_new (free);
	if (!p11_argv_parse (remote, on_argv_parsed, argv) || argv->num < 1) {
		p11_message ("invalid remote command line: %s", remote);
		p11_array_free (argv);
		return NULL;
	}

	rex = calloc (1, sizeof (rpc_exec));
	return_val_if_fail (rex != NULL, NULL);

	p11_array_push (argv, NULL);
	rex->argv = argv;
#ifdef OS_WIN32
	rex->pid = INVALID_HANDLE_VALUE;
#endif

	rex->base.vtable.connect = rpc_exec_connect;
	rex->base.vtable.disconnect = rpc_exec_disconnect;
	rex->base.vtable.transport = rpc_transport_buffer;
	rpc_transport_init (&rex->base, name, rpc_exec_free);

	p11_debug ("initialized rpc exec: %s", remote);
	return &rex->base;
}

#ifdef OS_UNIX

typedef struct {
	p11_rpc_transport base;
	struct sockaddr_un sa;
} rpc_unix;

static CK_RV
rpc_unix_connect (p11_rpc_client_vtable *vtable,
		    void *init_reserved)
{
	rpc_unix *run = (rpc_unix *)vtable;
	int fd;

	fd = socket (AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) {
		p11_message_err (errno, "failed to create socket for remote");
		return CKR_GENERAL_ERROR;
	}

	if (connect (fd, (struct sockaddr *)&run->sa, sizeof (run->sa)) < 0) {
		p11_debug_err (errno, "failed to connect to socket");
		close (fd);
		return CKR_DEVICE_REMOVED;
	}

	run->base.socket = rpc_socket_new (fd);
	return_val_if_fail (run->base.socket != NULL, CKR_GENERAL_ERROR);

	return CKR_OK;
}

static void
rpc_unix_disconnect (p11_rpc_client_vtable *vtable,
                     void *fini_reserved)
{
	rpc_unix *run = (rpc_unix *)vtable;

	if (run->base.socket)
		rpc_socket_close (run->base.socket);

	/* Do the common disconnect stuff */
	rpc_transport_disconnect (vtable, fini_reserved);
}

static void
rpc_unix_free (void *data)
{
	rpc_unix *run = data;
	rpc_unix_disconnect (data, NULL);
	rpc_transport_uninit (&run->base);
	free (run);
}

static p11_rpc_transport *
rpc_unix_init (const char *remote,
	       const char *name)
{
	rpc_unix *run;

	run = calloc (1, sizeof (rpc_unix));
	return_val_if_fail (run != NULL, NULL);

	memset (&run->sa, 0, sizeof (run->sa));
	run->sa.sun_family = AF_UNIX;
	snprintf (run->sa.sun_path, sizeof (run->sa.sun_path), "%s", remote);

	run->base.vtable.connect = rpc_unix_connect;
	run->base.vtable.disconnect = rpc_unix_disconnect;
	run->base.vtable.transport = rpc_transport_buffer;
	rpc_transport_init (&run->base, name, rpc_unix_free);

	p11_debug ("initialized rpc socket: %s", remote);
	return &run->base;
}

#endif /* OS_UNIX */

#ifdef HAVE_VSOCK
#include <linux/vm_sockets.h>
#include <vsock.h>

typedef struct {
	p11_rpc_transport base;
	struct sockaddr_vm sa;
} rpc_vsock;

static CK_RV
rpc_vsock_connect (p11_rpc_client_vtable *vtable,
		   void *init_reserved)
{
	rpc_vsock *run = (rpc_vsock *)vtable;
	int fd;

	fd = socket (AF_VSOCK, SOCK_STREAM, 0);
	if (fd < 0) {
		p11_message_err (errno, "failed to create socket for remote");
		return CKR_GENERAL_ERROR;
	}

	if (connect (fd, (struct sockaddr *)&run->sa, sizeof (run->sa)) < 0) {
		p11_debug_err (errno, "failed to connect to socket");
		close (fd);
		return CKR_DEVICE_REMOVED;
	}

	run->base.socket = rpc_socket_new (fd);
	return_val_if_fail (run->base.socket != NULL, CKR_GENERAL_ERROR);

	return CKR_OK;
}

static void
rpc_vsock_disconnect (p11_rpc_client_vtable *vtable,
                      void *fini_reserved)
{
	rpc_vsock *run = (rpc_vsock *)vtable;

	if (run->base.socket)
		rpc_socket_close (run->base.socket);

	/* Do the common disconnect stuff */
	rpc_transport_disconnect (vtable, fini_reserved);
}

static void
rpc_vsock_free (void *data)
{
	rpc_vsock *run = data;
	rpc_vsock_disconnect (data, NULL);
	rpc_transport_uninit (&run->base);
	free (run);
}

static p11_rpc_transport *
rpc_vsock_init (unsigned int cid,
		unsigned int port,
		const char *name)
{
	rpc_vsock *run;

	run = calloc (1, sizeof (rpc_vsock));
	return_val_if_fail (run != NULL, NULL);

	memset (&run->sa, 0, sizeof (run->sa));
	run->sa.svm_family = AF_VSOCK;
	run->sa.svm_cid = cid;
	run->sa.svm_port = port;

	run->base.vtable.connect = rpc_vsock_connect;
	run->base.vtable.disconnect = rpc_vsock_disconnect;
	run->base.vtable.transport = rpc_transport_buffer;
	rpc_transport_init (&run->base, name, rpc_vsock_free);

	p11_debug ("initialized rpc socket: vsock:cid=%u;port=%u",
		   cid, port);
	return &run->base;
}

#endif /* HAVE_VSOCK */

p11_rpc_transport *
p11_rpc_transport_new (p11_virtual *virt,
                       const char *remote,
                       const char *name)
{
	p11_rpc_transport *rpc = NULL;

	return_val_if_fail (virt != NULL, NULL);
	return_val_if_fail (remote != NULL, NULL);
	return_val_if_fail (name != NULL, NULL);

	/* This is a command we can execute */
	if (remote[0] == '|') {
		rpc = rpc_exec_init (remote + 1, name);

#ifdef OS_UNIX
	} else if (strncmp (remote, "unix:path=/", 11) == 0) {
		/* Only absolute path is supported */
		char *path;

		path = p11_path_decode (remote + 10);
		return_val_if_fail (path != NULL, NULL);
		rpc = rpc_unix_init (path, name);
		free (path);
#endif /* OS_UNIX */
#ifdef HAVE_VSOCK
	} else if (strncmp (remote, "vsock:", 6) == 0) {
		unsigned int cid = 0, port = 0;

		if (!p11_vsock_parse_addr (remote + 6, &cid, &port) ||
		    cid == VMADDR_CID_ANY) {
			p11_message ("failed to parse vsock address: '%s'",
				     remote + 6);
			return NULL;
		}

		rpc = rpc_vsock_init (cid, port, name);
#endif /* HAVE_VSOCK */
	} else {
		p11_message ("remote not supported: %s", remote);
		return NULL;
	}

	return_val_if_fail (rpc != NULL, NULL);

	if (!p11_rpc_client_init (virt, &rpc->vtable))
		return_val_if_reached (NULL);

	return rpc;
}

void
p11_rpc_transport_free (void *data)
{
	p11_rpc_transport *rpc = data;

	if (rpc != NULL) {
		assert (rpc->destroyer);
		(rpc->destroyer) (data);
	}
}
