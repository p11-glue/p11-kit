/*
 * Copyright © 2020 Amazon.com, Inc. or its affiliates.
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
 * Author: David Woodhouse <dwmw2@infradead.org>
 */

#include "config.h"

#include "vsock.h"

#include <limits.h>
#include <string.h>
#include <stdlib.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#ifdef HAVE_VSOCK
#include <sys/socket.h>
#include <linux/vm_sockets.h>
#include <sys/ioctl.h>
#endif

/* This generic parsing utility doesn't actually require the
 * vm_sockets.h header and thus doesn't require conditional
 * compiliation... except for this one definition. */
#ifndef VMADDR_CID_ANY
#define VMADDR_CID_ANY -1U
#endif

bool
p11_vsock_parse_addr (const char *target,
		      unsigned int *cid,
		      unsigned int *port)
{
	bool cid_found = false;
	bool port_found = false;
	unsigned long val;
	char *endptr;

	while (*target) {
		if (strncmp (target, "cid=", 4) == 0) {
			val = strtoul(target + 4, &endptr, 0);
			if (val > UINT_MAX || endptr == target + 4)
				return false;
			*cid = val;
			cid_found = true;
		} else if (strncmp (target, "port=", 5) == 0) {
			val = strtoul (target + 5, &endptr, 0);
			if (val > UINT_MAX || endptr == target + 5)
				return false;
			*port = val;
			port_found = true;
		} else {
			return false;
		}

		target = endptr;
		if (*target == ';')
			target++;
		else if (*target)
			return false;
	}

	/* Port is mandatory */
	if (!port_found)
		return false;

	/* CID is optional, defaulting to VMADDR_CID_ANY */
	if (!cid_found)
		*cid = VMADDR_CID_ANY;

	return true;
}

bool
p11_vsock_get_local_cid (unsigned int *cid)
{
#ifndef HAVE_VSOCK
	return false;
#else
	int fd = open ("/dev/vsock", O_RDONLY);
	int rc;

	if (fd == -1)
		return false;

	rc = ioctl (fd, IOCTL_VM_SOCKETS_GET_LOCAL_CID, cid, sizeof(*cid));
	close (fd);

	return (rc == 0);
#endif
}
