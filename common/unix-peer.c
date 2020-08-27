/*
 * Copyright (c) 2013 Nikos Mavrogiannopoulos
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
 * Author: Nikos Mavrogiannopoulos <nmav@redhat.com>
 */

#include "config.h"

#include "unix-peer.h"

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <errno.h>

#ifdef HAVE_UCRED_H
#  include <ucred.h>
#endif

/* Returns the unix domain socket peer information.
 * Returns zero on success.
 */
int
p11_get_upeer_id (int cfd, uid_t *uid, uid_t *gid, pid_t *pid)
{
	int ret;
#if defined(SO_PEERCRED)
	struct ucred cr;
	socklen_t cr_len;

	cr_len = sizeof (cr);
	ret = getsockopt (cfd, SOL_SOCKET, SO_PEERCRED, &cr, &cr_len);
	if (ret == -1)
		return -1;

	if (uid)
		*uid = cr.uid;

	if (gid)
		*gid = cr.gid;

	if (pid)
		*pid = cr.pid;

#elif defined(HAVE_GETPEEREID)
	/* *BSD/MacOSX */
	uid_t euid;
	gid_t egid;

	ret = getpeereid (cfd, &euid, &egid);

	if (ret == -1)
		return -1;

	if (uid)
		*uid = euid;

	if (gid)
		*gid = egid;

	if (pid)
		*pid = -1;

#elif defined(HAVE_GETPEERUCRED)
	/* *Solaris/OpenIndiana */
	ucred_t *ucred = NULL;

	if (getpeerucred(cfd, &ucred) == -1)
		return -1;

	ret = ( (uid && (*uid = ucred_geteuid(ucred)) == -1) ||
			(gid && (*gid = ucred_getrgid(ucred)) == -1) ||
			(pid && (*pid = ucred_getpid(ucred)) == -1)  );

	ucred_free(ucred);

	if (ret)
		return -1;
#else
#error "Unsupported UNIX variant"
#endif
	return 0;
}
