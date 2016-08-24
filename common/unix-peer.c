/*
 * Copyright (C) 2013 Nikos Mavrogiannopoulos
 *
 * This file is part of ocserv.
 *
 * ocserv is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * ocserv is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "config.h"

/* needed for struct ucred */
#if defined(__linux__) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif

#include "unix-peer.h"

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <sys/errno.h>

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

#else
#error "Unsupported UNIX variant"
#endif
	return 0;
}
